//! Configuration.
//!
//! Rotonda is configured through a single TOML configuration file. We use
//! [serde] to deserialize this file into the [`Config`] struct provided by
//! this module. This struct also provides the facilities to load the config
//! file referred to in command line options.

use crate::log::{LogConfig, Terminate};
use crate::manager::{Manager, TargetSet, UnitSet};
use clap::{Arg, ArgMatches, Command};
use log::{error, trace};
use serde::Deserialize;
use serde_with::serde_as;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{borrow, error, fmt, fs, io, ops};
use toml::{Spanned, Value};

//------------ Constants -----------------------------------------------------

const ARG_CONFIG: &str = "config";

//------------ Config --------------------------------------------------------

/// The complete Rotonda configuration.
///
/// All configuration is available via public fields.
///
/// The associated function [`init`](Self::init) should be called first thing
/// as it initializes the operational environment such as logging. Thereafter,
/// [`config_args`](Self::config_args) can be used to configure a clap app to
/// be able to pick up the path to the configuration file.
/// [`from_arg_matches`](Self::from_arg_matches) will then load the file
/// referenced in the command line and, upon success, return the config.
#[serde_as]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Location of the .roto script containing all user defined filters.
    pub roto_script: Option<PathBuf>,

    /// The set of configured units.
    pub units: UnitSet,

    /// The set of configured targets.
    pub targets: TargetSet,

    /// The logging configuration.
    #[serde(flatten)]
    pub log: LogConfig,

    /// The new HTTP server configuration.
    #[serde(rename = "http_listen")]
    pub http_ng_listen: Option<Vec<SocketAddr>>,
}

impl Config {
    /// Initialises everything.
    ///
    /// This function should be called first thing.
    pub fn init() -> Result<(), Terminate> {
        LogConfig::init_logging()
    }

    /// Creates a configuration from a bytes slice with TOML data.
    pub fn from_bytes(
        slice: &[u8],
        base_dir: Option<impl AsRef<Path>>,
    ) -> Result<Self, toml::de::Error> {
        if let Some(ref base_dir) = base_dir {
            ConfigPath::set_base_path(base_dir.as_ref().into())
        }
        let config_str = String::from_utf8_lossy(slice);
        let res = toml::from_str(&config_str);
        ConfigPath::clear_base_path();
        res
    }

    /// Configures a clap app with the arguments to load the configuration.
    pub fn config_args(app: Command) -> Command {
        let app = app.arg(
            Arg::new(ARG_CONFIG)
                .short('c')
                .long(ARG_CONFIG)
                .required(true)
                .value_name("PATH")
                .help("Config file to use"),
        );
        LogConfig::config_args(app)
    }

    /// Loads the configuration based on command line options provided.
    ///
    /// The `matches` must be the result of getting argument matches from a
    /// clap app previously configured with
    /// [`config_args`](Self::config_args). Otherwise, the function is likely
    /// to panic.
    ///
    /// The current path needs to be provided to be able to deal with relative
    /// paths. The manager is necessary to resolve links given in the
    /// configuration.
    pub fn from_arg_matches(
        args: &ArgMatches,
        cur_dir: &Path,
        manager: &mut Manager,
    ) -> Result<(Source, Self), Terminate> {
        let config_file = {
            // With ARG_CONFIG required, we can unwrap here.
            let conf_path_arg = args.get_one::<String>(ARG_CONFIG).unwrap();
            let config_path = cur_dir.join(conf_path_arg);
            ConfigFile::load(&config_path).map_err(|err| {
                error!(
                    "Failed to read config file '{}': {}",
                    config_path.display(),
                    err
                );
                Terminate::error()
            })?
        };

        let mut config = manager.load(&config_file)?;
        config.log.update_with_arg_matches(args, cur_dir)?;
        config.finalise(config_file, manager)
    }

    pub fn from_config_file(
        config_file: ConfigFile,
        manager: &mut Manager,
    ) -> Result<(Source, Self), Terminate> {
        manager.load(&config_file)?.finalise(config_file, manager)
    }

    fn finalise(
        mut self,
        config_file: ConfigFile,
        manager: &mut Manager,
    ) -> Result<(Source, Self), Terminate> {
        self.log.switch_logging(false)?;

        self.auto_enable_peer_stats_synthesis();

        if log::log_enabled!(log::Level::Trace) {
            trace!("After processing the config file looks like this:");
            trace!("{}", config_file.to_string());
        }

        manager.prepare(&self, &config_file)?;

        // Pass the config file path, as well as the processed config, back to
        // the caller so that they can monitor it for changes while the
        // application is running.
        Ok((config_file.source, self))
    }

    /// Resolve the tri-state `synthesize_peer_stats` flag on every
    /// `BgpTcpIn` unit: if the user didn't set it, default it to
    /// `true` when at least one `BmpTcpOut` unit is present in the
    /// same config (since that's the consumer that benefits), and
    /// `false` otherwise. Explicit user values are left untouched.
    fn auto_enable_peer_stats_synthesis(&mut self) {
        use crate::units::Unit;
        let has_bmp_out = self
            .units
            .units()
            .values()
            .any(|u| matches!(u, Unit::BmpTcpOut(_)));
        for unit in self.units.units_mut().values_mut() {
            if let Unit::BgpTcpIn(bgp) = unit {
                if bgp.synthesize_peer_stats.is_none() {
                    bgp.synthesize_peer_stats = Some(has_bmp_out);
                }
            }
        }
    }
}

//------------ Source --------------------------------------------------------

/// Description of the source of configuration.
///
/// This type is used for error reporting. It can refer to a configuration
/// file or an interactive session.
///
/// File names are kept behind and arc and thus this type can be cloned
/// cheaply.
#[derive(Clone, Debug, Default)]
pub struct Source {
    /// The optional path of a config file.
    ///
    /// If this in `None`, the source is an interactive session.
    path: Option<Arc<Path>>,
}

impl Source {
    pub fn is_path(&self) -> bool {
        self.path.is_some()
    }

    pub fn path(&self) -> &Option<Arc<Path>> {
        &self.path
    }
}

impl<'a, T: AsRef<Path>> From<&'a T> for Source {
    fn from(path: &'a T) -> Source {
        Source {
            path: Some(path.as_ref().into()),
        }
    }
}

//------------ LineCol -------------------------------------------------------

/// A pair of a line and column number.
///
/// This is used for error reporting.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct LineCol {
    pub line: usize,
    pub col: usize,
}

//------------ Marked --------------------------------------------------------

/// A value marked with its source location.
///
/// This wrapper is used when data needs to be resolved after parsing has
/// finished. In this case, we need information about the source location
/// to be able to produce meaningful error messages.
#[derive(Clone, Debug, Deserialize)]
#[serde(from = "Spanned<T>")]
pub struct Marked<T> {
    value: T,
    index: usize,
    source: Option<Source>,
    pos: Option<LineCol>,
}

impl<T> Marked<T> {
    /// Resolves the position for the given config file.
    pub fn resolve_config(&mut self, config: &ConfigFile) {
        self.source = Some(config.source.clone());
        self.pos = Some(config.resolve_pos(self.index));
    }

    /// Returns a reference to the value.
    pub fn as_inner(&self) -> &T {
        &self.value
    }

    /// Converts the marked value into is unmarked value.
    pub fn into_inner(self) -> T {
        self.value
    }

    /// Marks some other value with this value’s position.
    pub fn mark<U>(&self, value: U) -> Marked<U> {
        Marked {
            value,
            index: self.index,
            source: self.source.clone(),
            pos: self.pos,
        }
    }

    /// Formats the mark for displaying.
    pub fn format_mark(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let source =
            self.source.as_ref().and_then(|source| source.path.as_ref());
        match (source, self.pos) {
            (Some(source), Some(pos)) => {
                write!(f, "{}:{}:{}", source.display(), pos.line, pos.col)
            }
            (Some(source), None) => write!(f, "{}", source.display()),
            (None, Some(pos)) => write!(f, "{}:{}", pos.line, pos.col),
            (None, None) => Ok(()),
        }
    }
}

//--- From

impl<T> From<T> for Marked<T> {
    fn from(src: T) -> Marked<T> {
        Marked {
            value: src,
            index: 0,
            source: None,
            pos: None,
        }
    }
}

impl<T> From<Spanned<T>> for Marked<T> {
    fn from(src: Spanned<T>) -> Marked<T> {
        Marked {
            index: src.span().start,
            value: src.into_inner(),
            source: None,
            pos: None,
        }
    }
}

//--- Deref, AsRef, Borrow

impl<T> ops::Deref for Marked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.as_inner()
    }
}

impl<T> AsRef<T> for Marked<T> {
    fn as_ref(&self) -> &T {
        self.as_inner()
    }
}

impl<T> borrow::Borrow<T> for Marked<T> {
    fn borrow(&self) -> &T {
        self.as_inner()
    }
}

//--- Display and Error

impl<T: fmt::Display> fmt::Display for Marked<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format_mark(f)?;
        write!(f, ": {}", self.value)
    }
}

impl<T: error::Error> error::Error for Marked<T> {}

//------------ ConfigFile ----------------------------------------------------

/// A config file.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Default))]
pub struct ConfigFile {
    /// The source for this file.
    source: Source,

    /// The data of this file.
    bytes: Vec<u8>,

    /// The start indexes of lines.
    ///
    /// The start index of the first line is in `line_start[0]` and so on.
    line_starts: Vec<usize>,
}

impl ConfigFile {
    /// Load a config file from disk.
    pub fn load(path: &impl AsRef<Path>) -> Result<Self, io::Error> {
        match fs::read(path) {
            Ok(bytes) => Self::new(bytes, path.into()),
            Err(e) => Err(e),
        }
    }

    pub fn new(bytes: Vec<u8>, source: Source) -> Result<Self, io::Error> {
        // LH: leaving this comment here to figure out at a later point where/how we can improve
        //     the TOML loading. Note that the vrib part does not make sense anymore as we've
        //     removed all the vrib stuff.
        //
        // Handle the special case of a rib unit that is actually a physical
        // rib unit and one or more virtual rib units. Rather than have the
        // user manually configure these separate rib units by hand in the
        // config file, we expand any units with unit `type = "rib"` and
        // `filter_name = [a, b, c, ...]` into multiple chained units each
        // with a single roto script path.
        //
        // Why don't we do this as part of the normal config deserialization
        // then unit/target/gate creation and linking? A single unit can't
        // currently during deserialization cause the creation of additional
        // units.
        //
        // One downside of the approach used here is it will cause line
        // numbers for config file syntax error reports to be confusing as we
        // are changing the users provided config file without them knowing.
        //
        // Another downside is that we have to lookup TOML fields by string
        // name and if the actual field names are later changed in the actual
        // unit and target config definitions those changes won't break
        // anything here at compile time, it will just cease to work as
        // expected at runtime. The "integration test" in main.rs exercises
        // this expansion capability to give at least some verification that
        // it is not obviously broken, but it's not enough.
        let config_str = String::from_utf8_lossy(&bytes);
        let toml: Value = if let Ok(toml) = toml::de::from_str(&config_str) {
            toml
        } else {
            return Err(io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot parse config file",
            ));
        };

        let config_str = toml::to_string(&toml).unwrap();

        Ok(ConfigFile {
            source,
            line_starts: config_str.as_bytes().split(|ch| *ch == b'\n').fold(
                vec![0],
                |mut starts, slice| {
                    // `+ 1` accounts for the '\n' byte that `split` consumed,
                    // so each entry is the real byte offset of the next line's
                    // start in `config_str` (the same byte space the TOML
                    // span offsets in `Marked::index` are measured in).
                    starts.push(starts.last().unwrap() + slice.len() + 1);
                    starts
                },
            ),
            bytes: config_str.as_bytes().to_vec(),
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.source.path.as_ref().map(|path| path.as_ref())
    }

    pub fn dir(&self) -> Option<&Path> {
        self.source.path.as_ref().and_then(|path| path.parent())
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_string(&self) -> borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }

    fn resolve_pos(&self, pos: usize) -> LineCol {
        // `line_starts[i]` is the byte offset of the start of line `i`
        // (0-based), seeded with `0`. The line containing `pos` is the last
        // one whose start is `<= pos`. Because `line_starts[0] == 0 <= pos`
        // always holds, `rposition` always matches at least index 0, so this
        // can neither underflow nor index out of bounds (the previous
        // implementation compared offset *values* against line indices and
        // panicked via `0usize - 1` for essentially every non-zero `pos`).
        let idx = self
            .line_starts
            .iter()
            .rposition(|&start| start <= pos)
            .unwrap_or(0);
        LineCol {
            line: idx + 1,
            col: pos - self.line_starts[idx] + 1,
        }
    }
}

//------------ ConfigError --------------------------------------------------

/// An error occurred during parsing of a configuration file.
#[derive(Clone, Debug)]
pub struct ConfigError {
    err: toml::de::Error,
    pos: Marked<()>,
}

impl ConfigError {
    pub fn new(err: toml::de::Error, file: &ConfigFile) -> Self {
        ConfigError {
            pos: Marked {
                value: (),
                index: 0,
                source: Some(file.source.clone()),
                pos: err.span().map(|span| file.resolve_pos(span.start)),
            },
            err,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.pos.format_mark(f)?;
        write!(f, ": {}", self.err)
    }
}

impl error::Error for ConfigError {}

//------------ ConfigPath ----------------------------------------------------

/// A path that encountered in a config file.
///
/// This is a basically a `PathBuf` that, when, deserialized resolves all
/// relative paths from a certain base path so that all relative paths
/// encountered in a config file are automatically resolved relative to the
/// location of the config file.
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
#[serde(from = "String")]
pub struct ConfigPath(PathBuf);

impl ConfigPath {
    thread_local!(
        static BASE_PATH: RefCell<Option<PathBuf>> = const { RefCell::new(None) }
    );

    fn set_base_path(path: PathBuf) {
        Self::BASE_PATH.with(|base_path| {
            base_path.replace(Some(path));
        })
    }

    fn clear_base_path() {
        Self::BASE_PATH.with(|base_path| {
            base_path.replace(None);
        })
    }
}

impl From<PathBuf> for ConfigPath {
    fn from(path: PathBuf) -> Self {
        Self(path)
    }
}

impl From<ConfigPath> for PathBuf {
    fn from(path: ConfigPath) -> Self {
        path.0
    }
}

impl From<String> for ConfigPath {
    fn from(path: String) -> Self {
        Self::BASE_PATH.with(|base_path| {
            ConfigPath(match base_path.borrow().as_ref() {
                Some(base_path) => base_path.join(path.as_str()),
                None => path.into(),
            })
        })
    }
}

impl ops::Deref for ConfigPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl AsRef<Path> for ConfigPath {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(toml: &str) -> ConfigFile {
        ConfigFile::new(toml.as_bytes().to_vec(), Source::default()).unwrap()
    }

    /// Independently compute the expected 1-based (line, col) for a byte
    /// offset into the (re-serialized) config bytes.
    fn expected(bytes: &[u8], pos: usize) -> (usize, usize) {
        let mut line = 1;
        let mut line_start = 0;
        for (i, b) in bytes.iter().enumerate().take(pos) {
            if *b == b'\n' {
                line += 1;
                line_start = i + 1;
            }
        }
        (line, pos - line_start + 1)
    }

    #[test]
    fn resolve_pos_never_panics_and_is_correct() {
        // The unresolved-link error path (Manager::prepare -> resolve_config
        // -> resolve_pos) used to panic via `0usize - 1` for any non-zero
        // offset, crashing at startup and on SIGHUP reload. Verify every
        // byte offset now resolves without panicking and matches an
        // independent line/col computation.
        let cf =
            mk("[units.a]\ntype = \"bmp-tcp-in\"\nlisten = \"1.2.3.4:5\"\n");
        let bytes = cf.bytes().to_vec();
        for pos in 0..=bytes.len() {
            let lc = cf.resolve_pos(pos);
            assert_eq!((lc.line, lc.col), expected(&bytes, pos), "pos {pos}");
        }
    }

    #[test]
    fn resolve_pos_start_of_second_line() {
        // A position at the start of the 2nd line reports line 2, col 1 —
        // and is not off by the number of preceding newlines.
        let cf = mk("a = 1\nb = 2\n");
        let bytes = cf.to_string().into_owned();
        let nl = bytes.find('\n').unwrap();
        let lc = cf.resolve_pos(nl + 1);
        assert_eq!((lc.line, lc.col), (2, 1));
    }
}
