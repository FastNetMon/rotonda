//! Process-wide memory accounting, for leak hunting.
//!
//! This module is a single place to read "where is the RAM going?" from. It
//! holds a handful of process-global counters for memory consumers that live
//! in detached tasks / separate units (and so aren't reachable from one
//! handle), plus a reader for the process RSS. The periodic reporter lives in
//! the RIB unit (it owns the store, the path-attribute interner and the
//! ingress register — the three biggest consumers) and pulls these globals in
//! to produce one consolidated log block every few minutes.
//!
//! Adding a new consumer: declare a `static AtomicUsize`, `fetch_add` where it
//! grows and `fetch_sub` where it shrinks (keep the two exactly mirrored), and
//! print it from `RibUnit`'s reporter.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Bytes currently held across every bmp-out client's dump buffer (the sum of
/// `Update::shallow_bytes()` for buffered live updates). Mirrors the per-client
/// `ClientState::buffered_bytes`; see `client_state.rs`.
pub static BMP_OUT_BUFFERED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Number of `Update`s currently buffered across every bmp-out client.
pub static BMP_OUT_BUFFERED_ENTRIES: AtomicUsize = AtomicUsize::new(0);

/// Number of connected bmp-out consumer clients (one per live `ClientState`).
pub static BMP_OUT_CLIENTS: AtomicUsize = AtomicUsize::new(0);

/// Resident set size of this process in bytes, read from `/proc/self/statm`.
///
/// Returns `None` if the proc file can't be read or parsed (non-Linux, etc.).
pub fn read_rss_bytes() -> Option<usize> {
    // statm fields are in pages: size, resident, shared, text, lib, data, dt.
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages: usize =
        statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(resident_pages.saturating_mul(page_size()))
}

/// System page size in bytes (`sysconf(_SC_PAGESIZE)`), falling back to 4096.
fn page_size() -> usize {
    // SAFETY: sysconf with a constant name has no preconditions and only reads
    // a process-global value.
    let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if sz > 0 {
        sz as usize
    } else {
        4096
    }
}

/// Format a byte count as a human-readable string (e.g. `8.30 GiB`).
pub fn fmt_bytes(n: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", UNITS[unit])
    }
}

/// Format a large count compactly (e.g. `305.0M`, `1.50M`, `45.0k`).
pub fn fmt_count(n: usize) -> String {
    let v = n as f64;
    if n >= 1_000_000_000 {
        format!("{:.2}G", v / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.2}M", v / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}k", v / 1e3)
    } else {
        n.to_string()
    }
}

/// Snapshot of the bmp-out global counters.
pub struct BmpOutSnapshot {
    pub clients: usize,
    pub buffered_bytes: usize,
    pub buffered_entries: usize,
}

pub fn bmp_out_snapshot() -> BmpOutSnapshot {
    BmpOutSnapshot {
        clients: BMP_OUT_CLIENTS.load(Ordering::Relaxed),
        buffered_bytes: BMP_OUT_BUFFERED_BYTES.load(Ordering::Relaxed),
        buffered_entries: BMP_OUT_BUFFERED_ENTRIES.load(Ordering::Relaxed),
    }
}
