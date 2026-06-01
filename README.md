# Rotonda

<img align="right" src="doc/manual/source/resources/rotonda-illustrative-icon.png" height="150">

The composable, programmable BGP Engine

This repository is a FastNetMon Ltd maintained fork of NLnet Labs Rotonda. It
is not an official NLnet Labs release. The original upstream project is
available at <https://github.com/NLnetLabs/rotonda/>. See [NOTICE.md](NOTICE.md)
for fork attribution and licensing notes.

The current version of Rotonda allows you to open BGP and BMP sessions and
collect incoming routes from many peers into a in-memory database, modeled as
a Routing Information Base (RIB). It also supports importing routes from MRT
files into this database. Conditions for accepting incoming routes and sending
messages to log files or a MQTT stream can be created using filters with the
`Roto` programming language. The RIB can be queried through an HTTP/JSON
API.

Future versions of Rotonda will support an on-disk database, using external
datasets in filters, reading routes from Kafka streams, and more.

Read the fork documentation and release notes in this repository to install and
use this FastNetMon-maintained build of Rotonda.

> `Rotonda` is under active development and features are added regularly.
> The APIs, the configuration and the `Roto` syntax may change between
> 0.x versions.
>
> For more information on upstream NLnet Labs Rotonda, see
> <https://github.com/NLnetLabs/rotonda/>.

For issues with this fork, use the FastNetMon repository and support channels.
Upstream NLnet Labs community resources may not apply to this fork.

## GOALS

#### Modularity
   Rotonda applications are built by combining units into a pipeline through
   which BGP data will flow. You can filter, and store the BGP data along
   the way, and create signals based on it to send to other applications. We
   aim for units to be hot-swappable, i.e. they can be added and removed in a
   *running* Rotonda application.

   Rotonda offers units to create BGP and BMP sessions, Routing Information
   Bases (RIBs), and more.

#### Flexibility
   The behaviour of the units can be modeled by using a small, fun programming
   language called `Roto`, that we created to combine flexibility and
   ease-of-use. Right now, `Roto` is used define filters that run in the hot
   path of the Rotonda pipeline. It's our goal to integrate filter definition,
   configuration syntax, and query syntax into `Roto` scripts in one place.
   Modifying, versioning and provisioning of your `Roto` scripts should be
   as straight forward as possible.

#### Tailored Performance
   Rotonda aims to offer units that perform the same task, but with different
   performance characteristics, so that you can optimize for your needs, be it
   a high-volume, low latency installation or a small installation in a
   constraint environment.

#### Observability
   All Rotonda units will have their own finely-grained logging capabilities,
   and some have built-in queryable JSON API interfaces to give information
   about their current state and content through Rotonda’s built-in HTTPS
   server. Signals can be sent to other applications. Moreover, Rotonda aims
   to offer true observability by allowing the user to trace BMP/BGP packets
   start-to-end through the whole pipeline.

##### Storage Persistence
   By default a Rotonda application stores all the data that you want to
   collect in memory. It should be possible to configure parts to persist
   to another storage location, such as files or a database. Whether you put
   RIBs to files or in a database, you can should still be able to query it
   transparently with `Roto`.

#### External Data Sources
   `Roto` filter units should be able to make decisions based on real-time
   external data sources. Similarly filter units should be ahlt to make
   decisions based on data present in multiple RIBs. External data sources
   can be, among others, files, databases or even a RIB backed by an RTR
   connection.

#### Robustness & Scalability
   Multiple Rotonda instances should be able to synchronize or shard data via
   a binary protocol, that we dubbed `rotoro`.

#### Security & Safety
   Rotonda applications will be able to use data provided by the RPKI through
   connections with tools like Routinator and Krill. Besides that, Rotonda
   supports BGPsec out of the box. Again, no patching or recompiling required.

#### Open Source License

Rotonda is licensed under the [Mozilla Public License 2.0](LICENSE). This fork
preserves upstream NLnet Labs attribution and adds FastNetMon Ltd attribution
for fork-specific modifications.

## Memory allocator (jemalloc) tuning

This build uses jemalloc (`tikv-jemallocator`) as the global allocator instead
of the system allocator, because glibc malloc retains freed pages on its free
lists under the fragmented, small-allocation pattern the RIB store produces, so
RSS plateaus at the high-water mark after a large bmp-out dump instead of
falling back. jemalloc is tuned at runtime through the `_RJEM_MALLOC_CONF`
environment variable (note the `_RJEM_` prefix — the plain `MALLOC_CONF`
variable is silently ignored by this build).

### Make RSS actually return after a dump

```
_RJEM_MALLOC_CONF="background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000"
```

- `background_thread:true` — a background thread purges decayed pages even when
  an arena goes idle (critical: after a dump, if the feed quiets, idle arenas
  still get reclaimed). This is enabled because the build includes the
  `background_threads_runtime_support` feature.
- decay 5s — freed pages go back to the OS (via `MADV_DONTNEED`, which does drop
  RSS) within ~5s. Drop to `muzzy_decay_ms:0` for immediate return if you want
  it aggressive.
- Optional: `narenas:8` — jemalloc defaults to a high arena count (96 on a
  typical box here); fewer arenas means less per-arena retained slack and a
  lower baseline footprint, at a small concurrency cost. Worth trying.

### Leak hunting (heap profiling)

Profiling is compiled into this build, so it can be enabled at runtime:

```
_RJEM_MALLOC_CONF="prof:true,prof_active:true,lg_prof_sample:19,lg_prof_interval:31,prof_prefix:/tmp/jeprof"
```

- Samples roughly every 512 KiB (low overhead) and auto-dumps a heap profile
  every 2 GiB allocated to `/tmp/jeprof.*.heap`.
- Analyze with:
  ```
  jeprof --show_bytes --text ./target/release/rotonda /tmp/jeprof.*.heap
  ```
  `jeprof` ships with `libjemalloc-dev`. The release profile is built with
  `debug = 1`, so call sites are symbolized — the profile shows exactly which
  call sites hold the bytes.
