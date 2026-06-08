use std::io::Write;
use std::{
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use axum::{
    body::Body,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use bytes::Bytes;
use inetnum::{addr::Prefix, asn::Asn};
use log::{debug, warn};
use routecore::{
    bgp::{
        communities::{LargeCommunity, StandardCommunity},
        path_attributes::PathAttributeType,
        types::AfiSafiType,
    },
    bmp::message::RibType,
};
use serde::Deserialize;
use serde_with::formats::CommaSeparator;
use serde_with::serde_as;
use serde_with::StringWithSeparator;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    http_ng::{Api, ApiError, ApiState},
    ingress::IngressId,
    representation::{GenOutput, Json, OutputFormat},
    roto_runtime::types::PeerRibType,
    units::rib_unit::rpki::RovStatus,
};

/// Add ingress register specific endpoints to a HTTP API
pub fn register_routes(router: &mut Api) {
    router.add_get(
        "/ribs/ipv4unicast/routes/{prefix}/{prefix_len}",
        search_ipv4unicast,
    );
    router.add_get("/ribs/ipv4unicast/routes", search_ipv4unicast_all);
    router.add_get(
        "/ribs/ipv6unicast/routes/{prefix}/{prefix_len}",
        search_ipv6unicast,
    );
    router.add_get("/ribs/ipv6unicast/routes", search_ipv6unicast_all);

    // The 'hardcoded' afisafis above take precedence over this 'catch-all' one.
    router.add_get("/ribs/{afisafi}/routes", generic_afisafi_all);

    // Possible shortcuts:
    //router.add_get("/origin_asn/{asn}", search_origin_asn_shortcut);
    //router.add_get("/ipv4unicast/origin_asn/{asn}", search_origin_asn);
    // or, should we do this per afisafi, a la:
    // Because with a /origin_asn (without afisafi), we have to decide and hardcode for which
    // address families we'll do the lookups.
    // Perhaps, if we offer both, the /origin_asn can default to unicast stuff?
    //
    // Or, should all of this go as a URL query parameter?
    // so we get /ipv4unicast/0/0?origin=211321
}

#[derive(Debug, Deserialize)]
enum SupportedAfiSafi {
    #[serde(rename = "ipv4unicast")]
    Ipv4Unicast,
    #[serde(rename = "ipv6unicast")]
    Ipv6Unicast,
}

#[serde_as]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct QueryFilter {
    #[serde(default)]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, Include>")]
    pub include: Vec<Include>,

    pub ingress_id: Option<IngressId>,

    #[serde(rename = "filter[originAsn]")]
    pub origin_asn: Option<Asn>,

    #[serde(rename = "filter[otc]")]
    pub otc: Option<Asn>,

    #[serde(rename = "filter[community]")]
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    pub community: Option<StandardCommunity>,

    #[serde(rename = "filter[largeCommunity]")]
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    pub large_community: Option<LargeCommunity>,

    #[serde(rename = "filter[ribType]")]
    pub rib_type: Option<PeerRibType>,

    #[serde(rename = "filter[rovStatus]")]
    pub rov_status: Option<RovStatus>,

    #[serde(rename = "filter[peerAsn]")]
    pub peer_asn: Option<Asn>,

    #[serde(rename = "filter[peerAddress]")]
    pub peer_addr: Option<IpAddr>,

    // TODO: RouteDistinguisher,

    // content parameter (defaulting to 'all') to request only the nlri without path attributes, or
    // perhaps only specific path attributes?
    // rfc8040 (RESTCONF) describes content=all|config|nonconfig , but we could divert from that?
    //
    // json:api describes 'fields[]', e.g.:
    // ?include=author&fields[articles]=title,body&fields[people]=name
    //
    // We could go for e.g. fields[pathAttributes]=asPath,otc
    //
    // Then to alter representation, i.e. offer 'plain' communities and the exploded human readable
    // representation from the old API, .. what do we do/
    //
    // fields[communities]=humanReadable?
    // or do we use content for that? downside of 'content' is that it seems to be less
    // fine-grained, while fields[$foo] allows defining things on the $foo level

    //#[serde_as(as = "StringWithSeparator::<CommaSeparator, PathAttributeType>")]
    // TODO instead of u8, base this on strings
    // for that, add impl FromStr for PathAttributeType in routecore
    #[serde_as(as = "Option<StringWithSeparator::<CommaSeparator, u8>>")]
    #[serde(rename = "fields[pathAttributes]")]
    pub fields_path_attributes: Option<Vec<u8>>,

    #[serde(rename = "function[roto]")]
    pub roto_function: Option<String>,

    #[serde(default)]
    pub format: OutputFormat,
}

impl QueryFilter {
    pub fn enable_more_specifics(&mut self) {
        if !self.include.contains(&Include::MoreSpecifics) {
            self.include.push(Include::MoreSpecifics);
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Include {
    MoreSpecifics,
    LessSpecifics,
}

const STREAM_CHUNK_SIZE: usize = 256 * 1024;

/// How long a streaming response may block on a single channel send — i.e. a
/// client that has stopped reading, leaving the bounded response channel full
/// — before the dump is aborted. Without this bound a connected-but-stalled
/// client pins the blocking dump thread (and, for full-table dumps, its
/// [`super::rib::DumpGuard`] slot) indefinitely.
const STREAM_WRITE_STALL: std::time::Duration =
    std::time::Duration::from_secs(60);

struct StreamResponseWriter {
    sender: mpsc::Sender<Result<Bytes, io::Error>>,
    buffer: Vec<u8>,
    handle: tokio::runtime::Handle,
}

impl StreamResponseWriter {
    fn new(
        sender: mpsc::Sender<Result<Bytes, io::Error>>,
        handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(STREAM_CHUNK_SIZE),
            handle,
        }
    }

    fn send_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::copy_from_slice(&self.buffer);
        self.buffer.clear();
        // Bounded send (runs on a spawn_blocking thread, so block_on is legal):
        // abort the dump if the client stops draining for STREAM_WRITE_STALL
        // (channel stays full). A closed channel — client disconnected — still
        // maps to BrokenPipe exactly as the previous blocking_send did.
        self.handle
            .block_on(
                self.sender.send_timeout(Ok(chunk), STREAM_WRITE_STALL),
            )
            .map_err(|e| match e {
                mpsc::error::SendTimeoutError::Timeout(_) => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "client stalled draining response",
                ),
                mpsc::error::SendTimeoutError::Closed(_) => io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "receiver dropped",
                ),
            })
    }
}

impl io::Write for StreamResponseWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        if self.buffer.len() >= STREAM_CHUNK_SIZE {
            self.send_buffer()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffer()
    }
}

fn stream_search_result(
    search_result: super::rib::SearchResult,
) -> axum::response::Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, io::Error>>(64);
    let stream = ReceiverStream::new(rx);

    let format = search_result.query_filter().format;
    let handle = tokio::runtime::Handle::current();

    tokio::task::spawn_blocking(move || {
        let mut writer = StreamResponseWriter::new(tx, handle);
        match format {
            OutputFormat::Json => {
                let _ = search_result.write(&mut Json(&mut writer));
            }
            OutputFormat::Jsonl => {
                let _ = search_result.write_jsonl(&mut writer);
            }
        }
        let _ = writer.flush();
    });

    (
        [("content-type", format.content_type())],
        Body::from_stream(stream),
    )
        .into_response()
}

fn stream_all_routes(
    rib: std::sync::Arc<super::rib::Rib>,
    afisafi: AfiSafiType,
    query_prefix: Prefix,
    filter: QueryFilter,
) -> Result<axum::response::Response, ApiError> {
    rib.check_filter_and_store(afisafi, &filter)
        .map_err(ApiError::BadRequest)?;

    // This endpoint is unauthenticated and a full-table jsonl dump is heavy
    // (one blocking thread + a table-sized key buffer). Cap the number of
    // concurrent dumps across all output paths; refuse with 503 rather than
    // piling on another when the cap is reached. The permit is released when
    // the spawn_blocking closure below ends.
    let permit = super::rib::DumpGuard::try_enter().ok_or_else(|| {
        warn!(
            "rib dump refused: {} concurrent dumps already in flight \
             (cap reached)",
            super::rib::DumpGuard::active()
        );
        ApiError::ServiceUnavailable(
            "too many concurrent RIB dumps in progress; retry shortly"
                .to_string(),
        )
    })?;

    let (tx, rx) = mpsc::channel::<Result<Bytes, io::Error>>(64);
    let stream = ReceiverStream::new(rx);
    let handle = tokio::runtime::Handle::current();

    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut writer = StreamResponseWriter::new(tx, handle);
        let _ = rib.write_jsonl_stream(
            afisafi,
            query_prefix,
            filter,
            &mut writer,
        );
        let _ = writer.flush();
    });

    Ok((
        [("content-type", OutputFormat::Jsonl.content_type())],
        Body::from_stream(stream),
    )
        .into_response())
}

#[derive(Debug)]
pub struct UnknownInclude;
impl Display for UnknownInclude {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown include")
    }
}
impl std::str::FromStr for Include {
    type Err = UnknownInclude;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "moreSpecifics" => Ok(Include::MoreSpecifics),
            "lessSpecifics" => Ok(Include::LessSpecifics),
            _ => Err(UnknownInclude),
        }
    }
}

async fn generic_afisafi_all(
    Path(afisafi): Path<SupportedAfiSafi>,
    filter: Query<QueryFilter>,
    _state: State<ApiState>,
) -> Result<Vec<u8>, ApiError> {
    dbg!(afisafi, filter);
    warn!("searching routes other than unicast not yet implemented");
    Err(ApiError::InternalServerError("TODO".into()))
}

async fn search_ipv4unicast(
    Path((prefix, prefix_len)): Path<(Ipv4Addr, u8)>,
    Query(filter): Query<QueryFilter>,
    state: State<ApiState>,
) -> Result<impl IntoResponse, ApiError> {
    let prefix = Prefix::new_v4(prefix, prefix_len)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let s = state.store.load();
    let rib = match *s {
        Some(ref store) => store.clone(),
        None => {
            return Err(ApiError::InternalServerError(
                "store unavailable".into(),
            ))
        }
    };

    // A /0 + moreSpecifics request dumps every prefix in the RIB. Only the
    // jsonl path streams it through a byte-bounded buffer; the non-streaming
    // (default JSON) path collects the entire RIB into one in-memory
    // RecordSet before serializing, which spikes RSS / OOMs the process on a
    // production-sized table. Require the streaming format for full-RIB dumps
    // rather than risk a crash on the most obvious "show all routes" GET.
    if prefix.len() == 0 && filter.include.contains(&Include::MoreSpecifics) {
        if filter.format != OutputFormat::Jsonl {
            return Err(ApiError::BadRequest(
                "full-RIB dump (/0 with moreSpecifics) requires format=jsonl \
                 so it can be streamed within bounded memory"
                    .into(),
            ));
        }
        return Ok(stream_all_routes(
            rib,
            AfiSafiType::Ipv4Unicast,
            prefix,
            filter,
        )?);
    }

    // Run the synchronous query (store match_prefix + apply_filter, which
    // takes the roto_context lock when a roto filter is supplied) on the
    // blocking pool rather than inline on a tokio worker, so a CPU-bound or
    // roto-filtered query cannot stall the async runtime. Mirrors the jsonl
    // streaming path, which already uses spawn_blocking.
    let search_result = tokio::task::spawn_blocking(move || {
        rib.search_routes(AfiSafiType::Ipv4Unicast, prefix, filter)
    })
    .await
    .map_err(|e| {
        ApiError::InternalServerError(format!("search task failed: {e}"))
    })?
    .map_err(ApiError::BadRequest)?;

    Ok(stream_search_result(search_result))
}

// Search all routes, we mimic a 0.0.0.0/0 search, but most (or all) results will actually be
// more-specifics. These go into the "included" part of the response.
async fn search_ipv4unicast_all(
    mut filter: Query<QueryFilter>,
    state: State<ApiState>,
) -> Result<impl IntoResponse, ApiError> {
    filter.enable_more_specifics();
    search_ipv4unicast(Path((0.into(), 0)), filter, state).await
}

async fn search_ipv6unicast(
    Path((prefix, prefix_len)): Path<(Ipv6Addr, u8)>,
    Query(filter): Query<QueryFilter>,
    state: State<ApiState>,
) -> Result<impl IntoResponse, ApiError> {
    let prefix = Prefix::new_v6(prefix, prefix_len)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let s = state.store.load();
    let rib = match *s {
        Some(ref store) => store.clone(),
        None => {
            return Err(ApiError::InternalServerError(
                "store unavailable".into(),
            ))
        }
    };

    // See the IPv4 handler: full-RIB dumps must stream as jsonl, otherwise the
    // non-streaming path materializes the entire RIB in memory and can OOM.
    if prefix.len() == 0 && filter.include.contains(&Include::MoreSpecifics) {
        if filter.format != OutputFormat::Jsonl {
            return Err(ApiError::BadRequest(
                "full-RIB dump (/0 with moreSpecifics) requires format=jsonl \
                 so it can be streamed within bounded memory"
                    .into(),
            ));
        }
        return Ok(stream_all_routes(
            rib,
            AfiSafiType::Ipv6Unicast,
            prefix,
            filter,
        )?);
    }

    // See the IPv4 handler: run the synchronous query off the async worker.
    let search_result = tokio::task::spawn_blocking(move || {
        rib.search_routes(AfiSafiType::Ipv6Unicast, prefix, filter)
    })
    .await
    .map_err(|e| {
        ApiError::InternalServerError(format!("search task failed: {e}"))
    })?
    .map_err(ApiError::BadRequest)?;

    Ok(stream_search_result(search_result))
}

// Search all routes, we mimic a ::/0 search, but most (or all) results will actually be
// more-specifics. These go into the "included" part of the response.
async fn search_ipv6unicast_all(
    mut filter: Query<QueryFilter>,
    state: State<ApiState>,
) -> Result<impl IntoResponse, ApiError> {
    filter.enable_more_specifics();
    search_ipv6unicast(Path((0.into(), 0)), filter, state).await
}
