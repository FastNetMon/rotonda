use std::collections::VecDeque;
use std::future::{Future, IntoFuture};
use std::io::Read;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use bzip2::bufread::BzDecoder;
use flate2::read::GzDecoder;
use futures::future::{select, Either};
use futures::{pin_mut, FutureExt, TryFutureExt};
use log::{debug, error, info, warn};
use rotonda_store::prefix_record::RouteStatus;
use routecore::bgp::fsm::state_machine::State;
use routecore::bgp::message::{Message as BgpMsg, PduParseInfo};
use routecore::bgp::nlri::afisafi::{Ipv4UnicastNlri, Nlri};
use routecore::bgp::types::AfiSafiType;
use routecore::bgp::workshop::route::RouteWorkshop;
use routecore::bgp::ParseError;
use routecore::mrt::MrtFile;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use tokio::pin;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

use crate::common::unit::UnitActivity;
use crate::comms::{GateStatus, Terminated};
use crate::config::ConfigPath;
use crate::ingress::{self, IngressId, IngressInfo, IngressType};
use crate::manager::{Component, WaitPoint};
use crate::payload::{Payload, RotondaPaMap, RotondaRoute, Update};
use crate::roto_runtime::types::{
    explode_announcements, explode_withdrawals,
};
use crate::units::{Gate, Unit};

#[derive(Clone, Debug, Deserialize)]
pub struct MrtFileIn {
    pub filename: OneOrManyPaths,
    pub update_path: Option<ConfigPath>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum OneOrManyPaths {
    One(ConfigPath),
    Many(Vec<ConfigPath>),
}
pub enum PathsIterator<'a> {
    One(Option<PathBuf>),
    Many(std::slice::Iter<'a, ConfigPath>),
}
impl Iterator for PathsIterator<'_> {
    type Item = PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            PathsIterator::One(ref mut p) => p.take(),
            PathsIterator::Many(ref mut iter) => {
                iter.next().cloned().map(Into::into)
            }
        }
    }
}
impl OneOrManyPaths {
    pub fn iter(&self) -> PathsIterator<'_> {
        match self {
            OneOrManyPaths::One(p) => {
                PathsIterator::One(Some(p.clone().into()))
            }
            OneOrManyPaths::Many(m) => PathsIterator::Many(m.iter()),
        }
    }
}

#[allow(dead_code)]
pub struct MrtInRunner {
    config: MrtFileIn,
    gate: Gate,
    ingresses: Arc<ingress::Register>,
    parent_id: IngressId,
    queue_tx: mpsc::Sender<QueueEntry>,
    processing: Option<PathBuf>,
    processed: Vec<(PathBuf, String)>,
}

pub type QueueEntry = (
    // the file to be queued
    PathBuf,
    // optional response to the enqueuer
    Option<oneshot::Sender<Result<String, String>>>,
);

impl MrtFileIn {
    pub async fn run(
        self,
        component: Component,
        gate: Gate,
        mut waitpoint: WaitPoint,
    ) -> Result<(), crate::comms::Terminated> {
        gate.process_until(waitpoint.ready()).await?;
        waitpoint.running().await;

        let (queue_tx, queue_rx) = mpsc::channel::<QueueEntry>(1024);

        let ingresses = component.ingresses().clone();
        let parent_id = ingresses.register();
        let _ = ingresses.update_info(
            parent_id,
            IngressInfo::new()
                .with_unit_name(component.name().as_ref())
                .with_desc("mrt-file-in unit"),
        );

        for f in self.filename.iter() {
            let _ = queue_tx.send((f, None)).await;
        }

        MrtInRunner::new(self, gate, ingresses, parent_id, queue_tx)
            .run(queue_rx)
            .await
    }
}

impl MrtInRunner {
    fn new(
        mrtin: MrtFileIn,
        gate: Gate,
        ingresses: Arc<ingress::Register>,
        parent_id: IngressId,
        queue_tx: mpsc::Sender<QueueEntry>,
    ) -> Self {
        Self {
            gate,
            config: mrtin,
            ingresses,
            parent_id,
            queue_tx,
            processing: None,
            processed: vec![],
        }
    }

    async fn process_state_change(
        gate: &Gate,
        ingresses: &Arc<ingress::Register>,
        sc: routecore::mrt::StateChangeAs4,
    ) {
        match (sc.old_state(), sc.new_state()) {
            (x, y) if x == y => {
                warn!("State Change to same state {}, ignoring", x)
            }
            (State::Established, State::Idle) => {
                if let Some((ingress_id, _info)) = ingresses
                    .find_existing_peer(
                        &IngressInfo::new()
                            .with_remote_addr(sc.peer_addr())
                            .with_remote_asn(sc.peer_asn()),
                    )
                {
                    let update = Update::Withdraw(ingress_id, None);
                    gate.update_data(update).await;
                    debug!("Withdraw for {ingress_id} sent");
                } else {
                    debug!(
                        "No IngressInfo for {} {} going Established -> Idle",
                        sc.peer_asn(),
                        sc.peer_addr()
                    );
                }
            }
            // XXX signal a (re)appearing peer using an Update::IngressReappeared(..) ?
            (_, _) => {
                debug!(
                    "State Change: {} -> {} in MRT, not doing anything",
                    sc.old_state(),
                    sc.new_state()
                )
            }
        }
    }

    async fn process_message(
        gate: &Gate,
        ingresses: &Arc<ingress::Register>,
        parent_id: IngressId,
        msg: routecore::mrt::MessageAs4<'_, &[u8]>,
    ) -> Result<(usize, usize), MrtError> {
        let bgp_msg = match msg.bgp_msg() {
            Ok(msg) => msg,
            Err(e) => {
                error!("{e}");
                return Ok((0, 0));
            }
        };
        let mut announcements_sent = 0;
        let mut withdrawals_sent = 0;

        match bgp_msg {
            BgpMsg::Update(upd) => {
                let received = std::time::Instant::now();
                let mut payloads = SmallVec::new();
                let rr_reach = explode_announcements(&upd)?;
                let rr_unreach = explode_withdrawals(&upd)?;

                announcements_sent += rr_reach.len();
                withdrawals_sent += rr_unreach.len();

                let ingress_query = IngressInfo::new()
                    .with_parent_ingress(parent_id)
                    .with_remote_addr(msg.peer_addr())
                    .with_remote_asn(msg.peer_asn())
                    .with_ingress_type(IngressType::Mrt);

                let ingress_id = if let Some((id, _info)) =
                    ingresses.find_existing_peer(&ingress_query)
                {
                    id
                } else {
                    let new_id = ingresses.register();
                    ingresses.update_info(new_id, ingress_query);
                    warn!("no ingress info found, regged {new_id}");
                    new_id
                };

                payloads.extend(rr_reach.into_iter().map(|rr| {
                    Payload::with_received(
                        rr,
                        None,
                        received,
                        ingress_id,
                        RouteStatus::Active,
                    )
                }));

                payloads.extend(rr_unreach.into_iter().map(|rr| {
                    Payload::with_received(
                        rr,
                        None,
                        received,
                        ingress_id,
                        RouteStatus::Withdrawn,
                    )
                }));
                let update = payloads.into();
                gate.update_data(update).await;
            }
            BgpMsg::Open(_open_message) => {
                warn!("BGP OPEN in MRT, skipping");
            }
            BgpMsg::Notification(_notification_message) => {
                debug!("BGP NOTIFICATION in MRT, skipping");
            }
            BgpMsg::Keepalive(_keepalive_message) => {
                debug!("BGP KEEPALIVE in MRT, skipping");
            }
            BgpMsg::RouteRefresh(_route_refresh_message) => {
                debug!("BGP ROUTEREFRESH in MRT, skipping");
            }
        }
        Ok((announcements_sent, withdrawals_sent))
    }

    async fn process_file(
        gate: Gate,
        ingresses: Arc<ingress::Register>,
        parent_id: IngressId,
        filename: PathBuf,
    ) -> Result<(), MrtError> {
        info!(
            "processing {} on thread {:?}",
            filename.to_string_lossy(),
            std::thread::current().id()
        );
        #[allow(unused_variables)] // false positive, used in info!() below)
        let t0 = Instant::now();

        let file = std::fs::File::open(&filename)?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        let mut buf = Vec::<u8>::new();

        let t0 = Instant::now();
        let mrt_file = match filename
            .as_path()
            .extension()
            .and_then(std::ffi::OsStr::to_str)
        {
            Some("gz") => {
                let mut gz = GzDecoder::new(&mmap[..]);
                gz.read_to_end(&mut buf)
                    .map_err(|_e| MrtError::other("gz decoding failed"))?;
                info!(
                    "decompressed {} in {}ms",
                    &filename.to_string_lossy(),
                    t0.elapsed().as_millis()
                );
                MrtFile::new(&buf[..])
            }
            Some("bz2") => {
                let mut bz2 = BzDecoder::new(&mmap[..]);
                bz2.read_to_end(&mut buf).map_err(|e| {
                    error!("bz2 error: {e}");
                    MrtError::other("bz2 decoding failed")
                })?;
                info!(
                    "decompressed {} in {}ms",
                    &filename.to_string_lossy(),
                    t0.elapsed().as_millis()
                );
                MrtFile::new(&buf[..])
            }
            _ => MrtFile::new(&mmap[..]),
        };

        let mut routes_sent = 0;

        // --- Dump part (RIB entries)
        //
        if let Ok(peer_index_table) = mrt_file.pi() {
            debug!(
                "found peer index table of len {} in {}",
                peer_index_table.len(),
                filename.to_string_lossy()
            );
            let mut ingress_map = Vec::with_capacity(peer_index_table.len());
            for peer_entry in &peer_index_table[..] {
                let id = ingresses.register();
                ingresses.update_info(
                    id,
                    IngressInfo::new()
                        .with_parent_ingress(parent_id)
                        .with_remote_addr(peer_entry.addr)
                        .with_remote_asn(peer_entry.asn)
                        .with_filename(filename.clone())
                        .with_ingress_type(IngressType::Mrt),
                );
                ingress_map.push(id);
            }

            let rib_entries = mrt_file.rib_entries()?;
            for (afisafi, peer_id, _peer_entry, prefix, raw_attr) in
                rib_entries
            {
                let rr = match afisafi {
                    AfiSafiType::Ipv4Unicast => {
                        RotondaRoute::Ipv4Unicast(
                            prefix.try_into().map_err(MrtError::other)?,
                            RotondaPaMap::new(routecore::bgp::path_attributes::OwnedPathAttributes::new(PduParseInfo::modern(), raw_attr))
                        )
                    }
                    AfiSafiType::Ipv6Unicast => {
                        let raw_attr = normalize_mrt_mp_reach(raw_attr, 2, 1, &prefix);
                        RotondaRoute::Ipv6Unicast(
                            prefix.try_into().map_err(MrtError::other)?,
                            RotondaPaMap::new(routecore::bgp::path_attributes::OwnedPathAttributes::new(PduParseInfo::modern(), raw_attr))
                        )
                    }
                    AfiSafiType::Ipv4Multicast |
                    AfiSafiType::Ipv4MplsUnicast |
                    AfiSafiType::Ipv4MplsVpnUnicast |
                    AfiSafiType::Ipv4RouteTarget |
                    AfiSafiType::Ipv4FlowSpec |
                    AfiSafiType::Ipv6Multicast |
                    AfiSafiType::Ipv6MplsUnicast |
                    AfiSafiType::Ipv6MplsVpnUnicast |
                    AfiSafiType::Ipv6FlowSpec |
                    AfiSafiType::L2VpnVpls |
                    AfiSafiType::L2VpnEvpn |
                    AfiSafiType::Unsupported(_, _) => {
                        debug!("unsupported AFI/SAFI {}, skipping", afisafi);
                        continue
                    }
                };
                let ingress_id = ingress_map[usize::from(peer_id)];
                let update = Update::Single(Payload::new(
                    rr,
                    None,
                    ingress_id,
                    RouteStatus::Active,
                ));

                gate.update_data(update).await;

                // Allow other async tasks to have a go by introducing an
                // `await` every N entries:
                if routes_sent % 100_000 == 0 {
                    tokio::time::sleep(std::time::Duration::from_micros(1))
                        .await;
                }
                routes_sent += 1;
            }
        }

        // --- Messages part (update file)

        use routecore::mrt::Bgp4Mp;

        let mut announcements_sent = 0;
        let mut withdrawals_sent = 0;

        let mut messages_processed = 0;
        for msg in mrt_file.messages() {
            match msg {
                Bgp4Mp::StateChange(sc) => {
                    MrtInRunner::process_state_change(
                        &gate,
                        &ingresses,
                        sc.into(),
                    )
                    .await;
                }
                Bgp4Mp::StateChangeAs4(sc) => {
                    MrtInRunner::process_state_change(&gate, &ingresses, sc)
                        .await;
                }
                Bgp4Mp::Message(msg) => {
                    let (reach, unreach) = MrtInRunner::process_message(
                        &gate,
                        &ingresses,
                        parent_id,
                        msg.into(),
                    )
                    .await?;
                    announcements_sent += reach;
                    withdrawals_sent += unreach;
                }
                Bgp4Mp::MessageAs4(msg) => {
                    let (reach, unreach) = MrtInRunner::process_message(
                        &gate, &ingresses, parent_id, msg,
                    )
                    .await?;
                    announcements_sent += reach;
                    withdrawals_sent += unreach;
                    messages_processed += 1;
                }
            }

            // Allow other async tasks to have a go by introducing an
            // `await` every N entries:
            if messages_processed % 100_000 == 0 {
                tokio::time::sleep(std::time::Duration::from_micros(1)).await;
            }
        }

        info!(
            "mrt-in: done processing {}, emitted {} routes, {} announcements, {} withdrawals in {}s",
            filename.to_string_lossy(),
            routes_sent,
            announcements_sent,
            withdrawals_sent,
            t0.elapsed().as_secs()
        );

        Ok(())
    }

    async fn run(
        mut self,
        mut queue: mpsc::Receiver<QueueEntry>,
    ) -> Result<(), Terminated> {
        let gate = self.gate.clone();
        let ingresses = self.ingresses.clone();
        let (results_tx, mut results_rx) = mpsc::unbounded_channel();
        //let (handles_tx, mut handles_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            while let Some((p, enqueuer_tx)) = queue.recv().await {
                let gate = gate.clone();
                let ingresses = ingresses.clone();
                let results_tx = results_tx.clone();
                // concurrent:
                /*
                let handle = tokio::spawn(async move {
                    let r = Self::process_file(
                        gate,
                        ingresses,
                        p.clone()
                    ).await.map(|_| p);
                    results_tx.send(r)
                });
                let _ = handles_tx.send(handle);
                */

                // sequential:

                let r = Self::process_file(
                    gate,
                    ingresses,
                    self.parent_id,
                    p.clone(),
                )
                .await
                .map(|_| p)
                .inspect_err(|e| error!("process_file failed: {e}"));
                if let Err(e) = results_tx.send(r) {
                    error!("failed to send result of file {e}")
                }
                if let Some(tx) = enqueuer_tx {
                    let _ = tx.send(Ok("OK!".into()));
                }
            }
        });

        loop {
            let f = results_rx.recv().map(Ok);
            match self.process_until(f).await {
                ControlFlow::Continue(Ok(r)) => {
                    if let Some(Ok(p)) = r {
                        let filename = p.to_string_lossy();
                        let mut hasher = Sha256::new();
                        let mut file = std::fs::File::open(&p).unwrap();

                        let _bytes_written =
                            std::io::copy(&mut file, &mut hasher).unwrap();
                        let hash_bytes = hasher.finalize();
                        let hash_str = format!("{:x}", hash_bytes);
                        info!(
                            "processed {}, sha256: {}",
                            filename, &hash_str
                        );
                        self.processed.push((p, hash_str));
                    }
                }
                ControlFlow::Continue(Err(e)) => {
                    eprintln!("error: {e}");
                }
                ControlFlow::Break(_) => {
                    info!("terminating unit, processed {:?}", self.processed);
                    /* commented out while doing the sequential approach vs
                     * concurrent
                    while let Ok(Some(h)) = tokio::time::timeout(std::time::Duration::from_millis(100), handles_rx.recv()).await {
                        info!("aborting spawned task");
                        h.abort();
                    }
                    */
                    info!("timed out");
                    return Err(Terminated);
                }
            }
        }
    }

    async fn process_until<T, U>(
        &self,
        until_fut: T,
    ) -> ControlFlow<Terminated, std::io::Result<U>>
    where
        T: Future<Output = std::io::Result<U>>,
    {
        let mut until_fut = Box::pin(until_fut);

        loop {
            let process_fut = self.gate.process();
            pin_mut!(process_fut);

            let res = select(process_fut, until_fut).await;

            match res {
                Either::Left((Ok(gate_status), next_fut)) => {
                    match gate_status {
                        GateStatus::Active | GateStatus::Dormant => {}
                        GateStatus::Reconfiguring {
                            new_config:
                                Unit::MrtFileIn(MrtFileIn {
                                    filename: _new_filename,
                                    ..
                                }),
                        } => {
                            /*
                            if new_filename != self.config.filename {
                                info!("Reloading mrt-in, processing new file {}", &new_filename.to_string_lossy());
                                if let Err(e) = self
                                    .queue_tx
                                    .send(new_filename.clone())
                                    .await
                                {
                                    error!(
                                        "Failed to process {}: {}",
                                        new_filename.to_string_lossy(),
                                        e
                                    );
                                }
                                //self.config.file
                            }
                            */
                        }
                        GateStatus::Reconfiguring { .. } => {
                            // reconfiguring for other unit types, ignore
                        }
                        GateStatus::ReportLinks { report } => {
                            report.declare_source();
                            //report.set_graph_status(self.metrics.clone());
                        }
                        GateStatus::Triggered { .. } => {
                            warn!("got unexpected Triggered for this unit");
                        }
                    }
                    until_fut = next_fut;
                }
                Either::Left((Err(Terminated), _next_fut)) => {
                    debug!("self.process_until Left Terminated");
                    return ControlFlow::Break(Terminated);
                }
                Either::Right((Ok(until_res), _next_fut)) => {
                    return ControlFlow::Continue(Ok(until_res))
                }
                Either::Right((Err(err), _next_fut)) => {
                    return ControlFlow::Continue(Err(err))
                }
            }
        }
    }
}

/// Rewrite a TABLE_DUMP_V2 MRT path-attribute blob so its MP_REACH_NLRI is in
/// BGP wire format instead of MRT-truncated format.
///
/// RFC 6396 §4.3.4 says RIB entries store only `NH_LEN(1) + NH(NH_LEN)` in the
/// MP_REACH_NLRI value (AFI/SAFI/Reserved/NLRI are implicit from the table
/// subtype). Standard BGP wire format is `AFI(2) + SAFI(1) + NH_LEN(1) +
/// NH(NH_LEN) + Reserved(1) + NLRI`. Downstream consumers that parse the
/// blob with a wire-format BGP parser otherwise misread offsets and emit
/// malformed BGP UPDATEs for some peers (whose next-hop's 3rd byte gives a
/// nh_len bgpkit-parser rejects).
fn normalize_mrt_mp_reach(
    raw_attr: Vec<u8>,
    afi: u16,
    safi: u8,
    prefix: &inetnum::addr::Prefix,
) -> Vec<u8> {
    // Encode the prefix as wire-format NLRI: prefix_len byte + ceil(len/8) bytes.
    let nlri: Vec<u8> = {
        let prefix_len = prefix.len();
        let num_bytes = (prefix_len as usize).div_ceil(8);
        let mut buf = Vec::with_capacity(1 + num_bytes);
        buf.push(prefix_len);
        match prefix.addr() {
            std::net::IpAddr::V4(v4) => {
                buf.extend_from_slice(&v4.octets()[..num_bytes])
            }
            std::net::IpAddr::V6(v6) => {
                buf.extend_from_slice(&v6.octets()[..num_bytes])
            }
        }
        buf
    };

    let mut out = Vec::with_capacity(raw_attr.len() + 16);
    let mut pos = 0;
    while pos < raw_attr.len() {
        if pos + 2 > raw_attr.len() {
            out.extend_from_slice(&raw_attr[pos..]);
            break;
        }
        let flags = raw_attr[pos];
        let type_code = raw_attr[pos + 1];
        let (attr_len, header_len) = if flags & 0x10 != 0 {
            if pos + 4 > raw_attr.len() {
                out.extend_from_slice(&raw_attr[pos..]);
                break;
            }
            (
                ((raw_attr[pos + 2] as usize) << 8)
                    | (raw_attr[pos + 3] as usize),
                4,
            )
        } else {
            if pos + 3 > raw_attr.len() {
                out.extend_from_slice(&raw_attr[pos..]);
                break;
            }
            (raw_attr[pos + 2] as usize, 3)
        };
        let total = header_len + attr_len;
        if pos + total > raw_attr.len() {
            out.extend_from_slice(&raw_attr[pos..]);
            break;
        }

        if type_code == 14 {
            let mrt_value = &raw_attr[pos + header_len..pos + total];
            if !mrt_value.is_empty() {
                let nh_len = mrt_value[0] as usize;
                if mrt_value.len() >= 1 + nh_len {
                    let nh = &mrt_value[1..1 + nh_len];
                    let new_value_len = 2 + 1 + 1 + nh.len() + 1 + nlri.len();
                    let use_extended = new_value_len > 255;
                    let new_flags = if use_extended {
                        flags | 0x10
                    } else {
                        flags & !0x10
                    };
                    out.push(new_flags);
                    out.push(14);
                    if use_extended {
                        out.extend_from_slice(
                            &(new_value_len as u16).to_be_bytes(),
                        );
                    } else {
                        out.push(new_value_len as u8);
                    }
                    out.extend_from_slice(&afi.to_be_bytes());
                    out.push(safi);
                    out.push(nh_len as u8);
                    out.extend_from_slice(nh);
                    out.push(0); // Reserved
                    out.extend_from_slice(&nlri);
                    pos += total;
                    continue;
                }
            }
            // malformed MP_REACH; pass through unchanged so the consumer can decide.
        }

        out.extend_from_slice(&raw_attr[pos..pos + total]);
        pos += total;
    }
    out
}

#[derive(Debug)]
enum MrtErrorType {
    Io(std::io::Error),
    Parse(ParseError),
    Other(&'static str),
}
#[derive(Debug)]
pub struct MrtError(MrtErrorType);

impl MrtError {
    fn other(s: &'static str) -> Self {
        Self(MrtErrorType::Other(s))
    }
}

impl std::error::Error for MrtError {}
impl std::fmt::Display for MrtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            MrtErrorType::Io(e) => write!(f, "io error: {}", e),
            MrtErrorType::Parse(e) => write!(f, "parse error: {}", e),
            MrtErrorType::Other(e) => write!(f, "error: {}", e),
        }
    }
}

impl From<ParseError> for MrtError {
    fn from(e: ParseError) -> Self {
        Self(MrtErrorType::Parse(e))
    }
}

impl From<std::io::Error> for MrtError {
    fn from(e: std::io::Error) -> Self {
        Self(MrtErrorType::Io(e))
    }
}
impl From<MrtError> for std::io::Error {
    fn from(e: MrtError) -> Self {
        std::io::Error::other(e.to_string())
    }
}
