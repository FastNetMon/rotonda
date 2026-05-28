use bytes::Bytes;
use rotonda_store::prefix_record::{Meta, RouteStatus};
use routecore::bgp::message::PduParseInfo;
use routecore::bgp::path_attributes::OwnedPathAttributes;
use routecore::bgp::path_selection::TiebreakerInfo;
use routecore::bgp::types::AfiSafiType;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use smallvec::{smallvec, SmallVec};
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    fmt,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, Weak},
};

use crate::ingress::{self, IngressId, IngressInfo};
use crate::roto_runtime::types::OutputStreamMessage;
use crate::units::rib_unit::rpki::RpkiInfo;
use crate::units::rib_unit::QueryFilter;

// TODO: make this a reference
pub type RouterId = String;

//------------ UpstreamStatus ------------------------------------------------

#[derive(Clone, Debug)]
pub enum UpstreamStatus {
    /// No more data will be sent for the specified source.
    ///
    /// This could be because a network connection has been lost, or at the
    /// protocol level a session has been terminated, but need not be network
    /// related. E.g. it could be that the last message in a replay file has
    /// been loaded and replayed, or the last message in a test set has been
    /// pushed into the pipeline, etc.
    EndOfStream { ingress_id: ingress::IngressId },
}

//------------ Payload -------------------------------------------------------

// TODO macrofy
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotondaRoute {
    Ipv4Unicast(routecore::bgp::nlri::afisafi::Ipv4UnicastNlri, RotondaPaMap),
    Ipv6Unicast(routecore::bgp::nlri::afisafi::Ipv6UnicastNlri, RotondaPaMap),
    Ipv4Multicast(
        routecore::bgp::nlri::afisafi::Ipv4MulticastNlri,
        RotondaPaMap,
    ),
    Ipv6Multicast(
        routecore::bgp::nlri::afisafi::Ipv6MulticastNlri,
        RotondaPaMap,
    ),
    // TODO support all routecore AfiSafiTypes
}

impl Serialize for RotondaRoute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("Route", 2)?;
        match self {
            RotondaRoute::Ipv4Unicast(n, _) => s.serialize_field("prefix", n),
            RotondaRoute::Ipv6Unicast(n, _) => s.serialize_field("prefix", n),
            RotondaRoute::Ipv4Multicast(n, _) => {
                s.serialize_field("prefix", n)
            }
            RotondaRoute::Ipv6Multicast(n, _) => {
                s.serialize_field("prefix", n)
            }
        }?;

        s.serialize_field("attributes", self.rotonda_pamap())?;
        s.end()
    }
}

impl RotondaRoute {
    pub fn owned_map(
        &self,
    ) -> routecore::bgp::path_attributes::OwnedPathAttributes {
        match self {
            RotondaRoute::Ipv4Unicast(_, p) => p.path_attributes(),
            RotondaRoute::Ipv6Unicast(_, p) => p.path_attributes(),
            RotondaRoute::Ipv4Multicast(_, p) => p.path_attributes(),
            RotondaRoute::Ipv6Multicast(_, p) => p.path_attributes(),
        }
    }

    pub fn rotonda_pamap(&self) -> &RotondaPaMap {
        match self {
            RotondaRoute::Ipv4Unicast(_, p) => p,
            RotondaRoute::Ipv6Unicast(_, p) => p,
            RotondaRoute::Ipv4Multicast(_, p) => p,
            RotondaRoute::Ipv6Multicast(_, p) => p,
        }
    }

    pub fn rotonda_pamap_mut(&mut self) -> &mut RotondaPaMap {
        match self {
            RotondaRoute::Ipv4Unicast(_, ref mut p) => p,
            RotondaRoute::Ipv6Unicast(_, ref mut p) => p,
            RotondaRoute::Ipv4Multicast(_, ref mut p) => p,
            RotondaRoute::Ipv6Multicast(_, ref mut p) => p,
        }
    }
}

impl fmt::Display for RotondaRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RotondaRoute::Ipv4Unicast(p, ..) => {
                write!(f, "RR-Ipv4Unicast {}", p)
            }
            RotondaRoute::Ipv6Unicast(p, ..) => {
                write!(f, "RR-Ipv6Unicast {}", p)
            }
            RotondaRoute::Ipv4Multicast(p, ..) => {
                write!(f, "RR-Ipv4Multicast {}", p)
            }
            RotondaRoute::Ipv6Multicast(p, ..) => {
                write!(f, "RR-Ipv6Multicast {}", p)
            }
        }
    }
}

impl Meta for RotondaPaMap {
    type Orderable<'a> = routecore::bgp::path_selection::OrdRoute<
        'a,
        routecore::bgp::path_selection::Rfc4271,
    >;

    type TBI = TiebreakerInfo;

    fn as_orderable(&self, _tbi: Self::TBI) -> Self::Orderable<'_> {
        todo!()
    }
}

impl From<Vec<u8>> for RotondaPaMap {
    fn from(value: Vec<u8>) -> Self {
        OwnedPathAttributes::new(PduParseInfo::modern(), value).into()
    }
}

impl AsRef<[u8]> for RotondaPaMap {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct RotondaPaMap {
    // raw[0] is RpkiInfo
    // raw[1] is PduParseInfo
    // raw[2..] contains the path attributes blob
    raw: Arc<[u8]>,
}

#[derive(Debug)]
pub struct PathAttributeInterner {
    shards: Vec<Mutex<HashMap<u64, Vec<Weak<[u8]>>>>>,
}

impl Default for PathAttributeInterner {
    fn default() -> Self {
        const NUM_SHARDS: usize = 64;

        Self {
            shards: (0..NUM_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
        }
    }
}

impl PathAttributeInterner {
    pub fn intern(&self, raw: &[u8]) -> Arc<[u8]> {
        let hash = hash_bytes(raw);
        let shard_index = hash as usize % self.shards.len();
        let mut shard = self.shards[shard_index].lock().unwrap();
        let entries = shard.entry(hash).or_default();

        let mut idx = 0;
        while idx < entries.len() {
            match entries[idx].upgrade() {
                Some(existing) => {
                    if existing.as_ref() == raw {
                        return existing;
                    }
                    idx += 1;
                }
                None => {
                    entries.swap_remove(idx);
                }
            }
        }

        let interned = Arc::<[u8]>::from(raw);
        entries.push(Arc::downgrade(&interned));
        interned
    }
}

fn hash_bytes(raw: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    hasher.finish()
}

// These from/to byte functions should ideally live in routecore, but as we
// will refactor many routecore types to zerocopy structs soon(tm), we define
// these here for now.
fn ppi_to_byte(ppi: PduParseInfo) -> u8 {
    match ppi.four_octet_enabled() {
        true => 1,
        false => 0,
    }
}

fn byte_to_ppi(byte: u8) -> PduParseInfo {
    if byte == 0x01 {
        PduParseInfo::modern()
    } else {
        PduParseInfo::legacy()
    }
}

impl RotondaPaMap {
    pub fn empty_path_attributes() -> Self {
        OwnedPathAttributes::new(PduParseInfo::modern(), Vec::new()).into()
    }

    pub fn new(path_attributes: OwnedPathAttributes) -> Self {
        let ppi = path_attributes.pdu_parse_info();
        let mut pas = path_attributes.into_vec();
        let mut raw = Vec::with_capacity(2 + pas.len());

        let rpki_info = RpkiInfo::default();
        raw.push(rpki_info.into());
        raw.push(ppi_to_byte(ppi));

        raw.append(&mut pas);
        Self { raw: raw.into() }
    }

    pub fn dedup_with(&self, interner: &PathAttributeInterner) -> Self {
        Self {
            raw: interner.intern(self.raw.as_ref()),
        }
    }

    pub fn set_rpki_info(&mut self, rpki_info: RpkiInfo) {
        Arc::make_mut(&mut self.raw)[0] = rpki_info.into();
    }

    pub fn rpki_info(&self) -> RpkiInfo {
        self.raw[0].into()
    }

    pub fn path_attributes(&self) -> OwnedPathAttributes {
        let ppi = byte_to_ppi(self.raw[1]);
        OwnedPathAttributes::new(ppi, self.raw[2..].to_vec())
    }
}

impl fmt::Display for RotondaPaMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.path_attributes())
    }
}

impl Serialize for RotondaPaMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("route", 2)?;
        s.serialize_field("rpki", &self.rpki_info())?;
        s.serialize_field(
            "pathAttributes",
            &self
                .path_attributes()
                .iter()
                .flatten()
                .filter(|pa| pa.type_code() != 15)
                .flat_map(|pa| pa.to_owned())
                .collect::<Vec<_>>(),
        )?;
        s.end()
    }
}

pub struct RotondaPaMapWithQueryFilter<'a, 'b>(
    pub &'a RotondaPaMap,
    pub &'b QueryFilter,
);
impl<'a, 'b> Serialize for RotondaPaMapWithQueryFilter<'a, 'b> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("route", 2)?;
        s.serialize_field("rpki", &self.0.rpki_info())?;
        s.serialize_field(
            "pathAttributes",
            &self
                .0
                .path_attributes()
                .iter()
                .flatten()
                .filter(|pa| {
                    (self
                        .1
                        .fields_path_attributes
                        .as_ref()
                        .map(|fpa| fpa.contains(&pa.type_code()))
                        .unwrap_or(true))
                        && pa.type_code() != 15
                })
                .flat_map(|pa| pa.to_owned())
                .collect::<Vec<_>>(),
        )?;
        s.end()
    }
}

impl From<OwnedPathAttributes> for RotondaPaMap {
    fn from(value: OwnedPathAttributes) -> Self {
        RotondaPaMap::new(value)
    }
}

#[derive(Clone, Debug, Eq)]
pub struct Payload {
    pub rx_value: RotondaRoute, //RouteWorkshop<N>, //was: TypeValue,
    pub trace_id: Option<u8>,
    pub received: std::time::Instant,
    pub ingress_id: IngressId,
    pub route_status: RouteStatus,
}

impl PartialEq for Payload {
    fn eq(&self, other: &Self) -> bool {
        // Don't compare the received timestamp
        // self.source_id == other.source_id &&
        self.rx_value == other.rx_value && self.trace_id == other.trace_id
    }
}

impl Payload {
    pub fn new(
        rx_value: RotondaRoute,
        trace_id: Option<u8>,
        ingress_id: IngressId,
        route_status: RouteStatus,
    ) -> Self {
        Self {
            rx_value,
            trace_id,
            received: std::time::Instant::now(),
            ingress_id,
            route_status,
        }
    }

    pub fn with_received(
        rx_value: RotondaRoute,
        trace_id: Option<u8>,
        received: std::time::Instant,
        ingress_id: IngressId,
        route_status: RouteStatus,
    ) -> Self {
        Self {
            rx_value,
            trace_id,
            received,
            ingress_id,
            route_status,
        }
    }

    pub fn trace_id(&self) -> Option<u8> {
        self.trace_id
    }
}

//------------ Update --------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Update {
    Single(Payload),
    Bulk(Box<SmallVec<[Payload; 8]>>),
    // Withdraw everything or a particular AFISAFI because the session ended.
    // Not to be used for 'normal' withdrawals.
    Withdraw(IngressId, Option<AfiSafiType>),
    // Withdraw everything for multiple sessions. This is used when a BMP
    // connection goes down and everything for the monitored sessions has to
    // be marked Withdrawn.
    //
    // Each entry optionally carries an `IngressInfo` snapshot taken at emit
    // time. Consumers building Peer Down messages should prefer the inline
    // info when present, because the producer may be about to drop the entry
    // from the global ingress register (e.g. for synthesized peers in
    // bmp_tcp_in's peer_down workaround). The lookup-after-remove race would
    // otherwise yield `IngressInfo::default()` and a Peer Down with a wrong
    // PPH. Producers that don't need to carry info can pass `None`.
    //
    // The inner SmallVec is `Box`-ed so the enum doesn't reserve ~2.4 KB
    // of inline storage on every `Update` slot — `IngressInfo` is a
    // wide struct (~250–300 B) and an inline SmallVec<[(_, Option<II>); 8]>
    // dominated size_of::<Update>() for buffers like bmp-out's dump_buffer,
    // costing ~25x more memory per buffered entry than the variants
    // actually in flight (which are mostly Single / Withdraw).
    WithdrawBulk(Box<SmallVec<[(IngressId, Option<IngressInfo>); 8]>>),
    // Used to signal the RibUnit a MUI should be set to active again.
    IngressReappeared(IngressId),
    UpstreamStatusChange(UpstreamStatus),

    OutputStream(Box<SmallVec<[OutputStreamMessage; 2]>>),
    Rtr(crate::units::RtrUpdate),

    // BMP Statistics Report forwarded verbatim from an upstream router.
    // `body` is the raw bytes after the BMP per-peer header, i.e. the
    // 4-byte stats count followed by stat TLVs. The downstream re-streamer
    // re-prefixes a fresh common + per-peer header before sending.
    PeerStats { ingress_id: IngressId, body: Bytes },
}

impl Update {
    pub fn trace_ids(&self) -> SmallVec<[&Payload; 1]> {
        match self {
            Update::Single(payload) => {
                if payload.trace_id().is_some() {
                    [payload].into()
                } else {
                    smallvec![]
                }
            }
            Update::Bulk(payloads) => {
                payloads.iter().filter(|p| p.trace_id().is_some()).collect()
            }
            Update::Withdraw(_ingress_id, _maybe_afisafi) => smallvec![],
            Update::WithdrawBulk(..) => smallvec![],
            Update::IngressReappeared(..) => smallvec![],
            Update::UpstreamStatusChange(_) => smallvec![],
            Update::OutputStream(..) => smallvec![],
            Update::Rtr(..) => smallvec![],
            Update::PeerStats { .. } => smallvec![],
        }
    }

    /// Approximate the in-memory footprint of this `Update`, excluding
    /// Arc-shared bytes (`RotondaPaMap::raw`, `PeerStats::body`).
    ///
    /// Used by `bmp_tcp_out`'s dump_buffer accounting to apply a hard byte
    /// cap independent of the kernel's free-RAM heuristic. The intent is a
    /// fast, conservative estimate of *marginal* heap growth from keeping
    /// this `Update` alive — not a precise allocator size. PaMap byte
    /// blobs are interned/shared with the RIB store, so counting them
    /// here would double-count against memory we'd be holding anyway.
    pub fn shallow_bytes(&self) -> usize {
        use std::mem::size_of;
        let base = size_of::<Self>();
        match self {
            Update::Single(_) => base,
            Update::Bulk(payloads) => {
                base + payloads.len() * size_of::<Payload>()
            }
            Update::Withdraw(..) => base,
            Update::WithdrawBulk(items) => {
                // Box pointer is part of `base`; account for the heap
                // SmallVec storage too.
                base
                    + items.len()
                        * size_of::<(IngressId, Option<IngressInfo>)>()
            }
            Update::IngressReappeared(..) => base,
            Update::UpstreamStatusChange(..) => base,
            Update::OutputStream(msgs) => {
                base + msgs.len() * size_of::<OutputStreamMessage>()
            }
            Update::Rtr(..) => base,
            // body is a Bytes (Arc-backed); shallow accounting skips it.
            Update::PeerStats { .. } => base,
        }
    }
}

impl From<Payload> for Update {
    fn from(payload: Payload) -> Self {
        Update::Single(payload)
    }
}

impl<const N: usize> From<[Payload; N]> for Update {
    fn from(payloads: [Payload; N]) -> Self {
        Update::Bulk(Box::new(payloads.as_slice().into()))
    }
}

impl From<SmallVec<[Payload; 8]>> for Update {
    fn from(payloads: SmallVec<[Payload; 8]>) -> Self {
        Update::Bulk(Box::new(payloads))
    }
}
