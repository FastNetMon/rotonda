/// BMP message construction at byte level (RFC 7854).
///
/// Since routecore 0.6 has BMP parsing but no builder, we construct
/// messages directly from bytes.
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;

use inetnum::addr::Prefix;
use inetnum::asn::Asn;
use routecore::bgp::nlri::afisafi::IsPrefix;
use routecore::bgp::types::AfiSafiType;
use routecore::bmp::message::PeerType;

use crate::ingress::{IngressId, IngressInfo};
use crate::payload::{RotondaPaMap, RotondaRoute};
use crate::roto_runtime::types::PeerRibType;

// BMP message types (RFC 7854 Section 4.1)
const BMP_MSG_ROUTE_MONITORING: u8 = 0;
const BMP_MSG_STATISTICS_REPORT: u8 = 1;
const BMP_MSG_PEER_DOWN: u8 = 2;
const BMP_MSG_PEER_UP: u8 = 3;
const BMP_MSG_INITIATION: u8 = 4;
const BMP_MSG_TERMINATION: u8 = 5;

// BMP version
const BMP_VERSION: u8 = 3;

// BMP Common Header size
const BMP_COMMON_HEADER_LEN: usize = 6;

// BMP Per-Peer Header size
const BMP_PER_PEER_HEADER_LEN: usize = 42;

// BMP Initiation TLV types
const BMP_INIT_TLV_SYS_DESCR: u16 = 1;
const BMP_INIT_TLV_SYS_NAME: u16 = 2;

// BMP Termination TLV types
const BMP_TERM_TLV_REASON: u16 = 0;

// BMP Peer Up TLV types (RFC 9736)
const BMP_PEER_UP_TLV_ADMIN_LABEL: u16 = 4;

// BMP Peer Down reason codes
const BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION: u8 = 4;

// BGP marker: 16 bytes of 0xFF
const BGP_MARKER: [u8; 16] = [0xFF; 16];

// BGP message types
const BGP_MSG_OPEN: u8 = 1;
const BGP_MSG_UPDATE: u8 = 2;

/// Maximum size of a BGP UPDATE message (RFC 4271 §4: the BGP message length
/// field caps a non-extended message at 4096 bytes). The aggregating dump
/// builder packs as many same-attribute NLRI into one UPDATE as will fit
/// under this, then starts a new message. We stay within the classic 4096
/// limit (rather than the 2-byte field's 65535) so the synthetic feed is
/// accepted by consumers that did not negotiate BGP extended messages.
const MAX_BGP_UPDATE_LEN: usize = 4096;

/// Information about a peer extracted from IngressInfo, used to construct
/// BMP Per-Peer Headers and Peer Up messages.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub peer_type: PeerType,
    pub peer_flags: u8,
    pub peer_distinguisher: [u8; 8],
    pub peer_address: IpAddr,
    pub peer_asn: Asn,
    pub peer_bgp_id: [u8; 4],
    pub admin_label: Option<String>,
}

impl PeerInfo {
    /// Build PeerInfo from IngressInfo.
    pub fn from_ingress_info(info: &IngressInfo) -> Self {
        let peer_type = info.peer_type.unwrap_or(PeerType::GlobalInstance);
        let peer_address = info
            .remote_addr
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let peer_asn = info.remote_asn.unwrap_or(Asn::from_u32(0));
        let peer_distinguisher = info.distinguisher.unwrap_or([0u8; 8]);

        // Peer flags (RFC 7854 §4.2 + RFC 8671):
        //   V (0x80) = IPv6 peer address
        //   L (0x40) = post-policy Adj-RIB-In/Out
        //   A (0x20) = legacy 2-byte AS path format
        //   O (0x10) = Adj-RIB-Out (RFC 8671)
        //
        // Preserve the upstream router's L/O bits when known so downstream
        // consumers can distinguish pre-policy / post-policy / Adj-RIB-In /
        // Adj-RIB-Out variants of the same (peer_addr, peer_asn). For peers
        // whose origin doesn't carry this (MRT, direct BGP), fall back to
        // post-policy Adj-RIB-In which is the most semantically useful
        // default for restreamed BMP.
        let mut peer_flags = 0u8;
        if peer_address.is_ipv6() {
            peer_flags |= 0x80;
        }
        match info.peer_rib_type {
            Some(PeerRibType::InPost) => peer_flags |= 0x40,
            Some(PeerRibType::InPre) => { /* L=0, O=0 */ }
            Some(PeerRibType::OutPost) => peer_flags |= 0x40 | 0x10,
            Some(PeerRibType::OutPre) => peer_flags |= 0x10,
            Some(PeerRibType::Loc) | None => peer_flags |= 0x40,
        }

        PeerInfo {
            peer_type,
            peer_flags,
            peer_distinguisher,
            peer_address,
            peer_asn,
            peer_bgp_id: [0u8; 4],
            admin_label: None,
        }
    }

    /// Stamp the fan-in `peer_distinguisher` tag (RFC 7854 §4.2 opaque
    /// 8-byte field) when the inbound peer has no real RD/VRF context.
    ///
    /// When rotonda multiplexes multiple upstream BMP sessions into one
    /// downstream session, two upstream routers can each have a session
    /// with the same neighbor (same peer_ip + peer_asn). On the wire that
    /// produces identical per-peer-header tuples and most BMP receivers
    /// treat them as duplicates, collapsing one upstream's view into the
    /// other. The fix is to encode the upstream router identity in the
    /// per-peer header's opaque distinguisher so the (peer_ip, peer_pd,
    /// rib_type) tuple is unique per upstream.
    ///
    /// Behaviour:
    ///   * If the existing `peer_distinguisher` is non-zero, the peer
    ///     already carries a real RD (RFC 7854 RD Instance / VPN peer
    ///     types) — leave it untouched.
    ///   * Otherwise replace the zeros with `tag`.
    pub fn apply_fan_in_distinguisher(&mut self, tag: [u8; 8]) {
        if self.peer_distinguisher == [0u8; 8] {
            self.peer_distinguisher = tag;
        }
    }
}

/// Derive a stable 8-byte fan-in distinguisher tag for the given upstream
/// router (parent) IngressId.
///
/// Requirements:
///   * Stable for the rotonda process lifetime (`IngressId` is allocated
///     once per upstream session and reused on reconnect via the
///     register's find_existing_bmp_router path).
///   * Unique across concurrent upstream routers within one process
///     (`IngressId` is a process-global counter, so different parents
///     hash to different values modulo a 64-bit collision).
///   * Always non-zero so the downstream key (peer_ip, peer_pd, rib_type)
///     differs from the legacy pd=0 case.
///
/// Hash: `std::collections::hash_map::DefaultHasher` (SipHash-1-3 with
/// fixed keys) over a typed domain prefix + the parent IngressId. The
/// fixed seed is intentional — it makes the wire output reproducible for
/// pcap-based debugging.
pub fn fan_in_distinguisher_tag(parent_ingress_id: IngressId) -> [u8; 8] {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Domain-separation prefix: keep this fan-in hash output distinct
    // from any other use of DefaultHasher on the same numeric input.
    hasher.write(b"rotonda:bmp-out:fan-in:v1");
    hasher.write_u32(parent_ingress_id);
    let v = hasher.finish();
    // Guarantee non-zero: on the astronomically unlikely zero hash, fold
    // to a sentinel so the tag remains distinguishable from pd=0 "no
    // fan-in tag" / "real RD absent".
    let v = if v == 0 { 1 } else { v };
    v.to_be_bytes()
}

/// Write BMP Common Header to buffer.
fn write_common_header(buf: &mut Vec<u8>, msg_type: u8, total_len: u32) {
    buf.push(BMP_VERSION);
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.push(msg_type);
}

/// Write BMP Per-Peer Header to buffer.
fn write_per_peer_header(buf: &mut Vec<u8>, peer: &PeerInfo) {
    // Peer Type (1 byte)
    buf.push(peer.peer_type.into());

    // Peer Flags (1 byte)
    buf.push(peer.peer_flags);

    // Peer Distinguisher (8 bytes)
    buf.extend_from_slice(&peer.peer_distinguisher);

    // Peer Address (16 bytes) - RFC 7854: 12 zero bytes + IPv4 address
    match peer.peer_address {
        IpAddr::V4(v4) => {
            buf.extend_from_slice(&[0u8; 12]);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.extend_from_slice(&v6.octets());
        }
    }

    // Peer AS (4 bytes)
    buf.extend_from_slice(&u32::from(peer.peer_asn).to_be_bytes());

    // Peer BGP ID (4 bytes)
    buf.extend_from_slice(&peer.peer_bgp_id);

    // Timestamp seconds (4 bytes)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    buf.extend_from_slice(&(now.as_secs() as u32).to_be_bytes());

    // Timestamp microseconds (4 bytes)
    buf.extend_from_slice(&(now.subsec_micros()).to_be_bytes());
}

/// Build a BMP Initiation Message.
pub fn build_initiation_message(sys_name: &str, sys_descr: &str) -> Vec<u8> {
    let sys_descr_tlv_len = 4 + sys_descr.len();
    let sys_name_tlv_len = 4 + sys_name.len();
    let total_len =
        BMP_COMMON_HEADER_LEN + sys_descr_tlv_len + sys_name_tlv_len;

    let mut buf = Vec::with_capacity(total_len);
    write_common_header(&mut buf, BMP_MSG_INITIATION, total_len as u32);

    // sysDescr TLV (type=1)
    buf.extend_from_slice(&BMP_INIT_TLV_SYS_DESCR.to_be_bytes());
    buf.extend_from_slice(&(sys_descr.len() as u16).to_be_bytes());
    buf.extend_from_slice(sys_descr.as_bytes());

    // sysName TLV (type=2)
    buf.extend_from_slice(&BMP_INIT_TLV_SYS_NAME.to_be_bytes());
    buf.extend_from_slice(&(sys_name.len() as u16).to_be_bytes());
    buf.extend_from_slice(sys_name.as_bytes());

    buf
}

/// Build a BMP Termination Message with reason "administratively closed".
pub fn build_termination_message() -> Vec<u8> {
    let total_len = BMP_COMMON_HEADER_LEN + 6;

    let mut buf = Vec::with_capacity(total_len);
    write_common_header(&mut buf, BMP_MSG_TERMINATION, total_len as u32);

    // Reason TLV (type=0, reason=0 = administratively closed)
    buf.extend_from_slice(&BMP_TERM_TLV_REASON.to_be_bytes());
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    buf
}

/// Build a synthetic BGP OPEN message.
fn build_bgp_open(
    asn: Asn,
    include_ipv6: bool,
    advertise_graceful_restart: bool,
) -> Vec<u8> {
    let mut caps = Vec::new();

    // Capability: 4-octet ASN (code 65)
    caps.push(65);
    caps.push(4);
    caps.extend_from_slice(&u32::from(asn).to_be_bytes());

    // Capability: Multiprotocol Extensions - IPv4 Unicast (code 1)
    caps.push(1);
    caps.push(4);
    caps.extend_from_slice(&1u16.to_be_bytes()); // AFI=1
    caps.push(0);
    caps.push(1); // SAFI=1

    if include_ipv6 {
        // Capability: Multiprotocol Extensions - IPv6 Unicast
        caps.push(1);
        caps.push(4);
        caps.extend_from_slice(&2u16.to_be_bytes()); // AFI=2
        caps.push(0);
        caps.push(1); // SAFI=1
    }

    if advertise_graceful_restart {
        // Capability: Graceful Restart (code 64) - RFC 4724.
        // Advertising this tells receivers to expect matching End-of-RIB
        // markers for the listed AFI/SAFIs.
        caps.push(64); // Capability code
        let gr_afi_count = if include_ipv6 { 2 } else { 1 };
        let gr_len = 2 + gr_afi_count * 4; // restart flags/time + entries
        caps.push(gr_len as u8);
        caps.extend_from_slice(&0u16.to_be_bytes());
        // IPv4 Unicast with forwarding state not preserved.
        caps.extend_from_slice(&1u16.to_be_bytes()); // AFI=1
        caps.push(1); // SAFI=1
        caps.push(0); // Flags for this AFI/SAFI
        if include_ipv6 {
            // IPv6 Unicast with forwarding state not preserved
            caps.extend_from_slice(&2u16.to_be_bytes()); // AFI=2
            caps.push(1); // SAFI=1
            caps.push(0); // Flags for this AFI/SAFI
        }
    }

    // Optional Parameters: wrap capabilities in Parameter Type 2
    let mut opt_params = Vec::with_capacity(2 + caps.len());
    opt_params.push(2); // Parameter Type = Capabilities
    opt_params.push(caps.len() as u8);
    opt_params.extend_from_slice(&caps);

    // BGP OPEN: marker(16) + length(2) + type(1) + body
    let open_body_len = 10 + opt_params.len();
    let total_len = 19 + open_body_len;

    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(&BGP_MARKER);
    buf.extend_from_slice(&(total_len as u16).to_be_bytes());
    buf.push(BGP_MSG_OPEN);

    buf.push(4); // Version
    let two_byte_asn = if u32::from(asn) > 65535 {
        23456u16
    } else {
        u32::from(asn) as u16
    };
    buf.extend_from_slice(&two_byte_asn.to_be_bytes());
    buf.extend_from_slice(&90u16.to_be_bytes()); // Hold Time
    buf.extend_from_slice(&[0u8; 4]); // BGP Identifier
    buf.push(opt_params.len() as u8);
    buf.extend_from_slice(&opt_params);

    buf
}

/// Escape a string for JSON: handle `"`, `\`, and control characters.
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Build a JSON Admin Label string from upstream router name/description.
///
/// Filters out placeholder values ("no-sysname", "no-sysdesc") that some
/// BMP implementations send when the real value is unavailable. Returns
/// `None` if both fields are absent or placeholder.
pub fn build_admin_label_json(
    name: Option<&str>,
    desc: Option<&str>,
) -> Option<String> {
    let name = name.filter(|s| *s != "no-sysname" && !s.is_empty());
    let desc = desc.filter(|s| *s != "no-sysdesc" && !s.is_empty());

    if name.is_none() && desc.is_none() {
        return None;
    }

    let mut json = String::from("{");
    let mut first = true;

    if let Some(n) = name {
        json.push_str(&format!("\"sysName\":\"{}\"", escape_json_string(n)));
        first = false;
    }

    if let Some(d) = desc {
        if !first {
            json.push(',');
        }
        json.push_str(&format!("\"sysDescr\":\"{}\"", escape_json_string(d)));
    }

    json.push('}');
    Some(json)
}

/// Build a BMP Peer Up Notification message.
pub fn build_peer_up(
    peer: &PeerInfo,
    advertise_graceful_restart: bool,
) -> Vec<u8> {
    // BMP-out can emit IPv4 and IPv6 unicast route-monitoring messages for a
    // peer regardless of whether the peer's transport address is IPv4 or IPv6.
    let include_ipv6 = true;
    let sent_open = build_bgp_open(
        peer.peer_asn,
        include_ipv6,
        advertise_graceful_restart,
    );
    let received_open = build_bgp_open(
        peer.peer_asn,
        include_ipv6,
        advertise_graceful_restart,
    );
    let max_tlv_len = u16::MAX as usize;

    let admin_label = peer
        .admin_label
        .as_ref()
        .filter(|label| label.len() <= max_tlv_len);

    // Admin Label TLV: Type(2) + Length(2) + Value
    let admin_label_tlv_len = match &admin_label {
        Some(label) => 4 + label.len(),
        None => 0,
    };

    let peer_up_body_len = 16
        + 2
        + 2
        + sent_open.len()
        + received_open.len()
        + admin_label_tlv_len;
    let total_len =
        BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + peer_up_body_len;

    let mut buf = Vec::with_capacity(total_len);
    write_common_header(&mut buf, BMP_MSG_PEER_UP, total_len as u32);
    write_per_peer_header(&mut buf, peer);

    // Local Address (16 bytes) - zeros
    buf.extend_from_slice(&[0u8; 16]);
    // Local Port (2 bytes)
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Remote Port (2 bytes)
    buf.extend_from_slice(&179u16.to_be_bytes());
    // Sent OPEN
    buf.extend_from_slice(&sent_open);
    // Received OPEN
    buf.extend_from_slice(&received_open);

    // Admin Label TLV (type 4, RFC 9736)
    if let Some(label) = &admin_label {
        buf.extend_from_slice(&BMP_PEER_UP_TLV_ADMIN_LABEL.to_be_bytes());
        buf.extend_from_slice(&(label.len() as u16).to_be_bytes());
        buf.extend_from_slice(label.as_bytes());
    }

    buf
}

/// Build a BMP Peer Down Notification message.
pub fn build_peer_down(peer: &PeerInfo) -> Vec<u8> {
    let total_len = BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + 1;

    let mut buf = Vec::with_capacity(total_len);
    write_common_header(&mut buf, BMP_MSG_PEER_DOWN, total_len as u32);
    write_per_peer_header(&mut buf, peer);
    buf.push(BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION);

    buf
}

/// Build a BMP Route Monitoring message wrapping a BGP UPDATE.
pub fn build_route_monitoring(
    peer: &PeerInfo,
    prefix: Prefix,
    pamap: &RotondaPaMap,
    is_withdrawal: bool,
) -> Option<Vec<u8>> {
    let bgp_update = build_bgp_update(prefix, pamap, is_withdrawal)?;
    let total_len =
        BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + bgp_update.len();

    let mut buf = Vec::with_capacity(total_len);
    write_common_header(&mut buf, BMP_MSG_ROUTE_MONITORING, total_len as u32);
    write_per_peer_header(&mut buf, peer);
    buf.extend_from_slice(&bgp_update);

    Some(buf)
}

/// Build a BMP Route Monitoring message from a RotondaRoute.
pub fn build_route_monitoring_from_route(
    peer: &PeerInfo,
    route: &RotondaRoute,
    is_withdrawal: bool,
) -> Option<Vec<u8>> {
    let (prefix, pamap) = match route {
        RotondaRoute::Ipv4Unicast(nlri, pamap) => {
            let prefix =
                Prefix::new(nlri.prefix().addr(), nlri.prefix().len())
                    .ok()?;
            (prefix, pamap)
        }
        RotondaRoute::Ipv6Unicast(nlri, pamap) => {
            let prefix =
                Prefix::new(nlri.prefix().addr(), nlri.prefix().len())
                    .ok()?;
            (prefix, pamap)
        }
        RotondaRoute::Ipv4Multicast(nlri, pamap) => {
            let prefix =
                Prefix::new(nlri.prefix().addr(), nlri.prefix().len())
                    .ok()?;
            (prefix, pamap)
        }
        RotondaRoute::Ipv6Multicast(nlri, pamap) => {
            let prefix =
                Prefix::new(nlri.prefix().addr(), nlri.prefix().len())
                    .ok()?;
            (prefix, pamap)
        }
    };

    build_route_monitoring(peer, prefix, pamap, is_withdrawal)
}

fn hash_pa_blob(blob: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    blob.hash(&mut h);
    h.finish()
}

/// Build ONE BMP Route Monitoring message whose BGP UPDATE announces several
/// prefixes that share a single identical path-attribute set (NLRI
/// aggregation, RFC 4271 / RFC 4760).
///
/// All `prefixes` must belong to the same address family (`is_v4`) and the
/// caller must guarantee the encoded BGP UPDATE fits [`MAX_BGP_UPDATE_LEN`]
/// — [`RouteAggregator`] enforces both. `pa_bytes` are the path attributes
/// already filtered of MP_REACH/MP_UNREACH (types 14/15); for IPv6,
/// `next_hop` carries the next hop recovered from the original MP_REACH and a
/// fresh MP_REACH_NLRI is rebuilt around all the prefixes.
fn build_aggregated_route_monitoring(
    peer: &PeerInfo,
    prefixes: &[Prefix],
    pa_bytes: &[u8],
    next_hop: Option<&[u8]>,
    is_v4: bool,
) -> Vec<u8> {
    let mut nlri = Vec::new();
    for p in prefixes {
        append_prefix_nlri(&mut nlri, *p);
    }

    let bgp_update = if is_v4 {
        // IPv4: shared path attributes (incl. legacy NEXT_HOP, if any) once,
        // then every prefix in the NLRI field.
        let update_body_len = 2 + 2 + pa_bytes.len() + nlri.len();
        let total_len = 19 + update_body_len;

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push(BGP_MSG_UPDATE);
        buf.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
        buf.extend_from_slice(&(pa_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(pa_bytes);
        buf.extend_from_slice(&nlri);
        buf
    } else {
        // IPv6: shared attributes plus a single MP_REACH_NLRI (always encoded
        // with the extended-length flag so the 2-byte length math is uniform
        // regardless of how many prefixes are packed) carrying the shared
        // next hop once and all prefixes as NLRI.
        let default_nh = [0u8; 16];
        let nh: &[u8] = next_hop.unwrap_or(&default_nh);

        let value_len = 2 + 1 + 1 + nh.len() + 1 + nlri.len();
        let mp_reach_len = 4 + value_len; // flags + type + 2-byte ext length
        let total_pa_len = pa_bytes.len() + mp_reach_len;
        let update_body_len = 2 + 2 + total_pa_len;
        let total_len = 19 + update_body_len;

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push(BGP_MSG_UPDATE);
        buf.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length
        buf.extend_from_slice(&(total_pa_len as u16).to_be_bytes());
        buf.extend_from_slice(pa_bytes);
        // MP_REACH_NLRI (type 14), extended length.
        buf.push(0x90);
        buf.push(14);
        buf.extend_from_slice(&(value_len as u16).to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes()); // AFI = IPv6
        buf.push(1); // SAFI = unicast
        buf.push(nh.len() as u8);
        buf.extend_from_slice(nh);
        buf.push(0); // Reserved
        buf.extend_from_slice(&nlri);
        buf
    };

    let total_len =
        BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + bgp_update.len();
    let mut buf = Vec::with_capacity(total_len);
    write_common_header(&mut buf, BMP_MSG_ROUTE_MONITORING, total_len as u32);
    write_per_peer_header(&mut buf, peer);
    buf.extend_from_slice(&bgp_update);
    buf
}

/// In-memory cost charged to the accumulator budget per buffered prefix.
/// `Prefix` plus its slot in the group's `Vec`; deliberately generous so the
/// budget tracks real RSS rather than the (smaller) encoded NLRI length.
const AGG_MEM_PER_PREFIX: usize = 32;

/// In-memory cost charged per open group: the `AggGroup` struct, its hash-map
/// slot, and small `Vec` headers. The attribute bytes are NOT counted — the
/// group holds them via a shared `Arc<[u8]>` (no per-group allocation).
const AGG_MEM_PER_GROUP: usize = 128;

/// One open aggregation group: a (peer, address-family, attribute-set) under
/// which prefixes accumulate until the group is flushed into a single
/// multi-NLRI BGP UPDATE.
///
/// The group holds only a cheap `Arc<[u8]>` clone of the route's raw bytes
/// (shared with the RIB record, so no copy) plus the accumulating prefix
/// list. The filtered path attributes and next hop are recomputed from
/// `raw` at emit time — paid once per emitted message, not held per open
/// group — and the `PeerInfo` is looked up from the shared peer map at emit
/// rather than cloned into every group.
struct AggGroup {
    /// Raw `RotondaPaMap` bytes (`[rpki, ppi, pa_blob...]`), shared with the
    /// store record via `Arc`. Used both to detect hash collisions
    /// (`raw[2..]`) and to recompute the filtered attributes at emit.
    raw: Arc<[u8]>,
    is_v4: bool,
    prefixes: Vec<Prefix>,
    /// Running encoded length of the NLRI accumulated so far.
    nlri_total: usize,
    /// Encoded BGP UPDATE length with zero prefixes (everything but NLRI).
    base_len: usize,
}

impl AggGroup {
    fn new(pamap: &RotondaPaMap, is_v4: bool) -> Self {
        let (pa_bytes, next_hop_opt) = filter_raw_path_attributes(pamap);
        let base_len = if is_v4 {
            19 + 2 + 2 + pa_bytes.len()
        } else {
            let nh_len = next_hop_opt.as_ref().map(|n| n.len()).unwrap_or(16);
            // + MP_REACH header (4) + AFI(2)+SAFI(1)+NHLEN(1)+NH+Reserved(1)
            19 + 2 + 2 + pa_bytes.len() + 4 + (2 + 1 + 1 + nh_len + 1)
        };
        Self {
            raw: pamap.raw_arc(),
            is_v4,
            prefixes: Vec::new(),
            nlri_total: 0,
            base_len,
        }
    }

    /// The route's attribute blob (raw bytes after the rpki/ppi prefix),
    /// used to confirm a hash-map key match before merging.
    fn blob(&self) -> &[u8] {
        self.raw.get(2..).unwrap_or(&[])
    }

    fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }

    fn bgp_update_len(&self) -> usize {
        self.base_len + self.nlri_total
    }

    /// Real heap memory this group contributes to the accumulator budget.
    fn cost(&self) -> usize {
        AGG_MEM_PER_GROUP + self.prefixes.len() * AGG_MEM_PER_PREFIX
    }

    fn push(&mut self, prefix: Prefix, nlri_len: usize) {
        self.prefixes.push(prefix);
        self.nlri_total += nlri_len;
    }

    fn reset_prefixes(&mut self) {
        self.prefixes.clear();
        self.nlri_total = 0;
    }

    /// Encode the group's prefixes into one message (attributes recomputed
    /// from `raw`) and hand it to `sink` paired with its prefix count. No-op
    /// for an empty group. Returns `false` if the sink reports the consumer
    /// is gone.
    fn emit(
        &self,
        peer: &PeerInfo,
        sink: &mut dyn FnMut(Vec<u8>, usize) -> bool,
    ) -> bool {
        if self.prefixes.is_empty() {
            return true;
        }
        let (pa_bytes, next_hop) = filter_pa_from_raw(&self.raw);
        let nh = if self.is_v4 {
            None
        } else {
            next_hop.as_deref().or(Some(&[0u8; 16][..]))
        };
        let msg = build_aggregated_route_monitoring(
            peer,
            &self.prefixes,
            &pa_bytes,
            nh,
            self.is_v4,
        );
        sink(msg, self.prefixes.len())
    }
}

/// Accumulates dump-phase routes and emits them as aggregated multi-NLRI BGP
/// UPDATEs: prefixes sharing one (peer, address-family, attribute-set) are
/// packed into a single BMP Route Monitoring message instead of one message
/// per prefix.
///
/// Because the RIB walk is prefix-major, a group's prefixes are scattered
/// across the whole walk, so groups stay open until the end to aggregate
/// fully. Memory is bounded by `max_bytes`: when exceeded, the fullest groups
/// are flushed first (best aggregation, frees the most memory) until back
/// under budget, leaving the long tail of small groups open to keep growing.
/// This keeps aggregation effective at a given budget instead of repeatedly
/// dumping half-empty groups (which a flush-everything policy would do).
pub struct RouteAggregator {
    groups: HashMap<(IngressId, bool, u64), AggGroup>,
    peer_info: HashMap<IngressId, PeerInfo>,
    buffered_bytes: usize,
    max_bytes: usize,
    // Diagnostics, so the dump can report whether aggregation hit the budget
    // (premature eviction) versus the table's natural attribute diversity.
    groups_created: usize,
    budget_evictions: usize,
}

impl RouteAggregator {
    pub fn new(
        max_bytes: usize,
        peer_info: HashMap<IngressId, PeerInfo>,
    ) -> Self {
        Self {
            groups: HashMap::new(),
            peer_info,
            buffered_bytes: 0,
            max_bytes,
            groups_created: 0,
            budget_evictions: 0,
        }
    }

    /// Whether the given ingress is already a known peer in the map. The dump
    /// walk uses this to decide if it must discover-and-insert a peer (active
    /// routes in the store whose register entry wasn't enumerated) before
    /// adding its routes.
    pub fn has_peer(&self, id: IngressId) -> bool {
        self.peer_info.contains_key(&id)
    }

    /// Insert a peer discovered mid-walk so its deferred (and immediate) emits
    /// resolve the correct per-peer header.
    pub fn insert_peer(&mut self, id: IngressId, info: PeerInfo) {
        self.peer_info.insert(id, info);
    }

    /// `(groups_created, budget_evictions)` — number of distinct aggregation
    /// groups opened, and number of groups force-flushed by the memory budget
    /// before the final flush. A `budget_evictions` near zero means the
    /// achieved routes/msg ratio reflects the table's real attribute sharing,
    /// not a too-small budget.
    pub fn stats(&self) -> (usize, usize) {
        (self.groups_created, self.budget_evictions)
    }

    /// Add one stored route. Emits zero or more completed messages through
    /// `sink` (each as `(bytes, prefix_count)`); returns `false` as soon as
    /// the sink reports the consumer is gone, in which case the caller should
    /// abort the walk.
    pub fn add(
        &mut self,
        ingress_id: IngressId,
        prefix: Prefix,
        pamap: &RotondaPaMap,
        sink: &mut dyn FnMut(Vec<u8>, usize) -> bool,
    ) -> bool {
        // The walk guarantees the peer is in the map before calling `add`
        // (it discovers-and-inserts on miss). Resolve once for the
        // immediate-emit cases; a missing entry means the caller violated
        // that contract, so drop the route rather than panic.
        let peer = match self.peer_info.get(&ingress_id) {
            Some(pi) => pi.clone(),
            None => return true,
        };
        let peer = &peer;
        let is_v4 = prefix.is_v4();
        let raw = pamap.as_ref();
        let blob = raw.get(2..).unwrap_or(&[]);
        let key = (ingress_id, is_v4, hash_pa_blob(blob));
        let nlri_len = nlri_encoded_len(prefix);

        // Pull the group out so the budget bookkeeping below borrows `self`
        // freely.
        let mut group = match self.groups.remove(&key) {
            Some(g) if g.blob() == blob => {
                self.buffered_bytes -= g.cost();
                g
            }
            Some(other) => {
                // Hash collision (distinct attributes sharing a hash): flush
                // the displaced group and start fresh for these attributes.
                self.buffered_bytes -= other.cost();
                if !other.emit(peer, sink) {
                    return false;
                }
                self.groups_created += 1;
                AggGroup::new(pamap, is_v4)
            }
            None => {
                self.groups_created += 1;
                AggGroup::new(pamap, is_v4)
            }
        };

        // If this prefix would push a non-empty group past the BGP UPDATE
        // size limit, flush the group first (keeping its attribute set) and
        // continue accumulating into the now-empty group.
        if !group.is_empty()
            && group.bgp_update_len() + nlri_len > MAX_BGP_UPDATE_LEN
        {
            if !group.emit(peer, sink) {
                return false;
            }
            group.reset_prefixes();
        }

        // A single prefix whose attribute set alone overflows the limit can
        // never be aggregated; emit it via the single-route builder (which
        // also handles the truly-oversized drop case) and drop the group.
        if group.is_empty()
            && group.base_len + nlri_len > MAX_BGP_UPDATE_LEN
        {
            if let Some(msg) =
                build_route_monitoring(peer, prefix, pamap, false)
            {
                if !sink(msg, 1) {
                    return false;
                }
            }
            // `group` was counted out above (or never counted); nothing to
            // re-insert.
            return true;
        }

        group.push(prefix, nlri_len);
        self.buffered_bytes += group.cost();
        self.groups.insert(key, group);

        if self.buffered_bytes > self.max_bytes {
            if !self.evict_until_under_budget(sink) {
                return false;
            }
        }
        true
    }

    /// Flush the fullest open groups until the buffered total is back under
    /// `max_bytes`. Fullest-first maximises routes/msg on each evicted
    /// message and frees the most memory per flush, so the surviving small
    /// groups keep accumulating.
    fn evict_until_under_budget(
        &mut self,
        sink: &mut dyn FnMut(Vec<u8>, usize) -> bool,
    ) -> bool {
        // Order open groups by prefix count, descending.
        let mut keys: Vec<(IngressId, bool, u64)> =
            self.groups.keys().copied().collect();
        keys.sort_unstable_by_key(|k| {
            std::cmp::Reverse(
                self.groups.get(k).map(|g| g.prefixes.len()).unwrap_or(0),
            )
        });

        // Evict down to half the budget so we don't re-trigger immediately on
        // the next route.
        let target = self.max_bytes / 2;
        for k in keys {
            if self.buffered_bytes <= target {
                break;
            }
            // Take the group out first, then borrow `self.peer_info` for the
            // lookup — split borrows so the owned (non-Arc) peer map needs no
            // per-call clone.
            if let Some(group) = self.groups.remove(&k) {
                self.buffered_bytes -= group.cost();
                self.budget_evictions += 1;
                if let Some(peer) = self.peer_info.get(&k.0) {
                    if !group.emit(peer, sink) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Emit every open group. Call once after the walk completes.
    pub fn flush_all(
        &mut self,
        sink: &mut dyn FnMut(Vec<u8>, usize) -> bool,
    ) -> bool {
        // Drain groups into a temporary so `self.peer_info` can be borrowed
        // for the per-group lookup without conflicting with the drain (the
        // peer map is now an owned HashMap, not a cheap-to-clone Arc).
        let groups: Vec<((IngressId, bool, u64), AggGroup)> =
            self.groups.drain().collect();
        for (key, group) in groups {
            if let Some(peer) = self.peer_info.get(&key.0) {
                if !group.emit(peer, sink) {
                    self.buffered_bytes = 0;
                    return false;
                }
            }
        }
        self.buffered_bytes = 0;
        true
    }
}

/// Build a BMP Statistics Report (RFC 7854 §4.8) for the given peer.
///
/// `body` is the opaque stats body received from upstream — the 4-byte
/// stats count followed by stat TLVs. We rebuild only the BMP common
/// header and per-peer header so the report is attributed to the correct
/// re-streamed peer; the body is forwarded verbatim, preserving any
/// vendor / RFC-extension stat TLVs.
pub fn build_statistics_report(peer: &PeerInfo, body: &[u8]) -> Vec<u8> {
    let total_len =
        BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + body.len();

    let mut buf = Vec::with_capacity(total_len);
    write_common_header(
        &mut buf,
        BMP_MSG_STATISTICS_REPORT,
        total_len as u32,
    );
    write_per_peer_header(&mut buf, peer);
    buf.extend_from_slice(body);

    buf
}

/// Build a BMP Route Monitoring message representing an End-of-RIB marker for
/// the given AFI/SAFI.
///
/// For IPv4 unicast, this is the minimum-length BGP UPDATE (no withdrawn,
/// no path attributes, total length 23).
/// For other AFI/SAFIs, this is an MP_UNREACH_NLRI marker with an empty
/// withdrawal list for that family.
pub fn build_end_of_rib_marker(
    peer: &PeerInfo,
    afisafi: AfiSafiType,
) -> Option<Vec<u8>> {
    match afisafi {
        AfiSafiType::Ipv4Unicast => Some(build_eor_ipv4(peer)),
        AfiSafiType::Ipv6Unicast => Some(build_eor_mp_unreach(peer, afisafi)),
        _ => None,
    }
}

/// Build a BGP UPDATE message for a given prefix and path attributes.
///
/// Uses the raw path attributes from RotondaPaMap, filtering out
/// MP_REACH_NLRI (14) and MP_UNREACH_NLRI (15) and reconstructing
/// them as needed.
fn build_bgp_update(
    prefix: Prefix,
    pamap: &RotondaPaMap,
    is_withdrawal: bool,
) -> Option<Vec<u8>> {
    if is_withdrawal {
        // A single-prefix withdrawal is a small, fixed-shape message that
        // can never approach the 2-byte length limit.
        return Some(build_bgp_update_withdrawal(prefix));
    }

    let is_ipv4 = prefix.is_v4();

    // Get raw path attributes (filtering out types 14 and 15) and the
    // original next hop from MP_REACH_NLRI if present.
    let (pa_bytes, orig_next_hop) = filter_raw_path_attributes(pamap);

    if is_ipv4 {
        // For IPv4: put prefix in NLRI field
        let nlri_bytes = encode_prefix_nlri(prefix);
        let update_body_len = 2 + 2 + pa_bytes.len() + nlri_bytes.len();
        let total_len = 19 + update_body_len;

        if total_len > u16::MAX as usize {
            return bgp_update_too_long(prefix, total_len);
        }

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push(BGP_MSG_UPDATE);

        buf.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length = 0
        buf.extend_from_slice(&(pa_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&pa_bytes);
        buf.extend_from_slice(&nlri_bytes);

        Some(buf)
    } else {
        // For IPv6: add MP_REACH_NLRI (type 14) with the original next hop
        let mp_reach = build_mp_reach_nlri(prefix, orig_next_hop.as_deref());
        let total_pa_len = pa_bytes.len() + mp_reach.len();

        let update_body_len = 2 + 2 + total_pa_len;
        let total_len = 19 + update_body_len;

        if total_len > u16::MAX as usize {
            return bgp_update_too_long(prefix, total_len);
        }

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push(BGP_MSG_UPDATE);

        buf.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length = 0
        buf.extend_from_slice(&(total_pa_len as u16).to_be_bytes());
        buf.extend_from_slice(&pa_bytes);
        buf.extend_from_slice(&mp_reach);

        Some(buf)
    }
}

/// A re-encoded BGP UPDATE whose total length would not fit the 2-byte BGP
/// length field. Emitting it (with `total_len as u16` silently truncated)
/// would desynchronize the downstream consumer's BMP/BGP framing for the rest
/// of the stream, so drop the route instead. Reachable only with an unusually
/// large (~65 KB) single-route attribute set, e.g. from an MRT feed.
fn bgp_update_too_long(prefix: Prefix, total_len: usize) -> Option<Vec<u8>> {
    log::warn!(
        "bmp-out: dropping route for {prefix}: re-encoded BGP UPDATE length \
         {total_len} exceeds the 2-byte BGP length field; emitting it would \
         corrupt the BMP stream framing"
    );
    debug_assert!(total_len <= u16::MAX as usize);
    None
}

/// Filter raw path attributes from RotondaPaMap, removing types 14 and 15.
///
/// RotondaPaMap stores raw bytes as: [RpkiInfo(1), PduParseInfo(1), pa_blob...]
/// The pa_blob is a sequence of BGP path attributes in wire format.
///
/// Returns the filtered path attributes and, if found, the next hop bytes
/// extracted from the original MP_REACH_NLRI (type 14).
fn filter_raw_path_attributes(
    pamap: &RotondaPaMap,
) -> (Vec<u8>, Option<Vec<u8>>) {
    filter_pa_from_raw(pamap.as_ref())
}

/// As [`filter_raw_path_attributes`] but operating directly on the raw
/// `RotondaPaMap` bytes (`[rpki, ppi, pa_blob...]`). Lets the dump aggregator
/// recompute the filtered attributes from a held `Arc<[u8]>` at emit time
/// instead of caching a second copy per open group.
fn filter_pa_from_raw(raw: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    if raw.len() < 2 {
        return (Vec::new(), None);
    }

    let pa_blob = &raw[2..];
    let mut result = Vec::with_capacity(pa_blob.len());
    let mut next_hop = None;
    let mut pos = 0;

    while pos < pa_blob.len() {
        if pos + 2 > pa_blob.len() {
            break;
        }

        let flags = pa_blob[pos];
        let type_code = pa_blob[pos + 1];

        // Determine attribute length
        let (attr_len, header_len) = if flags & 0x10 != 0 {
            // Extended length (2 bytes)
            if pos + 4 > pa_blob.len() {
                break;
            }
            let len = u16::from_be_bytes([pa_blob[pos + 2], pa_blob[pos + 3]])
                as usize;
            (len, 4)
        } else {
            // Regular length (1 byte)
            if pos + 3 > pa_blob.len() {
                break;
            }
            (pa_blob[pos + 2] as usize, 3)
        };

        let total_attr_len = header_len + attr_len;

        if pos + total_attr_len > pa_blob.len() {
            break;
        }

        if type_code == 14 {
            // MP_REACH_NLRI: extract the next hop before discarding.
            // Wire format of the value: AFI(2) + SAFI(1) + NH_LEN(1) + NH(NH_LEN) + ...
            let value_start = pos + header_len;
            let value = &pa_blob[value_start..pos + total_attr_len];
            if value.len() >= 4 {
                let nh_len = value[3] as usize;
                if value.len() >= 4 + nh_len {
                    next_hop = Some(value[4..4 + nh_len].to_vec());
                }
            }
        } else if type_code != 15 {
            // Keep everything except MP_REACH_NLRI (14) and MP_UNREACH_NLRI (15)
            result.extend_from_slice(&pa_blob[pos..pos + total_attr_len]);
        }

        pos += total_attr_len;
    }

    (result, next_hop)
}

/// Build a BGP UPDATE withdrawal message.
fn build_bgp_update_withdrawal(prefix: Prefix) -> Vec<u8> {
    if prefix.is_v4() {
        let nlri_bytes = encode_prefix_nlri(prefix);
        let update_body_len = 2 + nlri_bytes.len() + 2;
        let total_len = 19 + update_body_len;

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push(BGP_MSG_UPDATE);

        buf.extend_from_slice(&(nlri_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&nlri_bytes);
        buf.extend_from_slice(&0u16.to_be_bytes()); // PA Length = 0

        buf
    } else {
        let mp_unreach = build_mp_unreach_nlri(prefix);
        let update_body_len = 2 + 2 + mp_unreach.len();
        let total_len = 19 + update_body_len;

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push(BGP_MSG_UPDATE);

        buf.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn = 0
        buf.extend_from_slice(&(mp_unreach.len() as u16).to_be_bytes());
        buf.extend_from_slice(&mp_unreach);

        buf
    }
}

/// Append a prefix encoded as BGP NLRI (prefix length byte + prefix bytes)
/// to `buf`. Shared by the single- and multi-prefix encoders.
fn append_prefix_nlri(buf: &mut Vec<u8>, prefix: Prefix) {
    let prefix_len = prefix.len();
    let num_bytes = ((prefix_len as usize) + 7) / 8;

    buf.push(prefix_len);

    match prefix.addr() {
        IpAddr::V4(v4) => {
            buf.extend_from_slice(&v4.octets()[..num_bytes]);
        }
        IpAddr::V6(v6) => {
            buf.extend_from_slice(&v6.octets()[..num_bytes]);
        }
    }
}

/// Encode a prefix as BGP NLRI (prefix length byte + prefix bytes).
fn encode_prefix_nlri(prefix: Prefix) -> Vec<u8> {
    let num_bytes = ((prefix.len() as usize) + 7) / 8;
    let mut buf = Vec::with_capacity(1 + num_bytes);
    append_prefix_nlri(&mut buf, prefix);
    buf
}

/// Wire length of a prefix encoded as BGP NLRI (length byte + significant
/// prefix bytes), without allocating.
fn nlri_encoded_len(prefix: Prefix) -> usize {
    1 + ((prefix.len() as usize) + 7) / 8
}

fn build_eor_ipv4(peer: &PeerInfo) -> Vec<u8> {
    // Minimal BGP UPDATE: marker(16) + length(2) + type(1) + withdrawn_len(2) + pa_len(2) = 23
    let bgp_update_len: usize = 23;
    let total_len =
        BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + bgp_update_len;
    let mut buf = Vec::with_capacity(total_len);
    write_common_header(&mut buf, BMP_MSG_ROUTE_MONITORING, total_len as u32);
    write_per_peer_header(&mut buf, peer);
    // BGP UPDATE header
    buf.extend_from_slice(&BGP_MARKER);
    buf.extend_from_slice(&(bgp_update_len as u16).to_be_bytes());
    buf.push(BGP_MSG_UPDATE);
    // BGP UPDATE body (empty = IPv4 Unicast EoR)
    buf.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length = 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // Path Attribute Length = 0
    buf
}

fn build_eor_mp_unreach(peer: &PeerInfo, afisafi: AfiSafiType) -> Vec<u8> {
    let (afi, safi) = afisafi.into();

    let mut mp_unreach = Vec::with_capacity(6);
    mp_unreach.push(0x80); // Optional
    mp_unreach.push(15); // MP_UNREACH_NLRI
    mp_unreach.push(3); // Length: AFI(2) + SAFI(1)
    mp_unreach.extend_from_slice(&afi.to_be_bytes());
    mp_unreach.push(safi);

    let total_pa_len = mp_unreach.len();
    let update_body_len = 2 + 2 + total_pa_len; // withdrawn_len(2) + pa_len(2) + PA data
    let bgp_update_len = 19 + update_body_len; // BGP header(19) + body
    let total_len =
        BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + bgp_update_len;
    let mut buf = Vec::with_capacity(total_len);
    write_common_header(&mut buf, BMP_MSG_ROUTE_MONITORING, total_len as u32);
    write_per_peer_header(&mut buf, peer);
    // BGP UPDATE header
    buf.extend_from_slice(&BGP_MARKER);
    buf.extend_from_slice(&(bgp_update_len as u16).to_be_bytes());
    buf.push(BGP_MSG_UPDATE);
    // BGP UPDATE body
    buf.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length = 0
    buf.extend_from_slice(&(total_pa_len as u16).to_be_bytes());
    buf.extend_from_slice(&mp_unreach);
    buf
}

/// Build MP_REACH_NLRI path attribute.
///
/// `next_hop` is the raw next hop bytes extracted from the original
/// MP_REACH_NLRI. If not available, falls back to a zeroed next hop
/// of the appropriate length (4 for IPv4, 16 for IPv6).
fn build_mp_reach_nlri(prefix: Prefix, next_hop: Option<&[u8]>) -> Vec<u8> {
    let nlri_bytes = encode_prefix_nlri(prefix);

    let afi: u16 = if prefix.is_v4() { 1 } else { 2 };
    let safi: u8 = 1; // Unicast

    let default_nh: Vec<u8>;
    let nh = match next_hop {
        Some(nh) => nh,
        None => {
            let len = if prefix.is_v4() { 4 } else { 16 };
            default_nh = vec![0u8; len];
            &default_nh
        }
    };
    let next_hop_len = nh.len() as u8;

    let value_len = 2 + 1 + 1 + nh.len() + 1 + nlri_bytes.len();

    let mut buf = Vec::new();
    if value_len > 255 {
        buf.push(0x90); // Optional, Transitive, Extended Length
        buf.push(14);
        buf.extend_from_slice(&(value_len as u16).to_be_bytes());
    } else {
        buf.push(0x80); // Optional, Transitive
        buf.push(14);
        buf.push(value_len as u8);
    }

    buf.extend_from_slice(&afi.to_be_bytes());
    buf.push(safi);
    buf.push(next_hop_len);
    buf.extend_from_slice(nh);
    buf.push(0); // Reserved
    buf.extend_from_slice(&nlri_bytes);

    buf
}

/// Build MP_UNREACH_NLRI path attribute for IPv6 withdrawal.
fn build_mp_unreach_nlri(prefix: Prefix) -> Vec<u8> {
    let nlri_bytes = encode_prefix_nlri(prefix);

    let afi: u16 = if prefix.is_v4() { 1 } else { 2 };
    let safi: u8 = 1;

    let value_len = 2 + 1 + nlri_bytes.len();

    let mut buf = Vec::new();
    if value_len > 255 {
        buf.push(0x90);
        buf.push(15);
        buf.extend_from_slice(&(value_len as u16).to_be_bytes());
    } else {
        buf.push(0x80);
        buf.push(15);
        buf.push(value_len as u8);
    }

    buf.extend_from_slice(&afi.to_be_bytes());
    buf.push(safi);
    buf.extend_from_slice(&nlri_bytes);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_initiation_message() {
        let msg = build_initiation_message("test-router", "Test BMP out");

        assert_eq!(msg[0], 3); // Version
        assert_eq!(msg[5], 4); // Type = Initiation

        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len as usize, msg.len());
    }

    #[test]
    fn test_build_termination_message() {
        let msg = build_termination_message();

        assert_eq!(msg[0], 3); // Version
        assert_eq!(msg[5], 5); // Type = Termination

        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len as usize, msg.len());
    }

    #[test]
    fn test_build_peer_up() {
        let peer = PeerInfo {
            peer_type: PeerType::GlobalInstance,
            peer_flags: 0x40,
            peer_distinguisher: [0u8; 8],
            peer_address: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: Asn::from_u32(65000),
            peer_bgp_id: [0u8; 4],
            admin_label: None,
        };

        let msg = build_peer_up(&peer, true);

        assert_eq!(msg[0], 3); // Version
        assert_eq!(msg[5], 3); // Type = Peer Up

        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len as usize, msg.len());
    }

    #[test]
    fn test_build_statistics_report() {
        let peer = PeerInfo {
            peer_type: PeerType::GlobalInstance,
            peer_flags: 0x40,
            peer_distinguisher: [0u8; 8],
            peer_address: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: Asn::from_u32(65000),
            peer_bgp_id: [0u8; 4],
            admin_label: None,
        };

        // One stat TLV: type=0 (rejected prefixes), len=4, value=0x000000AA.
        let body: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, // stats count = 1
            0x00, 0x00, // stat type = 0
            0x00, 0x04, // stat length = 4
            0x00, 0x00, 0x00, 0xAA, // stat value
        ];
        let msg = build_statistics_report(&peer, body);

        assert_eq!(msg[0], 3); // Version
        assert_eq!(msg[5], 1); // Type = Statistics Report

        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len as usize, msg.len());
        assert_eq!(
            msg.len(),
            BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + body.len()
        );

        // Body must be appended verbatim after common + per-peer header.
        let body_offset = BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN;
        assert_eq!(&msg[body_offset..], body);
    }

    #[test]
    fn test_build_peer_down() {
        let peer = PeerInfo {
            peer_type: PeerType::GlobalInstance,
            peer_flags: 0x40,
            peer_distinguisher: [0u8; 8],
            peer_address: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: Asn::from_u32(65000),
            peer_bgp_id: [0u8; 4],
            admin_label: None,
        };

        let msg = build_peer_down(&peer);

        assert_eq!(msg[0], 3); // Version
        assert_eq!(msg[5], 2); // Type = Peer Down

        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len as usize, msg.len());

        assert_eq!(*msg.last().unwrap(), 4); // Reason code
    }

    #[test]
    fn test_encode_prefix_nlri_v4() {
        let prefix =
            Prefix::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0)), 24)
                .unwrap();

        let bytes = encode_prefix_nlri(prefix);
        assert_eq!(bytes[0], 24);
        assert_eq!(bytes[1..], [10, 0, 0]);
    }

    #[test]
    fn test_encode_prefix_nlri_v4_host() {
        let prefix = Prefix::new(
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            32,
        )
        .unwrap();

        let bytes = encode_prefix_nlri(prefix);
        assert_eq!(bytes[0], 32);
        assert_eq!(bytes[1..], [192, 168, 1, 1]);
    }

    #[test]
    fn test_filter_raw_path_attributes_empty() {
        let pamap = RotondaPaMap::default();
        let (result, next_hop) = filter_raw_path_attributes(&pamap);
        assert!(result.is_empty());
        assert!(next_hop.is_none());
    }

    #[test]
    fn test_bgp_open_contains_graceful_restart() {
        // IPv4-only peer
        let open = build_bgp_open(Asn::from_u32(65000), false, true);
        // Find GR capability (code 64) in the capabilities
        let bgp_body = &open[19..]; // skip marker(16) + length(2) + type(1)
        let opt_params_len = bgp_body[9] as usize;
        let opt_params = &bgp_body[10..10 + opt_params_len];
        // opt_params: type(1) + len(1) + capabilities...
        assert_eq!(opt_params[0], 2); // Parameter Type = Capabilities
        let caps = &opt_params[2..];
        let mut found_gr = false;
        let mut pos = 0;
        while pos < caps.len() {
            let cap_code = caps[pos];
            let cap_len = caps[pos + 1] as usize;
            if cap_code == 64 {
                found_gr = true;
                // For IPv4-only: 2 (restart flags/time) + 4 (one AFI/SAFI) = 6
                assert_eq!(cap_len, 6);
            }
            pos += 2 + cap_len;
        }
        assert!(
            found_gr,
            "Graceful Restart capability not found in BGP OPEN"
        );

        // IPv6 peer
        let open_v6 = build_bgp_open(Asn::from_u32(65000), true, true);
        let bgp_body = &open_v6[19..];
        let opt_params_len = bgp_body[9] as usize;
        let opt_params = &bgp_body[10..10 + opt_params_len];
        let caps = &opt_params[2..];
        let mut pos = 0;
        while pos < caps.len() {
            let cap_code = caps[pos];
            let cap_len = caps[pos + 1] as usize;
            if cap_code == 64 {
                // For IPv6: 2 (restart flags/time) + 4*2 (two AFI/SAFIs) = 10
                assert_eq!(cap_len, 10);
            }
            pos += 2 + cap_len;
        }
    }

    #[test]
    fn test_bgp_open_can_omit_graceful_restart() {
        let open = build_bgp_open(Asn::from_u32(65000), true, false);
        let bgp_body = &open[19..];
        let opt_params_len = bgp_body[9] as usize;
        let opt_params = &bgp_body[10..10 + opt_params_len];
        let caps = &opt_params[2..];

        let mut pos = 0;
        while pos < caps.len() {
            let cap_code = caps[pos];
            let cap_len = caps[pos + 1] as usize;
            assert_ne!(cap_code, 64);
            pos += 2 + cap_len;
        }
    }

    #[test]
    fn test_eor_ipv4_is_valid_bgp_update() {
        let peer = PeerInfo {
            peer_type: PeerType::GlobalInstance,
            peer_flags: 0x40,
            peer_distinguisher: [0u8; 8],
            peer_address: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: Asn::from_u32(65000),
            peer_bgp_id: [0u8; 4],
            admin_label: None,
        };

        let msg = build_eor_ipv4(&peer);
        let total_len = BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + 23;
        assert_eq!(msg.len(), total_len);

        // Verify the BGP UPDATE portion
        let bgp_offset = BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN;
        let bgp_msg = &msg[bgp_offset..];
        // Marker: 16 bytes of 0xFF
        assert_eq!(&bgp_msg[..16], &[0xFF; 16]);
        // Length: 23
        let bgp_len = u16::from_be_bytes([bgp_msg[16], bgp_msg[17]]);
        assert_eq!(bgp_len, 23);
        // Type: UPDATE
        assert_eq!(bgp_msg[18], BGP_MSG_UPDATE);
        // Withdrawn Routes Length: 0
        assert_eq!(u16::from_be_bytes([bgp_msg[19], bgp_msg[20]]), 0);
        // Path Attribute Length: 0
        assert_eq!(u16::from_be_bytes([bgp_msg[21], bgp_msg[22]]), 0);
    }

    #[test]
    fn test_eor_ipv6_has_mp_unreach_nlri() {
        let peer = PeerInfo {
            peer_type: PeerType::GlobalInstance,
            peer_flags: 0xC0, // V + L flags
            peer_distinguisher: [0u8; 8],
            peer_address: IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
            )),
            peer_asn: Asn::from_u32(65000),
            peer_bgp_id: [0u8; 4],
            admin_label: None,
        };

        let msg = build_eor_mp_unreach(&peer, AfiSafiType::Ipv6Unicast);

        // Verify the BGP UPDATE portion
        let bgp_offset = BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN;
        let bgp_msg = &msg[bgp_offset..];
        // Marker
        assert_eq!(&bgp_msg[..16], &[0xFF; 16]);
        // Type: UPDATE
        assert_eq!(bgp_msg[18], BGP_MSG_UPDATE);
        // Withdrawn Routes Length: 0
        assert_eq!(u16::from_be_bytes([bgp_msg[19], bgp_msg[20]]), 0);
        // Path Attribute Length
        let pa_len = u16::from_be_bytes([bgp_msg[21], bgp_msg[22]]) as usize;
        assert_eq!(pa_len, 6); // MP_UNREACH_NLRI: flags(1) + type(1) + len(1) + AFI(2) + SAFI(1)
                               // MP_UNREACH_NLRI attribute
        assert_eq!(bgp_msg[23], 0x80); // Flags: Optional
        assert_eq!(bgp_msg[24], 15); // Type: MP_UNREACH_NLRI
        assert_eq!(bgp_msg[25], 3); // Length: AFI(2) + SAFI(1)
                                    // AFI = 2 (IPv6)
        assert_eq!(u16::from_be_bytes([bgp_msg[26], bgp_msg[27]]), 2);
        // SAFI = 1 (Unicast)
        assert_eq!(bgp_msg[28], 1);
    }

    #[test]
    fn test_escape_json_string() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(escape_json_string("back\\slash"), "back\\\\slash");
        assert_eq!(escape_json_string("line\nbreak"), "line\\nbreak");
        assert_eq!(escape_json_string("tab\there"), "tab\\there");
        assert_eq!(escape_json_string("cr\rhere"), "cr\\rhere");
        // Control character (bell)
        assert_eq!(escape_json_string("bell\x07"), "bell\\u0007");
    }

    #[test]
    fn test_build_admin_label_json() {
        // Both present
        let json = build_admin_label_json(Some("router1"), Some("Cisco IOS"));
        assert_eq!(
            json.unwrap(),
            r#"{"sysName":"router1","sysDescr":"Cisco IOS"}"#
        );

        // Only name
        let json = build_admin_label_json(Some("router1"), None);
        assert_eq!(json.unwrap(), r#"{"sysName":"router1"}"#);

        // Only desc
        let json = build_admin_label_json(None, Some("Cisco IOS"));
        assert_eq!(json.unwrap(), r#"{"sysDescr":"Cisco IOS"}"#);

        // Both absent
        assert!(build_admin_label_json(None, None).is_none());

        // Placeholder values filtered
        assert!(build_admin_label_json(
            Some("no-sysname"),
            Some("no-sysdesc")
        )
        .is_none());

        // Name with special characters
        let json = build_admin_label_json(Some(r#"rtr "A""#), None);
        assert_eq!(json.unwrap(), r#"{"sysName":"rtr \"A\""}"#);
    }

    #[test]
    fn test_build_peer_up_with_admin_label() {
        let peer = PeerInfo {
            peer_type: PeerType::GlobalInstance,
            peer_flags: 0x40,
            peer_distinguisher: [0u8; 8],
            peer_address: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: Asn::from_u32(65000),
            peer_bgp_id: [0u8; 4],
            admin_label: Some(r#"{"sysName":"router1"}"#.to_string()),
        };

        let msg = build_peer_up(&peer, true);

        assert_eq!(msg[0], 3); // Version
        assert_eq!(msg[5], 3); // Type = Peer Up

        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len as usize, msg.len());

        // Find the Admin Label TLV at the end of the message.
        // The TLV value is the JSON string.
        let label = r#"{"sysName":"router1"}"#;
        let tlv_offset = msg.len() - 4 - label.len();
        // Type = 4
        assert_eq!(
            u16::from_be_bytes([msg[tlv_offset], msg[tlv_offset + 1]]),
            4
        );
        // Length
        assert_eq!(
            u16::from_be_bytes([msg[tlv_offset + 2], msg[tlv_offset + 3]]),
            label.len() as u16
        );
        // Value
        assert_eq!(&msg[tlv_offset + 4..], label.as_bytes());
    }

    /// Extract the 8-byte peer_distinguisher from a BMP message that
    /// carries a per-peer header (RouteMonitoring, PeerUp, PeerDown,
    /// StatsReport). Layout: common header (6 bytes) + peer_type (1) +
    /// peer_flags (1) + peer_distinguisher (8) + ...
    fn pd_from_msg(msg: &[u8]) -> [u8; 8] {
        let off = BMP_COMMON_HEADER_LEN + 2;
        msg[off..off + 8].try_into().expect("pd slice")
    }

    fn make_peer(pd: [u8; 8]) -> PeerInfo {
        PeerInfo {
            peer_type: PeerType::GlobalInstance,
            peer_flags: 0x40,
            peer_distinguisher: pd,
            peer_address: IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0x7f8, 0x6c, 0, 0, 0, 0, 0x230,
            )),
            peer_asn: Asn::from_u32(6939),
            peer_bgp_id: [0u8; 4],
            admin_label: None,
        }
    }

    #[test]
    fn fan_in_tag_is_non_zero_and_stable() {
        let t1a = fan_in_distinguisher_tag(7);
        let t1b = fan_in_distinguisher_tag(7);
        assert_eq!(
            t1a, t1b,
            "tag must be deterministic for same parent IngressId"
        );
        assert_ne!(t1a, [0u8; 8], "tag must never be zero");
    }

    #[test]
    fn fan_in_tag_differs_per_parent() {
        // Many adjacent IngressIds; assert no pairwise collisions in the
        // small space we care about. A 64-bit SipHash should not collide
        // for the first thousand consecutive u32 inputs.
        let mut tags: Vec<[u8; 8]> =
            (1..=64).map(fan_in_distinguisher_tag).collect();
        tags.sort();
        let original_len = tags.len();
        tags.dedup();
        assert_eq!(
            tags.len(),
            original_len,
            "fan-in tags collided across distinct parent IngressIds"
        );
    }

    #[test]
    fn apply_fan_in_only_stamps_zero_pd() {
        // Inbound pd=0: tag is applied.
        let tag = fan_in_distinguisher_tag(42);
        let mut p = make_peer([0u8; 8]);
        p.apply_fan_in_distinguisher(tag);
        assert_eq!(p.peer_distinguisher, tag);

        // Inbound pd already non-zero (real RD/VRF): tag is NOT applied.
        let real_rd = [1, 2, 3, 4, 9, 9, 9, 9];
        let mut p = make_peer(real_rd);
        p.apply_fan_in_distinguisher(tag);
        assert_eq!(
            p.peer_distinguisher, real_rd,
            "must not overwrite real RD"
        );
    }

    #[test]
    fn fan_in_two_upstreams_same_peer_produce_different_pd_on_wire() {
        // Spec acceptance test #1: two fake upstream BMP sessions, each
        // with a PeerUp for the same (peer_ip, peer_asn). Resulting
        // per-peer headers must carry two different non-zero
        // peer_distinguisher values.
        let tag_a = fan_in_distinguisher_tag(101);
        let tag_b = fan_in_distinguisher_tag(202);
        assert_ne!(tag_a, tag_b);
        assert_ne!(tag_a, [0u8; 8]);
        assert_ne!(tag_b, [0u8; 8]);

        let mut peer_a = make_peer([0u8; 8]);
        peer_a.apply_fan_in_distinguisher(tag_a);

        let mut peer_b = make_peer([0u8; 8]);
        peer_b.apply_fan_in_distinguisher(tag_b);

        let msg_a = build_peer_up(&peer_a, false);
        let msg_b = build_peer_up(&peer_b, false);

        let pd_a = pd_from_msg(&msg_a);
        let pd_b = pd_from_msg(&msg_b);

        assert_eq!(pd_a, tag_a);
        assert_eq!(pd_b, tag_b);
        assert_ne!(pd_a, pd_b);
        assert_ne!(pd_a, [0u8; 8]);
    }

    #[test]
    fn fan_in_pd_consistent_across_message_types_for_one_upstream() {
        // Spec acceptance test #2: RouteMonitoring carries the same tag
        // as PeerUp, and PeerDown carries the matching tag.
        let tag = fan_in_distinguisher_tag(303);
        let mut peer = make_peer([0u8; 8]);
        peer.apply_fan_in_distinguisher(tag);

        let pd_peer_up = pd_from_msg(&build_peer_up(&peer, false));
        let pd_peer_down = pd_from_msg(&build_peer_down(&peer));
        let pd_eor =
            pd_from_msg(&build_eor_ipv4(&peer));
        let pd_eor6 = pd_from_msg(&build_eor_mp_unreach(
            &peer,
            AfiSafiType::Ipv6Unicast,
        ));
        let pd_stats = pd_from_msg(&build_statistics_report(
            &peer,
            &[0u8, 0, 0, 0],
        ));

        assert_eq!(pd_peer_up, tag);
        assert_eq!(pd_peer_down, tag);
        assert_eq!(pd_eor, tag);
        assert_eq!(pd_eor6, tag);
        assert_eq!(pd_stats, tag);
    }

    #[test]
    fn fan_in_preserves_inbound_non_zero_pd_on_wire() {
        // Spec acceptance test #3: an inbound peer whose own
        // peer_distinguisher is already non-zero (real RD context)
        // passes through unmodified even when fan-in tagging is on.
        let real_rd = [0u8, 1, 0, 0xfd, 0xe9, 0, 0, 1];
        let tag = fan_in_distinguisher_tag(404);
        let mut peer = make_peer(real_rd);
        peer.apply_fan_in_distinguisher(tag);

        assert_eq!(peer.peer_distinguisher, real_rd);
        assert_eq!(pd_from_msg(&build_peer_up(&peer, false)), real_rd);
        assert_eq!(pd_from_msg(&build_peer_down(&peer)), real_rd);
    }

    fn agg_test_peer() -> PeerInfo {
        PeerInfo {
            peer_type: PeerType::GlobalInstance,
            peer_flags: 0,
            peer_distinguisher: [0u8; 8],
            peer_address: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: Asn::from_u32(65000),
            peer_bgp_id: [0u8; 4],
            admin_label: None,
        }
    }

    /// An aggregated IPv4 message packs every prefix's NLRI into one BGP
    /// UPDATE behind a single shared attribute block, with self-consistent
    /// length fields and within the BGP size limit.
    #[test]
    fn aggregated_v4_packs_multiple_nlri() {
        let peer = agg_test_peer();
        let pamap = RotondaPaMap::from(vec![0x40, 1, 1, 0]); // ORIGIN=IGP
        let (pa_bytes, nh) = filter_raw_path_attributes(&pamap);
        let prefixes = vec![
            Prefix::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 0, 0)), 24)
                .unwrap(),
            Prefix::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, 0)), 24)
                .unwrap(),
            Prefix::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 3, 0, 0)), 16)
                .unwrap(),
        ];
        let msg = build_aggregated_route_monitoring(
            &peer, &prefixes, &pa_bytes, nh.as_deref(), true,
        );

        assert_eq!(msg[0], BMP_VERSION);
        assert_eq!(msg[5], BMP_MSG_ROUTE_MONITORING);
        let bmp_len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(bmp_len as usize, msg.len());

        let bgp = &msg[BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN..];
        let bgp_len = u16::from_be_bytes([bgp[16], bgp[17]]) as usize;
        assert_eq!(bgp_len, bgp.len());
        assert_eq!(bgp[18], BGP_MSG_UPDATE);
        assert_eq!(u16::from_be_bytes([bgp[19], bgp[20]]), 0); // Withdrawn=0
        let pa_len = u16::from_be_bytes([bgp[21], bgp[22]]) as usize;
        assert_eq!(pa_len, pa_bytes.len());
        // NLRI: (1+3) + (1+3) + (1+2) = 11 bytes for the three prefixes.
        let nlri = &bgp[23 + pa_len..];
        assert_eq!(nlri.len(), 11);
        assert_eq!(nlri[0], 24);
        assert!(bgp_len <= MAX_BGP_UPDATE_LEN);
    }

    /// The aggregator splits into a new message at the BGP UPDATE size limit,
    /// never exceeds it, accounts for every route, and actually aggregates.
    #[test]
    fn aggregator_respects_update_size_limit() {
        let peer = agg_test_peer();
        let pamap = RotondaPaMap::from(vec![0x40, 1, 1, 0]);
        let mut messages: Vec<(Vec<u8>, usize)> = Vec::new();
        let mut peer_map: HashMap<IngressId, PeerInfo> = HashMap::new();
        peer_map.insert(7, peer.clone());
        let mut agg =
            RouteAggregator::new(64 * 1024 * 1024, peer_map);
        {
            let mut sink = |m: Vec<u8>, n: usize| {
                messages.push((m, n));
                true
            };
            for i in 0..5000u32 {
                let p = Prefix::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        100,
                        (i >> 8) as u8,
                        (i & 0xff) as u8,
                        0,
                    )),
                    24,
                )
                .unwrap();
                assert!(agg.add(7, p, &pamap, &mut sink));
            }
            assert!(agg.flush_all(&mut sink));
        }

        let mut total_routes = 0usize;
        for (m, n) in &messages {
            total_routes += n;
            let bgp = &m[BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN..];
            let bgp_len = u16::from_be_bytes([bgp[16], bgp[17]]) as usize;
            assert_eq!(bgp_len, bgp.len());
            assert!(bgp_len <= MAX_BGP_UPDATE_LEN);
        }
        assert_eq!(total_routes, 5000);
        assert!(messages.len() < 100, "expected heavy aggregation");
    }

    /// Under a tiny budget the aggregator must evict (fullest-first) yet still
    /// deliver every route exactly once, with each message within the size
    /// limit — i.e. it degrades gracefully rather than losing or duplicating
    /// routes.
    #[test]
    fn aggregator_tiny_budget_loses_no_routes() {
        let peer = agg_test_peer();
        // Two distinct attribute sets so multiple groups coexist.
        let pamap_a = RotondaPaMap::from(vec![0x40, 1, 1, 0]); // ORIGIN IGP
        let pamap_b = RotondaPaMap::from(vec![0x40, 1, 1, 2]); // ORIGIN INCOMPLETE
        let mut peer_map: HashMap<IngressId, PeerInfo> = HashMap::new();
        peer_map.insert(7, peer.clone());
        // Budget of 1 KiB forces frequent eviction.
        let mut agg = RouteAggregator::new(1024, peer_map);
        let mut total = 0usize;
        let mut evicted_within_limit = true;
        {
            let mut sink = |m: Vec<u8>, n: usize| {
                total += n;
                let bgp =
                    &m[BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN..];
                let bgp_len =
                    u16::from_be_bytes([bgp[16], bgp[17]]) as usize;
                if bgp_len != bgp.len() || bgp_len > MAX_BGP_UPDATE_LEN {
                    evicted_within_limit = false;
                }
                true
            };
            for i in 0..2000u32 {
                let p = Prefix::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        172,
                        (i >> 8) as u8,
                        (i & 0xff) as u8,
                        0,
                    )),
                    24,
                )
                .unwrap();
                let pamap = if i % 2 == 0 { &pamap_a } else { &pamap_b };
                assert!(agg.add(7, p, pamap, &mut sink));
            }
            assert!(agg.flush_all(&mut sink));
        }
        assert_eq!(total, 2000);
        assert!(evicted_within_limit);
        // The budget was small enough that eviction actually fired.
        assert!(agg.stats().1 > 0, "expected budget evictions to occur");
    }
}
