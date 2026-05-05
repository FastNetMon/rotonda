/// BMP message construction at byte level (RFC 7854).
///
/// Since routecore 0.6 has BMP parsing but no builder, we construct
/// messages directly from bytes.
use std::net::IpAddr;

use inetnum::addr::Prefix;
use inetnum::asn::Asn;
use routecore::bgp::nlri::afisafi::IsPrefix;
use routecore::bgp::types::AfiSafiType;
use routecore::bmp::message::PeerType;

use crate::ingress::IngressInfo;
use crate::payload::{RotondaPaMap, RotondaRoute};

// BMP message types (RFC 7854 Section 4.1)
const BMP_MSG_ROUTE_MONITORING: u8 = 0;
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

        // Peer flags: bit 7 = IPv6 (V), bit 6 = post-policy (L), bit 5 = adj-rib-out (A)
        let mut peer_flags = 0u8;
        if peer_address.is_ipv6() {
            peer_flags |= 0x80; // V flag
        }
        // Default to post-policy for BMP restreaming
        peer_flags |= 0x40; // L flag

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
) -> Vec<u8> {
    let bgp_update = build_bgp_update(prefix, pamap, is_withdrawal);
    let total_len =
        BMP_COMMON_HEADER_LEN + BMP_PER_PEER_HEADER_LEN + bgp_update.len();

    let mut buf = Vec::with_capacity(total_len);
    write_common_header(&mut buf, BMP_MSG_ROUTE_MONITORING, total_len as u32);
    write_per_peer_header(&mut buf, peer);
    buf.extend_from_slice(&bgp_update);

    buf
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

    Some(build_route_monitoring(peer, prefix, pamap, is_withdrawal))
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
) -> Vec<u8> {
    if is_withdrawal {
        return build_bgp_update_withdrawal(prefix);
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

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push(BGP_MSG_UPDATE);

        buf.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length = 0
        buf.extend_from_slice(&(pa_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&pa_bytes);
        buf.extend_from_slice(&nlri_bytes);

        buf
    } else {
        // For IPv6: add MP_REACH_NLRI (type 14) with the original next hop
        let mp_reach = build_mp_reach_nlri(prefix, orig_next_hop.as_deref());
        let total_pa_len = pa_bytes.len() + mp_reach.len();

        let update_body_len = 2 + 2 + total_pa_len;
        let total_len = 19 + update_body_len;

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.push(BGP_MSG_UPDATE);

        buf.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length = 0
        buf.extend_from_slice(&(total_pa_len as u16).to_be_bytes());
        buf.extend_from_slice(&pa_bytes);
        buf.extend_from_slice(&mp_reach);

        buf
    }
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
    let raw = pamap.as_ref();
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

/// Encode a prefix as BGP NLRI (prefix length byte + prefix bytes).
fn encode_prefix_nlri(prefix: Prefix) -> Vec<u8> {
    let prefix_len = prefix.len();
    let num_bytes = ((prefix_len as usize) + 7) / 8;

    let mut buf = Vec::with_capacity(1 + num_bytes);
    buf.push(prefix_len);

    match prefix.addr() {
        IpAddr::V4(v4) => {
            buf.extend_from_slice(&v4.octets()[..num_bytes]);
        }
        IpAddr::V6(v6) => {
            buf.extend_from_slice(&v6.octets()[..num_bytes]);
        }
    }

    buf
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
}
