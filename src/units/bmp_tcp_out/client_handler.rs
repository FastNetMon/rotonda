use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use rotonda_store::prefix_record::RouteStatus;

use crate::{
    ingress::{
        self, http_ng::QueryFilter, register::IngressState, IngressId,
        IngressInfo, IngressType,
    },
    payload::{Payload, RotondaRoute, Update},
    units::rib_unit::rib::Rib,
};
use routecore::bgp::types::AfiSafiType;

use super::{
    bmp_builder::{self, PeerInfo},
    client_state::{ClientPhase, ClientState},
    metrics::BmpTcpOutMetrics,
    status_reporter::BmpTcpOutStatusReporter,
};

/// Look up the parent (router-level) IngressInfo for a peer and build a
/// JSON Admin Label string from its sysName/sysDescr.
fn resolve_admin_label(
    info: &IngressInfo,
    ingress_register: &register::Register,
    forward_router_info: bool,
) -> Option<String> {
    if !forward_router_info {
        return None;
    }
    let parent_id = info.parent_ingress?;
    let parent = ingress_register.get(parent_id)?;
    bmp_builder::build_admin_label_json(
        parent.name.as_deref(),
        parent.desc.as_deref(),
    )
}

/// Perform the initial table dump for a newly connected BMP client.
///
/// Uses a two-phase approach for fast dumps with many peers:
/// 1. BMP Initiation Message
/// 2. Peer Up for ALL active peers
/// 3. Single RIB walk sending all routes for all peers (interleaved)
/// 4. End-of-RIB markers for all peers
/// 5. Drains any buffered updates that arrived during dump
/// 6. Transitions client to Live phase
pub async fn perform_initial_dump(
    client: &Arc<ClientState>,
    rib: &Arc<Rib>,
    ingress_register: &Arc<register::Register>,
    sys_name: &str,
    sys_descr: &str,
    forward_router_info: bool,
    _metrics: &Arc<BmpTcpOutMetrics>,
    status_reporter: &Arc<BmpTcpOutStatusReporter>,
) -> bool {
    status_reporter.dump_started(client.remote_addr);

    // 1. Send Initiation Message
    let init_msg = bmp_builder::build_initiation_message(sys_name, sys_descr);
    if !client.send_message(init_msg).await {
        return false;
    }

    // 2. Find active BGP peers (BgpViaBmp, Bgp, and Mrt-replayed types).
    //
    // For Bgp / BgpViaBmp we filter on IngressState::Connected so that
    // peers preserved across flaps (bmp_tcp_in::peer_down keeps the
    // register entry around for IngressId rebinding, bgp_tcp_in does the
    // same) are not enumerated — their routes have been withdrawn and
    // would otherwise show up as ZERO-ROUTE peers in the dump.
    // Mrt ingresses do not track connection state (no lifecycle), so we
    // include them unconditionally.
    let peers = {
        let mut all_peers = Vec::new();
        for ingress_type in
            [IngressType::BgpViaBmp, IngressType::Bgp, IngressType::Mrt]
        {
            let type_name = format!("{:?}", ingress_type);
            let ingress_state = match ingress_type {
                IngressType::Mrt => None,
                _ => Some(IngressState::Connected),
            };
            let filter = QueryFilter {
                ingress_type: Some(ingress_type),
                ingress_state,
                ..Default::default()
            };
            let found = ingress_register.search(filter);
            info!(
                "bmp-out dump for {}: found {} peers of type {}",
                client.remote_addr,
                found.len(),
                type_name,
            );
            all_peers.extend(found);
        }
        all_peers
    };

    info!(
        "bmp-out dump for {}: total {} peers to dump",
        client.remote_addr,
        peers.len()
    );

    // 3. Phase 1: Send Peer Up for ALL peers first
    let dump_start = Instant::now();
    let bytes_before_dump = client.bytes_sent.load(Ordering::Relaxed);

    // Build a lookup map: IngressId -> PeerInfo for quick access during RIB walk
    let mut peer_info_map: HashMap<IngressId, PeerInfo> =
        HashMap::with_capacity(peers.len());

    for peer_entry in &peers {
        let ingress_id = peer_entry.ingress_id;
        let info = &peer_entry.ingress_info;
        let mut peer_info = PeerInfo::from_ingress_info(info);
        peer_info.admin_label =
            resolve_admin_label(info, ingress_register, forward_router_info);

        // Send Peer Up
        let peer_up_msg = bmp_builder::build_peer_up(&peer_info, true);
        if !client.send_message(peer_up_msg).await {
            return false;
        }

        client.add_known_peer(ingress_id).await;
        peer_info_map.insert(ingress_id, peer_info);
    }

    info!(
        "bmp-out dump for {}: sent Peer Up for {} peers in {:.2}s",
        client.remote_addr,
        peers.len(),
        dump_start.elapsed().as_secs_f64(),
    );

    // 4. Phase 2: Single RIB walk — send all routes for all peers interleaved
    //
    // Streaming model: a blocking thread holds the crossbeam_epoch guard and
    // builds BMP RouteMonitoring messages, pushing them into a bounded
    // mpsc channel. The async side `recv`s from the channel and forwards
    // each message to the client's writer task. Backpressure is natural —
    // a full channel blocks the producer until the consumer drains a slot,
    // which ties the RIB-walk rate to the client's TCP throughput.
    //
    // Why not just collect into a `Vec` first (the previous behavior):
    // at 100M+ routes the `Vec<PrefixRecord>` alone is many GB, and that
    // allocation has to coexist with the writer's mpsc, the dump_buffer
    // accumulating live updates, and every other client's identical
    // structures. The streaming bound is "channel capacity × message
    // size" — kilobytes, not gigabytes.
    //
    // The blocking thread also owns the per-ingress route counters and
    // the skipped-unknown map; both are returned via the JoinHandle so
    // diagnostic output is unchanged.
    //
    // Channel capacity 1024 → ~150 KB worth of queued messages at the
    // average BMP RouteMon size; small enough to apply backpressure
    // quickly, large enough to smooth over short writer hiccups.
    let rib_walk_start = Instant::now();
    let peer_info_arc: Arc<HashMap<IngressId, PeerInfo>> =
        Arc::new(peer_info_map);
    let (msg_tx, mut msg_rx) =
        tokio::sync::mpsc::channel::<Vec<u8>>(1024);
    let rib_for_walk = rib.clone();
    let peer_info_for_walk = peer_info_arc.clone();
    let walk_handle = tokio::task::spawn_blocking(move || {
        let mut routes_per_ingress: HashMap<IngressId, usize> =
            HashMap::with_capacity(peer_info_for_walk.len());
        let mut skipped_unknown: HashMap<IngressId, usize> = HashMap::new();
        let walk_result = rib_for_walk.stream_prefix_records(|pr| {
            let prefix = pr.prefix;
            for route_record in pr.meta {
                let ingress_id = route_record.multi_uniq_id;
                let peer_info =
                    match peer_info_for_walk.get(&ingress_id) {
                        Some(pi) => pi,
                        None => {
                            *skipped_unknown
                                .entry(ingress_id)
                                .or_insert(0) += 1;
                            continue;
                        }
                    };
                let pamap = &route_record.meta;
                let msg = bmp_builder::build_route_monitoring(
                    peer_info, prefix, pamap, false,
                );
                if msg_tx.blocking_send(msg).is_err() {
                    // Consumer dropped (client disconnected). Bail out
                    // of the iteration so the epoch guard is released.
                    return false;
                }
                *routes_per_ingress.entry(ingress_id).or_insert(0) += 1;
            }
            true
        });
        (routes_per_ingress, skipped_unknown, walk_result)
    });

    const YIELD_EVERY: usize = 1024;
    const PROGRESS_LOG_EVERY: Duration = Duration::from_secs(5);
    let mut total_routes: usize = 0;
    let mut since_yield: usize = 0;
    let mut last_progress_at = rib_walk_start;
    let mut last_progress_routes: usize = 0;
    let mut client_disconnected = false;

    while let Some(msg) = msg_rx.recv().await {
        if !client.send_message(msg).await {
            // Writer task gone — drop the receiver so the blocking
            // walker's next blocking_send fails and it can exit.
            client_disconnected = true;
            break;
        }
        total_routes += 1;

        since_yield += 1;
        if since_yield >= YIELD_EVERY {
            tokio::task::yield_now().await;
            since_yield = 0;

            let now = Instant::now();
            if now.duration_since(last_progress_at) >= PROGRESS_LOG_EVERY {
                let interval = now.duration_since(last_progress_at);
                let delta = total_routes - last_progress_routes;
                let instant_rate = delta as f64 / interval.as_secs_f64();
                let avg_rate = total_routes as f64
                    / now.duration_since(rib_walk_start).as_secs_f64();
                let buf_len = client.dump_buffer.lock().await.len();
                let buf_bytes =
                    client.buffered_bytes.load(Ordering::Relaxed);
                let bytes_sent_total = client
                    .bytes_sent
                    .load(Ordering::Relaxed)
                    .saturating_sub(bytes_before_dump);
                info!(
                    "bmp-out dump for {}: progress {} routes ({:.0} r/s now, \
                     {:.0} r/s avg), {} buffered ({:.1} MB), {:.1} MB sent",
                    client.remote_addr,
                    total_routes,
                    instant_rate,
                    avg_rate,
                    buf_len,
                    buf_bytes as f64 / (1024.0 * 1024.0),
                    bytes_sent_total as f64 / (1024.0 * 1024.0),
                );
                last_progress_at = now;
                last_progress_routes = total_routes;
            }
        }
    }
    drop(msg_rx);

    // Wait for the walker to finish so the epoch guard is released
    // before we proceed (and for the side-channel counters).
    let (routes_per_ingress, skipped_unknown, walk_result) =
        match walk_handle.await {
            Ok(triple) => triple,
            Err(join_err) => {
                warn!(
                    "bmp-out dump for {}: RIB walker task failed: {}",
                    client.remote_addr, join_err
                );
                (HashMap::new(), HashMap::new(), Ok(0))
            }
        };
    if let Err(e) = walk_result {
        warn!(
            "bmp-out dump for {}: stream_prefix_records error: {}",
            client.remote_addr, e
        );
    }

    if client_disconnected {
        return false;
    }

    let rib_walk_elapsed = rib_walk_start.elapsed();
    info!(
        "bmp-out dump for {}: RIB walk sent {} routes in {:.2}s",
        client.remote_addr,
        total_routes,
        rib_walk_elapsed.as_secs_f64(),
    );

    // Diagnostic: per-peer breakdown of sent routes. Highlight any peer that
    // is in peer_info_map but had zero routes sent — those are the silent
    // drops we're hunting.
    let mut peer_rows: Vec<(IngressId, &PeerInfo, usize)> = peer_info_arc
        .iter()
        .map(|(id, pi)| {
            (*id, pi, routes_per_ingress.get(id).copied().unwrap_or(0))
        })
        .collect();
    peer_rows.sort_by_key(|(_, _, count)| std::cmp::Reverse(*count));
    let zero_count = peer_rows.iter().filter(|(_, _, c)| *c == 0).count();
    info!(
        "bmp-out dump for {}: per-peer RIB-walk counts: {} peers with routes, {} peers with ZERO routes",
        client.remote_addr,
        peer_rows.len() - zero_count,
        zero_count,
    );
    for (id, pi, count) in &peer_rows {
        if *count == 0 {
            info!(
                "bmp-out dump for {}: ZERO-ROUTE peer ingress_id={} AS{} {}",
                client.remote_addr, id, pi.peer_asn, pi.peer_address,
            );
        }
    }
    if !skipped_unknown.is_empty() {
        let total_skipped: usize = skipped_unknown.values().sum();
        info!(
            "bmp-out dump for {}: skipped {} routes across {} unknown ingress_ids (not in peer_info_map)",
            client.remote_addr,
            total_skipped,
            skipped_unknown.len(),
        );
        let mut rows: Vec<(IngressId, usize)> =
            skipped_unknown.into_iter().collect();
        rows.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        for (id, c) in rows.iter().take(20) {
            info!(
                "bmp-out dump for {}: skipped unknown ingress_id={} routes={}",
                client.remote_addr, id, c
            );
        }
    }

    // 5. Phase 3: Send End-of-RIB markers for every AFI/SAFI advertised in
    // the synthetic Peer Up OPENs. Even an empty table needs an EoR marker.
    for peer_entry in &peers {
        let ingress_id = peer_entry.ingress_id;
        let peer_info = match peer_info_arc.get(&ingress_id) {
            Some(pi) => pi,
            None => continue,
        };

        for afisafi in [AfiSafiType::Ipv4Unicast, AfiSafiType::Ipv6Unicast] {
            if let Some(msg) =
                bmp_builder::build_end_of_rib_marker(peer_info, afisafi)
            {
                if !client.send_message(msg).await {
                    return false;
                }
            }
        }
    }

    let dump_bytes =
        client.bytes_sent.load(Ordering::Relaxed) - bytes_before_dump;
    let dump_elapsed = dump_start.elapsed();
    info!(
        "bmp-out dump for {}: dump complete, {} peers, {} total routes, {:.2} MB in {:.2}s",
        client.remote_addr,
        peers.len(),
        total_routes,
        dump_bytes as f64 / (1024.0 * 1024.0),
        dump_elapsed.as_secs_f64(),
    );

    // 4. Drain the dump buffer in chunks. Holding `phase.write()` across
    // the entire drain (potentially tens of millions of updates accumulated
    // during a long RIB walk) parks `direct_update` on `phase.read()` for
    // the duration, which then parks rib's `update_data` and cascades back
    // to bmp-in stalling on its sockets — the whole pipeline freezes for
    // many minutes. Instead: take a batch, release the lock, send it;
    // re-acquire and check if more arrived. When we reacquire and find the
    // buffer empty, we transition to Live atomically (no DU can be mid-push
    // because `buffer_update_if_dumping` holds `phase.read()` across the
    // `dump_buffer.lock()` acquisition).
    loop {
        let mut phase = client.phase.write().await;
        let buffered = client.take_buffered_updates().await;
        if buffered.is_empty() {
            *phase = ClientPhase::Live;
            break;
        }
        debug!(
            "Draining batch of {} buffered updates for client {}",
            buffered.len(),
            client.remote_addr
        );
        drop(phase); // release before slow sends; new DU calls re-buffer

        for update in buffered {
            if !send_update_to_client(
                client,
                &update,
                ingress_register,
                forward_router_info,
            )
            .await
            {
                return false;
            }
        }
    }
    status_reporter.dump_completed(client.remote_addr);

    true
}

/// Convert an Update to BMP messages and send to a single client.
///
/// Returns false if the send failed (client disconnected).
pub async fn send_update_to_client(
    client: &Arc<ClientState>,
    update: &Update,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
) -> bool {
    match update {
        Update::Single(payload) => {
            send_payload_to_client(
                client,
                payload,
                ingress_register,
                forward_router_info,
            )
            .await
        }
        Update::Bulk(payloads) => {
            for payload in payloads.iter() {
                if !send_payload_to_client(
                    client,
                    payload,
                    ingress_register,
                    forward_router_info,
                )
                .await
                {
                    return false;
                }
            }
            true
        }
        Update::Withdraw(ingress_id, _afisafi) => {
            send_peer_down(client, *ingress_id, None, ingress_register).await
        }
        Update::WithdrawBulk(entries) => {
            for (ingress_id, info) in entries.iter() {
                if !send_peer_down(
                    client,
                    *ingress_id,
                    info.as_ref(),
                    ingress_register,
                )
                .await
                {
                    return false;
                }
            }
            true
        }
        Update::IngressReappeared(ingress_id) => {
            send_peer_reappeared(
                client,
                *ingress_id,
                ingress_register,
                forward_router_info,
            )
            .await
        }
        Update::PeerStats { ingress_id, body } => {
            send_peer_stats(
                client,
                *ingress_id,
                body,
                ingress_register,
                forward_router_info,
            )
            .await
        }
        _ => {
            // Other update types are ignored for BMP out
            true
        }
    }
}

/// Forward an upstream BMP Statistics Report (RFC 7854 §4.8) to the
/// client. Ensures Peer Up has been re-streamed for this `ingress_id`
/// (lazy peer-up mirrors what `send_payload_to_client` does for Route
/// Monitoring), then re-encodes the stats body under a fresh per-peer
/// header that matches what we already sent for this peer.
async fn send_peer_stats(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    body: &bytes::Bytes,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
) -> bool {
    if client.register_known_peer_if_absent(ingress_id).await {
        if let Some(info) = ingress_register.get(ingress_id) {
            let mut peer_info = PeerInfo::from_ingress_info(&info);
            peer_info.admin_label = resolve_admin_label(
                &info,
                ingress_register,
                forward_router_info,
            );
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message(peer_up).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }

    let peer_info = match ingress_register.get(ingress_id) {
        Some(ref info) => PeerInfo::from_ingress_info(info),
        None => {
            // Peer is gone (e.g. just torn down); drop the stats report
            // rather than emit one with bogus PPH fields.
            return true;
        }
    };

    let msg = bmp_builder::build_statistics_report(&peer_info, body);
    client.send_message(msg).await
}

/// Send a single Payload as a Route Monitoring BMP message.
async fn send_payload_to_client(
    client: &Arc<ClientState>,
    payload: &Payload,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
) -> bool {
    let ingress_id = payload.ingress_id;

    // Ensure we have sent Peer Up for this peer
    if client.register_known_peer_if_absent(ingress_id).await {
        if let Some(info) = ingress_register.get(ingress_id) {
            let mut peer_info = PeerInfo::from_ingress_info(&info);
            peer_info.admin_label = resolve_admin_label(
                &info,
                ingress_register,
                forward_router_info,
            );
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message(peer_up).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }

    // Build and send Route Monitoring message
    let info = ingress_register.get(ingress_id);
    let peer_info = match info {
        Some(ref info) => PeerInfo::from_ingress_info(info),
        None => {
            // Fall back to a default peer info
            PeerInfo::from_ingress_info(&IngressInfo::default())
        }
    };

    let is_withdrawal = payload.route_status == RouteStatus::Withdrawn;
    if let Some(msg) = bmp_builder::build_route_monitoring_from_route(
        &peer_info,
        &payload.rx_value,
        is_withdrawal,
    ) {
        client.send_message(msg).await
    } else {
        true // Skip if we can't build the message
    }
}

/// Send a Peer Down notification for an ingress.
///
/// `snapshot_info` is preferred when present: producers that are about to
/// drop the entry from `ingress_register` (e.g. `bmp_tcp_in::peer_down`
/// reaping synthesized siblings) snapshot the info inline on
/// `Update::WithdrawBulk` so the lookup-after-remove race can't yield a
/// Peer Down with `IngressInfo::default()`.
async fn send_peer_down(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    snapshot_info: Option<&IngressInfo>,
    ingress_register: &Arc<register::Register>,
) -> bool {
    if !client.has_known_peer(ingress_id).await {
        return true; // Client doesn't know about this peer, nothing to do
    }

    let fetched = if snapshot_info.is_none() {
        ingress_register.get(ingress_id)
    } else {
        None
    };
    let peer_info = match (snapshot_info, fetched.as_ref()) {
        (Some(info), _) => PeerInfo::from_ingress_info(info),
        (None, Some(info)) => PeerInfo::from_ingress_info(info),
        (None, None) => PeerInfo::from_ingress_info(&IngressInfo::default()),
    };

    let msg = bmp_builder::build_peer_down(&peer_info);
    let sent = client.send_message(msg).await;

    client.remove_known_peer(ingress_id).await;

    sent
}

/// Handle IngressReappeared: send Peer Up for the reappeared peer.
async fn send_peer_reappeared(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
) -> bool {
    if let Some(info) = ingress_register.get(ingress_id) {
        let mut peer_info = PeerInfo::from_ingress_info(&info);
        peer_info.admin_label =
            resolve_admin_label(&info, ingress_register, forward_router_info);

        // Only send Peer Up if this peer was not already known.
        if client.register_known_peer_if_absent(ingress_id).await {
            // Send Peer Up
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message(peer_up).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }
    true
}

// Make register accessible from the ingress module
use crate::ingress::register;
