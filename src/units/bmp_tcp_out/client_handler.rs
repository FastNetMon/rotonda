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
    unit::FanInPeerDistinguisher,
};

/// Memory budget for the dump-phase route aggregator. Because the RIB walk is
/// prefix-major, a (peer, attribute-set) group's prefixes are scattered
/// across the whole walk, so groups must stay open to aggregate fully; this
/// bounds how much may be held before the fullest groups are evicted early.
/// The aggregator now holds attribute bytes via shared `Arc`s and looks up
/// peer info instead of cloning it, so the real per-group footprint is small
/// — 256 MB comfortably holds a full-table walk's groups, letting aggregation
/// reach the table's natural attribute-sharing ratio rather than being capped
/// by premature eviction. Logged `budget evictions` near zero confirm the
/// budget is not the limiting factor.
const DUMP_AGGREGATOR_MAX_BYTES: usize = 256 * 1024 * 1024;

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

/// Build a `PeerInfo` for re-streamed BMP output, applying both the
/// optional Admin Label TLV and the fan-in `peer_distinguisher` tag.
///
/// Centralising both steps here keeps every emitted message type (PeerUp,
/// PeerDown, RouteMonitoring, StatisticsReport, EoR) consistent on the
/// wire. The fan-in tag depends only on the peer's `parent_ingress` and
/// the configured policy, so the same upstream router always produces
/// the same tag regardless of which message type is being built.
fn build_peer_info_for_emit(
    info: &IngressInfo,
    ingress_register: &register::Register,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
) -> PeerInfo {
    let mut peer_info = PeerInfo::from_ingress_info(info);
    peer_info.admin_label =
        resolve_admin_label(info, ingress_register, forward_router_info);
    if fan_in_peer_distinguisher.is_enabled() {
        if let Some(parent_id) = info.parent_ingress {
            let tag = bmp_builder::fan_in_distinguisher_tag(parent_id);
            peer_info.apply_fan_in_distinguisher(tag);
        }
    }
    peer_info
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
#[allow(clippy::too_many_arguments)]
pub async fn perform_initial_dump(
    client: &Arc<ClientState>,
    rib: &Arc<Rib>,
    ingress_register: &Arc<register::Register>,
    sys_name: &str,
    sys_descr: &str,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
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
        let peer_info = build_peer_info_for_emit(
            info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        );

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
    // Keep an Arc copy of the enumerated (Connected) peers for the post-walk
    // EoR loop and the ZERO-ROUTE diagnostic. The aggregator OWNS its own
    // mutable copy of the same map (passed by value below) so it can absorb
    // peers discovered mid-walk; this Arc is the enumerated set only.
    let peer_info_arc: Arc<HashMap<IngressId, PeerInfo>> =
        Arc::new(peer_info_map.clone());
    // Channel item is (message bytes, number of routes packed in it): with
    // NLRI aggregation one message may carry many prefixes, so the consumer
    // needs the route count to keep its progress accounting accurate.
    let (msg_tx, mut msg_rx) =
        tokio::sync::mpsc::channel::<(Vec<u8>, usize)>(1024);
    let rib_for_walk = rib.clone();
    // Captured by the blocking walk so a peer whose routes are ACTIVE in the
    // store but whose register entry was NOT enumerated (e.g. reactivated on
    // reconnect without the register state flipping back to Connected) can be
    // discovered and emitted instead of silently dropped.
    let ingress_register_for_walk = ingress_register.clone();
    let walk_handle = tokio::task::spawn_blocking(move || {
        let mut routes_per_ingress: HashMap<IngressId, usize> =
            HashMap::with_capacity(peer_info_map.len());
        let mut skipped_unknown: HashMap<IngressId, usize> = HashMap::new();
        // Peers found mid-walk via the register fallback (active routes but
        // not in the enumerated set). Returned out so the async side can send
        // their EoR markers and register them as known peers.
        let mut discovered: Vec<(IngressId, PeerInfo)> = Vec::new();
        let mut aggregator = bmp_builder::RouteAggregator::new(
            DUMP_AGGREGATOR_MAX_BYTES,
            peer_info_map,
        );
        // Set if the consumer (client) goes away mid-walk, so we skip the
        // post-walk flush instead of re-encoding messages for a dead socket.
        let mut client_gone = false;
        let walk_result = rib_for_walk.stream_prefix_records(|pr| {
            let prefix = pr.prefix;
            for route_record in pr.meta {
                let ingress_id = route_record.multi_uniq_id;
                let mut sink = |msg: Vec<u8>, n: usize| {
                    msg_tx.blocking_send((msg, n)).is_ok()
                };
                // FIX A: include any peer that actually has active routes,
                // regardless of register state. If it wasn't enumerated, look
                // it up in the register and, if it's a real peer type, emit
                // its Peer Up now (so it precedes this peer's routes) and add
                // it to the aggregator's peer map.
                if !aggregator.has_peer(ingress_id) {
                    match ingress_register_for_walk.get(ingress_id) {
                        Some(info)
                            if matches!(
                                info.ingress_type,
                                Some(IngressType::BgpViaBmp)
                                    | Some(IngressType::Bgp)
                                    | Some(IngressType::Mrt)
                            ) =>
                        {
                            let pi = build_peer_info_for_emit(
                                &info,
                                &ingress_register_for_walk,
                                forward_router_info,
                                fan_in_peer_distinguisher,
                            );
                            let peer_up = bmp_builder::build_peer_up(&pi, false);
                            if !sink(peer_up, 0) {
                                client_gone = true;
                                return false;
                            }
                            aggregator.insert_peer(ingress_id, pi.clone());
                            discovered.push((ingress_id, pi));
                        }
                        _ => {
                            *skipped_unknown
                                .entry(ingress_id)
                                .or_insert(0) += 1;
                            continue;
                        }
                    }
                }
                let pamap = &route_record.meta;
                *routes_per_ingress.entry(ingress_id).or_insert(0) += 1;
                if !aggregator.add(ingress_id, prefix, pamap, &mut sink) {
                    // Consumer dropped (client disconnected). Bail out
                    // of the iteration so the epoch guard is released.
                    client_gone = true;
                    return false;
                }
            }
            true
        });
        // Flush whatever is still buffered into final aggregated messages,
        // unless the client already disconnected.
        if !client_gone {
            let mut sink = |msg: Vec<u8>, n: usize| {
                msg_tx.blocking_send((msg, n)).is_ok()
            };
            let _ = aggregator.flush_all(&mut sink);
        }
        let agg_stats = aggregator.stats();
        (
            routes_per_ingress,
            skipped_unknown,
            walk_result,
            agg_stats,
            discovered,
        )
    });

    const YIELD_EVERY: usize = 1024;
    const PROGRESS_LOG_EVERY: Duration = Duration::from_secs(5);
    let mut total_routes: usize = 0;
    let mut total_messages: usize = 0;
    let mut since_yield: usize = 0;
    let mut last_progress_at = rib_walk_start;
    let mut last_progress_routes: usize = 0;
    let mut client_disconnected = false;

    while let Some((msg, route_count)) = msg_rx.recv().await {
        if !client.send_message(msg).await {
            // Writer task gone — drop the receiver so the blocking
            // walker's next blocking_send fails and it can exit.
            client_disconnected = true;
            break;
        }
        total_routes += route_count;
        total_messages += 1;

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
                    "bmp-out dump for {}: progress {} routes in {} msgs \
                     ({:.0} r/s now, {:.0} r/s avg), {} buffered ({:.1} MB), \
                     {:.1} MB sent",
                    client.remote_addr,
                    total_routes,
                    total_messages,
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
    let (
        routes_per_ingress,
        skipped_unknown,
        walk_result,
        agg_stats,
        discovered,
    ) = match walk_handle.await {
        Ok(tuple) => tuple,
        Err(join_err) => {
            warn!(
                "bmp-out dump for {}: RIB walker task failed: {}",
                client.remote_addr, join_err
            );
            (HashMap::new(), HashMap::new(), Ok(0), (0, 0), Vec::new())
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
    let agg_ratio = if total_messages > 0 {
        total_routes as f64 / total_messages as f64
    } else {
        0.0
    };
    let (agg_groups, agg_budget_evictions) = agg_stats;
    info!(
        "bmp-out dump for {}: RIB walk sent {} routes in {} msgs \
         ({:.1} routes/msg via NLRI aggregation; {} groups, {} budget \
         evictions) in {:.2}s",
        client.remote_addr,
        total_routes,
        total_messages,
        agg_ratio,
        agg_groups,
        agg_budget_evictions,
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

    // FIX A: peers discovered mid-walk (active routes in the store but not
    // enumerated from the register). Their Peer Up was already sent inline by
    // the walk; here we register them as known peers and send their EoR
    // markers, exactly like the enumerated peers above.
    for (ingress_id, peer_info) in &discovered {
        client.add_known_peer(*ingress_id).await;
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
        "bmp-out dump for {}: dump complete, {} peers ({} discovered via walk \
         fallback), {} total routes, {:.2} MB in {:.2}s",
        client.remote_addr,
        peers.len() + discovered.len(),
        discovered.len(),
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
            // Per-client dump task: blocking send is correct here (only this
            // client's own task is back-pressured).
            if !send_update_to_client(
                client,
                &update,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
                true,
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
///
/// `blocking` is threaded down to the per-message send: `true` for the
/// per-client dump / buffered-replay tasks, `false` for the shared live
/// `direct_update` path (which must not park the ingest pipeline on a slow
/// consumer — see [`ClientState::send_message_mode`]).
pub async fn send_update_to_client(
    client: &Arc<ClientState>,
    update: &Update,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    match update {
        Update::Single(payload) => {
            send_payload_to_client(
                client,
                payload,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
                blocking,
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
                    fan_in_peer_distinguisher,
                    blocking,
                )
                .await
                {
                    return false;
                }
            }
            true
        }
        Update::Withdraw(ingress_id, _afisafi) => {
            send_peer_down(
                client,
                *ingress_id,
                None,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
                blocking,
            )
            .await
        }
        Update::WithdrawBulk(entries) => {
            for (ingress_id, info) in entries.iter() {
                if !send_peer_down(
                    client,
                    *ingress_id,
                    info.as_ref(),
                    ingress_register,
                    forward_router_info,
                    fan_in_peer_distinguisher,
                    blocking,
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
                fan_in_peer_distinguisher,
                blocking,
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
                fan_in_peer_distinguisher,
                blocking,
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
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    if client.register_known_peer_if_absent(ingress_id).await {
        if let Some(info) = ingress_register.get(ingress_id) {
            let peer_info = build_peer_info_for_emit(
                &info,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
            );
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message_mode(peer_up, blocking).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }

    let peer_info = match ingress_register.get(ingress_id) {
        Some(info) => build_peer_info_for_emit(
            &info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
        None => {
            // Peer is gone (e.g. just torn down); drop the stats report
            // rather than emit one with bogus PPH fields.
            return true;
        }
    };

    let msg = bmp_builder::build_statistics_report(&peer_info, body);
    client.send_message_mode(msg, blocking).await
}

/// Send a single Payload as a Route Monitoring BMP message.
async fn send_payload_to_client(
    client: &Arc<ClientState>,
    payload: &Payload,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    let ingress_id = payload.ingress_id;

    // Fast path: PeerInfo is constant per peer for the session, so once it is
    // cached (Peer Up already sent, header already built) every subsequent
    // route just reuses it -- no register lookups, no IngressInfo clones, no
    // per-route known_peers write-lock.
    if let Some(peer_info) = client.cached_peer_info(ingress_id).await {
        let is_withdrawal = payload.route_status == RouteStatus::Withdrawn;
        return match bmp_builder::build_route_monitoring_from_route(
            &peer_info,
            &payload.rx_value,
            is_withdrawal,
        ) {
            Some(msg) => client.send_message_mode(msg, blocking).await,
            None => true, // Skip if we can't build the message
        };
    }

    // Cache miss (first route for this peer on this client). This block is the
    // legacy first-sight path verbatim -- ensure Peer Up has been sent -- and
    // is followed by caching the built PeerInfo for the fast path above.
    if client.register_known_peer_if_absent(ingress_id).await {
        if let Some(info) = ingress_register.get(ingress_id) {
            let peer_info = build_peer_info_for_emit(
                &info,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
            );
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message_mode(peer_up, blocking).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }

    // Build the Route Monitoring peer header. The fan-in distinguisher tag
    // must match the Peer Up we sent for this peer, so use the same builder.
    let peer_info = Arc::new(match ingress_register.get(ingress_id) {
        Some(info) => build_peer_info_for_emit(
            &info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
        None => {
            // Fall back to a default peer info. No parent_ingress is
            // available, so the fan-in branch in
            // build_peer_info_for_emit is a no-op and pd stays at zero —
            // matching the legacy behaviour for this unknown-peer edge
            // case.
            build_peer_info_for_emit(
                &IngressInfo::default(),
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
            )
        }
    });

    // Cache only when the peer is actually registered, so the rare
    // route-before-register race re-resolves on the next route instead of
    // sticking with the default header.
    if ingress_register.get(ingress_id).is_some() {
        client.cache_peer_info(ingress_id, peer_info.clone()).await;
    }

    let is_withdrawal = payload.route_status == RouteStatus::Withdrawn;
    if let Some(msg) = bmp_builder::build_route_monitoring_from_route(
        &peer_info,
        &payload.rx_value,
        is_withdrawal,
    ) {
        client.send_message_mode(msg, blocking).await
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
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
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
        (Some(info), _) => build_peer_info_for_emit(
            info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
        (None, Some(info)) => build_peer_info_for_emit(
            info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
        (None, None) => build_peer_info_for_emit(
            &IngressInfo::default(),
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
    };

    let msg = bmp_builder::build_peer_down(&peer_info);
    let sent = client.send_message_mode(msg, blocking).await;

    client.remove_known_peer(ingress_id).await;

    sent
}

/// Handle IngressReappeared: send Peer Up for the reappeared peer.
async fn send_peer_reappeared(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    if let Some(info) = ingress_register.get(ingress_id) {
        let peer_info = build_peer_info_for_emit(
            &info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        );

        // Only send Peer Up if this peer was not already known.
        if client.register_known_peer_if_absent(ingress_id).await {
            // Send Peer Up
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message_mode(peer_up, blocking).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }
    true
}

// Make register accessible from the ingress module
use crate::ingress::register;

#[cfg(test)]
mod tests {
    use super::*;
    use inetnum::asn::Asn;
    use std::net::{IpAddr, Ipv6Addr};

    /// Build the same peer (same peer_ip, peer_asn) attributed to two
    /// different upstream BMP routers, and assert the fan-in distinguisher
    /// stamping yields two distinct non-zero pd values when enabled, but
    /// stays at pd=0 when disabled.
    #[test]
    fn build_peer_info_stamps_pd_from_parent_ingress() {
        let register = register::Register::default();
        let parent_a = register.register();
        let parent_b = register.register();
        register.update_info(
            parent_a,
            IngressInfo::new().with_name("router-edge-1"),
        );
        register.update_info(
            parent_b,
            IngressInfo::new().with_name("router-edge-2"),
        );

        let peer_for = |parent_id| {
            IngressInfo::new()
                .with_parent_ingress(parent_id)
                .with_remote_addr(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x7f8, 0x6c, 0, 0, 0, 0, 0x230,
                )))
                .with_remote_asn(Asn::from_u32(6939))
        };

        let info_a = peer_for(parent_a);
        let info_b = peer_for(parent_b);

        // With fan-in enabled the two upstreams must emit different
        // non-zero distinguishers despite sharing (peer_ip, peer_asn).
        let pi_a = build_peer_info_for_emit(
            &info_a,
            &register,
            false,
            FanInPeerDistinguisher::IngressHash,
        );
        let pi_b = build_peer_info_for_emit(
            &info_b,
            &register,
            false,
            FanInPeerDistinguisher::IngressHash,
        );
        assert_ne!(pi_a.peer_distinguisher, [0u8; 8]);
        assert_ne!(pi_b.peer_distinguisher, [0u8; 8]);
        assert_ne!(pi_a.peer_distinguisher, pi_b.peer_distinguisher);

        // With fan-in disabled both fall back to legacy pd=0.
        let off_a = build_peer_info_for_emit(
            &info_a,
            &register,
            false,
            FanInPeerDistinguisher::Off,
        );
        let off_b = build_peer_info_for_emit(
            &info_b,
            &register,
            false,
            FanInPeerDistinguisher::Off,
        );
        assert_eq!(off_a.peer_distinguisher, [0u8; 8]);
        assert_eq!(off_b.peer_distinguisher, [0u8; 8]);
    }

    /// A peer with no parent_ingress (e.g. synthetic IngressInfo::default
    /// fallback paths) must leave pd unchanged — there is no upstream
    /// identity to encode.
    #[test]
    fn build_peer_info_no_parent_leaves_pd_zero() {
        let register = register::Register::default();
        let info = IngressInfo::new();
        let pi = build_peer_info_for_emit(
            &info,
            &register,
            false,
            FanInPeerDistinguisher::IngressHash,
        );
        assert_eq!(pi.peer_distinguisher, [0u8; 8]);
    }

    /// A peer that already carries a real RD (non-zero inbound
    /// distinguisher, e.g. a VPN peer per RFC 7854 §4.2) must pass
    /// through unmodified even when fan-in stamping is on.
    #[test]
    fn build_peer_info_preserves_real_rd() {
        let register = register::Register::default();
        let parent = register.register();
        let real_rd = [0u8, 1, 0, 0xfd, 0xe9, 0, 0, 7];
        let info = IngressInfo::new()
            .with_parent_ingress(parent)
            .with_distinguisher(real_rd);
        let pi = build_peer_info_for_emit(
            &info,
            &register,
            false,
            FanInPeerDistinguisher::IngressHash,
        );
        assert_eq!(pi.peer_distinguisher, real_rd);
    }
}
