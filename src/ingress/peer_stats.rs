//! Per-peer BMP-style statistics for native BGP ingresses.
//!
//! Tracks the counters needed to synthesize BMP Statistics Reports
//! (RFC 7854 §4.8) for peers terminated directly by `bgp_tcp_in`. The
//! registry is shared as `Arc<BgpPeerStatsRegistry>` between the
//! per-connection task that updates counters and the periodic emitter
//! that snapshots them and publishes `Update::PeerStats`.
//!
//! Counters Rotonda doesn't compute (loop checks, RFC 7606
//! treat-as-withdraw, Loc-RIB totals) are kept as fields so the
//! emitted Stats Report has a stable RFC 7854 §4.8 TLV set; their
//! values are simply zero. See `stats_builder` for serialization.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::ingress::IngressId;

/// AFI/SAFI key used for the per-AFI/SAFI Adj-RIB-In and Loc-RIB
/// counters (RFC 7854 §4.8 stat types 9 and 10). AFI is u16, SAFI is
/// u8, both in IANA-assigned wire values.
pub type AfiSafiKey = (u16, u8);

/// Per-peer counters mapped 1:1 to RFC 7854 §4.8 stat TLVs.
///
/// Counters are atomic so the BGP-receive path can update them without
/// taking a lock. Gauges that are per-AFI/SAFI live behind a `RwLock`
/// because the set of active families is rarely larger than 2-4.
#[derive(Debug, Default)]
pub struct BgpPeerStats {
    pub prefixes_rejected: AtomicU64,
    pub dup_prefix_advertisements: AtomicU64,
    pub dup_withdraws: AtomicU64,
    pub invalid_cluster_list_loops: AtomicU64,
    pub invalid_as_path_loops: AtomicU64,
    pub invalid_originator_id: AtomicU64,
    pub invalid_as_confed_loops: AtomicU64,
    pub adj_rib_in_routes: AtomicU64,
    pub loc_rib_routes: AtomicU64,
    pub adj_rib_in_per_afi_safi: RwLock<HashMap<AfiSafiKey, u64>>,
    pub loc_rib_per_afi_safi: RwLock<HashMap<AfiSafiKey, u64>>,
    pub updates_treat_as_withdraw: AtomicU64,
    pub prefixes_treat_as_withdraw: AtomicU64,
    pub dup_updates: AtomicU64,
}

impl BgpPeerStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_prefixes_rejected(&self, n: u64) {
        self.prefixes_rejected.fetch_add(n, Ordering::Relaxed);
    }

    /// Record `n` accepted announcements for `afi_safi`. Updates both
    /// the per-AFI/SAFI map and the aggregate Adj-RIB-In counter.
    pub fn add_adj_rib_in(&self, afi_safi: AfiSafiKey, n: u64) {
        if n == 0 {
            return;
        }
        self.adj_rib_in_routes.fetch_add(n, Ordering::Relaxed);
        let mut map = self.adj_rib_in_per_afi_safi.write().unwrap();
        *map.entry(afi_safi).or_insert(0) += n;
    }

    /// Record `n` withdrawals for `afi_safi`. Saturates at zero so a
    /// burst of withdraws for unseen prefixes can't underflow.
    pub fn sub_adj_rib_in(&self, afi_safi: AfiSafiKey, n: u64) {
        if n == 0 {
            return;
        }
        let mut map = self.adj_rib_in_per_afi_safi.write().unwrap();
        let cur = map.entry(afi_safi).or_insert(0);
        let dec = (*cur).min(n);
        *cur = cur.saturating_sub(dec);
        // Mirror the same saturation for the aggregate.
        let agg = self.adj_rib_in_routes.load(Ordering::Relaxed);
        let new_agg = agg.saturating_sub(dec);
        self.adj_rib_in_routes.store(new_agg, Ordering::Relaxed);
    }

    /// Reset the per-AFI/SAFI Adj-RIB-In gauge to zero, e.g. on
    /// session reset or peer down. Aggregate is recomputed accordingly.
    pub fn reset_adj_rib_in(&self) {
        self.adj_rib_in_routes.store(0, Ordering::Relaxed);
        self.adj_rib_in_per_afi_safi.write().unwrap().clear();
    }
}

/// Snapshot of [`BgpPeerStats`] suitable for serialization without
/// holding the underlying locks.
#[derive(Clone, Debug, Default)]
pub struct BgpPeerStatsSnapshot {
    pub prefixes_rejected: u64,
    pub dup_prefix_advertisements: u64,
    pub dup_withdraws: u64,
    pub invalid_cluster_list_loops: u64,
    pub invalid_as_path_loops: u64,
    pub invalid_originator_id: u64,
    pub invalid_as_confed_loops: u64,
    pub adj_rib_in_routes: u64,
    pub loc_rib_routes: u64,
    pub adj_rib_in_per_afi_safi: Vec<(AfiSafiKey, u64)>,
    pub loc_rib_per_afi_safi: Vec<(AfiSafiKey, u64)>,
    pub updates_treat_as_withdraw: u64,
    pub prefixes_treat_as_withdraw: u64,
    pub dup_updates: u64,
}

impl BgpPeerStats {
    pub fn snapshot(&self) -> BgpPeerStatsSnapshot {
        BgpPeerStatsSnapshot {
            prefixes_rejected: self.prefixes_rejected.load(Ordering::Relaxed),
            dup_prefix_advertisements: self
                .dup_prefix_advertisements
                .load(Ordering::Relaxed),
            dup_withdraws: self.dup_withdraws.load(Ordering::Relaxed),
            invalid_cluster_list_loops: self
                .invalid_cluster_list_loops
                .load(Ordering::Relaxed),
            invalid_as_path_loops: self
                .invalid_as_path_loops
                .load(Ordering::Relaxed),
            invalid_originator_id: self
                .invalid_originator_id
                .load(Ordering::Relaxed),
            invalid_as_confed_loops: self
                .invalid_as_confed_loops
                .load(Ordering::Relaxed),
            adj_rib_in_routes: self.adj_rib_in_routes.load(Ordering::Relaxed),
            loc_rib_routes: self.loc_rib_routes.load(Ordering::Relaxed),
            adj_rib_in_per_afi_safi: self
                .adj_rib_in_per_afi_safi
                .read()
                .unwrap()
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            loc_rib_per_afi_safi: self
                .loc_rib_per_afi_safi
                .read()
                .unwrap()
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            updates_treat_as_withdraw: self
                .updates_treat_as_withdraw
                .load(Ordering::Relaxed),
            prefixes_treat_as_withdraw: self
                .prefixes_treat_as_withdraw
                .load(Ordering::Relaxed),
            dup_updates: self.dup_updates.load(Ordering::Relaxed),
        }
    }
}

/// Registry of per-peer stats keyed by [`IngressId`]. Cheaply cloneable
/// (it's just an `Arc<RwLock<HashMap<...>>>` internally) so it can be
/// passed to per-connection tasks and the emission timer alike.
#[derive(Debug, Default)]
pub struct BgpPeerStatsRegistry {
    inner: RwLock<HashMap<IngressId, Arc<BgpPeerStats>>>,
}

impl BgpPeerStatsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get-or-create the stats entry for `id`. The same `Arc` is
    /// returned on subsequent calls so the per-connection task can
    /// keep a clone for cheap counter updates.
    pub fn get_or_create(&self, id: IngressId) -> Arc<BgpPeerStats> {
        if let Some(s) = self.inner.read().unwrap().get(&id).cloned() {
            return s;
        }
        let mut w = self.inner.write().unwrap();
        w.entry(id)
            .or_insert_with(|| Arc::new(BgpPeerStats::new()))
            .clone()
    }

    pub fn get(&self, id: IngressId) -> Option<Arc<BgpPeerStats>> {
        self.inner.read().unwrap().get(&id).cloned()
    }

    pub fn remove(&self, id: IngressId) {
        self.inner.write().unwrap().remove(&id);
    }

    /// Snapshot every (id, snapshot) pair currently in the registry.
    /// Used by the periodic emitter to walk all peers without holding
    /// the lock for the full emit duration.
    pub fn snapshot_all(&self) -> Vec<(IngressId, BgpPeerStatsSnapshot)> {
        self.inner
            .read()
            .unwrap()
            .iter()
            .map(|(id, s)| (*id, s.snapshot()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_sub_adj_rib_in() {
        let s = BgpPeerStats::new();
        s.add_adj_rib_in((1, 1), 10);
        s.add_adj_rib_in((2, 1), 5);
        assert_eq!(s.adj_rib_in_routes.load(Ordering::Relaxed), 15);

        s.sub_adj_rib_in((1, 1), 3);
        let snap = s.snapshot();
        assert_eq!(snap.adj_rib_in_routes, 12);
        let by_key: HashMap<_, _> =
            snap.adj_rib_in_per_afi_safi.iter().cloned().collect();
        assert_eq!(by_key[&(1u16, 1u8)], 7);
        assert_eq!(by_key[&(2u16, 1u8)], 5);
    }

    #[test]
    fn sub_saturates_at_zero() {
        let s = BgpPeerStats::new();
        s.add_adj_rib_in((1, 1), 2);
        s.sub_adj_rib_in((1, 1), 99);
        assert_eq!(s.adj_rib_in_routes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn registry_get_or_create_is_idempotent() {
        let reg = BgpPeerStatsRegistry::new();
        let a = reg.get_or_create(42);
        let b = reg.get_or_create(42);
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn reset_clears_per_afi_safi() {
        let s = BgpPeerStats::new();
        s.add_adj_rib_in((1, 1), 10);
        s.add_adj_rib_in((2, 1), 5);
        s.reset_adj_rib_in();
        let snap = s.snapshot();
        assert_eq!(snap.adj_rib_in_routes, 0);
        assert!(snap.adj_rib_in_per_afi_safi.is_empty());
    }
}
