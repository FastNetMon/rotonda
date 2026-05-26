use std::{
    collections::{hash_set, HashMap},
    fmt,
    hash::{BuildHasher, Hasher},
    net::IpAddr,
    ops::Deref,
    sync::{Arc, Mutex},
};

use chrono::{Duration, Utc};
use inetnum::{addr::Prefix, asn::Asn};
use log::{debug, error, trace, warn};
use rotonda_store::{
    epoch,
    errors::{FatalResult, PrefixStoreError},
    match_options::{MatchOptions, QueryResult},
    prefix_record::{Meta, PrefixRecord, Record, RecordSet, RouteStatus},
    rib::{config::MemoryOnlyConfig, StarCastRib},
    stats::UpsertReport,
};
use routecore::bgp::{
    aspath::HopPath,
    nlri::afisafi::{IsPrefix, Nlri},
    path_attributes::PaMap,
    path_selection::{OrdRoute, Rfc4271, TiebreakerInfo},
    types::{AfiSafiType, Otc},
};
use serde::{
    ser::{SerializeSeq, SerializeStruct},
    Serialize, Serializer,
};

use crate::{
    ingress::{self, register::IdAndInfo, IngressId, IngressInfo},
    payload::{
        PathAttributeInterner, RotondaPaMap, RotondaPaMapWithQueryFilter,
        RotondaRoute, RouterId,
    },
    representation::{GenOutput, Json},
    roto_runtime::{types::RotoPackage, Ctx},
};

use super::{http_ng::Include, QueryFilter};

type Store = StarCastRib<RotondaPaMap, MemoryOnlyConfig>;

type RotoHttpFilter = roto::TypedFunc<
    Ctx,
    fn(
        roto::Val<crate::roto_runtime::RcRotondaPaMap>,
    ) -> roto::Verdict<(), ()>,
>;

#[derive(Clone)]
pub struct Rib {
    unicast: Arc<Option<Store>>,
    multicast: Arc<Option<Store>>,
    #[allow(dead_code)]
    other_fams:
        HashMap<AfiSafiType, HashMap<(IngressId, Nlri<bytes::Bytes>), PaMap>>,
    pub(crate) ingress_register: Arc<ingress::Register>,
    roto_package: Option<Arc<RotoPackage>>,
    roto_context: Arc<Mutex<Ctx>>,
    path_attribute_interner: Arc<PathAttributeInterner>,
    // Serialises every writer to the per-store `withdrawn_muis_bmin`
    // roaring bitmap: `withdraw_for_ingress` (mark_mui_as_withdrawn) AND
    // `mark_ingress_active` (mark_mui_as_active). rotonda-store 0.5.0's
    // `TreeBitMap::update_withdrawn_muis_bmin` has a CAS retry loop that
    // never reloads its `expected` value, so any concurrent writer that
    // loses a CAS race livelocks indefinitely. Holding this mutex around
    // every call guarantees there's only ever one in flight.
    withdraw_lock: Arc<Mutex<()>>,
}

#[derive(Copy, Clone, Debug)]
struct Multicast(bool);

impl Rib {
    pub fn new(
        ingress_register: Arc<ingress::Register>,
        roto_package: Option<Arc<RotoPackage>>,
        roto_context: Arc<Mutex<Ctx>>,
    ) -> Result<Self, PrefixStoreError> {
        Ok(Rib {
            unicast: Arc::new(Some(Store::try_default()?)),
            multicast: Arc::new(Some(Store::try_default()?)),
            other_fams: HashMap::new(),
            ingress_register,
            roto_package,
            roto_context,
            path_attribute_interner: Arc::new(
                PathAttributeInterner::default(),
            ),
            withdraw_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn store(&self) -> Result<&Store, PrefixStoreError> {
        if let Some(rib) = self.unicast.as_ref() {
            Ok(rib)
        } else {
            Err(PrefixStoreError::StoreNotReadyError)
        }
    }

    pub fn insert(
        &self,
        val: &RotondaRoute,
        route_status: RouteStatus,
        ltime: u64,
        ingress_id: IngressId,
        retain_withdrawn_attributes: bool,
        deduplicate_path_attributes: bool,
    ) -> Result<UpsertReport, String> {
        let res = match val {
            RotondaRoute::Ipv4Unicast(n, ..) => self.insert_prefix(
                &n.prefix(),
                Multicast(false),
                val,
                route_status,
                ltime,
                ingress_id,
                retain_withdrawn_attributes,
                deduplicate_path_attributes,
            ),
            RotondaRoute::Ipv6Unicast(n, ..) => self.insert_prefix(
                &n.prefix(),
                Multicast(false),
                val,
                route_status,
                ltime,
                ingress_id,
                retain_withdrawn_attributes,
                deduplicate_path_attributes,
            ),
            RotondaRoute::Ipv4Multicast(n, ..) => self.insert_prefix(
                &n.prefix(),
                Multicast(true),
                val,
                route_status,
                ltime,
                ingress_id,
                retain_withdrawn_attributes,
                deduplicate_path_attributes,
            ),
            RotondaRoute::Ipv6Multicast(n, ..) => self.insert_prefix(
                &n.prefix(),
                Multicast(true),
                val,
                route_status,
                ltime,
                ingress_id,
                retain_withdrawn_attributes,
                deduplicate_path_attributes,
            ),
        };
        res.map_err(|e| e.to_string())
    }

    fn insert_prefix(
        &self,
        prefix: &Prefix,
        multicast: Multicast,
        val: &RotondaRoute,
        route_status: RouteStatus,
        ltime: u64,
        ingress_id: IngressId,
        retain_withdrawn_attributes: bool,
        deduplicate_path_attributes: bool,
    ) -> Result<UpsertReport, PrefixStoreError> {
        // Check whether our self.rib is Some(..) or bail out.
        let arc_store = match multicast.0 {
            true => self.multicast.clone(),
            false => self.unicast.clone(),
        };

        let store = (*arc_store)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError)?;

        let mui = ingress_id;

        if route_status == RouteStatus::Withdrawn {
            if !retain_withdrawn_attributes {
                if !store.contains(prefix, Some(mui)) {
                    return Ok(UpsertReport {
                        cas_count: 0,
                        prefix_new: false,
                        mui_new: false,
                        mui_count: 0,
                    });
                }

                let pubrec = Record::new(
                    mui,
                    ltime,
                    RouteStatus::Withdrawn,
                    RotondaPaMap::empty_path_attributes(),
                );

                return store.insert(prefix, pubrec, None);
            }

            // instead of creating an empty PrefixRoute for this Prefix and
            // putting that in the store, we use the new
            // mark_mui_as_withdrawn_for_prefix . This way, we preserve the
            // last seen attributes/nexthop for this {prefix,mui} combination,
            // while setting the status to Withdrawn.
            store.mark_mui_as_withdrawn_for_prefix(prefix, mui, 0)?;

            // FIXME this is just to satisfy the function signature, but is
            // quite useless as-is.
            return Ok(UpsertReport {
                cas_count: 0,
                prefix_new: false,
                mui_new: false,
                mui_count: 0,
            });
        }

        let pubrec = Record::new(
            mui,
            ltime,
            route_status,
            if deduplicate_path_attributes {
                val.rotonda_pamap()
                    .dedup_with(&self.path_attribute_interner)
            } else {
                val.rotonda_pamap().clone()
            },
        );

        store.insert(
            prefix, pubrec, None, // Option<TBI>
        )
    }

    pub fn withdraw_for_ingress(
        &self,
        ingress_id: IngressId,
        specific_afisafi: Option<AfiSafiType>,
        retain_withdrawn_attributes: bool,
    ) {
        // See the `withdraw_lock` field comment for why this is held across
        // the whole body: rotonda-store 0.5.0's CAS retry loop livelocks
        // under concurrent writers.
        let _guard = self
            .withdraw_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // This signals a withdraw-all-for-peer, because a BGP session
        // was lost or because a BMP PeerDownNotification was
        // received.

        // Things to take care of, here of elsewhere:
        //
        // * mark all (active) prefixes for this ingress as
        //   'withdrawn' in the store
        // * generate BGP UPDATEs for those prefixes that were
        //   actually updated to the withdrawn state. Note that there
        //   might have been prefixes for this ingress that were
        //   previously withdrawn already, for which no UPDATEs should
        //   be generated!
        // * send out these UPDATEs as Update::Bulk payloads to the
        //   east:
        //     - what if the first unit eastwards is another RIB, does
        //     it make sense to create the UPDATEs? might make more
        //     sense to forward the current Update::Withdraw(..)
        //     instead.
        //     - the UPDATEs only make sense if anything needs to go
        //     out over a BGP session again. But, in that case, the
        //     UPDATE can only be correctly generated by the BGP
        //     connection (in the ingress unit) itself, because of
        //     possible session-level state (e.g. ADDPATH or Extended
        //     PDU size capabilities).
        //     Moreover, it only makes sense to send out the UPDATE if
        //     the specific prefix was previously annouced, i.e. it is
        //     in the Adj-RIB-Out for that session. This might be
        //     differ from session to session because of local policy,
        //     roto scripts, or what not.
        //     As such, perhaps we should leave the generation of
        //     those withdrawals to the very latest (most-East) point?

        debug!("withdraw_for_ingress for {ingress_id}");
        if !retain_withdrawn_attributes {
            self.compact_withdrawn_attributes_for_ingress(
                ingress_id,
                specific_afisafi,
            );
        }
        match specific_afisafi {
            None => {
                // Set all address families to withdrawn.
                // `mark_mui_as_withdrawn` already covers both v4 and v6 in
                // the unicast store in a single tree walk.

                debug!("mark_mui_as_withdrawn on unicast for {ingress_id}");
                if let Err(e) = (*self.unicast)
                    .as_ref()
                    .unwrap()
                    .mark_mui_as_withdrawn(ingress_id)
                {
                    error!(
                        "failed to mark MUI as withdrawn in unicast rib: {}",
                        e
                    )
                }

                if let Err(e) = (*self.multicast)
                    .as_ref()
                    .unwrap()
                    .mark_mui_as_withdrawn(ingress_id)
                {
                    error!("failed to mark MUI as withdrawn in multicast rib: {}", e)
                }

                // TODO withdraw all other afisafis as well!
            }
            Some(AfiSafiType::Ipv4Unicast) => {
                if let Err(e) = (*self.unicast)
                    .as_ref()
                    .unwrap()
                    .mark_mui_as_withdrawn_v4(ingress_id)
                {
                    error!("failed to mark MUI as withdrawn for v4: {}", e)
                }
            }
            Some(AfiSafiType::Ipv6Unicast) => {
                if let Err(e) = (*self.unicast)
                    .as_ref()
                    .unwrap()
                    .mark_mui_as_withdrawn_v6(ingress_id)
                {
                    error!("failed to mark MUI as withdrawn for v6: {}", e)
                }
            }
            Some(AfiSafiType::Ipv4Multicast) => {
                if let Err(e) = (*self.multicast)
                    .as_ref()
                    .unwrap()
                    .mark_mui_as_withdrawn_v4(ingress_id)
                {
                    error!("failed to mark MUI as withdrawn for v4: {}", e)
                }
            }
            Some(AfiSafiType::Ipv6Multicast) => {
                if let Err(e) = (*self.multicast)
                    .as_ref()
                    .unwrap()
                    .mark_mui_as_withdrawn_v6(ingress_id)
                {
                    error!("failed to mark MUI as withdrawn for v6: {}", e)
                }
            }

            afisafi => {
                panic!("no support to withdraw {:?} yet", afisafi)
            }
        }
    }

    pub fn compact_withdrawn_attributes_for_ingress(
        &self,
        ingress_id: IngressId,
        specific_afisafi: Option<AfiSafiType>,
    ) {
        match specific_afisafi {
            None => {
                self.compact_withdrawn_attributes_in_store(
                    self.unicast.as_ref().as_ref(),
                    ingress_id,
                    None,
                );
                self.compact_withdrawn_attributes_in_store(
                    self.multicast.as_ref().as_ref(),
                    ingress_id,
                    None,
                );
            }
            Some(AfiSafiType::Ipv4Unicast) => {
                self.compact_withdrawn_attributes_in_store(
                    self.unicast.as_ref().as_ref(),
                    ingress_id,
                    Some(AfiSafiType::Ipv4Unicast),
                );
            }
            Some(AfiSafiType::Ipv6Unicast) => {
                self.compact_withdrawn_attributes_in_store(
                    self.unicast.as_ref().as_ref(),
                    ingress_id,
                    Some(AfiSafiType::Ipv6Unicast),
                );
            }
            Some(AfiSafiType::Ipv4Multicast) => {
                self.compact_withdrawn_attributes_in_store(
                    self.multicast.as_ref().as_ref(),
                    ingress_id,
                    Some(AfiSafiType::Ipv4Multicast),
                );
            }
            Some(AfiSafiType::Ipv6Multicast) => {
                self.compact_withdrawn_attributes_in_store(
                    self.multicast.as_ref().as_ref(),
                    ingress_id,
                    Some(AfiSafiType::Ipv6Multicast),
                );
            }
            afisafi => {
                warn!(
                    "no support to compact withdrawn attributes for {:?} yet",
                    afisafi
                );
            }
        }
    }

    fn compact_withdrawn_attributes_in_store(
        &self,
        store: Option<&Store>,
        ingress_id: IngressId,
        specific_afisafi: Option<AfiSafiType>,
    ) {
        let Some(store) = store else {
            return;
        };

        let guard = &epoch::pin();
        let prefixes = match specific_afisafi {
            Some(AfiSafiType::Ipv4Unicast | AfiSafiType::Ipv4Multicast) => {
                store
                    .prefixes_iter_v4(guard)
                    .flatten()
                    .filter(|prefix_record| {
                        prefix_record
                            .meta
                            .iter()
                            .any(|record| record.multi_uniq_id == ingress_id)
                    })
                    .map(|prefix_record| prefix_record.prefix)
                    .collect::<Vec<_>>()
            }
            Some(AfiSafiType::Ipv6Unicast | AfiSafiType::Ipv6Multicast) => {
                store
                    .prefixes_iter_v6(guard)
                    .flatten()
                    .filter(|prefix_record| {
                        prefix_record
                            .meta
                            .iter()
                            .any(|record| record.multi_uniq_id == ingress_id)
                    })
                    .map(|prefix_record| prefix_record.prefix)
                    .collect::<Vec<_>>()
            }
            _ => store
                .prefixes_iter(guard)
                .flatten()
                .filter(|prefix_record| {
                    prefix_record
                        .meta
                        .iter()
                        .any(|record| record.multi_uniq_id == ingress_id)
                })
                .map(|prefix_record| prefix_record.prefix)
                .collect::<Vec<_>>(),
        };

        for prefix in prefixes {
            let pubrec = Record::new(
                ingress_id,
                0,
                RouteStatus::Withdrawn,
                RotondaPaMap::empty_path_attributes(),
            );

            if let Err(err) = store.insert(&prefix, pubrec, None) {
                warn!(
                    "failed to compact withdrawn attributes for {prefix} and ingress {ingress_id}: {err}"
                );
            }
        }
    }

    pub fn mark_ingress_active(&self, ingress_id: IngressId) {
        // Same hazard as `withdraw_for_ingress`: `mark_mui_as_active_*`
        // walks `update_withdrawn_muis_bmin`, whose CAS retry loop
        // livelocks under concurrent writers. Serialise with the
        // withdraw path.
        let _guard = self
            .withdraw_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(e) = (*self.unicast)
            .as_ref()
            .unwrap()
            .mark_mui_as_active_v4(ingress_id)
        {
            error!("failed to mark MUI as active in unicast v4 rib: {e}")
        }
        if let Err(e) = (*self.unicast)
            .as_ref()
            .unwrap()
            .mark_mui_as_active_v6(ingress_id)
        {
            error!("failed to mark MUI as active in unicast v6 rib: {e}")
        }
        if let Err(e) = (*self.multicast)
            .as_ref()
            .unwrap()
            .mark_mui_as_active_v4(ingress_id)
        {
            error!("failed to mark MUI as active in multicast v4 rib: {e}")
        }
        if let Err(e) = (*self.multicast)
            .as_ref()
            .unwrap()
            .mark_mui_as_active_v6(ingress_id)
        {
            error!("failed to mark MUI as active in multicast v6 rib: {e}")
        }
    }

    pub fn match_prefix(
        &self,
        prefix: &Prefix,
        match_options: &MatchOptions,
    ) -> Result<QueryResult<RotondaPaMap>, String> {
        let guard = &epoch::pin();
        let store = (*self.unicast)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;
        let unicast_res = store
            .match_prefix(prefix, match_options, guard)
            .map_err(|err| err.to_string())?;
        if unicast_res.records.is_empty()
            && unicast_res.less_specifics.is_none()
            && unicast_res.more_specifics.is_none()
        {
            debug!("no result in unicast store, trying multicast");
            let multicast_store = (*self.multicast)
                .as_ref()
                .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;
            let multicast_res = multicast_store
                .match_prefix(prefix, match_options, guard)
                .map_err(|err| err.to_string())?;
            if !(multicast_res.records.is_empty()
                && multicast_res.less_specifics.is_none()
                && multicast_res.more_specifics.is_none())
            {
                return Ok(multicast_res);
            }
        }
        Ok(unicast_res)
    }

    /// Iterate all prefix records in the unicast RIB.
    /// Each PrefixRecord contains the prefix and all non-withdrawn route
    /// records (from all peers). Withdrawn entries are filtered out at the
    /// iterator level so callers don't need to skip them, and PrefixRecords
    /// whose entire meta vec is withdrawn are dropped entirely — keeps the
    /// returned Vec smaller for large RIBs (relevant on initial BMP dump).
    pub fn iter_all_prefix_records(
        &self,
    ) -> Result<Vec<PrefixRecord<RotondaPaMap>>, String> {
        let guard = &epoch::pin();
        let store = (*self.unicast)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;

        let res: Vec<PrefixRecord<RotondaPaMap>> = store
            .prefixes_iter(guard)
            .flatten()
            .filter_map(|mut pr| {
                pr.meta.retain(|r| r.status != RouteStatus::Withdrawn);
                if pr.meta.is_empty() {
                    None
                } else {
                    Some(pr)
                }
            })
            .collect();

        debug!("rib::iter_all_prefix_records: {} prefix records", res.len());
        Ok(res)
    }

    pub fn match_ingress_id(
        &self,
        ingress_id: IngressId,
        //match_options: &MatchOptions,
    ) -> Result<Vec<PrefixRecord<RotondaPaMap>>, String> {
        let guard = &epoch::pin();
        let store = (*self.unicast)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;

        let include_withdrawals = false;

        let mut res = store
            .iter_records_for_mui_v4(ingress_id, include_withdrawals, guard)
            .collect::<FatalResult<Vec<_>>>()
            .map_err(|e| e.to_string())?;
        res.append(
            &mut store
                .iter_records_for_mui_v6(
                    ingress_id,
                    include_withdrawals,
                    guard,
                )
                .collect::<FatalResult<Vec<_>>>()
                .map_err(|e| e.to_string())?,
        );

        //tmp: while the per mui methods do not work yet, we can use
        //.prefixes_iter() to test the output.
        //let res = store.prefixes_iter().collect::<Vec<_>>();
        debug!(
            "rib::match_ingress_id for {ingress_id}: {} results",
            res.len()
        );
        Ok(res)
    }

    //
    // new methods returning results to be used by both HTTP API and CLI, i.e. types that will need
    // impls for ToJson and ToCli so they can be impl OutputFormat
    //
    // For now, all these new methods are prefixed search_
    //

    /// Query the Store for routes based on Nlri/prefix
    pub fn search_routes(
        &self,
        afisafi: AfiSafiType,
        //nlri: Nlri<&[u8]>,
        nlri: Prefix, // change to Nlri or equivalent after routecore refactor
        filter: QueryFilter,
        //) -> Result<QueryResult<RotondaPaMap>, String> {
    ) -> Result<SearchResult, String> {
        let guard = &epoch::pin();

        let store = match afisafi {
            AfiSafiType::Ipv4Unicast | AfiSafiType::Ipv6Unicast => (*self
                .unicast)
                .as_ref()
                .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?,
            AfiSafiType::Ipv4Multicast | AfiSafiType::Ipv6Multicast => {
                (*self.multicast)
                    .as_ref()
                    .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?
            }
            u => {
                return Err(format!("address family {u} unsupported"));
            }
        };

        let match_options = &MatchOptions {
            match_type: rotonda_store::match_options::MatchType::ExactMatch,
            include_withdrawn: false,
            include_less_specifics: filter
                .include
                .contains(&Include::LessSpecifics),
            include_more_specifics: filter
                .include
                .contains(&Include::MoreSpecifics),
            mui: filter.ingress_id,
            include_history:
                rotonda_store::match_options::IncludeHistory::None,
        };

        debug!("match_options.mui: {:?}", match_options.mui);

        let t0 = std::time::Instant::now();
        let mut res = store
            .match_prefix(&nlri, match_options, guard)
            .map(|res| {
                SearchResult::new(
                    res,
                    self.ingress_register.clone(),
                    filter.clone(),
                )
            })
            .map_err(|err| err.to_string());

        // filter on:
        // X origin asn
        // X peer rib type
        // X ingress_id -> done via Store.match_prefix already
        // X otc
        //
        // - community
        // - large community
        // - peer distinguisher

        debug!(
            "store lookup took {:?}",
            std::time::Instant::now().duration_since(t0)
        );

        // Find the roto function from the compiled Roto Package.
        // We do this here, once, to reduce acquiring locks and such over and over.
        // If the query contains a filter name for which no roto function exists, this simply
        // filters as if no filter was passed:

        //let maybe_roto_function: Option<RotoHttpFilter> = filter.roto_function.as_ref().and_then(|name| {
        //    self.roto_package.as_ref().and_then(|package| {
        //        let mut package = package.lock().unwrap();
        //        package.get_function(name.as_str()).ok()
        //    })
        //});

        // Alternatively, we could return an error:
        let maybe_roto_function: Option<RotoHttpFilter> = match filter
            .roto_function
            .as_ref()
        {
            Some(name) => {
                debug!("looking up {name} in compiled roto package");
                if let Some(f) =
                    self.roto_package.as_ref().and_then(|package| {
                        let mut package = package.lock().unwrap();
                        package.get_function(name.as_str()).ok()
                    })
                {
                    Some(f)
                } else {
                    error!("query for undefined roto filter");
                    return Err(format!("no roto function '{name}' defined"));
                }
            }
            None => None,
        };

        let t0 = std::time::Instant::now();

        let _ = res.as_mut().map(|sr| {
            self.apply_filter(
                &mut sr.query_result.records,
                &filter,
                maybe_roto_function.clone(),
                &sr.ingress_info,
            );
            if let Some(rs) = sr.query_result.more_specifics.as_mut() {
                rs.v4.retain_mut(|pr| {
                    self.apply_filter(
                        &mut pr.meta,
                        &filter,
                        maybe_roto_function.clone(),
                        &sr.ingress_info,
                    );
                    !pr.meta.is_empty()
                });
                rs.v6.retain_mut(|pr| {
                    self.apply_filter(
                        &mut pr.meta,
                        &filter,
                        maybe_roto_function.clone(),
                        &sr.ingress_info,
                    );
                    !pr.meta.is_empty()
                });
            }
            if let Some(rs) = sr.query_result.less_specifics.as_mut() {
                rs.v4.retain_mut(|pr| {
                    self.apply_filter(
                        &mut pr.meta,
                        &filter,
                        maybe_roto_function.clone(),
                        &sr.ingress_info,
                    );
                    !pr.meta.is_empty()
                });
                rs.v6.retain_mut(|pr| {
                    self.apply_filter(
                        &mut pr.meta,
                        &filter,
                        maybe_roto_function.clone(),
                        &sr.ingress_info,
                    );
                    !pr.meta.is_empty()
                });
            }
        });

        debug!(
            "filtering took {:?}",
            std::time::Instant::now().duration_since(t0)
        );

        res
    }

    // XXX:
    // if the results from the store are already filtered on a MUI/ingress_id, we do not need to
    // query the ingress register over and over to fetch info like peer_rib_type
    // In such case, we could optimize:
    //  - fetch the required info once, pass it into apply_filter
    //  - in apply_filter, check for such info and branch: if let Some(passed_info), etc

    fn apply_filter(
        &self,
        records: &mut Vec<Record<RotondaPaMap>>,
        filter: &QueryFilter,
        roto_filter: Option<RotoHttpFilter>,
        ingress_info: &HashMap<IngressId, IngressInfo>,
    ) {
        if let Some(ingress_id) = filter.ingress_id {
            records.retain(|r| r.multi_uniq_id == ingress_id);
        }

        if let Some(rib_type) = filter.rib_type {
            records.retain(|r| {
                ingress_info
                    .get(&r.multi_uniq_id)
                    .map(|ii| ii.peer_rib_type == Some(rib_type))
                    .unwrap_or(true)
            });
        }

        if let Some(peer_asn) = filter.peer_asn {
            records.retain(|r| {
                ingress_info
                    .get(&r.multi_uniq_id)
                    .map(|ii| ii.remote_asn == Some(peer_asn))
                    .unwrap_or(true)
            });
        }

        if let Some(peer_addr) = filter.peer_addr {
            records.retain(|r| {
                ingress_info
                    .get(&r.multi_uniq_id)
                    .map(|ii| ii.remote_addr == Some(peer_addr))
                    .unwrap_or(true)
            });
        }

        if let Some(f) = roto_filter {
            let mut ctx = self.roto_context.lock().unwrap();
            records.retain_mut(|r| {
                let rc_r: crate::roto_runtime::RcRotondaPaMap =
                    std::mem::take(&mut r.meta).into();
                match f.call(&mut ctx, roto::Val(rc_r.clone())) {
                    roto::Verdict::Accept(_) => {
                        r.meta = std::rc::Rc::into_inner(rc_r).unwrap();
                        true
                    }
                    roto::Verdict::Reject(_) => {
                        //debug!("in Reject for {}", roto_function);
                        false
                    }
                }
            });
        }

        if filter.origin_asn.is_some()
            || filter.otc.is_some()
            || filter.community.is_some()
            || filter.large_community.is_some()
            || filter.rov_status.is_some()
        {
            records.retain(|r| {
                if let Some(rov_status) = filter.rov_status {
                    if r.meta.rpki_info().rov_status() != rov_status {
                        return false
                    }
                }
                let path_attributes = r.meta.path_attributes();
                if let Some(otc) = filter.otc {
                    if Some(otc) != path_attributes.get::<Otc>().map(|otc| otc.0) {
                        return false
                    }
                }
                if let Some(large_community) = filter.large_community {
                    if let Some(list) = path_attributes.get::<routecore::bgp::path_attributes::LargeCommunitiesList>() {
                        if !list.communities().contains(&large_community) {
                            return false
                        }
                    } else {
                        return false
                    }
                }
                if let Some(community) = filter.community {
                    if let Some(list) = path_attributes.get::<routecore::bgp::message::update_builder::StandardCommunitiesList>() {
                        if !list.communities().contains(&community) {
                            return false
                        }
                    } else {
                        return false
                    }
                }
                if let Some(origin_asn) = filter.origin_asn {
                    if Some(origin_asn) != path_attributes.get::<HopPath>().and_then(|hp|
                        hp.origin().and_then(|hop| hop.clone().try_into().ok())
                    ) {
                        return false;
                    }
                }
                true
            });

            // TODO:
            // - communities
            // - large communities
            // - route distinguisher
        }
    }

    pub fn search_and_output_routes<T>(
        &self,
        mut target: T,
        afisafi: AfiSafiType,
        //nlri: Nlri<&[u8]>,
        nlri: Prefix, // change to Nlri or equivalent after routecore refactor
        filter: QueryFilter,
    ) -> Result<(), String>
    where
        SearchResult: GenOutput<T>,
    {
        match self.search_routes(afisafi, nlri, filter) {
            Ok(search_results) => {
                let _ = search_results.write(&mut target);
            }
            Err(e) => {
                error!("error in search_and_output_routes: {e}");
                return Err(format!("store error: {e}"));
            }
        }

        Ok(())
    }

    pub fn check_filter_and_store(
        &self,
        afisafi: AfiSafiType,
        filter: &QueryFilter,
    ) -> Result<(), String> {
        match afisafi {
            AfiSafiType::Ipv4Unicast | AfiSafiType::Ipv6Unicast => {
                if self.unicast.as_ref().is_none() {
                    return Err("Store not ready".to_string());
                }
            }
            AfiSafiType::Ipv4Multicast | AfiSafiType::Ipv6Multicast => {
                if self.multicast.as_ref().is_none() {
                    return Err("Store not ready".to_string());
                }
            }
            u => {
                return Err(format!("address family {u} unsupported"));
            }
        }

        if let Some(name) = filter.roto_function.as_ref() {
            let exists =
                self.roto_package.as_ref().map_or(false, |package| {
                    let mut package = package.lock().unwrap();
                    let res: Result<RotoHttpFilter, _> =
                        package.get_function(name.as_str());
                    res.is_ok()
                });
            if !exists {
                return Err(format!("no roto function '{name}' defined"));
            }
        }

        Ok(())
    }

    pub fn write_jsonl_stream<W: std::io::Write>(
        &self,
        afisafi: AfiSafiType,
        query_prefix: Prefix,
        filter: QueryFilter,
        target: &mut W,
    ) -> Result<(), crate::representation::OutputError> {
        let guard = &epoch::pin();

        let store = match afisafi {
            AfiSafiType::Ipv4Unicast | AfiSafiType::Ipv6Unicast => {
                (*self.unicast).as_ref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Store not ready",
                    )
                })?
            }
            AfiSafiType::Ipv4Multicast | AfiSafiType::Ipv6Multicast => {
                (*self.multicast).as_ref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Store not ready",
                    )
                })?
            }
            u => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("address family {u} unsupported"),
                )
                .into());
            }
        };

        let ingress_info = self.ingress_register.cloned_info();

        let maybe_roto_function: Option<RotoHttpFilter> =
            match filter.roto_function.as_ref() {
                Some(name) => {
                    if let Some(f) =
                        self.roto_package.as_ref().and_then(|package| {
                            let mut package = package.lock().unwrap();
                            package.get_function(name.as_str()).ok()
                        })
                    {
                        Some(f)
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("no roto function '{name}' defined"),
                        )
                        .into());
                    }
                }
                None => None,
            };

        // Determine if we iterate over IPv4 or IPv6
        let is_v4 = query_prefix.is_v4();
        let iter: Box<dyn Iterator<Item = PrefixRecord<RotondaPaMap>> + '_> =
            if is_v4 {
                Box::new(store.prefixes_iter_v4(guard).flatten())
            } else {
                Box::new(store.prefixes_iter_v6(guard).flatten())
            };

        for mut pr in iter {
            // 1. Filter out withdrawn records
            pr.meta.retain(|r| r.status != RouteStatus::Withdrawn);
            if pr.meta.is_empty() {
                continue;
            }

            // 2. Apply standard filters in place
            self.apply_filter(
                &mut pr.meta,
                &filter,
                maybe_roto_function.clone(),
                &ingress_info,
            );
            if pr.meta.is_empty() {
                continue;
            }

            // Determine if the prefix is the query prefix itself
            let section = if pr.prefix == query_prefix {
                "data"
            } else {
                "moreSpecifics"
            };

            for record in &pr.meta {
                let ingress = ingress_info
                    .get(&record.multi_uniq_id)
                    .map(|info| (record.multi_uniq_id, info).into());
                let status = RouteStatusWrapper(record.status);

                if filter.fields_path_attributes.is_some() {
                    let line = JsonlLineFiltered {
                        prefix: pr.prefix,
                        section,
                        status,
                        ingress,
                        pamap: RotondaPaMapWithQueryFilter(
                            &record.meta,
                            &filter,
                        ),
                    };
                    serde_json::to_writer(&mut *target, &line)?;
                } else {
                    let line = JsonlLine {
                        prefix: pr.prefix,
                        section,
                        status,
                        ingress,
                        pamap: &record.meta,
                    };
                    serde_json::to_writer(&mut *target, &line)?;
                }
                target.write_all(b"\n")?;
            }
        }

        Ok(())
    }

    /// Query the store based on `IngressId`/MUI
    pub fn search_routes_for_ingress(
        _afisafi: AfiSafiType,
        _nlri: Nlri<&[u8]>,
        _ingress_id: IngressId,
        _match_options: MatchOptions,
    ) -> Result<SearchResult, String> {
        todo!()
    }

    /// Query the store based on Origin AS in the AS_PATH
    pub fn search_routes_for_origin_as(
        _afisafi: AfiSafiType,
        _origin_as: Asn,
        _match_options: MatchOptions,
    ) -> Result<SearchResult, String> {
        todo!()
    }
}

/// Wrapper around `QueryResult` from rotonda-store
///
/// This wrapper is used to impl the necessary traits on, to enable consistent representation
/// between CLI, HTTP API, etc.
pub struct SearchResult {
    pub(crate) query_result: QueryResult<RotondaPaMap>,
    pub(crate) ingress_info: HashMap<IngressId, IngressInfo>,
    query_filter: QueryFilter,
}

crate::genoutput_json!(SearchResult);

impl SearchResult {
    fn new(
        query_result: QueryResult<RotondaPaMap>,
        ingress_register: Arc<ingress::Register>,
        query_filter: QueryFilter,
    ) -> Self {
        Self {
            query_result,
            ingress_info: ingress_register.cloned_info(),
            query_filter,
        }
    }

    pub(crate) fn ingress_info(
        &self,
        ingress_id: IngressId,
    ) -> Option<&IngressInfo> {
        self.ingress_info.get(&ingress_id)
    }

    pub fn query_filter(&self) -> &QueryFilter {
        &self.query_filter
    }

    fn id_and_info(&self, ingress_id: IngressId) -> Option<IdAndInfo<'_>> {
        self.ingress_info
            .get(&ingress_id)
            .map(|info| (ingress_id, info).into())
    }

    /// Write one JSON object per line (NDJSON / JSONL).
    ///
    /// Each line is a flat record uniquely identified by (prefix, ingressId).
    /// A `section` field marks whether the line came from the matched prefix
    /// itself or from the more-/less-specifics include sets, so no data is
    /// lost relative to the nested JSON shape.
    pub fn write_jsonl<W: std::io::Write>(
        &self,
        target: &mut W,
    ) -> Result<(), crate::representation::OutputError> {
        if let Some(prefix) = self.query_result.prefix {
            for record in &self.query_result.records {
                self.write_jsonl_line(target, prefix, record, "data")?;
            }
        }
        if let Some(set) = self.query_result.more_specifics.as_ref() {
            self.write_jsonl_recordset(target, set, "moreSpecifics")?;
        }
        if let Some(set) = self.query_result.less_specifics.as_ref() {
            self.write_jsonl_recordset(target, set, "lessSpecifics")?;
        }
        Ok(())
    }

    fn write_jsonl_recordset<W: std::io::Write>(
        &self,
        target: &mut W,
        set: &RecordSet<RotondaPaMap>,
        section: &'static str,
    ) -> Result<(), crate::representation::OutputError> {
        for pr in set.v4.iter().chain(set.v6.iter()) {
            for record in &pr.meta {
                self.write_jsonl_line(target, pr.prefix, record, section)?;
            }
        }
        Ok(())
    }

    fn write_jsonl_line<W: std::io::Write>(
        &self,
        target: &mut W,
        prefix: Prefix,
        record: &Record<RotondaPaMap>,
        section: &'static str,
    ) -> Result<(), crate::representation::OutputError> {
        let query_filter = &self.query_filter;
        let ingress = self.id_and_info(record.multi_uniq_id);
        let status = RouteStatusWrapper(record.status);
        if query_filter.fields_path_attributes.is_some() {
            let line = JsonlLineFiltered {
                prefix,
                section,
                status,
                ingress,
                pamap: RotondaPaMapWithQueryFilter(
                    &record.meta,
                    query_filter,
                ),
            };
            serde_json::to_writer(&mut *target, &line)?;
        } else {
            let line = JsonlLine {
                prefix,
                section,
                status,
                ingress,
                pamap: &record.meta,
            };
            serde_json::to_writer(&mut *target, &line)?;
        }
        target.write_all(b"\n")?;
        Ok(())
    }
}

#[derive(Serialize)]
struct JsonlLine<'a, 'b> {
    prefix: Prefix,
    section: &'static str,
    status: RouteStatusWrapper,
    #[serde(skip_serializing_if = "Option::is_none")]
    ingress: Option<IdAndInfo<'b>>,
    #[serde(flatten)]
    pamap: &'a RotondaPaMap,
}

#[derive(Serialize)]
struct JsonlLineFiltered<'a, 'b, 'c> {
    prefix: Prefix,
    section: &'static str,
    status: RouteStatusWrapper,
    #[serde(skip_serializing_if = "Option::is_none")]
    ingress: Option<IdAndInfo<'b>>,
    #[serde(flatten)]
    pamap: RotondaPaMapWithQueryFilter<'a, 'c>,
}

impl Serialize for SearchResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // TODO:
        // - ingress data (include in Arc<Register> in SearchResults wrapper?
        // X rpki rov status
        // X route status
        // - path attributes
        //      X first go based on existing Serialize impl
        //      - have a good look on what we did vs what we now think is best
        //      - especially communities:
        //          - old style was 241M vs ~90M for the 25M raw BMP input data
        //          - can we provide multiple 'styles' of output (via some query param), e.g.
        //              - the old, very verbose one,
        //              - one with Martin Pels' draft applied
        //
        //
        //
        // - includes:
        //  X more specifics
        //  X less specifics
        //  - lpm?
        //
        //  XXX: old format returned "data": [] (i.e. an array) so the matching prefix/nlri was
        //  repeated $n times.
        //  is that correct? shouldn't it be:
        //      "data": {
        //          "nlri": $some_nlri,
        //          "routes": [ ... ]
        //      },
        //      "included": ...
        //
        // the good thing about that repetition though is, that when including routes for more/less
        // specifics in the "included" section, we can follow the exact same structure?
        //
        //  XXX json:api states "included" is an _array_ where we returned a object before
        //  perhaps go with
        //
        //      "included": [
        //          {
        //              "include_type": "moreSpecifics",
        //                  "data": {
        //                      "nlri": $some_nlri,
        //                      "routes": [ { .. }, .. ]
        //                  }
        //          },
        //          {
        //              "include_type": "lessSpecifics",
        //                  "data": {
        //                      "nlri": $some_nlri,
        //                      "routes": [ { .. }, .. ]
        //                  }
        //          }
        //      ]
        //
        //
        //
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct IncludedData<'a, 'b> {
            #[serde(skip_serializing_if = "Option::is_none")]
            more_specifics: Option<RecordSetWrapper<'a, 'b>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            less_specifics: Option<RecordSetWrapper<'a, 'b>>,
        }

        let mut root = serializer.serialize_struct("nlri", 3)?;
        // TODO meta:
        // - routes pre filtering
        // - routes post filtering (== returned items)
        // - time to get from store
        // - time to serialize to json? (is that possible? or should meta then be at the end of the
        //   response perhaps?)
        root.serialize_field("meta", &None::<String>)?;
        root.serialize_field(
            "data",
            &Data {
                nlri: self.query_result.prefix,
                routes: RecordsWrapper(&self.query_result.records, self),
            },
        )?;

        root.serialize_field(
            "included",
            &IncludedData {
                more_specifics: self
                    .query_result
                    .more_specifics
                    .as_ref()
                    .map(|s| RecordSetWrapper(s, self)),
                less_specifics: self
                    .query_result
                    .less_specifics
                    .as_ref()
                    .map(|s| RecordSetWrapper(s, self)),
            },
        )?;
        root.end()
    }
}

#[derive(Serialize)]
struct Data<'a, 'b> {
    nlri: Option<Prefix>,
    routes: RecordsWrapper<'a, 'b>,
}

struct RecordsWrapper<'a, 'b>(
    &'a Vec<Record<RotondaPaMap>>,
    &'b SearchResult,
);
struct RecordWrapper<'a, 'b>(&'a Record<RotondaPaMap>, &'b SearchResult);
struct RecordSetWrapper<'a, 'b>(
    &'a RecordSet<RotondaPaMap>,
    &'b SearchResult,
);
struct PrefixRecordWrapper<'a, 'b>(
    &'a PrefixRecord<RotondaPaMap>,
    &'b SearchResult,
);
struct RouteStatusWrapper(RouteStatus);

impl Serialize for RecordsWrapper<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for e in self.0.iter() {
            seq.serialize_element(&RecordWrapper(e, self.1))?;
        }
        seq.end()
    }
}

impl Serialize for RecordWrapper<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // The RPKI information is stored in the value (so, RotondaPaMap) in the store.
        // The RotondaPaMap serializes to { rpki: {}, pathAttributes: [] },
        // so with serde(flatten) the wrapped store::Record serializes to
        // { status: foo, rpki: bla, pathAttributes: buzz, etc .. }
        // on 'one level'.
        //
        #[derive(Serialize)]
        struct Helper<'a, 'b> {
            status: RouteStatusWrapper,
            ingress: Option<IdAndInfo<'b>>,
            #[serde(flatten)]
            pamap: &'a RotondaPaMap,
            //pamap: RotondaPaMapWithQueryFilter<'a, 'b>,//(&RotondaPaMap, &self.2),
        }

        #[derive(Serialize)]
        struct HelperWithQueryFilter<'a, 'b, 'c> {
            status: RouteStatusWrapper,
            ingress: Option<IdAndInfo<'b>>,
            #[serde(flatten)]
            pamap: RotondaPaMapWithQueryFilter<'a, 'c>, //(&RotondaPaMap, &self.2),
        }

        // Possible optimisation: lift this wrapping (and thus branching up) into RecordsWrapper or
        // even SearchResult.
        // Have variants for:
        // - NoPathAttributes, i.e. &fields[pathAttributes]=
        // - FilteredPathAttrbutes, i.e. is_some() && !is_empty()
        // - Default case, not specified, so we only filter out typecodes 14 and 15 (MP
        // REACH/UNREACH) while those are stored. After the refactoring of routecore et al and we
        // are sure 14/15 do not end up in the store, that .filter can be removed completely.
        let query_filter = &self.1.query_filter;
        if query_filter.fields_path_attributes.is_some() {
            HelperWithQueryFilter {
                ingress: self.1.id_and_info(self.0.multi_uniq_id),
                status: RouteStatusWrapper(self.0.status),
                pamap: RotondaPaMapWithQueryFilter(
                    &self.0.meta,
                    query_filter,
                ),
            }
            .serialize(serializer)
        } else {
            Helper {
                ingress: self.1.id_and_info(self.0.multi_uniq_id),
                status: RouteStatusWrapper(self.0.status),
                pamap: &self.0.meta,
            }
            .serialize(serializer)
        }
    }
}

impl Serialize for RecordSetWrapper<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_seq(Some(self.0.len()))?;
        for e in &self.0.v4 {
            s.serialize_element(&PrefixRecordWrapper(e, self.1))?;
        }
        for e in &self.0.v6 {
            s.serialize_element(&PrefixRecordWrapper(e, self.1))?;
        }
        s.end()
    }
}

impl Serialize for PrefixRecordWrapper<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Data {
            nlri: Some(self.0.prefix),
            routes: RecordsWrapper(&self.0.meta, self.1),
        }
        .serialize(serializer)
    }
}

impl Serialize for RouteStatusWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            RouteStatus::Active => serializer.serialize_str("active"),
            RouteStatus::InActive => serializer.serialize_str("inactive"),
            RouteStatus::Withdrawn => serializer.serialize_str("withdrawn"),
        }
    }
}

#[derive(Debug)]
pub enum StoreInsertionEffect {
    RoutesWithdrawn(usize),
    #[allow(dead_code)]
    RoutesRemoved(usize),
    RouteAdded,
    RouteUpdated,
}

// --- Tests ----------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        alloc::System, net::IpAddr, ops::Deref, str::FromStr, sync::Arc,
    };

    use inetnum::{addr::Prefix, asn::Asn};
    //use roto::types::{
    //    builtin::{BuiltinTypeValue, NlriStatus, PrefixRoute, RotondaId},
    //    lazyrecord_types::BgpUpdateMessage,
    //    typevalue::TypeValue,
    //};
    use routecore::bgp::{message::SessionConfig, types::AfiSafiType};

    use crate::{
        bgp::encode::{mk_bgp_update, Announcements, Prefixes},
        common::memory::TrackingAllocator,
    };

    use super::*;

    // LH: these do not make much sense anymore with the new prefix store
    // doing all the updating/merging of entries. Adapting does not seem to be
    // worth it, perhaps we redo some of these from scratch?
    /*
    #[test]
    fn empty_by_default() {
        let rib_value = RibValue::default();
        assert!(rib_value.is_empty());
    }

    #[test]
    fn into_new() {
        let rib_value: RibValue =
            PreHashedTypeValue::new(123u8.into(), 18).into();
        assert_eq!(rib_value.len(), 1);
        assert_eq!(
            rib_value.iter().next(),
            Some(&Arc::new(PreHashedTypeValue::new(123u8.into(), 18)))
        );
    }

    #[test]
    fn merging_in_separate_values_yields_two_entries() {
        let settings = StoreEvictionPolicy::UpdateStatusOnWithdraw.into();
        let rib_value = RibValue::default();
        let value_one = PreHashedTypeValue::new(1u8.into(), 1);
        let value_two = PreHashedTypeValue::new(2u8.into(), 2);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&value_one.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 1);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&value_two.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 2);
    }

    #[test]
    fn merging_in_the_same_precomputed_hashcode_yields_one_entry() {
        let settings = StoreEvictionPolicy::UpdateStatusOnWithdraw.into();
        let rib_value = RibValue::default();
        let value_one = PreHashedTypeValue::new(1u8.into(), 1);
        let value_two = PreHashedTypeValue::new(2u8.into(), 1);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&value_one.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 1);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&value_two.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 1);
    }

    #[test]
    fn merging_in_a_withdrawal_updates_matching_entries() {
        // Given route announcements and withdrawals from a couple of peers to a single prefix
        let prefix = Prefix::new("127.0.0.1".parse().unwrap(), 32).unwrap();

        let peer_one = PeerId::new(
            Some(IpAddr::from_str("192.168.0.1").unwrap()),
            Some(Asn::from_u32(123)),
        );
        let peer_two = PeerId::new(
            Some(IpAddr::from_str("192.168.0.2").unwrap()),
            Some(Asn::from_u32(456)),
        );

        let peer_one_announcement_one =
            mk_route_announcement(prefix, "123,456,789", peer_one);
        let peer_one_announcement_two =
            mk_route_announcement(prefix, "123,789", peer_one);
        let peer_two_announcement_one =
            mk_route_announcement(prefix, "456,789", peer_two);
        let peer_one_withdrawal = mk_route_withdrawal(prefix, peer_one);

        let peer_one_announcement_one =
            PreHashedTypeValue::new(peer_one_announcement_one.into(), 1);
        let peer_one_announcement_two =
            PreHashedTypeValue::new(peer_one_announcement_two.into(), 2);
        let peer_two_announcement_one =
            PreHashedTypeValue::new(peer_two_announcement_one.into(), 3);
        let peer_one_withdrawal =
            PreHashedTypeValue::new(peer_one_withdrawal.into(), 4);

        // When merged into a RibValue
        let settings = StoreEvictionPolicy::UpdateStatusOnWithdraw.into();
        let rib_value = RibValue::default();

        // Unique announcements accumulate in the RibValue
        let (rib_value, _user_data) = rib_value
            .clone_merge_update(
                &peer_one_announcement_one.into(),
                Some(&settings),
            )
            .unwrap();
        assert_eq!(rib_value.len(), 1);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(
                &peer_one_announcement_two.into(),
                Some(&settings),
            )
            .unwrap();
        assert_eq!(rib_value.len(), 2);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(
                &peer_two_announcement_one.into(),
                Some(&settings),
            )
            .unwrap();
        assert_eq!(rib_value.len(), 3);

        // And a withdrawal by one peer of the prefix which the RibValue represents leaves the RibValue size unchanged
        let (rib_value, _user_data) = rib_value
            .clone_merge_update(
                &peer_one_withdrawal.clone().into(),
                Some(&settings),
            )
            .unwrap();
        assert_eq!(rib_value.len(), 3);

        // And routes from the first peer which were withdrawn are marked as such
        let mut iter = rib_value.iter();
        let first = iter.next();
        assert!(first.is_some());
        let first_ty: &TypeValue = first.unwrap().deref();
        assert!(matches!(
            first_ty,
            TypeValue::Builtin(BuiltinTypeValue::Route(_))
        ));
        if let TypeValue::Builtin(BuiltinTypeValue::Route(route)) = first_ty {
            assert_eq!(route.peer_ip(), Some(peer_one.ip.unwrap()));
            assert_eq!(route.peer_asn(), Some(peer_one.asn.unwrap()));
            assert_eq!(route.status(), NlriStatus::Withdrawn);
        }

        let next = iter.next();
        assert!(next.is_some());
        let next_ty: &TypeValue = next.unwrap().deref();
        assert!(matches!(
            next_ty,
            TypeValue::Builtin(BuiltinTypeValue::Route(_))
        ));
        if let TypeValue::Builtin(BuiltinTypeValue::Route(route)) = next_ty {
            assert_eq!(route.peer_ip(), Some(peer_one.ip.unwrap()));
            assert_eq!(route.peer_asn(), Some(peer_one.asn.unwrap()));
            assert_eq!(route.status(), NlriStatus::Withdrawn);
        }

        // But the route from the second peer remains untouched
        let next = iter.next();
        assert!(next.is_some());
        let next_ty: &TypeValue = next.unwrap().deref();
        assert!(matches!(
            next_ty,
            TypeValue::Builtin(BuiltinTypeValue::Route(_))
        ));
        if let TypeValue::Builtin(BuiltinTypeValue::Route(route)) = next_ty {
            assert_eq!(route.peer_ip(), Some(peer_two.ip.unwrap()));
            assert_eq!(route.peer_asn(), Some(peer_two.asn.unwrap()));
            assert_eq!(route.status(), NlriStatus::InConvergence);
        }

        // And a withdrawal by one peer of the prefix which the RibValue represents, when using the removal eviction
        // policy, causes the two routes from that peer to be removed leaving only one in the RibValue.
        let settings = StoreEvictionPolicy::RemoveOnWithdraw.into();
        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&peer_one_withdrawal.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 1);
    }

    #[test]
    fn test_route_comparison_using_default_hash_key_values() {
        let rib = HashedRib::default();
        let prefix = Prefix::new("127.0.0.1".parse().unwrap(), 32).unwrap();
        let peer_one = IpAddr::from_str("192.168.0.1").unwrap();
        let peer_two = IpAddr::from_str("192.168.0.2").unwrap();
        let announcement_one_from_peer_one =
            mk_route_announcement(prefix, "123,456", peer_one);
        let announcement_two_from_peer_one =
            mk_route_announcement(prefix, "789,456", peer_one);
        let announcement_one_from_peer_two =
            mk_route_announcement(prefix, "123,456", peer_two);
        let announcement_two_from_peer_two =
            mk_route_announcement(prefix, "789,456", peer_two);

        let hash_code_route_one_peer_one = rib.precompute_hash_code(
            &announcement_one_from_peer_one.clone().into(),
        );
        let hash_code_route_one_peer_one_again =
            rib.precompute_hash_code(&announcement_one_from_peer_one.into());
        let hash_code_route_one_peer_two =
            rib.precompute_hash_code(&announcement_one_from_peer_two.into());
        let hash_code_route_two_peer_one =
            rib.precompute_hash_code(&announcement_two_from_peer_one.into());
        let hash_code_route_two_peer_two =
            rib.precompute_hash_code(&announcement_two_from_peer_two.into());

        // Hashing sanity checks
        assert_ne!(hash_code_route_one_peer_one, 0);
        assert_eq!(
            hash_code_route_one_peer_one,
            hash_code_route_one_peer_one_again
        );

        assert_ne!(
            hash_code_route_one_peer_one, hash_code_route_one_peer_two,
            "Routes that differ only by peer IP should be considered different"
        );
        assert_ne!(
            hash_code_route_two_peer_one, hash_code_route_two_peer_two,
            "Routes that differ only by peer IP should be considered different"
        );
        assert_ne!(
            hash_code_route_one_peer_one, hash_code_route_two_peer_one,
            "Routes that differ only by AS path should be considered different"
        );
        assert_ne!(
            hash_code_route_one_peer_two, hash_code_route_two_peer_two,
            "Routes that differ only by AS path should be considered different"
        );

        // Sanity checks
        assert_eq!(
            hash_code_route_one_peer_one,
            hash_code_route_one_peer_one
        );
        assert_eq!(
            hash_code_route_one_peer_two,
            hash_code_route_one_peer_two
        );
        assert_eq!(
            hash_code_route_two_peer_one,
            hash_code_route_two_peer_one
        );
        assert_eq!(
            hash_code_route_two_peer_two,
            hash_code_route_two_peer_two
        );
    }

    #[test]
    fn test_merge_update_user_data_in_out() {
        const NUM_TEST_ITEMS: usize = 18;

        type TestMap<T> = hashbrown::HashSet<
            T,
            DefaultHashBuilder,
            TrackingAllocator<System>,
        >;

        #[derive(Debug)]
        struct MergeUpdateSettings {
            pub allocator: TrackingAllocator<System>,
            pub num_items_to_insert: usize,
        }

        impl MergeUpdateSettings {
            fn new(
                allocator: TrackingAllocator<System>,
                num_items_to_insert: usize,
            ) -> Self {
                Self {
                    allocator,
                    num_items_to_insert,
                }
            }
        }

        #[derive(Default)]
        struct TestMetaData(TestMap<usize>);

        // Create some settings
        let allocator = TrackingAllocator::default();
        let settings = MergeUpdateSettings::new(allocator, NUM_TEST_ITEMS);

        // Verify that it hasn't allocated anything yet
        assert_eq!(0, settings.allocator.stats().bytes_allocated);

        // Cause the allocator to be used by the merge update
        let meta = TestMetaData::default();
        let update_meta = TestMetaData::default();
        let (updated_meta, _user_data_out) = meta
            .clone_merge_update(&update_meta, Some(&settings))
            .unwrap();

        // Verify that the allocator was used
        assert!(settings.allocator.stats().bytes_allocated > 0);
        assert_eq!(NUM_TEST_ITEMS, updated_meta.0.len());

        // Drop the updated meta and check that no bytes are currently allocated
        drop(updated_meta);
        assert_eq!(0, settings.allocator.stats().bytes_allocated);
    }
    */

    // LH: which then obsoletes these as well

    /*
        fn mk_route_announcement<T: Into<PeerId>>(
            prefix: Prefix,
            as_path: &str,
            peer_id: T,
        ) -> PrefixRoute {
            let delta_id = (RotondaId(0), 0);
            let announcements = Announcements::from_str(&format!(
                "e [{as_path}] 10.0.0.1 BLACKHOLE,123:44 {}",
                prefix
            ))
            .unwrap();
            let bgp_update_bytes =
                mk_bgp_update(&Prefixes::default(), &announcements, &[]);

            // When it is processed by this unit
            let roto_update_msg =
                BgpUpdateMessage::new(bgp_update_bytes, SessionConfig::modern())
                .unwrap();
            let afi_safi = if prefix.is_v4() { AfiSafiType::Ipv4Unicast } else { AfiSafiType::Ipv6Unicast };
            // let bgp_update_msg =
            //     Arc::new(BgpUpdateMessage::new(delta_id, roto_update_msg));
            let mut route = PrefixRoute::new(
                delta_id,
                prefix,
                roto_update_msg,
                afi_safi,
                None,
                NlriStatus::InConvergence,
            );

            let peer_id = peer_id.into();

            if let Some(ip) = peer_id.ip {
                route = route.with_peer_ip(ip);
            }

            if let Some(asn) = peer_id.asn {
                route = route.with_peer_asn(asn);
            }

            route
        }

        fn mk_route_withdrawal(
            prefix: Prefix,
            peer_id: PeerId,
        ) -> MutableBasicRoute {
            let delta_id = (RotondaId(0), 0);
            let bgp_update_bytes = mk_bgp_update(
                &Prefixes::new(vec![prefix]),
                &Announcements::None,
                &[],
            );

            // When it is processed by this unit
            let roto_update_msg =
                BgpUpdateMessage::new(bgp_update_bytes, SessionConfig::modern()).unwrap();
            let afi_safi = if prefix.is_v4() { AfiSafiType::Ipv4Unicast } else { AfiSafiType::Ipv6Unicast };

            let mut route = BasicRoute::new(
                delta_id,
                prefix,
                roto_update_msg,
                afi_safi,
                None,
                NlriStatus::Withdrawn,
            );

            if let Some(ip) = peer_id.ip {
                route = route.with_peer_ip(ip);
            }

            if let Some(asn) = peer_id.asn {
                route = route.with_peer_asn(asn);
            }

            route
        }
    */
}
