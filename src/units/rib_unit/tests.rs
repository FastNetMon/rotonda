use crate::common::status_reporter::AnyStatusReporter;
use crate::roto_runtime::types::{
    explode_announcements, explode_withdrawals,
};
use crate::tests::util::internal::get_testable_metrics_snapshot;
use crate::{
    bgp::encode::{mk_bgp_update, Announcements, Prefixes},
    payload::{Payload, Update},
    units::rib_unit::unit::RibUnitRunner,
};
use chrono::Utc;
use futures::future::join_all;
use inetnum::{addr::Prefix, asn::Asn};
use rotonda_store::{
    epoch,
    match_options::{IncludeHistory, MatchOptions, MatchType},
    prefix_record::RouteStatus,
};
use routecore::bgp::communities::Wellknown;
use routecore::bgp::message::update_builder::StandardCommunitiesList;
use routecore::bgp::message::{SessionConfig, UpdateMessage};
use routecore::bgp::path_attributes::{PathAttribute, PathAttributeType};
use routecore::bgp::types::AfiSafiType;
use smallvec::SmallVec;

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;
use std::{str::FromStr, sync::Arc};

use super::status_reporter::RibUnitStatusReporter;

#[ignore]
#[tokio::test]
async fn process_non_route_update() {
    /*
    let (runner, _) = RibUnitRunner::mock(
        "",
        RibType::Physical,
    );

    // Given an update that is not a route
    let update = Update::from(Payload::from(TypeValue::Unknown));

    // When it is processed by this unit it should not be filtered
    assert!(!is_filtered(&runner, update).await);

    // And it should NOT be added to the route store
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 0);

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (0, 0, 0, 0, 0));
    */
}

#[tokio::test]
async fn process_update_single_route() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));

    //// When it is processed by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update).await);
    runner.process_update(update).await.unwrap();

    // And it should be added to the route store
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 1, 0, 1));
}

#[tokio::test]
#[ignore = "this is really different after refactoring of the store"]
async fn process_update_withdraw_unannounced_route() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();

    // Given a BGP update containing a single route withdrawal
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, None);

    //// When it is processed by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update.clone()).await);
    runner.process_update(update.clone()).await.unwrap();

    // And it should cause the prefix to be added to the route store
    // LH: errr, it should not?
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        0
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (0, 1, 0, 0, 1));

    //// When it is processed again by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update).await);
    runner.process_update(update).await.unwrap();

    // And it should cause the prefix to be added to the route store
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (0, 2, 0, 0, 1));
}

#[tokio::test]
async fn process_update_same_route_twice() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));

    //// When it is processed by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update.clone()).await);
    runner.process_update(update.clone()).await.unwrap();

    // And it should be added to the route store
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    //// When it is processed by this unit again it should not be filtered
    //assert!(!is_filtered(&runner, update).await);
    runner.process_update(update.clone()).await.unwrap();

    // And it should NOT be added again to the route store
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 1, 0, 1));

    // But when withdrawn
    let update = mk_route_update(&prefix, None);

    //// When it is processed by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update.clone()).await);
    runner.process_update(update).await.unwrap();

    // And it should cause the route to be marked as withdrawn
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 0, 1, 1));
}

#[tokio::test]
async fn process_update_withdraw_retains_attributes_by_default() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();

    runner
        .process_update(mk_route_update(&prefix, Some("[111,222,333]")))
        .await
        .unwrap();
    let announced_attr_len = stored_attr_len(&runner, &prefix);
    assert!(announced_attr_len > 2);

    runner
        .process_update(mk_route_update(&prefix, None))
        .await
        .unwrap();

    assert_eq!(stored_status(&runner, &prefix), RouteStatus::Withdrawn);
    assert_eq!(stored_attr_len(&runner, &prefix), announced_attr_len);
}

#[tokio::test]
async fn process_update_withdraw_can_drop_attributes() {
    let (runner, _) =
        RibUnitRunner::mock_with_retain_withdrawn_attributes(false).unwrap();
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();

    runner
        .process_update(mk_route_update(&prefix, Some("[111,222,333]")))
        .await
        .unwrap();
    assert!(stored_attr_len(&runner, &prefix) > 2);

    runner
        .process_update(mk_route_update(&prefix, None))
        .await
        .unwrap();

    assert_eq!(stored_status(&runner, &prefix), RouteStatus::Withdrawn);
    assert_eq!(stored_attr_len(&runner, &prefix), 2);
}

#[tokio::test]
async fn process_peer_withdraw_can_drop_attributes() {
    let (runner, _) =
        RibUnitRunner::mock_with_retain_withdrawn_attributes(false).unwrap();
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();

    runner
        .process_update(mk_route_update(&prefix, Some("[111,222,333]")))
        .await
        .unwrap();
    assert!(stored_attr_len(&runner, &prefix) > 2);

    runner
        .process_update(Update::Withdraw(1, None))
        .await
        .unwrap();

    assert_eq!(stored_status(&runner, &prefix), RouteStatus::Withdrawn);
    assert_eq!(stored_attr_len(&runner, &prefix), 2);
}

#[tokio::test]
async fn process_update_can_deduplicate_path_attributes() {
    let (runner, _) =
        RibUnitRunner::mock_with_deduplicate_path_attributes(true).unwrap();
    let prefix_one = Prefix::from_str("127.0.0.1/32").unwrap();
    let prefix_two = Prefix::from_str("127.0.0.2/32").unwrap();

    runner
        .process_update(mk_route_update(&prefix_one, Some("[111,222,333]")))
        .await
        .unwrap();
    runner
        .process_update(mk_route_update(&prefix_two, Some("[111,222,333]")))
        .await
        .unwrap();

    let record_one = stored_record(&runner, &prefix_one);
    let record_two = stored_record(&runner, &prefix_two);

    assert_eq!(record_one.meta.as_ref(), record_two.meta.as_ref());
    assert_eq!(
        record_one.meta.as_ref().as_ptr(),
        record_two.meta.as_ref().as_ptr()
    );
}

#[ignore]
#[tokio::test]
async fn process_update_equivalent_route_twice() {
    /*
    let (runner, _) = RibUnitRunner::mock("");

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update_with_communities(
        &prefix,
        Some("[111,222,333]"),
        Some("BLACKHOLE"),
    );

    // When it is processed by this unit it should not be filtered
    assert!(!is_filtered(&runner, update.clone()).await);

    // And it should be added to the route store
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 1, 0, 1));

    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    assert_eq!(
        metrics
            .with_name::<usize>("rib_unit_num_modified_route_announcements"),
        0
    );

    // And check the value stored
    let match_options = MatchOptions {
        match_type: MatchType::ExactMatch,
        include_withdrawn: false,
        mui: None,
        include_less_specifics: true,
        include_more_specifics: true,
    };
    eprintln!("Querying store match_prefix the first time");
    let match_result = runner.rib().store().unwrap().match_prefix(
        &prefix,
        &match_options,
        &epoch::pin(),
    );
    assert!(matches!(match_result.match_type, MatchType::ExactMatch));
    let rib_value = match_result.prefix_meta;
    assert_eq!(rib_value.len(), 1);
    let pubrecord = rib_value.iter().next().unwrap();
    let route = *pubrecord.meta;
    if let Some(comms) = route.get_attr::<StandardCommunitiesList>() {
        assert_eq!(
            comms.communities()
                .first()
                .unwrap(),
            Wellknown::Blackhole.into()
        );
    } else {
        unreachable!()
    };

    // When a route that is identical by key but different by value then the
    // new route should not be filtered, where the default key is peer IP,
    // peer ASN and AS path (see RibUnit::default_rib_keys()).
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update_with_communities(
        &prefix,
        Some("[111,222,333]"),
        Some("NO_EXPORT"),
    );
    if let Update::Single(Payload {
        rx_value: TypeValue::Builtin(BuiltinTypeValue::PrefixRoute(route)),
        ..
    }) = &update
    {
        assert_eq!(
            route
                .raw_message
                .0
                .communities()
                .unwrap()
                .unwrap()
                .next()
                .unwrap(),
            Wellknown::NoExport.into()
        );
    }
    assert!(!is_filtered(&runner, update).await);

    // And should replace the old route in the store
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);
    let match_options = MatchOptions {
        match_type: MatchType::ExactMatch,
        include_all_records: true,
        include_less_specifics: true,
        include_more_specifics: true,
    };
    eprintln!("Querying store match_prefix the second time");
    let match_result = runner.rib().store().unwrap().match_prefix(
        &prefix,
        &match_options,
        &epoch::pin(),
    );
    assert!(matches!(match_result.match_type, MatchType::ExactMatch));
    let rib_value = match_result.prefix_meta.as_ref().unwrap();
    assert_eq!(rib_value.len(), 1);
    let prehashed_type_value = rib_value.iter().next().unwrap();
    if let TypeValue::Builtin(BuiltinTypeValue::Route(route)) =
        &***prehashed_type_value
    {
        assert_eq!(
            route
                .raw_message
                .0
                .communities()
                .unwrap()
                .unwrap()
                .next()
                .unwrap(),
            Wellknown::NoExport.into()
        );
    } else {
        unreachable!()
    };

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 1, 0, 1));

    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    assert_eq!(
        metrics
            .with_name::<usize>("rib_unit_num_modified_route_announcements"),
        1
    );

    // But when withdrawn
    let update = mk_route_update(&prefix, None);

    // When it is processed by this unit it should not be filtered
    assert!(!is_filtered(&runner, update.clone()).await);

    // And it should cause the route to be marked as withdrawn
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 0, 1, 1));
    */
}

#[ignore]
#[tokio::test]
async fn process_update_two_routes_to_the_same_prefix() {
    /*
    #[rustfmt::skip]
    let (_match_result, match_result2) = {
        let (runner, _) = RibUnitRunner::mock("", RibType::Physical);

        // Given BGP updates for two different routes to the same prefix
        let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
        for as_path_str in ["[111,222,333]", "[111,444,333]"] {
            let update = mk_route_update(&prefix, Some(as_path_str));
            assert!(!is_filtered(&runner, update.clone()).await);
        }

        // Then only the one common prefix SHOULD be added to the route store
        assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);

        // And check that recorded metrics are correct
        assert_eq!(query_metrics(&runner.status_reporter()), (2, 0, 2, 0, 1));

        // And at that prefix there should be one RibValue containing two routes
        let match_options = MatchOptions {
            match_type: MatchType::ExactMatch,
            include_less_specifics: true,
            include_more_specifics: true,
        };
        eprintln!("Querying store match_prefix the first time");
        let match_result = runner.rib().store().unwrap().match_prefix(
            &prefix,
            &match_options,
            &epoch::pin(),
        );
        assert!(matches!(match_result.match_type, MatchType::ExactMatch));
        let rib_value = match_result.prefix_meta.as_ref().unwrap();
        assert_eq!(rib_value.len(), 2);

        // Check the Arc reference counts. The routes HashSet should have a strong reference count of 2 because the
        // MultiThreadedStore has the original Arc around the metadata that was inserted into the store, and it clones
        // that Arc when making a "copy" to include in the match prefix result set, thereby incrementing the strong
        // reference count. The items in the routes HashSet however should have a strong reference count of 1. This is
        // because we are accessing the one and only copy of the HashSet via the Arc and are thus seeing the actual
        // HashSet copy held by the store and thus its actual items, which have not been cloned and thus have a strong
        // reference count of 1. As we don't at this point use any Weak references to the HashSet or its items the
        // weak reference counts should be 0.
        assert_eq!(Arc::strong_count(rib_value.test_inner()), 2);
        assert_eq!(Arc::weak_count(rib_value.test_inner()), 0);
        for item in rib_value.iter() {
            assert_eq!(Arc::strong_count(item), 1);
            assert_eq!(Arc::weak_count(item), 0);
        }

        // If we repeat the match prefix query while still holding the previous match prefix query results, we should
        // see that the routes HashSet Arc strong reference count increases from 2 to 3 while the inner items of the
        // HashSet still have a strong reference count of 1.
        eprintln!("Querying store match_prefix the second time");
        let match_result2 = runner.rib().store().unwrap().match_prefix(
            &prefix,
            &match_options,
            &epoch::pin(),
        );
        assert!(matches!(match_result2.match_type, MatchType::ExactMatch));
        let rib_value = match_result2.prefix_meta.as_ref().unwrap();
        assert_eq!(rib_value.len(), 2);
        assert_eq!(Arc::strong_count(rib_value.test_inner()), 3);
        assert_eq!(Arc::weak_count(rib_value.test_inner()), 0);
        for item in rib_value.iter() {
            assert_eq!(Arc::strong_count(item), 1);
            assert_eq!(Arc::weak_count(item), 0);
        }

        // And when withdrawn
        let update = mk_route_update(&prefix, None);

        // When it is processed by this unit it should not be filtered
        assert!(!is_filtered(&runner, update.clone()).await);

        // And it should cause the route to be marked as withdrawn
        assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);

        // And check that recorded metrics are correct
        assert_eq!(query_metrics(&runner.status_reporter()), (2, 0, 0, 2, 1));

        (match_result, match_result2)
    };

    // The MultiThreadedStore has been dropped so the HashSet strong reference count should decrease from 3 to 2.
    eprintln!(
        "Checking the reference counts of the `match_result` query result var inner metadata item"
    );
    let rib_value = match_result2.prefix_meta.unwrap();
    // assert_eq!(Arc::strong_count(&rib_value.per_prefix_items), 2); // TODO: MultiThreadedStore doesn't cleanup on drop...
    assert_eq!(Arc::weak_count(rib_value.test_inner()), 0);
    for item in rib_value.iter() {
        assert_eq!(Arc::strong_count(item), 1);
        assert_eq!(Arc::weak_count(item), 0);
    }
    */
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn process_update_two_routes_to_different_prefixes() {
    /*
    let (runner, _) = RibUnitRunner::mock(
        "",
        RibType::Physical,
    );

    // Given BGP updates for two different routes to two different prefixes
    let prefix1 = Prefix::from_str("127.0.0.1/32").unwrap();
    let prefix2 = Prefix::from_str("127.0.0.2/32").unwrap();

    let update = mk_route_update(&prefix1, Some("[111,222,333]"));
    assert!(!is_filtered(&runner, update.clone()).await);

    let update = mk_route_update(&prefix2, Some("[111,444,333]"));
    assert!(!is_filtered(&runner, update.clone()).await);

    // Then two separate prefixes SHOULD be added to the route store
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 2);

    // And at that prefix there should be two RibValues
    let match_options = MatchOptions {
        match_type: MatchType::ExactMatch,
        include_less_specifics: true,
        include_more_specifics: true,
    };

    for prefix in [prefix1, prefix2] {
        let match_result = runner.rib().store().unwrap().match_prefix(
            &prefix,
            &match_options,
            &epoch::pin(),
        );
        assert!(matches!(match_result.match_type, MatchType::ExactMatch));
        let rib_value = match_result.prefix_meta.unwrap(); // TODO: Why do we get the actual value out of the store here and not an Arc?
        assert_eq!(rib_value.len(), 1);
    }

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (2, 0, 2, 0, 2));

    // And when one prefix is withdrawn
    let update = mk_route_update(&prefix1, None);

    // When it is processed by this unit it should not be filtered
    assert!(!is_filtered(&runner, update.clone()).await);

    // And it should cause the route to be marked as withdrawn
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 2);

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (2, 0, 1, 1, 2));
    */
}

#[ignore]
#[tokio::test]
async fn time_store_op_durations() {
    /*
    const INSERT_DELAY: Duration = Duration::from_secs(2);
    const UPDATE_DELAY: Duration = Duration::from_secs(3);
    let mut settings = StoreMergeUpdateSettings::new(
        StoreEvictionPolicy::UpdateStatusOnWithdraw,
    );
    settings.delay = Some(UPDATE_DELAY);

    let (runner, _) = RibUnitRunner::mock("", RibType::Physical, settings);

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));
    let started_at = Utc::now();

    // Insert it once, MergeUpdate won't be invoked so there should be no
    // delay there, but we deliberately introduce a delay around the store
    // insert call.
    runner
        .process_update(update.clone(), |pfx, meta, store| {
            eprintln!(
                "Sleeping in insert_fn() for {}ms",
                INSERT_DELAY.as_millis()
            );
            std::thread::sleep(INSERT_DELAY);
            store.insert(pfx, meta)
        })
        .await
        .unwrap();

    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    let insert_duration_micros =
        metrics.with_name::<u64>("rib_unit_insert_duration");
    let actual_duration = Duration::from_micros(insert_duration_micros);
    assert_eq!(actual_duration.as_secs(), INSERT_DELAY.as_secs());

    let propagation_duration_millis = metrics.with_label::<u64>(
        "rib_unit_e2e_duration",
        ("router", MOCK_ROUTER_ID),
    );
    let actual_duration = Duration::from_millis(propagation_duration_millis);
    assert_eq!(
        actual_duration.as_secs(),
        (Utc::now() - started_at).to_std().unwrap().as_secs()
    );

    // Insert it again, MergeUpdate should be invoked so insertion should be
    // delayed by DELAY as configured above.
    runner
        .process_update(update, |pfx, meta, store| store.insert(pfx, meta))
        .await
        .unwrap();

    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    let update_duration_micros =
        metrics.with_name::<u64>("rib_unit_update_duration");
    let actual_duration = Duration::from_micros(update_duration_micros);
    assert_eq!(actual_duration.as_secs(), UPDATE_DELAY.as_secs());

    let propagation_duration_millis = metrics.with_label::<u64>(
        "rib_unit_e2e_duration",
        ("router", MOCK_ROUTER_ID),
    );
    let actual_duration = Duration::from_millis(propagation_duration_millis);
    assert_eq!(
        actual_duration.as_secs(),
        (Utc::now() - started_at).to_std().unwrap().as_secs()
    );
    */
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn count_insert_retries_during_forced_contention() {
    /*
    const DELAY: Duration = Duration::from_millis(10);
    let mut settings = StoreMergeUpdateSettings::new(
        StoreEvictionPolicy::UpdateStatusOnWithdraw,
    );
    settings.delay = Some(DELAY);

    let (runner, _) = RibUnitRunner::mock("", RibType::Physical, settings);
    let runner = Arc::new(runner);

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));

    // Insert it.
    eprintln!("PERFORMING INITIAL STORE INSERT");
    runner
        .process_update(update.clone(), |pfx, meta, store| {
            store.insert(pfx, meta)
        })
        .await
        .unwrap();

    // Insert it again multiple times in parallel. MergeUpdate should be
    // invoked so insertion should be delayed by DELAY as configured above.
    // This should cause the parallel updates to contend with each other as
    // they each try to insert into the store at the same prefix "bucket"
    // so later inserts that occur during the sleep of the other must wait
    // for the other to stop sleeping and complete. One thing to note is
    // that the sleep is a thread sleep which will block Tokio on that
    // thread but we use #[tokio::test(flavor = "multi_thread")] attribute
    // on this test to use a multi-threaded Tokio so that blocking an
    // individual thread shouldn't block Tokio entirely, especially given
    // its work-stealing ability. Typically with Tokio one is supposed to
    // run blocking activities on a dedicated blocking Tokio thread pool.
    // This isn't done currentlty in Rotonda because store inserts are
    // intended and expected to be extremely fast, even with contention.
    // The point noted about thread sleep is only relevant to test builds
    // as release builds don't have the thread sleep code in the MergeUpdate
    // impl.
    eprintln!("PERFORMING PARALLEL STORE UPDATES");
    let mut join_handles = vec![];
    for _ in 0..10 {
        let bg_runner = runner.clone();
        let bg_update = update.clone();
        join_handles.push(tokio::task::spawn(async move {
            bg_runner
                .process_update(bg_update, |pfx, meta, store| {
                    store.insert(pfx, meta)
                })
                .await
        }));
    }

    eprintln!(
        "WAITING IN THEREAD {:?} FOR STORE UPDATES TO COMPLETE",
        std::thread::current().id()
    );
    join_all(join_handles).await;

    eprintln!("STORE UPDATES ARE COMPLETE");
    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    let num_retries =
        metrics.with_name::<usize>("rib_unit_num_insert_retries");
    assert!(num_retries > 0);
    */
}

#[ignore]
#[tokio::test]
async fn count_hard_insert_failures() {
    /*
    let settings = StoreEvictionPolicy::UpdateStatusOnWithdraw.into();
    let (runner, _) = RibUnitRunner::mock("", RibType::Physical, settings);

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));

    // Check that the counter is zero to begin with
    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    assert_eq!(
        metrics.with_name::<u64>("rib_unit_num_insert_hard_failures"),
        0
    );

    // Insert multiple times and check that the counter increases accordingly
    for expected_counter_value in 1..=10 {
        runner
            .process_update(update.clone(), |_, _, _| {
                eprintln!("Deliberately failing to insert into the store");
                Err(PrefixStoreError::StoreNotReadyError)
            })
            .await
            .unwrap();

        let metrics = runner.status_reporter().metrics().unwrap();
        let metrics = get_testable_metrics_snapshot(&metrics);
        assert_eq!(
            metrics.with_name::<u64>("rib_unit_num_insert_hard_failures"),
            expected_counter_value
        );
    }
    */
}

// --- Test helpers ------------------------------------------------------

fn mk_route_update(
    prefix: &Prefix,
    announced_as_path_str: Option<&str>,
) -> Update {
    mk_route_update_with_communities(
        prefix,
        announced_as_path_str,
        Some("BLACKHOLE,123:44"),
    )
}

fn mk_route_update_with_communities(
    prefix: &Prefix,
    announced_as_path_str: Option<&str>,
    communities: Option<&str>,
) -> Update {
    //let _delta_id = (RotondaId(0), 0);
    let ann;
    let wit;
    //let _route_status;
    match announced_as_path_str {
        Some(as_path_str) => {
            let communities = communities.unwrap_or("none");
            ann = Announcements::from_str(&format!(
                "e {as_path_str} 10.0.0.1 {communities} {prefix}",
            ))
            .unwrap();
            wit = Prefixes::default();
            //route_status = RouteStatus::Active;
        }
        None => {
            ann = Announcements::default();
            wit = Prefixes::new(vec![*prefix]);
            //route_status = RouteStatus::Withdrawn;
        }
    }
    let bgp_update_bytes = mk_bgp_update(&wit, &ann, &[]);

    let roto_update_msg = UpdateMessage::from_octets(
        bgp_update_bytes,
        &SessionConfig::modern(),
    )
    .unwrap();
    let rws = explode_announcements(
        &roto_update_msg,
        //&mut BTreeSet::new(),
    )
    .unwrap();
    let wdws = explode_withdrawals(
        &roto_update_msg,
        //&mut BTreeSet::new(),
    )
    .unwrap();

    let ingress_id = 1;

    let mut bulk = SmallVec::new();

    for r in rws {
        bulk.push(Payload::new(r, None, ingress_id, RouteStatus::Active));
    }

    for w in wdws {
        bulk.push(Payload::new(w, None, ingress_id, RouteStatus::Withdrawn));
    }
    Update::Bulk(Box::new(bulk))

    /*
    let afi_safi = if prefix.is_v4() { AfiSafiType::Ipv4Unicast } else { AfiSafiType::Ipv6Unicast };
    let route = RawRouteWithDeltas::new_with_message_ref(
        delta_id,
        *prefix,
        roto_update_msg,
        afi_safi,
        None,
        route_status,
    )
    .with_peer_asn(Asn::from_u32(64512))
    .with_peer_ip(IpAddr::from_str("127.0.0.1").unwrap())
    .with_router_id(MOCK_ROUTER_ID.to_string().into());
    */

    //Update::from(Payload::from(TypeValue::from(BuiltinTypeValue::Route(
    //    route,
    //))))
}

fn stored_attr_len(runner: &RibUnitRunner, prefix: &Prefix) -> usize {
    stored_record(runner, prefix).meta.as_ref().len()
}

fn stored_status(runner: &RibUnitRunner, prefix: &Prefix) -> RouteStatus {
    stored_record(runner, prefix).status
}

fn stored_record(
    runner: &RibUnitRunner,
    prefix: &Prefix,
) -> rotonda_store::prefix_record::Record<crate::payload::RotondaPaMap> {
    let match_result = runner
        .rib()
        .store()
        .unwrap()
        .match_prefix(prefix, &match_options(), &epoch::pin())
        .unwrap();

    assert!(matches!(match_result.match_type, MatchType::ExactMatch));
    assert_eq!(match_result.records.len(), 1);
    match_result.records.into_iter().next().unwrap()
}

fn match_options() -> MatchOptions {
    MatchOptions {
        match_type: MatchType::ExactMatch,
        include_withdrawn: true,
        include_less_specifics: false,
        include_more_specifics: false,
        mui: None,
        include_history: IncludeHistory::None,
    }
}

#[allow(dead_code)]
async fn is_filtered(_runner: &RibUnitRunner, _update: Update) -> bool {
    todo!() // before we start using this again, adapt it to the new codebase
            /*
            runner
                .process_update(update, |pfx, meta, store| store.insert(pfx, meta))
                .await
                .unwrap();
            let gate_metrics = runner.gate().metrics();
            let num_dropped_updates = gate_metrics.num_dropped_updates.load(SeqCst);
            let num_updates = gate_metrics.num_updates.load(SeqCst);
            num_dropped_updates == 0 && num_updates == 0
                */
}

fn query_metrics(
    status_reporter: &Arc<RibUnitStatusReporter>,
) -> (usize, usize, usize, usize, usize) {
    let metrics =
        get_testable_metrics_snapshot(&status_reporter.metrics().unwrap());
    (
        metrics.with_name::<usize>("rib_unit_num_items"),
        metrics.with_name::<usize>(
            "rib_unit_num_route_withdrawals_without_announcements",
        ),
        metrics.with_name::<usize>("rib_unit_num_routes_announced"),
        metrics.with_name::<usize>("rib_unit_num_routes_withdrawn"),
        metrics.with_name::<usize>("rib_unit_num_unique_prefixes"),
    )
}

fn mk_route_update_with_ingress(
    prefix: &Prefix,
    announced_as_path_str: Option<&str>,
    ingress_id: crate::ingress::IngressId,
) -> Update {
    let ann;
    let wit;
    match announced_as_path_str {
        Some(as_path_str) => {
            let next_hop = if prefix.is_v4() {
                "10.0.0.1"
            } else {
                "2001:db8::1"
            };
            ann = Announcements::from_str(&format!(
                "e {as_path_str} {next_hop} none {prefix}",
            ))
            .unwrap();
            wit = Prefixes::default();
        }
        None => {
            ann = Announcements::default();
            wit = Prefixes::new(vec![*prefix]);
        }
    }
    let bgp_update_bytes = mk_bgp_update(&wit, &ann, &[]);

    let roto_update_msg = UpdateMessage::from_octets(
        bgp_update_bytes,
        &SessionConfig::modern(),
    )
    .unwrap();
    let rws = explode_announcements(&roto_update_msg).unwrap();
    let wdws = explode_withdrawals(&roto_update_msg).unwrap();

    let mut bulk = SmallVec::new();

    for r in rws {
        bulk.push(Payload::new(r, None, ingress_id, RouteStatus::Active));
    }

    for w in wdws {
        bulk.push(Payload::new(w, None, ingress_id, RouteStatus::Withdrawn));
    }
    Update::Bulk(Box::new(bulk))
}

fn jsonl_ingress_ids(output: &str) -> Vec<u64> {
    output
        .lines()
        .map(|line| {
            let line: serde_json::Value = serde_json::from_str(line).unwrap();
            line["ingress"]["id"].as_u64().unwrap()
        })
        .collect()
}

#[tokio::test]
async fn test_check_filter_and_store_and_ingress_id_filtering() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();
    let rib = runner.rib();

    let mut filter = super::QueryFilter::default();

    assert!(rib
        .check_filter_and_store(AfiSafiType::Ipv4Unicast, &filter)
        .is_ok());
    assert!(rib
        .check_filter_and_store(AfiSafiType::Ipv6Unicast, &filter)
        .is_ok());

    filter.roto_function = Some("nonexistent_filter_name".to_string());
    let err = rib.check_filter_and_store(AfiSafiType::Ipv4Unicast, &filter);
    assert!(err.is_err());
    assert_eq!(
        err.unwrap_err(),
        "no roto function 'nonexistent_filter_name' defined"
    );

    rib.ingress_register
        .update_info(10, crate::ingress::IngressInfo::default());
    rib.ingress_register
        .update_info(20, crate::ingress::IngressInfo::default());

    let prefix_v4 = Prefix::from_str("192.0.2.0/24").unwrap();
    let prefix_v6 = Prefix::from_str("2001:db8::/32").unwrap();

    runner
        .process_update(mk_route_update_with_ingress(
            &prefix_v4,
            Some("[111,222]"),
            10,
        ))
        .await
        .unwrap();
    runner
        .process_update(mk_route_update_with_ingress(
            &prefix_v4,
            Some("[111,333]"),
            20,
        ))
        .await
        .unwrap();
    runner
        .process_update(mk_route_update_with_ingress(
            &prefix_v6,
            Some("[111,444]"),
            10,
        ))
        .await
        .unwrap();

    let mut buf = Vec::new();
    let query_filter_all = super::QueryFilter::default();
    rib.write_jsonl_stream(
        AfiSafiType::Ipv4Unicast,
        Prefix::from_str("0.0.0.0/0").unwrap(),
        query_filter_all.clone(),
        &mut buf,
    )
    .map_err(|_| "stream error")
    .unwrap();
    let output_all = String::from_utf8(buf).unwrap();
    let ids_all = jsonl_ingress_ids(&output_all);
    assert!(ids_all.contains(&10));
    assert!(ids_all.contains(&20));

    let mut buf10 = Vec::new();
    let mut query_filter_10 = super::QueryFilter::default();
    query_filter_10.ingress_id = Some(10);
    rib.write_jsonl_stream(
        AfiSafiType::Ipv4Unicast,
        Prefix::from_str("0.0.0.0/0").unwrap(),
        query_filter_10.clone(),
        &mut buf10,
    )
    .map_err(|_| "stream error")
    .unwrap();
    let output_10 = String::from_utf8(buf10).unwrap();
    let ids_10 = jsonl_ingress_ids(&output_10);
    assert!(ids_10.contains(&10));
    assert!(!ids_10.contains(&20));

    let mut buf_v6 = Vec::new();
    rib.write_jsonl_stream(
        AfiSafiType::Ipv6Unicast,
        Prefix::from_str("::/0").unwrap(),
        query_filter_all.clone(),
        &mut buf_v6,
    )
    .map_err(|_| "stream error")
    .unwrap();
    let output_v6 = String::from_utf8(buf_v6).unwrap();
    let ids_v6 = jsonl_ingress_ids(&output_v6);
    assert!(ids_v6.contains(&10));
}
