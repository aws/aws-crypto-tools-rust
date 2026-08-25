// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `cmc::cache_config` — the `CacheType` configuration types and
//! the `StormTrackingCache` fluent builder.
//!
//! `entryPruningTailSize` is deliberately optional here. The Smithy model
//! marks only `entryCapacity` `@required` on `StormTrackingCache`, and every
//! path in the Dafny implementation resolves an absent pruning tail to 1
//! (`entryPruningTailSize.UnwrapOr(1)` at the create-cache switch, and
//! `StormTracker.DefaultStorm()`), so an unset tail must build rather than
//! fail.

use aws_crypto_mpl::cmc::{
    MultiThreadedCache, SingleThreadedCache, StormTrackingCache, StormTrackingCacheBuilder,
    TimeUnits,
};
use aws_crypto_mpl::structures::MaterialsErrorKind;

/// Value the builder resolves an absent `entry_pruning_tail_size` to.
const EXPECTED_DEFAULT_PRUNING_TAIL: usize = 1;

/// Produces a builder with one required field deliberately omitted.
type BuilderFactory = fn() -> StormTrackingCacheBuilder;

/// A builder with all six required numeric fields set and both optional
/// fields (`entry_pruning_tail_size`, `time_units`) left unset.
fn builder_with_required_fields() -> StormTrackingCacheBuilder {
    StormTrackingCache::builder()
        .entry_capacity(100)
        .grace_period(10)
        .grace_interval(1)
        .fan_out(5)
        .inflight_ttl(10)
        .sleep_milli(20)
}

#[test]
fn build_with_pruning_tail_unset_defaults_to_one() {
    let cache = builder_with_required_fields()
        .build()
        .expect("an unset entry_pruning_tail_size must build, not fail");

    assert_eq!(
        cache.entry_pruning_tail_size, EXPECTED_DEFAULT_PRUNING_TAIL,
        "an absent pruning tail must resolve to 1, matching the model's optional \
         member and Dafny's UnwrapOr(1)",
    );
}

#[test]
fn build_with_explicit_pruning_tail_uses_the_supplied_value() {
    let cache = builder_with_required_fields()
        .entry_pruning_tail_size(7)
        .build()
        .expect("an explicit entry_pruning_tail_size must be honoured");

    assert_eq!(cache.entry_pruning_tail_size, 7);
}

#[test]
fn build_with_all_fields_set_round_trips_every_value() {
    let cache = builder_with_required_fields()
        .entry_pruning_tail_size(4)
        .time_units(TimeUnits::Milliseconds)
        .build()
        .expect("a fully populated builder must build");

    assert_eq!(cache.entry_capacity, 100);
    assert_eq!(cache.entry_pruning_tail_size, 4);
    assert_eq!(cache.grace_period, 10);
    assert_eq!(cache.grace_interval, 1);
    assert_eq!(cache.fan_out, 5);
    assert_eq!(cache.inflight_ttl, 10);
    assert_eq!(cache.sleep_milli, 20);
    assert_eq!(cache.time_units, Some(TimeUnits::Milliseconds));
}

#[test]
fn build_with_time_units_unset_leaves_it_none() {
    let cache = builder_with_required_fields()
        .build()
        .expect("time_units is optional");

    assert_eq!(
        cache.time_units, None,
        "an unset time_units stays None; the seconds default is applied by the \
         consuming CMP, not baked in here",
    );
}

#[test]
fn threaded_cache_constructors_leave_the_pruning_tail_unset() {
    // The Smithy model makes entryPruningTailSize optional on both of these,
    // so the constructor takes only the required entryCapacity and leaves the
    // tail None for the consuming CMP to resolve.
    assert_eq!(
        SingleThreadedCache::new(64),
        SingleThreadedCache {
            entry_capacity: 64,
            entry_pruning_tail_size: None,
        },
    );
    assert_eq!(
        MultiThreadedCache::new(64),
        MultiThreadedCache {
            entry_capacity: 64,
            entry_pruning_tail_size: None,
        },
    );
}

/// Each of the six required numeric fields, omitted one at a time, must fail
/// and name itself. `entry_pruning_tail_size` is absent from this table on
/// purpose — it is optional, and `build_with_pruning_tail_unset_defaults_to_one`
/// covers the case that used to belong here.
#[test]
fn build_without_a_required_field_names_the_missing_field() {
    let cases: Vec<(&str, BuilderFactory)> = vec![
        ("entry_capacity", || {
            StormTrackingCache::builder()
                .grace_period(10)
                .grace_interval(1)
                .fan_out(5)
                .inflight_ttl(10)
                .sleep_milli(20)
        }),
        ("grace_period", || {
            StormTrackingCache::builder()
                .entry_capacity(100)
                .grace_interval(1)
                .fan_out(5)
                .inflight_ttl(10)
                .sleep_milli(20)
        }),
        ("grace_interval", || {
            StormTrackingCache::builder()
                .entry_capacity(100)
                .grace_period(10)
                .fan_out(5)
                .inflight_ttl(10)
                .sleep_milli(20)
        }),
        ("fan_out", || {
            StormTrackingCache::builder()
                .entry_capacity(100)
                .grace_period(10)
                .grace_interval(1)
                .inflight_ttl(10)
                .sleep_milli(20)
        }),
        ("inflight_ttl", || {
            StormTrackingCache::builder()
                .entry_capacity(100)
                .grace_period(10)
                .grace_interval(1)
                .fan_out(5)
                .sleep_milli(20)
        }),
        ("sleep_milli", || {
            StormTrackingCache::builder()
                .entry_capacity(100)
                .grace_period(10)
                .grace_interval(1)
                .fan_out(5)
                .inflight_ttl(10)
        }),
    ];

    for (missing_field, make_builder) in cases {
        let err = match make_builder().build() {
            Ok(_) => panic!("omitting {missing_field} must fail"),
            Err(e) => e,
        };

        assert_eq!(
            err.kind,
            MaterialsErrorKind::Validation,
            "omitting {missing_field} must be a Validation error; got {err:?}",
        );
        assert!(
            err.message.contains(missing_field),
            "the error must name the missing field {missing_field}; got: {}",
            err.message,
        );
    }
}
