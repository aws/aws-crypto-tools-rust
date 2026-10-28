// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::search::test_fixtures::{item, s};

fn val_msg<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
    match r {
        Err(e @ Error::Validation(_)) => e.message().to_owned(),
        other => panic!("expected a Validation error, got {other:?}"),
    }
}

#[test]
fn input_builder() {
    let input = GetPartitionNumberInput::builder()
        .item("a", s("1"))
        .item("b", s("2"))
        .number_of_partitions(7)
        .logical_table_name("T")
        .build()
        .unwrap();
    assert_eq!(input.item(), &item(&[("a", s("1")), ("b", s("2"))]));
    assert_eq!(input.number_of_partitions(), 7);
    assert_eq!(input.logical_table_name(), "T");

    let rebuilt = GetPartitionNumberInput::builder()
        .set_item(Some(input.item().clone()))
        .set_number_of_partitions(Some(7))
        .set_logical_table_name(Some("T".to_owned()))
        .build()
        .unwrap();
    assert_eq!(rebuilt, input);
}

#[test]
fn input_builder_requires_every_field() {
    let full = || {
        GetPartitionNumberInput::builder()
            .item("a", s("1"))
            .number_of_partitions(2)
            .logical_table_name("T")
    };
    assert_eq!(val_msg(full().set_item(None).build()), "item is required");
    assert_eq!(
        val_msg(full().set_number_of_partitions(None).build()),
        "number_of_partitions is required"
    );
    assert_eq!(
        val_msg(full().set_logical_table_name(None).build()),
        "logical_table_name is required"
    );
}

#[test]
fn output_builder() {
    let out = GetPartitionNumberOutput::builder()
        .partition_number(3)
        .build()
        .unwrap();
    assert_eq!(out.partition_number(), 3);
    let err = GetPartitionNumberOutput::builder()
        .partition_number(3)
        .set_partition_number(None)
        .build();
    assert_eq!(val_msg(err), "partition_number is required");
}

fn input(num: u8) -> GetPartitionNumberInput {
    GetPartitionNumberInput::builder()
        .item("a", s("1"))
        .number_of_partitions(num)
        .logical_table_name("T")
        .build()
        .unwrap()
}

#[tokio::test]
async fn random_selector_stays_in_range() {
    let sel = SharedPartitionSelector::new(RandomPartitionSelector);
    for num in [0, 1] {
        let out = sel.get_partition_number(input(num)).await.unwrap();
        assert_eq!(out.partition_number(), 0);
    }
    let mut seen = [false; 3];
    for _ in 0..200 {
        let p = sel.get_partition_number(input(3)).await.unwrap();
        seen[usize::from(p.partition_number())] = true;
    }
    // 200 draws from 3 partitions miss one with probability below 1e-35.
    assert_eq!(seen, [true; 3]);
}

#[test]
fn shared_handle_is_not_rewrapped() {
    let a = SharedPartitionSelector::new(RandomPartitionSelector);
    let b = SharedPartitionSelector::new(a.clone());
    let c = SharedPartitionSelector::new(RandomPartitionSelector);
    assert!(SharedPartitionSelector::ptr_eq(&a, &b));
    assert!(!SharedPartitionSelector::ptr_eq(&a, &c));
    assert_eq!(format!("{a:?}"), "SharedPartitionSelector { .. }");
}
