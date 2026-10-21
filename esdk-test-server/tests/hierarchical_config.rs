// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The hierarchical keyring config decodes from CBOR built with the model's
//! literal wire names (as a generated rpcv2Cbor Test_Client sends them), using
//! the canonical branch-key-store fixtures shared across the ESDK/MPL test
//! suites. Offline only: the encrypt/decrypt round trip reaches KMS + DynamoDB
//! and runs elsewhere with AWS credentials.

use aws_esdk_test_server::model::CreateClientRequest;
use ciborium::value::Value;

fn text_entry(key: &str, value: &str) -> (Value, Value) {
    (Value::Text(key.to_owned()), Value::Text(value.to_owned()))
}

/// A `CreateClient` request body as it appears on the wire, keyed by the Smithy
/// member names. Changing any serde rename in the model breaks decoding here.
fn wire_create_client() -> Value {
    let hierarchical = Value::Map(vec![
        text_entry("branchKeyId", "3f43a9af-08c5-4317-b694-3d3e883dcaef"),
        text_entry("keyStoreTableName", "KeyStoreDdbTable"),
        text_entry("logicalKeyStoreName", "KeyStoreDdbTable"),
        text_entry(
            "kmsKeyArn",
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126",
        ),
        (
            Value::Text("ttlSeconds".to_owned()),
            Value::Integer(600.into()),
        ),
    ]);
    let keyring = Value::Map(vec![(
        Value::Text("AwsKmsHierarchical".to_owned()),
        hierarchical,
    )]);
    let cmm = Value::Map(vec![(
        Value::Text("Default".to_owned()),
        Value::Map(vec![(Value::Text("keyring".to_owned()), keyring)]),
    )]);
    let config = Value::Map(vec![
        text_entry("commitmentPolicy", "REQUIRE_ENCRYPT_REQUIRE_DECRYPT"),
        (Value::Text("cmm".to_owned()), cmm),
    ]);
    Value::Map(vec![(Value::Text("config".to_owned()), config)])
}

#[test]
fn hierarchical_config_decodes_from_wire_names() {
    let mut bytes = Vec::new();
    ciborium::into_writer(&wire_create_client(), &mut bytes).expect("encode");

    let decoded: CreateClientRequest = ciborium::from_reader(&bytes[..]).expect("decode");
    let hierarchical = decoded
        .config
        .cmm
        .default_cmm
        .expect("default cmm")
        .keyring
        .aws_kms_hierarchical
        .expect("hierarchical keyring variant set");

    assert_eq!(
        hierarchical.branch_key_id,
        "3f43a9af-08c5-4317-b694-3d3e883dcaef"
    );
    assert_eq!(hierarchical.key_store_table_name, "KeyStoreDdbTable");
    assert_eq!(hierarchical.logical_key_store_name, "KeyStoreDdbTable");
    assert_eq!(
        hierarchical.kms_key_arn,
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
    );
    assert_eq!(hierarchical.ttl_seconds, 600);
}
