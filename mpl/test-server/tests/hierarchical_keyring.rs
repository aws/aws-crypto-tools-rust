// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hierarchical keyring operations over the real wire, in process.
//!
//! These cover the paths that need no AWS call: union decoding, handle
//! resolution, and the MPL's own construction checks. Building a key store
//! or a keyring reads only configuration, so none of these reach KMS or
//! DynamoDB. The round trips that do are in the commons cross-language suite.

use std::collections::BTreeMap;
use std::sync::Arc;

use aws_mpl_test_server::handlers::AppState;
use aws_mpl_test_server::model::*;
use aws_mpl_test_server::wire::app;
use axum::Router;
use axum::body::Body;
use axum::http::Request;
use ciborium::value::Value;
use tower::ServiceExt;

const TABLE: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
const UNKNOWN_ID: &str = "00000000-0000-4000-8000-000000000000";

async fn post<Req: serde::Serialize>(
    router: &Router,
    operation: &str,
    req: &Req,
) -> (u16, Vec<u8>) {
    let mut body = Vec::new();
    ciborium::into_writer(req, &mut body).expect("encode request");
    let request = Request::builder()
        .method("POST")
        .uri(format!("/service/MPLTestServer/operation/{operation}"))
        .header("smithy-protocol", "rpc-v2-cbor")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .expect("build request");
    let response = router.clone().oneshot(request).await.expect("dispatch");
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    (status, bytes.to_vec())
}

async fn call<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
    router: &Router,
    operation: &str,
    req: &Req,
) -> Resp {
    let (status, body) = post(router, operation, req).await;
    assert_eq!(status, 200, "{operation} failed: {}", error_type(&body));
    ciborium::from_reader(&body[..]).expect("decode response")
}

fn error_type(body: &[u8]) -> String {
    let value: Value = ciborium::from_reader(body).expect("decode error body");
    let Value::Map(entries) = value else {
        panic!("error body is not a CBOR map");
    };
    entries
        .into_iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(k), Value::Text(v)) if k == "__type" => Some(v),
            _ => None,
        })
        .expect("error body has __type")
}

async fn expect_error<Req: serde::Serialize>(
    router: &Router,
    operation: &str,
    req: &Req,
    expected_type: &str,
) {
    let (status, body) = post(router, operation, req).await;
    assert_eq!(status, 400, "{operation} should fail");
    assert_eq!(
        error_type(&body),
        format!("aws.cryptography.mpl.testserver#{expected_type}")
    );
}

fn key_store_request(kms_configuration: KmsConfiguration) -> CreateKeyStoreClientRequest {
    CreateKeyStoreClientRequest {
        ddb_table_name: TABLE.to_owned(),
        logical_key_store_name: TABLE.to_owned(),
        kms_configuration,
        kms_client_region: "us-west-2".to_owned(),
        ddb_client_region: "us-west-2".to_owned(),
        ddb_endpoint: None,
    }
}

async fn key_store(router: &Router) -> String {
    let resp: CreateKeyStoreClientResponse = call(
        router,
        "CreateKeyStoreClient",
        &key_store_request(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.to_owned())),
    )
    .await;
    resp.key_store_id
}

fn keyring_request(key_store_id: String) -> CreateAwsKmsHierarchicalKeyringRequest {
    CreateAwsKmsHierarchicalKeyringRequest {
        key_store_id,
        branch_key_id: Some(BRANCH_KEY_ID.to_owned()),
        branch_key_id_supplier: None,
        ttl_seconds: 600,
        cache_id: None,
        partition_id: None,
    }
}

fn supplier() -> StaticBranchKeyIdSupplier {
    StaticBranchKeyIdSupplier {
        encryption_context_key: "branchKey".to_owned(),
        branch_key_ids: BTreeMap::from([("caseA".to_owned(), BRANCH_KEY_ID.to_owned())]),
    }
}

/// The client sends a union as a one-member CBOR map; `discovery` carries an
/// empty structure.
#[test]
fn kms_configuration_decodes_each_union_member() {
    let decode = |member: &str, value: Value| -> KmsConfiguration {
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![(Value::Text(member.to_owned()), value)]),
            &mut bytes,
        )
        .unwrap();
        ciborium::from_reader(&bytes[..]).unwrap()
    };

    assert!(matches!(
        decode("kmsKeyArn", Value::Text("arn".into())),
        KmsConfiguration::KmsKeyArn(arn) if arn == "arn"
    ));
    assert!(matches!(
        decode("kmsMRKeyArn", Value::Text("arn".into())),
        KmsConfiguration::KmsMrKeyArn(arn) if arn == "arn"
    ));
    assert!(matches!(
        decode("discovery", Value::Map(vec![])),
        KmsConfiguration::Discovery(Discovery {})
    ));
    assert!(matches!(
        decode(
            "mrDiscovery",
            Value::Map(vec![(Value::Text("region".into()), Value::Text("us-west-2".into()))])
        ),
        KmsConfiguration::MrDiscovery(MrDiscovery { region }) if region == "us-west-2"
    ));
}

/// The smithy-java client writes indefinite-length maps: 0xBF, entries, 0xFF.
#[test]
fn kms_configuration_decodes_an_indefinite_length_map() {
    let mut kms_key_arn = vec![0xBF, 0x69];
    kms_key_arn.extend_from_slice(b"kmsKeyArn");
    kms_key_arn.push(0x63);
    kms_key_arn.extend_from_slice(b"arn");
    kms_key_arn.push(0xFF);
    let decoded: KmsConfiguration = ciborium::from_reader(&kms_key_arn[..]).unwrap();
    assert!(matches!(decoded, KmsConfiguration::KmsKeyArn(arn) if arn == "arn"));

    let mut discovery = vec![0xBF, 0x69];
    discovery.extend_from_slice(b"discovery");
    discovery.extend_from_slice(&[0xBF, 0xFF, 0xFF]);
    let decoded: KmsConfiguration = ciborium::from_reader(&discovery[..]).unwrap();
    assert!(matches!(decoded, KmsConfiguration::Discovery(Discovery {})));
}

#[test]
fn kms_configuration_with_two_members_is_rejected() {
    let mut bytes = Vec::new();
    ciborium::into_writer(
        &Value::Map(vec![
            (Value::Text("kmsKeyArn".into()), Value::Text("arn".into())),
            (Value::Text("discovery".into()), Value::Map(vec![])),
        ]),
        &mut bytes,
    )
    .unwrap();
    assert!(ciborium::from_reader::<KmsConfiguration, _>(&bytes[..]).is_err());
}

#[tokio::test]
async fn create_key_store_client_accepts_each_kms_configuration() {
    let router = app(Arc::new(AppState::new()));
    for kms_configuration in [
        KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.to_owned()),
        KmsConfiguration::KmsMrKeyArn(KMS_KEY_ARN.to_owned()),
        KmsConfiguration::Discovery(Discovery {}),
        KmsConfiguration::MrDiscovery(MrDiscovery {
            region: "us-west-2".to_owned(),
        }),
    ] {
        let resp: CreateKeyStoreClientResponse = call(
            &router,
            "CreateKeyStoreClient",
            &key_store_request(kms_configuration),
        )
        .await;
        assert!(!resp.key_store_id.is_empty());
    }
}

#[tokio::test]
async fn create_key_store_client_rejects_a_malformed_kms_key_arn() {
    let router = app(Arc::new(AppState::new()));
    expect_error(
        &router,
        "CreateKeyStoreClient",
        &key_store_request(KmsConfiguration::KmsKeyArn("not-an-arn".to_owned())),
        "MPLClientError",
    )
    .await;
}

#[tokio::test]
async fn create_hierarchical_keyring_with_branch_key_id_or_supplier() {
    let router = app(Arc::new(AppState::new()));

    let by_id: CreateAwsKmsHierarchicalKeyringResponse = call(
        &router,
        "CreateAwsKmsHierarchicalKeyring",
        &keyring_request(key_store(&router).await),
    )
    .await;
    assert!(!by_id.keyring_id.is_empty());

    let by_supplier: CreateAwsKmsHierarchicalKeyringResponse = call(
        &router,
        "CreateAwsKmsHierarchicalKeyring",
        &CreateAwsKmsHierarchicalKeyringRequest {
            branch_key_id: None,
            branch_key_id_supplier: Some(supplier()),
            ..keyring_request(key_store(&router).await)
        },
    )
    .await;
    assert!(!by_supplier.keyring_id.is_empty());
}

#[tokio::test]
async fn create_hierarchical_keyring_over_a_shared_cache() {
    let router = app(Arc::new(AppState::new()));
    let cache: CreateCryptographicMaterialsCacheResponse = call(
        &router,
        "CreateCryptographicMaterialsCache",
        &CreateCryptographicMaterialsCacheRequest {
            entry_capacity: 100,
        },
    )
    .await;

    for partition_id in ["partitionIdHK1", "partitionIdHK2"] {
        let resp: CreateAwsKmsHierarchicalKeyringResponse = call(
            &router,
            "CreateAwsKmsHierarchicalKeyring",
            &CreateAwsKmsHierarchicalKeyringRequest {
                cache_id: Some(cache.cache_id.clone()),
                partition_id: Some(partition_id.to_owned()),
                ..keyring_request(key_store(&router).await)
            },
        )
        .await;
        assert!(!resp.keyring_id.is_empty());
    }
}

#[tokio::test]
async fn both_branch_key_id_and_supplier_is_an_mpl_error() {
    let router = app(Arc::new(AppState::new()));
    expect_error(
        &router,
        "CreateAwsKmsHierarchicalKeyring",
        &CreateAwsKmsHierarchicalKeyringRequest {
            branch_key_id_supplier: Some(supplier()),
            ..keyring_request(key_store(&router).await)
        },
        "MPLClientError",
    )
    .await;
}

#[tokio::test]
async fn neither_branch_key_id_nor_supplier_is_an_mpl_error() {
    let router = app(Arc::new(AppState::new()));
    expect_error(
        &router,
        "CreateAwsKmsHierarchicalKeyring",
        &CreateAwsKmsHierarchicalKeyringRequest {
            branch_key_id: None,
            ..keyring_request(key_store(&router).await)
        },
        "MPLClientError",
    )
    .await;
}

#[tokio::test]
async fn non_positive_ttl_is_an_mpl_error() {
    let router = app(Arc::new(AppState::new()));
    for ttl_seconds in [0, -1] {
        expect_error(
            &router,
            "CreateAwsKmsHierarchicalKeyring",
            &CreateAwsKmsHierarchicalKeyringRequest {
                ttl_seconds,
                ..keyring_request(key_store(&router).await)
            },
            "MPLClientError",
        )
        .await;
    }
}

#[tokio::test]
async fn negative_entry_capacity_is_an_mpl_error() {
    let router = app(Arc::new(AppState::new()));
    expect_error(
        &router,
        "CreateCryptographicMaterialsCache",
        &CreateCryptographicMaterialsCacheRequest { entry_capacity: -1 },
        "MPLClientError",
    )
    .await;
}

#[tokio::test]
async fn unknown_key_store_and_cache_handles_are_generic_server_errors() {
    let router = app(Arc::new(AppState::new()));
    expect_error(
        &router,
        "CreateAwsKmsHierarchicalKeyring",
        &keyring_request(UNKNOWN_ID.to_owned()),
        "GenericServerError",
    )
    .await;
    expect_error(
        &router,
        "CreateAwsKmsHierarchicalKeyring",
        &CreateAwsKmsHierarchicalKeyringRequest {
            cache_id: Some(UNKNOWN_ID.to_owned()),
            ..keyring_request(key_store(&router).await)
        },
        "GenericServerError",
    )
    .await;
}
