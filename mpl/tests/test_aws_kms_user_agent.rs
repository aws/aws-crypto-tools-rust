// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `aws_kms::user_agent::with_user_agent`.

#![cfg(feature = "test-utils")]

use aws_config::{BehaviorVersion, FrameworkMetadata, SdkConfig};
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::aws_kms::__test_internals::{MPL_FRAMEWORK_NAME, with_user_agent};

/// A zero-config KMS client.
/// Construction does no IO.
fn dummy_client() -> KmsClient {
    KmsClient::new(
        &SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .build(),
    )
}

/// The framework metadata names carried by a KMS client, in order.
fn identifiers(client: &KmsClient) -> Vec<String> {
    client
        .config()
        .framework_metadata()
        .iter()
        .map(|metadata| metadata.name().to_string())
        .collect()
}

#[test]
fn untagged_client_gains_the_identifier() {
    let client = dummy_client();
    assert!(
        identifiers(&client).is_empty(),
        "precondition: no identifier"
    );

    let tagged = with_user_agent(client);
    let metadata = tagged.config().framework_metadata();
    assert_eq!(metadata.len(), 1);
    // The SDK renders the metadata into the User-Agent header as `lib/<name>/<version>`,
    // so these two asserts pin exactly what goes onto the wire.
    assert_eq!(metadata[0].name(), "AwsCryptographicMPL-Rust");
    assert_eq!(metadata[0].version(), Some(env!("CARGO_PKG_VERSION")));
    assert!(
        !MPL_FRAMEWORK_NAME.contains('/'),
        "framework metadata names reject '/': {MPL_FRAMEWORK_NAME}"
    );
}

#[test]
fn already_tagged_client_is_not_tagged_twice() {
    let once = with_user_agent(dummy_client());
    let twice = with_user_agent(once);
    assert_eq!(identifiers(&twice), vec![MPL_FRAMEWORK_NAME]);
}

#[test]
fn caller_framework_metadata_is_preserved() {
    let caller = FrameworkMetadata::new("caller-framework", Some("1.2.3")).unwrap();
    let client = KmsClient::from_conf(
        dummy_client()
            .config()
            .to_builder()
            .framework_metadata(caller)
            .build(),
    );

    assert_eq!(
        identifiers(&with_user_agent(client)),
        vec!["caller-framework", MPL_FRAMEWORK_NAME]
    );
}
