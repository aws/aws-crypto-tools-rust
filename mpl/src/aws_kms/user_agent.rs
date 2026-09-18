// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! User agent identification for AWS KMS SDK clients.
//!
//! Separate from the branch key store so the AWS KMS keyrings, which also take
//! an optional KMS client, can reuse it.

use aws_config::FrameworkMetadata;
use aws_sdk_kms::Client as KmsClient;

// Mirrors the Dafny MPL's `AwsCryptographicMPL/<runtime>` identifier with `/`
// replaced by `-`, because a framework metadata name rejects `/`.
pub const MPL_FRAMEWORK_NAME: &str = "AwsCryptographicMPL-Rust";

// `FrameworkMetadata` is the AWS SDK for Rust's supported mechanism for a
// library built on top of the SDK to self-identify: the SDK renders it into the
// `User-Agent` header as `lib/<name>/<version>`. It is stored by appending, so
// any metadata the caller registered is kept — unlike the client's app name,
// which has a single slot.
//
// Per the branch key store specification the keystore appends a user agent
// string to the AWS KMS SDK client:
// https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/branch-key-store.md#kms-client
// The value used is the generic MPL identifier the Dafny implementation applies
// to every KMS client it constructs, not the `aws-kms-hierarchy` value the
// specification text names, which no Dafny runtime implements.
//
// The Dafny implementation sets the identifier only on clients it constructs
// itself; this applies to caller-supplied clients too, so requests are
// attributable however the client was obtained.
pub fn with_user_agent(client: KmsClient) -> KmsClient {
    let config = client.config();
    if config
        .framework_metadata()
        .iter()
        .any(|metadata| metadata.name() == MPL_FRAMEWORK_NAME)
    {
        return client;
    }
    // Cannot fail: both arguments are compile-time constants drawn from the
    // permitted charset (ASCII alphanumerics plus `-`, and the `.`, `-` and `+`
    // a Cargo semver version can add).
    let metadata = FrameworkMetadata::new(MPL_FRAMEWORK_NAME, Some(env!("CARGO_PKG_VERSION")))
        .expect("framework metadata is valid");
    // `to_builder` clones the whole configuration — config bag, runtime
    // components, runtime plugins and behavior version — so credentials,
    // region, HTTP client and interceptors all survive the round trip.
    KmsClient::from_conf(config.to_builder().framework_metadata(metadata).build())
}
