// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! User agent identification for AWS KMS requests.

use aws_sdk_kms::config::Builder as KmsConfigBuilder;
use aws_types::sdk_ua_metadata::FrameworkMetadata;

const MPL_FRAMEWORK_NAME: &str = "AwsCryptographicMPL-Rust";

// A library built on the AWS SDK for Rust identifies itself with FrameworkMetadata.
// The SDK renders it into the User-Agent header as `lib/<name>/<version>`.
// Each KMS request applies this as a config override and leaves the client unchanged.
// The override appends to the client's framework metadata instead of replacing it.
pub(crate) fn user_agent_override() -> KmsConfigBuilder {
    let metadata = FrameworkMetadata::new(MPL_FRAMEWORK_NAME, Some(env!("CARGO_PKG_VERSION")))
        .expect("framework metadata is valid");
    KmsConfigBuilder::default().framework_metadata(metadata)
}
