// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! User agent identification for AWS KMS SDK clients.

use aws_config::FrameworkMetadata;
use aws_sdk_kms::Client as KmsClient;

pub const MPL_FRAMEWORK_NAME: &str = "AwsCryptographicMPL-Rust";

// `FrameworkMetadata` is the AWS SDK for Rust's supported mechanism for a
// library built on top of the SDK to self-identify: the SDK renders it into the
// `User-Agent` header as `lib/<name>/<version>`. It is stored by appending, so
// any metadata the caller registered is kept.
pub fn with_user_agent(client: KmsClient) -> KmsClient {
    let config = client.config();
    if config
        .framework_metadata()
        .iter()
        .any(|metadata| metadata.name() == MPL_FRAMEWORK_NAME)
    {
        return client;
    }
    let metadata = FrameworkMetadata::new(MPL_FRAMEWORK_NAME, Some(env!("CARGO_PKG_VERSION")))
        .expect("framework metadata is valid");
    KmsClient::from_conf(config.to_builder().framework_metadata(metadata).build())
}
