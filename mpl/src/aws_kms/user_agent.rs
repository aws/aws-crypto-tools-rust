// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! User agent identification for AWS KMS SDK clients.

use aws_config::FrameworkMetadata;
use aws_sdk_kms::Client as KmsClient;

pub const MPL_FRAMEWORK_NAME: &str = "AwsCryptographicMPL-Rust";

// A library built on the AWS SDK for Rust identifies itself with FrameworkMetadata.
// The SDK renders it into the User-Agent header as `lib/<name>/<version>`.
// Registering ours appends instead of overwriting so the caller's existing entries stay intact.
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
