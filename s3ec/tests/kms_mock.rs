// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for the KMS keyring tests: building a no-network
//! `aws_sdk_kms::Client` backed by `aws-smithy-mocks` rules so the keyring's
//! KMS request construction and call behavior can be observed without any
//! network access.

#![allow(dead_code)]

use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region};
use aws_smithy_mocks::{MockResponseInterceptor, Rule, RuleMode};

/// The KMS key identifier the test keyrings are configured with.
pub const TEST_KEY_ID: &str = "arn:aws:kms:us-west-2:111122223333:key/test-key";

/// Build a no-network KMS client whose responses are served by `rules`.
///
/// `RuleMode::MatchAny` lets each rule match by its `match_requests` filter,
/// independent of ordering.
pub fn mock_kms(rules: &[&Rule]) -> aws_sdk_kms::Client {
    let mut interceptor = MockResponseInterceptor::new().rule_mode(RuleMode::MatchAny);
    for rule in rules {
        interceptor = interceptor.with_rule(rule);
    }
    let conf = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .credentials_provider(Credentials::new("ak", "sk", None, None, "test"))
        .interceptor(interceptor)
        .build();
    aws_sdk_kms::Client::from_conf(conf)
}
