// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Attribute names and `type` values for the branch key store, as defined by
//! the [record format] and [encryption context] sections of
//! `spec/framework/branch-key-store.md`.
//!
//! [record format]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/branch-key-store.md#record-format
//! [encryption context]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/branch-key-store.md#encryption-context

pub const ATTR_BRANCH_KEY_ID: &str = "branch-key-id";
pub const ATTR_TYPE: &str = "type";
pub const ATTR_VERSION: &str = "version";
pub const ATTR_CREATE_TIME: &str = "create-time";
pub const ATTR_KMS_ARN: &str = "kms-arn";
pub const ATTR_HIERARCHY_VERSION: &str = "hierarchy-version";
pub const ATTR_TABLENAME: &str = "tablename";
pub const ATTR_ENC: &str = "enc";

pub const TYPE_BRANCH_ACTIVE: &str = "branch:ACTIVE";
pub const TYPE_BEACON_ACTIVE: &str = "beacon:ACTIVE";
pub const TYPE_BRANCH_VERSION_PREFIX: &str = "branch:version:";

pub const CUSTOM_EC_PREFIX: &str = "aws-crypto-ec:";
