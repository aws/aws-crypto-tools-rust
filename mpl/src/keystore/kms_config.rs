// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ARN parsing, validation, and MRK-aware compatibility for KMS configurations.

use crate::Error;
use crate::aws_kms::mrk_match::aws_kms_mrk_match_for_decrypt;
use crate::error::Kind;
use crate::keystore::config::KmsConfiguration;

/// The parsed parts of an AWS ARN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArnParts {
    /// The ARN partition (e.g., "aws", "aws-cn").
    pub partition: String,
    /// The service name (e.g., "kms").
    pub service: String,
    /// The region (e.g., "us-east-1").
    pub region: String,
    /// The account ID.
    pub account_id: String,
    /// The resource type (e.g., "key", "alias").
    pub resource_type: String,
    /// The resource identifier.
    pub resource: String,
}

/// Parses an ARN string into its component parts.
///
/// Expected format: `arn:<partition>:<service>:<region>:<account>:<resourceType>/<resource>`
pub fn parse_arn(arn: &str) -> Result<ArnParts, Error> {
    let segments: Vec<&str> = arn.splitn(6, ':').collect();
    if segments.len() != 6 || segments[0] != "arn" {
        return Err(Error::new(
            Kind::Validation,
            format!(
                "malformed ARN: expected 6 colon-separated segments starting with 'arn', got: {arn}"
            ),
        ));
    }
    let (resource_type, resource) = segments[5].split_once('/').ok_or_else(|| {
        Error::new(
            Kind::Validation,
            format!(
                "malformed ARN: resource segment must contain '/', got: {}",
                segments[5]
            ),
        )
    })?;
    Ok(ArnParts {
        partition: segments[1].to_string(),
        service: segments[2].to_string(),
        region: segments[3].to_string(),
        account_id: segments[4].to_string(),
        resource_type: resource_type.to_string(),
        resource: resource.to_string(),
    })
}

/// Validates that an ARN is a usable AWS KMS Key ARN per the spec.
pub fn validate_kms_key_arn(arn: &str) -> Result<ArnParts, Error> {
    let parts = parse_arn(arn)?;

    if parts.service != "kms" {
        return Err(Error::new(
            Kind::Validation,
            format!("ARN service must be 'kms', got: {}", parts.service),
        ));
    }

    if parts.resource_type == "alias" {
        return Err(Error::new(
            Kind::Validation,
            format!("KMS Key ARN must not be an alias: {arn}"),
        ));
    }

    Ok(parts)
}

/// Returns true if `stored_arn` is compatible with the given KMS configuration.
///
/// - `KmsKeyArn`: byte-equality of the two ARNs.
/// - `KmsMrKeyArn`: defers to `aws_kms_mrk_match_for_decrypt`.
/// - `Discovery` / `MrDiscovery`: always compatible (returns true).
pub fn is_arn_compatible(config: &KmsConfiguration, stored_arn: &str) -> bool {
    match config {
        KmsConfiguration::KmsKeyArn(configured) => configured == stored_arn,
        KmsConfiguration::KmsMrKeyArn(configured) => {
            aws_kms_mrk_match_for_decrypt(configured, stored_arn)
        }
        KmsConfiguration::Discovery(_) | KmsConfiguration::MrDiscovery(_) => true,
    }
}

impl KmsConfiguration {
    /// Validates the configuration's ARN (if any) per the branch-key-store spec.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            KmsConfiguration::KmsKeyArn(a) | KmsConfiguration::KmsMrKeyArn(a) => {
                validate_kms_key_arn(a).map(|_| ())
            }
            KmsConfiguration::Discovery(_) | KmsConfiguration::MrDiscovery(_) => Ok(()),
        }
    }

    /// Returns true if `stored_arn` is compatible with this configuration.
    pub fn is_compatible_with(&self, stored_arn: &str) -> bool {
        is_arn_compatible(self, stored_arn)
    }
}
