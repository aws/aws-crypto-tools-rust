// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! KMS configuration of a [`KeyStore`](super::KeyStore).

use crate::Error;
use crate::builder::required;

/// The KMS key configuration for a key store.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KmsConfiguration {
    /// Single-region KMS Key ARN compatibility. ARN may be MRK or non-MRK.
    KmsKeyArn(String),
    /// MRK ARN compatibility. ARN may be MRK or non-MRK.
    KmsMrKeyArn(String),
    /// Discovery configuration; KMS Key ARN is read from each DDB record.
    Discovery(Discovery),
    /// MRDiscovery configuration; KMS Key ARN is read from each DDB record.
    /// The key store replaces the region of an MRK ARN with the configured region.
    MrDiscovery(MrDiscovery),
}

impl KmsConfiguration {
    /// The ARN if this is [`KmsKeyArn`](Self::KmsKeyArn), otherwise `Err(self)`.
    ///
    /// # Errors
    ///
    /// Returns `self` when it is another variant.
    pub const fn as_kms_key_arn(&self) -> Result<&String, &Self> {
        if let Self::KmsKeyArn(v) = self {
            Ok(v)
        } else {
            Err(self)
        }
    }

    /// Whether this is [`KmsKeyArn`](Self::KmsKeyArn).
    #[must_use]
    pub const fn is_kms_key_arn(&self) -> bool {
        matches!(self, Self::KmsKeyArn(_))
    }

    /// The ARN if this is [`KmsMrKeyArn`](Self::KmsMrKeyArn), otherwise `Err(self)`.
    ///
    /// # Errors
    ///
    /// Returns `self` when it is another variant.
    pub const fn as_kms_mr_key_arn(&self) -> Result<&String, &Self> {
        if let Self::KmsMrKeyArn(v) = self {
            Ok(v)
        } else {
            Err(self)
        }
    }

    /// Whether this is [`KmsMrKeyArn`](Self::KmsMrKeyArn).
    #[must_use]
    pub const fn is_kms_mr_key_arn(&self) -> bool {
        matches!(self, Self::KmsMrKeyArn(_))
    }

    /// The settings if this is [`Discovery`](Self::Discovery), otherwise `Err(self)`.
    ///
    /// # Errors
    ///
    /// Returns `self` when it is another variant.
    pub const fn as_discovery(&self) -> Result<&Discovery, &Self> {
        if let Self::Discovery(v) = self {
            Ok(v)
        } else {
            Err(self)
        }
    }

    /// Whether this is [`Discovery`](Self::Discovery).
    #[must_use]
    pub const fn is_discovery(&self) -> bool {
        matches!(self, Self::Discovery(_))
    }

    /// The settings if this is [`MrDiscovery`](Self::MrDiscovery), otherwise `Err(self)`.
    ///
    /// # Errors
    ///
    /// Returns `self` when it is another variant.
    pub const fn as_mr_discovery(&self) -> Result<&MrDiscovery, &Self> {
        if let Self::MrDiscovery(v) = self {
            Ok(v)
        } else {
            Err(self)
        }
    }

    /// Whether this is [`MrDiscovery`](Self::MrDiscovery).
    #[must_use]
    pub const fn is_mr_discovery(&self) -> bool {
        matches!(self, Self::MrDiscovery(_))
    }
}

/// Settings for [`KmsConfiguration::Discovery`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Discovery {}

impl Discovery {
    /// Start a builder for `Discovery`.
    #[must_use]
    pub fn builder() -> DiscoveryBuilder {
        DiscoveryBuilder::default()
    }
}

/// Builder for [`Discovery`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DiscoveryBuilder {}

impl DiscoveryBuilder {
    /// Build the `Discovery`.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub const fn build(self) -> Result<Discovery, Error> {
        Ok(Discovery {})
    }
}

/// Settings for [`KmsConfiguration::MrDiscovery`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MrDiscovery {
    region: String,
}

impl MrDiscovery {
    /// Start a builder for `MrDiscovery`.
    #[must_use]
    pub fn builder() -> MrDiscoveryBuilder {
        MrDiscoveryBuilder::default()
    }

    /// The region any discovered MRK ARN is rewritten to.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
}

/// Builder for [`MrDiscovery`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct MrDiscoveryBuilder {
    region: Option<String>,
}

impl MrDiscoveryBuilder {
    /// Set the region any discovered MRK ARN is rewritten to. Required.
    #[must_use]
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Set or clear the region from an `Option`.
    #[must_use]
    pub fn set_region(mut self, region: Option<String>) -> Self {
        self.region = region;
        self
    }

    /// The region set on this builder, if any.
    #[must_use]
    #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
    pub const fn get_region(&self) -> &Option<String> {
        &self.region
    }

    /// Build the `MrDiscovery`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no region was set.
    pub fn build(self) -> Result<MrDiscovery, Error> {
        Ok(MrDiscovery {
            region: required(self.region, "region")?,
        })
    }
}
