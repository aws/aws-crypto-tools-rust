// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! KMS configuration of a [`KeyStore`](super::KeyStore).

/// The KMS key configuration for a key store.
#[derive(Debug, Clone)]
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

/// Settings for [`KmsConfiguration::Discovery`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Discovery {}

/// Settings for [`KmsConfiguration::MrDiscovery`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MrDiscovery {
    region: String,
}

impl MrDiscovery {
    /// Rewrite any discovered MRK ARN to `region`.
    #[must_use]
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
        }
    }

    /// The region any discovered MRK ARN is rewritten to.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
}

impl From<Discovery> for KmsConfiguration {
    fn from(discovery: Discovery) -> Self {
        Self::Discovery(discovery)
    }
}

impl From<MrDiscovery> for KmsConfiguration {
    fn from(mr_discovery: MrDiscovery) -> Self {
        Self::MrDiscovery(mr_discovery)
    }
}
