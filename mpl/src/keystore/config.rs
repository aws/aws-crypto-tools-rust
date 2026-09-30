// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for the [`Keystore`](super::Keystore) trait.

/// Information about a configured keystore, returned by
/// [`Keystore::get_key_store_info`](super::Keystore::get_key_store_info).
#[derive(Debug, Clone)]
pub struct KeyStoreInfo {
    /// The keystore identifier.
    pub keystore_id: String,
    /// The DynamoDB table name.
    pub keystore_name: String,
    /// The logical keystore name.
    pub logical_keystore_name: String,
    /// The configured AWS KMS grant tokens.
    pub grant_tokens: Vec<String>,
    /// The KMS configuration for this keystore.
    pub kms_configuration: KmsConfiguration,
}

/// The KMS key configuration for a keystore.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KmsConfiguration {
    /// Single-region KMS Key ARN compatibility. ARN may be MRK or non-MRK.
    KmsKeyArn(String),
    /// MRK ARN compatibility. ARN may be MRK or non-MRK.
    KmsMrKeyArn(String),
    /// Discovery configuration; KMS Key ARN is read from each DDB record.
    Discovery(Discovery),
    /// MRDiscovery configuration; KMS Key ARN is read from each DDB record,
    /// with an MRK ARN's region replaced by the configured region.
    MrDiscovery(MrDiscovery),
}

/// Settings for [`KmsConfiguration::Discovery`].
///
/// Construct with [`Discovery::builder`].
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
    #[must_use]
    pub fn build(self) -> Discovery {
        Discovery {}
    }
}

/// Settings for [`KmsConfiguration::MrDiscovery`].
///
/// Construct with [`MrDiscovery::builder`].
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

    /// Build the `MrDiscovery`.
    ///
    /// # Errors
    ///
    /// Returns a [`KeystoreErrorKind::Configuration`](super::KeystoreErrorKind::Configuration)
    /// error if no region was set.
    pub fn build(self) -> Result<MrDiscovery, super::KeystoreError> {
        let Some(region) = self.region else {
            return Err(super::KeystoreError::new(
                super::KeystoreErrorKind::Configuration,
                "MrDiscovery: a region is required",
            ));
        };
        Ok(MrDiscovery { region })
    }
}
