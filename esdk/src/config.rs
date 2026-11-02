// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The [`Config`] a [`Client`](crate::Client) applies to every operation, and its [`Builder`].

use crate::Error;
use crate::error::val_err;
use crate::shapes::{CommitmentPolicy, DEFAULT_COMMITMENT_POLICY};
use std::num::NonZeroUsize;

/// Configuration for the [`Client`](crate::Client).
///
/// Holds the commitment policy and the optional cap on the number of encrypted
/// data keys per message. Build with [`Config::builder`] and pass to
/// [`Client::from_conf`](crate::Client::from_conf), or set the same options on [`Client::builder`](crate::Client::builder).
//= spec/client-apis/client.md#initialization
//= reason=field defaults to None via derive(Default); None means no cap
//# If no [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys) is provided
//# the default MUST result in no limit on the number of encrypted data keys (aside from the limit imposed by the [message format](../format/message-header.md)).
//
//= spec/client-apis/client.md#initialization
//= reason=Config::default() sets commitment_policy to DEFAULT_COMMITMENT_POLICY = RequireEncryptRequireDecrypt
//# If no [commitment policy](#commitment-policy) is provided the default MUST be [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../framework/algorithm-suites.md#require_encrypt_require_decrypt).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Commitment policy applied to every operation. Default is
    /// `CommitmentPolicy::RequireEncryptRequireDecrypt`.
    //= spec/client-apis/client.md#commitment-policy
    //= reason=CommitmentPolicy is a re-export of the MPL's aws_crypto_mpl::types::EsdkCommitmentPolicy
    //# The AWS Encryption SDK MUST use the ESDK [commitment policies](../framework/commitment-policy.md) defined in the Material Providers Library.
    pub(crate) commitment_policy: CommitmentPolicy,
    /// Optional cap on the number of encrypted data keys per message.
    /// Default is `None` (no cap beyond the message-format limit).
    pub(crate) max_encrypted_data_keys: Option<NonZeroUsize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            commitment_policy: DEFAULT_COMMITMENT_POLICY,
            max_encrypted_data_keys: None,
        }
    }
}

impl Config {
    /// Start a builder for `Config`.
    #[must_use]
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// A builder preloaded with this config's values.
    #[must_use]
    pub const fn to_builder(&self) -> Builder {
        Builder {
            commitment_policy: Some(self.commitment_policy),
            max_encrypted_data_keys: self.max_encrypted_data_keys(),
        }
    }

    /// The commitment policy applied to every operation.
    #[must_use]
    pub const fn commitment_policy(&self) -> CommitmentPolicy {
        self.commitment_policy
    }

    /// The maximum number of encrypted data keys per message, if capped.
    #[must_use]
    pub const fn max_encrypted_data_keys(&self) -> Option<usize> {
        match self.max_encrypted_data_keys {
            Some(n) => Some(n.get()),
            None => None,
        }
    }
}

/// Builder for [`Config`].
#[derive(Debug, Clone, Default)]
#[allow(missing_copy_implementations)] // not Copy, like Config, so it can gain settings that aren't Copy
pub struct Builder {
    commitment_policy: Option<CommitmentPolicy>,
    max_encrypted_data_keys: Option<usize>,
}

impl Builder {
    /// Set the commitment policy.
    #[must_use]
    pub const fn commitment_policy(mut self, commitment_policy: CommitmentPolicy) -> Self {
        self.commitment_policy = Some(commitment_policy);
        self
    }

    /// Set or clear the commitment policy from an `Option`.
    pub const fn set_commitment_policy(
        &mut self,
        commitment_policy: Option<CommitmentPolicy>,
    ) -> &mut Self {
        self.commitment_policy = commitment_policy;
        self
    }

    /// Set the maximum number of encrypted data keys per message.
    /// It must be greater than 0.
    #[must_use]
    pub const fn max_encrypted_data_keys(mut self, max_encrypted_data_keys: usize) -> Self {
        self.max_encrypted_data_keys = Some(max_encrypted_data_keys);
        self
    }

    /// Set or clear the maximum number of encrypted data keys from an `Option`.
    pub const fn set_max_encrypted_data_keys(
        &mut self,
        max_encrypted_data_keys: Option<usize>,
    ) -> &mut Self {
        self.max_encrypted_data_keys = max_encrypted_data_keys;
        self
    }

    /// The commitment policy set so far.
    #[must_use]
    #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
    pub const fn get_commitment_policy(&self) -> &Option<CommitmentPolicy> {
        &self.commitment_policy
    }

    /// The maximum number of encrypted data keys set so far.
    #[must_use]
    #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
    pub const fn get_max_encrypted_data_keys(&self) -> &Option<usize> {
        &self.max_encrypted_data_keys
    }

    /// Build the `Config`. Unset fields use their defaults
    /// (`RequireEncryptRequireDecrypt` commitment policy, no EDK cap).
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `max_encrypted_data_keys` is 0.
    pub fn build(self) -> Result<Config, Error> {
        let max_encrypted_data_keys = match self.max_encrypted_data_keys {
            None => None,
            Some(n) => Some(
                NonZeroUsize::new(n)
                    .ok_or_else(|| val_err("max_encrypted_data_keys must be greater than 0"))?,
            ),
        };
        Ok(Config {
            commitment_policy: self.commitment_policy.unwrap_or(DEFAULT_COMMITMENT_POLICY),
            max_encrypted_data_keys,
        })
    }
}
