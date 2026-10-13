// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The [`Esdk`] client and its [`EsdkConfig`].
//!
//! `Esdk` holds an [`EsdkConfig`]: a commitment policy and an optional cap on encrypted data keys.
//! Each operation's fluent builder takes both settings from the client and has no setters for them:
//!
//! ```ignore
//! let esdk = Esdk::builder().commitment_policy(policy).build();
//! let output = esdk.encrypt().plaintext(plaintext).keyring(keyring).send().await?;
//! ```

use crate::Error;
use crate::types::{
    AlgorithmSuiteId, DecryptInput, DecryptInputBuilder, DecryptOutput, DecryptStreamInput,
    DecryptStreamInputBuilder, DecryptStreamOutput, EncryptInput, EncryptInputBuilder,
    EncryptOutput, EncryptStreamInput, EncryptStreamInputBuilder, EncryptStreamOutput,
    EncryptionContext,
};
use crate::types::{CommitmentPolicy, DEFAULT_COMMITMENT_POLICY};
use aws_crypto_mpl::{Cmm, Keyring, SharedCmm, SharedKeyring};
use std::num::{NonZeroU32, NonZeroUsize};

/// Configuration for the [`Esdk`] client.
///
/// Holds the commitment policy and the optional cap on the number of encrypted
/// data keys per message. Construct via [`EsdkConfig::default`] and field
/// assignment, or via [`Esdk::builder`].
//= spec/client-apis/client.md#initialization
//= reason=field defaults to None via derive(Default); None means no cap
//# If no [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys) is provided
//# the default MUST result in no limit on the number of encrypted data keys (aside from the limit imposed by the [message format](../format/message-header.md)).
//
//= spec/client-apis/client.md#initialization
//= reason=EsdkConfig::default() sets commitment_policy to DEFAULT_COMMITMENT_POLICY = RequireEncryptRequireDecrypt
//# If no [commitment policy](#commitment-policy) is provided the default MUST be [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../framework/algorithm-suites.md#require_encrypt_require_decrypt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EsdkConfig {
    /// Commitment policy applied to every operation. Default is
    /// `CommitmentPolicy::RequireEncryptRequireDecrypt`.
    //= spec/client-apis/client.md#commitment-policy
    //= reason=CommitmentPolicy is a re-export of the MPL's aws_crypto_mpl::structures::EsdkCommitmentPolicy
    //# The AWS Encryption SDK MUST use the ESDK [commitment policies](../framework/commitment-policy.md) defined in the Material Providers Library.
    pub commitment_policy: CommitmentPolicy,
    /// Optional cap on the number of encrypted data keys per message.
    /// Default is `None` (no cap beyond the message-format limit).
    pub max_encrypted_data_keys: Option<NonZeroUsize>,
}

impl Default for EsdkConfig {
    fn default() -> Self {
        Self {
            commitment_policy: DEFAULT_COMMITMENT_POLICY,
            max_encrypted_data_keys: None,
        }
    }
}

/// The AWS Encryption SDK client.
/// Applies one [`EsdkConfig`] to every operation.
///
/// Each operation method returns a fluent builder that takes `commitment_policy`
/// and `max_encrypted_data_keys` from the client.
/// Set the rest on the builder and finish with `send`.
///
/// # Example
///
/// ```ignore
/// let esdk = Esdk::builder()
///     .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
///     .build();
/// let output = esdk
///     .encrypt()
///     .plaintext(plaintext)
///     .encryption_context(ec)
///     .keyring(keyring)
///     .send()
///     .await?;
/// ```
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct Esdk {
    /// Client configuration applied to every call.
    ///
    /// Private to enforce construction via [`Esdk::new`] / [`Esdk::builder`];
    /// read via [`Esdk::config`].
    //= spec/client-apis/client.md#initialization
    //= type=implication
    //= reason=pub(crate) prevents external mutation; Esdk is Copy so any "change" must construct a new value
    //# Once a [commitment policy](#commitment-policy) has been set it SHOULD be immutable.
    pub(crate) config: EsdkConfig,
}

impl Esdk {
    /// Construct an `Esdk` with the given config.
    #[must_use]
    pub const fn new(config: EsdkConfig) -> Self {
        Self { config }
    }

    /// Start a fluent builder for `Esdk`.
    #[must_use]
    pub fn builder() -> EsdkBuilder {
        EsdkBuilder::default()
    }

    /// Borrow this client's configuration.
    #[must_use]
    pub const fn config(&self) -> &EsdkConfig {
        &self.config
    }

    /// Start an encrypt with this client's commitment policy and encrypted data key cap.
    /// Set the rest on the returned builder, then call [`send`](EncryptFluentBuilder::send).
    //= spec/client-apis/client.md#encrypt
    //# The AWS Encryption SDK Client MUST provide an [encrypt](./encrypt.md#input) function
    //# that adheres to [encrypt](./encrypt.md).
    pub fn encrypt<'a>(&self) -> EncryptFluentBuilder<'a> {
        EncryptFluentBuilder {
            config: self.config,
            inner: EncryptInput::builder(),
        }
    }

    /// Start a decrypt with this client's commitment policy and encrypted data key cap.
    /// Set the rest on the returned builder, then call [`send`](DecryptFluentBuilder::send).
    //= spec/client-apis/client.md#decrypt
    //# The AWS Encryption SDK Client MUST provide an [decrypt](./decrypt.md#input) function
    //# that adheres to [decrypt](./decrypt.md).
    pub fn decrypt<'a>(&self) -> DecryptFluentBuilder<'a> {
        DecryptFluentBuilder {
            config: self.config,
            inner: DecryptInput::builder(),
        }
    }

    /// Start a streaming encrypt with this client's commitment policy and encrypted data key cap.
    /// Set the rest on the returned builder, then call [`send`](EncryptStreamFluentBuilder::send).
    pub fn encrypt_stream(&self) -> EncryptStreamFluentBuilder {
        EncryptStreamFluentBuilder {
            config: self.config,
            inner: EncryptStreamInput::builder(),
        }
    }

    /// Start a streaming decrypt with this client's commitment policy and encrypted data key cap.
    /// Set the rest on the returned builder, then call [`send`](DecryptStreamFluentBuilder::send).
    pub fn decrypt_stream(&self) -> DecryptStreamFluentBuilder {
        DecryptStreamFluentBuilder {
            config: self.config,
            inner: DecryptStreamInput::builder(),
        }
    }
}

/// Forward a member's setters to the wrapped input builder, and add its getter.
macro_rules! forward {
    (
        $(#[$getter_meta:meta])*
        $getter:ident -> $out:ty {
            $($(#[$meta:meta])* $name:ident($arg:ident: $ty:ty);)+
        }
    ) => {
        $(
            $(#[$meta])*
            pub fn $name(mut self, $arg: $ty) -> Self {
                self.inner = self.inner.$name($arg);
                self
            }
        )+

        $(#[$getter_meta])*
        #[must_use]
        #[allow(clippy::ref_option, clippy::ref_option_ref)] // AWS SDK for Rust getter shape
        pub const fn $getter(&self) -> &Option<$out> {
            self.inner.$getter()
        }
    };
}

/// The members every operation's fluent builder has.
macro_rules! forward_common {
    () => {
        forward!(
            /// The encryption context set so far.
            get_encryption_context -> EncryptionContext {
                /// Set the encryption context. Default is empty.
                encryption_context(encryption_context: impl Into<EncryptionContext>);
                /// Set or clear the encryption context from an `Option`.
                set_encryption_context(encryption_context: Option<EncryptionContext>);
            }
        );
        forward!(
            /// The keyring set so far.
            get_keyring -> SharedKeyring {
                /// Set the keyring. Set exactly one of a keyring or a CMM.
                keyring(keyring: impl Keyring + 'static);
                /// Set or clear the keyring from an `Option`.
                set_keyring(keyring: Option<SharedKeyring>);
            }
        );
        forward!(
            /// The CMM set so far.
            get_cmm -> SharedCmm {
                /// Set the cryptographic materials manager. Set exactly one of a keyring or a CMM.
                cmm(cmm: impl Cmm + 'static);
                /// Set or clear the CMM from an `Option`.
                set_cmm(cmm: Option<SharedCmm>);
            }
        );
    };
}

/// The members the two encrypt builders share.
macro_rules! forward_encrypt {
    () => {
        forward!(
            /// The algorithm suite set so far.
            get_algorithm_suite_id -> AlgorithmSuiteId {
                /// Set the algorithm suite. Unset uses the commitment policy's default suite.
                algorithm_suite_id(algorithm_suite_id: AlgorithmSuiteId);
                /// Set or clear the algorithm suite from an `Option`.
                set_algorithm_suite_id(algorithm_suite_id: Option<AlgorithmSuiteId>);
            }
        );
        forward!(
            /// The frame length set so far.
            get_frame_length -> NonZeroU32 {
                /// Set the frame length in bytes. Defaults to 4096.
                frame_length(frame_length: NonZeroU32);
                /// Set or clear the frame length from an `Option`.
                set_frame_length(frame_length: Option<NonZeroU32>);
            }
        );
    };
}

/// An encrypt started by [`Esdk::encrypt`].
#[derive(Debug, Clone)]
#[must_use = "a fluent builder does nothing until `send` is awaited"]
pub struct EncryptFluentBuilder<'a> {
    config: EsdkConfig,
    inner: EncryptInputBuilder<'a>,
}

impl<'a> EncryptFluentBuilder<'a> {
    forward!(
        /// The plaintext set so far.
        get_plaintext -> &'a [u8] {
            /// Set the plaintext to encrypt. Required.
            plaintext(plaintext: &'a [u8]);
        }
    );
    forward_common!();
    forward_encrypt!();

    /// Encrypt.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::Error), one of:
    /// - [`Validation`](crate::Error::Validation): an encryption context key uses the reserved `aws-crypto-` prefix, the commitment policy does not allow the requested algorithm suite, the encrypted data key count exceeds the configured maximum, or the plaintext exceeds the size limit.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keyring or CMM returns materials the ESDK cannot use, such as no plaintext data key, an unsupported algorithm suite, or no signing key for a signing suite.
    /// - [`EncryptionContextMismatch`](crate::Error::EncryptionContextMismatch): the keyring or CMM rejects the encryption context.
    /// - [`NoMatchingDataKey`](crate::Error::NoMatchingDataKey): the keyring or CMM produces no data key.
    /// - [`Cryptographic`](crate::Error::Cryptographic): data key derivation, frame encryption, or signing fails.
    /// - [`AccessDenied`](crate::Error::AccessDenied): AWS KMS or `DynamoDB` denies a call from a keyring, CMM, or key store.
    /// - [`ResourceNotFound`](crate::Error::ResourceNotFound): a KMS key, `DynamoDB` table, or branch key does not exist.
    /// - [`Throttling`](crate::Error::Throttling): AWS KMS, `DynamoDB`, or the materials cache throttles the request.
    /// - [`Conflict`](crate::Error::Conflict): the keyring or CMM reports a conflict with a resource's current state.
    /// - [`Service`](crate::Error::Service): AWS KMS or `DynamoDB` fails the request for another reason.
    /// - [`Dispatch`](crate::Error::Dispatch): a request to AWS KMS or `DynamoDB` is not sent, or its response does not arrive.
    /// - [`Internal`](crate::Error::Internal): an internal invariant is violated.
    pub async fn send(self) -> Result<EncryptOutput, Error> {
        let input = self
            .inner
            .commitment_policy(self.config.commitment_policy)
            .set_max_encrypted_data_keys(self.config.max_encrypted_data_keys)
            .build()?;
        crate::encrypt::encrypt(&input).await
    }
}

/// A decrypt started by [`Esdk::decrypt`].
#[derive(Debug, Clone)]
#[must_use = "a fluent builder does nothing until `send` is awaited"]
pub struct DecryptFluentBuilder<'a> {
    config: EsdkConfig,
    inner: DecryptInputBuilder<'a>,
}

impl<'a> DecryptFluentBuilder<'a> {
    forward!(
        /// The encrypted message set so far.
        get_ciphertext -> &'a [u8] {
            /// Set the encrypted message to decrypt. Required.
            ciphertext(ciphertext: &'a [u8]);
        }
    );
    forward_common!();

    /// Decrypt.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::Error), one of:
    /// - [`Validation`](crate::Error::Validation): the message's encrypted data key count exceeds the configured maximum, or the commitment policy does not allow the message's algorithm suite.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keyring or CMM returns materials the ESDK cannot use, or materials that do not match the message's algorithm suite or signature settings.
    /// - [`EncryptionContextMismatch`](crate::Error::EncryptionContextMismatch): the reproduced encryption context conflicts with the message, or a required key is missing.
    /// - [`NoMatchingDataKey`](crate::Error::NoMatchingDataKey): none of the message's encrypted data keys belongs to the keyring or CMM.
    /// - [`Cryptographic`](crate::Error::Cryptographic): the header tag, a frame tag, the key commitment, or the signature does not verify.
    /// - [`AccessDenied`](crate::Error::AccessDenied): AWS KMS or `DynamoDB` denies a call from a keyring, CMM, or key store.
    /// - [`ResourceNotFound`](crate::Error::ResourceNotFound): a KMS key, `DynamoDB` table, or branch key does not exist.
    /// - [`Throttling`](crate::Error::Throttling): AWS KMS, `DynamoDB`, or the materials cache throttles the request.
    /// - [`Conflict`](crate::Error::Conflict): the keyring or CMM reports a conflict with a resource's current state.
    /// - [`Service`](crate::Error::Service): AWS KMS or `DynamoDB` fails the request for another reason.
    /// - [`Dispatch`](crate::Error::Dispatch): a request to AWS KMS or `DynamoDB` is not sent, or its response does not arrive.
    /// - [`Serialization`](crate::Error::Serialization): the bytes are not a well-formed encrypted message, or carry trailing data after the footer.
    /// - [`Internal`](crate::Error::Internal): an internal invariant is violated.
    pub async fn send(self) -> Result<DecryptOutput, Error> {
        let input = self
            .inner
            .commitment_policy(self.config.commitment_policy)
            .set_max_encrypted_data_keys(self.config.max_encrypted_data_keys)
            .build()?;
        crate::decrypt::decrypt(&input).await
    }
}

/// A streaming encrypt started by [`Esdk::encrypt_stream`].
#[derive(Debug, Clone)]
#[must_use = "a fluent builder does nothing until `send` is awaited"]
pub struct EncryptStreamFluentBuilder {
    config: EsdkConfig,
    inner: EncryptStreamInputBuilder,
}

impl EncryptStreamFluentBuilder {
    forward_common!();
    forward_encrypt!();
    forward!(
        /// The plaintext length set so far.
        get_data_size -> usize {
            /// Set the plaintext length in bytes, when it is known in advance.
            data_size(data_size: usize);
            /// Set or clear the plaintext length from an `Option`.
            set_data_size(data_size: Option<usize>);
        }
    );

    /// Encrypt `plaintext` into `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::Error), one of:
    /// - [`Validation`](crate::Error::Validation): an encryption context key uses the reserved `aws-crypto-` prefix, the commitment policy does not allow the requested algorithm suite, the encrypted data key count exceeds the configured maximum, or the plaintext exceeds the size limit.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keyring or CMM returns materials the ESDK cannot use, such as no plaintext data key, an unsupported algorithm suite, or no signing key for a signing suite.
    /// - [`EncryptionContextMismatch`](crate::Error::EncryptionContextMismatch): the keyring or CMM rejects the encryption context.
    /// - [`NoMatchingDataKey`](crate::Error::NoMatchingDataKey): the keyring or CMM produces no data key.
    /// - [`Cryptographic`](crate::Error::Cryptographic): data key derivation, frame encryption, or signing fails.
    /// - [`AccessDenied`](crate::Error::AccessDenied): AWS KMS or `DynamoDB` denies a call from a keyring, CMM, or key store.
    /// - [`ResourceNotFound`](crate::Error::ResourceNotFound): a KMS key, `DynamoDB` table, or branch key does not exist.
    /// - [`Throttling`](crate::Error::Throttling): AWS KMS, `DynamoDB`, or the materials cache throttles the request.
    /// - [`Conflict`](crate::Error::Conflict): the keyring or CMM reports a conflict with a resource's current state.
    /// - [`Service`](crate::Error::Service): AWS KMS or `DynamoDB` fails the request for another reason.
    /// - [`Dispatch`](crate::Error::Dispatch): a request to AWS KMS or `DynamoDB` is not sent, or its response does not arrive.
    /// - [`Io`](crate::Error::Io): the supplied plaintext reader or ciphertext writer fails.
    /// - [`Internal`](crate::Error::Internal): an internal invariant is violated.
    pub async fn send<R, W>(self, plaintext: R, ciphertext: W) -> Result<EncryptStreamOutput, Error>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
        W: tokio::io::AsyncWrite + Unpin + Send,
    {
        let input = self
            .inner
            .commitment_policy(self.config.commitment_policy)
            .set_max_encrypted_data_keys(self.config.max_encrypted_data_keys)
            .build()?;
        crate::encrypt::encrypt_stream(plaintext, ciphertext, &input).await
    }
}

/// A streaming decrypt started by [`Esdk::decrypt_stream`].
#[derive(Debug, Clone)]
#[must_use = "a fluent builder does nothing until `send` is awaited"]
pub struct DecryptStreamFluentBuilder {
    config: EsdkConfig,
    inner: DecryptStreamInputBuilder,
}

impl DecryptStreamFluentBuilder {
    forward_common!();

    /// Decrypt `ciphertext` into `plaintext`.
    ///
    /// `plaintext` receives output before the whole message is verified.
    /// Don't act on it until `send` returns `Ok`; on `Err`, discard it.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::Error), one of:
    /// - [`Validation`](crate::Error::Validation): the message's encrypted data key count exceeds the configured maximum, the commitment policy does not allow the message's algorithm suite, or the message is multi-frame and signed (decrypt it with [`Esdk::decrypt`] instead).
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keyring or CMM returns materials the ESDK cannot use, or materials that do not match the message's algorithm suite or signature settings.
    /// - [`EncryptionContextMismatch`](crate::Error::EncryptionContextMismatch): the reproduced encryption context conflicts with the message, or a required key is missing.
    /// - [`NoMatchingDataKey`](crate::Error::NoMatchingDataKey): none of the message's encrypted data keys belongs to the keyring or CMM.
    /// - [`Cryptographic`](crate::Error::Cryptographic): the header tag, a frame tag, the key commitment, or the signature does not verify.
    /// - [`AccessDenied`](crate::Error::AccessDenied): AWS KMS or `DynamoDB` denies a call from a keyring, CMM, or key store.
    /// - [`ResourceNotFound`](crate::Error::ResourceNotFound): a KMS key, `DynamoDB` table, or branch key does not exist.
    /// - [`Throttling`](crate::Error::Throttling): AWS KMS, `DynamoDB`, or the materials cache throttles the request.
    /// - [`Conflict`](crate::Error::Conflict): the keyring or CMM reports a conflict with a resource's current state.
    /// - [`Service`](crate::Error::Service): AWS KMS or `DynamoDB` fails the request for another reason.
    /// - [`Dispatch`](crate::Error::Dispatch): a request to AWS KMS or `DynamoDB` is not sent, or its response does not arrive.
    /// - [`Serialization`](crate::Error::Serialization): the bytes are not a well-formed encrypted message, or carry trailing data after the footer.
    /// - [`Io`](crate::Error::Io): the supplied ciphertext reader or plaintext writer fails.
    /// - [`Internal`](crate::Error::Internal): an internal invariant is violated.
    pub async fn send<R, W>(self, ciphertext: R, plaintext: W) -> Result<DecryptStreamOutput, Error>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
        W: tokio::io::AsyncWrite + Unpin + Send,
    {
        let input = self
            .inner
            .commitment_policy(self.config.commitment_policy)
            .set_max_encrypted_data_keys(self.config.max_encrypted_data_keys)
            .build()?;
        crate::decrypt::decrypt_stream(ciphertext, plaintext, &input).await
    }
}

/// Fluent builder for [`Esdk`].
#[derive(Debug, Clone, Copy, Default)]
pub struct EsdkBuilder {
    commitment_policy: Option<CommitmentPolicy>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
}

impl EsdkBuilder {
    /// Set the commitment policy.
    //= spec/client-apis/client.md#initialization
    //# - On client initialization,
    //# the caller MUST have the option to provide a [commitment policy](#commitment-policy).
    #[must_use]
    pub const fn commitment_policy(mut self, p: CommitmentPolicy) -> Self {
        self.commitment_policy = Some(p);
        self
    }

    /// Set or clear the commitment policy from an `Option`.
    #[must_use]
    pub const fn set_commitment_policy(
        mut self,
        commitment_policy: Option<CommitmentPolicy>,
    ) -> Self {
        self.commitment_policy = commitment_policy;
        self
    }

    /// Set the maximum number of encrypted data keys per message.
    //= spec/client-apis/client.md#initialization
    //# - On client initialization,
    //# the caller MUST have the option to provide a [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys).
    #[must_use]
    pub const fn max_encrypted_data_keys(mut self, n: NonZeroUsize) -> Self {
        self.max_encrypted_data_keys = Some(n);
        self
    }

    /// Set or clear the maximum number of encrypted data keys from an `Option`.
    #[must_use]
    pub const fn set_max_encrypted_data_keys(
        mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> Self {
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
    pub const fn get_max_encrypted_data_keys(&self) -> &Option<NonZeroUsize> {
        &self.max_encrypted_data_keys
    }

    /// Build the `Esdk`. Unset fields use their defaults
    /// (`RequireEncryptRequireDecrypt` commitment policy, no EDK cap).
    #[must_use]
    pub fn build(self) -> Esdk {
        Esdk {
            config: EsdkConfig {
                commitment_policy: self.commitment_policy.unwrap_or(DEFAULT_COMMITMENT_POLICY),
                max_encrypted_data_keys: self.max_encrypted_data_keys,
            },
        }
    }
}
