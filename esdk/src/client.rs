// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The [`Client`] and its [`Config`].
//!
//! `Client` holds a [`Config`]: a commitment policy and an optional cap on encrypted data keys.
//! Each operation's fluent builder takes both settings from the client and has no setters for them:
//!
//! ```no_run
//! # use aws_esdk::{CommitmentPolicy, SharedKeyring};
//! # async fn example(policy: CommitmentPolicy, plaintext: &[u8], keyring: SharedKeyring) -> Result<(), aws_esdk::Error> {
//! let esdk = aws_esdk::Client::builder().commitment_policy(policy).build()?;
//! let output = esdk.encrypt().plaintext(plaintext).keyring(keyring).send().await?;
//! # Ok(())
//! # }
//! ```

use crate::Error;
use crate::types::{
    AlgorithmSuiteId, DecryptInput, DecryptInputBuilder, DecryptOutput, DecryptStreamInput,
    DecryptStreamInputBuilder, DecryptStreamOutput, EncryptInput, EncryptInputBuilder,
    EncryptOutput, EncryptStreamInput, EncryptStreamInputBuilder, EncryptStreamOutput,
    EncryptionContext,
};
use crate::types::{CommitmentPolicy, DEFAULT_COMMITMENT_POLICY};
use aws_crypto_mpl::{IntoShared, SharedCmm, SharedKeyring};
use std::fmt;
use std::num::{NonZeroU32, NonZeroUsize};
use tokio::io::{AsyncRead, AsyncWrite};

/// A stream reader held by a streaming fluent builder.
type Reader<'a> = Box<dyn AsyncRead + Unpin + Send + 'a>;
/// A stream writer held by a streaming fluent builder.
type Writer<'a> = Box<dyn AsyncWrite + Unpin + Send + 'a>;

/// Configuration for the [`Client`].
///
/// Holds the commitment policy and the optional cap on the number of encrypted
/// data keys per message. Build with [`Config::builder`] and pass to
/// [`Client::from_conf`], or set the same options on [`Client::builder`].
//= spec/client-apis/client.md#initialization
//= reason=field defaults to None via derive(Default); None means no cap
//# If no [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys) is provided
//# the default MUST result in no limit on the number of encrypted data keys (aside from the limit imposed by the [message format](../format/message-header.md)).
//
//= spec/client-apis/client.md#initialization
//= reason=Config::default() sets commitment_policy to DEFAULT_COMMITMENT_POLICY = RequireEncryptRequireDecrypt
//# If no [commitment policy](#commitment-policy) is provided the default MUST be [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../framework/algorithm-suites.md#require_encrypt_require_decrypt).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// Commitment policy applied to every operation. Default is
    /// `CommitmentPolicy::RequireEncryptRequireDecrypt`.
    //= spec/client-apis/client.md#commitment-policy
    //= reason=CommitmentPolicy is a re-export of the MPL's aws_crypto_mpl::structures::EsdkCommitmentPolicy
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
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// A builder preloaded with this config's values.
    #[must_use]
    pub const fn to_builder(&self) -> ConfigBuilder {
        ConfigBuilder {
            commitment_policy: Some(self.commitment_policy),
            max_encrypted_data_keys: self.max_encrypted_data_keys,
        }
    }

    /// The commitment policy applied to every operation.
    #[must_use]
    pub const fn commitment_policy(&self) -> CommitmentPolicy {
        self.commitment_policy
    }

    /// The maximum number of encrypted data keys per message, if capped.
    #[must_use]
    pub const fn max_encrypted_data_keys(&self) -> Option<NonZeroUsize> {
        self.max_encrypted_data_keys
    }
}

/// Builder for [`Config`].
#[derive(Debug, Clone, Default)]
#[allow(missing_copy_implementations)] // not Copy, like Config, so it can gain settings that aren't Copy
pub struct ConfigBuilder {
    commitment_policy: Option<CommitmentPolicy>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
}

impl ConfigBuilder {
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
    #[must_use]
    pub const fn max_encrypted_data_keys(mut self, max_encrypted_data_keys: NonZeroUsize) -> Self {
        self.max_encrypted_data_keys = Some(max_encrypted_data_keys);
        self
    }

    /// Set or clear the maximum number of encrypted data keys from an `Option`.
    pub const fn set_max_encrypted_data_keys(
        &mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
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
    pub const fn get_max_encrypted_data_keys(&self) -> &Option<NonZeroUsize> {
        &self.max_encrypted_data_keys
    }

    /// Build the `Config`. Unset fields use their defaults
    /// (`RequireEncryptRequireDecrypt` commitment policy, no EDK cap).
    ///
    /// # Errors
    ///
    /// Currently never fails. Returns a `Result` so that a future validated
    /// setting is not a breaking change.
    pub fn build(self) -> Result<Config, Error> {
        Ok(Config {
            commitment_policy: self.commitment_policy.unwrap_or(DEFAULT_COMMITMENT_POLICY),
            max_encrypted_data_keys: self.max_encrypted_data_keys,
        })
    }
}

/// The AWS Encryption SDK client.
/// Applies one [`Config`] to every operation.
/// Build with [`Client::builder`], or from a [`Config`] with [`Client::from_conf`].
///
/// Each operation method returns a fluent builder that takes `commitment_policy`
/// and `max_encrypted_data_keys` from the client.
/// Set the rest on the builder and finish with `send`.
///
/// # Example
///
/// ```no_run
/// # use aws_esdk::{CommitmentPolicy, EncryptionContext, SharedKeyring};
/// # async fn example(plaintext: &[u8], ec: EncryptionContext, keyring: SharedKeyring) -> Result<(), aws_esdk::Error> {
/// let esdk = aws_esdk::Client::builder()
///     .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
///     .build()?;
/// let output = esdk
///     .encrypt()
///     .plaintext(plaintext)
///     .encryption_context(ec)
///     .keyring(keyring)
///     .send()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Client {
    /// Client configuration applied to every call.
    ///
    /// Private to enforce construction via [`Client::builder`] / [`Client::from_conf`];
    /// read via [`Client::config`].
    //= spec/client-apis/client.md#initialization
    //= type=implication
    //= reason=pub(crate) prevents external mutation and Client has no setters, so any "change" must construct a new value
    //# Once a [commitment policy](#commitment-policy) has been set it SHOULD be immutable.
    pub(crate) config: Config,
}

impl Client {
    /// Construct a `Client` from a [`Config`].
    #[must_use]
    pub const fn from_conf(config: Config) -> Self {
        Self { config }
    }

    /// Start a fluent builder for `Client`.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Borrow this client's configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Constructs a fluent builder for the encrypt operation, which encrypts a plaintext held in memory into an encrypted message.
    ///
    /// The client's commitment policy and encrypted data key cap apply.
    /// Finish with [`send()`](EncryptFluentBuilder::send).
    ///
    /// - The fluent builder is configurable:
    ///   - [`plaintext(&[u8])`](EncryptFluentBuilder::plaintext) / [`set_plaintext(Option<&[u8]>)`](EncryptFluentBuilder::set_plaintext):<br>required: **true**<br>The data to encrypt.<br>
    ///   - [`encryption_context(impl Into<EncryptionContext>)`](EncryptFluentBuilder::encryption_context) / [`set_encryption_context(Option<EncryptionContext>)`](EncryptFluentBuilder::set_encryption_context):<br>required: **false**<br>Key-value pairs bound to the message. They are authenticated, not encrypted, so never put secrets in them.<br>
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](EncryptFluentBuilder::algorithm_suite_id) / [`set_algorithm_suite_id(Option<AlgorithmSuiteId>)`](EncryptFluentBuilder::set_algorithm_suite_id):<br>required: **false**<br>The algorithm suite to encrypt with. Unset uses the default suite for the client's commitment policy.<br>
    ///   - [`frame_length(NonZeroU32)`](EncryptFluentBuilder::frame_length) / [`set_frame_length(Option<NonZeroU32>)`](EncryptFluentBuilder::set_frame_length):<br>required: **false**<br>Bytes of plaintext per frame. Default is 4096.<br>
    ///   - [`keyring(impl Keyring)`](EncryptFluentBuilder::keyring) / [`set_keyring(Option<SharedKeyring>)`](EncryptFluentBuilder::set_keyring):<br>required: **one of keyring or cmm**<br>The keyring that protects the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`cmm(impl Cmm)`](EncryptFluentBuilder::cmm) / [`set_cmm(Option<SharedCmm>)`](EncryptFluentBuilder::set_cmm):<br>required: **one of keyring or cmm**<br>The cryptographic materials manager (CMM) that supplies the message's data key. Set exactly one of a keyring or a CMM.<br>
    /// - On success, responds with [`EncryptOutput`] with field(s):
    ///   - [`ciphertext(&[u8])`](EncryptOutput::ciphertext): The encrypted message.
    ///   - [`encryption_context(&EncryptionContext)`](EncryptOutput::encryption_context): The encryption context bound to the message, including any pairs the CMM added.
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](EncryptOutput::algorithm_suite_id): The algorithm suite the message uses.
    /// - On failure, responds with [`Error`](crate::Error); [`send`](EncryptFluentBuilder::send) lists each variant.
    //= spec/client-apis/client.md#encrypt
    //# The AWS Encryption SDK Client MUST provide an [encrypt](./encrypt.md#input) function
    //# that adheres to [encrypt](./encrypt.md).
    pub fn encrypt<'a>(&self) -> EncryptFluentBuilder<'a> {
        EncryptFluentBuilder {
            config: self.config.clone(),
            inner: EncryptInput::builder(),
        }
    }

    /// Constructs a fluent builder for the decrypt operation, which decrypts an encrypted message held in memory.
    ///
    /// The client's commitment policy and encrypted data key cap apply.
    /// Finish with [`send()`](DecryptFluentBuilder::send).
    ///
    /// - The fluent builder is configurable:
    ///   - [`ciphertext(&[u8])`](DecryptFluentBuilder::ciphertext) / [`set_ciphertext(Option<&[u8]>)`](DecryptFluentBuilder::set_ciphertext):<br>required: **true**<br>The encrypted message to decrypt.<br>
    ///   - [`encryption_context(impl Into<EncryptionContext>)`](DecryptFluentBuilder::encryption_context) / [`set_encryption_context(Option<EncryptionContext>)`](DecryptFluentBuilder::set_encryption_context):<br>required: **false**<br>Key-value pairs the message's encryption context must contain. Decrypt fails if a pair is missing from the message or has a different value.<br>
    ///   - [`keyring(impl Keyring)`](DecryptFluentBuilder::keyring) / [`set_keyring(Option<SharedKeyring>)`](DecryptFluentBuilder::set_keyring):<br>required: **one of keyring or cmm**<br>The keyring that protects the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`cmm(impl Cmm)`](DecryptFluentBuilder::cmm) / [`set_cmm(Option<SharedCmm>)`](DecryptFluentBuilder::set_cmm):<br>required: **one of keyring or cmm**<br>The cryptographic materials manager (CMM) that supplies the message's data key. Set exactly one of a keyring or a CMM.<br>
    /// - On success, responds with [`DecryptOutput`] with field(s):
    ///   - [`plaintext(&[u8])`](DecryptOutput::plaintext): The decrypted data.
    ///   - [`encryption_context(&EncryptionContext)`](DecryptOutput::encryption_context): The message's encryption context.
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](DecryptOutput::algorithm_suite_id): The algorithm suite the message uses.
    /// - On failure, responds with [`Error`](crate::Error); [`send`](DecryptFluentBuilder::send) lists each variant.
    //= spec/client-apis/client.md#decrypt
    //# The AWS Encryption SDK Client MUST provide an [decrypt](./decrypt.md#input) function
    //# that adheres to [decrypt](./decrypt.md).
    pub fn decrypt<'a>(&self) -> DecryptFluentBuilder<'a> {
        DecryptFluentBuilder {
            config: self.config.clone(),
            inner: DecryptInput::builder(),
        }
    }

    /// Constructs a fluent builder for the streaming encrypt operation, which reads plaintext from an `AsyncRead` and writes the encrypted message to an `AsyncWrite`.
    ///
    /// The client's commitment policy and encrypted data key cap apply.
    /// Finish with [`send()`](EncryptStreamFluentBuilder::send).
    ///
    /// - The fluent builder is configurable:
    ///   - [`plaintext(impl AsyncRead)`](EncryptStreamFluentBuilder::plaintext) / [`set_plaintext(Option<Box<dyn AsyncRead>>)`](EncryptStreamFluentBuilder::set_plaintext):<br>required: **true**<br>The reader the data to encrypt is read from, until end of stream.<br>
    ///   - [`ciphertext(impl AsyncWrite)`](EncryptStreamFluentBuilder::ciphertext) / [`set_ciphertext(Option<Box<dyn AsyncWrite>>)`](EncryptStreamFluentBuilder::set_ciphertext):<br>required: **true**<br>The writer the encrypted message is written to.<br>
    ///   - [`encryption_context(impl Into<EncryptionContext>)`](EncryptStreamFluentBuilder::encryption_context) / [`set_encryption_context(Option<EncryptionContext>)`](EncryptStreamFluentBuilder::set_encryption_context):<br>required: **false**<br>Key-value pairs bound to the message. They are authenticated, not encrypted, so never put secrets in them.<br>
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](EncryptStreamFluentBuilder::algorithm_suite_id) / [`set_algorithm_suite_id(Option<AlgorithmSuiteId>)`](EncryptStreamFluentBuilder::set_algorithm_suite_id):<br>required: **false**<br>The algorithm suite to encrypt with. Unset uses the default suite for the client's commitment policy.<br>
    ///   - [`frame_length(NonZeroU32)`](EncryptStreamFluentBuilder::frame_length) / [`set_frame_length(Option<NonZeroU32>)`](EncryptStreamFluentBuilder::set_frame_length):<br>required: **false**<br>Bytes of plaintext per frame. Default is 4096.<br>
    ///   - [`keyring(impl Keyring)`](EncryptStreamFluentBuilder::keyring) / [`set_keyring(Option<SharedKeyring>)`](EncryptStreamFluentBuilder::set_keyring):<br>required: **one of keyring or cmm**<br>The keyring that protects the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`cmm(impl Cmm)`](EncryptStreamFluentBuilder::cmm) / [`set_cmm(Option<SharedCmm>)`](EncryptStreamFluentBuilder::set_cmm):<br>required: **one of keyring or cmm**<br>The cryptographic materials manager (CMM) that supplies the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`data_size(usize)`](EncryptStreamFluentBuilder::data_size) / [`set_data_size(Option<usize>)`](EncryptStreamFluentBuilder::set_data_size):<br>required: **false**<br>An upper bound on the plaintext length, in bytes. It is passed to the CMM, and encrypt fails if the stream is longer.<br>
    /// - On success, responds with [`EncryptStreamOutput`] with field(s):
    ///   - [`encryption_context(&EncryptionContext)`](EncryptStreamOutput::encryption_context): The encryption context bound to the message, including any pairs the CMM added.
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](EncryptStreamOutput::algorithm_suite_id): The algorithm suite the message uses.
    /// - On failure, responds with [`Error`](crate::Error); [`send`](EncryptStreamFluentBuilder::send) lists each variant.
    pub fn encrypt_stream<'a>(&self) -> EncryptStreamFluentBuilder<'a> {
        EncryptStreamFluentBuilder {
            config: self.config.clone(),
            inner: EncryptStreamInput::builder(),
            plaintext: None,
            ciphertext: None,
        }
    }

    /// Constructs a fluent builder for the streaming decrypt operation, which reads an encrypted message from an `AsyncRead` and writes the plaintext to an `AsyncWrite`.
    ///
    /// The client's commitment policy and encrypted data key cap apply.
    /// Finish with [`send()`](DecryptStreamFluentBuilder::send).
    ///
    /// - The fluent builder is configurable:
    ///   - [`ciphertext(impl AsyncRead)`](DecryptStreamFluentBuilder::ciphertext) / [`set_ciphertext(Option<Box<dyn AsyncRead>>)`](DecryptStreamFluentBuilder::set_ciphertext):<br>required: **true**<br>The reader the encrypted message is read from.<br>
    ///   - [`plaintext(impl AsyncWrite)`](DecryptStreamFluentBuilder::plaintext) / [`set_plaintext(Option<Box<dyn AsyncWrite>>)`](DecryptStreamFluentBuilder::set_plaintext):<br>required: **true**<br>The writer the decrypted data is written to. It receives plaintext before the whole message is verified.<br>
    ///   - [`encryption_context(impl Into<EncryptionContext>)`](DecryptStreamFluentBuilder::encryption_context) / [`set_encryption_context(Option<EncryptionContext>)`](DecryptStreamFluentBuilder::set_encryption_context):<br>required: **false**<br>Key-value pairs the message's encryption context must contain. Decrypt fails if a pair is missing from the message or has a different value.<br>
    ///   - [`keyring(impl Keyring)`](DecryptStreamFluentBuilder::keyring) / [`set_keyring(Option<SharedKeyring>)`](DecryptStreamFluentBuilder::set_keyring):<br>required: **one of keyring or cmm**<br>The keyring that protects the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`cmm(impl Cmm)`](DecryptStreamFluentBuilder::cmm) / [`set_cmm(Option<SharedCmm>)`](DecryptStreamFluentBuilder::set_cmm):<br>required: **one of keyring or cmm**<br>The cryptographic materials manager (CMM) that supplies the message's data key. Set exactly one of a keyring or a CMM.<br>
    /// - On success, responds with [`DecryptStreamOutput`] with field(s):
    ///   - [`encryption_context(&EncryptionContext)`](DecryptStreamOutput::encryption_context): The message's encryption context.
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](DecryptStreamOutput::algorithm_suite_id): The algorithm suite the message uses.
    /// - On failure, responds with [`Error`](crate::Error); [`send`](DecryptStreamFluentBuilder::send) lists each variant.
    pub fn decrypt_stream<'a>(&self) -> DecryptStreamFluentBuilder<'a> {
        DecryptStreamFluentBuilder {
            config: self.config.clone(),
            inner: DecryptStreamInput::builder(),
            ciphertext: None,
            plaintext: None,
        }
    }
}

/// Add a member's setter, `set_` setter and getter, each documented with `doc`,
/// all forwarding to the wrapped input builder.
macro_rules! member {
    (
        $(#[doc = $doc:expr])+
        $name:ident($arg:ty), $set:ident, $get:ident -> $ty:ty
    ) => {
        $(#[doc = $doc])+
        pub fn $name(mut self, input: $arg) -> Self {
            self.inner = self.inner.$name(input);
            self
        }

        $(#[doc = $doc])+
        pub fn $set(mut self, input: Option<$ty>) -> Self {
            self.inner = self.inner.$set(input);
            self
        }

        $(#[doc = $doc])+
        #[must_use]
        #[allow(clippy::ref_option, clippy::ref_option_ref)] // AWS SDK for Rust getter shape
        pub const fn $get(&self) -> &Option<$ty> {
            self.inner.$get()
        }
    };
}

/// Add a stream member's setter, `set_` setter and getter, each documented with `doc`,
/// storing the boxed reader or writer on the fluent builder.
macro_rules! stream_member {
    (
        $(#[doc = $doc:expr])+
        $name:ident(impl $bound:ident), $set:ident, $get:ident -> $ty:ident
    ) => {
        $(#[doc = $doc])+
        pub fn $name(mut self, input: impl $bound + Unpin + Send + 'a) -> Self {
            self.$name = Some(Box::new(input));
            self
        }

        $(#[doc = $doc])+
        pub fn $set(mut self, input: Option<$ty<'a>>) -> Self {
            self.$name = input;
            self
        }

        $(#[doc = $doc])+
        #[must_use]
        #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
        pub const fn $get(&self) -> &Option<$ty<'a>> {
            &self.$name
        }
    };
}

/// The keyring and CMM members every operation's fluent builder has.
macro_rules! material_source_members {
    () => {
        member!(
            /// The keyring that protects the message's data key.
            /// Set exactly one of a keyring or a CMM.
            keyring(impl IntoShared<SharedKeyring>), set_keyring, get_keyring -> SharedKeyring
        );
        member!(
            /// The cryptographic materials manager (CMM) that supplies the message's data key.
            /// Set exactly one of a keyring or a CMM.
            cmm(impl IntoShared<SharedCmm>), set_cmm, get_cmm -> SharedCmm
        );
    };
}

/// The members the two encrypt builders share.
macro_rules! encrypt_members {
    () => {
        member!(
            /// Key-value pairs bound to the message.
            /// They are authenticated, not encrypted, so never put secrets in them.
            /// Default is empty.
            encryption_context(impl Into<EncryptionContext>),
            set_encryption_context,
            get_encryption_context -> EncryptionContext
        );
        member!(
            /// The algorithm suite to encrypt with.
            /// Unset uses the default suite for the client's commitment policy.
            algorithm_suite_id(AlgorithmSuiteId),
            set_algorithm_suite_id,
            get_algorithm_suite_id -> AlgorithmSuiteId
        );
        member!(
            /// Bytes of plaintext per frame. Default is 4096.
            frame_length(NonZeroU32), set_frame_length, get_frame_length -> NonZeroU32
        );
    };
}

/// The members the two decrypt builders share.
macro_rules! decrypt_members {
    () => {
        member!(
            /// Key-value pairs the message's encryption context must contain.
            /// Decrypt fails if a pair is missing from the message or has a different value.
            /// Default is empty.
            encryption_context(impl Into<EncryptionContext>),
            set_encryption_context,
            get_encryption_context -> EncryptionContext
        );
    };
}

/// Fluent builder for the encrypt operation, started by [`Client::encrypt`].
///
/// Encrypts a plaintext held in memory into an encrypted message.
/// The keyring or CMM supplies the data key and the encrypted data keys stored in the message header.
#[derive(Debug, Clone)]
#[must_use = "a fluent builder does nothing until `send` is awaited"]
pub struct EncryptFluentBuilder<'a> {
    config: Config,
    inner: EncryptInputBuilder<'a>,
}

impl<'a> EncryptFluentBuilder<'a> {
    member!(
        /// The data to encrypt.
        plaintext(&'a [u8]), set_plaintext, get_plaintext -> &'a [u8]
    );
    encrypt_members!();
    material_source_members!();

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

/// Fluent builder for the decrypt operation, started by [`Client::decrypt`].
///
/// Decrypts an encrypted message held in memory.
/// The keyring or CMM recovers the data key from one of the message's encrypted data keys.
/// No plaintext is returned unless the whole message, including any signature, verifies.
#[derive(Debug, Clone)]
#[must_use = "a fluent builder does nothing until `send` is awaited"]
pub struct DecryptFluentBuilder<'a> {
    config: Config,
    inner: DecryptInputBuilder<'a>,
}

impl<'a> DecryptFluentBuilder<'a> {
    member!(
        /// The encrypted message to decrypt.
        ciphertext(&'a [u8]), set_ciphertext, get_ciphertext -> &'a [u8]
    );
    decrypt_members!();
    material_source_members!();

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

/// Fluent builder for the streaming encrypt operation, started by [`Client::encrypt_stream`].
///
/// Reads plaintext from an `AsyncRead` and writes the encrypted message to an `AsyncWrite`, one frame at a time.
#[must_use = "a fluent builder does nothing until `send` is awaited"]
pub struct EncryptStreamFluentBuilder<'a> {
    config: Config,
    inner: EncryptStreamInputBuilder,
    plaintext: Option<Reader<'a>>,
    ciphertext: Option<Writer<'a>>,
}

impl fmt::Debug for EncryptStreamFluentBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptStreamFluentBuilder")
            .field("config", &self.config)
            .field("inner", &self.inner)
            .field("plaintext", &self.plaintext.as_ref().map(|_| "AsyncRead"))
            .field(
                "ciphertext",
                &self.ciphertext.as_ref().map(|_| "AsyncWrite"),
            )
            .finish()
    }
}

impl<'a> EncryptStreamFluentBuilder<'a> {
    stream_member!(
        /// The reader the data to encrypt is read from, until end of stream.
        plaintext(impl AsyncRead), set_plaintext, get_plaintext -> Reader
    );
    stream_member!(
        /// The writer the encrypted message is written to.
        ciphertext(impl AsyncWrite), set_ciphertext, get_ciphertext -> Writer
    );
    encrypt_members!();
    material_source_members!();
    member!(
        /// An upper bound on the plaintext length, in bytes.
        /// It is passed to the CMM, and encrypt fails if the stream is longer.
        data_size(usize), set_data_size, get_data_size -> usize
    );

    /// Encrypt the `plaintext` reader into the `ciphertext` writer.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::Error), one of:
    /// - [`Validation`](crate::Error::Validation): the plaintext reader or ciphertext writer is unset, an encryption context key uses the reserved `aws-crypto-` prefix, the commitment policy does not allow the requested algorithm suite, the encrypted data key count exceeds the configured maximum, or the plaintext exceeds the size limit.
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
    pub async fn send(self) -> Result<EncryptStreamOutput, Error> {
        let plaintext = crate::builder::required(self.plaintext, "plaintext")?;
        let ciphertext = crate::builder::required(self.ciphertext, "ciphertext")?;
        let input = self
            .inner
            .commitment_policy(self.config.commitment_policy)
            .set_max_encrypted_data_keys(self.config.max_encrypted_data_keys)
            .build()?;
        crate::encrypt::encrypt_stream(plaintext, ciphertext, &input).await
    }
}

/// Fluent builder for the streaming decrypt operation, started by [`Client::decrypt_stream`].
///
/// Reads an encrypted message from an `AsyncRead` and writes plaintext to an `AsyncWrite`, one frame at a time.
/// Plaintext is written before the whole message is verified: don't act on it until `send` returns `Ok`.
#[must_use = "a fluent builder does nothing until `send` is awaited"]
pub struct DecryptStreamFluentBuilder<'a> {
    config: Config,
    inner: DecryptStreamInputBuilder,
    ciphertext: Option<Reader<'a>>,
    plaintext: Option<Writer<'a>>,
}

impl fmt::Debug for DecryptStreamFluentBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptStreamFluentBuilder")
            .field("config", &self.config)
            .field("inner", &self.inner)
            .field("ciphertext", &self.ciphertext.as_ref().map(|_| "AsyncRead"))
            .field("plaintext", &self.plaintext.as_ref().map(|_| "AsyncWrite"))
            .finish()
    }
}

impl<'a> DecryptStreamFluentBuilder<'a> {
    stream_member!(
        /// The reader the encrypted message is read from.
        ciphertext(impl AsyncRead), set_ciphertext, get_ciphertext -> Reader
    );
    stream_member!(
        /// The writer the decrypted data is written to.
        /// It receives plaintext before the whole message is verified:
        /// don't act on it until `send` returns `Ok`.
        plaintext(impl AsyncWrite), set_plaintext, get_plaintext -> Writer
    );
    decrypt_members!();
    material_source_members!();

    /// Decrypt the `ciphertext` reader into the `plaintext` writer.
    ///
    /// The `plaintext` writer receives output before the whole message is verified.
    /// Don't act on it until `send` returns `Ok`; on `Err`, discard it.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::Error), one of:
    /// - [`Validation`](crate::Error::Validation): the ciphertext reader or plaintext writer is unset, the message's encrypted data key count exceeds the configured maximum, the commitment policy does not allow the message's algorithm suite, or the message is multi-frame and signed (decrypt it with [`Client::decrypt`] instead).
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
    pub async fn send(self) -> Result<DecryptStreamOutput, Error> {
        let ciphertext = crate::builder::required(self.ciphertext, "ciphertext")?;
        let plaintext = crate::builder::required(self.plaintext, "plaintext")?;
        let input = self
            .inner
            .commitment_policy(self.config.commitment_policy)
            .set_max_encrypted_data_keys(self.config.max_encrypted_data_keys)
            .build()?;
        crate::decrypt::decrypt_stream(ciphertext, plaintext, &input).await
    }
}

/// Fluent builder for [`Client`].
#[derive(Debug, Clone, Default)]
pub struct ClientBuilder {
    config: ConfigBuilder,
}

impl ClientBuilder {
    /// Set the commitment policy.
    //= spec/client-apis/client.md#initialization
    //# - On client initialization,
    //# the caller MUST have the option to provide a [commitment policy](#commitment-policy).
    #[must_use]
    pub const fn commitment_policy(mut self, p: CommitmentPolicy) -> Self {
        self.config = self.config.commitment_policy(p);
        self
    }

    /// Set or clear the commitment policy from an `Option`.
    pub const fn set_commitment_policy(
        &mut self,
        commitment_policy: Option<CommitmentPolicy>,
    ) -> &mut Self {
        self.config.set_commitment_policy(commitment_policy);
        self
    }

    /// Set the maximum number of encrypted data keys per message.
    //= spec/client-apis/client.md#initialization
    //# - On client initialization,
    //# the caller MUST have the option to provide a [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys).
    #[must_use]
    pub const fn max_encrypted_data_keys(mut self, n: NonZeroUsize) -> Self {
        self.config = self.config.max_encrypted_data_keys(n);
        self
    }

    /// Set or clear the maximum number of encrypted data keys from an `Option`.
    pub const fn set_max_encrypted_data_keys(
        &mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> &mut Self {
        self.config
            .set_max_encrypted_data_keys(max_encrypted_data_keys);
        self
    }

    /// The commitment policy set so far.
    #[must_use]
    #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
    pub const fn get_commitment_policy(&self) -> &Option<CommitmentPolicy> {
        self.config.get_commitment_policy()
    }

    /// The maximum number of encrypted data keys set so far.
    #[must_use]
    #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
    pub const fn get_max_encrypted_data_keys(&self) -> &Option<NonZeroUsize> {
        self.config.get_max_encrypted_data_keys()
    }

    /// Build the `Client`. Unset fields use their defaults
    /// (`RequireEncryptRequireDecrypt` commitment policy, no EDK cap).
    ///
    /// # Errors
    ///
    /// Currently never fails. Returns a `Result` so that a future validated
    /// setting is not a breaking change.
    pub fn build(self) -> Result<Client, Error> {
        Ok(Client::from_conf(self.config.build()?))
    }
}
