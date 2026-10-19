// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The [`Client`] and its [`Config`].
//!
//! `Client` holds a [`Config`]: a commitment policy and an optional cap on encrypted data keys.
//! Each operation's fluent builder takes both settings from the client and has no setters for them:
//!
//! ```no_run
//! # use aws_esdk::{types::CommitmentPolicy, keyring::SharedKeyring};
//! # async fn example(policy: CommitmentPolicy, plaintext: &[u8], keyring: SharedKeyring) -> Result<(), aws_esdk::Error> {
//! let esdk = aws_esdk::Client::builder().commitment_policy(policy).build()?;
//! let output = esdk.encrypt().plaintext(plaintext).keyring(keyring).send().await?;
//! # Ok(())
//! # }
//! ```

use crate::Error;
use crate::config::{self, Config};
use crate::operation::decrypt::builders::DecryptFluentBuilder;
use crate::operation::decrypt_stream::builders::DecryptStreamFluentBuilder;
use crate::operation::encrypt::builders::EncryptFluentBuilder;
use crate::operation::encrypt_stream::builders::EncryptStreamFluentBuilder;
use crate::shapes::CommitmentPolicy;
use std::num::NonZeroUsize;

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
/// # use aws_esdk::{types::CommitmentPolicy, types::EncryptionContext, keyring::SharedKeyring};
/// # async fn example(plaintext: &[u8], ec: EncryptionContext, keyring: SharedKeyring) -> Result<(), aws_esdk::Error> {
/// let esdk = aws_esdk::Client::builder()
///     .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
///     .build()?;
/// let output = esdk
///     .encrypt()
///     .plaintext(plaintext)
///     .set_encryption_context(Some(ec))
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
    pub fn builder() -> Builder {
        Builder::default()
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
    ///   - [`encryption_context(impl Into<String>, impl Into<String>)`](EncryptFluentBuilder::encryption_context) / [`set_encryption_context(Option<EncryptionContext>)`](EncryptFluentBuilder::set_encryption_context):<br>required: **false**<br>Key-value pairs bound to the message. They are authenticated, not encrypted, so never put secrets in them.<br>
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](EncryptFluentBuilder::algorithm_suite_id) / [`set_algorithm_suite_id(Option<AlgorithmSuiteId>)`](EncryptFluentBuilder::set_algorithm_suite_id):<br>required: **false**<br>The algorithm suite to encrypt with. Unset uses the default suite for the client's commitment policy.<br>
    ///   - [`frame_length(NonZeroU32)`](EncryptFluentBuilder::frame_length) / [`set_frame_length(Option<NonZeroU32>)`](EncryptFluentBuilder::set_frame_length):<br>required: **false**<br>Bytes of plaintext per frame. Default is 4096.<br>
    ///   - [`keyring(impl Keyring)`](EncryptFluentBuilder::keyring) / [`set_keyring(Option<SharedKeyring>)`](EncryptFluentBuilder::set_keyring):<br>required: **one of keyring or cmm**<br>The keyring that protects the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`cmm(impl Cmm)`](EncryptFluentBuilder::cmm) / [`set_cmm(Option<SharedCmm>)`](EncryptFluentBuilder::set_cmm):<br>required: **one of keyring or cmm**<br>The cryptographic materials manager (CMM) that supplies the message's data key. Set exactly one of a keyring or a CMM.<br>
    /// - On success, responds with [`EncryptOutput`](crate::operation::encrypt::EncryptOutput) with field(s):
    ///   - [`ciphertext(&[u8])`](crate::operation::encrypt::EncryptOutput::ciphertext): The encrypted message.
    ///   - [`encryption_context(&EncryptionContext)`](crate::operation::encrypt::EncryptOutput::encryption_context): The encryption context bound to the message, including any pairs the CMM added.
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](crate::operation::encrypt::EncryptOutput::algorithm_suite_id): The algorithm suite the message uses.
    /// - On failure, responds with [`Error`]; [`send`](EncryptFluentBuilder::send) lists each variant.
    //= spec/client-apis/client.md#encrypt
    //# The AWS Encryption SDK Client MUST provide an [encrypt](./encrypt.md#input) function
    //# that adheres to [encrypt](./encrypt.md).
    pub fn encrypt<'a>(&self) -> EncryptFluentBuilder<'a> {
        EncryptFluentBuilder::new(self.config.clone())
    }

    /// Constructs a fluent builder for the decrypt operation, which decrypts an encrypted message held in memory.
    ///
    /// The client's commitment policy and encrypted data key cap apply.
    /// Finish with [`send()`](DecryptFluentBuilder::send).
    ///
    /// - The fluent builder is configurable:
    ///   - [`ciphertext(&[u8])`](DecryptFluentBuilder::ciphertext) / [`set_ciphertext(Option<&[u8]>)`](DecryptFluentBuilder::set_ciphertext):<br>required: **true**<br>The encrypted message to decrypt.<br>
    ///   - [`encryption_context(impl Into<String>, impl Into<String>)`](DecryptFluentBuilder::encryption_context) / [`set_encryption_context(Option<EncryptionContext>)`](DecryptFluentBuilder::set_encryption_context):<br>required: **false**<br>Key-value pairs the message's encryption context must contain. Decrypt fails if a pair is missing from the message or has a different value.<br>
    ///   - [`keyring(impl Keyring)`](DecryptFluentBuilder::keyring) / [`set_keyring(Option<SharedKeyring>)`](DecryptFluentBuilder::set_keyring):<br>required: **one of keyring or cmm**<br>The keyring that protects the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`cmm(impl Cmm)`](DecryptFluentBuilder::cmm) / [`set_cmm(Option<SharedCmm>)`](DecryptFluentBuilder::set_cmm):<br>required: **one of keyring or cmm**<br>The cryptographic materials manager (CMM) that supplies the message's data key. Set exactly one of a keyring or a CMM.<br>
    /// - On success, responds with [`DecryptOutput`](crate::operation::decrypt::DecryptOutput) with field(s):
    ///   - [`plaintext(&[u8])`](crate::operation::decrypt::DecryptOutput::plaintext): The decrypted data.
    ///   - [`encryption_context(&EncryptionContext)`](crate::operation::decrypt::DecryptOutput::encryption_context): The message's encryption context.
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](crate::operation::decrypt::DecryptOutput::algorithm_suite_id): The algorithm suite the message uses.
    /// - On failure, responds with [`Error`]; [`send`](DecryptFluentBuilder::send) lists each variant.
    //= spec/client-apis/client.md#decrypt
    //# The AWS Encryption SDK Client MUST provide an [decrypt](./decrypt.md#input) function
    //# that adheres to [decrypt](./decrypt.md).
    pub fn decrypt<'a>(&self) -> DecryptFluentBuilder<'a> {
        DecryptFluentBuilder::new(self.config.clone())
    }

    /// Constructs a fluent builder for the streaming encrypt operation, which reads plaintext from an `AsyncRead` and writes the encrypted message to an `AsyncWrite`.
    ///
    /// The client's commitment policy and encrypted data key cap apply.
    /// Finish with [`send()`](EncryptStreamFluentBuilder::send).
    ///
    /// - The fluent builder is configurable:
    ///   - [`plaintext(impl AsyncRead)`](EncryptStreamFluentBuilder::plaintext) / [`set_plaintext(Option<Box<dyn AsyncRead>>)`](EncryptStreamFluentBuilder::set_plaintext):<br>required: **true**<br>The reader the data to encrypt is read from, until end of stream.<br>
    ///   - [`ciphertext(impl AsyncWrite)`](EncryptStreamFluentBuilder::ciphertext) / [`set_ciphertext(Option<Box<dyn AsyncWrite>>)`](EncryptStreamFluentBuilder::set_ciphertext):<br>required: **true**<br>The writer the encrypted message is written to.<br>
    ///   - [`encryption_context(impl Into<String>, impl Into<String>)`](EncryptStreamFluentBuilder::encryption_context) / [`set_encryption_context(Option<EncryptionContext>)`](EncryptStreamFluentBuilder::set_encryption_context):<br>required: **false**<br>Key-value pairs bound to the message. They are authenticated, not encrypted, so never put secrets in them.<br>
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](EncryptStreamFluentBuilder::algorithm_suite_id) / [`set_algorithm_suite_id(Option<AlgorithmSuiteId>)`](EncryptStreamFluentBuilder::set_algorithm_suite_id):<br>required: **false**<br>The algorithm suite to encrypt with. Unset uses the default suite for the client's commitment policy.<br>
    ///   - [`frame_length(NonZeroU32)`](EncryptStreamFluentBuilder::frame_length) / [`set_frame_length(Option<NonZeroU32>)`](EncryptStreamFluentBuilder::set_frame_length):<br>required: **false**<br>Bytes of plaintext per frame. Default is 4096.<br>
    ///   - [`keyring(impl Keyring)`](EncryptStreamFluentBuilder::keyring) / [`set_keyring(Option<SharedKeyring>)`](EncryptStreamFluentBuilder::set_keyring):<br>required: **one of keyring or cmm**<br>The keyring that protects the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`cmm(impl Cmm)`](EncryptStreamFluentBuilder::cmm) / [`set_cmm(Option<SharedCmm>)`](EncryptStreamFluentBuilder::set_cmm):<br>required: **one of keyring or cmm**<br>The cryptographic materials manager (CMM) that supplies the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`data_size(usize)`](EncryptStreamFluentBuilder::data_size) / [`set_data_size(Option<usize>)`](EncryptStreamFluentBuilder::set_data_size):<br>required: **false**<br>An upper bound on the plaintext length, in bytes. It is passed to the CMM, and encrypt fails if the stream is longer.<br>
    /// - On success, responds with [`EncryptStreamOutput`](crate::operation::encrypt_stream::EncryptStreamOutput) with field(s):
    ///   - [`encryption_context(&EncryptionContext)`](crate::operation::encrypt_stream::EncryptStreamOutput::encryption_context): The encryption context bound to the message, including any pairs the CMM added.
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](crate::operation::encrypt_stream::EncryptStreamOutput::algorithm_suite_id): The algorithm suite the message uses.
    /// - On failure, responds with [`Error`]; [`send`](EncryptStreamFluentBuilder::send) lists each variant.
    pub fn encrypt_stream<'a>(&self) -> EncryptStreamFluentBuilder<'a> {
        EncryptStreamFluentBuilder::new(self.config.clone())
    }

    /// Constructs a fluent builder for the streaming decrypt operation, which reads an encrypted message from an `AsyncRead` and writes the plaintext to an `AsyncWrite`.
    ///
    /// The client's commitment policy and encrypted data key cap apply.
    /// Finish with [`send()`](DecryptStreamFluentBuilder::send).
    ///
    /// - The fluent builder is configurable:
    ///   - [`ciphertext(impl AsyncRead)`](DecryptStreamFluentBuilder::ciphertext) / [`set_ciphertext(Option<Box<dyn AsyncRead>>)`](DecryptStreamFluentBuilder::set_ciphertext):<br>required: **true**<br>The reader the encrypted message is read from.<br>
    ///   - [`plaintext(impl AsyncWrite)`](DecryptStreamFluentBuilder::plaintext) / [`set_plaintext(Option<Box<dyn AsyncWrite>>)`](DecryptStreamFluentBuilder::set_plaintext):<br>required: **true**<br>The writer the decrypted data is written to. It receives plaintext before the whole message is verified.<br>
    ///   - [`encryption_context(impl Into<String>, impl Into<String>)`](DecryptStreamFluentBuilder::encryption_context) / [`set_encryption_context(Option<EncryptionContext>)`](DecryptStreamFluentBuilder::set_encryption_context):<br>required: **false**<br>Key-value pairs the message's encryption context must contain. Decrypt fails if a pair is missing from the message or has a different value.<br>
    ///   - [`keyring(impl Keyring)`](DecryptStreamFluentBuilder::keyring) / [`set_keyring(Option<SharedKeyring>)`](DecryptStreamFluentBuilder::set_keyring):<br>required: **one of keyring or cmm**<br>The keyring that protects the message's data key. Set exactly one of a keyring or a CMM.<br>
    ///   - [`cmm(impl Cmm)`](DecryptStreamFluentBuilder::cmm) / [`set_cmm(Option<SharedCmm>)`](DecryptStreamFluentBuilder::set_cmm):<br>required: **one of keyring or cmm**<br>The cryptographic materials manager (CMM) that supplies the message's data key. Set exactly one of a keyring or a CMM.<br>
    /// - On success, responds with [`DecryptStreamOutput`](crate::operation::decrypt_stream::DecryptStreamOutput) with field(s):
    ///   - [`encryption_context(&EncryptionContext)`](crate::operation::decrypt_stream::DecryptStreamOutput::encryption_context): The message's encryption context.
    ///   - [`algorithm_suite_id(AlgorithmSuiteId)`](crate::operation::decrypt_stream::DecryptStreamOutput::algorithm_suite_id): The algorithm suite the message uses.
    /// - On failure, responds with [`Error`]; [`send`](DecryptStreamFluentBuilder::send) lists each variant.
    pub fn decrypt_stream<'a>(&self) -> DecryptStreamFluentBuilder<'a> {
        DecryptStreamFluentBuilder::new(self.config.clone())
    }
}

/// Fluent builder for [`Client`].
#[derive(Debug, Clone, Default)]
pub struct Builder {
    config: config::Builder,
}

impl Builder {
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
