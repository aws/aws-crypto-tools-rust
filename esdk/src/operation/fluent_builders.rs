// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The fluent builders [`Client`](crate::Client)'s operation methods return.

use crate::Error;
use crate::config::Config;
use crate::shapes::{
    AlgorithmSuiteId, DecryptInput, DecryptInputBuilder, DecryptOutput, DecryptStreamInput,
    DecryptStreamInputBuilder, DecryptStreamOutput, EncryptInput, EncryptInputBuilder,
    EncryptOutput, EncryptStreamInput, EncryptStreamInputBuilder, EncryptStreamOutput,
    EncryptionContext, SignedStreaming,
};
use aws_crypto_mpl::cmm::SharedCmm;
use aws_crypto_mpl::keyring::SharedKeyring;
use aws_crypto_mpl::shared::IntoShared;
use std::fmt;
use std::num::NonZeroU32;
use tokio::io::{AsyncRead, AsyncWrite};

/// A stream reader held by a streaming fluent builder.
type Reader<'a> = Box<dyn AsyncRead + Unpin + Send + 'a>;
/// A stream writer held by a streaming fluent builder.
type Writer<'a> = Box<dyn AsyncWrite + Unpin + Send + 'a>;

/// Add a member's setter, `set_` setter and getter, each documented with `doc`,
/// all forwarding to the wrapped input builder.
macro_rules! member {
    (
        $(#[doc = $doc:expr])+
        map $name:ident, $set:ident, $get:ident -> $ty:ty
    ) => {
        $(#[doc = $doc])+
        ///
        /// Adds one pair. To replace the whole map, use the `set_` setter.
        pub fn $name(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
            let mut map = self.inner.$get().clone().unwrap_or_default();
            map.insert(k, v);
            self.inner = self.inner.$set(Some(map));
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
            map encryption_context,
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
            map encryption_context,
            set_encryption_context,
            get_encryption_context -> EncryptionContext
        );
    };
}

/// Fluent builder for the encrypt operation, started by [`Client::encrypt`](crate::Client::encrypt).
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
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config,
            inner: EncryptInput::builder(),
        }
    }

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

/// Fluent builder for the decrypt operation, started by [`Client::decrypt`](crate::Client::decrypt).
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
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config,
            inner: DecryptInput::builder(),
        }
    }

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

/// Fluent builder for the streaming encrypt operation, started by [`Client::encrypt_stream`](crate::Client::encrypt_stream).
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
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config,
            inner: EncryptStreamInput::builder(),
            plaintext: None,
            ciphertext: None,
        }
    }

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

/// Fluent builder for the streaming decrypt operation, started by [`Client::decrypt_stream`](crate::Client::decrypt_stream).
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
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config,
            inner: DecryptStreamInput::builder(),
            ciphertext: None,
            plaintext: None,
        }
    }

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
    member!(
        /// How a message with a signing algorithm suite is streamed.
        /// Default is [`SignedStreaming::RejectMultiFrame`].
        signed_streaming(SignedStreaming), set_signed_streaming, get_signed_streaming -> SignedStreaming
    );

    /// Decrypt the `ciphertext` reader into the `plaintext` writer.
    ///
    /// The `plaintext` writer receives output before the whole message is verified.
    /// Don't act on it until `send` returns `Ok`; on `Err`, discard it.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::Error), one of:
    /// - [`Validation`](crate::Error::Validation): the ciphertext reader or plaintext writer is unset, the message's encrypted data key count exceeds the configured maximum, the commitment policy does not allow the message's algorithm suite, the message is signed and `signed_streaming` is [`SignedStreaming::RejectSigned`], or the message is multi-frame and signed and `signed_streaming` is [`SignedStreaming::RejectMultiFrame`] (decrypt it with [`Client::decrypt`](crate::Client::decrypt), or set [`SignedStreaming::ReleaseRegularFrames`]).
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
