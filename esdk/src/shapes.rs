// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Public API types for encrypt and decrypt operations.

use crate::Error;
use crate::builder::required;
use crate::error::val_err;
use std::num::{NonZeroU32, NonZeroUsize};

/// Internal union of the two ways a caller can supply materials, resolved from
/// the `keyring` / `cmm` input fields and consumed by `create_cmm_from_input`.
#[derive(Clone)]
pub(crate) enum MaterialSource {
    Cmm(SharedCmm),
    Keyring(SharedKeyring),
}

impl std::fmt::Debug for MaterialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cmm(_) => f.write_str("MaterialSource::Cmm(..)"),
            Self::Keyring(_) => f.write_str("MaterialSource::Keyring(..)"),
        }
    }
}

/// Resolve the caller-supplied `keyring` / `cmm` fields into the internal
/// [`MaterialSource`], or `None` if not exactly one is set.
pub(crate) fn resolve_material_source(
    keyring: Option<&SharedKeyring>,
    cmm: Option<&SharedCmm>,
) -> Option<MaterialSource> {
    match (keyring, cmm) {
        (Some(k), None) => Some(MaterialSource::Keyring(k.clone())),
        (None, Some(c)) => Some(MaterialSource::Cmm(c.clone())),
        _ => None,
    }
}

/// Shared input validation: exactly one of `keyring` or `cmm` must be set.
fn validate_material_source(
    keyring: Option<&SharedKeyring>,
    cmm: Option<&SharedCmm>,
) -> Result<(), Error> {
    match (keyring.is_some(), cmm.is_some()) {
        (true, false) | (false, true) => Ok(()),
        _ => Err(val_err("exactly one of a keyring or CMM must be provided")),
    }
}

//= spec/client-apis/encrypt.md#frame-length
//# This value MUST default to 4096 bytes.
const DEFAULT_FRAME_LENGTH: NonZeroU32 = NonZeroU32::new(4096).expect("4096 is non-zero");

/// The output a streaming encrypt or decrypt writes to:
/// any [`AsyncWrite`](tokio::io::AsyncWrite) that is `Unpin + Send`.
//= spec/client-apis/streaming.md#outputs
//# In order to support streaming, the operation MUST produce some output within a streaming framework.
//
//= spec/client-apis/streaming.md#outputs
//= reason=Sink is tokio's AsyncWrite; write is the output release mechanism
//# - There MUST be a mechanism for output bytes to be released.
pub trait Sink: tokio::io::AsyncWrite + Unpin + Send {}
//= spec/client-apis/streaming.md#outputs
//= reason=encrypt_stream/decrypt_stream flush the output and then return Ok, the end-of-output indicator
//# - There MUST be a mechanism to indicate that the entire output has been released.
impl<T: tokio::io::AsyncWrite + Unpin + Send + ?Sized> Sink for T {}

/// The input a streaming encrypt or decrypt reads from:
/// any [`AsyncRead`](tokio::io::AsyncRead) that is `Unpin + Send`.
//= spec/client-apis/streaming.md#inputs
//# In order to support streaming, the operation MUST accept some input within a streaming framework.
//
//= spec/client-apis/streaming.md#inputs
//= reason=Source is tokio's AsyncRead; read is the input consumption mechanism
//# - There MUST be a mechanism for input bytes to become consumable.
pub trait Source: tokio::io::AsyncRead + Unpin + Send {}
//= spec/client-apis/streaming.md#overview
//= type=implication
//= reason=Source is tokio's AsyncRead; it exposes only incremental reads, so callers never need to hold the full input in memory
//# If an implementation requires holding the entire input in memory in order to perform the operation,
//# that implementation SHOULD NOT provide an API that allows the caller to stream the operation.
//
//= spec/client-apis/streaming.md#overview
//= type=implication
//= reason=Source is tokio's AsyncRead; processing happens incrementally regardless of input size
//# APIs that support streaming of the encrypt or decrypt operation SHOULD allow customers
//# to be able to process arbitrarily large inputs with a finite amount of working memory.
//
//= spec/client-apis/encrypt.md#plaintext
//= type=implication
//= reason=Source is tokio's AsyncRead; the plaintext flows in incrementally and is never held whole
//# If an implementation requires holding the input entire plaintext in memory in order to perform this operation,
//# that implementation SHOULD NOT provide an API that allows this input to be streamed.
//
//= spec/client-apis/streaming.md#inputs
//= reason=Source is tokio's AsyncRead; a read of zero bytes is the EOF indicator
//# - There MUST be a mechanism to indicate that there are no more input bytes.
impl<T: tokio::io::AsyncRead + Unpin + Send + ?Sized> Source for T {}

/// An in-memory writer that mirrors the bytes a step reads or writes, such as a signature digest.
pub type Tee = dyn std::io::Write + Send;

/// Algorithm suite identifiers for the ESDK.
///
/// This is the Material Providers Library's ESDK algorithm suite enum, re-exported.
/// It is wrapped in the MPL
/// [`AlgorithmSuiteId`](aws_crypto_mpl::structures::AlgorithmSuiteId) union at
/// the materials boundary.
pub use aws_crypto_mpl::structures::EsdkAlgorithmSuiteId as AlgorithmSuiteId;

/// The Material Providers Library's shared keyring handle, re-exported.
/// The `keyring` input of every operation holds one.
pub use aws_crypto_mpl::keyring::SharedKeyring;

/// The Material Providers Library's shared CMM handle, re-exported.
/// The `cmm` input of every operation holds one.
pub use aws_crypto_mpl::cmm::SharedCmm;

/// The Material Providers Library's keyring trait, re-exported.
/// Implement it to supply a custom keyring.
pub use aws_crypto_mpl::keyring::Keyring;

/// The Material Providers Library's CMM trait, re-exported.
/// Implement it to supply a custom CMM.
pub use aws_crypto_mpl::cmm::Cmm;

/// Put `#[async_trait]` on an `impl` of [`Keyring`] or [`Cmm`].
pub use aws_crypto_mpl::async_trait;

/// The Material Providers Library's conversion into a shared handle, re-exported.
/// `keyring.into_shared()` returns a [`SharedKeyring`], reusing it if it already is one.
pub use aws_crypto_mpl::IntoShared;

/// Key-Value pairs to associate with the encrypted data.
///
/// This is the Material Providers Library's own encryption context, re-exported,
/// so no conversion happens at the CMM boundary. The specification defines its
/// entries as UTF-8 encoded strings; that is enforced where the header is
/// serialized, and on the read side by the parser.
pub use aws_crypto_mpl::structures::EncryptionContext;

/// Commitment policies governing key commitment behavior.
///
/// This is the Material Providers Library's own ESDK commitment-policy enum,
/// re-exported. It is wrapped in the MPL
/// [`CommitmentPolicy`](aws_crypto_mpl::structures::CommitmentPolicy) union at
/// the materials boundary.
pub use aws_crypto_mpl::structures::EsdkCommitmentPolicy as CommitmentPolicy;

/// Commitment policy used when the caller provides none.
//= spec/client-apis/client.md#initialization
//# If no [commitment policy](#commitment-policy) is provided the default MUST be [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../framework/algorithm-suites.md#require_encrypt_require_decrypt).
/// What `Debug` prints in place of plaintext, as the AWS SDK for Rust does.
const REDACTED: &str = "*** Sensitive Data Redacted ***";

pub(crate) const DEFAULT_COMMITMENT_POLICY: CommitmentPolicy =
    CommitmentPolicy::RequireEncryptRequireDecrypt;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
/// Output of [`Client::encrypt`](crate::Client::encrypt).
//= spec/client-apis/encrypt.md#output
//= type=exception
//= reason=EncryptOutput provides encryption_context and algorithm_suite_id individually instead of a parsed header
//# - Encrypt operation output SHOULD include a [Parsed Header](#parsed-header) value.
//
//= spec/client-apis/encrypt.md#algorithm-suite-1
//= type=exception
//= reason=EncryptOutput returns algorithm_suite_id directly rather than via a parsed header
//# This output MAY be satisfied by outputting a [parsed header](#parsed-header) containing this value.
//
//= spec/client-apis/encrypt.md#encryption-context-1
//= type=exception
//= reason=EncryptOutput returns encryption_context directly rather than via a parsed header
//# This output MAY be satisfied by outputting a [parsed header](#parsed-header) containing this value.
pub struct EncryptOutput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub(crate) algorithm_suite_id: AlgorithmSuiteId,
    /// Encrypted message bytes (the serialized AWS Encryption SDK message).
    pub(crate) ciphertext: Vec<u8>,
    /// Encryption context associated with the encrypted message.
    pub(crate) encryption_context: EncryptionContext,
}

impl EncryptOutput {
    /// The algorithm suite the message is encrypted with.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The encryption context bound to the message.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// The encrypted message bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consume the output and return the ciphertext.
    #[must_use]
    pub fn into_ciphertext(self) -> Vec<u8> {
        self.ciphertext
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
/// Output of [`Client::encrypt_stream`](crate::Client::encrypt_stream).
pub struct EncryptStreamOutput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub(crate) algorithm_suite_id: AlgorithmSuiteId,
    /// Encryption context associated with the encrypted message.
    pub(crate) encryption_context: EncryptionContext,
}

impl EncryptStreamOutput {
    /// The algorithm suite the message is encrypted with.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The encryption context bound to the message.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }
}
#[derive(PartialEq, Eq, Clone)]
#[non_exhaustive]
/// Output of [`Client::decrypt`](crate::Client::decrypt).
pub struct DecryptOutput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub(crate) algorithm_suite_id: AlgorithmSuiteId,
    /// Encryption context recovered from the encrypted message.
    pub(crate) encryption_context: EncryptionContext,
    /// Decrypted plaintext data
    //= spec/client-apis/decrypt.md#plaintext
    //= type=implication
    //= reason=Vec<u8> is a sequence of bytes by definition
    //# This MUST be a sequence of bytes.
    pub(crate) plaintext: Vec<u8>,
}

impl std::fmt::Debug for DecryptOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptOutput")
            .field("algorithm_suite_id", &self.algorithm_suite_id)
            .field("encryption_context", &self.encryption_context)
            .field("plaintext", &REDACTED)
            .finish()
    }
}

impl DecryptOutput {
    /// The algorithm suite the message is encrypted with.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The encryption context bound to the message.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// The decrypted plaintext.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Consume the output and return the plaintext.
    #[must_use]
    pub fn into_plaintext(self) -> Vec<u8> {
        self.plaintext
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
/// Output of [`Client::decrypt_stream`](crate::Client::decrypt_stream).
pub struct DecryptStreamOutput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub(crate) algorithm_suite_id: AlgorithmSuiteId,
    /// Encryption context recovered from the encrypted message.
    pub(crate) encryption_context: EncryptionContext,
}

impl DecryptStreamOutput {
    /// The algorithm suite the message is encrypted with.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The encryption context bound to the message.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }
}
#[derive(Clone)]
#[non_exhaustive]
/// Input for [`Client::encrypt`](crate::Client::encrypt), built by its fluent builder.
//= spec/client-apis/encrypt.md#input
//= type=exception
//= reason=EncryptInput plaintext is &[u8] with known length; Plaintext Length Bound is not implemented here
//# Implementations SHOULD ensure that a caller is not able to specify both a [plaintext](#plaintext)
//# with known length and a [Plaintext Length Bound](#plaintext-length-bound) by construction.
//
//= spec/client-apis/encrypt.md#input
//= type=exception
//= reason=Plaintext Length Bound is not implemented on EncryptInput, so this conditional MUST does not apply
//# If a caller is able to specify both an input [plaintext](#plaintext) with known length and
//# a [Plaintext Length Bound](#plaintext-length-bound),
//# the [Plaintext Length Bound](#plaintext-length-bound) MUST NOT be used during the Encrypt operation
//# and MUST be ignored.
pub(crate) struct EncryptInput<'a> {
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [Algorithm Suite](#algorithm-suite) argument.
    pub(crate) algorithm_suite_id: Option<AlgorithmSuiteId>,
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
    pub(crate) encryption_context: EncryptionContext,
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [Frame Length](#frame-length) argument.
    //
    //= spec/data-format/message-body.md#framed-data
    //= reason=NonZeroU32 max value is u32::MAX = 2^32 - 1
    //# - The total bytes allowed in a single frame MUST be less than or equal to `2^32 - 1`.
    pub(crate) frame_length: NonZeroU32,
    /// The keyring to use for this operation.
    pub(crate) keyring: Option<SharedKeyring>,
    /// The cryptographic materials manager (CMM) to use for this operation.
    pub(crate) cmm: Option<SharedCmm>,
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept a required [plaintext](#plaintext) argument.
    //
    //= spec/client-apis/encrypt.md#plaintext
    //= type=implication
    //= reason=&[u8] is a sequence of bytes by definition
    //# This MUST be a sequence of bytes.
    pub(crate) plaintext: &'a [u8],
    pub(crate) max_encrypted_data_keys: Option<NonZeroUsize>,
    pub(crate) commitment_policy: CommitmentPolicy,
}

impl<'a> EncryptInput<'a> {
    /// Start a fluent builder for `EncryptInput`.
    #[must_use]
    pub(crate) fn builder() -> EncryptInputBuilder<'a> {
        EncryptInputBuilder::default()
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }
}

/// Fluent builder for [`EncryptInput`].
/// `get_x(&self) -> &Option<T>` getters for an input builder's `x: Option<T>` fields.
macro_rules! getters {
    ($($getter:ident: $field:ident -> $ty:ty),+ $(,)?) => {
        $(
            #[must_use]
            #[allow(clippy::ref_option, clippy::ref_option_ref)] // AWS SDK for Rust getter shape
            pub(crate) const fn $getter(&self) -> &Option<$ty> {
                &self.$field
            }
        )+
    };
}

#[derive(Clone, Default)]
pub(crate) struct EncryptInputBuilder<'a> {
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
    frame_length: Option<NonZeroU32>,
    keyring: Option<SharedKeyring>,
    cmm: Option<SharedCmm>,
    plaintext: Option<&'a [u8]>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
    commitment_policy: Option<CommitmentPolicy>,
}

impl std::fmt::Debug for EncryptInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptInput")
            .field("algorithm_suite_id", &self.algorithm_suite_id)
            .field("encryption_context", &self.encryption_context)
            .field("frame_length", &self.frame_length)
            .field("keyring", &self.keyring)
            .field("cmm", &self.cmm)
            .field("plaintext", &REDACTED)
            .field("max_encrypted_data_keys", &self.max_encrypted_data_keys)
            .field("commitment_policy", &self.commitment_policy)
            .finish()
    }
}

impl std::fmt::Debug for EncryptInputBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptInputBuilder")
            .field("algorithm_suite_id", &self.algorithm_suite_id)
            .field("encryption_context", &self.encryption_context)
            .field("frame_length", &self.frame_length)
            .field("keyring", &self.keyring)
            .field("cmm", &self.cmm)
            .field("plaintext", &REDACTED)
            .field("max_encrypted_data_keys", &self.max_encrypted_data_keys)
            .field("commitment_policy", &self.commitment_policy)
            .finish()
    }
}

impl<'a> EncryptInputBuilder<'a> {
    getters!(
        get_plaintext: plaintext -> &'a [u8],
        get_encryption_context: encryption_context -> EncryptionContext,
        get_keyring: keyring -> SharedKeyring,
        get_cmm: cmm -> SharedCmm,
        get_algorithm_suite_id: algorithm_suite_id -> AlgorithmSuiteId,
        get_frame_length: frame_length -> NonZeroU32,
    );

    /// Set the algorithm suite.
    /// See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    #[must_use]
    pub(crate) const fn algorithm_suite_id(mut self, id: AlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(id);
        self
    }

    /// Set the algorithm suite from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::algorithm_suite_id`].
    #[must_use]
    pub(crate) const fn set_algorithm_suite_id(
        mut self,
        algorithm_suite_id: Option<AlgorithmSuiteId>,
    ) -> Self {
        self.algorithm_suite_id = algorithm_suite_id;
        self
    }

    /// Set the key-value pairs to associate with the encrypted data.
    /// Default is empty.
    #[must_use]
    pub(crate) fn encryption_context(mut self, ec: impl Into<EncryptionContext>) -> Self {
        self.encryption_context = Some(ec.into());
        self
    }

    /// Set the encryption context from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::encryption_context`].
    #[must_use]
    pub(crate) fn set_encryption_context(
        mut self,
        encryption_context: Option<EncryptionContext>,
    ) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// Set the bytes of plaintext data per frame.
    /// Default is 4096.
    //
    //= spec/client-apis/encrypt.md#frame-length
    //= type=implication
    //= reason=NonZeroU32 is greater than 0 and at most u32::MAX = 2^32 - 1
    //# This value MUST be greater than 0 and MUST NOT exceed the value 2^32 - 1.
    #[must_use]
    pub(crate) const fn frame_length(mut self, frame_length: NonZeroU32) -> Self {
        self.frame_length = Some(frame_length);
        self
    }

    /// Set the frame length from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::frame_length`].
    #[must_use]
    pub(crate) const fn set_frame_length(mut self, frame_length: Option<NonZeroU32>) -> Self {
        self.frame_length = frame_length;
        self
    }

    /// Set the keyring.
    /// Provide exactly one of a keyring or a CMM.
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [keyring](../framework/keyring-interface.md) argument.
    #[must_use]
    pub(crate) fn keyring(mut self, keyring: impl IntoShared<SharedKeyring>) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// Set the keyring from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::keyring`].
    #[must_use]
    pub(crate) fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// Set the cryptographic materials manager (CMM).
    /// Provide exactly one of a keyring or a CMM.
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [cryptographic Materials Manager (CMM)](../framework/cmm-interface.md) argument.
    #[must_use]
    pub(crate) fn cmm(mut self, cmm: impl IntoShared<SharedCmm>) -> Self {
        self.cmm = Some(cmm.into_shared());
        self
    }

    /// Set the CMM from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::cmm`].
    #[must_use]
    pub(crate) fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Set the data to be encrypted.
    /// Required.
    #[must_use]
    pub(crate) const fn plaintext(mut self, plaintext: &'a [u8]) -> Self {
        self.plaintext = Some(plaintext);
        self
    }

    pub(crate) const fn set_plaintext(mut self, plaintext: Option<&'a [u8]>) -> Self {
        self.plaintext = plaintext;
        self
    }

    /// Set the maximum number of encrypted data keys from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::max_encrypted_data_keys`].
    #[must_use]
    pub(crate) const fn set_max_encrypted_data_keys(
        mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> Self {
        self.max_encrypted_data_keys = max_encrypted_data_keys;
        self
    }

    /// Set the commitment policy.
    /// Default is `CommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// The [`Client`](crate::Client)'s fluent builders set this from the client's config.
    #[must_use]
    pub(crate) const fn commitment_policy(mut self, p: CommitmentPolicy) -> Self {
        self.commitment_policy = Some(p);
        self
    }

    /// Build the `EncryptInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no plaintext was set, or not exactly one of a keyring or CMM was set.
    pub(crate) fn build(self) -> Result<EncryptInput<'a>, Error> {
        let plaintext = required(self.plaintext, "plaintext")?;
        //= spec/client-apis/encrypt.md#input
        //# The Encrypt operation MUST validate that exactly one keyring or CMM was provided by the caller.
        //
        //= spec/client-apis/encrypt.md#input
        //# If the caller does not provide exactly one of a keyring or CMM, the Encrypt operation MUST fail.
        validate_material_source(self.keyring.as_ref(), self.cmm.as_ref())?;
        Ok(EncryptInput {
            algorithm_suite_id: self.algorithm_suite_id,
            encryption_context: self.encryption_context.unwrap_or_default(),
            frame_length: self.frame_length.unwrap_or(DEFAULT_FRAME_LENGTH),
            keyring: self.keyring,
            cmm: self.cmm,
            plaintext,
            max_encrypted_data_keys: self.max_encrypted_data_keys,
            commitment_policy: self.commitment_policy.unwrap_or(DEFAULT_COMMITMENT_POLICY),
        })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`Client::encrypt_stream`](crate::Client::encrypt_stream), built by its fluent builder.
pub(crate) struct EncryptStreamInput {
    pub(crate) algorithm_suite_id: Option<AlgorithmSuiteId>,
    pub(crate) encryption_context: EncryptionContext,
    pub(crate) frame_length: NonZeroU32,
    /// The keyring to use for this operation.
    pub(crate) keyring: Option<SharedKeyring>,
    /// The cryptographic materials manager (CMM) to use for this operation.
    pub(crate) cmm: Option<SharedCmm>,
    //= spec/client-apis/encrypt.md#input
    //= reason=EncryptStreamInput accepts unknown-length plaintext via a stream; data_size serves as the optional Plaintext Length Bound
    //# If the [plaintext](#plaintext) is of unknown length, the caller MAY also input a
    //# [Plaintext Length Bound](#plaintext-length-bound).
    pub(crate) data_size: Option<usize>,
    pub(crate) max_encrypted_data_keys: Option<NonZeroUsize>,
    pub(crate) commitment_policy: CommitmentPolicy,
}

impl EncryptStreamInput {
    /// Start a fluent builder for `EncryptStreamInput`.
    #[must_use]
    pub(crate) fn builder() -> EncryptStreamInputBuilder {
        EncryptStreamInputBuilder::default()
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }
}

/// Fluent builder for [`EncryptStreamInput`].
#[derive(Debug, Clone, Default)]
pub(crate) struct EncryptStreamInputBuilder {
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
    frame_length: Option<NonZeroU32>,
    keyring: Option<SharedKeyring>,
    cmm: Option<SharedCmm>,
    data_size: Option<usize>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
    commitment_policy: Option<CommitmentPolicy>,
}

impl EncryptStreamInputBuilder {
    getters!(
        get_encryption_context: encryption_context -> EncryptionContext,
        get_keyring: keyring -> SharedKeyring,
        get_cmm: cmm -> SharedCmm,
        get_algorithm_suite_id: algorithm_suite_id -> AlgorithmSuiteId,
        get_frame_length: frame_length -> NonZeroU32,
        get_data_size: data_size -> usize,
    );

    /// Set the algorithm suite.
    /// See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    #[must_use]
    pub(crate) const fn algorithm_suite_id(mut self, id: AlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(id);
        self
    }

    /// Set the algorithm suite from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::algorithm_suite_id`].
    #[must_use]
    pub(crate) const fn set_algorithm_suite_id(
        mut self,
        algorithm_suite_id: Option<AlgorithmSuiteId>,
    ) -> Self {
        self.algorithm_suite_id = algorithm_suite_id;
        self
    }

    /// Set the key-value pairs to associate with the encrypted data.
    /// Default is empty.
    #[must_use]
    pub(crate) fn encryption_context(mut self, ec: impl Into<EncryptionContext>) -> Self {
        self.encryption_context = Some(ec.into());
        self
    }

    /// Set the encryption context from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::encryption_context`].
    #[must_use]
    pub(crate) fn set_encryption_context(
        mut self,
        encryption_context: Option<EncryptionContext>,
    ) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// Set the bytes of plaintext data per frame.
    /// Default is 4096.
    #[must_use]
    pub(crate) const fn frame_length(mut self, frame_length: NonZeroU32) -> Self {
        self.frame_length = Some(frame_length);
        self
    }

    /// Set the frame length from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::frame_length`].
    #[must_use]
    pub(crate) const fn set_frame_length(mut self, frame_length: Option<NonZeroU32>) -> Self {
        self.frame_length = frame_length;
        self
    }

    /// Set the keyring.
    /// Provide exactly one of a keyring or a CMM.
    #[must_use]
    pub(crate) fn keyring(mut self, keyring: impl IntoShared<SharedKeyring>) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// Set the keyring from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::keyring`].
    #[must_use]
    pub(crate) fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// Set the cryptographic materials manager (CMM).
    /// Provide exactly one of a keyring or a CMM.
    #[must_use]
    pub(crate) fn cmm(mut self, cmm: impl IntoShared<SharedCmm>) -> Self {
        self.cmm = Some(cmm.into_shared());
        self
    }

    /// Set the CMM from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::cmm`].
    #[must_use]
    pub(crate) fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Set the expected size of the input plaintext stream.
    ///
    /// Most CMMs and keyrings ignore this; provide it only when the configured
    /// CMM or keyring requires the plaintext length up front (e.g. for a
    /// signing scheme that pre-computes a digest size).
    #[must_use]
    pub(crate) const fn data_size(mut self, data_size: usize) -> Self {
        self.data_size = Some(data_size);
        self
    }

    /// Set the expected plaintext stream size from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::data_size`].
    #[must_use]
    pub(crate) const fn set_data_size(mut self, data_size: Option<usize>) -> Self {
        self.data_size = data_size;
        self
    }

    /// Set the maximum number of encrypted data keys from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::max_encrypted_data_keys`].
    #[must_use]
    pub(crate) const fn set_max_encrypted_data_keys(
        mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> Self {
        self.max_encrypted_data_keys = max_encrypted_data_keys;
        self
    }

    /// Set the commitment policy.
    /// Default is `CommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// The [`Client`](crate::Client)'s fluent builders set this from the client's config.
    #[must_use]
    pub(crate) const fn commitment_policy(mut self, p: CommitmentPolicy) -> Self {
        self.commitment_policy = Some(p);
        self
    }

    /// Build the `EncryptStreamInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): not exactly one of a keyring or CMM was set.
    pub(crate) fn build(self) -> Result<EncryptStreamInput, Error> {
        validate_material_source(self.keyring.as_ref(), self.cmm.as_ref())?;
        Ok(EncryptStreamInput {
            algorithm_suite_id: self.algorithm_suite_id,
            encryption_context: self.encryption_context.unwrap_or_default(),
            frame_length: self.frame_length.unwrap_or(DEFAULT_FRAME_LENGTH),
            keyring: self.keyring,
            cmm: self.cmm,
            data_size: self.data_size,
            max_encrypted_data_keys: self.max_encrypted_data_keys,
            commitment_policy: self.commitment_policy.unwrap_or(DEFAULT_COMMITMENT_POLICY),
        })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`Client::decrypt`](crate::Client::decrypt), built by its fluent builder.
pub(crate) struct DecryptInput<'a> {
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept a required [Encrypted Message](#encrypted-message) argument.
    //
    //= spec/client-apis/decrypt.md#encrypted-message
    //# The input encrypted message MUST be a sequence of bytes in the
    //# [message format](../data-format/message.md) specified by the AWS Encryption SDK.
    pub(crate) ciphertext: &'a [u8],
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
    pub(crate) encryption_context: EncryptionContext,
    /// The keyring to use for this operation.
    pub(crate) keyring: Option<SharedKeyring>,
    /// The cryptographic materials manager (CMM) to use for this operation.
    pub(crate) cmm: Option<SharedCmm>,
    pub(crate) max_encrypted_data_keys: Option<NonZeroUsize>,
    pub(crate) commitment_policy: CommitmentPolicy,
}

impl<'a> DecryptInput<'a> {
    /// Start a fluent builder for `DecryptInput`.
    #[must_use]
    pub(crate) fn builder() -> DecryptInputBuilder<'a> {
        DecryptInputBuilder::default()
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }
}

/// Fluent builder for [`DecryptInput`].
#[derive(Debug, Clone, Default)]
pub(crate) struct DecryptInputBuilder<'a> {
    ciphertext: Option<&'a [u8]>,
    encryption_context: Option<EncryptionContext>,
    keyring: Option<SharedKeyring>,
    cmm: Option<SharedCmm>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
    commitment_policy: Option<CommitmentPolicy>,
}

impl<'a> DecryptInputBuilder<'a> {
    getters!(
        get_ciphertext: ciphertext -> &'a [u8],
        get_encryption_context: encryption_context -> EncryptionContext,
        get_keyring: keyring -> SharedKeyring,
        get_cmm: cmm -> SharedCmm,
    );

    /// Set the encrypted message (the serialized AWS Encryption SDK message) to decrypt.
    /// Required.
    #[must_use]
    pub(crate) const fn ciphertext(mut self, ciphertext: &'a [u8]) -> Self {
        self.ciphertext = Some(ciphertext);
        self
    }

    pub(crate) const fn set_ciphertext(mut self, ciphertext: Option<&'a [u8]>) -> Self {
        self.ciphertext = ciphertext;
        self
    }

    /// Set the encryption context to verify against the encrypted message.
    /// If non-empty, decrypt requires every entry to be present in the message's encryption
    /// context (subset check).
    /// Default is empty.
    #[must_use]
    pub(crate) fn encryption_context(mut self, ec: impl Into<EncryptionContext>) -> Self {
        self.encryption_context = Some(ec.into());
        self
    }

    /// Set the encryption context from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::encryption_context`].
    #[must_use]
    pub(crate) fn set_encryption_context(
        mut self,
        encryption_context: Option<EncryptionContext>,
    ) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// Set the keyring.
    /// Provide exactly one of a keyring or a CMM.
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept an optional [Keyring](../framework/keyring-interface.md) argument.
    #[must_use]
    pub(crate) fn keyring(mut self, keyring: impl IntoShared<SharedKeyring>) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// Set the keyring from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::keyring`].
    #[must_use]
    pub(crate) fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// Set the cryptographic materials manager (CMM).
    /// Provide exactly one of a keyring or a CMM.
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept an optional [Cryptographic Materials Manager (CMM)](../framework/cmm-interface.md) argument.
    #[must_use]
    pub(crate) fn cmm(mut self, cmm: impl IntoShared<SharedCmm>) -> Self {
        self.cmm = Some(cmm.into_shared());
        self
    }

    /// Set the CMM from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::cmm`].
    #[must_use]
    pub(crate) fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Set the maximum number of encrypted data keys from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::max_encrypted_data_keys`].
    #[must_use]
    pub(crate) const fn set_max_encrypted_data_keys(
        mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> Self {
        self.max_encrypted_data_keys = max_encrypted_data_keys;
        self
    }

    /// Set the commitment policy.
    /// Default is `CommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// The [`Client`](crate::Client)'s fluent builders set this from the client's config.
    #[must_use]
    pub(crate) const fn commitment_policy(mut self, p: CommitmentPolicy) -> Self {
        self.commitment_policy = Some(p);
        self
    }

    /// Build the `DecryptInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no ciphertext was set, or not exactly one of a keyring or CMM was set.
    pub(crate) fn build(self) -> Result<DecryptInput<'a>, Error> {
        let ciphertext = required(self.ciphertext, "ciphertext")?;
        //= spec/client-apis/decrypt.md#input
        //# The Decrypt operation MUST validate that exactly one of a keyring or CMM was provided by the caller.
        //
        //= spec/client-apis/decrypt.md#input
        //# If the caller does not provide exactly one of a keyring or CMM, the Decrypt operation MUST fail.
        validate_material_source(self.keyring.as_ref(), self.cmm.as_ref())?;
        Ok(DecryptInput {
            ciphertext,
            encryption_context: self.encryption_context.unwrap_or_default(),
            keyring: self.keyring,
            cmm: self.cmm,
            max_encrypted_data_keys: self.max_encrypted_data_keys,
            commitment_policy: self.commitment_policy.unwrap_or(DEFAULT_COMMITMENT_POLICY),
        })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`Client::decrypt_stream`](crate::Client::decrypt_stream), built by its fluent builder.
pub(crate) struct DecryptStreamInput {
    pub(crate) encryption_context: EncryptionContext,
    /// The keyring to use for this operation.
    pub(crate) keyring: Option<SharedKeyring>,
    /// The cryptographic materials manager (CMM) to use for this operation.
    pub(crate) cmm: Option<SharedCmm>,
    pub(crate) max_encrypted_data_keys: Option<NonZeroUsize>,
    pub(crate) commitment_policy: CommitmentPolicy,
}

impl DecryptStreamInput {
    /// Start a fluent builder for `DecryptStreamInput`.
    #[must_use]
    pub(crate) fn builder() -> DecryptStreamInputBuilder {
        DecryptStreamInputBuilder::default()
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }
}

/// Fluent builder for [`DecryptStreamInput`].
#[derive(Debug, Clone, Default)]
pub(crate) struct DecryptStreamInputBuilder {
    encryption_context: Option<EncryptionContext>,
    keyring: Option<SharedKeyring>,
    cmm: Option<SharedCmm>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
    commitment_policy: Option<CommitmentPolicy>,
}

impl DecryptStreamInputBuilder {
    getters!(
        get_encryption_context: encryption_context -> EncryptionContext,
        get_keyring: keyring -> SharedKeyring,
        get_cmm: cmm -> SharedCmm,
    );

    /// Set the encryption context to verify against the encrypted message.
    /// If non-empty, `decrypt_stream` requires every entry to be present in the message's
    /// encryption context (subset check).
    /// Default is empty.
    #[must_use]
    pub(crate) fn encryption_context(mut self, ec: impl Into<EncryptionContext>) -> Self {
        self.encryption_context = Some(ec.into());
        self
    }

    /// Set the encryption context from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::encryption_context`].
    #[must_use]
    pub(crate) fn set_encryption_context(
        mut self,
        encryption_context: Option<EncryptionContext>,
    ) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// Set the keyring.
    /// Provide exactly one of a keyring or a CMM.
    #[must_use]
    pub(crate) fn keyring(mut self, keyring: impl IntoShared<SharedKeyring>) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// Set the keyring from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::keyring`].
    #[must_use]
    pub(crate) fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// Set the cryptographic materials manager (CMM).
    /// Provide exactly one of a keyring or a CMM.
    #[must_use]
    pub(crate) fn cmm(mut self, cmm: impl IntoShared<SharedCmm>) -> Self {
        self.cmm = Some(cmm.into_shared());
        self
    }

    /// Set the CMM from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::cmm`].
    #[must_use]
    pub(crate) fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Set the maximum number of encrypted data keys from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::max_encrypted_data_keys`].
    #[must_use]
    pub(crate) const fn set_max_encrypted_data_keys(
        mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> Self {
        self.max_encrypted_data_keys = max_encrypted_data_keys;
        self
    }

    /// Set the commitment policy.
    /// Default is `CommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// The [`Client`](crate::Client)'s fluent builders set this from the client's config.
    #[must_use]
    pub(crate) const fn commitment_policy(mut self, p: CommitmentPolicy) -> Self {
        self.commitment_policy = Some(p);
        self
    }

    /// Build the `DecryptStreamInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): not exactly one of a keyring or CMM was set.
    pub(crate) fn build(self) -> Result<DecryptStreamInput, Error> {
        validate_material_source(self.keyring.as_ref(), self.cmm.as_ref())?;
        Ok(DecryptStreamInput {
            encryption_context: self.encryption_context.unwrap_or_default(),
            keyring: self.keyring,
            cmm: self.cmm,
            max_encrypted_data_keys: self.max_encrypted_data_keys,
            commitment_policy: self.commitment_policy.unwrap_or(DEFAULT_COMMITMENT_POLICY),
        })
    }
}
