// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Public API types for encrypt and decrypt operations.

use crate::Error;
use crate::val_err;
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
        _ => Err(val_err("Exactly one of a keyring or CMM must be provided")),
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The length of one frame, must be non-zero, defaults to 4096.
//= spec/data-format/message-body.md#framed-data
//= reason=NonZeroU32 max value is u32::MAX = 2^32 - 1
//# - The total bytes allowed in a single frame MUST be less than or equal to `2^32 - 1`.
#[expect(clippy::exhaustive_structs)]
pub struct FrameLength(pub NonZeroU32);

impl Default for FrameLength {
    fn default() -> Self {
        //= spec/client-apis/encrypt.md#frame-length
        //# This value MUST default to 4096 bytes.
        // Safety: 4096 is a non-zero literal
        Self(NonZeroU32::new(4096).expect("4096 is non-zero"))
    }
}

impl FrameLength {
    /// Returns a new `FrameLength`, validated to be non-zero.
    ///
    /// # Errors
    /// Returns an error if `val` is zero.
    pub fn new(val: u32) -> Result<Self, Error> {
        //= spec/client-apis/encrypt.md#frame-length
        //# This value MUST be greater than 0 and MUST NOT exceed the value 2^32 - 1.
        Ok(Self(
            NonZeroU32::new(val).ok_or_else(|| val_err("Frame length must be non-zero"))?,
        ))
    }
}

/// Output bytes sink for streaming encrypt/decrypt operations.
///
/// Auto-implemented for any type that is `Write + Send + Sync + Debug`
/// (e.g. `Vec<u8>`, `std::fs::File`).
//= spec/client-apis/streaming.md#outputs
//# In order to support streaming, the operation MUST produce some output within a streaming framework.
//
//= spec/client-apis/streaming.md#outputs
//= reason=SafeWrite wraps std::io::Write; write() is the output release mechanism
//# - There MUST be a mechanism for output bytes to be released.
pub trait SafeWrite: std::io::Write + Send + Sync + std::fmt::Debug {}
//= spec/client-apis/streaming.md#outputs
//= reason=encrypt_stream/decrypt_stream return Result; Ok(()) is the end-of-output indicator
//# - There MUST be a mechanism to indicate that the entire output has been released.
impl<T: std::io::Write + Send + Sync + std::fmt::Debug> SafeWrite for T {}

/// Input bytes source for streaming encrypt/decrypt operations.
///
/// Auto-implemented for any type that is `Read + Send + Sync + Debug`
/// (e.g. `std::io::Cursor`, `std::fs::File`).
//= spec/client-apis/streaming.md#inputs
//# In order to support streaming, the operation MUST accept some input within a streaming framework.
//
//= spec/client-apis/streaming.md#inputs
//= reason=SafeRead wraps std::io::Read; read() is the input consumption mechanism
//# - There MUST be a mechanism for input bytes to become consumable.
pub trait SafeRead: std::io::Read + Send + Sync + std::fmt::Debug {}
//= spec/client-apis/streaming.md#overview
//= type=implication
//= reason=SafeRead wraps std::io::Read; the trait exposes only incremental reads, so callers never need to hold the full input in memory
//# If an implementation requires holding the entire input in memory in order to perform the operation,
//# that implementation SHOULD NOT provide an API that allows the caller to stream the operation.
//
//= spec/client-apis/streaming.md#overview
//= type=implication
//= reason=SafeRead wraps std::io::Read; processing happens incrementally regardless of input size
//# APIs that support streaming of the encrypt or decrypt operation SHOULD allow customers
//# to be able to process arbitrarily large inputs with a finite amount of working memory.
//
//= spec/client-apis/encrypt.md#plaintext
//= type=implication
//= reason=SafeRead wraps std::io::Read; the plaintext flows in incrementally and is never held whole
//# If an implementation requires holding the input entire plaintext in memory in order to perform this operation,
//# that implementation SHOULD NOT provide an API that allows this input to be streamed.
//
//= spec/client-apis/streaming.md#inputs
//= reason=SafeRead wraps std::io::Read; read() returning Ok(0) is the EOF indicator
//# - There MUST be a mechanism to indicate that there are no more input bytes.
impl<T: std::io::Read + Send + Sync + std::fmt::Debug> SafeRead for T {}

/// Algorithm suite identifiers for the ESDK.
pub use aws_crypto_mpl::structures::AlgorithmSuiteId as EsdkAlgorithmSuiteId;

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
pub use aws_crypto_mpl::structures::Esdk as EsdkCommitmentPolicy;

/// Commitment policy used when the caller provides none.
//= spec/client-apis/client.md#initialization
//# If no [commitment policy](#commitment-policy) is provided the default MUST be [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../framework/algorithm-suites.md#require_encrypt_require_decrypt).
pub(crate) const DEFAULT_COMMITMENT_POLICY: EsdkCommitmentPolicy =
    EsdkCommitmentPolicy::RequireEncryptRequireDecrypt;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
/// Output for [`encrypt`](crate::encrypt).
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
    pub algorithm_suite_id: EsdkAlgorithmSuiteId,
    /// Encrypted message bytes (the serialized AWS Encryption SDK message).
    pub ciphertext: Vec<u8>,
    /// Encryption context associated with the encrypted message.
    pub encryption_context: EncryptionContext,
}
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
/// Output for [`encrypt_stream`](crate::encrypt_stream).
pub struct EncryptStreamOutput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub algorithm_suite_id: EsdkAlgorithmSuiteId,
    /// Encryption context associated with the encrypted message.
    pub encryption_context: EncryptionContext,
}
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
/// Output for [decrypt](crate::decrypt).
pub struct DecryptOutput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub algorithm_suite_id: EsdkAlgorithmSuiteId,
    /// Encryption context recovered from the encrypted message.
    pub encryption_context: EncryptionContext,
    /// Decrypted plaintext data
    //= spec/client-apis/decrypt.md#plaintext
    //= type=implication
    //= reason=Vec<u8> is a sequence of bytes by definition
    //# This MUST be a sequence of bytes.
    pub plaintext: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
/// Output for [`decrypt_stream`](crate::decrypt_stream).
pub struct DecryptStreamOutput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub algorithm_suite_id: EsdkAlgorithmSuiteId,
    /// Encryption context recovered from the encrypted message.
    pub encryption_context: EncryptionContext,
}
#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`encrypt`](crate::encrypt).
/// Construct via [`EncryptInput::builder`].
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
pub struct EncryptInput<'a> {
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [Algorithm Suite](#algorithm-suite) argument.
    pub(crate) algorithm_suite_id: Option<EsdkAlgorithmSuiteId>,
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
    pub(crate) encryption_context: EncryptionContext,
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [Frame Length](#frame-length) argument.
    pub(crate) frame_length: FrameLength,
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
    //= spec/client-apis/client.md#initialization
    //# - On client initialization,
    //# the caller MUST have the option to provide a [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys).
    //
    //= spec/client-apis/client.md#initialization
    //# If no [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys) is provided
    //# the default MUST result in no limit on the number of encrypted data keys (aside from the limit imposed by the [message format](../format/message-header.md)).
    pub(crate) max_encrypted_data_keys: Option<NonZeroUsize>,
    //= spec/client-apis/client.md#commitment-policy
    //= reason=EsdkCommitmentPolicy is a re-export of the MPL's aws_crypto_mpl::structures::Esdk
    //# The AWS Encryption SDK MUST use the ESDK [commitment policies](../framework/commitment-policy.md) defined in the Material Providers Library.
    //
    //= spec/client-apis/client.md#initialization
    //= reason=EncryptInputBuilder::build() sets this field to DEFAULT_COMMITMENT_POLICY = RequireEncryptRequireDecrypt when unset
    //# If no [commitment policy](#commitment-policy) is provided the default MUST be [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../framework/algorithm-suites.md#require_encrypt_require_decrypt).
    //
    //= spec/client-apis/client.md#initialization
    //= type=implication
    //= reason=the field is private with a getter only, and encrypt()/decrypt() take &EncryptInput/&DecryptInput
    //# Once a [commitment policy](#commitment-policy) has been set it SHOULD be immutable.
    //
    //= spec/client-apis/client.md#initialization
    //# - On client initialization,
    //# the caller MUST have the option to provide a [commitment policy](#commitment-policy).
    pub(crate) commitment_policy: EsdkCommitmentPolicy,
}

impl<'a> EncryptInput<'a> {
    /// Start a fluent builder for `EncryptInput`.
    #[must_use]
    pub fn builder() -> EncryptInputBuilder<'a> {
        EncryptInputBuilder::default()
    }

    /// The algorithm suite, if one was set.
    /// See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> Option<EsdkAlgorithmSuiteId> {
        self.algorithm_suite_id
    }

    /// Key-value pairs to associate with the encrypted data.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// Bytes of plaintext data per frame.
    #[must_use]
    pub const fn frame_length(&self) -> NonZeroU32 {
        self.frame_length.0
    }

    /// The keyring, if this input was built with one.
    #[must_use]
    pub const fn keyring(&self) -> Option<&SharedKeyring> {
        self.keyring.as_ref()
    }

    /// The CMM, if this input was built with one.
    #[must_use]
    pub const fn cmm(&self) -> Option<&SharedCmm> {
        self.cmm.as_ref()
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }

    /// The data to be encrypted.
    #[must_use]
    pub const fn plaintext(&self) -> &'a [u8] {
        self.plaintext
    }

    /// The cap on the number of encrypted data keys, if one was set.
    #[must_use]
    pub const fn max_encrypted_data_keys(&self) -> Option<NonZeroUsize> {
        self.max_encrypted_data_keys
    }

    /// The commitment policy.
    #[must_use]
    pub const fn commitment_policy(&self) -> EsdkCommitmentPolicy {
        self.commitment_policy
    }
}

/// Fluent builder for [`EncryptInput`].
#[derive(Debug, Clone, Default)]
pub struct EncryptInputBuilder<'a> {
    algorithm_suite_id: Option<EsdkAlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
    frame_length: Option<FrameLength>,
    keyring: Option<SharedKeyring>,
    cmm: Option<SharedCmm>,
    plaintext: Option<&'a [u8]>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
    commitment_policy: Option<EsdkCommitmentPolicy>,
}

impl<'a> EncryptInputBuilder<'a> {
    /// Set the algorithm suite.
    /// See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    #[must_use]
    pub const fn algorithm_suite_id(mut self, id: EsdkAlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(id);
        self
    }

    /// Set the algorithm suite from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::algorithm_suite_id`].
    #[must_use]
    pub const fn set_algorithm_suite_id(
        mut self,
        algorithm_suite_id: Option<EsdkAlgorithmSuiteId>,
    ) -> Self {
        self.algorithm_suite_id = algorithm_suite_id;
        self
    }

    /// Set the key-value pairs to associate with the encrypted data.
    /// Default is empty.
    #[must_use]
    pub fn encryption_context(mut self, ec: EncryptionContext) -> Self {
        self.encryption_context = Some(ec);
        self
    }

    /// Set the encryption context from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::encryption_context`].
    #[must_use]
    pub fn set_encryption_context(mut self, encryption_context: Option<EncryptionContext>) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// Set the bytes of plaintext data per frame.
    /// Default is 4096.
    #[must_use]
    pub const fn frame_length(mut self, frame_length: NonZeroU32) -> Self {
        self.frame_length = Some(FrameLength(frame_length));
        self
    }

    /// Set the frame length from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::frame_length`].
    #[must_use]
    pub fn set_frame_length(mut self, frame_length: Option<NonZeroU32>) -> Self {
        self.frame_length = frame_length.map(FrameLength);
        self
    }

    /// Set the keyring.
    /// Provide exactly one of a keyring or a CMM.
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [keyring](../framework/keyring-interface.md) argument.
    #[must_use]
    pub fn keyring(mut self, keyring: impl Keyring + 'static) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// Set the keyring from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::keyring`].
    #[must_use]
    pub fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// Set the cryptographic materials manager (CMM).
    /// Provide exactly one of a keyring or a CMM.
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [cryptographic Materials Manager (CMM)](../framework/cmm-interface.md) argument.
    #[must_use]
    pub fn cmm(mut self, cmm: impl Cmm + 'static) -> Self {
        self.cmm = Some(cmm.into_shared());
        self
    }

    /// Set the CMM from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::cmm`].
    #[must_use]
    pub fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Set the data to be encrypted.
    /// Required.
    #[must_use]
    pub const fn plaintext(mut self, plaintext: &'a [u8]) -> Self {
        self.plaintext = Some(plaintext);
        self
    }

    /// Set the maximum number of encrypted data keys.
    /// Default is no limit.
    ///
    /// Leave unset when calling [`Esdk::encrypt`](crate::Esdk::encrypt) — the client provides this.
    #[must_use]
    pub const fn max_encrypted_data_keys(mut self, n: NonZeroUsize) -> Self {
        self.max_encrypted_data_keys = Some(n);
        self
    }

    /// Set the maximum number of encrypted data keys from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::max_encrypted_data_keys`].
    #[must_use]
    pub const fn set_max_encrypted_data_keys(
        mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> Self {
        self.max_encrypted_data_keys = max_encrypted_data_keys;
        self
    }

    /// Set the commitment policy.
    /// Default is `EsdkCommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// Leave unset when calling [`Esdk::encrypt`](crate::Esdk::encrypt) — the client provides this.
    #[must_use]
    pub const fn commitment_policy(mut self, p: EsdkCommitmentPolicy) -> Self {
        self.commitment_policy = Some(p);
        self
    }

    /// Set the commitment policy from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::commitment_policy`].
    #[must_use]
    pub const fn set_commitment_policy(
        mut self,
        commitment_policy: Option<EsdkCommitmentPolicy>,
    ) -> Self {
        self.commitment_policy = commitment_policy;
        self
    }

    /// Build the `EncryptInput`.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if no plaintext was set,
    /// or if not exactly one of a keyring or CMM was set.
    pub fn build(self) -> Result<EncryptInput<'a>, Error> {
        let plaintext = self
            .plaintext
            .ok_or_else(|| val_err("A plaintext must be provided"))?;
        //= spec/client-apis/encrypt.md#input
        //# The Encrypt operation MUST validate that exactly one keyring or CMM was provided by the caller.
        //
        //= spec/client-apis/encrypt.md#input
        //# If the caller does not provide exactly one of a keyring or CMM, the Encrypt operation MUST fail.
        validate_material_source(self.keyring.as_ref(), self.cmm.as_ref())?;
        Ok(EncryptInput {
            algorithm_suite_id: self.algorithm_suite_id,
            encryption_context: self.encryption_context.unwrap_or_default(),
            frame_length: self.frame_length.unwrap_or_default(),
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
/// Input for [`encrypt_stream`](crate::encrypt_stream).
/// Construct via [`EncryptStreamInput::builder`].
pub struct EncryptStreamInput {
    pub(crate) algorithm_suite_id: Option<EsdkAlgorithmSuiteId>,
    pub(crate) encryption_context: EncryptionContext,
    pub(crate) frame_length: FrameLength,
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
    pub(crate) commitment_policy: EsdkCommitmentPolicy,
}

impl EncryptStreamInput {
    /// Start a fluent builder for `EncryptStreamInput`.
    #[must_use]
    pub fn builder() -> EncryptStreamInputBuilder {
        EncryptStreamInputBuilder::default()
    }

    /// The algorithm suite, if one was set.
    /// See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> Option<EsdkAlgorithmSuiteId> {
        self.algorithm_suite_id
    }

    /// Key-value pairs to associate with the encrypted data.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// Bytes of plaintext data per frame.
    #[must_use]
    pub const fn frame_length(&self) -> NonZeroU32 {
        self.frame_length.0
    }

    /// The keyring, if this input was built with one.
    #[must_use]
    pub const fn keyring(&self) -> Option<&SharedKeyring> {
        self.keyring.as_ref()
    }

    /// The CMM, if this input was built with one.
    #[must_use]
    pub const fn cmm(&self) -> Option<&SharedCmm> {
        self.cmm.as_ref()
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }

    /// The expected size of the input plaintext stream, if one was set.
    #[must_use]
    pub const fn data_size(&self) -> Option<usize> {
        self.data_size
    }

    /// The cap on the number of encrypted data keys, if one was set.
    #[must_use]
    pub const fn max_encrypted_data_keys(&self) -> Option<NonZeroUsize> {
        self.max_encrypted_data_keys
    }

    /// The commitment policy.
    #[must_use]
    pub const fn commitment_policy(&self) -> EsdkCommitmentPolicy {
        self.commitment_policy
    }
}

/// Fluent builder for [`EncryptStreamInput`].
#[derive(Debug, Clone, Default)]
pub struct EncryptStreamInputBuilder {
    algorithm_suite_id: Option<EsdkAlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
    frame_length: Option<FrameLength>,
    keyring: Option<SharedKeyring>,
    cmm: Option<SharedCmm>,
    data_size: Option<usize>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
    commitment_policy: Option<EsdkCommitmentPolicy>,
}

impl EncryptStreamInputBuilder {
    /// Set the algorithm suite.
    /// See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    #[must_use]
    pub const fn algorithm_suite_id(mut self, id: EsdkAlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(id);
        self
    }

    /// Set the algorithm suite from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::algorithm_suite_id`].
    #[must_use]
    pub const fn set_algorithm_suite_id(
        mut self,
        algorithm_suite_id: Option<EsdkAlgorithmSuiteId>,
    ) -> Self {
        self.algorithm_suite_id = algorithm_suite_id;
        self
    }

    /// Set the key-value pairs to associate with the encrypted data.
    /// Default is empty.
    #[must_use]
    pub fn encryption_context(mut self, ec: EncryptionContext) -> Self {
        self.encryption_context = Some(ec);
        self
    }

    /// Set the encryption context from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::encryption_context`].
    #[must_use]
    pub fn set_encryption_context(mut self, encryption_context: Option<EncryptionContext>) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// Set the bytes of plaintext data per frame.
    /// Default is 4096.
    #[must_use]
    pub const fn frame_length(mut self, frame_length: NonZeroU32) -> Self {
        self.frame_length = Some(FrameLength(frame_length));
        self
    }

    /// Set the frame length from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::frame_length`].
    #[must_use]
    pub fn set_frame_length(mut self, frame_length: Option<NonZeroU32>) -> Self {
        self.frame_length = frame_length.map(FrameLength);
        self
    }

    /// Set the keyring.
    /// Provide exactly one of a keyring or a CMM.
    #[must_use]
    pub fn keyring(mut self, keyring: impl Keyring + 'static) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// Set the keyring from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::keyring`].
    #[must_use]
    pub fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// Set the cryptographic materials manager (CMM).
    /// Provide exactly one of a keyring or a CMM.
    #[must_use]
    pub fn cmm(mut self, cmm: impl Cmm + 'static) -> Self {
        self.cmm = Some(cmm.into_shared());
        self
    }

    /// Set the CMM from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::cmm`].
    #[must_use]
    pub fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Set the expected size of the input plaintext stream.
    ///
    /// Most CMMs and keyrings ignore this; provide it only when the configured
    /// CMM or keyring requires the plaintext length up front (e.g. for a
    /// signing scheme that pre-computes a digest size).
    #[must_use]
    pub const fn data_size(mut self, data_size: usize) -> Self {
        self.data_size = Some(data_size);
        self
    }

    /// Set the expected plaintext stream size from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::data_size`].
    #[must_use]
    pub const fn set_data_size(mut self, data_size: Option<usize>) -> Self {
        self.data_size = data_size;
        self
    }

    /// Set the maximum number of encrypted data keys.
    /// Default is no limit.
    ///
    /// Leave unset when calling [`Esdk::encrypt_stream`](crate::Esdk::encrypt_stream) — the client
    /// provides this.
    #[must_use]
    pub const fn max_encrypted_data_keys(mut self, n: NonZeroUsize) -> Self {
        self.max_encrypted_data_keys = Some(n);
        self
    }

    /// Set the maximum number of encrypted data keys from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::max_encrypted_data_keys`].
    #[must_use]
    pub const fn set_max_encrypted_data_keys(
        mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> Self {
        self.max_encrypted_data_keys = max_encrypted_data_keys;
        self
    }

    /// Set the commitment policy.
    /// Default is `EsdkCommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// Leave unset when calling [`Esdk::encrypt_stream`](crate::Esdk::encrypt_stream) — the client
    /// provides this.
    #[must_use]
    pub const fn commitment_policy(mut self, p: EsdkCommitmentPolicy) -> Self {
        self.commitment_policy = Some(p);
        self
    }

    /// Set the commitment policy from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::commitment_policy`].
    #[must_use]
    pub const fn set_commitment_policy(
        mut self,
        commitment_policy: Option<EsdkCommitmentPolicy>,
    ) -> Self {
        self.commitment_policy = commitment_policy;
        self
    }

    /// Build the `EncryptStreamInput`.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if not exactly one of a keyring or CMM was set.
    pub fn build(self) -> Result<EncryptStreamInput, Error> {
        validate_material_source(self.keyring.as_ref(), self.cmm.as_ref())?;
        Ok(EncryptStreamInput {
            algorithm_suite_id: self.algorithm_suite_id,
            encryption_context: self.encryption_context.unwrap_or_default(),
            frame_length: self.frame_length.unwrap_or_default(),
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
/// Input for [`decrypt`](crate::decrypt).
/// Construct via [`DecryptInput::builder`].
pub struct DecryptInput<'a> {
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
    pub(crate) commitment_policy: EsdkCommitmentPolicy,
}

impl<'a> DecryptInput<'a> {
    /// Start a fluent builder for `DecryptInput`.
    #[must_use]
    pub fn builder() -> DecryptInputBuilder<'a> {
        DecryptInputBuilder::default()
    }

    /// Start a `DecryptInput` builder with the encryption context, keyring or CMM,
    /// commitment policy, and EDK cap of `e`.
    /// Set the ciphertext before building.
    #[must_use]
    pub fn builder_from_encrypt(e: &EncryptInput<'_>) -> DecryptInputBuilder<'a> {
        DecryptInputBuilder {
            ciphertext: None,
            encryption_context: Some(e.encryption_context.clone()),
            keyring: e.keyring().cloned(),
            cmm: e.cmm().cloned(),
            max_encrypted_data_keys: e.max_encrypted_data_keys,
            commitment_policy: Some(e.commitment_policy),
        }
    }

    /// The encrypted message to decrypt.
    #[must_use]
    pub const fn ciphertext(&self) -> &'a [u8] {
        self.ciphertext
    }

    /// The encryption context to verify against the encrypted message.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// The keyring, if this input was built with one.
    #[must_use]
    pub const fn keyring(&self) -> Option<&SharedKeyring> {
        self.keyring.as_ref()
    }

    /// The CMM, if this input was built with one.
    #[must_use]
    pub const fn cmm(&self) -> Option<&SharedCmm> {
        self.cmm.as_ref()
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }

    /// The cap on the number of encrypted data keys, if one was set.
    #[must_use]
    pub const fn max_encrypted_data_keys(&self) -> Option<NonZeroUsize> {
        self.max_encrypted_data_keys
    }

    /// The commitment policy.
    #[must_use]
    pub const fn commitment_policy(&self) -> EsdkCommitmentPolicy {
        self.commitment_policy
    }
}

/// Fluent builder for [`DecryptInput`].
#[derive(Debug, Clone, Default)]
pub struct DecryptInputBuilder<'a> {
    ciphertext: Option<&'a [u8]>,
    encryption_context: Option<EncryptionContext>,
    keyring: Option<SharedKeyring>,
    cmm: Option<SharedCmm>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
    commitment_policy: Option<EsdkCommitmentPolicy>,
}

impl<'a> DecryptInputBuilder<'a> {
    /// Set the encrypted message (the serialized AWS Encryption SDK message) to decrypt.
    /// Required.
    #[must_use]
    pub const fn ciphertext(mut self, ciphertext: &'a [u8]) -> Self {
        self.ciphertext = Some(ciphertext);
        self
    }

    /// Set the encryption context to verify against the encrypted message.
    /// If non-empty, decrypt requires every entry to be present in the message's encryption
    /// context (subset check).
    /// Default is empty.
    #[must_use]
    pub fn encryption_context(mut self, ec: EncryptionContext) -> Self {
        self.encryption_context = Some(ec);
        self
    }

    /// Set the encryption context from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::encryption_context`].
    #[must_use]
    pub fn set_encryption_context(mut self, encryption_context: Option<EncryptionContext>) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// Set the keyring.
    /// Provide exactly one of a keyring or a CMM.
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept an optional [Keyring](../framework/keyring-interface.md) argument.
    #[must_use]
    pub fn keyring(mut self, keyring: impl Keyring + 'static) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// Set the keyring from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::keyring`].
    #[must_use]
    pub fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// Set the cryptographic materials manager (CMM).
    /// Provide exactly one of a keyring or a CMM.
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept an optional [Cryptographic Materials Manager (CMM)](../framework/cmm-interface.md) argument.
    #[must_use]
    pub fn cmm(mut self, cmm: impl Cmm + 'static) -> Self {
        self.cmm = Some(cmm.into_shared());
        self
    }

    /// Set the CMM from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::cmm`].
    #[must_use]
    pub fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Set the maximum number of encrypted data keys.
    /// Default is no limit.
    ///
    /// Leave unset when calling [`Esdk::decrypt`](crate::Esdk::decrypt) — the client provides this.
    #[must_use]
    pub const fn max_encrypted_data_keys(mut self, n: NonZeroUsize) -> Self {
        self.max_encrypted_data_keys = Some(n);
        self
    }

    /// Set the maximum number of encrypted data keys from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::max_encrypted_data_keys`].
    #[must_use]
    pub const fn set_max_encrypted_data_keys(
        mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> Self {
        self.max_encrypted_data_keys = max_encrypted_data_keys;
        self
    }

    /// Set the commitment policy.
    /// Default is `EsdkCommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// Leave unset when calling [`Esdk::decrypt`](crate::Esdk::decrypt) — the client provides this.
    #[must_use]
    pub const fn commitment_policy(mut self, p: EsdkCommitmentPolicy) -> Self {
        self.commitment_policy = Some(p);
        self
    }

    /// Set the commitment policy from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::commitment_policy`].
    #[must_use]
    pub const fn set_commitment_policy(
        mut self,
        commitment_policy: Option<EsdkCommitmentPolicy>,
    ) -> Self {
        self.commitment_policy = commitment_policy;
        self
    }

    /// Build the `DecryptInput`.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if no ciphertext was set,
    /// or if not exactly one of a keyring or CMM was set.
    pub fn build(self) -> Result<DecryptInput<'a>, Error> {
        let ciphertext = self
            .ciphertext
            .ok_or_else(|| val_err("A ciphertext must be provided"))?;
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
/// Input for [`decrypt_stream`](crate::decrypt_stream).
/// Construct via [`DecryptStreamInput::builder`].
pub struct DecryptStreamInput {
    pub(crate) encryption_context: EncryptionContext,
    /// The keyring to use for this operation.
    pub(crate) keyring: Option<SharedKeyring>,
    /// The cryptographic materials manager (CMM) to use for this operation.
    pub(crate) cmm: Option<SharedCmm>,
    pub(crate) max_encrypted_data_keys: Option<NonZeroUsize>,
    pub(crate) commitment_policy: EsdkCommitmentPolicy,
}

impl DecryptStreamInput {
    /// Start a fluent builder for `DecryptStreamInput`.
    #[must_use]
    pub fn builder() -> DecryptStreamInputBuilder {
        DecryptStreamInputBuilder::default()
    }

    /// Start a `DecryptStreamInput` builder with the encryption context, keyring or CMM,
    /// commitment policy, and EDK cap of `e`.
    #[must_use]
    pub fn builder_from_encrypt(e: &EncryptInput<'_>) -> DecryptStreamInputBuilder {
        DecryptStreamInputBuilder {
            encryption_context: Some(e.encryption_context.clone()),
            keyring: e.keyring().cloned(),
            cmm: e.cmm().cloned(),
            max_encrypted_data_keys: e.max_encrypted_data_keys,
            commitment_policy: Some(e.commitment_policy),
        }
    }

    /// The encryption context to verify against the encrypted message.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// The keyring, if this input was built with one.
    #[must_use]
    pub const fn keyring(&self) -> Option<&SharedKeyring> {
        self.keyring.as_ref()
    }

    /// The CMM, if this input was built with one.
    #[must_use]
    pub const fn cmm(&self) -> Option<&SharedCmm> {
        self.cmm.as_ref()
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }

    /// The cap on the number of encrypted data keys, if one was set.
    #[must_use]
    pub const fn max_encrypted_data_keys(&self) -> Option<NonZeroUsize> {
        self.max_encrypted_data_keys
    }

    /// The commitment policy.
    #[must_use]
    pub const fn commitment_policy(&self) -> EsdkCommitmentPolicy {
        self.commitment_policy
    }
}

/// Fluent builder for [`DecryptStreamInput`].
#[derive(Debug, Clone, Default)]
pub struct DecryptStreamInputBuilder {
    encryption_context: Option<EncryptionContext>,
    keyring: Option<SharedKeyring>,
    cmm: Option<SharedCmm>,
    max_encrypted_data_keys: Option<NonZeroUsize>,
    commitment_policy: Option<EsdkCommitmentPolicy>,
}

impl DecryptStreamInputBuilder {
    /// Set the encryption context to verify against the encrypted message.
    /// If non-empty, `decrypt_stream` requires every entry to be present in the message's
    /// encryption context (subset check).
    /// Default is empty.
    #[must_use]
    pub fn encryption_context(mut self, ec: EncryptionContext) -> Self {
        self.encryption_context = Some(ec);
        self
    }

    /// Set the encryption context from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::encryption_context`].
    #[must_use]
    pub fn set_encryption_context(mut self, encryption_context: Option<EncryptionContext>) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// Set the keyring.
    /// Provide exactly one of a keyring or a CMM.
    #[must_use]
    pub fn keyring(mut self, keyring: impl Keyring + 'static) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// Set the keyring from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::keyring`].
    #[must_use]
    pub fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// Set the cryptographic materials manager (CMM).
    /// Provide exactly one of a keyring or a CMM.
    #[must_use]
    pub fn cmm(mut self, cmm: impl Cmm + 'static) -> Self {
        self.cmm = Some(cmm.into_shared());
        self
    }

    /// Set the CMM from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::cmm`].
    #[must_use]
    pub fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Set the maximum number of encrypted data keys.
    /// Default is no limit.
    ///
    /// Leave unset when calling [`Esdk::decrypt_stream`](crate::Esdk::decrypt_stream) — the client
    /// provides this.
    #[must_use]
    pub const fn max_encrypted_data_keys(mut self, n: NonZeroUsize) -> Self {
        self.max_encrypted_data_keys = Some(n);
        self
    }

    /// Set the maximum number of encrypted data keys from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::max_encrypted_data_keys`].
    #[must_use]
    pub const fn set_max_encrypted_data_keys(
        mut self,
        max_encrypted_data_keys: Option<NonZeroUsize>,
    ) -> Self {
        self.max_encrypted_data_keys = max_encrypted_data_keys;
        self
    }

    /// Set the commitment policy.
    /// Default is `EsdkCommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// Leave unset when calling [`Esdk::decrypt_stream`](crate::Esdk::decrypt_stream) — the client
    /// provides this.
    #[must_use]
    pub const fn commitment_policy(mut self, p: EsdkCommitmentPolicy) -> Self {
        self.commitment_policy = Some(p);
        self
    }

    /// Set the commitment policy from an `Option`.
    /// `None` leaves it unset.
    /// To set a value, use [`Self::commitment_policy`].
    #[must_use]
    pub const fn set_commitment_policy(
        mut self,
        commitment_policy: Option<EsdkCommitmentPolicy>,
    ) -> Self {
        self.commitment_policy = commitment_policy;
        self
    }

    /// Build the `DecryptStreamInput`.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if not exactly one of a keyring or CMM was set.
    pub fn build(self) -> Result<DecryptStreamInput, Error> {
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
