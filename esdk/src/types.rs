// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Public API types for encrypt and decrypt operations.

use crate::Error;
use crate::val_err;
// TODO replace these with the new crate we write
use aws_mpl_legacy::CryptographicMaterialsManagerRef;
use aws_mpl_legacy::KeyringRef;
use aws_mpl_legacy::dafny::types::cryptographic_materials_manager::CryptographicMaterialsManagerRef as LegacyCMM;
use aws_mpl_legacy::dafny::types::keyring::KeyringRef as LegacyKeyring;
use std::num::NonZeroUsize;

/// A keyring supplied to an encrypt or decrypt operation.
///
/// Use [`Keyring::Modern`] for the higher-level `aws_mpl_legacy::KeyringRef`
/// wrapper, or [`Keyring::Legacy`] for the Dafny-generated MPL keyring ref.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Keyring {
    /// Legacy keyring, i.e. `aws_mpl_legacy::dafny::types::keyring::KeyringRef`
    Legacy(LegacyKeyring),
    /// Keyring, i.e. `aws_mpl_legacy::KeyringRef`
    Modern(KeyringRef),
}

/// A cryptographic materials manager (CMM) supplied to an encrypt or decrypt operation.
///
/// Use [`Cmm::Modern`] for the higher-level
/// `aws_mpl_legacy::CryptographicMaterialsManagerRef` wrapper, or
/// [`Cmm::Legacy`] for the Dafny-generated MPL CMM ref.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Cmm {
    /// Legacy CMM, i.e. `aws_mpl_legacy::dafny::types::cryptographic_materials_manager::CryptographicMaterialsManagerRef`
    Legacy(LegacyCMM),
    /// CMM, i.e. `aws_mpl_legacy::CryptographicMaterialsManagerRef`
    Modern(CryptographicMaterialsManagerRef),
}

impl PartialEq for Keyring {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Modern(x), Self::Modern(y)) => {
                std::ptr::addr_eq(std::sync::Arc::as_ptr(x), std::sync::Arc::as_ptr(y))
            }
            (Self::Legacy(x), Self::Legacy(y)) => x == y,
            _ => false,
        }
    }
}
impl Eq for Keyring {}

impl PartialEq for Cmm {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Modern(x), Self::Modern(y)) => {
                std::ptr::addr_eq(std::sync::Arc::as_ptr(x), std::sync::Arc::as_ptr(y))
            }
            (Self::Legacy(x), Self::Legacy(y)) => x == y,
            _ => false,
        }
    }
}
impl Eq for Cmm {}

impl From<LegacyKeyring> for Keyring {
    fn from(keyring: LegacyKeyring) -> Self {
        Self::Legacy(keyring)
    }
}
impl From<KeyringRef> for Keyring {
    fn from(keyring: KeyringRef) -> Self {
        Self::Modern(keyring)
    }
}
impl From<LegacyCMM> for Cmm {
    fn from(cmm: LegacyCMM) -> Self {
        Self::Legacy(cmm)
    }
}
impl From<CryptographicMaterialsManagerRef> for Cmm {
    fn from(cmm: CryptographicMaterialsManagerRef) -> Self {
        Self::Modern(cmm)
    }
}

/// Internal union of the four ways a caller can supply materials, resolved from
/// the `keyring` / `cmm` input fields and consumed by `create_cmm_from_input`.
#[derive(Debug, Clone)]
pub(crate) enum MaterialSource {
    LegacyCmm(LegacyCMM),
    LegacyKeyring(LegacyKeyring),
    Cmm(CryptographicMaterialsManagerRef),
    Keyring(KeyringRef),
}

/// Resolve the caller-supplied `keyring` / `cmm` fields into the internal
/// [`MaterialSource`], or `None` if not exactly one is set.
pub(crate) fn resolve_material_source(
    keyring: Option<&Keyring>,
    cmm: Option<&Cmm>,
) -> Option<MaterialSource> {
    match (keyring, cmm) {
        (Some(Keyring::Legacy(k)), None) => Some(MaterialSource::LegacyKeyring(k.clone())),
        (Some(Keyring::Modern(k)), None) => Some(MaterialSource::Keyring(k.clone())),
        (None, Some(Cmm::Legacy(c))) => Some(MaterialSource::LegacyCmm(c.clone())),
        (None, Some(Cmm::Modern(c))) => Some(MaterialSource::Cmm(c.clone())),
        _ => None,
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The length of one frame, must be non-zero, defaults to 4096.
//= spec/data-format/message-body.md#framed-data
//= reason=NonZeroU32 max value is u32::MAX = 2^32 - 1
//# - The total bytes allowed in a single frame MUST be less than or equal to `2^32 - 1`.
#[expect(clippy::exhaustive_structs)]
pub struct FrameLength(pub std::num::NonZeroU32);

impl Default for FrameLength {
    fn default() -> Self {
        //= spec/client-apis/encrypt.md#frame-length
        //# This value MUST default to 4096 bytes.
        // Safety: 4096 is a non-zero literal
        Self(std::num::NonZeroU32::new(4096).expect("4096 is non-zero"))
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
            std::num::NonZeroU32::new(val)
                .ok_or_else(|| val_err("Frame length must be non-zero"))?,
        ))
    }
}

/// Convenience constructor for a `MaterialProviders` library client.
///
/// Most call sites that need an MPL client (e.g. building a keyring) can
/// use this rather than re-deriving the `MaterialProvidersConfig` builder.
///
/// # Panics
/// Panics if the `MaterialProviders` client cannot be constructed.
#[must_use]
pub fn mpl() -> aws_mpl_legacy::dafny::client::Client {
    aws_mpl_legacy::dafny::client::Client::from_conf(
        aws_mpl_legacy::dafny::types::MaterialProvidersConfig::builder()
            .build()
            .unwrap(),
    )
    .unwrap()
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
pub use aws_mpl_legacy::suites::EsdkAlgorithmSuiteId;

/// Commitment policies governing key commitment behavior.
pub use aws_mpl_legacy::commitment::EsdkCommitmentPolicy;

/// Key-Value pairs to associate with the encrypted data
pub use aws_mpl_legacy::EncryptionContext;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
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
impl EncryptOutput {
    /// Create default `EncryptOutput`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
/// Output for [`encrypt_stream`](crate::encrypt_stream).
pub struct EncryptStreamOutput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub algorithm_suite_id: EsdkAlgorithmSuiteId,
    /// Encryption context associated with the encrypted message.
    pub encryption_context: EncryptionContext,
}
impl EncryptStreamOutput {
    /// Create default `EncryptStreamOutput`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
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
impl DecryptOutput {
    /// Create default `DecryptOutput`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
/// Output for [`decrypt_stream`](crate::decrypt_stream).
pub struct DecryptStreamOutput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub algorithm_suite_id: EsdkAlgorithmSuiteId,
    /// Encryption context recovered from the encrypted message.
    pub encryption_context: EncryptionContext,
}
impl DecryptStreamOutput {
    /// Create default `DecryptStreamOutput`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
/// Input for [`encrypt`](crate::encrypt).
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
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [Algorithm Suite](#algorithm-suite) argument.
    pub algorithm_suite_id: Option<EsdkAlgorithmSuiteId>,
    /// Key-Value pairs to associate with the encrypted data
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
    pub encryption_context: EncryptionContext,
    /// Bytes of plaintext data per frame. Default 4096.
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [Frame Length](#frame-length) argument.
    pub frame_length: FrameLength,
    /// The keyring to use for this operation. Provide exactly one of `keyring` or `cmm`.
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [keyring](../framework/keyring-interface.md) argument.
    pub keyring: Option<Keyring>,
    /// The cryptographic materials manager (CMM) to use for this operation.
    /// Provide exactly one of `keyring` or `cmm`.
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept an optional [cryptographic Materials Manager (CMM)](../framework/cmm-interface.md) argument.
    pub cmm: Option<Cmm>,
    /// data to be encrypted
    //= spec/client-apis/encrypt.md#input
    //# - Encrypt operation input MUST accept a required [plaintext](#plaintext) argument.
    //
    //= spec/client-apis/encrypt.md#plaintext
    //= type=implication
    //= reason=&[u8] is a sequence of bytes by definition
    //# This MUST be a sequence of bytes.
    pub plaintext: &'a [u8],
    /// Default is no limit
    //= spec/client-apis/client.md#initialization
    //# - On client initialization,
    //# the caller MUST have the option to provide a [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys).
    //
    //= spec/client-apis/client.md#initialization
    //# If no [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys) is provided
    //# the default MUST result in no limit on the number of encrypted data keys (aside from the limit imposed by the [message format](../format/message-header.md)).
    /// Default is no limit on the number of encrypted data keys.
    ///
    /// Leave as `None` when calling [`Esdk::encrypt`](crate::Esdk::encrypt) — the client provides this.
    pub max_encrypted_data_keys: Option<NonZeroUsize>,
    /// Default is `EsdkCommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// Leave at the default when calling [`Esdk::encrypt`](crate::Esdk::encrypt) — the client provides this.
    //= spec/client-apis/client.md#commitment-policy
    //= reason=commitment_policy field type is EsdkCommitmentPolicy from aws_mpl_legacy
    //# The AWS Encryption SDK MUST use the ESDK [commitment policies](../framework/commitment-policy.md) defined in the Material Providers Library.
    //
    //= spec/client-apis/client.md#initialization
    //= reason=EsdkCommitmentPolicy::default() returns RequireEncryptRequireDecrypt; EncryptInput uses #[derive(Default)]
    //# If no [commitment policy](#commitment-policy) is provided the default MUST be [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../framework/algorithm-suites.md#require_encrypt_require_decrypt).
    //
    //= spec/client-apis/client.md#initialization
    //= type=implication
    //= reason=encrypt()/decrypt() take &EncryptInput/&DecryptInput; the policy cannot be mutated through a shared reference
    //# Once a [commitment policy](#commitment-policy) has been set it SHOULD be immutable.
    //
    //= spec/client-apis/client.md#initialization
    //# - On client initialization,
    //# the caller MUST have the option to provide a [commitment policy](#commitment-policy).
    pub commitment_policy: EsdkCommitmentPolicy,
}

impl<'a> EncryptInput<'a> {
    /// Create default `EncryptInput`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Construct an `EncryptInput` with a legacy `CryptographicMaterialsManagerRef`
    #[must_use]
    pub fn with_legacy_cmm(plaintext: &'a [u8], ec: EncryptionContext, cmm: LegacyCMM) -> Self {
        Self {
            plaintext,
            encryption_context: ec,
            cmm: Some(Cmm::Legacy(cmm)),
            ..Default::default()
        }
    }
    /// Construct an `EncryptInput` with a legacy `KeyringRef`
    #[must_use]
    pub fn with_legacy_keyring(
        plaintext: &'a [u8],
        ec: EncryptionContext,
        keyring: LegacyKeyring,
    ) -> Self {
        Self {
            plaintext,
            encryption_context: ec,
            keyring: Some(Keyring::Legacy(keyring)),
            ..Default::default()
        }
    }
    /// Construct an `EncryptInput` with a `CryptographicMaterialsManagerRef`
    #[must_use]
    pub fn with_cmm(
        plaintext: &'a [u8],
        ec: EncryptionContext,
        cmm: CryptographicMaterialsManagerRef,
    ) -> Self {
        Self {
            plaintext,
            encryption_context: ec,
            cmm: Some(Cmm::Modern(cmm)),
            ..Default::default()
        }
    }
    /// Construct an `EncryptInput` with a `KeyringRef`
    #[must_use]
    pub fn with_keyring(plaintext: &'a [u8], ec: EncryptionContext, keyring: KeyringRef) -> Self {
        Self {
            plaintext,
            encryption_context: ec,
            keyring: Some(Keyring::Modern(keyring)),
            ..Default::default()
        }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        //= spec/client-apis/encrypt.md#input
        //# The Encrypt operation MUST validate that exactly one keyring or CMM was provided by the caller.
        match (self.keyring.is_some(), self.cmm.is_some()) {
            (true, false) | (false, true) => Ok(()),
            _ => {
                //= spec/client-apis/encrypt.md#input
                //# If the caller does not provide exactly one of a keyring or CMM, the Encrypt operation MUST fail.
                Err(val_err("Exactly one of a keyring or CMM must be provided"))
            }
        }
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
/// Input for [`encrypt_stream`](crate::encrypt_stream).
pub struct EncryptStreamInput {
    /// Algorithm Suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    pub algorithm_suite_id: Option<EsdkAlgorithmSuiteId>,
    /// Key-Value pairs to associate with the encrypted data
    pub encryption_context: EncryptionContext,
    /// Bytes of plaintext data per frame. Default 4096.
    pub frame_length: FrameLength,
    /// The keyring to use for this operation. Provide exactly one of `keyring` or `cmm`.
    pub keyring: Option<Keyring>,
    /// The cryptographic materials manager (CMM) to use for this operation.
    /// Provide exactly one of `keyring` or `cmm`.
    pub cmm: Option<Cmm>,
    /// Optional expected size of the input plaintext stream.
    ///
    /// Most CMMs and keyrings ignore this; provide it only when the configured
    /// CMM or keyring requires the plaintext length up front (e.g. for a
    /// signing scheme that pre-computes a digest size).
    //= spec/client-apis/encrypt.md#input
    //= reason=EncryptStreamInput accepts unknown-length plaintext via a stream; data_size serves as the optional Plaintext Length Bound
    //# If the [plaintext](#plaintext) is of unknown length, the caller MAY also input a
    //# [Plaintext Length Bound](#plaintext-length-bound).
    pub data_size: Option<usize>,
    /// Default is no limit on the number of encrypted data keys.
    ///
    /// Leave as `None` when calling [`Esdk::encrypt`](crate::Esdk::encrypt) — the client provides this.
    pub max_encrypted_data_keys: Option<NonZeroUsize>,
    /// Default is `EsdkCommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// Leave at the default when calling [`Esdk::encrypt`](crate::Esdk::encrypt) — the client provides this.
    pub commitment_policy: EsdkCommitmentPolicy,
}

impl EncryptStreamInput {
    /// Create default `EncryptStreamInput`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Construct an `EncryptStreamInput` with a legacy `CryptographicMaterialsManagerRef`
    #[must_use]
    pub fn with_legacy_cmm(ec: EncryptionContext, cmm: LegacyCMM) -> Self {
        Self {
            encryption_context: ec,
            cmm: Some(Cmm::Legacy(cmm)),
            ..Default::default()
        }
    }
    /// Construct an `EncryptStreamInput` with a legacy `KeyringRef`
    #[must_use]
    pub fn with_legacy_keyring(ec: EncryptionContext, keyring: LegacyKeyring) -> Self {
        Self {
            encryption_context: ec,
            keyring: Some(Keyring::Legacy(keyring)),
            ..Default::default()
        }
    }
    /// Construct an `EncryptStreamInput` with a `CryptographicMaterialsManagerRef`
    #[must_use]
    pub fn with_cmm(ec: EncryptionContext, cmm: CryptographicMaterialsManagerRef) -> Self {
        Self {
            encryption_context: ec,
            cmm: Some(Cmm::Modern(cmm)),
            ..Default::default()
        }
    }
    /// Construct an `EncryptStreamInput` with a `KeyringRef`
    #[must_use]
    pub fn with_keyring(ec: EncryptionContext, keyring: KeyringRef) -> Self {
        Self {
            encryption_context: ec,
            keyring: Some(Keyring::Modern(keyring)),
            ..Default::default()
        }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        match (self.keyring.is_some(), self.cmm.is_some()) {
            (true, false) | (false, true) => Ok(()),
            _ => Err(val_err("Exactly one of a keyring or CMM must be provided")),
        }
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
/// Input for [`decrypt`](crate::decrypt).
pub struct DecryptInput<'a> {
    /// Encrypted message bytes (the serialized AWS Encryption SDK message) to decrypt.
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept a required [Encrypted Message](#encrypted-message) argument.
    //
    //= spec/client-apis/decrypt.md#encrypted-message
    //# The input encrypted message MUST be a sequence of bytes in the
    //# [message format](../data-format/message.md) specified by the AWS Encryption SDK.
    pub ciphertext: &'a [u8],
    /// Optional encryption context to verify against the encrypted message.
    /// If non-empty, decrypt requires every entry to be present in the message's
    /// encryption context (subset check).
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
    pub encryption_context: EncryptionContext,
    /// The keyring to use for this operation. Provide exactly one of `keyring` or `cmm`.
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept an optional [Keyring](../framework/keyring-interface.md) argument.
    pub keyring: Option<Keyring>,
    /// The cryptographic materials manager (CMM) to use for this operation.
    /// Provide exactly one of `keyring` or `cmm`.
    //= spec/client-apis/decrypt.md#input
    //# - Decrypt operation input MUST accept an optional [Cryptographic Materials Manager (CMM)](../framework/cmm-interface.md) argument.
    pub cmm: Option<Cmm>,
    /// Default is no limit on the number of encrypted data keys.
    ///
    /// Leave as `None` when calling [`Esdk::decrypt`](crate::Esdk::decrypt) — the client provides this.
    pub max_encrypted_data_keys: Option<NonZeroUsize>,
    /// Default is `EsdkCommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// Leave at the default when calling [`Esdk::decrypt`](crate::Esdk::decrypt) — the client provides this.
    pub commitment_policy: EsdkCommitmentPolicy,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
/// Input for [`decrypt_stream`](crate::decrypt_stream).
pub struct DecryptStreamInput {
    /// Optional encryption context to verify against the encrypted message.
    /// If non-empty, `decrypt_stream` requires every entry to be present in the
    /// message's encryption context (subset check).
    pub encryption_context: EncryptionContext,
    /// The keyring to use for this operation. Provide exactly one of `keyring` or `cmm`.
    pub keyring: Option<Keyring>,
    /// The cryptographic materials manager (CMM) to use for this operation.
    /// Provide exactly one of `keyring` or `cmm`.
    pub cmm: Option<Cmm>,
    /// Default is no limit on the number of encrypted data keys.
    ///
    /// Leave as `None` when calling [`Esdk::decrypt_stream`](crate::Esdk::decrypt_stream) — the client provides this.
    pub max_encrypted_data_keys: Option<NonZeroUsize>,
    /// Default is `EsdkCommitmentPolicy::RequireEncryptRequireDecrypt`.
    ///
    /// Leave at the default when calling [`Esdk::decrypt_stream`](crate::Esdk::decrypt_stream) — the client provides this.
    pub commitment_policy: EsdkCommitmentPolicy,
}

impl<'a> DecryptInput<'a> {
    /// Create default `DecryptInput`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Construct a `DecryptInput` with a legacy `CryptographicMaterialsManagerRef`
    #[must_use]
    pub fn with_legacy_cmm(ciphertext: &'a [u8], ec: EncryptionContext, cmm: LegacyCMM) -> Self {
        Self {
            ciphertext,
            encryption_context: ec,
            cmm: Some(Cmm::Legacy(cmm)),
            ..Default::default()
        }
    }
    /// Construct a `DecryptInput` with a legacy `KeyringRef`
    #[must_use]
    pub fn with_legacy_keyring(
        ciphertext: &'a [u8],
        ec: EncryptionContext,
        keyring: LegacyKeyring,
    ) -> Self {
        Self {
            ciphertext,
            encryption_context: ec,
            keyring: Some(Keyring::Legacy(keyring)),
            ..Default::default()
        }
    }
    /// Construct a `DecryptInput` with a `CryptographicMaterialsManagerRef`
    #[must_use]
    pub fn with_cmm(
        ciphertext: &'a [u8],
        ec: EncryptionContext,
        cmm: CryptographicMaterialsManagerRef,
    ) -> Self {
        Self {
            ciphertext,
            encryption_context: ec,
            cmm: Some(Cmm::Modern(cmm)),
            ..Default::default()
        }
    }
    /// Construct a `DecryptInput` with a `KeyringRef`
    #[must_use]
    pub fn with_keyring(ciphertext: &'a [u8], ec: EncryptionContext, keyring: KeyringRef) -> Self {
        Self {
            ciphertext,
            encryption_context: ec,
            keyring: Some(Keyring::Modern(keyring)),
            ..Default::default()
        }
    }

    /// Construct a `DecryptInput` from an `EncryptInput`
    #[must_use]
    pub fn from_encrypt(ciphertext: &'a [u8], e: &EncryptInput<'_>) -> Self {
        Self {
            ciphertext,
            encryption_context: e.encryption_context.clone(),
            keyring: e.keyring.clone(),
            cmm: e.cmm.clone(),
            commitment_policy: e.commitment_policy,
            max_encrypted_data_keys: e.max_encrypted_data_keys,
            ..Default::default()
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        //= spec/client-apis/decrypt.md#input
        //# The Decrypt operation MUST validate that exactly one of a keyring or CMM was provided by the caller.
        match (self.keyring.is_some(), self.cmm.is_some()) {
            (true, false) | (false, true) => Ok(()),
            _ => {
                //= spec/client-apis/decrypt.md#input
                //# If the caller does not provide exactly one of a keyring or CMM, the Decrypt operation MUST fail.
                Err(val_err("Exactly one of a keyring or CMM must be provided"))
            }
        }
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }
}

impl DecryptStreamInput {
    /// Create default `DecryptStreamInput`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Construct a `DecryptStreamInput` with a legacy `CryptographicMaterialsManagerRef`
    #[must_use]
    pub fn with_legacy_cmm(ec: EncryptionContext, cmm: LegacyCMM) -> Self {
        Self {
            encryption_context: ec,
            cmm: Some(Cmm::Legacy(cmm)),
            ..Default::default()
        }
    }
    /// Construct a `DecryptStreamInput` with a legacy `KeyringRef`
    #[must_use]
    pub fn with_legacy_keyring(ec: EncryptionContext, keyring: LegacyKeyring) -> Self {
        Self {
            encryption_context: ec,
            keyring: Some(Keyring::Legacy(keyring)),
            ..Default::default()
        }
    }
    /// Construct a `DecryptStreamInput` with a `CryptographicMaterialsManagerRef`
    #[must_use]
    pub fn with_cmm(ec: EncryptionContext, cmm: CryptographicMaterialsManagerRef) -> Self {
        Self {
            encryption_context: ec,
            cmm: Some(Cmm::Modern(cmm)),
            ..Default::default()
        }
    }
    /// Construct a `DecryptStreamInput` with a `KeyringRef`
    #[must_use]
    pub fn with_keyring(ec: EncryptionContext, keyring: KeyringRef) -> Self {
        Self {
            encryption_context: ec,
            keyring: Some(Keyring::Modern(keyring)),
            ..Default::default()
        }
    }

    /// Construct a `DecryptStreamInput` from an `EncryptInput`
    #[must_use]
    pub fn from_encrypt(e: &EncryptInput<'_>) -> Self {
        Self {
            encryption_context: e.encryption_context.clone(),
            keyring: e.keyring.clone(),
            cmm: e.cmm.clone(),
            commitment_policy: e.commitment_policy,
            max_encrypted_data_keys: e.max_encrypted_data_keys,
            ..Default::default()
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        match (self.keyring.is_some(), self.cmm.is_some()) {
            (true, false) | (false, true) => Ok(()),
            _ => Err(val_err("Exactly one of a keyring or CMM must be provided")),
        }
    }

    pub(crate) fn material_source(&self) -> Option<MaterialSource> {
        resolve_material_source(self.keyring.as_ref(), self.cmm.as_ref())
    }
}
