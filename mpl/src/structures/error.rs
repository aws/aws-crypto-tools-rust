// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types for materials structures.
//!
//! # Why one `MaterialsError` (with a `kind`) instead of per-module errors
//!
//! The shape `struct MaterialsError { kind, message, cause }`
//! mirrors the AWS SDK for Rust's older operation-error convention — a public
//! `kind` enum carrying a categorisation, plus a free-form human-readable
//! message and an optional lower-level `cause` exposed through
//! [`std::error::Error::source`].

use std::fmt;
use std::sync::Arc;

/// Categorisation of a `MaterialsError`. New kinds may be added in minor
/// releases, hence `#[non_exhaustive]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MaterialsErrorKind {
    /// Construction- or invariant-validation failure on a structure type.
    /// Used by `EncryptionMaterials::new` / `DecryptionMaterials::new` /
    /// `EncryptionContext::new` / `BranchKeyMaterials::new`.
    Validation,
    /// A keyring's `on_encrypt` returned without attempting any of the
    /// `generate-data-key` or `encrypt-data-key` behaviors, OR a keyring's
    /// `on_decrypt` was called but the keyring chose not to attempt the
    /// `decrypt-data-key` behavior.
    NoBehaviorAttempted,
    /// Decrypt input materials already contain a plaintext data key, so the
    /// keyring fails per the OnDecrypt contract.
    PlaintextDataKeyAlreadyPresent,
    /// Keyring scanned the input EDK list and could not derive a plaintext
    /// data key from any entry. The decryption materials are NOT mutated.
    NoMatchingDataKey,
    /// Generic keyring-side failure (transport error, HSM unavailable,
    /// signature mismatch, etc.). The `message` field carries the cause.
    KeyringFailed,
    /// A required encryption context key declared by the request was not
    /// present in the encryption context the CMM produced (or, on decrypt,
    /// not present in the materials' encryption context). Traces to
    /// `cmm-interface.md#get-encryption-materials` /
    /// `cmm-interface.md#decrypt-materials`.
    RequiredEncryptionContextKeyMissing,
    /// The customer-supplied reproduced encryption context disagrees with
    /// the message's encryption context on a shared key. Traces to
    /// `cmm-interface.md#decrypt-materials`: "the values MUST be equal or
    /// the operation MUST fail".
    EncryptionContextValueMismatch,
    /// A signing-suite decrypt request had an encryption context that
    /// LACKED the reserved `aws-crypto-public-key` key. Traces to
    /// `cmm-interface.md#decrypt-materials` SHOULD-fail rule.
    AwsCryptoPublicKeyMissing,
    /// A non-signing-suite decrypt request had an encryption context that
    /// CONTAINED the reserved `aws-crypto-public-key` key. Traces to
    /// `cmm-interface.md#decrypt-materials` SHOULD-fail rule.
    AwsCryptoPublicKeyUnexpected,
}

/// Error type for materials structure construction, validation, and keyring
/// operations.
#[derive(Debug, Clone)]
pub struct MaterialsError {
    /// Categorisation of this error. Stable for matching at call sites.
    pub kind: MaterialsErrorKind,
    /// Free-form human-readable message describing this specific failure.
    pub message: String,
    /// The lower-level error that caused this error, if any. Exposed
    /// through [`std::error::Error::source`] so consumers can walk the
    /// error chain. Not compared by [`PartialEq`].
    pub cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
    /// Every error collected while attempting an operation that may fail
    /// several times before failing overall — a keyring's `on_decrypt`
    /// attempting each candidate encrypted data key, for instance. Empty for
    /// errors that describe a single failure.
    ///
    /// This exists because the specification requires that a keyring failing
    /// to decrypt any encrypted data key "MUST yield an error that includes
    /// all the collected errors", and a message built by formatting each
    /// error into a string cannot be inspected by a caller. Keeping the
    /// errors typed here is the same choice the Dafny implementation makes
    /// with its `CollectionOfErrors(list, message)` error variant.
    ///
    /// `cause` and `collected` answer different questions and are not
    /// alternatives: `cause` is why *this* failure happened and chains
    /// through [`std::error::Error::source`]; `collected` is what was tried
    /// and how each attempt failed. An aggregate over several failures has no
    /// single `cause` to nominate, so it carries only `collected`.
    pub collected: Vec<MaterialsError>,
}

impl PartialEq for MaterialsError {
    fn eq(&self, other: &Self) -> bool {
        // `cause` is excluded because `dyn Error` does not implement `Eq`.
        // `collected` is included: it is a `Vec<MaterialsError>`, so it
        // compares recursively, and two aggregates that collected different
        // failures are not the same error.
        self.kind == other.kind
            && self.message == other.message
            && self.collected == other.collected
    }
}
impl Eq for MaterialsError {}

impl MaterialsError {
    /// Shorthand for a `Validation` error — the kind produced by the
    /// structure constructors (`EncryptionMaterials::new`,
    /// `DecryptionMaterials::new`, `EncryptionContext::new`,
    /// `BranchKeyMaterials::new`) when an invariant check fails. For other
    /// categories, use the kind-specific constructors below
    /// (`no_behavior_attempted`, `keyring_failed`, `no_matching_data_key`,
    /// etc.).
    #[track_caller]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            kind: MaterialsErrorKind::Validation,
            message: message.into(),
            cause: None,
            collected: Vec::new(),
        }
    }

    /// Construct a `Validation` error that wraps a lower-level `cause`
    /// (e.g., a parse failure surfaced during structure validation). The
    /// wrapped cause is accessible via [`std::error::Error::source`].
    #[track_caller]
    pub fn new_with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind: MaterialsErrorKind::Validation,
            message: message.into(),
            cause: Some(Arc::new(cause)),
            collected: Vec::new(),
        }
    }

    /// Construct a `NoBehaviorAttempted` error.
    #[track_caller]
    pub fn no_behavior_attempted(context: impl Into<String>) -> Self {
        Self {
            kind: MaterialsErrorKind::NoBehaviorAttempted,
            message: context.into(),
            cause: None,
            collected: Vec::new(),
        }
    }

    /// Construct a `PlaintextDataKeyAlreadyPresent` error.
    #[track_caller]
    pub fn plaintext_data_key_already_present(context: impl Into<String>) -> Self {
        Self {
            kind: MaterialsErrorKind::PlaintextDataKeyAlreadyPresent,
            message: context.into(),
            cause: None,
            collected: Vec::new(),
        }
    }

    /// Construct a `NoMatchingDataKey` error.
    #[track_caller]
    pub fn no_matching_data_key(context: impl Into<String>) -> Self {
        Self {
            kind: MaterialsErrorKind::NoMatchingDataKey,
            message: context.into(),
            cause: None,
            collected: Vec::new(),
        }
    }

    /// Construct a `KeyringFailed` error.
    #[track_caller]
    pub fn keyring_failed(reason: impl Into<String>) -> Self {
        Self {
            kind: MaterialsErrorKind::KeyringFailed,
            message: reason.into(),
            cause: None,
            collected: Vec::new(),
        }
    }

    /// Construct a `KeyringFailed` error that wraps a lower-level `cause`
    /// (e.g., an HSM, KMS, or transport failure surfaced by an
    /// implementation of the keyring trait). The wrapped cause is
    /// accessible via [`std::error::Error::source`].
    #[track_caller]
    pub fn keyring_failed_with_cause(
        reason: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind: MaterialsErrorKind::KeyringFailed,
            message: reason.into(),
            cause: Some(Arc::new(cause)),
            collected: Vec::new(),
        }
    }

    /// Construct a `RequiredEncryptionContextKeyMissing` error.
    #[track_caller]
    pub fn required_encryption_context_key_missing(context: impl Into<String>) -> Self {
        Self {
            kind: MaterialsErrorKind::RequiredEncryptionContextKeyMissing,
            message: context.into(),
            cause: None,
            collected: Vec::new(),
        }
    }

    /// Construct an `EncryptionContextValueMismatch` error.
    #[track_caller]
    pub fn encryption_context_value_mismatch(context: impl Into<String>) -> Self {
        Self {
            kind: MaterialsErrorKind::EncryptionContextValueMismatch,
            message: context.into(),
            cause: None,
            collected: Vec::new(),
        }
    }

    /// Construct an `AwsCryptoPublicKeyMissing` error.
    #[track_caller]
    pub fn aws_crypto_public_key_missing(context: impl Into<String>) -> Self {
        Self {
            kind: MaterialsErrorKind::AwsCryptoPublicKeyMissing,
            message: context.into(),
            cause: None,
            collected: Vec::new(),
        }
    }

    /// Construct an `AwsCryptoPublicKeyUnexpected` error.
    #[track_caller]
    pub fn aws_crypto_public_key_unexpected(context: impl Into<String>) -> Self {
        Self {
            kind: MaterialsErrorKind::AwsCryptoPublicKeyUnexpected,
            message: context.into(),
            cause: None,
            collected: Vec::new(),
        }
    }

    /// Construct a `KeyringFailed` error carrying every error collected while
    /// attempting each candidate encrypted data key, for a keyring that failed
    /// to decrypt any of them.
    ///
    /// The collected errors stay typed and reachable through
    /// [`MaterialsError::collected`], so a caller can inspect why each attempt
    /// failed rather than parsing them back out of the message. `message`
    /// should still describe the overall failure, since that is what
    /// [`fmt::Display`] renders.
    ///
    /// When exactly one attempt failed there is an unambiguous cause, so that
    /// error is attached as the `cause` as well and
    /// [`std::error::Error::source`] reaches it — the idiomatic Rust access
    /// path for the common single-key case. With several failures there is no
    /// single one to nominate, so no `cause` is set and `collected` is the only
    /// way in. Either way `collected` holds every failure, so a caller does not
    /// have to branch on the count to find them.
    #[track_caller]
    pub fn keyring_failed_collection(
        message: impl Into<String>,
        collected: Vec<MaterialsError>,
    ) -> Self {
        let cause = match collected.as_slice() {
            [only] => {
                Some(Arc::new(only.clone()) as Arc<dyn std::error::Error + Send + Sync + 'static>)
            }
            _ => None,
        };
        Self {
            kind: MaterialsErrorKind::KeyringFailed,
            message: message.into(),
            cause,
            collected,
        }
    }

    /// Borrow the categorisation of this error.
    pub const fn kind(&self) -> &MaterialsErrorKind {
        &self.kind
    }

    /// Borrow the errors collected while attempting an operation that failed
    /// several times. Empty unless this error aggregates other failures — see
    /// [`MaterialsError::collected`].
    pub fn collected_errors(&self) -> &[MaterialsError] {
        &self.collected
    }
}

impl fmt::Display for MaterialsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MaterialsError({:?}): {}", self.kind, self.message)
    }
}

impl std::error::Error for MaterialsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Some(cause) => Some(cause.as_ref()),
            None => None,
        }
    }
}
