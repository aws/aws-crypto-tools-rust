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
//! [`std::error::Error::source`]. See for example
//! <https://github.com/awslabs/aws-sdk-rust/blob/v0.0.20-alpha/sdk/kms/src/error.rs>
//! where each KMS operation error is a struct with a `kind` field whose enum
//! variants enumerate the SDK-recognised failure categories. Customers
//! consuming the MPL want a SINGLE error type to filter on at the call site
//! (`match err.kind() { ... }` or `if matches!(err.kind(), ...)`), then drill
//! into the message for diagnostics. A separate `KeyringError`, `CmmError`,
//! `MaterialsValidationError` zoo would force the customer to either match on
//! a sum-of-sums or convert each into their own application error.

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
#[non_exhaustive]
pub struct MaterialsError {
    /// Categorisation of this error. Stable for matching at call sites.
    pub kind: MaterialsErrorKind,
    /// Free-form human-readable message describing this specific failure.
    pub message: String,
    /// The lower-level error that caused this error, if any. Exposed
    /// through [`std::error::Error::source`] so consumers can walk the
    /// error chain. Not compared by [`PartialEq`] because `dyn Error` does
    /// not implement [`Eq`].
    pub cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
    /// Every failure collected while attempting an operation that ultimately
    /// failed — for example, a keyring's `on_decrypt` trying each candidate
    /// encrypted data key.
    ///
    /// Non-empty exactly when this error aggregates others, which
    /// [`MaterialsError::is_collection`] reports.
    ///
    /// Keeping the failures typed here satisfies the specification's
    /// requirement that a keyring failing to decrypt any encrypted data key
    /// "MUST yield an error that includes all the collected errors", and lets
    /// a caller inspect each one. [`fmt::Display`] renders them from here, so
    /// `message` describes the overall failure alone.
    ///
    /// `cause` and `collected` answer different questions: `cause` is why
    /// *this* failure happened and chains through
    /// [`std::error::Error::source`]; `collected` is what was tried and how
    /// each attempt failed.
    pub collected: Vec<MaterialsError>,
}

impl PartialEq for MaterialsError {
    fn eq(&self, other: &Self) -> bool {
        // `cause` is excluded because `dyn Error` does not implement `Eq`.
        // `collected` is included: two aggregates that collected different
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

    /// Construct an error carrying every failure collected while attempting an
    /// operation that ultimately failed.
    ///
    /// `kind` is the category of the overall failure, not a statement about
    /// aggregation: a keyring that attempted keys and failed is
    /// `KeyringFailed`, while one whose every candidate was rejected by its
    /// own provider filter is `NoMatchingDataKey`.
    ///
    /// `collected` is expected to be non-empty; an empty `collected` yields an
    /// error that is not an aggregate, so an operation with nothing to report
    /// should use the plain constructor for its kind instead.
    ///
    /// `message` should describe the overall failure only — [`fmt::Display`]
    /// renders the collected errors from
    /// [`collected`](MaterialsError::collected).
    ///
    /// A single collected failure is also attached as the `cause`, so
    /// [`std::error::Error::source`] reaches it; with several there is no one
    /// failure to nominate and no `cause` is set. `collected` holds every
    /// failure either way.
    #[track_caller]
    pub fn collection(
        kind: MaterialsErrorKind,
        message: impl Into<String>,
        collected: Vec<MaterialsError>,
    ) -> Self {
        debug_assert!(
            !collected.is_empty(),
            "an aggregate must collect at least one failure; an operation with \
             nothing to report should use the plain constructor for its kind",
        );
        let cause = match collected.as_slice() {
            [only] => {
                Some(Arc::new(only.clone()) as Arc<dyn std::error::Error + Send + Sync + 'static>)
            }
            _ => None,
        };
        Self {
            kind,
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

    /// Whether this error aggregates other failures, as a keyring's
    /// `on_decrypt` does when every encrypted data key it examined produced a
    /// failure.
    ///
    /// Prefer this to inspecting [`collected`](MaterialsError::collected)
    /// directly. Collecting sub-errors does not change
    /// [`kind`](MaterialsError::kind): an aggregate can be a
    /// `NoMatchingDataKey` (every candidate was filtered out) as readily as a
    /// `KeyringFailed` (candidates were tried and failed).
    pub const fn is_collection(&self) -> bool {
        !self.collected.is_empty()
    }
}

impl fmt::Display for MaterialsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MaterialsError({:?}): {}", self.kind, self.message)?;
        // Rendered from `collected` so there is one representation of the
        // failures. A collected error renders in full, so an aggregate nested
        // inside an aggregate would nest this section.
        if let [first, rest @ ..] = self.collected.as_slice() {
            write!(f, " (collected errors: [{first}")?;
            for err in rest {
                write!(f, "; {err}")?;
            }
            f.write_str("])")?;
        }
        Ok(())
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
