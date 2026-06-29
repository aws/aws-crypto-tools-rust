// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The crate-wide error type for the native DB-ESDK item encryptor.

use std::fmt;

/// An error raised while configuring a client or encrypting / decrypting an item.
///
/// The TestServer adapter maps configuration / encrypt / decrypt failures to the
/// modeled `DBESDKClientError` and framework failures to `GenericServerError`;
/// this single type carries a human-readable message for either path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbEsdkError {
    /// The supplied configuration was rejected (e.g. an unsupported keyring,
    /// a key attribute marked for encryption, or a bad wrapping-key length).
    Config(String),

    /// An item (or key) was structurally invalid for the requested operation
    /// (e.g. a key attribute had the wrong action, or a stored item was missing
    /// the header / footer needed to decrypt it).
    InvalidItem(String),

    /// A cryptographic operation failed (key wrap/unwrap, AES-GCM seal/open,
    /// key derivation, or signature verification). Carries no key material.
    Crypto(String),
}

impl DbEsdkError {
    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub(crate) fn invalid_item(message: impl Into<String>) -> Self {
        Self::InvalidItem(message.into())
    }

    pub(crate) fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }

    /// Construct an error from an external keyring / intermediate-key provider
    /// (e.g. an AWS KMS `GenerateDataKey` / `Decrypt` failure). Available to
    /// [`crate::format::IntermediateKeyProvider`] implementations defined
    /// outside this crate; it maps to the [`DbEsdkError::Crypto`] variant.
    pub fn provider(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }
}

impl fmt::Display for DbEsdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "invalid DB-ESDK configuration: {m}"),
            Self::InvalidItem(m) => write!(f, "invalid item: {m}"),
            Self::Crypto(m) => write!(f, "cryptographic operation failed: {m}"),
        }
    }
}

impl std::error::Error for DbEsdkError {}

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, DbEsdkError>;
