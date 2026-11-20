// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Types that the DB-ESDK configuration and operations take.

pub use aws_crypto_mpl::types::{
    AesWrappingAlg, EncryptedDataKey, EncryptionContext, PaddingScheme,
};

/// A DB-ESDK algorithm suite.
///
/// The DB-ESDK uses only the Material Providers Library's DBE suites.
/// The default signs each item with both ECDSA P-384 and HMAC-SHA-384:
/// [`AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384`](AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384).
pub use aws_crypto_mpl::types::DbeAlgorithmSuiteId as AlgorithmSuiteId;

/// What to do with an attribute when encrypting an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CryptoAction {
    /// Encrypt the attribute, and include it in the signature.
    EncryptAndSign,
    /// Leave the attribute readable, and include it in the signature.
    SignOnly,
    /// Leave the attribute readable, include it in the signature,
    /// and bind its value into the encryption context.
    ///
    /// When any attribute has this action, the partition and sort keys must have it too.
    SignAndIncludeInEncryptionContext,
    /// Leave the attribute readable and unsigned.
    ///
    /// The table config must allow the attribute to be unsigned, with
    /// [`allowed_unsigned_attributes`](crate::TableConfigBuilder::allowed_unsigned_attributes) or
    /// [`allowed_unsigned_attribute_prefix`](crate::TableConfigBuilder::allowed_unsigned_attribute_prefix).
    DoNothing,
}

/// Whether an item encryptor writes and reads plaintext items,
/// for migrating a plaintext table to client-side encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PlaintextOverride {
    /// Write every item as plaintext; read both plaintext and encrypted items.
    ForcePlaintextWriteAllowPlaintextRead,
    /// Encrypt every item; read both plaintext and encrypted items.
    ForbidPlaintextWriteAllowPlaintextRead,
    /// Encrypt every item; read only encrypted items (the default).
    #[default]
    ForbidPlaintextWriteForbidPlaintextRead,
}
