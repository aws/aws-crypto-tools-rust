// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypted data key structure.

/// An encrypted data key comprised of provider ID, provider info, and ciphertext.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedDataKey {
    /// UTF-8 key provider identifier.
    ///
    /// The MUST-be-binary half of the spec citation below is satisfied by
    /// construction — Rust's `String` is a UTF-8 byte sequence. The
    /// SHOULD-equal-namespace half is concrete-keyring scope (each concrete
    /// keyring chooses the value when constructing the EDK).
    pub key_provider_id: String,
    /// Opaque key provider information bytes.
    ///
    /// The MUST-be-binary half of the spec citation below is satisfied by
    /// construction — `Vec<u8>` is a binary byte sequence. The
    /// SHOULD-equal-name half is concrete-keyring scope (each concrete
    /// keyring chooses the value when constructing the EDK).
    pub key_provider_info: Vec<u8>,
    /// Opaque ciphertext bytes.
    pub ciphertext: Vec<u8>,
}

impl EncryptedDataKey {
    /// Create a new encrypted data key.
    pub fn new(key_provider_id: String, key_provider_info: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            key_provider_id,
            key_provider_info,
            ciphertext,
        }
    }
}
