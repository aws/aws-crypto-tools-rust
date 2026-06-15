// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypted data key structure.

/// An encrypted data key comprised of provider ID, provider info, and ciphertext.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedDataKey {
    /// UTF-8 key provider identifier.
    pub key_provider_id: String,
    /// Opaque key provider information bytes.
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
