// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypted data key structure.

/// An encrypted data key comprised of provider ID, provider info, and ciphertext.
///
//= ../spec/framework/structures.md#ciphertext
//= type=exception
//= reason=Key provider responsibility; not enforceable from the holder type. The struct stores the opaque ciphertext bytes; deterministic recovery is the key provider's contract.
//# Some key provider MUST be capable of deterministically obtaining the plaintext key from the ciphertext.
//
//= ../spec/framework/structures.md#structure
//= type=exception
//= reason=Editorial clause about terminology; no behavior to implement.
//# This specification uses the terms "encrypt" and "decrypt" for simplicity,
//# but the actual process by which a key provider obtains the plaintext data key from the ciphertext
//# and vice versa MAY be any reversible operation, though we expect that most will use encryption.
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
