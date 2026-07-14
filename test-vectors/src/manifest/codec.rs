// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Base64 helpers for the byte-valued fields of manifests.
//!
//! The manifest format stores all raw bytes (plaintext data keys, provider
//! info, encrypted data key ciphertexts, …) as standard-alphabet base64
//! strings. These helpers wrap the `base64` crate with our error type so
//! project generators do not repeat the boilerplate.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::error::{Result, TestVectorError};

/// Encode raw bytes using the standard base64 alphabet.
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes.as_ref())
}

/// Decode a base64-encoded string using the standard alphabet.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(input)
        .map_err(|e| TestVectorError::other(format!("invalid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_matches_expected_output() {
        assert_eq!(encode(b"hello"), "aGVsbG8=");
        assert_eq!(encode([0u8; 0]), "");
    }

    #[test]
    fn decode_round_trips() {
        let raw = b"the quick brown fox";
        assert_eq!(decode(&encode(raw)).unwrap(), raw);
    }

    #[test]
    fn decode_rejects_invalid_input() {
        assert!(decode("not@@@valid").is_err());
    }
}
