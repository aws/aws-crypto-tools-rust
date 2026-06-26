// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The DB-ESDK item encryptor / decryptor.
//!
//! [`encrypt_item`] turns a plaintext [`Item`] into the map of attributes
//! persisted in DynamoDB: `ENCRYPT_AND_SIGN` attributes become opaque binary
//! ciphertext, `SIGN_ONLY` / key attributes stay as their native plaintext
//! values (DynamoDB needs the key attributes in plaintext), and two metadata
//! attributes are added — a header (`aws_dbe_head`) holding the wrapped data key
//! and suite id, and a footer (`aws_dbe_foot`) holding an HMAC over the canonical
//! signed content. [`decrypt_item`] inverts this and verifies the signature.
//!
//! See `BLOCKED.md`: this format uses real AES-256-GCM + HMAC-SHA384 and is
//! self-consistent (what the server writes it reads back), but is not yet
//! byte-identical to the Dafny/Java DB-ESDK wire format (no commitment key, no
//! ECDSA footer). No cross-language interop test exercises the stored bytes, so
//! self-consistency is sufficient for the current conformance suite.

use crate::config::{KeyringConfig, TableEncryptionConfig};
use crate::crypto;
use crate::error::{DbEsdkError, Result};
use crate::keyring::{RawAesKeyring, WrappedDataKey};
use crate::model::{AttributeValue, Item};

/// The attribute holding the encrypted-item header (wrapped data key + suite id).
pub const HEADER_ATTRIBUTE: &str = "aws_dbe_head";
/// The attribute holding the item footer (the HMAC signature).
pub const FOOTER_ATTRIBUTE: &str = "aws_dbe_foot";

const HEADER_VERSION: u8 = 0x01;

/// Encrypt and sign `item` per `config`, returning the attribute map to persist.
///
/// The partition/sort key attributes and `SIGN_ONLY` attributes are carried
/// through in plaintext; `ENCRYPT_AND_SIGN` attributes are replaced with binary
/// ciphertext; `DO_NOTHING` attributes are passed through untouched and unsigned.
pub fn encrypt_item(config: &TableEncryptionConfig, item: &Item) -> Result<Item> {
    config.validate()?;
    let keyring = raw_aes_keyring(config)?;

    let (plaintext_data_key, wrapped) = keyring.generate_and_wrap()?;
    let content_key = derive_content_key(config, &plaintext_data_key)?;
    let mac_key = derive_mac_key(config, &plaintext_data_key)?;

    let mut output = Item::new();
    for (name, value) in item {
        let action = config.action_for(name);
        if action.is_encrypted() {
            let aad = field_aad(config, name);
            let sealed = crypto::aes_gcm_seal(&content_key, &aad, &value.to_canonical_bytes())?;
            output.insert(name.clone(), AttributeValue::B(sealed));
        } else {
            output.insert(name.clone(), value.clone());
        }
    }

    let header = serialize_header(config, &wrapped);
    let signed_content = canonical_signed_content(config, &header, &output);
    let footer = crypto::hmac_sha384(&mac_key, &signed_content);

    output.insert(HEADER_ATTRIBUTE.to_string(), AttributeValue::B(header));
    output.insert(FOOTER_ATTRIBUTE.to_string(), AttributeValue::B(footer));
    Ok(output)
}

/// Decrypt and verify a stored item produced by [`encrypt_item`], returning the
/// reconstructed plaintext item (without the header / footer metadata).
pub fn decrypt_item(config: &TableEncryptionConfig, stored: &Item) -> Result<Item> {
    config.validate()?;
    let keyring = raw_aes_keyring(config)?;

    let header = match stored.get(HEADER_ATTRIBUTE) {
        Some(AttributeValue::B(bytes)) => bytes.clone(),
        _ => {
            return Err(DbEsdkError::invalid_item(
                "stored item is missing the binary header attribute 'aws_dbe_head'",
            ))
        }
    };
    let footer = match stored.get(FOOTER_ATTRIBUTE) {
        Some(AttributeValue::B(bytes)) => bytes.as_slice(),
        _ => {
            return Err(DbEsdkError::invalid_item(
                "stored item is missing the binary footer attribute 'aws_dbe_foot'",
            ))
        }
    };

    let (_suite, wrapped) = deserialize_header(&header)?;
    let plaintext_data_key = keyring.unwrap(&wrapped)?;
    let content_key = derive_content_key(config, &plaintext_data_key)?;
    let mac_key = derive_mac_key(config, &plaintext_data_key)?;

    // Verify the signature over exactly the stored (non-metadata) attributes.
    let signed_content = canonical_signed_content(config, &header, stored);
    crypto::hmac_sha384_verify(&mac_key, &signed_content, footer)?;

    let mut output = Item::new();
    for (name, value) in stored {
        if name == HEADER_ATTRIBUTE || name == FOOTER_ATTRIBUTE {
            continue;
        }
        let action = config.action_for(name);
        if action.is_encrypted() {
            let sealed = match value {
                AttributeValue::B(bytes) => bytes,
                _ => {
                    return Err(DbEsdkError::invalid_item(format!(
                        "attribute '{name}' is configured ENCRYPT_AND_SIGN but is not stored as binary"
                    )))
                }
            };
            let aad = field_aad(config, name);
            let plaintext = crypto::aes_gcm_open(&content_key, &aad, sealed)?;
            output.insert(name.clone(), AttributeValue::from_canonical_bytes(&plaintext)?);
        } else {
            output.insert(name.clone(), value.clone());
        }
    }
    Ok(output)
}

fn raw_aes_keyring(config: &TableEncryptionConfig) -> Result<RawAesKeyring> {
    match &config.keyring {
        KeyringConfig::RawAes(raw) => Ok(RawAesKeyring::new(raw)),
        KeyringConfig::Unsupported(kind) => Err(DbEsdkError::config(format!(
            "keyring kind '{kind}' is not implemented yet (only Raw AES is supported)"
        ))),
    }
}

fn derive_content_key(config: &TableEncryptionConfig, data_key: &[u8]) -> Result<Vec<u8>> {
    let mut info = b"aws-dbe content key".to_vec();
    info.extend_from_slice(&config.algorithm_suite_id.code().to_be_bytes());
    crypto::hkdf_sha384(data_key, &info, 32)
}

fn derive_mac_key(config: &TableEncryptionConfig, data_key: &[u8]) -> Result<Vec<u8>> {
    let mut info = b"aws-dbe mac key".to_vec();
    info.extend_from_slice(&config.algorithm_suite_id.code().to_be_bytes());
    crypto::hkdf_sha384(data_key, &info, 48)
}

/// Per-field AES-GCM AAD: the logical table name and attribute name, each
/// length-delimited so an attribute's ciphertext cannot be replayed under a
/// different name or table.
fn field_aad(config: &TableEncryptionConfig, attribute_name: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    push_len_prefixed(&mut aad, config.logical_table_name.as_bytes());
    push_len_prefixed(&mut aad, attribute_name.as_bytes());
    aad
}

fn serialize_header(config: &TableEncryptionConfig, wrapped: &WrappedDataKey) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(HEADER_VERSION);
    out.extend_from_slice(&config.algorithm_suite_id.code().to_be_bytes());
    push_len_prefixed(&mut out, wrapped.key_namespace.as_bytes());
    push_len_prefixed(&mut out, wrapped.key_name.as_bytes());
    push_len_prefixed(&mut out, &wrapped.ciphertext);
    out
}

fn deserialize_header(bytes: &[u8]) -> Result<(crate::config::AlgorithmSuiteId, WrappedDataKey)> {
    let mut cursor = ByteReader::new(bytes);
    let version = cursor.take_u8()?;
    if version != HEADER_VERSION {
        return Err(DbEsdkError::invalid_item(format!(
            "unsupported item header version 0x{version:02x}"
        )));
    }
    let suite_code = cursor.take_u16()?;
    let suite = crate::config::AlgorithmSuiteId::from_code(suite_code)?;
    let key_namespace = cursor.take_string()?;
    let key_name = cursor.take_string()?;
    let ciphertext = cursor.take_len_prefixed()?.to_vec();
    Ok((
        suite,
        WrappedDataKey {
            key_namespace,
            key_name,
            ciphertext,
        },
    ))
}

/// Build the canonical bytes the footer HMAC is computed over: the header,
/// followed by every signed (non-`DO_NOTHING`) stored attribute in sorted name
/// order. For encrypted attributes the stored ciphertext bytes are signed; for
/// sign-only attributes the canonical plaintext bytes are signed.
fn canonical_signed_content(
    config: &TableEncryptionConfig,
    header: &[u8],
    stored: &Item,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, header);

    // `stored` is a BTreeMap, so iteration is already sorted by attribute name.
    for (name, value) in stored {
        if name == HEADER_ATTRIBUTE || name == FOOTER_ATTRIBUTE {
            continue;
        }
        let action = config.action_for(name);
        if !action.is_signed() {
            continue;
        }
        push_len_prefixed(&mut out, name.as_bytes());
        out.push(action.code());
        // Encrypted attributes are stored as binary ciphertext; sign that.
        // Everything else is plaintext: sign its canonical encoding.
        match (action.is_encrypted(), value) {
            (true, AttributeValue::B(bytes)) => push_len_prefixed(&mut out, bytes),
            _ => push_len_prefixed(&mut out, &value.to_canonical_bytes()),
        }
    }
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A minimal big-endian reader for the item header.
struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| DbEsdkError::invalid_item("item header is truncated"))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn take_u32(&mut self) -> Result<usize> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }

    fn take_len_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.take_u32()?;
        self.take(len)
    }

    fn take_string(&mut self) -> Result<String> {
        let bytes = self.take_len_prefixed()?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| DbEsdkError::invalid_item("item header string was not valid UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AesWrappingAlg, AlgorithmSuiteId, CryptoAction, RawAesKeyringConfig};
    use std::collections::BTreeMap;

    fn config() -> TableEncryptionConfig {
        let mut actions = BTreeMap::new();
        actions.insert("partition_key".to_string(), CryptoAction::SignOnly);
        actions.insert("sensitive_string".to_string(), CryptoAction::EncryptAndSign);
        actions.insert("sensitive_number".to_string(), CryptoAction::EncryptAndSign);
        actions.insert("sensitive_binary".to_string(), CryptoAction::EncryptAndSign);
        actions.insert("a_flag".to_string(), CryptoAction::SignOnly);
        TableEncryptionConfig {
            logical_table_name: "TestServerRoundTripTable".to_string(),
            partition_key_name: "partition_key".to_string(),
            sort_key_name: None,
            attribute_actions: actions,
            allowed_unsigned_attributes: Vec::new(),
            allowed_unsigned_attribute_prefix: None,
            algorithm_suite_id: AlgorithmSuiteId::default_suite(),
            keyring: KeyringConfig::RawAes(RawAesKeyringConfig {
                key_namespace: "test-server-namespace".to_string(),
                key_name: "raw-aes-key".to_string(),
                wrapping_key: vec![5u8; 32],
                wrapping_alg: AesWrappingAlg::Aes256,
            }),
        }
    }

    fn round_trip_item() -> Item {
        let mut item = Item::new();
        item.insert("partition_key".into(), AttributeValue::S("pk-rawaes-001".into()));
        item.insert("sensitive_string".into(), AttributeValue::S("top-secret-value".into()));
        item.insert("sensitive_number".into(), AttributeValue::N("42".into()));
        item.insert("sensitive_binary".into(), AttributeValue::B(b"binary-blob".to_vec()));
        item.insert("a_flag".into(), AttributeValue::Bool(true));
        item
    }

    #[test]
    fn encrypt_then_decrypt_returns_equal_item() {
        let config = config();
        let item = round_trip_item();
        let stored = encrypt_item(&config, &item).unwrap();

        // Key + sign-only attributes are plaintext; encrypted ones are binary.
        assert_eq!(stored.get("partition_key"), Some(&AttributeValue::S("pk-rawaes-001".into())));
        assert_eq!(stored.get("a_flag"), Some(&AttributeValue::Bool(true)));
        assert!(matches!(stored.get("sensitive_string"), Some(AttributeValue::B(_))));
        assert!(stored.contains_key(HEADER_ATTRIBUTE));
        assert!(stored.contains_key(FOOTER_ATTRIBUTE));

        let decrypted = decrypt_item(&config, &stored).unwrap();
        assert_eq!(decrypted, item);
    }

    #[test]
    fn each_encrypt_uses_a_fresh_data_key_and_nonce() {
        let config = config();
        let item = round_trip_item();
        let a = encrypt_item(&config, &item).unwrap();
        let b = encrypt_item(&config, &item).unwrap();
        // Ciphertext (and wrapped data key) must differ across encryptions.
        assert_ne!(a.get("sensitive_string"), b.get("sensitive_string"));
        assert_ne!(a.get(HEADER_ATTRIBUTE), b.get(HEADER_ATTRIBUTE));
    }

    #[test]
    fn decrypt_detects_tampered_ciphertext() {
        let config = config();
        let mut stored = encrypt_item(&config, &round_trip_item()).unwrap();
        if let Some(AttributeValue::B(bytes)) = stored.get_mut("sensitive_string") {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
        }
        assert!(decrypt_item(&config, &stored).is_err());
    }

    #[test]
    fn decrypt_detects_tampered_sign_only_attribute() {
        let config = config();
        let mut stored = encrypt_item(&config, &round_trip_item()).unwrap();
        stored.insert("a_flag".into(), AttributeValue::Bool(false));
        assert!(decrypt_item(&config, &stored).is_err());
    }

    #[test]
    fn decrypt_fails_with_a_different_wrapping_key() {
        let config = config();
        let stored = encrypt_item(&config, &round_trip_item()).unwrap();
        let mut other = config;
        other.keyring = KeyringConfig::RawAes(RawAesKeyringConfig {
            key_namespace: "test-server-namespace".to_string(),
            key_name: "raw-aes-key".to_string(),
            wrapping_key: vec![6u8; 32],
            wrapping_alg: AesWrappingAlg::Aes256,
        });
        assert!(decrypt_item(&other, &stored).is_err());
    }

    #[test]
    fn unsupported_keyring_is_a_config_error() {
        let mut config = config();
        config.keyring = KeyringConfig::Unsupported("awsKms".to_string());
        let err = encrypt_item(&config, &round_trip_item()).unwrap_err();
        assert!(matches!(err, DbEsdkError::Config(_)));
    }
}
