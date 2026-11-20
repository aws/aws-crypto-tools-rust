// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Key derivation and per-field AES-GCM encryption.
//!
//! HKDF derives a field root key from the data key.
//! Each encrypted field gets its own AES-256-GCM key and nonce:
//! the bytes of the root key's AES-KDF-CTR stream at the field's position.

use aws_mpl_primitives::{AesGcm, aes_decrypt, aes_encrypt, aes_kdf_ctr_stream, hkdf_no_salt};
use zeroize::Zeroizing;

use super::header::MSGID_LEN;
use super::suite::DbeSuite;
use super::util::{BYTES_TYPE_ID, CanonItem, Terminal};
use crate::error::{Error, internal_err, ser_err, val_err};
use crate::types::CryptoAction;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const AUTH_TAG_SIZE: usize = 16;
/// Field keys are derived at `offset * 3`, which must fit in a `u32`.
pub(crate) const ONE_THIRD_MAX_INT: u32 = 1_431_655_765;

const LABEL_COMMITMENT_KEY: &[u8] = b"AWS_DBE_COMMIT_KEY";
const LABEL_ENCRYPTION_KEY: &[u8] = b"AWS_DBE_DERIVE_KEY";
const AWS_DBE_FIELD: &[u8] = b"AwsDbeField";

/// Whether this run encrypts or decrypts the fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Encrypt,
    Decrypt,
}

/// The key that commits the header to the data key.
pub(crate) fn commit_key(
    suite: DbeSuite,
    key: &[u8],
    msg_id: &[u8; MSGID_LEN],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    //= spec/structured-encryption/header.md#commit-key
    //= reason=DbeSuite::new rejects suites whose encryption key length is not KEY_SIZE (32)
    //# The calculated Commitment Key MUST have length equal to the
    //# [algorithm suite's encryption key length](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#algorithm-suites-encryption-settings).
    let mut out = Zeroizing::new(vec![0u8; KEY_SIZE]);

    //= spec/structured-encryption/header.md#commit-key
    //= reason=suite.commit is the suite's commit_kdf() hash (DbeSuite::new)
    //# The HKDF used to calculate the Commitment Key MUST be the
    //# [Commit Key KDF](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#algorithm-suites-commit-key-derivation-settings)
    //# indicated by the algorithm suite.
    //
    //= spec/structured-encryption/header.md#commit-key
    //# The `info` used for the HKDF function MUST be
    //# | Field | Length |
    //# | -------------------- | -------- |
    //# | "AWS_DBE_COMMIT_KEY" | 18 |
    //# | Message ID | 32 |
    //
    //= spec/structured-encryption/header.md#commit-key
    //# The HKDF calculation MUST use a supplied key, no salt, and an `info` as described above.
    hkdf_no_salt(suite.commit, key, &[LABEL_COMMITMENT_KEY, msg_id], &mut out)?;
    Ok(out)
}

fn field_key_nonce(offset: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(AWS_DBE_FIELD.len() + 5);

    //= spec/structured-encryption/encrypt-path-structure.md#calculate-cipherkey-and-nonce
    //# The `FieldKeyNonce` for a given offset MUST be 16 bytes comprised of
    //# | Field | Length | Interpretation |
    //# | ------------- | -------- | -------------- |
    //# | "AwsDbeField" | 11 | Literal Ascii String |
    //# | 0x2c | 1 | 44, the length of the eventual FieldKey |
    //# | offset | 4 | 32 bit integer representation of offset |
    out.extend_from_slice(AWS_DBE_FIELD);
    // KEY_SIZE + NONCE_SIZE is 44, which fits a byte.
    out.push(44);
    out.extend_from_slice(&offset.to_be_bytes());
    out
}

/// The bytes of key stream that each field takes: three AES blocks.
/// The first `KEY_SIZE + NONCE_SIZE` bytes are the field's key and nonce.
const FIELD_STRIDE: u32 = 48;
/// The number of fields whose keys one call to the key stream derives.
/// This bounds the size of the stream buffer.
const FIELD_BATCH: u32 = 64;

/// The AES-GCM keys and nonces of `count` encrypted fields, starting at field `offset`.
/// Each field's key and nonce start `FIELD_STRIDE` bytes after the previous field's.
///
/// The key of field `i` comes from the AES-CTR stream at counter block `3 * i`.
/// So consecutive fields take consecutive blocks of one stream, and one call derives them all.
fn field_keys(root: &[u8], offset: u32, count: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
    if offset
        .checked_add(count)
        .is_none_or(|end| end > ONE_THIRD_MAX_INT)
    {
        return Err(val_err("the item has too many encrypted attributes"));
    }

    //= spec/structured-encryption/encrypt-path-structure.md#calculate-cipherkey-and-nonce
    //= reason=the stream starts at counter 3 * offset; crypt takes each field's first 44 bytes
    //# The `FieldKey` for a given key and offset MUST be the first 44 bytes
    //# of the aes256ctr_stream
    //# of the `FieldRootKey` and the `FieldKeyNonce` of three times the given offset.
    let nonce = field_key_nonce(offset * 3);
    let len = count
        .checked_mul(FIELD_STRIDE)
        .ok_or_else(|| internal_err("the field key length overflowed"))?;
    Ok(Zeroizing::new(aes_kdf_ctr_stream(&nonce, root, len)?))
}

/// The AES-GCM key and nonce of the encrypted field at `offset`, on its own.
#[cfg(test)]
fn field_key(root: &[u8], offset: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
    if offset >= ONE_THIRD_MAX_INT {
        return Err(val_err("the item has too many encrypted attributes"));
    }
    let mut fk = field_keys(root, offset, 1)?;
    fk.truncate(KEY_SIZE + NONCE_SIZE);
    Ok(fk)
}

fn encrypt_terminal(fk: &[u8], path: &[u8], data: &Terminal) -> Result<Terminal, Error> {
    //= spec/structured-encryption/encrypt-path-structure.md#calculate-cipherkey-and-nonce
    //# The `Cipherkey` MUST be the first 32 bytes of the `FieldKey`
    //
    //= spec/structured-encryption/encrypt-path-structure.md#calculate-cipherkey-and-nonce
    //# The `Nonce` MUST be the remaining 12 bytes of the `FieldKey`
    let (key, nonce) = fk.split_at(KEY_SIZE);
    let mut out = Vec::with_capacity(2 + data.value.len() + AUTH_TAG_SIZE);

    //= spec/structured-encryption/encrypt-path-structure.md#terminal-data-encryption
    //# The output encrypted Terminal Data MUST have a [Terminal Value](./structures.md#terminal-value)
    //# with the following serialization:
    //
    //= spec/structured-encryption/encrypt-path-structure.md#terminal-type-id
    //# Terminal Type Id MUST equal the input Terminal Data's Terminal Type Id.
    out.extend_from_slice(&data.type_id);

    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-terminal-value
    //= reason=AES-256-GCM is every DBE suite's encryption; the AAD is the canonical path
    //# The Encrypted Terminal Value MUST be derived according to the following encryption:
    aes_encrypt(AesGcm::Aes256Gcm, nonce, key, &data.value, path, &mut out)?;

    //= spec/structured-encryption/encrypt-path-structure.md#terminal-data-encryption
    //# The output encrypted Terminal Data MUST have a [Terminal Type Id](./structures.md#terminal-type-id)
    //# equal `0xFFFF`.
    Ok(Terminal::new(BYTES_TYPE_ID, out))
}

fn decrypt_terminal(fk: &[u8], path: &[u8], data: &Terminal) -> Result<Terminal, Error> {
    let (key, nonce) = fk.split_at(KEY_SIZE);
    let value = &data.value;
    if value.len() < AUTH_TAG_SIZE + 2 {
        return Err(ser_err(
            "an encrypted attribute is too short to be a ciphertext",
        ));
    }

    //= spec/structured-encryption/decrypt-path-structure.md#terminal-data-decryption
    //= reason=the first 2 bytes are the type id; the rest is the ciphertext, then the tag
    //# The input [Terminal Value](./structures.md#terminal-value) MUST be deserialized as follows:
    let (ct, tag) = value[2..].split_at(value.len() - 2 - AUTH_TAG_SIZE);
    let mut plain = vec![0u8; ct.len()];

    //= spec/structured-encryption/decrypt-path-structure.md#terminal-data-decryption
    //= reason=AES-256-GCM is every DBE suite's encryption; the AAD is the canonical path
    //# The output Terminal Data MUST have a [Terminal Value](./structures.md#terminal-type-id)
    //# equal to the following decryption:
    aes_decrypt(AesGcm::Aes256Gcm, key, ct, tag, nonce, path, &mut plain)?;

    //= spec/structured-encryption/decrypt-path-structure.md#terminal-data-decryption
    //# The output Terminal Data MUST have a [Terminal Type Id](./structures.md#terminal-type-id)
    //# equal to the deserialized Terminal Type Id.
    Ok(Terminal::new([value[0], value[1]], plain))
}

/// Encrypt or decrypt every `ENCRYPT_AND_SIGN` field of `data`, which is in canonical order.
pub(crate) fn crypt(
    mode: Mode,
    suite: DbeSuite,
    key: &[u8],
    msg_id: &[u8; MSGID_LEN],
    data: Vec<CanonItem>,
) -> Result<Vec<CanonItem>, Error> {
    //= spec/structured-encryption/encrypt-path-structure.md#calculate-cipherkey-and-nonce
    //= type=implication
    //= reason=DbeSuite::new admits only suites whose encryption key length is KEY_SIZE (32)
    //# The calculated Field Root MUST have length equal to the
    //# [algorithm suite's encryption key length](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#algorithm-suites-encryption-settings).
    let mut root = Zeroizing::new(vec![0u8; KEY_SIZE]);

    //= spec/structured-encryption/encrypt-path-structure.md#calculate-info
    //# The `info` used for the HKDF function MUST be
    //# | Field | Length |
    //# | -------------------- | -------- |
    //# | "AWS_DBE_DERIVE_KEY" | 18 |
    //# | Message ID | 32 |
    //
    //= spec/structured-encryption/encrypt-path-structure.md#calculate-cipherkey-and-nonce
    //# The HKDF algorithm used to calculate the Field Root Key MUST be the
    //# [Encryption Key KDF](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings)
    //# indicated by the algorithm suite, using a provided plaintext data key, no salt,
    //# and an info as calculated [above](#calculate-info)
    hkdf_no_salt(suite.kdf, key, &[LABEL_ENCRYPTION_KEY, msg_id], &mut root)?;
    if u32::try_from(data.len()).is_err() {
        return Err(val_err("the item has too many attributes"));
    }
    let total = u32::try_from(
        data.iter()
            .filter(|x| x.action == CryptoAction::EncryptAndSign)
            .count(),
    )
    .map_err(|_| val_err("the item has too many encrypted attributes"))?;
    let mut data = data;
    let mut pos: u32 = 0;
    let mut keys = Zeroizing::new(Vec::new());
    for item in &mut data {
        if item.action != CryptoAction::EncryptAndSign {
            //= spec/structured-encryption/header.md#encrypt-legend-bytes
            //# This indicates that this field MUST NOT be attempted to be decrypted during decryption.
            //
            //= spec/structured-encryption/structures.md#do-not-encrypt
            //= reason=the field is skipped, so its value and type id pass through unchanged
            //# During [Encrypt Structure](encrypt-structure.md#encrypt-structure)
            //# and [Decrypt Structure](decrypt-structure.md#decrypt-structure),
            //# DO_NOT_ENCRYPT signifies that the [Terminal Data](#terminal-data)
            //# MUST have an equal [Terminal Value](#terminal-value) and
            //# [Terminal Type Id](#terminal-type-id) as the the Terminal Data
            //# in the same location in the resulting encrypted [Structured Data](#structured-data).
            //
            //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
            //# Otherwise, this Terminal Data MUST have [Terminal Type ID](./structures.md#terminal-type-id)
            //# and [Terminal Value](./structures.md#terminal-value) equal to the input Terminal Data's.
            //
            //= spec/structured-encryption/decrypt-path-structure.md#construct-decrypted-structured-data
            //# Otherwise, this Terminal Data MUST have [Terminal Type ID](./structures.md#terminal-type-id) and
            //# [Terminal Value](./structures.md#terminal-value) equal to the input Terminal Data.
            continue;
        }
        let slot = ((pos % FIELD_BATCH) * FIELD_STRIDE) as usize;
        if slot == 0 {
            keys = field_keys(&root, pos, FIELD_BATCH.min(total - pos))?;
        }
        let fk = &keys[slot..slot + KEY_SIZE + NONCE_SIZE];
        item.data = match mode {
            //= spec/structured-encryption/structures.md#encrypt
            //# During [Encrypt Structure](encrypt-structure.md#encrypt-structure),
            //# ENCRYPT signifies that the [Terminal Value](#terminal-value) in the [Terminal Data](#terminal-data)
            //# MUST be encrypted in the resulting encrypted [Structured Data](#structured-data).
            //
            //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
            //# If the [Crypto Schema](#crypto-list)
            //# indicates a [Crypto Action](./structures.md#crypto-action)
            //# of [ENCRYPT_AND_SIGN](./structures.md#encryptandsign),
            //# the Terminal Data MUST have [Terminal Type ID](./structures.md#terminal-type-id)
            //# equal to 0xffff and the value MUST be
            //# the [encryption](#terminal-data-encryption)
            //# of the input's Terminal Data.
            Mode::Encrypt => encrypt_terminal(fk, &item.canon, &item.data)?,

            //= spec/structured-encryption/header.md#encrypt-legend-bytes
            //= reason=for_decrypt maps legend byte 0x65 to EncryptAndSign, the only action reaching here
            //# This indicates that this field MUST be attempted to be decrypted during decryption.
            //
            //= spec/structured-encryption/structures.md#encrypt
            //# During [Decrypt Structure](decrypt-structure.md#decrypt-structure),
            //# ENCRYPT signifies that the [Terminal Value](#terminal-value) in the [Terminal Data](#terminal-data)
            //# MUST be attempted to be decrypted.
            //
            //= spec/structured-encryption/decrypt-path-structure.md#construct-decrypted-structured-data
            //# If the action is [ENCRYPT_AND_SIGN](./structures.md#encryptandsign)
            //# this Terminal Data MUST have [Terminal Type ID](./structures.md#terminal-type-id)
            //# equal to the first two bytes of the input Terminal Data's value,
            //# and a value equal to the [decryption](#terminal-data-decryption) of the input Terminal Data's value.
            Mode::Decrypt => decrypt_terminal(fk, &item.canon, &item.data)?,
        };
        pos += 1;
    }
    Ok(data)
}

#[cfg(test)]
#[path = "crypt_tests.rs"]
mod tests;
