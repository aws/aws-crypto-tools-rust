// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Key derivation and per-field AES-GCM encryption.
//!
//! The data key derives a field root key (HKDF), and each encrypted field gets its own
//! AES-256-GCM key and nonce from the root key by AES-KDF-CTR at the field's position.

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
    let mut out = Zeroizing::new(vec![0u8; KEY_SIZE]);
    hkdf_no_salt(suite.commit, key, &[LABEL_COMMITMENT_KEY, msg_id], &mut out)?;
    Ok(out)
}

fn field_key_nonce(offset: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(AWS_DBE_FIELD.len() + 5);
    out.extend_from_slice(AWS_DBE_FIELD);
    // KEY_SIZE + NONCE_SIZE is 44, which fits a byte.
    out.push(44);
    out.extend_from_slice(&offset.to_be_bytes());
    out
}

/// Bytes of key stream each field takes: three AES blocks, of which the first
/// `KEY_SIZE + NONCE_SIZE` are the field's key and nonce.
const FIELD_STRIDE: u32 = 48;
/// Fields whose keys one key-stream call derives. Bounds the stream buffer.
const FIELD_BATCH: u32 = 64;

/// The AES-GCM keys and nonces of the `count` encrypted fields from `offset`,
/// `FIELD_STRIDE` bytes apart.
///
/// Field `i` is keyed by the AES-CTR stream at counter block `3 * i`, so consecutive
/// fields are consecutive blocks of one stream: one call derives them all.
fn field_keys(root: &[u8], offset: u32, count: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
    if offset
        .checked_add(count)
        .is_none_or(|end| end > ONE_THIRD_MAX_INT)
    {
        return Err(val_err("Too many encrypted fields."));
    }
    let nonce = field_key_nonce(offset * 3);
    let len = count
        .checked_mul(FIELD_STRIDE)
        .ok_or_else(|| internal_err("field key size"))?;
    Ok(Zeroizing::new(aes_kdf_ctr_stream(&nonce, root, len)?))
}

/// The AES-GCM key and nonce of the encrypted field at `offset`, on its own.
#[cfg(test)]
fn field_key(root: &[u8], offset: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
    if offset >= ONE_THIRD_MAX_INT {
        return Err(val_err("Too many encrypted fields."));
    }
    let mut fk = field_keys(root, offset, 1)?;
    fk.truncate(KEY_SIZE + NONCE_SIZE);
    Ok(fk)
}

fn encrypt_terminal(fk: &[u8], path: &[u8], data: &Terminal) -> Result<Terminal, Error> {
    let (key, nonce) = fk.split_at(KEY_SIZE);
    let mut out = Vec::with_capacity(2 + data.value.len() + AUTH_TAG_SIZE);
    out.extend_from_slice(&data.type_id);
    aes_encrypt(AesGcm::Aes256Gcm, nonce, key, &data.value, path, &mut out)?;
    Ok(Terminal::new(BYTES_TYPE_ID, out))
}

fn decrypt_terminal(fk: &[u8], path: &[u8], data: &Terminal) -> Result<Terminal, Error> {
    let (key, nonce) = fk.split_at(KEY_SIZE);
    let value = &data.value;
    if value.len() < AUTH_TAG_SIZE + 2 {
        return Err(ser_err("cipherTxt too short."));
    }
    let (ct, tag) = value[2..].split_at(value.len() - 2 - AUTH_TAG_SIZE);
    let mut plain = vec![0u8; ct.len()];
    aes_decrypt(AesGcm::Aes256Gcm, key, ct, tag, nonce, path, &mut plain)?;
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
    let mut root = Zeroizing::new(vec![0u8; KEY_SIZE]);
    hkdf_no_salt(suite.kdf, key, &[LABEL_ENCRYPTION_KEY, msg_id], &mut root)?;
    if u32::try_from(data.len()).is_err() {
        return Err(val_err("Too many fields."));
    }
    let total = u32::try_from(
        data.iter()
            .filter(|x| x.action == CryptoAction::EncryptAndSign)
            .count(),
    )
    .map_err(|_| val_err("Too many encrypted fields."))?;
    let mut data = data;
    let mut pos: u32 = 0;
    let mut keys = Zeroizing::new(Vec::new());
    for item in &mut data {
        if item.action != CryptoAction::EncryptAndSign {
            continue;
        }
        let slot = ((pos % FIELD_BATCH) * FIELD_STRIDE) as usize;
        if slot == 0 {
            keys = field_keys(&root, pos, FIELD_BATCH.min(total - pos))?;
        }
        let fk = &keys[slot..slot + KEY_SIZE + NONCE_SIZE];
        item.data = match mode {
            Mode::Encrypt => encrypt_terminal(fk, &item.canon, &item.data)?,
            Mode::Decrypt => decrypt_terminal(fk, &item.canon, &item.data)?,
        };
        pos += 1;
    }
    Ok(data)
}

#[cfg(test)]
#[path = "crypt_tests.rs"]
mod tests;
