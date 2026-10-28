// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The header: version, flavor, message id, legend, stored encryption context,
//! encrypted data keys, and the commitment that binds them to the data key.

use std::collections::BTreeMap;

use aws_crypto_mpl::types::{EncryptedDataKey, EncryptionContext, EncryptionMaterials};
use aws_mpl_primitives::{DigestAlg, constant_time_equal, hmac};

use super::util::{
    CanonItem, ENCRYPT_AND_SIGN_LEGEND, SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT_LEGEND,
    SIGN_ONLY_LEGEND, is_auth_attr,
};
use crate::error::{Error, internal_err, ser_err, val_err};
use crate::types::CryptoAction;

pub(crate) const MSGID_LEN: usize = 32;
pub(crate) const COMMITMENT_LEN: usize = 32;
const PREFIX_LEN: usize = 1 + 1 + MSGID_LEN;
const UINT8_LIMIT: usize = 256;
const UINT16_LIMIT: usize = 65_536;

/// The first byte of every DBE algorithm suite id.
pub(crate) const DBE_ALGORITHM_FAMILY: u8 = 0x67;

/// A header without its commitment.
#[derive(Clone, Debug)]
pub(crate) struct PartialHeader {
    pub(crate) version: u8,
    pub(crate) flavor: u8,
    pub(crate) msg_id: [u8; MSGID_LEN],
    pub(crate) legend: Vec<u8>,
    pub(crate) enc_context: EncryptionContext,
    pub(crate) data_keys: Vec<EncryptedDataKey>,
}

const fn valid_version(x: u8) -> bool {
    x == 1 || x == 2
}

const fn valid_flavor(x: u8) -> bool {
    x == 0 || x == 1
}

const fn valid_legend_byte(x: u8) -> bool {
    matches!(
        x,
        ENCRYPT_AND_SIGN_LEGEND | SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT_LEGEND | SIGN_ONLY_LEGEND
    )
}

/// Whether every size in `ec` fits the header's 16-bit length fields.
pub(crate) fn valid_encryption_context(ec: &EncryptionContext) -> bool {
    ec.len() < UINT16_LIMIT
        && ec
            .iter()
            .all(|(k, v)| k.len() < UINT16_LIMIT && v.len() < UINT16_LIMIT)
}

fn valid_data_key(k: &EncryptedDataKey) -> bool {
    k.key_provider_id().len() < UINT16_LIMIT
        && k.key_provider_info().len() < UINT16_LIMIT
        && k.ciphertext().len() < UINT16_LIMIT
}

/// The header version for a schema: 2 when any field is `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT`.
pub(crate) fn version_from_schema(data: &[CanonItem]) -> u8 {
    if data
        .iter()
        .any(|x| x.action == CryptoAction::SignAndIncludeInEncryptionContext)
    {
        2
    } else {
        1
    }
}

const fn action_legend(action: CryptoAction) -> Option<u8> {
    match action {
        CryptoAction::EncryptAndSign => Some(ENCRYPT_AND_SIGN_LEGEND),
        CryptoAction::SignAndIncludeInEncryptionContext => {
            Some(SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT_LEGEND)
        }
        CryptoAction::SignOnly => Some(SIGN_ONLY_LEGEND),
        CryptoAction::DoNothing => None,
    }
}

/// One legend byte per signed field, in canonical order.
fn make_legend(schema: &[CanonItem]) -> Result<Vec<u8>, Error> {
    let legend: Vec<u8> = schema
        .iter()
        .filter_map(|x| action_legend(x.action))
        .collect();
    if legend.len() + 1 >= UINT16_LIMIT {
        return Err(val_err("Legend Too Long."));
    }
    let auth_count = schema.iter().filter(|x| is_auth_attr(x.action)).count();
    if auth_count != legend.len() {
        return Err(internal_err("Internal Error : bad legend calculation."));
    }
    Ok(legend)
}

/// A `u16` length; callers check the limit first.
fn u16_len(len: usize) -> [u8; 2] {
    u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes()
}

/// The count of pairs, then each key and value with its 16-bit length, in byte order of the keys.
pub(crate) fn serialize_context(ec: &EncryptionContext) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u16_len(ec.len()));
    for (k, v) in ec.as_map() {
        out.extend_from_slice(&u16_len(k.len()));
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&u16_len(v.len()));
        out.extend_from_slice(v.as_bytes());
    }
    out
}

fn serialize_data_keys(keys: &[EncryptedDataKey]) -> Vec<u8> {
    let mut out = vec![u8::try_from(keys.len()).unwrap_or(u8::MAX)];
    for k in keys {
        out.extend_from_slice(&u16_len(k.key_provider_id().len()));
        out.extend_from_slice(k.key_provider_id().as_bytes());
        out.extend_from_slice(&u16_len(k.key_provider_info().len()));
        out.extend_from_slice(k.key_provider_info());
        out.extend_from_slice(&u16_len(k.ciphertext().len()));
        out.extend_from_slice(k.ciphertext());
    }
    out
}

impl PartialHeader {
    /// Build the header for `schema` from the encryption materials.
    pub(crate) fn create(
        schema: &[CanonItem],
        msg_id: [u8; MSGID_LEN],
        mat: &EncryptionMaterials,
    ) -> Result<Self, Error> {
        if u64::try_from(schema.len()).unwrap_or(u64::MAX) > u64::from(u32::MAX) {
            return Err(val_err("Unexpected large schema"));
        }
        if !valid_encryption_context(mat.encryption_context()) {
            return Err(val_err("Invalid Encryption Context"));
        }
        let edks = mat.encrypted_data_keys();
        if edks.is_empty() {
            return Err(val_err("There must be at least one data key"));
        }
        if edks.len() >= UINT8_LIMIT {
            return Err(val_err("Too many data keys."));
        }
        if !edks.iter().all(valid_data_key) {
            return Err(val_err("Invalid Data Key"));
        }
        let id = mat.algorithm_suite().id();
        if id[0] != DBE_ALGORITHM_FAMILY {
            return Err(val_err(
                "Algorithm Suite not suitable for structured encryption.",
            ));
        }
        if !valid_flavor(id[1]) {
            return Err(val_err("Algorithm Suite has unexpected flavor."));
        }
        let legend = make_legend(schema)?;
        let required = mat.required_encryption_context_keys();
        let mut stored = EncryptionContext::new();
        for (k, v) in mat.encryption_context().iter() {
            if !required.contains(k) {
                stored.insert(k, v);
            }
        }
        if !valid_encryption_context(&stored) {
            return Err(val_err("Invalid Encryption Context"));
        }
        Ok(Self {
            version: version_from_schema(schema),
            flavor: id[1],
            msg_id,
            legend,
            enc_context: stored,
            data_keys: edks.to_vec(),
        })
    }

    /// The header bytes before the commitment.
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut out = vec![self.version, self.flavor];
        out.extend_from_slice(&self.msg_id);
        out.extend_from_slice(&u16_len(self.legend.len()));
        out.extend_from_slice(&self.legend);
        out.extend_from_slice(&serialize_context(&self.enc_context));
        out.extend_from_slice(&serialize_data_keys(&self.data_keys));
        out
    }

    /// The header bytes followed by their commitment under `commit_key`.
    pub(crate) fn serialize_with_commitment(
        &self,
        hmac_alg: DigestAlg,
        commit_key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut body = self.serialize();
        let commitment = header_commitment(hmac_alg, commit_key, &body)?;
        body.extend_from_slice(&commitment);
        Ok(body)
    }

    /// Parse a serialized header, commitment included.
    pub(crate) fn deserialize(data: &[u8]) -> Result<Self, Error> {
        if data.len() < PREFIX_LEN {
            return Err(ser_err("Serialized PartialHeader too short."));
        }
        let version = data[0];
        if !valid_version(version) {
            return Err(ser_err("Invalid Version Number"));
        }
        let flavor = data[1];
        if !valid_flavor(flavor) {
            return Err(ser_err("Invalid Flavor"));
        }
        let mut msg_id = [0u8; MSGID_LEN];
        msg_id.copy_from_slice(&data[2..PREFIX_LEN]);
        let legend_data = &data[PREFIX_LEN..];
        let (legend, legend_len) = get_legend(legend_data)?;
        let context_data = &legend_data[legend_len..];
        let (enc_context, context_len) = get_context(context_data)?;
        let keys_data = &context_data[context_len..];
        let (data_keys, keys_len) = get_data_keys(keys_data)?;
        let trailing = &keys_data[keys_len..];
        if trailing.len() < COMMITMENT_LEN {
            return Err(ser_err(
                "Invalid header serialization: unexpected end of data.",
            ));
        }
        if trailing.len() > COMMITMENT_LEN {
            return Err(ser_err("Invalid header serialization: unexpected bytes."));
        }
        Ok(Self {
            version,
            flavor,
            msg_id,
            legend,
            enc_context,
            data_keys,
        })
    }

    /// Check the commitment at the end of `data` against `commit_key`.
    pub(crate) fn verify_commitment(
        hmac_alg: DigestAlg,
        commit_key: &[u8],
        data: &[u8],
    ) -> Result<(), Error> {
        if data.len() <= COMMITMENT_LEN {
            return Err(ser_err("Serialized header too short"));
        }
        let (body, stored) = data.split_at(data.len() - COMMITMENT_LEN);
        let calculated = header_commitment(hmac_alg, commit_key, body)?;
        if !constant_time_equal(stored, &calculated) {
            return Err(crate::error::crypt_err("Key commitment mismatch."));
        }
        Ok(())
    }
}

/// The first 32 bytes of the HMAC of the header under the commitment key.
fn header_commitment(
    hmac_alg: DigestAlg,
    commit_key: &[u8],
    data: &[u8],
) -> Result<[u8; COMMITMENT_LEN], Error> {
    let mut full = vec![0u8; digest_len(hmac_alg)];
    hmac(hmac_alg, commit_key, data, &mut full)?;
    let mut out = [0u8; COMMITMENT_LEN];
    out.copy_from_slice(
        full.get(..COMMITMENT_LEN)
            .ok_or_else(|| internal_err("HMAC did not produce enough bits"))?,
    );
    Ok(out)
}

/// The output length of `alg`, in bytes.
pub(crate) const fn digest_len(alg: DigestAlg) -> usize {
    match alg {
        DigestAlg::Sha256 => 32,
        DigestAlg::Sha384 => 48,
        _ => 64,
    }
}

fn read_u16(data: &[u8], pos: usize) -> usize {
    usize::from(u16::from_be_bytes([data[pos], data[pos + 1]]))
}

fn get_legend(data: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    if data.len() < 2 {
        return Err(ser_err("Unexpected end of header data."));
    }
    let size = read_u16(data, 0) + 2;
    if size > data.len() {
        return Err(ser_err("Unexpected end of header data."));
    }
    let legend = data[2..size].to_vec();
    if !legend.iter().copied().all(valid_legend_byte) {
        return Err(ser_err("Invalid byte in stored legend"));
    }
    Ok((legend, size))
}

fn utf8(bytes: &[u8]) -> Result<String, Error> {
    String::from_utf8(bytes.to_vec()).map_err(|_| ser_err("Invalid UTF8 found in header."))
}

fn get_context(data: &[u8]) -> Result<(EncryptionContext, usize), Error> {
    if data.len() < 2 {
        return Err(ser_err("Unexpected end of header data."));
    }
    let count = read_u16(data, 0);
    let mut pos = 2usize;
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut prev_key: Vec<u8> = Vec::new();
    for _ in 0..count {
        if map.len() + 1 >= UINT16_LIMIT {
            return Err(ser_err("Too much context"));
        }
        if pos + 2 > data.len() {
            return Err(ser_err("Unexpected end of header data."));
        }
        let key_len = read_u16(data, pos);
        if key_len + 4 + pos > data.len() {
            return Err(ser_err("Unexpected end of header data."));
        }
        let key = &data[pos + 2..pos + 2 + key_len];
        let key_str = utf8(key)?;
        let value_len = read_u16(data, pos + 2 + key_len);
        let kv_len = 2 + key_len + 2 + value_len;
        if kv_len + pos > data.len() {
            return Err(ser_err("Unexpected end of header data."));
        }
        let value = utf8(&data[pos + key_len + 4..pos + kv_len])?;
        // Keys must be strictly ascending, which also rules out duplicates.
        if !bytes_less(&prev_key, key) {
            return Err(ser_err("Context keys out of order."));
        }
        prev_key = key.to_vec();
        map.insert(key_str, value);
        pos += kv_len;
    }
    let mut ec = EncryptionContext::new();
    for (k, v) in map {
        ec.insert(k, v);
    }
    Ok((ec, pos))
}

/// Whether `a` sorts strictly before `b`; the empty key sorts before every other key.
fn bytes_less(a: &[u8], b: &[u8]) -> bool {
    a != b && a < b
}

fn get_one_data_key(data: &[u8], pos: usize) -> Result<(EncryptedDataKey, usize), Error> {
    let size = data.len();
    if 2 + pos >= size {
        return Err(ser_err("Unexpected end of header data."));
    }
    let prov_id_size = read_u16(data, pos);
    if prov_id_size + 2 + pos >= size {
        return Err(ser_err("Unexpected end of header data."));
    }
    let prov_id = utf8(&data[pos + 2..pos + 2 + prov_id_size])?;
    let part1 = 2 + prov_id_size;
    if part1 + 2 + pos > size {
        return Err(ser_err("Unexpected end of header data."));
    }
    let prov_info_size = read_u16(data, pos + part1);
    let part2 = part1 + 2 + prov_info_size;
    if part2 + pos >= size {
        return Err(ser_err("Unexpected end of header data."));
    }
    let prov_info = data[pos + part1 + 2..pos + part2].to_vec();
    if part2 + 2 + pos > size {
        return Err(ser_err("Unexpected end of header data."));
    }
    let cipher_size = read_u16(data, pos + part2);
    let part3 = part2 + 2 + cipher_size;
    if part3 + pos > size {
        return Err(ser_err("Unexpected end of header data."));
    }
    let cipher = data[pos + part2 + 2..pos + part3].to_vec();
    let edk = EncryptedDataKey::builder()
        .key_provider_id(prov_id)
        .key_provider_info(prov_info)
        .ciphertext(cipher)
        .build()?;
    Ok((edk, part3))
}

fn get_data_keys(data: &[u8]) -> Result<(Vec<EncryptedDataKey>, usize), Error> {
    let Some(&count) = data.first() else {
        return Err(ser_err("Unexpected end of header data."));
    };
    let mut keys = Vec::with_capacity(usize::from(count));
    let mut pos = 1usize;
    for _ in 0..count {
        if keys.len() >= 255 {
            return Err(ser_err("Too Many Data Keys"));
        }
        let (edk, len) = get_one_data_key(data, pos)?;
        keys.push(edk);
        pos += len;
    }
    if keys.is_empty() {
        return Err(ser_err("At least one Data Key required"));
    }
    Ok((keys, pos))
}
