// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Data key wrapping shared by the raw ECDH and AWS KMS ECDH keyrings.
//! Ported from the Dafny `EcdhEdkWrapping.dfy` and the helpers in `RawECDHKeyring.dfy`.
//!
//! The keyring agrees on a shared secret with the other party.
//! KDF in counter mode derives 64 bytes from it:
//! a 32-byte commitment key, then a 32-byte AES-256-GCM wrapping key.
//! The wrapped material is `salt || commitment key || AES-GCM ciphertext || tag`.
//!
//! The key provider information is
//! `version || recipient key length || recipient key || sender key length || sender key`,
//! with each length a big-endian `u32` and each public key compressed.

use aws_mpl_primitives::{
    AesGcm, DigestAlg, aes_decrypt, aes_encrypt, constant_time_equal, generate_random_bytes,
    kbkdf_ctr_hmac,
};
use zeroize::Zeroizing;

use crate::Error;
use crate::error::Kind;
use crate::keyring::edk_wrapping;
use crate::structures::{
    AlgorithmSuite, DecryptionMaterials, EcdhCurveSpec, EdkWrapping, EncryptedDataKey,
    EncryptionMaterials, PlaintextDataKey,
};

/// The key provider ID of every encrypted data key that the raw ECDH keyring writes.
pub(crate) const RAW_ECDH_PROVIDER_ID: &str = "raw-ecdh";
/// The key provider ID of every encrypted data key that the AWS KMS ECDH keyring writes.
pub(crate) const KMS_ECDH_PROVIDER_ID: &str = "aws-kms-ecdh";
/// The version byte at the start of the key provider information. Both ECDH keyrings write it.
const ECDH_KEYRING_VERSION: u8 = 0x01;

const ECDH_KDF: &[u8] = b"ecdh-key-derivation";
const ECDH_KDF_PRF_NAME: &[u8] = b"HMAC_SHA384";
const ECDH_KDF_DELIMITER: u8 = 0x00;
const KDF_SALT_LEN: usize = 32;
/// The KDF output: the commitment key, then the wrapping key.
const KDF_EXPECTED_LEN: usize = 64;
const COMMITMENT_KEY_LEN: usize = 32;
/// Where the AES-GCM ciphertext starts in the wrapped material.
const WRAPPED_KEY_INDEX: usize = KDF_SALT_LEN + COMMITMENT_KEY_LEN;
/// The wrapped material must be longer than this.
const MIN_WRAPPED_MATERIAL_LEN: usize = 68;
const AES_GCM_IV: [u8; 12] = [0; 12];

/// The key provider information length on each curve.
const PROVIDER_INFO_LENS: [usize; 3] = [75, 107, 143];
const PUBLIC_KEY_LEN_FIELD: usize = 4;
const RECIPIENT_KEY_INDEX: usize = 1 + PUBLIC_KEY_LEN_FIELD;

/// The public keys that a parsed key provider information names, both compressed.
pub(crate) struct ProviderInfo<'a> {
    pub(crate) recipient_public_key: &'a [u8],
    pub(crate) sender_public_key: &'a [u8],
}

/// Serialize the key provider information.
pub(crate) fn serialize_provider_info(
    sender_public_key: &[u8],
    recipient_public_key: &[u8],
) -> Result<Vec<u8>, Error> {
    let length = |key: &[u8]| {
        u32::try_from(key.len())
            .map(u32::to_be_bytes)
            .map_err(|_| Error::new(Kind::Internal, "Invalid compressed public key length."))
    };
    let mut info = Vec::with_capacity(
        1 + 2 * PUBLIC_KEY_LEN_FIELD + sender_public_key.len() + recipient_public_key.len(),
    );
    info.push(ECDH_KEYRING_VERSION);
    info.extend_from_slice(&length(recipient_public_key)?);
    info.extend_from_slice(recipient_public_key);
    info.extend_from_slice(&length(sender_public_key)?);
    info.extend_from_slice(sender_public_key);
    Ok(info)
}

/// Parse the key provider information of an ECDH encrypted data key.
///
/// Like the Dafny MPL, this reads the recipient key's length field
/// and takes the sender key as the rest of the bytes after the sender key's length field.
pub(crate) fn parse_provider_info(info: &[u8]) -> Result<ProviderInfo<'_>, Error> {
    if !PROVIDER_INFO_LENS.contains(&info.len()) {
        return Err(Error::new(
            Kind::Cryptographic,
            "EDK ProviderInfo longer than expected",
        ));
    }
    if info[0] != ECDH_KEYRING_VERSION {
        return Err(Error::new(
            Kind::Cryptographic,
            "Incorrect Keyring version found in provider info.",
        ));
    }
    let too_short = || {
        Error::new(
            Kind::Cryptographic,
            "Key Provider Info Serialization Error. Serialized length less than expected.",
        )
    };
    let length_field: [u8; PUBLIC_KEY_LEN_FIELD] = info[1..RECIPIENT_KEY_INDEX]
        .try_into()
        .map_err(|_| too_short())?;
    let recipient_key_end = usize::try_from(u32::from_be_bytes(length_field))
        .ok()
        .and_then(|len| RECIPIENT_KEY_INDEX.checked_add(len))
        .ok_or_else(too_short)?;
    let sender_key_index = recipient_key_end + PUBLIC_KEY_LEN_FIELD;
    if sender_key_index >= info.len() {
        return Err(too_short());
    }
    Ok(ProviderInfo {
        recipient_public_key: &info[RECIPIENT_KEY_INDEX..recipient_key_end],
        sender_public_key: &info[sender_key_index..],
    })
}

/// Whether an ECDH keyring should try `edk`.
///
/// A discovery keyring matches on the recipient key alone.
/// Any other keyring matches when the sender and recipient keys match its own, in either order.
///
/// Fails when an ECDH encrypted data key has malformed key provider information.
pub(crate) fn should_decrypt(
    edk: &EncryptedDataKey,
    discovery: bool,
    compressed_sender_public_key: &[u8],
    compressed_recipient_public_key: &[u8],
) -> Result<bool, Error> {
    let provider_id = edk.key_provider_id();
    if provider_id != RAW_ECDH_PROVIDER_ID && provider_id != KMS_ECDH_PROVIDER_ID {
        return Ok(false);
    }
    let info = parse_provider_info(edk.key_provider_info())?;
    if discovery {
        return Ok(compressed_recipient_public_key == info.recipient_public_key);
    }
    Ok((compressed_sender_public_key == info.sender_public_key
        && compressed_recipient_public_key == info.recipient_public_key)
        || (compressed_sender_public_key == info.recipient_public_key
            && compressed_recipient_public_key == info.sender_public_key))
}

/// The KDF's fixed info.
/// The public keys are compressed, sender first;
/// `canonical_ec` is the serialized encryption context.
pub(crate) fn fixed_info(
    curve: EcdhCurveSpec,
    sender_public_key: &[u8],
    recipient_public_key: &[u8],
    canonical_ec: &[u8],
) -> Vec<u8> {
    let curve_name = curve.kdf_name().as_bytes();
    let mut info = Vec::with_capacity(
        ECDH_KDF.len()
            + curve_name.len()
            + ECDH_KDF_PRF_NAME.len()
            + sender_public_key.len()
            + recipient_public_key.len()
            + canonical_ec.len()
            + 6,
    );
    info.extend_from_slice(ECDH_KDF);
    info.push(ECDH_KDF_DELIMITER);
    info.extend_from_slice(curve_name);
    info.push(ECDH_KDF_DELIMITER);
    info.extend_from_slice(ECDH_KDF_PRF_NAME);
    info.push(ECDH_KDF_DELIMITER);
    info.extend_from_slice(sender_public_key);
    info.extend_from_slice(recipient_public_key);
    info.push(ECDH_KDF_DELIMITER);
    info.push(ECDH_KEYRING_VERSION);
    info.push(ECDH_KDF_DELIMITER);
    info.extend_from_slice(canonical_ec);
    info
}

/// KDF in counter mode with HMAC-SHA-384 over the shared secret: 64 bytes of keying material.
///
/// The PRF input after the counter is `fixed_info || 0x00 || salt || L`,
/// with `L` the output length in bits as a big-endian `u32`,
/// as the Dafny primitives' `KdfCounterMode` builds it.
fn derive_keying_material(
    shared_secret: &[u8],
    fixed_info: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let length_bits = u32::try_from(KDF_EXPECTED_LEN * 8)
        .map_err(|_| Error::new(Kind::Internal, "KDF output length too large"))?;
    let mut info = Vec::with_capacity(fixed_info.len() + 1 + salt.len() + 4);
    info.extend_from_slice(fixed_info);
    info.push(0x00);
    info.extend_from_slice(salt);
    info.extend_from_slice(&length_bits.to_be_bytes());
    let mut okm = Zeroizing::new(vec![0u8; KDF_EXPECTED_LEN]);
    kbkdf_ctr_hmac(DigestAlg::Sha384, shared_secret, &info, &mut okm).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "ECDH shared wrapping key derivation failed",
            e,
        )
    })?;
    Ok(okm)
}

/// Wrap `material` under a key derived from `shared_secret`.
fn wrap(shared_secret: &[u8], fixed_info: &[u8], material: &[u8]) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; KDF_SALT_LEN];
    generate_random_bytes(&mut salt).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "failed to obtain entropy for the ECDH key derivation salt",
            e,
        )
    })?;
    let okm = derive_keying_material(shared_secret, fixed_info, &salt)?;
    let (commitment_key, wrapping_key) = okm.split_at(COMMITMENT_KEY_LEN);
    let mut wrapped = Vec::with_capacity(WRAPPED_KEY_INDEX + material.len() + 16);
    wrapped.extend_from_slice(&salt);
    wrapped.extend_from_slice(commitment_key);
    aes_encrypt(
        AesGcm::Aes256Gcm,
        &AES_GCM_IV,
        wrapping_key,
        material,
        fixed_info,
        &mut wrapped,
    )
    .map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "AES-GCM encryption of the data key failed",
            e,
        )
    })?;
    Ok(wrapped)
}

/// Unwrap `wrapped`, which [`wrap`] produced, into `key_len` bytes.
fn unwrap(
    shared_secret: &[u8],
    fixed_info: &[u8],
    wrapped: &[u8],
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if wrapped.len() <= MIN_WRAPPED_MATERIAL_LEN {
        return Err(Error::new(
            Kind::Cryptographic,
            "Received ciphertext is shorter than expected.",
        ));
    }
    let tag_index = WRAPPED_KEY_INDEX + key_len;
    if wrapped.len() <= tag_index {
        return Err(Error::new(
            Kind::Cryptographic,
            "Received EDK Ciphertext of incorrect length.",
        ));
    }
    let salt = &wrapped[..KDF_SALT_LEN];
    let commitment_key = &wrapped[KDF_SALT_LEN..WRAPPED_KEY_INDEX];
    let ciphertext = &wrapped[WRAPPED_KEY_INDEX..tag_index];
    let tag = &wrapped[tag_index..];

    let okm = derive_keying_material(shared_secret, fixed_info, salt)?;
    let (calculated_commitment_key, wrapping_key) = okm.split_at(COMMITMENT_KEY_LEN);
    if !constant_time_equal(calculated_commitment_key, commitment_key) {
        return Err(Error::new(
            Kind::Cryptographic,
            "Commitment keys do not match",
        ));
    }
    let mut material = Zeroizing::new(vec![0u8; ciphertext.len()]);
    aes_decrypt(
        AesGcm::Aes256Gcm,
        wrapping_key,
        ciphertext,
        tag,
        &AES_GCM_IV,
        fixed_info,
        &mut material,
    )
    .map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "AES-GCM decryption of the data key failed",
            e,
        )
    })?;
    Ok(material)
}

/// Generate a random key of the algorithm suite's encryption key length.
fn random_key(suite: &AlgorithmSuite) -> Result<PlaintextDataKey, Error> {
    let mut bytes = vec![0u8; suite.encryption_key_length()];
    generate_random_bytes(&mut bytes).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "failed to obtain entropy for the plaintext data key",
            e,
        )
    })?;
    Ok(PlaintextDataKey::new(bytes))
}

/// Add an ECDH encrypted data key to `materials`, generating the plaintext data key if they have none.
///
/// With intermediate key wrapping, the shared secret wraps a fresh intermediate key
/// instead of the plaintext data key.
pub(crate) fn add_encrypted_data_key(
    materials: EncryptionMaterials,
    shared_secret: &[u8],
    fixed_info: &[u8],
    provider_id: &str,
    provider_info: Vec<u8>,
) -> Result<EncryptionMaterials, Error> {
    let suite = materials.algorithm_suite();
    let edk = |ciphertext: Vec<u8>| {
        EncryptedDataKey::builder()
            .key_provider_id(provider_id)
            .key_provider_info(provider_info.clone())
            .ciphertext(ciphertext)
            .build()
    };
    match (suite.edk_wrapping(), materials.plaintext_data_key()) {
        (EdkWrapping::IntermediateKeyWrapping(_), existing) => {
            let aad = materials
                .encryption_context()
                .to_bytes()
                .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
            let (pdk, generated) = match existing {
                Some(key) => (key.clone(), false),
                None => (random_key(&suite)?, true),
            };
            let ikm = random_key(&suite)?;
            let wrapped_ikm = wrap(shared_secret, fixed_info, ikm.as_bytes())?;
            let (mut ciphertext, signing_key) =
                edk_wrapping::encrypt_pdk(&suite, ikm.as_bytes(), &aad, &pdk)?;
            ciphertext.extend_from_slice(&wrapped_ikm);
            let edk = edk(ciphertext)?;
            if generated {
                materials.add_data_key_with_symmetric_signing_key(pdk, edk, signing_key)
            } else {
                materials.add_encrypted_data_key_with_symmetric_signing_key(edk, signing_key)
            }
        }
        (_, Some(pdk)) => {
            let edk = edk(wrap(shared_secret, fixed_info, pdk.as_bytes())?)?;
            materials.add_encrypted_data_key(edk)
        }
        (_, None) => {
            let pdk = random_key(&suite)?;
            let edk = edk(wrap(shared_secret, fixed_info, pdk.as_bytes())?)?;
            materials.add_data_key(pdk, edk)
        }
    }
}

/// Unwrap the ciphertext of an ECDH encrypted data key.
/// Returns a copy of `materials` with the plaintext data key added.
pub(crate) fn decrypt_encrypted_data_key(
    materials: &DecryptionMaterials,
    shared_secret: &[u8],
    fixed_info: &[u8],
    ciphertext: &[u8],
) -> Result<DecryptionMaterials, Error> {
    let suite = materials.algorithm_suite();
    let key_len = suite.encryption_key_length();
    match suite.edk_wrapping() {
        EdkWrapping::IntermediateKeyWrapping(_) => {
            let (encrypted_pdk, wrapped_ikm) = edk_wrapping::split(&suite, ciphertext)
                .map_err(|e| Error::wrap("Invalid material for Intermediate Unwrapping", e))?;
            let aad = materials
                .encryption_context()
                .to_bytes()
                .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
            let ikm = unwrap(shared_secret, fixed_info, wrapped_ikm, key_len)?;
            let (pdk, signing_key) = edk_wrapping::decrypt_pdk(&suite, &ikm, &aad, encrypted_pdk)?;
            materials
                .clone()
                .add_data_key_with_symmetric_signing_key(pdk, signing_key)
        }
        _ => {
            let pdk = unwrap(shared_secret, fixed_info, ciphertext, key_len)?;
            materials
                .clone()
                .add_data_key(PlaintextDataKey::new(pdk.to_vec()))
        }
    }
}
