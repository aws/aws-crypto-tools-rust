// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Byte-faithful DB-ESDK structured-encryption format (the real wire format the
//! canonical Java/Dafny DB-ESDK reads and writes), for the Raw AES keyring and
//! both DBE suites: the non-signing
//! `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384` (binaryId
//! `0x67 0x00`) and the ECDSA-P384 signing
//! `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384`
//! (binaryId `0x67 0x01`).
//!
//! This is a direct port of the Dafny `StructuredEncryption` modules
//! (`Header`, `Footer`, `Crypt`, `Paths`, `Canonize`) plus the MPL
//! `IntermediateKeyWrapping`, `RawAESKeyring`, and the default CMM's
//! signing-key handling, and the DynamoDB item encryptor's encryption-context
//! construction (`MakeEncryptionContextV1`). The bytes produced here are
//! intended to interoperate with the canonical Java/Dafny DB-ESDK server (the
//! cross-language conformance cells).
//!
//! For the signing suite the default CMM generates a per-item ECDSA P-384 key
//! pair, stores the base64 SEC1-compressed verification key in the encryption
//! context under `aws-crypto-public-key` (which therefore appears in the stored
//! header EC), and the footer carries an ECDSA signature after the recipient
//! tag.
//!
//! Scope this iteration: Raw AES keyring, scalar attribute types
//! (S / N / B / BOOL / NULL), no `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT`
//! (header version 1). See `BLOCKED.md` for what remains (KMS / RSA / ECDH EDK
//! wrapping, sets/maps/lists, number normalization).

use crate::config::{
    AlgorithmSuiteId, CryptoAction, RawAesKeyringConfig, RawEcdhKeyringConfig, RawRsaKeyringConfig,
    TableEncryptionConfig,
};
use crate::crypto;
use crate::error::{DbEsdkError, Result};
use crate::model::{AttributeValue, Item};

/// The attribute holding the serialized header (a Binary terminal).
pub const HEADER_ATTRIBUTE: &str = "aws_dbe_head";
/// The attribute holding the serialized footer (a Binary terminal).
pub const FOOTER_ATTRIBUTE: &str = "aws_dbe_foot";

const FLAVOR_AES_SYMSIG: u8 = 0x00;
const FLAVOR_AES_ECDSA: u8 = 0x01;
const HEADER_VERSION_1: u8 = 0x01;
const COMMITMENT_LEN: usize = 32;
const RECIPIENT_TAG_LEN: usize = 48;

// Legend bytes (Header.dfy).
const LEGEND_ENCRYPT_AND_SIGN: u8 = 0x65; // 'e'
const LEGEND_SIGN_AND_INCLUDE: u8 = 0x63; // 'c'
const LEGEND_SIGN_ONLY: u8 = 0x73; // 's'

// DynamoDB terminal type IDs (Util.dfy).
const TYPE_NULL: [u8; 2] = [0x00, 0x00];
const TYPE_STRING: [u8; 2] = [0x00, 0x01];
const TYPE_NUMBER: [u8; 2] = [0x00, 0x02];
const TYPE_BOOLEAN: [u8; 2] = [0x00, 0x04];
const TYPE_BINARY: [u8; 2] = [0xFF, 0xFF];

// KDF labels.
const LABEL_DERIVE_KEY: &[u8] = b"AWS_DBE_DERIVE_KEY"; // 18 bytes
const LABEL_COMMIT_KEY: &[u8] = b"AWS_DBE_COMMIT_KEY"; // 18 bytes
const LABEL_KEYWRAP_MAC: &[u8] = b"AWS_MPL_INTERMEDIATE_KEYWRAP_MAC";
const LABEL_KEYWRAP_ENC: &[u8] = b"AWS_MPL_INTERMEDIATE_KEYWRAP_ENC";

// Raw ECDH EDK wrapping (EcdhEdkWrapping.dfy + Constants.dfy).
const ECDH_PROVIDER_ID: &[u8] = b"raw-ecdh";
const ECDH_KDF_LABEL: &[u8] = b"ecdh-key-derivation";
const ECDH_KDF_PRF_NAME: &[u8] = b"HMAC_SHA384";
const ECDH_KDF_DELIMITER: u8 = 0x00;
const ECDH_KEYRING_VERSION: u8 = 0x01;
const ECDH_KDF_SALT_LEN: usize = 32;
const ECDH_KDF_OUTPUT_LEN: usize = 64;
const ECDH_COMMITMENT_KEY_LEN: usize = 32;
/// Offset of the AES-GCM wrapped intermediate key within `providerWrappedIkm`
/// (`salt(32) || commitmentKey(32) || ...`).
const ECDH_WRAPPED_KEY_INDEX: usize = ECDH_KDF_SALT_LEN + ECDH_COMMITMENT_KEY_LEN;
const AWS_DBE_FIELD: &[u8] = b"AwsDbeField"; // 11 bytes
const ENCRYPTED: &[u8] = b"ENCRYPTED"; // 9 bytes
const PLAINTEXT: &[u8] = b"PLAINTEXT"; // 9 bytes
const MAP_TAG: u8 = b'$'; // 0x24

// Base-context encryption-context keys (DynamoDb item encryptor, V1).
const EC_TABLE_NAME: &[u8] = b"aws-crypto-table-name";
const EC_PARTITION_NAME: &[u8] = b"aws-crypto-partition-name";
const EC_SORT_NAME: &[u8] = b"aws-crypto-sort-name";
const EC_ATTR_PREFIX: &str = "aws-crypto-attr.";

/// Reserved encryption-context key under which a signing suite stores the
/// base64-encoded SEC1-compressed ECDSA verification key (DBE default CMM).
const EC_PUBLIC_KEY: &[u8] = b"aws-crypto-public-key";

/// A signed field in canonical order: the attribute name, its action, the
/// terminal type id, and the terminal value bytes (the encrypted value already
/// includes its 2-byte type-id prefix; the plaintext value does not).
struct SignedField {
    name: String,
    action: CryptoAction,
    canonical_path: Vec<u8>,
    type_id: [u8; 2],
    /// For ENCRYPT_AND_SIGN after encryption: `type_id || gcm_ct || tag`.
    /// For plaintext signed fields: the raw terminal value (no type-id).
    value: Vec<u8>,
}

/// Encrypt and sign `item` per `config`, wrapping the data key with `provider`
/// (the keyring-specific portion of intermediate key wrapping), producing the
/// byte-faithful attribute map to persist.
///
/// The structured-encryption core (encryption-context material description,
/// PDK encryption, per-field keys, header, footer) is identical across all
/// keyrings; only how the per-item *intermediate key* is wrapped into the EDK
/// (and the EDK's provider id / info) differs, which is what [`provider`]
/// supplies. See [`IntermediateKeyProvider`].
pub fn encrypt_item(
    config: &TableEncryptionConfig,
    provider: &dyn IntermediateKeyProvider,
    item: &Item,
) -> Result<Item> {
    encrypt_item_multi(config, &[provider], item)
}

/// Encrypt and sign `item` per `config`, wrapping the data key with EACH of
/// `providers` (a multi-keyring producing one Encrypted Data Key per component
/// keyring), producing the byte-faithful attribute map to persist.
///
/// The structured-encryption core is identical to the single-keyring case
/// ([`encrypt_item`], which is the one-provider special case): the plaintext
/// data key is generated once, then — exactly as the MPL multi-keyring's
/// `OnEncrypt` (generator first, then each child) calls
/// `IntermediateKeyWrapping.IntermediateWrap` per keyring — each provider yields
/// its own random intermediate key, from which a distinct `(pdkEncryptionKey,
/// symmetricSigningKey)` pair is derived; the *same* plaintext data key is
/// sealed under each `pdkEncryptionKey` to form that keyring's EDK. The header
/// lists all EDKs in keyring order and the footer carries one recipient tag per
/// EDK (in the same order), each computed with that EDK's `symmetricSigningKey`
/// (Footer.dfy `CreateFooter`).
pub fn encrypt_item_multi(
    config: &TableEncryptionConfig,
    providers: &[&dyn IntermediateKeyProvider],
    item: &Item,
) -> Result<Item> {
    config.validate()?;
    if providers.is_empty() {
        return Err(DbEsdkError::config(
            "at least one keyring is required to encrypt",
        ));
    }
    let flavor = flavor_for(config.algorithm_suite_id);

    // 1. Generate the message id and plaintext data key.
    let mut msg_id = [0u8; 32];
    crypto::fill_random(&mut msg_id)?;
    let plaintext_data_key = crypto::random_bytes(32)?;

    // 2. Build the V1 base encryption context (the material description).
    let mut enc_context = make_encryption_context_v1(config, item)?;

    // 3. For a signing suite, generate the per-item ECDSA P-384 signing key and
    //    seed the encryption context with the compressed verification key under
    //    the reserved `aws-crypto-public-key` entry (DBE default CMM behavior).
    //    This must happen BEFORE wrapping, since the keyring authenticates the
    //    full encryption context (including the public key) as AAD.
    let signer = if flavor == FLAVOR_AES_ECDSA {
        let signer = crypto::EcdsaP384Signer::generate()?;
        let b64 = crypto::base64_encode(signer.compressed_public_key()).into_bytes();
        enc_context.push((EC_PUBLIC_KEY.to_vec(), b64));
        enc_context.sort_by(|a, b| a.0.cmp(&b.0));
        Some(signer)
    } else {
        None
    };
    let ec_aad = serialize_context(&enc_context);

    // 4. The stored header EC is the full EC minus the caller's required keys.
    //    The Raw AES round-trip has no caller-required keys, so the base context
    //    keys are not stored and only the signing suite's `aws-crypto-public-key`
    //    entry (if any) is written into the header.
    let stored_ec: Vec<(Vec<u8>, Vec<u8>)> = enc_context
        .iter()
        .filter(|(k, _)| k.as_slice() == EC_PUBLIC_KEY)
        .cloned()
        .collect();

    // 5. Intermediate key wrapping, once per keyring. The keyring-specific
    //    portion (wrap the intermediate key material + the EDK provider id /
    //    info) is delegated to each provider; the generic PDK encryption + EDK
    //    serialization is here (IntermediateKeyWrapping.dfy `IntermediateWrap`).
    //    Each keyring gets a distinct intermediate key and therefore a distinct
    //    symmetric signing key; all seal the same plaintext data key.
    let mut edks: Vec<EncryptedDataKey> = Vec::with_capacity(providers.len());
    let mut symmetric_signing_keys: Vec<Vec<u8>> = Vec::with_capacity(providers.len());
    for provider in providers {
        let generated = provider.generate_and_wrap(&enc_context, &ec_aad)?;
        let (pdk_encryption_key, symmetric_signing_key) =
            derive_keys_from_intermediate(&generated.intermediate_material)?;
        let encrypted_pdk = crypto::aes_gcm_encrypt(
            &pdk_encryption_key,
            &[0u8; 12],
            &ec_aad,
            &plaintext_data_key,
        )?;
        // EDK ciphertext = encryptedPdk(keyLen + tagLen = 48) || providerWrappedIkm.
        let mut edk_ciphertext = encrypted_pdk;
        edk_ciphertext.extend_from_slice(&generated.provider_wrapped_ikm);
        edks.push(EncryptedDataKey {
            provider_id: generated.edk_provider_id,
            provider_info: generated.edk_provider_info,
            ciphertext: edk_ciphertext,
        });
        symmetric_signing_keys.push(symmetric_signing_key);
    }

    // 6. Derive the field root key and per-field keys.
    let field_root_key = derive_field_root_key(&plaintext_data_key, &msg_id)?;

    // 7. Canonicalize + sort signed fields, encrypt ENCRYPT_AND_SIGN terminals.
    let mut signed = collect_signed_fields(config, item)?;
    signed.sort_by(|a, b| a.canonical_path.cmp(&b.canonical_path));

    let mut output = Item::new();
    // Pass through DO_NOTHING attributes untouched.
    for (name, value) in item {
        if config.action_for(name) == CryptoAction::DoNothing {
            output.insert(name.clone(), value.clone());
        }
    }

    let mut offset: u32 = 0;
    for field in &mut signed {
        if field.action == CryptoAction::EncryptAndSign {
            let (cipher_key, nonce) = field_key(&field_root_key, offset)?;
            offset += 1;
            // Terminal value to encrypt = the raw value bytes (no type-id).
            let plaintext = &field.value;
            let sealed = crypto::aes_gcm_encrypt(&cipher_key, &nonce, &field.canonical_path, plaintext)?;
            // Stored value = type_id(2) || ciphertext || tag.
            let mut stored_value = Vec::with_capacity(2 + sealed.len());
            stored_value.extend_from_slice(&field.type_id);
            stored_value.extend_from_slice(&sealed);
            // The output DDB attribute is Binary holding type_id||ct||tag.
            output.insert(field.name.clone(), AttributeValue::B(stored_value.clone()));
            // For the footer, the canonical value carries type_id||ct||tag.
            field.value = stored_value;
        } else {
            // Plaintext signed field: carried through as its native value.
            output.insert(
                field.name.clone(),
                item.get(&field.name)
                    .expect("signed field must be present in the item")
                    .clone(),
            );
        }
    }

    // 8. Build the header (version/flavor/msgID/legend/storedEC/EDKs) and append
    //    the key commitment.
    let commit_key = derive_commit_key(&plaintext_data_key, &msg_id)?;
    let header = serialize_header(flavor, &msg_id, &signed, &stored_ec, &edks, &commit_key)?;

    // 9. Build the footer: one recipient tag per EDK over the canonical record's
    //    SHA-384 (each with that EDK's symmetric signing key, in EDK order),
    //    followed by the single ECDSA signature for the signing suite.
    let canonical_hash = canonical_hash(&header, &ec_aad, &signed);
    let mut footer = Vec::with_capacity(symmetric_signing_keys.len() * RECIPIENT_TAG_LEN);
    for symmetric_signing_key in &symmetric_signing_keys {
        footer.extend_from_slice(&crypto::hmac_sha384(symmetric_signing_key, &canonical_hash));
    }
    if let Some(signer) = &signer {
        let signature = signer.sign(&canonical_hash)?;
        footer.extend_from_slice(&signature);
    }

    output.insert(HEADER_ATTRIBUTE.to_string(), AttributeValue::B(header));
    output.insert(FOOTER_ATTRIBUTE.to_string(), AttributeValue::B(footer));
    Ok(output)
}

/// Encrypt and sign `item` using a Raw AES keyring (a convenience wrapper over
/// [`encrypt_item`] with the [`RawAesProvider`]).
pub fn encrypt_item_raw_aes(
    config: &TableEncryptionConfig,
    raw: &RawAesKeyringConfig,
    item: &Item,
) -> Result<Item> {
    encrypt_item(config, &RawAesProvider { raw }, item)
}

/// Decrypt and verify a stored item using a Raw AES keyring (a convenience
/// wrapper over [`decrypt_item`] with the [`RawAesProvider`]).
pub fn decrypt_item_raw_aes(
    config: &TableEncryptionConfig,
    raw: &RawAesKeyringConfig,
    stored: &Item,
) -> Result<Item> {
    decrypt_item(config, &RawAesProvider { raw }, stored)
}

/// Decrypt and verify a stored item produced by [`encrypt_item`], unwrapping the
/// data key with `provider`.
pub fn decrypt_item(
    config: &TableEncryptionConfig,
    provider: &dyn IntermediateKeyProvider,
    stored: &Item,
) -> Result<Item> {
    decrypt_item_multi(config, &[provider], stored)
}

/// Decrypt and verify a stored item produced by [`encrypt_item_multi`],
/// unwrapping the data key with whichever of `providers` (a multi-keyring's
/// component keyrings) owns a decryptable Encrypted Data Key.
///
/// Mirrors the MPL multi-keyring `OnDecrypt` + Footer.dfy `validate`: every
/// keyring is offered each stored EDK and only attempts the ones it recognizes
/// (by provider id / info); the first EDK that unwraps yields the plaintext data
/// key and that EDK's symmetric signing key. The footer carries one recipient
/// tag per EDK, and verification succeeds if the tag recomputed with the
/// recovered symmetric signing key matches any stored tag.
pub fn decrypt_item_multi(
    config: &TableEncryptionConfig,
    providers: &[&dyn IntermediateKeyProvider],
    stored: &Item,
) -> Result<Item> {
    config.validate()?;
    if providers.is_empty() {
        return Err(DbEsdkError::config(
            "at least one keyring is required to decrypt",
        ));
    }

    let header = take_binary(stored, HEADER_ATTRIBUTE)?;
    let footer = take_binary(stored, FOOTER_ATTRIBUTE)?;

    let parsed = parse_header(&header)?;

    // Reconstruct the full encryption context: the V1 base context (rebuilt from
    // the stored item + config) plus any entries persisted in the header EC (the
    // signing suite's `aws-crypto-public-key`).
    let mut enc_context = make_encryption_context_v1(config, stored)?;
    for (key, value) in &parsed.stored_ec {
        enc_context.push((key.clone(), value.clone()));
    }
    enc_context.sort_by(|a, b| a.0.cmp(&b.0));
    let ec_aad = serialize_context(&enc_context);

    // Unwrap the data key. Offer each stored EDK to each keyring; a keyring
    // recognizes only EDKs whose provider id / info it owns. The EDK ciphertext
    // splits into the wrapped PDK (encryptKeyLength + tagLength = 48 bytes) and
    // the provider-wrapped intermediate key; the recovered intermediate key
    // yields this EDK's (pdkEncryptionKey, symmetricSigningKey), and the wrapped
    // PDK is decrypted with the key-encryption key (iv = 0).
    let mut recovered: Option<(Vec<u8>, Vec<u8>)> = None;
    'outer: for edk in &parsed.edks {
        if edk.ciphertext.len() < 48 {
            continue;
        }
        let (encrypted_pdk, provider_wrapped_ikm) = edk.ciphertext.split_at(48);
        for provider in providers {
            let intermediate = match provider.unwrap(
                &edk.provider_id,
                &edk.provider_info,
                provider_wrapped_ikm,
                &enc_context,
                &ec_aad,
            ) {
                Ok(intermediate) => intermediate,
                Err(_) => continue,
            };
            let (pdk_encryption_key, symmetric_signing_key) =
                derive_keys_from_intermediate(&intermediate)?;
            if let Ok(pdk) =
                crypto::aes_gcm_decrypt(&pdk_encryption_key, &[0u8; 12], &ec_aad, encrypted_pdk)
            {
                recovered = Some((pdk, symmetric_signing_key));
                break 'outer;
            }
        }
    }
    let (plaintext_data_key, symmetric_signing_key) = recovered.ok_or_else(|| {
        DbEsdkError::invalid_item("no configured keyring could decrypt any data key")
    })?;

    // Verify the header commitment.
    let commit_key = derive_commit_key(&plaintext_data_key, &parsed.msg_id)?;
    let expected_commitment = header_commitment(&commit_key, &parsed.partial_header);
    if !constant_time_eq(&expected_commitment, &parsed.commitment) {
        return Err(DbEsdkError::invalid_item("header key commitment mismatch"));
    }

    // Rebuild the signed-field list from the stored item, applying the legend
    // actions in canonical order, then verify the footer recipient tags.
    let mut signed = collect_signed_fields_for_decrypt(config, stored, &parsed.legend)?;
    signed.sort_by(|a, b| a.canonical_path.cmp(&b.canonical_path));

    let canonical_hash = canonical_hash(&header, &ec_aad, &signed);

    // The footer is one 48-byte recipient tag per EDK (in EDK order), optionally
    // followed by the 103-byte ECDSA signature for the signing suite.
    let n_edks = parsed.edks.len();
    let has_signature = parsed.flavor == FLAVOR_AES_ECDSA;
    let tags_len = n_edks * RECIPIENT_TAG_LEN;
    let expected_footer_len =
        tags_len + if has_signature { crypto::ECDSA_P384_SIGNATURE_LEN } else { 0 };
    if footer.len() != expected_footer_len {
        return Err(DbEsdkError::invalid_item(
            "footer length does not match the number of encrypted data keys",
        ));
    }

    // Verification succeeds if the tag recomputed with the recovered EDK's
    // symmetric signing key matches any of the stored recipient tags.
    let our_tag = crypto::hmac_sha384(&symmetric_signing_key, &canonical_hash);
    let tag_matches = footer[..tags_len]
        .chunks_exact(RECIPIENT_TAG_LEN)
        .any(|tag| constant_time_eq(&our_tag, tag));
    if !tag_matches {
        return Err(DbEsdkError::invalid_item(
            "footer recipient tag did not verify",
        ));
    }

    // Verify the ECDSA signature for the signing suite (the bytes after all
    // recipient tags), using the compressed verification key from the EC.
    if has_signature {
        let verification_key = parsed
            .stored_ec
            .iter()
            .find(|(k, _)| k.as_slice() == EC_PUBLIC_KEY)
            .map(|(_, v)| v.as_slice())
            .ok_or_else(|| {
                DbEsdkError::invalid_item(
                    "signing-suite header is missing the aws-crypto-public-key entry",
                )
            })?;
        let verification_key = crypto::base64_decode_bytes(verification_key)?;
        let signature = &footer[tags_len..];
        crypto::ecdsa_p384_verify(&verification_key, &canonical_hash, signature)?;
    }

    // Decrypt the ENCRYPT_AND_SIGN terminals.
    let field_root_key = derive_field_root_key(&plaintext_data_key, &parsed.msg_id)?;
    let mut output = Item::new();
    for (name, value) in stored {
        if name == HEADER_ATTRIBUTE || name == FOOTER_ATTRIBUTE {
            continue;
        }
        if config.action_for(name) == CryptoAction::DoNothing {
            output.insert(name.clone(), value.clone());
        }
    }

    let mut offset: u32 = 0;
    for field in &signed {
        if field.action == CryptoAction::EncryptAndSign {
            let (cipher_key, nonce) = field_key(&field_root_key, offset)?;
            offset += 1;
            let stored_value = match stored.get(&field.name) {
                Some(AttributeValue::B(bytes)) => bytes,
                _ => {
                    return Err(DbEsdkError::invalid_item(format!(
                        "encrypted attribute '{}' is not stored as binary",
                        field.name
                    )))
                }
            };
            if stored_value.len() < 2 {
                return Err(DbEsdkError::invalid_item("encrypted terminal too short"));
            }
            let type_id = [stored_value[0], stored_value[1]];
            let plaintext =
                crypto::aes_gcm_decrypt(&cipher_key, &nonce, &field.canonical_path, &stored_value[2..])?;
            output.insert(field.name.clone(), decode_terminal(type_id, &plaintext)?);
        } else {
            output.insert(
                field.name.clone(),
                stored
                    .get(&field.name)
                    .expect("signed field present")
                    .clone(),
            );
        }
    }
    Ok(output)
}

// ---------------------------------------------------------------------------
// Key derivation (Crypt.dfy + IntermediateKeyWrapping.dfy)
// ---------------------------------------------------------------------------

fn derive_field_root_key(plaintext_data_key: &[u8], msg_id: &[u8; 32]) -> Result<Vec<u8>> {
    let mut info = LABEL_DERIVE_KEY.to_vec();
    info.extend_from_slice(msg_id);
    crypto::hkdf_sha512(plaintext_data_key, &info, 32)
}

fn derive_commit_key(plaintext_data_key: &[u8], msg_id: &[u8; 32]) -> Result<Vec<u8>> {
    let mut info = LABEL_COMMIT_KEY.to_vec();
    info.extend_from_slice(msg_id);
    crypto::hkdf_sha512(plaintext_data_key, &info, 32)
}

/// The per-field cipher key (32 bytes) and nonce (12 bytes) for ENCRYPT_AND_SIGN
/// field at ordinal `offset` (Crypt.dfy `FieldKey`).
fn field_key(field_root_key: &[u8], offset: u32) -> Result<(Vec<u8>, [u8; 12])> {
    let iv = field_key_nonce(offset.wrapping_mul(3));
    let stream = crypto::aes256_ctr_keystream(field_root_key, &iv, 44)?;
    let cipher_key = stream[0..32].to_vec();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&stream[32..44]);
    Ok((cipher_key, nonce))
}

/// `"AwsDbeField" || 0x2c || UInt32BE(offset)` (Crypt.dfy `FieldKeyNonce`).
fn field_key_nonce(offset: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..11].copy_from_slice(AWS_DBE_FIELD);
    iv[11] = 44; // length of the eventual FieldKey
    iv[12..16].copy_from_slice(&offset.to_be_bytes());
    iv
}

/// The keyring-specific portion of intermediate key wrapping: produce (on
/// encrypt) and recover (on decrypt) the per-item *intermediate key*, plus the
/// EDK provider id / info that identify the wrapping key.
///
/// The MPL wraps a DBE data key in two layers: a generic layer (a per-item
/// random `intermediate key` from which the PDK-encryption key and symmetric
/// signing key are derived, with the plaintext data key sealed under the
/// PDK-encryption key) and a keyring layer (the intermediate key is wrapped by
/// the keyring). Only the keyring layer differs between keyrings — Raw AES seals
/// the intermediate key with the wrapping key, AWS KMS calls `GenerateDataKey` /
/// `Decrypt`, etc. — so that is exactly what this trait abstracts. The generic
/// layer lives in [`encrypt_item`] / [`decrypt_item`].
pub trait IntermediateKeyProvider {
    /// Produce a fresh intermediate key and its provider-wrapped form, plus the
    /// EDK provider id / info. `ec` is the full encryption context (sorted raw
    /// key/value byte pairs, including any signing-suite public key); `ec_aad`
    /// is its canonical serialization (the AAD the wrap authenticates).
    fn generate_and_wrap(&self, ec: &[(Vec<u8>, Vec<u8>)], ec_aad: &[u8]) -> Result<GeneratedKey>;

    /// Recover the intermediate key from a stored EDK's provider-wrapped
    /// intermediate-key material. `provider_id` / `provider_info` are the EDK's
    /// identifying fields; `ec` / `ec_aad` are as in [`Self::generate_and_wrap`].
    fn unwrap(
        &self,
        provider_id: &[u8],
        provider_info: &[u8],
        provider_wrapped_ikm: &[u8],
        ec: &[(Vec<u8>, Vec<u8>)],
        ec_aad: &[u8],
    ) -> Result<Vec<u8>>;
}

/// The output of [`IntermediateKeyProvider::generate_and_wrap`]: the freshly
/// generated intermediate key and the EDK fields that carry it.
pub struct GeneratedKey {
    /// The plaintext intermediate key material (the HKDF input keying material).
    pub intermediate_material: Vec<u8>,
    /// The keyring-wrapped intermediate key (the `providerWrappedIkm` appended
    /// after the wrapped PDK in the EDK ciphertext).
    pub provider_wrapped_ikm: Vec<u8>,
    /// The EDK key-provider id (e.g. the Raw AES key namespace, or `aws-kms`).
    pub edk_provider_id: Vec<u8>,
    /// The EDK key-provider info (e.g. the Raw AES `keyName||...||iv`, or the
    /// KMS key ARN).
    pub edk_provider_info: Vec<u8>,
}

#[derive(Clone)]
struct EncryptedDataKey {
    provider_id: Vec<u8>,
    provider_info: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// The [`IntermediateKeyProvider`] for a Raw AES keyring: the intermediate key
/// is sealed with the configured wrapping key under AES-256-GCM with a fresh
/// random IV (which is carried in the EDK provider info), exactly as the MPL
/// `RawAESKeyring` does under intermediate key wrapping.
pub struct RawAesProvider<'a> {
    /// The Raw AES keyring configuration (wrapping key + namespace / name).
    pub raw: &'a RawAesKeyringConfig,
}

impl IntermediateKeyProvider for RawAesProvider<'_> {
    fn generate_and_wrap(&self, _ec: &[(Vec<u8>, Vec<u8>)], ec_aad: &[u8]) -> Result<GeneratedKey> {
        // For each EDK a distinct intermediate key is generated at random.
        let intermediate = crypto::random_bytes(32)?;
        let mut iv = [0u8; 12];
        crypto::fill_random(&mut iv)?;
        let provider_wrapped_ikm =
            crypto::aes_gcm_encrypt(&self.raw.wrapping_key, &iv, ec_aad, &intermediate)?;
        Ok(GeneratedKey {
            intermediate_material: intermediate,
            provider_wrapped_ikm,
            edk_provider_id: self.raw.key_namespace.as_bytes().to_vec(),
            edk_provider_info: serialize_raw_aes_provider_info(&self.raw.key_name, &iv),
        })
    }

    fn unwrap(
        &self,
        _provider_id: &[u8],
        provider_info: &[u8],
        provider_wrapped_ikm: &[u8],
        _ec: &[(Vec<u8>, Vec<u8>)],
        ec_aad: &[u8],
    ) -> Result<Vec<u8>> {
        let iv = raw_aes_iv_from_provider_info(&self.raw.key_name, provider_info)?;
        crypto::aes_gcm_decrypt(&self.raw.wrapping_key, &iv, ec_aad, provider_wrapped_ikm)
    }
}

/// The [`IntermediateKeyProvider`] for a Raw RSA keyring: the intermediate key
/// is wrapped by RSA-encrypting it under the configured public key (and
/// recovered by RSA-decrypting under the private key), exactly as the MPL
/// `RawRSAKeyring` does under intermediate key wrapping
/// (`RsaGenerateAndWrapKeyMaterial` / `RsaUnwrapKeyMaterial`).
///
/// Unlike the Raw AES wrap, RSA padding takes no AAD, so the encryption context
/// does not authenticate the `providerWrappedIkm` here — the EC is still bound
/// to the message through the wrapped PDK and the footer. The EDK carries the
/// keyring's namespace as the provider id and the key name as the provider
/// info (`RawRSAKeyring.OnEncrypt`); the ciphertext is the RSA-wrapped
/// intermediate key.
pub struct RawRsaProvider<'a> {
    /// The Raw RSA keyring configuration (key material + namespace / name).
    pub raw: &'a RawRsaKeyringConfig,
}

impl IntermediateKeyProvider for RawRsaProvider<'_> {
    fn generate_and_wrap(&self, _ec: &[(Vec<u8>, Vec<u8>)], _ec_aad: &[u8]) -> Result<GeneratedKey> {
        let public_key_pem = self.raw.public_key.as_ref().ok_or_else(|| {
            DbEsdkError::config("a Raw RSA keyring without a public key cannot encrypt")
        })?;
        let public_key_der = crypto::pem_to_der(public_key_pem)?;
        // For each EDK a distinct intermediate key is generated at random
        // (GetEncryptKeyLength == 32 for the DBE AES-256 suites).
        let intermediate = crypto::random_bytes(32)?;
        let provider_wrapped_ikm = crypto::rsa_encrypt(
            &public_key_der,
            self.raw.padding_scheme.to_crypto(),
            &intermediate,
        )?;
        Ok(GeneratedKey {
            intermediate_material: intermediate,
            provider_wrapped_ikm,
            edk_provider_id: self.raw.key_namespace.as_bytes().to_vec(),
            edk_provider_info: self.raw.key_name.as_bytes().to_vec(),
        })
    }

    fn unwrap(
        &self,
        provider_id: &[u8],
        provider_info: &[u8],
        provider_wrapped_ikm: &[u8],
        _ec: &[(Vec<u8>, Vec<u8>)],
        _ec_aad: &[u8],
    ) -> Result<Vec<u8>> {
        // RawRSAKeyring.ShouldDecryptEDK: the keyring only attempts an EDK whose
        // provider id == key namespace and provider info == key name.
        if provider_id != self.raw.key_namespace.as_bytes()
            || provider_info != self.raw.key_name.as_bytes()
        {
            return Err(DbEsdkError::invalid_item(
                "Raw RSA EDK provider id/info does not match the configured keyring",
            ));
        }
        let private_key_pem = self.raw.private_key.as_ref().ok_or_else(|| {
            DbEsdkError::config("a Raw RSA keyring without a private key cannot decrypt")
        })?;
        let private_key_der = crypto::pem_to_der(private_key_pem)?;
        crypto::rsa_decrypt(
            &private_key_der,
            self.raw.padding_scheme.to_crypto(),
            provider_wrapped_ikm,
        )
    }
}

/// The [`IntermediateKeyProvider`] for a Raw ECDH keyring using the
/// `RawPrivateKeyToStaticPublicKey` agreement scheme, ported from the MPL Dafny
/// `RawECDHKeyring` + `EcdhEdkWrapping`.
///
/// Unlike Raw AES / RSA, the keyring does not encrypt the intermediate key
/// directly under a static wrapping key. Instead it derives a shared secret via
/// ECDH between the sender's static private key and the recipient's static
/// public key, runs it through the NIST SP 800-108 counter-mode KDF (HMAC-SHA384)
/// with a fresh 32-byte salt to produce a 64-byte block, splits that into a
/// 32-byte commitment key and a 32-byte shared wrapping key, and AES-256-GCM
/// seals the intermediate key (IV = 0) under the wrapping key with the
/// derivation `FixedInfo` as AAD. The `providerWrappedIkm` is
/// `salt(32) || commitmentKey(32) || ciphertext || tag`, and the EDK provider
/// info carries the compressed sender + recipient public keys.
pub struct RawEcdhProvider<'a> {
    /// The Raw ECDH keyring configuration (sender private + recipient public
    /// keys + curve).
    pub raw: &'a RawEcdhKeyringConfig,
}

impl RawEcdhProvider<'_> {
    /// `FixedInfo` for the key derivation (EcdhEdkWrapping.dfy `SerializeFixedInfo`):
    /// `"ecdh-key-derivation" || 0x00 || curve || 0x00 || "HMAC_SHA384" || 0x00
    /// || senderCompressed || recipientCompressed || 0x00 || version(0x01) ||
    /// 0x00 || canonicalEC`.
    fn fixed_info(
        curve: crypto::EcdhCurve,
        sender_compressed: &[u8],
        recipient_compressed: &[u8],
        ec_aad: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ECDH_KDF_LABEL);
        out.push(ECDH_KDF_DELIMITER);
        out.extend_from_slice(curve.kdf_name().as_bytes());
        out.push(ECDH_KDF_DELIMITER);
        out.extend_from_slice(ECDH_KDF_PRF_NAME);
        out.push(ECDH_KDF_DELIMITER);
        out.extend_from_slice(sender_compressed);
        out.extend_from_slice(recipient_compressed);
        out.push(ECDH_KDF_DELIMITER);
        out.push(ECDH_KEYRING_VERSION);
        out.push(ECDH_KDF_DELIMITER);
        out.extend_from_slice(ec_aad);
        out
    }

    /// EDK provider info (RawECDHKeyring.dfy `SerializeProviderInfo`):
    /// `version(0x01) || UInt32BE(recipientLen) || recipientCompressed ||
    /// UInt32BE(senderLen) || senderCompressed`.
    fn serialize_provider_info(sender_compressed: &[u8], recipient_compressed: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(ECDH_KEYRING_VERSION);
        out.extend_from_slice(&(recipient_compressed.len() as u32).to_be_bytes());
        out.extend_from_slice(recipient_compressed);
        out.extend_from_slice(&(sender_compressed.len() as u32).to_be_bytes());
        out.extend_from_slice(sender_compressed);
        out
    }

    /// Parse the provider info, returning `(senderCompressed, recipientCompressed)`.
    fn parse_provider_info(info: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let err = || DbEsdkError::invalid_item("malformed Raw ECDH EDK provider info");
        if info.len() < 5 || info[0] != ECDH_KEYRING_VERSION {
            return Err(DbEsdkError::invalid_item(
                "Raw ECDH provider info has an unexpected keyring version",
            ));
        }
        let recipient_len = u32::from_be_bytes([info[1], info[2], info[3], info[4]]) as usize;
        let recipient_end = 5usize.checked_add(recipient_len).ok_or_else(err)?;
        let sender_len_end = recipient_end.checked_add(4).ok_or_else(err)?;
        if info.len() < sender_len_end {
            return Err(err());
        }
        let recipient = info[5..recipient_end].to_vec();
        let sender_len = u32::from_be_bytes([
            info[recipient_end],
            info[recipient_end + 1],
            info[recipient_end + 2],
            info[recipient_end + 3],
        ]) as usize;
        let sender_end = sender_len_end.checked_add(sender_len).ok_or_else(err)?;
        if info.len() < sender_end {
            return Err(err());
        }
        let sender = info[sender_len_end..sender_end].to_vec();
        Ok((sender, recipient))
    }
}

impl IntermediateKeyProvider for RawEcdhProvider<'_> {
    fn generate_and_wrap(&self, _ec: &[(Vec<u8>, Vec<u8>)], ec_aad: &[u8]) -> Result<GeneratedKey> {
        let curve = self.raw.curve_spec.to_crypto();
        let sender_private_der = crypto::pem_to_der(&self.raw.sender_static_private_key)?;
        let sender_compressed = crypto::ecdh_compressed_public_key(&sender_private_der, curve)?;
        let recipient_compressed =
            crypto::ecdh_compress_spki_public_key(&self.raw.recipient_public_key, curve)?;
        let shared_secret =
            crypto::ecdh_shared_secret(&sender_private_der, &self.raw.recipient_public_key, curve)?;
        let fixed_info =
            Self::fixed_info(curve, &sender_compressed, &recipient_compressed, ec_aad);

        // For each EDK a distinct intermediate key is generated at random.
        let intermediate = crypto::random_bytes(32)?;
        let salt = crypto::random_bytes(ECDH_KDF_SALT_LEN)?;
        let derived =
            crypto::kdf_ctr_hmac_sha384(&shared_secret, &fixed_info, &salt, ECDH_KDF_OUTPUT_LEN)?;
        let (commitment_key, shared_wrapping_key) = derived.split_at(ECDH_COMMITMENT_KEY_LEN);
        // AES-256-GCM(sharedWrappingKey, iv=0, intermediate, aad=fixedInfo) → ct||tag.
        let wrapped = crypto::aes_gcm_encrypt(shared_wrapping_key, &[0u8; 12], &fixed_info, &intermediate)?;

        let mut provider_wrapped_ikm =
            Vec::with_capacity(salt.len() + commitment_key.len() + wrapped.len());
        provider_wrapped_ikm.extend_from_slice(&salt);
        provider_wrapped_ikm.extend_from_slice(commitment_key);
        provider_wrapped_ikm.extend_from_slice(&wrapped);

        Ok(GeneratedKey {
            intermediate_material: intermediate,
            provider_wrapped_ikm,
            edk_provider_id: ECDH_PROVIDER_ID.to_vec(),
            edk_provider_info: Self::serialize_provider_info(&sender_compressed, &recipient_compressed),
        })
    }

    fn unwrap(
        &self,
        provider_id: &[u8],
        provider_info: &[u8],
        provider_wrapped_ikm: &[u8],
        _ec: &[(Vec<u8>, Vec<u8>)],
        ec_aad: &[u8],
    ) -> Result<Vec<u8>> {
        if provider_id != ECDH_PROVIDER_ID {
            return Err(DbEsdkError::invalid_item(
                "Raw ECDH EDK provider id does not match the configured keyring",
            ));
        }
        let curve = self.raw.curve_spec.to_crypto();
        // The sender / recipient compressed keys are reconstructed from the EDK
        // provider info so the derivation FixedInfo matches what the writer used.
        let (sender_compressed, recipient_compressed) = Self::parse_provider_info(provider_info)?;
        let sender_private_der = crypto::pem_to_der(&self.raw.sender_static_private_key)?;
        // RawPrivateKeyToStaticPublicKey: the shared secret uses the configured
        // sender static private key and the configured recipient public key
        // (which the conformance test sets to the same key pair).
        let shared_secret =
            crypto::ecdh_shared_secret(&sender_private_der, &self.raw.recipient_public_key, curve)?;
        let fixed_info =
            Self::fixed_info(curve, &sender_compressed, &recipient_compressed, ec_aad);

        // Deserialize: salt(32) || commitmentKey(32) || encryptedKey || authTag.
        if provider_wrapped_ikm.len() <= ECDH_WRAPPED_KEY_INDEX {
            return Err(DbEsdkError::invalid_item(
                "Raw ECDH wrapped material is shorter than expected",
            ));
        }
        let salt = &provider_wrapped_ikm[..ECDH_KDF_SALT_LEN];
        let commitment_key =
            &provider_wrapped_ikm[ECDH_KDF_SALT_LEN..ECDH_WRAPPED_KEY_INDEX];
        let wrapped_key_and_tag = &provider_wrapped_ikm[ECDH_WRAPPED_KEY_INDEX..];

        let derived =
            crypto::kdf_ctr_hmac_sha384(&shared_secret, &fixed_info, salt, ECDH_KDF_OUTPUT_LEN)?;
        let (calculated_commitment_key, shared_wrapping_key) =
            derived.split_at(ECDH_COMMITMENT_KEY_LEN);
        // The calculated commitment key MUST equal the one stored in the EDK.
        if !constant_time_eq(calculated_commitment_key, commitment_key) {
            return Err(DbEsdkError::invalid_item(
                "Raw ECDH commitment key did not match",
            ));
        }
        crypto::aes_gcm_decrypt(shared_wrapping_key, &[0u8; 12], &fixed_info, wrapped_key_and_tag)
    }
}

/// `(pdkEncryptionKey, symmetricSigningKey)` derived from the intermediate key
/// (IntermediateKeyWrapping.dfy `DeriveKeysFromIntermediateMaterial`).
fn derive_keys_from_intermediate(intermediate: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let prk = crypto::hkdf_sha512_extract(&[], intermediate);
    let symmetric_signing_key = crypto::hkdf_sha512_expand(&prk, LABEL_KEYWRAP_MAC, 32)?;
    let pdk_encryption_key = crypto::hkdf_sha512_expand(&prk, LABEL_KEYWRAP_ENC, 32)?;
    Ok((pdk_encryption_key, symmetric_signing_key))
}

/// Raw AES provider info: `keyName || UInt32BE(128) || UInt32BE(12) || iv`.
fn serialize_raw_aes_provider_info(key_name: &str, iv: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(key_name.as_bytes());
    out.extend_from_slice(&128u32.to_be_bytes()); // auth tag length in bits
    out.extend_from_slice(&12u32.to_be_bytes()); // iv length in bytes
    out.extend_from_slice(iv);
    out
}

fn raw_aes_iv_from_provider_info(key_name: &str, info: &[u8]) -> Result<[u8; 12]> {
    let key_len = key_name.len();
    let iv_start = key_len + 8;
    if info.len() != iv_start + 12 || &info[..key_len] != key_name.as_bytes() {
        return Err(DbEsdkError::invalid_item(
            "raw AES provider info does not match the configured key name",
        ));
    }
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&info[iv_start..iv_start + 12]);
    Ok(iv)
}

// ---------------------------------------------------------------------------
// Encryption context (DynamoDb item encryptor V1 + EncryptionContextToAAD)
// ---------------------------------------------------------------------------

/// The V1 DynamoDB item base context (material description), as a sorted map of
/// raw key bytes to raw value bytes.
fn make_encryption_context_v1(
    config: &TableEncryptionConfig,
    item: &Item,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut ec: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    ec.push((EC_TABLE_NAME.to_vec(), config.logical_table_name.as_bytes().to_vec()));
    ec.push((
        EC_PARTITION_NAME.to_vec(),
        config.partition_key_name.as_bytes().to_vec(),
    ));
    ec.push((
        ec_attr_key(&config.partition_key_name),
        encode_terminal_base64(item, &config.partition_key_name)?,
    ));
    if let Some(sort_key_name) = &config.sort_key_name {
        ec.push((EC_SORT_NAME.to_vec(), sort_key_name.as_bytes().to_vec()));
        ec.push((
            ec_attr_key(sort_key_name),
            encode_terminal_base64(item, sort_key_name)?,
        ));
    }
    ec.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(ec)
}

fn ec_attr_key(attr_name: &str) -> Vec<u8> {
    let mut k = EC_ATTR_PREFIX.as_bytes().to_vec();
    k.extend_from_slice(attr_name.as_bytes());
    k
}

/// `UTF8(Base64(typeId || terminalValue))` for the key attribute named `name`.
fn encode_terminal_base64(item: &Item, name: &str) -> Result<Vec<u8>> {
    let value = item.get(name).ok_or_else(|| {
        DbEsdkError::invalid_item(format!("key attribute '{name}' not found in item"))
    })?;
    let (type_id, terminal) = terminal_bytes(value)?;
    let mut raw = type_id.to_vec();
    raw.extend_from_slice(&terminal);
    Ok(crypto::base64_encode(&raw).into_bytes())
}

/// Serialize an encryption context: `UInt16BE(count)` then, for each key sorted
/// ascending by raw bytes, `UInt16BE(keyLen)||key||UInt16BE(valLen)||val`.
/// Matches both `Header.SerializeContext` and `EncryptionContextToAAD`.
fn serialize_context(ec: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(ec.len() as u16).to_be_bytes());
    // ec is already sorted ascending by key bytes.
    for (k, v) in ec {
        out.extend_from_slice(&(k.len() as u16).to_be_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(&(v.len() as u16).to_be_bytes());
        out.extend_from_slice(v);
    }
    out
}

// ---------------------------------------------------------------------------
// DynamoToStruct scalar terminal serialization
// ---------------------------------------------------------------------------

/// The `(typeId, terminalValue)` for a scalar attribute, where `terminalValue`
/// is the value with no type-id / length prefix (DynamoToStruct, prefix=false).
fn terminal_bytes(value: &AttributeValue) -> Result<([u8; 2], Vec<u8>)> {
    match value {
        AttributeValue::S(s) => Ok((TYPE_STRING, s.as_bytes().to_vec())),
        AttributeValue::N(n) => Ok((TYPE_NUMBER, n.as_bytes().to_vec())),
        AttributeValue::B(b) => Ok((TYPE_BINARY, b.clone())),
        AttributeValue::Bool(v) => Ok((TYPE_BOOLEAN, vec![u8::from(*v)])),
        AttributeValue::Null(_) => Ok((TYPE_NULL, Vec::new())),
        other => Err(DbEsdkError::invalid_item(format!(
            "byte-faithful format does not yet support attribute type {other:?}"
        ))),
    }
}

fn decode_terminal(type_id: [u8; 2], value: &[u8]) -> Result<AttributeValue> {
    match type_id {
        TYPE_STRING => Ok(AttributeValue::S(
            String::from_utf8(value.to_vec())
                .map_err(|_| DbEsdkError::invalid_item("string terminal not valid UTF-8"))?,
        )),
        TYPE_NUMBER => Ok(AttributeValue::N(
            String::from_utf8(value.to_vec())
                .map_err(|_| DbEsdkError::invalid_item("number terminal not valid UTF-8"))?,
        )),
        TYPE_BINARY => Ok(AttributeValue::B(value.to_vec())),
        TYPE_BOOLEAN => Ok(AttributeValue::Bool(value.first().copied().unwrap_or(0) != 0)),
        TYPE_NULL => Ok(AttributeValue::Null(true)),
        other => Err(DbEsdkError::invalid_item(format!(
            "unknown terminal type id {other:02x?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Canonical path (Paths.dfy)
// ---------------------------------------------------------------------------

/// `UTF8(table) || UInt64BE(1) || 0x24 || UInt64BE(nameLen) || UTF8(name)`.
fn canonical_path(table: &str, attr_name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(table.as_bytes());
    out.extend_from_slice(&1u64.to_be_bytes()); // depth
    out.push(MAP_TAG);
    out.extend_from_slice(&(attr_name.len() as u64).to_be_bytes());
    out.extend_from_slice(attr_name.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Signed-field collection
// ---------------------------------------------------------------------------

fn collect_signed_fields(config: &TableEncryptionConfig, item: &Item) -> Result<Vec<SignedField>> {
    let mut fields = Vec::new();
    for (name, value) in item {
        let action = config.action_for(name);
        if action == CryptoAction::DoNothing {
            continue;
        }
        let (type_id, terminal) = terminal_bytes(value)?;
        fields.push(SignedField {
            name: name.clone(),
            action,
            canonical_path: canonical_path(&config.logical_table_name, name),
            type_id,
            value: terminal,
        });
    }
    Ok(fields)
}

/// Rebuild the signed-field list from a stored item, deriving each field's
/// action from the stored legend in canonical order (Canonize.ResolveLegend).
fn collect_signed_fields_for_decrypt(
    config: &TableEncryptionConfig,
    stored: &Item,
    legend: &[u8],
) -> Result<Vec<SignedField>> {
    // Gather all signed (non-DO_NOTHING by config) attributes, sorted by path.
    let mut fields: Vec<SignedField> = Vec::new();
    for (name, value) in stored {
        if name == HEADER_ATTRIBUTE || name == FOOTER_ATTRIBUTE {
            continue;
        }
        if config.action_for(name) == CryptoAction::DoNothing {
            continue;
        }
        // For encrypted fields the stored value is binary type_id||ct||tag; the
        // type id used in the footer canonical form is 0xFFFF (the encrypted
        // terminal), and the value is the full stored bytes. We resolve the
        // action from the legend below.
        let (type_id, terminal) = match value {
            AttributeValue::B(bytes) => (TYPE_BINARY, bytes.clone()),
            other => terminal_bytes(other)?,
        };
        fields.push(SignedField {
            name: name.clone(),
            action: CryptoAction::SignOnly, // placeholder; set from legend below
            canonical_path: canonical_path(&config.logical_table_name, name),
            type_id,
            value: terminal,
        });
    }
    fields.sort_by(|a, b| a.canonical_path.cmp(&b.canonical_path));

    if fields.len() != legend.len() {
        return Err(DbEsdkError::invalid_item(
            "stored legend length does not match the number of signed attributes",
        ));
    }
    for (field, &legend_byte) in fields.iter_mut().zip(legend) {
        field.action = legend_to_action(legend_byte)?;
        // For plaintext signed fields, recover the real type id + value so the
        // footer canonical form matches what was signed.
        if field.action != CryptoAction::EncryptAndSign {
            let value = stored.get(&field.name).expect("present");
            let (type_id, terminal) = terminal_bytes(value)?;
            field.type_id = type_id;
            field.value = terminal;
        }
    }
    Ok(fields)
}

fn legend_to_action(byte: u8) -> Result<CryptoAction> {
    match byte {
        LEGEND_ENCRYPT_AND_SIGN => Ok(CryptoAction::EncryptAndSign),
        LEGEND_SIGN_AND_INCLUDE => Ok(CryptoAction::SignAndIncludeInEncryptionContext),
        LEGEND_SIGN_ONLY => Ok(CryptoAction::SignOnly),
        other => Err(DbEsdkError::invalid_item(format!(
            "invalid legend byte 0x{other:02x}"
        ))),
    }
}

fn action_legend(action: CryptoAction) -> u8 {
    match action {
        CryptoAction::EncryptAndSign => LEGEND_ENCRYPT_AND_SIGN,
        CryptoAction::SignAndIncludeInEncryptionContext => LEGEND_SIGN_AND_INCLUDE,
        CryptoAction::SignOnly | CryptoAction::DoNothing => LEGEND_SIGN_ONLY,
    }
}

// ---------------------------------------------------------------------------
// Header serialization (Header.dfy)
// ---------------------------------------------------------------------------

/// The 1-byte algorithm-suite flavor (the low byte of the binaryId `[0x67, x]`)
/// for a DBE suite.
fn flavor_for(suite: AlgorithmSuiteId) -> u8 {
    match suite {
        AlgorithmSuiteId::SymsigHmacSha384 => FLAVOR_AES_SYMSIG,
        AlgorithmSuiteId::EcdsaP384SymsigHmacSha384 => FLAVOR_AES_ECDSA,
    }
}

fn serialize_header(
    flavor: u8,
    msg_id: &[u8; 32],
    signed: &[SignedField],
    stored_ec: &[(Vec<u8>, Vec<u8>)],
    edks: &[EncryptedDataKey],
    commit_key: &[u8],
) -> Result<Vec<u8>> {
    let partial = serialize_partial_header(flavor, msg_id, signed, stored_ec, edks)?;
    let commitment = header_commitment(commit_key, &partial);
    let mut full = partial;
    full.extend_from_slice(&commitment);
    Ok(full)
}

fn serialize_partial_header(
    flavor: u8,
    msg_id: &[u8; 32],
    signed: &[SignedField],
    stored_ec: &[(Vec<u8>, Vec<u8>)],
    edks: &[EncryptedDataKey],
) -> Result<Vec<u8>> {
    // The EDK count is a single byte (Header.dfy `SerializeDataKeys`: the list
    // type is bounded by UINT8_LIMIT), so at most 255 keys.
    if edks.is_empty() || edks.len() > u8::MAX as usize {
        return Err(DbEsdkError::config(format!(
            "a header must carry between 1 and 255 encrypted data keys (got {})",
            edks.len()
        )));
    }
    let mut out = Vec::new();
    out.push(HEADER_VERSION_1);
    out.push(flavor);
    out.extend_from_slice(msg_id);

    // Legend: one byte per signed field in canonical order.
    let legend: Vec<u8> = signed.iter().map(|f| action_legend(f.action)).collect();
    out.extend_from_slice(&(legend.len() as u16).to_be_bytes());
    out.extend_from_slice(&legend);

    // Stored encryption context: `UInt16(pairCount) || sorted(len-prefixed
    // key/val)`, identical to the AAD serialization. Empty for the non-signing
    // suite; one `aws-crypto-public-key` pair for the signing suite.
    out.extend_from_slice(&serialize_context(stored_ec));

    // Encrypted data keys: 1-byte count, then each EDK in order.
    out.push(edks.len() as u8);
    for edk in edks {
        out.extend_from_slice(&(edk.provider_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&edk.provider_id);
        out.extend_from_slice(&(edk.provider_info.len() as u16).to_be_bytes());
        out.extend_from_slice(&edk.provider_info);
        out.extend_from_slice(&(edk.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&edk.ciphertext);
    }
    Ok(out)
}

fn header_commitment(commit_key: &[u8], partial_header: &[u8]) -> Vec<u8> {
    // HMAC-SHA512(commitKey, partialHeader)[0..32].
    let mut mac = crypto::hmac_sha512(commit_key, partial_header);
    mac.truncate(COMMITMENT_LEN);
    mac
}

struct ParsedHeader {
    flavor: u8,
    msg_id: [u8; 32],
    legend: Vec<u8>,
    stored_ec: Vec<(Vec<u8>, Vec<u8>)>,
    edks: Vec<EncryptedDataKey>,
    partial_header: Vec<u8>,
    commitment: Vec<u8>,
}

fn parse_header(data: &[u8]) -> Result<ParsedHeader> {
    let mut r = Reader::new(data);
    let version = r.u8()?;
    if version != HEADER_VERSION_1 {
        return Err(DbEsdkError::invalid_item(format!(
            "unsupported header version 0x{version:02x} (byte-faithful path supports v1)"
        )));
    }
    let flavor = r.u8()?;
    let mut msg_id = [0u8; 32];
    msg_id.copy_from_slice(r.take(32)?);

    let legend_len = r.u16()? as usize;
    let legend = r.take(legend_len)?.to_vec();

    let ec_count = r.u16()?;
    let mut stored_ec = Vec::with_capacity(ec_count as usize);
    for _ in 0..ec_count {
        let kl = r.u16()? as usize;
        let key = r.take(kl)?.to_vec();
        let vl = r.u16()? as usize;
        let value = r.take(vl)?.to_vec();
        stored_ec.push((key, value));
    }

    // Encrypted data keys: a 1-byte count followed by that many EDK entries.
    let edk_count = r.u8()?;
    if edk_count == 0 {
        return Err(DbEsdkError::invalid_item(
            "header must carry at least one encrypted data key",
        ));
    }
    let mut edks = Vec::with_capacity(edk_count as usize);
    for _ in 0..edk_count {
        let pid_len = r.u16()? as usize;
        let provider_id = r.take(pid_len)?.to_vec();
        let pinfo_len = r.u16()? as usize;
        let provider_info = r.take(pinfo_len)?.to_vec();
        let ct_len = r.u16()? as usize;
        let ciphertext = r.take(ct_len)?.to_vec();
        edks.push(EncryptedDataKey {
            provider_id,
            provider_info,
            ciphertext,
        });
    }

    let consumed = r.pos;
    let partial_header = data[..consumed].to_vec();
    let commitment = r.take(COMMITMENT_LEN)?.to_vec();

    Ok(ParsedHeader {
        flavor,
        msg_id,
        legend,
        stored_ec,
        edks,
        partial_header,
        commitment,
    })
}

// ---------------------------------------------------------------------------
// Footer canonical hash (Footer.dfy)
// ---------------------------------------------------------------------------

/// SHA-384 over the canonical record:
/// `fullHeader || UInt64BE(len(AAD)) || AAD || CanonContent`.
fn canonical_hash(header: &[u8], ec_aad: &[u8], signed: &[SignedField]) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(header);
    record.extend_from_slice(&(ec_aad.len() as u64).to_be_bytes());
    record.extend_from_slice(ec_aad);

    // CanonContent: signed fields ordered lexicographically by canonical path.
    for field in signed {
        record.extend_from_slice(&field.canonical_path);
        if field.action == CryptoAction::EncryptAndSign {
            // value = type_id(2) || ct || tag ; length written is value.len()-2.
            record.extend_from_slice(&((field.value.len() - 2) as u64).to_be_bytes());
            record.extend_from_slice(ENCRYPTED);
            record.extend_from_slice(&field.value);
        } else {
            record.extend_from_slice(&(field.value.len() as u64).to_be_bytes());
            record.extend_from_slice(PLAINTEXT);
            record.extend_from_slice(&field.type_id);
            record.extend_from_slice(&field.value);
        }
    }
    crypto::sha384(&record)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn take_binary(item: &Item, name: &str) -> Result<Vec<u8>> {
    match item.get(name) {
        Some(AttributeValue::B(bytes)) => Ok(bytes.clone()),
        _ => Err(DbEsdkError::invalid_item(format!(
            "stored item is missing the binary attribute '{name}'"
        ))),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.bytes.len())
            .ok_or_else(|| DbEsdkError::invalid_item("header truncated"))?;
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AesWrappingAlg, AlgorithmSuiteId, KeyringConfig};
    use std::collections::BTreeMap;

    fn raw_config() -> RawAesKeyringConfig {
        RawAesKeyringConfig {
            key_namespace: "my-namespace".to_string(),
            key_name: "my-key".to_string(),
            wrapping_key: vec![7u8; 32],
            wrapping_alg: AesWrappingAlg::Aes256,
        }
    }

    fn config() -> TableEncryptionConfig {
        let mut actions = BTreeMap::new();
        actions.insert("partition_key".to_string(), CryptoAction::SignOnly);
        actions.insert("sensitive".to_string(), CryptoAction::EncryptAndSign);
        actions.insert("public".to_string(), CryptoAction::SignOnly);
        TableEncryptionConfig {
            logical_table_name: "TestTable".to_string(),
            partition_key_name: "partition_key".to_string(),
            sort_key_name: None,
            attribute_actions: actions,
            allowed_unsigned_attributes: Vec::new(),
            allowed_unsigned_attribute_prefix: None,
            algorithm_suite_id: AlgorithmSuiteId::SymsigHmacSha384,
            keyring: KeyringConfig::RawAes(raw_config()),
        }
    }

    /// The same table config but with the ECDSA-P384 signing suite (flavor 0x01).
    fn signing_config() -> TableEncryptionConfig {
        let mut cfg = config();
        cfg.algorithm_suite_id = AlgorithmSuiteId::EcdsaP384SymsigHmacSha384;
        cfg
    }

    fn item() -> Item {
        let mut item = Item::new();
        item.insert("partition_key".into(), AttributeValue::S("pk-1".into()));
        item.insert("sensitive".into(), AttributeValue::N("42".into()));
        item.insert("public".into(), AttributeValue::Bool(true));
        item
    }

    // ---- Known-answer tests for the deterministic building blocks ----

    #[test]
    fn field_key_nonce_matches_spec_layout() {
        // "AwsDbeField"(11) || 0x2c || UInt32BE(offset)
        let iv = field_key_nonce(0);
        assert_eq!(&iv[..11], b"AwsDbeField");
        assert_eq!(iv[11], 0x2c, "length byte must be 44 (0x2c)");
        assert_eq!(&iv[12..16], &[0, 0, 0, 0], "offset 0 big-endian");

        let iv3 = field_key_nonce(3);
        assert_eq!(&iv3[12..16], &[0, 0, 0, 3], "offset 3 big-endian");
        assert_eq!(iv.len(), 16);
    }

    #[test]
    fn canonical_path_matches_spec_layout() {
        let path = canonical_path("Tbl", "name");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"Tbl");
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.push(0x24);
        expected.extend_from_slice(&4u64.to_be_bytes());
        expected.extend_from_slice(b"name");
        assert_eq!(path, expected);
    }

    #[test]
    fn serialize_context_layout_is_count_then_sorted_pairs() {
        let ec = vec![
            (b"a".to_vec(), b"1".to_vec()),
            (b"bb".to_vec(), b"22".to_vec()),
        ];
        let out = serialize_context(&ec);
        // count = 2
        assert_eq!(&out[0..2], &[0x00, 0x02]);
        // first pair: keyLen=1, "a", valLen=1, "1"
        assert_eq!(&out[2..4], &[0x00, 0x01]);
        assert_eq!(out[4], b'a');
        assert_eq!(&out[5..7], &[0x00, 0x01]);
        assert_eq!(out[7], b'1');
    }

    #[test]
    fn terminal_bytes_use_dynamodb_type_ids() {
        assert_eq!(terminal_bytes(&AttributeValue::S("x".into())).unwrap().0, [0x00, 0x01]);
        assert_eq!(terminal_bytes(&AttributeValue::N("1".into())).unwrap().0, [0x00, 0x02]);
        assert_eq!(terminal_bytes(&AttributeValue::B(vec![1])).unwrap().0, [0xFF, 0xFF]);
        assert_eq!(terminal_bytes(&AttributeValue::Bool(true)).unwrap().0, [0x00, 0x04]);
        assert_eq!(terminal_bytes(&AttributeValue::Bool(true)).unwrap().1, vec![0x01]);
        assert_eq!(terminal_bytes(&AttributeValue::Bool(false)).unwrap().1, vec![0x00]);
        assert_eq!(terminal_bytes(&AttributeValue::Null(true)).unwrap().0, [0x00, 0x00]);
    }

    #[test]
    fn ec_v1_has_table_partition_and_attr_keys_sorted() {
        let ec = make_encryption_context_v1(&config(), &item()).unwrap();
        let keys: Vec<&[u8]> = ec.iter().map(|(k, _)| k.as_slice()).collect();
        // Sorted ascending by bytes; "aws-crypto-attr.partition_key" < "...partition-name" < "...table-name"
        assert!(keys.windows(2).all(|w| w[0] <= w[1]), "keys must be sorted");
        assert!(ec.iter().any(|(k, _)| k == EC_TABLE_NAME));
        assert!(ec.iter().any(|(k, _)| k == EC_PARTITION_NAME));
        assert!(ec
            .iter()
            .any(|(k, _)| k == &ec_attr_key("partition_key")));
        // table-name value is the logical table name
        let table_val = &ec.iter().find(|(k, _)| k == EC_TABLE_NAME).unwrap().1;
        assert_eq!(table_val.as_slice(), b"TestTable");
    }

    #[test]
    fn base64_encode_matches_known_vectors() {
        assert_eq!(crypto::base64_encode(b""), "");
        assert_eq!(crypto::base64_encode(b"f"), "Zg==");
        assert_eq!(crypto::base64_encode(b"fo"), "Zm8=");
        assert_eq!(crypto::base64_encode(b"foo"), "Zm9v");
        assert_eq!(crypto::base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn header_structure_is_well_formed() {
        let cfg = config();
        let raw = raw_config();
        let stored = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();
        let header = match stored.get(HEADER_ATTRIBUTE).unwrap() {
            AttributeValue::B(b) => b.clone(),
            _ => panic!("header must be binary"),
        };
        assert_eq!(header[0], HEADER_VERSION_1, "version byte");
        assert_eq!(header[1], FLAVOR_AES_SYMSIG, "flavor byte");
        // legend length is at offset 34 (1+1+32); 3 signed fields here
        // (partition_key SIGN_ONLY, sensitive ENCRYPT_AND_SIGN, public SIGN_ONLY).
        let legend_len = u16::from_be_bytes([header[34], header[35]]);
        assert_eq!(legend_len, 3, "three signed fields contribute one legend byte each");
        // parse must succeed and recover a 32-byte commitment.
        let parsed = parse_header(&header).unwrap();
        assert_eq!(parsed.commitment.len(), 32);
        assert_eq!(parsed.legend.len() as u16, legend_len);
    }

    // ---- Round-trip (self-consistency) ----

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let cfg = config();
        let raw = raw_config();
        let item = item();
        let stored = encrypt_item_raw_aes(&cfg, &raw, &item).unwrap();

        // encrypted attribute is binary; signed-only attributes are plaintext.
        assert!(matches!(stored.get("sensitive"), Some(AttributeValue::B(_))));
        assert_eq!(stored.get("partition_key"), Some(&AttributeValue::S("pk-1".into())));
        assert!(stored.contains_key(HEADER_ATTRIBUTE));
        assert!(stored.contains_key(FOOTER_ATTRIBUTE));

        let decrypted = decrypt_item_raw_aes(&cfg, &raw, &stored).unwrap();
        assert_eq!(decrypted, item);
    }

    #[test]
    fn each_encryption_uses_fresh_msg_id_and_data_key() {
        let cfg = config();
        let raw = raw_config();
        let a = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();
        let b = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();
        assert_ne!(a.get(HEADER_ATTRIBUTE), b.get(HEADER_ATTRIBUTE));
        assert_ne!(a.get("sensitive"), b.get("sensitive"));
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() {
        let cfg = config();
        let raw = raw_config();
        let mut stored = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();
        if let Some(AttributeValue::B(bytes)) = stored.get_mut("sensitive") {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
        }
        assert!(decrypt_item_raw_aes(&cfg, &raw, &stored).is_err());
    }

    #[test]
    fn tampered_sign_only_attribute_fails_decrypt() {
        let cfg = config();
        let raw = raw_config();
        let mut stored = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();
        stored.insert("public".into(), AttributeValue::Bool(false));
        assert!(decrypt_item_raw_aes(&cfg, &raw, &stored).is_err());
    }

    #[test]
    fn wrong_wrapping_key_fails_decrypt() {
        let cfg = config();
        let raw = raw_config();
        let stored = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();
        let mut other = raw_config();
        other.wrapping_key = vec![9u8; 32];
        assert!(decrypt_item_raw_aes(&cfg, &other, &stored).is_err());
    }

    // ---- Signing suite (flavor 0x01, ECDSA-P384) ----

    #[test]
    fn signing_suite_header_carries_flavor_and_public_key() {
        let cfg = signing_config();
        let raw = raw_config();
        let stored = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();

        let header = match stored.get(HEADER_ATTRIBUTE).unwrap() {
            AttributeValue::B(b) => b.clone(),
            _ => panic!("header must be binary"),
        };
        assert_eq!(header[0], HEADER_VERSION_1, "version byte");
        assert_eq!(header[1], FLAVOR_AES_ECDSA, "flavor byte is 0x01 for the signing suite");

        // The stored header EC must carry exactly the aws-crypto-public-key entry.
        let parsed = parse_header(&header).unwrap();
        assert_eq!(parsed.flavor, FLAVOR_AES_ECDSA);
        assert_eq!(parsed.stored_ec.len(), 1, "only the public-key entry is stored");
        let (k, v) = &parsed.stored_ec[0];
        assert_eq!(k.as_slice(), EC_PUBLIC_KEY);
        // base64 of a 49-byte compressed P-384 key is 68 ASCII bytes.
        assert_eq!(v.len(), 68, "base64(compressed P-384 key) is 68 bytes");

        // Footer = 48-byte recipient tag + 103-byte ECDSA signature.
        let footer = match stored.get(FOOTER_ATTRIBUTE).unwrap() {
            AttributeValue::B(b) => b.clone(),
            _ => panic!("footer must be binary"),
        };
        assert_eq!(
            footer.len(),
            RECIPIENT_TAG_LEN + crypto::ECDSA_P384_SIGNATURE_LEN,
            "signing-suite footer is tag(48) + signature(103) = 151 bytes"
        );
    }

    #[test]
    fn signing_suite_round_trips() {
        let cfg = signing_config();
        let raw = raw_config();
        let item = item();
        let stored = encrypt_item_raw_aes(&cfg, &raw, &item).unwrap();
        let decrypted = decrypt_item_raw_aes(&cfg, &raw, &stored).unwrap();
        assert_eq!(decrypted, item);
    }

    #[test]
    fn signing_suite_tampered_signature_fails_decrypt() {
        let cfg = signing_config();
        let raw = raw_config();
        let mut stored = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();
        if let Some(AttributeValue::B(footer)) = stored.get_mut(FOOTER_ATTRIBUTE) {
            // Flip a byte inside the ECDSA signature (past the recipient tag).
            let idx = RECIPIENT_TAG_LEN + 10;
            footer[idx] ^= 0x01;
        }
        assert!(decrypt_item_raw_aes(&cfg, &raw, &stored).is_err());
    }

    #[test]
    fn signing_suite_tampered_public_key_fails_decrypt() {
        let cfg = signing_config();
        let raw = raw_config();
        let stored = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();

        // Corrupt the stored verification key in the header; the signature must
        // then fail to verify against it (or the commitment/tag must break).
        let header = match stored.get(HEADER_ATTRIBUTE).unwrap() {
            AttributeValue::B(b) => b.clone(),
            _ => panic!(),
        };
        // Locate the public-key value bytes in the header and flip one.
        let mut tampered = header.clone();
        let needle = EC_PUBLIC_KEY;
        let pos = tampered
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("public-key key bytes present in header");
        // Skip key (21) + UInt16 value length (2) to reach the value.
        let value_start = pos + needle.len() + 2;
        tampered[value_start] ^= 0x01;

        let mut bad = stored.clone();
        bad.insert(HEADER_ATTRIBUTE.to_string(), AttributeValue::B(tampered));
        assert!(decrypt_item_raw_aes(&cfg, &raw, &bad).is_err());
    }

    #[test]
    fn signing_suite_uses_fresh_signature_each_call() {
        let cfg = signing_config();
        let raw = raw_config();
        let a = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();
        let b = encrypt_item_raw_aes(&cfg, &raw, &item()).unwrap();
        assert_ne!(a.get(FOOTER_ATTRIBUTE), b.get(FOOTER_ATTRIBUTE));
    }

    // ---- Generic provider abstraction ----

    /// A trivial [`IntermediateKeyProvider`] that exercises the generic
    /// [`encrypt_item`] / [`decrypt_item`] core independently of the Raw AES
    /// keyring: the "wrap" is a reversible XOR with a fixed pad and a distinct
    /// provider id / info. It proves the structured-encryption core consumes the
    /// provider's output generically (it is NOT a real, secure wrapping).
    struct XorProvider;

    impl XorProvider {
        const PAD: u8 = 0x5a;
    }

    impl IntermediateKeyProvider for XorProvider {
        fn generate_and_wrap(
            &self,
            _ec: &[(Vec<u8>, Vec<u8>)],
            _ec_aad: &[u8],
        ) -> Result<GeneratedKey> {
            let intermediate = crypto::random_bytes(32)?;
            let provider_wrapped_ikm = intermediate.iter().map(|b| b ^ Self::PAD).collect();
            Ok(GeneratedKey {
                intermediate_material: intermediate,
                provider_wrapped_ikm,
                edk_provider_id: b"x-test-provider".to_vec(),
                edk_provider_info: b"x-test-info".to_vec(),
            })
        }

        fn unwrap(
            &self,
            provider_id: &[u8],
            provider_info: &[u8],
            provider_wrapped_ikm: &[u8],
            _ec: &[(Vec<u8>, Vec<u8>)],
            _ec_aad: &[u8],
        ) -> Result<Vec<u8>> {
            // The provider id / info written on encrypt must survive the header
            // round-trip and reach unwrap unchanged.
            assert_eq!(provider_id, b"x-test-provider");
            assert_eq!(provider_info, b"x-test-info");
            Ok(provider_wrapped_ikm.iter().map(|b| b ^ Self::PAD).collect())
        }
    }

    #[test]
    fn generic_provider_round_trips_under_both_suites() {
        for cfg in [config(), signing_config()] {
            let item = item();
            let stored = encrypt_item(&cfg, &XorProvider, &item).unwrap();
            let decrypted = decrypt_item(&cfg, &XorProvider, &stored).unwrap();
            assert_eq!(decrypted, item);
        }
    }

    #[test]
    fn generic_provider_edk_identifiers_reach_the_header() {
        let stored = encrypt_item(&config(), &XorProvider, &item()).unwrap();
        let header = match stored.get(HEADER_ATTRIBUTE).unwrap() {
            AttributeValue::B(b) => b.clone(),
            _ => panic!("header must be binary"),
        };
        let parsed = parse_header(&header).unwrap();
        assert_eq!(parsed.edks[0].provider_id, b"x-test-provider");
        assert_eq!(parsed.edks[0].provider_info, b"x-test-info");
    }

    // ---- Multi-keyring (multiple EDKs) ----

    /// A second Raw AES keyring, distinct from [`raw_config`] in both namespace
    /// /name and wrapping key, used as a second multi-keyring component.
    fn raw_config_b() -> RawAesKeyringConfig {
        RawAesKeyringConfig {
            key_namespace: "other-namespace".to_string(),
            key_name: "other-key".to_string(),
            wrapping_key: vec![0x33u8; 32],
            wrapping_alg: AesWrappingAlg::Aes256,
        }
    }

    /// A multi-keyring (here two distinct Raw AES keyrings) writes one Encrypted
    /// Data Key per component and one footer recipient tag per EDK, and the item
    /// is decryptable by the full set of keyrings.
    #[test]
    fn multi_keyring_writes_one_edk_per_keyring() {
        for cfg in [config(), signing_config()] {
            let a = raw_config();
            let b = raw_config_b();
            let pa = RawAesProvider { raw: &a };
            let pb = RawAesProvider { raw: &b };
            let providers: [&dyn IntermediateKeyProvider; 2] = [&pa, &pb];

            let item = item();
            let stored = encrypt_item_multi(&cfg, &providers, &item).unwrap();

            // The header carries exactly two EDKs, in keyring order.
            let header = match stored.get(HEADER_ATTRIBUTE).unwrap() {
                AttributeValue::B(b) => b.clone(),
                _ => panic!("header must be binary"),
            };
            let parsed = parse_header(&header).unwrap();
            assert_eq!(parsed.edks.len(), 2);
            assert_eq!(parsed.edks[0].provider_id, b"my-namespace");
            assert_eq!(parsed.edks[1].provider_id, b"other-namespace");

            // The footer carries one 48-byte recipient tag per EDK, plus a
            // 103-byte ECDSA signature for the signing suite.
            let footer = match stored.get(FOOTER_ATTRIBUTE).unwrap() {
                AttributeValue::B(b) => b.clone(),
                _ => panic!("footer must be binary"),
            };
            let expected = 2 * RECIPIENT_TAG_LEN
                + if cfg.algorithm_suite_id == AlgorithmSuiteId::EcdsaP384SymsigHmacSha384 {
                    crypto::ECDSA_P384_SIGNATURE_LEN
                } else {
                    0
                };
            assert_eq!(footer.len(), expected);

            // The full keyring set decrypts to the original item.
            let decrypted = decrypt_item_multi(&cfg, &providers, &stored).unwrap();
            assert_eq!(decrypted, item);
        }
    }

    /// Any single component keyring of a multi-keyring can independently decrypt
    /// an item the multi-keyring wrote (MPL multi-keyring `OnDecrypt` semantics).
    #[test]
    fn multi_keyring_each_component_can_decrypt_alone() {
        let cfg = signing_config();
        let a = raw_config();
        let b = raw_config_b();
        let pa = RawAesProvider { raw: &a };
        let pb = RawAesProvider { raw: &b };
        let stored = encrypt_item_multi(&cfg, &[&pa, &pb], &item()).unwrap();

        // Either component alone recovers the item from its own EDK.
        assert_eq!(decrypt_item_multi(&cfg, &[&pa], &stored).unwrap(), item());
        assert_eq!(decrypt_item_multi(&cfg, &[&pb], &stored).unwrap(), item());

        // A keyring that owns none of the EDKs cannot decrypt.
        let other = RawAesKeyringConfig {
            key_namespace: "third-namespace".to_string(),
            key_name: "third-key".to_string(),
            wrapping_key: vec![0x99u8; 32],
            wrapping_alg: AesWrappingAlg::Aes256,
        };
        let po = RawAesProvider { raw: &other };
        assert!(decrypt_item_multi(&cfg, &[&po], &stored).is_err());
    }

    // ---- Raw RSA keyring provider ----

    /// Wrap raw DER in a single-line PEM document with the given label (the
    /// shape the conformance suite's `TestKeyMaterial` emits: standard
    /// `java.util.Base64` body with PEM headers).
    fn to_pem(label: &str, der: &[u8]) -> Vec<u8> {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            crypto::base64_encode(der)
        )
        .into_bytes()
    }

    /// Generate an RSA-2048 key pair and return `(public_key_pem, private_key_pem)`
    /// in the X.509 SubjectPublicKeyInfo / PKCS#8 PrivateKeyInfo PEM encodings the
    /// Raw RSA keyring config carries.
    fn rsa_keypair_pem() -> (Vec<u8>, Vec<u8>) {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let pkcs8 = private.as_der().unwrap();
        let public = private.public_key();
        let spki = public.as_der().unwrap();
        (
            to_pem("PUBLIC KEY", spki.as_ref()),
            to_pem("PRIVATE KEY", pkcs8.as_ref()),
        )
    }

    fn raw_rsa_config(public_key: Option<Vec<u8>>, private_key: Option<Vec<u8>>) -> RawRsaKeyringConfig {
        RawRsaKeyringConfig {
            key_namespace: "test-server-namespace".to_string(),
            key_name: "raw-rsa-key".to_string(),
            padding_scheme: crate::config::PaddingScheme::OaepSha256Mgf1,
            public_key,
            private_key,
        }
    }

    fn rsa_table_config(rsa: RawRsaKeyringConfig, suite: AlgorithmSuiteId) -> TableEncryptionConfig {
        let mut cfg = config();
        cfg.algorithm_suite_id = suite;
        cfg.keyring = KeyringConfig::RawRsa(rsa);
        cfg
    }

    #[test]
    fn raw_rsa_round_trips_under_both_suites() {
        let (pubk, privk) = rsa_keypair_pem();
        let rsa = raw_rsa_config(Some(pubk), Some(privk));
        for suite in [
            AlgorithmSuiteId::SymsigHmacSha384,
            AlgorithmSuiteId::EcdsaP384SymsigHmacSha384,
        ] {
            let cfg = rsa_table_config(rsa.clone(), suite);
            let item = item();
            let stored = encrypt_item(&cfg, &RawRsaProvider { raw: &rsa }, &item).unwrap();
            let decrypted = decrypt_item(&cfg, &RawRsaProvider { raw: &rsa }, &stored).unwrap();
            assert_eq!(decrypted, item);
        }
    }

    #[test]
    fn raw_rsa_edk_carries_namespace_and_name() {
        let (pubk, privk) = rsa_keypair_pem();
        let rsa = raw_rsa_config(Some(pubk), Some(privk));
        let cfg = rsa_table_config(rsa.clone(), AlgorithmSuiteId::SymsigHmacSha384);
        let stored = encrypt_item(&cfg, &RawRsaProvider { raw: &rsa }, &item()).unwrap();
        let header = match stored.get(HEADER_ATTRIBUTE).unwrap() {
            AttributeValue::B(b) => b.clone(),
            _ => panic!("header must be binary"),
        };
        let parsed = parse_header(&header).unwrap();
        // RawRSAKeyring.OnEncrypt: provider id = key namespace, info = key name.
        assert_eq!(parsed.edks[0].provider_id, b"test-server-namespace");
        assert_eq!(parsed.edks[0].provider_info, b"raw-rsa-key");
        // EDK ciphertext = encryptedPdk(48) || RSA-OAEP(intermediate) (256B for RSA-2048).
        assert_eq!(parsed.edks[0].ciphertext.len(), 48 + 256);
    }

    #[test]
    fn raw_rsa_without_public_key_cannot_encrypt() {
        let (_pubk, privk) = rsa_keypair_pem();
        let rsa = raw_rsa_config(None, Some(privk));
        let cfg = rsa_table_config(rsa.clone(), AlgorithmSuiteId::SymsigHmacSha384);
        assert!(encrypt_item(&cfg, &RawRsaProvider { raw: &rsa }, &item()).is_err());
    }

    #[test]
    fn raw_rsa_wrong_private_key_fails_decrypt() {
        let (pubk, _privk) = rsa_keypair_pem();
        let (_pubk2, privk2) = rsa_keypair_pem();
        let enc_cfg_rsa = raw_rsa_config(Some(pubk), None);
        let cfg = rsa_table_config(enc_cfg_rsa.clone(), AlgorithmSuiteId::SymsigHmacSha384);
        let stored = encrypt_item(&cfg, &RawRsaProvider { raw: &enc_cfg_rsa }, &item()).unwrap();

        // Decrypt with an unrelated private key -> RSA unwrap must fail.
        let dec_rsa = raw_rsa_config(None, Some(privk2));
        assert!(decrypt_item(&cfg, &RawRsaProvider { raw: &dec_rsa }, &stored).is_err());
    }

    // ---- Raw ECDH keyring provider ----

    use crate::config::{EcdhCurveSpec, RawEcdhKeyringConfig};

    /// Generate a P-256 EC key pair and return
    /// `(sender_private_key_pkcs8_pem, recipient_public_key_x509_der)`.
    ///
    /// Mirrors the conformance `RawEcdhKeyringTest`, which uses one P-256 key
    /// pair for BOTH the sender static private key (PEM PKCS#8) and the recipient
    /// public key (DER X.509 SPKI), so encrypt and decrypt derive the same shared
    /// secret under the RawPrivateKeyToStaticPublicKey scheme.
    fn ecdh_keypair() -> (Vec<u8>, Vec<u8>) {
        use aws_lc_rs::agreement::{PrivateKey, ECDH_P256};
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
        let private = PrivateKey::generate(&ECDH_P256).unwrap();
        let pkcs8 = AsDer::<Pkcs8V1Der>::as_der(&private).unwrap();
        let public = private.compute_public_key().unwrap();
        let spki = AsDer::<PublicKeyX509Der>::as_der(&public).unwrap();
        (to_pem("PRIVATE KEY", pkcs8.as_ref()), spki.as_ref().to_vec())
    }

    fn raw_ecdh_config() -> RawEcdhKeyringConfig {
        let (sender_private, recipient_public) = ecdh_keypair();
        RawEcdhKeyringConfig {
            sender_static_private_key: sender_private,
            recipient_public_key: recipient_public,
            curve_spec: EcdhCurveSpec::EccNistP256,
        }
    }

    fn ecdh_table_config(ecdh: RawEcdhKeyringConfig) -> TableEncryptionConfig {
        let mut cfg = config();
        // ECDH cannot use an asymmetric-signing suite (matches the conformance test).
        cfg.algorithm_suite_id = AlgorithmSuiteId::SymsigHmacSha384;
        cfg.keyring = KeyringConfig::RawEcdh(ecdh);
        cfg
    }

    #[test]
    fn raw_ecdh_round_trips() {
        let ecdh = raw_ecdh_config();
        let cfg = ecdh_table_config(ecdh.clone());
        let item = item();
        let stored = encrypt_item(&cfg, &RawEcdhProvider { raw: &ecdh }, &item).unwrap();
        let decrypted = decrypt_item(&cfg, &RawEcdhProvider { raw: &ecdh }, &stored).unwrap();
        assert_eq!(decrypted, item);
    }

    #[test]
    fn raw_ecdh_edk_layout_matches_reference() {
        let ecdh = raw_ecdh_config();
        let cfg = ecdh_table_config(ecdh.clone());
        let stored = encrypt_item(&cfg, &RawEcdhProvider { raw: &ecdh }, &item()).unwrap();
        let header = match stored.get(HEADER_ATTRIBUTE).unwrap() {
            AttributeValue::B(b) => b.clone(),
            _ => panic!("header must be binary"),
        };
        let parsed = parse_header(&header).unwrap();
        // RawECDHKeyring.OnEncrypt: provider id = "raw-ecdh".
        assert_eq!(parsed.edks[0].provider_id, b"raw-ecdh");
        // Provider info (P-256): version(1) + recipLen(4) + recip(33) + sndLen(4)
        // + snd(33) = 75 bytes (ECDH_PROVIDER_INFO_256_LEN).
        assert_eq!(parsed.edks[0].provider_info.len(), 75);
        assert_eq!(parsed.edks[0].provider_info[0], 0x01, "keyring version");
        // EDK ciphertext = encryptedPdk(48) || salt(32) || commitmentKey(32)
        // || wrappedIntermediate(32) || tag(16) = 48 + 112 = 160 bytes.
        assert_eq!(parsed.edks[0].ciphertext.len(), 48 + 112);
    }

    #[test]
    fn raw_ecdh_provider_info_round_trips() {
        let sender = vec![0x02u8; 33];
        let recipient = vec![0x03u8; 33];
        let info = RawEcdhProvider::serialize_provider_info(&sender, &recipient);
        let (parsed_sender, parsed_recipient) =
            RawEcdhProvider::parse_provider_info(&info).unwrap();
        assert_eq!(parsed_sender, sender);
        assert_eq!(parsed_recipient, recipient);
    }

    #[test]
    fn raw_ecdh_tampered_ciphertext_fails_decrypt() {
        let ecdh = raw_ecdh_config();
        let cfg = ecdh_table_config(ecdh.clone());
        let mut stored = encrypt_item(&cfg, &RawEcdhProvider { raw: &ecdh }, &item()).unwrap();
        if let Some(AttributeValue::B(bytes)) = stored.get_mut("sensitive") {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
        }
        assert!(decrypt_item(&cfg, &RawEcdhProvider { raw: &ecdh }, &stored).is_err());
    }

    #[test]
    fn raw_ecdh_wrong_private_key_fails_decrypt() {
        let ecdh = raw_ecdh_config();
        let cfg = ecdh_table_config(ecdh.clone());
        let stored = encrypt_item(&cfg, &RawEcdhProvider { raw: &ecdh }, &item()).unwrap();

        // A different sender key pair derives a different shared secret, so the
        // commitment-key check (or AES-GCM unwrap) must fail.
        let (other_private, _other_public) = ecdh_keypair();
        let mut other = ecdh.clone();
        other.sender_static_private_key = other_private;
        assert!(decrypt_item(&cfg, &RawEcdhProvider { raw: &other }, &stored).is_err());
    }
}
