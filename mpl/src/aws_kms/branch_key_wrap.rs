// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Branch-key wrapping/unwrapping primitives for the AWS KMS Hierarchical Keyring.
//!
//! Implements the [Branch Key Wrapping](
//! ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping),
//! [Branch Key Unwrapping](
//! ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping),
//! and [Branch Key Wrapping and Unwrapping AAD](
//! ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad)
//! sections — pure crypto leaves over `aws_lc_rs` primitives, with no
//! cache or KMS dependency. Used by the `Keyring` impl in
//! [`super::hierarchical_keyring`] (in a later cycle).

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::kdf::{KbkdfCtrHmacAlgorithmId, get_kbkdf_ctr_hmac_algorithm, kbkdf_ctr_hmac};
use aws_lc_rs::rand::fill;

use crate::structures::{BranchKeyMaterials, EncryptionContext, MaterialsError};

/// Length of the random salt used as the KDF context. Spec: 16 bytes.
const SALT_LEN: usize = 16;

/// Length of the AES-GCM IV. Spec: 12 bytes (matches `aws_lc_rs::aead::NONCE_LEN`).
const IV_LEN: usize = NONCE_LEN;

/// Length of the branch-key version (UUID) when serialized as raw bytes
/// inside the AAD and the on-wire layout. Spec: 16 bytes.
const VERSION_LEN: usize = 16;

/// AES-GCM authentication tag length. AES-256-GCM in `aws_lc_rs` always
/// produces a 16-byte tag (`MAX_TAG_LEN == TAG_LEN == 16`).
const TAG_LEN: usize = 16;

/// Length of the derived branch key produced by KBKDF-CTR-HMAC-SHA256.
/// AES-256-GCM requires a 32-byte cipher key.
const DERIVED_KEY_LEN: usize = 32;

/// Label for the KBKDF-CTR-HMAC-SHA256 derivation and for the AAD prefix.
/// Spec: "aws-kms-hierarchy" UTF-8 encoded — 17 bytes.
const HIERARCHY_LABEL: &[u8] = b"aws-kms-hierarchy";

/// Total fixed overhead of a wrap output relative to the plaintext data key:
///   salt (16) + IV (12) + version (16) + tag (16) = 60 bytes.
const FIXED_OVERHEAD_LEN: usize = SALT_LEN + IV_LEN + VERSION_LEN + TAG_LEN;

// ---- AAD construction --------------------------------------------------------

/// Build the Additional Authenticated Data (AAD) used by both branch-key
/// wrap and unwrap.
///
/// The output is the concatenation, in order, of:
/// 1. UTF-8 bytes of the literal `"aws-kms-hierarchy"`.
/// 2. UTF-8 bytes of `branch_key_id`.
/// 3. The 16-byte representation of `branch_key_version` (a v4 UUID hex
///    string with the four `-` separators stripped, parsed as 32 hex
///    digits).
/// 4. The serialized `EncryptionContext`.
///
/// Returns `MaterialsError` if the encryption context fails to serialize
/// (entry count or key/value length exceeds `u16::MAX`) or if the
/// `branch_key_version` cannot be parsed as a 16-byte UUID.
pub fn compute_aad(
    branch_key_id: &str,
    branch_key_version: &str,
    encryption_context: &EncryptionContext,
) -> Result<Vec<u8>, MaterialsError> {
    let version_bytes = uuid_str_to_16_bytes(branch_key_version)?;

    let serialized_ec = encryption_context.serialize()?;

    let mut aad = Vec::with_capacity(
        HIERARCHY_LABEL.len() + branch_key_id.len() + VERSION_LEN + serialized_ec.len(),
    );

    aad.extend_from_slice(HIERARCHY_LABEL);
    aad.extend_from_slice(branch_key_id.as_bytes());
    aad.extend_from_slice(&version_bytes);
    aad.extend_from_slice(&serialized_ec);

    Ok(aad)
}

/// Parse a v4 UUID canonical hex string (8-4-4-4-12) into its 16 raw bytes.
///
/// `BranchKeyMaterials::new` already validates the UUID shape via
/// `is_valid_uuid_v4`, so this parse is structurally infallible at the
/// call sites in this module. We still return `MaterialsError` rather
/// than panicking so a future caller that bypasses `BranchKeyMaterials::new`
/// (e.g. a fuzzer) gets a clean error instead of a process abort.
fn uuid_str_to_16_bytes(s: &str) -> Result<[u8; VERSION_LEN], MaterialsError> {
    let bytes = s.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
    {
        return Err(MaterialsError::new(format!(
            "Branch key version is not a valid 36-char UUID: {s}",
        )));
    }
    // Strip the four hyphens, leaving 32 hex digits.
    let mut hex = [0u8; 32];
    let mut hex_idx = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        hex[hex_idx] = b;
        hex_idx += 1;
    }
    debug_assert_eq!(
        hex_idx, 32,
        "uuid hex digit count must be 32 after stripping"
    );

    let mut out = [0u8; VERSION_LEN];
    for (i, chunk) in hex.chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| {
            MaterialsError::new(format!(
                "Branch key version contains non-ASCII hex digits: {s}",
            ))
        })?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| {
            MaterialsError::new(format!(
                "Branch key version contains non-hex characters: {s}",
            ))
        })?;
    }
    Ok(out)
}

// ---- KDF ---------------------------------------------------------------------

/// Derive the 32-byte AES-256-GCM cipher key from the branch key using
/// KBKDF-CTR-HMAC-SHA256 (NIST SP 800-108 §4.1).
///
/// The fixed-info string follows the standard NIST construction
/// `Label || 0x00 || Context || L_be32`, with:
/// * `Label`   = "aws-kms-hierarchy"
/// * `Context` = `salt`
/// * `L_be32`  = 0x00000100 (256 bits = 32 bytes of output)
///
/// The same construction is used on both wrap and unwrap so the round
/// trip is closed.
fn derive_branch_key(
    branch_key: &[u8; DERIVED_KEY_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<[u8; DERIVED_KEY_LEN], MaterialsError> {
    // FixedInfo: Label || 0x00 || salt || L_be32 (256-bit output).
    let mut info = Vec::with_capacity(HIERARCHY_LABEL.len() + 1 + SALT_LEN + 4);
    info.extend_from_slice(HIERARCHY_LABEL);
    info.push(0x00);
    info.extend_from_slice(salt);
    let output_len_bits: u32 = 256;
    info.extend_from_slice(&output_len_bits.to_be_bytes());

    let alg = get_kbkdf_ctr_hmac_algorithm(KbkdfCtrHmacAlgorithmId::Sha256).ok_or_else(|| {
        MaterialsError::keyring_failed(
            "Branch key wrap: KBKDF-CTR-HMAC-SHA256 algorithm is unavailable",
        )
    })?;

    let mut derived = [0u8; DERIVED_KEY_LEN];
    kbkdf_ctr_hmac(alg, branch_key, &info, &mut derived).map_err(|_| {
        MaterialsError::keyring_failed("Branch key wrap: KBKDF-CTR-HMAC-SHA256 derivation failed")
    })?;
    Ok(derived)
}

// ---- Wrap --------------------------------------------------------------------

/// Wrap a plaintext data key with the branch key materials and return the
/// on-wire ciphertext layout:
///
/// ```text
/// salt(16) || iv(12) || version(16) || encrypted_key(plaintext_len) || tag(16)
/// ```
///
/// `encryption_context` is the input encryption-materials' EC, bound
/// into the AAD per spec `#branch-key-wrapping-and-unwrapping-aad` item 4
/// ("encryption context from the input encryption materials").
pub fn wrap(
    materials: &BranchKeyMaterials,
    encryption_context: &EncryptionContext,
    plaintext_data_key: &[u8],
) -> Result<Vec<u8>, MaterialsError> {
    // 1. Generate a 16-byte random salt.
    let mut salt = [0u8; SALT_LEN];
    fill(&mut salt).map_err(|_| {
        MaterialsError::keyring_failed("Branch key wrap: failed to obtain entropy for salt")
    })?;

    // 2. Generate a 12-byte random IV.
    let mut iv = [0u8; IV_LEN];
    fill(&mut iv).map_err(|_| {
        MaterialsError::keyring_failed("Branch key wrap: failed to obtain entropy for IV")
    })?;

    // 3. Derive the AES-256-GCM cipher key.
    let derived_branch_key = derive_branch_key(materials.branch_key(), &salt)?;

    // 4. Construct the AAD.
    let aad_bytes = compute_aad(
        materials.branch_key_id(),
        materials.branch_key_version(),
        encryption_context,
    )?;

    // 5. AES-256-GCM seal.
    //
    // `seal_in_place_separate_tag` mutates `in_out` to the ciphertext and
    // returns the 16-byte tag separately, which is exactly the layout
    // required by the wire format below.
    let mut in_out = plaintext_data_key.to_vec();

    let unbound = UnboundKey::new(&AES_256_GCM, &derived_branch_key)
        .map_err(|_| MaterialsError::keyring_failed("Branch key wrap: invalid AES-256 key"))?;
    let key = LessSafeKey::new(unbound);

    let nonce = Nonce::assume_unique_for_key(iv);

    let version_bytes = uuid_str_to_16_bytes(materials.branch_key_version())?;

    //
    //
    // AES_256_GCM in aws-lc-rs always produces a 16-byte tag
    // (MAX_TAG_LEN == TAG_LEN == 16); the type-system / library
    // guarantee makes the requirement true by construction.
    //
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(&aad_bytes), &mut in_out)
        .map_err(|_| MaterialsError::keyring_failed("Branch key wrap: AES-256-GCM seal failed"))?;
    debug_assert_eq!(
        tag.as_ref().len(),
        TAG_LEN,
        "AES-256-GCM tag must be {TAG_LEN} bytes",
    );

    // Assemble the on-wire layout.
    let mut output = Vec::with_capacity(FIXED_OVERHEAD_LEN.saturating_add(in_out.len()));
    output.extend_from_slice(&salt);
    output.extend_from_slice(&iv);
    output.extend_from_slice(&version_bytes);
    output.extend_from_slice(&in_out);
    output.extend_from_slice(tag.as_ref());

    // Each fallible step (entropy, KDF, AAD construction, AES seal) uses `?`
    // to propagate; reaching this Ok requires every step to have succeeded.
    Ok(output)
}

// ---- Unwrap ------------------------------------------------------------------

/// Unwrap a branch-key-wrapped ciphertext produced by [`wrap`] and return
/// the plaintext data key.
///
/// Expects the on-wire layout
/// `salt(16) || iv(12) || version(16) || encrypted_key(var) || tag(16)`.
///
/// `encryption_context` is the input decryption-materials' EC, bound
/// into the AAD per spec `#branch-key-wrapping-and-unwrapping-aad` item 4.
pub fn unwrap(
    materials: &BranchKeyMaterials,
    encryption_context: &EncryptionContext,
    ciphertext: &[u8],
) -> Result<Vec<u8>, MaterialsError> {
    // Validate ciphertext is at least the fixed overhead so the slicing below is in-bounds.
    if ciphertext.len() < FIXED_OVERHEAD_LEN {
        return Err(MaterialsError::keyring_failed(format!(
            "Branch key unwrap: ciphertext too short: {} < {FIXED_OVERHEAD_LEN}",
            ciphertext.len(),
        )));
    }

    // Deserialize the layout.
    let salt: [u8; SALT_LEN] = ciphertext[0..SALT_LEN]
        .try_into()
        .expect("16-byte slice into [u8; 16]");
    let iv_bytes: [u8; IV_LEN] = ciphertext[SALT_LEN..SALT_LEN + IV_LEN]
        .try_into()
        .expect("12-byte slice into [u8; 12]");
    let version_offset = SALT_LEN + IV_LEN;
    let _version: [u8; VERSION_LEN] = ciphertext[version_offset..version_offset + VERSION_LEN]
        .try_into()
        .expect("16-byte slice into [u8; 16]");
    let body_offset = version_offset + VERSION_LEN;
    let encrypted_key_end = ciphertext.len() - TAG_LEN;
    let encrypted_key = &ciphertext[body_offset..encrypted_key_end];
    let tag = &ciphertext[encrypted_key_end..];
    debug_assert_eq!(tag.len(), TAG_LEN);

    // Derive the AES-256-GCM cipher key from the deserialized salt and the
    // in-memory branch key.
    let derived_branch_key = derive_branch_key(materials.branch_key(), &salt)?;

    // Build the AAD using the materials' branch_key_id, branch_key_version,
    // and the supplied encryption_context (the decryption-materials' EC).
    // Note: A1 mandates the AAD is included in the AES Decrypt call;
    // A2 mandates the concatenation order.
    let aad_bytes = compute_aad(
        materials.branch_key_id(),
        materials.branch_key_version(),
        encryption_context,
    )?;

    let unbound = UnboundKey::new(&AES_256_GCM, &derived_branch_key)
        .map_err(|_| MaterialsError::keyring_failed("Branch key unwrap: invalid AES-256 key"))?;
    let key = LessSafeKey::new(unbound);

    let nonce = Nonce::assume_unique_for_key(iv_bytes);

    // `LessSafeKey::open_in_place` consumes a single in-out buffer holding
    // ciphertext concatenated with the tag. Build that buffer here so the
    // following annotations can sit on the lines that copy in each piece.
    let mut combined = Vec::with_capacity(encrypted_key.len().saturating_add(TAG_LEN));

    combined.extend_from_slice(encrypted_key);

    combined.extend_from_slice(tag);

    // A1 ("the keyring MUST include the AAD values for the AES Encrypt/Decrypt
    // calls") is annotated at the wrap-side AES seal call; the requirement
    // applies symmetrically here on the AES open call.
    let plaintext_slice = key
        .open_in_place(nonce, Aad::from(&aad_bytes), &mut combined)
        .map_err(|_| {
            MaterialsError::keyring_failed("Branch key unwrap: AES-256-GCM open failed")
        })?;
    let plaintext = plaintext_slice.to_vec();

    // Each fallible step (deserialization, KDF, AAD construction, AES open)
    // uses `?` to propagate; reaching this Ok requires every step to have
    // succeeded.
    Ok(plaintext)
}
