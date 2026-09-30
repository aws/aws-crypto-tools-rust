// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Branch-key wrapping/unwrapping primitives for the AWS KMS Hierarchical Keyring.
//!
//! Wrapping, unwrapping, and the AAD both sides bind. Pure crypto over
//! `aws-mpl-primitives`, with no cache or KMS dependency. Used by the
//! `Keyring` impl in [`super::hierarchical_keyring`].

use crate::{Error, ErrorKind};
use aws_mpl_primitives::{
    AesGcm, DigestAlg, aes_decrypt, aes_encrypt, generate_random_bytes, kbkdf_ctr_hmac,
};
use uuid::Uuid;

use crate::structures::{BranchKeyMaterials, EncryptionContext};

/// Length of the random salt used as the KDF context: 16 bytes.
const SALT_LEN: usize = 16;

/// Length of the AES-GCM IV: 12 bytes.
const IV_LEN: usize = 12;

/// Length of the branch-key version (UUID) when serialized as raw bytes
/// inside the AAD and the on-wire layout: 16 bytes.
const VERSION_LEN: usize = 16;

/// AES-GCM authentication tag length. AES-256-GCM always produces a
/// 16-byte tag.
const TAG_LEN: usize = 16;

/// Length of the derived branch key produced by the KDF in Counter Mode with
/// HMAC SHA256. AES-256-GCM requires a 32-byte cipher key.
const DERIVED_KEY_LEN: usize = 32;

/// Label for the KDF in Counter Mode with HMAC SHA256 derivation and for the
/// AAD prefix: the literal "aws-kms-hierarchy", UTF-8 encoded — 17 bytes.
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
/// 3. The 16-byte representation of `branch_key_version` (parsed from its
///    canonical hyphenated UUID form).
/// 4. The serialized `EncryptionContext`.
///
/// Returns `Error` if the encryption context fails to serialize
/// (entry count or key/value length exceeds `u16::MAX`) or if the
/// `branch_key_version` cannot be parsed as a 16-byte UUID.
pub fn compute_aad(
    branch_key_id: &str,
    branch_key_version: &str,
    encryption_context: &EncryptionContext,
) -> Result<Vec<u8>, Error> {
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

/// Parse a UUID in canonical hyphenated form (8-4-4-4-12) into its 16 raw
/// bytes.
///
/// This parse is the validation gate on the branch-key-version string.
/// Returns `Error` rather than panicking so a caller that hands us a
/// malformed string (e.g. a corrupted keystore record or a fuzzer) gets a
/// clean error instead of a process abort.
///
/// The explicit length check keeps the gate strict: `Uuid::parse_str` also
/// accepts the 32-character simple form as well as braced and URN forms,
/// and only the canonical hyphenated form is 36 characters.
fn uuid_str_to_16_bytes(s: &str) -> Result<[u8; VERSION_LEN], Error> {
    if s.len() != 36 {
        return Err(Error::new(
            ErrorKind::Validation,
            format!("branch key version is not a valid 36-char UUID: {s}",),
        ));
    }
    let uuid = Uuid::parse_str(s).map_err(|e| {
        Error::with_cause(
            ErrorKind::Validation,
            format!("branch key version is not a valid UUID: {s}"),
            e,
        )
    })?;
    Ok(*uuid.as_bytes())
}

// ---- KDF ---------------------------------------------------------------------

/// Derive the 32-byte AES-256-GCM cipher key from the branch key using the
/// KDF in Counter Mode with HMAC SHA256 (NIST SP 800-108 §4.1).
///
/// The fixed-info string follows the standard NIST construction
/// `Label || 0x00 || Context || L_be32`, with:
/// * `Label`   = "aws-kms-hierarchy"
/// * `Context` = `salt`
/// * `L_be32`  = 0x00000100 (256 bits = 32 bytes of output)
fn derive_branch_key(
    branch_key: &[u8; DERIVED_KEY_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<[u8; DERIVED_KEY_LEN], Error> {
    // FixedInfo: Label || 0x00 || salt || L_be32 (256-bit output).
    let mut info = Vec::with_capacity(HIERARCHY_LABEL.len() + 1 + SALT_LEN + 4);
    info.extend_from_slice(HIERARCHY_LABEL);
    info.push(0x00);
    info.extend_from_slice(salt);
    let output_len_bits: u32 = 256;
    info.extend_from_slice(&output_len_bits.to_be_bytes());

    let mut derived = [0u8; DERIVED_KEY_LEN];
    kbkdf_ctr_hmac(DigestAlg::Sha256, branch_key, &info, &mut derived).map_err(|e| {
        Error::with_cause(
            ErrorKind::Cryptographic,
            "KDF in Counter Mode with HMAC SHA256 derivation failed",
            e,
        )
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
/// `encryption_context` is the input encryption-materials' EC, bound into
/// the AAD.
pub fn wrap(
    materials: &BranchKeyMaterials,
    encryption_context: &EncryptionContext,
    plaintext_data_key: &[u8],
) -> Result<Vec<u8>, Error> {
    // 1. Generate a 16-byte random salt.
    let mut salt = [0u8; SALT_LEN];
    generate_random_bytes(&mut salt).map_err(|e| {
        Error::with_cause(
            ErrorKind::Cryptographic,
            "failed to obtain entropy for salt",
            e,
        )
    })?;

    // 2. Generate a 12-byte random IV.
    let mut iv = [0u8; IV_LEN];
    generate_random_bytes(&mut iv).map_err(|e| {
        Error::with_cause(
            ErrorKind::Cryptographic,
            "failed to obtain entropy for IV",
            e,
        )
    })?;

    // 3. Derive the AES-256-GCM cipher key.
    let derived_branch_key = derive_branch_key(materials.branch_key(), &salt)?;

    // 4. Construct the AAD.
    let aad_bytes = compute_aad(
        materials.branch_key_id(),
        materials.branch_key_version(),
        encryption_context,
    )?;

    let version_bytes = uuid_str_to_16_bytes(materials.branch_key_version())?;

    // 5. Assemble the on-wire layout and AES-256-GCM encrypt directly into it.
    //
    // `aes_encrypt` appends `ciphertext || tag` to the buffer, which is
    // exactly the tail of the wire format:
    //   salt(16) || iv(12) || version(16) || encrypted_key(pt_len) || tag(16)
    let mut output =
        Vec::with_capacity(FIXED_OVERHEAD_LEN.saturating_add(plaintext_data_key.len()));
    output.extend_from_slice(&salt);
    output.extend_from_slice(&iv);
    output.extend_from_slice(&version_bytes);
    let pre_encrypt_len = output.len();

    aes_encrypt(
        AesGcm::Aes256Gcm,
        &iv,
        &derived_branch_key,
        plaintext_data_key,
        &aad_bytes,
        &mut output,
    )
    .map_err(|e| Error::with_cause(ErrorKind::Cryptographic, "AES-256-GCM encrypt failed", e))?;

    debug_assert_eq!(
        output.len() - pre_encrypt_len,
        plaintext_data_key.len() + TAG_LEN,
        "AES-256-GCM output must be ciphertext (pt_len) + tag ({TAG_LEN} bytes)",
    );

    // Each fallible step (entropy, KDF, AAD construction, AES encrypt) uses `?`
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
/// `encryption_context` is the input decryption-materials' EC, bound into
/// the AAD.
pub fn unwrap(
    materials: &BranchKeyMaterials,
    encryption_context: &EncryptionContext,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    // Validate ciphertext is at least the fixed overhead so the slicing below is in-bounds.
    if ciphertext.len() < FIXED_OVERHEAD_LEN {
        return Err(Error::new(
            ErrorKind::Cryptographic,
            format!(
                "ciphertext too short: {} < {FIXED_OVERHEAD_LEN}",
                ciphertext.len(),
            ),
        ));
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
    let aad_bytes = compute_aad(
        materials.branch_key_id(),
        materials.branch_key_version(),
        encryption_context,
    )?;

    let mut plaintext = vec![0u8; encrypted_key.len()];
    aes_decrypt(
        AesGcm::Aes256Gcm,
        &derived_branch_key,
        encrypted_key,
        tag,
        &iv_bytes,
        &aad_bytes,
        &mut plaintext,
    )
    .map_err(|e| Error::with_cause(ErrorKind::Cryptographic, "AES-256-GCM decrypt failed", e))?;

    // Each fallible step (deserialization, KDF, AAD construction, AES decrypt)
    // uses `?` to propagate; reaching this Ok requires every step to have
    // succeeded.
    Ok(plaintext)
}
