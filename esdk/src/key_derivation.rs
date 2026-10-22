// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Key derivation for the ESDK message encryption key.

use super::Error;
use crate::error::{Kind, err};
use crate::message::header_types::MESSAGE_ID_LEN_V2;
use crate::message::serializable_types::get_encrypt_key_length;
use crate::suites::kdf_digest;
use aws_crypto_mpl::types::{AlgorithmSuite, KeyDerivationAlgorithm};
use zeroize::Zeroizing;

// Holds a derived data key and an optional commitment key (the latter only for
// committing algorithm suites). This is `pub` only so `derive_keys` is reachable
// from integration tests via `__test_internals`; it is not supported public API.
#[doc(hidden)]
#[expect(
    clippy::exhaustive_structs,
    reason = "test-internal struct, not public API"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedKeyMaterial {
    pub data_key: Zeroizing<Vec<u8>>,
    pub commitment_key: Option<Zeroizing<Vec<u8>>>,
}

// Returns the HKDF key length defined by the algorithm suite, which serves as
// both the input (plaintext data key) length and the output (derived key)
// length. Only HKDF suites carry a length; the identity KDF reaching here is a
// config error.
fn hkdf_key_len(suite: &AlgorithmSuite) -> Result<usize, Error> {
    match suite.encryption_kdf() {
        KeyDerivationAlgorithm::IdentityKdf => Err(err(
            Kind::Internal,
            "algorithm suite KDF must be HKDF to derive a key length, got IdentityKdf",
        )),
        _ => Ok(suite.encryption_key_length()),
    }
}

// Output length in bytes of each supported hash. Used to size the all-zero HKDF
// salt for V1 derivation (the salt length equals the hash output length, RFC 5869).
fn digest_length(alg: aws_mpl_primitives::DigestAlg) -> Result<usize, Error> {
    match alg {
        aws_mpl_primitives::DigestAlg::Sha256 => Ok(32),
        aws_mpl_primitives::DigestAlg::Sha384 => Ok(48),
        aws_mpl_primitives::DigestAlg::Sha512 => Ok(64),
        other => Err(err(Kind::Internal, format!("unknown DigestAlg {other:?}"))),
    }
}

// Derives the message encryption key for V1 suites: a single HKDF call, with no
// key commitment.
pub(crate) fn derive_key_v1(
    message_id: &[u8],
    plaintext_data_key: &[u8],
    suite: &AlgorithmSuite,
) -> Result<ExpandedKeyMaterial, Error> {
    // `derive_keys` dispatches on the message version, so a non-V1 suite here is an
    // internal bug rather than bad input.
    debug_assert_eq!(suite.message_format_version(), 1);

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# The algorithm used to derive a data key from the plaintext data key MUST be
    //# the [key derivation algorithm](../framework/algorithm-suites.md#key-derivation-algorithm) included in the
    //# [algorithm suite](../framework/algorithm-suites.md) defined above.
    match suite.encryption_kdf() {
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# - If the key derivation algorithm is the [identity KDF](../framework/algorithm-suites.md#identity-kdf),
        //# then the derived data key MUST be the same as the plaintext data key.
        //
        //= spec/client-apis/decrypt.md#get-the-decryption-materials
        //# If the key derivation algorithm is the [identity KDF](../framework/algorithm-suites.md#identity-kdf),
        //# then the derived data key MUST be the same as the plaintext data key.
        KeyDerivationAlgorithm::IdentityKdf => {
            // The identity KDF uses the plaintext data key verbatim, so its length
            // must already equal the suite's encryption key length.
            let encrypt_key_len = get_encrypt_key_length(suite);
            if plaintext_data_key.len() != encrypt_key_len {
                return Err(err(
                    Kind::InvalidMaterials,
                    format!(
                        "identity KDF plaintext data key length {} does not match the suite encryption key length {encrypt_key_len}",
                        plaintext_data_key.len()
                    ),
                ));
            }
            Ok(ExpandedKeyMaterial {
                data_key: Zeroizing::new(plaintext_data_key.to_vec()),
                commitment_key: None,
            })
        }
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# - If the key derivation algorithm is [HKDF](../framework/algorithm-suites.md#hkdf),
        //# the derivation process used MUST be the process described in [HKDF Encryption Key](../transitive-requirements.md#hkdf-encryption-key).
        //
        //= spec/client-apis/key-derivation.md#hkdf-encryption-key
        //# If an algorithm suite uses HKDF to derive the encryption key,
        //# the AWS Encryption SDK MUST use HKDF as follows.
        kdf => {
            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //# - The hash function MUST be the hash function specified by the algorithm suite's encryption key derivation settings.
            let alg = kdf_digest(kdf)?;

            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //# - If the algorithm suite's encryption key derivation settings specify a salt length of 0,
            //# the salt MUST be a sequence of zero bytes as long as the hash function's output.
            let salt = vec![0u8; digest_length(alg)?];

            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //# - The length of the output keying material MUST equal the encryption key length
            //# specified by the algorithm suite's encryption settings.
            let output_len = suite.encryption_key_length();
            let mut derived_key = Zeroizing::new(vec![0u8; output_len]);

            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //# - If the algorithm suite is not key committing,
            //# the info MUST be the algorithm suite ID followed by the message ID.
            let suite_id = suite.id();
            let info: [&[u8]; 2] = [&suite_id[..], message_id];

            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //= type=implication
            //= reason=primitives::hkdf bundles HKDF-Extract and HKDF-Expand; the PRK input to expand is the extract output by construction of the helper
            //# - The pseudorandom key MUST be the output of the extract step.
            aws_mpl_primitives::hkdf(alg, &salt, plaintext_data_key, &info, &mut derived_key[..])?;

            Ok(ExpandedKeyMaterial {
                data_key: derived_key,
                commitment_key: None,
            })
        }
    }
}

// HKDF-expand info labels for V2 derivation: COMMITKEY produces the commitment
// key, DERIVEKEY (prefixed with the suite's binary ID) produces the encryption key.
const COMMIT_LABEL: &str = "COMMITKEY";
const KEY_LABEL: &str = "DERIVEKEY";

// Derives the message encryption key and key commitment value for V2 suites:
// one HKDF-extract followed by two HKDF-expands.
//
//= spec/client-apis/key-derivation.md#hkdf-encryption-key
//# If an algorithm suite uses HKDF to derive the encryption key,
//# the AWS Encryption SDK MUST use HKDF as follows.
//
//= spec/client-apis/key-derivation.md#hkdf-commit-key
//# If an algorithm suite uses HKDF to derive the commit key,
//# the AWS Encryption SDK MUST use HKDF as follows.
#[doc(hidden)]
pub fn derive_key_v2(
    message_id: &[u8],
    plaintext_data_key: &[u8],
    suite: &AlgorithmSuite,
) -> Result<ExpandedKeyMaterial, Error> {
    // `derive_keys` dispatches on the message version, so a non-V2 suite here is an
    // internal bug rather than bad input.
    debug_assert_eq!(suite.message_format_version(), 2);

    // For V2 algorithms the KDF can only be HKDF.
    let kdf_key_len = hkdf_key_len(suite)?;
    if message_id.len() != MESSAGE_ID_LEN_V2 {
        return Err(err(
            Kind::Internal,
            format!(
                "V2 message ID (HKDF salt) must be {MESSAGE_ID_LEN_V2} bytes, got {}",
                message_id.len()
            ),
        ));
    }
    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //# - The length of the input keying material MUST equal the key derivation input length
    //# specified by the algorithm suite's encryption key derivation settings.
    //
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //# - The length of the input keying material MUST equal the key derivation input length
    //# specified by the algorithm suite's commit key derivation settings.
    if plaintext_data_key.len() != kdf_key_len {
        return Err(err(
            Kind::InvalidMaterials,
            format!(
                "plaintext data key length {} does not match KDF input key length {kdf_key_len}",
                plaintext_data_key.len()
            ),
        ));
    }

    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //= reason=V2 suites share the same HKDF hash for encryption and commit derivation; suite.commitment.hkdf.hmac is the HKDF hash configured by the suite
    //# - The hash function MUST be the hash function specified by the algorithm suite's encryption key derivation settings.
    //
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //= type=implication
    //= reason=Hash is destructured directly from suite.commitment; both V2 committing suites (0x0478, 0x0578) carry SHA-512, so no observable runtime differential exists to falsify
    //# - The hash function MUST be the hash function specified by the algorithm suite's commit key derivation settings.
    let (alg, commit_len) = match suite.commit_kdf() {
        Some(commit_kdf) => (kdf_digest(commit_kdf)?, suite.algorithm_suite_data_length()),
        None => {
            return Err(err(Kind::Internal, "algorithm suite has no commitment KDF"));
        }
    };

    // V2 key commitment derivation. A single HKDF-extract over the message ID (used
    // as the salt) and the plaintext key yields one pseudo-random key, which is then
    // expanded twice with distinct info labels: `binary_id || DERIVEKEY` for the
    // message encryption key (binding it to the algorithm suite), and `COMMITKEY` for
    // the commitment key. See `framework/algorithm-suites.md`.
    //
    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //# - If the algorithm suite's encryption key derivation settings specify a nonzero salt length,
    //# the salt MUST be the [message ID](../data-format/message-header.md#message-id), with a length equal to that salt length.
    //
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //# - The salt MUST be the [message ID](../data-format/message-header.md#message-id),
    //# with a length equal to the salt length specified by the algorithm suite's commit key derivation settings.
    //
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //= type=implication
    //= reason=pseudo_random_key is bound once by hkdf_extract and reused for both hkdf_expand calls — extract-once is structural
    //# For key committing algorithm suites,
    //# the AWS Encryption SDK SHOULD perform the extract step once
    //# and use its output for both the encryption key and the commit key.
    let pseudo_random_key = aws_mpl_primitives::hkdf_extract(alg, message_id, plaintext_data_key);

    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //# - The length of the output keying material MUST equal the encryption key length
    //# specified by the algorithm suite's encryption settings.
    let mut encrypt_key = Zeroizing::new(vec![0u8; kdf_key_len]);

    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //# - The length of the output keying material MUST equal the key derivation output length
    //# specified by the algorithm suite's commit key derivation settings.
    let mut commit_key = Zeroizing::new(vec![0u8; commit_len]);

    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //# - If the algorithm suite is key committing,
    //# the info MUST be the [algorithm suite ID](../framework/algorithm-suites.md#algorithm-suite-id)
    //# followed by the string `DERIVEKEY` as UTF-8 encoded bytes.
    let suite_id = suite.id();
    let info = [&suite_id[..], KEY_LABEL.as_bytes()];

    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //= type=implication
    //= reason=pseudo_random_key holds the hkdf_extract return value above and is the only PRK input threaded into hkdf_expand here by data dependency
    //# - The pseudorandom key MUST be the output of the extract step.
    aws_mpl_primitives::hkdf_expand(&pseudo_random_key, &info, &mut encrypt_key[..])?;

    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //= type=implication
    //= reason=pseudo_random_key holds the hkdf_extract return value above and is the only PRK input threaded into hkdf_expand here by data dependency
    //# - The pseudorandom key MUST be the output of the extract step.
    //
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //# - The info MUST be the string `COMMITKEY` as UTF-8 encoded bytes.
    aws_mpl_primitives::hkdf_expand(
        &pseudo_random_key,
        &[COMMIT_LABEL.as_bytes()],
        &mut commit_key[..],
    )?;

    Ok(ExpandedKeyMaterial {
        data_key: encrypt_key,
        commitment_key: Some(commit_key),
    })
}

// Derives key material for encryption/decryption. Delegates to the V1 or V2
// routine based on the algorithm suite's message version. `pub` only so it is
// reachable from integration tests via `__test_internals`; internal callers use
// the crate path.
#[doc(hidden)]
pub fn derive_keys(
    message_id: &[u8],
    plaintext_data_key: &[u8],
    suite: &AlgorithmSuite,
) -> Result<ExpandedKeyMaterial, Error> {
    debug_assert_ne!(message_id.len(), 0);
    debug_assert_eq!(get_encrypt_key_length(suite), plaintext_data_key.len());

    match suite.message_format_version() {
        1 => derive_key_v1(message_id, plaintext_data_key, suite),
        2 => derive_key_v2(message_id, plaintext_data_key, suite),
        _ => Err(err(
            Kind::Internal,
            format!("unknown message version {}", suite.message_format_version()),
        )),
    }
}
