// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Key derivation for the ESDK message encryption key.

use super::{Error, val_err};
use crate::message::header_types::MESSAGE_ID_LEN_V2;
use crate::message::serializable_types::get_encrypt_key_length;
use aws_mpl_legacy::suites::AlgorithmSuite;
use aws_mpl_legacy::suites::DerivationAlgorithm;
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

// Returns the HKDF-derived (output) key length defined by the algorithm suite.
// Only HKDF suites carry this length; any other KDF reaching here is a config error.
fn get_kdf_output_len(suite: &AlgorithmSuite) -> Result<u32, Error> {
    match suite.kdf {
        DerivationAlgorithm::Hkdf(x) => Ok(x.output_key_length),
        other => Err(val_err(format!(
            "Algorithm suite KDF must be HKDF to derive output key length, got {other:?}"
        ))),
    }
}

// Returns the HKDF input (plaintext data key) length defined by the algorithm suite.
// Only HKDF suites carry this length; any other KDF reaching here is a config error.
fn get_kdf_input_len(suite: &AlgorithmSuite) -> Result<u32, Error> {
    match suite.kdf {
        DerivationAlgorithm::Hkdf(x) => Ok(x.input_key_length),
        other => Err(val_err(format!(
            "Algorithm suite KDF must be HKDF to derive input key length, got {other:?}"
        ))),
    }
}

// Output length in bytes of each supported hash. Used to size the all-zero HKDF
// salt for V1 derivation (the salt length equals the hash output length, RFC 5869).
fn digest_length(alg: aws_mpl_legacy::primitives::DigestAlg) -> Result<usize, Error> {
    match alg {
        aws_mpl_legacy::primitives::DigestAlg::Sha256 => Ok(32),
        aws_mpl_legacy::primitives::DigestAlg::Sha384 => Ok(48),
        aws_mpl_legacy::primitives::DigestAlg::Sha512 => Ok(64),
        other => Err(val_err(format!("Unknown DigestAlg {other:?}"))),
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
    debug_assert_eq!(suite.message_version, 1);

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# The algorithm used to derive a data key from the plaintext data key MUST be
    //# the [key derivation algorithm](../framework/algorithm-suites.md#key-derivation-algorithm) included in the
    //# [algorithm suite](../framework/algorithm-suites.md) defined above.
    match &suite.kdf {
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# - If the key derivation algorithm is the [identity KDF](../framework/algorithm-suites.md#identity-kdf),
        //# then the derived data key MUST be the same as the plaintext data key.
        //
        //= spec/client-apis/decrypt.md#get-the-decryption-materials
        //# If the key derivation algorithm is the [identity KDF](../framework/algorithm-suites.md#identity-kdf),
        //# then the derived data key MUST be the same as the plaintext data key.
        DerivationAlgorithm::Identity => {
            // The identity KDF uses the plaintext data key verbatim, so its length
            // must already equal the suite's encryption key length.
            let encrypt_key_len = usize::from(get_encrypt_key_length(suite));
            if plaintext_data_key.len() != encrypt_key_len {
                return Err(val_err(format!(
                    "Identity KDF plaintext data key length {} does not match the suite encryption key length {encrypt_key_len}",
                    plaintext_data_key.len()
                )));
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
        DerivationAlgorithm::Hkdf(hkdf) => {
            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //# - The hash function MUST be the hash function specified by the algorithm suite's encryption key derivation settings.
            let alg = hkdf.hmac;

            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //# - If the algorithm suite's encryption key derivation settings specify a salt length of 0,
            //# the salt MUST be a sequence of zero bytes as long as the hash function's output.
            let salt = vec![0u8; digest_length(alg)?];

            let Ok(output_len) = usize::try_from(hkdf.output_key_length) else {
                return Err(val_err(format!(
                    "HKDF output_key_length {} exceeds usize",
                    hkdf.output_key_length
                )));
            };
            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //# - The length of the output keying material MUST equal the encryption key length
            //# specified by the algorithm suite's encryption settings.
            let mut derived_key = Zeroizing::new(vec![0u8; output_len]);

            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //# - If the algorithm suite is not key committing,
            //# the info MUST be the algorithm suite ID followed by the message ID.
            let info: [&[u8]; 2] = [&suite.binary_id[..], message_id];

            //= spec/client-apis/key-derivation.md#hkdf-encryption-key
            //= type=implication
            //= reason=primitives::hkdf bundles HKDF-Extract and HKDF-Expand; the PRK input to expand is the extract output by construction of the helper
            //# - The pseudorandom key MUST be the output of the extract step.
            aws_mpl_legacy::primitives::hkdf(
                alg,
                &salt,
                plaintext_data_key,
                &info,
                &mut derived_key[..],
            )?;

            Ok(ExpandedKeyMaterial {
                data_key: derived_key,
                commitment_key: None,
            })
        }
        DerivationAlgorithm::None => Err(val_err("None is not a valid Key Derivation Function")),
        _ => Err(val_err("Unknown is not a valid Key Derivation Function")),
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
    debug_assert_eq!(suite.message_version, 2);

    // For V2 algorithms the KDF can only be HKDF, and the encryption key length must
    // match the KDF output length.
    let kdf_output_len = get_kdf_output_len(suite)?;
    let encrypt_key_len = u32::from(get_encrypt_key_length(suite));
    if encrypt_key_len != kdf_output_len {
        return Err(val_err(format!(
            "Encryption key length {encrypt_key_len} does not match KDF output key length {kdf_output_len}"
        )));
    }
    if message_id.len() != MESSAGE_ID_LEN_V2 {
        return Err(val_err(format!(
            "V2 message ID (HKDF salt) must be {MESSAGE_ID_LEN_V2} bytes, got {}",
            message_id.len()
        )));
    }
    let kdf_input_len = get_kdf_input_len(suite)?;
    let Ok(kdf_input_len) = usize::try_from(kdf_input_len) else {
        return Err(val_err(format!(
            "KDF input_key_length {kdf_input_len} exceeds usize"
        )));
    };
    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //# - The length of the input keying material MUST equal the key derivation input length
    //# specified by the algorithm suite's encryption key derivation settings.
    //
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //# - The length of the input keying material MUST equal the key derivation input length
    //# specified by the algorithm suite's commit key derivation settings.
    if plaintext_data_key.len() != kdf_input_len {
        return Err(val_err(format!(
            "Plaintext data key length {} does not match KDF input key length {kdf_input_len}",
            plaintext_data_key.len()
        )));
    }

    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //= reason=V2 suites share the same HKDF hash for encryption and commit derivation; suite.commitment.hkdf.hmac is the HKDF hash configured by the suite
    //# - The hash function MUST be the hash function specified by the algorithm suite's encryption key derivation settings.
    //
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //= type=implication
    //= reason=Hash is destructured directly from suite.commitment; both V2 committing suites (0x0478, 0x0578) carry SHA-512, so no observable runtime differential exists to falsify
    //# - The hash function MUST be the hash function specified by the algorithm suite's commit key derivation settings.
    let (alg, commit_len) = match &suite.commitment {
        DerivationAlgorithm::Hkdf(hkdf) => (hkdf.hmac, hkdf.output_key_length),
        DerivationAlgorithm::None => {
            return Err(val_err("None is not a valid Commitment Algorithm"));
        }
        other => {
            return Err(val_err(format!(
                "{other:?} is not a valid Commitment Algorithm"
            )));
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
    let pseudo_random_key =
        aws_mpl_legacy::primitives::hkdf_extract(alg, message_id, plaintext_data_key);

    let Ok(encrypt_key_len) = usize::try_from(kdf_output_len) else {
        return Err(val_err(format!(
            "KDF output_key_length {kdf_output_len} exceeds usize"
        )));
    };
    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //# - The length of the output keying material MUST equal the encryption key length
    //# specified by the algorithm suite's encryption settings.
    let mut encrypt_key = Zeroizing::new(vec![0u8; encrypt_key_len]);

    let Ok(commit_len) = usize::try_from(commit_len) else {
        return Err(val_err(format!(
            "Commit key length {commit_len} exceeds usize"
        )));
    };
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //# - The length of the output keying material MUST equal the key derivation output length
    //# specified by the algorithm suite's commit key derivation settings.
    let mut commit_key = Zeroizing::new(vec![0u8; commit_len]);

    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //# - If the algorithm suite is key committing,
    //# the info MUST be the [algorithm suite ID](../framework/algorithm-suites.md#algorithm-suite-id)
    //# followed by the string `DERIVEKEY` as UTF-8 encoded bytes.
    let info = [&suite.binary_id[..], KEY_LABEL.as_bytes()];

    //= spec/client-apis/key-derivation.md#hkdf-encryption-key
    //= type=implication
    //= reason=pseudo_random_key holds the hkdf_extract return value above and is the only PRK input threaded into hkdf_expand here by data dependency
    //# - The pseudorandom key MUST be the output of the extract step.
    aws_mpl_legacy::primitives::hkdf_expand(&pseudo_random_key, &info, &mut encrypt_key[..])?;

    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //= type=implication
    //= reason=pseudo_random_key holds the hkdf_extract return value above and is the only PRK input threaded into hkdf_expand here by data dependency
    //# - The pseudorandom key MUST be the output of the extract step.
    //
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //# - The info MUST be the string `COMMITKEY` as UTF-8 encoded bytes.
    aws_mpl_legacy::primitives::hkdf_expand(
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
    debug_assert!(!message_id.is_empty());
    debug_assert_eq!(
        usize::from(get_encrypt_key_length(suite)),
        plaintext_data_key.len()
    );

    match suite.message_version {
        1 => derive_key_v1(message_id, plaintext_data_key, suite),
        2 => derive_key_v2(message_id, plaintext_data_key, suite),
        _ => Err(val_err(format!(
            "Unknown Message Version {}",
            suite.message_version
        ))),
    }
}
