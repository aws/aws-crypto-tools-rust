// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Key derivation for the ESDK message encryption key.

use super::Error;
use crate::error::{Kind, err};
use crate::message::header_types::MESSAGE_ID_LEN_V2;
use crate::message::header_types::{MessageFormatVersion, msg_format_version_from_u8};
use crate::message::serializable_types::get_encrypt_key_length;
use crate::secret::{self, CommitmentValue, DataKeyRef, MessageKey};
use crate::suites::kdf_digest;
use aws_crypto_mpl::types::{AlgorithmSuite, KeyDerivationAlgorithm};
use vstd::prelude::*;

verus! {

/// Why `check_v2_key_lengths` rejected a V2 key derivation, in check order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum V2KeyLenError {
    /// The suite's encryption KDF is the identity KDF, which has no HKDF key length.
    IdentityKdf,
    /// The message ID (the HKDF salt) is not `MESSAGE_ID_LEN_V2` bytes.
    MessageIdLen,
    /// The plaintext data key (the HKDF input keying material) is not the
    /// suite's key length.
    PlaintextKeyLen,
}

/// Whether an identity-KDF plaintext data key of `plaintext_key_len` bytes can
/// be used verbatim as a suite encryption key of `encrypt_key_len` bytes.
fn identity_kdf_key_len_ok(plaintext_key_len: usize, encrypt_key_len: usize) -> (ok: bool)
    ensures
        ok <==> plaintext_key_len == encrypt_key_len,
{
    plaintext_key_len == encrypt_key_len
}

/// The V2 length checks: the KDF must be HKDF, the message ID must be
/// `MESSAGE_ID_LEN_V2` bytes, and the plaintext data key must be the suite's
/// key length `suite_key_len`. On success, returns the HKDF key length, which
/// sizes the derived encryption key buffer.
///
/// `derive_key_v2` is the unverified adapter: it reads these inputs from the
/// suite and the slices, and turns each `V2KeyLenError` into an `Error`.
fn check_v2_key_lengths(
    identity_kdf: bool,
    suite_key_len: usize,
    message_id_len: usize,
    plaintext_key_len: usize,
) -> (r: Result<usize, V2KeyLenError>)
    ensures
        (r is Ok) <==> (!identity_kdf && message_id_len == MESSAGE_ID_LEN_V2
            && plaintext_key_len == suite_key_len),
        r matches Ok(n) ==> n == suite_key_len && n == plaintext_key_len,
        (r matches Err(V2KeyLenError::IdentityKdf)) <==> identity_kdf,
        (r matches Err(V2KeyLenError::MessageIdLen)) <==> (!identity_kdf && message_id_len
            != MESSAGE_ID_LEN_V2),
        (r matches Err(V2KeyLenError::PlaintextKeyLen)) <==> (!identity_kdf && message_id_len
            == MESSAGE_ID_LEN_V2 && plaintext_key_len != suite_key_len),
{
    // For V2 algorithms the KDF can only be HKDF.
    if identity_kdf {
        return Err(V2KeyLenError::IdentityKdf);
    }
    if message_id_len != MESSAGE_ID_LEN_V2 {
        return Err(V2KeyLenError::MessageIdLen);
    }
    //= spec/framework/transitive-requirements.md#hkdf-encryption-key
    //# - The length of the input keying material MUST equal the key derivation input length
    //# specified by the algorithm suite's encryption key derivation settings.
    //
    //= spec/framework/transitive-requirements.md#hkdf-commit-key
    //# - The length of the input keying material MUST equal the key derivation input length
    //# specified by the algorithm suite's commit key derivation settings.
    if plaintext_key_len != suite_key_len {
        return Err(V2KeyLenError::PlaintextKeyLen);
    }
    Ok(suite_key_len)
}

} // verus!

// Holds the derived message encryption key and an optional commitment value (the
// latter only for committing algorithm suites). Both are opaque `secret` types:
// code outside `secret.rs` cannot read their bytes (VR-011).
pub(crate) struct DerivedKeys {
    pub(crate) data_key: MessageKey,
    pub(crate) commitment_key: Option<CommitmentValue>,
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
    plaintext_data_key: &DataKeyRef<'_>,
    suite: &AlgorithmSuite,
) -> Result<DerivedKeys, Error> {
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
            if !identity_kdf_key_len_ok(plaintext_data_key.len(), encrypt_key_len) {
                return Err(err(
                    Kind::InvalidMaterials,
                    format!(
                        "identity KDF plaintext data key length {} does not match the suite encryption key length {encrypt_key_len}",
                        plaintext_data_key.len()
                    ),
                ));
            }
            Ok(DerivedKeys {
                data_key: secret::identity_copy(plaintext_data_key),
                commitment_key: None,
            })
        }
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# - If the key derivation algorithm is [HKDF](../framework/algorithm-suites.md#hkdf),
        //# the derivation process used MUST be the process described in [HKDF Encryption Key](../framework/transitive-requirements.md#hkdf-encryption-key).
        //
        //= spec/framework/transitive-requirements.md#hkdf-encryption-key
        //# If an algorithm suite uses HKDF to derive the encryption key,
        //# the AWS Encryption SDK MUST use HKDF as follows.
        kdf => {
            //= spec/framework/transitive-requirements.md#hkdf-encryption-key
            //# - The hash function MUST be the hash function specified by the algorithm suite's encryption key derivation settings.
            let alg = kdf_digest(kdf)?;

            //= spec/framework/transitive-requirements.md#hkdf-encryption-key
            //# - If the algorithm suite's encryption key derivation settings specify a salt length of 0,
            //# the salt MUST be all 0x00 bytes, with a length equal to the hash function's output length in bytes.
            let salt = vec![0u8; digest_length(alg)?];

            //= spec/framework/transitive-requirements.md#hkdf-encryption-key
            //# - The length of the output keying material MUST equal the encryption key length
            //# specified by the algorithm suite's encryption settings.
            let output_len = suite.encryption_key_length();
            let mut derived_key = MessageKey::zeroed(output_len);

            //= spec/framework/transitive-requirements.md#hkdf-encryption-key
            //# - If the algorithm suite is not key committing,
            //# the info MUST be the algorithm suite ID followed by the message ID.
            let suite_id = suite.id();
            let info: [&[u8]; 2] = [&suite_id[..], message_id];

            //= spec/framework/transitive-requirements.md#hkdf-encryption-key
            //= type=implication
            //= reason=primitives::hkdf bundles HKDF-Extract and HKDF-Expand; the PRK input to expand is the extract output by construction of the helper
            //# - The pseudorandom key MUST be the output of the extract step.
            secret::hkdf_v1(alg, &salt, plaintext_data_key, &info, &mut derived_key)?;

            Ok(DerivedKeys {
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
//= spec/framework/transitive-requirements.md#hkdf-encryption-key
//# If an algorithm suite uses HKDF to derive the encryption key,
//# the AWS Encryption SDK MUST use HKDF as follows.
//
//= spec/framework/transitive-requirements.md#hkdf-commit-key
//# If an algorithm suite uses HKDF to derive the commit key,
//# the AWS Encryption SDK MUST use HKDF as follows.
pub(crate) fn derive_key_v2(
    message_id: &[u8],
    plaintext_data_key: &DataKeyRef<'_>,
    suite: &AlgorithmSuite,
) -> Result<DerivedKeys, Error> {
    // `derive_keys` dispatches on the message version, so a non-V2 suite here is an
    // internal bug rather than bad input.
    debug_assert_eq!(suite.message_format_version(), 2);

    // The HKDF key length is the suite's encryption key length; it is both the
    // input (plaintext data key) length and the output (derived key) length.
    // `check_v2_key_lengths` is the verified decision; this maps its rejections
    // to errors.
    let identity_kdf = matches!(suite.encryption_kdf(), KeyDerivationAlgorithm::IdentityKdf);
    let suite_key_len = suite.encryption_key_length();
    let kdf_key_len = match check_v2_key_lengths(
        identity_kdf,
        suite_key_len,
        message_id.len(),
        plaintext_data_key.len(),
    ) {
        Ok(n) => n,
        Err(V2KeyLenError::IdentityKdf) => {
            return Err(err(
                Kind::Internal,
                "algorithm suite KDF must be HKDF to derive a key length, got IdentityKdf",
            ));
        }
        Err(V2KeyLenError::MessageIdLen) => {
            return Err(err(
                Kind::Internal,
                format!(
                    "V2 message ID (HKDF salt) must be {MESSAGE_ID_LEN_V2} bytes, got {}",
                    message_id.len()
                ),
            ));
        }
        Err(V2KeyLenError::PlaintextKeyLen) => {
            return Err(err(
                Kind::InvalidMaterials,
                format!(
                    "plaintext data key length {} does not match KDF input key length {suite_key_len}",
                    plaintext_data_key.len()
                ),
            ));
        }
    };

    //= spec/framework/transitive-requirements.md#hkdf-encryption-key
    //= reason=V2 suites share the same HKDF hash for encryption and commit derivation; suite.commitment.hkdf.hmac is the HKDF hash configured by the suite
    //# - The hash function MUST be the hash function specified by the algorithm suite's encryption key derivation settings.
    //
    //= spec/framework/transitive-requirements.md#hkdf-commit-key
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
    //= spec/framework/transitive-requirements.md#hkdf-encryption-key
    //# - If the algorithm suite's encryption key derivation settings specify a nonzero salt length,
    //# the salt MUST be the [message ID](../data-format/message-header.md#message-id), with a length equal to that salt length.
    //
    //= spec/framework/transitive-requirements.md#hkdf-commit-key
    //# - The salt MUST be the [message ID](../data-format/message-header.md#message-id),
    //# with a length equal to the salt length specified by the algorithm suite's commit key derivation settings.
    //
    //= spec/framework/transitive-requirements.md#hkdf-commit-key
    //= type=implication
    //= reason=pseudo_random_key is bound once by hkdf_extract and reused for both hkdf_expand calls — extract-once is structural
    //# For algorithm suites that support commitment,
    //# the AWS Encryption SDK SHOULD only perform the extract step once
    //# and use the same output from the extract step
    //# for both the encryption key and the commitment key.
    let pseudo_random_key = secret::hkdf_v2_extract(alg, message_id, plaintext_data_key);

    //= spec/framework/transitive-requirements.md#hkdf-encryption-key
    //# - The length of the output keying material MUST equal the encryption key length
    //# specified by the algorithm suite's encryption settings.
    let mut encrypt_key = MessageKey::zeroed(kdf_key_len);

    //= spec/framework/transitive-requirements.md#hkdf-commit-key
    //# - The length of the output keying material MUST equal the key derivation output length
    //# specified by the algorithm suite's commit key derivation settings.
    let mut commit_key = CommitmentValue::zeroed(commit_len);

    //= spec/framework/transitive-requirements.md#hkdf-encryption-key
    //# - If the algorithm suite is key committing,
    //# the info MUST be the [algorithm suite ID](./algorithm-suites.md#algorithm-suite-id)
    //# followed by the string `DERIVEKEY` as UTF-8 encoded bytes.
    let suite_id = suite.id();
    let info = [&suite_id[..], KEY_LABEL.as_bytes()];

    //= spec/framework/transitive-requirements.md#hkdf-encryption-key
    //= type=implication
    //= reason=pseudo_random_key holds the hkdf_extract return value above and is the only PRK input threaded into hkdf_expand here by data dependency
    //# - The pseudorandom key MUST be the output of the extract step.
    secret::hkdf_v2_expand_key(&pseudo_random_key, &info, &mut encrypt_key)?;

    //= spec/framework/transitive-requirements.md#hkdf-commit-key
    //= type=implication
    //= reason=pseudo_random_key holds the hkdf_extract return value above and is the only PRK input threaded into hkdf_expand here by data dependency
    //# - The pseudorandom key MUST be the output of the extract step.
    //
    //= spec/framework/transitive-requirements.md#hkdf-commit-key
    //# - The info MUST be the string `COMMITKEY` as UTF-8 encoded bytes.
    secret::hkdf_v2_expand_commitment(
        &pseudo_random_key,
        &[COMMIT_LABEL.as_bytes()],
        &mut commit_key,
    )?;

    Ok(DerivedKeys {
        data_key: encrypt_key,
        commitment_key: Some(commit_key),
    })
}

// Derives key material for encryption/decryption. Delegates to the V1 or V2
// routine based on the algorithm suite's message version.
pub(crate) fn derive_keys(
    message_id: &[u8],
    plaintext_data_key: &DataKeyRef<'_>,
    suite: &AlgorithmSuite,
) -> Result<DerivedKeys, Error> {
    debug_assert_ne!(message_id.len(), 0);
    debug_assert_eq!(get_encrypt_key_length(suite), plaintext_data_key.len());

    // The version decision is the verified `msg_format_version_from_u8`
    // (exactly 1 => V1, exactly 2 => V2, anything else => None).
    match msg_format_version_from_u8(suite.message_format_version()) {
        Some(MessageFormatVersion::V1) => derive_key_v1(message_id, plaintext_data_key, suite),
        Some(MessageFormatVersion::V2) => derive_key_v2(message_id, plaintext_data_key, suite),
        None => Err(err(
            Kind::Internal,
            format!("unknown message version {}", suite.message_format_version()),
        )),
    }
}

/// Test-only API: key derivation over caller-supplied bytes, returning the
/// derived bytes so esdk's integration tests can assert on them. Built only with
/// the `test-internals` feature; it is a key accessor, so it is out of scope for
/// VR-011. Not public API; exempt from semantic versioning.
#[cfg(feature = "test-internals")]
pub(crate) mod test_api {
    use super::{AlgorithmSuite, DerivedKeys, Error, secret};
    use zeroize::Zeroizing;

    /// The derived data key and optional commitment key, as bytes.
    #[expect(
        clippy::exhaustive_structs,
        reason = "test-internal struct, not public API"
    )]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ExpandedKeyMaterial {
        /// The derived message encryption key.
        pub data_key: Zeroizing<Vec<u8>>,
        /// The V2 commitment key, if the suite commits.
        pub commitment_key: Option<Zeroizing<Vec<u8>>>,
    }

    fn expose(keys: &DerivedKeys) -> ExpandedKeyMaterial {
        ExpandedKeyMaterial {
            data_key: secret::expose_message_key_for_tests(&keys.data_key),
            commitment_key: keys
                .commitment_key
                .as_ref()
                .map(secret::expose_commitment_for_tests),
        }
    }

    /// `derive_keys` over a caller-supplied plaintext data key.
    ///
    /// # Errors
    ///
    /// As the crate-internal `derive_keys`.
    pub fn derive_keys(
        message_id: &[u8],
        plaintext_data_key: &[u8],
        suite: &AlgorithmSuite,
    ) -> Result<ExpandedKeyMaterial, Error> {
        let key = secret::data_key_from_slice_for_tests(plaintext_data_key);
        super::derive_keys(message_id, &key, suite).map(|k| expose(&k))
    }

    /// `derive_key_v2` over a caller-supplied plaintext data key.
    ///
    /// # Errors
    ///
    /// As the crate-internal `derive_key_v2`.
    pub fn derive_key_v2(
        message_id: &[u8],
        plaintext_data_key: &[u8],
        suite: &AlgorithmSuite,
    ) -> Result<ExpandedKeyMaterial, Error> {
        let key = secret::data_key_from_slice_for_tests(plaintext_data_key);
        super::derive_key_v2(message_id, &key, suite).map(|k| expose(&k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::header_types::MESSAGE_ID_LEN_V1;

    #[test]
    fn identity_kdf_key_len_ok_iff_equal() {
        assert!(identity_kdf_key_len_ok(32, 32));
        assert!(!identity_kdf_key_len_ok(31, 32));
        assert!(!identity_kdf_key_len_ok(33, 32));
        assert!(identity_kdf_key_len_ok(0, 0));
    }

    #[test]
    fn check_v2_key_lengths_cases() {
        assert_eq!(
            check_v2_key_lengths(false, 32, MESSAGE_ID_LEN_V2, 32),
            Ok(32)
        );
        // The identity KDF is rejected first, whatever the lengths.
        assert_eq!(
            check_v2_key_lengths(true, 32, MESSAGE_ID_LEN_V2, 32),
            Err(V2KeyLenError::IdentityKdf)
        );
        assert_eq!(
            check_v2_key_lengths(true, 32, 0, 0),
            Err(V2KeyLenError::IdentityKdf)
        );
        // Then the message ID length, before the key length.
        for mid in [
            0,
            MESSAGE_ID_LEN_V1,
            MESSAGE_ID_LEN_V2 - 1,
            MESSAGE_ID_LEN_V2 + 1,
        ] {
            assert_eq!(
                check_v2_key_lengths(false, 32, mid, 0),
                Err(V2KeyLenError::MessageIdLen)
            );
        }
        for pdk in [0, 16, 31, 33] {
            assert_eq!(
                check_v2_key_lengths(false, 32, MESSAGE_ID_LEN_V2, pdk),
                Err(V2KeyLenError::PlaintextKeyLen)
            );
        }
    }
}
