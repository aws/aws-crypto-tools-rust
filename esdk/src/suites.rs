// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Algorithm-suite helpers shared by the encrypt, decrypt, and message layers.
//!
//! The Material Providers Library (`aws_crypto_mpl`) exposes the ESDK suites as
//! [`EsdkAlgorithmSuiteId`](aws_crypto_mpl::structures::EsdkAlgorithmSuiteId),
//! which the ESDK re-exports as [`AlgorithmSuiteId`].
//! Materials carry the MPL's format-generic
//! [`AlgorithmSuiteId`](aws_crypto_mpl::structures::AlgorithmSuiteId) union instead.
//! Each suite's parameters come from an opaque
//! [`AlgorithmSuite`](aws_crypto_mpl::structures::AlgorithmSuite) specification.
//! This module wraps the MPL's `bytes -> id` lookup in the ESDK error type.
//! Its other helpers map MPL suite fields to the types the ESDK needs.

use crate::error::{Error, ErrorKind, err, val_err};
use crate::types::AlgorithmSuiteId;
use aws_crypto_mpl::structures::{
    AlgorithmSuite, AlgorithmSuiteId as MplAlgorithmSuiteId, AsymmetricSignatureAlgorithm,
    KeyDerivationAlgorithm,
};
use aws_mpl_primitives::{DigestAlg, EcdsaSignatureAlgorithm};

/// Resolve a 2-byte on-wire algorithm suite id to its [`AlgorithmSuiteId`].
///
/// # Errors
/// Returns an error if `bytes` is not a supported ESDK algorithm suite id.
pub fn algorithm_suite_id_from_bytes(bytes: [u8; 2]) -> Result<AlgorithmSuiteId, Error> {
    //= spec/data-format/message-header.md#algorithm-suite-id
    //# The value (hex) of this field MUST be a value that exists in the
    //# [Supported Algorithm Suites](../framework/algorithm-suites.md#supported-algorithm-suites) table.
    //
    //= spec/data-format/message-header.md#algorithm-suite-id
    //# This algorithm suite MUST be [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum).
    AlgorithmSuiteId::from_id_bytes(bytes).ok_or_else(|| {
        err(
            ErrorKind::Serialization,
            format!(
                "unrecognized or unsupported algorithm suite ID: 0x{:02X}{:02X}",
                bytes[0], bytes[1]
            ),
        )
    })
}

/// Extracts the ESDK algorithm suite id from a generic MPL algorithm suite id.
///
/// # Errors
/// Returns an error if `id` is not an ESDK algorithm suite.
pub fn get_esdk_algorithm_suite_id(id: MplAlgorithmSuiteId) -> Result<AlgorithmSuiteId, Error> {
    match id {
        MplAlgorithmSuiteId::Esdk(id) => Ok(id),
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# If this algorithm suite is not [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum)
        //# encrypt MUST yield an error.
        //
        //= spec/client-apis/decrypt.md#get-the-decryption-materials
        //# If this algorithm suite is not [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum)
        //# decrypt MUST yield an error.
        other => Err(err(
            ErrorKind::InvalidMaterials,
            format!("unsupported algorithm suite: {other:?}"),
        )),
    }
}

/// Resolve a 2-byte on-wire algorithm suite id to its [`AlgorithmSuite`] specification.
///
/// # Errors
/// Returns an error if `bytes` is not a supported ESDK algorithm suite id.
pub fn algorithm_suite_from_bytes(bytes: [u8; 2]) -> Result<AlgorithmSuite, Error> {
    Ok(algorithm_suite_id_from_bytes(bytes)?.specification())
}

/// Maps an MPL [`KeyDerivationAlgorithm`] to the primitives [`DigestAlg`] that
/// drives its HKDF, or an error if the KDF is the identity KDF (no hash).
///
/// # Errors
/// Returns an error if `kdf` is the identity KDF or a KDF the ESDK does not support.
pub(crate) fn kdf_digest(kdf: KeyDerivationAlgorithm) -> Result<DigestAlg, Error> {
    match kdf {
        KeyDerivationAlgorithm::HkdfSha256 => Ok(DigestAlg::Sha256),
        KeyDerivationAlgorithm::HkdfSha384 => Ok(DigestAlg::Sha384),
        KeyDerivationAlgorithm::HkdfSha512 => Ok(DigestAlg::Sha512),
        KeyDerivationAlgorithm::IdentityKdf => Err(val_err("identity KDF has no hash function")),
        other => Err(val_err(format!(
            "unsupported key derivation algorithm: {other:?}"
        ))),
    }
}

/// Extracts the ECDSA signature algorithm for a signing suite, mapping the MPL
/// [`AsymmetricSignatureAlgorithm`] to the primitives [`EcdsaSignatureAlgorithm`].
///
/// # Errors
/// Returns an error if the suite has no asymmetric signature algorithm the ESDK supports.
pub fn get_ecdsa_alg(suite: &AlgorithmSuite) -> Result<EcdsaSignatureAlgorithm, Error> {
    match suite.asymmetric_signature_algorithm() {
        Some(AsymmetricSignatureAlgorithm::EcdsaP256) => Ok(EcdsaSignatureAlgorithm::EcdsaP256),
        Some(AsymmetricSignatureAlgorithm::EcdsaP384) => Ok(EcdsaSignatureAlgorithm::EcdsaP384),
        None => Err(val_err("algorithm suite has no ECDSA signature algorithm")),
        Some(other) => Err(val_err(format!(
            "unsupported asymmetric signature algorithm: {other:?}"
        ))),
    }
}
