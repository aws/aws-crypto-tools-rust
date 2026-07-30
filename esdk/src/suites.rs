// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Algorithm-suite narrowing helpers shared by the encrypt and decrypt operations.

use crate::error::{Error, esdk_err, val_err};
use aws_mpl_legacy::primitives::EcdsaSignatureAlgorithm;

/// Extracts the ESDK algorithm suite id from a generic MPL algorithm suite id,
/// returning an error if the suite is not an ESDK suite.
///
/// # Errors
///
/// Returns an error if `id` is not an ESDK algorithm suite.
pub fn get_esdk_algorithm_suite_id(
    id: aws_mpl_legacy::suites::AlgorithmSuiteId,
) -> Result<aws_mpl_legacy::suites::EsdkAlgorithmSuiteId, Error> {
    match id {
        aws_mpl_legacy::suites::AlgorithmSuiteId::Esdk(x) => Ok(x),
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# If this algorithm suite is not [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum)
        //# encrypt MUST yield an error.
        //
        //= spec/client-apis/decrypt.md#get-the-decryption-materials
        //# If this algorithm suite is not [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum)
        //# decrypt MUST yield an error.
        //
        //= spec/client-apis/decrypt.md#algorithm-suite
        //# This algorithm suite MUST be [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum).
        other => Err(esdk_err(format!("Unsupported algorithm suite: {other:?}"))),
    }
}

/// Extracts the ECDSA signature algorithm from a generic MPL signature
/// algorithm, returning an error if the algorithm is not ECDSA.
///
/// # Errors
///
/// Returns an error if `alg` is not an ECDSA signature algorithm.
pub fn get_ecdsa_alg(
    alg: aws_mpl_legacy::suites::SignatureAlgorithm,
) -> Result<EcdsaSignatureAlgorithm, Error> {
    match alg {
        aws_mpl_legacy::suites::SignatureAlgorithm::Ecdsa(x) => Ok(x),
        other => Err(val_err(format!(
            "Unsupported signature algorithm: {other:?}"
        ))),
    }
}
