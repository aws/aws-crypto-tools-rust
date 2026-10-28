// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The parameters of a DBE algorithm suite that structured encryption uses.

use aws_crypto_mpl::types::{
    AlgorithmSuiteId as MplAlgorithmSuiteId, AsymmetricSignatureAlgorithm, KeyDerivationAlgorithm,
};
use aws_mpl_primitives::DigestAlg;

use super::header::DBE_ALGORITHM_FAMILY;
use crate::error::{Error, val_err};
use crate::types::AlgorithmSuiteId;

/// The asymmetric signature of a DBE suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Signature {
    None,
    EcdsaP384,
}

/// A DBE algorithm suite, resolved for structured encryption.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DbeSuite {
    pub(crate) id: AlgorithmSuiteId,
    /// The HKDF hash that derives the field root key.
    pub(crate) kdf: DigestAlg,
    /// The HKDF hash that derives the commitment key, and the HMAC hash of the commitment.
    pub(crate) commit: DigestAlg,
    pub(crate) signature: Signature,
}

fn digest_of(kdf: KeyDerivationAlgorithm) -> Result<DigestAlg, Error> {
    match kdf {
        KeyDerivationAlgorithm::HkdfSha256 => Ok(DigestAlg::Sha256),
        KeyDerivationAlgorithm::HkdfSha384 => Ok(DigestAlg::Sha384),
        KeyDerivationAlgorithm::HkdfSha512 => Ok(DigestAlg::Sha512),
        _ => Err(val_err(
            "the algorithm suite is not a DB-ESDK algorithm suite",
        )),
    }
}

impl DbeSuite {
    /// Resolve `id`, which must be a DBE suite.
    pub(crate) fn new(id: MplAlgorithmSuiteId) -> Result<Self, Error> {
        let MplAlgorithmSuiteId::Dbe(dbe) = id else {
            return Err(val_err(
                "the algorithm suite is not a DB-ESDK algorithm suite",
            ));
        };
        let spec = id.specification();
        if spec.id()[0] != DBE_ALGORITHM_FAMILY || spec.encryption_key_length() != 32 {
            return Err(val_err(
                "the algorithm suite is not a DB-ESDK algorithm suite",
            ));
        }
        let commit = spec
            .commit_kdf()
            .ok_or_else(|| val_err("the algorithm suite is not a DB-ESDK algorithm suite"))?;
        let signature = match spec.asymmetric_signature_algorithm() {
            None => Signature::None,
            Some(AsymmetricSignatureAlgorithm::EcdsaP384) => Signature::EcdsaP384,
            Some(_) => {
                return Err(val_err(
                    "the algorithm suite is not a DB-ESDK algorithm suite",
                ));
            }
        };
        if spec.symmetric_signature_algorithm().is_none() {
            return Err(val_err(
                "the algorithm suite is not a DB-ESDK algorithm suite",
            ));
        }
        Ok(Self {
            id: dbe,
            kdf: digest_of(spec.encryption_kdf())?,
            commit: digest_of(commit)?,
            signature,
        })
    }

    /// The suite with on-wire id `[0x67, flavor]`.
    pub(crate) fn from_flavor(flavor: u8) -> Result<Self, Error> {
        let id = MplAlgorithmSuiteId::from_id_bytes([DBE_ALGORITHM_FAMILY, flavor])
            .ok_or_else(|| val_err("the algorithm suite is not a DB-ESDK algorithm suite"))?;
        Self::new(id)
    }
}

#[cfg(test)]
#[path = "suite_tests.rs"]
mod tests;
