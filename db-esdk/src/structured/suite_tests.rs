// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::types::EsdkAlgorithmSuiteId;

use super::*;
use crate::error::Kind;

#[test]
fn symsig_only_suite() {
    let suite = DbeSuite::new(MplAlgorithmSuiteId::Dbe(
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384,
    ))
    .unwrap();
    assert_eq!(
        suite.id,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384
    );
    assert_eq!(suite.kdf, DigestAlg::Sha512);
    assert_eq!(suite.commit, DigestAlg::Sha512);
    assert_eq!(suite.signature, Signature::None);
}

#[test]
fn ecdsa_suite() {
    let suite = DbeSuite::new(MplAlgorithmSuiteId::Dbe(
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384,
    ))
    .unwrap();
    assert_eq!(
        suite.id,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384
    );
    assert_eq!(suite.kdf, DigestAlg::Sha512);
    assert_eq!(suite.commit, DigestAlg::Sha512);
    assert_eq!(suite.signature, Signature::EcdsaP384);
}

#[test]
fn esdk_suite_is_rejected() {
    let err = DbeSuite::new(MplAlgorithmSuiteId::Esdk(
        EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
    ))
    .unwrap_err();
    assert_eq!(err.kind(), Kind::Validation);
}

// Header flavor byte 0x00 / 0x01 selects the DBE suite 0x67 0x00 / 0x67 0x01.
#[test]
fn from_flavor_maps_wire_ids() {
    assert_eq!(
        DbeSuite::from_flavor(0).unwrap().id,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384
    );
    assert_eq!(
        DbeSuite::from_flavor(1).unwrap().id,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384
    );
    assert_eq!(
        DbeSuite::from_flavor(2).unwrap_err().kind(),
        Kind::Validation
    );
}

#[test]
fn digest_of_maps_hkdf_hashes() {
    assert_eq!(
        digest_of(KeyDerivationAlgorithm::HkdfSha256).unwrap(),
        DigestAlg::Sha256
    );
    assert_eq!(
        digest_of(KeyDerivationAlgorithm::HkdfSha384).unwrap(),
        DigestAlg::Sha384
    );
    assert_eq!(
        digest_of(KeyDerivationAlgorithm::HkdfSha512).unwrap(),
        DigestAlg::Sha512
    );
    assert_eq!(
        digest_of(KeyDerivationAlgorithm::IdentityKdf)
            .unwrap_err()
            .kind(),
        Kind::Validation
    );
}
