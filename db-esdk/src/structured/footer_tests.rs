// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::types::{
    AlgorithmSuiteId as MplAlgorithmSuiteId, EncryptedDataKey, EsdkAlgorithmSuiteId,
    SymmetricSigningKey,
};
use aws_mpl_primitives::{SignatureKeyPair, ecdsa_generate_keypair};

use super::*;
use crate::error::Kind;
use crate::structured::util::{NUMBER, STRING};
use crate::types::AlgorithmSuiteId;

const SYMSIG: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384;
const ECDSA: AlgorithmSuiteId =
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384;
const HEADER: &[u8] = b"HEADER";
const SYM_KEY: [u8; 48] = [5u8; 48];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn item(canon: &[u8], type_id: [u8; 2], value: &[u8], action: CryptoAction) -> CanonItem {
    CanonItem {
        canon: canon.to_vec(),
        key: vec![String::from_utf8(canon.to_vec()).unwrap()],
        data: Terminal::new(type_id, value.to_vec()),
        action,
    }
}

// An encrypted field (its value starts with the plaintext type id), a plaintext signed
// field, and an unsigned field.
fn fields() -> Vec<CanonItem> {
    vec![
        item(
            b"A",
            BYTES_TYPE_ID,
            &[0x00, 0x01, 0xAA, 0xBB],
            CryptoAction::EncryptAndSign,
        ),
        item(b"B", NUMBER, b"42", CryptoAction::SignOnly),
        item(b"C", STRING, b"ignored", CryptoAction::DoNothing),
    ]
}

fn ec() -> EncryptionContext {
    [("k", "v")].into()
}

fn edk(n: u8) -> EncryptedDataKey {
    EncryptedDataKey::builder()
        .key_provider_id("p")
        .key_provider_info(vec![n])
        .ciphertext(vec![n])
        .build()
        .unwrap()
}

fn suite(id: AlgorithmSuiteId) -> DbeSuite {
    DbeSuite::new(MplAlgorithmSuiteId::Dbe(id)).unwrap()
}

fn enc_materials(
    id: AlgorithmSuiteId,
    sym_keys: &[[u8; 48]],
    signing_key: Option<Vec<u8>>,
) -> EncryptionMaterials {
    EncryptionMaterials::builder()
        .algorithm_suite_id(MplAlgorithmSuiteId::Dbe(id))
        .encryption_context(ec())
        .plaintext_data_key(vec![7u8; 32])
        .encrypted_data_keys(
            (0..sym_keys.len())
                .map(|i| edk(u8::try_from(i).unwrap()))
                .collect::<Vec<_>>(),
        )
        .symmetric_signing_keys(
            sym_keys
                .iter()
                .map(|k| SymmetricSigningKey::from(k.to_vec()))
                .collect::<Vec<_>>(),
        )
        .set_signing_key(signing_key.map(Into::into))
        .build()
        .unwrap()
}

fn dec_materials(
    id: AlgorithmSuiteId,
    sym_key: &[u8],
    verification_key: Option<Vec<u8>>,
) -> DecryptionMaterials {
    DecryptionMaterials::builder()
        .algorithm_suite_id(MplAlgorithmSuiteId::Dbe(id))
        .encryption_context(ec())
        .plaintext_data_key(vec![7u8; 32])
        .symmetric_signing_key(sym_key.to_vec())
        .set_verification_key(verification_key.map(Into::into))
        .build()
        .unwrap()
}

fn keypair() -> SignatureKeyPair {
    ecdsa_generate_keypair(EcdsaSignatureAlgorithm::EcdsaP384).unwrap()
}

// SHA-384 of HEADER || u64(8) || serialize({"k": "v"}) || canonical A || canonical B,
// and HMAC-SHA-384 of that hash under SYM_KEY, computed independently with Python's hashlib.
const CANON_HASH: &str = "6bbc5fedf86f0e566b8e19342671b09e95e0e213d1dd49d83e1937fe246fe6f1c64eb1f7a41f332c984fd4cca70d2398";
const TAG: &str = "6b04e5a8c6da421226f60fadd1d721e7c09f421802c432a4b3947175dbd7c5a8ddecc01195e2b9f9f4ca4e7283890bd9";

#[test]
fn canonical_encrypted_field_layout() {
    let got = canonical_field(&fields()[0]).unwrap();
    let mut expected = b"A".to_vec();
    expected.extend_from_slice(&2u64.to_be_bytes());
    expected.extend_from_slice(b"ENCRYPTED");
    expected.extend_from_slice(&[0x00, 0x01, 0xAA, 0xBB]);
    assert_eq!(got, expected);
}

#[test]
fn canonical_plaintext_field_layout() {
    let got = canonical_field(&fields()[1]).unwrap();
    let mut expected = b"B".to_vec();
    expected.extend_from_slice(&2u64.to_be_bytes());
    expected.extend_from_slice(b"PLAINTEXT");
    expected.extend_from_slice(&NUMBER);
    expected.extend_from_slice(b"42");
    assert_eq!(got, expected);
}

#[test]
fn canonical_encrypted_field_needs_type_id() {
    let short = item(b"A", BYTES_TYPE_ID, &[0x00], CryptoAction::EncryptAndSign);
    let err = canonical_field(&short).unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization);
}

#[test]
fn canon_hash_known_answer_skips_unsigned_fields() {
    let hash = canon_hash(&fields(), HEADER, &ec()).unwrap();
    assert_eq!(hash.as_slice(), unhex(CANON_HASH).as_slice());
    let signed_only: Vec<_> = fields().into_iter().take(2).collect();
    assert_eq!(canon_hash(&signed_only, HEADER, &ec()).unwrap(), hash);
}

#[test]
fn create_writes_one_tag_per_key_in_key_order() {
    let other = [6u8; 48];
    let mat = enc_materials(SYMSIG, &[SYM_KEY, other], None);
    let footer = Footer::create(suite(SYMSIG), &mat, &fields(), HEADER).unwrap();
    let hash = unhex(CANON_HASH);
    let mut other_tag = vec![0u8; RECIPIENT_TAG_SIZE];
    hmac(DigestAlg::Sha384, &other, &hash, &mut other_tag).unwrap();

    let term = footer.into_terminal();
    assert_eq!(term.type_id, BYTES_TYPE_ID);
    let mut expected = unhex(TAG);
    expected.extend_from_slice(&other_tag);
    assert_eq!(term.value, expected);
}

#[test]
fn unsigned_round_trip_and_tamper() {
    let mat = enc_materials(SYMSIG, &[SYM_KEY], None);
    let stored = Footer::create(suite(SYMSIG), &mat, &fields(), HEADER)
        .unwrap()
        .into_terminal();
    assert_eq!(stored.value.len(), RECIPIENT_TAG_SIZE);
    let footer = Footer::deserialize(&stored.value, false).unwrap();
    let dec = dec_materials(SYMSIG, &SYM_KEY, None);
    footer.validate(&dec, 1, &fields(), HEADER).unwrap();

    // A changed signed field, a changed header, or another recipient's key fails.
    let mut changed = fields();
    changed[1].data.value = b"43".to_vec();
    let err = footer.validate(&dec, 1, &changed, HEADER).unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
    let err = footer.validate(&dec, 1, &fields(), b"HEADEr").unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
    let wrong = dec_materials(SYMSIG, &[6u8; 48], None);
    let err = footer.validate(&wrong, 1, &fields(), HEADER).unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);

    // An unsigned field may change.
    let mut unsigned_changed = fields();
    unsigned_changed[2].data.value = b"other".to_vec();
    footer.validate(&dec, 1, &unsigned_changed, HEADER).unwrap();
}

// Any one matching tag is enough: the second recipient's key verifies.
#[test]
fn validate_accepts_any_matching_tag() {
    let other = [6u8; 48];
    let mat = enc_materials(SYMSIG, &[SYM_KEY, other], None);
    let stored = Footer::create(suite(SYMSIG), &mat, &fields(), HEADER)
        .unwrap()
        .into_terminal();
    let footer = Footer::deserialize(&stored.value, false).unwrap();
    let dec = dec_materials(SYMSIG, &other, None);
    footer.validate(&dec, 2, &fields(), HEADER).unwrap();
}

#[test]
fn validate_rejects_tag_count_mismatch() {
    let mat = enc_materials(SYMSIG, &[SYM_KEY], None);
    let stored = Footer::create(suite(SYMSIG), &mat, &fields(), HEADER)
        .unwrap()
        .into_terminal();
    let footer = Footer::deserialize(&stored.value, false).unwrap();
    let dec = dec_materials(SYMSIG, &SYM_KEY, None);
    let err = footer.validate(&dec, 2, &fields(), HEADER).unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization);
}

#[test]
fn validate_needs_symmetric_signing_key() {
    let mat = enc_materials(SYMSIG, &[SYM_KEY], None);
    let stored = Footer::create(suite(SYMSIG), &mat, &fields(), HEADER)
        .unwrap()
        .into_terminal();
    let footer = Footer::deserialize(&stored.value, false).unwrap();
    // Materials without a data key yet carry no symmetric signing key either.
    let dec = DecryptionMaterials::builder()
        .algorithm_suite_id(MplAlgorithmSuiteId::Dbe(SYMSIG))
        .encryption_context(ec())
        .build()
        .unwrap();
    let err = footer.validate(&dec, 1, &fields(), HEADER).unwrap_err();
    assert_eq!(err.kind(), Kind::InvalidMaterials);
}

#[test]
fn signed_round_trip_and_tamper() {
    let kp = keypair();
    let mat = enc_materials(ECDSA, &[SYM_KEY], Some(kp.signing_key.clone()));
    let stored = Footer::create(suite(ECDSA), &mat, &fields(), HEADER)
        .unwrap()
        .into_terminal();
    assert_eq!(stored.value.len(), RECIPIENT_TAG_SIZE + SIGNATURE_SIZE);
    assert_eq!(&stored.value[..RECIPIENT_TAG_SIZE], unhex(TAG).as_slice());

    let footer = Footer::deserialize(&stored.value, true).unwrap();
    let dec = dec_materials(ECDSA, &SYM_KEY, Some(kp.verification_key.clone()));
    footer.validate(&dec, 1, &fields(), HEADER).unwrap();

    // Another signer's verification key fails.
    let other_dec = dec_materials(ECDSA, &SYM_KEY, Some(keypair().verification_key));
    let err = footer
        .validate(&other_dec, 1, &fields(), HEADER)
        .unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);

    // So does a footer whose tag is still good but whose signature (inside r) was altered.
    let mut bad = stored.value.clone();
    bad[RECIPIENT_TAG_SIZE + 10] ^= 1;
    let bad = Footer::deserialize(&bad, true).unwrap();
    let err = bad.validate(&dec, 1, &fields(), HEADER).unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
    assert_eq!(err.message(), "Signature did not verify");
}

#[test]
fn signed_validate_needs_verification_key() {
    let kp = keypair();
    let mat = enc_materials(ECDSA, &[SYM_KEY], Some(kp.signing_key));
    let stored = Footer::create(suite(ECDSA), &mat, &fields(), HEADER)
        .unwrap()
        .into_terminal();
    let footer = Footer::deserialize(&stored.value, true).unwrap();
    let dec = dec_materials(ECDSA, &SYM_KEY, None);
    let err = footer.validate(&dec, 1, &fields(), HEADER).unwrap_err();
    assert_eq!(err.kind(), Kind::InvalidMaterials);
}

// The signature's presence must agree with the suite of the decryption materials.
#[test]
fn validate_rejects_signature_presence_mismatch() {
    let mat = enc_materials(SYMSIG, &[SYM_KEY], None);
    let stored = Footer::create(suite(SYMSIG), &mat, &fields(), HEADER)
        .unwrap()
        .into_terminal();
    let unsigned = Footer::deserialize(&stored.value, false).unwrap();
    let ecdsa_dec = dec_materials(ECDSA, &SYM_KEY, Some(keypair().verification_key));
    let err = unsigned
        .validate(&ecdsa_dec, 1, &fields(), HEADER)
        .unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);

    let kp = keypair();
    let mat = enc_materials(ECDSA, &[SYM_KEY], Some(kp.signing_key));
    let stored = Footer::create(suite(ECDSA), &mat, &fields(), HEADER)
        .unwrap()
        .into_terminal();
    let signed = Footer::deserialize(&stored.value, true).unwrap();
    let symsig_dec = dec_materials(SYMSIG, &SYM_KEY, None);
    let err = signed
        .validate(&symsig_dec, 1, &fields(), HEADER)
        .unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
}

#[test]
fn create_needs_signing_key_for_ecdsa_suite() {
    let mat = enc_materials(ECDSA, &[SYM_KEY], None);
    let err = Footer::create(suite(ECDSA), &mat, &fields(), HEADER).unwrap_err();
    assert_eq!(err.kind(), Kind::InvalidMaterials);
}

#[test]
fn create_needs_symmetric_signing_keys() {
    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(MplAlgorithmSuiteId::Esdk(
            EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        ))
        .plaintext_data_key(vec![7u8; 32])
        .encrypted_data_keys(vec![edk(0)])
        .build()
        .unwrap();
    let err = Footer::create(suite(SYMSIG), &mat, &fields(), HEADER).unwrap_err();
    assert_eq!(err.kind(), Kind::InvalidMaterials);
}

#[test]
fn deserialize_unsigned_sizes() {
    assert_eq!(
        Footer::deserialize(&[0u8; 2 * RECIPIENT_TAG_SIZE], false)
            .unwrap()
            .tags
            .len(),
        2
    );
    for len in [0, 1, RECIPIENT_TAG_SIZE - 1, RECIPIENT_TAG_SIZE + 1] {
        let err = Footer::deserialize(&vec![0u8; len], false).unwrap_err();
        assert_eq!(err.kind(), Kind::Serialization, "len {len}");
    }
}

#[test]
fn deserialize_signed_sizes() {
    let footer =
        Footer::deserialize(&[0u8; 2 * RECIPIENT_TAG_SIZE + SIGNATURE_SIZE], true).unwrap();
    assert_eq!(footer.tags.len(), 2);
    assert_eq!(footer.sig.as_deref().map(<[u8]>::len), Some(SIGNATURE_SIZE));
    for len in [
        0,
        SIGNATURE_SIZE,
        RECIPIENT_TAG_SIZE + SIGNATURE_SIZE - 1,
        RECIPIENT_TAG_SIZE + SIGNATURE_SIZE + 1,
    ] {
        let err = Footer::deserialize(&vec![0u8; len], true).unwrap_err();
        assert_eq!(err.kind(), Kind::Serialization, "len {len}");
    }
}
