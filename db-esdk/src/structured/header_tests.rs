// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::types::{
    AlgorithmSuiteId as MplAlgorithmSuiteId, EsdkAlgorithmSuiteId, SymmetricSigningKey,
};

use super::*;
use crate::error::Kind;
use crate::structured::util::{CryptoField, Terminal};
use crate::types::AlgorithmSuiteId;

const MSG_ID: [u8; MSGID_LEN] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];
const ECDSA_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384;

fn edk(provider_id: &str, info: &[u8], ciphertext: &[u8]) -> EncryptedDataKey {
    EncryptedDataKey::builder()
        .key_provider_id(provider_id)
        .key_provider_info(info.to_vec())
        .ciphertext(ciphertext.to_vec())
        .build()
        .unwrap()
}

fn context(pairs: &[(&str, &str)]) -> EncryptionContext {
    pairs.iter().copied().collect()
}

// Header.dfy TestRoundTrip's header.
fn reference_header() -> PartialHeader {
    PartialHeader {
        version: 1,
        flavor: 1,
        msg_id: MSG_ID,
        legend: vec![0x65, 0x73],
        enc_context: context(&[("abc", "def")]),
        data_keys: vec![edk("provID", &[1, 2, 3, 4, 5], &[6, 7, 8, 9])],
    }
}

fn reference_header_bytes() -> Vec<u8> {
    let mut out = vec![1, 1];
    out.extend_from_slice(&MSG_ID);
    out.extend_from_slice(&[0, 2, 0x65, 0x73]);
    out.extend_from_slice(&[0, 1, 0, 3, b'a', b'b', b'c', 0, 3, b'd', b'e', b'f']);
    out.extend_from_slice(&[1, 0, 6]);
    out.extend_from_slice(b"provID");
    out.extend_from_slice(&[0, 5, 1, 2, 3, 4, 5, 0, 4, 6, 7, 8, 9]);
    out
}

fn assert_same_header(a: &PartialHeader, b: &PartialHeader) {
    assert_eq!(a.version, b.version);
    assert_eq!(a.flavor, b.flavor);
    assert_eq!(a.msg_id, b.msg_id);
    assert_eq!(a.legend, b.legend);
    assert_eq!(a.enc_context, b.enc_context);
    assert_eq!(a.data_keys, b.data_keys);
}

fn ser_message(data: &[u8]) -> String {
    let err = PartialHeader::deserialize(data).unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization, "{err}");
    err.message().to_owned()
}

#[test]
fn serialize_matches_spec_layout() {
    assert_eq!(reference_header().serialize(), reference_header_bytes());
}

// Header.dfy TestRoundTrip: the message id stands in for the commitment.
#[test]
fn round_trip() {
    let head = reference_header();
    let mut ser = head.serialize();
    ser.extend_from_slice(&head.msg_id);
    assert_same_header(&PartialHeader::deserialize(&ser).unwrap(), &head);
}

// Header.dfy TestRoundTripWithCommit.
#[test]
fn round_trip_with_commitment_and_tamper() {
    let head = reference_header();
    let key = head.msg_id;
    let ser = head
        .serialize_with_commitment(DigestAlg::Sha512, &key)
        .unwrap();
    assert_same_header(&PartialHeader::deserialize(&ser).unwrap(), &head);
    PartialHeader::verify_commitment(DigestAlg::Sha512, &key, &ser).unwrap();

    // The commitment is the first 32 bytes of the HMAC of the header under the commit key.
    let body = head.serialize();
    let mut full = [0u8; 64];
    hmac(DigestAlg::Sha512, &key, &body, &mut full).unwrap();
    assert_eq!(&ser[..body.len()], body.as_slice());
    assert_eq!(&ser[body.len()..], &full[..COMMITMENT_LEN]);

    let mut bad = ser.clone();
    let last = bad.len() - 1;
    bad[last] = if bad[last] == 0 { 255 } else { bad[last] - 1 };
    assert_same_header(&PartialHeader::deserialize(&bad).unwrap(), &head);
    let err = PartialHeader::verify_commitment(DigestAlg::Sha512, &key, &bad).unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
    assert_eq!(err.message(), "Key commitment mismatch.");

    let err = PartialHeader::verify_commitment(DigestAlg::Sha512, &[0u8; 32], &ser).unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
}

#[test]
fn verify_commitment_rejects_data_no_longer_than_commitment() {
    let err =
        PartialHeader::verify_commitment(DigestAlg::Sha512, &[0u8; 32], &[0u8; COMMITMENT_LEN])
            .unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization);
}

// Header.dfy TestDuplicateContext.
#[test]
fn context_serialization_and_duplicate_key() {
    let ec = context(&[("abc", "def"), ("cba", "fed")]);
    let ser = serialize_context(&ec);
    let expected = [
        0, 2, 0, 3, b'a', b'b', b'c', 0, 3, b'd', b'e', b'f', 0, 3, b'c', b'b', b'a', 0, 3, b'f',
        b'e', b'd',
    ];
    assert_eq!(ser, expected);
    let (parsed, len) = get_context(&ser).unwrap();
    assert_eq!(parsed, ec);
    assert_eq!(len, ser.len());

    let bad = [
        0, 3, 0, 3, b'a', b'b', b'c', 0, 3, b'd', b'e', b'f', 0, 3, b'c', b'b', b'a', 0, 3, b'f',
        b'e', b'd', 0, 3, b'a', b'b', b'c', 0, 3, b'e', b'd', b'f',
    ];
    let err = get_context(&bad).unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization);
    assert_eq!(err.message(), "Context keys out of order.");
}

// Header.dfy TestOutOfOrderContext.
#[test]
fn context_out_of_order() {
    let bad = [
        0, 2, 0, 3, b'c', b'b', b'a', 0, 3, b'f', b'e', b'd', 0, 3, b'a', b'b', b'c', 0, 3, b'd',
        b'e', b'f',
    ];
    let err = get_context(&bad).unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization);
    assert_eq!(err.message(), "Context keys out of order.");
}

// The reference starts the order check from an empty previous key and requires strictly
// ascending keys, so an empty key is rejected; an empty value is fine.
#[test]
fn context_empty_key_rejected_empty_value_accepted() {
    let ok = [0, 1, 0, 1, b'a', 0, 0];
    let (parsed, len) = get_context(&ok).unwrap();
    assert_eq!(parsed, context(&[("a", "")]));
    assert_eq!(len, ok.len());

    let empty_key = [0, 1, 0, 0, 0, 1, b'x'];
    assert_eq!(
        get_context(&empty_key).unwrap_err().message(),
        "Context keys out of order."
    );
}

#[test]
fn context_truncations_and_bad_utf8() {
    for bad in [
        &[0u8][..],
        &[0, 1][..],
        &[0, 1, 0][..],
        &[0, 1, 0, 3, b'a', b'b'][..],
        &[0, 1, 0, 1, b'a', 0, 2, b'x'][..],
    ] {
        let err = get_context(bad).unwrap_err();
        assert_eq!(err.kind(), Kind::Serialization);
        assert_eq!(err.message(), "Unexpected end of header data.", "{bad:?}");
    }
    assert_eq!(
        get_context(&[0, 1, 0, 1, 0xFF, 0, 0])
            .unwrap_err()
            .message(),
        "Invalid UTF8 found in header."
    );
    assert_eq!(
        get_context(&[0, 1, 0, 1, b'a', 0, 1, 0xFF])
            .unwrap_err()
            .message(),
        "Invalid UTF8 found in header."
    );
}

fn crypto(name: &str, action: CryptoAction) -> CryptoField {
    CryptoField {
        key: vec![name.to_owned()],
        data: Terminal::new([1, 2], Vec::new()),
        action,
    }
}

fn legend_of(fields: Vec<CryptoField>) -> Vec<u8> {
    make_legend(&crate::structured::for_encrypt("name", fields)).unwrap()
}

const E: u8 = ENCRYPT_AND_SIGN_LEGEND;
const S: u8 = SIGN_ONLY_LEGEND;

// Header.dfy TestSchemaOrderAlpha.
#[test]
fn legend_order_alpha() {
    let legend = legend_of(vec![
        crypto("abc", CryptoAction::EncryptAndSign),
        crypto("def", CryptoAction::SignOnly),
        crypto("ghi", CryptoAction::DoNothing),
        crypto("jkl", CryptoAction::EncryptAndSign),
        crypto("mno", CryptoAction::SignOnly),
        crypto("pqr", CryptoAction::DoNothing),
    ]);
    assert_eq!(legend, [E, S, E, S]);
}

// Header.dfy TestSchemaOrderLength: the canonical path has the length before the name,
// so shorter names sort first.
#[test]
fn legend_order_length() {
    let legend = legend_of(vec![
        crypto("aa", CryptoAction::EncryptAndSign),
        crypto("zz", CryptoAction::SignOnly),
        crypto("aaa", CryptoAction::DoNothing),
        crypto("zzz", CryptoAction::EncryptAndSign),
        crypto("aaaa", CryptoAction::SignOnly),
        crypto("zzzz", CryptoAction::DoNothing),
    ]);
    assert_eq!(legend, [E, S, E, S]);
}

// Header.dfy TestSchemaOrderLength2.
#[test]
fn legend_order_length_shuffled() {
    let legend = legend_of(vec![
        crypto("aa", CryptoAction::EncryptAndSign),
        crypto("zzz", CryptoAction::EncryptAndSign),
        crypto("zzzz", CryptoAction::DoNothing),
        crypto("aaa", CryptoAction::DoNothing),
        crypto("zz", CryptoAction::SignOnly),
        crypto("aaaa", CryptoAction::SignOnly),
    ]);
    assert_eq!(legend, [E, S, E, S]);
}

#[test]
fn legend_and_version_for_sign_and_include() {
    let fields = vec![
        crypto("a", CryptoAction::SignAndIncludeInEncryptionContext),
        crypto("b", CryptoAction::EncryptAndSign),
    ];
    let schema = crate::structured::for_encrypt("name", fields);
    assert_eq!(make_legend(&schema).unwrap(), [0x63, E]);
    assert_eq!(version_from_schema(&schema), 2);

    let schema = crate::structured::for_encrypt(
        "name",
        vec![
            crypto("a", CryptoAction::SignOnly),
            crypto("b", CryptoAction::EncryptAndSign),
        ],
    );
    assert_eq!(version_from_schema(&schema), 1);
}

#[test]
fn legend_too_long() {
    let schema: Vec<CanonItem> = (0..UINT16_LIMIT - 1)
        .map(|_| CanonItem {
            canon: Vec::new(),
            key: Vec::new(),
            data: Terminal::new([0, 0], Vec::new()),
            action: CryptoAction::SignOnly,
        })
        .collect();
    let err = make_legend(&schema).unwrap_err();
    assert_eq!(err.kind(), Kind::Validation);
    assert_eq!(make_legend(&schema[1..]).unwrap().len(), UINT16_LIMIT - 2);
}

#[test]
fn deserialize_rejects_bad_prefix() {
    let good = {
        let mut v = reference_header_bytes();
        v.extend_from_slice(&[0u8; COMMITMENT_LEN]);
        v
    };
    assert_eq!(
        ser_message(&good[..PREFIX_LEN - 1]),
        "Serialized PartialHeader too short."
    );
    for version in [0u8, 3] {
        let mut bad = good.clone();
        bad[0] = version;
        assert_eq!(ser_message(&bad), "Invalid Version Number");
    }
    let mut v2 = good.clone();
    v2[0] = 2;
    assert_eq!(PartialHeader::deserialize(&v2).unwrap().version, 2);
    let mut bad = good.clone();
    bad[1] = 2;
    assert_eq!(ser_message(&bad), "Invalid Flavor");
    let mut flavor0 = good;
    flavor0[1] = 0;
    assert_eq!(PartialHeader::deserialize(&flavor0).unwrap().flavor, 0);
}

#[test]
fn deserialize_rejects_bad_legend() {
    let mut bad = reference_header_bytes();
    bad.extend_from_slice(&[0u8; COMMITMENT_LEN]);
    bad[PREFIX_LEN + 3] = b'x';
    assert_eq!(ser_message(&bad), "Invalid byte in stored legend");

    let prefix = reference_header_bytes()[..PREFIX_LEN].to_vec();
    let mut one_byte = prefix.clone();
    one_byte.push(0);
    assert_eq!(ser_message(&one_byte), "Unexpected end of header data.");
    let mut long = prefix;
    long.extend_from_slice(&[0, 3, E, S]);
    assert_eq!(ser_message(&long), "Unexpected end of header data.");
}

#[test]
fn deserialize_rejects_bad_trailer() {
    let mut short = reference_header_bytes();
    short.extend_from_slice(&[0u8; COMMITMENT_LEN - 1]);
    assert_eq!(
        ser_message(&short),
        "Invalid header serialization: unexpected end of data."
    );
    let mut long = reference_header_bytes();
    long.extend_from_slice(&[0u8; COMMITMENT_LEN + 1]);
    assert_eq!(
        ser_message(&long),
        "Invalid header serialization: unexpected bytes."
    );
}

// The data key list of reference_header_bytes, cut after each length field and value.
#[test]
fn data_keys_truncations() {
    let keys = serialize_data_keys(&reference_header().data_keys);
    assert_eq!(
        keys,
        [
            1, 0, 6, b'p', b'r', b'o', b'v', b'I', b'D', 0, 5, 1, 2, 3, 4, 5, 0, 4, 6, 7, 8, 9
        ]
    );
    let (parsed, len) = get_data_keys(&keys).unwrap();
    assert_eq!(parsed, reference_header().data_keys);
    assert_eq!(len, keys.len());

    for cut in 0..keys.len() {
        let err = get_data_keys(&keys[..cut]).unwrap_err();
        assert_eq!(err.kind(), Kind::Serialization, "cut {cut}");
        assert_eq!(err.message(), "Unexpected end of header data.", "cut {cut}");
    }
}

#[test]
fn data_keys_count_and_utf8() {
    assert_eq!(
        get_data_keys(&[0]).unwrap_err().message(),
        "At least one Data Key required"
    );
    assert_eq!(
        get_data_keys(&[1, 0, 1, 0xFF, 0, 0, 0, 0])
            .unwrap_err()
            .message(),
        "Invalid UTF8 found in header."
    );
    // Two keys: the second starts right after the first.
    let two = serialize_data_keys(&[edk("a", &[1], &[2]), edk("b", &[], &[3, 4])]);
    let (parsed, len) = get_data_keys(&two).unwrap();
    assert_eq!(parsed, [edk("a", &[1], &[2]), edk("b", &[], &[3, 4])]);
    assert_eq!(len, two.len());
}

#[test]
fn digest_lengths() {
    assert_eq!(digest_len(DigestAlg::Sha256), 32);
    assert_eq!(digest_len(DigestAlg::Sha384), 48);
    assert_eq!(digest_len(DigestAlg::Sha512), 64);
}

#[test]
fn encryption_context_size_limits() {
    let big = "x".repeat(UINT16_LIMIT);
    let max = "x".repeat(UINT16_LIMIT - 1);
    assert!(valid_encryption_context(&context(&[("k", max.as_str())])));
    assert!(!valid_encryption_context(&context(&[("k", big.as_str())])));
    assert!(!valid_encryption_context(&context(&[(big.as_str(), "v")])));
}

fn dbe_materials(
    edks: Vec<EncryptedDataKey>,
    ec: EncryptionContext,
    required: &[&str],
) -> EncryptionMaterials {
    let sym: Vec<SymmetricSigningKey> = edks
        .iter()
        .map(|_| SymmetricSigningKey::from(vec![5u8; 48]))
        .collect();
    EncryptionMaterials::builder()
        .algorithm_suite_id(MplAlgorithmSuiteId::Dbe(ECDSA_SUITE))
        .encryption_context(ec)
        .required_encryption_context_keys(required.iter().copied())
        .plaintext_data_key(vec![7u8; 32])
        .encrypted_data_keys(edks)
        .symmetric_signing_keys(sym)
        .build()
        .unwrap()
}

fn sample_schema() -> Vec<CanonItem> {
    crate::structured::for_encrypt(
        "t",
        vec![
            crypto("a", CryptoAction::EncryptAndSign),
            crypto("b", CryptoAction::SignOnly),
            crypto("c", CryptoAction::DoNothing),
        ],
    )
}

// Required encryption context keys are not stored in the header.
#[test]
fn create_from_materials() {
    let mat = dbe_materials(
        vec![edk("provID", &[1, 2, 3, 4, 5], &[6, 7, 8, 9])],
        context(&[("abc", "def"), ("req", "x")]),
        &["req"],
    );
    let head = PartialHeader::create(&sample_schema(), MSG_ID, &mat).unwrap();
    assert_same_header(&head, &reference_header());
    assert_eq!(head.serialize(), reference_header_bytes());
}

#[test]
fn create_rejects_bad_materials() {
    let schema = sample_schema();
    let one = || vec![edk("p", &[], &[1])];

    let big = "x".repeat(UINT16_LIMIT);
    let mat = dbe_materials(one(), context(&[("k", big.as_str())]), &[]);
    let err = PartialHeader::create(&schema, MSG_ID, &mat).unwrap_err();
    assert_eq!(err.message(), "Invalid Encryption Context");

    let mat = dbe_materials(Vec::new(), EncryptionContext::new(), &[]);
    let err = PartialHeader::create(&schema, MSG_ID, &mat).unwrap_err();
    assert_eq!(err.message(), "There must be at least one data key");

    let many: Vec<_> = (0..UINT8_LIMIT).map(|_| edk("p", &[], &[1])).collect();
    let mat = dbe_materials(many, EncryptionContext::new(), &[]);
    let err = PartialHeader::create(&schema, MSG_ID, &mat).unwrap_err();
    assert_eq!(err.message(), "Too many data keys.");

    let mat = dbe_materials(
        vec![edk("p", &[], &vec![0u8; UINT16_LIMIT])],
        EncryptionContext::new(),
        &[],
    );
    let err = PartialHeader::create(&schema, MSG_ID, &mat).unwrap_err();
    assert_eq!(err.message(), "Invalid Data Key");

    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(MplAlgorithmSuiteId::Esdk(
            EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        ))
        .plaintext_data_key(vec![7u8; 32])
        .encrypted_data_keys(one())
        .build()
        .unwrap();
    let err = PartialHeader::create(&schema, MSG_ID, &mat).unwrap_err();
    assert_eq!(err.kind(), Kind::Validation);
    assert_eq!(
        err.message(),
        "Algorithm Suite not suitable for structured encryption."
    );
}

#[test]
fn create_accepts_limits() {
    let schema = sample_schema();
    let max: Vec<_> = (0..UINT8_LIMIT - 1).map(|_| edk("p", &[], &[1])).collect();
    let mat = dbe_materials(max, EncryptionContext::new(), &[]);
    let head = PartialHeader::create(&schema, MSG_ID, &mat).unwrap();
    assert_eq!(head.data_keys.len(), 255);
    let mut ser = head.serialize();
    ser.extend_from_slice(&[0u8; COMMITMENT_LEN]);
    assert_eq!(
        PartialHeader::deserialize(&ser).unwrap().data_keys.len(),
        255
    );
}
