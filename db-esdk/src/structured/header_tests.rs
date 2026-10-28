// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::types::{
    AlgorithmSuiteId as MplAlgorithmSuiteId, EsdkAlgorithmSuiteId, SymmetricSigningKey,
};

use super::*;
use crate::error::Kind;
use crate::structured::util::{CryptoField, Terminal};
use crate::types::AlgorithmSuiteId;

/// The version byte, the flavor byte, and the message id.
const PREFIX_LEN: usize = 1 + 1 + MSGID_LEN;

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
    //= spec/structured-encryption/header.md#partial-header
    //= type=test
    //# The Partial Header MUST be
    assert_eq!(reference_header().serialize(), reference_header_bytes());
}

// Header.dfy TestRoundTrip: the message id stands in for the commitment.
#[test]
fn round_trip() {
    let head = reference_header();
    let mut ser = head.serialize();
    ser.extend_from_slice(&head.msg_id);

    //= spec/structured-encryption/header.md#partial-header
    //= type=test
    //= reason=deserialize recovers every field of the spec-layout bytes
    //# The Partial Header MUST be
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

    //= spec/structured-encryption/header.md#full-header-value
    //= type=test
    //# The value of the header MUST be
    assert_eq!(&ser[..body.len()], body.as_slice());
    assert_eq!(&ser[body.len()..], &full[..COMMITMENT_LEN]);

    let mut bad = ser.clone();
    let last = bad.len() - 1;
    bad[last] = if bad[last] == 0 { 255 } else { bad[last] - 1 };
    assert_same_header(&PartialHeader::deserialize(&bad).unwrap(), &head);
    let err = PartialHeader::verify_commitment(DigestAlg::Sha512, &key, &bad).unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
    assert_eq!(
        err.message(),
        "the item's header (aws_dbe_head) failed its key commitment check: the header was changed, or the data key is not the one it was written with"
    );

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

    //= spec/structured-encryption/header.md#encryption-context
    //= type=test
    //# The Encryption Context MUST be serialized as follows
    //
    //= spec/structured-encryption/header.md#key-value-pair-entries
    //= type=test
    //# Each Key Value Pair MUST be serialized as follows
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
    assert_eq!(
        err.message(),
        "the item's header (aws_dbe_head) has encryption context keys that are not in sorted order"
    );

    // The same key twice in a row: only a strict order check rejects this.
    let duplicate = [
        0, 2, 0, 3, b'a', b'b', b'c', 0, 3, b'd', b'e', b'f', 0, 3, b'a', b'b', b'c', 0, 3, b'd',
        b'e', b'f',
    ];
    let err = get_context(&duplicate).unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization);

    //= spec/structured-encryption/header.md#key-value-pair-entries
    //= type=test
    //# This sequence MUST NOT contain duplicate entries.
    assert_eq!(
        err.message(),
        "the item's header (aws_dbe_head) has encryption context keys that are not in sorted order"
    );
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

    //= spec/structured-encryption/header.md#key-value-pair-entries
    //= type=test
    //# These entries MUST have entries sorted, by key,
    //# in ascending order according to the UTF-8 encoded binary value.
    assert_eq!(
        err.message(),
        "the item's header (aws_dbe_head) has encryption context keys that are not in sorted order"
    );
}

// U+FFFF sorts before U+1F600 by UTF-8 bytes but after it by UTF-16 code units,
// so this order shows the writer sorts keys by their UTF-8 bytes.
#[test]
fn serialize_context_sorts_keys_by_utf8_bytes() {
    let ec = context(&[("\u{1F600}", "x"), ("a", "y"), ("\u{FFFF}", "z")]);
    let expected = [
        0, 3, 0, 1, b'a', 0, 1, b'y', 0, 3, 0xEF, 0xBF, 0xBF, 0, 1, b'z', 0, 4, 0xF0, 0x9F, 0x98,
        0x80, 0, 1, b'x',
    ];

    //= spec/structured-encryption/header.md#key-value-pair-entries
    //= type=test
    //# These entries MUST have entries sorted, by key,
    //# in ascending order according to the UTF-8 encoded binary value.
    assert_eq!(serialize_context(&ec), expected);
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
    let err = get_context(&empty_key).unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization);
    assert_eq!(
        err.message(),
        "the item's header (aws_dbe_head) has encryption context keys that are not in sorted order"
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

        //= spec/structured-encryption/header.md#key-value-pair-entries
        //= type=test
        //= reason=each case is shorter than a length field says, so the reader honors every length
        //# Each Key Value Pair MUST be serialized as follows
        assert_eq!(
            err.message(),
            "the item's header (aws_dbe_head) ends early",
            "{bad:?}"
        );
    }
    assert_eq!(
        get_context(&[0, 1, 0, 1, 0xFF, 0, 0])
            .unwrap_err()
            .message(),
        "the item's header (aws_dbe_head) has a string that is not UTF-8"
    );
    assert_eq!(
        get_context(&[0, 1, 0, 1, b'a', 0, 1, 0xFF])
            .unwrap_err()
            .message(),
        "the item's header (aws_dbe_head) has a string that is not UTF-8"
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

    //= spec/structured-encryption/header.md#encrypt-legend-bytes
    //= type=test
    //# The length of this serialized value (in bytes) MUST equal the number of authenticated fields indicated
    //# by the caller's [Authenticate Schema](./structures.md#authenticate-schema).
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

    //= spec/structured-encryption/header.md#encrypt-legend-bytes
    //= type=test
    //# The Encrypt Legend Bytes MUST be serialized as follows:
    assert_eq!(legend, [E, S, E, S]);
}

#[test]
fn legend_and_version_for_sign_and_include() {
    let fields = vec![
        crypto("a", CryptoAction::SignAndIncludeInEncryptionContext),
        crypto("b", CryptoAction::EncryptAndSign),
    ];
    let schema = crate::structured::for_encrypt("name", fields);

    //= spec/structured-encryption/header.md#encrypt-legend-bytes
    //= type=test
    //# Each Crypto Action MUST be encoded as follows
    assert_eq!(make_legend(&schema).unwrap(), [0x63, E]);

    //= spec/structured-encryption/header.md#format-version
    //= type=test
    //# If any [Crypto Action](./structures.md#crypto-action) is configured as
    //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT Crypto Action](./structures.md#sign_and_include_in_encryption_context)
    //# the Version MUST be 0x02; otherwise, Version MUST be 0x01.
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
        "the item's header (aws_dbe_head) is too short"
    );
    for version in [0u8, 3] {
        let mut bad = good.clone();
        bad[0] = version;

        //= spec/structured-encryption/header.md#format-version
        //= type=test
        //# The Version MUST be `0x01` or `0x02`.
        assert_eq!(
            ser_message(&bad),
            "the item's header (aws_dbe_head) has an unknown version"
        );
    }
    let mut v2 = good.clone();
    v2[0] = 2;
    assert_eq!(PartialHeader::deserialize(&v2).unwrap().version, 2);
    let mut bad = good.clone();
    bad[1] = 2;

    //= spec/structured-encryption/header.md#format-flavor
    //= type=test
    //# The algorithm suite indicated by the flavor MUST be a
    //# [DBE supported algorithm suite](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#supported-algorithm-suites-enum).
    assert_eq!(
        ser_message(&bad),
        "the item's header (aws_dbe_head) names an unknown algorithm suite"
    );
    let mut flavor0 = good;
    flavor0[1] = 0;
    assert_eq!(PartialHeader::deserialize(&flavor0).unwrap().flavor, 0);
}

#[test]
fn deserialize_rejects_bad_legend() {
    let mut bad = reference_header_bytes();
    bad.extend_from_slice(&[0u8; COMMITMENT_LEN]);
    bad[PREFIX_LEN + 3] = b'x';

    //= spec/structured-encryption/header.md#encrypt-legend-bytes
    //= type=test
    //# Each Crypto Action MUST be encoded as follows
    assert_eq!(
        ser_message(&bad),
        "the item's header (aws_dbe_head) has an unknown byte in its legend"
    );

    let prefix = reference_header_bytes()[..PREFIX_LEN].to_vec();
    let mut one_byte = prefix.clone();
    one_byte.push(0);
    assert_eq!(
        ser_message(&one_byte),
        "the item's header (aws_dbe_head) ends early"
    );
    let mut long = prefix;
    long.extend_from_slice(&[0, 3, E, S]);

    //= spec/structured-encryption/header.md#encrypt-legend
    //= type=test
    //# The Encrypt Legend MUST be serialized as
    assert_eq!(
        ser_message(&long),
        "the item's header (aws_dbe_head) ends early"
    );
}

#[test]
fn deserialize_rejects_bad_trailer() {
    let mut short = reference_header_bytes();
    short.extend_from_slice(&[0u8; COMMITMENT_LEN - 1]);

    //= spec/structured-encryption/header.md#full-header-value
    //= type=test
    //# The value of the header MUST be
    assert_eq!(
        ser_message(&short),
        "the item's header (aws_dbe_head) ends early"
    );
    let mut long = reference_header_bytes();
    long.extend_from_slice(&[0u8; COMMITMENT_LEN + 1]);
    assert_eq!(
        ser_message(&long),
        "the item's header (aws_dbe_head) has extra bytes at the end"
    );
}

// The data key list of reference_header_bytes, cut after each length field and value.
#[test]
fn data_keys_truncations() {
    let keys = serialize_data_keys(&reference_header().data_keys);

    //= spec/structured-encryption/header.md#encrypted-data-keys
    //= type=test
    //# The Encrypted Data Keys MUST be serialized as follows
    assert_eq!(
        keys,
        [
            1, 0, 6, b'p', b'r', b'o', b'v', b'I', b'D', 0, 5, 1, 2, 3, 4, 5, 0, 4, 6, 7, 8, 9
        ]
    );
    let (parsed, len) = get_data_keys(&keys).unwrap();

    //= spec/structured-encryption/header.md#encrypted-data-key-entries
    //= type=test
    //# Each Encrypted Data Key MUST be serialized as follows
    assert_eq!(parsed, reference_header().data_keys);
    assert_eq!(len, keys.len());

    for cut in 0..keys.len() {
        let err = get_data_keys(&keys[..cut]).unwrap_err();
        assert_eq!(err.kind(), Kind::Serialization, "cut {cut}");
        assert_eq!(
            err.message(),
            "the item's header (aws_dbe_head) ends early",
            "cut {cut}"
        );
    }
}

#[test]
fn data_keys_count_and_utf8() {
    let err = get_data_keys(&[0]).unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization);

    //= spec/structured-encryption/header.md#encrypted-data-key-count
    //= type=test
    //# This value MUST be greater than 0.
    assert_eq!(
        err.message(),
        "the item's header (aws_dbe_head) has no encrypted data keys"
    );
    assert_eq!(
        get_data_keys(&[1, 0, 1, 0xFF, 0, 0, 0, 0])
            .unwrap_err()
            .message(),
        "the item's header (aws_dbe_head) has a string that is not UTF-8"
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
    assert_eq!(
        err.message(),
        "the encryption context cannot be stored: it has 65536 or more entries, or a key or value of 65536 or more bytes"
    );

    let mat = dbe_materials(Vec::new(), EncryptionContext::new(), &[]);
    let err = PartialHeader::create(&schema, MSG_ID, &mat).unwrap_err();
    assert_eq!(err.kind(), Kind::Validation);

    //= spec/structured-encryption/header.md#encrypted-data-key-count
    //= type=test
    //# This value MUST be greater than 0.
    assert_eq!(
        err.message(),
        "the encryption materials have no encrypted data keys"
    );

    let many: Vec<_> = (0..UINT8_LIMIT).map(|_| edk("p", &[], &[1])).collect();
    let mat = dbe_materials(many, EncryptionContext::new(), &[]);
    let err = PartialHeader::create(&schema, MSG_ID, &mat).unwrap_err();
    assert_eq!(
        err.message(),
        "the encryption materials have more than 255 encrypted data keys"
    );

    let mat = dbe_materials(
        vec![edk("p", &[], &vec![0u8; UINT16_LIMIT])],
        EncryptionContext::new(),
        &[],
    );
    let err = PartialHeader::create(&schema, MSG_ID, &mat).unwrap_err();
    assert_eq!(
        err.message(),
        "an encrypted data key cannot be stored: a field of it is 65536 or more bytes"
    );

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

    //= spec/structured-encryption/header.md#format-flavor
    //= type=test
    //# The algorithm suite indicated by the flavor MUST be a
    //# [DBE supported algorithm suite](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#supported-algorithm-suites-enum).
    assert_eq!(
        err.message(),
        "the materials use an algorithm suite that is not a DB-ESDK algorithm suite"
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
