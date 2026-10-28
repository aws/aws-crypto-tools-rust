// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structured encryption round trips: `HappyCaseTests.dfy`, every crypto action,
//! both algorithm suites, canonical path ordering, and `resolve_auth_actions`.

mod structured_api_support;

use std::collections::HashMap;

use aws_db_esdk::structured::{
    AuthItem, AuthenticateAction, CryptoItem, Path, PathSegment, StructuredDataTerminal,
};
use aws_db_esdk::types::{AlgorithmSuiteId, CryptoAction};
use structured_api_support::{
    BOOLEAN, FOOTER, HEADER, NULL, NUMBER, STRING, TABLE, TEST_BLOB_VALUE, blob, client, cmm,
    test_authenticate_schema, test_crypto_schema, test_crypto_schema_auth_only,
    test_structured_data,
};

const SIGNING_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384;
const SYMMETRIC_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384;

/// One HMAC-SHA-384 recipient tag.
const TAG_LEN: usize = 48;
/// The ECDSA P-384 signature the footer holds.
const SIG_LEN: usize = 103;
/// The AES-GCM tag appended to each encrypted value.
const GCM_TAG_LEN: usize = 16;

fn path(segments: &[&str]) -> Path {
    segments.iter().map(|s| PathSegment::member(*s)).collect()
}

fn auth_items(items: &[CryptoItem]) -> Vec<AuthItem> {
    items
        .iter()
        .map(|x| {
            let action = if x.action() == CryptoAction::DoNothing {
                AuthenticateAction::DoNotSign
            } else {
                AuthenticateAction::Sign
            };
            AuthItem::new(x.key().to_vec(), x.data().clone(), action)
        })
        .collect()
}

// Port of HappyCaseTests.TestRoundTrip, with a Raw AES keyring in place of KMS.
#[tokio::test]
async fn round_trip_test_structured_data() {
    let cmm = cmm();
    let enc = client()
        .encrypt_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(test_structured_data()))
        .set_crypto_schema(Some(test_crypto_schema()))
        .cmm(cmm.clone())
        .algorithm_suite_id(SIGNING_SUITE)
        .encryption_context("some", "value")
        .send()
        .await
        .unwrap();

    let new_data = enc.encrypted_structure();
    let mut keys: Vec<&str> = new_data.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["aws_dbe_foot", "aws_dbe_head", "bar", "fizzbuzz", "foo"]
    );
    assert_ne!(new_data["foo"], blob());
    assert_eq!(new_data["bar"], blob());
    assert_eq!(new_data["fizzbuzz"], blob());
    assert_eq!(enc.crypto_schema(), &test_crypto_schema_auth_only());
    assert_eq!(enc.parsed_header().algorithm_suite_id(), SIGNING_SUITE);

    let dec = client()
        .decrypt_structure()
        .table_name(TABLE)
        .set_encrypted_structure(Some(enc.into_encrypted_structure()))
        .set_authenticate_schema(Some(test_authenticate_schema()))
        .cmm(cmm)
        .send()
        .await
        .unwrap();

    assert_eq!(dec.plaintext_structure(), &test_structured_data());
    assert_eq!(dec.crypto_schema(), &test_crypto_schema_auth_only());
    let header = dec.parsed_header();
    assert_eq!(header.algorithm_suite_id(), SIGNING_SUITE);
    assert_eq!(
        header.stored_encryption_context().get("some"),
        Some("value")
    );
    assert_eq!(header.encryption_context().get("some"), Some("value"));
    assert_eq!(header.encrypted_data_keys().len(), 1);
    assert_eq!(
        header.encrypted_data_keys()[0].key_provider_id(),
        "structured-api-test"
    );
    assert_eq!(dec.into_plaintext_structure(), test_structured_data());
}

#[tokio::test]
async fn encrypt_and_sign_value_layout() {
    // An encrypted value is the original type id, the AES-GCM ciphertext, and the tag,
    // stored as binary.
    let value = b"hello".to_vec();
    let enc = client()
        .encrypt_structure()
        .table_name(TABLE)
        .plaintext_structure("s", StructuredDataTerminal::new(STRING, value.clone()))
        .crypto_schema("s", CryptoAction::EncryptAndSign)
        .cmm(cmm())
        .send()
        .await
        .unwrap();
    let ct = &enc.encrypted_structure()["s"];
    assert_eq!(ct.type_id(), [0xFF, 0xFF]);
    assert_eq!(ct.value().len(), 2 + value.len() + GCM_TAG_LEN);
    assert_eq!(&ct.value()[..2], &STRING);
    assert_ne!(&ct.value()[2..2 + value.len()], value.as_slice());
}

#[tokio::test]
async fn footer_holds_signature_only_for_the_signing_suite() {
    for (suite, footer_len) in [
        (SIGNING_SUITE, TAG_LEN + SIG_LEN),
        (SYMMETRIC_SUITE, TAG_LEN),
    ] {
        let cmm = cmm();
        let enc = client()
            .encrypt_structure()
            .table_name(TABLE)
            .set_plaintext_structure(Some(test_structured_data()))
            .set_crypto_schema(Some(test_crypto_schema()))
            .cmm(cmm.clone())
            .set_algorithm_suite_id(Some(suite))
            .send()
            .await
            .unwrap();
        let data = enc.encrypted_structure();

        //= spec/structured-encryption/footer.md#signature
        //= type=test
        //# The signature MUST be included in the footer if the flavor
        //# in the [header](./header.md#format-flavor) is 0x01
        //# and MUST NOT be included in the footer if the flavor
        //# in the [header](./header.md#format-flavor) is 0x00.
        assert_eq!(data[FOOTER].value().len(), footer_len, "{suite:?}");
        // Header: version 1 (no SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT field), then the flavor.
        let flavor = u8::from(suite == SIGNING_SUITE);
        assert_eq!(&data[HEADER].value()[..2], &[1, flavor], "{suite:?}");

        let dec = client()
            .decrypt_structure()
            .table_name(TABLE)
            .set_encrypted_structure(Some(enc.into_encrypted_structure()))
            .set_authenticate_schema(Some(test_authenticate_schema()))
            .cmm(cmm)
            .send()
            .await
            .unwrap();
        assert_eq!(dec.plaintext_structure(), &test_structured_data());
        assert_eq!(dec.parsed_header().algorithm_suite_id(), suite);
    }
}

#[tokio::test]
async fn default_suite_signs_with_ecdsa() {
    let enc = client()
        .encrypt_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(test_structured_data()))
        .set_crypto_schema(Some(test_crypto_schema()))
        .cmm(cmm())
        .set_algorithm_suite_id(None)
        .send()
        .await
        .unwrap();
    assert_eq!(enc.parsed_header().algorithm_suite_id(), SIGNING_SUITE);
    assert_eq!(
        enc.encrypted_structure()[FOOTER].value().len(),
        TAG_LEN + SIG_LEN
    );
}

#[tokio::test]
async fn sign_and_include_in_encryption_context_binds_each_type() {
    // One field of each encoding the encryption context legend distinguishes.
    let fields = [
        ("b", StructuredDataTerminal::new([0xFF, 0xFF], vec![1, 2])),
        ("f", StructuredDataTerminal::new(BOOLEAN, vec![0])),
        ("n", StructuredDataTerminal::new(NUMBER, b"12.5".to_vec())),
        ("u", StructuredDataTerminal::new(NULL, vec![])),
        ("s", StructuredDataTerminal::new(STRING, b"abc".to_vec())),
        ("t", StructuredDataTerminal::new(BOOLEAN, vec![1])),
    ];
    let mut builder = client()
        .encrypt_structure()
        .table_name(TABLE)
        .cmm(cmm())
        .encryption_context("caller", "ec")
        .plaintext_structure("secret", blob())
        .crypto_schema("secret", CryptoAction::EncryptAndSign);
    for (name, value) in &fields {
        builder = builder
            .plaintext_structure(*name, value.clone())
            .crypto_schema(*name, CryptoAction::SignAndIncludeInEncryptionContext);
    }
    let enc = builder.send().await.unwrap();
    let data = enc.encrypted_structure();
    // Version 2 header.
    assert_eq!(data[HEADER].value()[0], 2);
    for (name, value) in &fields {
        assert_eq!(&data[*name], value, "{name} stays plaintext");
    }

    let header = enc.parsed_header();
    let ec = header.encryption_context().clone();
    assert_eq!(ec.get("caller"), Some("ec"));
    assert_eq!(ec.get("aws-crypto-attr.b"), Some("//8BAg=="));
    assert_eq!(ec.get("aws-crypto-attr.f"), Some("false"));
    assert_eq!(ec.get("aws-crypto-attr.n"), Some("12.5"));
    assert_eq!(ec.get("aws-crypto-attr.s"), Some("abc"));
    assert_eq!(ec.get("aws-crypto-attr.t"), Some("true"));
    assert_eq!(ec.get("aws-crypto-attr.u"), Some("null"));
    // One legend character per attribute entry, in key order: b f n s t u.
    assert_eq!(ec.get("aws-crypto-legend"), Some("BLNSLL"));
    // The default suite also adds the ECDSA public key.
    assert!(ec.contains_key("aws-crypto-public-key"));
    assert_eq!(ec.len(), 9);
    // The attribute entries are required, so the header does not store them.
    let stored = header.stored_encryption_context();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored.get("caller"), Some("ec"));
    assert!(stored.contains_key("aws-crypto-public-key"));

    let mut auth = HashMap::from([
        ("secret".to_owned(), AuthenticateAction::Sign),
        (HEADER.to_owned(), AuthenticateAction::DoNotSign),
        (FOOTER.to_owned(), AuthenticateAction::DoNotSign),
    ]);
    for (name, _) in &fields {
        auth.insert((*name).to_owned(), AuthenticateAction::Sign);
    }
    let mut builder = client().decrypt_structure().table_name(TABLE).cmm(cmm());
    for (name, value) in enc.into_encrypted_structure() {
        builder = builder
            .authenticate_schema(name.clone(), auth[&name])
            .encrypted_structure(name, value);
    }
    let dec = builder.send().await.unwrap();
    assert_eq!(dec.plaintext_structure()["secret"], blob());
    for (name, value) in &fields {
        assert_eq!(&dec.plaintext_structure()[*name], value);
        assert_eq!(
            dec.crypto_schema()[*name],
            CryptoAction::SignAndIncludeInEncryptionContext
        );
    }
    assert_eq!(dec.crypto_schema()["secret"], CryptoAction::EncryptAndSign);
    assert_eq!(dec.parsed_header().encryption_context(), &ec);
}

#[tokio::test]
async fn path_structure_is_output_in_canonical_order() {
    // Canonical order compares depth, then each member's UTF-16 length, then its bytes;
    // so ["z"] < ["aa"] < ["a", "a"], whatever the input order.
    let input = vec![
        CryptoItem::new(path(&["a", "a"]), blob(), CryptoAction::EncryptAndSign),
        CryptoItem::new(path(&["aa"]), blob(), CryptoAction::SignOnly),
        CryptoItem::new(path(&["unsigned"]), blob(), CryptoAction::DoNothing),
        CryptoItem::new(path(&["z"]), blob(), CryptoAction::EncryptAndSign),
    ];
    let enc = client()
        .encrypt_path_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(input))
        .cmm(cmm())
        .encryption_context("k", "v")
        .send()
        .await
        .unwrap();
    let out = enc.encrypted_structure();
    let order: Vec<Path> = out.iter().map(|x| x.key().to_vec()).collect();
    assert_eq!(
        order,
        [
            path(&["z"]),
            path(&["aa"]),
            path(&["unsigned"]),
            path(&["a", "a"]),
            path(&[HEADER]),
            path(&[FOOTER]),
        ]
    );
    let actions: Vec<CryptoAction> = out.iter().map(CryptoItem::action).collect();
    assert_eq!(
        actions,
        [
            CryptoAction::EncryptAndSign,
            CryptoAction::SignOnly,
            CryptoAction::DoNothing,
            CryptoAction::EncryptAndSign,
            CryptoAction::DoNothing,
            CryptoAction::DoNothing,
        ]
    );
    // Legend: one byte per signed field in canonical order: 'e', 's', 'e'.
    let header = out[4].data().value();

    //= spec/structured-encryption/header.md#encrypt-legend
    //= type=test
    //# The Encrypt Legend MUST be serialized as
    assert_eq!(&header[2 + 32..2 + 32 + 5], &[0, 3, b'e', b's', b'e']);
    assert_eq!(
        enc.parsed_header().stored_encryption_context().get("k"),
        Some("v")
    );

    // Decrypt in reverse order: the result is canonical again, with each action from the legend.
    let mut auth = auth_items(&enc.into_encrypted_structure());
    auth.reverse();
    let dec = client()
        .decrypt_path_structure()
        .table_name(TABLE)
        .set_encrypted_structure(Some(auth))
        .cmm(cmm())
        .encryption_context("k", "v")
        .send()
        .await
        .unwrap();
    let plain: Vec<(Path, StructuredDataTerminal, CryptoAction)> = dec
        .plaintext_structure()
        .iter()
        .map(|x| (x.key().to_vec(), x.data().clone(), x.action()))
        .collect();
    assert_eq!(
        plain,
        [
            (path(&["z"]), blob(), CryptoAction::EncryptAndSign),
            (path(&["aa"]), blob(), CryptoAction::SignOnly),
            (path(&["unsigned"]), blob(), CryptoAction::DoNothing),
            (path(&["a", "a"]), blob(), CryptoAction::EncryptAndSign),
        ]
    );
    assert_eq!(dec.parsed_header().algorithm_suite_id(), SIGNING_SUITE);
    assert_eq!(dec.into_plaintext_structure().len(), 4);
}

// Identical encrypts must still get distinct message ids (header bytes 2..34).
#[tokio::test]
async fn each_encrypt_draws_a_fresh_message_id() {
    const RUNS: usize = 20;
    let cmm = cmm();
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..RUNS {
        let enc = client()
            .encrypt_structure()
            .table_name(TABLE)
            .set_plaintext_structure(Some(test_structured_data()))
            .set_crypto_schema(Some(test_crypto_schema()))
            .cmm(cmm.clone())
            .send()
            .await
            .unwrap();
        let id = enc.encrypted_structure()[HEADER].value()[2..34].to_vec();
        assert_ne!(id, [0u8; 32]);
        ids.insert(id);
    }

    //= spec/structured-encryption/header.md#message-id
    //= type=test
    //= reason=distinct ids across identical encrypts; a fixed or reused id would collide
    //# Implementations MUST generate a fresh 256-bit random MessageID, from a cryptographically secure source, for each record encrypted.
    assert_eq!(ids.len(), RUNS);
}

#[tokio::test]
async fn nested_path_round_trip_through_builder_adders() {
    let enc = client()
        .encrypt_path_structure()
        .table_name(TABLE)
        .plaintext_structure(CryptoItem::new(
            path(&["outer", "inner"]),
            StructuredDataTerminal::new(STRING, b"nested".to_vec()),
            CryptoAction::EncryptAndSign,
        ))
        .cmm(cmm())
        .algorithm_suite_id(SYMMETRIC_SUITE)
        .send()
        .await
        .unwrap();
    let mut builder = client()
        .decrypt_path_structure()
        .table_name(TABLE)
        .cmm(cmm());
    for item in auth_items(enc.encrypted_structure()) {
        builder = builder.encrypted_structure(item);
    }
    let dec = builder.send().await.unwrap();
    let [item] = dec.plaintext_structure() else {
        panic!("expected one field, got {:?}", dec.plaintext_structure());
    };
    assert_eq!(item.key(), path(&["outer", "inner"]).as_slice());
    assert_eq!(item.data().value(), b"nested");
    assert_eq!(item.data().type_id(), STRING);
    assert_eq!(dec.parsed_header().algorithm_suite_id(), SYMMETRIC_SUITE);
}

#[tokio::test]
async fn resolve_auth_actions_reads_the_legend() {
    let enc = client()
        .encrypt_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(test_structured_data()))
        .set_crypto_schema(Some(test_crypto_schema()))
        .cmm(cmm())
        .send()
        .await
        .unwrap();
    let data = enc.into_encrypted_structure();
    let header = data[HEADER].value().to_vec();
    let auth = test_authenticate_schema();
    let mut builder = client()
        .resolve_auth_actions()
        .table_name(TABLE)
        .header_bytes(header);
    let mut names: Vec<&String> = data.keys().collect();
    names.sort();
    for name in names {
        builder =
            builder.auth_actions(AuthItem::new(path(&[name]), data[name].clone(), auth[name]));
    }
    let out = builder.send().await.unwrap();
    let resolved: Vec<(Path, CryptoAction)> = out
        .crypto_actions()
        .iter()
        .map(|x| (x.key().to_vec(), x.action()))
        .collect();
    // Canonical order: by name length, then by name.
    assert_eq!(
        resolved,
        [
            (path(&["bar"]), CryptoAction::SignOnly),
            (path(&["foo"]), CryptoAction::EncryptAndSign),
            (path(&["fizzbuzz"]), CryptoAction::DoNothing),
            (path(&[FOOTER]), CryptoAction::DoNothing),
            (path(&[HEADER]), CryptoAction::DoNothing),
        ]
    );
    // Nothing is decrypted.
    assert_eq!(out.crypto_actions()[1].data(), &data["foo"]);
    assert_eq!(out.into_crypto_actions().len(), 5);
}

#[test]
fn terminal_accessors() {
    let t = StructuredDataTerminal::new(STRING, b"x".to_vec());
    assert_eq!(t.type_id(), STRING);
    assert_eq!(t.value(), b"x");
    assert_eq!(t.into_value(), b"x");
    let item = AuthItem::new(path(&["a"]), blob(), AuthenticateAction::Sign);
    assert_eq!(item.action(), AuthenticateAction::Sign);
    assert_eq!(item.data().value(), TEST_BLOB_VALUE);
    match &item.key()[0] {
        PathSegment::Member(m) => assert_eq!(m.key(), "a"),
        other => panic!("unexpected segment {other:?}"),
    }
}
