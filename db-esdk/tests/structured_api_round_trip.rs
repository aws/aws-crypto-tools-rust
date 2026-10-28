// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structured encryption round trips: `HappyCaseTests.dfy`, every crypto action,
//! both algorithm suites, canonical path ordering, and `resolve_auth_actions`.

mod structured_api_support;

use std::collections::{BTreeSet, HashMap};

use aws_db_esdk::mpl::types::{
    AlgorithmSuiteId as MplAlgorithmSuiteId, CommitmentPolicy, DbeCommitmentPolicy,
};
use aws_db_esdk::structured::{
    AuthItem, AuthenticateAction, CryptoItem, Path, PathSegment, StructuredDataTerminal,
};
use aws_db_esdk::types::{AlgorithmSuiteId, CryptoAction, EncryptionContext};
use structured_api_support::{
    BOOLEAN, FOOTER, HEADER, NULL, NUMBER, OnEncrypt, STRING, TABLE, TEST_BLOB_VALUE, blob, client,
    cmm, recording_cmm, test_authenticate_schema, test_crypto_schema, test_crypto_schema_auth_only,
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

    //= spec/structured-encryption/encrypt-structure.md#behavior
    //= type=test
    //# The output [Crypto List](encrypt-path-structure.md#crypto-list) produced by [Encrypt Path Structure](encrypt-path-structure.md)
    //# MUST be split into [Structured Data](encrypt-path-structure.md#structured-data) and [Crypto Schema](encrypt-path-structure.md#crypto-schema)
    //# maps.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#header-field
    //= type=test
    //# The Header Field name MUST be `aws_dbe_head`
    //
    //= spec/structured-encryption/encrypt-path-structure.md#footer-field
    //= type=test
    //# The Footer Field name MUST be `aws_dbe_foot`
    assert_eq!(
        keys,
        ["aws_dbe_foot", "aws_dbe_head", "bar", "fizzbuzz", "foo"]
    );

    //= spec/structured-encryption/encrypt-path-structure.md#header-field
    //= type=test
    //# The Header Field TypeID MUST be 0xFFFF
    assert_eq!(new_data[HEADER].type_id(), [0xFF, 0xFF]);

    //= spec/structured-encryption/encrypt-path-structure.md#footer-field
    //= type=test
    //# The Footer Field TypeID MUST be 0xFFFF
    assert_eq!(new_data[FOOTER].type_id(), [0xFF, 0xFF]);

    //= spec/structured-encryption/encrypt-structure.md#behavior
    //= type=test
    //= reason=foo got its EncryptAndSign action from the schema, so the field and action were combined
    //# The input [Structured Data](encrypt-path-structure.md#structured-data) and [Crypto Schema](encrypt-path-structure.md#crypto-schema)
    //# MUST be combined into a single [Crypto List](encrypt-path-structure.md#crypto-list).
    assert_ne!(new_data["foo"], blob());

    //= spec/structured-encryption/structures.md#do-not-encrypt
    //= type=test
    //# During [Encrypt Structure](encrypt-structure.md#encrypt-structure)
    //# and [Decrypt Structure](decrypt-structure.md#decrypt-structure),
    //# DO_NOT_ENCRYPT signifies that the [Terminal Data](#terminal-data)
    //# MUST have an equal [Terminal Value](#terminal-value) and
    //# [Terminal Type Id](#terminal-type-id) as the the Terminal Data
    //# in the same location in the resulting encrypted [Structured Data](#structured-data).
    assert_eq!(new_data["bar"], blob());
    assert_eq!(new_data["fizzbuzz"], blob());

    //= spec/structured-encryption/encrypt-structure.md#output
    //= type=test
    //= reason=the output holds the encrypted structure (above), the signed fields' schema, and the parsed header
    //# This operation MUST output the following:
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

    //= spec/structured-encryption/structures.md#encrypt
    //= type=test
    //= reason=foo was ciphertext before decrypt; getting its plaintext back proves it was decrypted
    //# During [Decrypt Structure](decrypt-structure.md#decrypt-structure),
    //# ENCRYPT signifies that the [Terminal Value](#terminal-value) in the [Terminal Data](#terminal-data)
    //# MUST be attempted to be decrypted.
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

    //= spec/structured-encryption/structures.md#terminal-type-id
    //= type=test
    //# If [Terminal Value](#terminal-value) is to be interpreted as raw bytes,
    //# the Terminal Type ID MUST be 0xFFFF.
    assert_eq!(ct.type_id(), [0xFF, 0xFF]);

    //= spec/structured-encryption/encrypt-path-structure.md#terminal-data-encryption
    //= type=test
    //# The output encrypted Terminal Data MUST have a [Terminal Value](./structures.md#terminal-value)
    //# with the following serialization:
    assert_eq!(ct.value().len(), 2 + value.len() + GCM_TAG_LEN);

    //= spec/structured-encryption/encrypt-path-structure.md#terminal-type-id
    //= type=test
    //# Terminal Type Id MUST equal the input Terminal Data's Terminal Type Id.
    assert_eq!(&ct.value()[..2], &STRING);

    //= spec/structured-encryption/structures.md#encrypt
    //= type=test
    //# During [Encrypt Structure](encrypt-structure.md#encrypt-structure),
    //# ENCRYPT signifies that the [Terminal Value](#terminal-value) in the [Terminal Data](#terminal-data)
    //# MUST be encrypted in the resulting encrypted [Structured Data](#structured-data).
    assert_ne!(&ct.value()[2..2 + value.len()], value.as_slice());

    let ct_type_id = ct.type_id();
    let dec = client()
        .decrypt_structure()
        .table_name(TABLE)
        .set_encrypted_structure(Some(enc.into_encrypted_structure()))
        .authenticate_schema("s", AuthenticateAction::Sign)
        .authenticate_schema(HEADER, AuthenticateAction::DoNotSign)
        .authenticate_schema(FOOTER, AuthenticateAction::DoNotSign)
        .cmm(cmm())
        .send()
        .await
        .unwrap();

    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
    //= type=test
    //= reason=the type id is 0xFFFF and the stored value decrypts back to the input
    //# If the [Crypto Schema](#crypto-list)
    //# indicates a [Crypto Action](./structures.md#crypto-action)
    //# of [ENCRYPT_AND_SIGN](./structures.md#encryptandsign),
    //# the Terminal Data MUST have [Terminal Type ID](./structures.md#terminal-type-id)
    //# equal to 0xffff and the value MUST be
    //# the [encryption](#terminal-data-encryption)
    //# of the input's Terminal Data.
    assert_eq!(
        (ct_type_id, &dec.plaintext_structure()["s"]),
        ([0xFF, 0xFF], &StructuredDataTerminal::new(STRING, value))
    );
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
        //
        //= spec/structured-encryption/encrypt-path-structure.md#footer-field
        //= type=test
        //= reason=the value is exactly the recipient tag plus, for ECDSA suites, the signature
        //# The Footer Field Value MUST be the serialized [footer](footer.md).
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

        //= spec/structured-encryption/encrypt-path-structure.md#algorithm-suite
        //= type=test
        //= reason=each requested suite is the one the item is encrypted with
        //# The [algorithm suite](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md) that SHOULD be used for encryption.
        assert_eq!(dec.parsed_header().algorithm_suite_id(), suite);
    }
}

#[tokio::test]
async fn default_suite_signs_with_ecdsa() {
    //= spec/structured-encryption/encrypt-structure.md#input
    //= type=test
    //= reason=neither the algorithm suite nor the encryption context is set, and encrypt succeeds
    //# The following inputs to this behavior MUST be OPTIONAL:
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
        //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
        //= type=test
        //# Otherwise, this Terminal Data MUST have [Terminal Type ID](./structures.md#terminal-type-id)
        //# and [Terminal Value](./structures.md#terminal-value) equal to the input Terminal Data's.
        assert_eq!(&data[*name], value, "{name} stays plaintext");
    }

    let header = enc.parsed_header();
    let ec = header.encryption_context().clone();
    assert_eq!(ec.get("caller"), Some("ec"));
    assert_eq!(ec.get("aws-crypto-attr.b"), Some("//8BAg=="));
    assert_eq!(ec.get("aws-crypto-attr.f"), Some("false"));
    assert_eq!(ec.get("aws-crypto-attr.n"), Some("12.5"));

    //= spec/structured-encryption/structures.md#sign-and-include-in-encryption-context
    //= type=test
    //# and further that the [Terminal Data](#terminal-data) MUST be included in the encryption context.
    assert_eq!(ec.get("aws-crypto-attr.s"), Some("abc"));
    assert_eq!(ec.get("aws-crypto-attr.t"), Some("true"));
    assert_eq!(ec.get("aws-crypto-attr.u"), Some("null"));

    // One legend character per attribute entry, in key order: b f n s t u.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= type=test
    //# The Legend MUST be named "aws-crypto-legend" and be a string with one character per attribute added above,
    //# with a one-to-one correspondence with the attributes sorted by their UTF8 encoding,
    //# each character designating the original type of the attribute,
    //# to allow reversing of the [encoding](../dynamodb-encryption-client/encrypt-item.md#base-context-value-version-2).
    assert_eq!(ec.get("aws-crypto-legend"), Some("BLNSLL"));
    // The default suite also adds the ECDSA public key.
    assert!(ec.contains_key("aws-crypto-public-key"));

    //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= type=test
    //= reason=6 attribute entries + the legend + the caller's entry + the ECDSA public key
    //# Otherwise, this operation MUST add an [entry](../dynamodb-encryption-client/encrypt-item.md#base-context-value-version-2) to the encryption context for every
    //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT Crypto Action](./structures.md#sign_and_include_in_encryption_context)
    //# [Terminal Data](./structures.md#terminal-data)
    //# in the input record, plus the Legend.
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

    //= spec/structured-encryption/encrypt-path-structure.md#calculate-intermediate-encrypted-structured-data
    //= type=test
    //= reason=the fields come out sorted by canonical path, one per input field
    //# For every entry
    //# in the input [Crypto List](#crypto-list)
    //# there MUST be an entry with the same [canonical path](./header.md#canonical-path)
    //# in Intermediate Encrypted Structured Data.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#calculate-intermediate-encrypted-structured-data
    //= type=test
    //# There MUST be no other entries in the Intermediate Encrypted Structured Data.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
    //= type=test
    //# - For every entry in the input [Crypto List](#crypto-list)
    //# an entry MUST exist with the same [path](./structures.md#path) in the final Encrypted Structured Data.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
    //= type=test
    //# - The [Header Field](#header-field) MUST exist in the final Encrypted Structured Data
    //
    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
    //= type=test
    //# - The [Footer Field](#footer-field) MUST exist in the final Encrypted Structured Data
    //
    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
    //= type=test
    //# - For every entry in the final Encrypted Structured Data, other than the header and footer,
    //# an entry MUST exist with the same [path](./structures.md#path) in the input [Crypto List](#crypto-list).
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

    //= spec/structured-encryption/encrypt-path-structure.md#output
    //= type=test
    //= reason=the output holds the encrypted list (asserted above) and the parsed header
    //# This operation MUST output the following:
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
    //
    //= spec/structured-encryption/encrypt-path-structure.md#calculate-intermediate-encrypted-structured-data
    //= type=test
    //= reason=distinct ids across identical encrypts; a fixed or weak id would repeat
    //# The process used to generate this identifier MUST use a good source of randomness
    //# to make the chance of duplicate identifiers negligible.
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

    //= spec/structured-encryption/resolve-auth-actions.md#output
    //= type=test
    //= reason=canonical order: by name length, then by name
    //# This operation MUST output the following:
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

fn context(pairs: &[(&str, &str)]) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for (k, v) in pairs {
        ec.insert(*k, *v);
    }
    ec
}

#[tokio::test]
async fn get_encryption_materials_is_called_once_with_the_spec_inputs() {
    // Two encrypted fields of 13 and 5 bytes; the large SIGN_ONLY and DO_NOTHING values
    // must not count toward the max plaintext length.
    let input = vec![
        CryptoItem::new(path(&["foo"]), blob(), CryptoAction::EncryptAndSign),
        CryptoItem::new(
            path(&["five"]),
            StructuredDataTerminal::new(STRING, b"12345".to_vec()),
            CryptoAction::EncryptAndSign,
        ),
        CryptoItem::new(
            path(&["bar"]),
            StructuredDataTerminal::new(STRING, vec![b'x'; 100]),
            CryptoAction::SignOnly,
        ),
        CryptoItem::new(path(&["fizzbuzz"]), blob(), CryptoAction::DoNothing),
    ];
    let (cmm, calls) = recording_cmm(OnEncrypt::Forward);
    client()
        .encrypt_path_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(input))
        .cmm(cmm)
        .algorithm_suite_id(SYMMETRIC_SUITE)
        .encryption_context("some", "value")
        .send()
        .await
        .unwrap();
    let calls = calls.lock().unwrap();

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //# This operation MUST obtain a set of encryption materials by calling
    //# [Get Encryption Materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cmm-interface.md#get-encryption-materials)
    //# on the [CMM](#cmm) calculated above.
    assert_eq!(calls.len(), 1);
    let input = &calls[0];

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //= reason=the recorded request has the context, policy, suite, and length asserted below
    //# This operation MUST call Get Encryption Materials on the CMM as follows.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= type=test
    //= reason=the caller's context reaches the input CMM as given, with no required keys added
    //# If no [Crypto Action](./structures.md#crypto-action) is configured to be
    //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT Crypto Action](./structures.md#sign_and_include_in_encryption_context)
    //# then the input cmm and encryption context MUST be used unchanged.
    assert_eq!(
        (
            input.encryption_context(),
            input.required_encryption_context_keys()
        ),
        (&context(&[("some", "value")]), None)
    );

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //# - Commitment Policy: This MUST be
    //# [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/commitment-policy.md#esdkrequire_encrypt_require_decrypt).
    assert_eq!(
        input.commitment_policy(),
        CommitmentPolicy::Dbe(DbeCommitmentPolicy::RequireEncryptRequireDecrypt)
    );
    assert_eq!(
        input.algorithm_suite_id(),
        Some(MplAlgorithmSuiteId::Dbe(SYMMETRIC_SUITE))
    );

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //= reason=2 encrypted fields * 2 + (13 + 5) bytes; signed and unsigned fields are not counted
    //# - Max Plaintext Length: This field MUST be the result of the calculation `encryptedTerminalDataNum * 2 + totalEncryptedTerminalValuesSize`
    assert_eq!(input.max_plaintext_length(), Some(22));
}

#[tokio::test]
async fn sign_and_include_wraps_the_cmm_in_a_required_context_cmm() {
    let (cmm, calls) = recording_cmm(OnEncrypt::Forward);
    client()
        .encrypt_path_structure()
        .table_name(TABLE)
        .plaintext_structure(CryptoItem::new(
            path(&["pk", "x"]),
            StructuredDataTerminal::new(STRING, b"a".to_vec()),
            CryptoAction::SignAndIncludeInEncryptionContext,
        ))
        .cmm(cmm)
        .encryption_context("caller", "ec")
        .send()
        .await
        .unwrap();
    let calls = calls.lock().unwrap();
    let [input] = calls.as_slice() else {
        panic!("expected one call, got {}", calls.len());
    };

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //# This operation MUST [calculate the appropriate CMM and encryption context](#create-new-encryption-context-and-cmm).
    //
    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //# - Encryption Context: This MUST be the encryption context calculated above.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#encryption-context-naming
    //= type=test
    //# When a key-value pair is added to the encryption context,
    //# the key MUST be the concatenation of the literal
    //# "aws-crypto-attr." and the member strings of the
    //# path joined by the '.' character.
    assert_eq!(
        input.encryption_context(),
        &context(&[
            ("caller", "ec"),
            ("aws-crypto-attr.pk.x", "a"),
            ("aws-crypto-legend", "S"),
        ])
    );

    //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= type=test
    //= reason=only a required encryption context CMM adds required keys before the input CMM
    //# Then, this operation MUST create a [Required Encryption Context CMM](https://github.com/awslabs/private-aws-encryption-sdk-specification-staging/blob/dafny-verified/framework/required-encryption-context-cmm.md)
    //# with the following inputs:
    assert_eq!(
        input.required_encryption_context_keys(),
        Some(&BTreeSet::from([
            "aws-crypto-attr.pk.x".to_owned(),
            "aws-crypto-legend".to_owned(),
        ]))
    );
}

#[tokio::test]
async fn materials_suite_is_used_even_when_it_differs_from_the_input() {
    // The CMM asks for the symmetric suite though the caller asked for ECDSA.
    let (overriding, calls) = recording_cmm(OnEncrypt::OverrideSuite(MplAlgorithmSuiteId::Dbe(
        SYMMETRIC_SUITE,
    )));
    let enc = client()
        .encrypt_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(test_structured_data()))
        .set_crypto_schema(Some(test_crypto_schema()))
        .cmm(overriding)
        .algorithm_suite_id(SIGNING_SUITE)
        .send()
        .await
        .unwrap();
    assert_eq!(
        calls.lock().unwrap()[0].algorithm_suite_id(),
        Some(MplAlgorithmSuiteId::Dbe(SIGNING_SUITE))
    );

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //# Note that the algorithm suite in the retrieved encryption materials MAY be different from the input algorithm suite.
    assert_eq!(enc.parsed_header().algorithm_suite_id(), SYMMETRIC_SUITE);
    let data = enc.encrypted_structure();
    // Header: version 1, then flavor 0 (no ECDSA).
    assert_eq!(&data[HEADER].value()[..2], &[1, 0]);

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //= reason=the footer has no ECDSA signature, as the materials' suite has none
    //# The algorithm suite used in all aspects of this operation MUST be
    //# the algorithm suite in the
    //# [encryption materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#encryption-materials)
    //# returned from the Get Encryption Materials call.
    assert_eq!(data[FOOTER].value().len(), TAG_LEN);

    let dec = client()
        .decrypt_structure()
        .table_name(TABLE)
        .set_encrypted_structure(Some(enc.into_encrypted_structure()))
        .set_authenticate_schema(Some(test_authenticate_schema()))
        .cmm(cmm())
        .send()
        .await
        .unwrap();
    assert_eq!(dec.plaintext_structure(), &test_structured_data());
}

#[tokio::test]
async fn encrypt_path_structure_needs_no_suite_or_context() {
    let (cmm, calls) = recording_cmm(OnEncrypt::Forward);

    //= spec/structured-encryption/encrypt-path-structure.md#input
    //= type=test
    //= reason=neither the algorithm suite nor the encryption context is set, and encrypt succeeds
    //# The following inputs to this behavior MUST be OPTIONAL:
    let enc = client()
        .encrypt_path_structure()
        .table_name(TABLE)
        .plaintext_structure(CryptoItem::new(
            path(&["a"]),
            blob(),
            CryptoAction::EncryptAndSign,
        ))
        .cmm(cmm)
        .send()
        .await
        .unwrap();

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //# - Algorithm Suite: If provided, this is the [input algorithm suite](#algorithm-suite);
    //# otherwise, this field MUST be the algorithm suite corresponding to the enum
    //# [DBE.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#supported-algorithm-suites-enum).
    assert_eq!(
        calls.lock().unwrap()[0].algorithm_suite_id(),
        Some(MplAlgorithmSuiteId::Dbe(SIGNING_SUITE))
    );
    assert_eq!(enc.parsed_header().algorithm_suite_id(), SIGNING_SUITE);
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
