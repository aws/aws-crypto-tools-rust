// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Round trips through `ItemEncryptor`, ported from `DynamoDBItemEncryptorTest.dfy`.

mod item_encryptor_support;

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::primitives::Blob;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::cmm::DefaultCmm;
use aws_db_esdk::types::{AlgorithmSuiteId, CryptoAction};
use aws_db_esdk::{ItemEncryptor, ParsedHeader};
use item_encryptor_support::*;

/// Encrypt `input`, check which attributes changed, decrypt, and return the decrypt header.
async fn round_trip(
    encryptor: &ItemEncryptor,
    decryptor: &ItemEncryptor,
    input: &Item,
    encrypted_names: &[&str],
) -> (Item, ParsedHeader) {
    let encrypted = encryptor
        .encrypt_item()
        .plaintext_item(input.clone())
        .send()
        .await
        .unwrap();
    let out = encrypted.encrypted_item();
    let mut expected_keys: Vec<&str> = input.keys().map(String::as_str).collect();
    expected_keys.extend([HEADER, FOOTER]);
    expected_keys.sort_unstable();
    let mut keys: Vec<&str> = out.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, expected_keys);
    for (name, value) in input {
        if encrypted_names.contains(&name.as_str()) {
            assert!(
                matches!(&out[name], AttributeValue::B(_)),
                "{name} not encrypted"
            );
            assert_ne!(&out[name], value);
        } else {
            assert_eq!(&out[name], value, "{name} changed");
        }
    }
    let encrypt_header = encrypted.parsed_header().unwrap().clone();
    assert_eq!(
        encrypted.algorithm_suite_id(),
        encrypt_header.algorithm_suite_id()
    );
    let ciphertext = encrypted.into_encrypted_item();

    let decrypted = decryptor
        .decrypt_item()
        .encrypted_item(ciphertext.clone())
        .send()
        .await
        .unwrap();
    let header = decrypted.parsed_header().unwrap().clone();
    assert_eq!(decrypted.plaintext_item(), input);
    assert_eq!(decrypted.into_plaintext_item(), *input);
    // Encrypt and decrypt describe the same header.
    assert_eq!(
        header.encryption_context(),
        encrypt_header.encryption_context()
    );
    assert_eq!(
        header.stored_encryption_context(),
        encrypt_header.stored_encryption_context()
    );
    assert_eq!(
        header.encrypted_data_keys(),
        encrypt_header.encrypted_data_keys()
    );
    (ciphertext, header)
}

/// The header checks that every Dafny round trip makes:
/// the default suite, only the verification key stored, and one data key.
fn assert_default_header(header: &ParsedHeader) {
    assert_eq!(header.algorithm_suite_id(), DEFAULT_SUITE);
    let stored: Vec<&str> = header.stored_encryption_context().keys().collect();
    assert_eq!(stored, ["aws-crypto-public-key"]);
    assert_eq!(header.encrypted_data_keys().len(), 1);
    assert_eq!(header.encrypted_data_keys()[0].key_provider_id(), "foo");
}

fn without(
    mut actions: HashMap<String, CryptoAction>,
    names: &[&str],
) -> HashMap<String, CryptoAction> {
    for n in names {
        actions.remove(*n);
    }
    actions
}

#[tokio::test]
async fn round_trip_v1() {
    let encryptor = default_encryptor();
    let (_, header) = round_trip(&encryptor, &encryptor, &v1_item(), &["encrypt"]).await;
    assert_default_header(&header);
    assert_eq!(
        header.attribute_actions_on_encrypt(),
        &actions([
            ("bar", CryptoAction::SignOnly),
            ("encrypt", CryptoAction::EncryptAndSign),
            ("sign", CryptoAction::SignOnly),
        ])
    );
    assert_eq!(
        context_without_public_key(header.encryption_context()),
        strings([
            ("aws-crypto-attr.bar", "AAFrZXk="),
            ("aws-crypto-partition-name", "bar"),
            ("aws-crypto-table-name", "foo"),
        ])
    );
}

#[tokio::test]
async fn round_trip_v2() {
    let encryptor = encryptor_from(config_builder(v2_actions()));
    let input = item([
        ("bar", s("key")),
        ("encrypt", s("text")),
        ("sign", s("barsoom")),
        ("nothing", s("baz")),
    ]);
    let (_, header) = round_trip(&encryptor, &encryptor, &input, &["encrypt"]).await;
    assert_default_header(&header);
    assert_eq!(
        header.attribute_actions_on_encrypt(),
        &without(v2_actions(), &["nothing"])
    );

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-2
    //= type=test
    //= reason=The legend and attr entries come from Encrypt Structure; the rest is the base context
    //# The DynamoDB Item Base Context MUST contain:
    assert_eq!(
        context_without_public_key(header.encryption_context()),
        strings([
            ("aws-crypto-legend", "SS"),
            ("aws-crypto-attr.bar", "key"),
            ("aws-crypto-attr.sign", "barsoom"),
            ("aws-crypto-partition-name", "bar"),
            ("aws-crypto-table-name", "foo"),
        ])
    );

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-2
    //= type=test
    //# If this item does not have a sort key attribute,
    //# the DynamoDB Item Context MUST NOT contain the key `aws-crypto-sort-name`.
    assert!(
        !header
            .encryption_context()
            .contains_key("aws-crypto-sort-name")
    );
}

fn complex_actions() -> HashMap<String, CryptoAction> {
    actions([
        ("bar", CryptoAction::SignAndIncludeInEncryptionContext),
        ("sortKey", CryptoAction::SignAndIncludeInEncryptionContext),
        ("encrypt", CryptoAction::EncryptAndSign),
        ("sign", CryptoAction::SignAndIncludeInEncryptionContext),
        ("sign2", CryptoAction::SignOnly),
        ("sign3", CryptoAction::SignAndIncludeInEncryptionContext),
        ("sign4", CryptoAction::SignAndIncludeInEncryptionContext),
        ("nothing", CryptoAction::DoNothing),
    ])
}

fn complex_item(bar: &str) -> Item {
    item([
        ("bar", AttributeValue::N(bar.to_owned())),
        ("sortKey", AttributeValue::B(Blob::new(vec![1, 2, 3, 4]))),
        ("encrypt", s("text")),
        ("sign", AttributeValue::Bool(true)),
        ("sign3", AttributeValue::Bool(false)),
        ("sign4", AttributeValue::Null(true)),
        ("nothing", s("baz")),
    ])
}

fn complex_context() -> HashMap<String, String> {
    strings([
        ("aws-crypto-legend", "NLLLB"),
        ("aws-crypto-attr.bar", "1234"),
        ("aws-crypto-attr.sortKey", "//8BAgME"),
        ("aws-crypto-attr.sign", "true"),
        ("aws-crypto-attr.sign3", "false"),
        ("aws-crypto-attr.sign4", "null"),
        ("aws-crypto-partition-name", "bar"),
        ("aws-crypto-sort-name", "sortKey"),
        ("aws-crypto-table-name", "foo"),
    ])
}

#[tokio::test]
async fn round_trip_v2_complex() {
    let encryptor = encryptor_from(config_builder(complex_actions()).sort_key_name("sortKey"));
    let (_, header) = round_trip(&encryptor, &encryptor, &complex_item("1234"), &["encrypt"]).await;
    assert_default_header(&header);
    assert_eq!(
        header.attribute_actions_on_encrypt(),
        &without(complex_actions(), &["nothing", "sign2"])
    );

    //= spec/dynamodb-encryption-client/encrypt-item.md#base-context-value-version-2
    //= type=test
    //# The value MUST be :
    assert_eq!(
        context_without_public_key(header.encryption_context()),
        complex_context()
    );

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-2
    //= type=test
    //# If this item has a Sort Key attribute, the DynamoDB Item Base Context MUST contain:
    assert_eq!(
        header.encryption_context().get("aws-crypto-sort-name"),
        Some("sortKey")
    );
}

#[tokio::test]
async fn round_trip_v2_complex_decrypts_under_different_actions() {
    // The decrypt configuration has different actions.
    // Decrypt uses the actions in the header.
    let decrypt_actions = actions([
        ("bar", CryptoAction::SignAndIncludeInEncryptionContext),
        ("sortKey", CryptoAction::SignAndIncludeInEncryptionContext),
        ("encrypt", CryptoAction::EncryptAndSign),
        ("sign", CryptoAction::SignOnly),
        ("sign2", CryptoAction::SignAndIncludeInEncryptionContext),
        ("sign3", CryptoAction::SignOnly),
        ("sign4", CryptoAction::SignOnly),
        ("nothing", CryptoAction::DoNothing),
    ]);
    let encryptor = encryptor_for(complex_actions());
    let decryptor = encryptor_for(decrypt_actions);
    // Encrypt normalizes the number in the encryption context but leaves it as is in the item.
    let (_, header) = round_trip(
        &encryptor,
        &decryptor,
        &complex_item("00001234"),
        &["encrypt"],
    )
    .await;
    assert_default_header(&header);
    assert_eq!(
        header.attribute_actions_on_encrypt(),
        &without(complex_actions(), &["nothing", "sign2"])
    );
    assert_eq!(
        context_without_public_key(header.encryption_context()),
        complex_context()
    );

    fn encryptor_for(a: HashMap<String, CryptoAction>) -> ItemEncryptor {
        encryptor_from(config_builder(a).sort_key_name("sortKey"))
    }
}

#[tokio::test]
async fn round_trip_v2_special_attribute_names() {
    let names = [
        "bar", "a.b", ".a", "a.", ".a.", "a[2]", "a#b", "$", "$a", "$a.b", "$[a]", "$['a']",
        "$[\"a\"]", "(a)", "$['", "$'a'", "$\"a\"", "$(a)", "$(a",
    ];
    let values = [
        "key", "aaa", "bbb", "ccc", "ddd", "eee", "fff", "ggg", "hhh", "iii", "jjj", "kkk", "lll",
        "mmm", "nnn", "ooo", "ppp", "qqq", "rrr",
    ];
    let actions: HashMap<String, CryptoAction> = names
        .iter()
        .map(|n| {
            (
                n.to_string(),
                CryptoAction::SignAndIncludeInEncryptionContext,
            )
        })
        .collect();
    let input: Item = names
        .iter()
        .zip(values)
        .map(|(n, v)| (n.to_string(), s(v)))
        .collect();
    let encryptor = encryptor_from(config_builder(actions.clone()));
    let (_, header) = round_trip(&encryptor, &encryptor, &input, &[]).await;
    assert_default_header(&header);
    assert_eq!(header.attribute_actions_on_encrypt(), &actions);
    let mut expected: HashMap<String, String> = names
        .iter()
        .zip(values)
        .map(|(n, v)| (format!("aws-crypto-attr.{n}"), v.to_owned()))
        .collect();
    expected.extend(strings([
        ("aws-crypto-legend", "SSSSSSSSSSSSSSSSSSS"),
        ("aws-crypto-partition-name", "bar"),
        ("aws-crypto-table-name", "foo"),
    ]));

    //= spec/dynamodb-encryption-client/encrypt-item.md#base-context-value-version-2
    //= type=test
    //# The key MUST be as per [Encryption Context Naming]
    //# (../structured-encryption/encrypt-path-structure.md#encryption-context-naming).
    //
    //= spec/structured-encryption/encrypt-path-structure.md#encryption-context-naming
    //= type=test
    //# When a key-value pair is added to the encryption context,
    //# the key MUST be the concatenation of the literal
    //# "aws-crypto-attr." and the member strings of the
    //# path joined by the '.' character.
    assert_eq!(
        context_without_public_key(header.encryption_context()),
        expected
    );
}

#[tokio::test]
async fn round_trip_large_item() {
    let mut input = item([("bar", s("key"))]);
    let mut acts = actions([("bar", CryptoAction::SignOnly)]);
    for i in 0..500 {
        input.insert(i.to_string(), s(&i.to_string()));
        acts.insert(i.to_string(), CryptoAction::EncryptAndSign);
    }
    let encrypted_names: Vec<String> = (0..500).map(|i| i.to_string()).collect();
    let encrypted_names: Vec<&str> = encrypted_names.iter().map(String::as_str).collect();
    let encryptor = encryptor_from(config_builder(acts));
    let (_, header) = round_trip(&encryptor, &encryptor, &input, &encrypted_names).await;
    assert_default_header(&header);
}

#[tokio::test]
async fn round_trip_with_symsig_only_suite() {
    let suite = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384;
    let encryptor = encryptor_from(config_builder(v1_actions()).algorithm_suite_id(suite));
    let (_, header) = round_trip(&encryptor, &encryptor, &v1_item(), &["encrypt"]).await;
    assert_eq!(header.algorithm_suite_id(), suite);
    // Without ECDSA there is no verification key to store.
    assert!(header.stored_encryption_context().is_empty());
    assert!(
        !header
            .encryption_context()
            .contains_key("aws-crypto-public-key")
    );
}

#[tokio::test]
async fn round_trip_with_cmm_and_sort_key() {
    let mut acts = v1_actions();
    acts.insert("sort".to_owned(), CryptoAction::SignOnly);
    let config = config_builder(acts)
        .set_keyring(None)
        .cmm(DefaultCmm::new(keyring()))
        .sort_key_name("sort");
    let encryptor = encryptor_from(config);
    let mut input = v1_item();
    input.insert("sort".to_owned(), AttributeValue::N("7".to_owned()));
    let (_, header) = round_trip(&encryptor, &encryptor, &input, &["encrypt"]).await;
    assert_default_header(&header);
    let ec = context_without_public_key(header.encryption_context());

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-1
    //= type=test
    //# If this item has a Sort Key attribute, the DynamoDB Item Base Context MUST contain:
    assert_eq!(ec["aws-crypto-sort-name"], "sort");

    //= spec/dynamodb-encryption-client/encrypt-item.md#base-context-value-version-1
    //= type=test
    //# The value MUST be the UTF8 Encoding of the
    //# [Base 64 encoded](https://www.rfc-editor.org/rfc/rfc4648),
    //# of the concatenation of the bytes `typeID + serializedValue`
    //# where `typeId` is the attribute's [type ID](./ddb-attribute-serialization.md#type-id)
    //# and `serializedValue` is the attribute's value serialized according to
    //# [Attribute Value Serialization](./ddb-attribute-serialization.md#attribute-value-serialization).
    assert_eq!(
        ec,
        strings([
            // 0x0001 (string) followed by "key"
            ("aws-crypto-attr.bar", "AAFrZXk="),
            // 0x0002 (number) followed by "7"
            ("aws-crypto-attr.sort", "AAI3"),
            ("aws-crypto-partition-name", "bar"),
            ("aws-crypto-sort-name", "sort"),
            ("aws-crypto-table-name", "foo"),
        ])
    );
}

#[tokio::test]
async fn logical_table_name_overrides_table_name() {
    let encryptor = encryptor_from(config_builder(v1_actions()).logical_table_name("logical"));
    let (ciphertext, header) = round_trip(&encryptor, &encryptor, &v1_item(), &["encrypt"]).await;
    assert_eq!(
        header.encryption_context().get("aws-crypto-table-name"),
        Some("logical")
    );
    // An encryptor bound to the physical name "foo" cannot decrypt it.
    let err = default_encryptor()
        .decrypt_item()
        .encrypted_item(ciphertext)
        .send()
        .await
        .unwrap_err();
    assert!(
        matches!(err, aws_db_esdk::Error::Cryptographic(_)),
        "{err:?}"
    );
}

#[tokio::test]
async fn unsigned_prefix_attributes_pass_through_unsigned() {
    let encryptor =
        encryptor_from(config_builder(v1_actions()).allowed_unsigned_attribute_prefix(":"));
    let mut input = v1_item();
    input.insert(":free".to_owned(), s("form"));
    let (mut ciphertext, header) = round_trip(&encryptor, &encryptor, &input, &["encrypt"]).await;
    // An unconfigured unsigned attribute is not in the header's signed actions.
    assert!(!header.attribute_actions_on_encrypt().contains_key(":free"));
    // Changing or adding unsigned attributes does not break the signature.
    ciphertext.insert(":free".to_owned(), s("changed"));
    ciphertext.insert("nothing".to_owned(), s("changed"));
    ciphertext.insert(":new".to_owned(), s("added"));
    let decrypted = encryptor
        .decrypt_item()
        .encrypted_item(ciphertext)
        .send()
        .await
        .unwrap();
    let mut expected = input;
    expected.insert(":free".to_owned(), s("changed"));
    expected.insert("nothing".to_owned(), s("changed"));
    expected.insert(":new".to_owned(), s("added"));

    //= spec/dynamodb-encryption-client/decrypt-item.md#signature-scope
    //= type=test
    //= reason=Changed and added unauthenticated attributes still verify, so they are outside the scope
    //# An Attribute on a DynamoDB Item MUST NOT be considered as within the signature scope
    //# if it's Attribute Name is included in [Unauthenticated Attributes](./ddb-table-encryption-config.md#unauthenticated-attributes)
    //# or if it's Attribute Name begins with the prefix specified in
    //# [Unauthenticated Attribute Prefix](./ddb-table-encryption-config.md#unauthenticated-attribute-prefix).
    assert_eq!(decrypted.plaintext_item(), &expected);
}

#[tokio::test]
async fn round_trip_with_only_required_inputs() {
    let table = aws_db_esdk::TableConfig::builder()
        .partition_key_name("bar")
        .attribute_actions_on_encrypt("bar", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("encrypt", CryptoAction::EncryptAndSign)
        .keyring(keyring())
        .build()
        .unwrap();
    let built = ItemEncryptor::builder().table(TABLE, table).build();

    //= spec/dynamodb-encryption-client/ddb-item-encryptor.md#initialization
    //= type=test
    //= reason=No sort key, unsigned attributes, prefix, suite, or plaintext policy is set
    //# The following are OPTIONAL for the DynamoDB Item Encryptor:
    let encryptor = built.unwrap();
    let input = item([("bar", s("key")), ("encrypt", s("text"))]);
    round_trip(&encryptor, &encryptor, &input, &["encrypt"]).await;
}

#[tokio::test]
async fn set_item_builders_replace_the_item() {
    let encryptor = default_encryptor();
    let encrypted = encryptor
        .encrypt_item()
        .plaintext_item(item([("bar", s("other"))]))
        .set_plaintext_item(Some(v1_item()))
        .send()
        .await
        .unwrap();
    let decrypted = encryptor
        .decrypt_item()
        .set_encrypted_item(Some(encrypted.into_encrypted_item()))
        .send()
        .await
        .unwrap();
    assert_eq!(decrypted.plaintext_item(), &v1_item());
}

#[tokio::test]
async fn describes_data_keys_of_encrypted_item() {
    let encrypted = encrypt_v1().await;
    let descriptions = aws_db_esdk::describe_encrypted_data_keys(&encrypted).unwrap();
    assert_eq!(descriptions.len(), 1);
    // A raw keyring's provider id is its namespace; it has no branch key.
    assert_eq!(descriptions[0].key_provider_id(), "foo");
    assert_eq!(descriptions[0].key_provider_info(), None);
    assert_eq!(descriptions[0].branch_key_id(), None);
    assert_eq!(descriptions[0].branch_key_version(), None);
    let AttributeValue::B(header) = &encrypted[HEADER] else {
        panic!("header not binary");
    };
    assert_eq!(
        aws_db_esdk::describe_header_encrypted_data_keys(header.as_ref()).unwrap(),
        descriptions
    );
}

async fn encrypt_v1() -> Item {
    default_encryptor()
        .encrypt_item()
        .plaintext_item(v1_item())
        .send()
        .await
        .unwrap()
        .into_encrypted_item()
}
