// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ItemKeyBranchKeySupplier`: the item key a supplier sees for each encryption context.
//! Ported from `DynamoDbEncryptionBranchKeyIdSupplierTest.dfy` (with an in-test supplier
//! instead of a key store) and from the selector contexts of `DynamoDBItemEncryptorTest.dfy`.

mod item_encryptor_support;

use std::sync::{Arc, Mutex};

use aws_db_esdk::async_trait;
use aws_db_esdk::aws_sdk_dynamodb::primitives::Blob;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::{
    BranchKeySupplier, GetBranchKeyIdFromItemKeyInput, GetBranchKeyIdInput, GetBranchKeyIdOutput,
    ItemKeyBranchKeySupplier, ItemKeySupplier,
};
use aws_db_esdk::mpl::Error as MplError;
use aws_db_esdk::types::{CryptoAction, EncryptionContext};
use item_encryptor_support::*;

const BRANCH_KEY_ID_A: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
const BRANCH_KEY_ID_B: &str = "4bb57643-07c1-419e-92ad-0df0df149d7c";

/// The Dafny `TestBranchKeyIdSupplier`: picks a branch key from the `branchKey` attribute,
/// and records the item key it was given.
#[derive(Default, Clone)]
struct TestSupplier {
    seen: Arc<Mutex<Vec<Item>>>,
}

#[async_trait]
impl ItemKeySupplier for TestSupplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdFromItemKeyInput,
    ) -> Result<GetBranchKeyIdOutput, MplError> {
        self.seen.lock().unwrap().push(input.item_key().clone());
        match input.into_item_key().get("branchKey") {
            Some(AttributeValue::S(v)) if v == "CASE_A" => Ok(BRANCH_KEY_ID_A.into()),
            Some(AttributeValue::S(v)) if v == "CASE_B" => GetBranchKeyIdOutput::builder()
                .branch_key_id(BRANCH_KEY_ID_B)
                .build(),
            _ => Err(MplError::validation(
                "Can't determine branchKeyId from item",
            )),
        }
    }
}

/// Call the supplier with `ec`; returns the result and the item key it saw.
async fn select(ec: EncryptionContext) -> (Result<String, MplError>, Option<Item>) {
    let inner = TestSupplier::default();
    let supplier = ItemKeyBranchKeySupplier::new(inner.clone());
    let input = GetBranchKeyIdInput::builder()
        .encryption_context(ec)
        .build()
        .unwrap();
    let result = supplier
        .get_branch_key_id(input)
        .await
        .map(GetBranchKeyIdOutput::into_branch_key_id);
    let seen = inner.seen.lock().unwrap().pop();
    (result, seen)
}

/// The error message when the context is rejected before the supplier is called.
async fn rejection(ec: EncryptionContext) -> String {
    match select(ec).await {
        (Err(MplError::Validation(e)), None) => e.message().to_owned(),
        other => panic!("expected a Validation error before the supplier, got {other:?}"),
    }
}

fn ec<const N: usize>(pairs: [(&str, &str); N]) -> EncryptionContext {
    pairs.into_iter().collect()
}

#[tokio::test]
async fn picks_branch_key_from_v1_context() {
    // "CASE_A" and "CASE_B" as DynamoDB strings: type 0x0001, then the UTF-8 bytes, base64.
    let (id, seen) = select(ec([
        ("aws-crypto-partition-name", "branchKey"),
        ("aws-crypto-attr.branchKey", "AAFDQVNFX0E="),
    ]))
    .await;
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //= reason=CASE_A is only in aws-crypto-attr.branchKey; a different value picks another key
    //# - It MUST get the serialized partition value by grabbing the `aws-crypto-attr.<partition_name>` from the encryption context.
    assert_eq!(id.unwrap(), BRANCH_KEY_ID_A);

    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //# - It MUST deserialize the "aws-crypto-partition-name" value in the input encryption context to determine the partition name.
    assert_eq!(seen.unwrap(), item([("branchKey", s("CASE_A"))]));

    let (id, _) = select(ec([
        ("aws-crypto-partition-name", "branchKey"),
        ("aws-crypto-attr.branchKey", "AAFDQVNFX0I="),
    ]))
    .await;

    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //# - If successful, the resulting string MUST be outputted by this operation.
    assert_eq!(id.unwrap(), BRANCH_KEY_ID_B);
}

#[tokio::test]
async fn supplier_errors_pass_through_unchanged() {
    // "CASE_C": a value TestSupplier has no key for.
    let (result, seen) = select(ec([
        ("aws-crypto-partition-name", "branchKey"),
        ("aws-crypto-attr.branchKey", "AAFDQVNFX0M="),
    ]))
    .await;
    match result {
        Err(MplError::Validation(e)) => {
            //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
            //= type=test
            //# - Otherwise, this operation MUST fail.
            assert_eq!(e.message(), "Can't determine branchKeyId from item");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(seen.unwrap(), item([("branchKey", s("CASE_C"))]));
}

/// The item key the supplier sees for the context of an item encrypted by `encryptor`.
async fn item_key_for(encryptor: &aws_db_esdk::ItemEncryptor, input: Item) -> Item {
    let out = encryptor
        .encrypt_item()
        .plaintext_item(input)
        .send()
        .await
        .unwrap();
    let ec = out.parsed_header().unwrap().encryption_context().clone();
    select(ec).await.1.unwrap()
}

#[tokio::test]
async fn item_key_of_v1_item_is_its_primary_key() {
    // Dafny TestRoundTrip's selectorContext.
    let key = item_key_for(&default_encryptor(), v1_item()).await;
    assert_eq!(key, item([("bar", s("key"))]));
}

#[tokio::test]
async fn item_key_of_v1_item_with_sort_key() {
    let mut acts = v1_actions();
    acts.insert("sort".to_owned(), CryptoAction::SignOnly);
    let encryptor = encryptor_from(config_builder(acts).sort_key_name("sort"));
    let mut input = v1_item();
    input.insert("sort".to_owned(), AttributeValue::N("7".to_owned()));
    let key = item_key_for(&encryptor, input).await;
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //# - It MUST check for the existence of "aws-crypto-sort-name" in the input encryption context.
    //
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //# - If this key exists, it MUST get the serialized sort value by grabbing the `aws-crypto.attr:<sort_name>` from the encryption context.
    //
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //# - If the field "aws-crypto-legend" does not exist in the encryption context, it MUST [deserialize the partition (and optionally sort) value](./ddb-attribute-serialization.md), and create a Key with these values.
    assert_eq!(
        key,
        item([
            ("bar", s("key")),
            ("sort", AttributeValue::N("7".to_owned()))
        ])
    );
}

#[tokio::test]
async fn item_key_of_v2_item_has_context_attributes_and_names() {
    // Dafny TestV2RoundTrip's selectorContext.
    let encryptor = encryptor_from(config_builder(v2_actions()));
    let input = item([
        ("bar", s("key")),
        ("encrypt", s("text")),
        ("sign", s("barsoom")),
        ("nothing", s("baz")),
    ]);
    assert_eq!(
        item_key_for(&encryptor, input).await,
        item([
            ("bar", s("key")),
            ("sign", s("barsoom")),
            ("aws_dbe_table_name", s("foo")),
            ("aws_dbe_partition_name", s("bar")),
        ])
    );
}

#[tokio::test]
async fn item_key_of_complex_v2_item() {
    // Dafny TestV2RoundTripComplex's selectorContext.
    let acts = actions([
        ("bar", CryptoAction::SignAndIncludeInEncryptionContext),
        ("sortKey", CryptoAction::SignAndIncludeInEncryptionContext),
        ("encrypt", CryptoAction::EncryptAndSign),
        ("sign", CryptoAction::SignAndIncludeInEncryptionContext),
        ("sign3", CryptoAction::SignAndIncludeInEncryptionContext),
        ("sign4", CryptoAction::SignAndIncludeInEncryptionContext),
        ("nothing", CryptoAction::DoNothing),
    ]);
    let encryptor = encryptor_from(config_builder(acts).sort_key_name("sortKey"));
    let input = item([
        ("bar", AttributeValue::N("1234".to_owned())),
        ("sortKey", AttributeValue::B(Blob::new(vec![1, 2, 3, 4]))),
        ("encrypt", s("text")),
        ("sign", AttributeValue::Bool(true)),
        ("sign3", AttributeValue::Bool(false)),
        ("sign4", AttributeValue::Null(true)),
        ("nothing", s("baz")),
    ]);
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#dynamodbkeybranchkeyidsupplier
    //= type=test
    //# This operation MUST take in a DDB `Key` structure
    //# (an attribute map containing the partition and sort attributes,
    //# along with the values of any attributes configured as SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT)
    //# as input.
    //
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //# - If the field "aws-crypto-legend" exists in the encryption context,
    //# it MUST [deserialize](./ddb-attribute-serialization.md), all values with keys beginning "aws-crypto-attr.",
    //# and create a Key with these values, using names with the "aws-crypto-attr." removed.
    assert_eq!(
        item_key_for(&encryptor, input).await,
        item([
            ("bar", AttributeValue::N("1234".to_owned())),
            ("sortKey", AttributeValue::B(Blob::new(vec![1, 2, 3, 4]))),
            ("sign", AttributeValue::Bool(true)),
            ("sign3", AttributeValue::Bool(false)),
            ("sign4", AttributeValue::Null(true)),
            ("aws_dbe_table_name", s("foo")),
            ("aws_dbe_partition_name", s("bar")),
            ("aws_dbe_sort_name", s("sortKey")),
        ])
    );
}

#[tokio::test]
async fn rejects_context_without_partition_name() {
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //# - If the partition name does not exist in the encryption context, this operation MUST fail.
    assert_eq!(
        rejection(ec([])).await,
        "Invalid encryption context: Missing partition name"
    );
}

#[tokio::test]
async fn rejects_context_without_partition_value() {
    let context = ec([("aws-crypto-partition-name", "bar")]);
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //# - If the partition value does not exist in the encryption context, this operation MUST fail.
    assert_eq!(
        rejection(context).await,
        "Invalid encryption context: Missing partition value"
    );
}

#[tokio::test]
async fn rejects_context_without_sort_value() {
    let context = ec([
        ("aws-crypto-partition-name", "bar"),
        // "key" as a DynamoDB string: type 0x0001 + UTF-8, base64.
        ("aws-crypto-attr.bar", "AAFrZXk="),
        ("aws-crypto-sort-name", "sort"),
    ]);
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //= type=test
    //# - If the sort value does not exist in the context, this operation MUST fail.
    assert_eq!(
        rejection(context).await,
        "Invalid encryption context: Missing sort value"
    );
}

#[tokio::test]
async fn rejects_malformed_contexts() {
    // Adjacent guard for #behavior "If the field \"aws-crypto-legend\" exists ... it MUST deserialize"
    // and "... does not exist ... it MUST deserialize": a context that cannot be deserialized fails.
    // No spec rule names these errors, so no requirement is cited here.
    let base = ("aws-crypto-partition-name", "bar");
    let v2 = [
        ("aws-crypto-table-name", "foo"),
        ("aws-crypto-partition-name", "bar"),
        ("aws-crypto-attr.bar", "key"),
    ];
    let cases: Vec<(EncryptionContext, &str)> = vec![
        (
            ec([base, ("aws-crypto-attr.bar", "!!!")]),
            "Invalid base64 in encryption context: Invalid symbol 33, offset 0.",
        ),
        (
            // One byte: too short for a type id.
            ec([base, ("aws-crypto-attr.bar", "AA==")]),
            "Invalid serialization of DDB Attribute in encryption context.",
        ),
        (
            ec([v2[0], v2[1], v2[2], ("aws-crypto-legend", "")]),
            "Encryption Context Legend is too short.",
        ),
        (
            ec([v2[0], v2[1], v2[2], ("aws-crypto-legend", "SS")]),
            "Encryption Context Legend is too long.",
        ),
        (
            ec([v2[0], v2[1], v2[2], ("aws-crypto-legend", "X")]),
            "Encryption Context Legend has unexpected character : 'X'.",
        ),
        (
            ec([
                v2[0],
                v2[1],
                ("aws-crypto-attr.bar", "maybe"),
                ("aws-crypto-legend", "L"),
            ]),
            "Encryption Context literal value has unexpected value : 'maybe'.",
        ),
        (
            ec([v2[1], v2[2], ("aws-crypto-legend", "S")]),
            "Internal error, table name not in encryption context.",
        ),
    ];
    for (context, expected) in cases {
        assert_eq!(rejection(context).await, expected);
    }
}

#[tokio::test]
async fn rejects_attribute_name_over_65535_characters() {
    // Adjacent guard: the rebuilt Key must hold valid DynamoDB attribute names
    // (cf. ddb-item-conversion "MUST NOT have any Key strings ... more than 65535 characters");
    // no rule of this spec covers it.
    // "key" as a DynamoDB string: type 0x0001 + UTF-8, base64.
    let context_named = |name: &str| {
        let key = format!("aws-crypto-attr.{name}");
        ec([
            ("aws-crypto-partition-name", name),
            (key.as_str(), "AAFrZXk="),
        ])
    };

    let at_limit = "a".repeat(65_535);
    let (_, seen) = select(context_named(&at_limit)).await;
    assert_eq!(seen.unwrap(), item([(at_limit.as_str(), s("key"))]));

    assert_eq!(
        rejection(context_named(&"a".repeat(65_536))).await,
        "Invalid serialization of DDB Attribute in encryption context."
    );
}

#[tokio::test]
async fn decodes_v2_binary_and_skips_the_bare_prefix() {
    // A 'B' legend entry holds a base64 terminal; a key that is only the prefix is not an attribute.
    let context = ec([
        ("aws-crypto-table-name", "foo"),
        ("aws-crypto-partition-name", "bar"),
        ("aws-crypto-attr.bar", "//8BAgME"),
        ("aws-crypto-attr.", "ignored"),
        ("aws-crypto-legend", "B"),
    ]);
    let (_, seen) = select(context).await;
    assert_eq!(
        seen.unwrap(),
        item([
            ("bar", AttributeValue::B(Blob::new(vec![1, 2, 3, 4]))),
            ("aws_dbe_table_name", s("foo")),
            ("aws_dbe_partition_name", s("bar")),
        ])
    );
}

#[test]
fn item_key_input_builder() {
    let input = GetBranchKeyIdFromItemKeyInput::builder()
        .item_key("a", s("1"))
        .item_key("b", s("2"))
        .build()
        .unwrap();
    assert_eq!(input.item_key(), &item([("a", s("1")), ("b", s("2"))]));

    let builder =
        GetBranchKeyIdFromItemKeyInput::builder().set_item_key(Some(item([("c", s("3"))])));
    assert_eq!(builder.get_item_key(), &Some(item([("c", s("3"))])));
    assert_eq!(
        builder.build().unwrap().into_item_key(),
        item([("c", s("3"))])
    );

    match GetBranchKeyIdFromItemKeyInput::builder().build() {
        Err(aws_db_esdk::Error::Validation(e)) => assert_eq!(e.message(), "item_key is required"),
        other => panic!("{other:?}"),
    }
    let supplier = ItemKeyBranchKeySupplier::new(TestSupplier::default());
    assert_eq!(format!("{supplier:?}"), "ItemKeyBranchKeySupplier { .. }");
}
