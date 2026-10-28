// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests of beaconized expressions, ported from the Dafny DB-ESDK's `FilterExpr.dfy`,
//! `Beacon.dfy`, `BeaconPartition.dfy` and `DDBSupport.dfy`, with their fixtures
//! from `BeaconTestFixtures.dfy`.
//!
//! The Dafny tests read HMAC keys from a literal key source holding `[1, 2, 3, 4, 5]`.
//! Here a fake key store returns that beacon key, which yields the same HMAC keys,
//! so the Dafny beacon values carry over unchanged.

use std::time::Duration;

use aws_crypto_mpl::Error as MplError;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::key_store::KeyStore;
use aws_crypto_mpl::key_store::operation::create_key::{CreateKeyInput, CreateKeyOutput};
use aws_crypto_mpl::key_store::operation::create_key_store::{
    CreateKeyStoreInput, CreateKeyStoreOutput,
};
use aws_crypto_mpl::key_store::operation::get_active_branch_key::{
    GetActiveBranchKeyInput, GetActiveBranchKeyOutput,
};
use aws_crypto_mpl::key_store::operation::get_beacon_key::{GetBeaconKeyInput, GetBeaconKeyOutput};
use aws_crypto_mpl::key_store::operation::get_branch_key_version::{
    GetBranchKeyVersionInput, GetBranchKeyVersionOutput,
};
use aws_crypto_mpl::key_store::operation::get_key_store_info::{
    GetKeyStoreInfoInput, GetKeyStoreInfoOutput,
};
use aws_crypto_mpl::key_store::operation::version_key::{VersionKeyInput, VersionKeyOutput};
use aws_crypto_mpl::key_store::types::{Discovery, KmsConfiguration};
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::types::{BeaconKeyMaterials, EncryptionContext};

use super::*;
use crate::TableConfig;
use crate::search::convert::convert;
use crate::search::{
    BeaconKeySource, BeaconStyle, BeaconVersion, BeaconVersionBuilder, CompoundBeacon, Constructor,
    ConstructorPart, EncryptedPart, MultiKeyStore, SearchConfig, SignedPart, SingleKeyStore,
    StandardBeacon, VirtualField, VirtualPart, VirtualTransform,
};
use crate::types::AesWrappingAlg;

// Beacon values of the fixtures under the literal key [1, 2, 3, 4, 5].
const STD2_BEACON: &str = "ac6f5d";
const NAME_BEACON: &str = "7d9bfa40";
const TITLE_BEACON: &str = "e4feb833";
const STD4_BEACON: &str = "0e9064";
const STD6_BEACON: &str = "2d99222";
const NAME_TITLE_BEACON: &str = "4c577d7";
const EMPTY_NAME_BEACON: &str = "e0e88994";

/// A key store whose every beacon key is the Dafny tests' literal key.
struct LiteralKeyStore;

fn unused() -> MplError {
    MplError::validation("not used by these tests")
}

#[async_trait]
impl KeyStore for LiteralKeyStore {
    async fn get_key_store_info(
        &self,
        _input: GetKeyStoreInfoInput,
    ) -> Result<GetKeyStoreInfoOutput, MplError> {
        GetKeyStoreInfoOutput::builder()
            .key_store_id("test-id")
            .key_store_name("KeyStoreDdbTable")
            .logical_key_store_name("KeyStoreDdbTable")
            .grant_tokens(Vec::<String>::new())
            .kms_configuration(KmsConfiguration::Discovery(
                Discovery::builder().build().unwrap(),
            ))
            .build()
    }

    async fn create_key_store(
        &self,
        _input: CreateKeyStoreInput,
    ) -> Result<CreateKeyStoreOutput, MplError> {
        Err(unused())
    }

    async fn create_key(&self, _input: CreateKeyInput) -> Result<CreateKeyOutput, MplError> {
        Err(unused())
    }

    async fn version_key(&self, _input: VersionKeyInput) -> Result<VersionKeyOutput, MplError> {
        Err(unused())
    }

    async fn get_active_branch_key(
        &self,
        _input: GetActiveBranchKeyInput,
    ) -> Result<GetActiveBranchKeyOutput, MplError> {
        Err(unused())
    }

    async fn get_branch_key_version(
        &self,
        _input: GetBranchKeyVersionInput,
    ) -> Result<GetBranchKeyVersionOutput, MplError> {
        Err(unused())
    }

    async fn get_beacon_key(
        &self,
        input: GetBeaconKeyInput,
    ) -> Result<GetBeaconKeyOutput, MplError> {
        GetBeaconKeyOutput::builder()
            .beacon_key_materials(
                BeaconKeyMaterials::builder()
                    .beacon_key_id(input.branch_key_id())
                    .encryption_context(EncryptionContext::new())
                    .beacon_key(vec![1u8, 2, 3, 4, 5])
                    .build()?,
            )
            .build()
    }
}

// ---- fixtures (BeaconTestFixtures.dfy) ----

fn std_beacon(name: &str, bits: u8, loc: Option<&str>) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .set_location(loc.map(str::to_owned))
        .build()
        .unwrap()
}

fn partitioned(name: &str, bits: u8, partitions: u8) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .number_of_partitions(partitions)
        .build()
        .unwrap()
}

fn styled(name: &str, bits: u8, style: BeaconStyle) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .style(style)
        .build()
        .unwrap()
}

fn std2() -> StandardBeacon {
    std_beacon("std2", 24, None)
}

fn lotsa_standard() -> Vec<StandardBeacon> {
    vec![
        std2(),
        std_beacon("std4", 24, Some("std4")),
        std_beacon("std6", 26, Some("std6[0]")),
        std_beacon("NameTitleField", 28, None),
        std_beacon("Name", 32, None),
        std_beacon("Title", 32, None),
    ]
}

fn enc(name: &str, prefix: &str) -> EncryptedPart {
    EncryptedPart::builder()
        .name(name)
        .prefix(prefix)
        .build()
        .unwrap()
}

fn signed(name: &str, prefix: &str, loc: Option<&str>) -> SignedPart {
    SignedPart::builder()
        .name(name)
        .prefix(prefix)
        .set_location(loc.map(str::to_owned))
        .build()
        .unwrap()
}

fn compound(
    name: &str,
    encrypted: Vec<EncryptedPart>,
    signed_parts: Vec<SignedPart>,
    constructors: Option<Vec<Constructor>>,
) -> CompoundBeacon {
    CompoundBeacon::builder()
        .name(name)
        .split(".")
        .set_encrypted((!encrypted.is_empty()).then_some(encrypted))
        .set_signed((!signed_parts.is_empty()).then_some(signed_parts))
        .set_constructors(constructors)
        .build()
        .unwrap()
}

fn name_title() -> CompoundBeacon {
    compound(
        "NameTitle",
        vec![enc("Name", "N_"), enc("Title", "T_")],
        vec![],
        None,
    )
}

fn optional(name: &str) -> ConstructorPart {
    ConstructorPart::builder()
        .name(name)
        .required(false)
        .build()
        .unwrap()
}

fn lotsa_compound() -> Vec<CompoundBeacon> {
    let year = || signed("Year", "Y_", None);
    let month = || signed("Month", "M_", Some("Date.Month"));
    vec![
        name_title(),
        compound("YearName", vec![enc("Name", "N_")], vec![year()], None),
        compound(
            "Mixed",
            vec![enc("Name", "N_"), enc("Title", "T_")],
            vec![year(), month()],
            Some(vec![
                Constructor::builder()
                    .parts(ConstructorPart::required("Name"))
                    .parts(ConstructorPart::required("Year"))
                    .build()
                    .unwrap(),
                Constructor::builder()
                    .parts(ConstructorPart::required("Title"))
                    .parts(optional("Month"))
                    .build()
                    .unwrap(),
            ]),
        ),
        compound("JustSigned", vec![], vec![year(), month()], None),
    ]
}

fn name_title_field() -> VirtualField {
    VirtualField::builder()
        .name("NameTitleField")
        .parts(
            VirtualPart::builder()
                .location("Name")
                .transforms(VirtualTransform::insert("__"))
                .build()
                .unwrap(),
        )
        .parts(
            VirtualPart::builder()
                .location("Title")
                .transforms(VirtualTransform::lower())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

fn single() -> BeaconKeySource {
    BeaconKeySource::Single(
        SingleKeyStore::builder()
            .key_id("foo")
            .cache_ttl(Duration::from_secs(42))
            .build()
            .unwrap(),
    )
}

fn multi() -> BeaconKeySource {
    BeaconKeySource::Multi(
        MultiKeyStore::builder()
            .key_field_name("TheKeyField")
            .cache_ttl(Duration::from_secs(42))
            .build()
            .unwrap(),
    )
}

/// A version with only the standard beacons `standard`: `GetEmptyBeacons` for `[std2]`.
fn version_with(standard: Vec<StandardBeacon>) -> BeaconVersionBuilder {
    BeaconVersion::builder()
        .version(1)
        .key_store(LiteralKeyStore)
        .key_source(single())
        .set_standard_beacons(Some(standard))
}

/// `GetLotsaBeacons`.
fn lotsa() -> BeaconVersionBuilder {
    version_with(lotsa_standard())
        .set_compound_beacons(Some(lotsa_compound()))
        .virtual_fields(name_title_field())
}

/// `FullTableConfig`'s attribute actions.
fn full_actions() -> HashMap<String, CryptoAction> {
    let mut actions = HashMap::new();
    for name in ["std2", "std4", "std6", "Name", "Title", "TooBad"] {
        actions.insert(name.to_owned(), CryptoAction::EncryptAndSign);
    }
    for name in ["Year", "Date", "TheKeyField"] {
        actions.insert(name.to_owned(), CryptoAction::SignOnly);
    }
    actions
}

/// The checked form of `version` in `FullTableConfig`, with `extra` also encrypted.
fn info_with(version: BeaconVersionBuilder, extra: &[&str]) -> BeaconVersionInfo {
    let keyring = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("name")
        .wrapping_key(vec![1u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap();
    let mut builder = TableConfig::builder().partition_key_name("foo");
    let mut actions = full_actions();
    for name in extra {
        actions.insert((*name).to_owned(), CryptoAction::EncryptAndSign);
    }
    for (name, action) in actions {
        builder = builder.attribute_actions_on_encrypt(name, action);
    }
    let table = builder
        .keyring(keyring)
        .search(
            SearchConfig::builder()
                .write_version(1)
                .versions(version.build().unwrap())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    convert(&table).unwrap().unwrap().version
}

fn info(version: BeaconVersionBuilder) -> BeaconVersionInfo {
    info_with(version, &[])
}

fn s(x: &str) -> AttributeValue {
    AttributeValue::S(x.to_owned())
}

fn n(x: &str) -> AttributeValue {
    AttributeValue::N(x.to_owned())
}

fn values(pairs: &[(&str, AttributeValue)]) -> Values {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn names(pairs: &[(&str, &str)]) -> Names {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn item(pairs: &[(&str, AttributeValue)]) -> Item {
    values(pairs)
}

/// `SimpleItem`.
fn simple_item() -> Item {
    let date = AttributeValue::M(item(&[("Month", s("May")), ("Year", n("1984"))]));
    item(&[
        ("std2", n("1.23")),
        ("std4", s("abc")),
        ("std6", AttributeValue::L(vec![s("666")])),
        ("Date", date),
        ("Year", n("1984")),
        ("Name", s("MyName")),
        ("Title", s("MyTitle")),
    ])
}

fn filter_ctx(filter: &str, vals: Option<Values>, nms: Option<Names>) -> ExprContext {
    ExprContext {
        key_expr: None,
        filter_expr: Some(filter.to_owned()),
        values: vals,
        names: nms,
    }
}

#[track_caller]
fn assert_validation(err: &Error, message: &str) {
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(err.message(), message);
}

/// `FilterResults` with only a filter expression.
fn run_filter(
    bv: &BeaconVersionInfo,
    items: &[Item],
    filter: &str,
    nms: Option<&Names>,
    vals: Option<&Values>,
) -> Result<Vec<Item>, Error> {
    bv.filter_results(items.to_vec(), None, Some(filter), nms, vals)
}

/// Whether `filter` keeps `one`, the only item.
#[track_caller]
fn keeps(
    bv: &BeaconVersionInfo,
    one: &Item,
    filter: &str,
    nms: Option<&Names>,
    vals: Option<&Values>,
) -> bool {
    let out = run_filter(bv, std::slice::from_ref(one), filter, nms, vals).unwrap();
    match out.as_slice() {
        [] => false,
        [kept] => {
            assert_eq!(kept, one);
            true
        }
        _ => panic!("{filter} returned more items than it was given"),
    }
}

// ---- FilterExpr.dfy ----

#[tokio::test]
async fn no_beacons_leaves_context_unchanged() {
    let bv = info(version_with(vec![std2()]));
    let vals = values(&[(":A", n("1.23")), (":B", s("abc"))]);
    let context = filter_ctx("A < :A AND B = :B", Some(vals.clone()), None);
    let out = bv
        .beaconize(&context, &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(out.key_expr, None);
    assert_eq!(out.filter_expr.as_deref(), Some("A < :A AND B = :B"));
    assert_eq!(out.values, Some(vals));
    assert_eq!(out.names, None);
}

#[test]
fn basic_parse() {
    let bv = info(lotsa());
    let vals = values(&[(":A", n("1.23")), (":B", s("abc"))]);
    let nms = names(&[("#Field_4", "std4")]);
    let parsed = parse_expr("std2 = :A AND #Field_4 = :B");
    assert_eq!(parsed.len(), 7);
    assert_eq!(parsed[0], Token::Attr("std2".to_owned()));
    assert!(op_needs_beacon(&parsed, 0));
    assert_eq!(bv.beacons["std2"].beacon_name(), "aws_dbe_b_std2");

    let ctx = bv
        .beaconize_parsed_expr(
            &parsed,
            &vals,
            Some(nms),
            &MaybeKeyMap::DontUseKeys,
            Values::new(),
            0,
        )
        .unwrap();
    assert_eq!(
        parsed_expr_to_string(&ctx.expr),
        "aws_dbe_b_std2 = :A AND #Field_4 = :B"
    );
    assert_eq!(ctx.names, Some(names(&[("#Field_4", "aws_dbe_b_std4")])));
    // Without keys, a value is compared as its plaintext.
    assert_eq!(ctx.values, vals);
}

#[test]
fn no_beacon_fail() {
    let bv = info(version_with(vec![std2()]));
    let vals = values(&[(":A", n("1.23")), (":B", s("abc"))]);
    let nms = names(&[("#Field4", "std4")]);
    let parsed = parse_expr("std2 = :A AND #Field4 = :B");
    let Err(err) = bv.beaconize_parsed_expr(
        &parsed,
        &vals,
        Some(nms.clone()),
        &MaybeKeyMap::DontUseKeys,
        Values::new(),
        0,
    ) else {
        panic!("std4 has no beacon");
    };
    assert_validation(
        &err,
        "Field std4 is encrypted, and cannot be searched without a beacon.",
    );

    let actions = full_actions();
    assert_eq!(
        uses_encrypted_field(Some("std2 <> :A AND #Field4 = :B"), &actions, None),
        Some("std2".to_owned())
    );
    assert_eq!(
        uses_encrypted_field(Some("#Field4 = :B"), &actions, Some(&nms)),
        Some("std4".to_owned())
    );
    assert_eq!(
        uses_encrypted_field(Some("Year = :A AND Other = :B"), &actions, None),
        None
    );
    assert_eq!(uses_encrypted_field(None, &actions, None), None);
}

#[tokio::test]
async fn basic_beacons() {
    let bv = info(lotsa());
    let context = filter_ctx(
        "std2 = :A AND #Field4 = :B",
        Some(values(&[(":A", n("1.23")), (":B", s("abc"))])),
        Some(names(&[("#Field4", "std4")])),
    );
    let out = bv
        .beaconize(&context, &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(
        out.filter_expr.as_deref(),
        Some("aws_dbe_b_std2 = :A AND #Field4 = :B")
    );
    assert_eq!(out.names, Some(names(&[("#Field4", "aws_dbe_b_std4")])));
    let expected = values(&[(":A", s(STD2_BEACON)), (":B", s(STD4_BEACON))]);
    assert_eq!(out.values, Some(expected));

    // The query values are the beacons written for an item with those values.
    let item_beacons = bv
        .generate_encrypted_beacons(&simple_item(), &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(item_beacons["aws_dbe_b_std2"], s(STD2_BEACON));
    assert_eq!(item_beacons["aws_dbe_b_std4"], s(STD4_BEACON));
}

#[tokio::test]
async fn multi_context_failures() {
    let bv = info(lotsa());
    let vals = Some(values(&[(":A", n("1.23"))]));
    let cases = [
        (None, Some("std2 = :A AND std4 = :A")),
        (Some("std2 = :A AND std4 = :A"), None),
        (Some("std2 = :A"), Some("std4 = :A")),
    ];
    for (key, filter) in cases {
        let context = ExprContext {
            key_expr: key.map(str::to_owned),
            filter_expr: filter.map(str::to_owned),
            values: vals.clone(),
            names: None,
        };
        let err = bv
            .beaconize(&context, &MaybeKeyId::DontUse, 0)
            .await
            .unwrap_err();
        assert_validation(
            &err,
            ":A used in two different contexts, which is not allowed.",
        );
    }
}

#[test]
fn filter_compare() {
    let bv = info(lotsa());
    let one = item(&[("one", s("abc")), ("two", s("cde")), ("three", s("cde"))]);
    let empty = Values::new();
    let with_values = [
        ("one < two", true),
        ("one > two", false),
        ("one <= two", true),
        ("one >= two", false),
        ("one <> two", true),
        ("one = two", false),
    ];
    for (filter, kept) in with_values {
        assert_eq!(
            keeps(&bv, &one, filter, None, Some(&empty)),
            kept,
            "{filter}"
        );
    }
    let without_values = [
        ("three < two", false),
        ("three > two", false),
        ("three <= two", true),
        ("three >= two", true),
        ("three <> two", false),
        ("three = two", true),
    ];
    for (filter, kept) in without_values {
        assert_eq!(keeps(&bv, &one, filter, None, None), kept, "{filter}");
    }
}

#[test]
fn filter_fail_numeric() {
    let bv = info(lotsa());
    let one = item(&[("one", n("800"))]);
    let vals = values(&[(":two", n("foo"))]);
    let err = run_filter(&bv, &[one], "one < :two", None, Some(&vals)).unwrap_err();
    assert_validation(
        &err,
        "Number needs digits either before or after the decimal point. when parsing 'foo'.",
    );
}

#[test]
fn filter_compare_numeric() {
    let bv = info(lotsa());
    let one = item(&[("one", n("800"))]);
    let vals = values(&[(":two", n("0800.000e0"))]);
    let cases = [
        ("one < :two", false),
        ("one > :two", false),
        ("one <= :two", true),
        ("one >= :two", true),
        ("one <> :two", false),
        ("one = :two", true),
        (":two < one", false),
        (":two > one", false),
        (":two <= one", true),
        (":two >= one", true),
        (":two <> one", false),
        (":two = one", true),
    ];
    for (filter, kept) in cases {
        assert_eq!(
            keeps(&bv, &one, filter, None, Some(&vals)),
            kept,
            "{filter}"
        );
    }
}

#[test]
fn filter_in() {
    let bv = info(lotsa());
    let one = item(&[("one", s("abc")), ("two", s("cde")), ("three", s("cde"))]);
    let cases = [
        ("one in (two, three)", false),
        ("two in (one, three)", true),
        ("three in (two, one)", true),
        ("three in (one, one, one, one, two, one, one)", true),
        ("three in (one, one, one, one, one, one, one)", false),
    ];
    for (filter, kept) in cases {
        assert_eq!(keeps(&bv, &one, filter, None, None), kept, "{filter}");
    }
}

#[test]
fn filter_between() {
    let bv = info(lotsa());
    let alpha = item(&[("one", s("abc")), ("two", s("bcd")), ("three", s("cde"))]);
    let number = item(&[("one", n("9")), ("two", n("52")), ("three", n("185"))]);
    let cases = [
        ("one between two and three", false),
        ("two between one and three", true),
        ("two between three and one", false),
        ("two between two and three", true),
        ("two between one and two", true),
    ];
    for one in [&alpha, &number] {
        for (filter, kept) in cases {
            assert_eq!(keeps(&bv, one, filter, None, None), kept, "{filter}");
        }
    }
}

#[test]
fn filter_size() {
    let bv = info(lotsa());
    let one = item(&[("one", n("9")), ("two", n("52")), ("three", n("185"))]);
    let vals = values(&[(":uno", n("1")), (":dos", n("2")), (":tres", n("3"))]);
    let cases = [
        ("size(one) = :uno", true),
        ("size(two) between :uno and :tres", true),
        ("size(three) > :dos", true),
        ("size(two) in (:uno, :dos)", true),
        ("size(two) in (:uno, :tres)", false),
        ("size(one) in (:uno, :dos, :tres)", true),
        (":uno in (size(one), :dos, :tres)", true),
        (":uno in (:dos, :tres, size(one))", true),
        (":uno in (:dos, :tres)", false),
    ];
    for (filter, kept) in cases {
        assert_eq!(
            keeps(&bv, &one, filter, None, Some(&vals)),
            kept,
            "{filter}"
        );
    }
}

#[test]
fn filter_contains_and_begins_with() {
    let bv = info(lotsa());
    let contains = item(&[
        ("one", n("abcdef")),
        ("two", n("a")),
        ("three", n("f")),
        ("four", n("cde")),
        ("five", n("efg")),
    ]);
    for (filter, kept) in [
        ("contains(one, two)", true),
        ("contains(one, three)", true),
        ("contains(one, four)", true),
        ("contains(one, five)", false),
    ] {
        assert_eq!(keeps(&bv, &contains, filter, None, None), kept, "{filter}");
    }
    let begins = item(&[
        ("one", n("abcdef")),
        ("two", n("a")),
        ("three", n("f")),
        ("four", n("abcd")),
        ("five", n("abcdf")),
    ]);
    for (filter, kept) in [
        ("begins_with(one, two)", true),
        ("begins_with(one, three)", false),
        ("begins_with(one, four)", true),
        ("begins_with(one, five)", false),
    ] {
        assert_eq!(keeps(&bv, &begins, filter, None, None), kept, "{filter}");
    }
}

#[test]
fn filter_complex() {
    let bv = info(lotsa());
    let one = item(&[("one", n("1")), ("two", n("2")), ("three", n("3"))]);
    let vals = values(&[(":four", n("4")), (":five", n("5")), (":six", n("6"))]);
    assert!(keeps(
        &bv,
        &one,
        "one < :four and two < :five",
        None,
        Some(&vals)
    ));
    assert!(keeps(
        &bv,
        &one,
        "one < :four or two > :five",
        None,
        Some(&vals)
    ));
}

#[test]
fn filter_indirect_names() {
    let bv = info(lotsa());
    let one = item(&[("one", s("abc")), ("two", s("cde")), ("three", s("cde"))]);
    let vals = values(&[(":uno", s("ab")), (":dos", s("bc"))]);
    let nms = names(&[("#eine", "one"), ("#zwei", "two"), ("#drei", "three")]);
    for (filter, kept) in [
        ("one < two", true),
        ("one > two", false),
        ("#eine < #zwei", true),
        ("#eine > #zwei", false),
        ("#eine < :dos", true),
        ("#eine > :dos", false),
    ] {
        assert_eq!(
            keeps(&bv, &one, filter, Some(&nms), Some(&vals)),
            kept,
            "{filter}"
        );
    }
}

#[test]
fn filter_indirect_names_with_loc() {
    let bv = info(lotsa());
    let vals = values(&[(":uno", s("ab")), (":dos", n("2"))]);
    let nms = names(&[("#eine", "Date"), ("#zwei", "Month"), ("#drei", "Year")]);
    for (filter, kept) in [
        ("Date.Month < :uno", true),
        ("Date.Month > :uno", false),
        ("Date.#zwei < :uno", true),
        ("Date.#zwei > :uno", false),
    ] {
        assert_eq!(
            keeps(&bv, &simple_item(), filter, Some(&nms), Some(&vals)),
            kept,
            "{filter}"
        );
    }
}

#[test]
fn filter_attr_ops() {
    let bv = info(lotsa());
    let nms = names(&[("#fecha", "Date")]);
    let vals = values(&[(":m", s("M")), (":s", s("N"))]);
    for (filter, kept) in [
        ("attribute_exists(Date)", true),
        ("attribute_exists(Nope)", false),
        ("attribute_not_exists(Date)", false),
        ("attribute_not_exists(Nope)", true),
        ("attribute_type(Date, :m)", true),
        ("attribute_type(std2, :s)", true),
        ("not attribute_exists(Date)", false),
        ("not attribute_exists(Nope)", true),
    ] {
        assert_eq!(
            keeps(&bv, &simple_item(), filter, Some(&nms), Some(&vals)),
            kept,
            "{filter}"
        );
    }
}

#[test]
fn filter_beacons() {
    let bv = info(lotsa());
    let vals = values(&[
        (":val2", n("1.23")),
        (":val3", s("N_MyName.T_MyTitle")),
        (":val4", s("T_MyTitle")),
        (":val5", s("MyName__mytitle")),
    ]);
    for filter in [
        "std2 = :val2",
        "NameTitle = :val3",
        "contains(NameTitle, :val4)",
        "NameTitleField = :val5)",
    ] {
        assert!(
            keeps(&bv, &simple_item(), filter, None, Some(&vals)),
            "{filter}"
        );
    }
}

#[test]
fn bad_between() {
    let bv = info(lotsa());
    let vals = values(&[(":val3", s("T_ATitle")), (":val4", s("T_MyTitle"))]);
    let err = run_filter(
        &bv,
        &[simple_item()],
        "NameTitle between :val3 and :val4",
        None,
        Some(&vals),
    )
    .unwrap_err();
    assert_validation(
        &err,
        "To use BETWEEN with a compound beacon, the part after any common prefix must be LessThanComparable : BETWEEN T_ATitle AND T_MyTitle",
    );
}

#[test]
fn bad_standard() {
    let bv = info(lotsa());
    let vals = values(&[(":val", s("foo")), (":other", s("bar"))]);
    let items = [simple_item()];
    // The item's std2 is a number, so it does not equal "foo".
    assert_eq!(
        run_filter(&bv, &items, "std2 = :val", None, Some(&vals)).unwrap(),
        Vec::<Item>::new()
    );
    for op in ["<>", "<", ">", "<=", ">="] {
        let err =
            run_filter(&bv, &items, &format!("std2 {op} :val"), None, Some(&vals)).unwrap_err();
        assert_validation(
            &err,
            &format!("The operation '{op}' cannot be used with a standard beacon."),
        );
    }
    let err = run_filter(&bv, &items, "begins_with(std2, :val)", None, Some(&vals)).unwrap_err();
    assert_validation(
        &err,
        "The operation 'begins_with' cannot be used with a standard beacon.",
    );
    let err = run_filter(
        &bv,
        &items,
        "std2 between :val and :other",
        None,
        Some(&vals),
    )
    .unwrap_err();
    assert_validation(
        &err,
        "The operation BETWEEN cannot be used with a standard beacon.",
    );
}

#[tokio::test]
async fn comparisons() {
    let bv = info(lotsa());
    let vals = values(&[
        (":val1", s("N_")),
        (":val2", s("N_MyName")),
        (":val3", s("N_MyName.T_")),
        (":val4", s("N_MyName.T_Title")),
        (":val5", s("T_")),
        (":val6", s("N_MyName.N_")),
    ]);
    let simple = simple_item();
    // SimpleItem's NameTitle is N_MyName.T_MyTitle.
    for (filter, kept) in [
        ("NameTitle between :val1 and :val5", true),
        ("NameTitle between :val3 and :val6", false),
        ("NameTitle between :val2 and :val3", false),
        ("NameTitle < :val1", false),
        ("NameTitle = :val1", false),
        ("NameTitle = :val2", false),
    ] {
        assert_eq!(
            keeps(&bv, &simple, filter, None, Some(&vals)),
            kept,
            "{filter}"
        );
    }
    let between = "To use BETWEEN with a compound beacon, the part after any common prefix must be LessThanComparable : BETWEEN";
    for (filter, message) in [
        (
            "NameTitle between :val1 and :val2",
            format!("{between} N_ AND N_MyName"),
        ),
        (
            "NameTitle between :val1 and :val4",
            format!("{between} N_ AND N_MyName.T_Title"),
        ),
        (
            "NameTitle < :val2",
            "The operation '<' cannot be used with a compound beacon, unless the value is LessThanComparable : N_MyName".to_owned(),
        ),
    ] {
        let err = run_filter(&bv, std::slice::from_ref(&simple), filter, None, Some(&vals)).unwrap_err();
        assert_validation(&err, &message);
    }

    // For equality a bare prefix is beaconized; for a comparison it is kept.
    let out = bv
        .beaconize(
            &filter_ctx("NameTitle = :val1", Some(vals.clone()), None),
            &MaybeKeyId::DontUse,
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        out.values,
        Some(values(&[(":val1", s(&format!("N_{EMPTY_NAME_BEACON}")))]))
    );
    let out = bv
        .beaconize(
            &filter_ctx("NameTitle < :val1", Some(vals), None),
            &MaybeKeyId::DontUse,
            0,
        )
        .await
        .unwrap();
    assert_eq!(out.values, Some(values(&[(":val1", s("N_"))])));
}

// ---- Beacon.dfy ----

#[tokio::test]
async fn compound_queries() {
    let bv = info(lotsa());
    let beaconize = |v: &str| {
        let context = filter_ctx("Mixed = :mixed", Some(values(&[(":mixed", s(v))])), None);
        let bv = &bv;
        async move {
            bv.beaconize(&context, &MaybeKeyId::DontUse, 0)
                .await
                .map(|c| c.values.unwrap()[":mixed"].clone())
        }
    };
    assert_eq!(
        beaconize("N_MyName.Y_1984").await.unwrap(),
        s(&format!("N_{NAME_BEACON}.Y_1984"))
    );
    assert_eq!(
        beaconize("N_MyName").await.unwrap(),
        s(&format!("N_{NAME_BEACON}"))
    );
    assert_eq!(beaconize("Y_1984").await.unwrap(), s("Y_1984"));
    assert_eq!(beaconize("M_bar").await.unwrap(), s("M_bar"));
    let AttributeValue::S(title) = beaconize("T_foo").await.unwrap() else {
        panic!("a compound beacon value is a string");
    };
    assert!(title.starts_with("T_") && title != "T_foo", "{title}");
    assert_eq!(
        beaconize("T_foo.M_bar").await.unwrap(),
        s(&format!("{title}.M_bar"))
    );

    for (value, parsed) in [
        ("N_MyName.N_MyName", "N_N_"),
        ("Y_1984.N_MyName", "Y_N_"),
        ("M_bar.T_foo", "M_T_"),
    ] {
        let err = beaconize(value).await.unwrap_err();
        assert_validation(
            &err,
            &format!(
                "Compound Beacon value '{value}' cannot be constructed from any available constructor for Mixed value parsed as {parsed} available constructors are N_Y_, T_[M_]."
            ),
        );
    }
}

/// The query of `TestQueryBeacons` and `TestQueryMixedTableBeaconPartitions`, and its beaconized values.
fn query_beacons_case() -> (ExprContext, Values) {
    let context = filter_ctx(
        "std2 = :std2 AND std4 = :std4 AND :std6 = std6 AND Name = :Name AND Mixed = :Mixed \
         AND :NameTitle = NameTitle AND NameTitle = :NameTitleN AND NameTitle = :NameTitleT AND NameTitle = :NameTitleTN \
         AND NameTitleField = :NameTitleField And Title = :Title AND YearName = :YearName",
        Some(values(&[
            (":std2", n("1.23")),
            (":std4", s("abc")),
            (":std6", s("666")),
            (":Name", s("MyName")),
            (":Title", s("MyTitle")),
            (":Mixed", s("N_MyName.Y_1984")),
            (":NameTitle", s("N_MyName.T_MyTitle")),
            (":NameTitleN", s("N_MyName")),
            (":NameTitleT", s("T_MyTitle")),
            (":NameTitleTN", s("N_MyName.T_MyTitle")),
            (":NameTitleField", s("MyName__mytitle")),
            (":YearName", s("Y_1984.N_MyName")),
        ])),
        None,
    );
    let name_title = format!("N_{NAME_BEACON}.T_{TITLE_BEACON}");
    let expected = values(&[
        (":Mixed", s(&format!("N_{NAME_BEACON}.Y_1984"))),
        (":Name", s(NAME_BEACON)),
        (":NameTitle", s(&name_title)),
        (":NameTitleTN", s(&name_title)),
        (":NameTitleN", s(&format!("N_{NAME_BEACON}"))),
        (":NameTitleT", s(&format!("T_{TITLE_BEACON}"))),
        (":NameTitleField", s(NAME_TITLE_BEACON)),
        (":std2", s(STD2_BEACON)),
        (":Title", s(TITLE_BEACON)),
        (":std6", s(STD6_BEACON)),
        (":std4", s(STD4_BEACON)),
        (":YearName", s(&format!("Y_1984.N_{NAME_BEACON}"))),
    ]);
    (context, expected)
}

#[tokio::test]
async fn query_beacons() {
    let bv = info(lotsa());
    let (context, expected) = query_beacons_case();
    let out = bv
        .beaconize(&context, &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(out.values, Some(expected));
    assert_eq!(out.names, None);
    assert_eq!(
        out.filter_expr.as_deref(),
        Some(
            "aws_dbe_b_std2 = :std2 AND aws_dbe_b_std4 = :std4 AND :std6 = aws_dbe_b_std6 AND aws_dbe_b_Name = :Name \
             AND aws_dbe_b_Mixed = :Mixed AND :NameTitle = aws_dbe_b_NameTitle AND aws_dbe_b_NameTitle = :NameTitleN \
             AND aws_dbe_b_NameTitle = :NameTitleT AND aws_dbe_b_NameTitle = :NameTitleTN \
             AND aws_dbe_b_NameTitleField = :NameTitleField AND aws_dbe_b_Title = :Title AND aws_dbe_b_YearName = :YearName"
        )
    );
}

#[tokio::test]
async fn query_mixed_table_beacon_partitions() {
    let mut standard = lotsa_standard();
    standard[1] = StandardBeacon::builder()
        .name("std4")
        .bits(24)
        .location("std4")
        .number_of_partitions(5)
        .build()
        .unwrap();
    let bv = info(
        version_with(standard)
            .set_compound_beacons(Some(lotsa_compound()))
            .virtual_fields(name_title_field())
            .maximum_number_of_partitions(10),
    );
    let (context, expected) = query_beacons_case();
    let out = bv
        .beaconize(&context, &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(out.values, Some(expected));
    assert_eq!(out.names, None);
}

#[tokio::test]
async fn part_only_query() {
    let compound_part = compound("compoundPart", vec![enc("partOnly", "S_")], vec![], None);
    let context = filter_ctx("partOnly = :val", Some(values(&[(":val", s("foo"))])), None);

    let bv = info_with(
        lotsa()
            .standard_beacons(std_beacon("partOnly", 23, None))
            .compound_beacons(compound_part.clone()),
        &["partOnly"],
    );
    let out = bv
        .beaconize(&context, &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(
        out.filter_expr.as_deref(),
        Some("aws_dbe_b_partOnly = :val")
    );

    let bv = info_with(
        lotsa()
            .standard_beacons(styled("partOnly", 23, BeaconStyle::part_only()))
            .compound_beacons(compound_part),
        &["partOnly"],
    );
    let err = bv
        .beaconize(&context, &MaybeKeyId::DontUse, 0)
        .await
        .unwrap_err();
    assert_validation(
        &err,
        "Field partOnly is encrypted, and has a PartOnly beacon, and so can only be used as part of a compound beacon.",
    );
}

#[tokio::test]
async fn shared_beacon_query() {
    let bv = info_with(
        lotsa().standard_beacons(styled("partOnly", 24, BeaconStyle::shared("std2"))),
        &["partOnly"],
    );
    let context = filter_ctx(
        "partOnly = :pVal AND std2 = :sVal",
        Some(values(&[(":pVal", s("foo")), (":sVal", s("foo"))])),
        None,
    );
    let out = bv
        .beaconize(&context, &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(
        out.values,
        Some(values(&[(":pVal", s("4379a7")), (":sVal", s("4379a7"))]))
    );
}

#[tokio::test]
async fn beacon_set_query() {
    let bv = info_with(
        lotsa().standard_beacons(styled("setAttr", 24, BeaconStyle::as_set())),
        &["setAttr"],
    );
    let query =
        |v: AttributeValue| filter_ctx("setAttr = :setVal", Some(values(&[(":setVal", v)])), None);
    let set = AttributeValue::Ss(vec!["abc".into(), "def".into(), "ghi".into()]);
    let out = bv
        .beaconize(&query(set), &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    let expected = AttributeValue::Ss(vec!["43c4d8".into(), "2f3278".into(), "f1972e".into()]);
    assert_eq!(out.values, Some(values(&[(":setVal", expected)])));

    // A single value is beaconized as the matching set element is.
    let out = bv
        .beaconize(&query(s("abc")), &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(out.values, Some(values(&[(":setVal", s("43c4d8"))])));

    let err = bv
        .beaconize(&query(AttributeValue::L(vec![])), &MaybeKeyId::DontUse, 0)
        .await
        .unwrap_err();
    assert_validation(
        &err,
        "Beacon setAttr has style AsSet, but attribute has type L.",
    );
}

// ---- DDBSupport.dfy: TestMulti ----

const KEY_ID: &str = "0ad21413-51aa-42e1-9c3d-6a4b1edf7e10";

#[tokio::test]
async fn multi_key_store_key_id() {
    let bv = info(lotsa().key_source(multi()));
    let vals = values(&[(":value", s(KEY_ID)), (":other", s("junk"))]);
    let key_id = |key: &str, nms: Option<&Names>| {
        bv.get_beacon_key_id(Some(key), None, Some(&vals), nms)
            .unwrap()
    };
    assert_eq!(
        key_id("TheKeyField = :value", None),
        MaybeKeyId::Id(KEY_ID.to_owned())
    );
    assert_eq!(
        key_id("TheKeyField = :value AND std2 = :other", None),
        MaybeKeyId::Id(KEY_ID.to_owned())
    );
    let nms = names(&[("#beacon", "std2"), ("#keyfield", "TheKeyField")]);
    let id = key_id("#keyfield = :value AND #beacon = :other", Some(&nms));
    assert_eq!(id, MaybeKeyId::Id(KEY_ID.to_owned()));

    let context = ExprContext {
        key_expr: Some("#keyfield = :value AND #beacon = :other".to_owned()),
        filter_expr: None,
        values: Some(vals.clone()),
        names: Some(nms),
    };
    let out = bv.beaconize(&context, &id, 0).await.unwrap();
    assert_eq!(
        out.names,
        Some(names(&[
            ("#beacon", "aws_dbe_b_std2"),
            ("#keyfield", "TheKeyField")
        ]))
    );
    // The key field is not a beacon, so its value is unchanged.
    assert_eq!(out.values.as_ref().unwrap()[":value"], s(KEY_ID));

    // A beacon with no key id in the query has no key.
    let id = key_id("std2 = :other", None);
    assert_eq!(id, MaybeKeyId::ShouldHave);
    let context = ExprContext {
        key_expr: Some("std2 = :other".to_owned()),
        filter_expr: None,
        values: Some(vals),
        names: None,
    };
    let err = bv.beaconize(&context, &id, 0).await.unwrap_err();
    assert_validation(
        &err,
        "Need KeyId because of beacon std2 but no KeyId found in query",
    );
}

#[test]
fn beacon_key_id_sources() {
    let single_bv = info(lotsa());
    let vals = values(&[(":a", s("k1")), (":b", s("k2"))]);
    assert_eq!(
        single_bv
            .get_beacon_key_id(Some("TheKeyField = :a"), None, Some(&vals), None)
            .unwrap(),
        MaybeKeyId::DontUse
    );

    // A compound beacon with a signed part on the key field names the key id too.
    let key_name = compound(
        "KeyName",
        vec![enc("Name", "N_")],
        vec![signed("TheKeyField", "K_", None)],
        None,
    );
    let bv = info(lotsa().key_source(multi()).compound_beacons(key_name));
    assert_eq!(
        bv.get_beacon_key_id(None, None, None, None).unwrap(),
        MaybeKeyId::ShouldHave
    );
    let vals = values(&[
        (":a", s("k1")),
        (":b", s("k2")),
        (":kn", s("K_k1.N_MyName")),
        (":n", n("1")),
    ]);
    let key_id = |key: Option<&str>, filter: Option<&str>| {
        bv.get_beacon_key_id(key, filter, Some(&vals), None)
    };
    assert_eq!(
        key_id(None, Some("KeyName = :kn")).unwrap(),
        MaybeKeyId::Id("k1".to_owned())
    );
    // The same key id named twice is one key id.
    assert_eq!(
        key_id(Some("TheKeyField = :a"), Some("KeyName = :kn")).unwrap(),
        MaybeKeyId::Id("k1".to_owned())
    );
    // A compound value with no key field part, or a number, names no key id.
    assert_eq!(
        key_id(Some("NameTitle = :kn AND TheKeyField = :n"), None).unwrap(),
        MaybeKeyId::ShouldHave
    );
    let err = key_id(Some("TheKeyField = :a"), Some("TheKeyField = :b")).unwrap_err();
    assert_validation(
        &err,
        "Multiple values found for TheKeyField in query : k1, k2",
    );
    let err = key_id(Some("TheKeyField = :missing"), None).unwrap_err();
    assert_validation(&err, ":missing not found in ExpressionAttributeValueMap");
}

// ---- BeaconPartition.dfy: GetNumberOfQueries ----

fn num_queries(bv: &BeaconVersionInfo, key: &str, vals: &[(&str, AttributeValue)]) -> u8 {
    bv.get_num_queries(Some(key), Some(&values(vals))).unwrap()
}

#[test]
fn number_of_queries_standard() {
    let std2_val = [(":std2", n("1.23"))];
    let bv = info(version_with(vec![std2()]));
    assert_eq!(num_queries(&bv, "std2 = :std2", &std2_val), 1);
    for (partitions, max) in [(5, 6), (25, 26), (64, 128)] {
        let bv = info(
            version_with(vec![partitioned("std2", 24, partitions)])
                .maximum_number_of_partitions(max),
        );
        assert_eq!(num_queries(&bv, "std2 = :std2", &std2_val), partitions);
    }
    // A beacon with no partitions of its own has the default.
    let bv = info(
        version_with(vec![std2()])
            .maximum_number_of_partitions(10)
            .default_number_of_partitions(3),
    );
    assert_eq!(num_queries(&bv, "std2 = :std2", &std2_val), 3);
}

#[test]
fn number_of_queries_multiple_beacons() {
    let beacons = || {
        vec![
            partitioned("std2", 24, 3),
            StandardBeacon::builder()
                .name("std4")
                .bits(24)
                .location("std4")
                .number_of_partitions(5)
                .build()
                .unwrap(),
        ]
    };
    let vals = [(":std4", s("abc")), (":std2", n("1.23"))];
    let key = "std4 = :std4 AND std2 = :std2";
    let bv = info(version_with(beacons()).maximum_number_of_partitions(16));
    assert_eq!(num_queries(&bv, key, &vals), 15);
    let bv = info(version_with(beacons()).maximum_number_of_partitions(6));
    assert_eq!(num_queries(&bv, key, &vals), 6);
}

#[test]
fn number_of_queries_compound() {
    let bv = info(
        version_with(vec![
            partitioned("Name", 32, 3),
            partitioned("Title", 32, 5),
        ])
        .compound_beacons(name_title())
        .maximum_number_of_partitions(16),
    );
    assert_eq!(
        num_queries(&bv, "NameTitle = :nt", &[(":nt", s("N_MyName.T_MyTitle"))]),
        15
    );
    assert_eq!(
        num_queries(&bv, "NameTitle = :nt", &[(":nt", s("N_MyName"))]),
        3
    );
}

#[test]
fn number_of_queries_edges() {
    let bv = info(version_with(vec![partitioned("std2", 24, 5)]).maximum_number_of_partitions(6));
    assert_eq!(bv.get_num_queries(None, Some(&Values::new())).unwrap(), 1);
    assert_eq!(bv.get_num_queries(Some("std2 = :v"), None).unwrap(), 1);
    // Values compared to no beacon, or of no string type, do not add queries.
    assert_eq!(
        num_queries(
            &bv,
            "other = :v AND std2 = :n",
            &[(":v", s("x")), (":n", n("1"))]
        ),
        5
    );
    let err = bv
        .get_num_queries(Some("std2 = :v"), Some(&Values::new()))
        .unwrap_err();
    assert_validation(&err, ":v not found in ExpressionAttributeValueMap");
}

// ---- partitions in one query ----

#[tokio::test]
async fn do_beaconize_ors_each_partition() {
    let bv = info(version_with(vec![std2()]).maximum_number_of_partitions(3));
    let context = filter_ctx("std2 = :v", Some(values(&[(":v", n("1.23"))])), None);
    let mut per_partition = Vec::new();
    for p in 0..3 {
        let out = bv
            .beaconize(&context, &MaybeKeyId::DontUse, p)
            .await
            .unwrap();
        per_partition.push(out.values.unwrap()[":v"].clone());
    }
    assert_eq!(per_partition[0], s(STD2_BEACON));
    assert_ne!(per_partition[0], per_partition[1]);
    assert_ne!(per_partition[1], per_partition[2]);

    let out = bv
        .do_beaconize(&context, &MaybeKeyId::DontUse, 0, 1)
        .await
        .unwrap();
    assert_eq!(
        out.filter_expr.as_deref(),
        Some("(aws_dbe_b_std2 = :v) OR (aws_dbe_b_std2 = :vAA) OR (aws_dbe_b_std2 = :vAB)")
    );
    assert_eq!(
        out.values,
        Some(values(&[
            (":v", per_partition[0].clone()),
            (":vAA", per_partition[1].clone()),
            (":vAB", per_partition[2].clone()),
        ]))
    );
    assert_eq!(out.key_expr, None);
    assert_eq!(out.names, None);

    // Starting at partition 1 covers partitions 1 and 2.
    let out = bv
        .do_beaconize(&context, &MaybeKeyId::DontUse, 1, 1)
        .await
        .unwrap();
    assert_eq!(
        out.filter_expr.as_deref(),
        Some("(aws_dbe_b_std2 = :v) OR (aws_dbe_b_std2 = :vAA)")
    );
    assert_eq!(
        out.values,
        Some(values(&[
            (":v", per_partition[1].clone()),
            (":vAA", per_partition[2].clone()),
        ]))
    );

    // One query per partition needs no OR.
    let out = bv
        .do_beaconize(&context, &MaybeKeyId::DontUse, 0, 3)
        .await
        .unwrap();
    assert_eq!(out.filter_expr.as_deref(), Some("aws_dbe_b_std2 = :v"));
    assert_eq!(
        out.values,
        Some(values(&[(":v", per_partition[0].clone())]))
    );
}

#[tokio::test]
async fn do_beaconize_without_beacons_is_one_filter() {
    let bv = info(version_with(vec![std2()]).maximum_number_of_partitions(3));
    let context = ExprContext {
        key_expr: Some("pk = :pk".to_owned()),
        filter_expr: Some("A = :a".to_owned()),
        values: Some(values(&[(":a", s("x")), (":pk", s("p"))])),
        names: None,
    };
    let out = bv
        .do_beaconize(&context, &MaybeKeyId::DontUse, 0, 1)
        .await
        .unwrap();
    assert_eq!(out.key_expr.as_deref(), Some("pk = :pk"));
    assert_eq!(out.filter_expr.as_deref(), Some("A = :a"));
    assert_eq!(out.values, Some(values(&[(":a", s("x")), (":pk", s("p"))])));
}

#[test]
fn add_context_renames_changed_values() {
    let old = values(&[(":a", s("1")), (":b", s("2"))]);
    // Unchanged values keep the filter as is.
    let (filter, vals) = add_context(old.clone(), "x = :a", &values(&[(":a", s("1"))])).unwrap();
    assert_eq!(filter, "x = :a");
    assert_eq!(vals, old);

    let (filter, vals) = add_context(
        old.clone(),
        "x = :a AND y = :b",
        &values(&[(":a", s("9")), (":b", s("2"))]),
    )
    .unwrap();
    assert_eq!(filter, "x = :aAA AND y = :b");
    assert_eq!(
        vals,
        values(&[(":a", s("1")), (":b", s("2")), (":aAA", s("9"))])
    );

    let err = add_context(values(&[("", s("1"))]), "x", &values(&[("", s("2"))])).unwrap_err();
    assert_validation(
        &err,
        "Unexpected zero length key in ExpressionAttributeValueMap",
    );
}

#[test]
fn make_new_name_skips_taken_names() {
    let v = s("new");
    let taken = values(&[(":aAA", s("old")), (":aAB", v.clone())]);
    assert_eq!(make_new_name(":a", &taken, &v).unwrap(), ":aAB");
    assert_eq!(make_new_name(":a", &taken, &s("other")).unwrap(), ":aAC");

    let mut all = Values::new();
    for i in 'A'..='Z' {
        for j in 'A'..='Z' {
            all.insert(format!(":a{i}{j}"), s("old"));
        }
    }
    let err = make_new_name(":a", &all, &v).unwrap_err();
    assert_validation(&err, "Could not find new name");
}

#[test]
fn replace_all_whole_replaces_only_whole_words() {
    assert_eq!(
        replace_all_whole("a = :v OR b = :vx OR c = b:v OR d = :v_", ":v", ":vAA"),
        "a = :vAA OR b = :vx OR c = b:v OR d = :v_"
    );
    assert_eq!(replace_all_whole(":v,:v", ":v", ":vAA"), ":vAA,:vAA");
    // A skipped match is stepped over a character at a time, not a byte at a time.
    assert_eq!(replace_all_whole("aé é", "é", "X"), "aé X");
}

// ---- rewrite paths and errors ----

#[tokio::test]
async fn beaconize_in_contains_and_prefixed_names() {
    let bv = info(lotsa());
    let cases = [
        (
            "std2 IN (:a, :b)",
            vec![(":a", n("1.23")), (":b", s("abc"))],
            "aws_dbe_b_std2 IN ( :a , :b )",
            vec![(":a", s(STD2_BEACON)), (":b", s("51e1da"))],
        ),
        (
            "contains(:v, std4)",
            vec![(":v", s("abc"))],
            "contains ( :v , aws_dbe_b_std4 )",
            vec![(":v", s(STD4_BEACON))],
        ),
        (
            "contains(NameTitle, :v)",
            vec![(":v", s("T_MyTitle"))],
            "contains ( aws_dbe_b_NameTitle , :v )",
            vec![(":v", s(&format!("T_{TITLE_BEACON}")))],
        ),
        (
            // A beacon attribute named directly still has its value beaconized.
            "aws_dbe_b_std2 = :v",
            vec![(":v", n("1.23"))],
            "aws_dbe_b_std2 = :v",
            vec![(":v", s(STD2_BEACON))],
        ),
        (
            // Whether an attribute exists needs no beacon.
            "attribute_exists(std2) AND :v = std4",
            vec![(":v", s("abc"))],
            "attribute_exists ( std2 ) AND :v = aws_dbe_b_std4",
            vec![(":v", s(STD4_BEACON))],
        ),
    ];
    for (filter, vals, expected_filter, expected_values) in cases {
        let out = bv
            .beaconize(
                &filter_ctx(filter, Some(values(&vals)), None),
                &MaybeKeyId::DontUse,
                0,
            )
            .await
            .unwrap();
        assert_eq!(
            out.filter_expr.as_deref(),
            Some(expected_filter),
            "{filter}"
        );
        assert_eq!(out.values, Some(values(&expected_values)), "{filter}");
    }

    // An indirect name of a beacon attribute finds the beacon through the name.
    let nms = names(&[("#b", "aws_dbe_b_std2")]);
    let out = bv
        .beaconize(
            &filter_ctx(
                "#b = :v",
                Some(values(&[(":v", n("1.23"))])),
                Some(nms.clone()),
            ),
            &MaybeKeyId::DontUse,
            0,
        )
        .await
        .unwrap();
    assert_eq!(out.names, Some(nms));
    assert_eq!(out.values, Some(values(&[(":v", s(STD2_BEACON))])));
}

#[tokio::test]
async fn beaconize_errors() {
    let bv = info(lotsa());
    let cases = [
        (
            "#missing = :a",
            vec![(":a", s("x"))],
            "Name #missing not in ExpressionAttributeNameMap.",
        ),
        (
            "A = :nope",
            vec![],
            ":nope not found in ExpressionAttributeValueMap",
        ),
        (
            "size(std2) = :a",
            vec![(":a", n("1"))],
            "Function size cannot be used on encrypted fields, but it is being used with std2",
        ),
        (
            "NameTitle = :a",
            vec![(":a", n("1"))],
            "Value :a supplied for compound beacon NameTitle is of type N but must be of type S (string).",
        ),
        (
            "NameTitle BETWEEN :a AND :b",
            vec![(":a", s("N_"))],
            "Value :b used in query string, but not supplied in value map.",
        ),
        (
            "TooBad = :a",
            vec![(":a", s("x"))],
            "Field TooBad is encrypted, and cannot be searched without a beacon.",
        ),
    ];
    for (filter, vals, message) in cases {
        let err = bv
            .beaconize(
                &filter_ctx(filter, Some(values(&vals)), None),
                &MaybeKeyId::DontUse,
                0,
            )
            .await
            .unwrap_err();
        assert_validation(&err, message);
    }
}

#[tokio::test]
async fn beaconize_without_expressions_is_unchanged() {
    let bv = info(lotsa().key_source(multi()));
    let context = ExprContext {
        key_expr: None,
        filter_expr: None,
        values: Some(values(&[(":a", s("x"))])),
        names: Some(names(&[("#a", "std2")])),
    };
    // No key is needed, so even a key id the multi key store rejects is fine.
    let out = bv
        .beaconize(&context, &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(out.values, context.values);
    assert_eq!(out.names, context.names);
    assert_eq!(out.filter_expr, None);
}

#[test]
fn filter_results_short_circuits() {
    let bv = info(lotsa());
    // An expression that cannot be beaconized is not even read without items.
    let bad = "std2 between :a and :b";
    assert_eq!(
        bv.filter_results(vec![], None, Some(bad), None, None)
            .unwrap(),
        Vec::<Item>::new()
    );
    // Without expressions every item is kept.
    let items = vec![simple_item()];
    assert_eq!(
        bv.filter_results(items.clone(), None, None, None, None)
            .unwrap(),
        items
    );
}

#[test]
fn filter_results_applies_key_and_filter() {
    let bv = info(lotsa());
    let other = item(&[("std2", n("4")), ("Name", s("MyName"))]);
    let items = vec![simple_item(), other.clone()];
    let vals = values(&[(":v", n("1.23")), (":name", s("MyName"))]);
    let out = bv
        .filter_results(
            items.clone(),
            Some("std2 = :v"),
            Some("Name = :name"),
            None,
            Some(&vals),
        )
        .unwrap();
    assert_eq!(out, vec![simple_item()]);
    let out = bv
        .filter_results(items, Some("Name = :name"), None, None, Some(&vals))
        .unwrap();
    assert_eq!(out, vec![simple_item(), other]);
}

/// `attr_for_value` finds the attribute a value is compared to, in each place a value can
/// appear: either side of a comparison, `contains` and `begins_with`, both `BETWEEN`
/// bounds, and every member of an `IN` list.
#[test]
fn attr_for_value_each_shape() {
    let cases: &[(&str, &str, Option<&str>)] = &[
        (":v = A", ":v", Some("A")),
        ("A < :v", ":v", Some("A")),
        ("contains(A, :v)", ":v", Some("A")),
        ("begins_with(A, :v)", ":v", Some("A")),
        ("A BETWEEN :lo AND :hi", ":lo", Some("A")),
        ("A BETWEEN :lo AND :hi", ":hi", Some("A")),
        ("A IN (:x, :y, :z)", ":x", Some("A")),
        ("A IN (:x, :y, :z)", ":z", Some("A")),
        ("size(A) = :v", ":v", None),
        (":v", ":v", None),
        ("(:x, :v)", ":v", None),
    ];
    for (expr, value, want) in cases {
        let parsed = parse_expr(expr);
        let pos = parsed
            .iter()
            .position(|t| *t == Token::Value((*value).to_owned()))
            .unwrap();
        let got = attr_for_value(&parsed, pos).map(|t| match t {
            Token::Attr(a) => a.as_str(),
            other => panic!("{expr}: not an attribute: {other:?}"),
        });
        assert_eq!(got, *want, "{expr} / {value}");
    }
}
