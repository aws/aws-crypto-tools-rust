// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures shared by the `transforms_*` tests, ported from the Dafny
//! `DynamoDbEncryptionTransforms/test/TestFixtures.dfy` and
//! `DynamoDbEncryption/test/BeaconTestFixtures.dfy`.
//!
//! Everything is offline: items are protected by a Raw AES keyring with a fixed key,
//! and beacon and branch keys come from an in-process key store.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::key_store::operation::create_key::{CreateKeyInput, CreateKeyOutput};
use aws_db_esdk::key_store::operation::create_key_store::{
    CreateKeyStoreInput, CreateKeyStoreOutput,
};
use aws_db_esdk::key_store::operation::get_active_branch_key::{
    GetActiveBranchKeyInput, GetActiveBranchKeyOutput,
};
use aws_db_esdk::key_store::operation::get_beacon_key::{GetBeaconKeyInput, GetBeaconKeyOutput};
use aws_db_esdk::key_store::operation::get_branch_key_version::{
    GetBranchKeyVersionInput, GetBranchKeyVersionOutput,
};
use aws_db_esdk::key_store::operation::get_key_store_info::{
    GetKeyStoreInfoInput, GetKeyStoreInfoOutput,
};
use aws_db_esdk::key_store::operation::version_key::{VersionKeyInput, VersionKeyOutput};
use aws_db_esdk::key_store::types::{Discovery, KmsConfiguration};
use aws_db_esdk::key_store::{self, KeyStore};
use aws_db_esdk::keyring::{HierarchicalKeyring, RawAesKeyring, SharedKeyring};
use aws_db_esdk::mpl::shared::IntoShared;
use aws_db_esdk::mpl::types::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};
use aws_db_esdk::search::{
    BeaconKeySource, BeaconVersion, CompoundBeacon, Constructor, ConstructorPart, EncryptedPart,
    MultiKeyStore, SearchConfig, SignedPart, SingleKeyStore, StandardBeacon, VirtualField,
    VirtualPart, VirtualTransform,
};
use aws_db_esdk::transforms::Transforms;
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction, PlaintextOverride};
use aws_db_esdk::{Error, TableConfig, async_trait};

pub type Item = HashMap<String, AttributeValue>;

pub fn s(v: &str) -> AttributeValue {
    AttributeValue::S(v.to_owned())
}

pub fn n(v: &str) -> AttributeValue {
    AttributeValue::N(v.to_owned())
}

pub fn item(pairs: &[(&str, AttributeValue)]) -> Item {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

/// `TestFixtures.ExpectFailure`: a `Validation` error with exactly `message`.
#[track_caller]
pub fn expect_validation<T: std::fmt::Debug>(result: Result<T, Error>, message: &str) {
    match result {
        Err(Error::Validation(e)) => assert_eq!(e.message(), message),
        other => panic!("expected Validation({message:?}), got {other:?}"),
    }
}

/// `TestFixtures.GetStaticKeyring`: namespace `foo`, name `bar`, 32 zero bytes.
pub fn static_keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("foo")
        .key_name("bar")
        .wrapping_key(vec![0u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap()
}

/// The table of `TestFixtures.GetDynamoDbEncryptionTransforms`, with the static keyring:
/// partition key `bar`, and `sort_key` as its sort key when given.
pub fn foo_table(sort_key: Option<&str>) -> TableConfig {
    TableConfig::builder()
        .logical_table_name("foo")
        .partition_key_name("bar")
        .set_sort_key_name(sort_key.map(str::to_owned))
        .attribute_actions_on_encrypt("bar", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sign", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("encrypt", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("plain", CryptoAction::DoNothing)
        .allowed_unsigned_attributes("plain")
        .keyring(static_keyring())
        .build()
        .unwrap()
}

/// `TestFixtures.GetDynamoDbEncryptionTransforms`: table `foo`, no sort key.
pub fn transforms() -> Transforms {
    Transforms::builder()
        .table_encryption_configs("foo", foo_table(None))
        .build()
        .unwrap()
}

/// `TestFixtures.GetDynamoDbEncryptionTransforms2`: table `foo`, sort key `sign`.
pub fn transforms2() -> Transforms {
    Transforms::builder()
        .table_encryption_configs("foo", foo_table(Some("sign")))
        .build()
        .unwrap()
}

/// Transforms for table `foo` with the given plaintext override.
pub fn transforms_with_override(o: PlaintextOverride) -> Transforms {
    let config = TableConfig::builder()
        .logical_table_name("foo")
        .partition_key_name("bar")
        .attribute_actions_on_encrypt("bar", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sign", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("encrypt", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("plain", CryptoAction::DoNothing)
        .allowed_unsigned_attributes("plain")
        .plaintext_override(o)
        .keyring(static_keyring())
        .build()
        .unwrap();
    Transforms::builder()
        .table_encryption_configs("foo", config)
        .build()
        .unwrap()
}

/// The key every beacon HMAC key is derived from: `GetLiteralSource([1,2,3,4,5], ..)`.
pub const BEACON_KEY: [u8; 5] = [1, 2, 3, 4, 5];
pub const BRANCH_KEY: [u8; 32] = [7u8; 32];
pub const BRANCH_KEY_VERSION: &str = "11111111-2222-4333-8444-555555555555";

/// A key store that never leaves the process: every beacon key is [`BEACON_KEY`],
/// and every branch key is [`BRANCH_KEY`] under the requested id.
#[derive(Clone, Debug, Default)]
pub struct FakeKeyStore {
    /// The branch key id of each beacon key request, in order.
    pub beacon_key_ids: Arc<Mutex<Vec<String>>>,
}

fn branch_materials(id: &str) -> BranchKeyMaterials {
    BranchKeyMaterials::builder()
        .branch_key(BRANCH_KEY)
        .branch_key_id(id.to_owned())
        .branch_key_version(BRANCH_KEY_VERSION.to_owned())
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap()
}

#[async_trait]
impl KeyStore for FakeKeyStore {
    async fn get_key_store_info(
        &self,
        _input: GetKeyStoreInfoInput,
    ) -> Result<GetKeyStoreInfoOutput, aws_db_esdk::mpl::Error> {
        GetKeyStoreInfoOutput::builder()
            .key_store_id("test-id")
            .key_store_name("test-table")
            .logical_key_store_name("test-logical-name")
            .set_grant_tokens(Some(Vec::<String>::new()))
            .kms_configuration(KmsConfiguration::Discovery(
                Discovery::builder().build().unwrap(),
            ))
            .build()
    }

    async fn create_key_store(
        &self,
        _input: CreateKeyStoreInput,
    ) -> Result<CreateKeyStoreOutput, aws_db_esdk::mpl::Error> {
        unimplemented!("FakeKeyStore::create_key_store")
    }

    async fn create_key(
        &self,
        _input: CreateKeyInput,
    ) -> Result<CreateKeyOutput, aws_db_esdk::mpl::Error> {
        unimplemented!("FakeKeyStore::create_key")
    }

    async fn version_key(
        &self,
        _input: VersionKeyInput,
    ) -> Result<VersionKeyOutput, aws_db_esdk::mpl::Error> {
        unimplemented!("FakeKeyStore::version_key")
    }

    async fn get_active_branch_key(
        &self,
        input: GetActiveBranchKeyInput,
    ) -> Result<GetActiveBranchKeyOutput, aws_db_esdk::mpl::Error> {
        GetActiveBranchKeyOutput::builder()
            .branch_key_materials(branch_materials(input.branch_key_id()))
            .build()
    }

    async fn get_branch_key_version(
        &self,
        input: GetBranchKeyVersionInput,
    ) -> Result<GetBranchKeyVersionOutput, aws_db_esdk::mpl::Error> {
        GetBranchKeyVersionOutput::builder()
            .branch_key_materials(branch_materials(input.branch_key_id()))
            .build()
    }

    async fn get_beacon_key(
        &self,
        input: GetBeaconKeyInput,
    ) -> Result<GetBeaconKeyOutput, aws_db_esdk::mpl::Error> {
        self.beacon_key_ids
            .lock()
            .unwrap()
            .push(input.branch_key_id().to_owned());
        let materials = BeaconKeyMaterials::builder()
            .beacon_key_id(input.branch_key_id())
            .set_encryption_context(Some(EncryptionContext::new()))
            .beacon_key(BEACON_KEY.to_vec())
            .build()?;
        GetBeaconKeyOutput::builder()
            .beacon_key_materials(materials)
            .build()
    }
}

pub fn fake_key_store() -> key_store::SharedKeyStore {
    key_store::SharedKeyStore::new(FakeKeyStore::default())
}

// The beacons of `BeaconTestFixtures.GetLotsaBeacons`.

fn standard(name: &str, bits: u8, loc: Option<&str>) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .set_location(loc.map(str::to_owned))
        .build()
        .unwrap()
}

fn encrypted_part(name: &str, prefix: &str) -> EncryptedPart {
    EncryptedPart::builder()
        .name(name)
        .prefix(prefix)
        .build()
        .unwrap()
}

fn signed_part(name: &str, prefix: &str, loc: Option<&str>) -> SignedPart {
    SignedPart::builder()
        .name(name)
        .prefix(prefix)
        .set_location(loc.map(str::to_owned))
        .build()
        .unwrap()
}

fn none_if_empty<T: Clone>(v: &[T]) -> Option<Vec<T>> {
    if v.is_empty() { None } else { Some(v.to_vec()) }
}

fn compound(
    name: &str,
    encrypted: &[EncryptedPart],
    signed: &[SignedPart],
    constructors: &[Constructor],
) -> CompoundBeacon {
    CompoundBeacon::builder()
        .name(name)
        .split(".")
        .set_encrypted(none_if_empty(encrypted))
        .set_signed(none_if_empty(signed))
        .set_constructors(none_if_empty(constructors))
        .build()
        .unwrap()
}

fn constructor(parts: &[(&str, bool)]) -> Constructor {
    let parts = parts
        .iter()
        .map(|(name, required)| {
            ConstructorPart::builder()
                .name(*name)
                .required(*required)
                .build()
                .unwrap()
        })
        .collect();
    Constructor::builder()
        .set_parts(Some(parts))
        .build()
        .unwrap()
}

/// `GetLotsaBeacons` (single key store, key id `foo`) or `GetLotsaBeaconsMulti`
/// (multi key store, key field `TheKeyField`).
pub fn lotsa_beacons(multi: bool) -> BeaconVersion {
    lotsa_beacons_with(multi, fake_key_store())
}

/// [`lotsa_beacons`] with its beacon keys from `store`.
pub fn lotsa_beacons_with(multi: bool, store: key_store::SharedKeyStore) -> BeaconVersion {
    let name = encrypted_part("Name", "N_");
    let title = encrypted_part("Title", "T_");
    let year = signed_part("Year", "Y_", None);
    let month = signed_part("Month", "M_", Some("Date.Month"));
    let name_title_field = VirtualField::builder()
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
        .unwrap();
    let key_source = if multi {
        BeaconKeySource::Multi(
            MultiKeyStore::builder()
                .key_field_name("TheKeyField")
                .cache_ttl(Duration::from_secs(42))
                .build()
                .unwrap(),
        )
    } else {
        BeaconKeySource::Single(
            SingleKeyStore::builder()
                .key_id("foo")
                .cache_ttl(Duration::from_secs(42))
                .build()
                .unwrap(),
        )
    };
    BeaconVersion::builder()
        .version(1)
        .key_store(store)
        .key_source(key_source)
        .standard_beacons(standard("std2", 24, None))
        .standard_beacons(standard("std4", 24, Some("std4")))
        .standard_beacons(standard("std6", 26, Some("std6[0]")))
        .standard_beacons(standard("NameTitleField", 28, None))
        .standard_beacons(standard("Name", 32, None))
        .standard_beacons(standard("Title", 32, None))
        .compound_beacons(compound(
            "NameTitle",
            &[name.clone(), title.clone()],
            &[],
            &[],
        ))
        .compound_beacons(compound(
            "YearName",
            std::slice::from_ref(&name),
            std::slice::from_ref(&year),
            &[],
        ))
        .compound_beacons(compound(
            "Mixed",
            &[name, title],
            &[year.clone(), month.clone()],
            &[
                constructor(&[("Name", true), ("Year", true)]),
                constructor(&[("Title", true), ("Month", false)]),
            ],
        ))
        .compound_beacons(compound("JustSigned", &[], &[year, month], &[]))
        .virtual_fields(name_title_field)
        .build()
        .unwrap()
}

/// `TestFixtures.MultiActions`, plus `foo` and `plain`.
pub fn multi_actions(b: aws_db_esdk::TableConfigBuilder) -> aws_db_esdk::TableConfigBuilder {
    MULTI_ACTIONS
        .into_iter()
        .fold(b, |b, (k, a)| b.attribute_actions_on_encrypt(k, a))
}

/// [`multi_actions`] with no action for the beacon key field `TheKeyField`,
/// so a multi key store removes that field before an item is encrypted.
pub fn multi_actions_without_key_field(
    b: aws_db_esdk::TableConfigBuilder,
) -> aws_db_esdk::TableConfigBuilder {
    MULTI_ACTIONS
        .into_iter()
        .filter(|(k, _)| *k != "TheKeyField")
        .fold(b, |b, (k, a)| b.attribute_actions_on_encrypt(k, a))
}

const MULTI_ACTIONS: [(&str, CryptoAction); 11] = [
    ("bar", CryptoAction::SignOnly),
    ("std2", CryptoAction::EncryptAndSign),
    ("std4", CryptoAction::EncryptAndSign),
    ("std6", CryptoAction::EncryptAndSign),
    ("Name", CryptoAction::EncryptAndSign),
    ("Title", CryptoAction::EncryptAndSign),
    ("TooBad", CryptoAction::EncryptAndSign),
    ("Year", CryptoAction::SignOnly),
    ("Date", CryptoAction::SignOnly),
    ("TheKeyField", CryptoAction::SignOnly),
    ("plain", CryptoAction::DoNothing),
];

/// A table `foo` with the `GetLotsaBeacons` search configuration and the static keyring.
pub fn beacon_transforms() -> Transforms {
    let search = SearchConfig::builder()
        .write_version(1)
        .versions(lotsa_beacons(false))
        .build()
        .unwrap();
    let config = multi_actions(TableConfig::builder())
        .logical_table_name("foo")
        .partition_key_name("bar")
        .allowed_unsigned_attributes("plain")
        .keyring(static_keyring())
        .search(search)
        .build()
        .unwrap();
    Transforms::builder()
        .table_encryption_configs("foo", config)
        .build()
        .unwrap()
}

/// A table `foo` whose only beacon, `std2`, has `partitions` partitions,
/// with at most `max` partitions per beacon version.
pub fn partitioned_transforms(partitions: u8, max: u8) -> Transforms {
    let std2 = StandardBeacon::builder()
        .name("std2")
        .bits(24)
        .number_of_partitions(partitions)
        .build()
        .unwrap();
    let version = BeaconVersion::builder()
        .version(1)
        .key_store(fake_key_store())
        .key_source(BeaconKeySource::Single(
            SingleKeyStore::builder()
                .key_id("foo")
                .cache_ttl(Duration::from_secs(42))
                .build()
                .unwrap(),
        ))
        .standard_beacons(std2)
        .maximum_number_of_partitions(max)
        .build()
        .unwrap();
    let search = SearchConfig::builder()
        .write_version(1)
        .versions(version)
        .build()
        .unwrap();
    let config = multi_actions(TableConfig::builder())
        .logical_table_name("foo")
        .partition_key_name("bar")
        .allowed_unsigned_attributes("plain")
        .keyring(static_keyring())
        .search(search)
        .build()
        .unwrap();
    Transforms::builder()
        .table_encryption_configs("foo", config)
        .build()
        .unwrap()
}

/// `TestFixtures.GetDynamoDbEncryptionTransformsMulti` with the static keyring.
pub fn multi_transforms_static(o: Option<PlaintextOverride>) -> Transforms {
    let search = SearchConfig::builder()
        .write_version(1)
        .versions(lotsa_beacons(true))
        .build()
        .unwrap();
    let config = multi_actions(TableConfig::builder())
        .logical_table_name("foo")
        .partition_key_name("bar")
        .allowed_unsigned_attributes("plain")
        .keyring(static_keyring())
        .search(search)
        .set_plaintext_override(o)
        .build()
        .unwrap();
    Transforms::builder()
        .table_encryption_configs("foo", config)
        .build()
        .unwrap()
}

/// `TestFixtures.GetDynamoDbEncryptionTransformsMulti` with a hierarchical keyring
/// over [`FakeKeyStore`] whose branch key id is `branch_key_id`.
pub async fn multi_transforms_hierarchical(branch_key_id: &str) -> Transforms {
    multi_transforms_hierarchical_with(branch_key_id, multi_actions).await
}

/// [`multi_transforms_hierarchical`] with the attribute actions `actions` sets.
pub async fn multi_transforms_hierarchical_with(
    branch_key_id: &str,
    actions: fn(aws_db_esdk::TableConfigBuilder) -> aws_db_esdk::TableConfigBuilder,
) -> Transforms {
    multi_transforms_configured(
        hierarchical_keyring(branch_key_id).await,
        fake_key_store(),
        actions,
    )
}

/// A hierarchical keyring over [`FakeKeyStore`] whose branch key id is `branch_key_id`.
pub async fn hierarchical_keyring(branch_key_id: &str) -> HierarchicalKeyring {
    HierarchicalKeyring::builder()
        .key_store(fake_key_store())
        .branch_key_id(branch_key_id)
        .ttl(Duration::from_secs(3600))
        .build()
        .await
        .unwrap()
}

/// `TestFixtures.GetDynamoDbEncryptionTransformsMulti` with `keyring`,
/// and beacon keys from `store`.
pub fn multi_transforms_with(
    keyring: impl IntoShared<SharedKeyring>,
    store: key_store::SharedKeyStore,
) -> Transforms {
    multi_transforms_configured(keyring, store, multi_actions)
}

/// [`multi_transforms_with`] with the attribute actions `actions` sets.
fn multi_transforms_configured(
    keyring: impl IntoShared<SharedKeyring>,
    store: key_store::SharedKeyStore,
    actions: fn(aws_db_esdk::TableConfigBuilder) -> aws_db_esdk::TableConfigBuilder,
) -> Transforms {
    let search = SearchConfig::builder()
        .write_version(1)
        .versions(lotsa_beacons_with(true, store))
        .build()
        .unwrap();
    let config = actions(TableConfig::builder())
        .logical_table_name("foo")
        .partition_key_name("bar")
        .allowed_unsigned_attributes("plain")
        .keyring(keyring)
        .search(search)
        .build()
        .unwrap();
    Transforms::builder()
        .table_encryption_configs("foo", config)
        .build()
        .unwrap()
}

// The beacon values of `BeaconTestFixtures`, under the key [`BEACON_KEY`].
pub const STD2_BEACON: &str = "ac6f5d";
pub const NAME_BEACON: &str = "7d9bfa40";
pub const TITLE_BEACON: &str = "e4feb833";
pub const STD4_BEACON: &str = "0e9064";
pub const STD6_BEACON: &str = "2d99222";
pub const NAME_TITLE_BEACON: &str = "4c577d7";

/// `BeaconTestFixtures.SimpleItem`, with partition key `bar`.
pub fn simple_item() -> Item {
    item(&[
        ("bar", s("key")),
        ("std2", n("1.23")),
        ("std4", s("abc")),
        ("std6", AttributeValue::L(vec![s("666")])),
        (
            "Date",
            AttributeValue::M(item(&[("Month", s("May")), ("Year", n("1984"))])),
        ),
        ("Year", n("1984")),
        ("Name", s("MyName")),
        ("Title", s("MyTitle")),
    ])
}
