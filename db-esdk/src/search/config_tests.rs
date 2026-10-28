// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests of the search configuration builders, and of converting a configuration to its
//! checked form. The fixtures are ported from `BeaconTestFixtures.dfy`, and the conversion
//! cases from `ConfigToInfo.dfy` and the configuration cases of `Beacon.dfy`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aws_crypto_mpl::Error as MplError;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;
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
use aws_crypto_mpl::key_store::{self, KeyStore};
use aws_crypto_mpl::types::{BeaconKeyMaterials, EncryptionContext};

use super::*;
use crate::ddb::Item;
use crate::keyring::RawAesKeyring;
use crate::search::convert::convert;
use crate::search::info::{Beacon, BeaconPart, ConstructorPartInfo, SearchInfo};
use crate::search::key_source::KeyLocation;
use crate::search::term_loc::TermLoc;
use crate::table_config::TableConfig;
use crate::types::{AesWrappingAlg, CryptoAction};

// ---------------------------------------------------------------------------
// Fixtures, ported from BeaconTestFixtures.dfy.
// ---------------------------------------------------------------------------

/// The beacon key every [`FakeKeyStore`] returns: `GetLiteralSource([1,2,3,4,5], ...)`.
pub(crate) const BEACON_KEY: [u8; 5] = [1, 2, 3, 4, 5];

/// An offline key store whose beacon key is always [`BEACON_KEY`].
/// It records the branch key id of every `get_beacon_key` call.
#[derive(Debug, Default)]
pub(crate) struct FakeKeyStore {
    pub(crate) requested: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl KeyStore for FakeKeyStore {
    async fn get_key_store_info(
        &self,
        _input: GetKeyStoreInfoInput,
    ) -> Result<GetKeyStoreInfoOutput, MplError> {
        GetKeyStoreInfoOutput::builder()
            .key_store_id("test-id")
            .key_store_name("KeyStoreDdbTable")
            .logical_key_store_name("KeyStoreDdbTable")
            .grant_tokens(Vec::<String>::new())
            .kms_configuration(KmsConfiguration::Discovery(Discovery::builder().build()?))
            .build()
    }

    async fn create_key_store(
        &self,
        _input: CreateKeyStoreInput,
    ) -> Result<CreateKeyStoreOutput, MplError> {
        unimplemented!("FakeKeyStore::create_key_store")
    }

    async fn create_key(&self, _input: CreateKeyInput) -> Result<CreateKeyOutput, MplError> {
        unimplemented!("FakeKeyStore::create_key")
    }

    async fn version_key(&self, _input: VersionKeyInput) -> Result<VersionKeyOutput, MplError> {
        unimplemented!("FakeKeyStore::version_key")
    }

    async fn get_active_branch_key(
        &self,
        _input: GetActiveBranchKeyInput,
    ) -> Result<GetActiveBranchKeyOutput, MplError> {
        unimplemented!("FakeKeyStore::get_active_branch_key")
    }

    async fn get_branch_key_version(
        &self,
        _input: GetBranchKeyVersionInput,
    ) -> Result<GetBranchKeyVersionOutput, MplError> {
        unimplemented!("FakeKeyStore::get_branch_key_version")
    }

    async fn get_beacon_key(
        &self,
        input: GetBeaconKeyInput,
    ) -> Result<GetBeaconKeyOutput, MplError> {
        self.requested
            .lock()
            .unwrap()
            .push(input.branch_key_id().to_owned());
        GetBeaconKeyOutput::builder()
            .beacon_key_materials(
                BeaconKeyMaterials::builder()
                    .beacon_key_id(input.branch_key_id())
                    .encryption_context(EncryptionContext::new())
                    .beacon_key(BEACON_KEY.to_vec())
                    .build()?,
            )
            .build()
    }
}

/// A [`FakeKeyStore`] client, and the branch key ids it is asked for.
pub(crate) fn fake_key_store() -> (key_store::Client, Arc<Mutex<Vec<String>>>) {
    let store = FakeKeyStore::default();
    let requested = Arc::clone(&store.requested);
    (key_store::Client::from(store), requested)
}

pub(crate) fn standard(name: &str, bits: u8, loc: Option<&str>) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .set_location(loc.map(str::to_owned))
        .build()
        .unwrap()
}

pub(crate) fn styled(name: &str, bits: u8, style: BeaconStyle) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .style(style)
        .build()
        .unwrap()
}

pub(crate) fn std2() -> StandardBeacon {
    standard("std2", 24, None)
}
pub(crate) fn std4() -> StandardBeacon {
    standard("std4", 24, Some("std4"))
}
pub(crate) fn std6() -> StandardBeacon {
    standard("std6", 26, Some("std6[0]"))
}
pub(crate) fn name_b() -> StandardBeacon {
    standard("Name", 32, None)
}
pub(crate) fn title_b() -> StandardBeacon {
    standard("Title", 32, None)
}
pub(crate) fn too_bad_b() -> StandardBeacon {
    standard("TooBad", 32, None)
}
pub(crate) fn name_title_beacon() -> StandardBeacon {
    standard("NameTitleField", 28, None)
}

pub(crate) fn signed_part(name: &str, prefix: &str, loc: Option<&str>) -> SignedPart {
    SignedPart::builder()
        .name(name)
        .prefix(prefix)
        .set_location(loc.map(str::to_owned))
        .build()
        .unwrap()
}

pub(crate) fn encrypted_part(name: &str, prefix: &str) -> EncryptedPart {
    EncryptedPart::builder()
        .name(name)
        .prefix(prefix)
        .build()
        .unwrap()
}

pub(crate) fn year() -> SignedPart {
    signed_part("Year", "Y_", None)
}
pub(crate) fn month() -> SignedPart {
    signed_part("Month", "M_", Some("Date.Month"))
}
pub(crate) fn nothing() -> SignedPart {
    signed_part("Nothing", "N__", None)
}
pub(crate) fn name_p() -> EncryptedPart {
    encrypted_part("Name", "N_")
}
pub(crate) fn title_p() -> EncryptedPart {
    encrypted_part("Title", "T_")
}
pub(crate) fn too_bad_p() -> EncryptedPart {
    encrypted_part("TooBad", "T")
}

pub(crate) fn compound(
    name: &str,
    encrypted: Option<Vec<EncryptedPart>>,
    signed: Option<Vec<SignedPart>>,
    constructors: Option<Vec<Constructor>>,
) -> CompoundBeacon {
    CompoundBeacon::builder()
        .name(name)
        .split(".")
        .set_encrypted(encrypted)
        .set_signed(signed)
        .set_constructors(constructors)
        .build()
        .unwrap()
}

pub(crate) fn constructor(parts: &[(&str, bool)]) -> Constructor {
    Constructor::builder()
        .set_parts(Some(
            parts
                .iter()
                .map(|(n, r)| {
                    ConstructorPart::builder()
                        .name(*n)
                        .required(*r)
                        .build()
                        .unwrap()
                })
                .collect(),
        ))
        .build()
        .unwrap()
}

pub(crate) fn name_title() -> CompoundBeacon {
    compound("NameTitle", Some(vec![name_p(), title_p()]), None, None)
}
pub(crate) fn year_name() -> CompoundBeacon {
    compound("YearName", Some(vec![name_p()]), Some(vec![year()]), None)
}
pub(crate) fn bad_prefix() -> CompoundBeacon {
    compound(
        "BadPrefix",
        Some(vec![name_p(), title_p(), too_bad_p()]),
        None,
        None,
    )
}
pub(crate) fn bad_prefix2() -> CompoundBeacon {
    compound(
        "BadPrefix2",
        Some(vec![name_p()]),
        Some(vec![nothing()]),
        None,
    )
}
pub(crate) fn just_signed() -> CompoundBeacon {
    compound("JustSigned", None, Some(vec![year(), month()]), None)
}
pub(crate) fn mixed() -> CompoundBeacon {
    compound(
        "Mixed",
        Some(vec![name_p(), title_p()]),
        Some(vec![year(), month()]),
        Some(vec![
            constructor(&[("Name", true), ("Year", true)]),
            constructor(&[("Title", true), ("Month", false)]),
        ]),
    )
}

pub(crate) fn virtual_part(loc: &str, transform: VirtualTransform) -> VirtualPart {
    VirtualPart::builder()
        .location(loc)
        .transforms(transform)
        .build()
        .unwrap()
}
pub(crate) fn vpart1() -> VirtualPart {
    virtual_part("Name", VirtualTransform::insert("__"))
}
pub(crate) fn vpart2() -> VirtualPart {
    virtual_part("Title", VirtualTransform::lower())
}
pub(crate) fn virtual_field(name: &str, parts: Vec<VirtualPart>) -> VirtualField {
    VirtualField::builder()
        .name(name)
        .set_parts(Some(parts))
        .build()
        .unwrap()
}
pub(crate) fn name_title_field() -> VirtualField {
    virtual_field("NameTitleField", vec![vpart1(), vpart2()])
}
pub(crate) fn name_virt_field() -> VirtualField {
    virtual_field("NameVirtField", vec![vpart1()])
}

pub(crate) fn single_source(key_id: &str) -> BeaconKeySource {
    BeaconKeySource::Single(
        SingleKeyStore::builder()
            .key_id(key_id)
            .cache_ttl(Duration::from_secs(42))
            .build()
            .unwrap(),
    )
}

pub(crate) fn multi_source(key_field_name: &str) -> BeaconKeySource {
    BeaconKeySource::Multi(
        MultiKeyStore::builder()
            .key_field_name(key_field_name)
            .cache_ttl(Duration::from_secs(42))
            .build()
            .unwrap(),
    )
}

/// `GetLotsaBeacons`, as an unbuilt builder so tests can replace parts of it.
pub(crate) fn lotsa_beacons(store: key_store::Client) -> BeaconVersionBuilder {
    BeaconVersion::builder()
        .version(1)
        .key_store(store)
        .key_source(single_source("foo"))
        .set_standard_beacons(Some(vec![
            std2(),
            std4(),
            std6(),
            name_title_beacon(),
            name_b(),
            title_b(),
        ]))
        .set_compound_beacons(Some(vec![
            name_title(),
            year_name(),
            mixed(),
            just_signed(),
        ]))
        .virtual_fields(name_title_field())
}

/// The attribute actions of `FullTableConfig`.
pub(crate) fn full_actions() -> HashMap<String, CryptoAction> {
    [
        ("std2", CryptoAction::EncryptAndSign),
        ("std4", CryptoAction::EncryptAndSign),
        ("std6", CryptoAction::EncryptAndSign),
        ("Name", CryptoAction::EncryptAndSign),
        ("Title", CryptoAction::EncryptAndSign),
        ("TooBad", CryptoAction::EncryptAndSign),
        ("Year", CryptoAction::SignOnly),
        ("Date", CryptoAction::SignOnly),
        ("TheKeyField", CryptoAction::SignOnly),
    ]
    .into_iter()
    .map(|(n, a)| (n.to_owned(), a))
    .collect()
}

/// `FullTableConfig` with `extra` actions added, searching with `version`.
pub(crate) fn table_with(
    extra: &[(&str, CryptoAction)],
    version: BeaconVersion,
) -> TableConfigBuilderExt {
    let mut actions = full_actions();
    for (n, a) in extra {
        actions.insert((*n).to_owned(), *a);
    }
    TableConfigBuilderExt {
        builder: TableConfig::builder()
            .logical_table_name("Foo")
            .partition_key_name("foo")
            .set_attribute_actions_on_encrypt(Some(actions))
            .keyring(
                RawAesKeyring::builder()
                    .key_namespace("ns")
                    .key_name("name")
                    .wrapping_key(vec![1u8; 32])
                    .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
                    .build()
                    .unwrap(),
            )
            .search(
                SearchConfig::builder()
                    .versions(version)
                    .write_version(1)
                    .build()
                    .unwrap(),
            ),
    }
}

/// A table builder that converts its search configuration.
pub(crate) struct TableConfigBuilderExt {
    pub(crate) builder: crate::table_config::TableConfigBuilder,
}

impl TableConfigBuilderExt {
    pub(crate) fn convert(self) -> Result<SearchInfo, Error> {
        convert(&self.builder.build().unwrap()).map(|info| info.unwrap())
    }
}

/// `ConvertVersionWithSource(FullTableConfig + extra, version, src)`.
pub(crate) fn convert_with(
    extra: &[(&str, CryptoAction)],
    version: BeaconVersionBuilder,
) -> Result<SearchInfo, Error> {
    table_with(extra, version.build().unwrap()).convert()
}

/// The message of a `Validation` error.
#[track_caller]
pub(crate) fn validation_message<T: std::fmt::Debug>(result: Result<T, Error>) -> String {
    let err = result.unwrap_err();
    assert!(err.is_validation(), "not a Validation error: {err:?}");
    err.message().to_owned()
}

/// `SimpleItem`.
pub(crate) fn simple_item() -> Item {
    [
        ("std2", AttributeValue::N("1.23".to_owned())),
        ("std4", AttributeValue::S("abc".to_owned())),
        (
            "std6",
            AttributeValue::L(vec![AttributeValue::S("666".to_owned())]),
        ),
        (
            "Date",
            AttributeValue::M(
                [
                    ("Month".to_owned(), AttributeValue::S("May".to_owned())),
                    ("Year".to_owned(), AttributeValue::N("1984".to_owned())),
                ]
                .into_iter()
                .collect(),
            ),
        ),
        ("Year", AttributeValue::N("1984".to_owned())),
        ("Name", AttributeValue::S("MyName".to_owned())),
        ("Title", AttributeValue::S("MyTitle".to_owned())),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_owned(), v))
    .collect()
}

fn store() -> key_store::Client {
    fake_key_store().0
}

// ---------------------------------------------------------------------------
// Builders.
// ---------------------------------------------------------------------------

#[test]
fn search_config_builder_checks_versions() {
    let version = lotsa_beacons(store()).build().unwrap();

    //= spec/searchable-encryption/search-config.md#initialization
    //= type=test
    //# On initialization of the Search Config, the caller MUST provide:
    assert_eq!(
        validation_message(SearchConfig::builder().write_version(1).build()),
        "versions is required"
    );
    assert_eq!(
        validation_message(
            SearchConfig::builder()
                .set_versions(Some(vec![version.clone(), version.clone()]))
                .write_version(1)
                .build()
        ),
        "versions must have exactly one beacon version"
    );
    assert_eq!(
        validation_message(SearchConfig::builder().versions(version.clone()).build()),
        "write_version is required"
    );
    assert_eq!(
        validation_message(
            SearchConfig::builder()
                .versions(version.clone())
                .set_write_version(Some(0))
                .build()
        ),
        "write_version must be at least 1"
    );

    let config = SearchConfig::builder()
        .versions(version)
        .write_version(1)
        .build()
        .unwrap();
    assert_eq!(config.write_version(), 1);
    assert_eq!(config.versions().len(), 1);
    assert_eq!(config.versions()[0].standard_beacons().len(), 6);
}

#[test]
fn beacon_version_builder_rejects_each_invalid_field() {
    let base = || lotsa_beacons(store());
    let cases: Vec<(BeaconVersionBuilder, &str)> = vec![
        (base().version(0), "version must be at least 1"),
        (
            base().set_standard_beacons(Some(vec![])),
            "standard_beacons must not be empty",
        ),
        (
            base().set_compound_beacons(Some(vec![])),
            "compound_beacons must not be empty",
        ),
        (
            base().set_virtual_fields(Some(vec![])),
            "virtual_fields must not be empty",
        ),
        (
            base().set_encrypted_parts(Some(vec![])),
            "encrypted_parts must not be empty",
        ),
        (
            base().set_signed_parts(Some(vec![])),
            "signed_parts must not be empty",
        ),
        (
            base().maximum_number_of_partitions(0),
            "maximum_number_of_partitions must be between 1 and 255",
        ),
        (
            base().default_number_of_partitions(0),
            "default_number_of_partitions must be between 1 and 255",
        ),
    ];
    for (builder, expected) in cases {
        assert_eq!(validation_message(builder.build()), expected);
    }
    // Each field the caller must provide.
    for (builder, expected) in [
        (base().set_version(None), "version is required"),
        (
            base().set_standard_beacons(None),
            "standard_beacons is required",
        ),
        (base().set_key_store(None), "key_store is required"),
        (base().set_key_source(None), "key_source is required"),
    ] {
        //= spec/searchable-encryption/search-config.md#beacon-version-initialization
        //= type=test
        //# On initialization of a Beacon Version, the caller MUST provide:
        assert_eq!(validation_message(builder.build()), expected);
    }
}

#[test]
fn beacon_version_builder_keeps_every_field() {
    let version = BeaconVersion::builder()
        .version(1)
        .key_store(store())
        .key_source(multi_source("TheKeyField"))
        .standard_beacons(std2())
        .standard_beacons(name_b())
        .compound_beacons(year_name())
        .virtual_fields(name_virt_field())
        .encrypted_parts(title_p())
        .signed_parts(month())
        .maximum_number_of_partitions(5)
        .set_maximum_number_of_partitions(Some(6))
        .default_number_of_partitions(3)
        .set_default_number_of_partitions(Some(4))
        .partition_selector(crate::search::partition::RandomPartitionSelector)
        .set_partition_selector(None)
        .build()
        .unwrap();
    assert_eq!(version.version(), 1);
    let names: Vec<&str> = version
        .standard_beacons()
        .iter()
        .map(StandardBeacon::name)
        .collect();
    assert_eq!(names, ["std2", "Name"]);

    //= spec/searchable-encryption/search-config.md#beacon-version-initialization
    //= type=test
    //# On initialization of the Beacon Version, the caller MAY provide:
    assert_eq!(version.compound_beacons()[0].name(), "YearName");
    assert_eq!(version.virtual_fields()[0].name(), "NameVirtField");
    assert_eq!(version.encrypted_parts()[0].name(), "Title");
    assert_eq!(version.signed_parts()[0].name(), "Month");
    assert_eq!(version.maximum_number_of_partitions(), Some(6));
    assert_eq!(version.default_number_of_partitions(), Some(4));
    assert!(version.partition_selector().is_none());
    assert!(matches!(
        version.key_source(),
        BeaconKeySource::Multi(m) if m.key_field_name() == "TheKeyField"
    ));

    // The optional lists read as empty when unset.
    let bare = BeaconVersion::builder()
        .version(1)
        .key_store(store())
        .key_source(single_source("foo"))
        .standard_beacons(std2())
        .build()
        .unwrap();
    assert!(bare.compound_beacons().is_empty());
    assert!(bare.virtual_fields().is_empty());
    assert!(bare.encrypted_parts().is_empty());
    assert!(bare.signed_parts().is_empty());
    assert_eq!(bare.maximum_number_of_partitions(), None);
    assert_eq!(bare.default_number_of_partitions(), None);
}

#[tokio::test]
async fn key_store_builders() {
    //= spec/searchable-encryption/search-config.md#single-key-store-initialization
    //= type=test
    //# On initialization of a Single Key Store, the caller MUST provide:
    assert_eq!(
        validation_message(
            SingleKeyStore::builder()
                .cache_ttl(Duration::from_secs(1))
                .build()
        ),
        "key_id is required"
    );
    assert_eq!(
        validation_message(SingleKeyStore::builder().key_id("k").build()),
        "cache_ttl is required"
    );

    //= spec/searchable-encryption/search-config.md#multi-key-store-initialization
    //= type=test
    //# On initialization of a Multi Key Store, the caller MUST provide:
    assert_eq!(
        validation_message(
            MultiKeyStore::builder()
                .cache_ttl(Duration::from_secs(1))
                .build()
        ),
        "key_field_name is required"
    );
    assert_eq!(
        validation_message(MultiKeyStore::builder().key_field_name("k").build()),
        "cache_ttl is required"
    );

    let cache: SharedCmc = aws_crypto_mpl::cmc::DefaultCmc::builder()
        .entry_capacity(1)
        .build()
        .unwrap()
        .into_shared();
    let single = SingleKeyStore::builder()
        .set_key_id(Some("k1".to_owned()))
        .set_cache_ttl(Some(Duration::from_secs(7)))
        .cache(cache.clone())
        .partition_id("p1")
        .build()
        .unwrap();
    assert_eq!(single.key_id(), "k1");
    assert_eq!(single.cache_ttl(), Duration::from_secs(7));
    assert!(single.cache().is_some());
    assert_eq!(single.partition_id(), Some("p1"));
    let single = SingleKeyStore::builder()
        .key_id("k1")
        .cache_ttl(Duration::from_secs(7))
        .cache(cache.clone())
        .set_cache(None)
        .partition_id("p1")
        .set_partition_id(None)
        .build()
        .unwrap();
    assert!(single.cache().is_none());
    assert_eq!(single.partition_id(), None);

    let multi = MultiKeyStore::builder()
        .set_key_field_name(Some("f".to_owned()))
        .set_cache_ttl(Some(Duration::from_secs(9)))
        .cache(cache.clone())
        .partition_id("p2")
        .build()
        .unwrap();
    assert_eq!(multi.key_field_name(), "f");
    assert_eq!(multi.cache_ttl(), Duration::from_secs(9));
    assert!(multi.cache().is_some());
    assert_eq!(multi.partition_id(), Some("p2"));
    let multi = MultiKeyStore::builder()
        .key_field_name("f")
        .cache_ttl(Duration::from_secs(9))
        .cache(cache)
        .set_cache(None)
        .partition_id("p2")
        .set_partition_id(None)
        .build()
        .unwrap();
    assert!(multi.cache().is_none());
    assert_eq!(multi.partition_id(), None);
}

#[test]
fn standard_beacon_builder_checks_length_location_and_partitions() {
    let base = || StandardBeacon::builder().name("b").bits(8);

    //= spec/searchable-encryption/beacons.md#standard-beacon-initialization
    //= type=test
    //# On initialization of a Standard Beacon, the caller MUST provide:
    assert_eq!(
        validation_message(StandardBeacon::builder().name("b").build()),
        "bits is required"
    );
    for bits in [0, 64, 255] {
        //= spec/searchable-encryption/beacons.md#beacon-length
        //= type=test
        //# A beacon length MUST be an integer between 1 and 63 inclusive,
        //# indicating the number of bits in the resulting beacon.
        assert_eq!(
            validation_message(base().bits(bits).build()),
            "bits must be between 1 and 63"
        );
    }
    assert_eq!(base().bits(1).build().unwrap().bits(), 1);
    assert_eq!(base().set_bits(Some(63)).build().unwrap().bits(), 63);
    assert_eq!(
        validation_message(base().location("").build()),
        "location must not be empty"
    );
    assert_eq!(
        validation_message(base().number_of_partitions(0).build()),
        "number_of_partitions must be between 1 and 255"
    );
    assert_eq!(
        validation_message(base().set_name(None).build()),
        "name is required"
    );

    //= spec/searchable-encryption/beacons.md#standard-beacon-initialization
    //= type=test
    //# On initialization of a Standard Beacon, the caller MAY provide:
    let beacon = base()
        .location("a.b[2]")
        .number_of_partitions(3)
        .style(BeaconStyle::as_set())
        .build()
        .unwrap();
    assert_eq!(beacon.name(), "b");
    assert_eq!(beacon.location(), Some("a.b[2]"));
    assert_eq!(beacon.number_of_partitions(), Some(3));
    assert!(matches!(beacon.style(), Some(BeaconStyle::AsSet(_))));

    let beacon = base()
        .location("x")
        .set_location(None)
        .number_of_partitions(3)
        .set_number_of_partitions(None)
        .style(BeaconStyle::part_only())
        .set_style(None)
        .build()
        .unwrap();
    assert_eq!(beacon.location(), None);
    assert_eq!(beacon.number_of_partitions(), None);
    assert!(beacon.style().is_none());
}

#[test]
fn beacon_styles() {
    assert!(matches!(BeaconStyle::part_only(), BeaconStyle::PartOnly(_)));
    assert!(matches!(BeaconStyle::shared("o"), BeaconStyle::Shared(s) if s.other() == "o"));
    assert!(matches!(
        BeaconStyle::shared_set("o"),
        BeaconStyle::SharedSet(s) if s.other() == "o"
    ));

    //= spec/searchable-encryption/beacons.md#shared-initialization
    //= type=test
    //# On initialization of a Shared, the caller MUST provide:
    assert_eq!(
        validation_message(Shared::builder().build()),
        "other is required"
    );
    assert_eq!(
        Shared::builder()
            .set_other(Some("x".to_owned()))
            .build()
            .unwrap()
            .other(),
        "x"
    );
    assert_eq!(Shared::builder().other("y").build().unwrap().other(), "y");

    //= spec/searchable-encryption/beacons.md#sharedset-initialization
    //= type=test
    //# On initialization of a SharedSet, the caller MUST provide:
    assert_eq!(
        validation_message(SharedSet::builder().build()),
        "other is required"
    );
    assert_eq!(
        SharedSet::builder()
            .set_other(Some("x".to_owned()))
            .build()
            .unwrap()
            .other(),
        "x"
    );
    assert_eq!(
        SharedSet::builder().other("y").build().unwrap().other(),
        "y"
    );
}

#[test]
fn compound_beacon_builder_checks_split_and_lists() {
    let split_dot = || CompoundBeacon::builder().name("c").split(".");

    //= spec/searchable-encryption/beacons.md#compound-beacon-initialization
    //= type=test
    //# On initialization of a Compound Beacon, the caller MUST provide:
    assert_eq!(
        validation_message(CompoundBeacon::builder().name("c").build()),
        "split is required"
    );
    for split in ["", "..", "ab"] {
        assert_eq!(
            validation_message(split_dot().split(split).build()),
            "split must be exactly one character"
        );
    }
    // One character, even when it is more than one byte.
    assert_eq!(
        split_dot().split("\u{e9}").build().unwrap().split(),
        '\u{e9}'
    );
    assert_eq!(
        validation_message(split_dot().set_encrypted(Some(vec![])).build()),
        "encrypted must not be empty"
    );
    assert_eq!(
        validation_message(split_dot().set_signed(Some(vec![])).build()),
        "signed must not be empty"
    );
    assert_eq!(
        validation_message(split_dot().set_constructors(Some(vec![])).build()),
        "constructors must not be empty"
    );
    assert_eq!(
        validation_message(split_dot().set_name(None).build()),
        "name is required"
    );

    //= spec/searchable-encryption/beacons.md#compound-beacon-initialization
    //= type=test
    //# On initialization of a Compound Beacon, the caller MAY provide:
    let beacon = CompoundBeacon::builder()
        .set_name(Some("c".to_owned()))
        .set_split(Some("|".to_owned()))
        .encrypted(name_p())
        .signed(year())
        .constructors(constructor(&[("Name", true)]))
        .build()
        .unwrap();
    assert_eq!(beacon.name(), "c");
    assert_eq!(beacon.split(), '|');
    assert_eq!(beacon.encrypted()[0].prefix(), "N_");
    assert_eq!(beacon.signed()[0].prefix(), "Y_");
    assert_eq!(beacon.constructors()[0].parts()[0].name(), "Name");

    let no_lists = split_dot().build().unwrap();
    assert!(no_lists.encrypted().is_empty());
    assert!(no_lists.signed().is_empty());
    assert!(no_lists.constructors().is_empty());
}

#[test]
fn part_builders_check_prefix_and_location() {
    //= spec/searchable-encryption/beacons.md#encrypted-part-initialization
    //= type=test
    //# On initialization of a [encrypted part](#encrypted-part-initialization), the caller MUST provide:
    assert_eq!(
        validation_message(EncryptedPart::builder().name("n").build()),
        "prefix is required"
    );
    assert_eq!(
        validation_message(EncryptedPart::builder().name("n").prefix("").build()),
        "prefix must not be empty"
    );
    assert_eq!(
        validation_message(EncryptedPart::builder().prefix("p").build()),
        "name is required"
    );
    let part = EncryptedPart::builder()
        .set_name(Some("n".to_owned()))
        .set_prefix(Some("p".to_owned()))
        .build()
        .unwrap();
    assert_eq!((part.name(), part.prefix()), ("n", "p"));

    //= spec/searchable-encryption/beacons.md#signed-part-initialization
    //= type=test
    //# On initialization of a [signed part](#signed-part-initialization), the caller MUST provide:
    assert_eq!(
        validation_message(SignedPart::builder().name("n").build()),
        "prefix is required"
    );
    assert_eq!(
        validation_message(SignedPart::builder().name("n").prefix("").build()),
        "prefix must not be empty"
    );
    assert_eq!(
        validation_message(
            SignedPart::builder()
                .name("n")
                .prefix("p")
                .location("")
                .build()
        ),
        "location must not be empty"
    );
    assert_eq!(
        validation_message(SignedPart::builder().prefix("p").build()),
        "name is required"
    );
    let part = SignedPart::builder()
        .set_name(Some("n".to_owned()))
        .set_prefix(Some("p".to_owned()))
        //= spec/searchable-encryption/beacons.md#signed-part-initialization
        //= type=test
        //# On initialization of a [signed parts](#signed-part-initialization), the caller MAY provide:
        .location("a.b")
        .build()
        .unwrap();
    assert_eq!(
        (part.name(), part.prefix(), part.location()),
        ("n", "p", Some("a.b"))
    );
}

#[test]
fn constructor_builders() {
    //= spec/searchable-encryption/beacons.md#constructor-initialization
    //= type=test
    //# On initialization of a constructor, the caller MUST provide:
    assert_eq!(
        validation_message(Constructor::builder().build()),
        "parts is required"
    );
    assert_eq!(
        validation_message(Constructor::builder().set_parts(Some(vec![])).build()),
        "parts must not be empty"
    );

    //= spec/searchable-encryption/beacons.md#constructor-part-initialization
    //= type=test
    //# On initialization of a constructor part, the caller MUST provide:
    assert_eq!(
        validation_message(ConstructorPart::builder().required(true).build()),
        "name is required"
    );
    assert_eq!(
        validation_message(ConstructorPart::builder().name("n").build()),
        "required is required"
    );

    let part = ConstructorPart::builder()
        .set_name(Some("n".to_owned()))
        .set_required(Some(false))
        .build()
        .unwrap();
    assert_eq!((part.name(), part.is_required()), ("n", false));
    let shortcut = ConstructorPart::required("m");
    assert_eq!((shortcut.name(), shortcut.is_required()), ("m", true));

    let c = Constructor::builder()
        .parts(shortcut)
        .parts(part)
        .build()
        .unwrap();
    let names: Vec<&str> = c.parts().iter().map(ConstructorPart::name).collect();
    assert_eq!(names, ["m", "n"]);
}

#[test]
fn virtual_field_builders() {
    //= spec/searchable-encryption/virtual.md#virtual-field-initialization
    //= type=test
    //# On initialization of a Virtual Field, the caller MUST provide:
    assert_eq!(
        validation_message(VirtualField::builder().name("v").build()),
        "parts is required"
    );
    assert_eq!(
        validation_message(
            VirtualField::builder()
                .name("v")
                .set_parts(Some(vec![]))
                .build()
        ),
        "parts must not be empty"
    );
    assert_eq!(
        validation_message(VirtualField::builder().parts(vpart1()).build()),
        "name is required"
    );
    let field = VirtualField::builder()
        .set_name(Some("v".to_owned()))
        .parts(vpart1())
        .parts(vpart2())
        .build()
        .unwrap();
    assert_eq!(field.name(), "v");
    let locs: Vec<&str> = field.parts().iter().map(VirtualPart::location).collect();
    assert_eq!(locs, ["Name", "Title"]);

    //= spec/searchable-encryption/virtual.md#virtual-part-initialization
    //= type=test
    //# On initialization of a Virtual Part, the caller MUST provide:
    assert_eq!(
        validation_message(VirtualPart::builder().build()),
        "location is required"
    );
    assert_eq!(
        validation_message(VirtualPart::builder().location("").build()),
        "location must not be empty"
    );
    assert_eq!(
        validation_message(
            VirtualPart::builder()
                .location("a")
                .set_transforms(Some(vec![]))
                .build()
        ),
        "transforms must not be empty"
    );
    let part = VirtualPart::builder()
        .set_location(Some("a".to_owned()))
        .build()
        .unwrap();
    assert_eq!(part.location(), "a");
    assert!(part.transforms().is_empty());

    //= spec/searchable-encryption/virtual.md#virtual-part-initialization
    //= type=test
    //# On initialization of a Virtual Part, the caller MAY provide:
    assert!(matches!(
        vpart1().transforms(),
        [VirtualTransform::Insert(i)] if i.literal() == "__"
    ));
}

#[test]
fn transform_builders() {
    //= spec/searchable-encryption/virtual.md#insert-transform-initialization
    //= type=test
    //# On initialization of an Insert Transform, the caller MUST provide:
    assert_eq!(
        validation_message(Insert::builder().build()),
        "literal is required"
    );
    assert_eq!(
        Insert::builder()
            .set_literal(Some("x".to_owned()))
            .build()
            .unwrap()
            .literal(),
        "x"
    );
    assert_eq!(
        Insert::builder().literal("y").build().unwrap().literal(),
        "y"
    );

    //= spec/searchable-encryption/virtual.md#getprefix-transform-initialization
    //= type=test
    //# On initialization of a GetPrefix Transform, the caller MUST provide:
    assert_eq!(
        validation_message(GetPrefix::builder().build()),
        "length is required"
    );
    assert_eq!(
        GetPrefix::builder().length(-1).build().unwrap().length(),
        -1
    );
    assert_eq!(
        GetPrefix::builder()
            .set_length(Some(3))
            .build()
            .unwrap()
            .length(),
        3
    );

    //= spec/searchable-encryption/virtual.md#getsuffix-transform-initialization
    //= type=test
    //# On initialization of a GetSuffix Transform, the caller MUST provide:
    assert_eq!(
        validation_message(GetSuffix::builder().build()),
        "length is required"
    );
    assert_eq!(
        GetSuffix::builder().length(-2).build().unwrap().length(),
        -2
    );
    assert_eq!(
        GetSuffix::builder()
            .set_length(Some(4))
            .build()
            .unwrap()
            .length(),
        4
    );

    //= spec/searchable-encryption/virtual.md#getsubstring-transform-initialization
    //= type=test
    //# On initialization of a GetSubstring Transform, the caller MUST provide:
    assert_eq!(
        validation_message(GetSubstring::builder().high(1).build()),
        "low is required"
    );
    assert_eq!(
        validation_message(GetSubstring::builder().low(1).build()),
        "high is required"
    );
    let s = GetSubstring::builder()
        .set_low(Some(1))
        .set_high(Some(-1))
        .build()
        .unwrap();
    assert_eq!((s.low(), s.high()), (1, -1));
    let s = GetSubstring::builder().low(2).high(5).build().unwrap();
    assert_eq!((s.low(), s.high()), (2, 5));

    //= spec/searchable-encryption/virtual.md#getsegment-transform-initialization
    //= type=test
    //# On initialization of a GetSegment Transform, the caller MUST provide:
    assert_eq!(
        validation_message(GetSegment::builder().index(1).build()),
        "split is required"
    );
    assert_eq!(
        validation_message(GetSegment::builder().split("ab").index(1).build()),
        "split must be exactly one character"
    );
    assert_eq!(
        validation_message(GetSegment::builder().split(".").build()),
        "index is required"
    );
    let s = GetSegment::builder()
        .set_split(Some("-".to_owned()))
        .set_index(Some(-1))
        .build()
        .unwrap();
    assert_eq!((s.split(), s.index()), ('-', -1));
    let s = GetSegment::builder().split(".").index(2).build().unwrap();
    assert_eq!((s.split(), s.index()), ('.', 2));

    //= spec/searchable-encryption/virtual.md#getsegments-transform-initialization
    //= type=test
    //# On initialization of a GetSegments Transform, the caller MUST provide:
    assert_eq!(
        validation_message(GetSegments::builder().low(0).high(1).build()),
        "split is required"
    );
    assert_eq!(
        validation_message(GetSegments::builder().split("").low(0).high(1).build()),
        "split must be exactly one character"
    );
    assert_eq!(
        validation_message(GetSegments::builder().split(".").high(1).build()),
        "low is required"
    );
    assert_eq!(
        validation_message(GetSegments::builder().split(".").low(0).build()),
        "high is required"
    );
    let s = GetSegments::builder()
        .set_split(Some("/".to_owned()))
        .set_low(Some(1))
        .set_high(Some(3))
        .build()
        .unwrap();
    assert_eq!((s.split(), s.low(), s.high()), ('/', 1, 3));
    let s = GetSegments::builder()
        .split(".")
        .low(0)
        .high(-1)
        .build()
        .unwrap();
    assert_eq!((s.split(), s.low(), s.high()), ('.', 0, -1));

    assert!(matches!(
        VirtualTransform::upper(),
        VirtualTransform::Upper(_)
    ));
    assert!(matches!(VirtualTransform::prefix(3), VirtualTransform::Prefix(p) if p.length() == 3));
    assert!(
        matches!(VirtualTransform::suffix(-3), VirtualTransform::Suffix(p) if p.length() == -3)
    );
    assert!(matches!(
        VirtualTransform::substring(1, 4),
        VirtualTransform::Substring(s) if (s.low(), s.high()) == (1, 4)
    ));
    assert!(matches!(
        VirtualTransform::segment('.', 2),
        VirtualTransform::Segment(s) if (s.split(), s.index()) == ('.', 2)
    ));
    assert!(matches!(
        VirtualTransform::segments('.', 0, 2),
        VirtualTransform::Segments(s) if (s.split(), s.low(), s.high()) == ('.', 0, 2)
    ));
}

// ---------------------------------------------------------------------------
// Conversion: ConfigToInfo.dfy.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_beacons_one_loc() {
    let fred = standard("fred", 16, Some("std6[0]"));
    let version = lotsa_beacons(store()).set_standard_beacons(Some(vec![
        std2(),
        std4(),
        std6(),
        name_title_beacon(),
        name_b(),
        title_b(),
        fred,
    ]));

    //= spec/searchable-encryption/beacons.md#standard-beacon-initialization
    //= type=test
    //# Initialization MUST fail if two standard beacons are configured with the same location.
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Beacon fred is defined on location std6[0], but beacon std6 is already defined on that location."
    );
}

#[tokio::test]
async fn two_virt_one_loc() {
    let title_name_field = virtual_field("TitleNameField", vec![vpart2(), vpart1()]);
    let version =
        lotsa_beacons(store()).set_virtual_fields(Some(vec![name_title_field(), title_name_field]));

    //= spec/searchable-encryption/virtual.md#virtual-field-initialization
    //= type=test
    //# Initialization MUST fail if two virtual fields are defined with the same set of locations.
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Virtual field TitleNameField is defined on the same locations as NameTitleField."
    );
}

#[tokio::test]
async fn virt_and_beacon_same_loc() {
    let version = lotsa_beacons(store())
        .set_virtual_fields(Some(vec![name_virt_field(), name_title_field()]));

    //= spec/searchable-encryption/virtual.md#virtual-field-initialization
    //= type=test
    //# Initialization MUST fail if a virtual field is defined with only one location,
    //# and also a [standard beacon](beacons.md#standard-beacon) is defined with that same location.
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Beacon Name is defined on location Name, but virtual field NameVirtField is already defined on that single location."
    );
}

#[tokio::test]
async fn ns_with_eb() {
    let standards = || Some(vec![std2(), std4(), std6(), name_title_beacon(), title_b()]);
    // A compound beacon named like an encrypted attribute is allowed when it has an encrypted part.
    let with_encrypted_part = compound(
        "Name",
        Some(vec![title_p()]),
        Some(vec![year(), month()]),
        None,
    );
    let version = lotsa_beacons(store())
        .set_compound_beacons(Some(vec![with_encrypted_part]))
        .set_standard_beacons(standards());
    let info = convert_with(&[], version).unwrap();
    assert_eq!(info.version.beacons["Name"].beacon_name(), "aws_dbe_b_Name");

    // A fully signed one is written to the attribute of its name, so it is not.
    let fully_signed = compound("Name", None, Some(vec![year(), month()]), None);
    let version = lotsa_beacons(store())
        .set_compound_beacons(Some(vec![fully_signed]))
        .set_standard_beacons(standards());
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Name not allowed as a CompoundBeacon because a fully signed beacon cannot have the same name as an existing attribute."
    );
}

// ---------------------------------------------------------------------------
// Conversion: the configuration cases of Beacon.dfy.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lotsa_beacons_converts() {
    let info = convert_with(&[], lotsa_beacons(store())).unwrap().version;
    let names: Vec<&str> = info.beacons.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "JustSigned",
            "Mixed",
            "Name",
            "NameTitle",
            "NameTitleField",
            "Title",
            "YearName",
            "std2",
            "std4",
            "std6"
        ]
    );
    assert_eq!(
        info.standard_names,
        ["Name", "NameTitleField", "Title", "std2", "std4", "std6"]
    );
    let encrypted: Vec<&str> = info.encrypted_fields.iter().map(String::as_str).collect();
    assert_eq!(
        encrypted,
        ["Name", "Title", "TooBad", "std2", "std4", "std6"]
    );
    assert_eq!(info.max_partitions, 1);
    assert_eq!(info.signed_beacon_names(), ["JustSigned"]);

    let Beacon::Standard(std6) = &info.beacons["std6"] else {
        panic!("std6 is not a standard beacon");
    };
    assert_eq!(std6.beacon_name, "aws_dbe_b_std6");
    assert_eq!(std6.length, 26);
    assert_eq!(std6.loc, TermLoc::parse("std6[0]").unwrap());
    assert_eq!(std6.number_of_partitions, 1);
    assert!(!std6.part_only && !std6.as_set && std6.share.is_none());

    let Beacon::Compound(just_signed) = &info.beacons["JustSigned"] else {
        panic!("JustSigned is not a compound beacon");
    };
    assert_eq!(just_signed.beacon_name, "JustSigned");
    assert!(!info.beacons["JustSigned"].is_encrypted());

    let Beacon::Compound(mixed) = &info.beacons["Mixed"] else {
        panic!("Mixed is not a compound beacon");
    };
    assert_eq!(mixed.beacon_name, "aws_dbe_b_Mixed");
    assert_eq!(mixed.split, '.');
    assert_eq!(mixed.num_signed, 2);
    let parts: Vec<(&str, &str)> = mixed.parts.iter().map(|p| (p.name(), p.prefix())).collect();
    assert_eq!(
        parts,
        [
            ("Year", "Y_"),
            ("Month", "M_"),
            ("Name", "N_"),
            ("Title", "T_")
        ]
    );
    assert!(info.beacons["Mixed"].is_encrypted());
    assert!(mixed.has_beacon("Title") && !mixed.has_beacon("std2"));
    // Constructor parts index into `parts`.
    let req = |part, required| ConstructorPartInfo { part, required };
    assert_eq!(
        mixed.constructors,
        [
            vec![req(2, true), req(0, true)],
            vec![req(3, true), req(1, false)]
        ]
    );

    // With no constructors, the default is every part, signed first, all required.
    let Beacon::Compound(year_name) = &info.beacons["YearName"] else {
        panic!("YearName is not a compound beacon");
    };
    assert_eq!(year_name.constructors, [vec![req(0, true), req(1, true)]]);

    let vf = &info.virtual_fields["NameTitleField"];
    let locs: Vec<String> = vf.locs().into_iter().map(ToString::to_string).collect();
    assert_eq!(locs, ["Name", "Title"]);
    assert!(vf.examine(|t| t.attribute_name() == "Title"));
    assert!(!vf.examine(|t| t.attribute_name() == "Year"));
}

#[tokio::test]
async fn bad_prefix_is_rejected() {
    let version = lotsa_beacons(store())
        .set_standard_beacons(Some(vec![name_b(), title_b(), too_bad_b()]))
        .set_compound_beacons(Some(vec![bad_prefix()]))
        .set_virtual_fields(None);

    //= spec/searchable-encryption/beacons.md#initialization-failure
    //= type=test
    //# Initialization MUST fail if any `prefix` in any [part](#part) is a prefix of
    //# the `prefix` of any other [part](#part).
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Compound beacon BadPrefix defines part Title with prefix T_ which is incompatible with part TooBad which has a prefix of T."
    );
}

#[tokio::test]
async fn bad_prefix_between_signed_and_encrypted_parts() {
    let version = lotsa_beacons(store())
        .set_standard_beacons(Some(vec![name_b()]))
        .set_compound_beacons(Some(vec![bad_prefix2()]))
        .set_virtual_fields(None);

    // `Nothing` must be signed for the prefix check to be reached.
    // Rejected by beacons.md#initialization-failure: a signed part holds only SIGN_ONLY fields.
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Signed Part Nothing is built from Nothing which is not SIGN_ONLY."
    );
    let version = lotsa_beacons(store())
        .set_standard_beacons(Some(vec![name_b()]))
        .set_compound_beacons(Some(vec![bad_prefix2()]))
        .set_virtual_fields(None);

    // Rejected by beacons.md#initialization-failure: no prefix begins another part's prefix.
    assert_eq!(
        validation_message(convert_with(
            &[("Nothing", CryptoAction::SignOnly)],
            version
        )),
        "Compound beacon BadPrefix2 defines part Nothing with prefix N__ which is incompatible with part Name which has a prefix of N_."
    );
}

#[tokio::test]
async fn unused_part_only() {
    let bad = styled("badBeacon", 24, BeaconStyle::part_only());
    let mut standards = lotsa_beacons(store()).build().unwrap().standard_beacons;
    standards.push(bad);
    let version = lotsa_beacons(store()).set_standard_beacons(Some(standards));

    //= spec/searchable-encryption/beacons.md#partonly-initialization
    //= type=test
    //# Initialization MUST fail if the configuration does not use a PartOnly in a [compound beacon](#compound-beacon).
    assert_eq!(
        validation_message(convert_with(
            &[("badBeacon", CryptoAction::EncryptAndSign)],
            version
        )),
        "PartOnly beacon badBeacon MUST be used in a compound beacon."
    );
}

#[tokio::test]
async fn compound_with_unknown() {
    let name_unknown = compound(
        "NameUnknown",
        Some(vec![name_p(), encrypted_part("Unknown", "U_")]),
        None,
        None,
    );
    let version = lotsa_beacons(store()).compound_beacons(name_unknown);

    //= spec/searchable-encryption/beacons.md#compound-beacon
    //= type=test
    //# The name MUST be the name of a configured standard beacon.
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Compound beacon NameUnknown refers to standard beacon Unknown which is not configured."
    );
}

#[tokio::test]
async fn set_in_compound() {
    let set_beacon = styled("setBeacon", 24, BeaconStyle::as_set());
    let compound_set = compound(
        "compoundSet",
        Some(vec![name_p(), encrypted_part("setBeacon", "S_")]),
        None,
        None,
    );
    let version = lotsa_beacons(store())
        .standard_beacons(set_beacon)
        .compound_beacons(compound_set);

    //= spec/searchable-encryption/beacons.md#asset-initialization
    //= type=test
    //# - initialization MUST fail if any compound beacon has an AsSet beacon as a part.
    assert_eq!(
        validation_message(convert_with(
            &[("setBeacon", CryptoAction::EncryptAndSign)],
            version
        )),
        "Compound beacon compoundSet uses setBeacon which is an AsSet beacon, and therefore cannot be used in a Compound Beacon."
    );
}

/// `GetLotsaBeacons` plus `beacons`, with `shareBeacon` encrypted.
fn share_case(
    standards: Option<Vec<StandardBeacon>>,
    extra: Vec<StandardBeacon>,
    keep_compound: bool,
) -> String {
    let mut version = lotsa_beacons(store());
    if let Some(s) = standards {
        version = version.set_standard_beacons(Some(s));
    }
    for b in extra {
        version = version.standard_beacons(b);
    }
    if !keep_compound {
        version = version.set_compound_beacons(None);
    }
    validation_message(convert_with(
        &[("shareBeacon", CryptoAction::EncryptAndSign)],
        version,
    ))
}

#[tokio::test]
async fn shared_bad_reference_to_compound() {
    let share = styled("shareBeacon", 24, BeaconStyle::shared("NameTitle"));

    // Rejected by beacons.md#shared-initialization: other names a standard beacon.
    assert_eq!(
        share_case(None, vec![share], true),
        "Beacon shareBeacon is shared to NameTitle but NameTitle is a compound beacon."
    );
}

#[tokio::test]
async fn chained_share() {
    let share = styled("shareBeacon", 24, BeaconStyle::shared("std2"));
    let other = StandardBeacon::builder()
        .name("std4")
        .bits(24)
        .style(BeaconStyle::shared("shareBeacon"))
        .build()
        .unwrap();
    assert_eq!(
        share_case(Some(vec![std2(), share, other]), vec![], false),
        "Beacon std4 is shared to shareBeacon which is in turn shared to std2. Share chains are not allowed."
    );
}

#[tokio::test]
async fn self_share() {
    let share = styled("shareBeacon", 24, BeaconStyle::shared("shareBeacon"));
    assert_eq!(
        share_case(Some(vec![std2(), share]), vec![], false),
        "Beacon shareBeacon is shared to itself."
    );
}

#[tokio::test]
async fn shared_bad_reference_non_existent() {
    let share = styled("shareBeacon", 24, BeaconStyle::shared("DoesNotExist"));

    //= spec/searchable-encryption/beacons.md#shared-initialization
    //= type=test
    //# This name MUST be the name of a previously defined Standard Beacon.
    assert_eq!(
        share_case(None, vec![share], true),
        "Beacon shareBeacon is shared to DoesNotExist which is not defined."
    );
}

#[tokio::test]
async fn shared_bad_length() {
    let share = styled("shareBeacon", 23, BeaconStyle::shared("std2"));

    //= spec/searchable-encryption/beacons.md#shared-initialization
    //= type=test
    //# This beacon's [length](#beacon-length) MUST be equal to the `other` beacon's [length](#beacon-length).
    assert_eq!(
        share_case(None, vec![share], true),
        "Beacon shareBeacon is shared to std2 but shareBeacon has length 23 and std2 has length 24."
    );
}

#[tokio::test]
async fn shared_and_shared_set_convert() {
    let shared = styled("shareBeacon", 24, BeaconStyle::shared("std2"));
    let shared_set = styled("setShare", 24, BeaconStyle::shared_set("std2"));
    let version = lotsa_beacons(store())
        .standard_beacons(shared)
        .standard_beacons(shared_set);
    let info = convert_with(
        &[
            ("shareBeacon", CryptoAction::EncryptAndSign),
            ("setShare", CryptoAction::EncryptAndSign),
        ],
        version,
    )
    .unwrap();
    let Beacon::Standard(s) = &info.version.beacons["shareBeacon"] else {
        panic!("not standard");
    };
    assert_eq!((s.share.as_deref(), s.as_set), (Some("std2"), false));
    let Beacon::Standard(s) = &info.version.beacons["setShare"] else {
        panic!("not standard");
    };
    assert_eq!((s.share.as_deref(), s.as_set), (Some("std2"), true));
}

#[tokio::test]
async fn global_part_not_exist() {
    let version = lotsa_beacons(store()).encrypted_parts(encrypted_part("NotExist", "Q_"));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Global Parts List refers to standard beacon NotExist which is not configured."
    );
}

#[tokio::test]
async fn duplicate_global_signed() {
    let version = lotsa_beacons(store())
        .set_compound_beacons(None)
        .set_signed_parts(Some(vec![year(), month(), year()]));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Duplicate part name Year in Global Parts List."
    );
}

#[tokio::test]
async fn duplicate_global_encrypted() {
    let version = lotsa_beacons(store())
        .set_compound_beacons(None)
        .set_encrypted_parts(Some(vec![name_p(), title_p(), name_p()]));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Duplicate part name Name in Global Parts List."
    );
}

#[tokio::test]
async fn duplicate_global_prefix() {
    let version = lotsa_beacons(store())
        .set_compound_beacons(None)
        .set_encrypted_parts(Some(vec![
            name_p(),
            title_p(),
            encrypted_part("std6", "N_"),
        ]));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Duplicate prefix N_ in Global Parts List."
    );
}

#[tokio::test]
async fn duplicate_global_vs_local_encrypted() {
    let version = lotsa_beacons(store()).encrypted_parts(name_p());
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Compound beacon NameTitle defines encrypted part Name which is already defined as a global part."
    );
}

#[tokio::test]
async fn duplicate_global_vs_local_signed() {
    let version = lotsa_beacons(store()).signed_parts(month());
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Compound beacon Mixed defines signed part Month which is already defined as a global part."
    );
}

#[tokio::test]
async fn global_and_local_prefix_clash() {
    // A local part with a new name but a global part's prefix.
    let version = lotsa_beacons(store()).signed_parts(signed_part("Other", "M_", Some("Year")));

    // Rejected by beacons.md#initialization-failure: no prefix begins another part's prefix.
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Compound beacon Mixed defines signed part Month with prefix M_ which is already defined as the prefix of a global part."
    );
    let version = lotsa_beacons(store()).encrypted_parts(encrypted_part("std2", "T_"));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Compound beacon NameTitle defines encrypted part Title with prefix T_ which is already defined as the prefix of a global part."
    );
}

#[tokio::test]
async fn global_signed_and_encrypted_lists_must_not_clash() {
    let version = lotsa_beacons(store())
        .signed_parts(signed_part("Q", "Q_", Some("Year")))
        .encrypted_parts(encrypted_part("std2", "Q_"));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Duplicate prefix(es) Q_ between Global Signed Parts List and Global Encrypted Parts List."
    );
    let version = lotsa_beacons(store())
        .signed_parts(signed_part("std2", "Q_", Some("Year")))
        .encrypted_parts(encrypted_part("std2", "R_"));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Duplicate part name(s) std2 between Global Signed Parts List and Global Encrypted Parts List."
    );
}

#[tokio::test]
async fn compound_no_constructor() {
    let compound_default = compound("compoundDefault", None, None, None);
    let version = lotsa_beacons(store())
        .set_compound_beacons(Some(vec![compound_default]))
        .signed_parts(month())
        .set_encrypted_parts(Some(vec![name_p(), title_p()]));

    //= spec/searchable-encryption/beacons.md#default-construction
    //= type=test
    //# - Initialization MUST fail if no constructors are configured, and no local parts are configured.
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Compound beacon compoundDefault defines no constructors, and also no local parts. Cannot make a default constructor from global parts."
    );
}

#[tokio::test]
async fn compound_mixed_uses_global_parts() {
    let mixed = compound(
        "Mixed",
        Some(vec![title_p()]),
        Some(vec![month()]),
        Some(vec![
            constructor(&[("Name", true), ("Year", true)]),
            constructor(&[("Title", true), ("Month", false)]),
        ]),
    );
    let version = lotsa_beacons(store())
        .set_compound_beacons(Some(vec![mixed]))
        .signed_parts(year())
        .encrypted_parts(name_p());
    let info = convert_with(&[], version).unwrap();
    let Beacon::Compound(mixed) = &info.version.beacons["Mixed"] else {
        panic!("Mixed is not a compound beacon");
    };
    // Local parts, then the global parts the constructors name; signed first.
    let parts: Vec<&str> = mixed.parts.iter().map(BeaconPart::name).collect();
    assert_eq!(parts, ["Month", "Year", "Title", "Name"]);
    assert_eq!(mixed.num_signed, 2);
    assert!(
        matches!(&mixed.parts[3], BeaconPart::Encrypted { beacon, .. } if beacon.name == "Name")
    );
}

// ---------------------------------------------------------------------------
// Conversion: the remaining checks.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_search_config_converts_to_none() {
    let table = table_with(&[], lotsa_beacons(store()).build().unwrap())
        .builder
        .set_search(None)
        .build()
        .unwrap();
    assert!(convert(&table).unwrap().is_none());
}

#[tokio::test]
async fn version_numbers_must_be_one() {
    let mut table = table_with(&[], lotsa_beacons(store()).build().unwrap())
        .builder
        .build()
        .unwrap();
    table.search.as_mut().unwrap().write_version = 2;
    assert_eq!(
        validation_message(convert(&table)),
        "write_version must be 1"
    );
    table.search.as_mut().unwrap().write_version = 1;
    table.search.as_mut().unwrap().versions[0].version = 2;
    assert_eq!(
        validation_message(convert(&table)),
        "the beacon version's version must be 1"
    );
    table.search.as_mut().unwrap().versions[0].version = 1;
    table.search.as_mut().unwrap().versions[0]
        .standard_beacons
        .clear();
    assert_eq!(
        validation_message(convert(&table)),
        "At least one standard beacon must be configured."
    );
    table.search.as_mut().unwrap().versions.clear();
    assert_eq!(
        validation_message(convert(&table)),
        "the search config must have exactly one beacon version"
    );
}

#[tokio::test]
async fn bad_standard_beacon_names() {
    let case = |name: &str, table: fn(TableConfigBuilderExt) -> TableConfigBuilderExt| {
        let version = lotsa_beacons(store())
            .standard_beacons(standard(name, 16, Some("std4")))
            .build()
            .unwrap();
        validation_message(table(table_with(&[], version)).convert())
    };
    assert_eq!(
        case("Year", |t| t),
        "Year not allowed as a StandardBeacon because it is already an unencrypted attribute."
    );
    assert_eq!(
        case("unsigned", |t| TableConfigBuilderExt {
            builder: t.builder.allowed_unsigned_attributes("unsigned"),
        }),
        "unsigned not allowed as a StandardBeacon because it is already an allowed unauthenticated attribute."
    );
    assert_eq!(
        case(":colon", |t| TableConfigBuilderExt {
            builder: t.builder.allowed_unsigned_attribute_prefix(":"),
        }),
        ":colon not allowed as a StandardBeacon because it begins with the allowed unauthenticated prefix."
    );
    assert_eq!(
        case("aws_dbe_foo", |t| t),
        "aws_dbe_foo not allowed as a StandardBeacon because it begins with the reserved prefix."
    );
}

#[tokio::test]
async fn bad_virtual_field_names() {
    let case = |name: &str, table: fn(TableConfigBuilderExt) -> TableConfigBuilderExt| {
        let version = lotsa_beacons(store())
            .virtual_fields(virtual_field(
                name,
                vec![virtual_part("Year", VirtualTransform::upper())],
            ))
            .build()
            .unwrap();
        validation_message(table(table_with(&[], version)).convert())
    };
    assert_eq!(
        case("Year", |t| t),
        "Year not allowed as a Virtual Field because it is already a configured attribute."
    );
    assert_eq!(
        case("unsigned", |t| TableConfigBuilderExt {
            builder: t.builder.allowed_unsigned_attributes("unsigned"),
        }),
        "unsigned not allowed as a Virtual Field because it is already an allowed unauthenticated attribute."
    );
    assert_eq!(
        case(":colon", |t| TableConfigBuilderExt {
            builder: t.builder.allowed_unsigned_attribute_prefix(":"),
        }),
        ":colon not allowed as a Virtual Field because it begins with the allowed unauthenticated prefix."
    );
    assert_eq!(
        case("aws_dbe_vf", |t| t),
        "aws_dbe_vf not allowed as a Virtual Field because it begins with the reserved prefix."
    );
}

#[tokio::test]
async fn duplicate_names() {
    let version = lotsa_beacons(store()).standard_beacons(std2());
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Duplicate StandardBeacon name : std2"
    );
    let version = lotsa_beacons(store()).compound_beacons(compound(
        "Name",
        Some(vec![title_p()]),
        None,
        None,
    ));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "two compound beacons are named Name"
    );
    let version = lotsa_beacons(store()).virtual_fields(name_title_field());
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Duplicate VirtualField name : NameTitleField"
    );
}

#[tokio::test]
async fn signed_and_encrypted_locations() {
    // A standard beacon must be on an encrypted field.
    let version = lotsa_beacons(store()).standard_beacons(standard("yb", 16, Some("Year")));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "StandardBeacon yb not defined on an encrypted field."
    );
    // A virtual field on signed-only fields is not encrypted either.
    let version = lotsa_beacons(store())
        .virtual_fields(virtual_field(
            "YearVF",
            vec![virtual_part("Year", VirtualTransform::upper())],
        ))
        .standard_beacons(standard("yvf", 16, Some("YearVF")));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "StandardBeacon yvf not defined on an encrypted field."
    );
    // A virtual field must be on signed fields.
    let version = lotsa_beacons(store()).virtual_fields(virtual_field(
        "vf",
        vec![virtual_part("Unknown", VirtualTransform::upper())],
    ));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "VirtualField vf must be defined on signed fields."
    );
    let version = lotsa_beacons(store()).virtual_fields(virtual_field(
        "vf",
        vec![virtual_part("Unsigned", VirtualTransform::upper())],
    ));
    assert_eq!(
        validation_message(convert_with(
            &[("Unsigned", CryptoAction::DoNothing)],
            version
        )),
        "VirtualField vf must be defined on signed fields."
    );
    // A signed part must be signed and not encrypted.
    let version = lotsa_beacons(store()).signed_parts(signed_part("sp", "S_", Some("Name")));

    //= spec/searchable-encryption/search-config.md#beacon-version-initialization
    //= type=test
    //# Initialization MUST fail if the [terminal location](virtual.md#terminal-location)
    //# reference by a [signed part](beacons.md#signed-part) is `encrypted`,
    //# or is not `signed`.
    //
    //= spec/searchable-encryption/beacons.md#initialization-failure
    //= type=test
    //# Initialization MUST fail if any [signed-part](#signed-part-initialization) contains
    //# anything but SIGN_ONLY fields.
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Signed Part sp is built from Name which is not SIGN_ONLY."
    );
    // SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT counts as signed only.
    let version = lotsa_beacons(store()).compound_beacons(compound(
        "ctx",
        None,
        Some(vec![signed_part("Ctx", "C_", None)]),
        None,
    ));
    let info = convert_with(
        &[("Ctx", CryptoAction::SignAndIncludeInEncryptionContext)],
        version,
    )
    .unwrap();
    assert_eq!(info.version.beacons["ctx"].beacon_name(), "ctx");
}

#[tokio::test]
async fn bad_locations_are_rejected() {
    let version = lotsa_beacons(store()).standard_beacons(standard("bad", 16, Some("std4[x]")));

    //= spec/searchable-encryption/virtual.md#segments
    //= type=test
    //= reason=[x] is neither ".key" nor "[N]", so the segment is rejected
    //# A Segment MUST be one of
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "a list index in a path has a character that is not a digit: x"
    );
}

#[tokio::test]
async fn constructor_checks() {
    let case = |constructors: Vec<Constructor>| {
        let version = lotsa_beacons(store()).set_compound_beacons(Some(vec![compound(
            "Mixed",
            Some(vec![name_p(), title_p()]),
            Some(vec![year(), month()]),
            Some(constructors),
        )]));
        convert_with(&[], version)
    };

    //= spec/searchable-encryption/beacons.md#initialization-failure
    //= type=test
    //# Initialization MUST fail if any [constructor](#constructor-initialization) is configured without at least one
    //# required part.
    assert_eq!(
        validation_message(case(vec![constructor(&[("Name", false), ("Year", false)])])),
        "A Constructor for beacon Mixed lacks any required parts"
    );

    //= spec/searchable-encryption/beacons.md#constructor-part-initialization
    //= type=test
    //# This name MUST match the name of one of the [encrypted](#encrypted-part-initialization) or [signed](#signed-part-initialization) parts.
    //
    //= spec/searchable-encryption/beacons.md#initialization-failure
    //= type=test
    //# Initialization MUST fail if any [constructor](#constructor-initialization) is configured with a field name
    //# that is not a defined [part](#part).
    assert_eq!(
        validation_message(case(vec![constructor(&[("Nope", true)])])),
        "Constructor refers to part name Nope but there is no part by that name."
    );

    //= spec/searchable-encryption/beacons.md#initialization-failure
    //= type=test
    //# Initialization MUST fail if two [constructors](#constructor-initialization) are configured
    //# with the same set of required parts.
    assert_eq!(
        validation_message(case(vec![
            constructor(&[("Name", true), ("Year", true)]),
            constructor(&[("Year", true), ("Name", true), ("Title", false)]),
        ])),
        "Multiple constructors for Mixed have the same set of required parts : Year, Name"
    );
}

#[tokio::test]
async fn empty_constructor_lists_built_without_the_builder() {
    let mut empty_list = mixed();
    empty_list.constructors = Some(vec![]);
    let version = lotsa_beacons(store()).set_compound_beacons(Some(vec![empty_list]));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "For beacon Mixed an empty constructor list was supplied."
    );

    let mut empty_parts = mixed();
    empty_parts.constructors = Some(vec![Constructor { parts: vec![] }]);
    let version = lotsa_beacons(store()).set_compound_beacons(Some(vec![empty_parts]));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Every constructor must have at least one part."
    );

    let mut no_parts = compound("Empty", None, None, None);
    no_parts.constructors = Some(vec![constructor(&[("Name", true)])]);
    let version = lotsa_beacons(store()).set_compound_beacons(Some(vec![no_parts]));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "For beacon Empty no parts were supplied."
    );
}

#[tokio::test]
async fn beacon_name_length_limit() {
    // DynamoDB attribute names are at most 65535 UTF-16 code units, prefix included.
    let longest = "a".repeat(65535 - "aws_dbe_b_".len());
    let version = lotsa_beacons(store()).standard_beacons(standard(&longest, 16, None));
    let info = convert_with(&[(&longest, CryptoAction::EncryptAndSign)], version).unwrap();
    assert_eq!(info.version.beacons[&longest].beacon_name().len(), 65535);

    let too_long = format!("{longest}a");
    let version = lotsa_beacons(store()).standard_beacons(standard(&too_long, 16, None));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        format!("aws_dbe_b_{too_long} is not a valid attribute name.")
    );

    let encrypted = compound(&too_long, Some(vec![name_p()]), None, None);
    let version = lotsa_beacons(store()).compound_beacons(encrypted);
    assert_eq!(
        validation_message(convert_with(&[], version)),
        format!("aws_dbe_b_{too_long} is not a valid attribute name.")
    );

    let signed_name = "s".repeat(65536);
    let signed = compound(&signed_name, None, Some(vec![year()]), None);
    let version = lotsa_beacons(store()).compound_beacons(signed);
    assert_eq!(
        validation_message(convert_with(&[], version)),
        format!("{signed_name} is not a valid attribute name.")
    );
}

#[tokio::test]
async fn partition_counts() {
    let version = lotsa_beacons(store()).maximum_number_of_partitions(255);
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Invalid maximumNumberOfPartitions specified, 255, must be 0 < maximumNumberOfPartitions <= 255."
    );
    let version = lotsa_beacons(store())
        .maximum_number_of_partitions(5)
        .default_number_of_partitions(5);
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Invalid defaultNumberOfPartitions specified, 5, must be 0 < defaultNumberOfPartitions < maximumNumberOfPartitions."
    );
    // std4Partitioned, with the default maximum of 1.
    let std4_partitioned = StandardBeacon::builder()
        .name("std4")
        .bits(24)
        .location("std4")
        .number_of_partitions(5)
        .build()
        .unwrap();
    let version = lotsa_beacons(store())
        .set_standard_beacons(Some(vec![std2(), std4_partitioned.clone(), std6()]))
        .set_compound_beacons(None)
        .set_virtual_fields(None);

    //= spec/searchable-encryption/beacons.md#standard-beacon-initialization
    //= type=test
    //# Initialization MUST fail if [number of partitions](#beacon-constraint) is specified, and is greater than or equal to
    //# the maximum number of partitions specified in the [beacon version](search-config.md#beacon-version-initialization).
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "Constrained numberOfPartitions for  std4 is 5 but it must be less than the maximumNumberOfPartitions 1"
    );

    let version = lotsa_beacons(store())
        .set_standard_beacons(Some(vec![std2(), std4_partitioned, std6()]))
        .set_compound_beacons(None)
        .set_virtual_fields(None)
        .maximum_number_of_partitions(6)
        .default_number_of_partitions(3);
    let info = convert_with(&[], version).unwrap().version;
    assert_eq!(info.max_partitions, 6);
    let counts: Vec<(&str, u8)> = info
        .beacons
        .iter()
        .map(|(n, b)| match b {
            Beacon::Standard(s) => (n.as_str(), s.number_of_partitions),
            Beacon::Compound(_) => panic!("unexpected compound beacon {n}"),
        })
        .collect();
    assert_eq!(counts, [("std2", 3), ("std4", 5), ("std6", 3)]);

    // With no default, a beacon gets the maximum.
    let version = lotsa_beacons(store())
        .set_standard_beacons(Some(vec![std2()]))
        .set_compound_beacons(None)
        .set_virtual_fields(None)
        .maximum_number_of_partitions(4);
    let info = convert_with(&[], version).unwrap().version;
    let Beacon::Standard(s) = &info.beacons["std2"] else {
        panic!("not standard");
    };
    assert_eq!(s.number_of_partitions, 4);
}

#[tokio::test]
async fn multi_key_source_checks() {
    let multi = |field: &str| lotsa_beacons(store()).key_source(multi_source(field));
    assert_eq!(
        validation_message(convert_with(&[], multi("Name"))),
        "Beacon key field name Name is configured as ENCRYPT_AND_SIGN which is not allowed."
    );
    assert_eq!(
        validation_message(convert_with(&[], multi("NameTitle"))),
        "A beacon key field name of NameTitle was configured, but there's also a beacon of that name."
    );
    let version = multi("YearVF").virtual_fields(virtual_field(
        "YearVF",
        vec![virtual_part("Year", VirtualTransform::upper())],
    ));
    assert_eq!(
        validation_message(convert_with(&[], version)),
        "A beacon key field name of YearVF was configured, but there's also a virtual field of that name."
    );

    // A signed key field is kept on the item; an unconfigured or unsigned one is removed.
    for (field, extra, delete) in [
        ("TheKeyField", vec![], false),
        ("Absent", vec![], true),
        (
            "Unsigned",
            vec![("Unsigned", CryptoAction::DoNothing)],
            true,
        ),
    ] {
        let info = convert_with(&extra, multi(field)).unwrap().version;
        match &info.key_source.location {
            KeyLocation::Multi {
                key_field_name,
                delete_key,
            } => {
                assert_eq!(key_field_name, field);
                assert_eq!(*delete_key, delete, "{field}");
            }
            KeyLocation::Single { .. } => panic!("not a multi key source"),
        }
    }

    let info = convert_with(&[], lotsa_beacons(store())).unwrap().version;
    assert!(matches!(
        &info.key_source.location,
        KeyLocation::Single { key_id } if key_id == "foo"
    ));
}

#[tokio::test]
async fn cache_ttl_must_be_at_least_one_second() {
    let ttl = Duration::from_millis(999);
    let single = BeaconKeySource::Single(
        SingleKeyStore::builder()
            .key_id("foo")
            .cache_ttl(ttl)
            .build()
            .unwrap(),
    );
    assert_eq!(
        validation_message(convert_with(&[], lotsa_beacons(store()).key_source(single))),
        "the beacon key cache TTL must be at least 1 second"
    );
    let multi = BeaconKeySource::Multi(
        MultiKeyStore::builder()
            .key_field_name("TheKeyField")
            .cache_ttl(ttl)
            .build()
            .unwrap(),
    );
    assert_eq!(
        validation_message(convert_with(&[], lotsa_beacons(store()).key_source(multi))),
        "the beacon key cache TTL must be at least 1 second"
    );
}
