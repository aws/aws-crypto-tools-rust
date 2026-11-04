// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures for the search unit tests, from the reference implementation's `BeaconTestFixtures.dfy`.
//! An in-memory key store takes the place of its literal key source.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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
use aws_crypto_mpl::key_store::types::KmsConfiguration;
use aws_crypto_mpl::key_store::{self, KeyStore};
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::types::{AesWrappingAlg, BeaconKeyMaterials, EncryptionContext};
use aws_mpl_primitives::{DigestAlg, hkdf_no_salt, hmac};

use crate::ddb::Item;
use crate::error::Error;
use crate::search::config::{
    BeaconKeySource, BeaconVersion, BeaconVersionBuilder, CompoundBeacon, Constructor,
    ConstructorPart, EncryptedPart, MultiKeyStore, SearchConfig, SignedPart, SingleKeyStore,
    StandardBeacon, VirtualField, VirtualPart, VirtualTransform,
};
use crate::search::convert::convert;
use crate::search::info::SearchInfo;
use crate::table_config::TableConfig;
use crate::types::CryptoAction;

/// The beacon key that every fixture key store returns.
pub(crate) const BEACON_KEY: [u8; 5] = [1, 2, 3, 4, 5];

// Expected beacon values under `BEACON_KEY`, from the reference fixtures.
pub(crate) const STD2_BEACON: &str = "ac6f5d";
pub(crate) const NAME_BEACON: &str = "7d9bfa40";
pub(crate) const TITLE_BEACON: &str = "e4feb833";
pub(crate) const STD4_BEACON: &str = "0e9064";
pub(crate) const STD6_BEACON: &str = "2d99222";
pub(crate) const NAME_TITLE_BEACON: &str = "4c577d7";
pub(crate) const EMPTY_NAME_BEACON: &str = "e0e88994";
pub(crate) const EMPTY_TITLE_BEACON: &str = "af34f26f";

/// A key store that serves `BEACON_KEY` for every branch key id, or fails every call.
#[derive(Clone, Debug)]
pub(crate) struct FakeKeyStore {
    logical_name: String,
    fail: bool,
    no_beacon_key: bool,
    /// The beacon key id the store answers with, instead of the requested one.
    answer_id: Option<String>,
    /// How many times `get_beacon_key` was called.
    pub(crate) beacon_calls: Arc<AtomicUsize>,
}

impl FakeKeyStore {
    pub(crate) fn new(logical_name: &str) -> Self {
        Self {
            logical_name: logical_name.to_owned(),
            fail: false,
            no_beacon_key: false,
            answer_id: None,
            beacon_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A store whose beacon key materials name `id`, whatever beacon key id was requested.
    pub(crate) fn answering_with(logical_name: &str, id: &str) -> Self {
        Self {
            answer_id: Some(id.to_owned()),
            ..Self::new(logical_name)
        }
    }

    /// A store whose `get_beacon_key` always fails, as a key store with a bad table does.
    pub(crate) fn failing(logical_name: &str) -> Self {
        Self {
            fail: true,
            ..Self::new(logical_name)
        }
    }

    /// A store whose beacon key materials have no beacon key.
    pub(crate) fn without_beacon_key() -> Self {
        Self {
            no_beacon_key: true,
            ..Self::new("KeyStoreDdbTable")
        }
    }

    pub(crate) fn calls(&self) -> usize {
        self.beacon_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn client(&self) -> key_store::SharedKeyStore {
        key_store::SharedKeyStore::new(self.clone())
    }
}

fn unsupported() -> aws_crypto_mpl::Error {
    aws_crypto_mpl::Error::validation("not supported by the test key store")
}

#[aws_crypto_mpl::async_trait]
impl KeyStore for FakeKeyStore {
    async fn get_key_store_info(
        &self,
        _input: GetKeyStoreInfoInput,
    ) -> Result<GetKeyStoreInfoOutput, aws_crypto_mpl::Error> {
        GetKeyStoreInfoOutput::builder()
            .key_store_id("test-id")
            .key_store_name("KeyStoreDdbTable")
            .logical_key_store_name(self.logical_name.clone())
            .set_grant_tokens(Some(Vec::new()))
            .kms_configuration(KmsConfiguration::kms_key_arn(
                "arn:aws:kms:us-west-2:111122223333:key/test",
            ))
            .build()
    }

    async fn create_key_store(
        &self,
        _input: CreateKeyStoreInput,
    ) -> Result<CreateKeyStoreOutput, aws_crypto_mpl::Error> {
        Err(unsupported())
    }

    async fn create_key(
        &self,
        _input: CreateKeyInput,
    ) -> Result<CreateKeyOutput, aws_crypto_mpl::Error> {
        Err(unsupported())
    }

    async fn version_key(
        &self,
        _input: VersionKeyInput,
    ) -> Result<VersionKeyOutput, aws_crypto_mpl::Error> {
        Err(unsupported())
    }

    async fn get_active_branch_key(
        &self,
        _input: GetActiveBranchKeyInput,
    ) -> Result<GetActiveBranchKeyOutput, aws_crypto_mpl::Error> {
        Err(unsupported())
    }

    async fn get_branch_key_version(
        &self,
        _input: GetBranchKeyVersionInput,
    ) -> Result<GetBranchKeyVersionOutput, aws_crypto_mpl::Error> {
        Err(unsupported())
    }

    async fn get_beacon_key(
        &self,
        input: GetBeaconKeyInput,
    ) -> Result<GetBeaconKeyOutput, aws_crypto_mpl::Error> {
        self.beacon_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(aws_crypto_mpl::Error::validation("bad key store"));
        }
        let mut materials = BeaconKeyMaterials::builder()
            .beacon_key_id(
                self.answer_id
                    .as_deref()
                    .unwrap_or_else(|| input.branch_key_id()),
            )
            .set_encryption_context(Some(EncryptionContext::new()));
        if !self.no_beacon_key {
            materials = materials.beacon_key(BEACON_KEY.to_vec());
        }
        GetBeaconKeyOutput::builder()
            .beacon_key_materials(materials.build()?)
            .build()
    }
}

/// The HMAC key of each of `names` under `key`, computed directly from the spec.
pub(crate) fn hmac_keys(names: &[&str], key: &[u8]) -> BTreeMap<String, Vec<u8>> {
    names
        .iter()
        .map(|name| {
            let mut out = vec![0u8; 64];
            hkdf_no_salt(
                DigestAlg::Sha512,
                key,
                &[b"AWS_DBE_SCAN_BEACON", name.as_bytes()],
                &mut out,
            )
            .unwrap();
            ((*name).to_owned(), out)
        })
        .collect()
}

/// The beacon of `value` for standard beacon `name` under `BEACON_KEY`, computed directly from the spec:
/// the rightmost `bits` bits of the first 8 bytes of the HMAC-SHA-384.
/// `bits` must be a multiple of 4.
pub(crate) fn spec_beacon(name: &str, value: &[u8], bits: u8) -> String {
    assert_eq!(bits % 4, 0, "spec_beacon takes whole hex digits");
    let key = &hmac_keys(&[name], &BEACON_KEY)[name];
    let mut out = [0u8; 48];
    hmac(DigestAlg::Sha384, key, value, &mut out).unwrap();
    let first8: [u8; 8] = out[..8].try_into().unwrap();
    let hex = format!("{:016x}", u64::from_be_bytes(first8));
    hex[16 - usize::from(bits / 4)..].to_owned()
}

pub(crate) fn standard(name: &str, bits: u8, loc: Option<&str>) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .set_location(loc.map(str::to_owned))
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
pub(crate) fn name_part() -> EncryptedPart {
    encrypted_part("Name", "N_")
}
pub(crate) fn title_part() -> EncryptedPart {
    encrypted_part("Title", "T_")
}

pub(crate) fn compound(
    name: &str,
    encrypted: Vec<EncryptedPart>,
    signed: Vec<SignedPart>,
    constructors: Option<Vec<Constructor>>,
) -> CompoundBeacon {
    CompoundBeacon::builder()
        .name(name)
        .split(".")
        .set_encrypted((!encrypted.is_empty()).then_some(encrypted))
        .set_signed((!signed.is_empty()).then_some(signed))
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
    compound("NameTitle", vec![name_part(), title_part()], vec![], None)
}
pub(crate) fn year_name() -> CompoundBeacon {
    compound("YearName", vec![name_part()], vec![year()], None)
}
pub(crate) fn just_signed() -> CompoundBeacon {
    compound("JustSigned", vec![], vec![year(), month()], None)
}
pub(crate) fn mixed() -> CompoundBeacon {
    compound(
        "Mixed",
        vec![name_part(), title_part()],
        vec![year(), month()],
        Some(vec![
            constructor(&[("Name", true), ("Year", true)]),
            constructor(&[("Title", true), ("Month", false)]),
        ]),
    )
}

pub(crate) fn name_title_field() -> VirtualField {
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

pub(crate) fn single_source(key_id: &str) -> BeaconKeySource {
    BeaconKeySource::Single(
        SingleKeyStore::builder()
            .key_id(key_id)
            .cache_ttl(Duration::from_secs(42))
            .build()
            .unwrap(),
    )
}

pub(crate) fn multi_source(field: &str) -> BeaconKeySource {
    BeaconKeySource::Multi(
        MultiKeyStore::builder()
            .key_field_name(field)
            .cache_ttl(Duration::from_secs(42))
            .build()
            .unwrap(),
    )
}

/// A version 1 beacon version reading keys from `store`, with only `standard` beacons.
pub(crate) fn version_with(
    store: &FakeKeyStore,
    source: BeaconKeySource,
    standard: Vec<StandardBeacon>,
) -> BeaconVersionBuilder {
    BeaconVersion::builder()
        .version(1)
        .key_store(store.client())
        .key_source(source)
        .set_standard_beacons(Some(standard))
}

/// The reference's `GetLotsaBeacons`, with key source `source`.
pub(crate) fn lotsa_with(store: &FakeKeyStore, source: BeaconKeySource) -> BeaconVersionBuilder {
    version_with(
        store,
        source,
        vec![
            std2(),
            std4(),
            std6(),
            name_title_beacon(),
            name_b(),
            title_b(),
        ],
    )
    .set_compound_beacons(Some(vec![
        name_title(),
        year_name(),
        mixed(),
        just_signed(),
    ]))
    .set_virtual_fields(Some(vec![name_title_field()]))
}

/// The reference's `GetLotsaBeacons`: a single key store with key id `foo`.
pub(crate) fn lotsa() -> BeaconVersionBuilder {
    lotsa_with(&FakeKeyStore::new("KeyStoreDdbTable"), single_source("foo"))
}

/// The reference's `FullTableConfig` actions.
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
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

/// The reference's `FullTableConfig` actions plus `extra` as `ENCRYPT_AND_SIGN`.
pub(crate) fn actions_plus(extra: &str) -> HashMap<String, CryptoAction> {
    let mut actions = full_actions();
    actions.insert(extra.to_owned(), CryptoAction::EncryptAndSign);
    actions
}

/// A table with `actions` and the search configuration of `version`.
pub(crate) fn table(
    actions: HashMap<String, CryptoAction>,
    version: BeaconVersion,
) -> Result<TableConfig, Error> {
    let keyring = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("name")
        .wrapping_key(vec![0u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    TableConfig::builder()
        .logical_table_name("Foo")
        .partition_key_name("foo")
        .set_attribute_actions_on_encrypt(Some(actions))
        .keyring(keyring)
        .search(
            SearchConfig::builder()
                .versions(version)
                .write_version(1)
                .build()?,
        )
        .build()
}

/// Check and convert `version` against `actions`.
pub(crate) fn search_info(
    actions: HashMap<String, CryptoAction>,
    version: BeaconVersionBuilder,
) -> Result<SearchInfo, Error> {
    let table = table(actions, version.build()?)?;
    Ok(convert(&table)?.expect("the table has a search config"))
}

/// The converted `lotsa()` beacons with the full table actions.
pub(crate) fn lotsa_info() -> SearchInfo {
    search_info(full_actions(), lotsa()).unwrap()
}

pub(crate) fn s(v: &str) -> AttributeValue {
    AttributeValue::S(v.to_owned())
}

pub(crate) fn n(v: &str) -> AttributeValue {
    AttributeValue::N(v.to_owned())
}

pub(crate) fn item(pairs: &[(&str, AttributeValue)]) -> Item {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

/// The reference's `SimpleItem`.
pub(crate) fn simple_item() -> Item {
    item(&[
        ("std2", n("1.23")),
        ("std4", s("abc")),
        ("std6", AttributeValue::L(vec![s("666")])),
        (
            "Date",
            AttributeValue::M(
                [("Month", s("May")), ("Year", n("1984"))]
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect(),
            ),
        ),
        ("Year", n("1984")),
        ("Name", s("MyName")),
        ("Title", s("MyTitle")),
    ])
}

/// A validation error's message; fails the test on any other result.
pub(crate) fn val_msg<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
    match r {
        Err(e @ Error::Validation(_)) => e.message().to_owned(),
        other => panic!("expected a Validation error, got {other:?}"),
    }
}
