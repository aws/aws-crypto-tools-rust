// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests of the search configuration checks, ported from the Dafny `ConfigToInfo.dfy`
//! and `Beacon.dfy` tests, with their fixtures from `BeaconTestFixtures.dfy`.

use std::collections::HashMap;
use std::time::Duration;

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

use super::convert;
use crate::error::Error;
use crate::keyring::RawAesKeyring;
use crate::search::config::{
    BeaconKeySource, BeaconStyle, BeaconVersion, CompoundBeacon, Constructor, ConstructorPart,
    EncryptedPart, MultiKeyStore, SearchConfig, SignedPart, SingleKeyStore, StandardBeacon,
    VirtualField, VirtualPart, VirtualTransform,
};
use crate::search::info::{
    Beacon, BeaconPart, BeaconVersionInfo, CompoundInfo, ConstructorPartInfo, SearchInfo,
    StandardInfo,
};
use crate::search::key_source::KeyLocation;
use crate::search::term_loc::TermLoc;
use crate::table_config::{TableConfig, TableConfigBuilder};
use crate::types::{AesWrappingAlg, CryptoAction};

/// A key store the checks never call: converting a configuration reads no keys.
struct UnusedKeyStore;

#[async_trait]
impl KeyStore for UnusedKeyStore {
    async fn get_key_store_info(
        &self,
        _: GetKeyStoreInfoInput,
    ) -> Result<GetKeyStoreInfoOutput, aws_crypto_mpl::Error> {
        unreachable!("convert reads no keys")
    }
    async fn create_key_store(
        &self,
        _: CreateKeyStoreInput,
    ) -> Result<CreateKeyStoreOutput, aws_crypto_mpl::Error> {
        unreachable!("convert reads no keys")
    }
    async fn create_key(
        &self,
        _: CreateKeyInput,
    ) -> Result<CreateKeyOutput, aws_crypto_mpl::Error> {
        unreachable!("convert reads no keys")
    }
    async fn version_key(
        &self,
        _: VersionKeyInput,
    ) -> Result<VersionKeyOutput, aws_crypto_mpl::Error> {
        unreachable!("convert reads no keys")
    }
    async fn get_active_branch_key(
        &self,
        _: GetActiveBranchKeyInput,
    ) -> Result<GetActiveBranchKeyOutput, aws_crypto_mpl::Error> {
        unreachable!("convert reads no keys")
    }
    async fn get_branch_key_version(
        &self,
        _: GetBranchKeyVersionInput,
    ) -> Result<GetBranchKeyVersionOutput, aws_crypto_mpl::Error> {
        unreachable!("convert reads no keys")
    }
    async fn get_beacon_key(
        &self,
        _: GetBeaconKeyInput,
    ) -> Result<GetBeaconKeyOutput, aws_crypto_mpl::Error> {
        unreachable!("convert reads no keys")
    }
}

// ---- Fixtures from BeaconTestFixtures.dfy ----

fn std_beacon(name: &str, bits: u8, loc: Option<&str>) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .set_location(loc.map(str::to_owned))
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
fn std4() -> StandardBeacon {
    std_beacon("std4", 24, Some("std4"))
}
fn std6() -> StandardBeacon {
    std_beacon("std6", 26, Some("std6[0]"))
}
fn name_b() -> StandardBeacon {
    std_beacon("Name", 32, None)
}
fn title_b() -> StandardBeacon {
    std_beacon("Title", 32, None)
}
fn too_bad_b() -> StandardBeacon {
    std_beacon("TooBad", 32, None)
}
fn name_title_beacon() -> StandardBeacon {
    std_beacon("NameTitleField", 28, None)
}

fn signed_part(name: &str, prefix: &str, loc: Option<&str>) -> SignedPart {
    SignedPart::builder()
        .name(name)
        .prefix(prefix)
        .set_location(loc.map(str::to_owned))
        .build()
        .unwrap()
}
fn year() -> SignedPart {
    signed_part("Year", "Y_", None)
}
fn month() -> SignedPart {
    signed_part("Month", "M_", Some("Date.Month"))
}
fn nothing() -> SignedPart {
    signed_part("Nothing", "N__", None)
}

fn enc_part(name: &str, prefix: &str) -> EncryptedPart {
    EncryptedPart::builder()
        .name(name)
        .prefix(prefix)
        .build()
        .unwrap()
}
fn name_p() -> EncryptedPart {
    enc_part("Name", "N_")
}
fn title_p() -> EncryptedPart {
    enc_part("Title", "T_")
}
fn too_bad_p() -> EncryptedPart {
    enc_part("TooBad", "T")
}

fn ctor(parts: &[(&str, bool)]) -> Constructor {
    Constructor {
        parts: parts
            .iter()
            .map(|(name, required)| ConstructorPart {
                name: (*name).to_owned(),
                required: *required,
            })
            .collect(),
    }
}

fn compound(
    name: &str,
    encrypted: Vec<EncryptedPart>,
    signed: Vec<SignedPart>,
    constructors: Option<Vec<Constructor>>,
) -> CompoundBeacon {
    CompoundBeacon {
        name: name.to_owned(),
        split: '.',
        encrypted: (!encrypted.is_empty()).then_some(encrypted),
        signed: (!signed.is_empty()).then_some(signed),
        constructors,
    }
}
fn name_title() -> CompoundBeacon {
    compound("NameTitle", vec![name_p(), title_p()], vec![], None)
}
fn year_name() -> CompoundBeacon {
    compound("YearName", vec![name_p()], vec![year()], None)
}
fn just_signed() -> CompoundBeacon {
    compound("JustSigned", vec![], vec![year(), month()], None)
}
fn mixed_constructors() -> Vec<Constructor> {
    vec![
        ctor(&[("Name", true), ("Year", true)]),
        ctor(&[("Title", true), ("Month", false)]),
    ]
}
fn mixed() -> CompoundBeacon {
    compound(
        "Mixed",
        vec![name_p(), title_p()],
        vec![year(), month()],
        Some(mixed_constructors()),
    )
}

fn vpart(loc: &str, transform: VirtualTransform) -> VirtualPart {
    VirtualPart::builder()
        .location(loc)
        .transforms(transform)
        .build()
        .unwrap()
}
fn vpart1() -> VirtualPart {
    vpart("Name", VirtualTransform::insert("__"))
}
fn vpart2() -> VirtualPart {
    vpart("Title", VirtualTransform::lower())
}
fn virtual_field(name: &str, parts: Vec<VirtualPart>) -> VirtualField {
    VirtualField {
        name: name.to_owned(),
        parts,
    }
}
fn name_title_field() -> VirtualField {
    virtual_field("NameTitleField", vec![vpart1(), vpart2()])
}
fn name_virt_field() -> VirtualField {
    virtual_field("NameVirtField", vec![vpart1()])
}

fn single_source(key_id: &str, ttl: u64) -> BeaconKeySource {
    BeaconKeySource::Single(
        SingleKeyStore::builder()
            .key_id(key_id)
            .cache_ttl(Duration::from_secs(ttl))
            .build()
            .unwrap(),
    )
}
fn multi_source(key_field_name: &str) -> BeaconKeySource {
    BeaconKeySource::Multi(
        MultiKeyStore::builder()
            .key_field_name(key_field_name)
            .cache_ttl(Duration::from_secs(42))
            .build()
            .unwrap(),
    )
}

/// `GetLotsaBeacons`.
fn lotsa() -> BeaconVersion {
    BeaconVersion::builder()
        .version(1)
        .key_store(aws_crypto_mpl::key_store::Client::new(UnusedKeyStore))
        .key_source(single_source("foo", 42))
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
        .build()
        .unwrap()
}

/// `GetLotsaBeacons` with only `beacons` and no compound beacons or virtual fields.
fn bare(beacons: Vec<StandardBeacon>) -> BeaconVersion {
    let mut v = lotsa();
    v.standard_beacons = beacons;
    v.compound_beacons = None;
    v.virtual_fields = None;
    v
}

/// `FullTableConfig`'s attribute actions.
fn full_actions() -> HashMap<String, CryptoAction> {
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

/// `FullTableConfig`'s actions, plus `name` with `action`.
fn with_action(name: &str, action: CryptoAction) -> HashMap<String, CryptoAction> {
    let mut actions = full_actions();
    actions.insert(name.to_owned(), action);
    actions
}

fn table_builder(actions: HashMap<String, CryptoAction>) -> TableConfigBuilder {
    let keyring = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap();
    TableConfig::builder()
        .logical_table_name("Foo")
        .partition_key_name("foo")
        .set_attribute_actions_on_encrypt(Some(actions))
        .keyring(keyring)
}

fn search(version: BeaconVersion) -> SearchConfig {
    SearchConfig::builder()
        .versions(version)
        .write_version(1)
        .build()
        .unwrap()
}

fn run_table(
    table: TableConfigBuilder,
    version: BeaconVersion,
) -> Result<Option<SearchInfo>, Error> {
    convert(&table.search(search(version)).build().unwrap())
}

fn run(
    actions: HashMap<String, CryptoAction>,
    version: BeaconVersion,
) -> Result<Option<SearchInfo>, Error> {
    run_table(table_builder(actions), version)
}

/// The converted beacon version of `version` on `FullTableConfig`'s actions.
fn info(actions: HashMap<String, CryptoAction>, version: BeaconVersion) -> BeaconVersionInfo {
    run(actions, version).unwrap().unwrap().version
}

/// The message of the `Validation` error `result` must be.
fn val_msg(result: Result<Option<SearchInfo>, Error>) -> String {
    let err = result.expect_err("the configuration must be rejected");
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    err.message().to_owned()
}

fn fail(version: BeaconVersion) -> String {
    val_msg(run(full_actions(), version))
}

fn standard<'a>(info: &'a BeaconVersionInfo, name: &str) -> &'a StandardInfo {
    match &info.beacons[name] {
        Beacon::Standard(s) => s,
        Beacon::Compound(_) => panic!("{name} is compound"),
    }
}

fn compound_info<'a>(info: &'a BeaconVersionInfo, name: &str) -> &'a CompoundInfo {
    match &info.beacons[name] {
        Beacon::Compound(c) => c,
        Beacon::Standard(_) => panic!("{name} is standard"),
    }
}

fn part_names(c: &CompoundInfo) -> Vec<&str> {
    c.parts.iter().map(BeaconPart::name).collect()
}

fn cp(part: usize, required: bool) -> ConstructorPartInfo {
    ConstructorPartInfo { part, required }
}

fn loc(s: &str) -> TermLoc {
    TermLoc::parse(s).unwrap()
}

// ---- Successful conversion ----

#[test]
fn no_search_config_converts_to_none() {
    let table = table_builder(full_actions()).build().unwrap();
    assert!(convert(&table).unwrap().is_none());
}

#[test]
fn lotsa_beacons_convert() {
    let info = info(full_actions(), lotsa());
    assert!(matches!(&info.key_source.location, KeyLocation::Single { key_id } if key_id == "foo"));
    assert_eq!(
        info.beacons.keys().collect::<Vec<_>>(),
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
    assert_eq!(
        info.encrypted_fields.iter().collect::<Vec<_>>(),
        ["Name", "Title", "TooBad", "std2", "std4", "std6"]
    );
    assert_eq!(info.max_partitions, 1);
    assert_eq!(info.signed_beacon_names(), ["JustSigned"]);
    assert_eq!(
        info.virtual_fields.keys().collect::<Vec<_>>(),
        ["NameTitleField"]
    );
    let vf = &info.virtual_fields["NameTitleField"];
    assert_eq!(
        vf.parts.iter().map(|p| &p.loc).collect::<Vec<_>>(),
        [&loc("Name"), &loc("Title")]
    );

    assert_eq!(
        *standard(&info, "std6"),
        StandardInfo {
            name: "std6".to_owned(),
            beacon_name: "aws_dbe_b_std6".to_owned(),
            length: 26,
            loc: loc("std6[0]"),
            part_only: false,
            as_set: false,
            share: None,
            number_of_partitions: 1,
        }
    );
    // A beacon without a location beacons the attribute of its own name.
    assert_eq!(standard(&info, "std2").loc, loc("std2"));
    // A beacon may be defined on a virtual field.
    assert_eq!(standard(&info, "NameTitleField").loc, loc("NameTitleField"));

    let js = compound_info(&info, "JustSigned");
    assert_eq!(js.beacon_name, "JustSigned");
    assert_eq!(js.num_signed, 2);
    assert_eq!(
        js.parts,
        [
            BeaconPart::Signed {
                prefix: "Y_".to_owned(),
                name: "Year".to_owned(),
                loc: loc("Year"),
            },
            BeaconPart::Signed {
                prefix: "M_".to_owned(),
                name: "Month".to_owned(),
                loc: loc("Date.Month"),
            },
        ]
    );
    // Without constructors, the default one requires every part.
    assert_eq!(js.constructors, [vec![cp(0, true), cp(1, true)]]);

    let yn = compound_info(&info, "YearName");
    assert_eq!(yn.beacon_name, "aws_dbe_b_YearName");
    assert_eq!(part_names(yn), ["Year", "Name"]);
    assert_eq!(yn.num_signed, 1);
    assert_eq!(
        yn.parts[1],
        BeaconPart::Encrypted {
            prefix: "N_".to_owned(),
            beacon: standard(&info, "Name").clone(),
        }
    );

    let m = compound_info(&info, "Mixed");
    assert_eq!(m.split, '.');
    assert_eq!(part_names(m), ["Year", "Month", "Name", "Title"]);
    assert_eq!(
        m.constructors,
        [
            vec![cp(2, true), cp(0, true)],
            vec![cp(3, true), cp(1, false)]
        ]
    );
}

/// `TestNSwithEB`, first half: a compound beacon with an encrypted part may share an
/// encrypted attribute's name.
#[test]
fn compound_with_encrypted_part_may_share_encrypted_attribute_name() {
    let mut v = lotsa();
    v.standard_beacons = vec![std2(), std4(), std6(), name_title_beacon(), title_b()];
    v.compound_beacons = Some(vec![compound(
        "Name",
        vec![title_p()],
        vec![year(), month()],
        None,
    )]);
    let info = info(full_actions(), v);
    let c = compound_info(&info, "Name");
    assert_eq!(c.beacon_name, "aws_dbe_b_Name");
    assert_eq!(part_names(c), ["Year", "Month", "Title"]);
}

/// `CompoundMixed`: global parts named by constructors join a beacon's local parts.
#[test]
fn compound_uses_global_parts_named_by_constructors() {
    let mut v = lotsa();
    v.compound_beacons = Some(vec![compound(
        "Mixed",
        vec![title_p()],
        vec![month()],
        Some(mixed_constructors()),
    )]);
    v.signed_parts = Some(vec![year()]);
    v.encrypted_parts = Some(vec![name_p()]);
    let info = info(full_actions(), v);
    let m = compound_info(&info, "Mixed");
    assert_eq!(part_names(m), ["Month", "Year", "Title", "Name"]);
    assert_eq!(m.num_signed, 2);
    assert_eq!(
        m.constructors,
        [
            vec![cp(3, true), cp(1, true)],
            vec![cp(2, true), cp(0, false)]
        ]
    );
}

/// A signed part may also be `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT`.
#[test]
fn signed_part_may_be_in_encryption_context() {
    let mut v = bare(vec![std2()]);
    v.compound_beacons = Some(vec![compound("YearOnly", vec![], vec![year()], None)]);
    let info = info(
        with_action("Year", CryptoAction::SignAndIncludeInEncryptionContext),
        v,
    );
    assert_eq!(part_names(compound_info(&info, "YearOnly")), ["Year"]);
}

/// The styles from `TestPartOnlyNotStored`, `TestShareSameBeacon`, `TestSetNotSet`,
/// and `TestSharedSet`.
#[test]
fn beacon_styles_convert() {
    let mut v = lotsa();
    v.standard_beacons.extend([
        styled("partOnly", 23, BeaconStyle::part_only()),
        styled("shared", 24, BeaconStyle::shared("std2")),
        styled("setAttr", 24, BeaconStyle::as_set()),
        styled("sharedSet", 24, BeaconStyle::shared_set("std2")),
    ]);
    v.compound_beacons.as_mut().unwrap().push(compound(
        "compoundPart",
        vec![enc_part("partOnly", "S_")],
        vec![],
        None,
    ));
    let mut actions = full_actions();
    for name in ["partOnly", "shared", "setAttr", "sharedSet"] {
        actions.insert(name.to_owned(), CryptoAction::EncryptAndSign);
    }
    let info = info(actions, v);

    let p = standard(&info, "partOnly");
    assert!(p.part_only && !p.as_set && p.share.is_none());
    let s = standard(&info, "shared");
    assert!(!s.part_only && !s.as_set);
    assert_eq!(s.share.as_deref(), Some("std2"));
    let a = standard(&info, "setAttr");
    assert!(!a.part_only && a.as_set && a.share.is_none());
    let ss = standard(&info, "sharedSet");
    assert!(!ss.part_only && ss.as_set);
    assert_eq!(ss.share.as_deref(), Some("std2"));
}

#[test]
fn partitions_default_to_the_version_default() {
    let mut v = lotsa();
    v.maximum_number_of_partitions = Some(5);
    v.default_number_of_partitions = Some(3);
    v.standard_beacons[1].number_of_partitions = Some(2);
    let info = info(full_actions(), v);
    assert_eq!(info.max_partitions, 5);
    assert_eq!(standard(&info, "std2").number_of_partitions, 3);
    assert_eq!(standard(&info, "std4").number_of_partitions, 2);
}

#[test]
fn default_partitions_default_to_the_maximum() {
    let mut v = lotsa();
    v.maximum_number_of_partitions = Some(5);
    let info = info(full_actions(), v);
    assert_eq!(standard(&info, "std2").number_of_partitions, 5);
}

#[test]
fn multi_key_field_is_deleted_only_when_not_signed() {
    for (field, actions, delete) in [
        ("TheKeyField", full_actions(), false),
        ("Absent", full_actions(), true),
        (
            "Unsigned",
            with_action("Unsigned", CryptoAction::DoNothing),
            true,
        ),
    ] {
        let mut v = lotsa();
        v.key_source = multi_source(field);
        let info = info(actions, v);
        assert!(
            matches!(
                &info.key_source.location,
                KeyLocation::Multi { key_field_name, delete_key }
                    if key_field_name == field && *delete_key == delete
            ),
            "{field}: {:?}",
            info.key_source.location
        );
    }
}

// ---- Rejections ported from ConfigToInfo.dfy ----

#[test]
fn two_beacons_one_location() {
    let mut v = lotsa();
    v.standard_beacons = vec![
        std2(),
        std4(),
        std6(),
        name_title_beacon(),
        name_b(),
        title_b(),
        std_beacon("fred", 16, Some("std6[0]")),
    ];
    assert_eq!(
        fail(v),
        "Beacon fred is defined on location std6[0], but beacon std6 is already defined on that location."
    );
}

#[test]
fn two_virtual_fields_one_location() {
    let mut v = lotsa();
    v.virtual_fields = Some(vec![
        name_title_field(),
        virtual_field("TitleNameField", vec![vpart2(), vpart1()]),
    ]);
    assert_eq!(
        fail(v),
        "Virtual field TitleNameField is defined on the same locations as NameTitleField."
    );
}

#[test]
fn virtual_field_and_beacon_same_location() {
    let mut v = lotsa();
    v.virtual_fields = Some(vec![name_virt_field(), name_title_field()]);
    assert_eq!(
        fail(v),
        "Beacon Name is defined on location Name, but virtual field NameVirtField is already defined on that single location."
    );
}

/// `TestNSwithEB`, second half.
#[test]
fn signed_compound_may_not_share_attribute_name() {
    let mut v = lotsa();
    v.standard_beacons = vec![std2(), std4(), std6(), name_title_beacon(), title_b()];
    v.compound_beacons = Some(vec![compound("Name", vec![], vec![year(), month()], None)]);
    assert_eq!(
        fail(v),
        "Name not allowed as a CompoundBeacon because a fully signed beacon cannot have the same name as an existing attribute."
    );
}

// ---- Rejections ported from Beacon.dfy ----

#[test]
fn bad_prefix() {
    let mut v = bare(vec![name_b(), title_b(), too_bad_b()]);
    v.compound_beacons = Some(vec![compound(
        "BadPrefix",
        vec![name_p(), title_p(), too_bad_p()],
        vec![],
        None,
    )]);
    assert_eq!(
        fail(v),
        "Compound beacon BadPrefix defines part Title with prefix T_ which is incompatible with part TooBad which has a prefix of T."
    );
}

/// `BadPrefix2`: a signed part's prefix begins with an encrypted part's.
#[test]
fn bad_prefix_signed_vs_encrypted() {
    let bad_prefix2 = || compound("BadPrefix2", vec![name_p()], vec![nothing()], None);
    let mut v = bare(vec![name_b()]);
    v.compound_beacons = Some(vec![bad_prefix2()]);
    assert_eq!(
        fail(v.clone()),
        "Signed Part Nothing is built from Nothing which is not SIGN_ONLY."
    );
    assert_eq!(
        val_msg(run(with_action("Nothing", CryptoAction::SignOnly), v)),
        "Compound beacon BadPrefix2 defines part Nothing with prefix N__ which is incompatible with part Name which has a prefix of N_."
    );
}

#[test]
fn unused_part_only() {
    let mut v = lotsa();
    v.standard_beacons
        .push(styled("badBeacon", 24, BeaconStyle::part_only()));
    assert_eq!(
        val_msg(run(
            with_action("badBeacon", CryptoAction::EncryptAndSign),
            v
        )),
        "PartOnly beacon badBeacon MUST be used in a compound beacon."
    );
}

#[test]
fn compound_with_unknown() {
    let mut v = lotsa();
    v.compound_beacons.as_mut().unwrap().push(compound(
        "NameUnknown",
        vec![name_p(), enc_part("Unknown", "U_")],
        vec![],
        None,
    ));
    assert_eq!(
        fail(v),
        "Compound beacon NameUnknown refers to standard beacon Unknown which is not configured."
    );
}

#[test]
fn set_in_compound() {
    let mut v = lotsa();
    v.standard_beacons
        .push(styled("setBeacon", 24, BeaconStyle::as_set()));
    v.compound_beacons.as_mut().unwrap().push(compound(
        "compoundSet",
        vec![name_p(), enc_part("setBeacon", "S_")],
        vec![],
        None,
    ));
    assert_eq!(
        val_msg(run(
            with_action("setBeacon", CryptoAction::EncryptAndSign),
            v
        )),
        "Compound beacon compoundSet uses setBeacon which is an AsSet beacon, and therefore cannot be used in a Compound Beacon."
    );
}

#[test]
fn set_in_global_parts() {
    let mut v = lotsa();
    v.standard_beacons
        .push(styled("setBeacon", 24, BeaconStyle::as_set()));
    v.encrypted_parts = Some(vec![enc_part("setBeacon", "S_")]);
    assert_eq!(
        val_msg(run(
            with_action("setBeacon", CryptoAction::EncryptAndSign),
            v
        )),
        "Global Parts List uses setBeacon which is an AsSet beacon, and therefore cannot be used in a Compound Beacon."
    );
}

fn share_fail(beacons: Vec<StandardBeacon>, keep_compound: bool) -> String {
    let mut v = lotsa();
    if keep_compound {
        v.standard_beacons.extend(beacons);
    } else {
        v.compound_beacons = None;
        v.standard_beacons = beacons;
    }
    val_msg(run(
        with_action("shareBeacon", CryptoAction::EncryptAndSign),
        v,
    ))
}

#[test]
fn shared_bad_reference_to_compound() {
    assert_eq!(
        share_fail(
            vec![styled("shareBeacon", 24, BeaconStyle::shared("NameTitle"))],
            true
        ),
        "Beacon shareBeacon is shared to NameTitle but NameTitle is a compound beacon."
    );
}

#[test]
fn chained_share() {
    assert_eq!(
        share_fail(
            vec![
                std2(),
                styled("shareBeacon", 24, BeaconStyle::shared("std2")),
                styled("std4", 24, BeaconStyle::shared("shareBeacon")),
            ],
            false
        ),
        "Beacon std4 is shared to shareBeacon which is in turn shared to std2. Share chains are not allowed."
    );
}

#[test]
fn self_share() {
    assert_eq!(
        share_fail(
            vec![
                std2(),
                styled("shareBeacon", 24, BeaconStyle::shared("shareBeacon")),
            ],
            false
        ),
        "Beacon shareBeacon is shared to itself."
    );
}

#[test]
fn shared_bad_reference_non_existent() {
    assert_eq!(
        share_fail(
            vec![styled(
                "shareBeacon",
                24,
                BeaconStyle::shared("DoesNotExist")
            )],
            true
        ),
        "Beacon shareBeacon is shared to DoesNotExist which is not defined."
    );
}

#[test]
fn shared_bad_length() {
    assert_eq!(
        share_fail(
            vec![styled("shareBeacon", 23, BeaconStyle::shared("std2"))],
            true
        ),
        "Beacon shareBeacon is shared to std2 but shareBeacon has length 23 and std2 has length 24."
    );
}

#[test]
fn global_part_not_exist() {
    let mut v = lotsa();
    v.encrypted_parts = Some(vec![enc_part("NotExist", "Q_")]);
    assert_eq!(
        fail(v),
        "Global Parts List refers to standard beacon NotExist which is not configured."
    );
}

#[test]
fn duplicate_global_signed() {
    let mut v = lotsa();
    v.compound_beacons = None;
    v.signed_parts = Some(vec![year(), month(), year()]);
    assert_eq!(fail(v), "Duplicate part name Year in Global Parts List.");
}

#[test]
fn duplicate_global_encrypted() {
    let mut v = lotsa();
    v.compound_beacons = None;
    v.encrypted_parts = Some(vec![name_p(), title_p(), name_p()]);
    assert_eq!(fail(v), "Duplicate part name Name in Global Parts List.");
}

#[test]
fn duplicate_global_prefix() {
    let mut v = lotsa();
    v.compound_beacons = None;
    v.encrypted_parts = Some(vec![name_p(), title_p(), enc_part("std6", "N_")]);
    assert_eq!(fail(v), "Duplicate prefix N_ in Global Parts List.");
}

#[test]
fn duplicate_global_vs_local_encrypted() {
    let mut v = lotsa();
    v.encrypted_parts = Some(vec![name_p()]);
    assert_eq!(
        fail(v),
        "Compound beacon NameTitle defines encrypted part Name which is already defined as a global part."
    );
}

#[test]
fn duplicate_global_vs_local_signed() {
    let mut v = lotsa();
    v.signed_parts = Some(vec![month()]);
    assert_eq!(
        fail(v),
        "Compound beacon Mixed defines signed part Month which is already defined as a global part."
    );
}

#[test]
fn compound_no_constructor() {
    let mut v = lotsa();
    v.compound_beacons = Some(vec![compound("compoundDefault", vec![], vec![], None)]);
    v.signed_parts = Some(vec![month()]);
    v.encrypted_parts = Some(vec![name_p(), title_p()]);
    assert_eq!(
        fail(v),
        "Compound beacon compoundDefault defines no constructors, and also no local parts. Cannot make a default constructor from global parts."
    );
}

// ---- Further rejections, one per check ----

#[test]
fn write_version_must_be_one() {
    let search = SearchConfig::builder()
        .versions(lotsa())
        .write_version(2)
        .build()
        .unwrap();
    let table = table_builder(full_actions())
        .search(search)
        .build()
        .unwrap();
    assert_eq!(val_msg(convert(&table)), "write_version must be 1");
}

#[test]
fn exactly_one_version() {
    let mut table = table_builder(full_actions())
        .search(search(lotsa()))
        .build()
        .unwrap();
    table.search.as_mut().unwrap().versions.clear();
    assert_eq!(
        val_msg(convert(&table)),
        "the search config must have exactly one beacon version"
    );
}

#[test]
fn version_must_be_one() {
    let mut v = lotsa();
    v.version = 2;
    assert_eq!(fail(v), "the beacon version's version must be 1");
}

#[test]
fn needs_a_standard_beacon() {
    let mut v = lotsa();
    v.standard_beacons.clear();
    assert_eq!(fail(v), "At least one standard beacon must be configured.");
}

#[test]
fn cache_ttl_must_not_be_zero() {
    let mut v = lotsa();
    v.key_source = single_source("foo", 0);
    assert_eq!(
        fail(v),
        "the beacon key cache TTL must be at least 1 second"
    );
}

#[test]
fn maximum_partitions_below_255() {
    let mut v = lotsa();
    v.maximum_number_of_partitions = Some(255);
    assert_eq!(
        fail(v),
        "Invalid maximumNumberOfPartitions specified, 255, must be 0 < maximumNumberOfPartitions <= 255."
    );
}

#[test]
fn default_partitions_below_maximum() {
    for (max, default) in [(Some(5), 5), (None, 1)] {
        let mut v = lotsa();
        v.maximum_number_of_partitions = max;
        v.default_number_of_partitions = Some(default);
        assert_eq!(
            fail(v),
            format!(
                "Invalid defaultNumberOfPartitions specified, {default}, must be 0 < defaultNumberOfPartitions < maximumNumberOfPartitions."
            )
        );
    }
}

#[test]
fn beacon_partitions_below_maximum() {
    let mut v = lotsa();
    v.maximum_number_of_partitions = Some(5);
    v.standard_beacons[1].number_of_partitions = Some(5);
    assert_eq!(
        fail(v),
        "Constrained numberOfPartitions for  std4 is 5 but it must be less than the maximumNumberOfPartitions 5"
    );
}

#[test]
fn multi_key_field_must_not_be_encrypted() {
    let mut v = lotsa();
    v.key_source = multi_source("Name");
    assert_eq!(
        fail(v),
        "Beacon key field name Name is configured as ENCRYPT_AND_SIGN which is not allowed."
    );
}

#[test]
fn multi_key_field_must_not_be_a_beacon() {
    let mut v = lotsa();
    v.key_source = multi_source("JustSigned");
    assert_eq!(
        fail(v),
        "A beacon key field name of JustSigned was configured, but there's also a beacon of that name."
    );
}

#[test]
fn multi_key_field_must_not_be_a_virtual_field() {
    let mut v = lotsa();
    v.virtual_fields.as_mut().unwrap().push(virtual_field(
        "YearField",
        vec![vpart("Year", VirtualTransform::upper())],
    ));
    v.key_source = multi_source("YearField");
    assert_eq!(
        fail(v),
        "A beacon key field name of YearField was configured, but there's also a virtual field of that name."
    );
}

/// A table that allows `Unsigned` and the prefix `:` unsigned.
fn unsigned_table() -> TableConfigBuilder {
    table_builder(full_actions())
        .allowed_unsigned_attributes("Unsigned")
        .allowed_unsigned_attribute_prefix(":")
}

#[test]
fn standard_beacon_name_conflicts() {
    for (name, reason) in [
        ("Year", "it is already an unencrypted attribute"),
        (
            "Unsigned",
            "it is already an allowed unauthenticated attribute",
        ),
        (":x", "it begins with the allowed unauthenticated prefix"),
        ("aws_dbe_x", "it begins with the reserved prefix"),
    ] {
        let v = bare(vec![std_beacon(name, 24, Some("std2"))]);
        assert_eq!(
            val_msg(run_table(unsigned_table(), v)),
            format!("{name} not allowed as a StandardBeacon because {reason}.")
        );
    }
}

#[test]
fn compound_beacon_name_conflicts() {
    for (name, reason) in [
        ("Year", "it is already an unencrypted attribute"),
        (
            "Unsigned",
            "it is already an allowed unauthenticated attribute",
        ),
        (":x", "it begins with the allowed unauthenticated prefix"),
        ("aws_dbe_x", "it begins with the reserved prefix"),
    ] {
        let mut v = bare(vec![name_b()]);
        v.compound_beacons = Some(vec![compound(name, vec![name_p()], vec![], None)]);
        assert_eq!(
            val_msg(run_table(unsigned_table(), v)),
            format!("{name} not allowed as a CompoundBeacon because {reason}.")
        );
    }
}

#[test]
fn virtual_field_name_conflicts() {
    for (name, reason) in [
        ("Year", "it is already a configured attribute"),
        (
            "Unsigned",
            "it is already an allowed unauthenticated attribute",
        ),
        (":x", "it begins with the allowed unauthenticated prefix"),
        ("aws_dbe_x", "it begins with the reserved prefix"),
    ] {
        let mut v = lotsa();
        v.virtual_fields = Some(vec![virtual_field(name, vec![vpart1()])]);
        assert_eq!(
            val_msg(run_table(unsigned_table(), v)),
            format!("{name} not allowed as a Virtual Field because {reason}.")
        );
    }
}

#[test]
fn duplicate_standard_beacon() {
    assert_eq!(
        fail(bare(vec![std2(), std2()])),
        "Duplicate StandardBeacon name : std2"
    );
}

#[test]
fn standard_beacon_on_unencrypted_field() {
    assert_eq!(
        fail(bare(vec![std_beacon("Plain", 24, None)])),
        "StandardBeacon Plain not defined on an encrypted field."
    );
    // A virtual field of only signed parts is not encrypted either.
    let mut v = bare(vec![std_beacon("YearBeacon", 24, Some("YearField"))]);
    v.virtual_fields = Some(vec![virtual_field(
        "YearField",
        vec![vpart("Year", VirtualTransform::upper())],
    )]);
    assert_eq!(
        fail(v),
        "StandardBeacon YearBeacon not defined on an encrypted field."
    );
}

#[test]
fn standard_beacon_bad_location() {
    assert_eq!(
        fail(bare(vec![std_beacon("bad", 24, Some("std2["))])),
        "a list index in a path must be written as [N]"
    );
}

/// The longest name whose beacon attribute `aws_dbe_b_<name>` is still a valid attribute name.
const LONGEST_BEACON_NAME: usize = 65535 - "aws_dbe_b_".len();

#[test]
fn standard_beacon_name_too_long() {
    let name = "a".repeat(LONGEST_BEACON_NAME + 1);
    assert_eq!(
        fail(bare(vec![std_beacon(&name, 24, Some("std2"))])),
        format!("aws_dbe_b_{name} is not a valid attribute name.")
    );
    let name = "a".repeat(LONGEST_BEACON_NAME);
    let info = info(
        full_actions(),
        bare(vec![std_beacon(&name, 24, Some("std2"))]),
    );
    assert_eq!(
        standard(&info, &name).beacon_name,
        format!("aws_dbe_b_{name}")
    );
}

#[test]
fn compound_beacon_name_too_long() {
    let name = "c".repeat(LONGEST_BEACON_NAME + 1);
    let mut v = bare(vec![name_b()]);
    v.compound_beacons = Some(vec![compound(&name, vec![name_p()], vec![], None)]);
    assert_eq!(
        fail(v),
        format!("aws_dbe_b_{name} is not a valid attribute name.")
    );
}

#[test]
fn duplicate_virtual_field() {
    let mut v = lotsa();
    v.virtual_fields = Some(vec![name_title_field(), name_title_field()]);
    assert_eq!(fail(v), "Duplicate VirtualField name : NameTitleField");
}

#[test]
fn virtual_field_on_unsigned_field() {
    let mut v = lotsa();
    v.virtual_fields = Some(vec![virtual_field(
        "Bad",
        vec![vpart1(), vpart("Plain", VirtualTransform::lower())],
    )]);
    assert_eq!(
        fail(v),
        "VirtualField Bad must be defined on signed fields."
    );
}

#[test]
fn virtual_field_bad_location() {
    let mut v = lotsa();
    v.virtual_fields = Some(vec![virtual_field(
        "Bad",
        vec![vpart("Name[x]", VirtualTransform::lower())],
    )]);
    assert_eq!(
        fail(v),
        "a list index in a path has a character that is not a digit: x"
    );
}

#[test]
fn duplicate_compound_beacon() {
    let mut v = bare(vec![name_b(), title_b()]);
    v.compound_beacons = Some(vec![name_title(), name_title()]);
    assert_eq!(fail(v), "two compound beacons are named NameTitle");
    // A compound beacon may not take a standard beacon's name either.
    let mut v = bare(vec![name_b(), title_b()]);
    v.compound_beacons = Some(vec![compound("Name", vec![title_p()], vec![], None)]);
    assert_eq!(fail(v), "two compound beacons are named Name");
}

/// A version with `NameB` and `TitleB`, and one compound beacon `C` of Name and Title.
fn with_constructors(constructors: Option<Vec<Constructor>>) -> BeaconVersion {
    let mut v = bare(vec![name_b(), title_b()]);
    v.compound_beacons = Some(vec![compound(
        "C",
        vec![name_p(), title_p()],
        vec![],
        constructors,
    )]);
    v
}

#[test]
fn constructor_checks() {
    for (constructors, msg) in [
        (
            vec![],
            "For beacon C an empty constructor list was supplied.",
        ),
        (
            vec![ctor(&[])],
            "Every constructor must have at least one part.",
        ),
        (
            vec![ctor(&[("Name", false)])],
            "A Constructor for beacon C lacks any required parts",
        ),
        (
            vec![ctor(&[("Bogus", true)])],
            "Constructor refers to part name Bogus but there is no part by that name.",
        ),
        (
            vec![
                ctor(&[("Name", true), ("Title", false)]),
                ctor(&[("Title", false), ("Name", true)]),
            ],
            "Multiple constructors for C have the same set of required parts : Name",
        ),
    ] {
        assert_eq!(fail(with_constructors(Some(constructors))), msg);
    }
}

#[test]
fn constructors_with_different_required_parts_are_kept_in_order() {
    let info = info(
        full_actions(),
        with_constructors(Some(vec![
            ctor(&[("Title", true)]),
            ctor(&[("Name", true), ("Title", false)]),
        ])),
    );
    assert_eq!(
        compound_info(&info, "C").constructors,
        [vec![cp(1, true)], vec![cp(0, true), cp(1, false)]]
    );
}

#[test]
fn compound_needs_parts() {
    let mut v = bare(vec![name_b()]);
    v.compound_beacons = Some(vec![compound(
        "C",
        vec![],
        vec![],
        Some(vec![ctor(&[("Name", true)])]),
    )]);
    assert_eq!(fail(v), "For beacon C no parts were supplied.");
}

/// A version whose compound beacon `C` has a local `Title` part, with these global parts.
fn with_globals(signed: Vec<SignedPart>, encrypted: Vec<EncryptedPart>) -> BeaconVersion {
    let mut v = bare(vec![name_b(), title_b()]);
    v.compound_beacons = Some(vec![compound("C", vec![title_p()], vec![], None)]);
    v.signed_parts = Some(signed);
    v.encrypted_parts = Some(encrypted);
    v
}

#[test]
fn global_signed_and_encrypted_parts_must_differ() {
    assert_eq!(
        fail(with_globals(
            vec![signed_part("Name", "Q_", Some("Year"))],
            vec![name_p()]
        )),
        "Duplicate part name(s) Name between Global Signed Parts List and Global Encrypted Parts List."
    );
    assert_eq!(
        fail(with_globals(
            vec![signed_part("Year", "N_", None)],
            vec![name_p()]
        )),
        "Duplicate prefix(es) N_ between Global Signed Parts List and Global Encrypted Parts List."
    );
}

#[test]
fn local_prefix_must_differ_from_global() {
    let mut v = with_globals(vec![year()], vec![]);
    v.encrypted_parts = None;
    v.compound_beacons.as_mut().unwrap()[0].signed =
        Some(vec![signed_part("Month", "Y_", Some("Date.Month"))]);
    assert_eq!(
        fail(v),
        "Compound beacon C defines signed part Month with prefix Y_ which is already defined as the prefix of a global part."
    );
}
