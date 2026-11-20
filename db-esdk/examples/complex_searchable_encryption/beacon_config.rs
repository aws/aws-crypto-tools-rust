// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds the table's searchable encryption configuration:
//! the standard and compound beacons, their encrypted and signed parts, the hierarchical keyring, and the crypto actions.
//! The constructors follow the PK/SK designs from the searchable encryption workshop.
//! The queries in `query_requests` use the beacons that this configuration writes.

use std::time::Duration;

use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::search::{
    BeaconKeySource, BeaconVersion, CompoundBeacon, Constructor, ConstructorPart, EncryptedPart,
    SearchConfig, SignedPart, SingleKeyStore, StandardBeacon,
};
use aws_db_esdk::types::CryptoAction;
use aws_db_esdk::{TableConfig, key_store};

/// Attributes to encrypt and sign.
/// Every attribute with a standard beacon must be here.
/// So must the other sensitive values (`Attendees`, `Subject`) and the `Location` map that the location beacons read from.
const ENCRYPT_AND_SIGN: &[&str] = &[
    "EmployeeID",
    "TicketNumber",
    "ProjectName",
    "EmployeeName",
    "EmployeeEmail",
    "CreatorEmail",
    "ProjectStatus",
    "OrganizerEmail",
    "ManagerEmail",
    "AssigneeEmail",
    "City",
    "Severity",
    "Location",
    "Attendees",
    "Subject",
];

/// Signed parts and other plaintext attributes.
/// They stay unencrypted so that range and sort queries can use them,
/// and signed so that the client detects tampering.
const SIGN_ONLY: &[&str] = &[
    "TicketModTime",
    "MeetingStart",
    "TimeCardStart",
    "EmployeeTitle",
    "Description",
    "ProjectTarget",
    "Hours",
    "Role",
    "Message",
    "ProjectStart",
    "Duration",
];

pub async fn table_config(
    key_store: &key_store::DynamoDbKeyStore,
) -> Result<TableConfig, crate::BoxError> {
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store.clone())
        // How long the keyring reuses cached branch key material.
        .ttl(Duration::from_secs(600))
        .branch_key_id(crate::BRANCH_KEY_ID)
        .build()
        .await?;

    // `bits` is how many bits of the HMAC each beacon keeps.
    // 4 suits this small demo data set.
    // In production, size each beacon as `basic_searchable_encryption` describes.
    // A beacon over a nested field names its location.
    let mut standard_beacons = Vec::new();
    for name in [
        "EmployeeID",
        "TicketNumber",
        "ProjectName",
        "EmployeeEmail",
        "CreatorEmail",
        "ProjectStatus",
        "OrganizerEmail",
        "ManagerEmail",
        "AssigneeEmail",
        "Severity",
    ] {
        standard_beacons.push(StandardBeacon::builder().name(name).bits(4).build()?);
    }
    for (name, location) in [
        ("City", "Location.City"),
        ("Building", "Location.Building"),
        ("Floor", "Location.Floor"),
        ("Room", "Location.Room"),
        ("Desk", "Location.Desk"),
    ] {
        standard_beacons.push(
            StandardBeacon::builder()
                .name(name)
                .location(location)
                .bits(4)
                .build()?,
        );
    }

    // Every prefix in a configuration must be unique.
    // So some prefixes here differ from the ones that the workshop suggests.
    let mut encrypted_parts = Vec::new();
    for (name, prefix) in [
        ("EmployeeID", "E-"),
        ("TicketNumber", "T-"),
        ("ProjectName", "P-"),
        ("EmployeeEmail", "EE-"),
        ("CreatorEmail", "CE-"),
        ("OrganizerEmail", "OE-"),
        ("ManagerEmail", "ME-"),
        ("AssigneeEmail", "AE-"),
        ("ProjectStatus", "PSts-"),
        ("City", "C-"),
        ("Severity", "S-"),
        ("Building", "B-"),
        ("Floor", "F-"),
        ("Room", "R-"),
        ("Desk", "D-"),
    ] {
        encrypted_parts.push(EncryptedPart::builder().name(name).prefix(prefix).build()?);
    }

    // Each signed part here is a date or time.
    // When a signed part comes first in a compound beacon, queries can sort and compare on it.
    let mut signed_parts = Vec::new();
    for (name, prefix) in [
        ("TicketModTime", "M-"),
        ("MeetingStart", "MS-"),
        ("TimeCardStart", "TC-"),
        ("ProjectStart", "PS-"),
    ] {
        signed_parts.push(SignedPart::builder().name(name).prefix(prefix).build()?);
    }

    // Builds a constructor whose parts are all required: an item matches it only if it has every part.
    // The client tries a beacon's constructors in order, and the first one that matches builds the value.
    // So list specific constructors before general ones.
    // The part order is the order that the parts appear in the beacon value.
    let required = |names: &[&str]| -> Result<Constructor, crate::BoxError> {
        let parts = names
            .iter()
            .map(|n| ConstructorPart::required(*n))
            .collect::<Vec<_>>();
        Ok(Constructor::builder().set_parts(Some(parts)).build()?)
    };

    // The split character must not appear in any part value.
    let compound_beacons = vec![
        CompoundBeacon::builder()
            .name("PK")
            .split("~")
            .constructors(required(&["EmployeeID"])?)
            .constructors(required(&["Building"])?)
            .constructors(required(&["TicketNumber"])?)
            .constructors(required(&["ProjectName"])?)
            .build()?,
        CompoundBeacon::builder()
            .name("SK")
            .split("~")
            .constructors(required(&["TicketModTime"])?)
            .constructors(required(&["MeetingStart", "Floor", "Room"])?)
            .constructors(required(&["TimeCardStart", "EmployeeEmail"])?)
            .constructors(required(&["ProjectName"])?)
            .constructors(required(&["EmployeeID"])?)
            .build()?,
        CompoundBeacon::builder()
            .name("PK1")
            .split("~")
            .constructors(required(&["CreatorEmail"])?)
            .constructors(required(&["EmployeeEmail"])?)
            .constructors(required(&["ProjectStatus"])?)
            .constructors(required(&["OrganizerEmail"])?)
            .build()?,
        CompoundBeacon::builder()
            .name("SK1")
            .split("~")
            .constructors(required(&["MeetingStart", "Floor", "Room"])?)
            .constructors(required(&["TimeCardStart"])?)
            .constructors(required(&["TicketModTime"])?)
            .constructors(required(&["ProjectStart"])?)
            .constructors(required(&["EmployeeID"])?)
            .build()?,
        CompoundBeacon::builder()
            .name("PK2")
            .split("~")
            .constructors(required(&["ManagerEmail"])?)
            .constructors(required(&["AssigneeEmail"])?)
            .build()?,
        CompoundBeacon::builder()
            .name("PK3")
            .split("~")
            .constructors(required(&["City"])?)
            .constructors(required(&["Severity"])?)
            .build()?,
        CompoundBeacon::builder()
            .name("SK3")
            .split("~")
            .constructors(required(&["Building", "Floor", "Desk"])?)
            .constructors(required(&["TicketModTime"])?)
            .build()?,
    ];

    // `version` matches the search config's `write_version`: both are 1.
    let beacon_version = BeaconVersion::builder()
        .version(1)
        .key_store(key_store.clone())
        .key_source(BeaconKeySource::Single(
            SingleKeyStore::builder()
                .key_id(crate::BRANCH_KEY_ID)
                .cache_ttl(Duration::from_secs(6000))
                .build()?,
        ))
        .set_standard_beacons(Some(standard_beacons))
        .set_compound_beacons(Some(compound_beacons))
        .set_encrypted_parts(Some(encrypted_parts))
        .set_signed_parts(Some(signed_parts))
        .build()?;

    let search = SearchConfig::builder()
        .write_version(1)
        .versions(beacon_version)
        .build()?;

    // The partition key is SignOnly, like the other plaintext attributes.
    let mut table = TableConfig::builder()
        .partition_key_name("partition_key")
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly);
    for name in ENCRYPT_AND_SIGN {
        table = table.attribute_actions_on_encrypt(*name, CryptoAction::EncryptAndSign);
    }
    for name in SIGN_ONLY {
        table = table.attribute_actions_on_encrypt(*name, CryptoAction::SignOnly);
    }
    let table = table.keyring(keyring).search(search).build()?;

    Ok(table)
}
