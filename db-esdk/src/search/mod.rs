// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Searchable encryption: beacons that let a [`Client`](crate::Client) query encrypted attributes.
//!
//! A beacon is a truncated HMAC of an attribute's plaintext, written next to the item.
//! Items with the same plaintext have the same beacon, so a query can match them
//! without decrypting. Configure the beacons of a table with a [`SearchConfig`],
//! and set it with [`TableConfigBuilder::search`](crate::TableConfigBuilder::search).
//!
//! The configuration is checked against the table's attribute actions
//! when the [`Client`](crate::Client) is built.

pub(crate) mod beacon;
mod config;
pub(crate) mod convert;
pub(crate) mod filter;
pub(crate) mod info;
mod key_source;
pub(crate) mod support;
pub(crate) mod term_loc;
pub(crate) mod virt;

pub use config::{
    AsSet, BeaconKeySource, BeaconStyle, BeaconVersion, BeaconVersionBuilder, CompoundBeacon,
    CompoundBeaconBuilder, Constructor, ConstructorBuilder, ConstructorPart,
    ConstructorPartBuilder, EncryptedPart, EncryptedPartBuilder, GetPrefix, GetPrefixBuilder,
    GetSegment, GetSegmentBuilder, GetSegments, GetSegmentsBuilder, GetSubstring,
    GetSubstringBuilder, GetSuffix, GetSuffixBuilder, Insert, InsertBuilder, Lower, MultiKeyStore,
    MultiKeyStoreBuilder, PartOnly, SearchConfig, SearchConfigBuilder, Shared, SharedBuilder,
    SharedSet, SharedSetBuilder, SignedPart, SignedPartBuilder, SingleKeyStore,
    SingleKeyStoreBuilder, StandardBeacon, StandardBeaconBuilder, Upper, VirtualField,
    VirtualFieldBuilder, VirtualPart, VirtualPartBuilder, VirtualTransform,
};
