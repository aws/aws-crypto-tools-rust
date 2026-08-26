// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the `error_chain` helpers over synthetic chains.
//!
//! Behavior against a real `SdkError` is asserted in
//! `tests/test_keystore_branch_key_store.rs`, which has the fixtures to
//! produce one; a real service code is asserted in the integration suites.

use std::error::Error as _;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use aws_crypto_mpl::cmc::CmcError;
use aws_crypto_mpl::error_chain::{aws_service_error_code, find_source};
use aws_crypto_mpl::keystore::{KeystoreError, KeystoreErrorKind};
use aws_crypto_mpl::structures::MaterialsError;

/// A three-link chain `MaterialsError -> KeystoreError -> io::Error`,
/// mirroring the real shape a keyring produces when the keystore fails
/// beneath it.
fn nested_chain() -> MaterialsError {
    let root = IoError::new(IoErrorKind::ConnectionReset, "connection reset by peer");
    let middle = KeystoreError::with_cause(KeystoreErrorKind::Dynamodb, "DynamoDB failed", root);
    MaterialsError::keyring_failed_with_cause("keyring could not reach its keystore", middle)
}

#[test]
fn find_source_returns_the_error_itself_at_depth_zero() {
    let err = nested_chain();
    let found = find_source::<MaterialsError>(&err).expect("the outermost error matches its type");
    assert_eq!(
        found.message, "keyring could not reach its keystore",
        "depth-0 lookup must return the outermost error, not a link below it"
    );
}

#[test]
fn find_source_walks_to_an_intermediate_link() {
    let err = nested_chain();
    let found = find_source::<KeystoreError>(&err).expect("the KeystoreError link is reachable");
    assert_eq!(found.kind(), &KeystoreErrorKind::Dynamodb);
    assert_eq!(found.message(), "DynamoDB failed");
}

#[test]
fn find_source_walks_to_the_root_of_the_chain() {
    let err = nested_chain();
    let found = find_source::<IoError>(&err).expect("the root io::Error is reachable");
    assert_eq!(
        found.kind(),
        IoErrorKind::ConnectionReset,
        "the concrete root error must survive two levels of wrapping"
    );
}

#[test]
fn find_source_returns_none_for_a_type_absent_from_the_chain() {
    let err = nested_chain();
    assert!(
        find_source::<CmcError>(&err).is_none(),
        "a type that does not appear in the chain must not match by coincidence"
    );
}

#[test]
fn find_source_returns_none_for_a_single_link_chain() {
    let err = MaterialsError::keyring_failed("no underlying cause");
    assert!(
        err.source().is_none(),
        "precondition: the chain has one link"
    );
    assert!(
        find_source::<IoError>(&err).is_none(),
        "walking a chain with no source must terminate and return None"
    );
}

#[test]
fn aws_service_error_code_is_none_when_no_sdk_error_is_present() {
    let err = nested_chain();
    assert!(
        aws_service_error_code(&err).is_none(),
        "a chain rooted in io::Error holds no AWS SDK error, so there is no service code"
    );
}
