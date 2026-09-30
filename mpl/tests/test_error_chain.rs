// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the `error_chain` helpers over synthetic chains.
//!
//! Behavior against a real `SdkError` is asserted in
//! `tests/test_keystore_branch_key_store.rs`, which has the fixtures to
//! produce one; a real service code is asserted in the integration suites.

use std::error::Error as _;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use aws_crypto_mpl::error_chain::{aws_service_error_code, find_in_error_chain};
use aws_crypto_mpl::{Error, ErrorKind};

/// A three-link chain `Error -> Error -> io::Error`,
/// the shape a keyring produces when the keystore fails beneath it.
fn nested_chain() -> Error {
    let root = IoError::new(IoErrorKind::ConnectionReset, "connection reset by peer");
    let middle = Error::with_cause(ErrorKind::RemoteTransport, "DynamoDB failed", root);
    Error::wrap("keyring could not reach its keystore", middle)
}

#[test]
fn find_in_error_chain_returns_the_error_itself_at_depth_zero() {
    let err = nested_chain();
    let found = find_in_error_chain::<Error>(&err).expect("the outermost error matches its type");
    assert_eq!(found.message(), "keyring could not reach its keystore");
}

#[test]
fn find_in_error_chain_walks_to_the_root_of_the_chain() {
    let err = nested_chain();
    let found = find_in_error_chain::<IoError>(&err).expect("the root io::Error is reachable");
    assert_eq!(found.kind(), IoErrorKind::ConnectionReset);
}

#[test]
fn find_in_error_chain_returns_none_for_a_type_absent_from_the_chain() {
    let err = nested_chain();
    assert!(find_in_error_chain::<std::fmt::Error>(&err).is_none());
}

#[test]
fn find_in_error_chain_returns_none_for_a_single_link_chain() {
    let err = Error::new(ErrorKind::Internal, "no underlying cause");
    assert!(
        err.source().is_none(),
        "precondition: the chain has one link"
    );
    assert!(find_in_error_chain::<IoError>(&err).is_none());
}

#[test]
fn aws_service_error_code_is_none_when_no_sdk_error_is_present() {
    let err = nested_chain();
    assert!(
        aws_service_error_code(&err).is_none(),
        "a chain rooted in io::Error holds no AWS SDK error, so there is no service code"
    );
}
