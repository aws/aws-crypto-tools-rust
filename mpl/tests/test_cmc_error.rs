// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `CmcError`'s cause channel.
//!
//! `Cmc` is a public trait, so an out-of-crate cache backed by a real store
//! needs a way to hand its own failure up without flattening it to text.
//! These tests pin that channel and cover every executable line added to
//! `mpl/src/cmc/mod.rs`.

use std::error::Error as _;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use aws_crypto_mpl::error_chain::find_source;
use aws_crypto_mpl::{CmcError, CmcErrorKind};

#[test]
fn storage_failed_with_cause_exposes_the_cause_through_source() {
    let root = IoError::new(IoErrorKind::PermissionDenied, "backing store unreadable");
    let err = CmcError::storage_failed_with_cause("remote cache read failed", root);

    assert_eq!(err.kind(), &CmcErrorKind::StorageFailed);
    assert_eq!(err.message, "remote cache read failed");

    let source = err
        .source()
        .expect("the underlying store error must be attached as the cause");
    let io = source
        .downcast_ref::<IoError>()
        .expect("the cause must still be the concrete io::Error, not a string");
    assert_eq!(io.kind(), IoErrorKind::PermissionDenied);
}

#[test]
fn storage_failed_with_cause_is_reachable_through_the_cause_accessor() {
    let root = IoError::new(IoErrorKind::TimedOut, "store timed out");
    let err = CmcError::storage_failed_with_cause("remote cache read failed", root);

    let cause = err.cause().expect("cause() must agree with source()");
    assert!(
        cause.downcast_ref::<IoError>().is_some(),
        "cause() must expose the same concrete error that source() does"
    );
}

#[test]
fn storage_failed_without_a_cause_has_no_source() {
    let err = CmcError::storage_failed("lock poisoned");
    assert_eq!(err.kind(), &CmcErrorKind::StorageFailed);
    assert!(
        err.source().is_none(),
        "the causeless constructor must not synthesize a source"
    );
    assert!(err.cause().is_none(), "cause() must agree with source()");
}

#[test]
fn invalid_entry_has_no_source() {
    let err = CmcError::invalid_entry("grace_period must be at least 1");
    assert_eq!(err.kind(), &CmcErrorKind::InvalidEntry);
    assert!(
        err.source().is_none(),
        "an invalid-entry rejection originates here and wraps nothing"
    );
}

#[test]
fn equality_ignores_the_cause() {
    let with = CmcError::storage_failed_with_cause(
        "remote cache read failed",
        IoError::other("some root cause"),
    );
    let without = CmcError::storage_failed("remote cache read failed");

    // `dyn Error` is not `Eq`, so `PartialEq` compares `kind` and `message`
    // only — matching `KeystoreError` and `MaterialsError`. Callers that need
    // to assert on the cause must downcast it rather than compare errors.
    assert_eq!(
        with, without,
        "two errors with the same kind and message compare equal regardless of cause"
    );
}

#[test]
fn display_renders_only_its_own_layer() {
    let err = CmcError::storage_failed_with_cause(
        "remote cache read failed",
        IoError::other("root cause text"),
    );
    let rendered = err.to_string();

    assert_eq!(
        rendered,
        "CmcError(StorageFailed): remote cache read failed"
    );
    assert!(
        !rendered.contains("root cause text"),
        "Display must not duplicate the cause; a chain-walking printer renders it"
    );
}

#[test]
fn the_cause_is_reachable_with_find_source() {
    let err = CmcError::storage_failed_with_cause(
        "remote cache read failed",
        IoError::new(IoErrorKind::NotFound, "entry vanished"),
    );
    let io = find_source::<IoError>(&err).expect("find_source must reach the CmcError's cause");
    assert_eq!(io.kind(), IoErrorKind::NotFound);
}
