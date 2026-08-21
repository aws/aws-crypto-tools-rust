// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Constant-time equality tests ported from Dafny [`ConstantTime.dfy`].
//! The Dafny test has six assertions covering empty inputs, single-byte
//! matches/mismatches, and three-byte matches/mismatches at both the head
//! and tail. A length-mismatch case is added on the Rust side for coverage.
//!
//! [`ConstantTime.dfy`]: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/test/ConstantTime.dfy

use aws_mpl_primitives::constant_time_equal;

#[test]
fn test_constant_time_equal_empty_slices() {
    assert!(constant_time_equal(&[], &[]));
}

#[test]
fn test_constant_time_equal_single_byte_match() {
    assert!(constant_time_equal(&[1], &[1]));
}

#[test]
fn test_constant_time_equal_single_byte_mismatch() {
    assert!(!constant_time_equal(&[1], &[2]));
}

#[test]
fn test_constant_time_equal_three_bytes_match() {
    assert!(constant_time_equal(&[1, 2, 3], &[1, 2, 3]));
}

#[test]
fn test_constant_time_equal_three_bytes_mismatch_head() {
    assert!(!constant_time_equal(&[2, 2, 3], &[1, 2, 3]));
}

#[test]
fn test_constant_time_equal_three_bytes_mismatch_tail() {
    assert!(!constant_time_equal(&[1, 2, 3], &[1, 2, 4]));
}

#[test]
fn test_constant_time_equal_length_mismatch() {
    // Not covered by Dafny, but aws-lc-rs's verify_slices_are_equal returns
    // an error (Err) for mismatched lengths — this exercises that branch.
    assert!(!constant_time_equal(&[1, 2, 3], &[1, 2, 3, 4]));
    assert!(!constant_time_equal(&[1, 2, 3, 4], &[1, 2, 3]));
}
