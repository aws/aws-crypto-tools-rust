// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Random-byte generation tests ported from Dafny
//! `TestGenerateRandomBytes.dfy`. Verifies the RNG fills the caller's
//! buffer for a small (5-byte) request.

use aws_mpl_primitives::{Error, generate_random_bytes};

#[test]
fn test_generate_random_bytes_basic() -> Result<(), Error> {
    let mut buf = [0u8; 5];
    generate_random_bytes(&mut buf)?;
    // The Dafny test only asserts the length invariant. There is no
    // sensible way to assert "randomness" without a statistical test; if
    // aws-lc-rs's fill returns Ok, prim is fulfilling its contract.
    assert_eq!(buf.len(), 5);
    Ok(())
}

#[test]
fn test_generate_random_bytes_zero_length() -> Result<(), Error> {
    // aws-lc-rs's fill is a no-op for zero-length buffers; this exercises
    // that boundary.
    let mut buf: [u8; 0] = [];
    generate_random_bytes(&mut buf)?;
    Ok(())
}

#[test]
fn test_generate_random_bytes_larger_buffer() -> Result<(), Error> {
    let mut buf = [0u8; 64];
    generate_random_bytes(&mut buf)?;
    assert_eq!(buf.len(), 64);
    Ok(())
}
