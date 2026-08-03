// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_mpl_primitives::{Error, generate_random_bytes};

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
    // 64 bytes because callers split a single request into two halves — e.g.
    // the first 32 bytes for one key and the second 32 for another.
    let mut buf = [0u8; 64];
    generate_random_bytes(&mut buf)?;
    // Only the length invariant is asserted. There is no sensible way to
    // assert "randomness" without a statistical test; if aws-lc-rs's fill
    // returns Ok, prim is fulfilling its contract.
    assert_eq!(buf.len(), 64);
    Ok(())
}
