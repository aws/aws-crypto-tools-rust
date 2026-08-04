// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_mpl_primitives::{Error, generate_random_bytes};

#[test]
fn test_generate_random_bytes_larger_buffer() -> Result<(), Error> {
    // 64 bytes because callers split a single request into two halves — e.g.
    // the first 32 bytes for one key and the second 32 for another.
    let mut first = [0u8; 64];
    let mut second = [0u8; 64];
    generate_random_bytes(&mut first)?;
    generate_random_bytes(&mut second)?;

    // Not a randomness test — that would need a statistical one. This
    // catches a stubbed or non-advancing RNG: two independent 64-byte fills
    // collide with probability 2^-512.
    assert_ne!(first, second);
    Ok(())
}
