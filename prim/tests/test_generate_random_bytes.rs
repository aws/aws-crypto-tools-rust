// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_mpl_primitives::{Error, generate_random_bytes};

#[test]
fn test_generate_random_bytes_larger_buffer() -> Result<(), Error> {
    // One 64-byte request rather than two 32-byte ones, because that is how
    // callers use this: a caller needing two 32-byte keys asks for 64 bytes
    // once and splits the result. Requesting the larger size here exercises
    // the same path they take.
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
