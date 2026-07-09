// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_mpl_primitives::{DigestAlg, Error, hkdf};

#[test]
fn test_hkdf() -> Result<(), Error> {
    let mut okm = [0u8; 32];
    let ikm = [0u8; 32];
    hkdf(
        DigestAlg::Sha512,
        &[1u8, 2, 3, 4, 5],
        &ikm,
        &[&[1u8, 2, 3, 4, 5]],
        &mut okm,
    )?;
    Ok(())
}
