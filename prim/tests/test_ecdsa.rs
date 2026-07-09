// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair};

use aws_mpl_primitives::{
    DigestContext, EcdsaSignatureAlgorithm, Error, ecdsa_sign, ecdsa_sign_digest, ecdsa_verify,
    ecdsa_verify_context,
};

#[test]
fn test_ecdsa() -> Result<(), Error> {
    let alg = EcdsaSignatureAlgorithm::EcdsaP256;
    let pair =
        EcdsaKeyPair::generate(&aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    let public_key: Vec<u8> = pair.public_key().as_ref().into();
    let private_key: Vec<u8> = pair.private_key().as_der().unwrap().as_ref().into();

    let data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let sign1 = ecdsa_sign(alg, &private_key, &data)?;

    let mut context = DigestContext::new_from_ecdsa(alg)?;
    context.update(&data);
    let sign2: Vec<u8> = ecdsa_sign_digest(alg, &private_key, context)?;

    assert!(ecdsa_verify(alg, &public_key, &data, &sign1)?);
    assert!(ecdsa_verify(alg, &public_key, &data, &sign2)?);

    let mut context = DigestContext::new_from_ecdsa(alg)?;
    context.update(&data);
    assert!(ecdsa_verify_context(alg, &public_key, context, &sign1)?);
    let mut context = DigestContext::new_from_ecdsa(alg)?;
    context.update(&data);
    assert!(ecdsa_verify_context(alg, &public_key, context, &sign2)?);

    Ok(())
}
