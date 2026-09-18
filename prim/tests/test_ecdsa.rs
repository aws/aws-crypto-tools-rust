// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ECDSA tests ported from Dafny [`TestSignature.dfy`]. Covers P-256 and
//! P-384 sign/verify round-trips (both the raw-message and streaming-digest
//! entry points), plus the tampered-message negative case that Dafny
//! asserts.
//!
//! [`TestSignature.dfy`]: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/test/TestSignature.dfy

use aws_mpl_primitives::{
    DigestAlg, DigestContext, EcdsaSignatureAlgorithm, Error, digest, ecdsa_generate_keypair,
    ecdsa_sign, ecdsa_sign_digest, ecdsa_verify, ecdsa_verify_context, field_size, signature_len,
};

fn verify_message_round_trip(alg: EcdsaSignatureAlgorithm) -> Result<(), Error> {
    let keys = ecdsa_generate_keypair(alg)?;
    let public_key = keys.verification_key;
    let private_key = keys.signing_key;
    let message = b"Hello, World!";

    // Raw-message sign + verify (positive).
    let mut sig_raw = vec![0u8; signature_len(alg)];
    ecdsa_sign(alg, &private_key, message, &mut sig_raw)?;
    assert!(ecdsa_verify(alg, &public_key, message, &sig_raw)?);

    // Streaming-digest sign + verify (positive), same algorithm.
    let mut ctx_sign = DigestContext::new_from_ecdsa(alg)?;
    ctx_sign.update(message);
    let mut sig_digest = vec![0u8; signature_len(alg)];
    ecdsa_sign_digest(alg, &private_key, ctx_sign, &mut sig_digest)?;
    assert!(ecdsa_verify(alg, &public_key, message, &sig_digest)?);

    // Cross-verify raw-signature through the digest-context verifier.
    let mut ctx_verify = DigestContext::new_from_ecdsa(alg)?;
    ctx_verify.update(message);
    assert!(ecdsa_verify_context(
        alg,
        &public_key,
        ctx_verify,
        &sig_raw
    )?);

    let mut ctx_verify2 = DigestContext::new_from_ecdsa(alg)?;
    ctx_verify2.update(message);
    assert!(ecdsa_verify_context(
        alg,
        &public_key,
        ctx_verify2,
        &sig_digest
    )?);

    // Tampered-message negative — Dafny's VerifyMessage asserts this returns
    // false. prim's ecdsa_verify returns Ok(false) on verification failure.
    let mut tampered = message.to_vec();
    tampered.push(1);
    assert!(!ecdsa_verify(alg, &public_key, &tampered, &sig_raw)?);

    let mut ctx_bad = DigestContext::new_from_ecdsa(alg)?;
    ctx_bad.update(&tampered);
    assert!(!ecdsa_verify_context(alg, &public_key, ctx_bad, &sig_raw)?);

    Ok(())
}

#[test]
fn test_ecdsa_p256_round_trip_and_tamper() -> Result<(), Error> {
    verify_message_round_trip(EcdsaSignatureAlgorithm::EcdsaP256)
}

#[test]
fn test_ecdsa_p384_round_trip_and_tamper() -> Result<(), Error> {
    verify_message_round_trip(EcdsaSignatureAlgorithm::EcdsaP384)
}

// Shape assertions for `ecdsa_generate_keypair`. The verification key is an
// X9.62 compressed point of exactly `field_size` bytes, and the signing key
// is DER, so it round-trips through `ecdsa_sign`.

fn assert_keypair_shape(alg: EcdsaSignatureAlgorithm, expected_field: usize) -> Result<(), Error> {
    let keys = ecdsa_generate_keypair(alg)?;
    assert_eq!(field_size(alg), expected_field);
    assert_eq!(keys.verification_key.len(), expected_field);
    // X9.62 compressed points carry a 0x02 or 0x03 parity tag.
    assert!(matches!(keys.verification_key[0], 0x02 | 0x03));
    // The signing key is usable by prim's own signer without conversion.
    let mut sig = vec![0u8; signature_len(alg)];
    ecdsa_sign(alg, &keys.signing_key, b"m", &mut sig)?;
    assert!(ecdsa_verify(alg, &keys.verification_key, b"m", &sig)?);
    Ok(())
}

#[test]
fn test_ecdsa_generate_keypair_p256_shape() -> Result<(), Error> {
    assert_keypair_shape(EcdsaSignatureAlgorithm::EcdsaP256, 33)
}

#[test]
fn test_ecdsa_generate_keypair_p384_shape() -> Result<(), Error> {
    assert_keypair_shape(EcdsaSignatureAlgorithm::EcdsaP384, 49)
}

/// `SignatureKeyPair`'s `Debug` must not leak the signing key.
#[test]
fn test_signature_key_pair_debug_redacts_signing_key() -> Result<(), Error> {
    let keys = ecdsa_generate_keypair(EcdsaSignatureAlgorithm::EcdsaP256)?;
    let rendered = format!("{keys:?}");
    assert!(rendered.contains("REDACTED"));
    // The signing key's own byte sequence must not appear in the output.
    let leaked = format!("{:?}", keys.signing_key);
    assert!(!rendered.contains(&leaked));
    Ok(())
}

// Signature-length invariants. `ecdsa_sign` loops until the DER-encoded
// signature has exactly `signature_len` bytes, so signing successfully into
// a buffer of that size is itself the proof that the emitted DER is that
// length — a wrong `signature_len` would exhaust the retries and error.

#[test]
fn test_ecdsa_p256_signature_length_is_71() -> Result<(), Error> {
    let alg = EcdsaSignatureAlgorithm::EcdsaP256;
    assert_eq!(signature_len(alg), 71);
    let keys = ecdsa_generate_keypair(alg)?;
    let mut sig = [0u8; 71];
    ecdsa_sign(alg, &keys.signing_key, b"m", &mut sig)?;
    assert!(ecdsa_verify(alg, &keys.verification_key, b"m", &sig)?);
    Ok(())
}

#[test]
fn test_ecdsa_p384_signature_length_is_103() -> Result<(), Error> {
    let alg = EcdsaSignatureAlgorithm::EcdsaP384;
    assert_eq!(signature_len(alg), 103);
    let keys = ecdsa_generate_keypair(alg)?;
    let mut sig = [0u8; 103];
    ecdsa_sign(alg, &keys.signing_key, b"m", &mut sig)?;
    assert!(ecdsa_verify(alg, &keys.verification_key, b"m", &sig)?);
    Ok(())
}

#[test]
fn test_ecdsa_sign_rejects_wrong_length_buffer() -> Result<(), Error> {
    let alg = EcdsaSignatureAlgorithm::EcdsaP256;
    let keys = ecdsa_generate_keypair(alg)?;
    // 103 is the P-384 length, so this also covers passing the right buffer
    // for the wrong curve.
    let mut sig = [0u8; 103];
    let err = ecdsa_sign(alg, &keys.signing_key, b"m", &mut sig).unwrap_err();
    assert!(err.message.contains("signature buffer length of 103"));
    Ok(())
}

#[test]
fn test_ecdsa_sign_digest_rejects_wrong_length_buffer() -> Result<(), Error> {
    let alg = EcdsaSignatureAlgorithm::EcdsaP256;
    let keys = ecdsa_generate_keypair(alg)?;
    let mut ctx = DigestContext::new_from_ecdsa(alg)?;
    ctx.update(b"m");
    let mut sig = [0u8; 70];
    let err = ecdsa_sign_digest(alg, &keys.signing_key, ctx, &mut sig).unwrap_err();
    assert!(err.message.contains("signature buffer length of 70"));
    Ok(())
}

// Error paths for sign/verify with malformed inputs — required for 100%
// coverage of the `serr(format!(...))` branches.

#[test]
fn test_ecdsa_sign_with_bad_private_key() {
    let alg = EcdsaSignatureAlgorithm::EcdsaP256;
    let mut sig = vec![0u8; signature_len(alg)];
    let err = ecdsa_sign(alg, &[0u8; 8], b"m", &mut sig).unwrap_err();
    assert!(!err.message.is_empty());
}

#[test]
fn test_ecdsa_sign_digest_with_bad_private_key() -> Result<(), Error> {
    let alg = EcdsaSignatureAlgorithm::EcdsaP256;
    let mut ctx = DigestContext::new_from_ecdsa(alg)?;
    ctx.update(b"m");
    let mut sig = vec![0u8; signature_len(alg)];
    let err = ecdsa_sign_digest(alg, &[0u8; 8], ctx, &mut sig).unwrap_err();
    assert!(!err.message.is_empty());
    Ok(())
}

// DigestContext type surface.

#[test]
fn test_digest_context_new_and_finish() -> Result<(), Error> {
    let mut ctx = DigestContext::new(DigestAlg::Sha256)?;
    ctx.update(b"asdf");
    let mut out = vec![0u8; ctx.output_len()];
    ctx.finish(&mut out)?;
    let mut expected = [0u8; 32];
    digest(DigestAlg::Sha256, b"asdf", &mut expected)?;
    assert_eq!(out, expected);
    Ok(())
}

#[test]
fn test_digest_context_new_for_all_algs() -> Result<(), Error> {
    for alg in [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512] {
        let mut ctx = DigestContext::new(alg)?;
        ctx.update(b"asdf");
        assert_eq!(ctx.output_len(), alg.output_len());
        let mut out = vec![0u8; ctx.output_len()];
        ctx.finish(&mut out)?;
        let mut expected = vec![0u8; alg.output_len()];
        digest(alg, b"asdf", &mut expected)?;
        assert_eq!(out, expected);
    }
    Ok(())
}

#[test]
fn test_digest_context_new_from_ecdsa_p256_matches_sha256() -> Result<(), Error> {
    let mut ctx = DigestContext::new_from_ecdsa(EcdsaSignatureAlgorithm::EcdsaP256)?;
    ctx.update(b"asdf");
    let mut out = [0u8; 32];
    ctx.finish(&mut out)?;
    let mut expected = [0u8; 32];
    digest(DigestAlg::Sha256, b"asdf", &mut expected)?;
    assert_eq!(out, expected);
    Ok(())
}

#[test]
fn test_digest_context_new_from_ecdsa_p384_matches_sha384() -> Result<(), Error> {
    let mut ctx = DigestContext::new_from_ecdsa(EcdsaSignatureAlgorithm::EcdsaP384)?;
    ctx.update(b"asdf");
    let mut out = [0u8; 48];
    ctx.finish(&mut out)?;
    let mut expected = [0u8; 48];
    digest(DigestAlg::Sha384, b"asdf", &mut expected)?;
    assert_eq!(out, expected);
    Ok(())
}

#[test]
fn test_digest_context_clone_and_debug() -> Result<(), Error> {
    let mut ctx = DigestContext::new(DigestAlg::Sha256)?;
    ctx.update(b"asdf");
    let cloned = ctx.clone();
    let mut from_ctx = [0u8; 32];
    let mut from_clone = [0u8; 32];
    ctx.finish(&mut from_ctx)?;
    cloned.finish(&mut from_clone)?;
    assert_eq!(from_ctx, from_clone);

    let ctx2 = DigestContext::new(DigestAlg::Sha256)?;
    let debug_str = format!("{ctx2:?}");
    assert!(debug_str.contains("DigestContext"));
    Ok(())
}

#[test]
fn test_ecdsa_signature_algorithm_default_is_p384() {
    assert_eq!(
        EcdsaSignatureAlgorithm::default(),
        EcdsaSignatureAlgorithm::EcdsaP384
    );
}
