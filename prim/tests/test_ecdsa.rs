// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ECDSA tests ported from Dafny `TestSignature.dfy`. Covers P-256 and
//! P-384 sign/verify round-trips (both the raw-message and streaming-digest
//! entry points), plus the tampered-message negative case that Dafny
//! asserts. The Dafny YCompression* tests are intentionally not ported —
//! prim exposes verification keys in SEC1-uncompressed form, not the
//! Y-compressed format that Dafny's `ExternKeyGen` yields.
//!
//! Note: prim's `ecdsa_sign` currently accepts a SEC1-DER-encoded private
//! key while `ecdsa_generate_keypair` returns the raw private scalar in
//! big-endian form (matching what `aws-crypto-mpl` needs to store in a
//! `SigningKey`). Because the two forms don't compose, the sign/verify
//! tests use aws-lc-rs directly to produce a DER-encoded keypair. A future
//! refactor should unify prim's private-key format.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair,
    EcdsaSigningAlgorithm, KeyPair,
};

use aws_mpl_primitives::{
    DigestAlg, DigestContext, EcdsaSignatureAlgorithm, Error, digest, ecdsa_generate_keypair,
    ecdsa_sign, ecdsa_sign_digest, ecdsa_verify, ecdsa_verify_context,
};

/// Helper: generate a keypair for the given algorithm and return
/// `(public_key_uncompressed_sec1, private_key_sec1_der)`. Used to
/// exercise `ecdsa_sign`/`ecdsa_verify` (which currently consume DER).
fn keypair_der(signing_alg: &'static EcdsaSigningAlgorithm) -> (Vec<u8>, Vec<u8>) {
    let pair = EcdsaKeyPair::generate(signing_alg).unwrap();
    let public_key: Vec<u8> = pair.public_key().as_ref().into();
    let private_key: Vec<u8> = pair.private_key().as_der().unwrap().as_ref().into();
    (public_key, private_key)
}

fn verify_message_round_trip(
    alg: EcdsaSignatureAlgorithm,
    signing_alg: &'static EcdsaSigningAlgorithm,
) -> Result<(), Error> {
    let (public_key, private_key) = keypair_der(signing_alg);
    let message = b"Hello, World!";

    // Raw-message sign + verify (positive).
    let sig_raw = ecdsa_sign(alg, &private_key, message)?;
    assert!(ecdsa_verify(alg, &public_key, message, &sig_raw)?);

    // Streaming-digest sign + verify (positive), same algorithm.
    let mut ctx_sign = DigestContext::new_from_ecdsa(alg)?;
    ctx_sign.update(message);
    let sig_digest = ecdsa_sign_digest(alg, &private_key, ctx_sign)?;
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
    verify_message_round_trip(
        EcdsaSignatureAlgorithm::EcdsaP256,
        &ECDSA_P256_SHA256_ASN1_SIGNING,
    )
}

#[test]
fn test_ecdsa_p384_round_trip_and_tamper() -> Result<(), Error> {
    verify_message_round_trip(
        EcdsaSignatureAlgorithm::EcdsaP384,
        &ECDSA_P384_SHA384_ASN1_SIGNING,
    )
}

// Shape assertions for `ecdsa_generate_keypair`. Verifies the byte lengths
// and SEC1 tag that consumers rely on.

#[test]
fn test_ecdsa_generate_keypair_p256_shape() -> Result<(), Error> {
    let (private_key, public_key) = ecdsa_generate_keypair(EcdsaSignatureAlgorithm::EcdsaP256)?;
    // Private scalar: 32 bytes for P-256.
    assert_eq!(private_key.len(), 32);
    // Public point (uncompressed SEC1): 1 tag byte + 2 * 32 = 65 bytes.
    assert_eq!(public_key.len(), 65);
    assert_eq!(public_key[0], 0x04);
    Ok(())
}

#[test]
fn test_ecdsa_generate_keypair_p384_shape() -> Result<(), Error> {
    let (private_key, public_key) = ecdsa_generate_keypair(EcdsaSignatureAlgorithm::EcdsaP384)?;
    // Private scalar: 48 bytes for P-384.
    assert_eq!(private_key.len(), 48);
    // Public point (uncompressed SEC1): 1 tag byte + 2 * 48 = 97 bytes.
    assert_eq!(public_key.len(), 97);
    assert_eq!(public_key[0], 0x04);
    Ok(())
}

// Signature-length invariants. `ecdsa_sign` loops until the DER-encoded
// signature has a specific length (71 for P-256, 103 for P-384).

#[test]
fn test_ecdsa_p256_signature_length_is_71() -> Result<(), Error> {
    let (_, private_key) = keypair_der(&ECDSA_P256_SHA256_ASN1_SIGNING);
    let sig = ecdsa_sign(EcdsaSignatureAlgorithm::EcdsaP256, &private_key, b"m")?;
    assert_eq!(sig.len(), 71);
    Ok(())
}

#[test]
fn test_ecdsa_p384_signature_length_is_103() -> Result<(), Error> {
    let (_, private_key) = keypair_der(&ECDSA_P384_SHA384_ASN1_SIGNING);
    let sig = ecdsa_sign(EcdsaSignatureAlgorithm::EcdsaP384, &private_key, b"m")?;
    assert_eq!(sig.len(), 103);
    Ok(())
}

// Error paths for sign/verify with malformed inputs — required for 100%
// coverage of the `serr(format!(...))` branches.

#[test]
fn test_ecdsa_sign_with_bad_private_key() {
    let err = ecdsa_sign(EcdsaSignatureAlgorithm::EcdsaP256, &[0u8; 8], b"m").unwrap_err();
    assert!(!err.message.is_empty());
}

#[test]
fn test_ecdsa_sign_digest_with_bad_private_key() -> Result<(), Error> {
    let mut ctx = DigestContext::new_from_ecdsa(EcdsaSignatureAlgorithm::EcdsaP256)?;
    ctx.update(b"m");
    let err = ecdsa_sign_digest(EcdsaSignatureAlgorithm::EcdsaP256, &[0u8; 8], ctx).unwrap_err();
    assert!(!err.message.is_empty());
    Ok(())
}

// DigestContext type surface.

#[test]
fn test_digest_context_new_and_finish() -> Result<(), Error> {
    let mut ctx = DigestContext::new(DigestAlg::Sha256)?;
    ctx.update(b"asdf");
    let out = ctx.finish();
    assert_eq!(out, digest(DigestAlg::Sha256, b"asdf"));
    Ok(())
}

#[test]
fn test_digest_context_new_for_all_algs() -> Result<(), Error> {
    for alg in [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512] {
        let mut ctx = DigestContext::new(alg)?;
        ctx.update(b"asdf");
        let out = ctx.finish();
        assert_eq!(out, digest(alg, b"asdf"));
    }
    Ok(())
}

#[test]
fn test_digest_context_new_from_ecdsa_p256_matches_sha256() -> Result<(), Error> {
    let mut ctx = DigestContext::new_from_ecdsa(EcdsaSignatureAlgorithm::EcdsaP256)?;
    ctx.update(b"asdf");
    assert_eq!(ctx.finish(), digest(DigestAlg::Sha256, b"asdf"));
    Ok(())
}

#[test]
fn test_digest_context_new_from_ecdsa_p384_matches_sha384() -> Result<(), Error> {
    let mut ctx = DigestContext::new_from_ecdsa(EcdsaSignatureAlgorithm::EcdsaP384)?;
    ctx.update(b"asdf");
    assert_eq!(ctx.finish(), digest(DigestAlg::Sha384, b"asdf"));
    Ok(())
}

#[test]
fn test_digest_context_clone_and_debug() -> Result<(), Error> {
    let mut ctx = DigestContext::new(DigestAlg::Sha256)?;
    ctx.update(b"asdf");
    let cloned = ctx.clone();
    assert_eq!(ctx.finish(), cloned.finish());

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
