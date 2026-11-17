// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Characterization tests for the prim wrapper contracts that VR-013 and
//! VR-014 prove in place (pipeline target VR-2026-C03).
//!
//! They pin the observable behavior the verified cores must preserve: the
//! exact-length guards of `digest`, `hmac` and `DigestContext::finish`, the
//! error messages, and the `aes_encrypt` / `aes_decrypt` buffer effects
//! described in BUG-07.

use aws_mpl_primitives::{
    AesGcm, DigestAlg, DigestContext, aes_decrypt, aes_encrypt, digest, hmac, kbkdf_ctr_hmac,
};

const ALGS: [DigestAlg; 3] = [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512];
const KEY_256: [u8; 32] = [1; 32];
const IV: [u8; 12] = [2; 12];
const AAD: [u8; 4] = [3; 4];
const PLAINTEXT: [u8; 4] = [97, 115, 100, 102]; // "asdf"
const HEADER: &[u8] = b"HDR:";

fn assert_err_contains<T: std::fmt::Debug>(r: Result<T, aws_mpl_primitives::Error>, want: &str) {
    let err = r.unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains(want), "{msg:?} does not contain {want:?}");
}

#[test]
fn digest_exact_length_only() {
    for alg in ALGS {
        let n = alg.output_len();
        for bad in [n - 1, n + 1] {
            let mut out = vec![0u8; bad];
            assert_err_contains(
                digest(alg, b"abc", &mut out),
                &format!("output buffer of {bad} bytes does not match the {n} byte {alg:?} output"),
            );
            assert_eq!(out, vec![0u8; bad], "out untouched on Err");
        }
        let mut out = vec![0u8; n];
        digest(alg, b"abc", &mut out).unwrap();
    }
}

#[test]
fn hmac_exact_length_only() {
    for alg in ALGS {
        let n = alg.output_len();
        for bad in [n - 1, n + 1] {
            let mut out = vec![0u8; bad];
            assert_err_contains(
                hmac(alg, b"key", b"msg", &mut out),
                &format!("output buffer of {bad} bytes does not match the {n} byte {alg:?} output"),
            );
            assert_eq!(out, vec![0u8; bad], "out untouched on Err");
        }
        let mut out = vec![0u8; n];
        hmac(alg, b"key", b"msg", &mut out).unwrap();
    }
}

#[test]
fn digest_context_finish_exact_length_only() {
    for alg in ALGS {
        let n = alg.output_len();
        for bad in [n - 1, n + 1] {
            let mut ctx = DigestContext::new(alg).unwrap();
            ctx.update(b"abc");
            assert_eq!(ctx.output_len(), n);
            let mut out = vec![0u8; bad];
            assert_err_contains(
                ctx.finish(&mut out),
                &format!("output buffer of {bad} bytes does not match the {n} byte digest"),
            );
            assert_eq!(out, vec![0u8; bad], "out untouched on Err");
        }
        let mut ctx = DigestContext::new(alg).unwrap();
        ctx.update(b"abc");
        let mut out = vec![0u8; n];
        ctx.finish(&mut out).unwrap();
        let mut want = vec![0u8; n];
        digest(alg, b"abc", &mut want).unwrap();
        assert_eq!(out, want);
    }
}

/// Pins current BUG-07(a) behavior: on a key or nonce error the plaintext
/// stays appended to the caller's buffer. Update if the owners fix BUG-07.
#[test]
fn aes_encrypt_err_leaves_plaintext_appended() {
    let mut want = HEADER.to_vec();
    want.extend_from_slice(&PLAINTEXT);

    let mut buf = HEADER.to_vec();
    assert_err_contains(
        aes_encrypt(
            AesGcm::Aes256Gcm,
            &IV,
            &[1u8; 15],
            &PLAINTEXT,
            &AAD,
            &mut buf,
        ),
        "invalid AES-GCM key",
    );
    assert_eq!(buf, want);

    let mut buf = HEADER.to_vec();
    assert_err_contains(
        aes_encrypt(
            AesGcm::Aes256Gcm,
            &[2u8; 11],
            &KEY_256,
            &PLAINTEXT,
            &AAD,
            &mut buf,
        ),
        "invalid AES-GCM nonce",
    );
    assert_eq!(buf, want);
}

#[test]
fn aes_encrypt_ok_appends_ciphertext_then_tag() {
    let mut buf = HEADER.to_vec();
    aes_encrypt(AesGcm::Aes256Gcm, &IV, &KEY_256, &PLAINTEXT, &AAD, &mut buf).unwrap();
    assert_eq!(buf.len(), HEADER.len() + PLAINTEXT.len() + 16);
    assert_eq!(&buf[..HEADER.len()], HEADER);

    let mut fresh = Vec::new();
    aes_encrypt(
        AesGcm::Aes256Gcm,
        &IV,
        &KEY_256,
        &PLAINTEXT,
        &AAD,
        &mut fresh,
    )
    .unwrap();
    assert_eq!(&buf[HEADER.len()..], &fresh[..]);
}

/// BUG-07(b): buffers longer than the ciphertext pass the prim guard and are
/// rejected by aws-lc-rs, which reports it as a tag mismatch.
#[test]
fn aes_decrypt_buffer_length_cases() {
    let mut ct_tag = Vec::new();
    aes_encrypt(
        AesGcm::Aes256Gcm,
        &IV,
        &KEY_256,
        &PLAINTEXT,
        &AAD,
        &mut ct_tag,
    )
    .unwrap();
    let (ct, tag) = ct_tag.split_at(PLAINTEXT.len());

    for extra in [1usize, 16] {
        let mut pt = vec![0u8; ct.len() + extra];
        assert_err_contains(
            aes_decrypt(AesGcm::Aes256Gcm, &KEY_256, ct, tag, &IV, &AAD, &mut pt),
            "authentication tag did not match",
        );
    }

    let mut pt = vec![0u8; ct.len() - 1];
    assert_err_contains(
        aes_decrypt(AesGcm::Aes256Gcm, &KEY_256, ct, tag, &IV, &AAD, &mut pt),
        &format!(
            "plaintext buffer of {} bytes is shorter than the {} byte ciphertext",
            ct.len() - 1,
            ct.len()
        ),
    );

    let mut pt = vec![0u8; ct.len()];
    aes_decrypt(AesGcm::Aes256Gcm, &KEY_256, ct, tag, &IV, &AAD, &mut pt).unwrap();
    assert_eq!(pt, PLAINTEXT);
}

#[test]
fn kbkdf_empty_okm_is_derivation_failure() {
    for alg in ALGS {
        let mut okm: [u8; 0] = [];
        assert_err_contains(
            kbkdf_ctr_hmac(alg, &[7u8; 32], b"info", &mut okm),
            "KBKDF-CTR-HMAC derivation failed",
        );
    }
}
