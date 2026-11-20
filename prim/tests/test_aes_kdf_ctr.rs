// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_mpl_primitives::aes_kdf_ctr_stream;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// NIST SP 800-38A F.5.5 (CTR-AES256.Encrypt): the keystream is plaintext XOR ciphertext.
#[test]
fn matches_nist_ctr_aes256_keystream() {
    let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
    let ciphertext = hex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5");
    let expected: Vec<u8> = plaintext
        .iter()
        .zip(&ciphertext)
        .map(|(p, c)| p ^ c)
        .collect();

    let stream = aes_kdf_ctr_stream(&counter, &key, 32).unwrap();
    assert_eq!(stream, expected);
    // A shorter stream is a prefix of the longer one.
    assert_eq!(
        aes_kdf_ctr_stream(&counter, &key, 44).unwrap()[..32],
        expected[..]
    );
}

#[test]
fn rejects_wrong_sizes() {
    assert!(aes_kdf_ctr_stream(&[0u8; 12], &[0u8; 32], 44).is_err());
    assert!(aes_kdf_ctr_stream(&[0u8; 16], &[0u8; 16], 44).is_err());
}
