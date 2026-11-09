// TEMPORARY reproducer for BUG-07 (T07 / C03). Delete after running.
use aws_mpl_primitives::{AesGcm, aes_decrypt, aes_encrypt};

#[test]
fn aes_encrypt_leaves_plaintext_in_buffer_on_err() {
    let msg = b"SECRET-PLAINTEXT";
    // Bad key length (5 bytes for AES-256).
    let mut out = b"HDR:".to_vec();
    let r = aes_encrypt(AesGcm::Aes256Gcm, &[0u8; 12], &[0u8; 5], msg, b"", &mut out);
    println!("REPRO BUG-07a bad key: is_err={} err={:?}", r.is_err(), r.err().map(|e| format!("{e:?}")));
    println!("REPRO BUG-07a buffer after Err = {:?}", String::from_utf8_lossy(&out));
    // Bad IV length (11 bytes).
    let mut out2 = Vec::new();
    let r2 = aes_encrypt(AesGcm::Aes256Gcm, &[0u8; 11], &[0u8; 32], msg, b"", &mut out2);
    println!("REPRO BUG-07a bad iv: is_err={} buffer after Err = {:?}", r2.is_err(), String::from_utf8_lossy(&out2));
}

#[test]
fn aes_decrypt_longer_buffer_rejected_by_callee_not_guard() {
    let key = [3u8; 32];
    let iv = [4u8; 12];
    let mut ct = Vec::new();
    aes_encrypt(AesGcm::Aes256Gcm, &iv, &key, b"0123456789abcdef", b"aad", &mut ct).unwrap();
    let (body, tag) = ct.split_at(ct.len() - 16);
    for extra in [0usize, 1, 16] {
        let mut pt = vec![0u8; body.len() + extra];
        let r = aes_decrypt(AesGcm::Aes256Gcm, &key, body, tag, &iv, b"aad", &mut pt);
        println!("REPRO BUG-07b plain_text len = ct len + {extra}: {:?}", r.map_err(|e| format!("{e:?}")));
    }
    let mut short = vec![0u8; body.len() - 1];
    let r = aes_decrypt(AesGcm::Aes256Gcm, &key, body, tag, &iv, b"aad", &mut short);
    println!("REPRO BUG-07b plain_text len = ct len - 1: {:?}", r.map_err(|e| format!("{e:?}")));
}
