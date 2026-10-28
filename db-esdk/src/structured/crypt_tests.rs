// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::types::AlgorithmSuiteId as MplAlgorithmSuiteId;

use super::*;
use crate::error::Kind;
use crate::structured::util::{NUMBER, STRING};
use crate::types::AlgorithmSuiteId;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Crypt.dfy FieldKeyTestVector: (root key, field offset, 32-byte key || 12-byte nonce).
const FIELD_KEY_VECTORS: &[(&str, u32, &str)] = &[
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
        "4d17ac4f80763c4f5c1523ca2322b89918d5ad8b728aea9e052b177e41570f7be7ff404ace5e9b22aa1e8968",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        1,
        "18fcefe222b4d2a414c908f35c2e09153068198ad2b33fd0921596e5b02e7c1a48b2c6e720dc75167db54f46",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        2,
        "ec387607afb264f56ba44abd037c469fdfff9d5861a976a4261083e6dfa48d883b6c85c440003ed094a1eee7",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        3,
        "7124e0a5e057d168d17c76be6d61efff694048b301786d7952f463b509d2a542fe5cdf045f096f99ec3dca5b",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        4,
        "56e053ebe6f7a937b9fec2847e82b3a9c5daa20d49d9e6eb7951595e68a0bb826277d52685464da6cf8271d8",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        5,
        "8aacffc78d68c3350f510883394edfb1caaf21ddf363485dc4f6bcb4aef7a4dfaf8a0a0b9f647accc39db0f6",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        6,
        "7fb8a9f5b5e8c838523944fe7da143ef0dab663df66ef22c0cec7653b541115dfda3a55fae43c4a27459909d",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        7,
        "edfa5a6c99e14d131753163c2b890b135b8a6d4e310884d7d365a0670ef46686ef44b77c1c5a945797f17dd5",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        0,
        "c6a8b4e10a23bac8e13ae2d4edc0311509a5ce01b4d2357f8b1e667eeef77066cb9a2c4481d66ad1ede3d50f",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        1,
        "d54d4fe8e8295a523644dd49698f637a30f0c1e868c47a2a38e0e756ca0fcdee8e5aa355796debbb8fcb898b",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        2,
        "254489ab5be234d848f4fb21cba3ea27962c50363c9924054fffe34bd4f87d641fdb793224ccbf3e6ca9fa60",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        3,
        "b600f98e1c868209de7d563362ab8131bc8d0a5b58bf2590a8309889a94ee505515a02692824f7e32a31142f",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        4,
        "0af797f151dca40bd6db2cf69d5f3fdb98f34a3efe5f4af778cb3f8b942b507bd6eca848dd8e4b62e9d2db42",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        5,
        "9207c0c3dacd1b015d92689b78ba0bd49a1547f670d20097cc94cd35e569af02597a187f2ff7402f92149a19",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        6,
        "ca14fb5a292ec5f76669a04811532d3ed0d09421bdce95d629b0d3259b35888cf17e28e1ed4c1c136b4e5866",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        7,
        "da1188242ab66975027f11e49ecca9e7e23aaf1215855c263460a24f7d000cab89600be8ad6781d226190bed",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        0,
        "0c7e451b952b793d95c66bef5df16a7e42cd70bca33d5f9e01651751b4dbff0e4f9524335caef55a68d55f2a",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        1,
        "de3cdd84c99d3f6c011469433b2c24994e1836f2c923ee1fab47c3bedca95c1dd0fc547887cf9948efe1ffb6",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        2,
        "a088b21f062333d7a588da26ae30e11239949abd30b8a971621f2d664e5f2406212a4d51a04e63d314de54c3",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        3,
        "dc3448317b6d74b6dd662a9270fe808ab1dd7faf0f009e6e5e9f3aaac969d947d81e5bbc933819b8d6f2d76e",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        4,
        "87c5acfda18b650896588cd1f67e8f69cab31aed59df54b49c0748f4646e4789153bccb33b96ed760e9dfd44",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        5,
        "392d11b7e0884a5e42ef50f408cd79cbb0b96f792d67025527fd0ff0cfacad33c4dcead6021b34e4d0d1a3a2",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        6,
        "6092ee61588d3b1013b82c05ea7a894cdb9649d2fa8695f731c946aa75c47c4db0996bff661f8a796533c348",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        7,
        "d0270cfa0da88692a057c39b39644970786367da64008206e51a799af19f65db5b1531d01c52216431c451e5",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        0,
        "772cb513bc2bebfed36dfa3c22dec2c5cb09466dd1b5275cd1f2713339b32e9c7993c521808a0bd6faa4cb4f",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        1,
        "e93a3a5dd1633af15027c2ec078fc536ddf295110dfa5053592842a8c1f1010ad15c2462d0371ff27d98e99b",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        2,
        "66f92041859c2000b8ff492629ae1ef875666c360fcfadeefe11e9f9f257887c4d1289c43ac1a442ec14a426",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        3,
        "02dd4a565fcc6d308ce3f9a2818c8426c3476b2fb6ea66f1c4688c313b061177a6c69a2663122e4c5f3895dd",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        4,
        "010a7cd17c89ac7668ba45332bdd956e388113f1ee9d01f387c5574ffdd86ade24b0430300d4009b0802335f",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        5,
        "aecfa53a5f05f6b3b5185584573d527790c8d3504d5a0deb2af3d58c35164d58f232704851f7c9f357dcfb5b",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        6,
        "3482b90bb7ddbed3d2b1f270ea648043539d7d6797861ec12c3d0797a07d31ecf3b160aab844008934823436",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        7,
        "5c82960fb8370644b7fb7fd41f090e0098f52130379381ed4c21379fa65884e6e1367326c067856388b57589",
    ),
    (
        "59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc",
        0,
        "d7d8c2e84dd5f56663b98501bf702a04f32451e62a1c30177d89bbf51beadd1090718c72ba120f7f20cf1e97",
    ),
    (
        "59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc",
        1,
        "fadae5fa4f62e4cbec50d3b4572166fbccc114cb800ed066a4632e966fa18f1189a1fb7cd20ad1c93f29531d",
    ),
    (
        "59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc",
        2,
        "14db82fab8f6f8e49a8061cf1689172b5bd37508560a8e9d42c21c507657a64a47545b155304c73198847429",
    ),
    (
        "59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc",
        3,
        "4d83002cf87da3f9670999c707ee4ed8483c297390eb5abb989ea8cb514f4bf27e43bf1f92e6b76c3045080e",
    ),
    (
        "59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc",
        4,
        "06fbc86f1e9716f218823710ef51b4558476a1cff4e5d706baac5ad14de544eb7e94197677f99cb46e12d63c",
    ),
    (
        "59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc",
        5,
        "12ede6750d1f02e0aca4b159f4b7aac9fca85355ac7f21e39f44b37e4157dea6f76b9fd44aa7fe540256522b",
    ),
    (
        "59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc",
        6,
        "7bfd555c3be12c57402b5db97cbfd897aefec952c3ba878642e5b22005cf1074ce854d210ac3c48c5fd0fbe2",
    ),
    (
        "59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc",
        7,
        "20847d5de204cb578f3012940fa9876ddb3386ae9719cf9adcbdd611385011b2e7d5375fb6d3fd5ea77ba461",
    ),
];

// Crypt.dfy TestFieldKey.
#[test]
fn field_key_matches_reference_vectors() {
    assert_eq!(FIELD_KEY_VECTORS.len(), 40);
    for (input, offset, output) in FIELD_KEY_VECTORS {
        let key = unhex(input);
        assert_eq!(key.len(), KEY_SIZE);
        let got = field_key(&key, *offset).unwrap();
        assert_eq!(got.as_slice(), unhex(output).as_slice(), "offset {offset}");
    }
}

#[test]
fn field_key_rejects_offset_that_overflows() {
    let key = [0u8; KEY_SIZE];
    let err = field_key(&key, ONE_THIRD_MAX_INT).unwrap_err();
    assert_eq!(err.kind(), Kind::Validation);
    assert_eq!(field_key(&key, ONE_THIRD_MAX_INT - 1).unwrap().len(), 44);
}

#[test]
fn field_keys_and_nonces_never_repeat_across_offsets() {
    // Offsets are derived 3 apart, so adjacent fields' 44-byte streams never overlap.
    let root = [7u8; KEY_SIZE];
    let mut keys = std::collections::HashSet::new();
    let mut nonces = std::collections::HashSet::new();
    for offset in 0..2000 {
        let fk = field_key(&root, offset).unwrap();
        let (key, nonce) = fk.split_at(KEY_SIZE);
        assert_eq!(nonce.len(), NONCE_SIZE);
        assert!(keys.insert(key.to_vec()), "key repeats at offset {offset}");
        assert!(
            nonces.insert(nonce.to_vec()),
            "nonce repeats at offset {offset}"
        );
    }
}

#[test]
fn field_key_nonce_layout() {
    let mut expected = b"AwsDbeField".to_vec();
    expected.push(44);
    expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(field_key_nonce(0x0102_0304), expected);
}

fn suite() -> DbeSuite {
    DbeSuite::new(MplAlgorithmSuiteId::Dbe(
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384,
    ))
    .unwrap()
}

fn item(name: &str, type_id: [u8; 2], value: &[u8], action: CryptoAction) -> CanonItem {
    CanonItem {
        canon: name.as_bytes().to_vec(),
        key: vec![name.to_owned()],
        data: Terminal::new(type_id, value.to_vec()),
        action,
    }
}

const DATA_KEY: [u8; 32] = [7u8; 32];
const MSG_ID: [u8; MSGID_LEN] = [9u8; MSGID_LEN];

fn sample() -> Vec<CanonItem> {
    vec![
        item("a", STRING, b"secret one", CryptoAction::EncryptAndSign),
        item("b", NUMBER, b"42", CryptoAction::SignOnly),
        item("c", STRING, b"secret two", CryptoAction::EncryptAndSign),
        item("d", STRING, b"untouched", CryptoAction::DoNothing),
    ]
}

#[test]
fn crypt_round_trip_encrypts_only_encrypt_and_sign() {
    let original = sample();
    let encrypted = crypt(Mode::Encrypt, suite(), &DATA_KEY, &MSG_ID, original.clone()).unwrap();

    for (orig, enc) in original.iter().zip(&encrypted) {
        assert_eq!(enc.canon, orig.canon);
        if orig.action == CryptoAction::EncryptAndSign {
            // The encrypted value is the plaintext type id, the ciphertext, then the tag.
            assert_eq!(enc.data.type_id, BYTES_TYPE_ID);
            assert_eq!(&enc.data.value[..2], &orig.data.type_id);
            assert_eq!(
                enc.data.value.len(),
                2 + orig.data.value.len() + AUTH_TAG_SIZE
            );
            assert_ne!(
                &enc.data.value[2..2 + orig.data.value.len()],
                orig.data.value.as_slice()
            );
        } else {
            assert_eq!(enc.data, orig.data);
        }
    }

    let decrypted = crypt(Mode::Decrypt, suite(), &DATA_KEY, &MSG_ID, encrypted).unwrap();
    for (orig, dec) in original.iter().zip(&decrypted) {
        assert_eq!(dec.data, orig.data);
    }
}

#[test]
fn crypt_depends_on_data_key_and_message_id() {
    let base = crypt(Mode::Encrypt, suite(), &DATA_KEY, &MSG_ID, sample()).unwrap();
    let other_key = crypt(Mode::Encrypt, suite(), &[8u8; 32], &MSG_ID, sample()).unwrap();
    let other_id = crypt(
        Mode::Encrypt,
        suite(),
        &DATA_KEY,
        &[1u8; MSGID_LEN],
        sample(),
    )
    .unwrap();
    assert_ne!(base[0].data.value, other_key[0].data.value);
    assert_ne!(base[0].data.value, other_id[0].data.value);
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    let mut enc = crypt(Mode::Encrypt, suite(), &DATA_KEY, &MSG_ID, sample()).unwrap();
    enc[0].data.value[3] ^= 1;
    let err = crypt(Mode::Decrypt, suite(), &DATA_KEY, &MSG_ID, enc).unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
}

// The canonical path is the AAD, so moving a ciphertext to another field fails.
#[test]
fn decrypt_rejects_changed_path() {
    let mut enc = crypt(Mode::Encrypt, suite(), &DATA_KEY, &MSG_ID, sample()).unwrap();
    enc[0].canon = b"z".to_vec();
    let err = crypt(Mode::Decrypt, suite(), &DATA_KEY, &MSG_ID, enc).unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
}

#[test]
fn decrypt_rejects_wrong_key() {
    let enc = crypt(Mode::Encrypt, suite(), &DATA_KEY, &MSG_ID, sample()).unwrap();
    let err = crypt(Mode::Decrypt, suite(), &[8u8; 32], &MSG_ID, enc).unwrap_err();
    assert_eq!(err.kind(), Kind::Cryptographic);
}

#[test]
fn decrypt_rejects_value_shorter_than_type_id_and_tag() {
    let short = vec![item(
        "a",
        BYTES_TYPE_ID,
        &[0u8; AUTH_TAG_SIZE + 1],
        CryptoAction::EncryptAndSign,
    )];
    let err = crypt(Mode::Decrypt, suite(), &DATA_KEY, &MSG_ID, short).unwrap_err();
    assert_eq!(err.kind(), Kind::Serialization);
    assert_eq!(err.message(), "cipherTxt too short.");
}

// An empty plaintext encrypts to just the type id and the tag, and decrypts back.
#[test]
fn crypt_round_trips_empty_value() {
    let data = vec![item("a", STRING, b"", CryptoAction::EncryptAndSign)];
    let enc = crypt(Mode::Encrypt, suite(), &DATA_KEY, &MSG_ID, data).unwrap();
    assert_eq!(enc[0].data.value.len(), 2 + AUTH_TAG_SIZE);
    let dec = crypt(Mode::Decrypt, suite(), &DATA_KEY, &MSG_ID, enc).unwrap();
    assert_eq!(dec[0].data, Terminal::new(STRING, Vec::new()));
}

// HKDF-SHA-512 (no salt) of the data key, info "AWS_DBE_COMMIT_KEY" || message id,
// computed independently with Python's hmac module.
#[test]
fn commit_key_known_answer() {
    let ck = commit_key(suite(), &DATA_KEY, &MSG_ID).unwrap();
    assert_eq!(
        ck.as_slice(),
        unhex("e1f9dd71239213dc41d6253307bca4f5ff62e06df2866480e87b01415fc7b01b").as_slice()
    );
}

// The field root key is HKDF-SHA-512 (no salt) of the data key, info "AWS_DBE_DERIVE_KEY" ||
// message id (computed independently with Python's hmac module); the first encrypted field
// opens under field_key(root, 0) with its canonical path as AAD.
#[test]
fn crypt_encrypts_first_field_under_root_key_offset_zero() {
    let root = unhex("2c8aa8ac569062534c6cc5bfbbe5ed90967d7311a3f925169433151865270700");
    let enc = crypt(Mode::Encrypt, suite(), &DATA_KEY, &MSG_ID, sample()).unwrap();
    let value = &enc[0].data.value;
    let fk = field_key(&root, 0).unwrap();
    let (key, nonce) = fk.split_at(KEY_SIZE);
    let (ct, tag) = value[2..].split_at(value.len() - 2 - AUTH_TAG_SIZE);
    let mut plain = vec![0u8; ct.len()];
    aes_decrypt(AesGcm::Aes256Gcm, key, ct, tag, nonce, b"a", &mut plain).unwrap();
    assert_eq!(plain, b"secret one");

    // "c" is the second encrypted field, so it uses offset 1 ("b" is not encrypted).
    let value = &enc[2].data.value;
    let fk = field_key(&root, 1).unwrap();
    let (key, nonce) = fk.split_at(KEY_SIZE);
    let (ct, tag) = value[2..].split_at(value.len() - 2 - AUTH_TAG_SIZE);
    let mut plain = vec![0u8; ct.len()];
    aes_decrypt(AesGcm::Aes256Gcm, key, ct, tag, nonce, b"c", &mut plain).unwrap();
    assert_eq!(plain, b"secret two");
}
