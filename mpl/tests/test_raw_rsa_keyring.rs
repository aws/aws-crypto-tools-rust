// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw RSA keyring tests, ported from the Dafny `TestRawRSAKeyring.dfy`:
//! - round trips for every padding scheme, with direct and intermediate key wrapping
//! - the builder validations
//! - the decrypt failures
//!
//! The keys below are throwaway test keys that protect nothing.

use aws_crypto_mpl::keyring::RawRsaKeyring;
use aws_crypto_mpl::types::PaddingScheme;
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, DbeAlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey,
    EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId, PlaintextDataKey,
};

const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);
const DBE_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Dbe(DbeAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384);

fn ec() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("keyA", "valA");
    ec
}

fn enc_materials(suite: AlgorithmSuiteId, pdk: Option<Vec<u8>>) -> EncryptionMaterials {
    EncryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .set_encryption_context(Some(ec()))
        .set_plaintext_data_key(pdk.map(PlaintextDataKey::new))
        .build()
        .unwrap()
}

fn dec_materials(suite: AlgorithmSuiteId, pdk: Option<Vec<u8>>) -> DecryptionMaterials {
    DecryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .set_encryption_context(Some(ec()))
        .set_plaintext_data_key(pdk.map(PlaintextDataKey::new))
        .build()
        .unwrap()
}

const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCpspcXyiO3wdmj
gOnXlLHyYQFI7mkugjNlKZb+a34yKpTZbQ55OJa5R6B7RN4HRr869W6yfW30Nhw5
0UXp6wIr4BzxB7jnWVDFRPgS3q4OzjxdtWu8AAyCAZCRqhWgu1ddTvISJ4LhWBYn
jXRseUBIpSSLXfyty+ZZtuNmEBzJa3YfAAf+2UsB8CyKwRV2pHWUYWJEWEOVn+J7
3pNSt2pO1IZmkFwZ+9irIGLMPP/IIR6p4XArBilFoWvbqhsHZm0+5fwHlY7MhdY4
35y2GT+AK6kCauYkLXOVG6xnKJiRlg4qtMJCbc4otCV13d0O0ZqkiWiKWS6IZiEZ
GWP96/qZAgMBAAECggEAAtPhCCXXhk67t/vI5SjB9eST+qcqEN+B483ApPVvy5Bq
uJxWonAb2WonTqw+WU5VTjIpsIJ+CwJ0hrxAlOBLFDgnnZa0iAPG8s6Obz0z4BKj
m/CO/p44Tf4gwOQLittsS+6OcEaA6cPaBvCflHokm9OQWRNx9Sxqyyr6dGh1HA3t
/j6ka/p5UM4EZZAya9kGksPwJo2RYQDeU4ZH/3VjHC1ZAh0GvFOyQxb8VygPUfpU
1D6FZPLmQjVCRKJq+Yr5MJt9fP9NLFps0/JD8+tl40DF+xtfl8yevNJEHTk0AAiB
j0NDvmMxjxJLM9PKFpn/8Fbac7ySrhxQyz86gepxwQKBgQDgNI7SEsMxdaVl7x7P
0DrsGQ76F7yZph0zRusjOR2B0jWSk9aFVMYirgY0jHSmhHug/+glNTYLfp2SV5RW
DwNtF5tWwzWOIrpbbZ+T3Yw8+oxy1Dr1L0Ywqti9iEUEkfQKGy4lZHLvdX3+Sp9j
6gX6Uf1/YLON81U1fBAbiRoE4QKBgQDBwzYa4GGVIh7GIxFEcTxFDbnKhpv/d5Pr
ye+fjFqWzMVBDvTh4Z3B/pWuHpn2lFQMaSpY36hu5YcqoHLcUCYld3blWgZcuOz3
4Zc2whS+uJrg6VNic/hbfBsuBF1Ivjw+1pOlnS9EnNM2PF4IDzdRcV0MtyzIwF5g
0cSlVHj0uQKBgBxjSzoaGhDnHnwbnMEfUnaWbakI3F5wA/58GkWpc6z+Wr4mbeEP
7M5zTmHU7ugumiC2hkQ/yooGDBl9cVC8MejcNlTz/pHyn7n31V65jIokByh66sQk
qjR7TVoiKOr9N/MXoe4mG89qBvvtouTZuswJGZnJOrLcfot5G+kAoQTBAoGBAI/1
rdlCJL5c32hu3YFwcEsN66Ahav3fpjNlkXeFHDk2Ysf3iNHagw+DS0pWyiV+BwRB
jokBg28Bce+lzjEKC42CuP+mZ1u0ubtiDKtOf4NEPS4lrSJU741pI/iInZZSYQh+
/KvroRblPbfqGiL6yyrjgzLTVZ7B7l0Y/XWo0UVhAoGAR7I9/nxJvEtTblMbGod+
GjcaMc2iwrwQPS+Qwfu0JbSaumW8mmN2VtUyD/BiQtc/R4klxebOcFrf1rAGpl5N
iQr05Yv9toiMak0fEq2ZAo5646q/4eC1pxdUl2cWsRVpeNk9LI0pND1jBn14NA1p
w9JQo2VTZJb9EBIcYy01tgE=
-----END PRIVATE KEY-----\n";
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqbKXF8ojt8HZo4Dp15Sx
8mEBSO5pLoIzZSmW/mt+MiqU2W0OeTiWuUege0TeB0a/OvVusn1t9DYcOdFF6esC
K+Ac8Qe451lQxUT4Et6uDs48XbVrvAAMggGQkaoVoLtXXU7yEieC4VgWJ410bHlA
SKUki138rcvmWbbjZhAcyWt2HwAH/tlLAfAsisEVdqR1lGFiRFhDlZ/ie96TUrdq
TtSGZpBcGfvYqyBizDz/yCEeqeFwKwYpRaFr26obB2ZtPuX8B5WOzIXWON+cthk/
gCupAmrmJC1zlRusZyiYkZYOKrTCQm3OKLQldd3dDtGapIloilkuiGYhGRlj/ev6
mQIDAQAB
-----END PUBLIC KEY-----\n";
const OTHER_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDSW/BAfM2wtm0Y
VxiZR3YapxEo3NW0T1LdJxudGAFfxvHcNQk5Zb9cQY7g0u+g/rIT7g4t1q8kABHj
vv6revtiIV+eEbqnlOM+y2Eo3LF54uqBsB9PqGm1KpErts5SuiYcjK68V+dENPJt
PxkyE+dzri/vcjekbHvNiSS24DerhBQJ0X+2rxCvuWju/OlChmXHcs3UTNPIvdLw
OY1tevOggAV6AW+1yLSQKf3Qyuz1tOPVwtCuY+umyxloTSs8F3P4JEbEVNDhJ8sV
v6m0GHJpeC5vSLhN38k44oTWrH/xZbApu5MPHRir5gKszsd+Phus7CMVGSY6dHFU
rj0q3hIfAgMBAAECggEAIkJx9va8gy66xs+MhI40aHPUIh0ROvv+SWFQqH2b367l
fhEvLudoyowsymXgPA6vDvri2UlRHeJbB4X4MRJm9Zzs1zAY/6kKd5Qk/0QuLWUs
/zEhcFZD3QsROJbdtHB3u4eX/7mrQxsCbpNrtZGzTM5OJUerUz6NzTQsRBJxTp/4
xOFbiFMJFCvIgBdfk7c/ND7uXRmSc+wwulaXxJPQjfaE+sgtTCGu/oCRb4PJSkSt
Uym0wKfzZurlNjzePJwbS6Ta6UdeAANd2RRm23k71xKCOEsKhb/cVzEmK/3qjEkc
57fOFSll+iQPzPMMqdVQzLOiT5Jh4DZeF53GAvVb5QKBgQD91ZikUe0Tlw6tGJry
zsO6RXoVquGCN/Tw+E9sT20iYhM0l4xmHi1GFWx/a80vKrOyoOqo9X9z181OaJ+a
+Kf0TcUzFJO6EBTgYDvZ0LMuIGA1Zue8cGbZWUCSK1bVxomI2UmtoJ7kyZcGYZrj
lDP00o+51iy/YAuA5n+1GamMawKBgQDUJ2Mk3bwRGDbreVNHsrA3N+ddJr8Yfodp
u5XkjVc4G3c29LrOjwJVqbNcmSDiMDh5fOrdfjuvzcj2tSG+5u45SeCqIH/VDb8I
rduY6yDhB56FAwYlftgFnUeEYnF2QoRXXAlT9zGg3oevxUCKG0fWScVtcz3FWbDH
IRYcscX+HQKBgQCbmofTG4HYw340sGO0OvoTQyn/BFzvhbv6yE1v2RTOwg6B6/Ee
XJtmXhW/2ubSZjv4YdrYLn6uFfl+enZ0+r+C7PXZRWD164vQrE2kTeK5gRFZSzb9
9m2mCaeiszytGeMP6BvZeyBMoiOZvtXDcwOSrk17H4cY3hjPMP3Sl+Ou9wKBgQCh
746VzUqIIduJ0Ynn6FTpURqg17p1j978rdq0Ic65XP2aTSNqF27IxEfMHnYjMHtr
ABamCny0rHcBGTEw7kRYJjP+p9/rWBrBHTPJfXATVCWDkdNXO4LYhjzYp+vDQPKT
XAUiukR/blxTplSlFj23K4gvCw/TW6q71F10eZ2PYQKBgH+kQaSvEPtJtEBlMx8f
QBNWZaRm3v+zZcSKxxiM4/vy5xiAfp/4N9tsE2xvyBPGC1y683bLW28oXAyKx7YX
nZGIdHtKWK7K6QOXas1/vvwddz+1ESLbnBUb0nSD2MiqYmCFUoGGvE/WpkhFKgkh
kS0UbRRsk/J7RXVZma4zi9+u
-----END PRIVATE KEY-----\n";

const ALL_PADDINGS: [PaddingScheme; 5] = [
    PaddingScheme::Pkcs1,
    PaddingScheme::OaepSha1Mgf1,
    PaddingScheme::OaepSha256Mgf1,
    PaddingScheme::OaepSha384Mgf1,
    PaddingScheme::OaepSha512Mgf1,
];

fn keyring(padding: PaddingScheme, public: Option<&str>, private: Option<&str>) -> RawRsaKeyring {
    RawRsaKeyring::builder()
        .key_namespace("rsa-namespace")
        .key_name("rsa-name")
        .padding_scheme(padding)
        .set_public_key(public.map(|k| k.as_bytes().to_vec()))
        .set_private_key(private.map(|k| k.as_bytes().to_vec()))
        .build()
        .unwrap()
}

fn full(padding: PaddingScheme) -> RawRsaKeyring {
    keyring(padding, Some(PUBLIC_KEY), Some(PRIVATE_KEY))
}

async fn encrypt(
    k: &RawRsaKeyring,
    suite: AlgorithmSuiteId,
    pdk: Option<Vec<u8>>,
) -> EncryptionMaterials {
    k.on_encrypt()
        .materials(enc_materials(suite, pdk))
        .send()
        .await
        .unwrap()
        .into_materials()
}

#[tokio::test]
async fn every_padding_round_trips_a_generated_data_key() {
    for padding in ALL_PADDINGS {
        let k = full(padding);
        let out = encrypt(&k, SUITE, None).await;
        let pdk = out.plaintext_data_key().unwrap().as_bytes().to_vec();
        assert_eq!(out.encrypted_data_keys().len(), 1);
        let edk = &out.encrypted_data_keys()[0];
        assert_eq!(edk.key_provider_id(), "rsa-namespace");
        assert_eq!(edk.key_provider_info(), b"rsa-name");
        let dec = k
            .on_decrypt()
            .materials(dec_materials(SUITE, None))
            .set_encrypted_data_keys(Some(out.encrypted_data_keys().to_vec()))
            .send()
            .await
            .unwrap()
            .into_materials();
        assert_eq!(
            dec.plaintext_data_key().unwrap().as_bytes(),
            pdk.as_slice(),
            "{padding:?}"
        );
    }
}

#[tokio::test]
async fn a_supplied_data_key_is_wrapped_not_replaced() {
    let k = full(PaddingScheme::OaepSha256Mgf1);
    let out = encrypt(&k, SUITE, Some(vec![7u8; 32])).await;
    assert_eq!(out.plaintext_data_key().unwrap().as_bytes(), &[7u8; 32]);
    let dec = k
        .on_decrypt()
        .materials(dec_materials(SUITE, None))
        .set_encrypted_data_keys(Some(out.encrypted_data_keys().to_vec()))
        .send()
        .await
        .unwrap()
        .into_materials();
    assert_eq!(dec.plaintext_data_key().unwrap().as_bytes(), &[7u8; 32]);
}

#[tokio::test]
async fn intermediate_key_wrapping_round_trips() {
    for pdk in [None, Some(vec![9u8; 32])] {
        let k = full(PaddingScheme::OaepSha256Mgf1);
        let out = encrypt(&k, DBE_SUITE, pdk.clone()).await;
        let expected = out.plaintext_data_key().unwrap().as_bytes().to_vec();
        if let Some(pdk) = &pdk {
            assert_eq!(&expected, pdk);
        }
        let dec = k
            .on_decrypt()
            .materials(dec_materials(DBE_SUITE, None))
            .set_encrypted_data_keys(Some(out.encrypted_data_keys().to_vec()))
            .send()
            .await
            .unwrap()
            .into_materials();
        assert_eq!(
            dec.plaintext_data_key().unwrap().as_bytes(),
            expected.as_slice()
        );
    }
}

#[tokio::test]
async fn tampered_intermediate_ciphertext_fails() {
    let k = full(PaddingScheme::OaepSha256Mgf1);
    let out = encrypt(&k, DBE_SUITE, None).await;
    let edk = &out.encrypted_data_keys()[0];
    for ciphertext in [vec![1u8; 5], {
        let mut c = edk.ciphertext().to_vec();
        c[0] ^= 1;
        c
    }] {
        let bad = EncryptedDataKey::builder()
            .key_provider_id(edk.key_provider_id())
            .key_provider_info(edk.key_provider_info().to_vec())
            .ciphertext(ciphertext)
            .build()
            .unwrap();
        let err = k
            .on_decrypt()
            .materials(dec_materials(DBE_SUITE, None))
            .set_encrypted_data_keys(Some(vec![bad]))
            .send()
            .await
            .unwrap_err();
        // With one failure, `all_failed` returns that error unchanged.
        assert!(err.is_cryptographic(), "{err:?}");
        assert!(err.to_string().contains("did not decrypt"), "{err}");
    }
}

#[tokio::test]
async fn the_wrong_private_key_fails() {
    let encryptor = keyring(PaddingScheme::OaepSha1Mgf1, Some(PUBLIC_KEY), None);
    let decryptor = keyring(PaddingScheme::OaepSha1Mgf1, None, Some(OTHER_PRIVATE_KEY));
    let out = encrypt(&encryptor, SUITE, None).await;
    let err = decryptor
        .on_decrypt()
        .materials(dec_materials(SUITE, None))
        .set_encrypted_data_keys(Some(out.encrypted_data_keys().to_vec()))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_cryptographic(), "{err:?}");
    assert!(
        format!("{err:?}").contains("RSA decryption of the data key failed"),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_wrapped_key_of_the_wrong_length_fails() {
    // A 16-byte data key does not fit a 32-byte suite.
    let k = full(PaddingScheme::Pkcs1);
    let short = encrypt(
        &k,
        AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf),
        None,
    )
    .await;
    let err = k
        .on_decrypt()
        .materials(dec_materials(SUITE, None))
        .set_encrypted_data_keys(Some(short.encrypted_data_keys().to_vec()))
        .send()
        .await
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("Invalid plaintext length"),
        "{err:?}"
    );
}

#[tokio::test]
async fn non_matching_and_empty_edks_are_skipped() {
    let k = full(PaddingScheme::OaepSha256Mgf1);
    let other = EncryptedDataKey::builder()
        .key_provider_id("other")
        .key_provider_info(b"rsa-name".to_vec())
        .ciphertext(vec![1, 2, 3])
        .build()
        .unwrap();
    let empty = EncryptedDataKey::builder()
        .key_provider_id("rsa-namespace")
        .key_provider_info(b"rsa-name".to_vec())
        .ciphertext(Vec::new())
        .build()
        .unwrap();
    let err = k
        .on_decrypt()
        .materials(dec_materials(SUITE, None))
        .set_encrypted_data_keys(Some(vec![other, empty]))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.collected().len(), 2, "{err:?}");
    assert!(err.collected().iter().all(|e| e.is_no_matching_data_key()));

    let err = k
        .on_decrypt()
        .materials(dec_materials(SUITE, None))
        .set_encrypted_data_keys(Some(Vec::new()))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_no_matching_data_key(), "{err:?}");
}

#[tokio::test]
async fn decrypt_with_a_data_key_already_present_fails() {
    let err = full(PaddingScheme::Pkcs1)
        .on_decrypt()
        .materials(dec_materials(SUITE, Some(vec![0u8; 32])))
        .set_encrypted_data_keys(Some(Vec::new()))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_invalid_materials(), "{err:?}");
}

#[tokio::test]
async fn a_keyring_without_the_needed_key_fails() {
    let public_only = keyring(PaddingScheme::Pkcs1, Some(PUBLIC_KEY), None);
    let err = public_only
        .on_decrypt()
        .materials(dec_materials(SUITE, None))
        .set_encrypted_data_keys(Some(Vec::new()))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");

    let private_only = keyring(PaddingScheme::Pkcs1, None, Some(PRIVATE_KEY));
    let err = private_only
        .on_encrypt()
        .materials(enc_materials(SUITE, None))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");
}

#[tokio::test]
async fn an_invalid_public_key_fails_on_encrypt() {
    let k = keyring(PaddingScheme::Pkcs1, Some("not a key"), None);
    let err = k
        .on_encrypt()
        .materials(enc_materials(SUITE, Some(vec![0u8; 32])))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_cryptographic(), "{err:?}");
}

#[test]
fn the_builder_validates_its_inputs() {
    let base = || {
        RawRsaKeyring::builder()
            .key_namespace("ns")
            .key_name("name")
            .padding_scheme(PaddingScheme::Pkcs1)
            .public_key(PUBLIC_KEY.as_bytes().to_vec())
    };
    assert!(
        base()
            .set_key_namespace(None)
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        base()
            .set_key_name(None)
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        base()
            .set_padding_scheme(None)
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        base()
            .key_namespace("aws-kms")
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        base()
            .key_namespace("aws-kms-x")
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        base()
            .set_public_key(Some(Vec::new()))
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        base()
            .set_public_key(None)
            .private_key(PRIVATE_KEY.as_bytes().to_vec())
            .build()
            .is_ok()
    );

    let k = base().build().unwrap();
    assert_eq!(k.name(), "ns/name");
    assert_eq!(k.key_namespace(), "ns");
    assert_eq!(k.key_name(), "name");
    assert_eq!(k.padding_scheme(), PaddingScheme::Pkcs1);
    assert_eq!(k.public_key(), Some(PUBLIC_KEY.as_bytes()));
    let debug = format!("{k:?}");
    assert!(
        !debug.contains("BEGIN"),
        "Debug must not print key material: {debug}"
    );
    let builder_debug = format!("{:?}", base().private_key(PRIVATE_KEY.as_bytes().to_vec()));
    assert!(
        !builder_debug.contains("PRIVATE KEY-----\nMII"),
        "{builder_debug}"
    );
    let _ = base().get_key_namespace();
    let _ = base().get_key_name();
}
