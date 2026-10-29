// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! RSA tests ported from Dafny `TestRSA.dfy`: encrypt/decrypt round trips for
//! every padding scheme, the modulus length, and the failures for empty input,
//! malformed keys, wrong keys, tampered ciphertext and oversized plaintext.
//!
//! The keys below are throwaway test keys. They protect nothing.

use aws_mpl_primitives::{RsaPadding, rsa_decrypt, rsa_encrypt, rsa_modulus_length_bits};

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
const EC_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglKHYOEhpSaQQPQEi
ngMpRTgLfKaWwsQz8zt77JxWxS6hRANCAAQfHQgeYe+x3dC1OyjNDGxUdGITLHwJ
eeleywEsbd3vgZ6r7WpfS5mSqXRIyLpSPUzSjQ2BG5FWkz8ciSptyCx7
-----END PRIVATE KEY-----\n";
const EC_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHx0IHmHvsd3QtTsozQxsVHRiEyx8
CXnpXssBLG3d74Geq+1qX0uZkql0SMi6Uj1M0o0NgRuRVpM/HIkqbcgsew==
-----END PUBLIC KEY-----\n";

const ALL_PADDINGS: [RsaPadding; 5] = [
    RsaPadding::Pkcs1,
    RsaPadding::OaepSha1,
    RsaPadding::OaepSha256,
    RsaPadding::OaepSha384,
    RsaPadding::OaepSha512,
];

#[test]
fn every_padding_round_trips() {
    let plaintext = b"Hello, World!";
    for padding in ALL_PADDINGS {
        let ciphertext = rsa_encrypt(padding, PUBLIC_KEY.as_bytes(), plaintext).unwrap();
        assert_eq!(ciphertext.len(), 256, "{padding:?}");
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
        let decrypted = rsa_decrypt(padding, PRIVATE_KEY.as_bytes(), &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext, "{padding:?}");
    }
}

#[test]
fn the_modulus_length_is_the_key_size() {
    assert_eq!(
        rsa_modulus_length_bits(PUBLIC_KEY.as_bytes()).unwrap(),
        2048
    );
}

#[test]
fn the_modulus_length_of_a_non_rsa_key_fails() {
    let err = rsa_modulus_length_bits(EC_PUBLIC_KEY.as_bytes()).unwrap_err();
    assert!(err.is_cryptographic(), "{err}");
}

#[test]
fn empty_inputs_fail() {
    for padding in ALL_PADDINGS {
        assert!(
            rsa_encrypt(padding, b"", b"x")
                .unwrap_err()
                .is_cryptographic()
        );
        assert!(
            rsa_encrypt(padding, PUBLIC_KEY.as_bytes(), b"")
                .unwrap_err()
                .is_cryptographic()
        );
        assert!(
            rsa_decrypt(padding, b"", b"x")
                .unwrap_err()
                .is_cryptographic()
        );
        assert!(
            rsa_decrypt(padding, PRIVATE_KEY.as_bytes(), b"")
                .unwrap_err()
                .is_cryptographic()
        );
    }
}

#[test]
fn a_key_that_is_not_utf8_fails() {
    let not_utf8 = [0xff, 0xfe, 0xfd];
    let err = rsa_encrypt(RsaPadding::OaepSha256, &not_utf8, b"x").unwrap_err();
    assert!(err.to_string().contains("not UTF-8 PEM"), "{err}");
    let err = rsa_decrypt(RsaPadding::OaepSha256, &not_utf8, b"x").unwrap_err();
    assert!(err.to_string().contains("not UTF-8 PEM"), "{err}");
}

#[test]
fn a_key_that_is_not_pem_fails() {
    let err = rsa_encrypt(RsaPadding::OaepSha256, b"not a pem key", b"x").unwrap_err();
    assert!(err.to_string().contains("not valid PEM"), "{err}");
    let err = rsa_decrypt(RsaPadding::OaepSha256, b"not a pem key", b"x").unwrap_err();
    assert!(err.to_string().contains("not valid PEM"), "{err}");
}

#[test]
fn a_non_rsa_key_fails() {
    let err = rsa_encrypt(RsaPadding::OaepSha256, EC_PUBLIC_KEY.as_bytes(), b"x").unwrap_err();
    assert!(
        err.to_string().contains("not a valid X.509 RSA public key"),
        "{err}"
    );
    let err = rsa_decrypt(RsaPadding::OaepSha256, EC_PRIVATE_KEY.as_bytes(), b"x").unwrap_err();
    assert!(
        err.to_string()
            .contains("not a valid PKCS #8 RSA private key"),
        "{err}"
    );
}

#[test]
fn the_wrong_private_key_fails() {
    for padding in ALL_PADDINGS {
        let ciphertext = rsa_encrypt(padding, PUBLIC_KEY.as_bytes(), b"secret").unwrap();
        let err = rsa_decrypt(padding, OTHER_PRIVATE_KEY.as_bytes(), &ciphertext).unwrap_err();
        assert!(err.is_cryptographic(), "{padding:?}: {err}");
    }
}

#[test]
fn tampered_ciphertext_fails() {
    for padding in ALL_PADDINGS {
        let mut ciphertext = rsa_encrypt(padding, PUBLIC_KEY.as_bytes(), b"secret").unwrap();
        ciphertext[10] ^= 0x01;
        let err = rsa_decrypt(padding, PRIVATE_KEY.as_bytes(), &ciphertext).unwrap_err();
        assert!(
            err.to_string().contains("decryption failed"),
            "{padding:?}: {err}"
        );
    }
}

#[test]
fn a_different_padding_fails_to_decrypt() {
    let ciphertext = rsa_encrypt(RsaPadding::OaepSha256, PUBLIC_KEY.as_bytes(), b"secret").unwrap();
    let err = rsa_decrypt(RsaPadding::OaepSha512, PRIVATE_KEY.as_bytes(), &ciphertext).unwrap_err();
    assert!(err.is_cryptographic(), "{err}");
}

#[test]
fn plaintext_too_long_for_the_key_fails() {
    let plaintext = vec![0x42u8; 256];
    for padding in ALL_PADDINGS {
        let err = rsa_encrypt(padding, PUBLIC_KEY.as_bytes(), &plaintext).unwrap_err();
        assert!(
            err.to_string().contains("encryption failed"),
            "{padding:?}: {err}"
        );
    }
}
