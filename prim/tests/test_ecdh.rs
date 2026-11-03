// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ECDH tests ported from Dafny [`TestECDH.dfy`], with its fixed keys and invalid public keys.
//!
//! [`TestECDH.dfy`]: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/test/TestECDH.dfy

use aws_mpl_primitives::{
    EcdhCurveSpec, ecdh_compress_public_key, ecdh_decompress_public_key, ecdh_derive_shared_secret,
    ecdh_generate_key_pair, ecdh_public_key_from_private_key, ecdh_validate_public_key,
};

const CURVES: [EcdhCurveSpec; 3] = [
    EcdhCurveSpec::EccNistP256,
    EcdhCurveSpec::EccNistP384,
    EcdhCurveSpec::EccNistP521,
];

const P256_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgw+7YSKEOEAh8/DFZ\n\
22oSTm/D3jo4nH5tN48IUp0WjyuhRANCAASnUgx7SrlHhPIn3McZfc3cEIs8+XFf\n\
7JvhcuV1wWELGZ8AjuwnKjE0ielEwSY5HYzWCF773FvJaWGYGYGhSba8\n\
-----END PRIVATE KEY-----";
const P256_PUBLIC: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004a7520c7b4ab9478\
4f227dcc7197dcddc108b3cf9715fec9be172e575c1610b199f008eec272a313489\
e944c126391d8cd6085efbdc5bc96961981981a149b6bc";
const P256_PUBLIC_COMPRESSED: &str =
    "02a7520c7b4ab94784f227dcc7197dcddc108b3cf9715fec9be172e575c1610b19";

const P384_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\n\
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAE/GcrZaGaZKKnWsbi\n\
6OiMB8HlhoyF1CQeaZHFdp1VFu7mSM2mUrSolCfpYRB50aahZANiAAQayPW6B3aV\n\
GKWFBbDH3SeuMhiY2GIPG+tBEHmMZ3QUaG6qNnQxXS+QpR95IWyQWZjInyDk2upe\n\
b1TivP0UYay+dIS8MrBFM7oLBsJIqxGiRQ1EPFIpBLv4mmteOma5qt8=\n\
-----END PRIVATE KEY-----";
const P384_PUBLIC: &str = "3076301006072a8648ce3d020106052b81040022036200041ac8f5ba07769518a58505\
b0c7dd27ae321898d8620f1beb4110798c677414686eaa3674315d2f90a51f79216c\
905998c89f20e4daea5e6f54e2bcfd1461acbe7484bc32b04533ba0b06c248ab11a2\
450d443c522904bbf89a6b5e3a66b9aadf";
const P384_PUBLIC_COMPRESSED: &str = "031ac8f5ba07769518a58505b0c7dd27ae321898d8620f1beb4110798c677414686eaa3674315d2f90a51f79216c905998";

const P521_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\n\
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB3azBoPIuF7SY3Z7g\n\
xK/dEnSqoqBsHaoiI78Sfs9Ydxsd/3Ref4xZC0v58EwZjKxIMWwcqxSNzg8yLOAV\n\
oaRbwryhgYkDgYYABAHeMnMkadh2nketUTcDvKE4WCcdTdIFKaDqwtMIbq/y5N4E\n\
I77OxYwKP7IdGBC9n/GkcNIWx6R91zc3AId9a7VrOQF9+HitnblByL1u3N6kWhUf\n\
C3ury11T8dkNW+LbVkmX8B3+s6VaEQWKa+SYBemPV05aJhU0xaaF/MhsLGwKLpPp\n\
Qg==\n\
-----END PRIVATE KEY-----";
const P521_PUBLIC: &str = "30819b301006072a8648ce3d020106052b81040023038186000401de32732469d8769e\
47ad513703bca13858271d4dd20529a0eac2d3086eaff2e4de0423becec58c0a3fb2\
1d1810bd9ff1a470d216c7a47dd7373700877d6bb56b39017df878ad9db941c8bd6e\
dcdea45a151f0b7babcb5d53f1d90d5be2db564997f01dfeb3a55a11058a6be49805\
e98f574e5a261534c5a685fcc86c2c6c0a2e93e942";
const P521_PUBLIC_COMPRESSED: &str = "0201de32732469d8769e47ad513703bca13858271d4dd20529a0eac2d3086eaff2e4de0423becec58c0a3fb21d1810bd9ff1a470d216c7a47dd7373700877d6bb56b39";

/// SubjectPublicKeyInfo encodings of the point at infinity, which the parser rejects.
const INFINITY_PUBLIC_KEYS: [&str; 3] = [
    "3019301306072a8648ce3d020106082a8648ce3d03010703020000",
    "3016301006072a8648ce3d020106052b8104002203020000",
    "3016301006072a8648ce3d020106052b8104002303020000",
];

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// A public key whose X and Y coordinates are all `0xff`, which is greater than the field prime.
fn out_of_bounds_public_key(curve: EcdhCurveSpec) -> Vec<u8> {
    let mut der = hex(match curve {
        EcdhCurveSpec::EccNistP256 => "3059301306072a8648ce3d020106082a8648ce3d03010703420004",
        EcdhCurveSpec::EccNistP384 => "3076301006072a8648ce3d020106052b8104002203620004",
        _ => "30819b301006072a8648ce3d020106052b810400230381860004",
    });
    der.resize(curve.public_key_der_len(), 0xff);
    der
}

fn fixed_keys() -> [(EcdhCurveSpec, &'static str, Vec<u8>, Vec<u8>); 3] {
    [
        (
            EcdhCurveSpec::EccNistP256,
            P256_PRIVATE,
            hex(P256_PUBLIC),
            hex(P256_PUBLIC_COMPRESSED),
        ),
        (
            EcdhCurveSpec::EccNistP384,
            P384_PRIVATE,
            hex(P384_PUBLIC),
            hex(P384_PUBLIC_COMPRESSED),
        ),
        (
            EcdhCurveSpec::EccNistP521,
            P521_PRIVATE,
            hex(P521_PUBLIC),
            hex(P521_PUBLIC_COMPRESSED),
        ),
    ]
}

#[test]
fn generated_key_pairs_are_valid_and_distinct() {
    for curve in CURVES {
        let a = ecdh_generate_key_pair(curve).unwrap();
        let b = ecdh_generate_key_pair(curve).unwrap();
        assert_ne!(a.private_key, b.private_key);
        assert_ne!(a.public_key, b.public_key);
        assert_eq!(a.public_key.len(), curve.public_key_der_len());
        ecdh_validate_public_key(curve, &a.public_key).unwrap();
        assert_eq!(
            ecdh_public_key_from_private_key(curve, &a.private_key).unwrap(),
            a.public_key
        );
    }
}

#[test]
fn public_key_from_fixed_private_key() {
    for (curve, private_key, public_key, _) in fixed_keys() {
        assert_eq!(
            ecdh_public_key_from_private_key(curve, private_key.as_bytes()).unwrap(),
            public_key
        );
    }
}

#[test]
fn public_key_from_private_key_on_wrong_curve_fails() {
    ecdh_public_key_from_private_key(EcdhCurveSpec::EccNistP384, P256_PRIVATE.as_bytes())
        .unwrap_err();
}

#[test]
fn public_key_from_non_pem_private_key_fails() {
    ecdh_public_key_from_private_key(EcdhCurveSpec::EccNistP256, b"not a key").unwrap_err();
}

#[test]
fn validate_public_key_rejects_other_curves() {
    for key_curve in CURVES {
        let public_key = ecdh_generate_key_pair(key_curve)
            .unwrap()
            .public_key
            .clone();
        for curve in CURVES {
            assert_eq!(
                ecdh_validate_public_key(curve, &public_key).is_ok(),
                curve == key_curve,
                "{key_curve:?} key validated as {curve:?}"
            );
        }
    }
}

#[test]
fn validate_public_key_rejects_point_at_infinity() {
    for (curve, key) in CURVES.into_iter().zip(INFINITY_PUBLIC_KEYS) {
        let err = ecdh_validate_public_key(curve, &hex(key)).unwrap_err();
        assert_eq!(err.message(), "Invalid X509 Public Key.");
    }
}

#[test]
fn validate_public_key_rejects_point_greater_than_p() {
    for curve in CURVES {
        let err = ecdh_validate_public_key(curve, &out_of_bounds_public_key(curve)).unwrap_err();
        assert_eq!(err.message(), "Invalid X509 Public Key.");
    }
}

#[test]
fn validate_public_key_rejects_compressed_point() {
    for (curve, _, _, compressed) in fixed_keys() {
        ecdh_validate_public_key(curve, &compressed).unwrap_err();
    }
}

#[test]
fn both_parties_derive_the_same_shared_secret() {
    for curve in CURVES {
        let a = ecdh_generate_key_pair(curve).unwrap();
        let b = ecdh_generate_key_pair(curve).unwrap();
        let ab = ecdh_derive_shared_secret(curve, &a.private_key, &b.public_key).unwrap();
        let ba = ecdh_derive_shared_secret(curve, &b.private_key, &a.public_key).unwrap();
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), curve.compressed_public_key_len() - 1);
    }
}

#[test]
fn shared_secret_with_public_key_on_other_curve_fails() {
    let a = ecdh_generate_key_pair(EcdhCurveSpec::EccNistP256).unwrap();
    let b = ecdh_generate_key_pair(EcdhCurveSpec::EccNistP384).unwrap();
    ecdh_derive_shared_secret(EcdhCurveSpec::EccNistP256, &a.private_key, &b.public_key)
        .unwrap_err();
}

#[test]
fn compress_fixed_public_keys() {
    for (curve, _, public_key, compressed) in fixed_keys() {
        assert_eq!(
            ecdh_compress_public_key(curve, &public_key).unwrap(),
            compressed
        );
        assert_eq!(
            ecdh_decompress_public_key(curve, &compressed).unwrap(),
            public_key
        );
    }
}

#[test]
fn compress_decompress_round_trip() {
    for curve in CURVES {
        let public_key = ecdh_generate_key_pair(curve).unwrap().public_key.clone();
        let compressed = ecdh_compress_public_key(curve, &public_key).unwrap();
        assert_eq!(compressed.len(), curve.compressed_public_key_len());
        assert_eq!(
            ecdh_decompress_public_key(curve, &compressed).unwrap(),
            public_key
        );
    }
}

#[test]
fn decompress_rejects_uncompressed_or_short_points() {
    for (curve, _, _, compressed) in fixed_keys() {
        let mut uncompressed_prefix = compressed.clone();
        uncompressed_prefix[0] = 0x04;
        ecdh_decompress_public_key(curve, &uncompressed_prefix).unwrap_err();
        ecdh_decompress_public_key(curve, &compressed[..compressed.len() - 1]).unwrap_err();
    }
}

#[test]
fn compress_rejects_public_key_on_other_curve() {
    let public_key = hex(P256_PUBLIC);
    ecdh_compress_public_key(EcdhCurveSpec::EccNistP384, &public_key).unwrap_err();
}

#[test]
fn key_pair_debug_redacts_the_private_key() {
    let pair = ecdh_generate_key_pair(EcdhCurveSpec::EccNistP256).unwrap();
    let debug = format!("{pair:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("PRIVATE KEY"));
}
