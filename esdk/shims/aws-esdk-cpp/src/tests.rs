//! Bridge-internal tests: translation helpers, null-handle checks, and inputs
//! the facade cannot express. Everything here runs offline. Facade-observable
//! behavior lives in the C++ suites under tests/. The error wire encoding has
//! no test of its own: every C++ typed-exception check on a Rust-produced error
//! covers the encode and decode end to end.

use super::*;
use ffi::EsdkAlgorithmSuiteId as F;
use ffi::EsdkCommitmentPolicy as P;

// Helpers
//
// Constructors for the presence-encoded optionals, all-unset fixtures
// mirroring the C++ side's value-initialized inputs, and shared builders.

fn unset_u32() -> ffi::OptU32 {
    ffi::OptU32 {
        set: false,
        value: 0,
    }
}
fn set_u32(value: u32) -> ffi::OptU32 {
    ffi::OptU32 { set: true, value }
}
fn unset_alg_id() -> ffi::OptAlgId {
    ffi::OptAlgId {
        set: false,
        value: F { repr: 0 },
    }
}
fn set_alg_id(value: F) -> ffi::OptAlgId {
    ffi::OptAlgId { set: true, value }
}
fn unset_policy() -> ffi::OptCommitmentPolicy {
    ffi::OptCommitmentPolicy {
        set: false,
        value: P { repr: 0 },
    }
}
fn set_policy(value: P) -> ffi::OptCommitmentPolicy {
    ffi::OptCommitmentPolicy { set: true, value }
}

fn unset_encrypt_input() -> ffi::EncryptInput<'static> {
    ffi::EncryptInput {
        algorithm_suite_id: unset_alg_id(),
        encryption_context: Vec::new(),
        frame_length: unset_u32(),
        keyring: std::ptr::null(),
        plaintext: &[],
        max_encrypted_data_keys: unset_u32(),
        commitment_policy: unset_policy(),
    }
}

fn unset_decrypt_input() -> ffi::DecryptInput<'static> {
    ffi::DecryptInput {
        ciphertext: &[],
        encryption_context: Vec::new(),
        keyring: std::ptr::null(),
        max_encrypted_data_keys: unset_u32(),
        commitment_policy: unset_policy(),
    }
}

fn expect_err<T>(result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

// Type translation

// Must mirror the discriminants of `ffi::EsdkAlgorithmSuiteId` in the bridge.
const ALG_REPRS: [u16; 11] = [
    0x0014, 0x0046, 0x0078, 0x0114, 0x0146, 0x0178, 0x0214, 0x0346, 0x0378, 0x0478, 0x0578,
];

#[test]
fn alg_id_target_to_core_accepts_exactly_known_reprs() {
    let mut accepted: Vec<u16> = (0..=u16::MAX)
        .filter(|&n| alg_id_target_to_core(F { repr: n }).is_ok())
        .collect();
    accepted.sort_unstable();
    let mut expected = ALG_REPRS.to_vec();
    expected.sort_unstable();
    assert_eq!(accepted, expected);
}

#[test]
fn alg_id_target_to_core_maps_each_repr_to_matching_variant() {
    use aws_esdk::EsdkAlgorithmSuiteId as C;
    let pairs: [(u16, C); 11] = [
        (0x0014, C::AlgAes128GcmIv12Tag16NoKdf),
        (0x0046, C::AlgAes192GcmIv12Tag16NoKdf),
        (0x0078, C::AlgAes256GcmIv12Tag16NoKdf),
        (0x0114, C::AlgAes128GcmIv12Tag16HkdfSha256),
        (0x0146, C::AlgAes192GcmIv12Tag16HkdfSha256),
        (0x0178, C::AlgAes256GcmIv12Tag16HkdfSha256),
        (0x0214, C::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256),
        (0x0346, C::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384),
        (0x0378, C::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384),
        (0x0478, C::AlgAes256GcmHkdfSha512CommitKey),
        (0x0578, C::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384),
    ];
    for (repr, core) in pairs {
        //= spec/shim/esdk-shim.md#algorithm-suite-identifier
        //= type=test
        //# - The shim MUST translate a target algorithm suite identifier to the core ESDK
        //# algorithm suite that has the same two-byte ID.
        assert_eq!(alg_id_target_to_core(F { repr }).unwrap(), core);
    }
}

#[test]
fn alg_id_target_to_core_rejects_unknown() {
    //= spec/shim/esdk-shim.md#algorithm-suite-identifier
    //= type=test
    //# - The shim MUST return an error when the target value is not one of the algorithm
    //# suite IDs defined by the core ESDK.
    let err = alg_id_target_to_core(F { repr: 0xFFFF }).unwrap_err();
    assert!(err.contains("unrecognized"), "unexpected error: {err}");
    assert!(alg_id_target_to_core(F { repr: 0x0000 }).is_err());
}

#[test]
fn alg_id_core_to_target_maps_every_core_variant() {
    use aws_esdk::EsdkAlgorithmSuiteId as C;
    let pairs: [(C, u16); 11] = [
        (C::AlgAes128GcmIv12Tag16NoKdf, 0x0014),
        (C::AlgAes192GcmIv12Tag16NoKdf, 0x0046),
        (C::AlgAes256GcmIv12Tag16NoKdf, 0x0078),
        (C::AlgAes128GcmIv12Tag16HkdfSha256, 0x0114),
        (C::AlgAes192GcmIv12Tag16HkdfSha256, 0x0146),
        (C::AlgAes256GcmIv12Tag16HkdfSha256, 0x0178),
        (C::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256, 0x0214),
        (C::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384, 0x0346),
        (C::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384, 0x0378),
        (C::AlgAes256GcmHkdfSha512CommitKey, 0x0478),
        (C::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384, 0x0578),
    ];
    for (core, repr) in pairs {
        //= spec/shim/esdk-shim.md#algorithm-suite-identifier
        //= type=test
        //# - The shim MUST translate a core ESDK algorithm suite to the target algorithm
        //# suite identifier that has the same two-byte ID.
        assert_eq!(alg_id_core_to_target(core).unwrap().repr, repr);
    }
}

#[test]
fn alg_id_round_trips_through_both_conversions() {
    for &n in &ALG_REPRS {
        let core = alg_id_target_to_core(F { repr: n }).expect("known suite id converts");
        let back = alg_id_core_to_target(core).expect("round-trips back");
        assert_eq!(back.repr, n);
    }
}

#[test]
fn commitment_policy_target_to_core_accepts_exactly_known_reprs() {
    use aws_esdk::EsdkCommitmentPolicy as C;
    let pairs: [(P, C); 3] = [
        (P::ForbidEncryptAllowDecrypt, C::ForbidEncryptAllowDecrypt),
        (P::RequireEncryptAllowDecrypt, C::RequireEncryptAllowDecrypt),
        (
            P::RequireEncryptRequireDecrypt,
            C::RequireEncryptRequireDecrypt,
        ),
    ];
    for (target, expected_core) in pairs {
        //= spec/shim/esdk-shim.md#commitment-policy
        //= type=test
        //# - The shim MUST translate the target commitment policy to the core ESDK
        //# commitment policy of the same meaning.
        assert_eq!(
            commitment_policy_target_to_core(target).unwrap(),
            expected_core
        );
    }

    let accepted: Vec<u8> = (0..=u8::MAX)
        .filter(|&n| commitment_policy_target_to_core(P { repr: n }).is_ok())
        .collect();
    //= spec/shim/esdk-shim.md#commitment-policy
    //= type=test
    //= reason=Sweeping 0..=u8::MAX, only 1,2,3 are accepted; every other value (including the unassigned 0) returns an error.
    //# - The shim MUST return an error when the target commitment policy is not a supported value.
    assert_eq!(accepted, vec![1u8, 2, 3]);
}

#[test]
fn encryption_context_round_trips() {
    use std::collections::HashMap;
    let mut m = HashMap::new();
    m.insert("k1".to_string(), "v1".to_string());
    m.insert("k2".to_string(), "v2".to_string());
    let list = encryption_context_core_to_target(m.clone()).unwrap();
    assert_eq!(list.len(), 2);
    //= spec/shim/esdk-shim.md#encryption-context
    //= type=test
    //# - The shim MUST translate the core ESDK's encryption context, given as a
    //# key-value map, to the target's list of key-value pairs, preserving every pair
    //# and the exact key and value of each.
    for (k, v) in &m {
        assert_eq!(
            list.iter().filter(|i| &i.key == k && &i.value == v).count(),
            1,
            "pair {k}={v} must appear exactly once"
        );
    }
    //= spec/shim/esdk-shim.md#encryption-context
    //= type=test
    //# - The shim MUST translate the target's encryption context, given as a list of
    //# key-value pairs, to the core ESDK's key-value map, preserving every pair and
    //# the exact key and value of each.
    assert_eq!(encryption_context_target_to_core(&list).unwrap(), m);
}

#[test]
fn encryption_context_empty() {
    use std::collections::HashMap;
    let empty: HashMap<String, String> = HashMap::new();
    assert!(encryption_context_core_to_target(empty).unwrap().is_empty());
    assert!(encryption_context_target_to_core(&[]).unwrap().is_empty());
}

#[test]
fn make_frame_length_translates_and_rejects_zero() {
    //= spec/shim/esdk-shim.md#frame-length
    //= type=test
    //# - The shim MUST translate the target frame length using the core ESDK's frame
    //# length constructor, and MUST return an error when the core ESDK rejects the
    //# value.
    let err = make_frame_length(0).unwrap_err();
    assert!(
        err.contains("Frame length must be non-zero"),
        "unexpected error: {err}"
    );
    assert!(make_frame_length(4096).is_ok());
    assert!(make_frame_length(1).is_ok());
}

#[test]
fn max_edks_zero_is_no_limit_positive_is_limit() {
    //= spec/shim/esdk-shim.md#maximum-encrypted-data-keys
    //= type=test
    //# The shim MUST translate zero to the core ESDK's "no limit" representation,
    //# and a positive value `n` to a limit of `n`.
    assert_eq!(max_edks_target_to_core(0), None);
    assert_eq!(max_edks_target_to_core(1), std::num::NonZeroUsize::new(1));
    assert_eq!(max_edks_target_to_core(42), std::num::NonZeroUsize::new(42));
}

#[test]
fn classify_core_error_maps_each_kind() {
    use aws_esdk::ErrorKind;
    // ErrorKind::Esdk has no explicit arm; it maps through the wildcard.
    let cases = [
        (ErrorKind::Esdk, ffi::ShimErrorKind::Esdk),
        (
            ErrorKind::SerializationError,
            ffi::ShimErrorKind::SerializationError,
        ),
        (
            ErrorKind::CryptographicError,
            ffi::ShimErrorKind::CryptographicError,
        ),
        (ErrorKind::MplError, ffi::ShimErrorKind::MplError),
        (
            ErrorKind::ValidationError,
            ffi::ShimErrorKind::ValidationError,
        ),
    ];
    for (kind, expected) in cases {
        assert_eq!(
            classify_core_error(&kind).repr,
            expected.repr,
            "for {kind:?}"
        );
    }
}

// Inputs the facade cannot express, so must be tested in Rust
//
// - Null resource handles (the facade passes references)
// - unset/unknown enum reprs (the facade's factories only produce valid values)

#[test]
fn encrypt_rejects_null_keyring() {
    //= spec/shim/esdk-shim.md#materials-source
    //= type=test
    //# - The shim MUST return an error, and MUST NOT invoke the core ESDK, when no
    //# materials source is supplied.
    let err = expect_err(encrypt(&unset_encrypt_input()));
    assert!(err.contains("keyring is null"), "unexpected error: {err}");
}

#[test]
fn decrypt_rejects_null_keyring() {
    let err = expect_err(decrypt(&unset_decrypt_input()));
    assert!(err.contains("keyring is null"), "unexpected error: {err}");
}

#[test]
fn create_raw_aes_keyring_rejects_unsupported_wrapping_alg() {
    //= spec/shim/esdk-shim.md#aes-wrapping-algorithm
    //= type=test
    //# - The shim MUST return an error when the target wrapping algorithm is not a
    //# supported value.
    let unset = expect_err(create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 32],
        wrapping_alg: ffi::AesWrappingAlg::Unset,
    }));
    assert!(
        unset.contains("wrapping_alg is unset"),
        "unexpected error: {unset}"
    );

    let unknown = expect_err(create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 32],
        wrapping_alg: ffi::AesWrappingAlg { repr: 99 },
    }));
    assert!(
        unknown.contains("Invalid AesWrappingAlg"),
        "unexpected error: {unknown}"
    );
}

// Options forwarding

#[test]
fn apply_encrypt_options_forwards_every_optional_input() {
    use aws_esdk::EsdkCommitmentPolicy as C;
    let input = ffi::EncryptInput {
        algorithm_suite_id: set_alg_id(F { repr: 0x0578 }),
        encryption_context: Vec::new(),
        frame_length: set_u32(1024),
        keyring: std::ptr::null(),
        plaintext: &[],
        max_encrypted_data_keys: set_u32(5),
        commitment_policy: set_policy(P::ForbidEncryptAllowDecrypt),
    };
    let mut core = aws_esdk::EncryptInput::default();
    apply_encrypt_options(&mut core, &input).expect("options apply");

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied maximum-encrypted-data-keys value to
    //# the core ESDK, converted as defined in
    //# [Maximum encrypted data keys](#maximum-encrypted-data-keys).
    assert_eq!(core.max_encrypted_data_keys, std::num::NonZeroUsize::new(5));

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied frame length to the core ESDK,
    //# converted as defined in [Frame length](#frame-length).
    assert_eq!(core.frame_length.0.get(), 1024);

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied commitment policy to the core ESDK,
    //# converted as defined in [Commitment policy](#commitment-policy).
    assert_eq!(core.commitment_policy, C::ForbidEncryptAllowDecrypt);
}

#[test]
fn apply_decrypt_options_forwards_every_optional_input() {
    use aws_esdk::EsdkCommitmentPolicy as C;
    let input = ffi::DecryptInput {
        ciphertext: &[],
        encryption_context: Vec::new(),
        keyring: std::ptr::null(),
        max_encrypted_data_keys: set_u32(7),
        commitment_policy: set_policy(P::RequireEncryptAllowDecrypt),
    };
    let mut core = aws_esdk::DecryptInput::default();
    apply_decrypt_options(&mut core, &input).expect("options apply");

    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied maximum-encrypted-data-keys value to
    //# the core ESDK, converted as defined in
    //# [Maximum encrypted data keys](#maximum-encrypted-data-keys).
    assert_eq!(core.max_encrypted_data_keys, std::num::NonZeroUsize::new(7));

    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied commitment policy to the core ESDK,
    //# converted as defined in [Commitment policy](#commitment-policy).
    assert_eq!(core.commitment_policy, C::RequireEncryptAllowDecrypt);
}
