//! Bridge-internal tests: translation helpers, null-handle checks, and inputs
//! the facade cannot express. Everything here runs offline. Facade-observable
//! behavior, including the credentialed integration coverage, lives in the C++
//! suites under tests/. The error wire encoding has no test of its own: every
//! C++ typed-exception check on a Rust-produced error covers the encode and
//! decode end to end.

use super::*;
use ffi::EsdkAlgorithmSuiteId as F;
use ffi::EsdkCommitmentPolicy as P;

// Constructors for the presence-encoded optionals.

fn unset_u32() -> ffi::OptU32 {
    ffi::OptU32 {
        set: false,
        value: 0,
    }
}
fn set_u32(value: u32) -> ffi::OptU32 {
    ffi::OptU32 { set: true, value }
}
fn unset_string() -> ffi::OptString {
    ffi::OptString {
        set: false,
        value: String::new(),
    }
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
fn unset_cache() -> ffi::OptCacheType {
    ffi::OptCacheType {
        set: false,
        value: ffi::CacheType {
            kind: ffi::CacheKind { repr: 0 },
            entry_capacity: 0,
            entry_pruning_tail_size: unset_u32(),
            shared: std::ptr::null(),
        },
    }
}

// All-unset test fixtures, mirroring the C++ side's value-initialized inputs.

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

fn unset_hierarchical_keyring_input() -> ffi::HierarchicalKeyringInput {
    ffi::HierarchicalKeyringInput {
        branch_key_id: String::new(),
        key_store: std::ptr::null(),
        ttl_seconds: 0,
        cache: unset_cache(),
        partition_id: unset_string(),
    }
}

fn unset_keystore_config() -> ffi::KeyStoreConfig {
    ffi::KeyStoreConfig {
        ddb_table_name: String::new(),
        kms_configuration_type: ffi::KmsConfigurationType::Unset,
        kms_configuration_value: String::new(),
        logical_key_store_name: String::new(),
        id: unset_string(),
        grant_tokens: Vec::new(),
        ddb_client: std::ptr::null(),
        kms_client: std::ptr::null(),
    }
}

fn unset_client_config() -> ffi::MplAwsClientConfig {
    ffi::MplAwsClientConfig {
        region: unset_string(),
        retry: ffi::RetryConfig {
            mode_adaptive: false,
            max_attempts: unset_u32(),
        },
    }
}

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
    use aws_mpl_legacy::suites::EsdkAlgorithmSuiteId as C;
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
    use aws_mpl_legacy::suites::EsdkAlgorithmSuiteId as C;
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
    use aws_mpl_legacy::commitment::EsdkCommitmentPolicy as C;
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

fn expect_err<T>(result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

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
fn create_keystore_rejects_null_clients() {
    let err = expect_err(create_keystore(&unset_keystore_config()));
    //= spec/shim/shim.md#handles-and-lifetimes
    //= type=test
    //= reason=Exercises a common `require_handle` method call, so this is universal
    //# - Before dereferencing a target-supplied resource handle, the shim MUST check it
    //# and MUST return an error when a required handle is absent.
    //
    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - Creating a key store MUST require a KMS client handle and a DynamoDB client
    //# handle, checked as defined in
    //# [Shim Specification: Handles and lifetimes](./shim.md#handles-and-lifetimes),
    //# and MUST provide both to the core ESDK.
    assert!(
        err.contains("kms_client is null"),
        "unexpected error: {err}"
    );

    let kms = create_kms_client(&unset_client_config()).expect("create kms client");
    let mut cfg = unset_keystore_config();
    cfg.kms_client = &*kms as *const MplKmsClient;
    let err = expect_err(create_keystore(&cfg));
    assert!(
        err.contains("ddb_client is null"),
        "unexpected error: {err}"
    );
}

#[test]
fn create_hierarchical_keyring_rejects_null_key_store() {
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //# - Creating a hierarchical keyring MUST require a key store handle, checked as defined in
    //# [Shim Specification: Handles and lifetimes](./shim.md#handles-and-lifetimes),
    //# and MUST provide it to the core ESDK.
    let err = expect_err(create_hierarchical_keyring(
        &unset_hierarchical_keyring_input(),
    ));
    assert!(err.contains("key_store is null"), "unexpected error: {err}");
}

#[test]
fn make_kms_config_rejects_unknown_type() {
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST return an error when the target KMS configuration type is not a
    //# supported value.
    let err = make_kms_config(ffi::KmsConfigurationType { repr: 99 }, "").unwrap_err();
    assert!(
        err.contains("Invalid KmsConfigurationType"),
        "unexpected error: {err}"
    );
    let err = make_kms_config(ffi::KmsConfigurationType::Unset, "").unwrap_err();
    assert!(
        err.contains("kms_configuration_type is unset"),
        "unexpected error: {err}"
    );
}

#[test]
fn make_kms_config_accepts_key_arn() {
    use aws_mpl_legacy::dafny::deps::aws_cryptography_keyStore::types::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a KMS key ARN configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::KmsKeyArn, "arn:test-key").unwrap(),
        KmsConfiguration::KmsKeyArn(v) if v == "arn:test-key"
    ));
}

#[test]
fn make_kms_config_accepts_mr_key_arn() {
    use aws_mpl_legacy::dafny::deps::aws_cryptography_keyStore::types::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a KMS multi-Region-key ARN configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::KmsMrKeyArn, "arn:test-mr-key").unwrap(),
        KmsConfiguration::KmsMrKeyArn(v) if v == "arn:test-mr-key"
    ));
}

#[test]
fn make_kms_config_accepts_discovery() {
    use aws_mpl_legacy::dafny::deps::aws_cryptography_keyStore::types::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a discovery configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::Discovery, "").unwrap(),
        KmsConfiguration::Discovery(_)
    ));
}

#[test]
fn make_kms_config_accepts_mr_discovery() {
    use aws_mpl_legacy::dafny::deps::aws_cryptography_keyStore::types::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a multi-Region-key discovery configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::MrDiscovery, "").unwrap(),
        KmsConfiguration::MrDiscovery(_)
    ));
}

#[test]
fn create_cache_rejects_unknown_kind() {
    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //= type=test
    //= reason=Repr 0 (the deliberately unassigned zero value) and 99 are both rejected.
    //# - The shim MUST return an error when the target cache kind is not a supported value.
    for repr in [0u8, 99] {
        let err = expect_err(create_cryptographic_materials_cache(&ffi::CacheType {
            kind: ffi::CacheKind { repr },
            entry_capacity: 0,
            entry_pruning_tail_size: unset_u32(),
            shared: std::ptr::null(),
        }));
        assert!(
            err.contains("unrecognized or unset cache kind"),
            "unexpected error: {err}"
        );
    }
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
fn user_agent_form_and_append() {
    //= spec/shim/esdk-shim.md#service-client-configuration
    //= type=test
    //# - The shim MUST set a user-agent on each service client of the form
    //# `AwsEncryptionSdk-Shim-<target-language>-<core-language>-<version>`, where
    //# `<target-language>` is the target language, `<core-language>` is the core
    //# ESDK's implementation language, and `<version>` is the shim's published version.
    let ua = shim_user_agent();
    assert_eq!(merge_user_agent("", &ua), ua);
    assert!(ua.starts_with("AwsEncryptionSdk-Shim-C++-Rust-"));

    //= spec/shim/esdk-shim.md#service-client-configuration
    //= type=test
    //# - The shim MUST preserve any user-agent already present in the loaded
    //# configuration, appending its own rather than replacing it.
    let merged = merge_user_agent("existing-agent/1.0", &ua);
    assert!(
        merged.starts_with("existing-agent/1.0"),
        "must preserve existing: {merged}"
    );
    assert!(merged.contains(&ua), "must append shim UA: {merged}");
}

#[test]
fn create_sdk_config_defers_retry_when_unset() {
    let default_ref = TOKIO_RUNTIME.block_on(aws_config::load_defaults(
        aws_config::BehaviorVersion::latest(),
    ));
    let sdk = create_sdk_config(&unset_client_config()).expect("build sdk config");
    //= spec/shim/esdk-shim.md#service-client-configuration
    //= type=test
    //# - If the target does not supply a retry configuration, the shim MUST defer to
    //# the core ESDK's default retry configuration and MUST NOT substitute its own.
    assert_eq!(
        sdk.retry_config().map(|r| r.max_attempts()),
        default_ref.retry_config().map(|r| r.max_attempts())
    );
}

#[test]
fn create_sdk_config_applies_region_retry_and_user_agent() {
    let mut cfg = unset_client_config();
    cfg.region = ffi::OptString {
        set: true,
        value: "us-west-2".to_string(),
    };
    cfg.retry.max_attempts = set_u32(7);
    let sdk = create_sdk_config(&cfg).expect("build sdk config");

    let region: Option<&str> = sdk.region().map(|r| r.as_ref());
    //= spec/shim/esdk-shim.md#service-client-configuration
    //= type=test
    //# - If the target supplies a region, the shim MUST apply it to each service client.
    assert_eq!(region, Some("us-west-2"));

    //= spec/shim/esdk-shim.md#service-client-configuration
    //= type=test
    //# - If the target supplies a retry configuration, the shim MUST apply it to each
    //# service client.
    assert_eq!(sdk.retry_config().map(|r| r.max_attempts()), Some(7));

    let app_name: &str = sdk.app_name().expect("app name is set").as_ref();
    assert!(app_name.contains("AwsEncryptionSdk-Shim-C++-Rust-"));
}

fn test_raw_aes_keyring() -> Box<Keyring> {
    create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 32],
        wrapping_alg: ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16,
    })
    .expect("create raw AES keyring")
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

// Each value differs from the ESDK Rust default, so a dropped assignment fails.
#[test]
fn apply_encrypt_options_forwards_every_optional_input() {
    use aws_mpl_legacy::commitment::EsdkCommitmentPolicy as C;
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
    use aws_mpl_legacy::commitment::EsdkCommitmentPolicy as C;
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

// The C++ facade releases resources by dropping their `rust::Box`, so these
// explicit bridge deletes have no facade caller; exercise each release path here.
#[test]
fn delete_releases_client_keyring_and_cache() {
    delete_kms_client(create_kms_client(&unset_client_config()).expect("kms client"))
        .expect("delete kms client");
    delete_ddb_client(create_ddb_client(&unset_client_config()).expect("ddb client"))
        .expect("delete ddb client");
    delete_keyring(test_raw_aes_keyring()).expect("delete keyring");
    let cache = create_cryptographic_materials_cache(&ffi::CacheType {
        kind: ffi::CacheKind { repr: 1 }, // No
        entry_capacity: 0,
        entry_pruning_tail_size: unset_u32(),
        shared: std::ptr::null(),
    })
    .expect("cache");
    delete_cryptographic_materials_cache(cache).expect("delete cache");
}

#[test]
fn delete_keystore_releases_the_key_store() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");
    let mut cfg = unset_keystore_config();
    cfg.kms_client = &*kms as *const MplKmsClient;
    cfg.ddb_client = &*ddb as *const MplDdbClient;
    cfg.ddb_table_name = "test-key-store-table".to_string();
    cfg.logical_key_store_name = "test-key-store-table".to_string();
    cfg.kms_configuration_type = ffi::KmsConfigurationType::KmsKeyArn;
    cfg.kms_configuration_value = "arn:aws:kms:us-west-2:000000000000:key/test".to_string();
    let keystore = create_keystore(&cfg).expect("key store");
    delete_keystore(keystore).expect("delete key store");
}

// Covers the adaptive-mode branch of make_retry_config; the retry-config
// requirement is cited by create_sdk_config_applies_region_retry_and_user_agent.
#[test]
fn create_sdk_config_applies_adaptive_retry_mode() {
    let mut cfg = unset_client_config();
    cfg.retry.mode_adaptive = true;
    let sdk = create_sdk_config(&cfg).expect("build sdk config");
    assert_eq!(
        sdk.retry_config().map(|r| r.mode()),
        Some(aws_config::retry::RetryConfig::adaptive().mode())
    );
}

// into_keyring_handle backs the C++ `Keyring::adopt` path, which test_esdk does
// not exercise; check it yields an owned Box<Keyring> pointer.
#[test]
fn into_keyring_handle_boxes_the_keyring() {
    let keyring = test_raw_aes_keyring();
    let handle = into_keyring_handle(keyring.client.clone());
    assert!(!handle.is_null());
    // Reclaim ownership so nothing leaks; a non-Keyring pointer would corrupt here.
    unsafe { drop(Box::from_raw(handle.cast::<Keyring>())) };
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

#[test]
fn channel_reader_and_writer_debug() {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let reader = ChannelReader {
        rx: std::sync::Mutex::new(rx),
        pending: Vec::new(),
        offset: 0,
    };
    assert_eq!(format!("{reader:?}"), "ChannelReader");
    let writer = ChannelWriter { tx };
    assert_eq!(format!("{writer:?}"), "ChannelWriter");
}

#[test]
fn channel_writer_flush_is_noop_and_reports_broken_pipe() {
    use std::io::Write;
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut writer = ChannelWriter { tx };
    writer.flush().expect("flush is a no-op");
    // A non-empty write forwards the bytes and returns the count.
    assert_eq!(writer.write(b"data").expect("write succeeds"), 4);
    assert_eq!(rx.recv().unwrap(), b"data");
    // An empty write is a no-op poll.
    assert_eq!(writer.write(b"").expect("empty write"), 0);
    // Receiver gone: a non-empty write reports the broken pipe.
    drop(rx);
    let err = writer
        .write(b"more")
        .expect_err("write must fail once the receiver is gone");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

// A panicking worker: finish joins it and reports the panic. The worker's
// panic message prints to stderr; the join converts it to an error.
#[test]
fn stream_finish_surfaces_worker_panic() {
    let mut state = StreamState::spawn("test_stream", |_reader, _writer| panic!("worker boom"));
    let err = expect_err(state.finish());
    assert!(
        err.contains("stream worker panicked"),
        "unexpected error: {err}"
    );
}

// A worker that fails drops its reader; the next write can't send and must
// surface the worker's error rather than report success.
#[test]
fn stream_write_after_worker_failure_surfaces_error() {
    let mut state = StreamState::spawn("test_stream", |_reader, _writer| {
        Err("worker failed".to_string())
    });
    let mut surfaced = None;
    for _ in 0..200 {
        match state.write(b"data") {
            Ok(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
            Err(e) => {
                surfaced = Some(e);
                break;
            }
        }
    }
    let err = surfaced.expect("write must surface the failed worker");
    assert!(err.contains("worker failed"), "unexpected error: {err}");
}

fn keystore_config_with_clients(kms: &MplKmsClient, ddb: &MplDdbClient) -> ffi::KeyStoreConfig {
    let mut cfg = unset_keystore_config();
    cfg.kms_client = kms as *const MplKmsClient;
    cfg.ddb_client = ddb as *const MplDdbClient;
    cfg.ddb_table_name = "valid-table-name".to_string();
    cfg.logical_key_store_name = "valid-table-name".to_string();
    cfg.kms_configuration_type = ffi::KmsConfigurationType::KmsKeyArn;
    cfg.kms_configuration_value = "arn:aws:kms:us-west-2:000000000000:key/test".to_string();
    cfg
}

// An unset KMS configuration type is inexpressible through the facade (its
// KeyStore constructor always supplies a key ARN), so the rejection pins here.
#[test]
fn create_keystore_rejects_unset_kms_config_type() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");
    let mut unset_kms = keystore_config_with_clients(&kms, &ddb);
    unset_kms.kms_configuration_type = ffi::KmsConfigurationType::Unset;
    let err = expect_err(create_keystore(&unset_kms));
    assert!(
        err.contains("kms_configuration_type is unset"),
        "unexpected error: {err}"
    );
}

#[test]
fn create_hierarchical_keyring_reports_bad_cache() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");
    let keystore = create_keystore(&keystore_config_with_clients(&kms, &ddb)).expect("key store");

    let mut input = unset_hierarchical_keyring_input();
    input.key_store = &*keystore as *const KeyStore;
    input.cache = ffi::OptCacheType {
        set: true,
        value: ffi::CacheType {
            kind: ffi::CacheKind { repr: 99 },
            entry_capacity: 0,
            entry_pruning_tail_size: unset_u32(),
            shared: std::ptr::null(),
        },
    };
    let err = expect_err(create_hierarchical_keyring(&input));
    assert!(
        err.contains("unrecognized or unset cache kind"),
        "unexpected error: {err}"
    );
}
