//! Bridge-internal tests: translation helpers, null-handle checks, and inputs
//! the facade cannot express. Everything here runs offline. Facade-observable
//! behavior, including the credentialed integration coverage, lives in the C++
//! suites under tests/. The error wire encoding has no test of its own: every
//! C++ typed-exception check on a Rust-produced error covers the encode and
//! decode end to end.

use super::*;
use aws_crypto_mpl::keystore::Keystore as _;
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
const ZERO_DURATION: ffi::Duration = ffi::Duration { secs: 0, nanos: 0 };

fn unset_cache() -> ffi::OptCacheType {
    ffi::OptCacheType {
        set: false,
        value: ffi::CacheType {
            kind: ffi::CacheKind { repr: 0 },
            entry_capacity: 0,
            entry_pruning_tail_size: 0,
            grace_period: ZERO_DURATION,
            grace_interval: ZERO_DURATION,
            fan_out: 0,
            inflight_ttl: ZERO_DURATION,
            sleep: ZERO_DURATION,
            shared: std::ptr::null(),
        },
    }
}

fn test_keyring() -> Box<Keyring> {
    create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x2A; 32],
        wrapping_alg: ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16,
    })
    .expect("raw AES keyring should build")
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

fn unset_hierarchical_keyring_input() -> ffi::HierarchicalKeyringInput {
    ffi::HierarchicalKeyringInput {
        branch_key_id: String::new(),
        key_store: std::ptr::null(),
        ttl: ffi::Duration { secs: 0, nanos: 0 },
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
    use super::EsdkAlgorithmSuiteId as C;
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
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
    assert!(alg_id_target_to_core(F { repr: 0x0000 }).is_err());
}

// Catches if ESDK Rust adds a suite but C++ doesn't.
// The new id falls through to the error arm of `alg_id_core_to_target`.
#[test]
fn alg_id_core_to_target_maps_every_core_variant() {
    for &core in super::EsdkAlgorithmSuiteId::ALL {
        //= spec/shim/esdk-shim.md#algorithm-suite-identifier
        //= type=test
        //# - The shim MUST translate a core ESDK algorithm suite to the target algorithm
        //# suite identifier that has the same two-byte ID.
        let target = alg_id_core_to_target(core)
            .unwrap_or_else(|e| panic!("{core:?} has no C++ mapping: {e}"));
        assert_eq!(target.repr, u16::from_be_bytes(core.id_bytes()));
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
    use super::EsdkCommitmentPolicy as C;
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
    let mut m = aws_esdk::EncryptionContext::new();
    m.insert("k1", "v1");
    m.insert("k2", "\u{1F600}");
    let list = encryption_context_core_to_target(m.clone());
    assert_eq!(list.len(), 2);
    //= spec/shim/esdk-shim.md#encryption-context
    //= type=test
    //# - The shim MUST translate the core ESDK's encryption context, given as a
    //# key-value map, to the target's list of key-value pairs, preserving every pair
    //# and the exact key and value of each.
    for (k, v) in m.iter() {
        assert_eq!(
            list.iter().filter(|i| i.key == k && i.value == v).count(),
            1,
            "pair {k:?}={v:?} must appear exactly once"
        );
    }
    //= spec/shim/esdk-shim.md#encryption-context
    //= type=test
    //# - The shim MUST translate the target's encryption context, given as a list of
    //# key-value pairs, to the core ESDK's key-value map, preserving every pair and
    //# the exact key and value of each.
    assert_eq!(encryption_context_target_to_core(&list), m);
}

#[test]
fn encryption_context_empty() {
    let empty = aws_esdk::EncryptionContext::new();
    assert!(encryption_context_core_to_target(empty).is_empty());
    assert!(encryption_context_target_to_core(&[]).is_empty());
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
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
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
fn make_kms_config_accepts_key_arn() {
    use aws_crypto_mpl::keystore::KmsConfiguration;
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
    use aws_crypto_mpl::keystore::KmsConfiguration;
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
    use aws_crypto_mpl::keystore::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a discovery configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::Discovery, "").unwrap(),
        KmsConfiguration::Discovery
    ));
}

#[test]
fn make_kms_config_accepts_mr_discovery() {
    use aws_crypto_mpl::keystore::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a multi-Region-key discovery configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::MrDiscovery, "us-west-2").unwrap(),
        KmsConfiguration::MrDiscovery { region } if region == "us-west-2"
    ));
}

#[test]
fn make_kms_config_rejects_unknown_type() {
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST return an error when the target KMS configuration type is not a
    //# supported value.
    let err = make_kms_config(ffi::KmsConfigurationType { repr: 99 }, "").unwrap_err();
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
    let err = make_kms_config(ffi::KmsConfigurationType::Unset, "").unwrap_err();
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
}

#[test]
fn classify_core_error_maps_each_kind_to_the_same_name() {
    use aws_esdk::ErrorKind as E;
    use ffi::ShimErrorKind as S;
    let cases = [
        (E::Validation, S::Validation),
        (E::Serialization, S::Serialization),
        (E::Cryptographic, S::Cryptographic),
        (E::InvalidMaterials, S::InvalidMaterials),
        (E::EncryptionContextMismatch, S::EncryptionContextMismatch),
        (E::NoMatchingDataKey, S::NoMatchingDataKey),
        (E::RemoteAccessDenied, S::RemoteAccessDenied),
        (E::RemoteResourceNotFound, S::RemoteResourceNotFound),
        (E::RemoteThrottled, S::RemoteThrottled),
        (E::RemoteTransport, S::RemoteTransport),
        (E::Remote, S::Remote),
        (E::Internal, S::Internal),
        (E::Io, S::Io),
    ];
    for (kind, expected) in cases {
        assert_eq!(
            classify_core_error(kind).repr,
            expected.repr,
            "for {kind:?}"
        );
    }
}

/// The `{kind}{SEP}{retryable}{SEP}` prefix the facade decodes.
fn err_prefix(kind: ffi::ShimErrorKind, retryable: bool) -> String {
    format!(
        "{}{ERROR_KIND_SEPARATOR}{}{ERROR_KIND_SEPARATOR}",
        kind.repr,
        u8::from(retryable)
    )
}

#[test]
fn core_err_encodes_an_mpl_errors_kind_and_retryability() {
    use aws_crypto_mpl::{Error as MplError, ErrorKind as MplErrorKind};
    let cases = [
        (
            MplError::new(MplErrorKind::NoMatchingDataKey, "x"),
            ffi::ShimErrorKind::NoMatchingDataKey,
            false,
        ),
        (
            MplError::new(MplErrorKind::RemoteThrottled, "x"),
            ffi::ShimErrorKind::RemoteThrottled,
            true,
        ),
        (
            MplError::new(MplErrorKind::Validation, "x"),
            ffi::ShimErrorKind::Validation,
            false,
        ),
    ];
    for (e, kind, retryable) in cases {
        let err = core_err("op", e);
        assert!(
            err.starts_with(&err_prefix(kind, retryable)),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn shim_err_is_not_retryable() {
    let err = shim_err(ffi::ShimErrorKind::Validation, "op", "x");
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
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
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
}

#[test]
fn decrypt_rejects_null_keyring() {
    let err = expect_err(decrypt(&unset_decrypt_input()));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
}

#[test]
fn create_keystore_defaults_absent_clients() {
    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - Creating a key store MAY be supplied with a KMS client and a DynamoDB client,
    //# each checked as defined in
    //# [Shim Specification: Handles and lifetimes](./shim.md#handles-and-lifetimes); a
    //# supplied client MUST be provided to the core ESDK, and an absent one MUST be
    //# left for the core ESDK to default.
    // Neither client is supplied (both handles null); the core ESDK builds its own,
    // so key-store creation still succeeds.
    let mut cfg = unset_keystore_config();
    cfg.ddb_table_name = "valid-table-name".to_string();
    cfg.logical_key_store_name = "valid-table-name".to_string();
    cfg.kms_configuration_type = ffi::KmsConfigurationType::KmsKeyArn;
    cfg.kms_configuration_value = "arn:aws:kms:us-west-2:000000000000:key/test".to_string();
    assert!(cfg.kms_client.is_null() && cfg.ddb_client.is_null());
    create_keystore(&cfg).expect("key store should build with defaulted clients");
}

#[test]
fn create_keystore_rejects_unset_kms_config_type() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");
    let mut unset_kms = keystore_config_with_clients(&kms, &ddb);
    // An unset KMS configuration type is inexpressible through the facade
    // (KeyStore constructor always supplies a key ARN)
    // so the rejection pins here.
    unset_kms.kms_configuration_type = ffi::KmsConfigurationType::Unset;
    let err = expect_err(create_keystore(&unset_kms));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
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
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
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
            entry_pruning_tail_size: 0,
            grace_period: ZERO_DURATION,
            grace_interval: ZERO_DURATION,
            fan_out: 0,
            inflight_ttl: ZERO_DURATION,
            sleep: ZERO_DURATION,
            shared: std::ptr::null(),
        },
    };
    let err = expect_err(create_hierarchical_keyring(&input));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
}

fn hierarchical_keyring_input_with_ttl(
    keystore: &KeyStore,
    ttl: ffi::Duration,
) -> ffi::HierarchicalKeyringInput {
    let mut input = unset_hierarchical_keyring_input();
    input.key_store = keystore as *const KeyStore;
    input.branch_key_id = "branch-key-id".to_string();
    input.ttl = ttl;
    input
}

#[test]
fn create_hierarchical_keyring_passes_ttl_nanos_to_the_core() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");
    let keystore = create_keystore(&keystore_config_with_clients(&kms, &ddb)).expect("key store");

    create_hierarchical_keyring(&hierarchical_keyring_input_with_ttl(
        &keystore,
        ffi::Duration {
            secs: 0,
            nanos: 500_000_000,
        },
    ))
    .expect("a 500 ms TTL must be accepted");

    let err = expect_err(create_hierarchical_keyring(
        &hierarchical_keyring_input_with_ttl(
            &keystore,
            ffi::Duration {
                secs: u64::MAX,
                nanos: 1_000_000_000,
            },
        ),
    ));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
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
            entry_pruning_tail_size: 0,
            grace_period: ZERO_DURATION,
            grace_interval: ZERO_DURATION,
            fan_out: 0,
            inflight_ttl: ZERO_DURATION,
            sleep: ZERO_DURATION,
            shared: std::ptr::null(),
        }));
        assert!(
            err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn shared_cache_type_references_the_supplied_cache() {
    let base = ffi::CacheType {
        kind: ffi::CacheKind::Default,
        entry_capacity: 10,
        entry_pruning_tail_size: 0,
        grace_period: ZERO_DURATION,
        grace_interval: ZERO_DURATION,
        fan_out: 0,
        inflight_ttl: ZERO_DURATION,
        sleep: ZERO_DURATION,
        shared: std::ptr::null(),
    };
    let cache = create_cryptographic_materials_cache(&base).expect("default cache should build");
    let shared = ffi::CacheType {
        kind: ffi::CacheKind::Shared,
        shared: &*cache as *const CryptographicMaterialsCache,
        ..base
    };
    let Ok(CacheType::Shared(referenced)) = make_cache_type(&shared) else {
        panic!("a Shared cache kind must yield CacheType::Shared");
    };
    assert!(SharedCmc::ptr_eq(&referenced, &cache.inner));
}

fn storm_tracking_cache_input() -> ffi::CacheType {
    ffi::CacheType {
        kind: ffi::CacheKind::StormTracking,
        entry_capacity: 10,
        entry_pruning_tail_size: 1,
        grace_period: ffi::Duration { secs: 10, nanos: 0 },
        grace_interval: ffi::Duration {
            secs: 0,
            nanos: 500_000_000,
        },
        fan_out: 20,
        inflight_ttl: ffi::Duration {
            secs: 2,
            nanos: 250_000_000,
        },
        sleep: ffi::Duration {
            secs: 0,
            nanos: 20_000_000,
        },
        shared: std::ptr::null(),
    }
}

#[test]
fn create_storm_tracking_cache_passes_each_duration_to_the_core() {
    let input = storm_tracking_cache_input();
    let Ok(CacheType::StormTracking(params)) = make_cache_type(&input) else {
        panic!("storm-tracking cache input must convert to a storm-tracking cache");
    };
    assert_eq!(params.entry_capacity(), 10);
    assert_eq!(params.entry_pruning_tail_size(), 1);
    assert_eq!(params.grace_period(), Duration::from_secs(10));
    assert_eq!(params.grace_interval(), Duration::from_millis(500));
    assert_eq!(params.fan_out(), 20);
    assert_eq!(params.inflight_ttl(), Duration::from_millis(2250));
    assert_eq!(params.sleep(), Duration::from_millis(20));
    create_cryptographic_materials_cache(&input).expect("storm-tracking cache should build");
}

#[test]
fn create_storm_tracking_cache_rejects_zero_sleep() {
    let mut input = storm_tracking_cache_input();
    input.sleep = ZERO_DURATION;
    let err = expect_err(make_cache_type(&input));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
}

#[test]
fn create_storm_tracking_cache_rejects_out_of_range_durations() {
    let mut input = storm_tracking_cache_input();
    input.grace_period = ffi::Duration {
        secs: u64::MAX,
        nanos: 1_000_000_000,
    };
    let err = expect_err(make_cache_type(&input));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {err}"
    );
}

#[test]
fn opt_to_option_returns_the_value_only_when_set() {
    assert_eq!(unset_u32().to_option(), None);
    assert_eq!(set_u32(7).to_option(), Some(7));

    assert_eq!(unset_string().to_option(), None);
    let set_string = ffi::OptString {
        set: true,
        value: "v".to_string(),
    };
    assert_eq!(set_string.to_option(), Some("v".to_string()));

    // The bridge enums don't implement Debug, so compare their reprs.
    assert!(unset_alg_id().to_option().is_none());
    let alg = F::AlgAes256GcmHkdfSha512CommitKey;
    assert_eq!(set_alg_id(alg).to_option().map(|a| a.repr), Some(alg.repr));

    assert!(unset_policy().to_option().is_none());
    let policy = P::RequireEncryptRequireDecrypt;
    assert_eq!(
        set_policy(policy).to_option().map(|p| p.repr),
        Some(policy.repr)
    );

    assert!(unset_cache().to_option().is_none());
    let mut cache = unset_cache();
    cache.set = true;
    cache.value.entry_capacity = 42;
    let got = cache.to_option().expect("a set cache is Some");
    assert_eq!(got.entry_capacity, 42);
}

#[test]
fn create_keystore_forwards_id_and_grant_tokens() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");

    let unset = create_keystore(&keystore_config_with_clients(&kms, &ddb)).expect("key store");
    let info = unset.inner.get_key_store_info().expect("info");
    assert!(info.grant_tokens.is_empty());

    let mut cfg = keystore_config_with_clients(&kms, &ddb);
    cfg.id = ffi::OptString {
        set: true,
        value: "the-id".to_string(),
    };
    cfg.grant_tokens = vec!["g1".to_string(), "g2".to_string()];
    let store = create_keystore(&cfg).expect("key store");
    let info = store.inner.get_key_store_info().expect("info");
    assert_eq!(info.keystore_id, "the-id");
    assert_eq!(info.grant_tokens, vec!["g1", "g2"]);
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
        unset.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {unset}"
    );

    let unknown = expect_err(create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 32],
        wrapping_alg: ffi::AesWrappingAlg { repr: 99 },
    }));
    assert!(
        unknown.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, false)),
        "unexpected error: {unknown}"
    );
}

// Options forwarding

#[test]
fn apply_encrypt_options_forwards_every_optional_input() {
    use super::EsdkCommitmentPolicy as C;
    let input = ffi::EncryptInput {
        algorithm_suite_id: set_alg_id(F { repr: 0x0578 }),
        encryption_context: Vec::new(),
        frame_length: set_u32(1024),
        keyring: std::ptr::null(),
        plaintext: &[],
        max_encrypted_data_keys: set_u32(5),
        commitment_policy: set_policy(P::ForbidEncryptAllowDecrypt),
    };
    let builder = aws_esdk::EncryptInput::builder()
        .plaintext(&[])
        .keyring(test_keyring().inner.clone());
    let core = apply_encrypt_options(builder, &input)
        .expect("options apply")
        .build()
        .expect("input builds");

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied maximum-encrypted-data-keys value to
    //# the core ESDK, converted as defined in
    //# [Maximum encrypted data keys](#maximum-encrypted-data-keys).
    assert_eq!(
        core.max_encrypted_data_keys(),
        std::num::NonZeroUsize::new(5)
    );

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied frame length to the core ESDK,
    //# converted as defined in [Frame length](#frame-length).
    assert_eq!(core.frame_length().get(), 1024);

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied commitment policy to the core ESDK,
    //# converted as defined in [Commitment policy](#commitment-policy).
    assert_eq!(core.commitment_policy(), C::ForbidEncryptAllowDecrypt);

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied algorithm suite to the core ESDK,
    //# converted as defined in [Algorithm suite identifier](#algorithm-suite-identifier).
    assert_eq!(
        core.algorithm_suite_id(),
        Some(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
    );
}

#[test]
fn apply_encrypt_options_leaves_unset_inputs_defaulted() {
    let builder = aws_esdk::EncryptInput::builder()
        .plaintext(&[])
        .keyring(test_keyring().inner.clone());
    let core = apply_encrypt_options(builder, &unset_encrypt_input())
        .expect("options apply")
        .build()
        .expect("input builds");
    assert_eq!(core.max_encrypted_data_keys(), None);
    assert_eq!(core.frame_length().get(), 4096);
    assert_eq!(
        core.commitment_policy(),
        EsdkCommitmentPolicy::RequireEncryptRequireDecrypt
    );
    assert_eq!(core.algorithm_suite_id(), None);
}

#[test]
fn apply_decrypt_options_forwards_every_optional_input() {
    use super::EsdkCommitmentPolicy as C;
    let input = ffi::DecryptInput {
        ciphertext: &[],
        encryption_context: Vec::new(),
        keyring: std::ptr::null(),
        max_encrypted_data_keys: set_u32(7),
        commitment_policy: set_policy(P::RequireEncryptAllowDecrypt),
    };
    let builder = aws_esdk::DecryptInput::builder()
        .ciphertext(&[])
        .keyring(test_keyring().inner.clone());
    let core = apply_decrypt_options(builder, &input)
        .expect("options apply")
        .build()
        .expect("input builds");

    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied maximum-encrypted-data-keys value to
    //# the core ESDK, converted as defined in
    //# [Maximum encrypted data keys](#maximum-encrypted-data-keys).
    assert_eq!(
        core.max_encrypted_data_keys(),
        std::num::NonZeroUsize::new(7)
    );

    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied commitment policy to the core ESDK,
    //# converted as defined in [Commitment policy](#commitment-policy).
    assert_eq!(core.commitment_policy(), C::RequireEncryptAllowDecrypt);
}

#[test]
fn opt_to_option_is_some_only_when_set() {
    assert_eq!(set_u32(5).to_option(), Some(5));
    assert_eq!(unset_u32().to_option(), None);

    let region = ffi::OptString {
        set: true,
        value: "us-west-2".to_string(),
    };
    assert_eq!(region.to_option().as_deref(), Some("us-west-2"));
    assert_eq!(unset_string().to_option(), None);

    assert_eq!(
        set_alg_id(F { repr: 0x0578 }).to_option().map(|v| v.repr),
        Some(0x0578)
    );
    assert!(unset_alg_id().to_option().is_none());

    assert!(
        set_policy(P::ForbidEncryptAllowDecrypt).to_option() == Some(P::ForbidEncryptAllowDecrypt)
    );
    assert!(unset_policy().to_option().is_none());

    let mut cache = unset_cache();
    assert!(cache.to_option().is_none());
    cache.set = true;
    cache.value.entry_capacity = 9;
    assert_eq!(cache.to_option().map(|c| c.entry_capacity), Some(9));
}

// AWS SDK client configuration
// The built SdkConfig is opaque through the facade, so the values must be tested from Rust

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
fn create_sdk_config_applies_every_field() {
    let mut cfg = unset_client_config();
    cfg.region = ffi::OptString {
        set: true,
        value: "us-west-2".to_string(),
    };
    cfg.retry.max_attempts = set_u32(7);
    cfg.retry.mode_adaptive = true;
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
    assert_eq!(
        sdk.retry_config().map(|r| r.mode()),
        Some(aws_config::retry::RetryConfig::adaptive().mode())
    );

    let app_name: &str = sdk.app_name().expect("app name is set").as_ref();
    assert!(app_name.contains("AwsEncryptionSdk-Shim-C++-Rust-"));
}

// Handles

// into_keyring_handle is the Rust that backs the public C++ `Keyring::adopt` path.
// Check it yields an owned Box<Keyring> pointer. (Type only testable in Rust).
#[test]
fn into_keyring_handle_boxes_the_keyring() {
    let keyring = create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x2A; 32],
        wrapping_alg: ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16,
    })
    .expect("raw AES keyring should build");
    let handle = into_keyring_handle(keyring.inner.clone());
    assert!(!handle.is_null());
    unsafe { drop(Box::from_raw(handle.cast::<Keyring>())) };
}

// Streaming internals
//
// Stream internals (ChannelReader/ChannelWriter and the worker thread)
// are unconstructible from C++, so internals must be tested here.
// Actual streamed encrypt/decrypt behavior lives in the C++ test_streaming.

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

// A panicking worker.
// Finish will join it and surface the Rust panic as an error to C++.
#[test]
fn stream_finish_surfaces_worker_panic() {
    let mut state = StreamState::spawn("test_stream", |_reader, _writer| panic!("worker panic"));
    let err = expect_err(state.finish());
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Internal, false)),
        "unexpected error: {err}"
    );
}

// An erroring worker.
// Assert its error is raised.
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
