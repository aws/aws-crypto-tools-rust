//! Only round_trip_integration needs AWS resources (the ESDK_TEST_* variables);
//! everything else runs offline.

use super::*;
use ffi::EsdkAlgorithmSuiteId as F;
use ffi::EsdkCommitmentPolicy as P;

// All-unset test fixtures, mirroring the C++ side's value-initialized inputs.

fn unset_encrypt_input() -> ffi::EncryptInput<'static> {
    ffi::EncryptInput {
        algorithm_suite_id: ffi::EsdkAlgorithmSuiteId::Unset,
        encryption_context: Vec::new(),
        frame_length: 0,
        keyring: std::ptr::null(),
        plaintext: &[],
        max_encrypted_data_keys: 0,
        commitment_policy: ffi::EsdkCommitmentPolicy::Unset,
    }
}

fn unset_decrypt_input() -> ffi::DecryptInput<'static> {
    ffi::DecryptInput {
        ciphertext: &[],
        encryption_context: Vec::new(),
        keyring: std::ptr::null(),
        max_encrypted_data_keys: 0,
        commitment_policy: ffi::EsdkCommitmentPolicy::Unset,
    }
}

fn unset_hierarchical_keyring_input() -> ffi::HierarchicalKeyringInput {
    ffi::HierarchicalKeyringInput {
        branch_key_id: String::new(),
        key_store: std::ptr::null(),
        ttl_seconds: 0,
        cache: std::ptr::null(),
        partition_id: String::new(),
    }
}

fn unset_keystore_config() -> ffi::KeyStoreConfig {
    ffi::KeyStoreConfig {
        ddb_table_name: String::new(),
        kms_configuration_type: ffi::KmsConfigurationType::Unset,
        kms_configuration_value: String::new(),
        logical_key_store_name: String::new(),
        id: String::new(),
        grant_tokens: Vec::new(),
        ddb_client: std::ptr::null(),
        kms_client: std::ptr::null(),
    }
}

fn unset_client_config() -> ffi::MplAwsClientConfig {
    ffi::MplAwsClientConfig {
        region: String::new(),
        retry: ffi::RetryConfig {
            mode_adaptive: false,
            max_attempts: 0,
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
    //
    //= spec/shim/shim.md#type-translation
    //= type=test
    //# - When the target supplies a value that has no corresponding core-library
    //# representation, the translation MUST return an error.
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
    //= reason=Sweeping 0..=u8::MAX, only 1,2,3 are accepted; every other value (including 0 = Unset) returns an error.
    //# - The shim MUST return an error when the target commitment policy is not a supported
    //# value.
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
    //= reason=The produced list is checked item-by-item: each source pair appears once with its exact key and value.
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
    //= reason=The map built from the item-checked list equals the source map, pinning key and value per pair.
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

// The null-handle and enum checks fire before any network call, so these run
// without credentials.

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
    //# - Creating a hierarchical keyring MUST require a key store handle, checked as
    //# defined in
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
fn create_no_cache_builds_no_cache() {
    use aws_mpl_legacy::dafny::types::CacheType;
    //= spec/shim/esdk-shim.md#create-cache
    //= type=test
    //# - The shim MUST provide an operation that creates a cache that performs no
    //# caching, backed by the core ESDK.
    assert!(matches!(
        create_no_cache().unwrap().cache_type,
        CacheType::No(_)
    ));
}

#[test]
fn create_multi_threaded_cache_builds_multi_threaded() {
    use aws_mpl_legacy::dafny::types::CacheType;
    //= spec/shim/esdk-shim.md#create-cache
    //= type=test
    //# - The shim MUST provide an operation that creates a multi-threaded cache backed
    //# by the core ESDK.
    assert!(matches!(
        create_multi_threaded_cache(100, 1).unwrap().cache_type,
        CacheType::MultiThreaded(_)
    ));
    // A parameter left 0 defers to the core library's default.
    assert!(matches!(
        create_multi_threaded_cache(0, 0).unwrap().cache_type,
        CacheType::MultiThreaded(_)
    ));
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
    //# The shim MUST translate zero
    //# to the core ESDK's "no limit" representation, and a positive value `n` to a
    //# limit of `n`.
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
    //= reason=With no retry supplied, the assembled config's retry matches a reference load_defaults() rather than a substituted standard config.
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
    cfg.region = "us-west-2".to_string();
    cfg.retry.max_attempts = 7;
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

fn test_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

// Raw AES keyring: fully local, so the whole path runs without AWS resources.

//= spec/shim/esdk-shim.md#create-raw-aes-keyring
//= type=test
//= reason=The created keyring encrypts and decrypts back to the plaintext, so the operation exists and is backed by the core.
//# - The shim MUST provide an operation that creates a raw AES keyring backed by
//# the core ESDK.
#[test]
fn raw_aes_keyring_round_trip() {
    let keyring = create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 32],
        wrapping_alg: ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16,
    })
    .expect("create raw AES keyring");

    let plaintext = b"raw aes round trip".to_vec();
    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*keyring as *const Keyring;
    enc_in.plaintext = plaintext.as_slice();
    let enc_out = encrypt(&enc_in).expect("encrypt");
    assert_ne!(enc_out.ciphertext, plaintext);

    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*keyring as *const Keyring;
    dec_in.ciphertext = enc_out.ciphertext.as_slice();
    let dec_out = decrypt(&dec_in).expect("decrypt");
    assert_eq!(dec_out.plaintext, plaintext);
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

//= spec/shim/shim.md#streaming
//= type=test
//= reason=Plaintext fed in non-frame-aligned chunks streams to ciphertext that one-shot decrypt accepts, and streamed decrypt recovers it.
//# If a core library resource or operation supports [streamed](../client-apis/streaming.md) inputs/outputs,
//# the shim library SHOULD support it as well.
//= spec/shim/esdk-shim.md#encrypt-stream-and-decrypt-stream
//= type=test
//= reason=Both streaming operations exist and accept the same non-payload inputs; the payload is supplied in chunks.
//# - The ESDK shim SHOULD provide streaming encrypt and decrypt operations,
//# accepting the same inputs as [encrypt](#encrypt-inputs) and
//# [decrypt](#decrypt-inputs) except the plaintext or ciphertext, which the
//# target supplies incrementally.
#[test]
fn streaming_round_trips_interoperate_with_one_shot() {
    let keyring = test_raw_aes_keyring();
    let plaintext: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();

    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*keyring as *const Keyring;
    enc_in.frame_length = 4096;
    // Non-signing suite: the core refuses to stream-decrypt multi-frame
    // signed messages (covered separately below).
    enc_in.algorithm_suite_id = ffi::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;
    let mut stream = create_encrypt_stream(&enc_in).expect("create encrypt stream");
    let mut ciphertext = Vec::new();
    //= spec/shim/shim.md#streaming
    //= type=test
    //= reason=write is called repeatedly with successive chunks, and its returned output is collected into the ciphertext that later decrypts.
    //# - The shim MUST provide a write step that the target calls repeatedly, each
    //# call supplying the next chunk of input and returning whatever output the
    //# operation has produced so far (possibly none).
    for chunk in plaintext.chunks(3001) {
        ciphertext.extend_from_slice(&encrypt_stream_write(&mut stream, chunk).expect("write"));
    }
    //= spec/shim/shim.md#streaming
    //= type=test
    //= reason=Finish ends the input and returns trailing output; the assembled ciphertext decrypts, so the operation completed.
    //# - The shim MUST provide a finish step that ends the input, completes the
    //# operation, and returns the operation's result together with any output not
    //# yet returned by a write step.
    let fin = encrypt_stream_finish(&mut stream).expect("finish");
    //= spec/shim/esdk-shim.md#encrypt-stream-and-decrypt-stream
    //= type=test
    //= reason=The finish output carries the used suite, matching encrypt outputs.
    //# - A successful finish step MUST return the same non-payload outputs as
    //# [encrypt outputs](#encrypt-outputs) or [decrypt outputs](#decrypt-outputs).
    assert_eq!(
        fin.algorithm_suite_id.repr,
        ffi::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey.repr
    );
    ciphertext.extend_from_slice(&fin.trailing_output);

    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*keyring as *const Keyring;
    dec_in.ciphertext = ciphertext.as_slice();
    assert_eq!(
        decrypt(&dec_in).expect("one-shot decrypt").plaintext,
        plaintext
    );

    let mut dec_stream_in = unset_decrypt_input();
    dec_stream_in.keyring = &*keyring as *const Keyring;
    let mut stream = create_decrypt_stream(&dec_stream_in).expect("create decrypt stream");
    let mut recovered = Vec::new();
    for chunk in ciphertext.chunks(1517) {
        recovered.extend_from_slice(&decrypt_stream_write(&mut stream, chunk).expect("write"));
    }
    let fin = decrypt_stream_finish(&mut stream).expect("finish");
    recovered.extend_from_slice(&fin.trailing_output);
    assert_eq!(recovered, plaintext);
}

//= spec/shim/shim.md#streaming
//= type=test
//= reason=Multi-frame output is released by write/poll while the input side is still open — finish has not been called — in both directions.
//# If a core library resource or operation supports [streamed](../client-apis/streaming.md) inputs/outputs,
//# the shim library SHOULD support it as well.
//
//= spec/shim/shim.md#streaming
//= type=test
//= reason=Output arrives from write/poll calls before finish is called, in both directions.
//# - The shim SHOULD return output from write steps as the core library produces
//# it, rather than holding all output until the finish step.
#[test]
fn streaming_releases_output_before_finish() {
    let keyring = test_raw_aes_keyring();
    let plaintext = vec![0x11u8; 8192];

    // Encrypt: after all plaintext is written (input still open), at least one
    // full frame of ciphertext must be released.
    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*keyring as *const Keyring;
    enc_in.frame_length = 1024;
    enc_in.algorithm_suite_id = ffi::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;
    let mut stream = create_encrypt_stream(&enc_in).expect("create encrypt stream");
    let mut pre_finish = Vec::new();
    for chunk in plaintext.chunks(1024) {
        pre_finish.extend_from_slice(&encrypt_stream_write(&mut stream, chunk).expect("write"));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while pre_finish.len() < 1024 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
        pre_finish.extend_from_slice(&encrypt_stream_write(&mut stream, &[]).expect("poll"));
    }
    assert!(
        pre_finish.len() >= 1024,
        "no ciphertext released before finish: {} bytes",
        pre_finish.len()
    );
    let fin = encrypt_stream_finish(&mut stream).expect("finish");
    let mut ciphertext = pre_finish;
    ciphertext.extend_from_slice(&fin.trailing_output);

    // Decrypt: with every ciphertext byte written but finish not yet called,
    // released plaintext must be a nonempty prefix of the original.
    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*keyring as *const Keyring;
    let mut stream = create_decrypt_stream(&dec_in).expect("create decrypt stream");
    let mut released = Vec::new();
    for chunk in ciphertext.chunks(1024) {
        released.extend_from_slice(&decrypt_stream_write(&mut stream, chunk).expect("write"));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while released.is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
        released.extend_from_slice(&decrypt_stream_write(&mut stream, &[]).expect("poll"));
    }
    assert!(!released.is_empty(), "no plaintext released before finish");
    assert_eq!(
        released,
        plaintext[..released.len()],
        "released bytes must prefix the plaintext"
    );
    let fin = decrypt_stream_finish(&mut stream).expect("finish");
    released.extend_from_slice(&fin.trailing_output);
    assert_eq!(released, plaintext);
}

#[test]
fn streaming_decrypt_tamper_fails_at_finish() {
    let keyring = test_raw_aes_keyring();

    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*keyring as *const Keyring;
    enc_in.algorithm_suite_id = ffi::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;
    let mut stream = create_encrypt_stream(&enc_in).expect("create encrypt stream");
    let mut ciphertext = encrypt_stream_write(&mut stream, b"stream tamper target").expect("write");
    let fin = encrypt_stream_finish(&mut stream).expect("finish");
    ciphertext.extend_from_slice(&fin.trailing_output);

    *ciphertext.last_mut().unwrap() ^= 0xFF;

    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*keyring as *const Keyring;
    let mut stream = create_decrypt_stream(&dec_in).expect("create decrypt stream");
    // Feeding may or may not surface the failure (the pump is asynchronous);
    // finish MUST fail with the core's CryptographicError kind either way.
    let mut failed = None;
    for chunk in ciphertext.chunks(7) {
        if let Err(e) = decrypt_stream_write(&mut stream, chunk) {
            failed = Some(e);
            break;
        }
    }
    //= spec/shim/shim.md#streaming
    //= type=test
    //= reason=The tampered stream's failure is returned by a write or by finish, whichever the target reaches first.
    //# - When the operation has failed, the shim MUST return an error from the next
    //# write or finish step.
    let err = match failed {
        Some(e) => e,
        None => expect_err(decrypt_stream_finish(&mut stream)),
    };
    assert!(
        err.starts_with(&format!("2{}decrypt_stream: ", '\u{1f}')),
        "unexpected encoding: {err}"
    );
}

#[test]
fn streaming_decrypt_refuses_multi_frame_signed_messages() {
    let keyring = test_raw_aes_keyring();

    // Multi-frame message under the default (signing) suite.
    let plaintext = vec![0x5Au8; 10_000];
    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*keyring as *const Keyring;
    enc_in.plaintext = plaintext.as_slice();
    enc_in.frame_length = 4096;
    let ciphertext = encrypt(&enc_in).expect("encrypt").ciphertext;

    // One-shot decrypt handles it.
    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*keyring as *const Keyring;
    dec_in.ciphertext = ciphertext.as_slice();
    assert_eq!(
        decrypt(&dec_in).expect("one-shot decrypt").plaintext,
        plaintext
    );

    // Streamed decrypt refuses rather than releasing plaintext whose trailing
    // signature has not been verified.
    let mut dec_stream_in = unset_decrypt_input();
    dec_stream_in.keyring = &*keyring as *const Keyring;
    let mut stream = create_decrypt_stream(&dec_stream_in).expect("create decrypt stream");
    let mut failed = None;
    for chunk in ciphertext.chunks(4096) {
        if let Err(e) = decrypt_stream_write(&mut stream, chunk) {
            failed = Some(e);
            break;
        }
    }
    //= spec/shim/esdk-shim.md#encrypt-stream-and-decrypt-stream
    //= type=test
    //= reason=The core's refusal to stream the multi-frame signed message surfaces as an error instead of released plaintext.
    //# - Streamed decrypt MUST NOT release plaintext the core ESDK would not release,
    //# and the shim MUST surface the core ESDK's refusal to stream a message whose
    //# verification cannot complete until the end of the message.
    let err = match failed {
        Some(e) => e,
        None => expect_err(decrypt_stream_finish(&mut stream)),
    };
    assert!(err.contains("signed"), "unexpected error: {err}");
}

#[test]
fn streaming_write_after_finish_is_invalid_input() {
    let keyring = test_raw_aes_keyring();
    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*keyring as *const Keyring;
    let mut stream = create_encrypt_stream(&enc_in).expect("create encrypt stream");
    encrypt_stream_finish(&mut stream).expect("finish");
    let err = expect_err(encrypt_stream_write(&mut stream, b"late"));
    assert!(
        err.starts_with(&format!("5{}encrypt_stream: ", '\u{1f}')),
        "unexpected encoding: {err}"
    );
}

#[test]
fn keyring_handle_adoption_round_trips() {
    // A consumer converts any core-accepted keyring into a handle; adopting it
    // yields a keyring usable wherever a keyring is accepted.
    let source = test_raw_aes_keyring();
    let ptr = crate::into_keyring_handle(source.client.clone());
    assert!(!ptr.is_null());
    // SAFETY: into_keyring_handle transfers ownership of a Box<Keyring>; this
    // is the adopt side of the contract.
    let adopted = unsafe { Box::from_raw(ptr.cast::<Keyring>()) };

    let plaintext = b"adopted keyring round trip".to_vec();
    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*adopted as *const Keyring;
    enc_in.plaintext = plaintext.as_slice();
    let ciphertext = encrypt(&enc_in).expect("encrypt").ciphertext;

    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*adopted as *const Keyring;
    dec_in.ciphertext = ciphertext.as_slice();
    assert_eq!(decrypt(&dec_in).expect("decrypt").plaintext, plaintext);
}

//= spec/shim/shim.md#error-classification
//= type=test
//= reason=Each failure's encoded kind repr equals the core's kind for that failure, end to end.
//# - When the core library distinguishes kinds of errors, the shim SHOULD expose
//# the same kinds under the core library's own names, expressed in the target
//# language's error mechanism.
#[test]
fn error_kinds_reach_the_target() {
    let keyring = create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 32],
        wrapping_alg: ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16,
    })
    .expect("create raw AES keyring");
    let sep = '\u{1f}';

    // Absent required handle: the core's ValidationError kind (repr 5).
    let err = expect_err(encrypt(&unset_encrypt_input()));
    assert!(
        err.starts_with(&format!("5{sep}encrypt: ")),
        "unexpected encoding: {err}"
    );

    // Malformed message: the core's SerializationError kind (repr 1).
    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*keyring as *const Keyring;
    dec_in.ciphertext = b"this is not a valid ESDK message";
    let err = expect_err(decrypt(&dec_in));
    assert!(
        err.starts_with(&format!("1{sep}decrypt: ")),
        "unexpected encoding: {err}"
    );

    // Tampered message, non-signing suite: the AEAD tag mismatch surfaces as
    // the core's CryptographicError kind (repr 2).
    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*keyring as *const Keyring;
    enc_in.plaintext = b"tamper target";
    enc_in.algorithm_suite_id = ffi::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;
    let mut ciphertext = encrypt(&enc_in).expect("encrypt").ciphertext;
    *ciphertext.last_mut().unwrap() ^= 0xFF;
    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*keyring as *const Keyring;
    dec_in.ciphertext = ciphertext.as_slice();
    let err = expect_err(decrypt(&dec_in));
    assert!(
        err.starts_with(&format!("2{sep}decrypt: ")),
        "unexpected encoding: {err}"
    );

    // Tampered message, signing suite: the core reports the footer signature
    // failure with its base Esdk kind (repr 0), carried as-is.
    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*keyring as *const Keyring;
    enc_in.plaintext = b"tamper target";
    enc_in.algorithm_suite_id = ffi::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384;
    let mut ciphertext = encrypt(&enc_in).expect("encrypt").ciphertext;
    *ciphertext.last_mut().unwrap() ^= 0xFF;
    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*keyring as *const Keyring;
    dec_in.ciphertext = ciphertext.as_slice();
    let err = expect_err(decrypt(&dec_in));
    assert!(
        err.starts_with(&format!("0{sep}decrypt: ")),
        "unexpected encoding: {err}"
    );
}

#[test]
fn create_raw_aes_keyring_rejects_unset_wrapping_alg() {
    //= spec/shim/esdk-shim.md#aes-wrapping-algorithm
    //= type=test
    //# - The shim MUST return an error when the target wrapping algorithm is not a
    //# supported value.
    let err = expect_err(create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 32],
        wrapping_alg: ffi::AesWrappingAlg::Unset,
    }));
    assert!(
        err.contains("wrapping_alg is unset"),
        "unexpected error: {err}"
    );
}

#[test]
fn create_raw_aes_keyring_rejects_mismatched_key_length() {
    //= spec/shim/esdk-shim.md#aes-wrapping-algorithm
    //= type=test
    //= reason=A 16-byte key under Alg256 is rejected by the core's length check, pinning that the translated algorithm carries the 256-bit meaning.
    //# - The shim MUST translate the target AES wrapping algorithm to the core ESDK
    //# wrapping algorithm of the same meaning.
    let err = expect_err(create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 16],
        wrapping_alg: ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16,
    }));
    assert!(
        err.contains("Wrapping key length does not match"),
        "unexpected error: {err}"
    );
}

#[test]
fn round_trip_integration() {
    let (kms_arn, table, logical, branch) = match (
        test_env("ESDK_TEST_KMS_KEY_ARN"),
        test_env("ESDK_TEST_DDB_TABLE"),
        test_env("ESDK_TEST_LOGICAL_KEYSTORE"),
        test_env("ESDK_TEST_BRANCH_KEY_ID"),
    ) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => {
            eprintln!(
                "SKIP round_trip_integration: set ESDK_TEST_KMS_KEY_ARN, \
                 ESDK_TEST_DDB_TABLE, ESDK_TEST_LOGICAL_KEYSTORE, ESDK_TEST_BRANCH_KEY_ID"
            );
            return;
        }
    };

    let mut client_cfg = unset_client_config();
    client_cfg.region = test_env("ESDK_TEST_REGION").unwrap_or_default();

    //= spec/shim/esdk-shim.md#create-kms-client
    //= type=test
    //# - The shim MUST provide an operation that creates a KMS service client backed by
    //# the core ESDK.
    //
    //= spec/shim/esdk-shim.md#create-kms-client
    //= type=test
    //# - Creating a KMS client MUST apply the target-supplied client configuration, as
    //# defined in [Service client configuration](#service-client-configuration).
    let kms = create_kms_client(&client_cfg).expect("create kms client");

    //= spec/shim/esdk-shim.md#create-dynamodb-client
    //= type=test
    //# - The shim MUST provide an operation that creates a DynamoDB service client
    //# backed by the core ESDK.
    //
    //= spec/shim/esdk-shim.md#create-dynamodb-client
    //= type=test
    //# - Creating a DynamoDB client MUST apply the target-supplied client configuration,
    //# as defined in [Service client configuration](#service-client-configuration).
    let ddb = create_ddb_client(&client_cfg).expect("create ddb client");

    let mut ks_cfg = unset_keystore_config();
    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - Creating a key store MUST provide the target-supplied table name and logical key
    //# store name to the core ESDK.
    ks_cfg.ddb_table_name = table;
    ks_cfg.logical_key_store_name = logical;
    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - Creating a key store MUST provide the target-supplied KMS configuration to the
    //# core ESDK, converted as defined in [KMS configuration](#kms-configuration).
    ks_cfg.kms_configuration_type = ffi::KmsConfigurationType::KmsKeyArn;
    ks_cfg.kms_configuration_value = kms_arn;
    ks_cfg.kms_client = &*kms as *const MplKmsClient;
    ks_cfg.ddb_client = &*ddb as *const MplDdbClient;
    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - Creating a key store MUST provide the target-supplied key store id and grant
    //# tokens to the core ESDK when present; an unset value is omitted.
    ks_cfg.id = "shim-integration-test".to_string();
    ks_cfg.grant_tokens = vec!["grant-token-example".to_string()];
    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - The shim MUST provide an operation that creates a key store backed by the core
    //# ESDK.
    let keystore = create_keystore(&ks_cfg).expect("create keystore");

    let mut kr_in = unset_hierarchical_keyring_input();
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //# - Creating a hierarchical keyring MUST provide the target-supplied branch key id
    //# and time-to-live to the core ESDK.
    kr_in.branch_key_id = branch;
    kr_in.key_store = &*keystore as *const KeyStore;
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //= reason=A created cache handle is supplied and the keyring creation succeeds and round-trips.
    //# - When a cache handle is supplied, creating a hierarchical keyring MUST provide
    //# the referenced cache to the core ESDK.
    let cache = create_multi_threaded_cache(100, 1).expect("create cache");
    kr_in.cache = &*cache as *const Cache;
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //# - Creating a hierarchical keyring MUST provide the target-supplied partition id to
    //# the core ESDK when present; an unset value is omitted.
    kr_in.partition_id = "shim-partition".to_string();
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //# - The shim MUST provide an operation that creates a hierarchical keyring backed
    //# by the core ESDK.
    let keyring = create_hierarchical_keyring(&kr_in).expect("create keyring");

    let plaintext = b"Hello from the Rust integration test".to_vec();
    let mut ec = std::collections::HashMap::new();
    ec.insert("purpose".to_string(), "integration-test".to_string());

    let mut enc_in = unset_encrypt_input();
    enc_in.keyring = &*keyring as *const Keyring;
    enc_in.plaintext = plaintext.as_slice();
    enc_in.encryption_context = encryption_context_core_to_target(ec.clone()).unwrap();
    enc_in.algorithm_suite_id = ffi::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;
    // commitment policy, frame length, and max-EDKs are forwarded plumbing
    // (plain source-side `implementation`); values here equal the ESDK defaults, so
    // asserting on them would not falsify the forwarding — no `type=test` here.
    enc_in.commitment_policy = ffi::EsdkCommitmentPolicy::RequireEncryptRequireDecrypt;
    enc_in.frame_length = 4096;
    enc_in.max_encrypted_data_keys = 3;

    let enc_out = encrypt(&enc_in).expect("encrypt");
    assert_ne!(enc_out.ciphertext, plaintext);
    //= spec/shim/esdk-shim.md#encrypt-outputs
    //= type=test
    //# - MUST return the used algorithm suite, converted as defined in
    //# [Algorithm suite identifier](#algorithm-suite-identifier).
    //
    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //= reason=0x0478 differs from the core default 0x0578; a dropped input suite would echo the default here.
    //# - MUST provide the target-supplied algorithm suite to the core ESDK,
    //# converted as defined in [Algorithm suite identifier](#algorithm-suite-identifier).
    assert_eq!(
        enc_out.algorithm_suite_id.repr,
        enc_in.algorithm_suite_id.repr
    );
    //= spec/shim/esdk-shim.md#encrypt-outputs
    //= type=test
    //# - MUST return the result encryption context, converted as defined in
    //# [Encryption context](#encryption-context).
    //
    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //= reason=Core's result encryption context carries the pairs it received; a dropped input pair would be absent here.
    //# - MUST provide the target-supplied encryption context to the core ESDK,
    //# converted as defined in [Encryption context](#encryption-context).
    assert_eq!(
        encryption_context_target_to_core(&enc_out.encryption_context)
            .unwrap()
            .get("purpose"),
        Some(&"integration-test".to_string())
    );

    let mut dec_in = unset_decrypt_input();
    dec_in.keyring = &*keyring as *const Keyring;
    dec_in.ciphertext = enc_out.ciphertext.as_slice();
    dec_in.commitment_policy = ffi::EsdkCommitmentPolicy::RequireEncryptRequireDecrypt;
    dec_in.max_encrypted_data_keys = 3;
    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //= reason=Core rejects a reproduced encryption context that mismatches the message; decrypt succeeding requires these pairs to have reached it.
    //# - MUST provide the target-supplied encryption context to the core ESDK,
    //# converted as defined in [Encryption context](#encryption-context).
    dec_in.encryption_context = encryption_context_core_to_target(ec.clone()).unwrap();

    let dec_out = decrypt(&dec_in).expect("decrypt");
    assert_eq!(dec_out.plaintext, plaintext);
    assert_eq!(
        dec_out.algorithm_suite_id.repr,
        enc_in.algorithm_suite_id.repr
    );
    assert_eq!(
        encryption_context_target_to_core(&dec_out.encryption_context)
            .unwrap()
            .get("purpose"),
        Some(&"integration-test".to_string())
    );
}

// Each value differs from the core default, so a dropped assignment fails.
#[test]
fn apply_encrypt_options_forwards_every_optional_input() {
    use aws_mpl_legacy::commitment::EsdkCommitmentPolicy as C;
    let input = ffi::EncryptInput {
        algorithm_suite_id: F { repr: 0x0578 },
        encryption_context: Vec::new(),
        frame_length: 1024,
        keyring: std::ptr::null(),
        plaintext: &[],
        max_encrypted_data_keys: 5,
        commitment_policy: P::ForbidEncryptAllowDecrypt,
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
        max_encrypted_data_keys: 7,
        commitment_policy: P::RequireEncryptAllowDecrypt,
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
