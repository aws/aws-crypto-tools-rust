// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bridge-internal tests: translation helpers, null-handle checks, and inputs
//! the facade cannot express. Everything here runs offline. Facade-observable
//! behavior, including the credentialed integration coverage, lives in the C++
//! suites under tests/. The error wire encoding has no test of its own: every
//! C++ typed-exception check on a Rust-produced error covers the encode and
//! decode end to end.

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
fn unset_signed_streaming() -> ffi::OptSignedStreaming {
    ffi::OptSignedStreaming {
        set: false,
        value: ffi::SignedStreaming { repr: 0 },
    }
}
fn set_policy(value: P) -> ffi::OptCommitmentPolicy {
    ffi::OptCommitmentPolicy { set: true, value }
}
fn unset_duration() -> ffi::OptDuration {
    ffi::OptDuration {
        set: false,
        value: ffi::Duration { secs: 0, nanos: 0 },
    }
}
fn set_duration(secs: u64, nanos: u32) -> ffi::OptDuration {
    ffi::OptDuration {
        set: true,
        value: ffi::Duration { secs, nanos },
    }
}

fn unset_storm_tracking_options() -> ffi::StormTrackingCmcOptions {
    ffi::StormTrackingCmcOptions {
        entry_capacity: unset_u32(),
        entry_pruning_tail_size: unset_u32(),
        grace_period: unset_duration(),
        grace_interval: unset_duration(),
        fan_out: unset_u32(),
        in_flight_ttl: unset_duration(),
        sleep: unset_duration(),
    }
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
        plaintext_length_bound: ffi::OptU64 {
            set: false,
            value: 0,
        },
    }
}

fn unset_decrypt_input() -> ffi::DecryptInput<'static> {
    ffi::DecryptInput {
        ciphertext: &[],
        encryption_context: Vec::new(),
        keyring: std::ptr::null(),
        max_encrypted_data_keys: unset_u32(),
        commitment_policy: unset_policy(),
        signed_streaming: unset_signed_streaming(),
    }
}

#[cfg(all(feature = "kms", feature = "ddb"))]
fn unset_hierarchical_keyring_input() -> ffi::HierarchicalKeyringInput {
    ffi::HierarchicalKeyringInput {
        branch_key_id: String::new(),
        key_store: std::ptr::null(),
        ttl: ffi::Duration { secs: 0, nanos: 0 },
        cache: std::ptr::null(),
        partition_id: unset_string(),
    }
}

#[cfg(all(feature = "kms", feature = "ddb"))]
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
        credentials: ffi::OptCredentials {
            set: false,
            value: test_credentials("", "", None),
        },
    }
}

fn test_credentials(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
) -> ffi::Credentials {
    ffi::Credentials {
        access_key_id: access_key_id.to_string(),
        secret_access_key: secret_access_key.to_string(),
        session_token: ffi::OptString {
            set: session_token.is_some(),
            value: session_token.unwrap_or_default().to_string(),
        },
        expiration: unset_duration(),
    }
}

fn client_config_with_credentials(credentials: ffi::Credentials) -> ffi::MplAwsClientConfig {
    let mut cfg = unset_client_config();
    cfg.region = ffi::OptString {
        set: true,
        value: "us-west-2".to_string(),
    };
    cfg.retry.max_attempts = set_u32(1);
    cfg.credentials = ffi::OptCredentials {
        set: true,
        value: credentials,
    };
    cfg
}

#[cfg(all(feature = "kms", feature = "ddb"))]
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
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
    assert!(alg_id_target_to_core(F { repr: 0x0000 }).is_err());
}

// Catches if ESDK Rust adds a suite but C++ doesn't.
// The new id falls through to the error arm of `alg_id_bytes_to_target`.
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
fn alg_id_bytes_to_target_rejects_an_id_the_shim_does_not_define() {
    //= spec/shim/esdk-shim.md#algorithm-suite-identifier
    //= type=test
    //# - The shim MUST return an error when the core ESDK produces an algorithm suite
    //# the shim does not define.
    let err = expect_err(alg_id_bytes_to_target([0xFF, 0xFF]));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Internal, "")),
        "unexpected error: {err}"
    );
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
fn signed_streaming_target_to_core_accepts_exactly_known_reprs() {
    use super::SignedStreaming as C;
    use ffi::SignedStreaming as T;
    for (target, expected_core) in [
        (T::RejectMultiFrame, C::RejectMultiFrame),
        (T::ReleaseRegularFrames, C::ReleaseRegularFrames),
        (T::RejectSigned, C::RejectSigned),
    ] {
        assert_eq!(
            signed_streaming_target_to_core(target).unwrap(),
            expected_core
        );
    }
    let accepted: Vec<u8> = (0..=u8::MAX)
        .filter(|&n| signed_streaming_target_to_core(T { repr: n }).is_ok())
        .collect();
    assert_eq!(accepted, vec![1u8, 2, 3]);
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
    let mut m = aws_esdk::types::EncryptionContext::new();
    m.insert("k1", "v1");
    m.insert("k2", "\u{1F600}");
    let list = encryption_context_core_to_target(&m);
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
    let empty = aws_esdk::types::EncryptionContext::new();
    assert!(encryption_context_core_to_target(&empty).is_empty());
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
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
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
    assert_eq!(max_edks_target_to_core(1), Some(1));
    assert_eq!(max_edks_target_to_core(42), Some(42));
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn make_kms_config_accepts_key_arn() {
    use aws_crypto_mpl::key_store::types::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a KMS key ARN configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::KmsKeyArn, "arn:test-key").unwrap(),
        KmsConfiguration::KmsKeyArn(v) if v.arn() == "arn:test-key"
    ));
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn make_kms_config_accepts_mr_key_arn() {
    use aws_crypto_mpl::key_store::types::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a KMS multi-Region-key ARN configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::KmsMrKeyArn, "arn:test-mr-key").unwrap(),
        KmsConfiguration::KmsMrKeyArn(v) if v.arn() == "arn:test-mr-key"
    ));
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn make_kms_config_accepts_discovery() {
    use aws_crypto_mpl::key_store::types::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a discovery configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::Discovery, "").unwrap(),
        KmsConfiguration::Discovery(_)
    ));
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn make_kms_config_accepts_mr_discovery() {
    use aws_crypto_mpl::key_store::types::KmsConfiguration;
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST translate a multi-Region-key discovery configuration.
    assert!(matches!(
        make_kms_config(ffi::KmsConfigurationType::MrDiscovery, "us-west-2").unwrap(),
        KmsConfiguration::MrDiscovery(m) if m.region() == "us-west-2"
    ));
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn make_kms_config_rejects_unknown_type() {
    //= spec/shim/esdk-shim.md#kms-configuration
    //= type=test
    //# - The shim MUST return an error when the target KMS configuration type is not a
    //# supported value.
    let err = make_kms_config(ffi::KmsConfigurationType { repr: 99 }, "").unwrap_err();
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
    let err = make_kms_config(ffi::KmsConfigurationType::Unset, "").unwrap_err();
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

#[test]
fn classify_core_error_maps_each_variant_to_the_same_name() {
    use aws_esdk::error as e;
    use ffi::ShimErrorKind as S;
    let cases: [(aws_esdk::Error, S); 14] = [
        (e::ValidationError::new("x").into(), S::Validation),
        (e::SerializationError::new("x").into(), S::Serialization),
        (e::CryptographicError::new("x").into(), S::Cryptographic),
        (
            e::InvalidMaterialsError::new("x").into(),
            S::InvalidMaterials,
        ),
        (
            e::EncryptionContextMismatchError::new("x").into(),
            S::EncryptionContextMismatch,
        ),
        (
            e::NoMatchingDataKeyError::new("x").into(),
            S::NoMatchingDataKey,
        ),
        (e::AccessDeniedError::new("x").into(), S::AccessDenied),
        (
            e::ResourceNotFoundError::new("x").into(),
            S::ResourceNotFound,
        ),
        (e::ServiceError::new("x").into(), S::Service),
        (e::DispatchError::new("x").into(), S::Dispatch),
        (e::InternalError::new("x").into(), S::Internal),
        (e::IoError::new("x").into(), S::Io),
        (e::ThrottlingError::new("x").into(), S::Throttling),
        (e::ConflictError::new("x").into(), S::Conflict),
    ];
    for (err, expected) in cases {
        assert_eq!(classify_core_error(&err).repr, expected.repr, "for {err:?}");
    }
}

/// The `kind=K<US>retryable=Y<US>retry=R` prefix the facade decodes.
fn err_prefix(kind: ffi::ShimErrorKind, retry: &str) -> String {
    let sep = ERROR_FIELD_SEPARATOR;
    let retryable = u8::from(!retry.is_empty());
    format!(
        "kind={}{sep}retryable={retryable}{sep}retry={retry}{sep}",
        kind.repr
    )
}

#[test]
fn core_err_encodes_an_mpl_errors_kind_and_retry_kind() {
    use aws_crypto_mpl::Error as MplError;
    use aws_crypto_mpl::error::{NoMatchingDataKeyError, RetryKind, ServiceError, ValidationError};
    let cases = [
        (
            MplError::from(NoMatchingDataKeyError::new("x")),
            ffi::ShimErrorKind::NoMatchingDataKey,
            "",
        ),
        (
            MplError::from(
                ServiceError::builder()
                    .message("x")
                    .retry_kind(RetryKind::Throttling)
                    .build(),
            ),
            ffi::ShimErrorKind::Service,
            "throttling",
        ),
        (
            MplError::from(aws_crypto_mpl::error::ThrottlingError::new("x")),
            ffi::ShimErrorKind::Throttling,
            "throttling",
        ),
        (
            MplError::from(ValidationError::new("x")),
            ffi::ShimErrorKind::Validation,
            "",
        ),
    ];
    for (e, kind, retry) in cases {
        let err = core_err(e);
        assert!(
            err.starts_with(&err_prefix(kind, retry)),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn core_err_encodes_the_aws_call() {
    use aws_crypto_mpl::Error as MplError;
    use aws_crypto_mpl::error::{AccessDeniedError, KmsKey, Resource, Service};
    let err = core_err(MplError::from(
        AccessDeniedError::builder()
            .message("denied")
            .service(Service::Kms)
            .resource(Resource::KmsKey(KmsKey::new("arn:aws:kms:k")))
            .build(),
    ));
    let sep = ERROR_FIELD_SEPARATOR;
    assert!(
        err.contains(&format!(
            "{sep}service=kms{sep}resource_type=kms_key{sep}resource=arn:aws:kms:k{sep}"
        )),
        "unexpected error: {err}"
    );
}

/// The header field `name`, from an encoded error.
fn header_field<'a>(encoded: &'a str, name: &str) -> &'a str {
    let header = &encoded[..encoded.find(ERROR_HEADER_END).expect("a header")];
    header
        .split(ERROR_FIELD_SEPARATOR)
        .find_map(|f| f.strip_prefix(&format!("{name}=")))
        .expect("the field")
}

/// The Rust `{}` and `{:#}` text after the header.
fn message_parts(encoded: &str) -> (&str, &str) {
    let (display, full, _) = body_parts(encoded);
    (display, full)
}

/// The Rust `{}` text, `{:#}` text and backtrace after the header.
fn body_parts(encoded: &str) -> (&str, &str, &str) {
    let body = &encoded[encoded.find(ERROR_HEADER_END).expect("a header") + 1..];
    let display_len: usize = header_field(encoded, "display_len").parse().unwrap();
    let full_len: usize = header_field(encoded, "full_len").parse().unwrap();
    let (display, rest) = body.split_at(display_len);
    let (full, backtrace) = rest.split_at(full_len);
    (display, full, backtrace)
}

#[test]
fn core_err_carries_the_backtrace_after_the_messages() {
    use aws_esdk::error::InternalError;
    let err = InternalError::new("example");
    let captured = backtrace_text(origin_backtrace(&aws_esdk::Error::from(err.clone())));
    let encoded = core_err(err);
    let (display, full, backtrace) = body_parts(&encoded);
    assert_eq!(display, "Internal: example");
    assert_eq!(full, "Internal: example");
    assert_eq!(backtrace, captured);
}

#[test]
fn the_backtrace_is_the_innermost_library_errors() {
    let inner = aws_crypto_mpl::Error::internal("origin");
    let outer = aws_esdk::Error::from(inner.clone());
    assert!(std::ptr::eq(origin_backtrace(&outer), inner.backtrace()));
}

#[test]
fn shim_err_has_no_backtrace() {
    let encoded = shim_err(ffi::ShimErrorKind::Validation, "decrypt", "bad input");
    let (_, _, backtrace) = body_parts(&encoded);
    assert_eq!(backtrace, "");
}

#[test]
fn core_err_encodes_the_new_resources_reason_credentials_and_name() {
    use aws_esdk::error::{
        AccessDeniedError, Cache, CmmResource, ConflictError, ConflictReason, KeyringResource,
        Resource, Service, ThrottlingError,
    };
    let throttled = core_err(
        ThrottlingError::builder()
            .resource(Resource::Cache(Cache::new()))
            .build(),
    );
    assert_eq!(header_field(&throttled, "resource_type"), "cache");
    assert_eq!(header_field(&throttled, "service"), "");
    assert_eq!(header_field(&throttled, "name"), "Throttling");

    let keyring = core_err(
        aws_esdk::error::NoMatchingDataKeyError::builder()
            .resource(Resource::Keyring(KeyringResource::new("ns/name")))
            .build(),
    );
    assert_eq!(header_field(&keyring, "resource_type"), "keyring");
    assert_eq!(header_field(&keyring, "resource"), "ns/name");

    let cmm = core_err(
        aws_esdk::error::InvalidMaterialsError::builder()
            .resource(Resource::Cmm(CmmResource::new("default")))
            .build(),
    );
    assert_eq!(header_field(&cmm, "resource_type"), "cmm");
    assert_eq!(header_field(&cmm, "resource"), "default");

    let conflict = core_err(
        ConflictError::builder()
            .service(Service::DynamoDb)
            .reason(ConflictReason::ConcurrentModification)
            .build(),
    );
    assert_eq!(
        header_field(&conflict, "conflict_reason"),
        "concurrent_modification"
    );
    assert_eq!(header_field(&conflict, "credentials"), "0");

    let expired = core_err(
        AccessDeniedError::builder()
            .code("ExpiredTokenException")
            .build(),
    );
    assert_eq!(header_field(&expired, "credentials"), "1");
}

#[test]
fn core_err_sends_the_display_and_alternate_text() {
    use aws_esdk::error::InternalError;
    let err = aws_esdk::Error::from(
        InternalError::new("outer").with_source(std::io::Error::other("the cause")),
    );
    let encoded = core_err(err);
    let (display, full) = message_parts(&encoded);
    assert_eq!(display, "Internal: outer");
    assert_eq!(full, "Internal: outer: the cause");
}

#[test]
fn a_message_holding_the_separators_still_decodes() {
    use aws_esdk::error::InternalError;
    let message = format!("a{ERROR_HEADER_END}b{ERROR_FIELD_SEPARATOR}c");
    let encoded = core_err(InternalError::new(message.clone()));
    let (display, full) = message_parts(&encoded);
    assert_eq!(display, format!("Internal: {message}"));
    assert_eq!(full, display);
}

#[test]
fn shim_err_is_not_retryable() {
    let err = shim_err(ffi::ShimErrorKind::Validation, "op", "x");
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

// Inputs the facade cannot express, so must be tested in Rust
//
// - Null resource handles (the facade passes references)
// - unset/unknown enum reprs (the facade's factories only produce valid values)

#[test]
fn require_handle_rejects_null_and_borrows_non_null() {
    //= spec/shim/shim.md#handles-and-lifetimes
    //= type=test
    //# - Before dereferencing a target-supplied resource handle, the shim MUST check it
    //# and MUST return an error when a required handle is absent.
    let err = expect_err(require_handle(std::ptr::null::<u32>(), "handle", "op"));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
    assert!(err.contains("handle is null"), "unexpected error: {err}");

    let value = 7u32;
    let borrowed = require_handle(&value as *const u32, "handle", "op").expect("non-null handle");
    assert!(std::ptr::eq(borrowed, &value));
}

#[test]
fn encrypt_rejects_null_keyring() {
    //= spec/shim/esdk-shim.md#materials-source
    //= type=test
    //# - The shim MUST return an error, and MUST NOT invoke the core ESDK, when no
    //# materials source is supplied.
    let err = expect_err(encrypt(&unset_encrypt_input()));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

#[test]
fn decrypt_rejects_null_keyring() {
    let err = expect_err(decrypt(&unset_decrypt_input()));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
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
#[cfg(all(feature = "kms", feature = "ddb"))]
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
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
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
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

#[cfg(all(feature = "kms", feature = "ddb"))]
fn hierarchical_keyring_input_with_ttl(
    key_store: &KeyStore,
    ttl: ffi::Duration,
) -> ffi::HierarchicalKeyringInput {
    let mut input = unset_hierarchical_keyring_input();
    input.key_store = key_store as *const KeyStore;
    input.branch_key_id = "branch-key-id".to_string();
    input.ttl = ttl;
    input
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn create_hierarchical_keyring_passes_ttl_nanos_to_the_core() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");
    let key_store = create_keystore(&keystore_config_with_clients(&kms, &ddb)).expect("key store");

    create_hierarchical_keyring(&hierarchical_keyring_input_with_ttl(
        &key_store,
        ffi::Duration {
            secs: 10,
            nanos: 500_000_000,
        },
    ))
    .expect("a 10.5 s TTL must be accepted");

    let err = expect_err(create_hierarchical_keyring(
        &hierarchical_keyring_input_with_ttl(
            &key_store,
            ffi::Duration {
                secs: u64::MAX,
                nanos: 1_000_000_000,
            },
        ),
    ));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn create_hierarchical_keyring_defers_to_the_default_cache() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");
    let key_store = create_keystore(&keystore_config_with_clients(&kms, &ddb)).expect("key store");

    // Indirect assertion that not supplying a cache means the HKeyring gets a default cache.
    // No cache is supplied when creating this HKeyring, so it should get the ESDK Rust default cache.
    // The default cache is a storm tracking cache with a 10s grace period.
    // The HKeyring's TTL == 5s is less than 10s. This is an invalid configuration for the storm tracking cache and should result in an error.
    // If an error about storm tracking config was raised,
    // then the default cache is probably a storm tracking cache.
    // So not supplying a cache created the default cache.
    let err = expect_err(create_hierarchical_keyring(
        &hierarchical_keyring_input_with_ttl(&key_store, ffi::Duration { secs: 5, nanos: 0 }),
    ));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //= reason=ESDK Rust rejects the TTL against a storm-tracking cache with a 10 s grace period, which is its default cache
    //# - When no cache is supplied, creating a hierarchical keyring MUST defer to the
    //# core ESDK's default cache.
    assert!(
        err.contains("storm-tracking grace period (10s)"),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn create_hierarchical_keyring_uses_the_supplied_cache() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");
    let key_store = create_keystore(&keystore_config_with_clients(&kms, &ddb)).expect("key store");

    // Inverse of create_hierarchical_keyring_defers_to_the_default_cache's indirect testing logic.
    // Indirect assertion that supplying a cache means the HKeyring uses that cache instead of the default.
    // A local cache is supplied when creating this HKeyring. A local cache has no grace period.
    // The HKeyring's TTL == 5s would be rejected by the default storm tracking cache (10s grace period),
    // but is a valid configuration for the local cache.
    // If no error was raised,
    // then the HKeyring is probably not using the default cache.
    // So supplying a cache made the HKeyring use the supplied cache.
    let mut input =
        hierarchical_keyring_input_with_ttl(&key_store, ffi::Duration { secs: 5, nanos: 0 });
    let cache = create_local_cmc(10).expect("local cache should build");
    input.cache = &*cache as *const CryptographicMaterialsCache;
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //= reason=The 5 s TTL is accepted only if the keyring uses the supplied cache
    //# - When a cache is supplied, creating a hierarchical keyring MUST reference that
    //# exact cache, so several keyrings given the same cache share it.
    create_hierarchical_keyring(&input).expect("a local cache has no grace period");
}

#[test]
#[cfg(feature = "rt-tokio")]
fn create_default_cmc_builds_a_default_storm_tracking_cache() {
    let cache = create_default_cmc(10).expect("default cache should build");
    assert_eq!(cache.inner.grace_period(), Some(Duration::from_secs(10)));
    let err = expect_err(create_default_cmc(0x8000_0000));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg(feature = "rt-tokio")]
fn unset_storm_tracking_options_keep_the_core_defaults() {
    let cache = create_storm_tracking_cmc(&unset_storm_tracking_options())
        .expect("storm-tracking cache should build");
    assert_eq!(cache.inner.grace_period(), Some(Duration::from_secs(10)));
}

fn storm_tracking_options() -> ffi::StormTrackingCmcOptions {
    ffi::StormTrackingCmcOptions {
        entry_capacity: set_u32(10),
        entry_pruning_tail_size: set_u32(1),
        grace_period: set_duration(10, 0),
        grace_interval: set_duration(0, 500_000_000),
        fan_out: set_u32(20),
        in_flight_ttl: set_duration(2, 250_000_000),
        sleep: set_duration(0, 20_000_000),
    }
}

#[test]
#[cfg(feature = "rt-tokio")]
fn create_storm_tracking_cmc_passes_each_option_to_the_core() {
    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //= type=test
    //# - Creating a cryptographic materials cache MUST provide the target-supplied
    //# cache type, with its values, to the core ESDK.
    let cache =
        apply_storm_tracking_options(StormTrackingCmc::builder(), &storm_tracking_options())
            .expect("options convert")
            .build()
            .expect("storm-tracking cache should build");
    assert_eq!(cache.entry_capacity(), 10);
    assert_eq!(cache.entry_pruning_tail_size(), 1);
    assert_eq!(cache.grace_period(), Some(Duration::from_secs(10)));
    assert_eq!(cache.grace_interval(), Duration::from_millis(500));
    assert_eq!(cache.fan_out(), 20);
    assert_eq!(cache.in_flight_ttl(), Duration::from_millis(2250));
    assert_eq!(cache.sleep(), Duration::from_millis(20));
}

#[test]
#[cfg(feature = "rt-tokio")]
fn create_storm_tracking_cmc_rejects_zero_sleep() {
    let mut options = storm_tracking_options();
    options.sleep = set_duration(0, 0);
    let err = expect_err(create_storm_tracking_cmc(&options));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg(feature = "rt-tokio")]
fn create_storm_tracking_cmc_rejects_out_of_range_durations() {
    let mut options = storm_tracking_options();
    options.grace_period = set_duration(u64::MAX, 1_000_000_000);
    let err = expect_err(create_storm_tracking_cmc(&options));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
}

#[test]
fn create_local_cmc_rejects_out_of_range_capacity() {
    let err = expect_err(create_local_cmc(0x8000_0000));
    assert!(
        err.contains("entry_capacity 2147483648 exceeds"),
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

    assert!(unset_duration().to_option().is_none());
    let got = set_duration(3, 500)
        .to_option()
        .expect("a set duration is Some");
    assert_eq!((got.secs, got.nanos), (3, 500));
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn create_keystore_forwards_id_and_grant_tokens() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");

    let unset = create_keystore(&keystore_config_with_clients(&kms, &ddb)).expect("key store");
    let info = TOKIO_RUNTIME
        .block_on(unset.inner.get_key_store_info().send())
        .expect("info");
    assert!(info.grant_tokens().is_empty());

    let mut cfg = keystore_config_with_clients(&kms, &ddb);
    cfg.id = ffi::OptString {
        set: true,
        value: "the-id".to_string(),
    };
    cfg.grant_tokens = vec!["g1".to_string(), "g2".to_string()];
    let store = create_keystore(&cfg).expect("key store");
    let info = TOKIO_RUNTIME
        .block_on(store.inner.get_key_store_info().send())
        .expect("info");
    assert_eq!(info.key_store_id(), "the-id");
    assert_eq!(info.grant_tokens(), ["g1", "g2"]);
}

#[test]
fn create_raw_aes_keyring_rejects_unsupported_wrapping_alg() {
    //= spec/shim/esdk-shim.md#aes-wrapping-algorithm
    //= type=test
    //# - The shim MUST return an error when the target wrapping algorithm configuration is not
    //# supported.
    let unset = expect_err(create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 32],
        wrapping_alg: ffi::AesWrappingAlg::Unset,
    }));
    assert!(
        unset.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {unset}"
    );

    let unknown = expect_err(create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: "test-ns".to_string(),
        key_name: "test-key".to_string(),
        wrapping_key: &[0x01; 32],
        wrapping_alg: ffi::AesWrappingAlg { repr: 99 },
    }));
    assert!(
        unknown.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {unknown}"
    );
}

// Raw AES pass-through: encrypt with the shim's keyring, decrypt with an ESDK Rust keyring.

fn shim_raw_aes(namespace: &str, name: &str, key: &[u8], alg: ffi::AesWrappingAlg) -> Box<Keyring> {
    create_raw_aes_keyring(&ffi::RawAesKeyringInput {
        key_namespace: namespace.to_string(),
        key_name: name.to_string(),
        wrapping_key: key,
        wrapping_alg: alg,
    })
    .expect("shim keyring")
}

fn rust_raw_aes(
    namespace: &str,
    name: &str,
    key: &[u8],
    alg: aws_crypto_mpl::types::AesWrappingAlg,
) -> Keyring {
    Keyring {
        inner: SharedKeyring::new(
            RawAesKeyring::builder()
                .key_namespace(namespace)
                .key_name(name)
                .wrapping_key(key.to_vec())
                .wrapping_alg(alg)
                .build()
                .expect("ESDK Rust keyring"),
        ),
    }
}

fn encrypt_with(keyring: &Keyring) -> Vec<u8> {
    let mut input = unset_encrypt_input();
    input.plaintext = b"raw aes inputs";
    input.keyring = keyring as *const Keyring;
    encrypt(&input).expect("encrypt").ciphertext
}

fn decrypt_with(ciphertext: &[u8], keyring: &Keyring) -> Result<Vec<u8>, String> {
    let mut input = unset_decrypt_input();
    input.ciphertext = ciphertext;
    input.keyring = keyring as *const Keyring;
    decrypt(&input).map(|out| out.plaintext)
}

const AES_256: ffi::AesWrappingAlg = ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16;
const RUST_AES_256: aws_crypto_mpl::types::AesWrappingAlg =
    aws_crypto_mpl::types::AesWrappingAlg::AlgAes256GcmIv12Tag16;

#[test]
fn create_raw_aes_keyring_passes_namespace_and_name_to_the_core() {
    let key = [0x2A; 32];
    let ciphertext = encrypt_with(&shim_raw_aes("test-ns", "test-key", &key, AES_256));

    //= spec/shim/esdk-shim.md#create-raw-aes-keyring
    //= type=test
    //= reason=Only an ESDK Rust keyring with the same namespace and name decrypts the shim keyring's message
    //# - Creating a raw AES keyring MUST provide the target-supplied key namespace and
    //# key name to the core ESDK.
    assert!(
        decrypt_with(
            &ciphertext,
            &rust_raw_aes("test-ns", "test-key", &key, RUST_AES_256)
        )
        .is_ok()
    );
    assert!(
        decrypt_with(
            &ciphertext,
            &rust_raw_aes("other-ns", "test-key", &key, RUST_AES_256)
        )
        .is_err()
    );
    assert!(
        decrypt_with(
            &ciphertext,
            &rust_raw_aes("test-ns", "other-key", &key, RUST_AES_256)
        )
        .is_err()
    );
}

#[test]
fn create_raw_aes_keyring_passes_the_wrapping_key_unmodified() {
    let key: Vec<u8> = (0..32).collect();
    let ciphertext = encrypt_with(&shim_raw_aes("test-ns", "test-key", &key, AES_256));
    let mut other_key = key.clone();
    other_key[31] ^= 1;

    //= spec/shim/esdk-shim.md#create-raw-aes-keyring
    //= type=test
    //= reason=Only an ESDK Rust keyring with the identical key bytes decrypts the shim keyring's message
    //# - Creating a raw AES keyring MUST pass the target-supplied wrapping key to the
    //# core ESDK unmodified.
    assert!(
        decrypt_with(
            &ciphertext,
            &rust_raw_aes("test-ns", "test-key", &key, RUST_AES_256)
        )
        .is_ok()
    );
    assert!(
        decrypt_with(
            &ciphertext,
            &rust_raw_aes("test-ns", "test-key", &other_key, RUST_AES_256)
        )
        .is_err()
    );
}

#[test]
fn create_raw_aes_keyring_converts_the_wrapping_algorithm() {
    use aws_crypto_mpl::types::AesWrappingAlg as Core;
    let cases = [
        (
            ffi::AesWrappingAlg::AlgAes128GcmIv12Tag16,
            Core::AlgAes128GcmIv12Tag16,
            16,
        ),
        (
            ffi::AesWrappingAlg::AlgAes192GcmIv12Tag16,
            Core::AlgAes192GcmIv12Tag16,
            24,
        ),
        (
            ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16,
            Core::AlgAes256GcmIv12Tag16,
            32,
        ),
    ];
    for (target_alg, core_alg, key_len) in cases {
        let key = vec![0x2A; key_len];
        let ciphertext = encrypt_with(&shim_raw_aes("test-ns", "test-key", &key, target_alg));
        //= spec/shim/esdk-shim.md#create-raw-aes-keyring
        //= type=test
        //= reason=An ESDK Rust keyring with the matching ESDK Rust algorithm decrypts the shim keyring's message
        //# - Creating a raw AES keyring MUST provide the target-supplied wrapping algorithm
        //# to the core ESDK, converted as defined in
        //# [AES wrapping algorithm](#aes-wrapping-algorithm).
        assert!(
            decrypt_with(
                &ciphertext,
                &rust_raw_aes("test-ns", "test-key", &key, core_alg)
            )
            .is_ok()
        );
    }
}

// Options forwarding

#[test]
fn encrypt_settings_forwards_every_optional_input() {
    use super::EsdkCommitmentPolicy as C;
    let input = ffi::EncryptInput {
        algorithm_suite_id: set_alg_id(F { repr: 0x0578 }),
        encryption_context: Vec::new(),
        frame_length: set_u32(1024),
        keyring: std::ptr::null(),
        plaintext: &[],
        max_encrypted_data_keys: set_u32(5),
        commitment_policy: set_policy(P::ForbidEncryptAllowDecrypt),
        plaintext_length_bound: ffi::OptU64 {
            set: false,
            value: 0,
        },
    };
    let settings = encrypt_settings(&input).expect("settings convert");
    let config = settings.esdk.config();

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied maximum-encrypted-data-keys value to
    //# the core ESDK, converted as defined in
    //# [Maximum encrypted data keys](#maximum-encrypted-data-keys).
    assert_eq!(config.max_encrypted_data_keys(), Some(5));

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied frame length to the core ESDK,
    //# converted as defined in [Frame length](#frame-length).
    assert_eq!(settings.frame_length, NonZeroU32::new(1024));

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied commitment policy to the core ESDK,
    //# converted as defined in [Commitment policy](#commitment-policy).
    assert_eq!(config.commitment_policy(), C::ForbidEncryptAllowDecrypt);

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied algorithm suite to the core ESDK,
    //# converted as defined in [Algorithm suite identifier](#algorithm-suite-identifier).
    assert_eq!(
        settings.algorithm_suite_id,
        Some(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
    );
}

#[test]
fn encrypt_settings_leaves_unset_inputs_defaulted() {
    let settings = encrypt_settings(&unset_encrypt_input()).expect("settings convert");
    let config = settings.esdk.config();
    assert_eq!(config.max_encrypted_data_keys(), None);
    assert_eq!(settings.frame_length, None);
    assert_eq!(
        config.commitment_policy(),
        EsdkCommitmentPolicy::RequireEncryptRequireDecrypt
    );
    assert_eq!(settings.algorithm_suite_id, None);
}

#[test]
fn decrypt_client_forwards_every_optional_input() {
    use super::EsdkCommitmentPolicy as C;
    let input = ffi::DecryptInput {
        ciphertext: &[],
        encryption_context: Vec::new(),
        keyring: std::ptr::null(),
        max_encrypted_data_keys: set_u32(7),
        commitment_policy: set_policy(P::RequireEncryptAllowDecrypt),
        signed_streaming: unset_signed_streaming(),
    };
    let esdk = decrypt_client(&input).expect("settings convert");
    let config = esdk.config();

    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied maximum-encrypted-data-keys value to
    //# the core ESDK, converted as defined in
    //# [Maximum encrypted data keys](#maximum-encrypted-data-keys).
    assert_eq!(config.max_encrypted_data_keys(), Some(7));

    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //# - MUST provide the target-supplied commitment policy to the core ESDK,
    //# converted as defined in [Commitment policy](#commitment-policy).
    assert_eq!(config.commitment_policy(), C::RequireEncryptAllowDecrypt);
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

    assert!(unset_duration().to_option().is_none());
    assert_eq!(set_duration(9, 0).to_option().map(|d| d.secs), Some(9));
}

// AWS SDK client configuration
// The built SdkConfig is opaque through the facade, so the values must be tested from Rust

#[test]
#[cfg(any(feature = "kms", feature = "ddb"))]
fn shim_framework_metadata_is_valid() {
    //= spec/shim/esdk-shim.md#service-client-configuration
    //= type=test
    //# - The shim MUST set a user-agent on each service client of the form
    //# `AwsEncryptionSdk-Shim-<target-language>-<core-language>-<version>`, where
    //# `<target-language>` is the target language, `<core-language>` is the core
    //# ESDK's implementation language, and `<version>` is the shim's published version.
    let md = shim_framework_metadata();
    assert_eq!(md.name(), "AwsEncryptionSdk-Shim-C++-Rust");
    assert_eq!(md.version(), Some(env!("CARGO_PKG_VERSION")));
}

#[test]
#[cfg(any(feature = "kms", feature = "ddb"))]
fn create_sdk_config_defers_retry_when_unset() {
    let default_ref = TOKIO_RUNTIME.block_on(aws_config::load_defaults(
        aws_config::BehaviorVersion::latest(),
    ));
    let sdk = create_sdk_config(&unset_client_config(), None).expect("build sdk config");
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
#[cfg(any(feature = "kms", feature = "ddb"))]
fn create_sdk_config_applies_every_field() {
    let mut cfg = unset_client_config();
    cfg.region = ffi::OptString {
        set: true,
        value: "us-west-2".to_string(),
    };
    cfg.retry.max_attempts = set_u32(7);
    cfg.retry.mode_adaptive = true;
    let sdk = create_sdk_config(&cfg, None).expect("build sdk config");

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

    assert!(
        sdk.framework_metadata()
            .iter()
            .any(|md| md.name() == SHIM_FRAMEWORK_NAME)
    );
}

#[test]
#[cfg(any(feature = "kms", feature = "ddb"))]
fn create_sdk_config_adds_the_user_agent_once() {
    for _ in 0..2 {
        let sdk = create_sdk_config(&unset_client_config(), None).expect("build sdk config");
        let count = sdk
            .framework_metadata()
            .iter()
            .filter(|md| md.name() == SHIM_FRAMEWORK_NAME)
            .count();
        assert_eq!(count, 1);
    }
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn clients_carry_an_explicit_http_client() {
    let cfg = unset_client_config();
    let kms = create_kms_client(&cfg).expect("kms client");
    let ddb = create_ddb_client(&cfg).expect("ddb client");
    let creds = test_credentials("AKIDDERIVED", "secret", None);
    let derived_kms = kms_client_with_credentials(&kms, &creds).expect("derived kms");
    let derived_ddb = ddb_client_with_credentials(&ddb, &creds).expect("derived ddb");
    assert!(kms.inner.config().http_client().is_some());
    assert!(ddb.inner.config().http_client().is_some());
    assert!(derived_kms.inner.config().http_client().is_some());
    assert!(derived_ddb.inner.config().http_client().is_some());
}

// Records the signing headers of a request, then fails it before it is sent.
#[derive(Debug, Clone, Default)]
struct CaptureSigning(std::sync::Arc<std::sync::Mutex<Option<SigningHeaders>>>);

#[derive(Debug)]
struct SigningHeaders {
    authorization: String,
    security_token: Option<String>,
}

#[cfg(any(feature = "kms", feature = "ddb"))]
impl sdk_config::Intercept for CaptureSigning {
    fn name(&self) -> &'static str {
        "CaptureSigning"
    }

    fn read_before_transmit(
        &self,
        context: &sdk_config::interceptors::BeforeTransmitInterceptorContextRef<'_>,
        _runtime_components: &sdk_config::RuntimeComponents,
        _cfg: &mut sdk_config::ConfigBag,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let headers = context.request().headers();
        *self.0.lock().unwrap() = Some(SigningHeaders {
            authorization: headers.get("authorization").unwrap_or_default().to_string(),
            security_token: headers.get("x-amz-security-token").map(str::to_string),
        });
        Err("request captured".into())
    }
}

impl CaptureSigning {
    fn take(&self) -> SigningHeaders {
        self.0.lock().unwrap().take().expect("a request was signed")
    }
}

#[cfg(feature = "kms")]
fn kms_signing(client: &MplKmsClient) -> SigningHeaders {
    let capture = CaptureSigning::default();
    let config = client
        .inner
        .config()
        .to_builder()
        .interceptor(capture.clone())
        .build();
    let result = TOKIO_RUNTIME.block_on(aws_sdk_kms::Client::from_conf(config).list_keys().send());
    assert!(result.is_err(), "the interceptor stops every request");
    capture.take()
}

#[cfg(feature = "ddb")]
fn ddb_signing(client: &MplDdbClient) -> SigningHeaders {
    let capture = CaptureSigning::default();
    let config = client
        .inner
        .config()
        .to_builder()
        .interceptor(capture.clone())
        .build();
    let result = TOKIO_RUNTIME.block_on(
        aws_sdk_dynamodb::Client::from_conf(config)
            .list_tables()
            .send(),
    );
    assert!(result.is_err(), "the interceptor stops every request");
    capture.take()
}

#[test]
#[cfg(feature = "kms")]
fn kms_clients_sign_with_their_own_credentials() {
    let cfg = client_config_with_credentials(test_credentials("AKIDBASE", "secret-base", None));
    let base = create_kms_client(&cfg).expect("kms client");
    let derived = kms_client_with_credentials(
        &base,
        &test_credentials("AKIDDERIVED", "secret-derived", Some("token-derived")),
    )
    .expect("derived kms client");

    let base_signing = kms_signing(&base);
    assert!(
        base_signing.authorization.contains("Credential=AKIDBASE/"),
        "{base_signing:?}"
    );
    assert_eq!(base_signing.security_token, None);

    let derived_signing = kms_signing(&derived);
    assert!(
        derived_signing
            .authorization
            .contains("Credential=AKIDDERIVED/"),
        "{derived_signing:?}"
    );
    assert_eq!(
        derived_signing.security_token.as_deref(),
        Some("token-derived")
    );
}

#[test]
#[cfg(feature = "ddb")]
fn ddb_clients_sign_with_their_own_credentials() {
    let cfg = client_config_with_credentials(test_credentials("AKIDBASE", "secret-base", None));
    let base = create_ddb_client(&cfg).expect("ddb client");
    let derived = ddb_client_with_credentials(
        &base,
        &test_credentials("AKIDDERIVED", "secret-derived", Some("token-derived")),
    )
    .expect("derived ddb client");

    let base_signing = ddb_signing(&base);
    assert!(
        base_signing.authorization.contains("Credential=AKIDBASE/"),
        "{base_signing:?}"
    );
    let derived_signing = ddb_signing(&derived);
    assert!(
        derived_signing
            .authorization
            .contains("Credential=AKIDDERIVED/"),
        "{derived_signing:?}"
    );
    assert_eq!(
        derived_signing.security_token.as_deref(),
        Some("token-derived")
    );
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn derived_clients_keep_the_base_configuration() {
    let mut cfg = client_config_with_credentials(test_credentials("AKIDBASE", "secret", None));
    cfg.retry.max_attempts = set_u32(5);
    let creds = test_credentials("AKIDDERIVED", "secret", None);

    let kms = create_kms_client(&cfg).expect("kms client");
    let derived = kms_client_with_credentials(&kms, &creds).expect("derived kms");
    let config = derived.inner.config();
    assert_eq!(config.region().map(|r| r.as_ref()), Some("us-west-2"));
    assert_eq!(config.retry_config().map(|r| r.max_attempts()), Some(5));

    let ddb = create_ddb_client(&cfg).expect("ddb client");
    let derived = ddb_client_with_credentials(&ddb, &creds).expect("derived ddb");
    let config = derived.inner.config();
    assert_eq!(config.region().map(|r| r.as_ref()), Some("us-west-2"));
    assert_eq!(config.retry_config().map(|r| r.max_attempts()), Some(5));
}

#[test]
#[cfg(all(feature = "kms", feature = "ddb"))]
fn empty_credentials_are_rejected_without_echoing_them() {
    let kms = create_kms_client(&unset_client_config()).expect("kms client");
    let ddb = create_ddb_client(&unset_client_config()).expect("ddb client");
    for (access_key_id, secret_access_key) in [("", "secret-value"), ("AKIDVALUE", "")] {
        let creds = || test_credentials(access_key_id, secret_access_key, Some("token-value"));
        let errors = [
            expect_err(create_kms_client(&client_config_with_credentials(creds()))),
            expect_err(create_ddb_client(&client_config_with_credentials(creds()))),
            expect_err(kms_client_with_credentials(&kms, &creds())),
            expect_err(ddb_client_with_credentials(&ddb, &creds())),
        ];
        for err in errors {
            assert!(
                err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
                "unexpected error: {err}"
            );
            assert!(err.contains("must not be empty"), "unexpected error: {err}");
            for value in ["AKIDVALUE", "secret-value", "token-value"] {
                assert!(!err.contains(value), "error contains {value}: {err}");
            }
        }
    }
}

#[test]
#[cfg(any(feature = "kms", feature = "ddb"))]
fn credentials_expiration_is_time_since_the_epoch() {
    let mut creds = test_credentials("AKID", "secret", None);
    let unset = credentials_target_to_core(&creds, "test").expect("credentials");
    assert_eq!(unset.expiry(), None);

    creds.expiration = set_duration(1_700_000_000, 5);
    let set = credentials_target_to_core(&creds, "test").expect("credentials");
    assert_eq!(
        set.expiry(),
        Some(SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 5))
    );

    creds.expiration = set_duration(u64::MAX, 0);
    let err = expect_err(credentials_target_to_core(&creds, "test"));
    assert!(
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
        "unexpected error: {err}"
    );
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
        err.starts_with(&err_prefix(ffi::ShimErrorKind::Internal, "")),
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

// Records every header of a request, then fails it before it is sent.
#[derive(Debug, Clone, Default)]
struct CaptureHeaders(std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>);

#[cfg(feature = "kms")]
impl aws_sdk_kms::config::Intercept for CaptureHeaders {
    fn name(&self) -> &'static str {
        "CaptureHeaders"
    }

    fn read_before_transmit(
        &self,
        context: &aws_sdk_kms::config::interceptors::BeforeTransmitInterceptorContextRef<'_>,
        _runtime_components: &aws_sdk_kms::config::RuntimeComponents,
        _cfg: &mut aws_sdk_kms::config::ConfigBag,
    ) -> Result<(), aws_sdk_kms::error::BoxError> {
        *self.0.lock().unwrap() = context
            .request()
            .headers()
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        Err("request captured".into())
    }
}

#[cfg(feature = "kms")]
fn kms_sent_headers(client: &MplKmsClient) -> Vec<(String, String)> {
    let capture = CaptureHeaders::default();
    let config = client
        .inner
        .config()
        .to_builder()
        .interceptor(capture.clone())
        .build();
    let result = TOKIO_RUNTIME.block_on(aws_sdk_kms::Client::from_conf(config).list_keys().send());
    assert!(result.is_err(), "the interceptor stops every request");
    capture.0.lock().unwrap().clone()
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[test]
#[cfg(feature = "kms")]
fn shim_user_agent_keeps_the_customers_app_id() {
    let loaded = SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .app_name(aws_config::AppName::new("my-service").expect("valid app name"))
        .credentials_provider(SharedCredentialsProvider::new(
            aws_sdk_kms::config::Credentials::new("AKID", "secret", None, None, "test"),
        ))
        .build();
    let kms = MplKmsClient {
        inner: aws_sdk_kms::Client::new(&with_shim_user_agent(loaded)),
    };

    let sent = kms_sent_headers(&kms);
    let ua = header_value(&sent, "x-amz-user-agent").expect("user agent header");
    //= spec/shim/esdk-shim.md#service-client-configuration
    //= type=test
    //# - The shim MUST preserve any user-agent already present in the loaded
    //# configuration, appending its own rather than replacing it.
    assert!(ua.contains("app/my-service"), "{ua}");
    assert!(
        ua.contains(&format!(
            "lib/{SHIM_FRAMEWORK_NAME}/{}",
            env!("CARGO_PKG_VERSION")
        )),
        "{ua}"
    );
}

fn http_header(name: &str, value: &str) -> ffi::HttpHeader {
    ffi::HttpHeader {
        name: name.to_string(),
        value: value.to_string(),
    }
}

#[test]
#[cfg(feature = "kms")]
fn kms_client_with_headers_sends_and_signs_the_headers() {
    let cfg = client_config_with_credentials(test_credentials("AKIDBASE", "secret-base", None));
    let base = create_kms_client(&cfg).expect("kms client");
    let derived = kms_client_with_headers(
        &base,
        vec![
            http_header("x-test-one", "1"),
            http_header("x-test-two", "two"),
        ],
    )
    .expect("derived kms client");

    let sent = kms_sent_headers(&derived);
    assert_eq!(header_value(&sent, "x-test-one"), Some("1"));
    assert_eq!(header_value(&sent, "x-test-two"), Some("two"));
    let authorization = header_value(&sent, "authorization").expect("signed request");
    assert!(
        authorization.contains("x-test-one;x-test-two"),
        "headers must be signed: {authorization}"
    );

    assert_eq!(header_value(&kms_sent_headers(&base), "x-test-one"), None);
}

#[test]
#[cfg(feature = "kms")]
fn kms_client_with_headers_rejects_invalid_headers() {
    let base = create_kms_client(&unset_client_config()).expect("kms client");
    let cases = [
        vec![],
        vec![http_header("", "v")],
        vec![http_header("x-test", "")],
        vec![http_header("bad name", "v")],
        vec![http_header("x-test", "bad\nvalue")],
        vec![http_header("x-test", "a"), http_header("X-Test", "b")],
    ];
    for headers in cases {
        let err = expect_err(kms_client_with_headers(&base, headers));
        assert!(
            err.starts_with(&err_prefix(ffi::ShimErrorKind::Validation, "")),
            "{err}"
        );
    }
}

// A local HTTP/1.1 server that answers every KMS request with an empty `ListKeys` result
// and counts the TCP connections it accepts.
fn connection_counting_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TOKIO_RUNTIME
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let accepted = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    TOKIO_RUNTIME.spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                loop {
                    // Read one request: headers, then a Content-Length body.
                    let header_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        let mut chunk = [0u8; 4096];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
                    let body_len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while buf.len() < header_end + body_len {
                        let mut chunk = [0u8; 4096];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    buf.drain(..header_end + body_len);
                    let body = br#"{"Keys":[],"Truncated":false}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/x-amz-json-1.1\r\ncontent-length: {}\r\n\r\n",
                        body.len()
                    );
                    if socket.write_all(response.as_bytes()).await.is_err()
                        || socket.write_all(body).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (url, accepted)
}

/// A copy of `client` that sends to `url`, keeping its HTTP client.
#[cfg(feature = "kms")]
fn pointed_at(client: &MplKmsClient, url: &str) -> aws_sdk_kms::Client {
    aws_sdk_kms::Client::from_conf(client.inner.config().to_builder().endpoint_url(url).build())
}

#[cfg(feature = "kms")]
fn list_keys(client: &aws_sdk_kms::Client) {
    TOKIO_RUNTIME
        .block_on(client.list_keys().send())
        .expect("list_keys against the local server");
    // Wait for the connection to return to the pool so the next request reuses it.
    TOKIO_RUNTIME.block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    });
}

#[test]
#[cfg(feature = "kms")]
fn clients_sharing_an_http_client_reuse_one_connection() {
    let (url, accepted) = connection_counting_server();
    let cfg = client_config_with_credentials(test_credentials("AKIDBASE", "secret-base", None));
    let http = create_http_client().expect("http client");
    let first = create_kms_client_with_http_client(&cfg, &http).expect("kms client");
    let second = create_kms_client_with_http_client(&cfg, &http).expect("kms client");
    let derived = kms_client_with_headers(&first, vec![http_header("x-test", "1")]).expect("copy");

    list_keys(&pointed_at(&first, &url));
    list_keys(&pointed_at(&second, &url));
    list_keys(&pointed_at(&derived, &url));

    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
#[cfg(feature = "kms")]
fn clients_without_a_shared_http_client_use_their_own_connections() {
    let (url, accepted) = connection_counting_server();
    let cfg = client_config_with_credentials(test_credentials("AKIDBASE", "secret-base", None));
    let first = create_kms_client(&cfg).expect("kms client");
    let second = create_kms_client(&cfg).expect("kms client");

    list_keys(&pointed_at(&first, &url));
    list_keys(&pointed_at(&second, &url));

    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
}
