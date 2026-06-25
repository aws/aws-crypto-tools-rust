// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the client API surface in
//! `../spec/s3-encryption/client.md`: the required GetObject / PutObject /
//! DeleteObject / DeleteObjects operations, the optional ReEncryptInstructionFile
//! operation, keyring acceptance at initialization, and the
//! enable-legacy-unauthenticated-modes decrypt gate.
//!
//! S3 is mocked with an in-memory object store (`aws-smithy-mocks`) so the full
//! PutObject -> GetObject pipeline runs without any network access. The raw AES
//! and RSA keyrings are used so no KMS call is made.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::operation::delete_object::DeleteObjectOutput;
use aws_sdk_s3::operation::delete_objects::DeleteObjectsOutput;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_mocks::{mock, MockResponseInterceptor, Rule, RuleMode};

use aws_s3_encryption::client::S3EncryptionClient;
use aws_s3_encryption::config::{CommitmentPolicy, EncryptionAlgorithm, S3EncryptionConfig};
use aws_s3_encryption::error::S3EncryptionError;
use aws_s3_encryption::keyring::AesKeyring;
use aws_s3_encryption::metadata::{self, ObjectMetadata, CONTENT_CIPHER_CBC};

const COMMITTING: EncryptionAlgorithm = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;

// ===========================================================================
// In-memory S3 mock
// ===========================================================================

/// In-memory S3 object store: key -> (body bytes, user metadata).
type Store = Arc<Mutex<HashMap<String, (Vec<u8>, HashMap<String, String>)>>>;

fn new_store() -> Store {
    Arc::new(Mutex::new(HashMap::new()))
}

/// PutObject: capture the uploaded body + metadata into the store.
fn put_rule(store: Store) -> Rule {
    mock!(aws_sdk_s3::Client::put_object).then_compute_output(move |req| {
        let key = req.key().unwrap_or_default().to_string();
        let body = req.body().bytes().map(|b| b.to_vec()).unwrap_or_default();
        let metadata = req.metadata().cloned().unwrap_or_default();
        store.lock().unwrap().insert(key, (body, metadata));
        PutObjectOutput::builder().build()
    })
}

/// GetObject: serve the stored body + metadata for the requested key.
fn get_rule(store: Store) -> Rule {
    mock!(aws_sdk_s3::Client::get_object).then_compute_output(move |req| {
        let key = req.key().unwrap_or_default().to_string();
        match store.lock().unwrap().get(&key) {
            Some((body, metadata)) => GetObjectOutput::builder()
                .body(ByteStream::from(body.clone()))
                .set_metadata(Some(metadata.clone()))
                .build(),
            None => GetObjectOutput::builder()
                .body(ByteStream::from(Vec::new()))
                .build(),
        }
    })
}

/// DeleteObject: remove the requested key from the store.
fn delete_object_rule(store: Store) -> Rule {
    mock!(aws_sdk_s3::Client::delete_object).then_compute_output(move |req| {
        let key = req.key().unwrap_or_default().to_string();
        store.lock().unwrap().remove(&key);
        DeleteObjectOutput::builder().build()
    })
}

/// DeleteObjects: remove every key in the batch from the store.
fn delete_objects_rule(store: Store) -> Rule {
    mock!(aws_sdk_s3::Client::delete_objects).then_compute_output(move |req| {
        if let Some(delete) = req.delete() {
            let mut guard = store.lock().unwrap();
            for object in delete.objects() {
                guard.remove(object.key());
            }
        }
        DeleteObjectsOutput::builder().build()
    })
}

/// A KMS client that is never called (the raw keyrings wrap/unwrap locally).
fn kms_stub() -> aws_sdk_kms::Client {
    aws_sdk_kms::Client::from_conf(
        aws_sdk_kms::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-west-2"))
            .credentials_provider(Credentials::new("ak", "sk", None, None, "test"))
            .build(),
    )
}

/// Build an `S3EncryptionClient` whose wrapped S3 client is the in-memory store.
fn build_client(store: &Store, cfg: S3EncryptionConfig) -> S3EncryptionClient {
    let pr = put_rule(store.clone());
    let gr = get_rule(store.clone());
    let dr = delete_object_rule(store.clone());
    let dor = delete_objects_rule(store.clone());
    let interceptor = MockResponseInterceptor::new()
        .rule_mode(RuleMode::MatchAny)
        .with_rule(&pr)
        .with_rule(&gr)
        .with_rule(&dr)
        .with_rule(&dor);
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .credentials_provider(Credentials::new("ak", "sk", None, None, "test"))
        .interceptor(interceptor)
        .build();
    let s3 = aws_sdk_s3::Client::from_conf(conf);
    S3EncryptionClient::new(cfg, s3, kms_stub()).unwrap()
}

// ===========================================================================
// Test fixtures
// ===========================================================================

/// A raw-AES config that encrypts with the key-committing V3 suite.
fn aes_committing_config(instruction_file: bool) -> S3EncryptionConfig {
    S3EncryptionConfig {
        aes_wrapping_key: Some(vec![0x42u8; 32]),
        encryption_algorithm: Some(COMMITTING),
        commitment_policy: Some(CommitmentPolicy::RequireEncryptRequireDecrypt),
        instruction_file_put_enabled: instruction_file,
        ..Default::default()
    }
}

/// A raw-AES config that allows decrypting non-committing (V2) objects, with the
/// legacy-unauthenticated-modes toggle wired through.
fn aes_allow_decrypt_config(enable_legacy: bool) -> S3EncryptionConfig {
    S3EncryptionConfig {
        aes_wrapping_key: Some(vec![0x42u8; 32]),
        commitment_policy: Some(CommitmentPolicy::RequireEncryptAllowDecrypt),
        enable_legacy_unauthenticated_modes: enable_legacy,
        ..Default::default()
    }
}

/// Generate an RSA-2048 private key in PKCS#8 DER form for the raw RSA keyring.
fn rsa_pkcs8_key() -> Vec<u8> {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
    let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    key.as_der().unwrap().as_ref().to_vec()
}

/// Encrypt `plaintext` with AES-256-CBC/PKCS7, returning `(iv, ciphertext)` —
/// the legacy unauthenticated content format an old S3 encryption client wrote.
fn cbc_encrypt(data_key: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use aws_lc_rs::cipher::{PaddedBlockEncryptingKey, UnboundCipherKey, AES_256};
    let unbound = UnboundCipherKey::new(&AES_256, data_key).unwrap();
    let key = PaddedBlockEncryptingKey::cbc_pkcs7(unbound).unwrap();
    let mut in_out = plaintext.to_vec();
    let context = key.encrypt(&mut in_out).unwrap();
    let iv = <&[u8]>::try_from(&context).unwrap().to_vec();
    (iv, in_out)
}

/// Seed the store with a legacy AES-CBC (V2 format) object wrapped under the
/// raw-AES keyring's wrapping key.
fn seed_legacy_cbc_object(store: &Store, key: &str, plaintext: &[u8]) {
    let data_key = vec![0x5Au8; 32];
    let aes = AesKeyring::new(vec![0x42u8; 32]);
    let wrapped = aes
        .encrypt_data_key(&data_key, EncryptionAlgorithm::AlgAes256CbcIv16NoKdf)
        .unwrap();
    let (iv, body) = cbc_encrypt(&data_key, plaintext);

    // The legacy CBC suite reuses the V2 metadata layout; only the content
    // cipher (`x-amz-cek-alg`) distinguishes it, and CBC carries no auth tag.
    let mut md = ObjectMetadata::for_v2_raw_aes(&wrapped, &iv).unwrap();
    md.content_cipher = Some(CONTENT_CIPHER_CBC.to_string());
    md.tag_length = None;
    let map: HashMap<String, String> = md.to_map().into_iter().collect();
    store.lock().unwrap().insert(key.to_string(), (body, map));
}

fn instruction_key(key: &str) -> String {
    format!("{key}{}", metadata::DEFAULT_INSTRUCTION_FILE_SUFFIX)
}

// ===========================================================================
// Cryptographic Materials (#cryptographic-materials)
// ===========================================================================

#[test]
fn new_accepts_a_single_keyring_at_initialization() {
    let cfg = S3EncryptionConfig {
        aes_wrapping_key: Some(vec![0x42u8; 32]),
        ..Default::default()
    };
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .credentials_provider(Credentials::new("ak", "sk", None, None, "test"))
        .build();
    let s3 = aws_sdk_s3::Client::from_conf(conf);

    //= ../spec/s3-encryption/client.md#cryptographic-materials
    //= type=test
    //= reason=constructing the client with a single configured keyring succeeds, so one keyring is accepted at initialization
    //# The S3EC MUST accept either one CMM or one Keyring instance upon initialization.
    assert!(S3EncryptionClient::new(cfg, s3, kms_stub()).is_ok());
}

// ===========================================================================
// Required API Operations (#required-api-operations)
// ===========================================================================

#[tokio::test]
async fn put_object_encrypts_and_get_object_decrypts_round_trip() {
    let store = new_store();
    let client = build_client(&store, aes_committing_config(false));
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    let ctx = BTreeMap::new();

    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //# - PutObject MUST be implemented by the S3EC.
    client
        .put_object("bucket", "obj", plaintext, &ctx)
        .await
        .unwrap();

    // The body captured by the mocked S3 PutObject is the ciphertext.
    let stored_body = store.lock().unwrap().get("obj").unwrap().0.clone();
    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //= reason=the body uploaded to S3 is ciphertext, not the plaintext, proving the input was encrypted before upload
    //# - PutObject MUST encrypt its input data before it is uploaded to S3.
    assert_ne!(stored_body.as_slice(), plaintext.as_slice());

    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //# - GetObject MUST be implemented by the S3EC.
    let decrypted = client
        .get_object("bucket", "obj", &ctx, None, None)
        .await
        .unwrap();

    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //= reason=GetObject returns the original plaintext, only possible by decrypting the stored ciphertext received from S3
    //# - GetObject MUST decrypt data received from the S3 server and return it as plaintext.
    assert_eq!(decrypted.plaintext.as_slice(), plaintext.as_slice());
}

#[tokio::test]
async fn delete_object_removes_object_and_its_instruction_file() {
    let store = new_store();
    let client = build_client(&store, aes_committing_config(false));
    {
        let mut guard = store.lock().unwrap();
        guard.insert("obj".to_string(), (b"ciphertext".to_vec(), HashMap::new()));
        guard.insert(instruction_key("obj"), (b"{}".to_vec(), HashMap::new()));
    }

    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //# - DeleteObject MUST be implemented by the S3EC.
    client.delete_object("bucket", "obj").await.unwrap();

    let guard = store.lock().unwrap();
    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //# - DeleteObject MUST delete the given object key.
    assert!(!guard.contains_key("obj"));

    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //# - DeleteObject MUST delete the associated instruction file using the default instruction file suffix.
    assert!(!guard.contains_key(&instruction_key("obj")));
}

#[tokio::test]
async fn delete_objects_removes_each_object_and_its_instruction_file() {
    let store = new_store();
    let client = build_client(&store, aes_committing_config(false));
    {
        let mut guard = store.lock().unwrap();
        for key in ["a", "b"] {
            guard.insert(key.to_string(), (b"ciphertext".to_vec(), HashMap::new()));
            guard.insert(instruction_key(key), (b"{}".to_vec(), HashMap::new()));
        }
    }

    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //# - DeleteObjects MUST be implemented by the S3EC.
    client
        .delete_objects("bucket", &["a".to_string(), "b".to_string()])
        .await
        .unwrap();

    let guard = store.lock().unwrap();
    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //# - DeleteObjects MUST delete each of the given objects.
    assert!(!guard.contains_key("a") && !guard.contains_key("b"));

    //= ../spec/s3-encryption/client.md#required-api-operations
    //= type=test
    //# - DeleteObjects MUST delete each of the corresponding instruction files using the default instruction file suffix.
    assert!(
        !guard.contains_key(&instruction_key("a")) && !guard.contains_key(&instruction_key("b"))
    );
}

// ===========================================================================
// Enable Legacy Unauthenticated Modes (#enable-legacy-unauthenticated-modes)
// ===========================================================================

#[tokio::test]
async fn legacy_cbc_object_decrypts_when_legacy_modes_enabled() {
    let store = new_store();
    let plaintext = b"legacy CBC content payload";
    seed_legacy_cbc_object(&store, "legacy", plaintext);
    let client = build_client(&store, aes_allow_decrypt_config(true));

    //= ../spec/s3-encryption/client.md#enable-legacy-unauthenticated-modes
    //= type=test
    //= reason=with legacy unauthenticated modes enabled, GetObject decrypts the AES-CBC (legacy) object and returns its plaintext
    //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all content encryption algorithms (both legacy and fully supported).
    let decrypted = client
        .get_object("bucket", "legacy", &BTreeMap::new(), None, None)
        .await
        .unwrap();
    assert_eq!(decrypted.plaintext.as_slice(), plaintext.as_slice());
}

#[tokio::test]
async fn legacy_cbc_object_rejected_when_legacy_modes_disabled() {
    let store = new_store();
    seed_legacy_cbc_object(&store, "legacy", b"legacy CBC content payload");
    let client = build_client(&store, aes_allow_decrypt_config(false));

    let err = client
        .get_object("bucket", "legacy", &BTreeMap::new(), None, None)
        .await
        .unwrap_err();
    //= ../spec/s3-encryption/client.md#enable-legacy-unauthenticated-modes
    //= type=test
    //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy content encryption algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy content encryption algorithm.
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
}

// ===========================================================================
// Optional API Operations — ReEncryptInstructionFile (#optional-api-operations)
// ===========================================================================

#[tokio::test]
async fn re_encrypt_instruction_file_rotates_aes_to_rsa() {
    let store = new_store();
    let rsa_key = rsa_pkcs8_key();
    let plaintext = b"rotate my wrapping key";
    let ctx = BTreeMap::new();

    // Source object written with an instruction file: its data key lives in the
    // sidecar, wrapped under the AES keyring.
    let source = build_client(&store, aes_committing_config(true));
    source
        .put_object("bucket", "obj", plaintext, &ctx)
        .await
        .unwrap();

    //= ../spec/s3-encryption/client.md#optional-api-operations
    //= type=test
    //# - ReEncryptInstructionFile MAY be implemented by the S3EC.
    //
    //= ../spec/s3-encryption/client.md#optional-api-operations
    //= type=test
    //= reason=re-encryption succeeds only by first decrypting the source instruction file's data key with the client's (AES) keyring
    //# - ReEncryptInstructionFile MUST decrypt the instruction file's encrypted data key for the given object using the client's CMM.
    source
        .re_encrypt("bucket", "obj", None, Some(rsa_key.clone()), None, false)
        .await
        .unwrap();

    // A client holding only the new RSA keyring can now decrypt the object,
    // which is only possible if the data key was re-wrapped under that keyring.
    let rotated_cfg = S3EncryptionConfig {
        rsa_wrapping_key: Some(rsa_key),
        encryption_algorithm: Some(COMMITTING),
        commitment_policy: Some(CommitmentPolicy::RequireEncryptRequireDecrypt),
        instruction_file_put_enabled: true,
        ..Default::default()
    };
    let rotated = build_client(&store, rotated_cfg);
    let decrypted = rotated
        .get_object("bucket", "obj", &ctx, None, None)
        .await
        .unwrap();
    //= ../spec/s3-encryption/client.md#optional-api-operations
    //= type=test
    //= reason=the new RSA keyring recovers the plaintext, proving re_encrypt re-wrapped the plaintext data key under the provided keyring
    //# - ReEncryptInstructionFile MUST re-encrypt the plaintext data key with a provided keyring.
    assert_eq!(decrypted.plaintext.as_slice(), plaintext.as_slice());
}
