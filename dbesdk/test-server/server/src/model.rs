// The rpcv2Cbor wire model, hand-mapped from
// aws-crypto-tools-commons/dbesdk/test-server/model/dbesdk-test-server.smithy.
//
// rpcv2Cbor encodes each structure as a CBOR map keyed by member name, so every
// field here renames to its exact Smithy member name. The polymorphic shapes
// (Keyring, CryptographicMaterialsManager, AttributeValue) are modeled in the
// Smithy file as *structures* with all-optional members (exactly one set at
// runtime), not as Smithy unions — so they are plain structs here too, and
// serialize as a one-key map, which is byte-identical to the wire.
//
// serde treats a missing `Option<T>` field as `None`, and ignores unknown map
// keys, so absent optional members and forward-compatible additions both
// deserialize cleanly. `serde_bytes::ByteBuf` forces Blob members to CBOR byte
// strings (major type 2) rather than arrays of integers.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::HashMap;

pub type DdbItem = HashMap<String, AttributeValue>;

// ---------------------------------------------------------------------------
// Operation request / response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub config: DbeClientConfig,
}

#[derive(Debug, Serialize)]
pub struct CreateClientResponse {
    #[serde(rename = "clientId")]
    pub client_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EncryptItemRequest {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "plaintextItem")]
    pub plaintext_item: DdbItem,
}

#[derive(Debug, Serialize)]
pub struct EncryptItemResponse {
    #[serde(rename = "encryptedItem")]
    pub encrypted_item: DdbItem,
}

#[derive(Debug, Deserialize)]
pub struct DecryptItemRequest {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "encryptedItem")]
    pub encrypted_item: DdbItem,
}

#[derive(Debug, Serialize)]
pub struct DecryptItemResponse {
    #[serde(rename = "plaintextItem")]
    pub plaintext_item: DdbItem,
}

// ---------------------------------------------------------------------------
// AttributeValue — DDB data-plane scalar shape (MVP: S / N / B / BOOL / NULL).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeValue {
    #[serde(rename = "S", skip_serializing_if = "Option::is_none", default)]
    pub s: Option<String>,
    #[serde(rename = "N", skip_serializing_if = "Option::is_none", default)]
    pub n: Option<String>,
    #[serde(rename = "B", skip_serializing_if = "Option::is_none", default)]
    pub b: Option<ByteBuf>,
    #[serde(rename = "BOOL", skip_serializing_if = "Option::is_none", default)]
    pub bool_value: Option<bool>,
    #[serde(rename = "NULL", skip_serializing_if = "Option::is_none", default)]
    pub null: Option<bool>,
}

// ---------------------------------------------------------------------------
// DBE client configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DbeClientConfig {
    #[serde(rename = "logicalTableName")]
    pub logical_table_name: String,
    #[serde(rename = "partitionKeyName")]
    pub partition_key_name: String,
    #[serde(rename = "sortKeyName", default)]
    pub sort_key_name: Option<String>,
    #[serde(rename = "attributeActionsOnEncrypt")]
    pub attribute_actions_on_encrypt: HashMap<String, CryptoAction>,
    #[serde(rename = "allowedUnsignedAttributePrefix", default)]
    pub allowed_unsigned_attribute_prefix: Option<String>,
    #[serde(rename = "allowedUnsignedAttributes", default)]
    pub allowed_unsigned_attributes: Option<Vec<String>>,
    #[serde(rename = "algorithmSuiteId", default)]
    pub algorithm_suite_id: Option<DbeAlgorithmSuiteId>,
    #[serde(default)]
    pub keyring: Option<Keyring>,
    #[serde(default)]
    pub cmm: Option<CryptographicMaterialsManager>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum CryptoAction {
    #[serde(rename = "ENCRYPT_AND_SIGN")]
    EncryptAndSign,
    #[serde(rename = "SIGN_ONLY")]
    SignOnly,
    #[serde(rename = "DO_NOTHING")]
    DoNothing,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum DbeAlgorithmSuiteId {
    #[serde(rename = "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384")]
    Symsig,
    #[serde(rename = "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384")]
    EcdsaSymsig,
}

// ---------------------------------------------------------------------------
// Cryptographic Materials Managers (recursive; one member set)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CryptographicMaterialsManager {
    #[serde(rename = "Default", default)]
    pub default: Option<DefaultCmmConfig>,
    #[serde(rename = "RequiredEncryptionContext", default)]
    pub required_encryption_context: Option<RequiredEncryptionContextCmmConfig>,
    #[serde(rename = "Caching", default)]
    pub caching: Option<CachingCmmConfig>,
}

#[derive(Debug, Deserialize)]
pub struct DefaultCmmConfig {
    pub keyring: Keyring,
}

#[derive(Debug, Deserialize)]
pub struct RequiredEncryptionContextCmmConfig {
    #[serde(rename = "underlyingCMM")]
    pub underlying_cmm: Box<CryptographicMaterialsManager>,
    #[serde(rename = "requiredEncryptionContextKeys")]
    pub required_encryption_context_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
// Wire-complete but deferred in factory.rs (returns GenericServerError); the
// Java factory also leaves the Caching CMM unwired.
#[allow(dead_code)]
pub struct CachingCmmConfig {
    #[serde(rename = "underlyingCMM")]
    pub underlying_cmm: Box<CryptographicMaterialsManager>,
    #[serde(rename = "cacheLimitTtlSeconds")]
    pub cache_limit_ttl_seconds: i32,
    #[serde(rename = "partitionId", default)]
    pub partition_id: Option<String>,
    #[serde(rename = "limitBytes", default)]
    pub limit_bytes: Option<i64>,
    #[serde(rename = "limitMessages", default)]
    pub limit_messages: Option<i64>,
}

// ---------------------------------------------------------------------------
// Keyrings (recursive via Multi; one member set)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Keyring {
    #[serde(rename = "AwsKms", default)]
    pub aws_kms: Option<AwsKmsKeyringConfig>,
    #[serde(rename = "AwsKmsMrk", default)]
    pub aws_kms_mrk: Option<AwsKmsMrkKeyringConfig>,
    #[serde(rename = "AwsKmsMultiKeyring", default)]
    pub aws_kms_multi: Option<AwsKmsMultiKeyringConfig>,
    #[serde(rename = "AwsKmsMrkMultiKeyring", default)]
    pub aws_kms_mrk_multi: Option<AwsKmsMrkMultiKeyringConfig>,
    #[serde(rename = "AwsKmsDiscovery", default)]
    pub aws_kms_discovery: Option<AwsKmsDiscoveryKeyringConfig>,
    #[serde(rename = "AwsKmsMrkDiscovery", default)]
    pub aws_kms_mrk_discovery: Option<AwsKmsMrkDiscoveryKeyringConfig>,
    #[serde(rename = "AwsKmsRsa", default)]
    pub aws_kms_rsa: Option<AwsKmsRsaKeyringConfig>,
    #[serde(rename = "RawAes", default)]
    pub raw_aes: Option<RawAesKeyringConfig>,
    #[serde(rename = "RawRsa", default)]
    pub raw_rsa: Option<RawRsaKeyringConfig>,
    #[serde(rename = "AwsKmsHierarchical", default)]
    pub aws_kms_hierarchical: Option<AwsKmsHierarchicalKeyringConfig>,
    #[serde(rename = "Multi", default)]
    pub multi: Option<MultiKeyringConfig>,
}

#[derive(Debug, Deserialize)]
pub struct AwsKmsKeyringConfig {
    #[serde(rename = "kmsKeyId")]
    pub kms_key_id: String,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct AwsKmsMrkKeyringConfig {
    #[serde(rename = "kmsKeyId")]
    pub kms_key_id: String,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct AwsKmsMultiKeyringConfig {
    #[serde(rename = "generator", default)]
    pub generator: Option<String>,
    #[serde(rename = "kmsKeyIds", default)]
    pub kms_key_ids: Option<Vec<String>>,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct AwsKmsMrkMultiKeyringConfig {
    #[serde(rename = "generator", default)]
    pub generator: Option<String>,
    #[serde(rename = "kmsKeyIds", default)]
    pub kms_key_ids: Option<Vec<String>>,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct AwsKmsDiscoveryKeyringConfig {
    #[serde(rename = "discoveryFilter", default)]
    pub discovery_filter: Option<DiscoveryFilter>,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct AwsKmsMrkDiscoveryKeyringConfig {
    pub region: String,
    #[serde(rename = "discoveryFilter", default)]
    pub discovery_filter: Option<DiscoveryFilter>,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
// Wire-complete but deferred in factory.rs (returns GenericServerError): fields
// are parsed off the wire but not yet consumed. Not in the [raw-aes, aws-kms]
// Feature_Catalog.
#[allow(dead_code)]
pub struct AwsKmsRsaKeyringConfig {
    #[serde(rename = "kmsKeyId")]
    pub kms_key_id: String,
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<ByteBuf>,
    #[serde(rename = "encryptionAlgorithm", default)]
    pub encryption_algorithm: Option<KmsRsaEncryptionAlgorithm>,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct DiscoveryFilter {
    pub partition: String,
    #[serde(rename = "accountIds")]
    pub account_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum KmsRsaEncryptionAlgorithm {
    #[serde(rename = "RSAES_OAEP_SHA_1")]
    OaepSha1,
    #[serde(rename = "RSAES_OAEP_SHA_256")]
    OaepSha256,
}

#[derive(Debug, Deserialize)]
pub struct RawAesKeyringConfig {
    #[serde(rename = "keyNamespace")]
    pub key_namespace: String,
    #[serde(rename = "keyName")]
    pub key_name: String,
    #[serde(rename = "wrappingKey")]
    pub wrapping_key: ByteBuf,
    #[serde(rename = "wrappingAlg")]
    pub wrapping_alg: AesWrappingAlg,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum AesWrappingAlg {
    #[serde(rename = "ALG_AES128_GCM_IV12_TAG16")]
    Aes128,
    #[serde(rename = "ALG_AES192_GCM_IV12_TAG16")]
    Aes192,
    #[serde(rename = "ALG_AES256_GCM_IV12_TAG16")]
    Aes256,
}

#[derive(Debug, Deserialize)]
pub struct RawRsaKeyringConfig {
    #[serde(rename = "keyNamespace")]
    pub key_namespace: String,
    #[serde(rename = "keyName")]
    pub key_name: String,
    #[serde(rename = "paddingScheme")]
    pub padding_scheme: PaddingScheme,
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<ByteBuf>,
    #[serde(rename = "privateKey", default)]
    pub private_key: Option<ByteBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum PaddingScheme {
    #[serde(rename = "PKCS1")]
    Pkcs1,
    #[serde(rename = "OAEP_SHA1_MGF1")]
    OaepSha1Mgf1,
    #[serde(rename = "OAEP_SHA256_MGF1")]
    OaepSha256Mgf1,
    #[serde(rename = "OAEP_SHA384_MGF1")]
    OaepSha384Mgf1,
    #[serde(rename = "OAEP_SHA512_MGF1")]
    OaepSha512Mgf1,
}

#[derive(Debug, Deserialize)]
// Wire-complete but deferred in factory.rs (returns GenericServerError).
#[allow(dead_code)]
pub struct AwsKmsHierarchicalKeyringConfig {
    #[serde(rename = "branchKeyId")]
    pub branch_key_id: String,
    #[serde(rename = "keyStoreTableName")]
    pub key_store_table_name: String,
    #[serde(rename = "logicalKeyStoreName")]
    pub logical_key_store_name: String,
    #[serde(rename = "kmsKeyArn")]
    pub kms_key_arn: String,
    #[serde(rename = "ttlSeconds")]
    pub ttl_seconds: i32,
}

#[derive(Debug, Deserialize)]
pub struct MultiKeyringConfig {
    #[serde(rename = "generator", default)]
    pub generator: Option<Box<Keyring>>,
    #[serde(rename = "childKeyrings")]
    pub child_keyrings: Vec<Keyring>,
}
