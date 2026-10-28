// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native Rust mirror of the DB-ESDK TestServer Smithy model shapes this server
//! serves, with serde renames matching each model member name and `serde_bytes`
//! on blob members so they travel as CBOR byte strings (rpcv2Cbor), not arrays.
//!
//! `AttributeValue` and `Keyring` are modeled in Smithy as structures whose
//! members are all optional ("tagged union via optional members"); the
//! exactly-one-set invariant is enforced at runtime.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::HashMap;

/// A DDB item: attribute name to value.
pub type DdbItem = HashMap<String, AttributeValue>;

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

#[derive(Debug, Deserialize)]
pub struct GetEncryptedDataKeyDescriptionRequest {
    pub input: EncryptedDataKeyDescriptionSource,
}

/// The `header` / `item` union; exactly one member is set.
#[derive(Debug, Deserialize)]
pub struct EncryptedDataKeyDescriptionSource {
    #[serde(default)]
    pub header: Option<ByteBuf>,
    #[serde(default)]
    pub item: Option<DdbItem>,
}

#[derive(Debug, Serialize)]
pub struct GetEncryptedDataKeyDescriptionResponse {
    pub descriptions: Vec<EncryptedDataKeyDescription>,
}

#[derive(Debug, Serialize)]
pub struct EncryptedDataKeyDescription {
    #[serde(rename = "keyProviderId")]
    pub key_provider_id: String,
    #[serde(rename = "keyProviderInfo", skip_serializing_if = "Option::is_none")]
    pub key_provider_info: Option<String>,
    #[serde(rename = "branchKeyId", skip_serializing_if = "Option::is_none")]
    pub branch_key_id: Option<String>,
    #[serde(rename = "branchKeyVersion", skip_serializing_if = "Option::is_none")]
    pub branch_key_version: Option<String>,
}

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
    #[serde(rename = "SS", skip_serializing_if = "Option::is_none", default)]
    pub ss: Option<Vec<String>>,
    #[serde(rename = "NS", skip_serializing_if = "Option::is_none", default)]
    pub ns: Option<Vec<String>>,
    #[serde(rename = "BS", skip_serializing_if = "Option::is_none", default)]
    pub bs: Option<Vec<ByteBuf>>,
    #[serde(rename = "L", skip_serializing_if = "Option::is_none", default)]
    pub l: Option<Vec<AttributeValue>>,
    #[serde(rename = "M", skip_serializing_if = "Option::is_none", default)]
    pub m: Option<HashMap<String, AttributeValue>>,
}

/// The DBE item encryptor configuration. A legacy override, which this server
/// does not serve, is kept opaque so a request naming it is refused rather
/// than silently ignored.
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
    #[serde(rename = "plaintextOverride", default)]
    pub plaintext_override: Option<PlaintextOverride>,
    #[serde(rename = "legacyOverride", default)]
    pub legacy_override: Option<ciborium::Value>,
    #[serde(default)]
    pub keyring: Option<Keyring>,
    #[serde(default)]
    pub cmm: Option<CryptographicMaterialsManager>,
    #[serde(default)]
    pub search: Option<crate::search::SearchConfig>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CryptoAction {
    #[serde(rename = "ENCRYPT_AND_SIGN")]
    EncryptAndSign,
    #[serde(rename = "SIGN_ONLY")]
    SignOnly,
    #[serde(rename = "SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT")]
    SignAndIncludeInEncryptionContext,
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

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum PlaintextOverride {
    #[serde(rename = "FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ")]
    ForceWriteAllowRead,
    #[serde(rename = "FORBID_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ")]
    ForbidWriteAllowRead,
    #[serde(rename = "FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ")]
    ForbidWriteForbidRead,
}

/// The keyring union. Only the variants this server builds are typed; the rest
/// are kept opaque so naming one is refused.
#[derive(Debug, Deserialize)]
pub struct Keyring {
    #[serde(rename = "AwsKms", default)]
    pub aws_kms: Option<AwsKmsKeyringConfig>,
    #[serde(rename = "RawAes", default)]
    pub raw_aes: Option<RawAesKeyringConfig>,
    #[serde(rename = "RawRsa", default)]
    pub raw_rsa: Option<RawRsaKeyringConfig>,
    #[serde(rename = "AwsKmsRsa", default)]
    pub aws_kms_rsa: Option<AwsKmsRsaKeyringConfig>,
    #[serde(rename = "AwsKmsHierarchical", default)]
    pub aws_kms_hierarchical: Option<AwsKmsHierarchicalKeyringConfig>,
    #[serde(rename = "AwsKmsDiscovery", default)]
    pub aws_kms_discovery: Option<AwsKmsDiscoveryKeyringConfig>,
    #[serde(rename = "AwsKmsMultiKeyring", default)]
    pub aws_kms_multi_keyring: Option<AwsKmsMultiKeyringConfig>,
    #[serde(rename = "AwsKmsMrk", default)]
    pub aws_kms_mrk: Option<AwsKmsKeyringConfig>,
    #[serde(rename = "AwsKmsMrkDiscovery", default)]
    pub aws_kms_mrk_discovery: Option<AwsKmsMrkDiscoveryKeyringConfig>,
    #[serde(rename = "AwsKmsMrkMultiKeyring", default)]
    pub aws_kms_mrk_multi_keyring: Option<AwsKmsMultiKeyringConfig>,
    #[serde(rename = "Multi", default)]
    pub multi: Option<MultiKeyringConfig>,
    #[serde(flatten)]
    pub other: HashMap<String, ciborium::Value>,
}

/// A CMM: a tagged union via optional members; exactly one must be set.
#[derive(Debug, Default, Deserialize)]
pub struct CryptographicMaterialsManager {
    #[serde(rename = "Default", default)]
    pub default: Option<DefaultCmmConfig>,
    #[serde(rename = "RequiredEncryptionContext", default)]
    pub required_encryption_context: Option<Box<RequiredEncryptionContextCmmConfig>>,
    #[serde(flatten)]
    pub other: HashMap<String, ciborium::Value>,
}

/// A Default CMM over a keyring.
#[derive(Debug, Deserialize)]
pub struct DefaultCmmConfig {
    pub keyring: Keyring,
}

/// A CMM that requires some encryption context keys, over another CMM.
#[derive(Debug, Deserialize)]
pub struct RequiredEncryptionContextCmmConfig {
    #[serde(rename = "underlyingCMM")]
    pub underlying_cmm: CryptographicMaterialsManager,
    #[serde(rename = "requiredEncryptionContextKeys")]
    pub required_encryption_context_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AwsKmsKeyringConfig {
    #[serde(rename = "kmsKeyId")]
    pub kms_key_id: String,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

/// An AWS KMS RSA keyring: wraps client-side with the key's public key, unwraps with KMS.
/// Without `public_key`, the server fetches it with KMS `GetPublicKey`.
#[derive(Debug, Deserialize)]
pub struct AwsKmsRsaKeyringConfig {
    #[serde(rename = "kmsKeyId")]
    pub kms_key_id: String,
    #[serde(rename = "publicKey", default, with = "serde_bytes")]
    pub public_key: Option<Vec<u8>>,
    #[serde(rename = "encryptionAlgorithm", default)]
    pub encryption_algorithm: Option<KmsRsaEncryptionAlgorithm>,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum KmsRsaEncryptionAlgorithm {
    #[serde(rename = "RSAES_OAEP_SHA_1")]
    OaepSha1,
    #[serde(rename = "RSAES_OAEP_SHA_256")]
    OaepSha256,
}

/// A discovery keyring: decrypts with the AWS KMS key each data key names.
#[derive(Debug, Deserialize)]
pub struct AwsKmsDiscoveryKeyringConfig {
    #[serde(rename = "discoveryFilter", default)]
    pub discovery_filter: Option<DiscoveryFilter>,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

/// An MRK discovery keyring: decrypts in `region`, with the local replica of a multi-Region key.
#[derive(Debug, Deserialize)]
pub struct AwsKmsMrkDiscoveryKeyringConfig {
    pub region: String,
    #[serde(rename = "discoveryFilter", default)]
    pub discovery_filter: Option<DiscoveryFilter>,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct DiscoveryFilter {
    pub partition: String,
    #[serde(rename = "accountIds")]
    pub account_ids: Vec<String>,
}

/// A multi-keyring of AWS KMS keyrings: a generator key and other keys.
#[derive(Debug, Deserialize)]
pub struct AwsKmsMultiKeyringConfig {
    #[serde(default)]
    pub generator: Option<String>,
    #[serde(rename = "kmsKeyIds", default)]
    pub kms_key_ids: Option<Vec<String>>,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
}

/// A multi-keyring of modeled keyrings.
#[derive(Debug, Deserialize)]
pub struct MultiKeyringConfig {
    #[serde(default)]
    pub generator: Option<Box<Keyring>>,
    #[serde(rename = "childKeyrings")]
    pub child_keyrings: Vec<Keyring>,
}

/// A hierarchical keyring over a DynamoDB branch key store.
/// Exactly one of `branch_key_id` and `branch_key_id_supplier` is set.
#[derive(Debug, Deserialize)]
pub struct AwsKmsHierarchicalKeyringConfig {
    #[serde(rename = "branchKeyId", default)]
    pub branch_key_id: Option<String>,
    #[serde(rename = "branchKeyIdSupplier", default)]
    pub branch_key_id_supplier: Option<DdbKeyBranchKeyIdSupplier>,
    #[serde(rename = "keyStoreTableName")]
    pub key_store_table_name: String,
    #[serde(rename = "logicalKeyStoreName")]
    pub logical_key_store_name: String,
    #[serde(rename = "kmsKeyArn")]
    pub kms_key_arn: String,
    #[serde(rename = "ttlSeconds")]
    pub ttl_seconds: i64,
}

/// Route each item to a branch key by the String value of one of its key attributes.
#[derive(Debug, Deserialize)]
pub struct DdbKeyBranchKeyIdSupplier {
    #[serde(rename = "routeAttribute")]
    pub route_attribute: String,
    pub routes: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct RawAesKeyringConfig {
    #[serde(rename = "keyNamespace")]
    pub key_namespace: String,
    #[serde(rename = "keyName")]
    pub key_name: String,
    #[serde(rename = "wrappingKey", with = "serde_bytes")]
    pub wrapping_key: Vec<u8>,
    #[serde(rename = "wrappingAlg")]
    pub wrapping_alg: AesWrappingAlg,
}

#[derive(Debug, Deserialize)]
pub struct RawRsaKeyringConfig {
    #[serde(rename = "keyNamespace")]
    pub key_namespace: String,
    #[serde(rename = "keyName")]
    pub key_name: String,
    #[serde(rename = "paddingScheme")]
    pub padding_scheme: PaddingScheme,
    #[serde(rename = "publicKey", default, with = "serde_bytes")]
    pub public_key: Option<Vec<u8>>,
    #[serde(rename = "privateKey", default, with = "serde_bytes")]
    pub private_key: Option<Vec<u8>>,
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
pub struct CreateStructuredClientRequest {
    pub config: DbeClientConfig,
}

#[derive(Debug, Serialize)]
pub struct CreateStructuredClientResponse {
    #[serde(rename = "clientId")]
    pub client_id: String,
}

/// One structured-data terminal: opaque value bytes plus a 2-byte type id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredDataTerminal {
    pub value: ByteBuf,
    #[serde(rename = "typeId")]
    pub type_id: ByteBuf,
}

/// A field name to terminal map.
pub type StructuredDataMap = HashMap<String, StructuredDataTerminal>;

#[derive(Debug, Deserialize)]
pub struct EncryptStructureRequest {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "tableName")]
    pub table_name: String,
    #[serde(rename = "plaintextStructure")]
    pub plaintext_structure: StructuredDataMap,
    #[serde(rename = "cryptoSchema")]
    pub crypto_schema: HashMap<String, CryptoAction>,
}

#[derive(Debug, Serialize)]
pub struct EncryptStructureResponse {
    #[serde(rename = "encryptedStructure")]
    pub encrypted_structure: StructuredDataMap,
}

#[derive(Debug, Deserialize)]
pub struct DecryptStructureRequest {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "tableName")]
    pub table_name: String,
    #[serde(rename = "encryptedStructure")]
    pub encrypted_structure: StructuredDataMap,
    #[serde(rename = "authenticateSchema")]
    pub authenticate_schema: HashMap<String, AuthenticateAction>,
}

#[derive(Debug, Serialize)]
pub struct DecryptStructureResponse {
    #[serde(rename = "plaintextStructure")]
    pub plaintext_structure: StructuredDataMap,
}

/// One path-keyed Crypto Item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCryptoItem {
    pub path: Vec<String>,
    pub data: StructuredDataTerminal,
    pub action: CryptoAction,
}

/// One path-keyed Auth Item.
#[derive(Debug, Clone, Deserialize)]
pub struct PathAuthItem {
    pub path: Vec<String>,
    pub data: StructuredDataTerminal,
    pub action: AuthenticateAction,
}

#[derive(Debug, Deserialize)]
pub struct EncryptPathStructureRequest {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "tableName")]
    pub table_name: String,
    #[serde(rename = "plaintextStructure")]
    pub plaintext_structure: Vec<PathCryptoItem>,
}

#[derive(Debug, Serialize)]
pub struct EncryptPathStructureResponse {
    #[serde(rename = "encryptedStructure")]
    pub encrypted_structure: Vec<PathCryptoItem>,
}

#[derive(Debug, Deserialize)]
pub struct DecryptPathStructureRequest {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "tableName")]
    pub table_name: String,
    #[serde(rename = "encryptedStructure")]
    pub encrypted_structure: Vec<PathAuthItem>,
}

#[derive(Debug, Serialize)]
pub struct DecryptPathStructureResponse {
    #[serde(rename = "plaintextStructure")]
    pub plaintext_structure: Vec<PathCryptoItem>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveAuthActionsRequest {
    #[serde(rename = "tableName")]
    pub table_name: String,
    #[serde(rename = "authActions")]
    pub auth_actions: Vec<PathAuthItem>,
    #[serde(rename = "headerBytes")]
    pub header_bytes: ByteBuf,
}

#[derive(Debug, Serialize)]
pub struct ResolveAuthActionsResponse {
    #[serde(rename = "cryptoActions")]
    pub crypto_actions: Vec<PathCryptoItem>,
}

/// Whether a field is within the signature scope on decrypt.
#[derive(Debug, Clone, Copy, Deserialize)]
pub enum AuthenticateAction {
    #[serde(rename = "SIGN")]
    Sign,
    #[serde(rename = "DO_NOT_SIGN")]
    DoNotSign,
}
