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

/// The DBE item encryptor configuration. Members this server does not serve
/// (a CMM, a legacy override, a search config) are kept opaque so a request
/// naming them is refused rather than silently ignored.
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
    pub cmm: Option<ciborium::Value>,
    #[serde(default)]
    pub search: Option<ciborium::Value>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
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
    #[serde(flatten)]
    pub other: HashMap<String, ciborium::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AwsKmsKeyringConfig {
    #[serde(rename = "kmsKeyId")]
    pub kms_key_id: String,
    #[serde(rename = "grantTokens", default)]
    pub grant_tokens: Option<Vec<String>>,
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

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum AesWrappingAlg {
    #[serde(rename = "ALG_AES128_GCM_IV12_TAG16")]
    Aes128,
    #[serde(rename = "ALG_AES192_GCM_IV12_TAG16")]
    Aes192,
    #[serde(rename = "ALG_AES256_GCM_IV12_TAG16")]
    Aes256,
}
