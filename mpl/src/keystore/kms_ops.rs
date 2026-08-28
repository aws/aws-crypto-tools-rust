// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! KMS-backed read helpers for the [`BranchKeyStore`](super::BranchKeyStore).
//!
//! Implements the cross-cutting "Authenticating a Keystore item" and
//! "AWS KMS Branch Key Decryption" sections of `branch-key-store.md`,
//! used by `GetActiveBranchKey`, `GetBranchKeyVersion`, `GetBeaconKey`,
//! and `VersionKey`.
//!
//! These helpers are crate-internal and live separately from
//! `branch_key_store.rs` so the trait impl stays focused on op routing.
//! Callers pass references — neither helper takes ownership of the KMS
//! client or the record.

use std::collections::BTreeMap;

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;

use crate::keystore::attributes::{ATTR_ENC, ATTR_KMS_ARN};
use crate::keystore::config::KmsConfiguration;
use crate::keystore::error::{KeystoreError, KeystoreErrorKind};
use crate::keystore::kms_config::{is_arn_compatible, parse_arn};
use crate::keystore::record::EncryptedRecord;

/// Encryption-context key under which the logical keystore name is
/// bound. Per `branch-key-store.md#encryption-context` this key is the
/// only EC key NOT echoed as a DDB attribute.
const EC_KEY_TABLENAME: &str = "tablename";

/// Build the authenticated encryption context used for both
/// `Authenticating a Keystore item` and `AWS KMS Branch Key Decryption`.
///
/// The constructed EC contains:
/// 1. Every attribute on the DDB response item (these are authenticated
///    end-to-end by KMS).
/// 2. A single `tablename` entry whose value is the configured logical
///    keystore name.
///
/// `record_attributes` is taken from [`EncryptedRecord::attributes`] —
/// note that `enc` is not part of `attributes` (it lives in the
/// separate [`EncryptedRecord::enc`] field), so the "MUST NOT contain
/// `enc`" rule is satisfied by the input shape.
pub(crate) fn build_authenticated_encryption_context(
    record_attributes: &BTreeMap<String, String>,
    logical_keystore_name: &str,
) -> BTreeMap<String, String> {
    let mut ec = BTreeMap::new();

    //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //# Every attribute except for `enc` on the AWS DDB response item
    //# MUST be authenticated in the decryption of `enc`
    //
    //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //# Every key in the constructed [encryption context](#encryption-context)
    //# except `tableName`
    //# MUST exist as a string attribute in the AWS DDB response item.
    //
    //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //# Every value in the constructed [encryption context](#encryption-context)
    //# except the logical table name
    //# MUST equal the value with the same key in the AWS DDB response item.
    //
    //= spec/framework/branch-key-store.md#encryption-context
    //# Any additionally attributes on the DynamoDB item
    //# MUST be added to the encryption context.
    for (k, v) in record_attributes {
        ec.insert(k.clone(), v.clone());
    }

    // Bind the configured logical keystore name. This is the only EC key
    // that is NOT echoed as a DDB attribute (it lives in the keystore's
    // configuration, not the record).
    ec.insert(
        EC_KEY_TABLENAME.to_string(),
        logical_keystore_name.to_string(),
    );

    // `EncryptedRecord::attributes` does not contain `enc` by construction
    // — `enc` is the binary `EncryptedRecord::enc` field — so the EC built
    // above cannot contain an `enc` key.
    //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //# The key `enc` MUST NOT exist in the constructed [encryption context](#encryption-context).
    debug_assert!(
        !ec.contains_key(ATTR_ENC),
        "constructed EC must not contain 'enc'"
    );

    ec
}

/// Resolve the KMS Key ARN to use as `KeyId` (for `Decrypt`) or as
/// `SourceKeyId`/`DestinationKeyId` (for `ReEncrypt`).
///
/// - `KmsKeyArn` / `KmsMrKeyArn`: the record's `kms-arn` MUST be
///   compatible with the configured ARN. Returns the configured ARN.
/// - `Discovery`: the record's `kms-arn` MUST NOT be an alias. Returns
///   the record's ARN verbatim.
/// - `MrDiscovery { region }`: the record's `kms-arn` MUST NOT be an
///   alias. Returns the record's ARN with its region rewritten to the
///   configured region.
pub(crate) fn resolve_keystore_arn(
    kms_config: &KmsConfiguration,
    record_kms_arn: &str,
) -> Result<String, KeystoreError> {
    match kms_config {
        KmsConfiguration::KmsKeyArn(configured) | KmsConfiguration::KmsMrKeyArn(configured) => {
            //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
            //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `KMS Key ARN` or `KMS MRKey ARN`,
            //# the `kms-arn` field of the DDB response item MUST be
            //# [compatible with](#aws-key-arn-compatibility) the configured KMS Key in
            //# the [AWS KMS Configuration](#aws-kms-configuration) for this keystore,
            //# or the operation MUST fail.
            if !is_arn_compatible(kms_config, record_kms_arn) {
                return Err(KeystoreError::new(
                    KeystoreErrorKind::Authentication,
                    format!(
                        "Record kms-arn '{record_kms_arn}' is not compatible with the configured KMS Key '{configured}'",
                    ),
                ));
            }
            //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
            //# Otherwise, it MUST BE the Keystore's configured KMS Key.
            Ok(configured.clone())
        }
        KmsConfiguration::Discovery => {
            reject_alias_arn(record_kms_arn)?;
            //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
            //# - `KeyId`, if the KMS Configuration is Discovery, MUST be the `kms-arn` attribute value of the AWS DDB response item.
            //
            //= spec/framework/branch-key-store.md#discovery
            //# The Keystore MAY use the KMS Key ARNs already
            //# persisted to the backing DynamoDB table,
            //# provided they are in records created
            //# with an identical Logical Keystore Name.
            Ok(record_kms_arn.to_string())
        }
        KmsConfiguration::MrDiscovery { region } => {
            reject_alias_arn(record_kms_arn)?;
            //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
            //# If the KMS Configuration is MRDiscovery, `KeyId` MUST be the `kms-arn` attribute value of the AWS DDB response item, with the region replaced by the configured region.
            //
            //= spec/framework/branch-key-store.md#mrdiscovery
            //# The Keystore MAY use the KMS Key ARNs already
            //# persisted to the backing DynamoDB table,
            //# provided they are in records created
            //# with an identical Logical Keystore Name.
            rewrite_arn_region(record_kms_arn, region)
        }
    }
}

/// Validate that `arn` is not an AWS KMS alias ARN. Used by Discovery
/// and MRDiscovery before passing the record's `kms-arn` to KMS.
fn reject_alias_arn(arn: &str) -> Result<(), KeystoreError> {
    let parts = parse_arn(arn).map_err(|e| {
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!("Record kms-arn is malformed: {}", e.message()),
        )
    })?;
    if parts.resource_type == "alias" {
        //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
        //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `Discovery` or `MRDiscovery`,
        //# the `kms-arn` field of DDB response item MUST NOT be an Alias
        //# or the operation MUST fail.
        return Err(KeystoreError::new(
            KeystoreErrorKind::Authentication,
            format!("Record kms-arn must not be an alias: {arn}"),
        ));
    }
    Ok(())
}

/// Rewrite the region segment of an AWS ARN to `new_region`. The
/// resource-type / resource portion (which may itself contain `/`) is
/// preserved verbatim.
fn rewrite_arn_region(arn: &str, new_region: &str) -> Result<String, KeystoreError> {
    let parts = parse_arn(arn).map_err(|e| {
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!("Record kms-arn is malformed: {}", e.message()),
        )
    })?;
    Ok(format!(
        "arn:{}:{}:{}:{}:{}/{}",
        parts.partition,
        parts.service,
        new_region,
        parts.account_id,
        parts.resource_type,
        parts.resource,
    ))
}

/// Decrypt a branch-key record's `enc` blob through KMS, with the
/// constructed encryption context bound as the AAD. Returns the
/// plaintext branch key bytes.
pub(crate) async fn decrypt_branch_key(
    kms_client: &KmsClient,
    kms_config: &KmsConfiguration,
    record: &EncryptedRecord,
    logical_keystore_name: &str,
    grant_tokens: &[String],
) -> Result<Vec<u8>, KeystoreError> {
    let ec = build_authenticated_encryption_context(&record.attributes, logical_keystore_name);

    let record_kms_arn = record.attributes.get(ATTR_KMS_ARN).ok_or_else(|| {
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!("Record is missing the '{ATTR_KMS_ARN}' attribute"),
        )
    })?;

    let resolved_key_id = resolve_keystore_arn(kms_config, record_kms_arn)?;

    //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //# The operation MUST use the configured `KMS SDK Client` to decrypt the value of the branch key field.
    //
    //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //# When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html),
    //# the keystore operation MUST call with a request constructed as follows:
    let response = kms_client
        .decrypt()
        .key_id(resolved_key_id)
        //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
        //# - `CiphertextBlob` MUST be the `enc` attribute value on the AWS DDB response item
        .ciphertext_blob(Blob::new(record.enc.clone()))
        //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
        //# - `EncryptionContext` MUST be the [encryption context](#encryption-context) constructed above
        .set_encryption_context(Some(ec.into_iter().collect()))
        //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
        //# - `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
        .set_grant_tokens(Some(grant_tokens.to_vec()))
        .send()
        .await
        .map_err(map_kms_error)?;

    let plaintext = response
        .plaintext
        .ok_or_else(|| {
            KeystoreError::new(
                KeystoreErrorKind::Kms,
                "KMS Decrypt response is missing Plaintext",
            )
        })?
        .into_inner();
    Ok(plaintext)
}

/// Map any AWS KMS SDK error into a `KeystoreError`. We collapse all
/// SDK error variants into `KeystoreErrorKind::Kms` since callers only
/// need the categorisation, not the raw SDK error type.
// TODO: attach the SDK error as the `cause` instead of only formatting it into
// the message. Collapsing to a kind is right for callers that just branch on
// category, but discarding the error loses the KMS exception name, so nothing
// downstream can tell an IncorrectKeyException from throttling or access
// denied. `KeystoreError` already carries a `cause` field for this; the
// blocker is the `E: std::error::Error` bound here, which needs
// `Send + Sync + 'static` to be storable. Tests currently have to settle for
// asserting the kind — see `assert_failed_at_kms` in
// tests/test_aws_kms_hierarchical_keyring_integ.rs.
fn map_kms_error<E>(err: E) -> KeystoreError
where
    E: std::error::Error,
{
    KeystoreError::new(
        KeystoreErrorKind::Kms,
        format!("AWS KMS call failed: {err}"),
    )
}

/// Generate a fresh 32-byte data key wrapped under `key_arn`, bound to
/// `encryption_context`, via KMS `GenerateDataKeyWithoutPlaintext`.
/// Returns the wrapped-key `CiphertextBlob`.
pub(crate) async fn generate_wrapped_key(
    kms_client: &KmsClient,
    key_arn: &str,
    encryption_context: &BTreeMap<String, String>,
    grant_tokens: &[String],
) -> Result<Vec<u8>, KeystoreError> {
    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //# The call to AWS KMS GenerateDataKeyWithoutPlaintext MUST use the configured AWS KMS client to make the call.
    //
    //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //# The call to AWS KMS GenerateDataKeyWithoutPlaintext MUST use the configured AWS KMS client to make the call.
    let response = kms_client
        //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
        //# The operation MUST call [AWS KMS API GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html).
        //
        //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
        //# The operation MUST call [AWS KMS API GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html).
        //
        //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
        //# The operation MUST call AWS KMS GenerateDataKeyWithoutPlaintext with a request constructed as follows:
        //
        //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
        //# The operation MUST call AWS KMS GenerateDataKeyWithoutPlaintext with a request constructed as follows:
        .generate_data_key_without_plaintext()
        .key_id(key_arn)
        //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
        //# - `NumberOfBytes` MUST be 32.
        //
        //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
        //# - `NumberOfBytes` MUST be 32.
        .number_of_bytes(32)
        .set_encryption_context(Some(
            encryption_context
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ))
        //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
        //# - GenerateDataKeyWithoutPlaintext `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
        //
        //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
        //# - `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
        .set_grant_tokens(Some(grant_tokens.to_vec()))
        .send()
        .await
        .map_err(map_kms_error)?;

    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //# If the call to AWS KMS GenerateDataKeyWithoutPlaintext succeeds,
    //# the operation MUST use the GenerateDataKeyWithoutPlaintext result `CiphertextBlob`
    //# as the wrapped DECRYPT_ONLY Branch Key.
    //
    //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //# If the call to AWS KMS GenerateDataKeyWithoutPlaintext succeeds,
    //# the operation MUST use the `CiphertextBlob` as the wrapped Beacon Key.
    Ok(response
        .ciphertext_blob
        .ok_or_else(|| {
            KeystoreError::new(
                KeystoreErrorKind::Kms,
                "KMS GenerateDataKeyWithoutPlaintext response is missing CiphertextBlob",
            )
        })?
        .into_inner())
}

/// Re-encrypt a wrapped key from `source_encryption_context` to
/// `destination_encryption_context` under the same `key_arn`, via KMS
/// `ReEncrypt`. Returns the re-wrapped `CiphertextBlob`.
pub(crate) async fn reencrypt_wrapped_key(
    kms_client: &KmsClient,
    key_arn: &str,
    ciphertext: &[u8],
    source_encryption_context: &BTreeMap<String, String>,
    destination_encryption_context: &BTreeMap<String, String>,
    grant_tokens: &[String],
) -> Result<Vec<u8>, KeystoreError> {
    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //# The operation MUST call [AWS KMS API ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)
    //# with a request constructed as follows:
    //
    //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
    //# The operation MUST call [AWS KMS API ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)
    //# with a request constructed as follows:
    let response = kms_client
        .re_encrypt()
        .ciphertext_blob(Blob::new(ciphertext.to_vec()))
        .source_key_id(key_arn)
        .destination_key_id(key_arn)
        .set_source_encryption_context(Some(
            source_encryption_context
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ))
        .set_destination_encryption_context(Some(
            destination_encryption_context
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ))
        //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
        //# - ReEncrypt `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
        //
        //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
        //# - `GrantTokens` MUST be the configured [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
        .set_grant_tokens(Some(grant_tokens.to_vec()))
        .send()
        .await
        .map_err(map_kms_error)?;

    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //# If the call to AWS KMS ReEncrypt succeeds,
    //# the operation MUST use the ReEncrypt result `CiphertextBlob`
    //# as the wrapped ACTIVE Branch Key.
    Ok(response
        .ciphertext_blob
        .ok_or_else(|| {
            KeystoreError::new(
                KeystoreErrorKind::Kms,
                "KMS ReEncrypt response is missing CiphertextBlob",
            )
        })?
        .into_inner())
}
