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
//!
//! Slice 1b lands these helpers and their pure-logic unit tests; slice
//! 1c wires them into `get_active_branch_key` / `get_branch_key_version`
//! / `version_key`. Until that wiring lands the helpers compile but are
//! not called from anywhere in the library — `#[allow(dead_code)]` keeps
//! the build clean.
#![allow(dead_code)]

use std::collections::BTreeMap;

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;

use crate::keystore::config::KmsConfiguration;
use crate::keystore::error::{KeystoreError, KeystoreErrorKind};
use crate::keystore::kms_config::{is_arn_compatible, parse_arn};
use crate::keystore::record::{EncryptedRecord, FIELD_ENC, FIELD_KMS_ARN};

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
//
pub(crate) fn build_authenticated_encryption_context(
    record_attributes: &BTreeMap<String, String>,
    logical_keystore_name: &str,
) -> BTreeMap<String, String> {
    let mut ec = BTreeMap::new();

    //
    //
    //
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

    //
    //
    // `EncryptedRecord::attributes` does not contain `enc` by construction
    // — `enc` is the binary `EncryptedRecord::enc` field — so the EC built
    // above cannot contain an `enc` key.
    debug_assert!(
        !ec.contains_key(FIELD_ENC),
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
            if !is_arn_compatible(kms_config, record_kms_arn) {
                return Err(KeystoreError::new(
                    KeystoreErrorKind::Authentication,
                    format!(
                        "Record kms-arn '{record_kms_arn}' is not compatible with the configured KMS Key '{configured}'",
                    ),
                ));
            }
            Ok(configured.clone())
        }
        KmsConfiguration::Discovery => {
            reject_alias_arn(record_kms_arn)?;
            Ok(record_kms_arn.to_string())
        }
        KmsConfiguration::MrDiscovery { region } => {
            reject_alias_arn(record_kms_arn)?;
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

/// Authenticate a DDB-fetched keystore item by re-encrypting its `enc`
/// blob through KMS with the constructed encryption context as both
/// the source and destination EC. A successful `ReEncrypt` proves the
/// item's attributes have not been tampered with.
///
/// Returns the new ciphertext blob from the `ReEncrypt` response.
pub(crate) async fn authenticate_keystore_item(
    kms_client: &KmsClient,
    kms_config: &KmsConfiguration,
    record: &EncryptedRecord,
    logical_keystore_name: &str,
    grant_tokens: &[String],
) -> Result<Vec<u8>, KeystoreError> {
    let ec = build_authenticated_encryption_context(&record.attributes, logical_keystore_name);

    let record_kms_arn = record.attributes.get(FIELD_KMS_ARN).ok_or_else(|| {
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!("Record is missing the '{FIELD_KMS_ARN}' attribute"),
        )
    })?;

    let resolved_key_id = resolve_keystore_arn(kms_config, record_kms_arn)?;

    //
    let response = kms_client
        .re_encrypt()
        .set_source_encryption_context(Some(
            ec.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ))
        .source_key_id(resolved_key_id.clone())
        .ciphertext_blob(Blob::new(record.enc.clone()))
        .set_grant_tokens(Some(grant_tokens.to_vec()))
        .destination_key_id(resolved_key_id)
        .set_destination_encryption_context(Some(ec.into_iter().collect()))
        .send()
        .await
        .map_err(map_kms_error)?;

    let new_ciphertext = response
        .ciphertext_blob
        .ok_or_else(|| {
            KeystoreError::new(
                KeystoreErrorKind::Kms,
                "KMS ReEncrypt response is missing CiphertextBlob",
            )
        })?
        .into_inner();
    Ok(new_ciphertext)
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

    let record_kms_arn = record.attributes.get(FIELD_KMS_ARN).ok_or_else(|| {
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!("Record is missing the '{FIELD_KMS_ARN}' attribute"),
        )
    })?;

    //
    //
    let resolved_key_id = resolve_keystore_arn(kms_config, record_kms_arn)?;

    //
    let response = kms_client
        .decrypt()
        .key_id(resolved_key_id)
        .ciphertext_blob(Blob::new(record.enc.clone()))
        .set_encryption_context(Some(ec.into_iter().collect()))
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
fn map_kms_error<E>(err: E) -> KeystoreError
where
    E: std::error::Error,
{
    KeystoreError::new(
        KeystoreErrorKind::Kms,
        format!("AWS KMS call failed: {err}"),
    )
}
