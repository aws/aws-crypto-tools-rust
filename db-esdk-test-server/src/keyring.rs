// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Translate the modeled `Keyring` union into an MPL keyring.

use crate::error::ServerError;
use crate::model::{AesWrappingAlg, AwsKmsKeyringConfig, Keyring, RawAesKeyringConfig};
use aws_db_esdk::aws_config;
use aws_db_esdk::aws_sdk_kms;
use aws_db_esdk::keyring::{AwsKmsKeyring, RawAesKeyring, SharedKeyring};
use aws_db_esdk::types::AesWrappingAlg as MplAesWrappingAlg;

/// Build the keyring a modeled `Keyring` names; exactly one variant must be set.
pub async fn keyring_for_config(keyring: &Keyring) -> Result<SharedKeyring, ServerError> {
    let set = usize::from(keyring.aws_kms.is_some())
        + usize::from(keyring.raw_aes.is_some())
        + keyring.other.len();
    if set != 1 {
        return Err(ServerError::generic(format!(
            "Keyring must set exactly one variant, found {set}"
        )));
    }
    if let Some(raw_aes) = &keyring.raw_aes {
        return build_raw_aes(raw_aes);
    }
    if let Some(aws_kms) = &keyring.aws_kms {
        return build_aws_kms(aws_kms).await;
    }
    let name = keyring.other.keys().next().map_or("", String::as_str);
    Err(ServerError::generic(format!(
        "keyring variant {name} is not supported by the native Rust language server"
    )))
}

fn build_raw_aes(config: &RawAesKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let alg = match config.wrapping_alg {
        AesWrappingAlg::Aes128 => MplAesWrappingAlg::AlgAes128GcmIv12Tag16,
        AesWrappingAlg::Aes192 => MplAesWrappingAlg::AlgAes192GcmIv12Tag16,
        AesWrappingAlg::Aes256 => MplAesWrappingAlg::AlgAes256GcmIv12Tag16,
    };
    let keyring = RawAesKeyring::builder()
        .key_namespace(config.key_namespace.as_str())
        .key_name(config.key_name.as_str())
        .wrapping_key(config.wrapping_key.clone())
        .wrapping_alg(alg)
        .build()
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// The region of a KMS key ARN, if it is one.
fn region_of(key_id: &str) -> Option<String> {
    let parts: Vec<&str> = key_id.split(':').collect();
    match parts.as_slice() {
        ["arn", _, "kms", region, _, _] if !region.is_empty() => Some((*region).to_owned()),
        _ => None,
    }
}

async fn build_aws_kms(config: &AwsKmsKeyringConfig) -> Result<SharedKeyring, ServerError> {
    // AWS KMS rejects an ARN whose region differs from the client's.
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = region_of(&config.kms_key_id) {
        loader = loader.region(aws_config::Region::new(region));
    }
    let sdk_config = loader.load().await;
    let keyring = AwsKmsKeyring::builder()
        .kms_key_id(config.kms_key_id.as_str())
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}
