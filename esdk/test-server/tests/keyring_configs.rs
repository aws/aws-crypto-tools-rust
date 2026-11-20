// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Every modeled keyring and CMM builds from its `CreateClient` config.
//! The AWS KMS ones only build,
//! because building contacts no AWS service when every key is supplied.

use aws_esdk_test_server::handlers::AppState;
use aws_esdk_test_server::model::{
    AwsKmsKeyringConfig, CreateClientRequest, CryptographicMaterialsManager, DefaultCmmConfig,
    EsdkClientConfig, EsdkCommitmentPolicy, Keyring,
};

const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

fn default_cmm(keyring: Keyring) -> CryptographicMaterialsManager {
    CryptographicMaterialsManager {
        default_cmm: Some(DefaultCmmConfig { keyring }),
        ..Default::default()
    }
}

fn config(cmm: CryptographicMaterialsManager) -> CreateClientRequest {
    CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm,
        },
    }
}

async fn create(state: &AppState, cmm: CryptographicMaterialsManager) -> String {
    state
        .create_client(config(cmm))
        .await
        .unwrap_or_else(|e| panic!("CreateClient failed: {}", e.message()))
        .client_id
}

#[tokio::test]
async fn aws_kms_keyring_builds() {
    let keyring = Keyring {
        aws_kms: Some(AwsKmsKeyringConfig {
            kms_key_id: KMS_KEY_ARN.to_owned(),
            grant_tokens: None,
        }),
        ..Default::default()
    };
    create(&AppState::new(), default_cmm(keyring)).await;
}
