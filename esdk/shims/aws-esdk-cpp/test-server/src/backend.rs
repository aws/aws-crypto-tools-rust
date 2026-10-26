// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operation handlers: build a hierarchical keyring through the C++ shim and
//! forward encrypt/decrypt to the facade via `spawn_blocking` (the shim drives
//! its own runtime with `block_on`, which must not run on an async worker).

use crate::seam::{self, CppClient};
use aws_esdk_test_server::error::ServerError;
use aws_esdk_test_server::model::{
    AesWrappingAlg, CreateClientRequest, CreateClientResponse, CryptographicMaterialsManager,
    DecryptRequest, DecryptResponse, DecryptStreamRequest, DecryptStreamResponse, EncryptRequest,
    EncryptResponse, EncryptStreamRequest, EncryptStreamResponse, EsdkAlgorithmSuiteId,
    EsdkClientConfig, EsdkCommitmentPolicy, Keyring,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// A registered client: its C++ keyring plus the config applied to every call.
struct ClientEntry {
    client: Arc<Mutex<CppClient>>,
    commitment_policy: u8,
    /// 0 means "unset — no limit".
    max_encrypted_data_keys: u32,
}

/// The `clientId -> ClientEntry` registry.
#[derive(Default)]
pub struct CppBackend {
    clients: Mutex<HashMap<String, ClientEntry>>,
}

// Matches the C++ facade's CommitmentPolicy enum values.
fn commitment_code(policy: EsdkCommitmentPolicy) -> u8 {
    match policy {
        EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt => 1,
        EsdkCommitmentPolicy::RequireEncryptAllowDecrypt => 2,
        EsdkCommitmentPolicy::RequireEncryptRequireDecrypt => 3,
    }
}

// The C++ facade AlgorithmSuiteId enum is valued with the ESDK on-wire suite IDs.
fn suite_id(id: EsdkAlgorithmSuiteId) -> u16 {
    match id {
        EsdkAlgorithmSuiteId::Alg128GcmNoKdf => 0x0014,
        EsdkAlgorithmSuiteId::Alg192GcmNoKdf => 0x0046,
        EsdkAlgorithmSuiteId::Alg256GcmNoKdf => 0x0078,
        EsdkAlgorithmSuiteId::Alg128GcmHkdf => 0x0114,
        EsdkAlgorithmSuiteId::Alg192GcmHkdf => 0x0146,
        EsdkAlgorithmSuiteId::Alg256GcmHkdf => 0x0178,
        EsdkAlgorithmSuiteId::Alg128GcmHkdfEcdsa => 0x0214,
        EsdkAlgorithmSuiteId::Alg192GcmHkdfEcdsa => 0x0346,
        EsdkAlgorithmSuiteId::Alg256GcmHkdfEcdsa => 0x0378,
        EsdkAlgorithmSuiteId::Alg256GcmCommit => 0x0478,
        EsdkAlgorithmSuiteId::Alg256GcmCommitEcdsa => 0x0578,
    }
}

// 0 encodes "unset" over the FFI, so a configured value must be positive.
fn max_edks_code(config: &EsdkClientConfig) -> Result<u32, ServerError> {
    let Some(value) = config.max_encrypted_data_keys else {
        return Ok(0);
    };
    let Ok(code) = u32::try_from(value) else {
        return Err(ServerError::generic(format!(
            "maxEncryptedDataKeys out of range: {value}"
        )));
    };
    if code == 0 {
        return Err(ServerError::generic(
            "maxEncryptedDataKeys must be positive",
        ));
    }
    Ok(code)
}

fn encryption_context(map: Option<BTreeMap<String, String>>) -> Vec<(String, String)> {
    map.map(|m| m.into_iter().collect()).unwrap_or_default()
}

// 0 encodes "unset" over the FFI, so a configured frame length must be in 1..=u32::MAX.
// The commons suite expects an out-of-range frame length as ESDKClientError.
fn frame_length_code(frame_length: Option<i64>) -> Result<u32, ServerError> {
    match frame_length {
        Some(value) => match u32::try_from(value) {
            Ok(code) if code > 0 => Ok(code),
            _ => Err(ServerError::esdk(format!(
                "frameLength must be in 1..=u32::MAX, got {value}"
            ))),
        },
        None => Ok(0),
    }
}

// The C++ facade exposes the hierarchical and raw-AES keyrings, both wrapped in
// the Default CMM.
fn default_cmm_keyring(cmm: &CryptographicMaterialsManager) -> Result<&Keyring, ServerError> {
    let Some(default_cmm) = &cmm.default_cmm else {
        return Err(ServerError::generic(
            "the C++ shim server supports only the Default CMM",
        ));
    };
    Ok(&default_cmm.keyring)
}

// The FFI encodes the AES wrapping suite as 1/2/3 for AES-128/192/256-GCM.
fn wrapping_alg_code(alg: AesWrappingAlg) -> u8 {
    match alg {
        AesWrappingAlg::Alg128 => 1,
        AesWrappingAlg::Alg192 => 2,
        AesWrappingAlg::Alg256 => 3,
    }
}

/// The registered materials needed for one operation.
struct Materials {
    client: Arc<Mutex<CppClient>>,
    commitment_policy: u8,
    max_encrypted_data_keys: u32,
}

impl CppBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the configured keyring through the shim, register it, return its id.
    pub async fn create_client(
        &self,
        req: CreateClientRequest,
    ) -> Result<CreateClientResponse, ServerError> {
        let config = req.config;
        let commitment_policy = commitment_code(config.commitment_policy);
        let max_encrypted_data_keys = max_edks_code(&config)?;
        let keyring = default_cmm_keyring(&config.cmm)?;

        let create = if let Some(raw_aes) = &keyring.raw_aes {
            let key_namespace = raw_aes.key_namespace.clone();
            let key_name = raw_aes.key_name.clone();
            let wrapping_key = raw_aes.wrapping_key.clone();
            let wrapping_alg = wrapping_alg_code(raw_aes.wrapping_alg);
            tokio::task::spawn_blocking(move || {
                seam::create_raw_aes_client(&key_namespace, &key_name, &wrapping_key, wrapping_alg)
            })
        } else if let Some(hierarchical) = &keyring.aws_kms_hierarchical {
            let hierarchical = hierarchical.clone();
            let Ok(ttl) = u32::try_from(hierarchical.ttl_seconds) else {
                return Err(ServerError::generic(format!(
                    "ttlSeconds out of range: {}",
                    hierarchical.ttl_seconds
                )));
            };
            // The facade resolves the rest of the AWS configuration (credentials,
            // region) from the ambient environment.
            let region = std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("ESDK_TEST_REGION"))
                .unwrap_or_default();
            tokio::task::spawn_blocking(move || {
                seam::create_hierarchical_client(
                    &region,
                    &hierarchical.key_store_table_name,
                    &hierarchical.logical_key_store_name,
                    &hierarchical.kms_key_arn,
                    &hierarchical.branch_key_id,
                    ttl,
                )
            })
        } else {
            return Err(ServerError::generic(
                "the C++ shim server supports only the AwsKmsHierarchical and RawAes keyrings",
            ));
        };

        // The commons suite expects GenericServerError when CreateClient rejects its configuration.
        let client = create
            .await
            .map_err(|e| ServerError::generic(format!("create_client task failed: {e}")))?
            .map_err(ServerError::generic)?;

        let client_id = uuid::Uuid::new_v4().to_string();
        self.clients.lock().expect("registry mutex").insert(
            client_id.clone(),
            ClientEntry {
                client: Arc::new(Mutex::new(client)),
                commitment_policy,
                max_encrypted_data_keys,
            },
        );
        Ok(CreateClientResponse { client_id })
    }

    pub async fn encrypt(&self, req: EncryptRequest) -> Result<EncryptResponse, ServerError> {
        let materials = self.materials(&req.client_id)?;
        let algorithm_suite_id = req.algorithm_suite_id.map(suite_id).unwrap_or(0);
        let frame_length = frame_length_code(req.frame_length)?;
        let ec = encryption_context(req.encryption_context);
        let plaintext = req.plaintext;
        let commitment_policy = materials.commitment_policy;
        let max = materials.max_encrypted_data_keys;
        let client = materials.client;

        let ciphertext = tokio::task::spawn_blocking(move || {
            let client = client.lock().expect("client mutex");
            seam::encrypt(
                &client,
                &plaintext,
                commitment_policy,
                algorithm_suite_id,
                frame_length,
                max,
                &ec,
            )
        })
        .await
        .map_err(|e| ServerError::generic(format!("encrypt task failed: {e}")))?
        .map_err(ServerError::esdk)?;

        Ok(EncryptResponse { ciphertext })
    }

    pub async fn decrypt(&self, req: DecryptRequest) -> Result<DecryptResponse, ServerError> {
        let materials = self.materials(&req.client_id)?;
        let ec = encryption_context(req.encryption_context);
        let ciphertext = req.ciphertext;
        let commitment_policy = materials.commitment_policy;
        let max = materials.max_encrypted_data_keys;
        let client = materials.client;

        let plaintext = tokio::task::spawn_blocking(move || {
            let client = client.lock().expect("client mutex");
            seam::decrypt(&client, &ciphertext, commitment_policy, max, &ec)
        })
        .await
        .map_err(|e| ServerError::generic(format!("decrypt task failed: {e}")))?
        .map_err(ServerError::esdk)?;

        Ok(DecryptResponse { plaintext })
    }

    pub async fn encrypt_stream(
        &self,
        req: EncryptStreamRequest,
    ) -> Result<EncryptStreamResponse, ServerError> {
        let materials = self.materials(&req.client_id)?;
        let algorithm_suite_id = req.algorithm_suite_id.map(suite_id).unwrap_or(0);
        let frame_length = frame_length_code(req.frame_length)?;
        let plaintext_length_bound = match req.plaintext_length_bound {
            Some(bound) => Some(u64::try_from(bound).map_err(|_| {
                ServerError::esdk(format!(
                    "plaintextLengthBound must be non-negative, got {bound}"
                ))
            })?),
            None => None,
        };
        let ec = encryption_context(req.encryption_context);
        let plaintext = req.plaintext;
        let commitment_policy = materials.commitment_policy;
        let max = materials.max_encrypted_data_keys;
        let client = materials.client;

        let ciphertext = tokio::task::spawn_blocking(move || {
            let client = client.lock().expect("client mutex");
            seam::encrypt_stream(
                &client,
                &plaintext,
                commitment_policy,
                algorithm_suite_id,
                frame_length,
                max,
                plaintext_length_bound,
                &ec,
            )
        })
        .await
        .map_err(|e| ServerError::generic(format!("encrypt_stream task failed: {e}")))?
        .map_err(ServerError::esdk)?;

        Ok(EncryptStreamResponse { ciphertext })
    }

    pub async fn decrypt_stream(
        &self,
        req: DecryptStreamRequest,
    ) -> Result<DecryptStreamResponse, ServerError> {
        let materials = self.materials(&req.client_id)?;
        let ec = encryption_context(req.encryption_context);
        let ciphertext = req.ciphertext;
        let commitment_policy = materials.commitment_policy;
        let max = materials.max_encrypted_data_keys;
        let client = materials.client;

        let plaintext = tokio::task::spawn_blocking(move || {
            let client = client.lock().expect("client mutex");
            seam::decrypt_stream(&client, &ciphertext, commitment_policy, max, &ec)
        })
        .await
        .map_err(|e| ServerError::generic(format!("decrypt_stream task failed: {e}")))?
        .map_err(ServerError::esdk)?;

        Ok(DecryptStreamResponse { plaintext })
    }

    fn materials(&self, client_id: &str) -> Result<Materials, ServerError> {
        if client_id.is_empty() {
            return Err(ServerError::generic("clientId must be non-empty"));
        }
        let clients = self.clients.lock().expect("registry mutex");
        let entry = clients
            .get(client_id)
            .ok_or_else(|| ServerError::generic(format!("unknown clientId: {client_id}")))?;
        Ok(Materials {
            client: Arc::clone(&entry.client),
            commitment_policy: entry.commitment_policy,
            max_encrypted_data_keys: entry.max_encrypted_data_keys,
        })
    }
}
