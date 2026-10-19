//! Operation handlers and the `clientId` registry.
//!
//! `CreateClient` builds the keyring from the modeled config (delegating to the
//! MPL), registers it under a fresh UUID, and returns the id. `Encrypt` and
//! `Decrypt` look the registered client up by `clientId` and run the operation
//! on its `aws_esdk::Client`.

use crate::error::ServerError;
use crate::keyring::keyring_for_cmm;
use crate::model::{
    CreateClientRequest, CreateClientResponse, DecryptRequest, DecryptResponse, EncryptRequest,
    EncryptResponse, EsdkAlgorithmSuiteId, EsdkClientConfig, EsdkCommitmentPolicy,
};
use aws_esdk::types::AlgorithmSuiteId as MplAlgorithmSuiteId;
use aws_esdk::types::CommitmentPolicy as MplCommitmentPolicy;
use aws_esdk::{keyring::SharedKeyring, types::EncryptionContext, Client};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// The ESDK client and keyring a registered client encrypts/decrypts with.
struct ClientEntry {
    esdk: Client,
    keyring: SharedKeyring,
}

/// Shared server state: the thread-safe `clientId -> ClientEntry` registry.
#[derive(Default)]
pub struct AppState {
    clients: Mutex<HashMap<String, ClientEntry>>,
}

fn map_commitment(policy: EsdkCommitmentPolicy) -> MplCommitmentPolicy {
    match policy {
        EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt => {
            MplCommitmentPolicy::ForbidEncryptAllowDecrypt
        }
        EsdkCommitmentPolicy::RequireEncryptAllowDecrypt => {
            MplCommitmentPolicy::RequireEncryptAllowDecrypt
        }
        EsdkCommitmentPolicy::RequireEncryptRequireDecrypt => {
            MplCommitmentPolicy::RequireEncryptRequireDecrypt
        }
    }
}

fn map_algorithm_suite(id: EsdkAlgorithmSuiteId) -> MplAlgorithmSuiteId {
    match id {
        EsdkAlgorithmSuiteId::Alg128GcmNoKdf => MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
        EsdkAlgorithmSuiteId::Alg192GcmNoKdf => MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
        EsdkAlgorithmSuiteId::Alg256GcmNoKdf => MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        EsdkAlgorithmSuiteId::Alg128GcmHkdf => MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
        EsdkAlgorithmSuiteId::Alg192GcmHkdf => MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
        EsdkAlgorithmSuiteId::Alg256GcmHkdf => MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
        EsdkAlgorithmSuiteId::Alg128GcmHkdfEcdsa => {
            MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256
        }
        EsdkAlgorithmSuiteId::Alg192GcmHkdfEcdsa => {
            MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384
        }
        EsdkAlgorithmSuiteId::Alg256GcmHkdfEcdsa => {
            MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384
        }
        EsdkAlgorithmSuiteId::Alg256GcmCommit => {
            MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
        }
        EsdkAlgorithmSuiteId::Alg256GcmCommitEcdsa => {
            MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
        }
    }
}

fn max_edks(config: &EsdkClientConfig) -> Result<Option<NonZeroUsize>, ServerError> {
    let Some(v) = config.max_encrypted_data_keys else {
        return Ok(None);
    };
    usize::try_from(v)
        .ok()
        .and_then(NonZeroUsize::new)
        .map(Some)
        .ok_or_else(|| {
            ServerError::generic(format!("maxEncryptedDataKeys must be positive, got {v}"))
        })
}

fn encryption_context(
    map: Option<std::collections::BTreeMap<String, String>>,
) -> EncryptionContext {
    map.map(EncryptionContext::from).unwrap_or_default()
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build and register a client; returns its new id.
    pub async fn create_client(
        &self,
        req: CreateClientRequest,
    ) -> Result<CreateClientResponse, ServerError> {
        let keyring = keyring_for_cmm(&req.config.cmm).await?;
        let mut builder =
            Client::builder().commitment_policy(map_commitment(req.config.commitment_policy));
        builder.set_max_encrypted_data_keys(max_edks(&req.config)?);
        let esdk = builder
            .build()
            .map_err(|e| ServerError::esdk(e.to_string()))?;
        let entry = ClientEntry { esdk, keyring };
        let client_id = uuid::Uuid::new_v4().to_string();
        self.clients
            .lock()
            .expect("registry mutex")
            .insert(client_id.clone(), entry);
        Ok(CreateClientResponse { client_id })
    }

    pub async fn encrypt(&self, req: EncryptRequest) -> Result<EncryptResponse, ServerError> {
        let (esdk, keyring) = self.client(&req.client_id)?;
        let ec = encryption_context(req.encryption_context);
        let frame_length = req
            .frame_length
            .map(|frame| {
                u32::try_from(frame)
                    .ok()
                    .and_then(std::num::NonZeroU32::new)
                    .ok_or_else(|| {
                        ServerError::generic(format!(
                            "frameLength must be in 1..=u32::MAX, got {frame}"
                        ))
                    })
            })
            .transpose()?;
        let output = esdk
            .encrypt()
            .plaintext(&req.plaintext)
            .set_encryption_context(Some(ec))
            .keyring(keyring)
            .set_algorithm_suite_id(req.algorithm_suite_id.map(map_algorithm_suite))
            .set_frame_length(frame_length)
            .send()
            .await
            .map_err(|e| ServerError::esdk(e.to_string()))?;
        Ok(EncryptResponse {
            ciphertext: output.into_ciphertext(),
        })
    }

    pub async fn decrypt(&self, req: DecryptRequest) -> Result<DecryptResponse, ServerError> {
        let (esdk, keyring) = self.client(&req.client_id)?;
        let output = esdk
            .decrypt()
            .ciphertext(&req.ciphertext)
            .set_encryption_context(Some(encryption_context(req.encryption_context)))
            .keyring(keyring)
            .send()
            .await
            .map_err(|e| ServerError::esdk(e.to_string()))?;
        Ok(DecryptResponse {
            plaintext: output.into_plaintext(),
        })
    }

    /// Look up a registered client by id, cloning the shared keyring handle.
    fn client(&self, client_id: &str) -> Result<(Client, SharedKeyring), ServerError> {
        if client_id.is_empty() {
            return Err(ServerError::generic("clientId must be non-empty"));
        }
        let clients = self.clients.lock().expect("registry mutex");
        let entry = clients
            .get(client_id)
            .ok_or_else(|| ServerError::generic(format!("unknown clientId: {client_id}")))?;
        Ok((entry.esdk.clone(), entry.keyring.clone()))
    }
}
