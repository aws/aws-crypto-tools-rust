//! Operation handlers and the `clientId` registry.
//!
//! `CreateClient` builds the keyring from the modeled config (delegating to the
//! MPL), registers it under a fresh UUID, and returns the id. `Encrypt` and
//! `Decrypt` look the registered keyring up by `clientId` and forward to the
//! real `aws-esdk` free functions.

use crate::error::ServerError;
use crate::keyring::keyring_for_cmm;
use crate::model::{
    CreateClientRequest, CreateClientResponse, DecryptRequest, DecryptResponse, EncryptRequest,
    EncryptResponse, EsdkAlgorithmSuiteId, EsdkClientConfig, EsdkCommitmentPolicy,
};
use aws_esdk::AlgorithmSuiteId as MplAlgorithmSuiteId;
use aws_esdk::CommitmentPolicy as MplCommitmentPolicy;
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, SharedKeyring};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// The materials a registered client encrypts/decrypts with.
struct ClientEntry {
    keyring: SharedKeyring,
    commitment_policy: MplCommitmentPolicy,
    max_encrypted_data_keys: Option<NonZeroUsize>,
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
        let entry = ClientEntry {
            keyring,
            commitment_policy: map_commitment(req.config.commitment_policy),
            max_encrypted_data_keys: max_edks(&req.config)?,
        };
        let client_id = uuid::Uuid::new_v4().to_string();
        self.clients
            .lock()
            .expect("registry mutex")
            .insert(client_id.clone(), entry);
        Ok(CreateClientResponse { client_id })
    }

    pub async fn encrypt(&self, req: EncryptRequest) -> Result<EncryptResponse, ServerError> {
        let (keyring, commitment_policy, max) = self.materials(&req.client_id)?;
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
        let input = EncryptInput::builder()
            .plaintext(&req.plaintext)
            .encryption_context(ec)
            .set_keyring(Some(keyring))
            .commitment_policy(commitment_policy)
            .set_max_encrypted_data_keys(max)
            .set_algorithm_suite_id(req.algorithm_suite_id.map(map_algorithm_suite))
            .set_frame_length(frame_length)
            .build()
            .map_err(|e| ServerError::Esdk(e.message().to_string()))?;
        let output = aws_esdk::encrypt(&input)
            .await
            .map_err(|e| ServerError::Esdk(e.message().to_string()))?;
        Ok(EncryptResponse {
            ciphertext: output.ciphertext,
        })
    }

    pub async fn decrypt(&self, req: DecryptRequest) -> Result<DecryptResponse, ServerError> {
        let (keyring, commitment_policy, max) = self.materials(&req.client_id)?;
        let ec = encryption_context(req.encryption_context);
        let input = DecryptInput::builder()
            .ciphertext(&req.ciphertext)
            .encryption_context(ec)
            .set_keyring(Some(keyring))
            .commitment_policy(commitment_policy)
            .set_max_encrypted_data_keys(max)
            .build()
            .map_err(|e| ServerError::Esdk(e.message().to_string()))?;
        let output = aws_esdk::decrypt(&input)
            .await
            .map_err(|e| ServerError::Esdk(e.message().to_string()))?;
        Ok(DecryptResponse {
            plaintext: output.plaintext,
        })
    }

    /// Look up registered materials by id, cloning the shared keyring handle.
    fn materials(
        &self,
        client_id: &str,
    ) -> Result<(SharedKeyring, MplCommitmentPolicy, Option<NonZeroUsize>), ServerError> {
        if client_id.is_empty() {
            return Err(ServerError::generic("clientId must be non-empty"));
        }
        let clients = self.clients.lock().expect("registry mutex");
        let entry = clients
            .get(client_id)
            .ok_or_else(|| ServerError::generic(format!("unknown clientId: {client_id}")))?;
        Ok((
            entry.keyring.clone(),
            entry.commitment_policy,
            entry.max_encrypted_data_keys,
        ))
    }
}
