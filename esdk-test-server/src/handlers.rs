//! Operation handlers and the `clientId` registry.
//!
//! `CreateClient` builds the keyring from the modeled config (delegating to the
//! vendored MPL), registers it under a fresh UUID, and returns the id. `Encrypt`
//! and `Decrypt` look the registered materials up by `clientId` and forward to
//! the real `aws-esdk` free functions.

use crate::error::ServerError;
use crate::keyring::keyring_for_cmm;
use crate::model::{
    CreateClientRequest, CreateClientResponse, DecryptRequest, DecryptResponse, EncryptRequest,
    EncryptResponse, EsdkClientConfig, EsdkCommitmentPolicy,
};
use aws_esdk::{DecryptInput, EncryptInput};
use aws_mpl_legacy::commitment::EsdkCommitmentPolicy as MplCommitmentPolicy;
use aws_mpl_legacy::keyring::KeyringRef;
use aws_mpl_legacy::EncryptionContext;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// The materials a registered client encrypts/decrypts with.
struct ClientEntry {
    keyring: KeyringRef,
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

fn max_edks(config: &EsdkClientConfig) -> Option<NonZeroUsize> {
    config
        .max_encrypted_data_keys
        .and_then(|v| usize::try_from(v).ok())
        .and_then(NonZeroUsize::new)
}

fn encryption_context(
    map: Option<std::collections::BTreeMap<String, String>>,
) -> EncryptionContext {
    map.map(|m| m.into_iter().collect()).unwrap_or_default()
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build and register a client; returns its new id. The keyring is built via
    /// the MPL here — the current stopping point for the offline Raw-AES path.
    pub fn create_client(
        &self,
        req: CreateClientRequest,
    ) -> Result<CreateClientResponse, ServerError> {
        let keyring = keyring_for_cmm(&req.config.cmm)?;
        let entry = ClientEntry {
            keyring,
            commitment_policy: map_commitment(req.config.commitment_policy),
            max_encrypted_data_keys: max_edks(&req.config),
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
        let mut input = EncryptInput::with_keyring(&req.plaintext, ec, keyring);
        input.commitment_policy = commitment_policy;
        input.max_encrypted_data_keys = max;
        if let Some(frame) = req.frame_length {
            if let Ok(frame) = u32::try_from(frame) {
                if let Ok(frame_length) = aws_esdk::FrameLength::new(frame) {
                    input.frame_length = frame_length;
                }
            }
        }
        let output = aws_esdk::encrypt(&input)
            .await
            .map_err(|e| ServerError::Esdk(e.message))?;
        Ok(EncryptResponse {
            ciphertext: output.ciphertext,
        })
    }

    pub async fn decrypt(&self, req: DecryptRequest) -> Result<DecryptResponse, ServerError> {
        let (keyring, commitment_policy, max) = self.materials(&req.client_id)?;
        let ec = encryption_context(req.encryption_context);
        let mut input = DecryptInput::with_keyring(&req.ciphertext, ec, keyring);
        input.commitment_policy = commitment_policy;
        input.max_encrypted_data_keys = max;
        let output = aws_esdk::decrypt(&input)
            .await
            .map_err(|e| ServerError::Esdk(e.message))?;
        Ok(DecryptResponse {
            plaintext: output.plaintext,
        })
    }

    /// Look up registered materials by id, cloning the shared keyring handle.
    fn materials(
        &self,
        client_id: &str,
    ) -> Result<(KeyringRef, MplCommitmentPolicy, Option<NonZeroUsize>), ServerError> {
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
