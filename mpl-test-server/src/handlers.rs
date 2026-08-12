//! Operation handlers and multi-type object registry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aws_crypto_mpl::cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
use aws_crypto_mpl::keyring::Keyring;
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId as MplAlgorithmSuiteId, CommitmentPolicy as MplCommitmentPolicy,
    EncryptedDataKey, EncryptionContext,
};
use aws_crypto_mpl::AesGcm;

use crate::error::ServerError;
use crate::model::*;

/// Shared server state: multi-type registry for keyrings and CMMs.
#[derive(Default)]
pub struct AppState {
    keyrings: Mutex<HashMap<String, Arc<dyn Keyring>>>,
    cmms: Mutex<HashMap<String, Arc<dyn Cmm>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_raw_aes_keyring(
        &self,
        req: CreateRawAesKeyringRequest,
    ) -> Result<CreateRawAesKeyringResponse, ServerError> {
        let alg = match req.wrapping_alg {
            AesWrappingAlg::Aes128 => AesGcm::Aes128Gcm,
            AesWrappingAlg::Aes192 => AesGcm::Aes192Gcm,
            AesWrappingAlg::Aes256 => AesGcm::Aes256Gcm,
        };

        let keyring = aws_crypto_mpl::RawAesKeyring::new(
            req.key_namespace,
            req.key_name,
            req.wrapping_key,
            alg,
        )
        .map_err(|e| ServerError::mpl(e.to_string()))?;

        let id = uuid::Uuid::new_v4().to_string();
        self.keyrings
            .lock()
            .expect("keyrings mutex")
            .insert(id.clone(), Arc::new(keyring));
        Ok(CreateRawAesKeyringResponse { keyring_id: id })
    }

    pub fn create_default_cmm(
        &self,
        req: CreateDefaultCmmRequest,
    ) -> Result<CreateDefaultCmmResponse, ServerError> {
        let keyring = self
            .keyrings
            .lock()
            .expect("keyrings mutex")
            .get(&req.keyring_id)
            .cloned()
            .ok_or_else(|| {
                ServerError::generic(format!("unknown keyringId: {}", req.keyring_id))
            })?;

        let cmm = DefaultCmm::new(keyring);
        let id = uuid::Uuid::new_v4().to_string();
        self.cmms
            .lock()
            .expect("cmms mutex")
            .insert(id.clone(), Arc::new(cmm));
        Ok(CreateDefaultCmmResponse { cmm_id: id })
    }

    pub async fn get_encryption_materials(
        &self,
        req: GetEncryptionMaterialsRequest,
    ) -> Result<GetEncryptionMaterialsResponse, ServerError> {
        let cmm = self.get_cmm(&req.cmm_id)?;

        let ec = map_encryption_context(&req.encryption_context);
        let policy = map_commitment_policy(req.commitment_policy);

        let mut mpl_req = EncryptionMaterialsRequest::new(ec, policy);
        if let Some(suite) = req.algorithm_suite_id {
            mpl_req = mpl_req.with_algorithm_suite_id(map_algorithm_suite_id(suite));
        }
        if let Some(len) = req.max_plaintext_length {
            mpl_req = mpl_req.with_max_plaintext_length(len);
        }

        let materials = cmm
            .get_encryption_materials(mpl_req)
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;

        let pdk = materials
            .plaintext_data_key()
            .ok_or_else(|| ServerError::mpl("no plaintext data key in materials"))?
            .as_bytes()
            .to_vec();

        let edks: Vec<EncryptedDataKeyShape> = materials
            .encrypted_data_keys()
            .iter()
            .map(|edk| EncryptedDataKeyShape {
                key_provider_id: edk.key_provider_id.clone(),
                key_provider_info: edk.key_provider_info.clone(),
                ciphertext: edk.ciphertext.clone(),
            })
            .collect();

        let ec_out = encryption_context_to_map(materials.encryption_context());

        let signing_key = materials.signing_key().map(|sk| sk.as_bytes().to_vec());
        let symmetric_signing_keys = materials.symmetric_signing_keys().map(|keys| {
            keys.iter()
                .map(|k| serde_bytes::ByteBuf::from(k.as_bytes().to_vec()))
                .collect()
        });

        Ok(GetEncryptionMaterialsResponse {
            algorithm_suite_id: reverse_map_algorithm_suite_id(materials.algorithm_suite_id()),
            encryption_context: ec_out,
            encrypted_data_keys: edks,
            plaintext_data_key: pdk,
            signing_key,
            symmetric_signing_keys,
        })
    }

    pub async fn decrypt_materials(
        &self,
        req: DecryptMaterialsRequest,
    ) -> Result<DecryptMaterialsResponse, ServerError> {
        let cmm = self.get_cmm(&req.cmm_id)?;

        let suite = map_algorithm_suite_id(req.algorithm_suite_id);
        let policy = map_commitment_policy(req.commitment_policy);
        let ec = map_encryption_context(&req.encryption_context);
        let edks: Vec<EncryptedDataKey> = req
            .encrypted_data_keys
            .into_iter()
            .map(|edk| EncryptedDataKey::new(edk.key_provider_id, edk.key_provider_info, edk.ciphertext))
            .collect();

        let mut mpl_req = DecryptMaterialsRequest::new(suite, policy, edks, ec);
        if let Some(reproduced) = req.reproduced_encryption_context {
            mpl_req = mpl_req.with_reproduced_encryption_context(map_encryption_context(&reproduced));
        }

        let materials = cmm
            .decrypt_materials(mpl_req)
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;

        let pdk = materials
            .plaintext_data_key()
            .ok_or_else(|| ServerError::mpl("no plaintext data key in materials"))?
            .as_bytes()
            .to_vec();

        let ec_out = encryption_context_to_map(materials.encryption_context());
        let verification_key = materials.verification_key().map(|vk| vk.as_bytes().to_vec());
        let symmetric_signing_key = materials
            .symmetric_signing_key()
            .map(|sk| sk.as_bytes().to_vec());

        Ok(DecryptMaterialsResponse {
            plaintext_data_key: pdk,
            encryption_context: ec_out,
            verification_key,
            symmetric_signing_key,
        })
    }

    fn get_cmm(&self, cmm_id: &str) -> Result<Arc<dyn Cmm>, ServerError> {
        if cmm_id.is_empty() {
            return Err(ServerError::generic("cmmId must be non-empty"));
        }
        self.cmms
            .lock()
            .expect("cmms mutex")
            .get(cmm_id)
            .cloned()
            .ok_or_else(|| ServerError::generic(format!("unknown cmmId: {cmm_id}")))
    }
}

// ─── Mapping helpers ────────────────────────────────────────────────────────

fn map_encryption_context(map: &std::collections::BTreeMap<String, String>) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for (k, v) in map {
        ec.insert(k.as_bytes().to_vec(), v.as_bytes().to_vec());
    }
    ec
}

fn encryption_context_to_map(
    ec: &EncryptionContext,
) -> std::collections::BTreeMap<String, String> {
    ec.iter()
        .map(|(k, v)| {
            (
                String::from_utf8_lossy(k).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            )
        })
        .collect()
}

fn map_commitment_policy(policy: CommitmentPolicy) -> MplCommitmentPolicy {
    use aws_crypto_mpl::structures::commitment_policy::Esdk;
    match policy {
        CommitmentPolicy::EsdkForbidEncryptAllowDecrypt => {
            MplCommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt)
        }
        CommitmentPolicy::EsdkRequireEncryptAllowDecrypt => {
            MplCommitmentPolicy::Esdk(Esdk::RequireEncryptAllowDecrypt)
        }
        CommitmentPolicy::EsdkRequireEncryptRequireDecrypt => {
            MplCommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt)
        }
    }
}

fn map_algorithm_suite_id(id: AlgorithmSuiteId) -> MplAlgorithmSuiteId {
    match id {
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf => MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf => MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf => MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256 => MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256 => MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256 => MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey => MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
    }
}

fn reverse_map_algorithm_suite_id(id: MplAlgorithmSuiteId) -> AlgorithmSuiteId {
    match id {
        MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf => AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
        MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf => AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
        MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf => AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256 => AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
        MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256 => AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
        MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256 => AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
        MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
        MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
        MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
        MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey => AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
    }
}
