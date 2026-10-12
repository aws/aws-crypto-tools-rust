//! Operation handlers and multi-type object registry.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

use aws_crypto_mpl::AesGcm;
use aws_crypto_mpl::cmm::{DefaultCmm, SharedCmm};
use aws_crypto_mpl::keyring::SharedKeyring;
use aws_crypto_mpl::structures::algorithm_suite::{
    PlaintextDataKey, SigningKey, SymmetricSigningKey, VerificationKey,
};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId as MplSuiteId, CommitmentPolicy as MplCommitmentPolicy, DecryptionMaterials,
    EncryptedDataKey, EncryptionContext, EncryptionMaterials,
    EsdkAlgorithmSuiteId as MplAlgorithmSuiteId, EsdkCommitmentPolicy,
};

use crate::error::ServerError;
use crate::model::*;

/// Shared server state: multi-type registry for keyrings and CMMs.
#[derive(Default)]
pub struct AppState {
    keyrings: Mutex<HashMap<String, SharedKeyring>>,
    cmms: Mutex<HashMap<String, SharedCmm>>,
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

        let keyring = aws_crypto_mpl::RawAesKeyring::builder()
            .key_namespace(req.key_namespace)
            .key_name(req.key_name)
            .wrapping_key(req.wrapping_key)
            .wrapping_alg(alg)
            .build()
            .map_err(|e| ServerError::mpl(e.to_string()))?;

        let id = uuid::Uuid::new_v4().to_string();
        self.keyrings
            .lock()
            .expect("keyrings mutex")
            .insert(id.clone(), SharedKeyring::new(keyring));
        Ok(CreateRawAesKeyringResponse { keyring_id: id })
    }

    pub fn create_default_cmm(
        &self,
        req: CreateDefaultCmmRequest,
    ) -> Result<CreateDefaultCmmResponse, ServerError> {
        let keyring = self.get_keyring(&req.keyring_id)?;

        let cmm = DefaultCmm::new(keyring);
        let id = uuid::Uuid::new_v4().to_string();
        self.cmms
            .lock()
            .expect("cmms mutex")
            .insert(id.clone(), SharedCmm::new(cmm));
        Ok(CreateDefaultCmmResponse { cmm_id: id })
    }

    pub fn initialize_encryption_materials(
        &self,
        req: InitializeEncryptionMaterialsRequest,
    ) -> Result<InitializeEncryptionMaterialsResponse, ServerError> {
        let materials = EncryptionMaterials::builder()
            .algorithm_suite_id(map_algorithm_suite_id(req.algorithm_suite_id))
            .encryption_context(map_encryption_context(&req.encryption_context))
            .required_encryption_context_keys(req.required_encryption_context_keys)
            .build()
            .map_err(|e| ServerError::mpl(e.to_string()))?;
        Ok(InitializeEncryptionMaterialsResponse {
            materials: encryption_materials_to_shape(&materials)?,
        })
    }

    pub fn initialize_decryption_materials(
        &self,
        req: InitializeDecryptionMaterialsRequest,
    ) -> Result<InitializeDecryptionMaterialsResponse, ServerError> {
        let materials = DecryptionMaterials::builder()
            .algorithm_suite_id(map_algorithm_suite_id(req.algorithm_suite_id))
            .encryption_context(map_encryption_context(&req.encryption_context))
            .required_encryption_context_keys(req.required_encryption_context_keys)
            .build()
            .map_err(|e| ServerError::mpl(e.to_string()))?;
        Ok(InitializeDecryptionMaterialsResponse {
            materials: decryption_materials_to_shape(&materials)?,
        })
    }

    pub async fn on_encrypt(
        &self,
        req: OnEncryptRequest,
    ) -> Result<OnEncryptResponse, ServerError> {
        let keyring = self.get_keyring(&req.keyring_id)?;
        let output = keyring
            .on_encrypt()
            .materials(shape_to_encryption_materials(req.materials)?)
            .send()
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;
        Ok(OnEncryptResponse {
            materials: encryption_materials_to_shape(output.materials())?,
        })
    }

    pub async fn on_decrypt(
        &self,
        req: OnDecryptRequest,
    ) -> Result<OnDecryptResponse, ServerError> {
        let keyring = self.get_keyring(&req.keyring_id)?;
        let output = keyring
            .on_decrypt()
            .materials(shape_to_decryption_materials(req.materials)?)
            .encrypted_data_keys(map_edks(req.encrypted_data_keys)?)
            .send()
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;
        Ok(OnDecryptResponse {
            materials: decryption_materials_to_shape(output.materials())?,
        })
    }

    pub async fn get_encryption_materials(
        &self,
        req: GetEncryptionMaterialsRequest,
    ) -> Result<GetEncryptionMaterialsResponse, ServerError> {
        let cmm = self.get_cmm(&req.cmm_id)?;

        let output = cmm
            .get_encryption_materials()
            .encryption_context(map_encryption_context(&req.encryption_context))
            .commitment_policy(map_commitment_policy(req.commitment_policy))
            .set_algorithm_suite_id(req.algorithm_suite_id.map(map_algorithm_suite_id))
            .set_max_plaintext_length(req.max_plaintext_length)
            .send()
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;
        let materials = output.encryption_materials();

        let pdk = materials
            .plaintext_data_key()
            .ok_or_else(|| ServerError::mpl("no plaintext data key in materials"))?
            .as_bytes()
            .to_vec();

        let edks = edks_to_shapes(materials.encrypted_data_keys());

        let ec_out = encryption_context_to_map(materials.encryption_context());

        let signing_key = materials.signing_key().map(|sk| sk.as_bytes().to_vec());
        let symmetric_signing_keys = materials.symmetric_signing_keys().map(|keys| {
            keys.iter()
                .map(|k| serde_bytes::ByteBuf::from(k.as_bytes().to_vec()))
                .collect()
        });

        Ok(GetEncryptionMaterialsResponse {
            algorithm_suite_id: reverse_map_algorithm_suite_id(materials.algorithm_suite_id())?,
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

        let output = cmm
            .decrypt_materials()
            .algorithm_suite_id(map_algorithm_suite_id(req.algorithm_suite_id))
            .commitment_policy(map_commitment_policy(req.commitment_policy))
            .encrypted_data_keys(map_edks(req.encrypted_data_keys)?)
            .encryption_context(map_encryption_context(&req.encryption_context))
            .set_reproduced_encryption_context(
                req.reproduced_encryption_context
                    .as_ref()
                    .map(map_encryption_context),
            )
            .send()
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;
        let materials = output.decryption_materials();

        let pdk = materials
            .plaintext_data_key()
            .ok_or_else(|| ServerError::mpl("no plaintext data key in materials"))?
            .as_bytes()
            .to_vec();

        let ec_out = encryption_context_to_map(materials.encryption_context());
        let verification_key = materials
            .verification_key()
            .map(|vk| vk.as_bytes().to_vec());
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

    fn get_cmm(&self, cmm_id: &str) -> Result<SharedCmm, ServerError> {
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

    fn get_keyring(&self, keyring_id: &str) -> Result<SharedKeyring, ServerError> {
        if keyring_id.is_empty() {
            return Err(ServerError::generic("keyringId must be non-empty"));
        }
        self.keyrings
            .lock()
            .expect("keyrings mutex")
            .get(keyring_id)
            .cloned()
            .ok_or_else(|| ServerError::generic(format!("unknown keyringId: {keyring_id}")))
    }
}

// ─── Mapping helpers ────────────────────────────────────────────────────────

fn map_edks(edks: Vec<EncryptedDataKeyShape>) -> Result<Vec<EncryptedDataKey>, ServerError> {
    edks.into_iter()
        .map(|edk| {
            EncryptedDataKey::builder()
                .key_provider_id(edk.key_provider_id)
                .key_provider_info(edk.key_provider_info)
                .ciphertext(edk.ciphertext)
                .build()
                .map_err(|e| ServerError::mpl(e.to_string()))
        })
        .collect()
}

fn edks_to_shapes(edks: &[EncryptedDataKey]) -> Vec<EncryptedDataKeyShape> {
    edks.iter()
        .map(|edk| EncryptedDataKeyShape {
            key_provider_id: edk.key_provider_id().to_owned(),
            key_provider_info: edk.key_provider_info().to_vec(),
            ciphertext: edk.ciphertext().to_vec(),
        })
        .collect()
}

fn required_keys_to_wire(keys: &BTreeSet<String>) -> Vec<String> {
    keys.iter().cloned().collect()
}

/// Materials a client sends must satisfy the MPL's own invariants; a rejection
/// is the MPL's, so it is an `MPLClientError`.
fn shape_to_encryption_materials(
    shape: EncryptionMaterialsShape,
) -> Result<EncryptionMaterials, ServerError> {
    EncryptionMaterials::builder()
        .algorithm_suite_id(map_algorithm_suite_id(shape.algorithm_suite_id))
        .encrypted_data_keys(map_edks(shape.encrypted_data_keys)?)
        .encryption_context(map_encryption_context(&shape.encryption_context))
        .required_encryption_context_keys(shape.required_encryption_context_keys)
        .set_plaintext_data_key(shape.plaintext_data_key.map(PlaintextDataKey::new))
        .set_signing_key(shape.signing_key.map(SigningKey::new))
        .set_symmetric_signing_keys(shape.symmetric_signing_keys.map(|keys| {
            keys.into_iter()
                .map(|k| SymmetricSigningKey::new(k.into_vec()))
                .collect()
        }))
        .build()
        .map_err(|e| ServerError::mpl(e.to_string()))
}

fn shape_to_decryption_materials(
    shape: DecryptionMaterialsShape,
) -> Result<DecryptionMaterials, ServerError> {
    DecryptionMaterials::builder()
        .algorithm_suite_id(map_algorithm_suite_id(shape.algorithm_suite_id))
        .encryption_context(map_encryption_context(&shape.encryption_context))
        .required_encryption_context_keys(shape.required_encryption_context_keys)
        .set_plaintext_data_key(shape.plaintext_data_key.map(PlaintextDataKey::new))
        .set_verification_key(shape.verification_key.map(VerificationKey::new))
        .set_symmetric_signing_key(shape.symmetric_signing_key.map(SymmetricSigningKey::new))
        .build()
        .map_err(|e| ServerError::mpl(e.to_string()))
}

fn encryption_materials_to_shape(
    materials: &EncryptionMaterials,
) -> Result<EncryptionMaterialsShape, ServerError> {
    Ok(EncryptionMaterialsShape {
        algorithm_suite_id: reverse_map_algorithm_suite_id(materials.algorithm_suite_id())?,
        encryption_context: encryption_context_to_map(materials.encryption_context()),
        encrypted_data_keys: edks_to_shapes(materials.encrypted_data_keys()),
        required_encryption_context_keys: required_keys_to_wire(
            materials.required_encryption_context_keys(),
        ),
        plaintext_data_key: materials
            .plaintext_data_key()
            .map(|k| k.as_bytes().to_vec()),
        signing_key: materials.signing_key().map(|k| k.as_bytes().to_vec()),
        symmetric_signing_keys: materials.symmetric_signing_keys().map(|keys| {
            keys.iter()
                .map(|k| serde_bytes::ByteBuf::from(k.as_bytes().to_vec()))
                .collect()
        }),
    })
}

fn decryption_materials_to_shape(
    materials: &DecryptionMaterials,
) -> Result<DecryptionMaterialsShape, ServerError> {
    Ok(DecryptionMaterialsShape {
        algorithm_suite_id: reverse_map_algorithm_suite_id(materials.algorithm_suite_id())?,
        encryption_context: encryption_context_to_map(materials.encryption_context()),
        required_encryption_context_keys: required_keys_to_wire(
            materials.required_encryption_context_keys(),
        ),
        plaintext_data_key: materials
            .plaintext_data_key()
            .map(|k| k.as_bytes().to_vec()),
        verification_key: materials.verification_key().map(|k| k.as_bytes().to_vec()),
        symmetric_signing_key: materials
            .symmetric_signing_key()
            .map(|k| k.as_bytes().to_vec()),
    })
}

fn map_encryption_context(map: &BTreeMap<String, String>) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for (k, v) in map {
        ec.insert(k.as_str(), v.as_str());
    }
    ec
}

fn encryption_context_to_map(ec: &EncryptionContext) -> BTreeMap<String, String> {
    ec.iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn map_commitment_policy(policy: CommitmentPolicy) -> MplCommitmentPolicy {
    use EsdkCommitmentPolicy as Esdk;
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

fn map_algorithm_suite_id(id: AlgorithmSuiteId) -> MplSuiteId {
    MplSuiteId::Esdk(match id {
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf => {
            MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf
        }
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf => {
            MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf
        }
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf => {
            MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf
        }
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256 => {
            MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256
        }
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256 => {
            MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256
        }
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256 => {
            MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256
        }
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {
            MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256
        }
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {
            MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384
        }
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {
            MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384
        }
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey => {
            MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
        }
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {
            MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
        }
    })
}

fn reverse_map_algorithm_suite_id(id: MplSuiteId) -> Result<AlgorithmSuiteId, ServerError> {
    let MplSuiteId::Esdk(id) = id else {
        return Err(ServerError::mpl(format!(
            "unsupported algorithm suite {id:?}"
        )));
    };
    Ok(match id {
        MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf => {
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf
        }
        MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf => {
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf
        }
        MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf => {
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf
        }
        MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256 => {
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256
        }
        MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256 => {
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256
        }
        MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256 => {
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256
        }
        MplAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256
        }
        MplAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384
        }
        MplAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384
        }
        MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey => {
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
        }
        MplAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
        }
        _ => {
            return Err(ServerError::mpl(format!(
                "unsupported algorithm suite {id:?}"
            )));
        }
    })
}
