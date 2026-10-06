//! Operation handlers and multi-type object registry.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use aws_crypto_mpl::AesGcm;
// `DecryptMaterialsRequest` is aliased because `crate::model` defines a
// same-named wire shape; an unaliased import would shadow the glob-imported
// model type and bind this module's handler signatures to the MPL type.
use aws_crypto_mpl::cmm::{
    Cmm, DecryptMaterialsRequest as MplDecryptMaterialsRequest, DefaultCmm,
    EncryptionMaterialsRequest,
};
use aws_crypto_mpl::keyring::Keyring;
use aws_crypto_mpl::structures::algorithm_suite::{
    PlaintextDataKey, SigningKey, SymmetricSigningKey, VerificationKey,
};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId as MplAlgorithmSuiteId, CommitmentPolicy as MplCommitmentPolicy,
    DecryptionMaterials, EncryptedDataKey, EncryptionContext, EncryptionMaterials,
};

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
        let keyring = self.get_keyring(&req.keyring_id)?;

        let cmm = DefaultCmm::new(keyring);
        let id = uuid::Uuid::new_v4().to_string();
        self.cmms
            .lock()
            .expect("cmms mutex")
            .insert(id.clone(), Arc::new(cmm));
        Ok(CreateDefaultCmmResponse { cmm_id: id })
    }

    pub fn initialize_encryption_materials(
        &self,
        req: InitializeEncryptionMaterialsRequest,
    ) -> Result<InitializeEncryptionMaterialsResponse, ServerError> {
        let materials = EncryptionMaterials::new(
            map_algorithm_suite_id(req.algorithm_suite_id),
            Vec::new(),
            map_encryption_context(&req.encryption_context),
            map_required_keys(&req.required_encryption_context_keys),
            None,
            None,
            None,
        )
        .map_err(|e| ServerError::mpl(e.to_string()))?;
        Ok(InitializeEncryptionMaterialsResponse {
            materials: encryption_materials_to_shape(&materials),
        })
    }

    pub fn initialize_decryption_materials(
        &self,
        req: InitializeDecryptionMaterialsRequest,
    ) -> Result<InitializeDecryptionMaterialsResponse, ServerError> {
        let materials = DecryptionMaterials::new(
            map_algorithm_suite_id(req.algorithm_suite_id),
            map_encryption_context(&req.encryption_context),
            map_required_keys(&req.required_encryption_context_keys),
            None,
            None,
            None,
        )
        .map_err(|e| ServerError::mpl(e.to_string()))?;
        Ok(InitializeDecryptionMaterialsResponse {
            materials: decryption_materials_to_shape(&materials),
        })
    }

    pub async fn on_encrypt(
        &self,
        req: OnEncryptRequest,
    ) -> Result<OnEncryptResponse, ServerError> {
        let keyring = self.get_keyring(&req.keyring_id)?;
        let materials = shape_to_encryption_materials(req.materials)?;
        let materials = keyring
            .on_encrypt(materials)
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;
        Ok(OnEncryptResponse {
            materials: encryption_materials_to_shape(&materials),
        })
    }

    pub async fn on_decrypt(
        &self,
        req: OnDecryptRequest,
    ) -> Result<OnDecryptResponse, ServerError> {
        let keyring = self.get_keyring(&req.keyring_id)?;
        let materials = shape_to_decryption_materials(req.materials)?;
        let edks = map_edks(req.encrypted_data_keys);
        let materials = keyring
            .on_decrypt(materials, &edks)
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;
        Ok(OnDecryptResponse {
            materials: decryption_materials_to_shape(&materials),
        })
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

        let edks = edks_to_shapes(materials.encrypted_data_keys());

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
        let edks = map_edks(req.encrypted_data_keys);

        let mut mpl_req = MplDecryptMaterialsRequest::new(suite, policy, edks, ec);
        if let Some(reproduced) = req.reproduced_encryption_context {
            mpl_req =
                mpl_req.with_reproduced_encryption_context(map_encryption_context(&reproduced));
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

    fn get_keyring(&self, keyring_id: &str) -> Result<Arc<dyn Keyring>, ServerError> {
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

fn map_edks(edks: Vec<EncryptedDataKeyShape>) -> Vec<EncryptedDataKey> {
    edks.into_iter()
        .map(|edk| {
            EncryptedDataKey::new(edk.key_provider_id, edk.key_provider_info, edk.ciphertext)
        })
        .collect()
}

fn edks_to_shapes(edks: &[EncryptedDataKey]) -> Vec<EncryptedDataKeyShape> {
    edks.iter()
        .map(|edk| EncryptedDataKeyShape {
            key_provider_id: edk.key_provider_id.clone(),
            key_provider_info: edk.key_provider_info.clone(),
            ciphertext: edk.ciphertext.clone(),
        })
        .collect()
}

fn map_required_keys(keys: &[String]) -> BTreeSet<Vec<u8>> {
    keys.iter().map(|k| k.as_bytes().to_vec()).collect()
}

fn required_keys_to_wire(keys: &BTreeSet<Vec<u8>>) -> Vec<String> {
    keys.iter()
        .map(|k| String::from_utf8_lossy(k).into_owned())
        .collect()
}

/// Materials a client sends must satisfy the MPL's own invariants; a rejection
/// is the MPL's, so it is an `MPLClientError`.
fn shape_to_encryption_materials(
    shape: EncryptionMaterialsShape,
) -> Result<EncryptionMaterials, ServerError> {
    EncryptionMaterials::new(
        map_algorithm_suite_id(shape.algorithm_suite_id),
        map_edks(shape.encrypted_data_keys),
        map_encryption_context(&shape.encryption_context),
        map_required_keys(&shape.required_encryption_context_keys),
        shape.plaintext_data_key.map(PlaintextDataKey::new),
        shape.signing_key.map(SigningKey::new),
        shape.symmetric_signing_keys.map(|keys| {
            keys.into_iter()
                .map(|k| SymmetricSigningKey::new(k.into_vec()))
                .collect()
        }),
    )
    .map_err(|e| ServerError::mpl(e.to_string()))
}

fn shape_to_decryption_materials(
    shape: DecryptionMaterialsShape,
) -> Result<DecryptionMaterials, ServerError> {
    DecryptionMaterials::new(
        map_algorithm_suite_id(shape.algorithm_suite_id),
        map_encryption_context(&shape.encryption_context),
        map_required_keys(&shape.required_encryption_context_keys),
        shape.plaintext_data_key.map(PlaintextDataKey::new),
        shape.verification_key.map(VerificationKey::new),
        shape.symmetric_signing_key.map(SymmetricSigningKey::new),
    )
    .map_err(|e| ServerError::mpl(e.to_string()))
}

fn encryption_materials_to_shape(materials: &EncryptionMaterials) -> EncryptionMaterialsShape {
    EncryptionMaterialsShape {
        algorithm_suite_id: reverse_map_algorithm_suite_id(materials.algorithm_suite_id()),
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
    }
}

fn decryption_materials_to_shape(materials: &DecryptionMaterials) -> DecryptionMaterialsShape {
    DecryptionMaterialsShape {
        algorithm_suite_id: reverse_map_algorithm_suite_id(materials.algorithm_suite_id()),
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
    }
}

fn map_encryption_context(map: &BTreeMap<String, String>) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for (k, v) in map {
        ec.insert(k.as_bytes().to_vec(), v.as_bytes().to_vec());
    }
    ec
}

fn encryption_context_to_map(ec: &EncryptionContext) -> BTreeMap<String, String> {
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
    }
}

fn reverse_map_algorithm_suite_id(id: MplAlgorithmSuiteId) -> AlgorithmSuiteId {
    match id {
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
    }
}
