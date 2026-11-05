// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operation handlers and multi-type object registry.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::Duration;

use aws_crypto_mpl::aws_config::{self, BehaviorVersion, Region};
use aws_crypto_mpl::cmc::{DefaultCmc, SharedCmc};
use aws_crypto_mpl::cmm::{DefaultCmm, SharedCmm};
use aws_crypto_mpl::key_store::types::{
    Discovery as MplDiscovery, KmsConfiguration as MplKmsConfiguration,
    MrDiscovery as MplMrDiscovery,
};
use aws_crypto_mpl::key_store::{DynamoDbKeyStore, SharedKeyStore};
use aws_crypto_mpl::keyring::{
    BranchKeyIdSupplier, GetBranchKeyIdInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    SharedBranchKeyIdSupplier, SharedKeyring,
};
use aws_crypto_mpl::types::{
    AlgorithmSuiteId as MplSuiteId, CommitmentPolicy as MplCommitmentPolicy, DecryptionMaterials,
    EncryptedDataKey, EncryptionContext, EncryptionMaterials,
    EsdkAlgorithmSuiteId as MplAlgorithmSuiteId, EsdkCommitmentPolicy,
};
use aws_crypto_mpl::types::{
    PlaintextDataKey, RequiredEncryptionContextKeys, SigningKey, SymmetricSigningKey,
    VerificationKey,
};
use aws_crypto_mpl::{aws_sdk_dynamodb, aws_sdk_kms};

use crate::error::ServerError;
use crate::model::*;

/// Shared server state: multi-type registry for keyrings, CMMs, key stores,
/// and materials caches.
#[derive(Default)]
pub struct AppState {
    keyrings: Mutex<HashMap<String, SharedKeyring>>,
    cmms: Mutex<HashMap<String, SharedCmm>>,
    key_stores: Mutex<HashMap<String, SharedKeyStore>>,
    caches: Mutex<HashMap<String, SharedCmc>>,
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
            AesWrappingAlg::Aes128 => aws_crypto_mpl::types::AesWrappingAlg::AlgAes128GcmIv12Tag16,
            AesWrappingAlg::Aes192 => aws_crypto_mpl::types::AesWrappingAlg::AlgAes192GcmIv12Tag16,
            AesWrappingAlg::Aes256 => aws_crypto_mpl::types::AesWrappingAlg::AlgAes256GcmIv12Tag16,
        };

        let keyring = aws_crypto_mpl::keyring::RawAesKeyring::builder()
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

    pub async fn create_key_store_client(
        &self,
        req: CreateKeyStoreClientRequest,
    ) -> Result<CreateKeyStoreClientResponse, ServerError> {
        let kms_configuration = match req.kms_configuration {
            KmsConfiguration::KmsKeyArn(arn) => MplKmsConfiguration::kms_key_arn(arn),
            KmsConfiguration::KmsMrKeyArn(arn) => MplKmsConfiguration::kms_mr_key_arn(arn),
            KmsConfiguration::Discovery(Discovery {}) => MplKmsConfiguration::Discovery(
                MplDiscovery::builder()
                    .build()
                    .map_err(|e| ServerError::mpl(e.to_string()))?,
            ),
            KmsConfiguration::MrDiscovery(MrDiscovery { region }) => {
                MplKmsConfiguration::MrDiscovery(
                    MplMrDiscovery::builder()
                        .region(region)
                        .build()
                        .map_err(|e| ServerError::mpl(e.to_string()))?,
                )
            }
        };

        let kms = aws_sdk_kms::Client::new(&sdk_config(req.kms_client_region).await);
        let ddb = aws_sdk_dynamodb::Client::new(&sdk_config(req.ddb_client_region).await);
        let key_store = DynamoDbKeyStore::builder()
            .ddb_table_name(req.ddb_table_name)
            .logical_key_store_name(req.logical_key_store_name)
            .kms_configuration(kms_configuration)
            .kms_client(kms)
            .ddb_client(ddb)
            .build()
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;

        let id = uuid::Uuid::new_v4().to_string();
        self.key_stores
            .lock()
            .expect("key stores mutex")
            .insert(id.clone(), SharedKeyStore::new(key_store));
        Ok(CreateKeyStoreClientResponse { key_store_id: id })
    }

    pub fn create_cryptographic_materials_cache(
        &self,
        req: CreateCryptographicMaterialsCacheRequest,
    ) -> Result<CreateCryptographicMaterialsCacheResponse, ServerError> {
        let Ok(entry_capacity) = usize::try_from(req.entry_capacity) else {
            return Err(ServerError::mpl(format!(
                "entryCapacity must not be negative: {}",
                req.entry_capacity
            )));
        };
        let cache = DefaultCmc::builder()
            .entry_capacity(entry_capacity)
            .build()
            .map_err(|e| ServerError::mpl(e.to_string()))?;

        let id = uuid::Uuid::new_v4().to_string();
        self.caches
            .lock()
            .expect("caches mutex")
            .insert(id.clone(), SharedCmc::new(cache));
        Ok(CreateCryptographicMaterialsCacheResponse { cache_id: id })
    }

    pub async fn create_aws_kms_hierarchical_keyring(
        &self,
        req: CreateAwsKmsHierarchicalKeyringRequest,
    ) -> Result<CreateAwsKmsHierarchicalKeyringResponse, ServerError> {
        let key_store = self.get_key_store(&req.key_store_id)?;
        let cache = req
            .cache_id
            .as_deref()
            .map(|id| self.get_cache(id))
            .transpose()?;
        // The MPL takes a Duration, which cannot be negative; the Dafny MPLs
        // reject a non-positive TTL themselves, so this is the MPL's error too.
        let Ok(ttl_seconds) = u64::try_from(req.ttl_seconds) else {
            return Err(ServerError::mpl(format!(
                "ttlSeconds must not be negative: {}",
                req.ttl_seconds
            )));
        };
        let supplier = req.branch_key_id_supplier.map(|supplier| {
            SharedBranchKeyIdSupplier::new(StaticBranchKeyIdSupplierImpl {
                encryption_context_key: supplier.encryption_context_key,
                branch_key_ids: supplier.branch_key_ids,
            })
        });

        let keyring = HierarchicalKeyring::builder()
            .key_store(key_store)
            .ttl(Duration::from_secs(ttl_seconds))
            .set_branch_key_id(req.branch_key_id)
            .set_branch_key_id_supplier(supplier)
            .set_cache(cache)
            .set_partition_id(req.partition_id)
            .build()
            .await
            .map_err(|e| ServerError::mpl(e.to_string()))?;

        let id = uuid::Uuid::new_v4().to_string();
        self.keyrings
            .lock()
            .expect("keyrings mutex")
            .insert(id.clone(), SharedKeyring::new(keyring));
        Ok(CreateAwsKmsHierarchicalKeyringResponse { keyring_id: id })
    }

    pub fn initialize_encryption_materials(
        &self,
        req: InitializeEncryptionMaterialsRequest,
    ) -> Result<InitializeEncryptionMaterialsResponse, ServerError> {
        let materials = EncryptionMaterials::builder()
            .algorithm_suite_id(map_algorithm_suite_id(req.algorithm_suite_id))
            .set_encryption_context(Some(map_encryption_context(&req.encryption_context)))
            .set_required_encryption_context_keys(Some(
                req.required_encryption_context_keys.into_iter().collect(),
            ))
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
            .set_encryption_context(Some(map_encryption_context(&req.encryption_context)))
            .set_required_encryption_context_keys(Some(
                req.required_encryption_context_keys.into_iter().collect(),
            ))
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
            .set_encrypted_data_keys(Some(map_edks(req.encrypted_data_keys)?))
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
            .set_encryption_context(Some(map_encryption_context(&req.encryption_context)))
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
        let symmetric_signing_keys = symmetric_signing_keys_to_shapes(materials);

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
            .set_encrypted_data_keys(Some(map_edks(req.encrypted_data_keys)?))
            .set_encryption_context(Some(map_encryption_context(&req.encryption_context)))
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

    fn get_key_store(&self, key_store_id: &str) -> Result<SharedKeyStore, ServerError> {
        if key_store_id.is_empty() {
            return Err(ServerError::generic("keyStoreId must be non-empty"));
        }
        self.key_stores
            .lock()
            .expect("key stores mutex")
            .get(key_store_id)
            .cloned()
            .ok_or_else(|| ServerError::generic(format!("unknown keyStoreId: {key_store_id}")))
    }

    fn get_cache(&self, cache_id: &str) -> Result<SharedCmc, ServerError> {
        if cache_id.is_empty() {
            return Err(ServerError::generic("cacheId must be non-empty"));
        }
        self.caches
            .lock()
            .expect("caches mutex")
            .get(cache_id)
            .cloned()
            .ok_or_else(|| ServerError::generic(format!("unknown cacheId: {cache_id}")))
    }
}

/// An AWS SDK configuration for `region`, with credentials from the ambient
/// provider chain.
async fn sdk_config(region: String) -> aws_config::SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region))
        .load()
        .await
}

/// The model's `StaticBranchKeyIdSupplier`: look up the encryption context
/// value under `encryption_context_key` and return the branch key id mapped to
/// it, or fail.
struct StaticBranchKeyIdSupplierImpl {
    encryption_context_key: String,
    branch_key_ids: BTreeMap<String, String>,
}

#[aws_crypto_mpl::async_trait]
impl BranchKeyIdSupplier for StaticBranchKeyIdSupplierImpl {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, aws_crypto_mpl::Error> {
        let branch_key_id = input
            .encryption_context()
            .get(&self.encryption_context_key)
            .and_then(|value| self.branch_key_ids.get(value));
        let Some(branch_key_id) = branch_key_id else {
            return Err(aws_crypto_mpl::Error::validation(format!(
                "no branch key id for encryption context key {}",
                self.encryption_context_key
            )));
        };
        GetBranchKeyIdOutput::builder()
            .branch_key_id(branch_key_id.clone())
            .build()
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

/// The materials' symmetric signing keys, or `None` when there are none.
fn symmetric_signing_keys_to_shapes(
    materials: &EncryptionMaterials,
) -> Option<Vec<serde_bytes::ByteBuf>> {
    let keys = materials.symmetric_signing_keys();
    (!keys.is_empty()).then(|| {
        keys.iter()
            .map(|k| serde_bytes::ByteBuf::from(k.as_bytes().to_vec()))
            .collect()
    })
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

fn required_keys_to_wire(keys: &RequiredEncryptionContextKeys) -> Vec<String> {
    keys.to_vec()
}

/// Materials a client sends must satisfy the MPL's own invariants; a rejection
/// is the MPL's, so it is an `MPLClientError`.
fn shape_to_encryption_materials(
    shape: EncryptionMaterialsShape,
) -> Result<EncryptionMaterials, ServerError> {
    EncryptionMaterials::builder()
        .algorithm_suite_id(map_algorithm_suite_id(shape.algorithm_suite_id))
        .set_encrypted_data_keys(Some(map_edks(shape.encrypted_data_keys)?))
        .set_encryption_context(Some(map_encryption_context(&shape.encryption_context)))
        .set_required_encryption_context_keys(Some(
            shape.required_encryption_context_keys.into_iter().collect(),
        ))
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
        .set_encryption_context(Some(map_encryption_context(&shape.encryption_context)))
        .set_required_encryption_context_keys(Some(
            shape.required_encryption_context_keys.into_iter().collect(),
        ))
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
        symmetric_signing_keys: symmetric_signing_keys_to_shapes(materials),
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
