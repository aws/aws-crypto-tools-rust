// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operation handlers and the `clientId` registry.
//!
//! `CreateClient` builds a DB-ESDK item encryptor from the modeled config,
//! registers it under a fresh UUID, and returns the id. `EncryptItem` and
//! `DecryptItem` look the encryptor up by `clientId` and run the operation.
//! `GetEncryptedDataKeyDescription` needs no client: it only parses a header.

use std::collections::HashMap;
use std::sync::Mutex;

use aws_db_esdk::aws_sdk_dynamodb::primitives::Blob;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue as DdbAttributeValue;
use aws_db_esdk::cmm::{DefaultCmm, SharedCmm};
use aws_db_esdk::structured::{
    AuthItem, AuthenticateAction as DbeAuthenticateAction, CryptoItem, PathSegment,
    StructuredDataTerminal as DbeTerminal, StructuredEncryption,
};
use aws_db_esdk::transforms::Transforms;
use aws_db_esdk::types::{
    AlgorithmSuiteId, CryptoAction as DbeCryptoAction, PlaintextOverride as DbePlaintextOverride,
};
use aws_db_esdk::{ItemEncryptor, TableConfig};
use serde_bytes::ByteBuf;

use crate::error::ServerError;
use crate::keyring::{cmm_for_config, keyring_for_config};
use crate::model::{
    AttributeValue, AuthenticateAction, CreateClientRequest, CreateClientResponse,
    CreateStructuredClientRequest, CreateStructuredClientResponse, CryptoAction,
    DbeAlgorithmSuiteId, DbeClientConfig, DdbItem, DecryptItemRequest, DecryptItemResponse,
    DecryptPathStructureRequest, DecryptPathStructureResponse, DecryptStructureRequest,
    DecryptStructureResponse, EncryptItemRequest, EncryptItemResponse, EncryptPathStructureRequest,
    EncryptPathStructureResponse, EncryptStructureRequest, EncryptStructureResponse,
    EncryptedDataKeyDescription, GetEncryptedDataKeyDescriptionRequest,
    GetEncryptedDataKeyDescriptionResponse, PathAuthItem, PathCryptoItem, PlaintextOverride,
    ResolveAuthActionsRequest, ResolveAuthActionsResponse, StructuredDataMap,
    StructuredDataTerminal,
};
use crate::search::search_config;

/// Shared server state: the thread-safe `clientId -> ItemEncryptor` and
/// `clientId -> StructuredClient` registries.
#[derive(Default)]
pub struct AppState {
    clients: Mutex<HashMap<String, ItemEncryptor>>,
    structured_clients: Mutex<HashMap<String, StructuredClient>>,
    pub(crate) transforms_clients: Mutex<HashMap<String, Transforms>>,
}

/// A structured encryption client and the CMM and algorithm suite its config names.
#[derive(Clone)]
struct StructuredClient {
    client: StructuredEncryption,
    cmm: SharedCmm,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
}

const fn crypto_action(action: CryptoAction) -> DbeCryptoAction {
    match action {
        CryptoAction::EncryptAndSign => DbeCryptoAction::EncryptAndSign,
        CryptoAction::SignOnly => DbeCryptoAction::SignOnly,
        CryptoAction::SignAndIncludeInEncryptionContext => {
            DbeCryptoAction::SignAndIncludeInEncryptionContext
        }
        CryptoAction::DoNothing => DbeCryptoAction::DoNothing,
    }
}

/// A library Crypto Action as the wire's; `None` for an action the model lacks.
const fn from_crypto_action(action: DbeCryptoAction) -> Option<CryptoAction> {
    Some(match action {
        DbeCryptoAction::EncryptAndSign => CryptoAction::EncryptAndSign,
        DbeCryptoAction::SignOnly => CryptoAction::SignOnly,
        DbeCryptoAction::SignAndIncludeInEncryptionContext => {
            CryptoAction::SignAndIncludeInEncryptionContext
        }
        DbeCryptoAction::DoNothing => CryptoAction::DoNothing,
        _ => return None,
    })
}

const fn authenticate_action(action: AuthenticateAction) -> DbeAuthenticateAction {
    match action {
        AuthenticateAction::Sign => DbeAuthenticateAction::Sign,
        AuthenticateAction::DoNotSign => DbeAuthenticateAction::DoNotSign,
    }
}

/// A wire terminal as the library's; the type id must be two bytes.
fn to_terminal(t: StructuredDataTerminal) -> Result<DbeTerminal, ServerError> {
    let type_id = <[u8; 2]>::try_from(t.type_id.as_slice()).map_err(|_| {
        ServerError::client(format!("typeId must be 2 bytes, found {}", t.type_id.len()))
    })?;
    Ok(DbeTerminal::new(type_id, t.value.into_vec()))
}

fn from_terminal(t: DbeTerminal) -> StructuredDataTerminal {
    StructuredDataTerminal {
        type_id: ByteBuf::from(t.type_id().to_vec()),
        value: ByteBuf::from(t.into_value()),
    }
}

fn to_structure(map: StructuredDataMap) -> Result<HashMap<String, DbeTerminal>, ServerError> {
    map.into_iter()
        .map(|(k, v)| Ok((k, to_terminal(v)?)))
        .collect()
}

fn from_structure(map: HashMap<String, DbeTerminal>) -> StructuredDataMap {
    map.into_iter()
        .map(|(k, v)| (k, from_terminal(v)))
        .collect()
}

fn to_path(path: Vec<String>) -> Vec<PathSegment> {
    path.into_iter().map(PathSegment::member).collect()
}

/// A library path as the wire's; only structure-member segments are modeled.
fn from_path(path: &[PathSegment]) -> Result<Vec<String>, ServerError> {
    path.iter()
        .map(|segment| match segment {
            PathSegment::Member(member) => Ok(member.key().to_owned()),
            other => Err(ServerError::generic(format!(
                "unsupported path segment {other:?}"
            ))),
        })
        .collect()
}

fn to_crypto_item(item: PathCryptoItem) -> Result<CryptoItem, ServerError> {
    Ok(CryptoItem::new(
        to_path(item.path),
        to_terminal(item.data)?,
        crypto_action(item.action),
    ))
}

fn to_auth_item(item: PathAuthItem) -> Result<AuthItem, ServerError> {
    Ok(AuthItem::new(
        to_path(item.path),
        to_terminal(item.data)?,
        authenticate_action(item.action),
    ))
}

fn from_crypto_item(item: &CryptoItem) -> Result<PathCryptoItem, ServerError> {
    Ok(PathCryptoItem {
        path: from_path(item.key())?,
        data: from_terminal(item.data().clone()),
        action: from_crypto_action(item.action()).ok_or_else(|| {
            ServerError::generic(format!("unsupported CryptoAction {:?}", item.action()))
        })?,
    })
}

fn from_crypto_items(items: &[CryptoItem]) -> Result<Vec<PathCryptoItem>, ServerError> {
    items.iter().map(from_crypto_item).collect()
}

const fn algorithm_suite(id: DbeAlgorithmSuiteId) -> AlgorithmSuiteId {
    match id {
        DbeAlgorithmSuiteId::Symsig => {
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384
        }
        DbeAlgorithmSuiteId::EcdsaSymsig => {
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384
        }
    }
}

const fn plaintext_override(policy: PlaintextOverride) -> DbePlaintextOverride {
    match policy {
        PlaintextOverride::ForceWriteAllowRead => {
            DbePlaintextOverride::ForcePlaintextWriteAllowPlaintextRead
        }
        PlaintextOverride::ForbidWriteAllowRead => {
            DbePlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead
        }
        PlaintextOverride::ForbidWriteForbidRead => {
            DbePlaintextOverride::ForbidPlaintextWriteForbidPlaintextRead
        }
    }
}

/// A wire `AttributeValue` as the DynamoDB SDK's; exactly one member must be set.
pub fn to_ddb(value: AttributeValue) -> Result<DdbAttributeValue, ServerError> {
    let AttributeValue {
        s,
        n,
        b,
        bool_value,
        null,
        ss,
        ns,
        bs,
        l,
        m,
    } = value;
    let mut set: Vec<DdbAttributeValue> = Vec::with_capacity(1);
    if let Some(v) = s {
        set.push(DdbAttributeValue::S(v));
    }
    if let Some(v) = n {
        set.push(DdbAttributeValue::N(v));
    }
    if let Some(v) = b {
        set.push(DdbAttributeValue::B(Blob::new(v.into_vec())));
    }
    if let Some(v) = bool_value {
        set.push(DdbAttributeValue::Bool(v));
    }
    if let Some(v) = null {
        set.push(DdbAttributeValue::Null(v));
    }
    if let Some(v) = ss {
        set.push(DdbAttributeValue::Ss(v));
    }
    if let Some(v) = ns {
        set.push(DdbAttributeValue::Ns(v));
    }
    if let Some(v) = bs {
        set.push(DdbAttributeValue::Bs(
            v.into_iter().map(|x| Blob::new(x.into_vec())).collect(),
        ));
    }
    if let Some(v) = l {
        set.push(DdbAttributeValue::L(
            v.into_iter().map(to_ddb).collect::<Result<_, _>>()?,
        ));
    }
    if let Some(v) = m {
        set.push(DdbAttributeValue::M(to_ddb_item(v)?));
    }
    match <[DdbAttributeValue; 1]>::try_from(set) {
        Ok([one]) => Ok(one),
        Err(set) => Err(ServerError::generic(format!(
            "AttributeValue must set exactly one member, found {}",
            set.len()
        ))),
    }
}

/// The DynamoDB SDK's `AttributeValue` as the wire shape.
pub fn from_ddb(value: DdbAttributeValue) -> Result<AttributeValue, ServerError> {
    let mut out = AttributeValue::default();
    match value {
        DdbAttributeValue::S(v) => out.s = Some(v),
        DdbAttributeValue::N(v) => out.n = Some(v),
        DdbAttributeValue::B(v) => out.b = Some(ByteBuf::from(v.into_inner())),
        DdbAttributeValue::Bool(v) => out.bool_value = Some(v),
        DdbAttributeValue::Null(v) => out.null = Some(v),
        DdbAttributeValue::Ss(v) => out.ss = Some(v),
        DdbAttributeValue::Ns(v) => out.ns = Some(v),
        DdbAttributeValue::Bs(v) => {
            out.bs = Some(
                v.into_iter()
                    .map(|x| ByteBuf::from(x.into_inner()))
                    .collect(),
            );
        }
        DdbAttributeValue::L(v) => {
            out.l = Some(v.into_iter().map(from_ddb).collect::<Result<_, _>>()?);
        }
        DdbAttributeValue::M(v) => out.m = Some(from_ddb_item(v)?),
        other => {
            return Err(ServerError::generic(format!(
                "unsupported DynamoDB AttributeValue {other:?}"
            )))
        }
    }
    Ok(out)
}

pub(crate) fn to_ddb_item(
    item: DdbItem,
) -> Result<HashMap<String, DdbAttributeValue>, ServerError> {
    item.into_iter().map(|(k, v)| Ok((k, to_ddb(v)?))).collect()
}

pub(crate) fn from_ddb_item(
    item: HashMap<String, DdbAttributeValue>,
) -> Result<DdbItem, ServerError> {
    item.into_iter()
        .map(|(k, v)| Ok((k, from_ddb(v)?)))
        .collect()
}

/// The keyring or the CMM of `config`; exactly one must be set.
async fn materials(
    config: &DbeClientConfig,
) -> Result<
    (
        Option<aws_db_esdk::keyring::SharedKeyring>,
        Option<SharedCmm>,
    ),
    ServerError,
> {
    match (&config.keyring, &config.cmm) {
        (Some(keyring), None) => Ok((Some(keyring_for_config(keyring).await?), None)),
        (None, Some(cmm)) => Ok((None, Some(cmm_for_config(cmm).await?))),
        _ => Err(ServerError::generic(
            "DBEClientConfig must set exactly one of a keyring or a CMM",
        )),
    }
}

/// The library's table configuration for the wire's `config`.
pub(crate) async fn table_config(mut config: DbeClientConfig) -> Result<TableConfig, ServerError> {
    if config.legacy_override.is_some() {
        // The native library has no legacy DDBEC encryptor, so a legacy override
        // fails as a library validation error, as the Dafny Rust library does.
        return Err(ServerError::client("Legacy configuration unsupported."));
    }
    let search = match config.search.take() {
        Some(search) => Some(search_config(search).await?),
        None => None,
    };
    let (keyring, cmm) = materials(&config).await?;
    let table = TableConfig::builder()
        .partition_key_name(config.partition_key_name)
        .set_sort_key_name(config.sort_key_name)
        .set_attribute_actions_on_encrypt(Some(
            config
                .attribute_actions_on_encrypt
                .into_iter()
                .map(|(k, a)| (k, crypto_action(a)))
                .collect(),
        ))
        .set_allowed_unsigned_attribute_prefix(config.allowed_unsigned_attribute_prefix)
        .set_allowed_unsigned_attributes(config.allowed_unsigned_attributes)
        .set_algorithm_suite_id(config.algorithm_suite_id.map(algorithm_suite))
        .set_plaintext_override(config.plaintext_override.map(plaintext_override))
        .set_keyring(keyring)
        .set_cmm(cmm)
        .set_logical_table_name(Some(config.logical_table_name))
        .set_search(search)
        .build()?;
    Ok(table)
}

async fn item_encryptor(mut config: DbeClientConfig) -> Result<ItemEncryptor, ServerError> {
    // Only a transforms client honors a search config; the item encryptor ignores it.
    config.search = None;
    let name = config.logical_table_name.clone();
    Ok(ItemEncryptor::builder()
        .table(name, table_config(config).await?)
        .build()?)
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build and register an item encryptor; returns its new id.
    pub async fn create_client(
        &self,
        req: CreateClientRequest,
    ) -> Result<CreateClientResponse, ServerError> {
        let encryptor = item_encryptor(req.config).await?;
        let client_id = uuid::Uuid::new_v4().to_string();
        self.clients
            .lock()
            .expect("registry mutex")
            .insert(client_id.clone(), encryptor);
        Ok(CreateClientResponse { client_id })
    }

    pub async fn encrypt_item(
        &self,
        req: EncryptItemRequest,
    ) -> Result<EncryptItemResponse, ServerError> {
        let encryptor = self.client(&req.client_id)?;
        let output = encryptor
            .encrypt_item()
            .plaintext_item(to_ddb_item(req.plaintext_item)?)
            .send()
            .await?;
        Ok(EncryptItemResponse {
            encrypted_item: from_ddb_item(output.into_encrypted_item())?,
        })
    }

    pub async fn decrypt_item(
        &self,
        req: DecryptItemRequest,
    ) -> Result<DecryptItemResponse, ServerError> {
        let encryptor = self.client(&req.client_id)?;
        let output = encryptor
            .decrypt_item()
            .encrypted_item(to_ddb_item(req.encrypted_item)?)
            .send()
            .await?;
        Ok(DecryptItemResponse {
            plaintext_item: from_ddb_item(output.into_plaintext_item())?,
        })
    }

    /// Describe the EDKs of a header, or of an encrypted item's header. Needs no client.
    pub fn get_encrypted_data_key_description(
        &self,
        req: GetEncryptedDataKeyDescriptionRequest,
    ) -> Result<GetEncryptedDataKeyDescriptionResponse, ServerError> {
        let keys = match (req.input.header, req.input.item) {
            (Some(header), None) => {
                aws_db_esdk::describe_header_encrypted_data_keys(header.as_slice())?
            }
            (None, Some(item)) => aws_db_esdk::describe_encrypted_data_keys(&to_ddb_item(item)?)?,
            _ => {
                return Err(ServerError::generic(
                    "EncryptedDataKeyDescriptionSource must set exactly one of header or item",
                ))
            }
        };
        Ok(GetEncryptedDataKeyDescriptionResponse {
            descriptions: keys
                .iter()
                .map(|k| EncryptedDataKeyDescription {
                    key_provider_id: k.key_provider_id().to_owned(),
                    key_provider_info: k.key_provider_info().map(str::to_owned),
                    branch_key_id: k.branch_key_id().map(str::to_owned),
                    branch_key_version: k.branch_key_version().map(str::to_owned),
                })
                .collect(),
        })
    }

    /// Build and register a structured encryption client over the config's
    /// keyring or CMM; returns its new id.
    pub async fn create_structured_client(
        &self,
        req: CreateStructuredClientRequest,
    ) -> Result<CreateStructuredClientResponse, ServerError> {
        let cmm = match materials(&req.config).await? {
            (Some(keyring), None) => SharedCmm::new(DefaultCmm::new(keyring)),
            (None, Some(cmm)) => cmm,
            _ => unreachable!("materials returns exactly one of a keyring or a CMM"),
        };
        let client = StructuredClient {
            client: StructuredEncryption::new(),
            cmm,
            algorithm_suite_id: req.config.algorithm_suite_id.map(algorithm_suite),
        };
        let client_id = uuid::Uuid::new_v4().to_string();
        self.structured_clients
            .lock()
            .expect("registry mutex")
            .insert(client_id.clone(), client);
        Ok(CreateStructuredClientResponse { client_id })
    }

    pub async fn encrypt_structure(
        &self,
        req: EncryptStructureRequest,
    ) -> Result<EncryptStructureResponse, ServerError> {
        let sc = self.structured_client(&req.client_id)?;
        let output = sc
            .client
            .encrypt_structure()
            .table_name(req.table_name)
            .set_plaintext_structure(Some(to_structure(req.plaintext_structure)?))
            .set_crypto_schema(Some(
                req.crypto_schema
                    .into_iter()
                    .map(|(k, a)| (k, crypto_action(a)))
                    .collect(),
            ))
            .cmm(sc.cmm)
            .set_algorithm_suite_id(sc.algorithm_suite_id)
            .send()
            .await?;
        Ok(EncryptStructureResponse {
            encrypted_structure: from_structure(output.into_encrypted_structure()),
        })
    }

    pub async fn decrypt_structure(
        &self,
        req: DecryptStructureRequest,
    ) -> Result<DecryptStructureResponse, ServerError> {
        let sc = self.structured_client(&req.client_id)?;
        let output = sc
            .client
            .decrypt_structure()
            .table_name(req.table_name)
            .set_encrypted_structure(Some(to_structure(req.encrypted_structure)?))
            .set_authenticate_schema(Some(
                req.authenticate_schema
                    .into_iter()
                    .map(|(k, a)| (k, authenticate_action(a)))
                    .collect(),
            ))
            .cmm(sc.cmm)
            .send()
            .await?;
        Ok(DecryptStructureResponse {
            plaintext_structure: from_structure(output.into_plaintext_structure()),
        })
    }

    pub async fn encrypt_path_structure(
        &self,
        req: EncryptPathStructureRequest,
    ) -> Result<EncryptPathStructureResponse, ServerError> {
        let sc = self.structured_client(&req.client_id)?;
        let items = req
            .plaintext_structure
            .into_iter()
            .map(to_crypto_item)
            .collect::<Result<_, _>>()?;
        let output = sc
            .client
            .encrypt_path_structure()
            .table_name(req.table_name)
            .set_plaintext_structure(Some(items))
            .cmm(sc.cmm)
            .set_algorithm_suite_id(sc.algorithm_suite_id)
            .send()
            .await?;
        Ok(EncryptPathStructureResponse {
            encrypted_structure: from_crypto_items(output.encrypted_structure())?,
        })
    }

    pub async fn decrypt_path_structure(
        &self,
        req: DecryptPathStructureRequest,
    ) -> Result<DecryptPathStructureResponse, ServerError> {
        let sc = self.structured_client(&req.client_id)?;
        let items = req
            .encrypted_structure
            .into_iter()
            .map(to_auth_item)
            .collect::<Result<_, _>>()?;
        let output = sc
            .client
            .decrypt_path_structure()
            .table_name(req.table_name)
            .set_encrypted_structure(Some(items))
            .cmm(sc.cmm)
            .send()
            .await?;
        Ok(DecryptPathStructureResponse {
            plaintext_structure: from_crypto_items(output.plaintext_structure())?,
        })
    }

    /// Resolve each terminal's Crypto Action from the header. Needs no client.
    pub async fn resolve_auth_actions(
        &self,
        req: ResolveAuthActionsRequest,
    ) -> Result<ResolveAuthActionsResponse, ServerError> {
        let items = req
            .auth_actions
            .into_iter()
            .map(to_auth_item)
            .collect::<Result<_, _>>()?;
        let output = StructuredEncryption::new()
            .resolve_auth_actions()
            .table_name(req.table_name)
            .set_auth_actions(Some(items))
            .header_bytes(req.header_bytes.into_vec())
            .send()
            .await?;
        Ok(ResolveAuthActionsResponse {
            crypto_actions: from_crypto_items(output.crypto_actions())?,
        })
    }

    /// Look up a registered structured encryption client by id.
    fn structured_client(&self, client_id: &str) -> Result<StructuredClient, ServerError> {
        if client_id.is_empty() {
            return Err(ServerError::generic("clientId must be non-empty"));
        }
        self.structured_clients
            .lock()
            .expect("registry mutex")
            .get(client_id)
            .cloned()
            .ok_or_else(|| ServerError::generic(format!("unknown clientId: {client_id}")))
    }

    /// Look up a registered item encryptor by id.
    fn client(&self, client_id: &str) -> Result<ItemEncryptor, ServerError> {
        if client_id.is_empty() {
            return Err(ServerError::generic("clientId must be non-empty"));
        }
        self.clients
            .lock()
            .expect("registry mutex")
            .get(client_id)
            .cloned()
            .ok_or_else(|| ServerError::generic(format!("unknown clientId: {client_id}")))
    }
}
