// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operation handlers and the `clientId` registry.
//!
//! `CreateClient` builds a DB-ESDK item encryptor from the modeled config,
//! registers it under a fresh UUID, and returns the id. `EncryptItem` and
//! `DecryptItem` look the encryptor up by `clientId` and run the operation.

use std::collections::HashMap;
use std::sync::Mutex;

use aws_db_esdk::aws_sdk_dynamodb::primitives::Blob;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue as DdbAttributeValue;
use aws_db_esdk::types::{
    AlgorithmSuiteId, CryptoAction as DbeCryptoAction, PlaintextOverride as DbePlaintextOverride,
};
use aws_db_esdk::{ItemEncryptor, TableConfig};
use serde_bytes::ByteBuf;

use crate::error::ServerError;
use crate::keyring::keyring_for_config;
use crate::model::{
    AttributeValue, CreateClientRequest, CreateClientResponse, CryptoAction, DbeAlgorithmSuiteId,
    DbeClientConfig, DdbItem, DecryptItemRequest, DecryptItemResponse, EncryptItemRequest,
    EncryptItemResponse, PlaintextOverride,
};

/// Shared server state: the thread-safe `clientId -> ItemEncryptor` registry.
#[derive(Default)]
pub struct AppState {
    clients: Mutex<HashMap<String, ItemEncryptor>>,
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

fn to_ddb_item(item: DdbItem) -> Result<HashMap<String, DdbAttributeValue>, ServerError> {
    item.into_iter().map(|(k, v)| Ok((k, to_ddb(v)?))).collect()
}

fn from_ddb_item(item: HashMap<String, DdbAttributeValue>) -> Result<DdbItem, ServerError> {
    item.into_iter()
        .map(|(k, v)| Ok((k, from_ddb(v)?)))
        .collect()
}

async fn item_encryptor(config: DbeClientConfig) -> Result<ItemEncryptor, ServerError> {
    if config.cmm.is_some() {
        return Err(ServerError::generic(
            "a CMM is not supported by the native Rust language server",
        ));
    }
    if config.legacy_override.is_some() {
        return Err(ServerError::generic(
            "a legacy override is not supported by the native Rust language server",
        ));
    }
    if config.search.is_some() {
        return Err(ServerError::generic(
            "a search config is not supported by the native Rust language server",
        ));
    }
    let keyring = config
        .keyring
        .as_ref()
        .ok_or_else(|| ServerError::generic("DBEClientConfig must set a keyring or a CMM"))?;
    let keyring = keyring_for_config(keyring).await?;
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
        .keyring(keyring)
        .build()?;
    Ok(ItemEncryptor::builder()
        .table(config.logical_table_name, table)
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
