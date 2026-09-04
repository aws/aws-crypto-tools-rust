// The three operation handlers: CreateClient / EncryptItem / DecryptItem.
// They delegate to the real DBE `item_encryptor` client and translate between
// the wire `AttributeValue` (scalars only) and the AWS SDK's `AttributeValue`
// that the item encryptor consumes and produces.
//
// A DBE-library failure on Encrypt/Decrypt becomes a DBESDKClientError (this is
// the failure a tamper test asserts on); a bad clientId or an unsupported wire
// value is a GenericServerError.

use crate::error::ServerError;
use crate::factory;
use crate::model;
use crate::registry::ClientRegistry;
use aws_config::SdkConfig;
use aws_db_esdk::material_providers::client::Client as MplClient;
use aws_sdk_dynamodb::operation::get_item::{
    GetItemInput as SdkGetItemInput, GetItemOutput as SdkGetItemOutput,
};
use aws_sdk_dynamodb::operation::put_item::PutItemInput as SdkPutItemInput;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue as Ddb;
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::sync::Arc;

/// Shared, thread-safe state handed to every axum request task.
#[derive(Clone)]
pub struct AppState {
    pub mpl: Arc<MplClient>,
    pub sdk_config: Arc<SdkConfig>,
    pub registry: ClientRegistry,
}

pub async fn create_client(
    state: &AppState,
    request: model::CreateClientRequest,
) -> Result<model::CreateClientResponse, ServerError> {
    let encryptor = factory::build_client(&state.mpl, &state.sdk_config, &request.config).await?;
    let client_id = state.registry.register(encryptor);
    Ok(model::CreateClientResponse { client_id })
}

pub async fn encrypt_item(
    state: &AppState,
    request: model::EncryptItemRequest,
) -> Result<model::EncryptItemResponse, ServerError> {
    let handle = state.registry.get(&request.client_id)?;
    let plaintext = to_ddb_item(&request.plaintext_item)?;
    // Serialize operations on this client: the DBE client cannot tolerate
    // concurrent calls (see registry.rs).
    let _guard = handle.op_lock.lock().await;
    let output = handle
        .encryptor
        .encrypt_item()
        .plaintext_item(plaintext)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let encrypted = output
        .encrypted_item
        .ok_or_else(|| ServerError::Client("EncryptItem returned no encrypted_item".into()))?;
    Ok(model::EncryptItemResponse {
        encrypted_item: from_ddb_item(&encrypted)?,
    })
}

pub async fn decrypt_item(
    state: &AppState,
    request: model::DecryptItemRequest,
) -> Result<model::DecryptItemResponse, ServerError> {
    let handle = state.registry.get(&request.client_id)?;
    let encrypted = to_ddb_item(&request.encrypted_item)?;
    // Serialize operations on this client: the DBE client cannot tolerate
    // concurrent calls (see registry.rs).
    let _guard = handle.op_lock.lock().await;
    let output = handle
        .encryptor
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let plaintext = output
        .plaintext_item
        .ok_or_else(|| ServerError::Client("DecryptItem returned no plaintext_item".into()))?;
    Ok(model::DecryptItemResponse {
        plaintext_item: from_ddb_item(&plaintext)?,
    })
}

// ---------------------------------------------------------------------------
// DDB SDK transform handlers. CreateTransformsClient builds a transforms client
// bound to one table; PutItemInputTransform encrypts a PutItem input;
// GetItemOutputTransform decrypts a GetItem output. Each maps the minimal wire
// shape onto the real aws_sdk_dynamodb request/response type.
// ---------------------------------------------------------------------------

pub async fn create_transforms_client(
    state: &AppState,
    request: model::CreateTransformsClientRequest,
) -> Result<model::CreateTransformsClientResponse, ServerError> {
    let client = factory::build_transforms_client(
        &state.mpl,
        &state.sdk_config,
        &request.config,
        &request.table_name,
    )
    .await?;
    let client_id = state.registry.register_transforms(client);
    Ok(model::CreateTransformsClientResponse { client_id })
}

pub async fn put_item_input_transform(
    state: &AppState,
    request: model::PutItemInputTransformRequest,
) -> Result<model::PutItemInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let sdk_input = SdkPutItemInput::builder()
        .table_name(&request.sdk_input.table_name)
        .set_item(Some(to_ddb_item(&request.sdk_input.item)?))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid PutItemInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .put_item_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_input.ok_or_else(|| {
        ServerError::Client("PutItemInputTransform returned no transformed_input".into())
    })?;

    let table_name = transformed.table_name().unwrap_or_default().to_string();
    let item = transformed.item().cloned().unwrap_or_default();
    Ok(model::PutItemInputTransformResponse {
        transformed_input: model::PutItemInput {
            table_name,
            item: from_ddb_item(&item)?,
        },
    })
}

pub async fn get_item_output_transform(
    state: &AppState,
    request: model::GetItemOutputTransformRequest,
) -> Result<model::GetItemOutputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let original_input = SdkGetItemInput::builder()
        .table_name(&request.original_input.table_name)
        .set_key(Some(to_ddb_item(&request.original_input.key)?))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid GetItemInput: {e}")))?;

    let mut out_builder = SdkGetItemOutput::builder();
    if let Some(item) = &request.sdk_output.item {
        out_builder = out_builder.set_item(Some(to_ddb_item(item)?));
    }
    let sdk_output = out_builder.build();

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .get_item_output_transform()
        .original_input(original_input)
        .sdk_output(sdk_output)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_output.ok_or_else(|| {
        ServerError::Client("GetItemOutputTransform returned no transformed_output".into())
    })?;

    let item = match transformed.item() {
        Some(map) if !map.is_empty() => Some(from_ddb_item(map)?),
        _ => None,
    };
    Ok(model::GetItemOutputTransformResponse {
        transformed_output: model::GetItemOutput { item },
    })
}

// ---------------------------------------------------------------------------
// AttributeValue conversion (wire scalars <-> AWS SDK AttributeValue)
// ---------------------------------------------------------------------------

fn to_ddb_item(item: &model::DdbItem) -> Result<HashMap<String, Ddb>, ServerError> {
    item.iter()
        .map(|(name, value)| Ok((name.clone(), to_ddb_value(value)?)))
        .collect()
}

fn to_ddb_value(value: &model::AttributeValue) -> Result<Ddb, ServerError> {
    if let Some(s) = &value.s {
        return Ok(Ddb::S(s.clone()));
    }
    if let Some(n) = &value.n {
        return Ok(Ddb::N(n.clone()));
    }
    if let Some(b) = &value.b {
        return Ok(Ddb::B(Blob::new(b.to_vec())));
    }
    if let Some(flag) = value.bool_value {
        return Ok(Ddb::Bool(flag));
    }
    if value.null.is_some() {
        return Ok(Ddb::Null(true));
    }
    if let Some(ss) = &value.ss {
        return Ok(Ddb::Ss(ss.clone()));
    }
    if let Some(ns) = &value.ns {
        return Ok(Ddb::Ns(ns.clone()));
    }
    if let Some(bs) = &value.bs {
        return Ok(Ddb::Bs(bs.iter().map(|b| Blob::new(b.to_vec())).collect()));
    }
    if let Some(l) = &value.l {
        let items = l
            .iter()
            .map(to_ddb_value)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Ddb::L(items));
    }
    if let Some(m) = &value.m {
        return Ok(Ddb::M(to_ddb_item(m)?));
    }
    Err(ServerError::Generic(
        "AttributeValue had no member set".into(),
    ))
}

fn from_ddb_item(item: &HashMap<String, Ddb>) -> Result<model::DdbItem, ServerError> {
    item.iter()
        .map(|(name, value)| Ok((name.clone(), from_ddb_value(value)?)))
        .collect()
}

fn from_ddb_value(value: &Ddb) -> Result<model::AttributeValue, ServerError> {
    let mut out = model::AttributeValue::default();
    match value {
        Ddb::S(s) => out.s = Some(s.clone()),
        Ddb::N(n) => out.n = Some(n.clone()),
        Ddb::B(b) => out.b = Some(ByteBuf::from(b.as_ref().to_vec())),
        Ddb::Bool(flag) => out.bool_value = Some(*flag),
        Ddb::Null(_) => out.null = Some(true),
        Ddb::Ss(ss) => out.ss = Some(ss.clone()),
        Ddb::Ns(ns) => out.ns = Some(ns.clone()),
        Ddb::Bs(bs) => {
            out.bs = Some(bs.iter().map(|b| ByteBuf::from(b.as_ref().to_vec())).collect());
        }
        Ddb::L(list) => {
            let items = list
                .iter()
                .map(from_ddb_value)
                .collect::<Result<Vec<_>, _>>()?;
            out.l = Some(items);
        }
        Ddb::M(map) => out.m = Some(from_ddb_item(map)?),
        other => {
            return Err(ServerError::Generic(format!(
                "unsupported AttributeValue variant on the wire: {other:?}"
            )));
        }
    }
    Ok(out)
}
