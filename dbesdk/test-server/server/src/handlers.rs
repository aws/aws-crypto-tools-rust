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
use aws_sdk_dynamodb::operation::batch_get_item::{
    BatchGetItemInput as SdkBatchGetItemInput, BatchGetItemOutput as SdkBatchGetItemOutput,
};
use aws_sdk_dynamodb::operation::batch_write_item::{
    BatchWriteItemInput as SdkBatchWriteItemInput, BatchWriteItemOutput as SdkBatchWriteItemOutput,
};
use aws_sdk_dynamodb::operation::batch_execute_statement::BatchExecuteStatementInput as SdkBatchExecuteStatementInput;
use aws_sdk_dynamodb::operation::delete_item::DeleteItemInput as SdkDeleteItemInput;
use aws_sdk_dynamodb::operation::execute_statement::ExecuteStatementInput as SdkExecuteStatementInput;
use aws_sdk_dynamodb::operation::execute_transaction::ExecuteTransactionInput as SdkExecuteTransactionInput;
use aws_sdk_dynamodb::operation::get_item::{
    GetItemInput as SdkGetItemInput, GetItemOutput as SdkGetItemOutput,
};
use aws_sdk_dynamodb::operation::put_item::PutItemInput as SdkPutItemInput;
use aws_sdk_dynamodb::operation::query::{QueryInput as SdkQueryInput, QueryOutput as SdkQueryOutput};
use aws_sdk_dynamodb::operation::scan::{ScanInput as SdkScanInput, ScanOutput as SdkScanOutput};
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsInput as SdkTransactWriteItemsInput;
use aws_sdk_dynamodb::operation::update_item::UpdateItemInput as SdkUpdateItemInput;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue as Ddb;
use aws_sdk_dynamodb::types::{
    BatchStatementRequest as SdkBatchStatementRequest, DeleteRequest as SdkDeleteRequest,
    KeysAndAttributes as SdkKeysAndAttributes, ParameterizedStatement as SdkParameterizedStatement,
    Put as SdkPut, PutRequest as SdkPutRequest, TransactWriteItem as SdkTransactWriteItem,
    WriteRequest as SdkWriteRequest,
};
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

pub async fn batch_write_item_input_transform(
    state: &AppState,
    request: model::BatchWriteItemInputTransformRequest,
) -> Result<model::BatchWriteItemInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;

    let sdk_input = SdkBatchWriteItemInput::builder()
        .set_request_items(Some(to_sdk_write_request_map(&request.sdk_input.request_items)?))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid BatchWriteItemInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .batch_write_item_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_input.ok_or_else(|| {
        ServerError::Client("BatchWriteItemInputTransform returned no transformed_input".into())
    })?;

    let request_items = match transformed.request_items() {
        Some(items) => to_wire_write_request_map(items)?,
        None => HashMap::new(),
    };
    Ok(model::BatchWriteItemInputTransformResponse {
        transformed_input: model::BatchWriteItemInput { request_items },
    })
}

pub async fn batch_write_item_output_transform(
    state: &AppState,
    request: model::BatchWriteItemOutputTransformRequest,
) -> Result<model::BatchWriteItemOutputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;

    let original_input = SdkBatchWriteItemInput::builder()
        .set_request_items(Some(to_sdk_write_request_map(
            &request.original_input.request_items,
        )?))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid BatchWriteItemInput: {e}")))?;

    let mut out_builder = SdkBatchWriteItemOutput::builder();
    if let Some(unprocessed) = &request.sdk_output.unprocessed_items {
        out_builder = out_builder.set_unprocessed_items(Some(to_sdk_write_request_map(unprocessed)?));
    }
    let sdk_output = out_builder.build();

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .batch_write_item_output_transform()
        .original_input(original_input)
        .sdk_output(sdk_output)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_output.ok_or_else(|| {
        ServerError::Client("BatchWriteItemOutputTransform returned no transformed_output".into())
    })?;

    let unprocessed_items = match transformed.unprocessed_items() {
        Some(items) if !items.is_empty() => Some(to_wire_write_request_map(items)?),
        _ => None,
    };
    Ok(model::BatchWriteItemOutputTransformResponse {
        transformed_output: model::BatchWriteItemOutput { unprocessed_items },
    })
}

pub async fn transact_write_items_input_transform(
    state: &AppState,
    request: model::TransactWriteItemsInputTransformRequest,
) -> Result<model::TransactWriteItemsInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;

    let mut sdk_items = Vec::with_capacity(request.sdk_input.transact_items.len());
    for item in &request.sdk_input.transact_items {
        sdk_items.push(to_sdk_transact_write_item(item)?);
    }
    let sdk_input = SdkTransactWriteItemsInput::builder()
        .set_transact_items(Some(sdk_items))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid TransactWriteItemsInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .transact_write_items_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_input.ok_or_else(|| {
        ServerError::Client("TransactWriteItemsInputTransform returned no transformed_input".into())
    })?;

    let mut wire_items = Vec::with_capacity(transformed.transact_items().len());
    for item in transformed.transact_items() {
        wire_items.push(to_wire_transact_write_item(item)?);
    }
    Ok(model::TransactWriteItemsInputTransformResponse {
        transformed_input: model::TransactWriteItemsInput {
            transact_items: wire_items,
        },
    })
}

fn to_sdk_write_request(wr: &model::WriteRequest) -> Result<SdkWriteRequest, ServerError> {
    if let Some(pr) = &wr.put_request {
        let put = SdkPutRequest::builder()
            .set_item(Some(to_ddb_item(&pr.item)?))
            .build()
            .map_err(|e| ServerError::Generic(format!("invalid PutRequest: {e}")))?;
        return Ok(SdkWriteRequest::builder().put_request(put).build());
    }
    if let Some(dr) = &wr.delete_request {
        let del = SdkDeleteRequest::builder()
            .set_key(Some(to_ddb_item(&dr.key)?))
            .build()
            .map_err(|e| ServerError::Generic(format!("invalid DeleteRequest: {e}")))?;
        return Ok(SdkWriteRequest::builder().delete_request(del).build());
    }
    Err(ServerError::Generic(
        "WriteRequest must set exactly one of putRequest or deleteRequest".into(),
    ))
}

fn to_wire_write_request(wr: &SdkWriteRequest) -> Result<model::WriteRequest, ServerError> {
    if let Some(pr) = wr.put_request() {
        return Ok(model::WriteRequest {
            put_request: Some(model::PutRequest {
                item: from_ddb_item(pr.item())?,
            }),
            delete_request: None,
        });
    }
    if let Some(dr) = wr.delete_request() {
        return Ok(model::WriteRequest {
            put_request: None,
            delete_request: Some(model::DeleteRequest {
                key: from_ddb_item(dr.key())?,
            }),
        });
    }
    Err(ServerError::Client(
        "DBE returned a WriteRequest with neither putRequest nor deleteRequest".into(),
    ))
}

fn to_sdk_write_request_map(
    wire: &HashMap<String, Vec<model::WriteRequest>>,
) -> Result<HashMap<String, Vec<SdkWriteRequest>>, ServerError> {
    let mut out = HashMap::new();
    for (table, list) in wire {
        let mut sdk_list = Vec::with_capacity(list.len());
        for wr in list {
            sdk_list.push(to_sdk_write_request(wr)?);
        }
        out.insert(table.clone(), sdk_list);
    }
    Ok(out)
}

fn to_wire_write_request_map(
    sdk: &HashMap<String, Vec<SdkWriteRequest>>,
) -> Result<HashMap<String, Vec<model::WriteRequest>>, ServerError> {
    let mut out = HashMap::new();
    for (table, list) in sdk {
        let mut wire_list = Vec::with_capacity(list.len());
        for wr in list {
            wire_list.push(to_wire_write_request(wr)?);
        }
        out.insert(table.clone(), wire_list);
    }
    Ok(out)
}

fn to_sdk_transact_write_item(
    item: &model::TransactWriteItem,
) -> Result<SdkTransactWriteItem, ServerError> {
    let put = item.put.as_ref().ok_or_else(|| {
        ServerError::Generic("TransactWriteItem must set a put action (only Put is modeled)".into())
    })?;
    let sdk_put = SdkPut::builder()
        .table_name(&put.table_name)
        .set_item(Some(to_ddb_item(&put.item)?))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid Put: {e}")))?;
    Ok(SdkTransactWriteItem::builder().put(sdk_put).build())
}

fn to_wire_transact_write_item(
    item: &SdkTransactWriteItem,
) -> Result<model::TransactWriteItem, ServerError> {
    let put = item.put().ok_or_else(|| {
        ServerError::Client("DBE returned a TransactWriteItem with no put action".into())
    })?;
    Ok(model::TransactWriteItem {
        put: Some(model::Put {
            table_name: put.table_name().to_string(),
            item: from_ddb_item(put.item())?,
        }),
    })
}

pub async fn scan_output_transform(
    state: &AppState,
    request: model::ScanOutputTransformRequest,
) -> Result<model::ScanOutputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let original_input = SdkScanInput::builder()
        .table_name(&request.original_input.table_name)
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid ScanInput: {e}")))?;

    let mut out_builder = SdkScanOutput::builder();
    if let Some(items) = &request.sdk_output.items {
        out_builder = out_builder.set_items(Some(to_ddb_items(items)?));
    }
    let sdk_output = out_builder.build();

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .scan_output_transform()
        .original_input(original_input)
        .sdk_output(sdk_output)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_output.ok_or_else(|| {
        ServerError::Client("ScanOutputTransform returned no transformed_output".into())
    })?;

    Ok(model::ScanOutputTransformResponse {
        transformed_output: model::ScanOutput {
            items: from_ddb_items_opt(transformed.items())?,
        },
    })
}

pub async fn query_output_transform(
    state: &AppState,
    request: model::QueryOutputTransformRequest,
) -> Result<model::QueryOutputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let original_input = SdkQueryInput::builder()
        .table_name(&request.original_input.table_name)
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid QueryInput: {e}")))?;

    let mut out_builder = SdkQueryOutput::builder();
    if let Some(items) = &request.sdk_output.items {
        out_builder = out_builder.set_items(Some(to_ddb_items(items)?));
    }
    let sdk_output = out_builder.build();

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .query_output_transform()
        .original_input(original_input)
        .sdk_output(sdk_output)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_output.ok_or_else(|| {
        ServerError::Client("QueryOutputTransform returned no transformed_output".into())
    })?;

    Ok(model::QueryOutputTransformResponse {
        transformed_output: model::QueryOutput {
            items: from_ddb_items_opt(transformed.items())?,
        },
    })
}

pub async fn batch_get_item_output_transform(
    state: &AppState,
    request: model::BatchGetItemOutputTransformRequest,
) -> Result<model::BatchGetItemOutputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;

    let mut sdk_request_items: HashMap<String, SdkKeysAndAttributes> = HashMap::new();
    for (table, ka) in &request.original_input.request_items {
        let sdk_ka = SdkKeysAndAttributes::builder()
            .set_keys(Some(to_ddb_items(&ka.keys)?))
            .build()
            .map_err(|e| ServerError::Generic(format!("invalid KeysAndAttributes: {e}")))?;
        sdk_request_items.insert(table.clone(), sdk_ka);
    }
    let original_input = SdkBatchGetItemInput::builder()
        .set_request_items(Some(sdk_request_items))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid BatchGetItemInput: {e}")))?;

    let mut out_builder = SdkBatchGetItemOutput::builder();
    if let Some(responses) = &request.sdk_output.responses {
        let mut sdk_responses: HashMap<String, Vec<HashMap<String, Ddb>>> = HashMap::new();
        for (table, items) in responses {
            sdk_responses.insert(table.clone(), to_ddb_items(items)?);
        }
        out_builder = out_builder.set_responses(Some(sdk_responses));
    }
    let sdk_output = out_builder.build();

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .batch_get_item_output_transform()
        .original_input(original_input)
        .sdk_output(sdk_output)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_output.ok_or_else(|| {
        ServerError::Client("BatchGetItemOutputTransform returned no transformed_output".into())
    })?;

    let responses = match transformed.responses() {
        Some(map) if !map.is_empty() => {
            let mut wire = HashMap::new();
            for (table, items) in map {
                wire.insert(table.clone(), from_ddb_items(items)?);
            }
            Some(wire)
        }
        _ => None,
    };
    Ok(model::BatchGetItemOutputTransformResponse {
        transformed_output: model::BatchGetItemOutput { responses },
    })
}

fn to_ddb_items(items: &[model::DdbItem]) -> Result<Vec<HashMap<String, Ddb>>, ServerError> {
    items.iter().map(to_ddb_item).collect()
}

fn from_ddb_items(items: &[HashMap<String, Ddb>]) -> Result<Vec<model::DdbItem>, ServerError> {
    items.iter().map(from_ddb_item).collect()
}

/// Map an SDK item slice to the wire, treating an empty slice as absent (an
/// SDK output exposes an unset item list as an empty slice, not None).
fn from_ddb_items_opt(
    items: &[HashMap<String, Ddb>],
) -> Result<Option<Vec<model::DdbItem>>, ServerError> {
    if items.is_empty() {
        Ok(None)
    } else {
        Ok(Some(from_ddb_items(items)?))
    }
}

pub async fn execute_statement_input_transform(
    state: &AppState,
    request: model::ExecuteStatementInputTransformRequest,
) -> Result<model::ExecuteStatementInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let sdk_input = SdkExecuteStatementInput::builder()
        .statement(&request.sdk_input.statement)
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid ExecuteStatementInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .execute_statement_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_input.ok_or_else(|| {
        ServerError::Client("ExecuteStatementInputTransform returned no transformed_input".into())
    })?;
    Ok(model::ExecuteStatementInputTransformResponse {
        transformed_input: model::ExecuteStatementInput {
            statement: transformed.statement().unwrap_or_default().to_string(),
        },
    })
}

pub async fn batch_execute_statement_input_transform(
    state: &AppState,
    request: model::BatchExecuteStatementInputTransformRequest,
) -> Result<model::BatchExecuteStatementInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let mut sdk_statements = Vec::with_capacity(request.sdk_input.statements.len());
    for s in &request.sdk_input.statements {
        sdk_statements.push(
            SdkBatchStatementRequest::builder()
                .statement(&s.statement)
                .build()
                .map_err(|e| ServerError::Generic(format!("invalid BatchStatementRequest: {e}")))?,
        );
    }
    let sdk_input = SdkBatchExecuteStatementInput::builder()
        .set_statements(Some(sdk_statements))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid BatchExecuteStatementInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .batch_execute_statement_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_input.ok_or_else(|| {
        ServerError::Client(
            "BatchExecuteStatementInputTransform returned no transformed_input".into(),
        )
    })?;
    let statements = transformed
        .statements()
        .iter()
        .map(|s| model::BatchStatementRequest {
            statement: s.statement().to_string(),
        })
        .collect();
    Ok(model::BatchExecuteStatementInputTransformResponse {
        transformed_input: model::BatchExecuteStatementInput { statements },
    })
}

pub async fn execute_transaction_input_transform(
    state: &AppState,
    request: model::ExecuteTransactionInputTransformRequest,
) -> Result<model::ExecuteTransactionInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let mut sdk_statements = Vec::with_capacity(request.sdk_input.transact_statements.len());
    for s in &request.sdk_input.transact_statements {
        sdk_statements.push(
            SdkParameterizedStatement::builder()
                .statement(&s.statement)
                .build()
                .map_err(|e| ServerError::Generic(format!("invalid ParameterizedStatement: {e}")))?,
        );
    }
    let sdk_input = SdkExecuteTransactionInput::builder()
        .set_transact_statements(Some(sdk_statements))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid ExecuteTransactionInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .execute_transaction_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let transformed = output.transformed_input.ok_or_else(|| {
        ServerError::Client("ExecuteTransactionInputTransform returned no transformed_input".into())
    })?;
    let transact_statements = transformed
        .transact_statements()
        .iter()
        .map(|s| model::ParameterizedStatement {
            statement: s.statement().to_string(),
        })
        .collect();
    Ok(model::ExecuteTransactionInputTransformResponse {
        transformed_input: model::ExecuteTransactionInput {
            transact_statements,
        },
    })
}

pub async fn update_item_input_transform(
    state: &AppState,
    request: model::UpdateItemInputTransformRequest,
) -> Result<model::UpdateItemInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let wire = &request.sdk_input;
    let mut b = SdkUpdateItemInput::builder()
        .table_name(&wire.table_name)
        .set_key(Some(to_ddb_item(&wire.key)?));
    if let Some(e) = &wire.update_expression {
        b = b.update_expression(e);
    }
    if let Some(e) = &wire.condition_expression {
        b = b.condition_expression(e);
    }
    if let Some(names) = &wire.expression_attribute_names {
        if !names.is_empty() {
            b = b.set_expression_attribute_names(Some(names.clone()));
        }
    }
    if let Some(vals) = &wire.expression_attribute_values {
        if !vals.is_empty() {
            b = b.set_expression_attribute_values(Some(to_ddb_item(vals)?));
        }
    }
    let sdk_input = b
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid UpdateItemInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .update_item_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let t = output.transformed_input.ok_or_else(|| {
        ServerError::Client("UpdateItemInputTransform returned no transformed_input".into())
    })?;

    Ok(model::UpdateItemInputTransformResponse {
        transformed_input: model::UpdateItemInput {
            table_name: t.table_name().unwrap_or_default().to_string(),
            key: match t.key() {
                Some(m) => from_ddb_item(m)?,
                None => HashMap::new(),
            },
            update_expression: t.update_expression().map(String::from),
            condition_expression: t.condition_expression().map(String::from),
            expression_attribute_names: t.expression_attribute_names().cloned(),
            expression_attribute_values: match t.expression_attribute_values() {
                Some(m) => Some(from_ddb_item(m)?),
                None => None,
            },
        },
    })
}

pub async fn delete_item_input_transform(
    state: &AppState,
    request: model::DeleteItemInputTransformRequest,
) -> Result<model::DeleteItemInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let wire = &request.sdk_input;
    let mut b = SdkDeleteItemInput::builder()
        .table_name(&wire.table_name)
        .set_key(Some(to_ddb_item(&wire.key)?));
    if let Some(e) = &wire.condition_expression {
        b = b.condition_expression(e);
    }
    if let Some(names) = &wire.expression_attribute_names {
        if !names.is_empty() {
            b = b.set_expression_attribute_names(Some(names.clone()));
        }
    }
    if let Some(vals) = &wire.expression_attribute_values {
        if !vals.is_empty() {
            b = b.set_expression_attribute_values(Some(to_ddb_item(vals)?));
        }
    }
    let sdk_input = b
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid DeleteItemInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .delete_item_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let t = output.transformed_input.ok_or_else(|| {
        ServerError::Client("DeleteItemInputTransform returned no transformed_input".into())
    })?;

    Ok(model::DeleteItemInputTransformResponse {
        transformed_input: model::DeleteItemInput {
            table_name: t.table_name().unwrap_or_default().to_string(),
            key: match t.key() {
                Some(m) => from_ddb_item(m)?,
                None => HashMap::new(),
            },
            condition_expression: t.condition_expression().map(String::from),
            expression_attribute_names: t.expression_attribute_names().cloned(),
            expression_attribute_values: match t.expression_attribute_values() {
                Some(m) => Some(from_ddb_item(m)?),
                None => None,
            },
        },
    })
}

pub async fn scan_input_transform(
    state: &AppState,
    request: model::ScanInputTransformRequest,
) -> Result<model::ScanInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let wire = &request.sdk_input;
    let mut b = SdkScanInput::builder().table_name(&wire.table_name);
    if let Some(f) = &wire.filter_expression {
        b = b.filter_expression(f);
    }
    if let Some(names) = &wire.expression_attribute_names {
        if !names.is_empty() {
            b = b.set_expression_attribute_names(Some(names.clone()));
        }
    }
    if let Some(vals) = &wire.expression_attribute_values {
        if !vals.is_empty() {
            b = b.set_expression_attribute_values(Some(to_ddb_item(vals)?));
        }
    }
    let sdk_input = b
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid ScanInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .scan_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let t = output.transformed_input.ok_or_else(|| {
        ServerError::Client("ScanInputTransform returned no transformed_input".into())
    })?;

    Ok(model::ScanInputTransformResponse {
        transformed_input: model::ScanInput {
            table_name: t.table_name().unwrap_or_default().to_string(),
            filter_expression: t.filter_expression().map(String::from),
            expression_attribute_names: t.expression_attribute_names().cloned(),
            expression_attribute_values: match t.expression_attribute_values() {
                Some(m) => Some(from_ddb_item(m)?),
                None => None,
            },
        },
    })
}

pub async fn query_input_transform(
    state: &AppState,
    request: model::QueryInputTransformRequest,
) -> Result<model::QueryInputTransformResponse, ServerError> {
    let handle = state.registry.get_transforms(&request.client_id)?;
    let wire = &request.sdk_input;
    let mut b = SdkQueryInput::builder().table_name(&wire.table_name);
    if let Some(k) = &wire.key_condition_expression {
        b = b.key_condition_expression(k);
    }
    if let Some(f) = &wire.filter_expression {
        b = b.filter_expression(f);
    }
    if let Some(names) = &wire.expression_attribute_names {
        if !names.is_empty() {
            b = b.set_expression_attribute_names(Some(names.clone()));
        }
    }
    if let Some(vals) = &wire.expression_attribute_values {
        if !vals.is_empty() {
            b = b.set_expression_attribute_values(Some(to_ddb_item(vals)?));
        }
    }
    let sdk_input = b
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid QueryInput: {e}")))?;

    let _guard = handle.op_lock.lock().await;
    let output = handle
        .client
        .query_input_transform()
        .sdk_input(sdk_input)
        .send()
        .await
        .map_err(|e| ServerError::Client(e.to_string()))?;
    let t = output.transformed_input.ok_or_else(|| {
        ServerError::Client("QueryInputTransform returned no transformed_input".into())
    })?;

    Ok(model::QueryInputTransformResponse {
        transformed_input: model::QueryInput {
            table_name: t.table_name().unwrap_or_default().to_string(),
            key_condition_expression: t.key_condition_expression().map(String::from),
            filter_expression: t.filter_expression().map(String::from),
            expression_attribute_names: t.expression_attribute_names().cloned(),
            expression_attribute_values: match t.expression_attribute_values() {
                Some(m) => Some(from_ddb_item(m)?),
                None => None,
            },
        },
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
