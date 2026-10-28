// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The DDB-SDK transform operations.
//!
//! `CreateTransformsClient` builds the library's transforms from one or more table
//! configurations and registers them under a fresh UUID. Each transform operation maps
//! its wire shape onto the AWS SDK's DynamoDB type, runs the library's transform, and
//! maps the result back.

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::operation::{
    batch_get_item, batch_write_item, delete_item, get_item, put_item, query, scan,
    transact_get_items, transact_write_items, update_item,
};
use aws_db_esdk::aws_sdk_dynamodb::types as ddb;
use aws_db_esdk::transforms::Transforms;

use crate::error::ServerError;
use crate::handlers::{from_ddb_item, table_config, to_ddb_item, AppState};
use crate::model::DdbItem;
use crate::transforms_model::{
    AttributesOutput, BatchGetItemInput, BatchGetItemOutput, BatchWriteItemInput,
    BatchWriteItemOutput, ConditionCheck, CreateTransformsClientRequest,
    CreateTransformsClientResponse, Delete, DeleteItemInput, DeleteRequest, Get, GetItemInput,
    GetItemOutput, InputTransformRequest, InputTransformResponse, ItemResponse, ItemsOutput,
    KeysAndAttributes, OutputTransformRequest, OutputTransformResponse, Put, PutItemInput,
    PutRequest, QueryInput, ScanInput, TransactGetItem, TransactGetItemsInput,
    TransactGetItemsOutput, TransactWriteItem, TransactWriteItemsInput, TransactWriteItemsOutput,
    Update, UpdateItemInput, WriteRequest, WriteRequestMap,
};

/// A wire shape the AWS SDK's builder rejected.
fn build_err(e: impl std::fmt::Display) -> ServerError {
    ServerError::generic(format!("invalid DynamoDB request shape: {e}"))
}

fn opt_item(
    item: Option<DdbItem>,
) -> Result<Option<HashMap<String, ddb::AttributeValue>>, ServerError> {
    item.map(to_ddb_item).transpose()
}

fn opt_from_item(
    item: Option<HashMap<String, ddb::AttributeValue>>,
) -> Result<Option<DdbItem>, ServerError> {
    item.map(from_ddb_item).transpose()
}

fn to_put_item(i: PutItemInput) -> Result<put_item::PutItemInput, ServerError> {
    put_item::PutItemInput::builder()
        .table_name(i.table_name)
        .set_item(Some(to_ddb_item(i.item)?))
        .build()
        .map_err(build_err)
}

fn from_put_item(i: put_item::PutItemInput) -> Result<PutItemInput, ServerError> {
    Ok(PutItemInput {
        table_name: i.table_name.unwrap_or_default(),
        item: from_ddb_item(i.item.unwrap_or_default())?,
    })
}

fn to_get_item(i: GetItemInput) -> Result<get_item::GetItemInput, ServerError> {
    get_item::GetItemInput::builder()
        .table_name(i.table_name)
        .set_key(Some(to_ddb_item(i.key)?))
        .build()
        .map_err(build_err)
}

fn from_get_item(i: get_item::GetItemInput) -> Result<GetItemInput, ServerError> {
    Ok(GetItemInput {
        table_name: i.table_name.unwrap_or_default(),
        key: from_ddb_item(i.key.unwrap_or_default())?,
    })
}

fn to_update_item(i: UpdateItemInput) -> Result<update_item::UpdateItemInput, ServerError> {
    update_item::UpdateItemInput::builder()
        .table_name(i.table_name)
        .set_key(Some(to_ddb_item(i.key)?))
        .set_update_expression(i.update_expression)
        .set_condition_expression(i.condition_expression)
        .set_expression_attribute_names(i.expression_attribute_names)
        .set_expression_attribute_values(opt_item(i.expression_attribute_values)?)
        .build()
        .map_err(build_err)
}

fn from_update_item(i: update_item::UpdateItemInput) -> Result<UpdateItemInput, ServerError> {
    Ok(UpdateItemInput {
        table_name: i.table_name.unwrap_or_default(),
        key: from_ddb_item(i.key.unwrap_or_default())?,
        update_expression: i.update_expression,
        condition_expression: i.condition_expression,
        expression_attribute_names: i.expression_attribute_names,
        expression_attribute_values: opt_from_item(i.expression_attribute_values)?,
    })
}

fn to_delete_item(i: DeleteItemInput) -> Result<delete_item::DeleteItemInput, ServerError> {
    delete_item::DeleteItemInput::builder()
        .table_name(i.table_name)
        .set_key(Some(to_ddb_item(i.key)?))
        .set_condition_expression(i.condition_expression)
        .set_expression_attribute_names(i.expression_attribute_names)
        .set_expression_attribute_values(opt_item(i.expression_attribute_values)?)
        .build()
        .map_err(build_err)
}

fn from_delete_item(i: delete_item::DeleteItemInput) -> Result<DeleteItemInput, ServerError> {
    Ok(DeleteItemInput {
        table_name: i.table_name.unwrap_or_default(),
        key: from_ddb_item(i.key.unwrap_or_default())?,
        condition_expression: i.condition_expression,
        expression_attribute_names: i.expression_attribute_names,
        expression_attribute_values: opt_from_item(i.expression_attribute_values)?,
    })
}

fn to_write_request(r: WriteRequest) -> Result<ddb::WriteRequest, ServerError> {
    let put = r
        .put_request
        .map(|p| {
            ddb::PutRequest::builder()
                .set_item(Some(to_ddb_item(p.item)?))
                .build()
                .map_err(build_err)
        })
        .transpose()?;
    let delete = r
        .delete_request
        .map(|d| {
            ddb::DeleteRequest::builder()
                .set_key(Some(to_ddb_item(d.key)?))
                .build()
                .map_err(build_err)
        })
        .transpose()?;
    Ok(ddb::WriteRequest::builder()
        .set_put_request(put)
        .set_delete_request(delete)
        .build())
}

fn from_write_request(r: ddb::WriteRequest) -> Result<WriteRequest, ServerError> {
    Ok(WriteRequest {
        put_request: r
            .put_request
            .map(|p| {
                Ok::<_, ServerError>(PutRequest {
                    item: from_ddb_item(p.item)?,
                })
            })
            .transpose()?,
        delete_request: r
            .delete_request
            .map(|d| {
                Ok::<_, ServerError>(DeleteRequest {
                    key: from_ddb_item(d.key)?,
                })
            })
            .transpose()?,
    })
}

fn to_write_map(
    m: WriteRequestMap,
) -> Result<HashMap<String, Vec<ddb::WriteRequest>>, ServerError> {
    m.into_iter()
        .map(|(t, reqs)| {
            Ok((
                t,
                reqs.into_iter()
                    .map(to_write_request)
                    .collect::<Result<_, _>>()?,
            ))
        })
        .collect()
}

fn from_write_map(
    m: HashMap<String, Vec<ddb::WriteRequest>>,
) -> Result<WriteRequestMap, ServerError> {
    m.into_iter()
        .map(|(t, reqs)| {
            Ok((
                t,
                reqs.into_iter()
                    .map(from_write_request)
                    .collect::<Result<_, _>>()?,
            ))
        })
        .collect()
}

fn to_batch_write(
    i: BatchWriteItemInput,
) -> Result<batch_write_item::BatchWriteItemInput, ServerError> {
    batch_write_item::BatchWriteItemInput::builder()
        .set_request_items(Some(to_write_map(i.request_items)?))
        .build()
        .map_err(build_err)
}

fn from_batch_write(
    i: batch_write_item::BatchWriteItemInput,
) -> Result<BatchWriteItemInput, ServerError> {
    Ok(BatchWriteItemInput {
        request_items: from_write_map(i.request_items.unwrap_or_default())?,
    })
}

fn to_transact_item(t: TransactWriteItem) -> Result<ddb::TransactWriteItem, ServerError> {
    let put = t
        .put
        .map(|p| {
            ddb::Put::builder()
                .table_name(p.table_name)
                .set_item(Some(to_ddb_item(p.item)?))
                .build()
                .map_err(build_err)
        })
        .transpose()?;
    let delete = t
        .delete
        .map(|d| {
            ddb::Delete::builder()
                .table_name(d.table_name)
                .set_key(Some(to_ddb_item(d.key)?))
                .set_condition_expression(d.condition_expression)
                .set_expression_attribute_names(d.expression_attribute_names)
                .set_expression_attribute_values(opt_item(d.expression_attribute_values)?)
                .build()
                .map_err(build_err)
        })
        .transpose()?;
    let update = t
        .update
        .map(|u| {
            ddb::Update::builder()
                .table_name(u.table_name)
                .set_key(Some(to_ddb_item(u.key)?))
                .update_expression(u.update_expression)
                .set_condition_expression(u.condition_expression)
                .set_expression_attribute_names(u.expression_attribute_names)
                .set_expression_attribute_values(opt_item(u.expression_attribute_values)?)
                .build()
                .map_err(build_err)
        })
        .transpose()?;
    let condition_check = t
        .condition_check
        .map(|c| {
            ddb::ConditionCheck::builder()
                .table_name(c.table_name)
                .set_key(Some(to_ddb_item(c.key)?))
                .condition_expression(c.condition_expression)
                .set_expression_attribute_names(c.expression_attribute_names)
                .set_expression_attribute_values(opt_item(c.expression_attribute_values)?)
                .build()
                .map_err(build_err)
        })
        .transpose()?;
    Ok(ddb::TransactWriteItem::builder()
        .set_put(put)
        .set_delete(delete)
        .set_update(update)
        .set_condition_check(condition_check)
        .build())
}

fn from_transact_item(t: ddb::TransactWriteItem) -> Result<TransactWriteItem, ServerError> {
    Ok(TransactWriteItem {
        put: t
            .put
            .map(|p| {
                Ok::<_, ServerError>(Put {
                    table_name: p.table_name,
                    item: from_ddb_item(p.item)?,
                })
            })
            .transpose()?,
        delete: t
            .delete
            .map(|d| {
                Ok::<_, ServerError>(Delete {
                    table_name: d.table_name,
                    key: from_ddb_item(d.key)?,
                    condition_expression: d.condition_expression,
                    expression_attribute_names: d.expression_attribute_names,
                    expression_attribute_values: opt_from_item(d.expression_attribute_values)?,
                })
            })
            .transpose()?,
        update: t
            .update
            .map(|u| {
                Ok::<_, ServerError>(Update {
                    table_name: u.table_name,
                    key: from_ddb_item(u.key)?,
                    update_expression: u.update_expression,
                    condition_expression: u.condition_expression,
                    expression_attribute_names: u.expression_attribute_names,
                    expression_attribute_values: opt_from_item(u.expression_attribute_values)?,
                })
            })
            .transpose()?,
        condition_check: t
            .condition_check
            .map(|c| {
                Ok::<_, ServerError>(ConditionCheck {
                    table_name: c.table_name,
                    key: from_ddb_item(c.key)?,
                    condition_expression: c.condition_expression,
                    expression_attribute_names: c.expression_attribute_names,
                    expression_attribute_values: opt_from_item(c.expression_attribute_values)?,
                })
            })
            .transpose()?,
    })
}

fn to_transact_write(
    i: TransactWriteItemsInput,
) -> Result<transact_write_items::TransactWriteItemsInput, ServerError> {
    transact_write_items::TransactWriteItemsInput::builder()
        .set_transact_items(Some(
            i.transact_items
                .into_iter()
                .map(to_transact_item)
                .collect::<Result<_, _>>()?,
        ))
        .build()
        .map_err(build_err)
}

fn from_transact_write(
    i: transact_write_items::TransactWriteItemsInput,
) -> Result<TransactWriteItemsInput, ServerError> {
    Ok(TransactWriteItemsInput {
        transact_items: i
            .transact_items
            .unwrap_or_default()
            .into_iter()
            .map(from_transact_item)
            .collect::<Result<_, _>>()?,
    })
}

fn to_items(
    items: Option<Vec<DdbItem>>,
) -> Result<Option<Vec<HashMap<String, ddb::AttributeValue>>>, ServerError> {
    items
        .map(|v| v.into_iter().map(to_ddb_item).collect::<Result<_, _>>())
        .transpose()
}

fn from_items(
    items: Option<Vec<HashMap<String, ddb::AttributeValue>>>,
) -> Result<Option<Vec<DdbItem>>, ServerError> {
    items
        .map(|v| v.into_iter().map(from_ddb_item).collect::<Result<_, _>>())
        .transpose()
}

fn to_scan(i: ScanInput) -> Result<scan::ScanInput, ServerError> {
    scan::ScanInput::builder()
        .table_name(i.table_name)
        .set_filter_expression(i.filter_expression)
        .set_expression_attribute_names(i.expression_attribute_names)
        .set_expression_attribute_values(opt_item(i.expression_attribute_values)?)
        .build()
        .map_err(build_err)
}

fn from_scan(i: scan::ScanInput) -> Result<ScanInput, ServerError> {
    Ok(ScanInput {
        table_name: i.table_name.unwrap_or_default(),
        filter_expression: i.filter_expression,
        expression_attribute_names: i.expression_attribute_names,
        expression_attribute_values: opt_from_item(i.expression_attribute_values)?,
    })
}

fn to_query(i: QueryInput) -> Result<query::QueryInput, ServerError> {
    query::QueryInput::builder()
        .table_name(i.table_name)
        .set_key_condition_expression(i.key_condition_expression)
        .set_filter_expression(i.filter_expression)
        .set_expression_attribute_names(i.expression_attribute_names)
        .set_expression_attribute_values(opt_item(i.expression_attribute_values)?)
        .build()
        .map_err(build_err)
}

fn from_query(i: query::QueryInput) -> Result<QueryInput, ServerError> {
    Ok(QueryInput {
        table_name: i.table_name.unwrap_or_default(),
        key_condition_expression: i.key_condition_expression,
        filter_expression: i.filter_expression,
        expression_attribute_names: i.expression_attribute_names,
        expression_attribute_values: opt_from_item(i.expression_attribute_values)?,
    })
}

fn to_batch_get(i: BatchGetItemInput) -> Result<batch_get_item::BatchGetItemInput, ServerError> {
    let request_items = i
        .request_items
        .into_iter()
        .map(|(t, k)| {
            let keys = to_items(Some(k.keys))?;
            let ka = ddb::KeysAndAttributes::builder()
                .set_keys(keys)
                .build()
                .map_err(build_err)?;
            Ok((t, ka))
        })
        .collect::<Result<HashMap<_, _>, ServerError>>()?;
    batch_get_item::BatchGetItemInput::builder()
        .set_request_items(Some(request_items))
        .build()
        .map_err(build_err)
}

fn from_batch_get(i: batch_get_item::BatchGetItemInput) -> Result<BatchGetItemInput, ServerError> {
    Ok(BatchGetItemInput {
        request_items: i
            .request_items
            .unwrap_or_default()
            .into_iter()
            .map(|(t, k)| {
                Ok((
                    t,
                    KeysAndAttributes {
                        keys: from_items(Some(k.keys))?.unwrap_or_default(),
                    },
                ))
            })
            .collect::<Result<_, ServerError>>()?,
    })
}

fn to_transact_get(
    i: TransactGetItemsInput,
) -> Result<transact_get_items::TransactGetItemsInput, ServerError> {
    let items = i
        .transact_items
        .into_iter()
        .map(|t| {
            let get = ddb::Get::builder()
                .table_name(t.get.table_name)
                .set_key(Some(to_ddb_item(t.get.key)?))
                .build()
                .map_err(build_err)?;
            Ok(ddb::TransactGetItem::builder().get(get).build())
        })
        .collect::<Result<Vec<_>, ServerError>>()?;
    transact_get_items::TransactGetItemsInput::builder()
        .set_transact_items(Some(items))
        .build()
        .map_err(build_err)
}

fn from_transact_get(
    i: transact_get_items::TransactGetItemsInput,
) -> Result<TransactGetItemsInput, ServerError> {
    Ok(TransactGetItemsInput {
        transact_items: i
            .transact_items
            .unwrap_or_default()
            .into_iter()
            .filter_map(|t| t.get)
            .map(|g| {
                Ok(TransactGetItem {
                    get: Get {
                        table_name: g.table_name,
                        key: from_ddb_item(g.key)?,
                    },
                })
            })
            .collect::<Result<_, ServerError>>()?,
    })
}

impl AppState {
    /// Build and register transforms over the request's tables; returns their new id.
    pub async fn create_transforms_client(
        &self,
        req: CreateTransformsClientRequest,
    ) -> Result<CreateTransformsClientResponse, ServerError> {
        let mut builder = Transforms::builder()
            .table_encryption_configs(req.table_name, table_config(req.config).await?);
        for extra in req.additional_tables.unwrap_or_default() {
            builder = builder
                .table_encryption_configs(extra.table_name, table_config(extra.config).await?);
        }
        let transforms = builder.build()?;
        let client_id = uuid::Uuid::new_v4().to_string();
        self.transforms_clients
            .lock()
            .expect("registry mutex")
            .insert(client_id.clone(), transforms);
        Ok(CreateTransformsClientResponse { client_id })
    }

    /// Look up registered transforms by id.
    fn transforms(&self, client_id: &str) -> Result<Transforms, ServerError> {
        if client_id.is_empty() {
            return Err(ServerError::generic("clientId must be non-empty"));
        }
        self.transforms_clients
            .lock()
            .expect("registry mutex")
            .get(client_id)
            .cloned()
            .ok_or_else(|| ServerError::generic(format!("unknown clientId: {client_id}")))
    }

    pub async fn put_item_input_transform(
        &self,
        req: InputTransformRequest<PutItemInput>,
    ) -> Result<InputTransformResponse<PutItemInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t.put_item_input(to_put_item(req.sdk_input)?).await?;
        Ok(InputTransformResponse {
            transformed_input: from_put_item(out)?,
        })
    }

    pub async fn put_item_output_transform(
        &self,
        req: OutputTransformRequest<AttributesOutput, PutItemInput>,
    ) -> Result<OutputTransformResponse<AttributesOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let output = put_item::PutItemOutput::builder()
            .set_attributes(opt_item(req.sdk_output.attributes)?)
            .build();
        let out = t
            .put_item_output(output, &to_put_item(req.original_input)?)
            .await?;
        Ok(OutputTransformResponse {
            transformed_output: AttributesOutput {
                attributes: opt_from_item(out.attributes)?,
            },
        })
    }

    pub async fn get_item_input_transform(
        &self,
        req: InputTransformRequest<GetItemInput>,
    ) -> Result<InputTransformResponse<GetItemInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t.get_item_input(to_get_item(req.sdk_input)?).await?;
        Ok(InputTransformResponse {
            transformed_input: from_get_item(out)?,
        })
    }

    pub async fn get_item_output_transform(
        &self,
        req: OutputTransformRequest<GetItemOutput, GetItemInput>,
    ) -> Result<OutputTransformResponse<GetItemOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let output = get_item::GetItemOutput::builder()
            .set_item(opt_item(req.sdk_output.item)?)
            .build();
        let out = t
            .get_item_output(output, &to_get_item(req.original_input)?)
            .await?;
        Ok(OutputTransformResponse {
            transformed_output: GetItemOutput {
                item: opt_from_item(out.item)?,
            },
        })
    }

    pub async fn update_item_input_transform(
        &self,
        req: InputTransformRequest<UpdateItemInput>,
    ) -> Result<InputTransformResponse<UpdateItemInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t.update_item_input(to_update_item(req.sdk_input)?).await?;
        Ok(InputTransformResponse {
            transformed_input: from_update_item(out)?,
        })
    }

    pub async fn update_item_output_transform(
        &self,
        req: OutputTransformRequest<AttributesOutput, UpdateItemInput>,
    ) -> Result<OutputTransformResponse<AttributesOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let output = update_item::UpdateItemOutput::builder()
            .set_attributes(opt_item(req.sdk_output.attributes)?)
            .build();
        let out = t
            .update_item_output(output, &to_update_item(req.original_input)?)
            .await?;
        Ok(OutputTransformResponse {
            transformed_output: AttributesOutput {
                attributes: opt_from_item(out.attributes)?,
            },
        })
    }

    pub async fn delete_item_input_transform(
        &self,
        req: InputTransformRequest<DeleteItemInput>,
    ) -> Result<InputTransformResponse<DeleteItemInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t.delete_item_input(to_delete_item(req.sdk_input)?).await?;
        Ok(InputTransformResponse {
            transformed_input: from_delete_item(out)?,
        })
    }

    pub async fn delete_item_output_transform(
        &self,
        req: OutputTransformRequest<AttributesOutput, DeleteItemInput>,
    ) -> Result<OutputTransformResponse<AttributesOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let output = delete_item::DeleteItemOutput::builder()
            .set_attributes(opt_item(req.sdk_output.attributes)?)
            .build();
        let out = t
            .delete_item_output(output, &to_delete_item(req.original_input)?)
            .await?;
        Ok(OutputTransformResponse {
            transformed_output: AttributesOutput {
                attributes: opt_from_item(out.attributes)?,
            },
        })
    }

    pub async fn batch_write_item_input_transform(
        &self,
        req: InputTransformRequest<BatchWriteItemInput>,
    ) -> Result<InputTransformResponse<BatchWriteItemInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t
            .batch_write_item_input(to_batch_write(req.sdk_input)?)
            .await?;
        Ok(InputTransformResponse {
            transformed_input: from_batch_write(out)?,
        })
    }

    pub async fn batch_write_item_output_transform(
        &self,
        req: OutputTransformRequest<BatchWriteItemOutput, BatchWriteItemInput>,
    ) -> Result<OutputTransformResponse<BatchWriteItemOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let output = batch_write_item::BatchWriteItemOutput::builder()
            .set_unprocessed_items(
                req.sdk_output
                    .unprocessed_items
                    .map(to_write_map)
                    .transpose()?,
            )
            .build();
        let out = t
            .batch_write_item_output(output, &to_batch_write(req.original_input)?)
            .await?;
        Ok(OutputTransformResponse {
            transformed_output: BatchWriteItemOutput {
                unprocessed_items: out.unprocessed_items.map(from_write_map).transpose()?,
            },
        })
    }

    pub async fn transact_write_items_input_transform(
        &self,
        req: InputTransformRequest<TransactWriteItemsInput>,
    ) -> Result<InputTransformResponse<TransactWriteItemsInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t
            .transact_write_items_input(to_transact_write(req.sdk_input)?)
            .await?;
        Ok(InputTransformResponse {
            transformed_input: from_transact_write(out)?,
        })
    }

    pub async fn transact_write_items_output_transform(
        &self,
        req: OutputTransformRequest<TransactWriteItemsOutput, TransactWriteItemsInput>,
    ) -> Result<OutputTransformResponse<TransactWriteItemsOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let output = transact_write_items::TransactWriteItemsOutput::builder().build();
        t.transact_write_items_output(output, &to_transact_write(req.original_input)?)
            .await?;
        Ok(OutputTransformResponse {
            transformed_output: TransactWriteItemsOutput {},
        })
    }

    pub async fn scan_input_transform(
        &self,
        req: InputTransformRequest<ScanInput>,
    ) -> Result<InputTransformResponse<ScanInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t.scan_input(to_scan(req.sdk_input)?).await?;
        Ok(InputTransformResponse {
            transformed_input: from_scan(out)?,
        })
    }

    pub async fn scan_output_transform(
        &self,
        req: OutputTransformRequest<ItemsOutput, ScanInput>,
    ) -> Result<OutputTransformResponse<ItemsOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let output = scan::ScanOutput::builder()
            .set_items(to_items(req.sdk_output.items)?)
            .build();
        let out = t.scan_output(output, &to_scan(req.original_input)?).await?;
        Ok(OutputTransformResponse {
            transformed_output: ItemsOutput {
                items: from_items(out.items)?,
            },
        })
    }

    pub async fn query_input_transform(
        &self,
        req: InputTransformRequest<QueryInput>,
    ) -> Result<InputTransformResponse<QueryInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t.query_input(to_query(req.sdk_input)?).await?;
        Ok(InputTransformResponse {
            transformed_input: from_query(out)?,
        })
    }

    pub async fn query_output_transform(
        &self,
        req: OutputTransformRequest<ItemsOutput, QueryInput>,
    ) -> Result<OutputTransformResponse<ItemsOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let output = query::QueryOutput::builder()
            .set_items(to_items(req.sdk_output.items)?)
            .build();
        let out = t
            .query_output(output, &to_query(req.original_input)?)
            .await?;
        Ok(OutputTransformResponse {
            transformed_output: ItemsOutput {
                items: from_items(out.items)?,
            },
        })
    }

    pub async fn batch_get_item_input_transform(
        &self,
        req: InputTransformRequest<BatchGetItemInput>,
    ) -> Result<InputTransformResponse<BatchGetItemInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t.batch_get_item_input(to_batch_get(req.sdk_input)?).await?;
        Ok(InputTransformResponse {
            transformed_input: from_batch_get(out)?,
        })
    }

    pub async fn batch_get_item_output_transform(
        &self,
        req: OutputTransformRequest<BatchGetItemOutput, BatchGetItemInput>,
    ) -> Result<OutputTransformResponse<BatchGetItemOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let responses = req
            .sdk_output
            .responses
            .map(|m| {
                m.into_iter()
                    .map(|(k, v)| Ok((k, to_items(Some(v))?.unwrap_or_default())))
                    .collect::<Result<HashMap<_, _>, ServerError>>()
            })
            .transpose()?;
        let output = batch_get_item::BatchGetItemOutput::builder()
            .set_responses(responses)
            .build();
        let out = t
            .batch_get_item_output(output, &to_batch_get(req.original_input)?)
            .await?;
        let responses = out
            .responses
            .map(|m| {
                m.into_iter()
                    .map(|(k, v)| Ok((k, from_items(Some(v))?.unwrap_or_default())))
                    .collect::<Result<HashMap<_, _>, ServerError>>()
            })
            .transpose()?;
        Ok(OutputTransformResponse {
            transformed_output: BatchGetItemOutput { responses },
        })
    }

    pub async fn transact_get_items_input_transform(
        &self,
        req: InputTransformRequest<TransactGetItemsInput>,
    ) -> Result<InputTransformResponse<TransactGetItemsInput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let out = t
            .transact_get_items_input(to_transact_get(req.sdk_input)?)
            .await?;
        Ok(InputTransformResponse {
            transformed_input: from_transact_get(out)?,
        })
    }

    pub async fn transact_get_items_output_transform(
        &self,
        req: OutputTransformRequest<TransactGetItemsOutput, TransactGetItemsInput>,
    ) -> Result<OutputTransformResponse<TransactGetItemsOutput>, ServerError> {
        let t = self.transforms(&req.client_id)?;
        let responses = req
            .sdk_output
            .responses
            .map(|v| {
                v.into_iter()
                    .map(|r| {
                        Ok(ddb::ItemResponse::builder()
                            .set_item(opt_item(r.item)?)
                            .build())
                    })
                    .collect::<Result<Vec<_>, ServerError>>()
            })
            .transpose()?;
        let output = transact_get_items::TransactGetItemsOutput::builder()
            .set_responses(responses)
            .build();
        let out = t
            .transact_get_items_output(output, &to_transact_get(req.original_input)?)
            .await?;
        let responses = out
            .responses
            .map(|v| {
                v.into_iter()
                    .map(|r| {
                        Ok(ItemResponse {
                            item: opt_from_item(r.item)?,
                        })
                    })
                    .collect::<Result<Vec<_>, ServerError>>()
            })
            .transpose()?;
        Ok(OutputTransformResponse {
            transformed_output: TransactGetItemsOutput { responses },
        })
    }
}
