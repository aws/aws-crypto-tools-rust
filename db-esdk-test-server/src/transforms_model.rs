// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The wire shapes of the DDB-SDK transform operations: the transforms client, and the
//! minimal DynamoDB request and response shapes the model carries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::model::{DbeClientConfig, DdbItem};

/// An expression attribute name map: `#placeholder` to attribute name.
pub type ExpressionAttributeNameMap = HashMap<String, String>;

#[derive(Debug, Deserialize)]
pub struct CreateTransformsClientRequest {
    pub config: DbeClientConfig,
    #[serde(rename = "tableName")]
    pub table_name: String,
    #[serde(rename = "additionalTables", default)]
    pub additional_tables: Option<Vec<TransformsTableConfig>>,
}

#[derive(Debug, Deserialize)]
pub struct TransformsTableConfig {
    #[serde(rename = "tableName")]
    pub table_name: String,
    pub config: DbeClientConfig,
}

#[derive(Debug, Serialize)]
pub struct CreateTransformsClientResponse {
    #[serde(rename = "clientId")]
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutItemInput {
    #[serde(rename = "tableName")]
    pub table_name: String,
    pub item: DdbItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetItemInput {
    #[serde(rename = "tableName")]
    pub table_name: String,
    pub key: DdbItem,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetItemOutput {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub item: Option<DdbItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateItemInput {
    #[serde(rename = "tableName")]
    pub table_name: String,
    pub key: DdbItem,
    #[serde(
        rename = "updateExpression",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub update_expression: Option<String>,
    #[serde(
        rename = "conditionExpression",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub condition_expression: Option<String>,
    #[serde(
        rename = "expressionAttributeNames",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_names: Option<ExpressionAttributeNameMap>,
    #[serde(
        rename = "expressionAttributeValues",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_values: Option<DdbItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteItemInput {
    #[serde(rename = "tableName")]
    pub table_name: String,
    pub key: DdbItem,
    #[serde(
        rename = "conditionExpression",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub condition_expression: Option<String>,
    #[serde(
        rename = "expressionAttributeNames",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_names: Option<ExpressionAttributeNameMap>,
    #[serde(
        rename = "expressionAttributeValues",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_values: Option<DdbItem>,
}

/// Table name to that table's write requests.
pub type WriteRequestMap = HashMap<String, Vec<WriteRequest>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchWriteItemInput {
    #[serde(rename = "requestItems")]
    pub request_items: WriteRequestMap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    #[serde(
        rename = "putRequest",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub put_request: Option<PutRequest>,
    #[serde(
        rename = "deleteRequest",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub delete_request: Option<DeleteRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutRequest {
    pub item: DdbItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub key: DdbItem,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BatchWriteItemOutput {
    #[serde(
        rename = "unprocessedItems",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub unprocessed_items: Option<WriteRequestMap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactWriteItemsInput {
    #[serde(rename = "transactItems")]
    pub transact_items: Vec<TransactWriteItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransactWriteItem {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub put: Option<Put>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delete: Option<Delete>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub update: Option<Update>,
    #[serde(
        rename = "conditionCheck",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub condition_check: Option<ConditionCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Put {
    #[serde(rename = "tableName")]
    pub table_name: String,
    pub item: DdbItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delete {
    #[serde(rename = "tableName")]
    pub table_name: String,
    pub key: DdbItem,
    #[serde(
        rename = "conditionExpression",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub condition_expression: Option<String>,
    #[serde(
        rename = "expressionAttributeNames",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_names: Option<ExpressionAttributeNameMap>,
    #[serde(
        rename = "expressionAttributeValues",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_values: Option<DdbItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Update {
    #[serde(rename = "tableName")]
    pub table_name: String,
    pub key: DdbItem,
    #[serde(rename = "updateExpression")]
    pub update_expression: String,
    #[serde(
        rename = "conditionExpression",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub condition_expression: Option<String>,
    #[serde(
        rename = "expressionAttributeNames",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_names: Option<ExpressionAttributeNameMap>,
    #[serde(
        rename = "expressionAttributeValues",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_values: Option<DdbItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionCheck {
    #[serde(rename = "tableName")]
    pub table_name: String,
    pub key: DdbItem,
    #[serde(rename = "conditionExpression")]
    pub condition_expression: String,
    #[serde(
        rename = "expressionAttributeNames",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_names: Option<ExpressionAttributeNameMap>,
    #[serde(
        rename = "expressionAttributeValues",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expression_attribute_values: Option<DdbItem>,
}

/// The attributes a PutItem, UpdateItem, or DeleteItem response returns, if any.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributesOutput {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attributes: Option<DdbItem>,
}

/// TransactWriteItems returns no item content.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransactWriteItemsOutput {}

/// An input transform's request: the client and the SDK input.
#[derive(Debug, Deserialize)]
pub struct InputTransformRequest<I> {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "sdkInput")]
    pub sdk_input: I,
}

/// An input transform's response: the transformed SDK input.
#[derive(Debug, Serialize)]
pub struct InputTransformResponse<I> {
    #[serde(rename = "transformedInput")]
    pub transformed_input: I,
}

/// An output transform's request: the client, the SDK output, and the input that produced it.
#[derive(Debug, Deserialize)]
pub struct OutputTransformRequest<O, I> {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "sdkOutput")]
    pub sdk_output: O,
    #[serde(rename = "originalInput")]
    pub original_input: I,
}

/// An output transform's response: the transformed SDK output.
#[derive(Debug, Serialize)]
pub struct OutputTransformResponse<O> {
    #[serde(rename = "transformedOutput")]
    pub transformed_output: O,
}
