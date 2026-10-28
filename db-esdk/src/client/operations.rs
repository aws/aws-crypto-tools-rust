// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The fluent builders of [`Client`](super::Client)'s operations.
//!
//! Each wraps the AWS SDK's fluent builder of the same name and has the same setters.
//! Its `send` runs the operation's input transform, sends the transformed request,
//! and runs the output transform on the response.

use std::collections::HashMap;

use aws_crypto_mpl::aws_sdk_dynamodb::operation::{
    batch_execute_statement, batch_get_item, batch_write_item, delete_item, execute_statement,
    execute_transaction, get_item, put_item, query, scan, transact_get_items, transact_write_items,
    update_item,
};
use aws_crypto_mpl::aws_sdk_dynamodb::types::{
    AttributeValue, AttributeValueUpdate, BatchStatementRequest, Condition, ConditionalOperator,
    ExpectedAttributeValue, KeysAndAttributes, ParameterizedStatement, ReturnConsumedCapacity,
    ReturnItemCollectionMetrics, ReturnValue, ReturnValuesOnConditionCheckFailure, Select,
    TransactGetItem, TransactWriteItem, WriteRequest,
};

use super::build_error;
use crate::error::Error;
use crate::transforms::{
    ResolveAttributesInput, ResolveAttributesInputBuilder, ResolveAttributesOutput, Transforms,
};

/// One setter, its `set_` form, and its getter, forwarded to the AWS SDK's fluent builder.
macro_rules! setter {
    (value $field:ident, $set:ident, $get:ident: $ty:ty) => {
        #[doc = concat!("Set `", stringify!($field), "`, as on the AWS SDK's fluent builder.")]
        #[must_use]
        pub fn $field(mut self, input: impl Into<$ty>) -> Self {
            self.inner = self.inner.$field(input.into());
            self
        }

        #[doc = concat!("Set or clear `", stringify!($field), "`.")]
        #[must_use]
        pub fn $set(mut self, input: Option<$ty>) -> Self {
            self.inner = self.inner.$set(input);
            self
        }

        #[doc = concat!("The `", stringify!($field), "` set so far.")]
        #[must_use]
        pub fn $get(&self) -> &Option<$ty> {
            self.inner.$get()
        }
    };
    (map $field:ident, $set:ident, $get:ident: $ty:ty) => {
        #[doc = concat!("Add one entry to `", stringify!($field), "`, as on the AWS SDK's fluent builder.")]
        #[must_use]
        pub fn $field(mut self, key: impl Into<String>, value: impl Into<$ty>) -> Self {
            self.inner = self.inner.$field(key.into(), value.into());
            self
        }

        #[doc = concat!("Replace or clear the whole `", stringify!($field), "` map.")]
        #[must_use]
        pub fn $set(mut self, input: Option<HashMap<String, $ty>>) -> Self {
            self.inner = self.inner.$set(input);
            self
        }

        #[doc = concat!("The `", stringify!($field), "` map set so far.")]
        #[must_use]
        pub fn $get(&self) -> &Option<HashMap<String, $ty>> {
            self.inner.$get()
        }
    };
    (list $field:ident, $set:ident, $get:ident: $ty:ty) => {
        #[doc = concat!("Add one element to `", stringify!($field), "`, as on the AWS SDK's fluent builder.")]
        #[must_use]
        pub fn $field(mut self, input: impl Into<$ty>) -> Self {
            self.inner = self.inner.$field(input.into());
            self
        }

        #[doc = concat!("Replace or clear the whole `", stringify!($field), "` list.")]
        #[must_use]
        pub fn $set(mut self, input: Option<Vec<$ty>>) -> Self {
            self.inner = self.inner.$set(input);
            self
        }

        #[doc = concat!("The `", stringify!($field), "` list set so far.")]
        #[must_use]
        pub fn $get(&self) -> &Option<Vec<$ty>> {
            self.inner.$get()
        }
    };
}

/// A fluent builder wrapping the AWS SDK's, with every member's setters,
/// and `with_input`, which sets every member from a whole input.
macro_rules! fluent_builder {
    (
        $(#[$doc:meta])*
        $name:ident($sdk:ty, $input:ty) {
            $($kind:ident $field:ident, $set:ident, $get:ident: $ty:ty;)*
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone, Debug)]
        #[non_exhaustive]
        pub struct $name {
            inner: $sdk,
            transforms: Transforms,
        }

        impl $name {
            pub(super) const fn new(inner: $sdk, transforms: Transforms) -> Self {
                Self { inner, transforms }
            }

            $(setter!($kind $field, $set, $get: $ty);)*

            /// The AWS SDK builder with every member set from `input`.
            fn with_input(inner: $sdk, input: $input) -> $sdk {
                inner$(.$set(input.$field))*
            }
        }
    };
}

fluent_builder! {
    /// The PutItem operation. Set the request, then call [`send`](Self::send).
    PutItemFluentBuilder(put_item::builders::PutItemFluentBuilder, put_item::PutItemInput) {
        value table_name, set_table_name, get_table_name: String;
        map item, set_item, get_item: AttributeValue;
        map expected, set_expected, get_expected: ExpectedAttributeValue;
        value return_values, set_return_values, get_return_values: ReturnValue;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
        value return_item_collection_metrics, set_return_item_collection_metrics, get_return_item_collection_metrics: ReturnItemCollectionMetrics;
        value conditional_operator, set_conditional_operator, get_conditional_operator: ConditionalOperator;
        value condition_expression, set_condition_expression, get_condition_expression: String;
        map expression_attribute_names, set_expression_attribute_names, get_expression_attribute_names: String;
        map expression_attribute_values, set_expression_attribute_values, get_expression_attribute_values: AttributeValue;
        value return_values_on_condition_check_failure, set_return_values_on_condition_check_failure, get_return_values_on_condition_check_failure: ReturnValuesOnConditionCheckFailure;
    }
}

impl PutItemFluentBuilder {
    /// Encrypt and sign the item when its table is configured, then write it.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the request is invalid for an encrypted table,
    /// for example a condition expression that reads an encrypted attribute,
    /// or, with a multi key store, a beacon key field that names a different branch key
    /// than the one that encrypted the item.
    /// Encryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<put_item::PutItemOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
        //# If any of the above fails,
        //# the client MUST NOT make a network call to DynamoDB,
        //# and PutItem MUST yield an error.
        let transformed = self.transforms.put_item_input(input.clone()).await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("PutItem", input.table_name.as_deref(), e))?;
        self.transforms.put_item_output(output, &input).await
    }
}

fluent_builder! {
    /// The GetItem operation. Set the request, then call [`send`](Self::send).
    GetItemFluentBuilder(get_item::builders::GetItemFluentBuilder, get_item::GetItemInput) {
        value table_name, set_table_name, get_table_name: String;
        map key, set_key, get_key: AttributeValue;
        list attributes_to_get, set_attributes_to_get, get_attributes_to_get: String;
        value consistent_read, set_consistent_read, get_consistent_read: bool;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
        value projection_expression, set_projection_expression, get_projection_expression: String;
        map expression_attribute_names, set_expression_attribute_names, get_expression_attribute_names: String;
    }
}

impl GetItemFluentBuilder {
    /// Read the item, then verify and decrypt it when its table is configured.
    ///
    /// # Errors
    ///
    /// A `Serialization` error when the item is not a well-formed encrypted item,
    /// and a `Cryptographic` error when its signature does not verify.
    /// Decryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<get_item::GetItemOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self.transforms.get_item_input(input.clone()).await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("GetItem", input.table_name.as_deref(), e))?;
        self.transforms.get_item_output(output, &input).await
    }
}

fluent_builder! {
    /// The UpdateItem operation. Set the request, then call [`send`](Self::send).
    UpdateItemFluentBuilder(update_item::builders::UpdateItemFluentBuilder, update_item::UpdateItemInput) {
        value table_name, set_table_name, get_table_name: String;
        map key, set_key, get_key: AttributeValue;
        map attribute_updates, set_attribute_updates, get_attribute_updates: AttributeValueUpdate;
        map expected, set_expected, get_expected: ExpectedAttributeValue;
        value conditional_operator, set_conditional_operator, get_conditional_operator: ConditionalOperator;
        value return_values, set_return_values, get_return_values: ReturnValue;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
        value return_item_collection_metrics, set_return_item_collection_metrics, get_return_item_collection_metrics: ReturnItemCollectionMetrics;
        value update_expression, set_update_expression, get_update_expression: String;
        value condition_expression, set_condition_expression, get_condition_expression: String;
        map expression_attribute_names, set_expression_attribute_names, get_expression_attribute_names: String;
        map expression_attribute_values, set_expression_attribute_values, get_expression_attribute_values: AttributeValue;
        value return_values_on_condition_check_failure, set_return_values_on_condition_check_failure, get_return_values_on_condition_check_failure: ReturnValuesOnConditionCheckFailure;
    }
}

impl UpdateItemFluentBuilder {
    /// Update the item. On a configured table, the update must not touch a signed attribute,
    /// and a returned whole item is verified and decrypted.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the update expression names a signed attribute,
    /// or the response returns part of an item that includes a signed attribute.
    /// Decryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<update_item::UpdateItemOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self.transforms.update_item_input(input.clone()).await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("UpdateItem", input.table_name.as_deref(), e))?;
        self.transforms.update_item_output(output, &input).await
    }
}

fluent_builder! {
    /// The DeleteItem operation. Set the request, then call [`send`](Self::send).
    DeleteItemFluentBuilder(delete_item::builders::DeleteItemFluentBuilder, delete_item::DeleteItemInput) {
        value table_name, set_table_name, get_table_name: String;
        map key, set_key, get_key: AttributeValue;
        map expected, set_expected, get_expected: ExpectedAttributeValue;
        value conditional_operator, set_conditional_operator, get_conditional_operator: ConditionalOperator;
        value return_values, set_return_values, get_return_values: ReturnValue;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
        value return_item_collection_metrics, set_return_item_collection_metrics, get_return_item_collection_metrics: ReturnItemCollectionMetrics;
        value condition_expression, set_condition_expression, get_condition_expression: String;
        map expression_attribute_names, set_expression_attribute_names, get_expression_attribute_names: String;
        map expression_attribute_values, set_expression_attribute_values, get_expression_attribute_values: AttributeValue;
        value return_values_on_condition_check_failure, set_return_values_on_condition_check_failure, get_return_values_on_condition_check_failure: ReturnValuesOnConditionCheckFailure;
    }
}

impl DeleteItemFluentBuilder {
    /// Delete the item. On a configured table, the condition must not read an encrypted attribute,
    /// and a returned old item is verified and decrypted.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the condition expression reads an encrypted attribute.
    /// Decryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<delete_item::DeleteItemOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self.transforms.delete_item_input(input.clone()).await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("DeleteItem", input.table_name.as_deref(), e))?;
        self.transforms.delete_item_output(output, &input).await
    }
}

fluent_builder! {
    /// The BatchWriteItem operation. Set the request, then call [`send`](Self::send).
    BatchWriteItemFluentBuilder(batch_write_item::builders::BatchWriteItemFluentBuilder, batch_write_item::BatchWriteItemInput) {
        map request_items, set_request_items, get_request_items: Vec<WriteRequest>;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
        value return_item_collection_metrics, set_return_item_collection_metrics, get_return_item_collection_metrics: ReturnItemCollectionMetrics;
    }
}

impl BatchWriteItemFluentBuilder {
    /// Encrypt and sign each item written to a configured table, then write the batch.
    ///
    /// Each unprocessed put request in the response holds the original plaintext item,
    /// so it can be sent again with this client.
    ///
    /// # Errors
    ///
    /// A `Validation` error when a put request writes an attribute whose name begins with `aws_dbe_`,
    /// or, with a multi key store, an item's beacon key field names a different branch key
    /// than the one that encrypted it.
    /// Encryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<batch_write_item::BatchWriteItemOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
        //# If any of the above fails,
        //# the client MUST NOT make a network call to DynamoDB,
        //# and BatchWriteItem MUST yield an error.
        let transformed = self
            .transforms
            .batch_write_item_input(input.clone())
            .await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("BatchWriteItem", None, e))?;
        self.transforms
            .batch_write_item_output(output, &input)
            .await
    }
}

fluent_builder! {
    /// The TransactWriteItems operation. Set the request, then call [`send`](Self::send).
    TransactWriteItemsFluentBuilder(transact_write_items::builders::TransactWriteItemsFluentBuilder, transact_write_items::TransactWriteItemsInput) {
        list transact_items, set_transact_items, get_transact_items: TransactWriteItem;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
        value return_item_collection_metrics, set_return_item_collection_metrics, get_return_item_collection_metrics: ReturnItemCollectionMetrics;
        value client_request_token, set_client_request_token, get_client_request_token: String;
    }
}

impl TransactWriteItemsFluentBuilder {
    /// Encrypt and sign each item put in a configured table, check every other action,
    /// then write the transaction.
    ///
    /// # Errors
    ///
    /// A `Validation` error when an action sets no operation,
    /// a condition expression reads an encrypted attribute,
    /// an update expression names a signed attribute,
    /// or, with a multi key store, a put item's beacon key field names a different branch key
    /// than the one that encrypted it.
    /// Encryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<transact_write_items::TransactWriteItemsOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
        //# - If any of the above fails,
        //# the client MUST NOT make a network call to DynamoDB,
        //# and PutItem MUST yield an error.
        let transformed = self
            .transforms
            .transact_write_items_input(input.clone())
            .await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("TransactWriteItems", None, e))?;
        self.transforms
            .transact_write_items_output(output, &input)
            .await
    }
}

fluent_builder! {
    /// The Query operation. Set the request, then call [`send`](Self::send).
    QueryFluentBuilder(query::builders::QueryFluentBuilder, query::QueryInput) {
        value table_name, set_table_name, get_table_name: String;
        value index_name, set_index_name, get_index_name: String;
        value select, set_select, get_select: Select;
        list attributes_to_get, set_attributes_to_get, get_attributes_to_get: String;
        value limit, set_limit, get_limit: i32;
        value consistent_read, set_consistent_read, get_consistent_read: bool;
        map key_conditions, set_key_conditions, get_key_conditions: Condition;
        map query_filter, set_query_filter, get_query_filter: Condition;
        value conditional_operator, set_conditional_operator, get_conditional_operator: ConditionalOperator;
        value scan_index_forward, set_scan_index_forward, get_scan_index_forward: bool;
        map exclusive_start_key, set_exclusive_start_key, get_exclusive_start_key: AttributeValue;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
        value projection_expression, set_projection_expression, get_projection_expression: String;
        value filter_expression, set_filter_expression, get_filter_expression: String;
        value key_condition_expression, set_key_condition_expression, get_key_condition_expression: String;
        map expression_attribute_names, set_expression_attribute_names, get_expression_attribute_names: String;
        map expression_attribute_values, set_expression_attribute_values, get_expression_attribute_values: AttributeValue;
    }
}

impl QueryFluentBuilder {
    /// Query the table, then verify and decrypt each item when the table is configured.
    ///
    /// # Errors
    ///
    /// A `Validation` error when, on a configured table, the request sets a legacy parameter,
    /// or its key condition or filter expression reads an encrypted attribute.
    /// Decryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<query::QueryOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self.transforms.query_input(input.clone()).await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("Query", input.table_name.as_deref(), e))?;
        self.transforms.query_output(output, &input).await
    }
}

fluent_builder! {
    /// The Scan operation. Set the request, then call [`send`](Self::send).
    ScanFluentBuilder(scan::builders::ScanFluentBuilder, scan::ScanInput) {
        value table_name, set_table_name, get_table_name: String;
        value index_name, set_index_name, get_index_name: String;
        list attributes_to_get, set_attributes_to_get, get_attributes_to_get: String;
        value limit, set_limit, get_limit: i32;
        value select, set_select, get_select: Select;
        map scan_filter, set_scan_filter, get_scan_filter: Condition;
        value conditional_operator, set_conditional_operator, get_conditional_operator: ConditionalOperator;
        map exclusive_start_key, set_exclusive_start_key, get_exclusive_start_key: AttributeValue;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
        value total_segments, set_total_segments, get_total_segments: i32;
        value segment, set_segment, get_segment: i32;
        value projection_expression, set_projection_expression, get_projection_expression: String;
        value filter_expression, set_filter_expression, get_filter_expression: String;
        map expression_attribute_names, set_expression_attribute_names, get_expression_attribute_names: String;
        map expression_attribute_values, set_expression_attribute_values, get_expression_attribute_values: AttributeValue;
        value consistent_read, set_consistent_read, get_consistent_read: bool;
    }
}

impl ScanFluentBuilder {
    /// Scan the table, then verify and decrypt each item when the table is configured.
    ///
    /// # Errors
    ///
    /// A `Validation` error when, on a configured table, the request sets a legacy parameter,
    /// or its filter expression reads an encrypted attribute.
    /// Decryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<scan::ScanOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self.transforms.scan_input(input.clone()).await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("Scan", input.table_name.as_deref(), e))?;
        self.transforms.scan_output(output, &input).await
    }
}

fluent_builder! {
    /// The BatchGetItem operation. Set the request, then call [`send`](Self::send).
    BatchGetItemFluentBuilder(batch_get_item::builders::BatchGetItemFluentBuilder, batch_get_item::BatchGetItemInput) {
        map request_items, set_request_items, get_request_items: KeysAndAttributes;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
    }
}

impl BatchGetItemFluentBuilder {
    /// Read items from several tables, then verify and decrypt each item of a configured table.
    ///
    /// # Errors
    ///
    /// Decryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<batch_get_item::BatchGetItemOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self.transforms.batch_get_item_input(input.clone()).await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("BatchGetItem", None, e))?;
        self.transforms.batch_get_item_output(output, &input).await
    }
}

fluent_builder! {
    /// The TransactGetItems operation. Set the request, then call [`send`](Self::send).
    TransactGetItemsFluentBuilder(transact_get_items::builders::TransactGetItemsFluentBuilder, transact_get_items::TransactGetItemsInput) {
        list transact_items, set_transact_items, get_transact_items: TransactGetItem;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
    }
}

impl TransactGetItemsFluentBuilder {
    /// Read items in one transaction, then verify and decrypt each item of a configured table.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the response has a different number of items than the request has gets.
    /// Decryption errors keep their variant.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<transact_get_items::TransactGetItemsOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self
            .transforms
            .transact_get_items_input(input.clone())
            .await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("TransactGetItems", None, e))?;
        self.transforms
            .transact_get_items_output(output, &input)
            .await
    }
}

fluent_builder! {
    /// The ExecuteStatement operation. Set the request, then call [`send`](Self::send).
    ExecuteStatementFluentBuilder(execute_statement::builders::ExecuteStatementFluentBuilder, execute_statement::ExecuteStatementInput) {
        value statement, set_statement, get_statement: String;
        list parameters, set_parameters, get_parameters: AttributeValue;
        value consistent_read, set_consistent_read, get_consistent_read: bool;
        value next_token, set_next_token, get_next_token: String;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
        value limit, set_limit, get_limit: i32;
        value return_values_on_condition_check_failure, set_return_values_on_condition_check_failure, get_return_values_on_condition_check_failure: ReturnValuesOnConditionCheckFailure;
    }
}

impl ExecuteStatementFluentBuilder {
    /// Run the PartiQL statement, unless it names a configured table.
    ///
    /// # Errors
    ///
    /// A `Validation` error, before any call to DynamoDB, when the statement names
    /// a configured table, or when no table name can be read from it.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<execute_statement::ExecuteStatementOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self
            .transforms
            .execute_statement_input(input.clone())
            .await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("ExecuteStatement", None, e))?;
        self.transforms
            .execute_statement_output(output, &input)
            .await
    }
}

fluent_builder! {
    /// The BatchExecuteStatement operation. Set the request, then call [`send`](Self::send).
    BatchExecuteStatementFluentBuilder(batch_execute_statement::builders::BatchExecuteStatementFluentBuilder, batch_execute_statement::BatchExecuteStatementInput) {
        list statements, set_statements, get_statements: BatchStatementRequest;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
    }
}

impl BatchExecuteStatementFluentBuilder {
    /// Run the PartiQL statements, unless any names a configured table.
    ///
    /// # Errors
    ///
    /// A `Validation` error, before any call to DynamoDB, when a statement names
    /// a configured table, or when no table name can be read from one.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<batch_execute_statement::BatchExecuteStatementOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self
            .transforms
            .batch_execute_statement_input(input.clone())
            .await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("BatchExecuteStatement", None, e))?;
        self.transforms
            .batch_execute_statement_output(output, &input)
            .await
    }
}

fluent_builder! {
    /// The ExecuteTransaction operation. Set the request, then call [`send`](Self::send).
    ExecuteTransactionFluentBuilder(execute_transaction::builders::ExecuteTransactionFluentBuilder, execute_transaction::ExecuteTransactionInput) {
        list transact_statements, set_transact_statements, get_transact_statements: ParameterizedStatement;
        value client_request_token, set_client_request_token, get_client_request_token: String;
        value return_consumed_capacity, set_return_consumed_capacity, get_return_consumed_capacity: ReturnConsumedCapacity;
    }
}

impl ExecuteTransactionFluentBuilder {
    /// Run the PartiQL statements in one transaction, unless any names a configured table.
    ///
    /// # Errors
    ///
    /// A `Validation` error, before any call to DynamoDB, when a statement names
    /// a configured table, or when no table name can be read from one.
    /// A failed DynamoDB call keeps DynamoDB's error: see [`Error::as_service_error`].
    pub async fn send(self) -> Result<execute_transaction::ExecuteTransactionOutput, Error> {
        let input = self.inner.as_input().clone().build().map_err(build_error)?;
        let transformed = self
            .transforms
            .execute_transaction_input(input.clone())
            .await?;
        let output = Self::with_input(self.inner, transformed)
            .send()
            .await
            .map_err(|e| Error::from_ddb("ExecuteTransaction", None, e))?;
        self.transforms
            .execute_transaction_output(output, &input)
            .await
    }
}

/// The ResolveAttributes operation: the plaintext virtual field and compound beacon
/// values the client computes for an item. It sends nothing to DynamoDB.
/// Set the request, then call [`send`](Self::send).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ResolveAttributesFluentBuilder {
    inner: ResolveAttributesInputBuilder,
    transforms: Transforms,
}

impl ResolveAttributesFluentBuilder {
    pub(super) fn new(transforms: Transforms) -> Self {
        Self {
            inner: ResolveAttributesInput::builder(),
            transforms,
        }
    }

    /// The table whose configuration is used. Required.
    #[must_use]
    pub fn table_name(mut self, name: impl Into<String>) -> Self {
        self.inner = self.inner.table_name(name);
        self
    }

    /// Set or clear the table name.
    #[must_use]
    pub fn set_table_name(mut self, name: Option<String>) -> Self {
        self.inner = self.inner.set_table_name(name);
        self
    }

    /// The table name set so far.
    #[must_use]
    pub const fn get_table_name(&self) -> &Option<String> {
        self.inner.get_table_name()
    }

    /// The plaintext item to examine. Required.
    #[must_use]
    pub fn item(mut self, item: HashMap<String, AttributeValue>) -> Self {
        self.inner = self.inner.item(item);
        self
    }

    /// Set or clear the item.
    #[must_use]
    pub fn set_item(mut self, item: Option<HashMap<String, AttributeValue>>) -> Self {
        self.inner = self.inner.set_item(item);
        self
    }

    /// The item set so far.
    #[must_use]
    pub const fn get_item(&self) -> &Option<HashMap<String, AttributeValue>> {
        self.inner.get_item()
    }

    /// Compute the item's virtual field and compound beacon values.
    ///
    /// A table with no search configuration gives empty maps.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the table name or the item is not set,
    /// or when a compound beacon part of the item contains the split character.
    pub async fn send(self) -> Result<ResolveAttributesOutput, Error> {
        let input = self.inner.build()?;
        self.transforms.resolve_attributes(input).await
    }
}
