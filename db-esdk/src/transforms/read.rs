// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The read operations' transforms: get, query, scan, batch get, and transact get.

use std::collections::HashMap;

use aws_crypto_mpl::aws_sdk_dynamodb::operation::batch_get_item::{
    BatchGetItemInput, BatchGetItemOutput,
};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::get_item::{GetItemInput, GetItemOutput};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::query::{QueryInput, QueryOutput};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::scan::{ScanInput, ScanOutput};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::transact_get_items::{
    TransactGetItemsInput, TransactGetItemsOutput,
};
use aws_crypto_mpl::aws_sdk_dynamodb::types::ItemResponse;

use super::{
    Transforms, decrypt, decrypt_all, decrypt_search_results, no_map, test_beaconize,
    validate_expression_length,
};
use crate::error::{Error, val_err};

/// Whether `l` is absent or empty.
fn no_list<T>(l: Option<&Vec<T>>) -> bool {
    l.is_none_or(Vec::is_empty)
}

impl Transforms {
    /// A GetItem request needs no change, so it passes through unchanged.
    ///
    /// # Errors
    ///
    /// Never fails; the signature matches the other input transforms.
    pub async fn get_item_input(&self, input: GetItemInput) -> Result<GetItemInput, Error> {
        Ok(input)
    }

    /// Verify and decrypt the item a GetItem response returns.
    ///
    /// # Errors
    ///
    /// Decryption errors keep their variant:
    /// for example `Serialization` for an item that is not a well-formed encrypted item,
    /// and `Cryptographic` for one whose signature does not verify.
    pub async fn get_item_output(
        &self,
        mut output: GetItemOutput,
        original_input: &GetItemInput,
    ) -> Result<GetItemOutput, Error> {
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-getitem
        //# After a [GetItem](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetItem.html)
        //# call is made to DynamoDB,
        //# the resulting response MUST be modified before
        //# being returned to the caller if there exists
        //# an Item Encryptor specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
        //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
        //# equal to the `TableName` on the GetItem request.
        let Some(table) = self.table(original_input.table_name.as_deref()) else {
            return Ok(output);
        };
        if no_map(output.item.as_ref()) {
            return Ok(output);
        }
        let item = output.item.take().unwrap_or_default();

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-getitem
        //# The [Item Encryptor](./ddb-item-encryptor.md) MUST perform
        //# [Decrypt Item](./decrypt-item.md) where the input
        //# [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is the `Item` field in the original response
        let decrypted = decrypt(table, item).await?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-getitem
        //# The GetItem response's `Item` field MUST be
        //# replaced by the encrypted DynamoDb Item outputted above.
        output.item = Some(decrypted);
        Ok(output)
    }

    /// Check a Query request on a configured table.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the request sets a legacy parameter
    /// (`AttributesToGet`, `KeyConditions`, `QueryFilter`, or `ConditionalOperator`),
    /// when its key condition or filter expression is longer than 4096 characters,
    /// or when either reads an encrypted attribute that has no beacon.
    /// On a table with beacons, the expressions are rewritten to compare beacons.
    pub async fn query_input(&self, mut input: QueryInput) -> Result<QueryInput, Error> {
        let Some(table) = self.table_info(input.table_name.as_deref()) else {
            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-query
            //# If the `TableName` in the request does not refer to an [encrypted-table](#encrypted-table),
            //# the Query request MUST be unchanged.
            return Ok(input);
        };

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-query
        //# The Query request MUST NOT refer to any legacy parameters,
        //# specifically AttributesToGet, KeyConditions, QueryFilter and ConditionalOperator MUST NOT be set.
        if !no_list(input.attributes_to_get.as_ref()) {
            return Err(val_err(
                "Legacy parameter 'AttributesToGet' not supported in Query with Encryption",
            ));
        }
        if !no_map(input.key_conditions.as_ref()) {
            //= spec/dynamodb-encryption-client/ddb-support.md#queryinputforbeacons
            //# The KeyConditions property MUST NOT be defined on [QueryInput](#queryinput).
            return Err(val_err(
                "Legacy parameter 'KeyConditions' not supported in Query with Encryption",
            ));
        }
        if !no_map(input.query_filter.as_ref()) {
            return Err(val_err(
                "Legacy parameter 'QueryFilter' not supported in Query with Encryption",
            ));
        }
        if input.conditional_operator.is_some() {
            return Err(val_err(
                "Legacy parameter 'ConditionalOperator' not supported in Query with Encryption",
            ));
        }
        validate_expression_length(
            input.key_condition_expression.as_deref(),
            "KeyConditionExpression",
        )?;
        validate_expression_length(input.filter_expression.as_deref(), "FilterExpression")?;
        let Some(search) = &table.search else {
            test_beaconize(
                &table.encryptor,
                input.key_condition_expression.as_deref(),
                input.filter_expression.as_deref(),
                input.expression_attribute_names.as_ref(),
            )?;
            return Ok(input);
        };

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-query
        //# The request MUST be [altered](./ddb-support.md#queryinputforbeacons)
        //# to transform any references to encrypted attributes into references to beacons.
        let ctx = search
            .query_input_for_beacons(
                &table.encryptor.config().attribute_actions_on_encrypt,
                input.key_condition_expression.take(),
                input.filter_expression.take(),
                input.expression_attribute_names.take(),
                input.expression_attribute_values.take(),
            )
            .await?;
        input.key_condition_expression = ctx.key_expr;
        input.filter_expression = ctx.filter_expr;
        input.expression_attribute_names = ctx.names;
        input.expression_attribute_values = ctx.values;
        Ok(input)
    }

    /// How many queries, one per beacon partition, together read every item `input` matches.
    ///
    /// Run the query once for each partition, with `:aws_dbe_partition` set to
    /// `0`, `1`, ... in its expression attribute values.
    /// The count is the least common multiple of the partition counts of the beacons
    /// the key condition compares, at most the beacon version's maximum number of partitions.
    /// It is 1 for a table without beacons.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the key condition expression is longer than 4096 characters,
    /// or names an expression attribute value that the input does not have.
    //= spec/dynamodb-encryption-client/ddb-get-number-of-queries.md#input
    //= type=implication
    //= reason=the only parameter is &QueryInput; any other input type does not compile
    //# This operation MUST take as input the QueryInput structure under consideration.
    pub async fn get_number_of_queries(&self, input: &QueryInput) -> Result<u8, Error> {
        let Some(search) = self
            .table_info(input.table_name.as_deref())
            .and_then(|t| t.search.as_ref())
        else {
            return Ok(1);
        };
        validate_expression_length(
            input.key_condition_expression.as_deref(),
            "KeyConditionExpression",
        )?;

        //= spec/dynamodb-encryption-client/ddb-get-number-of-queries.md#input
        //# This operation MUST return the number of queries necessary.
        search.version.get_num_queries(
            input.key_condition_expression.as_deref(),
            input.expression_attribute_values.as_ref(),
        )
    }

    /// Verify and decrypt each item a Query response returns.
    ///
    /// On a table with beacons, the items are filtered again with the original
    /// key condition and filter, dropping those that matched only by their beacons.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the original key condition or filter expression
    /// is longer than 4096 characters, or cannot be evaluated.
    /// Decryption errors keep their variant.
    pub async fn query_output(
        &self,
        mut output: QueryOutput,
        original_input: &QueryInput,
    ) -> Result<QueryOutput, Error> {
        let Some(table) = self.table_info(original_input.table_name.as_deref()) else {
            return Ok(output);
        };
        if no_list(output.items.as_ref()) {
            return Ok(output);
        }
        let items = output.items.take().unwrap_or_default();
        let items = decrypt_search_results(
            table,
            items,
            original_input.key_condition_expression.as_deref(),
            original_input.filter_expression.as_deref(),
            original_input.expression_attribute_names.as_ref(),
            original_input.expression_attribute_values.as_ref(),
            "Query",
        )
        .await?;
        if table.search.is_some() && output.count != 0 {
            //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
            //# The `Count` field, MUST be updated to reflect the new item count.
            output.count = i32::try_from(items.len()).unwrap_or(i32::MAX);
        }

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-query
        //# Each of these entries on the original response MUST be replaced
        //# with the resulting decrypted [DynamoDB Item](./decrypt-item.md#dynamodb-item-1).
        output.items = Some(items);
        Ok(output)
    }

    /// Check a Scan request on a configured table.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the request sets a legacy parameter
    /// (`AttributesToGet`, `ScanFilter`, or `ConditionalOperator`),
    /// when its filter expression is longer than 4096 characters,
    /// or when it reads an encrypted attribute that has no beacon.
    /// On a table with beacons, the filter is rewritten to compare beacons.
    pub async fn scan_input(&self, mut input: ScanInput) -> Result<ScanInput, Error> {
        let Some(table) = self.table_info(input.table_name.as_deref()) else {
            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-scan
            //# If the `TableName` in the request does not refer to an [encrypted-table](#encrypted-table),
            //# the Scan request MUST be unchanged.
            return Ok(input);
        };

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-scan
        //# The Scan request MUST NOT refer to any legacy parameters,
        //# specifically AttributesToGet, ScanFilter and ConditionalOperator MUST NOT be set.
        if !no_list(input.attributes_to_get.as_ref()) {
            return Err(val_err(
                "Legacy parameter 'AttributesToGet' not supported in UpdateItem with Encryption",
            ));
        }
        if !no_map(input.scan_filter.as_ref()) {
            return Err(val_err(
                "Legacy parameter 'ScanFilter' not supported in UpdateItem with Encryption",
            ));
        }
        if input.conditional_operator.is_some() {
            return Err(val_err(
                "Legacy parameter 'ConditionalOperator' not supported in UpdateItem with Encryption",
            ));
        }
        validate_expression_length(input.filter_expression.as_deref(), "FilterExpression")?;
        let Some(search) = &table.search else {
            test_beaconize(
                &table.encryptor,
                None,
                input.filter_expression.as_deref(),
                input.expression_attribute_names.as_ref(),
            )?;
            return Ok(input);
        };

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-scan
        //# The request MUST be [altered](./ddb-support.md#scaninputforbeacons)
        //# to transform any references to encrypted attributes into references to beacons.
        let ctx = search
            .scan_input_for_beacons(
                input.filter_expression.take(),
                input.expression_attribute_names.take(),
                input.expression_attribute_values.take(),
            )
            .await?;
        input.filter_expression = ctx.filter_expr;
        input.expression_attribute_names = ctx.names;
        input.expression_attribute_values = ctx.values;
        Ok(input)
    }

    /// Verify and decrypt each item a Scan response returns.
    ///
    /// On a table with beacons, the items are filtered again with the original filter,
    /// dropping those that matched only by their beacons.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the original filter expression is longer than 4096 characters,
    /// or cannot be evaluated.
    /// Decryption errors keep their variant.
    pub async fn scan_output(
        &self,
        mut output: ScanOutput,
        original_input: &ScanInput,
    ) -> Result<ScanOutput, Error> {
        let Some(table) = self.table_info(original_input.table_name.as_deref()) else {
            return Ok(output);
        };
        if no_list(output.items.as_ref()) {
            return Ok(output);
        }
        let items = output.items.take().unwrap_or_default();
        let items = decrypt_search_results(
            table,
            items,
            None,
            original_input.filter_expression.as_deref(),
            original_input.expression_attribute_names.as_ref(),
            original_input.expression_attribute_values.as_ref(),
            "Scan",
        )
        .await?;
        if table.search.is_some() && output.count != 0 {
            output.count = i32::try_from(items.len()).unwrap_or(i32::MAX);
        }

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-scan
        //# Each of these entries on the original response MUST be replaced
        //# with the resulting decrypted
        //# [DynamoDB Item](./decrypt-item.md#dynamodb-item-1).
        output.items = Some(items);
        Ok(output)
    }

    /// A BatchGetItem request needs no change, so it passes through unchanged.
    ///
    /// # Errors
    ///
    /// Never fails; the signature matches the other input transforms.
    pub async fn batch_get_item_input(
        &self,
        input: BatchGetItemInput,
    ) -> Result<BatchGetItemInput, Error> {
        Ok(input)
    }

    /// Verify and decrypt each item a BatchGetItem response returns for a configured table.
    ///
    /// # Errors
    ///
    /// Decryption errors keep their variant.
    pub async fn batch_get_item_output(
        &self,
        mut output: BatchGetItemOutput,
        _original_input: &BatchGetItemInput,
    ) -> Result<BatchGetItemOutput, Error> {
        if no_map(output.responses.as_ref()) {
            return Ok(output);
        }
        let mut responses = output.responses.take().unwrap_or_default();
        // Sorted, so the same response always fails on the same table.
        let mut names: Vec<String> = responses.keys().cloned().collect();
        names.sort();
        let mut result = HashMap::with_capacity(names.len());
        for name in names {
            let Some(items) = responses.remove(&name) else {
                continue;
            };
            let items = match self.table(Some(&name)) {
                None => items,
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchgetitem
                //# For each list item under each key in `Responses`,
                //# if there is a configured Item Encryptor with [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name) equal to the key,
                //# that Item Encryptor MUST perform [Decrypt Item](./decrypt-item.md) where the input
                //# [DynamoDB Item](./decrypt-item.md#dynamodb-item)
                //# is the `Item` field in the original response.
                //
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchgetitem
                //# If any [Decrypt Item](./decrypt-item.md) operation fails,
                //# BatchGetItem MUST yield an error.
                Some(table) => decrypt_all(table, items).await?,
            };
            result.insert(name, items);
        }

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchgetitem
        //# Each of these items on the original response MUST be replaced
        //# with a value that is equivalent to
        //# this result.
        output.responses = Some(result);
        Ok(output)
    }

    /// A TransactGetItems request needs no change, so it passes through unchanged.
    ///
    /// # Errors
    ///
    /// Never fails; the signature matches the other input transforms.
    pub async fn transact_get_items_input(
        &self,
        input: TransactGetItemsInput,
    ) -> Result<TransactGetItemsInput, Error> {
        Ok(input)
    }

    /// Verify and decrypt each item a TransactGetItems response returns for a configured table.
    ///
    /// The `n`th response is the item of the `n`th get of `original_input`.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the response has a different number of items
    /// than `original_input` has gets.
    /// Decryption errors keep their variant.
    pub async fn transact_get_items_output(
        &self,
        mut output: TransactGetItemsOutput,
        original_input: &TransactGetItemsInput,
    ) -> Result<TransactGetItemsOutput, Error> {
        if no_list(output.responses.as_ref()) {
            return Ok(output);
        }
        let responses = output.responses.take().unwrap_or_default();
        let gets = original_input.transact_items.as_deref().unwrap_or_default();
        if responses.len() != gets.len() {
            return Err(val_err(
                "Invalid TransactGetItems response for original request: Number of items returned must equal number of items requested.",
            ));
        }
        let mut result = Vec::with_capacity(responses.len());
        for (response, get) in responses.into_iter().zip(gets) {
            let table_name = get.get.as_ref().map(|g| g.table_name.as_str());
            let Some(table) = self.table(table_name) else {
                result.push(response);
                continue;
            };
            let item = match response.item {
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-transactgetitems
                //# For each list item under each key in `Responses`,
                //# if there exists an Item Encryptor specified within
                //# the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
                //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
                //# equal to the key,
                //# the Item Encryptor that corresponds to the key in the request
                //# MUST perform [Decrypt Item](./decrypt-item.md) where the input
                //# [DynamoDB Item](./decrypt-item.md#dynamodb-item) is the `Item` in the original response.
                //
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-transactgetitems
                //# If any [Decrypt Item](./decrypt-item.md) fails,
                //# TransactGetItems MUST yield an error.
                Some(item) if !item.is_empty() => Some(decrypt(table, item).await?),
                _ => None,
            };

            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-transactgetitems
            //# Each of these items on the original response MUST be replaced
            //# with a value that is equivalent to the resulting item.
            result.push(ItemResponse::builder().set_item(item).build());
        }
        output.responses = Some(result);
        Ok(output)
    }
}
