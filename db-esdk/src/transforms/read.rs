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
        let Some(table) = self.table(original_input.table_name.as_deref()) else {
            return Ok(output);
        };
        if no_map(output.item.as_ref()) {
            return Ok(output);
        }
        let item = output.item.take().unwrap_or_default();
        output.item = Some(decrypt(table, item).await?);
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
            return Ok(input);
        };
        if !no_list(input.attributes_to_get.as_ref()) {
            return Err(val_err(
                "Legacy parameter 'AttributesToGet' not supported in Query with Encryption",
            ));
        }
        if !no_map(input.key_conditions.as_ref()) {
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
            output.count = i32::try_from(items.len()).unwrap_or(i32::MAX);
        }
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
            return Ok(input);
        };
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
                Some(table) => decrypt_all(table, items).await?,
            };
            result.insert(name, items);
        }
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
                Some(item) if !item.is_empty() => Some(decrypt(table, item).await?),
                _ => None,
            };
            result.push(ItemResponse::builder().set_item(item).build());
        }
        output.responses = Some(result);
        Ok(output)
    }
}
