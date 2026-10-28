// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The write operations' transforms: put, update, delete, batch write, and transact write.

use std::collections::HashMap;

use aws_crypto_mpl::aws_sdk_dynamodb::operation::batch_write_item::{
    BatchWriteItemInput, BatchWriteItemOutput,
};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::delete_item::{DeleteItemInput, DeleteItemOutput};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::put_item::{PutItemInput, PutItemOutput};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::transact_write_items::{
    TransactWriteItemsInput, TransactWriteItemsOutput,
};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::update_item::{UpdateItemInput, UpdateItemOutput};
use aws_crypto_mpl::aws_sdk_dynamodb::types::{ReturnValue, WriteRequest};

use super::{
    Table, Transforms, decrypt, encrypt, is_signed, is_writeable, no_map,
    test_condition_expression, test_update_expression,
};
use crate::error::{Error, val_err};
use crate::item_encryptor::ItemEncryptor;

impl Transforms {
    /// Encrypt the item of a PutItem request.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the request sets `Expected` or `ConditionalOperator`,
    /// writes an attribute whose name begins with `aws_dbe_`,
    /// or has a condition expression that reads an encrypted attribute.
    /// Encryption errors keep their variant.
    pub async fn put_item_input(&self, mut input: PutItemInput) -> Result<PutItemInput, Error> {
        let Some(table) = self.encrypted_write(input.table_name.as_deref()) else {
            return Ok(input);
        };
        if !no_map(input.expected.as_ref()) {
            return Err(val_err(
                "Legacy parameter 'Expected' not supported in PutItem with Encryption.",
            ));
        }
        if input.conditional_operator.is_some() {
            return Err(val_err(
                "Legacy parameter 'ConditionalOperator' not supported in PutItem with Encryption.",
            ));
        }
        let item = input.item.take().unwrap_or_default();
        is_writeable(&item)?;
        test_condition_expression(
            &table.encryptor,
            input.condition_expression.as_deref(),
            input.expression_attribute_names.as_ref(),
        )?;
        input.item = Some(encrypt(table, item).await?);
        Ok(input)
    }

    /// Decrypt the old item a PutItem response returns.
    ///
    /// # Errors
    ///
    /// Decryption errors keep their variant.
    pub async fn put_item_output(
        &self,
        mut output: PutItemOutput,
        original_input: &PutItemInput,
    ) -> Result<PutItemOutput, Error> {
        let Some(table) = self.table(original_input.table_name.as_deref()) else {
            return Ok(output);
        };
        if no_map(output.attributes.as_ref()) {
            return Ok(output);
        }
        let attributes = output.attributes.take().unwrap_or_default();
        output.attributes = Some(decrypt(table, attributes).await?);
        Ok(output)
    }

    /// Check an UpdateItem request: it must not update a signed attribute.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the request sets `Expected`, `AttributeUpdates`, or `ConditionalOperator`,
    /// or has an update expression that names a signed attribute.
    pub async fn update_item_input(
        &self,
        input: UpdateItemInput,
    ) -> Result<UpdateItemInput, Error> {
        let Some(table) = self.table(input.table_name.as_deref()) else {
            return Ok(input);
        };
        if !no_map(input.expected.as_ref()) {
            return Err(val_err(
                "Legacy parameter 'Expected' not supported in UpdateItem with Encryption",
            ));
        }
        if !no_map(input.attribute_updates.as_ref()) {
            return Err(val_err(
                "Legacy parameter 'AttributeUpdates' not supported in UpdateItem with Encryption",
            ));
        }
        if input.conditional_operator.is_some() {
            return Err(val_err(
                "Legacy parameter 'ConditionalOperator' not supported in UpdateItem with Encryption",
            ));
        }
        test_update_expression(
            table,
            input.update_expression.as_deref(),
            input.expression_attribute_names.as_ref(),
        )?;
        Ok(input)
    }

    /// Decrypt the item an UpdateItem response returns, when it returns the whole item.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the response returns only some attributes and any is signed,
    /// since a part of an item cannot be verified.
    /// Decryption errors keep their variant.
    pub async fn update_item_output(
        &self,
        mut output: UpdateItemOutput,
        original_input: &UpdateItemInput,
    ) -> Result<UpdateItemOutput, Error> {
        let Some(table) = self.table(original_input.table_name.as_deref()) else {
            return Ok(output);
        };
        if no_map(output.attributes.as_ref()) {
            return Ok(output);
        }
        let whole_item = matches!(
            original_input.return_values,
            Some(ReturnValue::AllNew | ReturnValue::AllOld)
        );
        if !whole_item {
            let actions = &table.config().attribute_actions_on_encrypt;
            if output
                .attributes
                .iter()
                .flat_map(HashMap::keys)
                .any(|k| is_signed(actions, k))
            {
                return Err(val_err(
                    "UpdateItems response contains signed attributes, but does not include the entire item which is required for verification.",
                ));
            }
            return Ok(output);
        }
        let attributes = output.attributes.take().unwrap_or_default();
        output.attributes = Some(decrypt(table, attributes).await?);
        Ok(output)
    }

    /// Check a DeleteItem request: its condition must not read an encrypted attribute.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the request sets `Expected` or `ConditionalOperator`,
    /// or has a condition expression that reads an encrypted attribute.
    pub async fn delete_item_input(
        &self,
        input: DeleteItemInput,
    ) -> Result<DeleteItemInput, Error> {
        let Some(table) = self.table(input.table_name.as_deref()) else {
            return Ok(input);
        };
        if !no_map(input.expected.as_ref()) {
            return Err(val_err(
                "Legacy parameter 'Expected' not supported in UpdateItem with Encryption",
            ));
        }
        if input.conditional_operator.is_some() {
            return Err(val_err(
                "Legacy parameter 'ConditionalOperator' not supported in UpdateItem with Encryption",
            ));
        }
        test_condition_expression(
            table,
            input.condition_expression.as_deref(),
            input.expression_attribute_names.as_ref(),
        )?;
        Ok(input)
    }

    /// Decrypt the old item a DeleteItem response returns.
    ///
    /// # Errors
    ///
    /// Decryption errors keep their variant.
    pub async fn delete_item_output(
        &self,
        mut output: DeleteItemOutput,
        original_input: &DeleteItemInput,
    ) -> Result<DeleteItemOutput, Error> {
        let Some(table) = self.table(original_input.table_name.as_deref()) else {
            return Ok(output);
        };
        if no_map(output.attributes.as_ref()) {
            return Ok(output);
        }
        let attributes = output.attributes.take().unwrap_or_default();
        output.attributes = Some(decrypt(table, attributes).await?);
        Ok(output)
    }

    /// Encrypt the item of each put request of a BatchWriteItem request.
    ///
    /// # Errors
    ///
    /// A `Validation` error when a put request writes an attribute whose name begins with `aws_dbe_`.
    /// Encryption errors keep their variant.
    pub async fn batch_write_item_input(
        &self,
        mut input: BatchWriteItemInput,
    ) -> Result<BatchWriteItemInput, Error> {
        let Some(request_items) = input.request_items.take() else {
            return Ok(input);
        };
        let mut result = HashMap::with_capacity(request_items.len());
        for (table_name, requests) in request_items {
            let requests = match self.encrypted_write(Some(&table_name)) {
                None => requests,
                Some(table) => encrypt_write_requests(table, requests).await?,
            };
            result.insert(table_name, requests);
        }
        input.request_items = Some(result);
        Ok(input)
    }

    /// Put the original plaintext item back in each unprocessed put request of a BatchWriteItem response.
    ///
    /// # Errors
    ///
    /// A `Validation` error when an unprocessed put request matches no put request of `original_input`.
    pub async fn batch_write_item_output(
        &self,
        mut output: BatchWriteItemOutput,
        original_input: &BatchWriteItemInput,
    ) -> Result<BatchWriteItemOutput, Error> {
        let Some(unprocessed) = output.unprocessed_items.take() else {
            return Ok(output);
        };
        let empty = HashMap::new();
        let src_items = original_input.request_items.as_ref().unwrap_or(&empty);
        let mut result = HashMap::with_capacity(unprocessed.len());
        for (table_name, requests) in unprocessed {
            let requests = match self.encrypted_write(Some(&table_name)) {
                None => requests,
                Some(table) => {
                    let table = &table.encryptor;
                    let src = src_items.get(&table_name).ok_or_else(|| {
                        val_err(format!(
                            "{table_name} in UnprocessedItems for BatchWriteItem response, but not in original request."
                        ))
                    })?;
                    requests
                        .into_iter()
                        .map(|req| original_request(table, src, req))
                        .collect::<Result<_, _>>()?
                }
            };
            result.insert(table_name, requests);
        }
        output.unprocessed_items = Some(result);
        Ok(output)
    }

    /// Encrypt the item of each put of a TransactWriteItems request,
    /// and check the conditions and updates of its other actions.
    ///
    /// # Errors
    ///
    /// A `Validation` error when an action sets no operation,
    /// a put writes an attribute whose name begins with `aws_dbe_`,
    /// a condition expression reads an encrypted attribute,
    /// or an update expression names a signed attribute.
    /// Encryption errors keep their variant.
    pub async fn transact_write_items_input(
        &self,
        mut input: TransactWriteItemsInput,
    ) -> Result<TransactWriteItemsInput, Error> {
        let Some(items) = input.transact_items.take() else {
            return Ok(input);
        };
        if !items.iter().all(|i| {
            i.put.is_some()
                || i.update.is_some()
                || i.delete.is_some()
                || i.condition_check.is_some()
        }) {
            return Err(val_err(
                "Each item in TransactWriteItems must specify at least one supported operation",
            ));
        }
        let mut result = Vec::with_capacity(items.len());
        for mut item in items {
            if let Some(check) = &item.condition_check
                && let Some(table) = self.table(Some(&check.table_name))
            {
                test_condition_expression(
                    table,
                    Some(&check.condition_expression),
                    check.expression_attribute_names.as_ref(),
                )?;
            }
            if let Some(delete) = &item.delete
                && let Some(table) = self.table(Some(&delete.table_name))
            {
                test_condition_expression(
                    table,
                    delete.condition_expression.as_deref(),
                    delete.expression_attribute_names.as_ref(),
                )?;
            }
            if let Some(update) = &item.update
                && let Some(table) = self.table(Some(&update.table_name))
            {
                test_update_expression(
                    table,
                    Some(&update.update_expression),
                    update.expression_attribute_names.as_ref(),
                )?;
                test_condition_expression(
                    table,
                    update.condition_expression.as_deref(),
                    update.expression_attribute_names.as_ref(),
                )?;
            }
            if let Some(put) = &mut item.put
                && let Some(table) = self.encrypted_write(Some(&put.table_name))
            {
                is_writeable(&put.item)?;
                test_condition_expression(
                    &table.encryptor,
                    put.condition_expression.as_deref(),
                    put.expression_attribute_names.as_ref(),
                )?;
                let plaintext = std::mem::take(&mut put.item);
                put.item = encrypt(table, plaintext).await?;
            }
            result.push(item);
        }
        input.transact_items = Some(result);
        Ok(input)
    }

    /// A TransactWriteItems response returns no items, so it passes through unchanged.
    ///
    /// # Errors
    ///
    /// Never fails; the signature matches the other output transforms.
    pub async fn transact_write_items_output(
        &self,
        output: TransactWriteItemsOutput,
        _original_input: &TransactWriteItemsInput,
    ) -> Result<TransactWriteItemsOutput, Error> {
        Ok(output)
    }
}

/// Encrypt the item of each put request in `requests`; delete requests pass through.
async fn encrypt_write_requests(
    table: &Table,
    requests: Vec<WriteRequest>,
) -> Result<Vec<WriteRequest>, Error> {
    let mut out = Vec::with_capacity(requests.len());
    for mut req in requests {
        if let Some(put) = &mut req.put_request {
            is_writeable(&put.item)?;
            let plaintext = std::mem::take(&mut put.item);
            put.item = encrypt(table, plaintext).await?;
        }
        out.push(req);
    }
    Ok(out)
}

/// The put request of `src` whose primary key matches the unprocessed put request `req`.
fn original_request(
    table: &ItemEncryptor,
    src: &[WriteRequest],
    req: WriteRequest,
) -> Result<WriteRequest, Error> {
    let Some(put) = &req.put_request else {
        return Ok(req);
    };
    let config = table.config();
    let part_key = &config.partition_key_name;
    let sort_key = config.sort_key_name.as_ref();
    let item = &put.item;
    let part = item
        .get(part_key)
        .ok_or_else(|| val_err("Required partition key not in unprocessed item"))?;
    let sort = match sort_key {
        None => None,
        Some(k) => Some(
            item.get(k)
                .ok_or_else(|| val_err("Required sort key not in unprocessed item"))?,
        ),
    };
    src.iter()
        .find(|s| {
            s.put_request.as_ref().is_some_and(|p| {
                p.item.get(part_key) == Some(part) && sort_key.is_none_or(|k| p.item.get(k) == sort)
            })
        })
        .cloned()
        .ok_or_else(|| val_err("Item in UnprocessedItems not found in original request."))
}
