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
    /// has a condition expression that reads an encrypted attribute,
    /// or, with a multi key store, has a beacon key field that names a different branch key
    /// than the one that encrypted the item.
    /// Encryption errors keep their variant.
    pub async fn put_item_input(&self, mut input: PutItemInput) -> Result<PutItemInput, Error> {
        let Some(table) = self.encrypted_write(input.table_name.as_deref()) else {
            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
            //# If the `TableName` in the request does not refer to an [encrypted-table](#encrypted-table),
            //# the PutItem request MUST be unchanged.
            return Ok(input);
        };

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
        //= reason=this check and the next reject Expected and ConditionalOperator
        //# The PutItem request MUST NOT refer to any legacy parameters,
        //# specifically Expected and ConditionalOperator MUST NOT be set.
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

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
        //# The Item MUST be [writable](ddb-support.md#writable).
        is_writeable(&item)?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
        //# The ConditionExpression MUST be [valid](ddb-support.md#testconditionexpression).
        test_condition_expression(
            &table.encryptor,
            input.condition_expression.as_deref(),
            input.expression_attribute_names.as_ref(),
        )?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
        //# The PutItem request's `Item` field MUST be replaced
        //# with a value that is equivalent to
        //# the output of the [add encrypted beacons](ddb-support.md#addencryptedbeacons) operation
        //# calculated above.
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
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-putitem
        //# After a [PutItem](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html)
        //# call is made to DynamoDB,
        //# the resulting response MUST be modified before
        //# being returned to the caller if:
        let Some(table) = self.table(original_input.table_name.as_deref()) else {
            return Ok(output);
        };
        if no_map(output.attributes.as_ref()) {
            return Ok(output);
        }
        let attributes = output.attributes.take().unwrap_or_default();

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-putitem
        //# In this case, the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
        //# [Decrypt Item](./decrypt-item.md) where the input
        //# [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is the `Attributes` field in the original response
        let decrypted = decrypt(table, attributes).await?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-putitem
        //# The PutItem response's `Attributes` field MUST be
        //# replaced by the encrypted DynamoDb Item outputted above.
        output.attributes = Some(decrypted);
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
            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-updateitem
            //# If the `TableName` in the request does not refer to an [encrypted-table](#encrypted-table),
            //# the UpdateItem request MUST be unchanged.
            return Ok(input);
        };

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-updateitem
        //# The UpdateItem request MUST NOT refer to any legacy parameters,
        //# specifically Expected, AttributeUpdates and ConditionalOperator MUST NOT be set.
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

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-updateitem
        //# The UpdateExpression MUST be [valid](ddb-support.md#testupdateexpression).
        test_update_expression(
            table,
            input.update_expression.as_deref(),
            input.expression_attribute_names.as_ref(),
        )?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-updateitem
        //# If all of the above validation succeeds, the UpdateItem request MUST be unchanged.
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
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-updateitem
        //# After a [UpdateItem](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html)
        //# call is made to DynamoDB,
        //# the resulting response MUST be modified before
        //# being returned to the caller if:
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
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-updateitem
                //# Additionally, if a value of `UPDATED_OLD` or `UPDATED_NEW` was used,
                //# and any Attributes in the response are authenticated
                //# per the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration),
                //# an error MUST be raised.
                return Err(val_err(
                    "UpdateItems response contains signed attributes, but does not include the entire item which is required for verification.",
                ));
            }

            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-updateitem
            //= reason=the unconfigured-table and no-Attributes returns above also leave output untouched
            //# In all other cases, the UpdateItem response MUST NOT be modified.
            return Ok(output);
        }
        let attributes = output.attributes.take().unwrap_or_default();

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-updateitem
        //# In this case, the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
        //# [Decrypt Item](./decrypt-item.md) where the input
        //# [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is the `Attributes` field in the original response
        let decrypted = decrypt(table, attributes).await?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-updateitem
        //# The UpdateItem response's `Attributes` field MUST be
        //# replaced by the encrypted DynamoDb Item outputted above.
        output.attributes = Some(decrypted);
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
            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-deleteitem
            //# If the `TableName` in the request does not refer to an [encrypted-table](#encrypted-table),
            //# the DeleteItem request MUST be unchanged.
            return Ok(input);
        };

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-deleteitem
        //# The DeleteItem request MUST NOT refer to any legacy parameters,
        //# specifically Expected and ConditionalOperator MUST NOT be set.
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

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-deleteitem
        //# The ConditionExpression MUST be [valid](ddb-support.md#testconditionexpression).
        test_condition_expression(
            table,
            input.condition_expression.as_deref(),
            input.expression_attribute_names.as_ref(),
        )?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-deleteitem
        //# If all of the above validation succeeds, the DeleteItem request MUST be unchanged.
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
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-deleteitem
        //# After a [DeleteItem](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DeleteItem.html)
        //# call is made to DynamoDB,
        //# the resulting response MUST be modified before
        //# being returned to the caller if:
        let Some(table) = self.table(original_input.table_name.as_deref()) else {
            return Ok(output);
        };
        if no_map(output.attributes.as_ref()) {
            return Ok(output);
        }
        let attributes = output.attributes.take().unwrap_or_default();

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-deleteitem
        //# In this case, the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
        //# [Decrypt Item](./decrypt-item.md) where the input
        //# [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is the `Attributes` field in the original response
        let decrypted = decrypt(table, attributes).await?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-deleteitem
        //# The DeleteItem response's `Attributes` field MUST be
        //# replaced by the encrypted DynamoDb Item outputted above.
        output.attributes = Some(decrypted);
        Ok(output)
    }

    /// Encrypt the item of each put request of a BatchWriteItem request.
    ///
    /// # Errors
    ///
    /// A `Validation` error when a put request writes an attribute whose name begins with `aws_dbe_`,
    /// or, with a multi key store, its item's beacon key field names a different branch key
    /// than the one that encrypted it.
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
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
                //# If the table name does not refer to an [encrypted-table](#encrypted-table),
                //# the list of operations MUST be unchanged.
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
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchwriteitem
        //# If there are no UnprocessedItems, then the BatchWriteItemOutput MUST be returned unchanged.
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
                        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchwriteitem
                        //# Each item in UnprocessedItems MUST be replaced by its original plaintext value.
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
    /// an update expression names a signed attribute,
    /// or, with a multi key store, a put item's beacon key field names a different
    /// branch key than the one that encrypted it.
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
            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
            //# To protect against a possible fifth field being added to the TransactWriteItem structure in the future,
            //# the client MUST fail if none of the `Update`, `ConditionCheck`, `Delete` and `Put` fields are set.
            return Err(val_err(
                "Each item in TransactWriteItems must specify at least one supported operation",
            ));
        }
        let mut result = Vec::with_capacity(items.len());
        for mut item in items {
            if let Some(check) = &item.condition_check
                && let Some(table) = self.table(Some(&check.table_name))
            {
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
                //# - The ConditionExpression of the `ConditionCheck` MUST be [valid](ddb-support.md#testconditionexpression).
                test_condition_expression(
                    table,
                    Some(&check.condition_expression),
                    check.expression_attribute_names.as_ref(),
                )?;
            }
            if let Some(delete) = &item.delete
                && let Some(table) = self.table(Some(&delete.table_name))
            {
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
                //# - The ConditionExpression of the `Delete` MUST be [valid](ddb-support.md#testconditionexpression).
                test_condition_expression(
                    table,
                    delete.condition_expression.as_deref(),
                    delete.expression_attribute_names.as_ref(),
                )?;
            }
            if let Some(update) = &item.update
                && let Some(table) = self.table(Some(&update.table_name))
            {
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
                //# - The UpdateExpression of the `Update` MUST be [valid](ddb-support.md#testupdateexpression).
                test_update_expression(
                    table,
                    Some(&update.update_expression),
                    update.expression_attribute_names.as_ref(),
                )?;

                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
                //# - The ConditionExpression of the `Update` MUST be [valid](ddb-support.md#testconditionexpression).
                test_condition_expression(
                    table,
                    update.condition_expression.as_deref(),
                    update.expression_attribute_names.as_ref(),
                )?;
            }

            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
            //# Any `Put` actions with a `TableName` that does not refer to an [encrypted-table](#encrypted-table),
            //# MUST be unchanged.
            if let Some(put) = &mut item.put
                && let Some(table) = self.encrypted_write(Some(&put.table_name))
            {
                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
                //# - The Item MUST be [writable](ddb-support.md#writable).
                is_writeable(&put.item)?;

                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
                //# - The ConditionExpression `Put` MUST be [valid](ddb-support.md#testconditionexpression).
                test_condition_expression(
                    &table.encryptor,
                    put.condition_expression.as_deref(),
                    put.expression_attribute_names.as_ref(),
                )?;
                let plaintext = std::mem::take(&mut put.item);

                //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
                //# - The PutItem request's `Item` field MUST be replaced
                //# with a value that is equivalent to
                //# the result [Encrypted DynamoDB Item](./encrypt-item.md#encrypted-dynamodb-item)
                //# calculated above.
                put.item = encrypt(table, plaintext).await?;
            }

            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
            //= reason=only a put item is reassigned; the other actions are only borrowed for checks
            //# Any actions other than `Put`, MUST be unchanged.
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
            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
            //# The Item MUST be [writable](ddb-support.md#writable).
            is_writeable(&put.item)?;
            let plaintext = std::mem::take(&mut put.item);

            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
            //# The PutRequest request's `Item` field MUST be replaced
            //# with a value that is equivalent to
            //# the result [Encrypted DynamoDB Item](./encrypt-item.md#encrypted-dynamodb-item)
            //# calculated above.
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
