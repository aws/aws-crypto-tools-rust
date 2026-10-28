// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The read operations' transforms.

use aws_crypto_mpl::aws_sdk_dynamodb::operation::get_item::{GetItemInput, GetItemOutput};

use super::{Transforms, decrypt, no_map};
use crate::error::Error;

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
}
