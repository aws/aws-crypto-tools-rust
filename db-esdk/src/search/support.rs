// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The searchable-encryption steps of the DynamoDB operations:
//! beacons added to written items, and queries and scans rewritten onto beacons.

use std::collections::HashMap;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::ddb::Item;
use crate::ddb::number::str_to_int;
use crate::error::{Error, val_err};
use crate::search::beacon::MaybeKeyId;
use crate::search::filter::{ExprContext, uses_encrypted_field};
use crate::search::info::SearchInfo;
use crate::search::key_source::KeyLocation;
use crate::search::partition::GetPartitionNumberInput;
use crate::types::CryptoAction;

/// The expression value naming the beacon partition a query reads.
pub(crate) const PARTITION_NAME: &str = ":aws_dbe_partition";
/// The attribute written to every item of a table with beacons.
const VERSION_TAG: &str = "aws_dbe_v_1";

type Values = HashMap<String, AttributeValue>;

impl SearchInfo {
    /// The partition `item` is written in, as the partition selector picks it.
    ///
    /// # Errors
    ///
    /// The selector's error, or a `Validation` error when the selector
    /// returns a partition that is not less than the number of partitions.
    pub(crate) async fn get_partition(
        &self,
        item: &Item,
        logical_table_name: &str,
    ) -> Result<u8, Error> {
        let num = self.version.max_partitions;
        if num <= 1 {
            return Ok(0);
        }

        //= spec/searchable-encryption/search-config.md#partition-selector
        //# GetPartitionNumber MUST take as input
        let input = GetPartitionNumberInput::builder()
            .set_item(Some(item.clone()))
            .number_of_partitions(num)
            .logical_table_name(logical_table_name)
            .build()?;

        //= spec/dynamodb-encryption-client/ddb-support.md#getencryptedbeacons
        //# A [partition number](search-config.md#partitionnumber) MUST be generated
        //# by calling the [partition selector](search-config.md#partition-selector).
        let partition = self
            .version
            .partition_selector
            .get_partition_number(input)
            .await?
            .partition_number();
        if partition >= num {
            return Err(val_err(format!(
                "Partition Selector returned {partition} which should have been no more than {num}"
            )));
        }
        Ok(partition)
    }

    /// `item` with its signed beacons and the version tag added,
    /// and the beacon key field removed when it is not configured.
    ///
    /// # Errors
    ///
    /// A `Validation` error when `item` already has a signed beacon with a different value.
    pub(crate) fn add_signed_beacons(&self, mut item: Item, partition: u8) -> Result<Item, Error> {
        let version = &self.version;

        //= spec/dynamodb-encryption-client/ddb-support.md#addsignedbeacons
        //= reason=generate_signed_beacons keeps only the beacons that are not encrypted
        //# AddSignedBeacons MUST only operate on [compound beacons](../searchable-encryption/beacons.md#compound-beacon)
        //# that do not have any [encrypted parts](../searchable-encryption/beacons.md#compound-beacon-initialization).
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#addsignedbeacons
        //# The value of this attribute MUST be a string,
        //# and must have the value defined in [beacons](../searchable-encryption/beacons.md#beacon-value).
        let new_attrs = version.generate_signed_beacons(&item, partition)?;
        if new_attrs
            .iter()
            .any(|(k, v)| item.get(k).is_some_and(|i| i != v))
        {
            //= spec/dynamodb-encryption-client/ddb-support.md#addsignedbeacons
            //# If the attribute NAME already exists,
            //# if the constructed compound beacon does not match
            //# the existing attribute value AddSignedBeacons MUST fail.
            return Err(val_err(
                "Signed beacons have generated values different from supplied values.",
            ));
        }

        //= spec/dynamodb-encryption-client/ddb-support.md#handlebeaconkeyfieldname
        //= type=implication
        //= reason=Only a multi key store has a key field name, so no other key source gets here
        //# The [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
        //# MUST be [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
        //# or HandleBeaconKeyFieldName MUST fail.
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#handlebeaconkeyfieldname
        //= type=exception
        //= reason=The write-side beacon key id is the branch key id in the encrypt header (key_id_from_header), not this attribute
        //# If the AttributeMap does not have a key
        //# equal to [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
        //# HandleBeaconKeyFieldName MUST return a `beacon key id` of None
        //# and the unaltered AttributeMap.
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#handlebeaconkeyfieldname
        //= type=exception
        //= reason=The write-side beacon key id is the branch key id in the encrypt header (key_id_from_header), not this attribute
        //# If the AttributeMap does have a key
        //# equal to [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
        //# then the `beacon key id` MUST be the value of this Attribute.
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#handlebeaconkeyfieldname
        //= reason=delete_key is false for SIGN_ONLY (should_delete_key_field), so the field is kept
        //# If there is an [Attribute Action](./ddb-table-encryption-config.md#attribute-actions)
        //# configured for the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
        //# and that action is [SIGN_ONLY](../structured-encryption/structures.md#sign_only)
        //# HandleBeaconKeyFieldName MUST return the `beacon key id`
        //# and the unaltered AttributeMap.
        if let KeyLocation::Multi {
            key_field_name,
            delete_key: true,
        } = &version.key_source.location
        {
            //= spec/dynamodb-encryption-client/ddb-support.md#handlebeaconkeyfieldname
            //= reason=delete_key is true when the field has no action or DO_NOTHING (should_delete_key_field)
            //# If there is not an [Attribute Action](./ddb-table-encryption-config.md#attribute-actions)
            //# configured for the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
            //# HandleBeaconKeyFieldName MUST remove the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
            //# from the AttributeMap and return the `beacon key id` and the altered AttributeMap.
            //
            //= spec/dynamodb-encryption-client/ddb-support.md#handlebeaconkeyfieldname
            //= reason=delete_key is true when the field has no action or DO_NOTHING (should_delete_key_field)
            //# If there is an [Attribute Action](./ddb-table-encryption-config.md#attribute-actions)
            //# configured for the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
            //# and that action is [DO_NOTHING](../structured-encryption/structures.md#do_nothing)
            //# HandleBeaconKeyFieldName MUST remove the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
            //# from the AttributeMap and return the `beacon key id` and the altered AttributeMap.
            item.remove(key_field_name);
        }

        //= spec/dynamodb-encryption-client/ddb-support.md#addsignedbeacons
        //# For every configured compound beacons which only contains non encrypted parts
        //# that can be successfully built from the attributes in the input AttributeMap,
        //# AddSignedBeacons MUST add an attribute named NAME,
        //# where NAME is the name of the beacon.
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#addsignedbeacons
        //= reason=new_attrs are added to the input map; only an unconfigured beacon key field is removed
        //# The result of AddSignedBeacons MUST be a super set of everything in the input AttributeMap.
        item.extend(new_attrs);

        //= spec/searchable-encryption/search-config.md#versioning
        //# In addition to the configured beacons, a [version tag](#version-tag) MUST also be written.
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#addsignedbeacons
        //# AddSignedBeacons MUST also add an attribute with name `aws_dbe_v_1` and whose value is a string containing a single space.
        item.insert(VERSION_TAG.to_owned(), AttributeValue::S(" ".to_owned()));
        Ok(item)
    }

    /// The beacons of the encrypted fields of `item`.
    pub(crate) async fn get_encrypted_beacons(
        &self,
        item: &Item,
        key_id: &MaybeKeyId,
        partition: u8,
    ) -> Result<Item, Error> {
        //= spec/dynamodb-encryption-client/ddb-support.md#getencryptedbeacons
        //= reason=generate_encrypted_beacons gets the key map for the key id parsed from the encrypt header
        //# To obtain [Beacon Key Materials] GetEncryptedBeacons
        //# MUST call [Get beacon key after encrypt](../searchable-encryption/search-config.md#get-beacon-key-after-encrypt).
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#getencryptedbeacons
        //= reason=generate_encrypted_beacons skips the beacons that are not encrypted
        //# GetEncryptedBeacons MUST NOT operate on [compound beacons](../searchable-encryption/beacons.md#compound-beacon)
        //# that only have [signed parts](../searchable-encryption/beacons.md#compound-beacon-initialization).
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#getencryptedbeacons
        //# For all other configured beacons
        //# that can be successfully built from the attributes in the input AttributeMap,
        //# GetEncryptedBeacons MUST add an attribute named aws_dbe_b_NAME,
        //# where NAME is the name of the beacon.
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#getencryptedbeacons
        //# The value of this attribute MUST be a string,
        //# and must have the value defined in [beacons](../searchable-encryption/beacons.md#beacon-value)
        //
        //= spec/dynamodb-encryption-client/ddb-support.md#getencryptedbeacons
        //= reason=Every encrypted beacon is named aws_dbe_b_NAME, a prefix configured attributes cannot use
        //# The result of GetEncryptedBeacons MUST NOT contain any keys
        //# in the [Encrypt Item Output](./encrypt-item.md#output) AttributeMap.
        self.version
            .generate_encrypted_beacons(item, key_id, partition)
            .await
    }

    /// Whether the beacon key source has a key per item, named in the item.
    pub(crate) const fn is_multi_key(&self) -> bool {
        matches!(self.version.key_source.location, KeyLocation::Multi { .. })
    }

    /// The values without the partition value, and the partition a query reads.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the partition value is malformed or out of range,
    /// is given though there is one partition,
    /// or is missing though there are several and the query reads an encrypted field.
    pub(crate) fn extract_partition(
        &self,
        key_expr: Option<&str>,
        filter_expr: Option<&str>,
        names: Option<&HashMap<String, String>>,
        values: Option<Values>,
        actions: &HashMap<String, CryptoAction>,
    ) -> Result<(Option<Values>, u8), Error> {
        let num = self.version.max_partitions;
        if num <= 1 {
            if values
                .as_ref()
                .is_some_and(|v| v.contains_key(PARTITION_NAME))
            {
                return Err(val_err(format!(
                    "If no partitions are configured, do not specify {PARTITION_NAME}"
                )));
            }
            return Ok((values, 0));
        }

        //= spec/dynamodb-encryption-client/ddb-support.md#queryinputforbeacons
        //# When querying, a [partition number](search-config.md#partitionnumber) MUST be determined by examining
        //# the `:aws_dbe_partition` value in the `ExpressionAttributeValues`.
        if let Some(v) = values.as_ref()
            && let Some(p) = v.get(PARTITION_NAME)
        {
            let partition = get_partition_value(p, num)?;
            let mut v = values.unwrap_or_default();

            //= spec/dynamodb-encryption-client/ddb-support.md#queryinputforbeacons
            //# If this value is valid, then this value is used and the `:aws_dbe_partition` field MUST
            //# be removed from the `ExpressionAttributeValues`.
            v.remove(PARTITION_NAME);
            let v = (!v.is_empty()).then_some(v);
            return Ok((v, partition));
        }
        if uses_encrypted_field(key_expr, actions, names).is_some()
            || uses_encrypted_field(filter_expr, actions, names).is_some()
        {
            return Err(val_err(format!(
                "When numberOfPartitions is greater than one, Values must contain {PARTITION_NAME}"
            )));
        }

        //= spec/dynamodb-encryption-client/ddb-support.md#queryinputforbeacons
        //= reason=Deviation, as in the reference: with several partitions, a query on an ENCRYPT_AND_SIGN field errors above instead
        //# If this value is absent, a partition number of `0` MUST be used.
        Ok((values, 0))
    }

    /// Rewrite a query's key condition and filter onto beacons.
    pub(crate) async fn query_input_for_beacons(
        &self,
        actions: &HashMap<String, CryptoAction>,
        key_expr: Option<String>,
        filter_expr: Option<String>,
        names: Option<HashMap<String, String>>,
        values: Option<Values>,
    ) -> Result<ExprContext, Error> {
        let version = &self.version;
        let key_id = version.get_beacon_key_id(
            key_expr.as_deref(),
            filter_expr.as_deref(),
            values.as_ref(),
            names.as_ref(),
        )?;
        let (new_values, partition) = self.extract_partition(
            key_expr.as_deref(),
            filter_expr.as_deref(),
            names.as_ref(),
            values.clone(),
            actions,
        )?;
        let num_queries = version.get_num_queries(key_expr.as_deref(), values.as_ref())?;
        if num_queries <= partition {
            return Err(val_err(format!(
                "Partition number was {partition} but should have been less than number of queries : {num_queries}"
            )));
        }
        let context = ExprContext {
            key_expr,
            filter_expr,
            values: new_values,
            names,
        };
        version
            .do_beaconize(&context, &key_id, partition, num_queries)
            .await
    }

    /// Rewrite a scan's filter onto beacons.
    pub(crate) async fn scan_input_for_beacons(
        &self,
        filter_expr: Option<String>,
        names: Option<HashMap<String, String>>,
        values: Option<Values>,
    ) -> Result<ExprContext, Error> {
        let version = &self.version;
        let key_id = version.get_beacon_key_id(
            None,
            filter_expr.as_deref(),
            values.as_ref(),
            names.as_ref(),
        )?;
        if values
            .as_ref()
            .is_some_and(|v| v.contains_key(PARTITION_NAME))
        {
            return Err(val_err(format!(
                "A value for {PARTITION_NAME} must not be specified for Scan operations."
            )));
        }
        let context = ExprContext {
            key_expr: None,
            filter_expr,
            values,
            names,
        };
        version.do_beaconize(&context, &key_id, 0, 1).await
    }
}

/// The partition that `val`, the value of `:aws_dbe_partition`, names
/// when the table has `num` partitions.
fn get_partition_value(val: &AttributeValue, num: u8) -> Result<u8, Error> {
    let problem = match val {
        AttributeValue::N(n) => match str_to_int(n) {
            Ok(v) => match u8::try_from(v) {
                Ok(partition) if partition < num => return Ok(partition),
                _ if (0..i128::from(i32::MAX)).contains(&v) => format!(
                    "{PARTITION_NAME} specified in FilterExpression was {v} must be less than the number of partitions: {num}"
                ),
                _ => format!("Value of {PARTITION_NAME} out of range."),
            },
            Err(e) => e,
        },
        _ => format!("Value of {PARTITION_NAME} is not numeric (i.e. 'N')"),
    };

    //= spec/dynamodb-encryption-client/ddb-support.md#queryinputforbeacons
    //# If this value is not of type `N` or fails to hold an integer value
    //# greater than or equal to zero and less than the [max partitions](search-config.md#max-partitions),
    //# an error MUST be returned.
    Err(val_err(problem))
}

#[cfg(test)]
#[path = "support_tests.rs"]
mod tests;
