// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The searchable-encryption steps of the DynamoDB operations:
//! beacons added to written items, and queries and scans rewritten onto beacons.

use std::collections::HashMap;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;
use aws_mpl_primitives::generate_random_bytes;

use crate::ddb::Item;
use crate::ddb::number::str_to_int;
use crate::error::{Error, val_err};
use crate::search::beacon::MaybeKeyId;
use crate::search::filter::{ExprContext, uses_encrypted_field};
use crate::search::info::SearchInfo;
use crate::search::key_source::KeyLocation;
use crate::types::CryptoAction;

/// The expression value naming the beacon partition a query reads.
pub(crate) const PARTITION_NAME: &str = ":aws_dbe_partition";
/// The attribute written to every item of a table with beacons.
const VERSION_TAG: &str = "aws_dbe_v_1";

type Values = HashMap<String, AttributeValue>;

impl SearchInfo {
    /// The partition an item is written in: random when there are several.
    pub(crate) fn random_partition(&self) -> Result<u8, Error> {
        let num = self.version.max_partitions;
        if num <= 1 {
            return Ok(0);
        }
        let mut rand = [0u8; 1];
        generate_random_bytes(&mut rand)?;
        Ok(rand[0] % num)
    }

    /// `item` with its signed beacons and the version tag added,
    /// and the beacon key field removed when it is not configured.
    ///
    /// # Errors
    ///
    /// A `Validation` error when `item` already has a signed beacon with a different value.
    pub(crate) fn add_signed_beacons(&self, mut item: Item, partition: u8) -> Result<Item, Error> {
        let version = &self.version;
        let new_attrs = version.generate_signed_beacons(&item, partition)?;
        if new_attrs
            .iter()
            .any(|(k, v)| item.get(k).is_some_and(|i| i != v))
        {
            return Err(val_err(
                "Signed beacons have generated values different from supplied values.",
            ));
        }
        if let KeyLocation::Multi {
            key_field_name,
            delete_key: true,
        } = &version.key_source.location
        {
            item.remove(key_field_name);
        }
        item.extend(new_attrs);
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
        if let Some(v) = values.as_ref()
            && let Some(p) = v.get(PARTITION_NAME)
        {
            let partition = get_number(p, PARTITION_NAME)?;
            if partition >= u32::from(num) {
                return Err(val_err(format!(
                    "{PARTITION_NAME} specified in FilterExpression was {partition} must be less than the number of partitions: {num}"
                )));
            }
            let mut v = values.unwrap_or_default();
            v.remove(PARTITION_NAME);
            let v = (!v.is_empty()).then_some(v);
            return Ok((v, u8::try_from(partition).unwrap_or(0)));
        }
        if uses_encrypted_field(key_expr, actions, names).is_some()
            || uses_encrypted_field(filter_expr, actions, names).is_some()
        {
            return Err(val_err(format!(
                "When numberOfPartitions is greater than one, Values must contain {PARTITION_NAME}"
            )));
        }
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

/// The non-negative 32-bit number `val` holds.
fn get_number(val: &AttributeValue, name: &str) -> Result<u32, Error> {
    let AttributeValue::N(n) = val else {
        return Err(val_err(format!(
            "Value of {name} is not numeric (i.e. 'N')"
        )));
    };
    let v = str_to_int(n).map_err(val_err)?;
    if (0..i128::from(i32::MAX)).contains(&v) {
        Ok(u32::try_from(v).unwrap_or(0))
    } else {
        Err(val_err(format!("Value of {name} out of range.")))
    }
}
