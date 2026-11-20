// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The item encryptor's configuration: one table, validated once.

use std::collections::HashMap;

use aws_crypto_mpl::cmm::{DefaultCmm, SharedCmm};
use aws_crypto_mpl::types::EncryptionContext;

use crate::ddb::Item;
use crate::error::{Error, val_err};
use crate::structured::util::{
    ATTR_PREFIX, AuthAction, RESERVED_CRYPTO_CONTEXT_PREFIX, RESERVED_PREFIX, Terminal, utf16_cmp,
};
use crate::table_config::{Materials, TableConfig, check_table_name};
use crate::types::{AlgorithmSuiteId, CryptoAction, PlaintextOverride};

pub(crate) const TABLE_NAME: &str = "aws-crypto-table-name";
pub(crate) const PARTITION_NAME: &str = "aws-crypto-partition-name";
pub(crate) const SORT_NAME: &str = "aws-crypto-sort-name";

/// A table configuration resolved for encrypting and decrypting items.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) version: u8,
    pub(crate) logical_table_name: String,
    pub(crate) partition_key_name: String,
    pub(crate) sort_key_name: Option<String>,
    pub(crate) cmm: SharedCmm,
    pub(crate) attribute_actions_on_encrypt: HashMap<String, CryptoAction>,
    pub(crate) allowed_unsigned_attributes: Option<Vec<String>>,
    pub(crate) allowed_unsigned_attribute_prefix: Option<String>,
    pub(crate) algorithm_suite_id: Option<AlgorithmSuiteId>,
    pub(crate) plaintext_override: PlaintextOverride,
}

const fn action_str(action: CryptoAction) -> &'static str {
    match action {
        CryptoAction::DoNothing => "DO_NOTHING",
        CryptoAction::SignOnly => "SIGN_ONLY",
        CryptoAction::SignAndIncludeInEncryptionContext => "SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT",
        CryptoAction::EncryptAndSign => "ENCRYPT_AND_SIGN",
    }
}

fn allowed_unsigned(names: Option<&[String]>, prefix: Option<&str>, attr: &str) -> bool {
    //= spec/dynamodb-encryption-client/decrypt-item.md#signature-scope
    //# An Attribute on a DynamoDB Item MUST NOT be considered as within the signature scope
    //# if it's Attribute Name is included in [Unauthenticated Attributes](./ddb-table-encryption-config.md#unauthenticated-attributes)
    //# or if it's Attribute Name begins with the prefix specified in
    //# [Unauthenticated Attribute Prefix](./ddb-table-encryption-config.md#unauthenticated-attribute-prefix).
    names.is_some_and(|n| n.iter().any(|x| x == attr))
        || prefix.is_some_and(|p| attr.starts_with(p))
        || attr.starts_with(RESERVED_PREFIX)
}

fn version_from_actions(actions: &HashMap<String, CryptoAction>) -> u8 {
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#configuration-version
    //# If any of the [Attribute Actions](#attribute-actions) are configured as
    //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign)
    //# then the configuration version MUST be 2; otherwise,
    //# the configuration version MUST be 1.
    if actions
        .values()
        .any(|a| *a == CryptoAction::SignAndIncludeInEncryptionContext)
    {
        2
    } else {
        1
    }
}

const fn key_action(version: u8) -> CryptoAction {
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#key-action
    //# if the [configuration version](#configuration-version) is 2, then
    //# the key action MUST be [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign);
    //# otherwise, the key action MUST be [SIGN_ONLY](../structured-encryption/structures.md#signonly).
    if version == 2 {
        CryptoAction::SignAndIncludeInEncryptionContext
    } else {
        CryptoAction::SignOnly
    }
}

impl Config {
    /// Validate `table` as the configuration of table `name`.
    ///
    /// A `Validation` error when `name` has fewer than 3 or more than 255 characters,
    /// or when the attribute actions of `table` are invalid,
    /// for example a key attribute with the wrong action.
    pub(crate) fn new(name: String, table: TableConfig) -> Result<Self, Error> {
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#dynamodb-table-name
        //# This Table Name MUST be a valid DynamoDB Table Name.
        check_table_name(&name)?;
        let actions = &table.attribute_actions_on_encrypt;
        let version = version_from_actions(actions);
        let key_action = key_action(version);
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#attribute-actions
        //# The [Key Action](#key-action)
        //# MUST be configured to the partition attribute and, if present, sort attribute.
        if actions.get(&table.partition_key_name) != Some(&key_action) {
            return Err(val_err(format!(
                "Partition key attribute action MUST be {}",
                action_str(key_action)
            )));
        }
        if let Some(sort) = &table.sort_key_name
            && actions.get(sort) != Some(&key_action)
        {
            return Err(val_err(format!(
                "Sort key attribute action MUST be {}",
                action_str(key_action)
            )));
        }
        let names = table.allowed_unsigned_attributes.as_deref();
        let prefix = table.allowed_unsigned_attribute_prefix.as_deref();
        let mut attribute_names: Vec<&String> = actions.keys().collect();
        attribute_names.sort_by(|a, b| utf16_cmp(a, b));
        for attr in attribute_names {
            let action = actions[attr];
            let unsigned = allowed_unsigned(names, prefix, attr);
            if (action == CryptoAction::DoNothing) != unsigned {
                let why = if action == CryptoAction::DoNothing {
                    "it must also be in unauthenticatedAttributes or begin with the unauthenticatedPrefix."
                } else if names.is_some_and(|n| n.iter().any(|x| x == attr)) {
                    "it is also in unauthenticatedAttributes."
                } else if prefix.is_some_and(|p| attr.starts_with(p)) {
                    "it also begins with the unauthenticatedPrefix."
                } else {
                    "it also begins with the reserved prefix."
                };

                //= spec/dynamodb-encryption-client/decrypt-item.md#signature-scope
                //# If an Authenticate Action other than DO_NOTHING is configured for an attribute name included in [Unauthenticated Attributes](./ddb-table-encryption-config.md#unauthenticated-attributes)
                //# or beginning with the prefix specified in [Unauthenticated Attribute Prefix](./ddb-table-encryption-config.md#unauthenticated-attribute-prefix),
                //# this operation MUST yield an error.
                return Err(val_err(format!(
                    "Attribute {attr} is configured as {} but {why}",
                    action_str(action)
                )));
            }
            if attr.starts_with(RESERVED_PREFIX) || attr.starts_with(RESERVED_CRYPTO_CONTEXT_PREFIX)
            {
                return Err(val_err(format!(
                    "Attribute: {attr} is reserved, and may not be configured."
                )));
            }
        }
        let cmm = match table.materials {
            Materials::Cmm(c) => c,
            //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#cmm
            //# If not supplied during initialization,
            //# the CMM considered "configured" to this
            //# Item Encryptor MUST be a
            //# [default CMM](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md)
            //# constructed using the [supplied keyring](#keyring) as input.
            Materials::Keyring(k) => SharedCmm::new(DefaultCmm::new(k)),
        };
        Ok(Self {
            version,
            //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
            //= reason=Every Config has a logical name; an unset one defaults to the physical table name
            //# - [Logical Table Name](#logical-table-name)
            logical_table_name: table.logical_table_name.unwrap_or(name),
            partition_key_name: table.partition_key_name,
            sort_key_name: table.sort_key_name,
            cmm,
            attribute_actions_on_encrypt: table.attribute_actions_on_encrypt,
            allowed_unsigned_attributes: table.allowed_unsigned_attributes,
            allowed_unsigned_attribute_prefix: table.allowed_unsigned_attribute_prefix,
            algorithm_suite_id: table.algorithm_suite_id,
            //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#plaintext-policy
            //# If not specified, encryption and decryption MUST behave according to `FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ`.
            plaintext_override: table.plaintext_override.unwrap_or_default(),
        })
    }

    /// Whether the signature covers `attr`.
    pub(crate) fn in_signature_scope(&self, attr: &str) -> bool {
        //= spec/dynamodb-encryption-client/decrypt-item.md#signature-scope
        //# Otherwise, Attributes MUST be considered as within the signature scope.
        !allowed_unsigned(
            self.allowed_unsigned_attributes.as_deref(),
            self.allowed_unsigned_attribute_prefix.as_deref(),
            attr,
        )
    }

    /// The action of each attribute of `item`.
    pub(crate) fn crypto_schema(
        &self,
        item: &HashMap<String, Terminal>,
    ) -> Result<HashMap<String, CryptoAction>, Error> {
        let mut errors = Vec::new();
        let mut out = HashMap::with_capacity(item.len());

        //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
        //# - The Crypto Schema MUST NOT contain more Crypto Actions than those specified by the previous point.
        for k in item.keys() {
            if let Some(a) = self.attribute_actions_on_encrypt.get(k) {
                //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
                //# - For every attribute on the input Item,
                //# there MUST exist a Crypto Action in the Crypto Schema
                //# such that the Crypto Action indexed by that attribute name in the Crypto Schema
                //# equals the Crypto Action indexed by that attribute name in the configured Attribute Actions.
                out.insert(k.clone(), *a);
            } else if !self.in_signature_scope(k) {
                out.insert(k.clone(), CryptoAction::DoNothing);
            } else {
                //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
                //# The [Attributes Actions](./ddb-table-encryption-config.md#attribute-actions)
                //# configured on this Item Encryptor MUST specify a Crypto Action
                //# for every attribute in the [input DynamoDB Item](#dynamodb-item)
                //# (Attribute Actions MAY specify a Crypto Action for an attribute not
                //# in the input DynamoDB Item).
                errors.push(format!("No Crypto Action configured for attribute {k}"));
            }
        }
        if errors.is_empty() {
            Ok(out)
        } else {
            errors.sort();
            Err(val_err(errors.join("\n")))
        }
    }

    /// Whether each attribute of `item` is signed.
    pub(crate) fn authenticate_schema(
        &self,
        item: &HashMap<String, Terminal>,
    ) -> HashMap<String, AuthAction> {
        //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
        //# - The number of Authenticate Actions in the Authenticate Schema
        //# MUST EQUAL the number of Attributes on the [input DynamoDB Item](#input-dynamodb-item).
        item.keys()
            .map(|k| {
                let action = if self.in_signature_scope(k) {
                    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
                    //# - For every Attribute in the [input DynamoDB Item](#input-dynamodb-item)
                    //# that is in the [signature scope](#signature-scope),
                    //# there MUST exist a [SIGN Authenticate Action](../structured-encryption/structures.md#sign)
                    //# in the Authenticate Schema,
                    //# string indexed at the top level by that attribute name.
                    AuthAction::Sign
                } else {
                    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
                    //# - For every Attribute in the [input DynamoDB Item](#input-dynamodb-item)
                    //# that is not in the [signature scope](#signature-scope),
                    //# there MUST exist a [DO_NOT_SIGN Authenticate Action](../structured-encryption/structures.md#do_not_sign)
                    //# in the Authenticate Schema,
                    //# string indexed at the top level by that attribute name.
                    AuthAction::DoNotSign
                };
                (k.clone(), action)
            })
            .collect()
    }

    /// Why the item lacks its partition or sort key, or `None` when it has both.
    pub(crate) fn key_missing(&self, item: &Item, tag: &str) -> Option<String> {
        let pk_missing = !item.contains_key(&self.partition_key_name);
        let sk_missing = self
            .sort_key_name
            .as_ref()
            .is_some_and(|s| !item.contains_key(s));
        if !pk_missing && !sk_missing {
            return None;
        }
        let mut msg = format!("On {tag} : ");
        if pk_missing {
            msg.push_str("Partition key '");
            msg.push_str(&self.partition_key_name);
            msg.push_str("' does not exist in item. ");
        }
        if let Some(s) = self.sort_key_name.as_ref().filter(|_| sk_missing) {
            msg.push_str("Sort key '");
            msg.push_str(s);
            msg.push_str("' does not exist in item. ");
        }
        let mut names: Vec<&String> = item.keys().collect();
        names.sort_by(|a, b| utf16_cmp(a, b));
        let names = if names.is_empty() {
            "item is empty".to_owned()
        } else {
            names
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };
        msg.push_str("Item contains these attributes : ");
        msg.push_str(&names);
        msg.push('.');
        Some(msg)
    }

    /// Why a `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT` attribute is missing from the item,
    /// or `None` when none is.
    pub(crate) fn context_missing(&self, item: &Item) -> Option<String> {
        let mut missing: Vec<&String> = self
            .attribute_actions_on_encrypt
            .iter()
            .filter(|(k, a)| {
                **a == CryptoAction::SignAndIncludeInEncryptionContext && !item.contains_key(*k)
            })
            .map(|(k, _)| k)
            .collect();
        missing.sort_by(|a, b| utf16_cmp(a, b));
        match missing.as_slice() {
            [] => None,
            [one] => Some(format!(
                "Attribute {one} was configured with SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT but was not present in item to be encrypted."
            )),
            many => Some(format!(
                "These attributes were configured with SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT but were not present in item to be encrypted.{}",
                many.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            )),
        }
    }

    /// The encryption context of an item written with header `version`.
    pub(crate) fn encryption_context(
        &self,
        version: u8,
        item: &HashMap<String, Terminal>,
    ) -> Result<EncryptionContext, Error> {
        let pk = item.get(&self.partition_key_name).ok_or_else(|| {
            val_err(format!(
                "Partition key {} not found in Item to be encrypted or decrypted",
                self.partition_key_name
            ))
        })?;
        let mut ec = EncryptionContext::new();

        //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-1
        //# The DynamoDB Item Base Context MUST contain:
        //
        //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-2
        //= reason=The table name entry is the logical table name, as in the Dafny DB-ESDK
        //# The DynamoDB Item Base Context MUST contain:
        ec.insert(TABLE_NAME, self.logical_table_name.as_str());
        ec.insert(PARTITION_NAME, self.partition_key_name.as_str());
        if version == 1 {
            ec.insert(
                //= spec/dynamodb-encryption-client/encrypt-item.md#base-context-value-version-1
                //# The key MUST be as per [Encryption Context Naming]
                //# (../structured-encryption/encrypt-path-structure.md#encryption-context-naming).
                //
                //= spec/structured-encryption/encrypt-path-structure.md#encryption-context-naming
                //# When a key-value pair is added to the encryption context,
                //# the key MUST be the concatenation of the literal
                //# "aws-crypto-attr." and the member strings of the
                //# path joined by the '.' character.
                format!("{ATTR_PREFIX}{}", self.partition_key_name),
                pk.encode(),
            );
        }

        //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-1
        //# If this item does not have a sort key attribute,
        //# the DynamoDB Item Context MUST NOT contain the key `aws-crypto-sort-name`.
        //
        //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-2
        //# If this item does not have a sort key attribute,
        //# the DynamoDB Item Context MUST NOT contain the key `aws-crypto-sort-name`.
        if let Some(sort) = &self.sort_key_name {
            let sk = item.get(sort).ok_or_else(|| {
                val_err(format!(
                    "Sort key {sort} not found in Item to be encrypted or decrypted"
                ))
            })?;

            //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-1
            //# If this item has a Sort Key attribute, the DynamoDB Item Base Context MUST contain:
            //
            //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-2
            //# If this item has a Sort Key attribute, the DynamoDB Item Base Context MUST contain:
            ec.insert(SORT_NAME, sort.as_str());
            if version == 1 {
                ec.insert(format!("{ATTR_PREFIX}{sort}"), sk.encode());
            }
        }
        Ok(ec)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_crypto_mpl::keyring::RawAesKeyring;
    use aws_crypto_mpl::types::AesWrappingAlg;

    use crate::structured::util::STRING;

    /// A V1 configuration: partition key `pk`, sort key `sk`, unsigned prefix `:`.
    pub(crate) fn config() -> Config {
        let keyring = RawAesKeyring::builder()
            .key_namespace("ns")
            .key_name("name")
            .wrapping_key(vec![0; 32])
            .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
            .build()
            .unwrap();
        let table = TableConfig::builder()
            .partition_key_name("pk")
            .sort_key_name("sk")
            .attribute_actions_on_encrypt("pk", CryptoAction::SignOnly)
            .attribute_actions_on_encrypt("sk", CryptoAction::SignOnly)
            .allowed_unsigned_attribute_prefix(":")
            .keyring(keyring)
            .build()
            .unwrap();
        Config::new("table".to_owned(), table).unwrap()
    }

    fn terminals(names: &[&str]) -> HashMap<String, Terminal> {
        names
            .iter()
            .map(|n| ((*n).to_owned(), Terminal::new(STRING, b"v".to_vec())))
            .collect()
    }

    fn message(err: Error) -> String {
        match err {
            Error::Validation(e) => e.message().to_owned(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn encryption_context_requires_both_keys() {
        let config = config();
        assert_eq!(
            message(
                config
                    .encryption_context(1, &terminals(&["sk"]))
                    .unwrap_err()
            ),
            "Partition key pk not found in Item to be encrypted or decrypted"
        );
        assert_eq!(
            message(
                config
                    .encryption_context(1, &terminals(&["pk"]))
                    .unwrap_err()
            ),
            "Sort key sk not found in Item to be encrypted or decrypted"
        );
    }

    #[test]
    fn version_2_context_leaves_out_key_values() {
        let ec = config()
            .encryption_context(2, &terminals(&["pk", "sk"]))
            .unwrap();
        let keys: Vec<&str> = ec.keys().collect();
        assert_eq!(
            keys,
            [PARTITION_NAME, SORT_NAME, TABLE_NAME],
            "only the names, no aws-crypto-attr. values"
        );
    }

    #[test]
    fn schemas_follow_the_signature_scope() {
        let config = config();
        let item = terminals(&["pk", ":free"]);
        let schema = config.crypto_schema(&item).unwrap();
        assert_eq!(schema["pk"], CryptoAction::SignOnly);
        assert_eq!(schema[":free"], CryptoAction::DoNothing);
        let auth = config.authenticate_schema(&item);
        assert_eq!(auth["pk"], AuthAction::Sign);
        assert_eq!(auth[":free"], AuthAction::DoNotSign);
    }
}
