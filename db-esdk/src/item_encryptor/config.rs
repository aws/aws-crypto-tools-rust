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
use crate::table_config::{Materials, TableConfig};
use crate::types::{AlgorithmSuiteId, CryptoAction, PlaintextOverride};

const TABLE_NAME: &str = "aws-crypto-table-name";
const PARTITION_NAME: &str = "aws-crypto-partition-name";
const SORT_NAME: &str = "aws-crypto-sort-name";

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
    names.is_some_and(|n| n.iter().any(|x| x == attr))
        || prefix.is_some_and(|p| attr.starts_with(p))
        || attr.starts_with(RESERVED_PREFIX)
}

fn version_from_actions(actions: &HashMap<String, CryptoAction>) -> u8 {
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
    if version == 2 {
        CryptoAction::SignAndIncludeInEncryptionContext
    } else {
        CryptoAction::SignOnly
    }
}

impl Config {
    /// Validate `table` as the configuration of table `name`.
    pub(crate) fn new(name: String, table: TableConfig) -> Result<Self, Error> {
        let actions = &table.attribute_actions_on_encrypt;
        let version = version_from_actions(actions);
        let key_action = key_action(version);
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
            Materials::Keyring(k) => SharedCmm::new(DefaultCmm::new(k)),
        };
        Ok(Self {
            version,
            logical_table_name: table.logical_table_name.unwrap_or(name),
            partition_key_name: table.partition_key_name,
            sort_key_name: table.sort_key_name,
            cmm,
            attribute_actions_on_encrypt: table.attribute_actions_on_encrypt,
            allowed_unsigned_attributes: table.allowed_unsigned_attributes,
            allowed_unsigned_attribute_prefix: table.allowed_unsigned_attribute_prefix,
            algorithm_suite_id: table.algorithm_suite_id,
            plaintext_override: table.plaintext_override.unwrap_or_default(),
        })
    }

    /// Whether `attr` is covered by the signature.
    pub(crate) fn in_signature_scope(&self, attr: &str) -> bool {
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
        for k in item.keys() {
            if let Some(a) = self.attribute_actions_on_encrypt.get(k) {
                out.insert(k.clone(), *a);
            } else if !self.in_signature_scope(k) {
                out.insert(k.clone(), CryptoAction::DoNothing);
            } else {
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
        item.keys()
            .map(|k| {
                let action = if self.in_signature_scope(k) {
                    AuthAction::Sign
                } else {
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
            msg.push_str(&format!(
                "Partition key '{}' does not exist in item. ",
                self.partition_key_name
            ));
        }
        if let Some(s) = self.sort_key_name.as_ref().filter(|_| sk_missing) {
            msg.push_str(&format!("Sort key '{s}' does not exist in item. "));
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
        msg.push_str(&format!("Item contains these attributes : {names}."));
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
        ec.insert(TABLE_NAME, self.logical_table_name.as_str());
        ec.insert(PARTITION_NAME, self.partition_key_name.as_str());
        if version == 1 {
            ec.insert(
                format!("{ATTR_PREFIX}{}", self.partition_key_name),
                pk.encode(),
            );
        }
        if let Some(sort) = &self.sort_key_name {
            let sk = item.get(sort).ok_or_else(|| {
                val_err(format!(
                    "Sort key {sort} not found in Item to be encrypted or decrypted"
                ))
            })?;
            ec.insert(SORT_NAME, sort.as_str());
            if version == 1 {
                ec.insert(format!("{ATTR_PREFIX}{sort}"), sk.encode());
            }
        }
        Ok(ec)
    }
}
