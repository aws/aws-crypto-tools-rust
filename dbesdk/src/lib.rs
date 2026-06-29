// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native Rust AWS Database Encryption SDK for DynamoDB (DB-ESDK).
//!
//! This crate is being ported from the Dafny reference implementation in
//! `aws-database-encryption-sdk-dynamodb` and validated against the
//! cross-language TestServer conformance suite (the Java JUnit suite drives a
//! Rust Language_Server over rpcv2Cbor).
//!
//! # Layout
//!
//! * [`model`] — the DynamoDB item / attribute-value types and their canonical
//!   binary serialization.
//! * [`config`] — the per-table encryption configuration (attribute actions,
//!   keyring, algorithm suite) a `CreateClient` call supplies.
//! * [`crypto`] — low-level AES-GCM / HKDF / HMAC primitives over `aws-lc-rs`.
//! * [`format`] — the byte-faithful DB-ESDK structured-encryption format (the
//!   real wire format the canonical Java/Dafny DB-ESDK reads and writes), for
//!   both DBE algorithm suites. The keyring-specific portion of intermediate
//!   key wrapping is abstracted behind
//!   [`format::IntermediateKeyProvider`] (a Raw AES provider ships here; the
//!   AWS KMS provider lives in the TestServer adapter).
//!
//! # State
//!
//! The only encryption path is the byte-faithful [`format`] module, a direct
//! port of the Dafny `StructuredEncryption` + MPL `IntermediateKeyWrapping`
//! reference. The earlier home-grown, self-consistent-only encryptor was
//! removed: it produced bytes no other DB-ESDK runtime could read, so it could
//! never pass the cross-language conformance cells. Raw AES and single-key AWS
//! KMS (`awsKms` / `awsKmsMrk`) keyrings are implemented under both suites;
//! remaining keyrings (KMS RSA/ECDH/multi/discovery, Raw RSA/ECDH, hierarchical)
//! await their own intermediate-key providers (see `BLOCKED.md`) and are
//! rejected by the server until then.
//!
//! The [`ClientRegistry`] binds a configured set of
//! [`config::TableEncryptionConfig`]s to a unique [`ClientId`] for the
//! TestServer `CreateClient` contract; `WriteItem` / `ReadItem` resolve the
//! client by that id.

pub mod config;
pub mod crypto;
pub mod error;
pub mod format;
pub mod model;

pub use error::{DbEsdkError, Result};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use config::TableEncryptionConfig;

/// A unique, non-empty identifier for a constructed client, mirroring the
/// model's `@length(min: 1) string ClientId`.
pub type ClientId = String;

/// The configuration of a constructed Enhanced Client: the per-physical-table
/// encryption configuration the client encrypts and decrypts items with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientConfig {
    /// Physical DynamoDB table name -> its encryption configuration.
    pub table_configs: HashMap<String, TableEncryptionConfig>,
}

impl ClientConfig {
    /// Construct a config from the per-table encryption configurations.
    pub fn new(table_configs: HashMap<String, TableEncryptionConfig>) -> Self {
        Self { table_configs }
    }

    /// Resolve the encryption configuration for a physical table name.
    pub fn table(&self, table_name: &str) -> Option<&TableEncryptionConfig> {
        self.table_configs.get(table_name)
    }

    /// The physical table names this client is configured for.
    pub fn table_names(&self) -> Vec<String> {
        self.table_configs.keys().cloned().collect()
    }
}

/// A thread-safe registry of constructed clients, keyed by [`ClientId`].
///
/// `CreateClient` calls [`register`](Self::register) to bind a freshly built
/// client config to a new id; `WriteItem` / `ReadItem` call [`get`](Self::get)
/// to resolve the client for a supplied id (an unknown id is a server error the
/// handler surfaces as a structured `GenericServerError`).
#[derive(Debug, Default)]
pub struct ClientRegistry {
    inner: Mutex<HashMap<ClientId, Arc<ClientConfig>>>,
}

impl ClientRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Register `config` under a freshly generated, non-empty [`ClientId`] and
    /// return that id.
    pub fn register(&self, config: ClientConfig) -> ClientId {
        let id = uuid::Uuid::new_v4().to_string();
        self.inner
            .lock()
            .expect("ClientRegistry mutex poisoned")
            .insert(id.clone(), Arc::new(config));
        id
    }

    /// Resolve the client config previously bound to `id`, if any.
    pub fn get(&self, id: &str) -> Option<Arc<ClientConfig>> {
        self.inner
            .lock()
            .expect("ClientRegistry mutex poisoned")
            .get(id)
            .cloned()
    }

    /// Number of currently registered clients.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("ClientRegistry mutex poisoned")
            .len()
    }

    /// Whether the registry holds no clients.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AesWrappingAlg, AlgorithmSuiteId, KeyringConfig, RawAesKeyringConfig, TableEncryptionConfig,
    };
    use std::collections::BTreeMap;

    fn sample_config(table: &str) -> ClientConfig {
        let table_config = TableEncryptionConfig {
            logical_table_name: table.to_string(),
            partition_key_name: "partition_key".to_string(),
            sort_key_name: None,
            attribute_actions: BTreeMap::new(),
            allowed_unsigned_attributes: Vec::new(),
            allowed_unsigned_attribute_prefix: None,
            algorithm_suite_id: AlgorithmSuiteId::default_suite(),
            keyring: KeyringConfig::RawAes(RawAesKeyringConfig {
                key_namespace: "ns".to_string(),
                key_name: "k".to_string(),
                wrapping_key: vec![0u8; 32],
                wrapping_alg: AesWrappingAlg::Aes256,
            }),
        };
        let mut configs = HashMap::new();
        configs.insert(table.to_string(), table_config);
        ClientConfig::new(configs)
    }

    #[test]
    fn register_returns_non_empty_unique_ids() {
        let registry = ClientRegistry::new();
        assert!(registry.is_empty());

        let id1 = registry.register(sample_config("TableA"));
        let id2 = registry.register(sample_config("TableB"));

        assert!(!id1.is_empty(), "ClientId must be non-empty");
        assert!(!id2.is_empty(), "ClientId must be non-empty");
        assert_ne!(id1, id2, "each CreateClient must yield a distinct id");
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn get_resolves_registered_client_and_misses_unknown() {
        let registry = ClientRegistry::new();
        let id = registry.register(sample_config("T"));

        let resolved = registry.get(&id).expect("registered id must resolve");
        assert!(resolved.table("T").is_some());
        assert!(registry.get("not-a-real-id").is_none());
    }
}
