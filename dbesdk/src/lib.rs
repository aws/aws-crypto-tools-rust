// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native Rust AWS Database Encryption SDK for DynamoDB (DB-ESDK).
//!
//! This crate is being ported from the Dafny reference implementation in
//! `aws-database-encryption-sdk-dynamodb` and validated against the
//! cross-language TestServer conformance suite (the Java JUnit suite drives a
//! Rust Language_Server over rpcv2Cbor).
//!
//! # Milestone state
//!
//! M1 (current): the [`ClientRegistry`] models the TestServer `CreateClient`
//! contract — a configured Enhanced Client is constructed and bound to a unique,
//! non-empty [`ClientId`]; later `WriteItem` / `ReadItem` calls resolve the same
//! client by that id. The cryptographic item encrypt/decrypt path (attribute
//! actions, material description, signing) and the keyring wiring (reusing the
//! native Rust MPL crate) land in later milestones (M2+).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A unique, non-empty identifier for a constructed client, mirroring the
/// model's `@length(min: 1) string ClientId`.
pub type ClientId = String;

/// The configuration of a constructed Enhanced Client.
///
/// For M1 this captures the physical table names the client was configured for
/// (the keys of `tableEncryptionConfigs`); later milestones grow this into the
/// full per-table encryption configuration (attribute actions, algorithm suite,
/// keyring, allowed-unsigned settings) needed to encrypt/decrypt items.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientConfig {
    /// Physical DynamoDB table names this client is configured for.
    pub table_names: Vec<String>,
}

impl ClientConfig {
    /// Construct a config for the given set of physical table names.
    pub fn new(table_names: Vec<String>) -> Self {
        Self { table_names }
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

    #[test]
    fn register_returns_non_empty_unique_ids() {
        let registry = ClientRegistry::new();
        assert!(registry.is_empty());

        let id1 = registry.register(ClientConfig::new(vec!["TableA".to_string()]));
        let id2 = registry.register(ClientConfig::new(vec!["TableB".to_string()]));

        assert!(!id1.is_empty(), "ClientId must be non-empty");
        assert!(!id2.is_empty(), "ClientId must be non-empty");
        assert_ne!(id1, id2, "each CreateClient must yield a distinct id");
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn get_resolves_registered_client_and_misses_unknown() {
        let registry = ClientRegistry::new();
        let id = registry.register(ClientConfig::new(vec!["T".to_string()]));

        let resolved = registry.get(&id).expect("registered id must resolve");
        assert_eq!(resolved.table_names, vec!["T".to_string()]);
        assert!(registry.get("not-a-real-id").is_none());
    }
}
