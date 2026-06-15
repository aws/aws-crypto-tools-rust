// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Beacon key materials structure.

use std::collections::BTreeMap;

use super::encryption_context::EncryptionContext;

/// Materials used in structured encryption containing HMAC keys derived from a beacon key.
///
//= ../spec/framework/structures.md#structure-4
//= type=implication
//# This structure MUST include the following fields:
//
//= ../spec/framework/structures.md#structure-4
//= type=implication
//# This structure MAY include the following fields:
pub struct BeaconKeyMaterials {
    beacon_key_id: String,
    encryption_context: EncryptionContext,
    beacon_key: Option<Vec<u8>>,
    hmac_keys: Option<BTreeMap<String, Vec<u8>>>,
}

impl BeaconKeyMaterials {
    pub fn new(
        beacon_key_id: String,
        encryption_context: EncryptionContext,
        beacon_key: Option<Vec<u8>>,
        hmac_keys: Option<BTreeMap<String, Vec<u8>>>,
    ) -> Self {
        Self {
            beacon_key_id,
            encryption_context,
            beacon_key,
            hmac_keys,
        }
    }

    pub fn beacon_key_id(&self) -> &str {
        &self.beacon_key_id
    }

    pub fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    pub fn beacon_key(&self) -> Option<&[u8]> {
        self.beacon_key.as_deref()
    }

    pub fn hmac_keys(&self) -> Option<&BTreeMap<String, Vec<u8>>> {
        self.hmac_keys.as_ref()
    }
}

impl std::fmt::Debug for BeaconKeyMaterials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconKeyMaterials")
            .field("beacon_key_id", &self.beacon_key_id)
            .field("encryption_context", &self.encryption_context)
            .field(
                "beacon_key",
                &self
                    .beacon_key
                    .as_ref()
                    .map(|k| format!("[REDACTED; {} bytes]", k.len())),
            )
            .field(
                "hmac_keys",
                &self
                    .hmac_keys
                    .as_ref()
                    .map(|m| format!("[{} keys; REDACTED]", m.len())),
            )
            .finish()
    }
}
