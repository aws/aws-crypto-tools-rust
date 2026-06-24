// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sample `BranchKeySupplier` implementation used by the supplier and
//! cache-configurations demos.
//!
//! Demonstrates how a real-world multi-tenant integration might choose
//! a branch key based on the `tenant` key in the encryption context.
//! The supplier is part of the data plane: it runs on every encrypt
//! and decrypt call. Implementations MUST be `Send + Sync` and SHOULD
//! be allocation-free on the hot path; this example uses cheap clones
//! for clarity.

use async_trait::async_trait;

use aws_crypto_mpl::aws_kms::hierarchical_keyring::BranchKeySupplier;
use aws_crypto_mpl::structures::{EncryptionContext, MaterialsError};

/// Maps `tenant=A` → `branch_key_id_for_tenant_a` and
/// `tenant=B` → `branch_key_id_for_tenant_b`. Any other tenant value
/// (or a missing `tenant` key) is rejected with a descriptive error.
pub struct ExampleBranchKeyIdSupplier {
    branch_key_id_for_tenant_a: String,
    branch_key_id_for_tenant_b: String,
}

impl ExampleBranchKeyIdSupplier {
    /// Construct a supplier that knows about exactly two tenants.
    pub fn new(tenant_a_id: &str, tenant_b_id: &str) -> Self {
        Self {
            branch_key_id_for_tenant_a: tenant_a_id.to_string(),
            branch_key_id_for_tenant_b: tenant_b_id.to_string(),
        }
    }
}

#[async_trait]
impl BranchKeySupplier for ExampleBranchKeyIdSupplier {
    async fn get_branch_key_id(
        &self,
        encryption_context: &EncryptionContext,
    ) -> Result<String, MaterialsError> {
        let tenant_value = encryption_context
            .get(b"tenant".as_slice())
            .ok_or_else(|| {
                MaterialsError::new(
                    "ExampleBranchKeyIdSupplier: encryption context is missing the `tenant` key",
                )
            })?;
        match tenant_value.as_slice() {
            b"TenantA" => Ok(self.branch_key_id_for_tenant_a.clone()),
            b"TenantB" => Ok(self.branch_key_id_for_tenant_b.clone()),
            other => {
                let display = std::str::from_utf8(other).unwrap_or("<non-utf8>");
                Err(MaterialsError::new(format!(
                    "ExampleBranchKeyIdSupplier: unknown tenant {display:?}",
                )))
            }
        }
    }
}
