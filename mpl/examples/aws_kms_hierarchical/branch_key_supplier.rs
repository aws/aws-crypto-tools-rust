// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Demo 2: Hierarchical Keyring with a `BranchKeySupplier`.
//!
//! Models a multi-tenant deployment: encryption-context metadata
//! (`tenant=TenantA` / `tenant=TenantB`) selects the branch key on
//! every operation. We then build two static-id keyrings — one per
//! tenant — and demonstrate that each rejects the other's ciphertext.

use std::sync::Arc;

use aws_crypto_mpl::MaterialProviders;

use super::common::{
    Config, build_keystore, demo_encryption_context, empty_decryption_materials,
    empty_encryption_materials, round_trip,
};
use super::example_branch_key_id_supplier::ExampleBranchKeyIdSupplier;
use aws_crypto_mpl::Keyring;

/// Run the branch-key-supplier demo end-to-end.
pub async fn run(
    mpl: &MaterialProviders,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("--- demo 2: branch key id supplier (multi-tenant) ---");

    // One keystore reused across every keyring in this demo.
    let keystore = build_keystore(mpl, config).await?;

    // Build the supplier that maps `tenant` → branch-key-id. Wrap in
    // Arc so it can be cheaply shared if the keyring is constructed
    // multiple times (e.g. for retries or per-request handlers).
    let supplier = Arc::new(ExampleBranchKeyIdSupplier::new(
        &config.branch_key_id_tenant_a,
        &config.branch_key_id_tenant_b,
    ));

    // The "data plane" keyring uses the supplier. Same TTL / partition
    // id as the rest of this demo.
    let supplier_keyring = mpl
        .create_aws_kms_hierarchical_keyring()
        .key_store(Arc::clone(&keystore))
        .branch_key_id_supplier(supplier)
        .ttl_seconds(600)
        .partition_id("mpl-example-supplier")
        .send()?;

    assert!(
        supplier_keyring.branch_key_id_supplier().is_some(),
        "supplier-path keyring must record a branch key id supplier",
    );
    assert!(
        supplier_keyring.branch_key_id().is_none(),
        "supplier-path keyring must not also record a static branch key id",
    );

    // Round-trip TenantA traffic and TenantB traffic via the same keyring.
    round_trip(
        &supplier_keyring,
        demo_encryption_context(&[("tenant", "TenantA")]),
    )
    .await?;
    round_trip(
        &supplier_keyring,
        demo_encryption_context(&[("tenant", "TenantB")]),
    )
    .await?;
    println!("    ✓ supplier keyring round-trip succeeded for TenantA and TenantB");

    // Build two narrow, single-tenant keyrings to demonstrate cross-
    // tenant isolation: TenantA-keyring MUST fail to decrypt EDKs
    // produced under TenantB, and vice versa.
    let keyring_a = mpl
        .create_aws_kms_hierarchical_keyring()
        .key_store(Arc::clone(&keystore))
        .branch_key_id(config.branch_key_id_tenant_a.clone())
        .ttl_seconds(600)
        .partition_id("mpl-example-supplier-tenant-a")
        .send()?;
    let keyring_b = mpl
        .create_aws_kms_hierarchical_keyring()
        .key_store(keystore)
        .branch_key_id(config.branch_key_id_tenant_b.clone())
        .ttl_seconds(600)
        .partition_id("mpl-example-supplier-tenant-b")
        .send()?;

    // If the configured tenant ids point at the same physical branch
    // key (single-key fallback in `Config::from_env`), the cross-tenant
    // isolation check is vacuous; skip it with a clear note.
    if config.branch_key_id_tenant_a == config.branch_key_id_tenant_b {
        println!(
            "    ⚠ MPL_EXAMPLE_BRANCH_KEY_ID_TENANT_A == MPL_EXAMPLE_BRANCH_KEY_ID_TENANT_B; \
             skipping cross-tenant isolation check"
        );
        return Ok(());
    }

    let ec_a = demo_encryption_context(&[("tenant", "TenantA")]);
    let ec_b = demo_encryption_context(&[("tenant", "TenantB")]);

    // Encrypt under TenantA via the static keyring_a (without using the
    // supplier so we control which branch key is used).
    let em_a = keyring_a
        .on_encrypt(empty_encryption_materials(ec_a.clone())?)
        .await?;
    let edks_a = em_a.encrypted_data_keys().to_vec();

    // Try to decrypt TenantA's EDKs with keyring_b. This MUST fail —
    // keyring_b only knows TenantB's branch key, and the EDKs encode
    // TenantA's branch key id in their key_provider_info field.
    let dm_b = empty_decryption_materials(ec_a)?;
    let cross_attempt = keyring_b.on_decrypt(dm_b, &edks_a).await;
    if cross_attempt.is_ok() {
        return Err("TenantB keyring decrypted TenantA EDKs; cross-tenant isolation broken".into());
    }
    println!("    ✓ TenantB keyring correctly refused TenantA ciphertext");

    // And the symmetric direction.
    let em_b = keyring_b
        .on_encrypt(empty_encryption_materials(ec_b.clone())?)
        .await?;
    let edks_b = em_b.encrypted_data_keys().to_vec();
    let dm_a = empty_decryption_materials(ec_b)?;
    let cross_attempt_2 = keyring_a.on_decrypt(dm_a, &edks_b).await;
    if cross_attempt_2.is_ok() {
        return Err("TenantA keyring decrypted TenantB EDKs; cross-tenant isolation broken".into());
    }
    println!("    ✓ TenantA keyring correctly refused TenantB ciphertext");

    Ok(())
}
