// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::{app_config, dynamodb_key_store};
use aws_crypto_mpl::cmc::{DefaultCmc, LocalCmc, SharedCmc, StormTrackingCmc};
use aws_crypto_mpl::key_store::SharedKeyStore;
use aws_crypto_mpl::keyring::{
    BranchKeyIdSupplier, GetBranchKeyIdInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    SharedBranchKeyIdSupplier,
};
use aws_crypto_mpl::{Error, async_trait};

/// Picks a tenant's branch key from the encryption context.
struct TenantBranchKeyIdSupplier;

#[async_trait]
impl BranchKeyIdSupplier for TenantBranchKeyIdSupplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, Error> {
        let tenant = input
            .encryption_context()
            .get("tenant")
            .unwrap_or("default");
        GetBranchKeyIdOutput::builder()
            .branch_key_id(format!("{tenant}-branch-key-id"))
            .build()
    }
}

#[tokio::test]
async fn builder() -> Result<(), Error> {
    let dynamodb_key_store = dynamodb_key_store().await;
    // api-example: api=hierarchical-keyring way=builder takes=none kind=pass
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    assert_eq!(
        hierarchical_keyring.branch_key_id(),
        Some("my-branch-key-id")
    );
    Ok(())
}

#[tokio::test]
async fn key_store() -> Result<(), Error> {
    let dynamodb_key_store = dynamodb_key_store().await;
    // api-example: api=hierarchical-keyring way=key_store takes=DynamoDbKeyStore kind=pass
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    let logical_key_store_name = hierarchical_keyring
        .key_store()
        .get_key_store_info()
        .send()
        .await?
        .logical_key_store_name()
        .to_string();
    assert_eq!(logical_key_store_name, "KeyStoreDdbTable");

    // api-example: api=hierarchical-keyring way=set_key_store takes=Option<SharedKeyStore> kind=pass
    // snippet-start
    let key_store: Option<SharedKeyStore> = Some(SharedKeyStore::new(dynamodb_key_store));
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .set_key_store(key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    let logical_key_store_name_from_option = hierarchical_keyring
        .key_store()
        .get_key_store_info()
        .send()
        .await?
        .logical_key_store_name()
        .to_string();
    assert_eq!(logical_key_store_name_from_option, logical_key_store_name);

    // api-example: api=hierarchical-keyring way=key_store kind=missing
    // snippet-start
    let result = HierarchicalKeyring::builder()
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn ttl() -> Result<(), Error> {
    let dynamodb_key_store = dynamodb_key_store().await;
    // api-example: api=hierarchical-keyring way=ttl takes=Duration kind=pass
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    assert_eq!(hierarchical_keyring.ttl(), Duration::from_secs(600));

    // api-example: api=hierarchical-keyring way=set_ttl takes=Option<Duration> kind=pass
    // snippet-start
    let ttl: Option<Duration> = Some(Duration::from_secs(600));
    let hierarchical_keyring_from_option = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .set_ttl(ttl)
        .build()
        .await?;
    // snippet-end
    assert_eq!(
        hierarchical_keyring_from_option.ttl(),
        hierarchical_keyring.ttl()
    );

    // api-example: api=hierarchical-keyring way=ttl kind=missing
    // snippet-start
    let result = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .build()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=hierarchical-keyring way=ttl takes=Duration kind=reject
    // snippet-start
    let result = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::ZERO)
        .build()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn branch_key_id() -> Result<(), Error> {
    let dynamodb_key_store = dynamodb_key_store().await;
    let app_config = app_config();
    // api-example: api=hierarchical-keyring way=branch_key_id takes=&str kind=pass
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    assert_eq!(
        hierarchical_keyring.branch_key_id(),
        Some("my-branch-key-id")
    );

    // api-example: api=hierarchical-keyring way=branch_key_id takes=String kind=pass
    // snippet-start
    let branch_key_id: String = app_config.branch_key_id;
    let hierarchical_keyring_from_string = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id(branch_key_id)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    assert_eq!(
        hierarchical_keyring_from_string.branch_key_id(),
        hierarchical_keyring.branch_key_id()
    );

    // api-example: api=hierarchical-keyring way=set_branch_key_id takes=Option<String> kind=pass
    // snippet-start
    let branch_key_id: Option<String> = Some("my-branch-key-id".to_string());
    let hierarchical_keyring_from_option = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .set_branch_key_id(branch_key_id)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    assert_eq!(
        hierarchical_keyring_from_option.branch_key_id(),
        hierarchical_keyring.branch_key_id()
    );

    // api-example: api=hierarchical-keyring way=branch_key_id kind=omitted
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id_supplier(TenantBranchKeyIdSupplier)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    assert_eq!(hierarchical_keyring.branch_key_id(), None);

    // api-example: api=hierarchical-keyring way=branch_key_id takes=&str kind=reject
    // snippet-start
    let result = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store)
        .branch_key_id("my-branch-key-id")
        .branch_key_id_supplier(TenantBranchKeyIdSupplier)
        .ttl(Duration::from_secs(600))
        .build()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn branch_key_id_supplier() -> Result<(), Error> {
    let dynamodb_key_store = dynamodb_key_store().await;
    // api-example: api=hierarchical-keyring way=branch_key_id_supplier takes=BranchKeyIdSupplier kind=pass
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id_supplier(TenantBranchKeyIdSupplier)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    assert!(hierarchical_keyring.branch_key_id_supplier().is_some());

    // api-example: api=hierarchical-keyring way=set_branch_key_id_supplier takes=Option<SharedBranchKeyIdSupplier> kind=pass
    // snippet-start
    let supplier: Option<SharedBranchKeyIdSupplier> =
        Some(SharedBranchKeyIdSupplier::new(TenantBranchKeyIdSupplier));
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .set_branch_key_id_supplier(supplier)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    assert!(hierarchical_keyring.branch_key_id_supplier().is_some());

    // api-example: api=hierarchical-keyring way=branch_key_id_supplier kind=omitted
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    assert!(hierarchical_keyring.branch_key_id_supplier().is_none());
    Ok(())
}

// The keyring does not expose its cache, so the test only checks that it builds.
#[allow(unused_variables)]
#[tokio::test]
async fn cache() -> Result<(), Error> {
    let dynamodb_key_store = dynamodb_key_store().await;
    // api-example: api=hierarchical-keyring way=cache takes=DefaultCmc kind=pass
    // snippet-start
    let default_cmc = DefaultCmc::builder().entry_capacity(100).build()?;
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .cache(default_cmc)
        .build()
        .await?;
    // snippet-end

    // api-example: api=hierarchical-keyring way=cache takes=LocalCmc kind=pass
    // snippet-start
    let local_cmc = LocalCmc::builder().entry_capacity(100).build()?;
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .cache(local_cmc)
        .build()
        .await?;
    // snippet-end

    // api-example: api=hierarchical-keyring way=cache takes=StormTrackingCmc kind=pass
    // snippet-start
    let storm_tracking_cmc = StormTrackingCmc::builder().entry_capacity(100).build()?;
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .cache(storm_tracking_cmc)
        .build()
        .await?;
    // snippet-end

    // api-example: api=hierarchical-keyring way=set_cache takes=Option<SharedCmc> kind=pass
    // snippet-start
    let cache: Option<SharedCmc> = Some(SharedCmc::new(
        DefaultCmc::builder().entry_capacity(100).build()?,
    ));
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .set_cache(cache)
        .build()
        .await?;
    // snippet-end

    // api-example: api=hierarchical-keyring way=cache kind=omitted
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end

    // The storm-tracking cache's grace period must be less than the TTL.
    // api-example: api=hierarchical-keyring way=cache takes=StormTrackingCmc kind=reject
    // snippet-start
    let storm_tracking_cmc = StormTrackingCmc::builder()
        .entry_capacity(100)
        .grace_period(Duration::from_secs(60))
        .build()?;
    let result = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(30))
        .cache(storm_tracking_cmc)
        .build()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

// The keyring does not expose its partition id, so the test only checks that it builds.
#[allow(unused_variables)]
#[tokio::test]
async fn partition_id() -> Result<(), Error> {
    let dynamodb_key_store = dynamodb_key_store().await;
    let app_config = app_config();
    // api-example: api=hierarchical-keyring way=partition_id takes=&str kind=pass
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .partition_id("my-partition-id")
        .build()
        .await?;
    // snippet-end

    // api-example: api=hierarchical-keyring way=partition_id takes=String kind=pass
    // snippet-start
    let partition_id: String = app_config.partition_id;
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .partition_id(partition_id)
        .build()
        .await?;
    // snippet-end

    // api-example: api=hierarchical-keyring way=set_partition_id takes=Option<String> kind=pass
    // snippet-start
    let partition_id: Option<String> = Some("my-partition-id".to_string());
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store.clone())
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .set_partition_id(partition_id)
        .build()
        .await?;
    // snippet-end

    // api-example: api=hierarchical-keyring way=partition_id kind=omitted
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // snippet-end
    Ok(())
}
