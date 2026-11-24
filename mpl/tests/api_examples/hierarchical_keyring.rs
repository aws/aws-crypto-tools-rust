// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::support::*;

#[tokio::test]
async fn builder() -> Result<(), Error> {
    let dynamodb_key_store = make_dynamodb_key_store().await;
    // api-example: api=hierarchical-keyring frame way=builder one-of=branch_key_id,branch_key_id_supplier
    let hierarchical_keyring = HierarchicalKeyring::builder()
        // api-example: options
        .key_store(dynamodb_key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        // api-example: tail
        .build()
        .await?;
    // api-example: end
    assert_eq!(
        hierarchical_keyring.branch_key_id(),
        Some("my-branch-key-id")
    );
    Ok(())
}

#[tokio::test]
async fn key_store() -> Result<(), Error> {
    // api-example: api=hierarchical-keyring way=key_store have="a key store" takes=DynamoDbKeyStore default
    let dynamodb_key_store = make_dynamodb_key_store().await;
    // api-example: call
    let hierarchical_keyring = HierarchicalKeyring::builder()
        // api-example: setter
        .key_store(dynamodb_key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    let logical_key_store_name = hierarchical_keyring
        .key_store()
        .get_key_store_info()
        .send()
        .await?
        .logical_key_store_name()
        .to_string();
    assert_eq!(logical_key_store_name, "KeyStoreDdbTable");

    // api-example: api=hierarchical-keyring way=set_key_store have="a key store" takes=Option<SharedKeyStore> alt
    let key_store: Option<SharedKeyStore> =
        Some(SharedKeyStore::new(make_dynamodb_key_store().await));
    // api-example: call
    let hierarchical_keyring = HierarchicalKeyring::builder()
        // api-example: setter
        .set_key_store(key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    let logical_key_store_name = hierarchical_keyring
        .key_store()
        .get_key_store_info()
        .send()
        .await?
        .logical_key_store_name()
        .to_string();
    assert_eq!(logical_key_store_name, "KeyStoreDdbTable");

    // api-example: api=hierarchical-keyring way=key_store left-out fails=validation
    let result = HierarchicalKeyring::builder()
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn ttl() -> Result<(), Error> {
    // api-example: api=hierarchical-keyring way=ttl have="a duration" takes=Duration default
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        // api-example: setter
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    assert_eq!(hierarchical_keyring.ttl(), Duration::from_secs(600));

    // api-example: api=hierarchical-keyring way=set_ttl have="a duration" takes=Option<Duration> alt
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        // api-example: setter
        .set_ttl(Some(Duration::from_secs(600)))
        .build()
        .await?;
    // api-example: end
    assert_eq!(hierarchical_keyring.ttl(), Duration::from_secs(600));

    // api-example: api=hierarchical-keyring way=ttl have="zero" takes=Duration fails=validation
    let result = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        // api-example: setter
        .ttl(Duration::ZERO)
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=hierarchical-keyring way=ttl left-out fails=validation
    let result = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn branch_key_id() -> Result<(), Error> {
    // api-example: api=hierarchical-keyring way=branch_key_id have="a string" takes=&str default
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        // api-example: setter
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    assert_eq!(
        hierarchical_keyring.branch_key_id(),
        Some("my-branch-key-id")
    );

    // api-example: api=hierarchical-keyring way=branch_key_id have="a string from your config" takes=String
    let branch_key_id: String = app_config().branch_key_id;
    // api-example: call
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        // api-example: setter
        .branch_key_id(branch_key_id)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    assert_eq!(
        hierarchical_keyring.branch_key_id(),
        Some("my-branch-key-id")
    );

    // api-example: api=hierarchical-keyring way=set_branch_key_id have="a string" takes=Option<String> alt
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        // api-example: setter
        .set_branch_key_id(Some("my-branch-key-id".to_string()))
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    assert_eq!(
        hierarchical_keyring.branch_key_id(),
        Some("my-branch-key-id")
    );

    // The keyring needs a branch key ID or a branch key ID supplier, and this one has the supplier.
    // api-example: api=hierarchical-keyring way=branch_key_id left-out
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id_supplier(TenantBranchKeyIdSupplier)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    assert_eq!(hierarchical_keyring.branch_key_id(), None);
    Ok(())
}

#[tokio::test]
async fn branch_key_id_supplier() -> Result<(), Error> {
    // api-example: api=hierarchical-keyring way=branch_key_id_supplier have="a branch key ID supplier" takes=BranchKeyIdSupplier
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        // api-example: setter
        .branch_key_id_supplier(TenantBranchKeyIdSupplier)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    assert!(hierarchical_keyring.branch_key_id_supplier().is_some());

    // api-example: api=hierarchical-keyring way=set_branch_key_id_supplier have="a branch key ID supplier" takes=Option<SharedBranchKeyIdSupplier> alt
    let supplier: Option<SharedBranchKeyIdSupplier> =
        Some(SharedBranchKeyIdSupplier::new(TenantBranchKeyIdSupplier));
    // api-example: call
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        // api-example: setter
        .set_branch_key_id_supplier(supplier)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    assert!(hierarchical_keyring.branch_key_id_supplier().is_some());

    // api-example: api=hierarchical-keyring way=branch_key_id_supplier left-out
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    assert!(hierarchical_keyring.branch_key_id_supplier().is_none());
    Ok(())
}

#[tokio::test]
async fn branch_key_id_or_supplier() -> Result<(), Error> {
    // api-example: api=hierarchical-keyring way=branch_key_id,branch_key_id_supplier left-out fails=validation
    let result = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .ttl(Duration::from_secs(600))
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=hierarchical-keyring way=branch_key_id,branch_key_id_supplier together fails=validation
    let result = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .branch_key_id_supplier(TenantBranchKeyIdSupplier)
        .ttl(Duration::from_secs(600))
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

// The keyring does not expose its cache, so these tests only check whether it builds.
#[tokio::test]
async fn cache() -> Result<(), Error> {
    // api-example: api=hierarchical-keyring way=cache have="a default cache" takes=DefaultCmc
    let default_cmc = DefaultCmc::builder().entry_capacity(100).build()?;
    // api-example: call
    HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        // api-example: setter
        .cache(default_cmc)
        .build()
        .await?;
    // api-example: end

    // api-example: api=hierarchical-keyring way=cache have="a local cache" takes=LocalCmc
    let local_cmc = LocalCmc::builder().entry_capacity(100).build()?;
    // api-example: call
    HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        // api-example: setter
        .cache(local_cmc)
        .build()
        .await?;
    // api-example: end

    // api-example: api=hierarchical-keyring way=cache have="a storm-tracking cache" takes=StormTrackingCmc
    let storm_tracking_cmc = StormTrackingCmc::builder().entry_capacity(100).build()?;
    // api-example: call
    HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        // api-example: setter
        .cache(storm_tracking_cmc)
        .build()
        .await?;
    // api-example: end

    // api-example: api=hierarchical-keyring way=set_cache have="a default cache" takes=Option<SharedCmc> alt
    let cache: Option<SharedCmc> = Some(SharedCmc::new(
        DefaultCmc::builder().entry_capacity(100).build()?,
    ));
    // api-example: call
    HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        // api-example: setter
        .set_cache(cache)
        .build()
        .await?;
    // api-example: end

    // The storm-tracking cache's grace period must be less than the TTL, which is 600 seconds here.
    // api-example: api=hierarchical-keyring way=cache have="a storm-tracking cache with a grace period longer than the TTL" takes=StormTrackingCmc fails=validation
    let storm_tracking_cmc = StormTrackingCmc::builder()
        .entry_capacity(100)
        .grace_period(Duration::from_secs(3600))
        .build()?;
    // api-example: call
    let result = HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        // api-example: setter
        .cache(storm_tracking_cmc)
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=hierarchical-keyring way=cache left-out
    HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    Ok(())
}

// The keyring does not expose its partition ID, so these tests only check that it builds.
#[tokio::test]
async fn partition_id() -> Result<(), Error> {
    // api-example: api=hierarchical-keyring way=partition_id have="a string" takes=&str
    HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        // api-example: setter
        .partition_id("my-partition-id")
        .build()
        .await?;
    // api-example: end

    // api-example: api=hierarchical-keyring way=partition_id have="a string from your config" takes=String
    let partition_id: String = app_config().partition_id;
    // api-example: call
    HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        // api-example: setter
        .partition_id(partition_id)
        .build()
        .await?;
    // api-example: end

    // api-example: api=hierarchical-keyring way=set_partition_id have="a string" takes=Option<String> alt
    HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        // api-example: setter
        .set_partition_id(Some("my-partition-id".to_string()))
        .build()
        .await?;
    // api-example: end

    // api-example: api=hierarchical-keyring way=partition_id left-out
    HierarchicalKeyring::builder()
        .key_store(make_dynamodb_key_store().await)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    // api-example: end
    Ok(())
}
