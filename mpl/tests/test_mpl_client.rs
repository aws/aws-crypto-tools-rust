// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::{MaterialProviders, MaterialProvidersConfig};

#[test]
fn test_mpl_default_uses_default_config() {
    let mpl = MaterialProviders::default();
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}

#[test]
fn test_mpl_new_uses_provided_config() {
    let mpl = MaterialProviders::new(MaterialProvidersConfig::default());
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}

#[test]
fn test_mpl_builder() {
    let mpl = MaterialProviders::builder().build();
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}

#[test]
fn test_mpl_builder_with_config() {
    let mpl = MaterialProviders::builder()
        .config(MaterialProvidersConfig::default())
        .build();
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}

// ─── create_cryptographic_materials_cache ───────────────────────────────────

mod cache_factory {
    use std::sync::Arc;

    use aws_crypto_mpl::cmc::Cmc;
    use aws_crypto_mpl::{
        CacheType, DefaultCache, LocalCmc, MaterialProviders, StormTrackingCache,
    };

    /// `Default` variant builds a fresh `LocalCmc`.
    #[test]
    fn default_variant_builds_local_cmc() {
        let mpl = MaterialProviders::builder().build();
        let cache = mpl
            .create_cryptographic_materials_cache()
            .cache(CacheType::Default(DefaultCache::new(1000)))
            .send()
            .expect("default cache must build");
        // Smoke-test that the returned Arc<dyn Cmc> is functional.
        assert!(Arc::strong_count(&cache) >= 1);
    }

    /// `Default` variant honors an explicitly-built [`DefaultCache`].
    #[test]
    fn default_variant_honors_explicit_default_cache() {
        let mpl = MaterialProviders::default();
        let cfg = DefaultCache::new(7);
        assert_eq!(cfg.entry_capacity, 7);
        let _ = mpl
            .create_cryptographic_materials_cache()
            .cache(CacheType::Default(cfg))
            .send()
            .expect("custom-capacity default cache must build");
    }

    /// `Shared` variant returns the supplied Arc verbatim (Arc identity).
    #[test]
    fn shared_variant_returns_supplied_arc_verbatim() {
        let mpl = MaterialProviders::default();
        let local: Arc<dyn Cmc> = Arc::new(LocalCmc::new(4, 1).unwrap());
        let returned = mpl
            .create_cryptographic_materials_cache()
            .cache(CacheType::Shared(Arc::clone(&local)))
            .send()
            .expect("shared cache must pass through");
        assert!(
            Arc::ptr_eq(&local, &returned),
            "Shared variant must return the same Arc<dyn Cmc>"
        );
    }

    /// `StormTracking` variant builds a fresh `StormTrackingCmc`.
    #[test]
    fn storm_tracking_variant_builds_storm_tracking_cmc() {
        let mpl = MaterialProviders::default();
        let params = StormTrackingCache::builder()
            .entry_capacity(8)
            .entry_pruning_tail_size(2)
            .grace_period(10)
            .grace_interval(1)
            .fan_out(2)
            .inflight_ttl(5)
            .sleep_milli(10)
            .build()
            .unwrap();
        let _ = mpl
            .create_cryptographic_materials_cache()
            .cache(CacheType::StormTracking(params))
            .send()
            .expect("storm-tracking cache must build");
    }

    /// `.send()` without `.cache(...)` returns a descriptive error.
    #[test]
    fn missing_cache_returns_required_field_error() {
        let mpl = MaterialProviders::default();
        let err = match mpl.create_cryptographic_materials_cache().send() {
            Ok(_) => panic!("missing cache must error"),
            Err(e) => e,
        };
        assert!(
            err.message.contains("cache is required"),
            "unexpected message: {}",
            err.message
        );
    }

    /// Bubbles up a `StormTrackingCmc::new` failure when grace_interval > grace_period.
    #[test]
    fn storm_tracking_variant_propagates_construction_error() {
        let mpl = MaterialProviders::default();
        let bad = StormTrackingCache::builder()
            .entry_capacity(8)
            .entry_pruning_tail_size(2)
            .grace_period(1)
            .grace_interval(10) // > grace_period — must error per spec.
            .fan_out(2)
            .inflight_ttl(1)
            .sleep_milli(10)
            .build()
            .unwrap();
        let err = match mpl
            .create_cryptographic_materials_cache()
            .cache(CacheType::StormTracking(bad))
            .send()
        {
            Ok(_) => panic!("grace_interval > grace_period must surface"),
            Err(e) => e,
        };
        assert!(
            err.message.contains("StormTrackingCmc"),
            "unexpected message: {}",
            err.message
        );
    }

    /// Each missing required field on `StormTrackingCacheBuilder::build` is named.
    #[test]
    fn storm_tracking_builder_missing_field_names_it() {
        // Each builder method consumes `self`, so we enumerate explicitly:
        macro_rules! expect_missing {
            ($builder_expr:expr, $needle:literal) => {{
                let err = $builder_expr.build().expect_err("missing field must error");
                assert!(
                    err.message.contains($needle),
                    "expected {:?} in message; got: {}",
                    $needle,
                    err.message
                );
            }};
        }
        expect_missing!(StormTrackingCache::builder(), "entry_capacity");
        expect_missing!(
            StormTrackingCache::builder().entry_capacity(1),
            "entry_pruning_tail_size"
        );
        expect_missing!(
            StormTrackingCache::builder()
                .entry_capacity(1)
                .entry_pruning_tail_size(1),
            "grace_period"
        );
        expect_missing!(
            StormTrackingCache::builder()
                .entry_capacity(1)
                .entry_pruning_tail_size(1)
                .grace_period(1),
            "grace_interval"
        );
        expect_missing!(
            StormTrackingCache::builder()
                .entry_capacity(1)
                .entry_pruning_tail_size(1)
                .grace_period(1)
                .grace_interval(1),
            "fan_out"
        );
        expect_missing!(
            StormTrackingCache::builder()
                .entry_capacity(1)
                .entry_pruning_tail_size(1)
                .grace_period(1)
                .grace_interval(1)
                .fan_out(1),
            "inflight_ttl"
        );
        expect_missing!(
            StormTrackingCache::builder()
                .entry_capacity(1)
                .entry_pruning_tail_size(1)
                .grace_period(1)
                .grace_interval(1)
                .fan_out(1)
                .inflight_ttl(1),
            "sleep_milli"
        );
    }

    /// `time_units` setter survives round-trip on `StormTrackingCacheBuilder`.
    #[test]
    fn storm_tracking_builder_round_trips_time_units() {
        use aws_crypto_mpl::TimeUnits;
        let cache = StormTrackingCache::builder()
            .entry_capacity(1)
            .entry_pruning_tail_size(1)
            .grace_period(1)
            .grace_interval(1)
            .fan_out(1)
            .inflight_ttl(1)
            .sleep_milli(1)
            .time_units(TimeUnits::Milliseconds)
            .build()
            .unwrap();
        assert_eq!(cache.time_units, Some(TimeUnits::Milliseconds));
    }

    /// `DefaultCache::new` records the supplied capacity verbatim. Capacity is
    /// the struct's only member: the pruning tail size is an internal constant,
    /// not a customer-set knob, and there is no `Default` impl because the
    /// Smithy model makes `entryCapacity` required.
    #[test]
    fn default_cache_new_records_capacity_verbatim() {
        let d = DefaultCache::new(42);
        assert_eq!(d.entry_capacity, 42);
    }
}

// ─── create_branch_key_store ────────────────────────────────────────────────

mod keystore_factory {
    use aws_config::{BehaviorVersion, SdkConfig};
    use aws_sdk_dynamodb::Client as DynamoDbClient;
    use aws_sdk_kms::Client as KmsClient;

    use aws_crypto_mpl::{
        KeyStoreConfig, KmsConfiguration, MaterialProviders, keystore::KeystoreErrorKind,
    };

    fn dummy_clients() -> (KmsClient, DynamoDbClient) {
        let cfg = SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .build();
        (KmsClient::new(&cfg), DynamoDbClient::new(&cfg))
    }

    fn fixture_config() -> KeyStoreConfig {
        KeyStoreConfig {
            ddb_table_name: "test-table".to_string(),
            kms_configuration: KmsConfiguration::KmsKeyArn(
                "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                    .to_string(),
            ),
            logical_keystore_name: "test-logical".to_string(),
            id: Some("kid".to_string()),
            grant_tokens: None,
            ddb_client: None,
            kms_client: None,
        }
    }

    #[tokio::test]
    async fn happy_path_builds_branch_key_store() {
        let (kms, ddb) = dummy_clients();
        let mpl = MaterialProviders::default();
        let _ks = mpl
            .create_branch_key_store()
            .key_store_config(fixture_config())
            .kms_client(kms)
            .ddb_client(ddb)
            .send()
            .await
            .expect("happy path must build");
    }

    #[tokio::test]
    async fn missing_key_store_config_errors() {
        let (kms, ddb) = dummy_clients();
        let mpl = MaterialProviders::default();
        let err = match mpl
            .create_branch_key_store()
            .kms_client(kms)
            .ddb_client(ddb)
            .send()
            .await
        {
            Ok(_) => panic!("missing config must error"),
            Err(e) => e,
        };
        assert_eq!(err.kind, KeystoreErrorKind::Configuration);
        assert!(err.message.contains("key_store_config is required"));
    }

    #[tokio::test]
    async fn malformed_kms_arn_propagates_branch_key_store_error() {
        let (kms, ddb) = dummy_clients();
        let mpl = MaterialProviders::default();
        let mut bad = fixture_config();
        bad.kms_configuration = KmsConfiguration::KmsKeyArn("not-an-arn".to_string());
        let err = match mpl
            .create_branch_key_store()
            .key_store_config(bad)
            .kms_client(kms)
            .ddb_client(ddb)
            .send()
            .await
        {
            Ok(_) => panic!("malformed ARN must surface"),
            Err(e) => e,
        };
        assert_eq!(err.kind, KeystoreErrorKind::Configuration);
    }
}

// ─── create_aws_kms_hierarchical_keyring ────────────────────────────────────

mod keyring_factory {
    use std::sync::Arc;

    use async_trait::async_trait;

    use aws_crypto_mpl::aws_kms::hierarchical_keyring::{
        BranchKeySupplier, GetBranchKeyIdInput, GetBranchKeyIdOutput,
    };
    use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
    use aws_crypto_mpl::structures::{
        BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext, MaterialsError,
    };
    use aws_crypto_mpl::{CacheType, DefaultCache, MaterialProviders};

    /// Minimal stub keystore. Every data-plane method errors; only
    /// `get_key_store_info` is real, because `HierarchicalKeyring::new`
    /// resolves the logical keystore name from it at construction time.
    /// Construction requires no AWS calls; it's only used to satisfy the
    /// `Arc<dyn Keystore>` parameter on `HierarchicalKeyring::new`.
    struct StubKeystore;

    #[async_trait]
    impl Keystore for StubKeystore {
        async fn create_key(
            &self,
            _branch_key_id: Option<String>,
            _encryption_context: Option<EncryptionContext>,
        ) -> Result<String, KeystoreError> {
            unimplemented!()
        }
        async fn version_key(&self, _branch_key_id: String) -> Result<(), KeystoreError> {
            unimplemented!()
        }
        async fn get_active_branch_key(
            &self,
            _branch_key_id: String,
        ) -> Result<BranchKeyMaterials, KeystoreError> {
            unimplemented!()
        }
        async fn get_branch_key_version(
            &self,
            _branch_key_id: String,
            _branch_key_version: String,
        ) -> Result<BranchKeyMaterials, KeystoreError> {
            unimplemented!()
        }
        async fn get_beacon_key(
            &self,
            _branch_key_id: String,
        ) -> Result<BeaconKeyMaterials, KeystoreError> {
            unimplemented!()
        }
        async fn create_key_store(&self) -> Result<String, KeystoreError> {
            unimplemented!()
        }
        fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
            Ok(KeyStoreInfo {
                keystore_id: "stub-id".to_string(),
                keystore_name: "stub-table".to_string(),
                logical_keystore_name: "stub-logical-name".to_string(),
                grant_tokens: Vec::new(),
                kms_configuration: KmsConfiguration::Discovery,
            })
        }
    }

    fn stub_keystore() -> Arc<dyn Keystore> {
        Arc::new(StubKeystore)
    }

    /// Stub supplier for the supplier-path test.
    struct StubSupplier;

    #[async_trait]
    impl BranchKeySupplier for StubSupplier {
        fn get_branch_key_id(
            &self,
            _input: GetBranchKeyIdInput,
        ) -> Result<GetBranchKeyIdOutput, MaterialsError> {
            Ok(GetBranchKeyIdOutput::new("bk".to_string()))
        }
    }

    #[test]
    fn happy_path_with_branch_key_id() {
        let mpl = MaterialProviders::default();
        let _kr = mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(stub_keystore())
            .branch_key_id("bk-1")
            .ttl_seconds(60)
            .send()
            .expect("identifier path must succeed");
    }

    #[test]
    fn happy_path_with_supplier_and_full_options() {
        let mpl = MaterialProviders::default();
        let _kr = mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(stub_keystore())
            .branch_key_id_supplier(Arc::new(StubSupplier))
            .ttl_seconds(60)
            .cache(CacheType::Default(DefaultCache::new(1000)))
            .partition_id("p-id")
            .send()
            .expect("supplier path with full options must succeed");
    }

    #[test]
    fn missing_key_store_errors() {
        let mpl = MaterialProviders::default();
        let err = match mpl
            .create_aws_kms_hierarchical_keyring()
            .branch_key_id("bk-1")
            .ttl_seconds(60)
            .send()
        {
            Ok(_) => panic!("missing key_store must error"),
            Err(e) => e,
        };
        assert!(err.message.contains("key_store is required"));
    }

    #[test]
    fn missing_ttl_errors() {
        let mpl = MaterialProviders::default();
        let err = match mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(stub_keystore())
            .branch_key_id("bk-1")
            .send()
        {
            Ok(_) => panic!("missing ttl must error"),
            Err(e) => e,
        };
        assert!(err.message.contains("ttl_seconds is required"));
    }

    #[test]
    fn missing_branch_key_source_errors() {
        let mpl = MaterialProviders::default();
        let err = match mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(stub_keystore())
            .ttl_seconds(60)
            .send()
        {
            Ok(_) => panic!("missing source must error"),
            Err(e) => e,
        };
        assert!(
            err.message
                .contains("one of branch_key_id or branch_key_id_supplier must be set"),
            "unexpected: {}",
            err.message
        );
    }

    #[test]
    fn both_id_and_supplier_errors() {
        let mpl = MaterialProviders::default();
        let err = match mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(stub_keystore())
            .branch_key_id("bk-1")
            .branch_key_id_supplier(Arc::new(StubSupplier))
            .ttl_seconds(60)
            .send()
        {
            Ok(_) => panic!("both set must error"),
            Err(e) => e,
        };
        assert!(
            err.message
                .contains("only one of branch_key_id or branch_key_id_supplier"),
            "unexpected: {}",
            err.message
        );
    }

    #[test]
    fn ttl_zero_propagates_keyring_validation_error() {
        let mpl = MaterialProviders::default();
        let err = match mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(stub_keystore())
            .branch_key_id("bk-1")
            .ttl_seconds(0)
            .send()
        {
            Ok(_) => panic!("ttl=0 must surface"),
            Err(e) => e,
        };
        assert!(err.message.contains("greater than zero"));
    }
}
