// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use aws_esdk::{Esdk, EsdkCommitmentPolicy};
use aws_mpl_legacy::dafny::aws_cryptography_keyStore::client::Client as KeystoreClient;
use aws_mpl_legacy::dafny::aws_cryptography_keyStore::types::KmsConfiguration;
use aws_mpl_legacy::dafny::aws_cryptography_keyStore::types::key_store_config::KeyStoreConfig;
use aws_mpl_legacy::dafny::types::keyring::KeyringRef;
use log::info;
use sysinfo::System;

use crate::config::{TestConfig, load_config};
use crate::results::BenchmarkResult;

pub const MEMORY_TEST_ITERATIONS: usize = 5;

// Shared AWS Crypto Tools test resources in the public ESDK CI account
// (us-west-2, account 370957321024). The performance-benchmarks workflow
// assumes the public ESDK CI role, which can read this branch key store.
// These values mirror esdk/tests/fixtures.rs; keep the two in sync.
const HIERARCHY_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_STORE_NAME: &str = "KeyStoreDdbTable";
const LOGICAL_KEY_STORE_NAME: &str = BRANCH_KEY_STORE_NAME;
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

// Raw AES keyring identity; the C++ benchmark uses the same values so the two
// series are comparable.
const RAW_AES_KEY_NAMESPACE: &str = "performance-test";
const RAW_AES_KEY_NAME: &str = "raw-aes-256";

/// Which keyring the benchmark exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringChoice {
    Hierarchical,
    RawAes,
}

impl KeyringChoice {
    /// Name used in results metadata and CloudWatch log streams.
    pub fn name(self) -> &'static str {
        match self {
            Self::Hierarchical => "hierarchical",
            Self::RawAes => "raw-aes",
        }
    }
}

pub struct EsdkBenchmark {
    pub esdk_client: Esdk,
    pub keyring: KeyringRef,
    pub keyring_name: &'static str,
    pub config: TestConfig,
    pub results: Vec<BenchmarkResult>,
    pub cpu_count: usize,
    pub total_memory_gb: f64,
}

impl EsdkBenchmark {
    pub async fn new(config_path: &str, keyring_choice: KeyringChoice) -> Result<Self> {
        let mut system = System::new_all();
        system.refresh_all();
        let cpu_count = system.cpus().len();
        let total_memory_gb = system.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0);

        let config = load_config(config_path)?;

        let (esdk_client, keyring) = Self::setup_esdk(keyring_choice).await?;

        info!(
            "Initialized ESDK Benchmark ({} keyring) - CPU cores: {}, Memory: {:.1}GB",
            keyring_choice.name(),
            cpu_count,
            total_memory_gb
        );

        Ok(Self {
            esdk_client,
            keyring,
            keyring_name: keyring_choice.name(),
            config,
            results: Vec::new(),
            cpu_count,
            total_memory_gb,
        })
    }

    async fn setup_esdk(keyring_choice: KeyringChoice) -> Result<(Esdk, KeyringRef)> {
        let esdk_client = Esdk::builder()
            .commitment_policy(EsdkCommitmentPolicy::RequireEncryptRequireDecrypt)
            .build();

        let keyring = match keyring_choice {
            KeyringChoice::Hierarchical => Self::hierarchical_keyring().await?,
            KeyringChoice::RawAes => Self::raw_aes_keyring().await?,
        };

        Ok((esdk_client, keyring))
    }

    async fn hierarchical_keyring() -> Result<KeyringRef> {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let kms_client = aws_sdk_kms::Client::new(&sdk_config);
        let ddb_client = aws_sdk_dynamodb::Client::new(&sdk_config);

        let key_store_config = KeyStoreConfig::builder()
            .kms_client(kms_client)
            .ddb_client(ddb_client)
            .ddb_table_name(BRANCH_KEY_STORE_NAME)
            .logical_key_store_name(LOGICAL_KEY_STORE_NAME)
            .kms_configuration(KmsConfiguration::KmsKeyArn(HIERARCHY_KEY_ARN.to_string()))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build key store config: {e:?}"))?;

        let key_store = KeystoreClient::from_conf(key_store_config)
            .map_err(|e| anyhow::anyhow!("failed to build key store client: {e:?}"))?;

        aws_esdk::mpl()
            .create_aws_kms_hierarchical_keyring()
            .key_store(key_store)
            .branch_key_id(BRANCH_KEY_ID)
            .ttl_seconds(600_000)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to create hierarchical keyring: {e:?}"))
    }

    /// Raw AES keyring with a fixed 256-bit wrapping key. Wraps data keys
    /// locally, so it needs no AWS resources or credentials.
    async fn raw_aes_keyring() -> Result<KeyringRef> {
        aws_esdk::mpl()
            .create_raw_aes_keyring()
            .key_namespace(RAW_AES_KEY_NAMESPACE)
            .key_name(RAW_AES_KEY_NAME)
            .wrapping_key(vec![0u8; 32])
            .wrapping_alg(aws_mpl_legacy::dafny::types::AesWrappingAlg::AlgAes256GcmIv12Tag16)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to create raw AES keyring: {e:?}"))
    }

    pub fn save_results(&self, output_path: &str) -> Result<()> {
        crate::results::save_results(
            &self.results,
            output_path,
            self.keyring_name,
            self.cpu_count,
            self.total_memory_gb,
        )
    }
}
