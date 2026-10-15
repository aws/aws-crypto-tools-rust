// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a hierarchical keyring that calls AWS KMS with credentials issued for one request.
//!
//! Requires an existing key store with a provisioned branch key.
//! The request credentials are read from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN.
//! Each KMS call also carries a header naming the request.

use std::time::{Duration, SystemTime};

use aws_crypto_mpl::key_store::{KeyStoreClient, KmsConfiguration};
use aws_crypto_mpl::{HierarchicalKeyring, aws_config, aws_sdk_dynamodb, aws_sdk_kms};
use aws_sdk_kms::config::Credentials;
use aws_smithy_http_client::tls::{Provider, rustls_provider::CryptoMode};

/// Stands in for the credentials a service receives with each request.
fn credentials_for_request() -> Result<Credentials, Box<dyn std::error::Error>> {
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")?;
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")?;
    let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
    Ok(Credentials::new(
        access_key_id,
        secret_access_key,
        session_token,
        Some(SystemTime::now() + Duration::from_secs(15 * 60)),
        "request",
    ))
}

/// Adds fixed headers to every KMS request.
#[derive(Debug)]
struct RequestHeaders(Vec<(String, String)>);

impl aws_sdk_kms::config::Intercept for RequestHeaders {
    fn name(&self) -> &'static str {
        "RequestHeaders"
    }

    // Before signing, so SigV4 signs the headers.
    fn modify_before_signing(
        &self,
        context: &mut aws_sdk_kms::config::interceptors::BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &aws_sdk_kms::config::RuntimeComponents,
        _cfg: &mut aws_sdk_kms::config::ConfigBag,
    ) -> Result<(), aws_sdk_kms::error::BoxError> {
        let headers = context.request_mut().headers_mut();
        for (name, value) in &self.0 {
            headers.try_insert(name.clone(), value.clone())?;
        }
        Ok(())
    }
}

/// Handles one request: every KMS call it makes uses that request's credentials.
async fn handle_request(
    base_kms: &aws_sdk_kms::Client,
    ddb: &aws_sdk_dynamodb::Client,
    esdk: &aws_esdk::Client,
    credentials: Credentials,
) -> Result<(), Box<dyn std::error::Error>> {
    // A copy of the base client that signs with this request's credentials
    // and sends this request's headers.
    // It keeps the base client's HTTP client, so it reuses the same connections.
    let kms = aws_sdk_kms::Client::from_conf(
        base_kms
            .config()
            .to_builder()
            .credentials_provider(credentials)
            .interceptor(RequestHeaders(vec![(
                "x-example-request-id".to_string(),
                "request-1".to_string(),
            )]))
            .build(),
    );

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    let key_store = KeyStoreClient::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126".into(),
        ))
        .kms_client(kms)
        .ddb_client(ddb.clone())
        .build()
        .await?;

    // A keyring with its own cache, so branch key material fetched with one request's
    // credentials is never served to another request.
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        .branch_key_id("3ce7656b-e166-40f3-8c9b-a920ce6596cd")
        .ttl(Duration::from_secs(300))
        .build()?;

    let plaintext = b"Hello World";
    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .send()
        .await?;
    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .keyring(keyring)
        .send()
        .await?;
    assert_eq!(decrypted.plaintext(), plaintext, "plaintext mismatch");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Created once and shared by every request.
    // One HTTP client gives the KMS and DynamoDB clients, and every per-request copy of them,
    // a single connection pool.
    // DynamoDB calls use the default credential chain; KMS calls use each request's credentials.
    let http_client = aws_smithy_http_client::Builder::new()
        .tls_provider(Provider::Rustls(CryptoMode::AwsLc))
        .build_https();
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region("us-west-2")
        .http_client(http_client)
        .load()
        .await;
    let kms = aws_sdk_kms::Client::new(&sdk_config);
    let ddb = aws_sdk_dynamodb::Client::new(&sdk_config);
    let esdk = aws_esdk::Client::default();

    handle_request(&kms, &ddb, &esdk, credentials_for_request()?).await?;

    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}
