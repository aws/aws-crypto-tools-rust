// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The tests never call AWS KMS: building the keyring makes no request,
//! so they only check what the keyring was built with.

use super::support::*;

const KEY_ARN: &str = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

#[tokio::test]
async fn builder() -> Result<(), Error> {
    let kms_client = make_kms_client();
    // api-example: api=aws-kms-keyring frame way=builder
    let aws_kms_keyring = AwsKmsKeyring::builder()
        // api-example: options
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        .kms_client(kms_client)
        // api-example: tail
        .build()
        .await?;
    // api-example: end
    assert_eq!(aws_kms_keyring.kms_key_id(), KEY_ARN);
    Ok(())
}

#[tokio::test]
async fn kms_key_id() -> Result<(), Error> {
    // api-example: api=aws-kms-keyring way=kms_key_id have="a key ARN" takes=&str default
    let aws_kms_keyring = AwsKmsKeyring::builder()
        // api-example: setter
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        .kms_client(make_kms_client())
        .build()
        .await?;
    // api-example: end
    assert_eq!(aws_kms_keyring.kms_key_id(), KEY_ARN);

    // api-example: api=aws-kms-keyring way=kms_key_id have="a key ARN from your config" takes=String
    let kms_key_arn: String = app_config().kms_key_arn;
    // api-example: call
    let aws_kms_keyring = AwsKmsKeyring::builder()
        // api-example: setter
        .kms_key_id(kms_key_arn)
        .kms_client(make_kms_client())
        .build()
        .await?;
    // api-example: end
    assert_eq!(aws_kms_keyring.kms_key_id(), KEY_ARN);

    // api-example: api=aws-kms-keyring way=set_kms_key_id have="a key ARN" takes=Option<String> alt
    let kms_key_arn: Option<String> = Some(
        "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab".to_string(),
    );
    // api-example: call
    let aws_kms_keyring = AwsKmsKeyring::builder()
        // api-example: setter
        .set_kms_key_id(kms_key_arn)
        .kms_client(make_kms_client())
        .build()
        .await?;
    // api-example: end
    assert_eq!(aws_kms_keyring.kms_key_id(), KEY_ARN);

    // A keyring built from an alias or a key ID can encrypt but not decrypt.
    // api-example: api=aws-kms-keyring way=kms_key_id have="an alias ARN" takes=&str
    let aws_kms_keyring = AwsKmsKeyring::builder()
        // api-example: setter
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:alias/my-alias")
        .kms_client(make_kms_client())
        .build()
        .await?;
    // api-example: end
    assert_eq!(
        aws_kms_keyring.kms_key_id(),
        "arn:aws:kms:us-west-2:111122223333:alias/my-alias"
    );

    // api-example: api=aws-kms-keyring way=kms_key_id have="an alias name" takes=&str
    let aws_kms_keyring = AwsKmsKeyring::builder()
        // api-example: setter
        .kms_key_id("alias/my-alias")
        .kms_client(make_kms_client())
        .build()
        .await?;
    // api-example: end
    assert_eq!(aws_kms_keyring.kms_key_id(), "alias/my-alias");

    // api-example: api=aws-kms-keyring way=kms_key_id have="a key ID" takes=&str
    let aws_kms_keyring = AwsKmsKeyring::builder()
        // api-example: setter
        .kms_key_id("1234abcd-12ab-34cd-56ef-1234567890ab")
        .kms_client(make_kms_client())
        .build()
        .await?;
    // api-example: end
    assert_eq!(
        aws_kms_keyring.kms_key_id(),
        "1234abcd-12ab-34cd-56ef-1234567890ab"
    );

    // api-example: api=aws-kms-keyring way=kms_key_id have="an empty string" takes=&str fails=validation
    let result = AwsKmsKeyring::builder()
        // api-example: setter
        .kms_key_id("")
        .kms_client(make_kms_client())
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=aws-kms-keyring way=kms_key_id have="an ARN with no key or alias" takes=&str fails=validation
    let result = AwsKmsKeyring::builder()
        // api-example: setter
        .kms_key_id("arn:aws:kms:us-west-2:111122223333")
        .kms_client(make_kms_client())
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=aws-kms-keyring way=kms_key_id left-out fails=validation
    let result = AwsKmsKeyring::builder()
        .kms_client(make_kms_client())
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

// The keyring does not expose its client, so these tests only check that it builds.
#[tokio::test]
async fn kms_client() -> Result<(), Error> {
    // api-example: api=aws-kms-keyring way=kms_client have="a KMS client" takes=aws_sdk_kms::Client default
    let kms_client = make_kms_client();
    // api-example: call
    AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        // api-example: setter
        .kms_client(kms_client)
        .build()
        .await?;
    // api-example: end

    // api-example: api=aws-kms-keyring way=kms_client have="an AWS SDK config" takes=aws_sdk_kms::Client
    let sdk_config = aws_config::SdkConfig::builder()
        .region(aws_config::Region::new("us-west-2"))
        .behavior_version(aws_config::BehaviorVersion::latest())
        .build();
    // api-example: call
    AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        // api-example: setter
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .build()
        .await?;
    // api-example: end

    // api-example: api=aws-kms-keyring way=set_kms_client have="a KMS client" takes=Option<aws_sdk_kms::Client> alt
    let kms_client = make_kms_client();
    // api-example: call
    AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        // api-example: setter
        .set_kms_client(Some(kms_client))
        .build()
        .await?;
    // api-example: end

    // api-example: api=aws-kms-keyring way=kms_client left-out fails=validation
    let result = AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn grant_tokens() -> Result<(), Error> {
    // api-example: api=aws-kms-keyring way=grant_tokens have="a grant token" takes=&str
    let aws_kms_keyring = AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        .kms_client(make_kms_client())
        // api-example: setter
        .grant_tokens("my-grant-token")
        .build()
        .await?;
    // api-example: end
    assert_eq!(aws_kms_keyring.grant_tokens(), ["my-grant-token"]);

    // api-example: api=aws-kms-keyring way=grant_tokens have="a grant token from your config" takes=String
    let grant_token: String = app_config().grant_token;
    // api-example: call
    let aws_kms_keyring = AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        .kms_client(make_kms_client())
        // api-example: setter
        .grant_tokens(grant_token)
        .build()
        .await?;
    // api-example: end
    assert_eq!(aws_kms_keyring.grant_tokens(), ["my-grant-token"]);

    // api-example: api=aws-kms-keyring way=set_grant_tokens have="a list of grant tokens" takes=Option<Vec<String>>
    let grant_tokens: Option<Vec<String>> = Some(vec![
        "my-grant-token".to_string(),
        "my-other-grant-token".to_string(),
    ]);
    // api-example: call
    let aws_kms_keyring = AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        .kms_client(make_kms_client())
        // api-example: setter
        .set_grant_tokens(grant_tokens)
        .build()
        .await?;
    // api-example: end
    assert_eq!(
        aws_kms_keyring.grant_tokens(),
        ["my-grant-token", "my-other-grant-token"]
    );

    // api-example: api=aws-kms-keyring way=grant_tokens have="an empty grant token" takes=&str fails=validation
    let result = AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        .kms_client(make_kms_client())
        // api-example: setter
        .grant_tokens("")
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=aws-kms-keyring way=set_grant_tokens have="more than 10 grant tokens" takes=Option<Vec<String>> fails=validation
    let grant_tokens: Option<Vec<String>> = Some(vec!["my-grant-token".to_string(); 11]);
    // api-example: call
    let result = AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        .kms_client(make_kms_client())
        // api-example: setter
        .set_grant_tokens(grant_tokens)
        .build()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=aws-kms-keyring way=grant_tokens left-out
    let aws_kms_keyring = AwsKmsKeyring::builder()
        .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
        .kms_client(make_kms_client())
        .build()
        .await?;
    // api-example: end
    assert!(aws_kms_keyring.grant_tokens().is_empty());
    Ok(())
}
