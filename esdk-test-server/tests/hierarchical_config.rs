//! The hierarchical keyring config decodes from the rpcv2Cbor wire model using
//! the canonical branch-key-store fixtures shared across the ESDK/MPL test
//! suites. This is the offline half of hierarchical support: the actual
//! encrypt/decrypt round trip reaches KMS + DynamoDB and runs only with AWS
//! credentials and a provisioned key store.

use aws_esdk_test_server::model::{
    AwsKmsHierarchicalKeyringConfig, CreateClientRequest, CryptographicMaterialsManager,
    DefaultCmmConfig, EsdkClientConfig, EsdkCommitmentPolicy, Keyring,
};

fn hierarchical_create_client() -> CreateClientRequest {
    CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm: CryptographicMaterialsManager {
                default_cmm: Some(DefaultCmmConfig {
                    keyring: Keyring {
                        aws_kms_hierarchical: Some(AwsKmsHierarchicalKeyringConfig {
                            branch_key_id: "3f43a9af-08c5-4317-b694-3d3e883dcaef".to_owned(),
                            key_store_table_name: "KeyStoreDdbTable".to_owned(),
                            logical_key_store_name: "KeyStoreDdbTable".to_owned(),
                            kms_key_arn:
                                "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
                                    .to_owned(),
                            ttl_seconds: 600,
                        }),
                        ..Default::default()
                    },
                }),
                ..Default::default()
            },
        },
    }
}

#[test]
fn hierarchical_config_round_trips_through_cbor() {
    let mut bytes = Vec::new();
    ciborium::into_writer(&hierarchical_create_client(), &mut bytes).expect("encode");

    let decoded: CreateClientRequest = ciborium::from_reader(&bytes[..]).expect("decode");
    let hierarchical = decoded
        .config
        .cmm
        .default_cmm
        .expect("default cmm")
        .keyring
        .aws_kms_hierarchical
        .expect("hierarchical keyring variant set");

    assert_eq!(
        hierarchical.branch_key_id,
        "3f43a9af-08c5-4317-b694-3d3e883dcaef"
    );
    assert_eq!(hierarchical.key_store_table_name, "KeyStoreDdbTable");
    assert_eq!(hierarchical.logical_key_store_name, "KeyStoreDdbTable");
    assert_eq!(
        hierarchical.kms_key_arn,
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
    );
    assert_eq!(hierarchical.ttl_seconds, 600);
}
