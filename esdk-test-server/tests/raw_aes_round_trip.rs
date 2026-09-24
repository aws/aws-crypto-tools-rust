//! An offline Raw-AES client encrypts and decrypts through the MPL
//! keyring, carrying the encryption context across both calls, and decrypt
//! rejects a context that disagrees with the one bound into the message.

use std::collections::BTreeMap;

use aws_esdk_test_server::handlers::AppState;
use aws_esdk_test_server::model::{
    AesWrappingAlg, CreateClientRequest, CryptographicMaterialsManager, DecryptRequest,
    DefaultCmmConfig, EncryptRequest, EsdkClientConfig, EsdkCommitmentPolicy, Keyring,
    RawAesKeyringConfig,
};

fn raw_aes_create_client() -> CreateClientRequest {
    CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm: CryptographicMaterialsManager {
                default_cmm: Some(DefaultCmmConfig {
                    keyring: Keyring {
                        raw_aes: Some(RawAesKeyringConfig {
                            key_namespace: "esdk-test-server".to_owned(),
                            key_name: "raw-aes-round-trip-key".to_owned(),
                            wrapping_key: (0u8..32).collect(),
                            wrapping_alg: AesWrappingAlg::Alg256,
                        }),
                        ..Default::default()
                    },
                }),
                ..Default::default()
            },
        },
    }
}

fn context(pairs: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
    Some(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    )
}

#[tokio::test]
async fn raw_aes_encrypt_decrypt_round_trips() {
    let state = AppState::new();
    let client_id = state
        .create_client(raw_aes_create_client())
        .await
        .expect("create client")
        .client_id;
    let plaintext = b"esdk-test-server round trip".to_vec();

    let ciphertext = state
        .encrypt(EncryptRequest {
            client_id: client_id.clone(),
            plaintext: plaintext.clone(),
            encryption_context: context(&[("purpose", "round-trip")]),
            algorithm_suite_id: None,
            frame_length: None,
        })
        .await
        .expect("encrypt")
        .ciphertext;
    assert_ne!(ciphertext, plaintext);

    let decrypted = state
        .decrypt(DecryptRequest {
            client_id: client_id.clone(),
            ciphertext: ciphertext.clone(),
            encryption_context: context(&[("purpose", "round-trip")]),
        })
        .await
        .expect("decrypt")
        .plaintext;
    assert_eq!(decrypted, plaintext);

    let mismatch = state
        .decrypt(DecryptRequest {
            client_id,
            ciphertext,
            encryption_context: context(&[("purpose", "other")]),
        })
        .await;
    assert!(
        mismatch.is_err(),
        "decrypt must reject an encryption context that disagrees with the message"
    );
}
