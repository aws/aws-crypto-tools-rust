//! Your custom keyring, defined in Rust and exported to C++.
//!
//! Step 2 (`LocalKekKeyring`): define your keyring.
//! Step 3 (`custom_keyring_create`): export it as a handle for C++ to adopt.
//! See README.md for the full setup, and example.cpp for the C++ side.

use std::ffi::c_void;

use aws_crypto_mpl::keyring::{OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use aws_crypto_mpl::structures::{EncryptedDataKey, PlaintextDataKey};
use aws_crypto_mpl::{Error, Keyring, async_trait};
use aws_mpl_primitives::{AesGcm, aes_decrypt, aes_encrypt, generate_random_bytes};

/// For demonstration only: a real application must source its wrapping key
/// from a secure store and never hardcode it.
const WRAPPING_KEY: [u8; 32] = [0x2A; 32];

/// Identifies this keyring's encrypted data keys inside the message header.
const PROVIDER_ID: &str = "custom-keyring-example";
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Step 2: define your keyring.
///
/// Wraps each message's data key with AES-256-GCM under a local key-encryption key (KEK).
/// Each EDK's ciphertext is `iv || ciphertext || tag`.
struct LocalKekKeyring {
    kek: [u8; 32],
}

impl LocalKekKeyring {
    fn wrap(&self, data_key: &PlaintextDataKey) -> Result<EncryptedDataKey, Error> {
        let mut iv = vec![0u8; IV_LEN];
        generate_random_bytes(&mut iv)
            .map_err(|e| Error::cryptographic("failed to generate wrap IV").with_source(e))?;
        let mut wrapped = Vec::new();
        aes_encrypt(
            AesGcm::Aes256Gcm,
            &iv,
            &self.kek,
            data_key.as_bytes(),
            &[],
            &mut wrapped,
        )
        .map_err(|e| Error::cryptographic("failed to wrap data key").with_source(e))?;
        iv.extend_from_slice(&wrapped);
        EncryptedDataKey::builder()
            .key_provider_id(PROVIDER_ID)
            .key_provider_info(b"kek-v1")
            .ciphertext(iv)
            .build()
    }

    fn unwrap(&self, edk: &EncryptedDataKey, key_len: usize) -> Result<PlaintextDataKey, Error> {
        let bytes = edk.ciphertext();
        if bytes.len() != IV_LEN + key_len + TAG_LEN {
            return Err(Error::cryptographic("EDK ciphertext has unexpected length"));
        }
        let (iv, rest) = bytes.split_at(IV_LEN);
        let (wrapped_key, tag) = rest.split_at(key_len);
        let mut data_key = vec![0u8; key_len];
        aes_decrypt(
            AesGcm::Aes256Gcm,
            &self.kek,
            wrapped_key,
            tag,
            iv,
            &[],
            &mut data_key,
        )
        .map_err(|e| Error::cryptographic("failed to unwrap data key").with_source(e))?;
        Ok(data_key.into())
    }
}

#[async_trait]
impl Keyring for LocalKekKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let materials = input.into_materials();
        let materials = match materials.plaintext_data_key() {
            // Another keyring already generated the data key: wrap it and add our EDK.
            Some(data_key) => {
                let edk = self.wrap(data_key)?;
                materials.add_encrypted_data_key(edk)?
            }
            // No data key yet: generate one, wrap it, and add both.
            None => {
                let mut bytes = vec![0u8; materials.algorithm_suite().encryption_key_length()];
                generate_random_bytes(&mut bytes).map_err(|e| {
                    Error::cryptographic("failed to generate data key").with_source(e)
                })?;
                let data_key = PlaintextDataKey::from(bytes);
                let edk = self.wrap(&data_key)?;
                materials.add_data_key(data_key, edk)?
            }
        };
        Ok(materials.into())
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let (materials, encrypted_data_keys) = input.into_parts();
        let key_len = materials.algorithm_suite().encryption_key_length();
        // Skip EDKs written by other keyrings.
        let Some(edk) = encrypted_data_keys
            .iter()
            .find(|edk| edk.key_provider_id() == PROVIDER_ID)
        else {
            return Err(Error::no_matching_data_key("no EDK matched this keyring"));
        };
        let data_key = self.unwrap(edk, key_len)?;
        Ok(materials.add_data_key(data_key)?.into())
    }
}

/// Step 3: export your keyring.
#[unsafe(no_mangle)]
pub extern "C" fn custom_keyring_create() -> *mut c_void {
    aws_esdk_cpp::into_keyring_handle(LocalKekKeyring { kek: WRAPPING_KEY })
}
