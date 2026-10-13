//! Your custom keyring, defined in Rust and exported to C++.
//!
//! Step 2 (`RequireContextKeyring`): define your keyring.
//! Step 3 (`custom_keyring_create`): export it as a handle for C++ to adopt.
//! See README.md for the full setup, and example.cpp for the C++ side.

use std::ffi::c_void;

use aws_crypto_mpl::keyring::{OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use aws_crypto_mpl::structures::EncryptionContext;
use aws_crypto_mpl::{AesGcm, Error, Keyring, RawAesKeyring, async_trait};

/// The encryption context key every message must carry.
const REQUIRED_KEY: &str = "department";

/// Step 2: define your keyring.
///
/// Wraps another keyring and refuses any message whose encryption context lacks `department`.
struct RequireContextKeyring {
    inner: RawAesKeyring,
}

fn check(encryption_context: &EncryptionContext) -> Result<(), Error> {
    if encryption_context.contains_key(REQUIRED_KEY) {
        Ok(())
    } else {
        Err(Error::validation(format!(
            "the encryption context must contain {REQUIRED_KEY:?}"
        )))
    }
}

#[async_trait]
impl Keyring for RequireContextKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        check(input.materials().encryption_context())?;
        Keyring::on_encrypt(&self.inner, input).await
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        check(input.materials().encryption_context())?;
        Keyring::on_decrypt(&self.inner, input).await
    }
}

/// Step 3: export your keyring.
#[unsafe(no_mangle)]
pub extern "C" fn custom_keyring_create() -> *mut c_void {
    // For demonstration only: a real application must source its wrapping key
    // from a secure store and never hardcode it.
    let Ok(inner) = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x2A; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
    else {
        return std::ptr::null_mut();
    };
    aws_esdk_cpp::into_keyring_handle(RequireContextKeyring { inner })
}
