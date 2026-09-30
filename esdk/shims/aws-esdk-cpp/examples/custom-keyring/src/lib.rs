//! Your custom keyring, defined in Rust and exported to C++.
//!
//! Step 2 (`build_keyring`): define your keyring.
//! Step 3 (`custom_keyring_create`): export it as a handle for C++ to adopt.
//! See README.md for the full setup, and example.cpp for the C++ side.

use std::ffi::c_void;

/// For demonstration only: a real application must source its wrapping key
/// from a secure store and never hardcode it.
const WRAPPING_KEY: [u8; 32] = [0x2A; 32];

/// Step 2: define your keyring.
///
/// TODO: provide custom implementations of the Keyring interface's methods
fn build_keyring() -> Result<impl aws_esdk::Keyring, Box<dyn std::error::Error>> {
    Ok(aws_crypto_mpl::keyring::RawAesKeyring::builder()
        .key_namespace("custom-keyring-example")
        .key_name("demo-key")
        .wrapping_key(WRAPPING_KEY.to_vec())
        .wrapping_alg(aws_crypto_mpl::AesGcm::Aes256Gcm)
        .build()?)
}

/// Step 3: export your keyring.
#[unsafe(no_mangle)]
pub extern "C" fn custom_keyring_create() -> *mut c_void {
    match build_keyring() {
        Ok(keyring) => aws_esdk_cpp::into_keyring_handle(keyring),
        Err(e) => {
            eprintln!("custom_keyring_create failed: {e}");
            std::ptr::null_mut()
        }
    }
}
