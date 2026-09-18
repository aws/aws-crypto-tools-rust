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
/// TODO(native-mpl): once native MPL is available,
/// model the custom keyring example off of
/// https://github.com/aws/aws-encryption-sdk-python/blob/master/examples/src/custom_mpl_cmm_example.py
fn build_keyring() -> Result<aws_esdk::Keyring, Box<dyn std::error::Error>> {
    let mpl = aws_mpl_legacy::dafny::Client::from_conf(
        aws_mpl_legacy::dafny::types::MaterialProvidersConfig::builder().build()?,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let keyring = runtime.block_on(
        mpl.create_raw_aes_keyring()
            .key_namespace("custom-keyring-example")
            .key_name("demo-key")
            .wrapping_key(WRAPPING_KEY.to_vec())
            .wrapping_alg(aws_mpl_legacy::dafny::types::AesWrappingAlg::AlgAes256GcmIv12Tag16)
            .send(),
    )?;
    Ok(keyring.into())
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
