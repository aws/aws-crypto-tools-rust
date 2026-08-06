//! A consumer-defined keyring, built in Rust and exported to C++.
//!
//! This crate owns the keyring: which algorithm wraps data keys and where the
//! wrapping key comes from. `custom_keyring_create` packages it as a handle
//! that C++ adopts with `Aws::Esdk::Keyring::adopt` (see `example.cpp`).

use std::ffi::c_void;

/// For demonstration only: a real application must source its wrapping key
/// from a secure store and never hardcode it.
const WRAPPING_KEY: [u8; 32] = [0x2A; 32];

/// This consumer's keyring: raw AES-256-GCM over the crate's own key material.
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

/// Entry point the C++ example calls. Returns a keyring handle for
/// `Aws::Esdk::Keyring::adopt`, or null when construction fails. Ownership of
/// a non-null handle transfers to the caller's single adopt call.
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
