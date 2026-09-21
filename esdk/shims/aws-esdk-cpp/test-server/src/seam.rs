//! Safe wrappers over the C++ facade seam (src/seam.cpp).

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

extern "C" {
    fn esdk_cpp_create_hierarchical_client(
        region: *const c_char,
        table_name: *const c_char,
        logical_key_store_name: *const c_char,
        kms_key_arn: *const c_char,
        branch_key_id: *const c_char,
        ttl_seconds: u32,
        out_client: *mut *mut c_void,
        out_err: *mut *mut c_char,
    ) -> c_int;

    fn esdk_cpp_create_raw_aes_client(
        key_namespace: *const c_char,
        key_name: *const c_char,
        wrapping_key: *const u8,
        wrapping_key_len: usize,
        wrapping_alg: u8,
        out_client: *mut *mut c_void,
        out_err: *mut *mut c_char,
    ) -> c_int;

    fn esdk_cpp_encrypt(
        client: *mut c_void,
        plaintext: *const u8,
        plaintext_len: usize,
        commitment_policy: u8,
        algorithm_suite_id: u16,
        frame_length: u32,
        max_encrypted_data_keys: u32,
        ec_keys: *const *const c_char,
        ec_vals: *const *const c_char,
        ec_len: usize,
        out_buf: *mut *mut u8,
        out_len: *mut usize,
        out_err: *mut *mut c_char,
    ) -> c_int;

    fn esdk_cpp_decrypt(
        client: *mut c_void,
        ciphertext: *const u8,
        ciphertext_len: usize,
        commitment_policy: u8,
        max_encrypted_data_keys: u32,
        ec_keys: *const *const c_char,
        ec_vals: *const *const c_char,
        ec_len: usize,
        out_buf: *mut *mut u8,
        out_len: *mut usize,
        out_err: *mut *mut c_char,
    ) -> c_int;

    fn esdk_cpp_encrypt_stream(
        client: *mut c_void,
        plaintext: *const u8,
        plaintext_len: usize,
        commitment_policy: u8,
        algorithm_suite_id: u16,
        frame_length: u32,
        max_encrypted_data_keys: u32,
        ec_keys: *const *const c_char,
        ec_vals: *const *const c_char,
        ec_len: usize,
        out_buf: *mut *mut u8,
        out_len: *mut usize,
        out_err: *mut *mut c_char,
    ) -> c_int;

    fn esdk_cpp_decrypt_stream(
        client: *mut c_void,
        ciphertext: *const u8,
        ciphertext_len: usize,
        commitment_policy: u8,
        max_encrypted_data_keys: u32,
        ec_keys: *const *const c_char,
        ec_vals: *const *const c_char,
        ec_len: usize,
        out_buf: *mut *mut u8,
        out_len: *mut usize,
        out_err: *mut *mut c_char,
    ) -> c_int;

    fn esdk_cpp_free_client(client: *mut c_void);
    fn esdk_cpp_free_buf(buf: *mut u8);
    fn esdk_cpp_free_err(err: *mut c_char);
}

/// Owns a C++ keyring handle (a `Keyring` base pointer) and frees it on drop.
pub struct CppClient {
    handle: *mut c_void,
}

// SAFETY: the handle is only dereferenced by the C++ seam while the backend
// holds this client's Mutex, so it is never used concurrently. The resources it
// wraps are the same ones aws-esdk drives across tokio worker threads.
unsafe impl Send for CppClient {}

impl Drop for CppClient {
    fn drop(&mut self) {
        // SAFETY: `handle` came from a successful create call and is freed once.
        unsafe { esdk_cpp_free_client(self.handle) };
    }
}

/// Encryption context marshalled into the C string arrays the seam expects.
/// The owned `CString`s must outlive the pointer vectors, so both are kept here.
struct CEncryptionContext {
    _keys: Vec<CString>,
    _vals: Vec<CString>,
    key_ptrs: Vec<*const c_char>,
    val_ptrs: Vec<*const c_char>,
}

fn to_c_encryption_context(ec: &[(String, String)]) -> Result<CEncryptionContext, String> {
    let mut keys = Vec::with_capacity(ec.len());
    let mut vals = Vec::with_capacity(ec.len());
    for (key, value) in ec {
        let key = CString::new(key.as_str())
            .map_err(|_| "encryption-context key contains an interior NUL".to_string())?;
        let value = CString::new(value.as_str())
            .map_err(|_| "encryption-context value contains an interior NUL".to_string())?;
        keys.push(key);
        vals.push(value);
    }
    let key_ptrs = keys.iter().map(|c| c.as_ptr()).collect();
    let val_ptrs = vals.iter().map(|c| c.as_ptr()).collect();
    Ok(CEncryptionContext {
        _keys: keys,
        _vals: vals,
        key_ptrs,
        val_ptrs,
    })
}

/// SAFETY: `err` is either null or a message the seam malloc'd for us to free.
unsafe fn take_err(err: *mut c_char) -> String {
    if err.is_null() {
        return "C++ seam reported failure without a message".to_string();
    }
    let message = CStr::from_ptr(err).to_string_lossy().into_owned();
    esdk_cpp_free_err(err);
    message
}

/// SAFETY: `buf`/`len` describe a buffer the seam malloc'd for us to free.
unsafe fn take_buf(buf: *mut u8, len: usize) -> Vec<u8> {
    let out = std::slice::from_raw_parts(buf, len).to_vec();
    esdk_cpp_free_buf(buf);
    out
}

pub fn create_hierarchical_client(
    region: &str,
    table_name: &str,
    logical_key_store_name: &str,
    kms_key_arn: &str,
    branch_key_id: &str,
    ttl_seconds: u32,
) -> Result<CppClient, String> {
    let region = CString::new(region).map_err(|_| "region contains an interior NUL".to_string())?;
    let table = CString::new(table_name)
        .map_err(|_| "keyStoreTableName contains an interior NUL".to_string())?;
    let logical = CString::new(logical_key_store_name)
        .map_err(|_| "logicalKeyStoreName contains an interior NUL".to_string())?;
    let kms =
        CString::new(kms_key_arn).map_err(|_| "kmsKeyArn contains an interior NUL".to_string())?;
    let branch = CString::new(branch_key_id)
        .map_err(|_| "branchKeyId contains an interior NUL".to_string())?;

    let mut handle: *mut c_void = ptr::null_mut();
    let mut err: *mut c_char = ptr::null_mut();
    // SAFETY: every pointer is valid for the call; the seam writes exactly one
    // of *out_client / *out_err according to its return code.
    let rc = unsafe {
        esdk_cpp_create_hierarchical_client(
            region.as_ptr(),
            table.as_ptr(),
            logical.as_ptr(),
            kms.as_ptr(),
            branch.as_ptr(),
            ttl_seconds,
            &mut handle,
            &mut err,
        )
    };
    if rc == 0 {
        Ok(CppClient { handle })
    } else {
        Err(unsafe { take_err(err) })
    }
}

pub fn create_raw_aes_client(
    key_namespace: &str,
    key_name: &str,
    wrapping_key: &[u8],
    wrapping_alg: u8,
) -> Result<CppClient, String> {
    let namespace = CString::new(key_namespace)
        .map_err(|_| "keyNamespace contains an interior NUL".to_string())?;
    let name =
        CString::new(key_name).map_err(|_| "keyName contains an interior NUL".to_string())?;

    let mut handle: *mut c_void = ptr::null_mut();
    let mut err: *mut c_char = ptr::null_mut();
    // SAFETY: the strings and slice outlive the call; the seam writes exactly
    // one of *out_client / *out_err according to its return code.
    let rc = unsafe {
        esdk_cpp_create_raw_aes_client(
            namespace.as_ptr(),
            name.as_ptr(),
            wrapping_key.as_ptr(),
            wrapping_key.len(),
            wrapping_alg,
            &mut handle,
            &mut err,
        )
    };
    if rc == 0 {
        Ok(CppClient { handle })
    } else {
        Err(unsafe { take_err(err) })
    }
}

pub fn encrypt(
    client: &CppClient,
    plaintext: &[u8],
    commitment_policy: u8,
    algorithm_suite_id: u16,
    frame_length: u32,
    max_encrypted_data_keys: u32,
    encryption_context: &[(String, String)],
) -> Result<Vec<u8>, String> {
    let ec = to_c_encryption_context(encryption_context)?;
    let mut buf: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let mut err: *mut c_char = ptr::null_mut();
    // SAFETY: the client handle is live, the slices outlive the call, and the
    // seam writes exactly one of the out buffer / out error.
    let rc = unsafe {
        esdk_cpp_encrypt(
            client.handle,
            plaintext.as_ptr(),
            plaintext.len(),
            commitment_policy,
            algorithm_suite_id,
            frame_length,
            max_encrypted_data_keys,
            ec.key_ptrs.as_ptr(),
            ec.val_ptrs.as_ptr(),
            ec.key_ptrs.len(),
            &mut buf,
            &mut len,
            &mut err,
        )
    };
    if rc == 0 {
        Ok(unsafe { take_buf(buf, len) })
    } else {
        Err(unsafe { take_err(err) })
    }
}

pub fn decrypt(
    client: &CppClient,
    ciphertext: &[u8],
    commitment_policy: u8,
    max_encrypted_data_keys: u32,
    encryption_context: &[(String, String)],
) -> Result<Vec<u8>, String> {
    let ec = to_c_encryption_context(encryption_context)?;
    let mut buf: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let mut err: *mut c_char = ptr::null_mut();
    // SAFETY: as in `encrypt`.
    let rc = unsafe {
        esdk_cpp_decrypt(
            client.handle,
            ciphertext.as_ptr(),
            ciphertext.len(),
            commitment_policy,
            max_encrypted_data_keys,
            ec.key_ptrs.as_ptr(),
            ec.val_ptrs.as_ptr(),
            ec.key_ptrs.len(),
            &mut buf,
            &mut len,
            &mut err,
        )
    };
    if rc == 0 {
        Ok(unsafe { take_buf(buf, len) })
    } else {
        Err(unsafe { take_err(err) })
    }
}

pub fn encrypt_stream(
    client: &CppClient,
    plaintext: &[u8],
    commitment_policy: u8,
    algorithm_suite_id: u16,
    frame_length: u32,
    max_encrypted_data_keys: u32,
    encryption_context: &[(String, String)],
) -> Result<Vec<u8>, String> {
    let ec = to_c_encryption_context(encryption_context)?;
    let mut buf: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let mut err: *mut c_char = ptr::null_mut();
    // SAFETY: as in `encrypt`.
    let rc = unsafe {
        esdk_cpp_encrypt_stream(
            client.handle,
            plaintext.as_ptr(),
            plaintext.len(),
            commitment_policy,
            algorithm_suite_id,
            frame_length,
            max_encrypted_data_keys,
            ec.key_ptrs.as_ptr(),
            ec.val_ptrs.as_ptr(),
            ec.key_ptrs.len(),
            &mut buf,
            &mut len,
            &mut err,
        )
    };
    if rc == 0 {
        Ok(unsafe { take_buf(buf, len) })
    } else {
        Err(unsafe { take_err(err) })
    }
}

pub fn decrypt_stream(
    client: &CppClient,
    ciphertext: &[u8],
    commitment_policy: u8,
    max_encrypted_data_keys: u32,
    encryption_context: &[(String, String)],
) -> Result<Vec<u8>, String> {
    let ec = to_c_encryption_context(encryption_context)?;
    let mut buf: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let mut err: *mut c_char = ptr::null_mut();
    // SAFETY: as in `encrypt`.
    let rc = unsafe {
        esdk_cpp_decrypt_stream(
            client.handle,
            ciphertext.as_ptr(),
            ciphertext.len(),
            commitment_policy,
            max_encrypted_data_keys,
            ec.key_ptrs.as_ptr(),
            ec.val_ptrs.as_ptr(),
            ec.key_ptrs.len(),
            &mut buf,
            &mut len,
            &mut err,
        )
    };
    if rc == 0 {
        Ok(unsafe { take_buf(buf, len) })
    } else {
        Err(unsafe { take_err(err) })
    }
}
