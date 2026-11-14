// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Controls that the commons test runner sends to a Rust test server between tests.
//!
//! The servers answer `POST /control/coverage` only when they are built with
//! `RUSTFLAGS="-C instrument-coverage --cfg testserver_coverage"`.

#[cfg(testserver_coverage)]
mod llvm {
    use std::ffi::{c_char, c_int};

    // The LLVM profile runtime that `-C instrument-coverage` links into the binary.
    extern "C" {
        pub fn __llvm_profile_set_filename(name: *const c_char);
        pub fn __llvm_profile_write_file() -> c_int;
        pub fn __llvm_profile_reset_counters();
    }
}

/// Writes the coverage counters to `path`, then sets them all to zero.
///
/// The runner calls this after each test, so each file holds the lines that one test ran.
#[cfg(testserver_coverage)]
pub fn dump_coverage(path: &str) -> Result<(), String> {
    use std::ffi::CString;
    use std::sync::Mutex;

    // Two dumps at once would interleave their file names and resets.
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let test_file = CString::new(path).map_err(|e| format!("bad coverage path {path:?}: {e}"))?;
    // At exit the runtime writes to the last file name it was given,
    // so after the dump it gets the server's own LLVM_PROFILE_FILE back.
    let exit_file = CString::new(std::env::var("LLVM_PROFILE_FILE").unwrap_or_default())
        .map_err(|e| format!("bad LLVM_PROFILE_FILE: {e}"))?;
    // SAFETY: both names are NUL-terminated and the runtime copies them.
    let status = unsafe {
        llvm::__llvm_profile_set_filename(test_file.as_ptr());
        let status = llvm::__llvm_profile_write_file();
        llvm::__llvm_profile_reset_counters();
        llvm::__llvm_profile_set_filename(exit_file.as_ptr());
        status
    };
    if status == 0 {
        Ok(())
    } else {
        Err(format!("the LLVM profile runtime could not write {path}"))
    }
}
