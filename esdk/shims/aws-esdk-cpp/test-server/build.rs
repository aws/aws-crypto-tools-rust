// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

// Link the server against the prebuilt aws-esdk-cpp shim: compile the C++ seam,
// the shim's compiled facade (EncryptionSDK.cpp), and the shim's generated cxx
// bridge, then link the shim cdylib (its Rust side stays inside that shared
// object). Build the shim first with `make build-shim` (or
// `cargo build` in esdk/shims/aws-esdk-cpp); the server build does not build it,
// so the two heavy Rust builds never contend.
fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let shim = manifest
        .join("..")
        .canonicalize()
        .expect("locate the aws-esdk-cpp shim crate");
    let target = shim.join("target");
    let cxxbridge = target.join("cxxbridge");
    let generated = cxxbridge.join("aws-esdk-cpp/src/lib.rs.cc");
    let profile = std::env::var("PROFILE").expect("PROFILE");

    let profile_dir = pick_profile_dir(&target, &profile).unwrap_or_else(|| {
        panic!(
            "the aws-esdk-cpp shim is not built. Build it first:\n  (cd {} && cargo build --release)",
            shim.display()
        )
    });
    assert!(
        generated.exists(),
        "missing generated bridge at {generated:?}; build the aws-esdk-cpp shim first"
    );

    // cc links the C++ standard library itself (libstdc++ on GNU/Linux, libc++
    // on macOS), so it is not named explicitly here.
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .file(manifest.join("src/seam.cpp"))
        .file(shim.join("src/EncryptionSDK.cpp"))
        .file(&generated)
        .include(&cxxbridge)
        .include(shim.join("include"))
        .include(profile_dir.join("include"))
        .compile("esdk_cpp_seam");

    println!("cargo:rustc-link-search=native={}", profile_dir.display());
    println!("cargo:rustc-link-lib=dylib=aws_esdk_cpp");
    // rpath so the server finds libaws_esdk_cpp at runtime.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", profile_dir.display());

    println!("cargo:rerun-if-changed=src/seam.cpp");
    println!(
        "cargo:rerun-if-changed={}",
        shim.join("src/EncryptionSDK.cpp").display()
    );
    println!("cargo:rerun-if-changed=build.rs");
}

// Prefer the server's own profile, then release, then debug — whichever the shim
// was built in. The shim links dynamically, so the profiles need not match.
fn pick_profile_dir(target: &Path, profile: &str) -> Option<PathBuf> {
    let mut order = vec![profile.to_owned()];
    for fallback in ["release", "debug"] {
        if !order.iter().any(|p| p == fallback) {
            order.push(fallback.to_owned());
        }
    }
    order
        .into_iter()
        .map(|p| target.join(p))
        .find(|dir| has_cdylib(dir))
}

fn has_cdylib(dir: &Path) -> bool {
    dir.join("libaws_esdk_cpp.so").exists() || dir.join("libaws_esdk_cpp.dylib").exists()
}
