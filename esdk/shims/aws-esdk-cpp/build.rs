// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// "1" when Cargo turned on every named feature of this crate, else "0".
fn features_on(features: &[&str]) -> &'static str {
    let on = features.iter().all(|feature| {
        let var = format!("CARGO_FEATURE_{}", feature.to_uppercase().replace('-', "_"));
        std::env::var_os(var).is_some()
    });
    if on { "1" } else { "0" }
}

fn main() {
    // Generates the cxx bridge code and compile it together
    // with the shim's facade into the same staticlib.
    cxx_build::bridge("src/lib.rs")
        .file("src/EncryptionSDK.cpp")
        .include("include")
        .flag_if_supported("-std=c++17")
        // Tells EncryptionSDK.cpp which optional parts of the API to build.
        // EncryptionSDK.h explains each one.
        .define(
            "AWS_ESDK_CPP_HIERARCHICAL_KEYRING",
            features_on(&["kms", "ddb", "default-aws-sdk-clients"]),
        )
        .define(
            "AWS_ESDK_CPP_STORM_TRACKING_CMC",
            features_on(&["kms", "ddb", "default-aws-sdk-clients", "rt-tokio"]),
        )
        .compile("cxxbridge-aws-mpl-cxx");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/EncryptionSDK.cpp");
    println!("cargo:rerun-if-changed=include/aws/esdk/EncryptionSDK.h");
}
