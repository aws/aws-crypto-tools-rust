// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    // Generates the cxx bridge code and compile it together
    // with the shim's facade into the same staticlib.
    cxx_build::bridge("src/lib.rs")
        .file("src/EncryptionSDK.cpp")
        .include("include")
        .flag_if_supported("-std=c++17")
        .compile("cxxbridge-aws-mpl-cxx");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/EncryptionSDK.cpp");
    println!("cargo:rerun-if-changed=include/aws/esdk/EncryptionSDK.h");
}
