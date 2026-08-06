fn main() {
    // Generate the cxx bridge code and compile it, together with the shim's
    // compiled facade (EncryptionSDK.cpp) — the only translation unit that
    // touches the cxx-generated FFI layer. Building it here bundles the facade
    // into the same staticlib, so consumers link exactly what they did before.
    cxx_build::bridge("src/lib.rs")
        .file("src/EncryptionSDK.cpp")
        .include("include")
        .flag_if_supported("-std=c++17")
        .compile("cxxbridge-aws-mpl-cxx");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/EncryptionSDK.cpp");
    println!("cargo:rerun-if-changed=include/aws/esdk/EncryptionSDK.h");
}
