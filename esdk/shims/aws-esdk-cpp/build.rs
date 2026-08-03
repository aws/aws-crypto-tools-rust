fn main() {
    // Generate the cxx bridge code and compile it.
    cxx_build::bridge("src/lib.rs")
        .flag_if_supported("-std=c++11")
        .compile("cxxbridge-aws-mpl-cxx");
    println!("cargo:rerun-if-changed=src/lib.rs");
}
