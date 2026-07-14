fn main() {
    // Generate the cxx bridge code and compile it.
    cxx_build::bridge("src/lib.rs")
        .flag_if_supported("-std=c++11")
        .compile("cxxbridge-aws-mpl-cxx");

    // The C++ standard library is linked automatically by the `link-cplusplus`
    // crate (a transitive dependency of `cxx`), which selects the platform's
    // C++ runtime (libstdc++ on GNU/Linux, libc++ on macOS).
    println!("cargo:rerun-if-changed=src/lib.rs");
}
