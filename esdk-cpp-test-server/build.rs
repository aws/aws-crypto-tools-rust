use std::path::{Path, PathBuf};

// Link the server against the prebuilt aws-esdk-cpp shim: compile the C++ seam
// plus the shim's generated cxx bridge, then link the shim cdylib (its Rust side
// stays inside that shared object) and the cxx runtime. Build the shim first
// with `make build-shim` (or `cargo build` in esdk/shims/aws-esdk-cpp); the
// server build does not build it, so the two heavy Rust builds never contend.
fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let shim = manifest
        .join("../esdk/shims/aws-esdk-cpp")
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
        .file(&generated)
        .include(&cxxbridge)
        .include(shim.join("include"))
        .compile("esdk_cpp_seam");

    let cxx_runtime_dir = find_cxx_runtime(&profile_dir.join("build"))
        .expect("locate libcxxbridge1.a under the shim build output");

    println!("cargo:rustc-link-search=native={}", profile_dir.display());
    println!("cargo:rustc-link-lib=dylib=aws_esdk_cpp");
    println!(
        "cargo:rustc-link-search=native={}",
        cxx_runtime_dir.display()
    );
    println!("cargo:rustc-link-lib=static=cxxbridge1");
    // rpath so the server finds libaws_esdk_cpp at runtime.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", profile_dir.display());
    // CI links with rust-lld + --gc-sections (rustc default), which drops the
    // header-only Aws::Esdk facade weak inline symbols; keep all sections.
    println!("cargo:rustc-link-arg=-Wl,--no-gc-sections");

    println!("cargo:rerun-if-changed=src/seam.cpp");
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

fn find_cxx_runtime(build_dir: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(build_dir).ok()? {
        let dir = entry.ok()?.path();
        let name = dir.file_name()?.to_string_lossy().into_owned();
        if name.starts_with("cxx-") && dir.join("out/libcxxbridge1.a").exists() {
            return Some(dir.join("out"));
        }
    }
    None
}
