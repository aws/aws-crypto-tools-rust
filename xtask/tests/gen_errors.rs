// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The checks `gen-errors` runs before it writes anything.

const SPEC: &str = include_str!("../../errors.toml");

fn spec() -> xtask::Spec {
    xtask::parse(SPEC).unwrap()
}

fn library<'a>(spec: &'a mut xtask::Spec, name: &str) -> &'a mut xtask::Library {
    spec.libraries.iter_mut().find(|l| l.name == name).unwrap()
}

fn generation_error(spec: &xtask::Spec) -> String {
    xtask::generate(spec).unwrap_err()
}

#[test]
fn the_checked_in_spec_generates_every_library() {
    let outputs = xtask::generate(&spec()).unwrap();
    assert_eq!(outputs.len(), 2);
    for out in outputs {
        assert!(out.contents.starts_with(xtask::HEADER), "{}", out.path);
    }
}

#[test]
fn a_source_variant_with_no_target_and_no_fallback_fails() {
    let mut spec = spec();
    library(&mut spec, "mpl")
        .variants
        .retain(|v| v != "Cryptographic");
    let err = generation_error(&spec);
    assert!(err.contains("`mpl` converts from `prim`"), "{err}");
    assert!(err.contains("variant `Cryptographic`"), "{err}");
    assert!(err.contains("no fallback"), "{err}");
}

#[test]
fn a_fallback_covers_a_missing_variant() {
    let mut spec = spec();
    let mpl = library(&mut spec, "mpl");
    mpl.variants.retain(|v| v != "Cryptographic");
    mpl.from[0]
        .fallback
        .insert("Cryptographic".into(), "Internal".into());
    let outputs = xtask::generate(&spec).unwrap();
    let mpl = outputs.iter().find(|o| o.path.starts_with("mpl")).unwrap();
    assert!(
        mpl.contents
            .contains("aws_mpl_primitives::error::Error::Cryptographic(_) => Kind::Internal")
    );
}

#[test]
fn a_fallback_to_a_variant_the_target_lacks_fails() {
    let mut spec = spec();
    let mpl = library(&mut spec, "mpl");
    mpl.variants.retain(|v| v != "Io");
    mpl.from[0]
        .fallback
        .insert("Cryptographic".into(), "Io".into());
    let err = generation_error(&spec);
    assert!(err.contains("maps `Cryptographic` to `Io`"), "{err}");
    assert!(err.contains("which `mpl` does not have"), "{err}");
}

#[test]
fn a_fallback_for_a_variant_the_source_lacks_fails() {
    let mut spec = spec();
    library(&mut spec, "mpl").from[0]
        .fallback
        .insert("Throttling".into(), "Internal".into());
    let err = generation_error(&spec);
    assert!(err.contains("source variant `Throttling`"), "{err}");
}

#[test]
fn a_library_without_internal_fails() {
    let mut spec = spec();
    library(&mut spec, "prim")
        .variants
        .retain(|v| v != "Internal");
    let err = generation_error(&spec);
    assert!(err.contains("`prim` has no `Internal` variant"), "{err}");
}

#[test]
fn an_undefined_variant_fails() {
    let mut spec = spec();
    library(&mut spec, "prim").variants.push("Nope".into());
    let err = generation_error(&spec);
    assert!(
        err.contains("variant `Nope`, which no [[variant]] defines"),
        "{err}"
    );
}
