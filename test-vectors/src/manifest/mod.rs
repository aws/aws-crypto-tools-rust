// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Manifest schema and IO layer.
//!
//! The submodules define:
//!
//! * [`header`] — the shared `manifest` block (`{version, type}`)
//! * [`encrypt`] — the `awses-mpl-encrypt` schema
//! * [`decrypt`] — the `awses-mpl-decrypt` schema
//! * [`keys`] — the `keys.json` schema
//! * [`codec`] — base64 encode/decode helpers for byte-valued fields
//! * [`io`] — read/write and `file://` URI helpers
//!
//! All shapes deliberately mirror the JSON produced by the MPL Dafny tool so
//! manifests can be exchanged with other language implementations.
//!
//! `encrypt::NegativeDecryptVector` (an encrypt-manifest vector whose
//! subsequent decrypt is expected to fail) and `decrypt::NegativeDecryptVector`
//! (a decrypt-manifest vector) share a name but describe different things; both
//! are re-exported below under distinct aliases so callers can disambiguate at
//! the use-site.

pub mod codec;
pub mod decrypt;
pub mod encrypt;
pub mod header;
pub mod io;
pub mod keys;

use serde::Serialize;
use uuid::Uuid;

/// Namespace under which every test-vector UUID emitted by this crate lives.
///
/// We reuse the RFC 4122 URL namespace and derive a project-scoped sub-namespace
/// from a fixed string identifying this crate. Both hops are v5, so the value
/// is fully determined by the crate identity — no persistent state required.
fn test_vectors_namespace() -> Uuid {
    // std::sync::LazyLock is stable in the Rust versions we target, but a
    // tiny helper function avoids adding a `use` and keeps the API narrow.
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        b"https://github.com/aws/aws-crypto-tools-rust/test-vectors",
    )
}

/// Deterministic UUID for a serializable test vector.
///
/// The UUID is a v5 hash of `serde_json::to_string(vector)` under
/// [`test_vectors_namespace`]. Two structurally identical vectors always
/// resolve to the same UUID, which is what keeps checked-in manifests
/// byte-stable across regeneration.
///
/// # Panics
///
/// Panics if `vector` fails to serialize. All vector types in this crate use
/// derived `Serialize` impls over primitive types and never fail to serialize
/// in practice; a panic here would indicate a programmer error (custom impl
/// or a NaN in a float field), not a runtime data problem.
pub fn vector_uuid<T: Serialize>(vector: &T) -> String {
    let seed = serde_json::to_string(vector)
        .expect("test-vector serialization is infallible for this crate's vector types");
    Uuid::new_v5(&test_vectors_namespace(), seed.as_bytes()).to_string()
}

pub use decrypt::{
    DecryptManifest, DecryptResult, DecryptTestVector, EncryptedDataKey,
    NegativeDecryptVector as NegativeDecryptManifestVector, PositiveDecryptVector,
};
pub use encrypt::{
    EncryptManifest, EncryptTestVector, NegativeDecryptVector as NegativeDecryptEncryptVector,
    NegativeEncryptVector, PositiveEncryptVector,
};
pub use header::{
    CURRENT_MANIFEST_VERSION, DECRYPT_MANIFEST_TYPE, ENCRYPT_MANIFEST_TYPE, ManifestHeader,
};
pub use keys::{CURRENT_KEYS_VERSION, KEYS_MANIFEST_TYPE, KeyManifest};
