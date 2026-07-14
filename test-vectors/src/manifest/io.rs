// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for reading and writing manifests to disk.
//!
//! The MPL Dafny tool references the keys file with a `file://` URI relative
//! to the manifest directory (`"keys": "file://keys.json"`). These helpers
//! preserve that convention and resolve the URI so callers get an absolute
//! path back.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Result, TestVectorError};

/// Filename the tool always writes for the top-level manifest.
pub const MANIFEST_FILENAME: &str = "manifest.json";

/// Filename the tool always writes for the associated keys.
pub const KEYS_FILENAME: &str = "keys.json";

/// URI written into the top-level manifest's `keys` field.
pub const DEFAULT_KEYS_URI: &str = "file://keys.json";

/// Ensure `dir` exists as a directory, creating it (and parents) if needed.
pub fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() {
        return Err(TestVectorError::other("empty output directory"));
    }
    fs::create_dir_all(dir).map_err(|e| TestVectorError::io(dir, e))
}

/// Serialize `value` as pretty-printed JSON and write it to `path`. Parent
/// directories are created if they do not exist.
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_dir(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| TestVectorError::json(path, e))?;
    fs::write(path, bytes).map_err(|e| TestVectorError::io(path, e))
}

/// Read `path` and deserialize it as JSON.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).map_err(|e| TestVectorError::io(path, e))?;
    serde_json::from_slice(&bytes).map_err(|e| TestVectorError::json(path, e))
}

/// Return `dir/manifest.json`.
pub fn manifest_path(dir: &Path) -> PathBuf {
    dir.join(MANIFEST_FILENAME)
}

/// Return `dir/keys.json`.
pub fn keys_path(dir: &Path) -> PathBuf {
    dir.join(KEYS_FILENAME)
}

/// Resolve a `file://` URI relative to `manifest_dir` into an absolute path.
///
/// The MPL Dafny tool writes `"file://keys.json"` and expects the reader to
/// join that relative path with the manifest directory. This helper matches
/// that behavior and returns an error for unsupported URI schemes.
pub fn resolve_keys_uri(manifest_dir: &Path, uri: &str) -> Result<PathBuf> {
    let stripped = uri.strip_prefix("file://").ok_or_else(|| {
        TestVectorError::manifest(
            manifest_dir.to_path_buf(),
            format!("unsupported keys URI scheme: '{uri}' (only file:// is supported)"),
        )
    })?;
    Ok(manifest_dir.join(stripped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn resolve_keys_uri_joins_relative_path() {
        let dir = Path::new("/tmp/some/where");
        let resolved = resolve_keys_uri(dir, "file://keys.json").unwrap();
        assert_eq!(resolved, dir.join("keys.json"));
    }

    #[test]
    fn resolve_keys_uri_rejects_unknown_scheme() {
        let err = resolve_keys_uri(Path::new("/tmp"), "http://example.com/keys.json").unwrap_err();
        assert!(
            format!("{err}").contains("unsupported keys URI scheme"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn write_and_read_json_round_trips_a_value() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.json");
        let value = json!({"hello": "world"});
        write_json(&path, &value).unwrap();
        let read: serde_json::Value = read_json(&path).unwrap();
        assert_eq!(read, value);
    }

    #[test]
    fn write_json_creates_missing_parent_directories() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("a/b/c/out.json");
        write_json(&nested, &json!({"ok": true})).unwrap();
        assert!(nested.exists());
    }
}
