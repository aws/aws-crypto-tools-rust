// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types shared across the CLI, manifest layer, and project generators.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, TestVectorError>;

/// All errors surfaced by the test-vectors CLI and library.
///
/// The variants are grouped by concern so callers can pattern-match without
/// caring about the specific IO/serde error underneath.
#[derive(Debug, Error)]
pub enum TestVectorError {
    /// The caller asked for a project that is not registered.
    #[error("unknown project '{0}'. Run `test-vectors list` to see registered projects.")]
    UnknownProject(String),

    /// A project trait method has not been implemented yet.
    #[error("project '{project}' does not implement '{operation}' yet")]
    NotImplemented {
        project: &'static str,
        operation: &'static str,
    },

    /// A manifest file is missing, unreadable, or malformed.
    #[error("manifest error at {path}: {message}")]
    Manifest { path: PathBuf, message: String },

    /// A test vector did not produce the expected result.
    #[error("test vector '{name}' failed: {message}")]
    VectorFailure { name: String, message: String },

    /// Filesystem IO error with the offending path attached.
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// serde_json failure. Kept separate from `Manifest` because we want the
    /// underlying error's `line`/`column` for debugging.
    #[error("json error at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// Catch-all for validation and invariant failures that do not fit above.
    #[error("{0}")]
    Other(String),
}

impl TestVectorError {
    /// Convenience constructor for [`TestVectorError::Manifest`].
    pub fn manifest(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::Manifest {
            path: path.into(),
            message: message.into(),
        }
    }

    /// Convenience constructor for [`TestVectorError::Io`].
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Convenience constructor for [`TestVectorError::Json`].
    pub fn json(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::Json {
            path: path.into(),
            source,
        }
    }

    /// Convenience constructor for [`TestVectorError::Other`].
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }
}
