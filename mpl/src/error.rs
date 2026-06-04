// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types for the Material Providers Library.

use std::fmt;

/// Errors returned by the Material Providers Library.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The configuration provided to the builder is invalid.
    InvalidConfig {
        /// Description of what is invalid.
        message: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig { message } => write!(f, "invalid config: {message}"),
        }
    }
}

impl std::error::Error for Error {}
