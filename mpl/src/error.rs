// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types for the Material Providers Library.

use std::fmt;

/// Errors returned by the Material Providers Library.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {}

impl fmt::Display for Error {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}

impl std::error::Error for Error {}
