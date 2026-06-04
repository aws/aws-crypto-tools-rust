// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    #[non_exhaustive]
    InvalidConfig { message: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig { message } => write!(f, "invalid config: {message}"),
        }
    }
}

impl std::error::Error for Error {}
