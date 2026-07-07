// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types for materials structures.

use std::fmt;

/// Error type for materials structure construction and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterialsError {
    pub message: String,
}

impl MaterialsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MaterialsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MaterialsError: {}", self.message)
    }
}

impl std::error::Error for MaterialsError {}
