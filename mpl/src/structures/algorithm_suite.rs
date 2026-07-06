// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stub algorithm suite and key newtypes.

use std::fmt;

/// Stub algorithm suite with signing capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmSuite {
    has_asymmetric_signing: bool,
    has_symmetric_signing: bool,
}

impl AlgorithmSuite {
    pub const fn new(has_asymmetric_signing: bool, has_symmetric_signing: bool) -> Self {
        Self {
            has_asymmetric_signing,
            has_symmetric_signing,
        }
    }

    pub const fn has_asymmetric_signing(&self) -> bool {
        self.has_asymmetric_signing
    }

    pub const fn has_symmetric_signing(&self) -> bool {
        self.has_symmetric_signing
    }
}

/// Plaintext data key (secret).
#[derive(Clone, PartialEq, Eq)]
pub struct PlaintextDataKey(Vec<u8>);

impl PlaintextDataKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Zero the plaintext data key material.
    //
    pub fn zeroize(&mut self) {
        let ptr = self.0.as_mut_ptr();
        let len = self.0.len();
        for i in 0..len {
            // SAFETY: we're within bounds of the allocated Vec
            unsafe {
                core::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
    }
}

impl fmt::Debug for PlaintextDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlaintextDataKey([REDACTED; {} bytes])", self.0.len())
    }
}

/// Signing key (secret).
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKey(Vec<u8>);

impl SigningKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey([REDACTED; {} bytes])", self.0.len())
    }
}

/// Verification key (public, not secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey(Vec<u8>);

impl VerificationKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Symmetric signing key (secret).
#[derive(Clone, PartialEq, Eq)]
pub struct SymmetricSigningKey(Vec<u8>);

impl SymmetricSigningKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SymmetricSigningKey {
    //
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymmetricSigningKey([REDACTED; {} bytes])", self.0.len())
    }
}
