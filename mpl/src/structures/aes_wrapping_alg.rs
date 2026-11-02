// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The AES wrapping algorithms a raw AES keyring supports.

use aws_mpl_primitives::AesGcm;

/// An AES-GCM wrapping algorithm, with a 12-byte IV and a 16-byte tag.
/// The wrapping key's length must match the algorithm's key size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AesWrappingAlg {
    /// AES-128-GCM: a 16-byte wrapping key.
    AlgAes128GcmIv12Tag16,
    /// AES-192-GCM: a 24-byte wrapping key.
    AlgAes192GcmIv12Tag16,
    /// AES-256-GCM: a 32-byte wrapping key.
    AlgAes256GcmIv12Tag16,
}

impl AesWrappingAlg {
    /// The wrapping key length this algorithm needs, in bytes.
    #[must_use]
    pub fn key_length(self) -> usize {
        usize::from(self.primitive().key_len())
    }

    /// The primitive that implements this algorithm.
    pub(crate) const fn primitive(self) -> AesGcm {
        match self {
            Self::AlgAes128GcmIv12Tag16 => AesGcm::Aes128Gcm,
            Self::AlgAes192GcmIv12Tag16 => AesGcm::Aes192Gcm,
            Self::AlgAes256GcmIv12Tag16 => AesGcm::Aes256Gcm,
        }
    }
}
