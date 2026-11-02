// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The RSA padding schemes that a raw RSA keyring supports.

use aws_mpl_primitives::RsaPadding;

/// The RSA padding scheme that a raw RSA keyring wraps data keys with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PaddingScheme {
    /// RSAES-PKCS1-v1_5.
    Pkcs1,
    /// RSAES-OAEP with SHA-1 and MGF1 with SHA-1.
    OaepSha1Mgf1,
    /// RSAES-OAEP with SHA-256 and MGF1 with SHA-256.
    OaepSha256Mgf1,
    /// RSAES-OAEP with SHA-384 and MGF1 with SHA-384.
    OaepSha384Mgf1,
    /// RSAES-OAEP with SHA-512 and MGF1 with SHA-512.
    OaepSha512Mgf1,
}

impl PaddingScheme {
    /// The primitive that implements this padding scheme.
    pub(crate) const fn primitive(self) -> RsaPadding {
        match self {
            Self::Pkcs1 => RsaPadding::Pkcs1,
            Self::OaepSha1Mgf1 => RsaPadding::OaepSha1,
            Self::OaepSha256Mgf1 => RsaPadding::OaepSha256,
            Self::OaepSha384Mgf1 => RsaPadding::OaepSha384,
            Self::OaepSha512Mgf1 => RsaPadding::OaepSha512,
        }
    }
}
