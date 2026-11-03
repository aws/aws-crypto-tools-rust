// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The elliptic curves that the ECDH keyrings support.

use aws_mpl_primitives::EcdhCurveSpec as PrimCurve;

/// The elliptic curve that an ECDH keyring's keys are on.
///
/// The Dafny MPL also names SM2, which no Rust implementation supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EcdhCurveSpec {
    /// NIST P-256.
    EccNistP256,
    /// NIST P-384.
    EccNistP384,
    /// NIST P-521.
    EccNistP521,
}

impl EcdhCurveSpec {
    /// The primitive curve.
    pub(crate) const fn primitive(self) -> PrimCurve {
        match self {
            Self::EccNistP256 => PrimCurve::EccNistP256,
            Self::EccNistP384 => PrimCurve::EccNistP384,
            Self::EccNistP521 => PrimCurve::EccNistP521,
        }
    }

    /// The curve's name in the ECDH key derivation's fixed info.
    pub(crate) const fn kdf_name(self) -> &'static str {
        match self {
            Self::EccNistP256 => "p256",
            Self::EccNistP384 => "p384",
            Self::EccNistP521 => "p521",
        }
    }
}
