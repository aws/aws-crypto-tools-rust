// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod aws_kms;
mod builder;
pub mod cmc;
pub mod cmm;
pub mod error;
#[cfg(feature = "test-utils")]
mod error_chain;
pub mod key_store;
pub mod keyring;
pub mod shared;
mod structures;
pub mod types;

pub use error::generated::Error;

/// Put `#[async_trait]` on an `impl` of a [`Keyring`](keyring::Keyring), [`Cmm`](cmm::Cmm), [`Cmc`](cmc::Cmc), [`KeyStore`](key_store::KeyStore), or [`BranchKeySupplier`](keyring::BranchKeySupplier).
pub use async_trait::async_trait;

#[cfg(feature = "default-aws-sdk-clients")]
pub use aws_config;

// Both SDK clients appear in the key store `Builder`'s public signature,
// and a key store `Error` carries their SDK errors as its source.
// Downcasting that source needs the exact SDK version this crate uses,
// which the consumer's own dependency might not resolve to.
#[cfg(feature = "ddb")]
pub use aws_sdk_dynamodb;
#[cfg(feature = "kms")]
pub use aws_sdk_kms;

#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod __test_internals {
    pub mod error_chain {
        pub use crate::error_chain::*;
    }
    pub mod aws_kms {
        pub use crate::aws_kms::__test_internals::*;
    }
}
