// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared handles for the pluggable-component traits.
//!
//! A trait is not a type, so an API cannot store "some keyring" by value.
//! Each trait has a handle that can be stored: [`SharedKeyring`](crate::keyring::SharedKeyring),
//! [`SharedCmm`](crate::cmm::SharedCmm), [`SharedCmc`](crate::cmc::SharedCmc), and
//! [`SharedBranchKeySupplier`](crate::keyring::SharedBranchKeySupplier).
//! A [`key_store::Client`](crate::key_store::Client) holds a key store instead.
//!
//! Each handle implements its own trait, so a handle works anywhere a component does.
//! APIs take `impl Keyring + 'static` and convert with [`IntoShared`]:
//!
//! ```ignore
//! pub fn keyring(mut self, keyring: impl Keyring + 'static) -> Self {
//!     self.keyring = Some(keyring.into_shared());
//!     self
//! }
//! ```
//!
//! Callers pass a concrete component or an existing handle:
//!
//! ```ignore
//! let raw = RawAesKeyring::builder()...build()?;
//! esdk.encrypt().plaintext(pt).keyring(raw.clone());
//!
//! let shared = SharedKeyring::new(raw);
//! esdk.encrypt().plaintext(pt).keyring(shared);  // reuses the handle, no second Arc
//! ```
//!
//! This matches the AWS SDK for Rust (`SharedCredentialsProvider`, `SharedHttpClient`)
//! and its `aws_smithy_runtime_api::shared` module.

use std::any::{Any, TypeId};

/// The conversion a handle implements for every implementation of its trait.
///
/// Callers use [`IntoShared::into_shared`], which calls this.
pub trait FromUnshared<Unshared> {
    /// Create the handle from `value`.
    fn from_unshared(value: Unshared) -> Self;
}

/// Converts a component into its shared handle.
///
/// A value that is already the handle is returned as-is, not wrapped again.
pub trait IntoShared<Shared> {
    /// Convert `self` into the shared handle.
    fn into_shared(self) -> Shared;
}

impl<Unshared, Shared> IntoShared<Shared> for Unshared
where
    Shared: FromUnshared<Unshared>,
{
    fn into_shared(self) -> Shared {
        Shared::from_unshared(self)
    }
}

/// Return `value` itself if it is already a `Shared`, otherwise `wrap(value)`.
pub(crate) fn maybe_shared<Shared, MaybeShared>(
    value: MaybeShared,
    wrap: impl FnOnce(MaybeShared) -> Shared,
) -> Shared
where
    Shared: 'static,
    MaybeShared: 'static,
{
    if TypeId::of::<MaybeShared>() == TypeId::of::<Shared>() {
        let mut value = Some(value);
        (&mut value as &mut dyn Any)
            .downcast_mut::<Option<Shared>>()
            .expect("TypeId matched")
            .take()
            .expect("set to Some above")
    } else {
        wrap(value)
    }
}

macro_rules! shared_handle {
    ($(#[$meta:meta])* $name:ident, $trait:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name(::std::sync::Arc<dyn $trait>);

        impl $name {
            /// Wrap `component` in a handle.
            /// An existing handle is returned as-is, not wrapped again.
            pub fn new(component: impl $trait + 'static) -> Self {
                $crate::shared::maybe_shared(component, |c| Self(::std::sync::Arc::new(c)))
            }

            /// Whether both handles refer to the same component.
            pub fn ptr_eq(this: &Self, other: &Self) -> bool {
                ::std::ptr::addr_eq(
                    ::std::sync::Arc::as_ptr(&this.0),
                    ::std::sync::Arc::as_ptr(&other.0),
                )
            }
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl<T: $trait + 'static> $crate::shared::FromUnshared<T> for $name {
            fn from_unshared(value: T) -> Self {
                Self::new(value)
            }
        }
    };
}

pub(crate) use shared_handle;
