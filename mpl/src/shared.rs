// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared handles for the pluggable-component traits.
//!
//! A trait is not a type, so an API cannot store "some keyring" by value.
//! Each trait has a handle that can be stored: [`SharedKeyring`](crate::keyring::SharedKeyring),
//! [`SharedCmm`](crate::cmm::SharedCmm), [`SharedCmc`](crate::cmc::SharedCmc), and
//! [`SharedBranchKeyIdSupplier`](crate::keyring::SharedBranchKeyIdSupplier).
//! A [`key_store::SharedKeyStore`](crate::key_store::SharedKeyStore) holds a key store instead.
//!
//! A handle is called like an AWS SDK client: each operation returns a fluent builder.
//! The trait is what an implementation writes. Neither the handle nor a built-in component
//! such as [`RawAesKeyring`](crate::keyring::RawAesKeyring) implements it, so each has one
//! method per operation: the fluent one.
//! APIs take `impl IntoShared<SharedKeyring>`, which accepts a component or an existing handle:
//!
//! ```ignore
//! pub fn keyring(mut self, keyring: impl IntoShared<SharedKeyring>) -> Self {
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
//! [`IntoShared`] follows the AWS SDK for Rust's `aws_smithy_runtime_api::shared` module.

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

macro_rules! shared_handle {
    ($(#[$meta:meta])* $name:ident, $trait:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name(::std::sync::Arc<dyn $trait>);

        impl $name {
            /// Wrap `component` in a handle. An existing handle is returned as-is.
            pub fn new(component: impl $crate::shared::IntoShared<Self>) -> Self {
                component.into_shared()
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
                Self(::std::sync::Arc::new(value))
            }
        }

        /// A handle converts to itself, so an existing handle is not wrapped again.
        impl $crate::shared::FromUnshared<$name> for $name {
            fn from_unshared(value: $name) -> Self {
                value
            }
        }
    };
}

pub(crate) use shared_handle;

/// A built-in component as an implementation of its trait.
///
/// The built-in types have only the fluent calls, so the trait is implemented here instead.
#[derive(Clone, Debug)]
pub(crate) struct Builtin<T>(pub(crate) T);

impl<T> std::ops::Deref for Builtin<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}
