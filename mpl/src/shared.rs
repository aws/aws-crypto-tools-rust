// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generator for the `Shared*` handles over the pluggable-component traits.
//!
//! One macro defines all four handles,
//! so their conversions and trait impls stay identical.

/// Define a cheaply-cloneable handle `$name` around `Arc<dyn $trait>`.
///
/// The handle deliberately does not implement `$trait`.
/// If it did, the blanket `From<T: $trait>` would overlap
/// with the standard library's reflexive `From<$name> for $name`.
macro_rules! shared_handle {
    ($(#[$meta:meta])* $name:ident, $trait:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name(::std::sync::Arc<dyn $trait>);

        impl ::std::ops::Deref for $name {
            type Target = dyn $trait;
            fn deref(&self) -> &Self::Target {
                &*self.0
            }
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        /// Wraps the owned component in a new `Arc`.
        impl<T: $trait + 'static> From<T> for $name {
            fn from(component: T) -> Self {
                Self(::std::sync::Arc::new(component))
            }
        }

        /// Reuses the caller's `Arc`.
        impl<T: $trait + 'static> From<::std::sync::Arc<T>> for $name {
            fn from(component: ::std::sync::Arc<T>) -> Self {
                Self(component)
            }
        }

        /// Reuses the caller's `Arc`.
        impl From<::std::sync::Arc<dyn $trait>> for $name {
            fn from(component: ::std::sync::Arc<dyn $trait>) -> Self {
                Self(component)
            }
        }
    };
}

pub(crate) use shared_handle;
