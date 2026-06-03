// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MaterialProvidersConfig {}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct MaterialProviders {
    pub(crate) config: MaterialProvidersConfig, 
}
impl MaterialProviders {
    /// Construct an `Esdk` with the given config.
    #[must_use]
    pub const fn new(config: MaterialProvidersConfig) -> Self {
        Self { config }
    }

    /// Start a fluent builder for `Esdk`.
    #[must_use]
    pub fn builder() -> MaterialProvidersBuilder {
        MaterialProvidersBuilder::default()
    }

    /// Borrow this client's configuration.
    #[must_use]
    pub const fn config(&self) -> &MaterialProvidersConfig {
        &self.config
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MaterialProvidersBuilder {}
impl MaterialProvidersBuilder {
    #[must_use]
    pub fn build(self) -> MaterialProviders {
        MaterialProviders { 
            config: MaterialProvidersConfig {  }
        }
    } 
}