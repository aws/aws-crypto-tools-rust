// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::{MaterialProviders, MaterialProvidersConfig};

#[test]
fn test_mpl_default_uses_default_config() {
    let mpl = MaterialProviders::default();
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}

#[test]
fn test_mpl_new_uses_provided_config() {
    let mpl = MaterialProviders::new(MaterialProvidersConfig::default());
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}

#[test]
fn test_mpl_builder() {
    let mpl = MaterialProviders::builder().build();
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}

#[test]
fn test_mpl_builder_with_config() {
    let mpl = MaterialProviders::builder()
        .config(MaterialProvidersConfig::default())
        .build();
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}
