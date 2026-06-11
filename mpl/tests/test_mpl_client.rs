// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::{MaterialProviders, MaterialProvidersConfig};

#[test]
fn test_mpl_default_uses_default_config() {
    let _ = MaterialProviders::default();

    let config = MaterialProvidersConfig::default();
    let mpl = MaterialProviders::new(config);
    assert_eq!(mpl.config(), &config);
}

#[test]
fn test_mpl_builder() {
    let mpl = MaterialProviders::builder().build();
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}

#[test]
fn test_mpl_builder_with_config() {
    let config = MaterialProvidersConfig::default();
    let mpl = MaterialProviders::builder().config(config).build();
    assert_eq!(mpl.config(), &config);
}
