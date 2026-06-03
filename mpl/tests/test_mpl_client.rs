// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::{MaterialProviders, MaterialProvidersConfig};

#[test]
fn test_mpl_default_uses_default_config() {
    // pass through since the client does not return a result
    let _ = MaterialProviders::default();
    
    // assert that if you provide an empty config, the mpl uses it
    // in it's construction
    let config = MaterialProvidersConfig::default();
    let mpl = MaterialProviders::new(config);
    assert_eq!(
        mpl.config(),
        &config
    );
}