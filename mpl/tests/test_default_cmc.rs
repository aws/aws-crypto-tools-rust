// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for [`aws_crypto_mpl::DefaultCmc`].

use std::time::Duration;

use aws_crypto_mpl::{Cmc, DefaultCmc, ErrorKind};

#[test]
fn default_cmc_is_a_default_storm_tracking_cache_with_the_given_capacity() {
    let cache = DefaultCmc::builder()
        .entry_capacity(5000)
        .build()
        .expect("a DefaultCmc with a capacity builds");
    assert_eq!(cache.entry_capacity(), 5000);
    assert_eq!(cache.grace_period(), Some(Duration::from_secs(10)));
}

#[test]
fn default_cmc_requires_an_entry_capacity() {
    let err = DefaultCmc::builder()
        .build()
        .expect_err("an unset entry capacity is rejected");
    assert_eq!(err.kind(), ErrorKind::Validation);
}
