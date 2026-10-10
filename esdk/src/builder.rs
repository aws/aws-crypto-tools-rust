// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::Error;
use crate::error::val_err;

/// `value`, or a `Validation` error naming the unset `field`.
#[track_caller]
pub(crate) fn required<T>(value: Option<T>, field: &str) -> Result<T, Error> {
    value.ok_or_else(|| val_err(format!("{field} is required")))
}
