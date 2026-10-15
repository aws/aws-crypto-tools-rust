// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::Error;

/// `value`, or a `Validation` error naming the unset `field`.
pub(crate) fn required<T>(value: Option<T>, field: &str) -> Result<T, Error> {
    value.ok_or_else(|| Error::validation(format!("{field} is required")))
}
