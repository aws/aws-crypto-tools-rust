// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Message body encryption and decryption.

pub(crate) mod body_aad;
mod body_decrypt;
mod body_encrypt;

pub(crate) use body_aad::*;
pub(crate) use body_decrypt::*;
pub(crate) use body_encrypt::*;

use crate::error::{Error, val_err};
use aws_mpl_primitives::AesGcm;
use aws_crypto_mpl::structures::AlgorithmSuite;

pub(crate) fn get_alg_suite(info: &AlgorithmSuite) -> Result<AesGcm, Error> {
    match info.encryption_key_length() {
        16 => Ok(AesGcm::Aes128Gcm),
        24 => Ok(AesGcm::Aes192Gcm),
        32 => Ok(AesGcm::Aes256Gcm),
        other => Err(val_err(format!(
            "Unsupported AES-GCM key length {other} in algorithm suite"
        ))),
    }
}
