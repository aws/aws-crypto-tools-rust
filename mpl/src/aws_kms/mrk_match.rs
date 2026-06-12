// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS MRK Match for Decrypt.
//!
//! Implements the multi-Region key matching algorithm specified in
//! `spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md`.

/// Determines whether two AWS KMS key identifiers refer to the same
/// multi-Region key for the purpose of decryption.
///
/// See `spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation`.
//= ../spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
//= type=implication
//# The caller MUST provide:
pub fn aws_kms_mrk_match_for_decrypt(a: &str, b: &str) -> bool {
    //= ../spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
    //# If both identifiers are identical, this function MUST return `true`.
    if a == b {
        return true;
    }

    //= ../spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
    //# Otherwise if either input is not [identified as a multi-Region key](aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key),
    //# then this function MUST return `false`.
    if !is_multi_region_arn(a) || !is_multi_region_arn(b) {
        return false;
    }

    // Both inputs are multi-Region key ARNs. Compare all parts except region.
    let pa: Vec<&str> = a.split(':').collect();
    let pb: Vec<&str> = b.split(':').collect();
    let (rt_a, res_a) = pa[5].split_once('/').unwrap_or((pa[5], ""));
    let (rt_b, res_b) = pb[5].split_once('/').unwrap_or((pb[5], ""));

    //= ../spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
    //# Otherwise if both inputs are [identified as a multi-Region keys](aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key),
    //# this function MUST return the result of comparing
    //# the `partition`, `service`, `accountId`, `resourceType`, and `resource` parts of both ARN inputs.
    pa[1] == pb[1] // partition
        && pa[2] == pb[2] // service
        && pa[4] == pb[4] // accountId
        && rt_a == rt_b // resourceType
        && res_a == res_b // resource
}

// TODO: when aws-kms-key-arn.md is onboarded into duvet, promote this to its
// own module and add duvet annotations. See decisions.md D11.
fn is_multi_region_arn(s: &str) -> bool {
    let segments: Vec<&str> = s.split(':').collect();
    segments.len() == 6
        && segments[0] == "arn"
        && segments[2] == "kms"
        && segments[5].starts_with("key/mrk-")
}
