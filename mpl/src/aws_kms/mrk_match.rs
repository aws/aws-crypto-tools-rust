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
///
/// Deviation from spec: AWS KMS alias ARNs (`arn:aws:kms:...:alias/...`)
/// are rejected up front (this function returns `false` when either input
/// is an alias, including the byte-identical case that the spec would
/// otherwise resolve to `true`). Aliases cannot appear on the ESDK
/// decrypt path — the wire-format EDK carries a resolved key ARN, and
/// aliases resolve at wrap time — so an alias reaching this function
/// indicates a caller bug. Rejecting them defensively avoids silently
/// treating two identical alias strings as a match even though the alias
/// may point to a different underlying key at decrypt time than at
/// encrypt time.
//= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
//= type=implication
//# The caller MUST provide:
pub fn aws_kms_mrk_match_for_decrypt(a: &str, b: &str) -> bool {
    if is_alias_arn(a) || is_alias_arn(b) {
        return false;
    }

    //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
    //# If both identifiers are identical, this function MUST return `true`.
    if a == b {
        return true;
    }

    //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
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

    //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
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

// TODO: when aws-kms-key-arn.md is onboarded into duvet, promote this to its
// own module and add duvet annotations. See decisions.md D11.
fn is_alias_arn(s: &str) -> bool {
    let segments: Vec<&str> = s.split(':').collect();
    segments.len() == 6
        && segments[0] == "arn"
        && segments[2] == "kms"
        && segments[5].starts_with("alias/")
}
