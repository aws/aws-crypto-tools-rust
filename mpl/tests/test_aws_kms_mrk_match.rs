// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `aws_kms::mrk_match::aws_kms_mrk_match_for_decrypt`.

use aws_crypto_mpl::aws_kms::mrk_match::aws_kms_mrk_match_for_decrypt;

const MRK_EAST: &str =
    "arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
const MRK_WEST: &str =
    "arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
const NON_MRK_KEY: &str =
    "arn:aws:kms:us-east-1:111122223333:key/abcd1234-1234-abcd-1234-1234567890ab";
const ALIAS: &str = "arn:aws:kms:us-east-1:111122223333:alias/test-key";
const MALFORMED: &str = "not-an-arn";

#[test]
fn identical_mrk_arns_return_true() {
    let result = aws_kms_mrk_match_for_decrypt(MRK_EAST, MRK_EAST);

    //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
    //= type=test
    //# If both identifiers are identical, this function MUST return `true`.
    assert!(result);
}

#[test]
fn identical_non_mrk_arns_return_true() {
    assert!(aws_kms_mrk_match_for_decrypt(NON_MRK_KEY, NON_MRK_KEY));
}

#[test]
fn identical_aliases_return_false() {
    // Alias ARNs are rejected up front — ESDK decrypt does not accept
    // aliases (the wire EDK always carries a resolved key ARN), so an
    // alias reaching this function is a caller bug. Byte-identical
    // aliases still return `false` per the Rust-side deviation
    // documented on `aws_kms_mrk_match_for_decrypt`.
    assert!(!aws_kms_mrk_match_for_decrypt(ALIAS, ALIAS));
}

#[test]
fn identical_plain_strings_return_true() {
    assert!(aws_kms_mrk_match_for_decrypt(MALFORMED, MALFORMED));
}

#[test]
fn mrk_arns_same_key_different_region_return_true() {
    //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
    //= type=test
    //# Otherwise if both inputs are [identified as a multi-Region keys](aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key),
    //# this function MUST return the result of comparing
    //# the `partition`, `service`, `accountId`, `resourceType`, and `resource` parts of both ARN inputs.
    assert!(aws_kms_mrk_match_for_decrypt(MRK_EAST, MRK_WEST));
}

#[test]
fn mrk_arns_same_key_same_region_return_true() {
    // Falls through byte-equality branch (R2).
    assert!(aws_kms_mrk_match_for_decrypt(MRK_EAST, MRK_EAST));
}

#[test]
fn two_non_mrk_arns_return_false() {
    let other_non_mrk =
        "arn:aws:kms:us-east-1:111122223333:key/eeee1234-1234-abcd-1234-1234567890ab";
    //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
    //= type=test
    //# Otherwise if either input is not [identified as a multi-Region key](aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key),
    //# then this function MUST return `false`.
    assert!(!aws_kms_mrk_match_for_decrypt(NON_MRK_KEY, other_non_mrk));
}

#[test]
fn mrk_arn_and_non_mrk_arn_return_false() {
    assert!(!aws_kms_mrk_match_for_decrypt(MRK_EAST, NON_MRK_KEY));
}

#[test]
fn non_mrk_arn_and_mrk_arn_return_false() {
    assert!(!aws_kms_mrk_match_for_decrypt(NON_MRK_KEY, MRK_EAST));
}

#[test]
fn alias_and_mrk_arn_return_false() {
    assert!(!aws_kms_mrk_match_for_decrypt(ALIAS, MRK_EAST));
}

#[test]
fn mrk_arn_and_alias_return_false() {
    assert!(!aws_kms_mrk_match_for_decrypt(MRK_EAST, ALIAS));
}

#[test]
fn alias_and_non_mrk_arn_return_false() {
    assert!(!aws_kms_mrk_match_for_decrypt(ALIAS, NON_MRK_KEY));
}

#[test]
fn malformed_arn_and_mrk_arn_return_false() {
    assert!(!aws_kms_mrk_match_for_decrypt(MALFORMED, MRK_EAST));
}

#[test]
fn mrk_arns_different_account_return_false() {
    let different_account =
        "arn:aws:kms:us-east-1:444455556666:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
    assert!(!aws_kms_mrk_match_for_decrypt(MRK_EAST, different_account));
}

#[test]
fn mrk_arns_different_resource_return_false() {
    let different_resource =
        "arn:aws:kms:us-east-1:111122223333:key/mrk-aaaabbbb-cccc-dddd-eeee-ffffffffffff";
    assert!(!aws_kms_mrk_match_for_decrypt(MRK_EAST, different_resource));
}

#[test]
fn mrk_arns_different_partition_return_false() {
    let aws_cn =
        "arn:aws-cn:kms:cn-north-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
    assert!(!aws_kms_mrk_match_for_decrypt(MRK_EAST, aws_cn));
}

#[test]
fn mrk_arns_different_service_return_false() {
    // Synthetic: segments[2] is not "kms", so is_multi_region_arn rejects it (R3 branch).
    let not_kms =
        "arn:aws:lambda:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
    assert!(!aws_kms_mrk_match_for_decrypt(MRK_EAST, not_kms));
}
