// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Cryptographic materials management — CMM creation and materials retrieval.


use crate::error::{Error, val_err};
use crate::message::header_types::HeaderBody;
use crate::message::serializable_types::{is_esdk_encrypted_data_keys, is_esdk_encryption_context};
use crate::types::{EncryptionContext, EsdkCommitmentPolicy, MaterialSource};
use aws_crypto_mpl::cmm::DefaultCmm;
use aws_crypto_mpl::cmm::{Cmm, DecryptMaterialsRequest, EncryptionMaterialsRequest, SharedCmm};
use aws_crypto_mpl::structures::{
    CommitmentPolicy, DecryptionMaterials, EncryptedDataKey, EncryptionMaterials,
    EsdkAlgorithmSuiteId,
};

/// Resolve the CMM for an operation from the resolved material source.
/// A supplied CMM is used directly.
/// A supplied keyring is wrapped in a [`DefaultCmm`](aws_crypto_mpl::cmm::DefaultCmm).
pub(crate) fn create_cmm_from_input(
    input_source: Option<MaterialSource>,
) -> Result<SharedCmm, Error> {
    match input_source.ok_or_else(|| val_err("A Materials Source must be provided"))? {
        MaterialSource::Cmm(cmm) => Ok(cmm),
        MaterialSource::Keyring(keyring) => {
            //= spec/client-apis/encrypt.md#get-the-encryption-materials
            //# If instead the caller supplied a [keyring](../framework/keyring-interface.md),
            //# this behavior MUST use a [default CMM](../framework/default-cmm.md)
            //# constructed using the caller-supplied keyring as input.
            //
            //= spec/client-apis/decrypt.md#keyring
            //# If the Keyring is provided as the input, the client MUST construct a [default CMM](../framework/default-cmm.md) that uses this keyring,
            //# to obtain the [decryption materials](../framework/structures.md#decryption-materials) that is required for decryption.
            Ok(SharedCmm::new(DefaultCmm::new(keyring)))
        }
    }
}

pub(crate) async fn get_decryption_materials(
    cmm: SharedCmm,
    algorithm_suite_id: EsdkAlgorithmSuiteId,
    header_body: &HeaderBody,
    reproduced_encryption_context: &EncryptionContext,
    commitment_policy: EsdkCommitmentPolicy,
) -> Result<DecryptionMaterials, Error> {
    let policy = CommitmentPolicy::Esdk(commitment_policy);
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# - Encryption Context: This MUST be the parsed [encryption context](../data-format/message-header.md#aad)
    //# from the message header.
    let encryption_context = header_body.encryption_context().clone();

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# - Encrypted Data Keys: This MUST be the parsed [encrypted data keys](../data-format/message-header.md#encrypted-data-keys)
    //# from the message header.
    let edks: Vec<EncryptedDataKey> = header_body.encrypted_data_keys().to_vec();

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# The call to the CMM's [Decrypt Materials](../framework/cmm-interface.md#decrypt-materials) operation
    //# MUST be constructed as follows:
    //
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# - Algorithm Suite ID: This MUST be the parsed
    //# [algorithm suite ID](../data-format/message-header.md#algorithm-suite-id)
    //# from the message header.
    //
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# - Commitment Policy: This MUST be the commitment policy configured on the client.
    let mut request =
        DecryptMaterialsRequest::new(algorithm_suite_id.into(), policy, edks, encryption_context);

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# - Reproduced Encryption Context: This MUST be the [input](#input) encryption context.
    if !reproduced_encryption_context.is_empty() {
        request = request.with_reproduced_encryption_context(reproduced_encryption_context.clone());
    }

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# This operation MUST obtain this set of [decryption materials](../framework/structures.md#decryption-materials),
    //# by calling [Decrypt Materials](../framework/cmm-interface.md#decrypt-materials) on a [CMM](../framework/cmm-interface.md).
    //
    //= spec/client-apis/decrypt.md#cryptographic-materials-manager
    //# This CMM MUST obtain the [decryption materials](../framework/structures.md#decryption-materials) required for decryption.
    //
    //= spec/client-apis/decrypt.md#keyring
    //# This default CMM constructed from the keyring MUST obtain the decryption materials required for decryption.
    let materials = cmm.decrypt_materials(request).await?;

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# If the algorithm suite is not supported by the [commitment policy](client.md#commitment-policy)
    //# configured in the [client](client.md) decrypt MUST yield an error.
    if !policy.allows_for_decrypt(materials.algorithm_suite_id()) {
        return Err(val_err(
            "Algorithm suite is not supported by the configured commitment policy for decryption",
        ));
    }

    if materials.plaintext_data_key().is_none() {
        return Err(val_err(
            "Decryption materials are missing a plaintext data key",
        ));
    }

    if !is_esdk_encryption_context(materials.encryption_context()) {
        return Err(val_err(
            "CMM failed to return serializable decryption materials",
        ));
    }
    Ok(materials)
}

pub(crate) async fn get_encryption_materials(
    cmm: SharedCmm,
    algorithm_suite_id: Option<EsdkAlgorithmSuiteId>,
    encryption_context: EncryptionContext,
    max_plaintext_length: Option<usize>,
    commitment_policy: EsdkCommitmentPolicy,
) -> Result<EncryptionMaterials, Error> {
    let policy = CommitmentPolicy::Esdk(commitment_policy);

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# - Commitment Policy: This MUST be the [commitment policy](client.md#commitment-policy)
    //# configured in the [client](client.md) exposing this encrypt function.
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# - Encryption Context: If provided, this MUST be the [input encryption context](#encryption-context).
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= reason=Encryption context is empty by default
    //# Otherwise, this MUST be an empty encryption context.
    let mut request = EncryptionMaterialsRequest::new(encryption_context, policy);

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= reason=algorithm_suite_id is Option; None means the field is not set on the request
    //# If no Algorithm Suite is provided, this field MUST NOT be included.
    if let Some(id) = algorithm_suite_id {
        request = request.with_algorithm_suite_id(id.into());
    }

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# - Max Plaintext Length: If the [input plaintext](#plaintext) has known length,
    //# this length MUST be used.
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= reason=The caller's Plaintext Length Bound arrives as max_plaintext_length for unknown-length input
    //# If the input [plaintext](#plaintext) has unknown length and a [Plaintext Length Bound](#plaintext-length-bound)
    //# was provided, this MUST be the [Plaintext Length Bound](#plaintext-length-bound).
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= reason=max_plaintext_length is Option; None means the field is not set on the request
    //# If no Plaintext Length Bound is provided, this field MUST NOT be included.
    if let Some(len) = max_plaintext_length {
        request = request.with_max_plaintext_length(len as u64);
    }

    let materials = cmm.get_encryption_materials(request).await?;

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# If this [algorithm suite](../framework/algorithm-suites.md) is not supported by the [commitment policy](client.md#commitment-policy)
    //# configured in the [client](client.md) encrypt MUST yield an error.
    if !policy.allows_for_encrypt(materials.algorithm_suite_id()) {
        return Err(val_err(
            "Algorithm suite is not supported by the configured commitment policy for encryption",
        ));
    }

    if materials.plaintext_data_key().is_none() {
        return Err(val_err(
            "Encryption materials are missing a plaintext data key",
        ));
    }

    if !is_esdk_encryption_context(materials.encryption_context()) {
        return Err(val_err(
            "CMM failed to return serializable encryption materials",
        ));
    }
    if !is_esdk_encrypted_data_keys(materials.encrypted_data_keys()) {
        return Err(val_err(
            "CMM failed to return serializable encrypted data keys",
        ));
    }
    Ok(materials)
}
