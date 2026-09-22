// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Cryptographic materials management — CMM creation and materials retrieval.

use std::sync::Arc;

use crate::error::{Error, val_err};
use crate::message::header_types::HeaderBody;
use crate::message::serializable_types::{
    from_canonical_pairs, is_esdk_encrypted_data_keys, is_esdk_encryption_context,
};
use crate::types::{EncryptionContext, EsdkCommitmentPolicy, MaterialSource};
use aws_crypto_mpl::cmm::DefaultCmm;
use aws_crypto_mpl::cmm::{Cmm, DecryptMaterialsRequest, EncryptionMaterialsRequest};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, CommitmentPolicy, DecryptionMaterials, EncryptedDataKey,
    EncryptionContext as MplEncryptionContext, EncryptionMaterials,
};

/// A cryptographic materials manager resolved from the caller's input: either
/// the caller's own CMM, or a [`DefaultCmm`] wrapping the caller's keyring.
pub(crate) struct ResolvedCmm(Arc<dyn Cmm>);

/// Convert an ESDK (`HashMap<String, String>`) encryption context to the MPL's
/// byte-oriented [`MplEncryptionContext`].
fn to_mpl_ec(ec: &EncryptionContext) -> MplEncryptionContext {
    let mut out = MplEncryptionContext::new();
    for (k, v) in ec {
        out.insert(k.clone().into_bytes(), v.clone().into_bytes());
    }
    out
}

/// Convert an MPL encryption context back to the ESDK's `HashMap<String, String>`.
///
/// # Errors
/// Returns an error if any key or value is not valid UTF-8, which the ESDK
/// message format requires.
fn from_mpl_ec(ec: &MplEncryptionContext) -> Result<EncryptionContext, Error> {
    let mut out = EncryptionContext::new();
    for (k, v) in ec.iter() {
        let key = String::from_utf8(k.clone())
            .map_err(|_| val_err("Encryption context key is not valid UTF-8"))?;
        let value = String::from_utf8(v.clone())
            .map_err(|_| val_err("Encryption context value is not valid UTF-8"))?;
        out.insert(key, value);
    }
    Ok(out)
}

/// Build the internal [`ResolvedCmm`] from the resolved material source. A
/// supplied CMM is used directly; a supplied keyring is wrapped in a
/// [`DefaultCmm`](aws_crypto_mpl::cmm::DefaultCmm).
pub(crate) fn create_cmm_from_input(
    input_source: Option<MaterialSource>,
) -> Result<ResolvedCmm, Error> {
    match input_source.ok_or_else(|| val_err("A Materials Source must be provided"))? {
        MaterialSource::Cmm(cmm) => Ok(ResolvedCmm(cmm)),
        MaterialSource::Keyring(keyring) => {
            //= spec/client-apis/encrypt.md#get-the-encryption-materials
            //# If instead the caller supplied a [keyring](../framework/keyring-interface.md),
            //# this behavior MUST use a [default CMM](../framework/default-cmm.md)
            //# constructed using the caller-supplied keyring as input.
            //
            //= spec/client-apis/decrypt.md#keyring
            //# If the Keyring is provided as the input, the client MUST construct a [default CMM](../framework/default-cmm.md) that uses this keyring,
            //# to obtain the [decryption materials](../framework/structures.md#decryption-materials) that is required for decryption.
            Ok(ResolvedCmm(Arc::new(DefaultCmm::new(keyring))))
        }
    }
}

pub(crate) async fn get_decryption_materials(
    cmm: ResolvedCmm,
    algorithm_suite_id: AlgorithmSuiteId,
    header_body: &HeaderBody,
    reproduced_encryption_context: &EncryptionContext,
    commitment_policy: EsdkCommitmentPolicy,
) -> Result<DecryptionMaterials, Error> {
    let policy = CommitmentPolicy::Esdk(commitment_policy);
    let encryption_context = to_mpl_ec(&from_canonical_pairs(
        header_body.encryption_context().clone(),
    ));
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
        DecryptMaterialsRequest::new(algorithm_suite_id, policy, edks, encryption_context);

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# - Reproduced Encryption Context: This MUST be the [input](#input) encryption context.
    if !reproduced_encryption_context.is_empty() {
        request =
            request.with_reproduced_encryption_context(to_mpl_ec(reproduced_encryption_context));
    }

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# This operation MUST obtain this set of [decryption materials](../framework/structures.md#decryption-materials),
    //# by calling [Decrypt Materials](../framework/cmm-interface.md#decrypt-materials) on a [CMM](../framework/cmm-interface.md).
    let materials = cmm.0.decrypt_materials(request).await?;

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

    if !is_esdk_encryption_context(&from_mpl_ec(materials.encryption_context())?) {
        return Err(val_err(
            "CMM failed to return serializable decryption materials",
        ));
    }
    Ok(materials)
}

pub(crate) async fn get_encryption_materials(
    cmm: ResolvedCmm,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
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
    let mut request = EncryptionMaterialsRequest::new(to_mpl_ec(&encryption_context), policy);

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= reason=algorithm_suite_id is Option; None means the field is not set on the request
    //# If no Algorithm Suite is provided, this field MUST NOT be included.
    if let Some(id) = algorithm_suite_id {
        request = request.with_algorithm_suite_id(id);
    }

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# - Max Plaintext Length: If the [input plaintext](#plaintext) has known length,
    //# this length MUST be used.
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= reason=max_plaintext_length is Option; None means the field is not set on the request
    //# If no Plaintext Length Bound is provided, this field MUST NOT be included.
    if let Some(len) = max_plaintext_length {
        request = request.with_max_plaintext_length(len as u64);
    }

    let materials = cmm.0.get_encryption_materials(request).await?;

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

    if !is_esdk_encryption_context(&from_mpl_ec(materials.encryption_context())?) {
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
