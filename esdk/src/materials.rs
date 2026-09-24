// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Cryptographic materials management — CMM creation and materials retrieval.

use std::collections::BTreeSet;

use crate::error::{Error, val_err};
use crate::message::header_types::HeaderBody;
use crate::message::serializable_types::{
    from_canonical_pairs, is_esdk_encrypted_data_keys, is_esdk_encryption_context,
};
use crate::types::{EncryptionContext, EsdkCommitmentPolicy, MaterialSource};
use aws_crypto_mpl::cmm::DefaultCmm;
use aws_crypto_mpl::cmm::{DecryptMaterialsRequest, EncryptionMaterialsRequest, SharedCmm};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, CommitmentPolicy, DecryptionMaterials, EncryptedDataKey, EncryptionMaterials,
};

/// Check that every encryption context entry is valid UTF-8.
///
/// The context is byte-keyed, but the specification defines its entries as UTF-8
/// encoded strings, so a CMM returning non-UTF-8 bytes has violated the
/// materials contract. Rejecting at this boundary names the CMM as the culprit
/// and fails before any of it reaches the header.
///
/// # Errors
/// Returns an error if any key or value is not valid UTF-8.
// https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md#encryption-context
fn validate_utf8_encryption_context(ec: &EncryptionContext) -> Result<(), Error> {
    for (key, value) in ec.iter() {
        if std::str::from_utf8(key).is_err() {
            return Err(val_err("Encryption context key is not valid UTF-8"));
        }
        if std::str::from_utf8(value).is_err() {
            return Err(val_err("Encryption context value is not valid UTF-8"));
        }
    }
    Ok(())
}

/// Convert the MPL's byte-keyed required-encryption-context key set to the
/// `String` keys the ESDK header serialization works with.
///
/// # Errors
/// Returns an error if any key is not valid UTF-8, which the ESDK message
/// format requires.
fn from_mpl_required_keys(keys: &BTreeSet<Vec<u8>>) -> Result<Vec<String>, Error> {
    keys.iter()
        .map(|k| {
            String::from_utf8(k.clone())
                .map_err(|_| val_err("Required encryption context key is not valid UTF-8"))
        })
        .collect()
}

/// Materials returned by a CMM, together with the UTF-8 views of the two
/// byte-keyed fields the ESDK must serialize as strings.
///
/// The MPL models the encryption context and the required-encryption-context
/// keys as raw bytes, but the encryption context is specified as "a key-value
/// mapping of arbitrary, non-secret, UTF-8 encoded strings". Converting at this
/// single boundary means a CMM returning non-UTF-8 bytes is rejected once, with
/// an error, and every later stage works from `String`.
// https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md#encryption-context
pub(crate) struct ValidatedMaterials<M> {
    pub(crate) materials: M,
    pub(crate) encryption_context: EncryptionContext,
    pub(crate) required_encryption_context_keys: Vec<String>,
}

/// Resolve the CMM for an operation from the resolved material source. A
/// supplied CMM is used directly; a supplied keyring is wrapped in a
/// [`DefaultCmm`](aws_crypto_mpl::cmm::DefaultCmm).
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
            Ok(DefaultCmm::new(keyring).into())
        }
    }
}

pub(crate) async fn get_decryption_materials(
    cmm: SharedCmm,
    algorithm_suite_id: AlgorithmSuiteId,
    header_body: &HeaderBody,
    reproduced_encryption_context: &EncryptionContext,
    commitment_policy: EsdkCommitmentPolicy,
) -> Result<ValidatedMaterials<DecryptionMaterials>, Error> {
    let policy = CommitmentPolicy::Esdk(commitment_policy);
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //# - Encryption Context: This MUST be the parsed [encryption context](../data-format/message-header.md#aad)
    //# from the message header.
    let encryption_context = from_canonical_pairs(header_body.encryption_context().clone());

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
        DecryptMaterialsRequest::new(algorithm_suite_id, policy, edks, encryption_context);

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

    // Required keys first: the MPL constructors enforce that the required-key set
    // is a subset of the context keys, so a non-UTF-8 required key is always also
    // a non-UTF-8 context key. Checking it first makes the specific error reachable.
    let required_encryption_context_keys =
        from_mpl_required_keys(materials.required_encryption_context_keys())?;
    let encryption_context = materials.encryption_context();
    validate_utf8_encryption_context(encryption_context)?;
    let encryption_context = encryption_context.clone();

    if !is_esdk_encryption_context(&encryption_context) {
        return Err(val_err(
            "CMM failed to return serializable decryption materials",
        ));
    }
    Ok(ValidatedMaterials {
        materials,
        encryption_context,
        required_encryption_context_keys,
    })
}

pub(crate) async fn get_encryption_materials(
    cmm: SharedCmm,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: EncryptionContext,
    max_plaintext_length: Option<usize>,
    commitment_policy: EsdkCommitmentPolicy,
) -> Result<ValidatedMaterials<EncryptionMaterials>, Error> {
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
        request = request.with_algorithm_suite_id(id);
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

    // Required keys first: the MPL constructors enforce that the required-key set
    // is a subset of the context keys, so a non-UTF-8 required key is always also
    // a non-UTF-8 context key. Checking it first makes the specific error reachable.
    let required_encryption_context_keys =
        from_mpl_required_keys(materials.required_encryption_context_keys())?;
    let encryption_context = materials.encryption_context();
    validate_utf8_encryption_context(encryption_context)?;
    let encryption_context = encryption_context.clone();

    if !is_esdk_encryption_context(&encryption_context) {
        return Err(val_err(
            "CMM failed to return serializable encryption materials",
        ));
    }
    if !is_esdk_encrypted_data_keys(materials.encrypted_data_keys()) {
        return Err(val_err(
            "CMM failed to return serializable encrypted data keys",
        ));
    }
    Ok(ValidatedMaterials {
        materials,
        encryption_context,
        required_encryption_context_keys,
    })
}
