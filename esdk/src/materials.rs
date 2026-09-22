// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Cryptographic materials management — CMM creation and materials retrieval.

use std::collections::BTreeSet;
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
/// keys as raw bytes, but the ESDK message format requires UTF-8. Converting
/// here -- at the single boundary the MPL hands materials back across -- means
/// a non-UTF-8 entry is rejected once, with an error, instead of each later
/// stage re-deriving the strings and having to decide what to do about one.
pub(crate) struct ValidatedMaterials<M> {
    pub(crate) materials: M,
    pub(crate) encryption_context: EncryptionContext,
    pub(crate) required_encryption_context_keys: Vec<String>,
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
) -> Result<ValidatedMaterials<DecryptionMaterials>, Error> {
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

    // The encryption context is "a key-value mapping of arbitrary, non-secret,
    // UTF-8 encoded strings", so a CMM returning bytes that are not UTF-8 has
    // violated the structure the ESDK must serialize. Reject it here, at the one
    // boundary the MPL hands materials back across, rather than letting each
    // later stage re-derive the strings and decide what to do about one.
    // https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md#encryption-context
    //
    // Required keys first: the MPL constructors enforce that the required-key
    // set is a subset of the encryption context keys, so a non-UTF-8 required
    // key is always also a non-UTF-8 encryption context key. Checking the
    // subset first is what makes the more specific error reachable.
    let required_encryption_context_keys =
        from_mpl_required_keys(materials.required_encryption_context_keys())?;
    let encryption_context = from_mpl_ec(materials.encryption_context())?;

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
    cmm: ResolvedCmm,
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

    // The encryption context is "a key-value mapping of arbitrary, non-secret,
    // UTF-8 encoded strings", so a CMM returning bytes that are not UTF-8 has
    // violated the structure the ESDK must serialize. Reject it here, at the one
    // boundary the MPL hands materials back across, rather than letting each
    // later stage re-derive the strings and decide what to do about one.
    // https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md#encryption-context
    //
    // Required keys first: the MPL constructors enforce that the required-key
    // set is a subset of the encryption context keys, so a non-UTF-8 required
    // key is always also a non-UTF-8 encryption context key. Checking the
    // subset first is what makes the more specific error reachable.
    let required_encryption_context_keys =
        from_mpl_required_keys(materials.required_encryption_context_keys())?;
    let encryption_context = from_mpl_ec(materials.encryption_context())?;

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
