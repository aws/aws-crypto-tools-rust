// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Default CMM — concrete implementation of the [`Cmm`](super::Cmm) trait
//! that wraps a single keyring.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use aws_mpl_primitives::{
    EcdsaSignatureAlgorithm as PrimEcdsaSignatureAlgorithm, ecdsa_generate_keypair,
};
use base64::Engine;

use super::Cmm;
use super::request::{DecryptMaterialsRequest, EncryptionMaterialsRequest};
use crate::keyring::Keyring;
use crate::structures::{
    AsymmetricSignatureAlgorithm, DecryptionMaterials, EncryptionContext, EncryptionMaterials,
    MaterialsError, SigningKey, VerificationKey,
};

/// Reserved encryption-context key under which the default CMM stores the
/// base64-encoded ECDSA verification key for signing-suite messages.
const RESERVED_AWS_CRYPTO_PUBLIC_KEY: &[u8] = b"aws-crypto-public-key";

/// Concrete CMM that uses a single keyring and resolves an algorithm suite
/// from each request's commitment policy.
///
/// On `get_encryption_materials` the default CMM:
/// - Resolves the algorithm suite from the request (or, if absent, from the
///   commitment policy's default).
/// - For signing suites: generates an ECDSA key pair via `aws-mpl-primitives`, attaches
///   the private signing key to the materials, and inserts the
///   base64-encoded SEC1-compressed public key into a copy of the request's
///   encryption context under the reserved `aws-crypto-public-key` key.
/// - Calls the wrapped keyring's `on_encrypt` to populate the plaintext data
///   key and encrypted data keys.
///
/// On `decrypt_materials` the default CMM:
/// - Validates the algorithm suite against the request's commitment policy.
/// - Merges the request's encryption context with its Reproduced
///   Encryption Context: shared keys must agree, and pairs present only in
///   the reproduced context are appended and reported as Required Encryption
///   Context Keys. See [`merge_reproduced_encryption_context`].
/// - For signing suites: extracts and base64-decodes the verification key
///   from the merged encryption context.
/// - For non-signing suites: rejects requests whose merged encryption
///   context contains the reserved `aws-crypto-public-key`.
/// - Calls the wrapped keyring's `on_decrypt` to populate the plaintext data
///   key.
pub struct DefaultCmm {
    // DefaultCmm holds only a keyring, structurally excluding master key providers.
    //= spec/framework/default-cmm.md#legacy
    //= type=implication
    //# Master key providers SHOULD NOT be included in any additional implementations.
    keyring: Arc<dyn Keyring>,
}

impl DefaultCmm {
    /// Construct a `DefaultCmm` wrapping the given keyring.
    pub fn new(keyring: Arc<dyn Keyring>) -> Self {
        // The keyring is a required constructor parameter: the caller cannot
        // build a DefaultCmm without providing one.
        //= spec/framework/default-cmm.md#initialization
        //= type=implication
        //# On default CMM initialization,
        //# the caller MUST provide the following value:
        Self { keyring }
    }
}

#[async_trait]
impl Cmm for DefaultCmm {
    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        let commitment_policy = request.commitment_policy();

        // Resolve the algorithm suite for this request: either from the
        // commitment policy's default (when the request doesn't specify one)
        // or by validating the request's choice against the policy.
        let suite_id = match request.algorithm_suite_id() {
            //= spec/framework/default-cmm.md#get-encryption-materials
            //# - If the [encryption materials request](cmm-interface.md#encryption-materials-request) does not contain an algorithm suite,
            //# the operation MUST add the default algorithm suite for the [commitment policy](./commitment-policy.md#supported-commitment-policy-enum)
            //# as the algorithm suite in the encryption materials returned.
            None => commitment_policy.default_algorithm_suite_id(),
            Some(id) => {
                //= spec/framework/default-cmm.md#get-encryption-materials
                //# - If the [encryption materials request](cmm-interface.md#encryption-materials-request) does contain an algorithm suite,
                //# the request MUST fail if the algorithm suite is not supported by the [commitment policy](./commitment-policy.md#supported-commitment-policy-enum) on the request.
                if !commitment_policy.allows_for_encrypt(id) {
                    return Err(MaterialsError::new(format!(
                        "Algorithm suite {id:?} is not supported by commitment policy {commitment_policy:?} for encryption"
                    )));
                }
                //= spec/framework/default-cmm.md#get-encryption-materials
                //# - If the [encryption materials request](cmm-interface.md#encryption-materials-request) does contain an algorithm suite,
                //# the encryption materials returned MUST contain the same algorithm suite.
                //
                //= spec/framework/cmm-interface.md#get-encryption-materials
                //# - If the encryption materials request contains an algorithm suite, the encryption materials returned SHOULD contain the same algorithm suite.
                id
            }
        };

        let suite = suite_id.specification();

        //= spec/framework/default-cmm.md#get-encryption-materials
        //# Adding the key `aws-crypto-public-key` SHOULD be done to a copy of the encryption context
        //# so that the caller's encryption context is not mutated.
        let mut ec = request.encryption_context().clone();

        //= spec/framework/default-cmm.md#get-encryption-materials
        //# If the encryption context included in the [encryption materials request](cmm-interface.md#encryption-materials-request)
        //# already contains the `aws-crypto-public-key` key,
        //# this operation MUST fail rather than overwrite the associated value.
        if ec.contains_key(RESERVED_AWS_CRYPTO_PUBLIC_KEY) {
            return Err(MaterialsError::new(
                "Encryption context already contains reserved key 'aws-crypto-public-key'; refusing to overwrite",
            ));
        }

        // Generate a signing key (and seed the EC with the verification key)
        // when the resolved suite has an asymmetric signature algorithm.
        let signing_key = if suite_id.has_asymmetric_signing() {
            let alg = match suite.asymmetric_signature_algorithm().expect(
                "has_asymmetric_signing() == true implies asymmetric_signature_algorithm() is Some",
            ) {
                AsymmetricSignatureAlgorithm::EcdsaP256 => PrimEcdsaSignatureAlgorithm::EcdsaP256,
                AsymmetricSignatureAlgorithm::EcdsaP384 => PrimEcdsaSignatureAlgorithm::EcdsaP384,
            };

            // `prim` returns the key pair in the Dafny MPL's formats: the
            // verification key is already an X9.62 compressed point (33 bytes
            // for P-256, 49 for P-384), which is exactly the form the spec
            // requires in the encryption context per
            // `spec/framework/transitive-requirements.md#ecdsa` (SEC 1 v2.0
            // §2.3.3), and the signing key is DER-encoded, the form
            // `ecdsa_sign_digest` accepts when the message is signed.
            //= spec/framework/default-cmm.md#get-encryption-materials
            //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
            //# the default CMM MUST Generate a [signing key](structures.md#signing-key).
            let keys = ecdsa_generate_keypair(alg)
                .expect("ECDSA keypair generation cannot fail for fixed P-256/P-384 algorithms");
            let scalar_bytes = keys.signing_key;
            let public_key_bytes = keys.verification_key;

            // Encode the verification key as base64 (standard alphabet, with
            // padding) and store the resulting ASCII bytes in the EC.
            //= spec/framework/cmm-interface.md#get-encryption-materials
            //# If it does, the mapped value SHOULD be the signature verification key corresponding to the signing key.
            let base64_public_key = base64::engine::general_purpose::STANDARD
                .encode(&public_key_bytes)
                .into_bytes();

            //= spec/framework/default-cmm.md#get-encryption-materials
            //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
            //# the default CMM MUST Add the key-value pair of
            //# key `aws-crypto-public-key`,
            //# value `base64-encoded public verification key`
            //# to the [encryption context](structures.md#encryption-context).
            //
            //= spec/framework/cmm-interface.md#get-encryption-materials
            //# - The CMM SHOULD also add a key-value pair using the reserved key `aws-crypto-public-key` to the encryption context.
            //
            //= spec/framework/cmm-interface.md#get-encryption-materials
            //# - The CMM MAY modify the encryption context.
            ec.insert(RESERVED_AWS_CRYPTO_PUBLIC_KEY.to_vec(), base64_public_key);

            //= spec/framework/cmm-interface.md#get-encryption-materials
            //# - The CMM MUST include a [signing key](structures.md#signing-key).
            //
            //= spec/framework/cmm-interface.md#get-encryption-materials
            //# - If the algorithm suite contains a signing algorithm, the encryption materials returned MUST include the generated signing key.
            Some(SigningKey::new(scalar_bytes))
        } else {
            //= spec/framework/cmm-interface.md#get-encryption-materials
            //# - The CMM SHOULD NOT add a key-value pair using the reserved key `aws-crypto-public-key` to the encryption context.
            None
        };

        // Required-encryption-context-keys come from the request (or empty).
        // reck is copied verbatim from the request, so it is trivially a
        // superset of the request's set.
        //= spec/framework/cmm-interface.md#get-encryption-materials
        //# - The [Required Encryption Context Keys](structures.md#required-encryption-context-keys) MUST be
        //# a super set of the Required Encryption Context Keys in the [encryption materials request](#encryption-materials-request).
        let reck = request
            .required_encryption_context_keys()
            .cloned()
            .unwrap_or_default();

        // Build empty materials carrying the resolved suite, the (possibly
        // signing-key-augmented) EC, the request's RECK, and the freshly
        // generated signing key. The keyring populates the PDK and EDK list.
        //= spec/framework/cmm-interface.md#get-encryption-materials
        //# The CMM MUST ensure that the encryption materials returned are valid.
        //
        //= spec/framework/cmm-interface.md#get-encryption-materials
        //# - The encryption materials returned MUST follow the specification for [encryption-materials](structures.md#encryption-materials).
        let empty_materials =
            EncryptionMaterials::new(suite_id, vec![], ec, reck, None, signing_key, None)?;

        //= spec/framework/default-cmm.md#get-encryption-materials
        //# On each call to Get Encryption Materials,
        //# the default CMM MUST make a call to its [keyring's](#keyring)
        //# [On Encrypt](keyring-interface.md#onencrypt) operation.
        let materials = self.keyring.on_encrypt(empty_materials).await?;

        // on_encrypt populates PDK; returning materials passes it through unchanged.
        //= spec/framework/cmm-interface.md#get-encryption-materials
        //# When the CMM gets an [encryption materials request](#encryption-materials-request),
        //# it MUST return [encryption materials](structures.md#encryption-materials) appropriate for the request.
        //
        //= spec/framework/cmm-interface.md#get-encryption-materials
        //# The encryption materials returned MUST include the following:
        //
        //= spec/framework/default-cmm.md#get-encryption-materials
        //# The default CMM MUST obtain the Plaintext Data Key from the
        //# On Encrypt Response and include it in the
        //# [encryption materials](structures.md#encryption-materials) returned.
        //
        //= spec/framework/default-cmm.md#get-encryption-materials
        //# The default CMM MUST obtain the
        //# [Encrypted Data Keys](structures.md#encrypted-data-keys)
        //# from the On Encrypt Response and include it
        //# in the [encryption materials](structures.md#encryption-materials) returned.
        Ok(materials)
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MaterialsError> {
        let suite_id = request.algorithm_suite_id();
        let commitment_policy = request.commitment_policy();

        if !commitment_policy.allows_for_decrypt(suite_id) {
            //= spec/framework/default-cmm.md#decrypt-materials
            //# The request MUST fail if the algorithm suite on the request is not supported by the [commitment policy](./commitment-policy.md#supported-commitment-policy-enum) on the request.
            return Err(MaterialsError::new(format!(
                "Algorithm suite {suite_id:?} is not supported by commitment policy {commitment_policy:?} for decryption"
            )));
        }

        // Merge the message's encryption context with the customer-supplied
        // Reproduced Encryption Context before anything reads the context. Every
        // subsequent step — the reserved-key checks, the verification key, and
        // the context handed to the keyring as AAD — MUST see the merged
        // context, not the message's.
        let (ec, required_encryption_context_keys) = merge_reproduced_encryption_context(
            request.encryption_context(),
            request.reproduced_encryption_context(),
        )?;

        // For signing suites: extract the verification key from the EC under
        // the reserved aws-crypto-public-key. For non-signing suites: reject
        // the request if the EC unexpectedly carries that reserved key.
        let verification_key = if suite_id.has_asymmetric_signing() {
            //= spec/framework/default-cmm.md#decrypt-materials
            //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
            //# the default CMM MUST extract the verification key
            //# from the encryption context under the reserved `aws-crypto-public-key` key.
            let Some(b64_bytes) = ec.get(RESERVED_AWS_CRYPTO_PUBLIC_KEY) else {
                //= spec/framework/default-cmm.md#decrypt-materials
                //# If this key is not present in the encryption context, the operation MUST fail
                //# without returning any decryption materials.
                //
                //= spec/framework/cmm-interface.md#decrypt-materials
                //# Likewise, if the requested algorithm suite includes a signing algorithm but the encryption context does not include the reserved `aws-crypto-public-key` key, the operation SHOULD fail.
                return Err(MaterialsError::aws_crypto_public_key_missing(
                    "decrypt_materials: signing-suite request encryption context is missing the reserved 'aws-crypto-public-key' entry",
                ));
            };
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64_bytes)
                .map_err(|e| {
                    MaterialsError::new(format!(
                        "Failed to base64-decode aws-crypto-public-key value: {e}"
                    ))
                })?;
            //= spec/framework/cmm-interface.md#decrypt-materials
            //# If the algorithm suite obtained from the decryption request contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
            //# the decryption materials MUST include the [signature verification key](structures.md#verification-key).
            Some(VerificationKey::new(decoded))
        } else {
            if ec.contains_key(RESERVED_AWS_CRYPTO_PUBLIC_KEY) {
                //= spec/framework/default-cmm.md#decrypt-materials
                //# If the algorithm suite does not contain a [signing algorithm](algorithm-suites.md#signature-algorithm),
                //# but the encryption context includes the reserved `aws-crypto-public-key` key,
                //# the operation MUST fail without returning any decryption materials.
                //
                //= spec/framework/cmm-interface.md#decrypt-materials
                //# If the requested algorithm suite does not include a signing algorithm but the encryption context includes the reserved `aws-crypto-public-key` key, the operation SHOULD fail.
                return Err(MaterialsError::aws_crypto_public_key_unexpected(
                    "decrypt_materials: non-signing-suite request encryption context contains the reserved 'aws-crypto-public-key' entry",
                ));
            }
            None
        };

        // Build empty decryption materials. The keyring populates the PDK by
        // recovering it from one of the request's encrypted data keys.
        //= spec/framework/cmm-interface.md#decrypt-materials
        //# The CMM MUST ensure that the decryption materials returned are valid.
        //
        //= spec/framework/cmm-interface.md#decrypt-materials
        //# - The decryption materials returned MUST follow the specification for [decryption-materials](structures.md#decryption-materials).
        //
        //= spec/framework/cmm-interface.md#decrypt-materials
        //# - If the decrypt materials request contains an algorithm suite,
        //# the decryption materials returned SHOULD contain the same algorithm suite.
        let empty_materials = DecryptionMaterials::new(
            suite_id,
            ec,
            required_encryption_context_keys,
            None,
            verification_key,
            None,
        )?;

        //= spec/framework/default-cmm.md#decrypt-materials
        //# On each call to Decrypt Materials,
        //# the default CMM MUST make a call to its [keyring's](#keyring)
        //# [On Decrypt](keyring-interface.md#ondecrypt) operation.
        let materials = self
            .keyring
            .on_decrypt(empty_materials, request.encrypted_data_keys())
            .await?;

        // on_decrypt populates PDK; returning materials passes it through unchanged.
        //= spec/framework/cmm-interface.md#decrypt-materials
        //# When the CMM gets a [decrypt materials request](#decrypt-materials-request),
        //# it MUST return [decryption materials](structures.md#decryption-materials) appropriate for the request.
        //
        //= spec/framework/cmm-interface.md#decrypt-materials
        //# The decryption materials returned MUST include the following:
        //
        //= spec/framework/default-cmm.md#decrypt-materials
        //# The default CMM MUST obtain the Plaintext Data Key from
        //# the On Decrypt response and include it in the decrypt
        //# materials returned.
        Ok(materials)
    }
}

/// Merge the message's encryption context with the customer-supplied
/// Reproduced Encryption Context, per
/// `spec/framework/cmm-interface.md#decrypt-materials`.
///
/// Returns the encryption context to place on the decryption materials and the
/// Required Encryption Context Keys that accompany it:
///
/// - For every key present in both contexts, the values MUST be equal or the
///   operation fails with `MaterialsErrorKind::EncryptionContextValueMismatch`.
/// - Every pair present in the reproduced context but absent from the message's
///   is appended to the returned context, and its key becomes a Required
///   Encryption Context Key.
///
/// The appended pairs are what make a keyring's AAD whole again: an encrypting
/// CMM may hold required keys back from the message, so a decryptor that only
/// ever saw the message's context would compute a short AAD and fail
/// authentication.
fn merge_reproduced_encryption_context(
    message_ec: &EncryptionContext,
    reproduced_ec: Option<&EncryptionContext>,
) -> Result<(EncryptionContext, BTreeSet<Vec<u8>>), MaterialsError> {
    let mut ec = message_ec.clone();
    let mut required_keys = BTreeSet::new();

    let Some(reproduced_ec) = reproduced_ec else {
        return Ok((ec, required_keys));
    };

    for (key, value) in reproduced_ec.iter() {
        //= spec/framework/cmm-interface.md#decrypt-materials
        //# The CMM MUST validate the [Encryption Context](structures.md#encryption-context)
        //# by comparing it to the customer supplied [Reproduced Encryption Context](structures.md#encryption-context)
        //# in [decrypt materials request](#decrypt-materials-request).
        match message_ec.get(key) {
            Some(message_value) => {
                if message_value != value {
                    //= spec/framework/cmm-interface.md#decrypt-materials
                    //# For every key that exists in both [Reproduced Encryption Context](structures.md#encryption-context)
                    //# and [Encryption Context](structures.md#encryption-context),
                    //# the values MUST be equal or the operation MUST fail.
                    return Err(MaterialsError::encryption_context_value_mismatch(format!(
                        "decrypt_materials: reproduced encryption context disagrees with the message's encryption context on key '{}'",
                        String::from_utf8_lossy(key),
                    )));
                }
            }
            None => {
                //= spec/framework/cmm-interface.md#decrypt-materials
                //# - All key-value pairs that exist in [Reproduced Encryption Context](structures.md#encryption-context)
                //# but do not exist in encryption context on the [decrypt materials request](#decrypt-materials-request)
                //# SHOULD be appended to the decryption materials.
                //
                //= spec/framework/cmm-interface.md#decrypt-materials
                //# - The CMM MAY modify the encryption context.
                ec.insert(key.clone(), value.clone());
                //= spec/framework/cmm-interface.md#decrypt-materials
                //# - This set MUST include all keys added to the decryption materials encryption context
                //# that existed in the [decrypt materials request's](#decrypt-materials-request) reproduced encryption context
                //# but did not exist in the [decrypt materials request's](#decrypt-materials-request) encryption context.
                //
                // Every key inserted into required_keys was inserted into `ec` on the line
                // above, so the set is always a subset of the returned context's keys.
                //= spec/framework/cmm-interface.md#decrypt-materials
                //= type=implication
                //# - All keys in this set MUST exist in the decryption materials encryption context.
                required_keys.insert(key.clone());
            }
        }
    }

    Ok((ec, required_keys))
}
