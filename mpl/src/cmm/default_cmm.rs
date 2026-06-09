// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Default CMM — concrete implementation of the [`Cmm`](super::Cmm) trait
//! that wraps a single keyring.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
};
use base64::Engine;

use super::Cmm;
use super::request::{DecryptMaterialsRequest, EncryptionMaterialsRequest};
use crate::keyring::Keyring;
use crate::structures::{
    AsymmetricSignatureAlgorithm, DecryptionMaterials, EncryptionMaterials, MaterialsError,
    SigningKey, VerificationKey,
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
/// - For signing suites: generates an ECDSA key pair via `aws-lc-rs`, attaches
///   the private signing key to the materials, and inserts the
///   base64-encoded SEC1-uncompressed public key into a copy of the request's
///   encryption context under the reserved `aws-crypto-public-key` key.
/// - Calls the wrapped keyring's `on_encrypt` to populate the plaintext data
///   key and encrypted data keys.
///
/// On `decrypt_materials` the default CMM:
/// - Validates the algorithm suite against the request's commitment policy.
/// - For signing suites: extracts and base64-decodes the verification key
///   from the request's encryption context.
/// - For non-signing suites: rejects requests whose encryption context
///   contains the reserved `aws-crypto-public-key`.
/// - Calls the wrapped keyring's `on_decrypt` to populate the plaintext data
///   key.
pub struct DefaultCmm {
    keyring: Arc<dyn Keyring>,
}

impl DefaultCmm {
    /// Construct a `DefaultCmm` wrapping the given keyring.
    //= ../spec/framework/default-cmm.md#initialization
    //# On default CMM initialization,
    //# the caller MUST provide the following value:
    pub fn new(keyring: Arc<dyn Keyring>) -> Self {
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
            None => {
                //= ../spec/framework/default-cmm.md#get-encryption-materials
                //# - If the [encryption materials request](cmm-interface.md#encryption-materials-request) does not contain an algorithm suite,
                //# the operation MUST add the default algorithm suite for the [commitment policy](./commitment-policy.md#supported-commitment-policy-enum)
                //# as the algorithm suite in the encryption materials returned.
                commitment_policy.default_algorithm_suite_id()
            }
            Some(id) => {
                if !commitment_policy.allows_for_encrypt(id) {
                    //= ../spec/framework/default-cmm.md#get-encryption-materials
                    //# - If the [encryption materials request](cmm-interface.md#encryption-materials-request) does contain an algorithm suite,
                    //# the request MUST fail if the algorithm suite is not supported by the [commitment policy](./commitment-policy.md#supported-commitment-policy-enum) on the request.
                    return Err(MaterialsError::new(format!(
                        "Algorithm suite {id:?} is not supported by commitment policy {commitment_policy:?} for encryption"
                    )));
                }
                //= ../spec/framework/default-cmm.md#get-encryption-materials
                //# - If the [encryption materials request](cmm-interface.md#encryption-materials-request) does contain an algorithm suite,
                //# the encryption materials returned MUST contain the same algorithm suite.
                id
            }
        };

        let suite = suite_id.specification();

        //= ../spec/framework/default-cmm.md#get-encryption-materials
        //# Adding the key `aws-crypto-public-key` SHOULD be done to a copy of the encryption context
        //# so that the caller's encryption context is not mutated.
        let mut ec = request.encryption_context().clone();

        if ec.contains_key(RESERVED_AWS_CRYPTO_PUBLIC_KEY) {
            //= ../spec/framework/default-cmm.md#get-encryption-materials
            //# If the encryption context included in the [encryption materials request](cmm-interface.md#encryption-materials-request)
            //# already contains the `aws-crypto-public-key` key,
            //# this operation MUST fail rather than overwrite the associated value.
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
                AsymmetricSignatureAlgorithm::EcdsaP256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
                AsymmetricSignatureAlgorithm::EcdsaP384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            };

            //= ../spec/framework/default-cmm.md#get-encryption-materials
            //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
            //# the default CMM MUST Generate a [signing key](structures.md#signing-key).
            let key_pair = EcdsaKeyPair::generate(alg)
                .expect("ECDSA keypair generation cannot fail for fixed P-256/P-384 algorithms");

            // Extract the raw private scalar (32 bytes for P-256, 48 for P-384).
            let scalar_bytes = key_pair
                .private_key()
                .as_be_bytes()
                .expect("ECDSA private scalar encoding cannot fail for valid keypair")
                .as_ref()
                .to_vec();

            // SEC1-uncompressed public point: 65 bytes for P-256, 97 for P-384.
            let public_key_bytes = key_pair.public_key().as_ref();

            // Encode the verification key as base64 (standard alphabet, with
            // padding) and store the resulting ASCII bytes in the EC.
            let base64_public_key = base64::engine::general_purpose::STANDARD
                .encode(public_key_bytes)
                .into_bytes();

            //= ../spec/framework/default-cmm.md#get-encryption-materials
            //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
            //# the default CMM MUST Add the key-value pair of
            //# key `aws-crypto-public-key`,
            //# value `base64-encoded public verification key`
            //# to the [encryption context](structures.md#encryption-context).
            ec.insert(RESERVED_AWS_CRYPTO_PUBLIC_KEY.to_vec(), base64_public_key);

            Some(SigningKey::new(scalar_bytes))
        } else {
            None
        };

        // Required-encryption-context-keys come from the request (or empty).
        let reck = request
            .required_encryption_context_keys()
            .cloned()
            .unwrap_or_default();

        // Build empty materials carrying the resolved suite, the (possibly
        // signing-key-augmented) EC, the request's RECK, and the freshly
        // generated signing key. The keyring populates the PDK and EDK list.
        let empty_materials =
            EncryptionMaterials::new(suite_id, vec![], ec, reck, None, signing_key, None)?;

        //= ../spec/framework/default-cmm.md#get-encryption-materials
        //# On each call to Get Encryption Materials,
        //# the default CMM MUST make a call to its [keyring's](#keyring)
        //# [On Encrypt](keyring-interface.md#onencrypt) operation.
        let materials = self.keyring.on_encrypt(empty_materials).await?;

        // on_encrypt populates PDK; returning materials passes it through unchanged.
        //= ../spec/framework/default-cmm.md#get-encryption-materials
        //# The default CMM MUST obtain the Plaintext Data Key from the
        //# On Encrypt Response and include it in the
        //# [encryption materials](structures.md#encryption-materials) returned.
        //
        //= ../spec/framework/default-cmm.md#get-encryption-materials
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
        let ec = request.encryption_context();

        if !commitment_policy.allows_for_decrypt(suite_id) {
            //= ../spec/framework/default-cmm.md#decrypt-materials
            //# The request MUST fail if the algorithm suite on the request is not supported by the [commitment policy](./commitment-policy.md#supported-commitment-policy-enum) on the request.
            return Err(MaterialsError::new(format!(
                "Algorithm suite {suite_id:?} is not supported by commitment policy {commitment_policy:?} for decryption"
            )));
        }

        // For signing suites: extract the verification key from the EC under
        // the reserved aws-crypto-public-key. For non-signing suites: reject
        // the request if the EC unexpectedly carries that reserved key.
        let verification_key = if suite_id.has_asymmetric_signing() {
            //= ../spec/framework/default-cmm.md#decrypt-materials
            //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
            //# the default CMM MUST extract the verification key
            //# from the encryption context under the reserved `aws-crypto-public-key` key.
            let Some(b64_bytes) = ec.get(RESERVED_AWS_CRYPTO_PUBLIC_KEY) else {
                //= ../spec/framework/default-cmm.md#decrypt-materials
                //# If this key is not present in the encryption context, the operation MUST fail
                //# without returning any decryption materials.
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
            Some(VerificationKey::new(decoded))
        } else {
            if ec.contains_key(RESERVED_AWS_CRYPTO_PUBLIC_KEY) {
                //= ../spec/framework/default-cmm.md#decrypt-materials
                //# If the algorithm suite does not contain a [signing algorithm](algorithm-suites.md#signature-algorithm),
                //# but the encryption context includes the reserved `aws-crypto-public-key` key,
                //# the operation MUST fail without returning any decryption materials.
                return Err(MaterialsError::aws_crypto_public_key_unexpected(
                    "decrypt_materials: non-signing-suite request encryption context contains the reserved 'aws-crypto-public-key' entry",
                ));
            }
            None
        };

        // Build empty decryption materials. The keyring populates the PDK by
        // recovering it from one of the request's encrypted data keys.
        let empty_materials = DecryptionMaterials::new(
            suite_id,
            ec.clone(),
            BTreeSet::new(),
            None,
            verification_key,
            None,
        )?;

        //= ../spec/framework/default-cmm.md#decrypt-materials
        //# On each call to Decrypt Materials,
        //# the default CMM MUST make a call to its [keyring's](#keyring)
        //# [On Decrypt](keyring-interface.md#ondecrypt) operation.
        let materials = self
            .keyring
            .on_decrypt(empty_materials, request.encrypted_data_keys())
            .await?;

        // on_decrypt populates PDK; returning materials passes it through unchanged.
        //= ../spec/framework/default-cmm.md#decrypt-materials
        //# The default CMM MUST obtain the Plaintext Data Key from
        //# the On Decrypt response and include it in the decrypt
        //# materials returned.
        Ok(materials)
    }
}

// =====================================================================
// Legacy MKP requirements — not implemented
//
// Per §Legacy of the Default CMM specification:
//
//     "Master key providers SHOULD NOT be included in any additional
//     implementations."
//
// The Rust MPL has no master-key-provider interface and intentionally
// omits one per that guidance. The 8 legacy `[[spec]]` entries below
// are annotated `type=exception` with that sentence as their reason.
// Each annotation block is anchored above a private zero-cost
// `const _: () = ();` so duvet's "annotation immediately followed by
// executable line" rule holds.
// =====================================================================

//= ../spec/framework/default-cmm.md#legacy
//= type=exception
//= reason=Master key providers SHOULD NOT be included in any additional implementations.
//# Master key providers SHOULD NOT be included in any additional implementations.
const _LEGACY_MKP_NOT_IMPLEMENTED_LEGACY: () = ();

//= ../spec/framework/default-cmm.md#legacy-behavior-master-key-providers
//= type=exception
//= reason=Master key providers SHOULD NOT be included in any additional implementations.
//# For implementations that support [master key providers](master-key-provider-interface.md),
//# the default CMM MUST support generating, encrypting, and decrypting data keys
//# using master key providers.
const _LEGACY_MKP_NOT_IMPLEMENTED_LEGACY_BEHAVIOR: () = ();

//= ../spec/framework/default-cmm.md#initialization-1
//= type=exception
//= reason=Master key providers SHOULD NOT be included in any additional implementations.
//# On default CMM initialization,
//# the caller MUST provide the following value:
const _LEGACY_MKP_NOT_IMPLEMENTED_INIT_1: () = ();

//= ../spec/framework/default-cmm.md#get-encryption-materials-master-key-provider
//= type=exception
//= reason=Master key providers SHOULD NOT be included in any additional implementations.
//# The default CMM MUST call its master key provider's
//# [Get Master Keys for Encryption](master-key-provider-interface.md#get-master-keys-for-encryption) operation
//# to obtain a list of master keys to use.
const _LEGACY_MKP_NOT_IMPLEMENTED_GEM_1: () = ();

//= ../spec/framework/default-cmm.md#get-encryption-materials-master-key-provider
//= type=exception
//= reason=Master key providers SHOULD NOT be included in any additional implementations.
//# If the master key provider does not identify which master key MUST generate the data key,
//# the default CMM MUST use the first master key in the list for that purpose.
const _LEGACY_MKP_NOT_IMPLEMENTED_GEM_2: () = ();

//= ../spec/framework/default-cmm.md#get-encryption-materials-master-key-provider
//= type=exception
//= reason=Master key providers SHOULD NOT be included in any additional implementations.
//# The default CMM MUST generate the data key using this master key's
//# [Generate Data Key](master-key-interface.md#generate-data-key) operation.
const _LEGACY_MKP_NOT_IMPLEMENTED_GEM_3: () = ();

//= ../spec/framework/default-cmm.md#get-encryption-materials-master-key-provider
//= type=exception
//= reason=Master key providers SHOULD NOT be included in any additional implementations.
//# For each remaining master key,
//# the default CMM MUST call the master key's
//# [Encrypt Data Key](master-key-interface.md#encrypt-data-key) operation
//# with the plaintext data key.
const _LEGACY_MKP_NOT_IMPLEMENTED_GEM_4: () = ();

//= ../spec/framework/default-cmm.md#decrypt-materials-master-key-provider
//= type=exception
//= reason=Master key providers SHOULD NOT be included in any additional implementations.
//# The default CMM MUST call its master key provider's
//# [Decrypt Data Key](master-key-provider-interface.md#decrypt-data-key) operation.
const _LEGACY_MKP_NOT_IMPLEMENTED_DM: () = ();
