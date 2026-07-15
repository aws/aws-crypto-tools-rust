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
///   base64-encoded SEC1-compressed public key into a copy of the request's
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
            None => commitment_policy.default_algorithm_suite_id(),
            Some(id) => {
                if !commitment_policy.allows_for_encrypt(id) {
                    return Err(MaterialsError::new(format!(
                        "Algorithm suite {id:?} is not supported by commitment policy {commitment_policy:?} for encryption"
                    )));
                }
                id
            }
        };

        let suite = suite_id.specification();

        let mut ec = request.encryption_context().clone();

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
                AsymmetricSignatureAlgorithm::EcdsaP256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
                AsymmetricSignatureAlgorithm::EcdsaP384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            };

            let key_pair = EcdsaKeyPair::generate(alg)
                .expect("ECDSA keypair generation cannot fail for fixed P-256/P-384 algorithms");

            // Extract the raw private scalar (32 bytes for P-256, 48 for P-384).
            let scalar_bytes = key_pair
                .private_key()
                .as_be_bytes()
                .expect("ECDSA private scalar encoding cannot fail for valid keypair")
                .as_ref()
                .to_vec();

            // SEC1-compressed public point: tag byte (`0x02` when Y is even,
            // `0x03` when Y is odd) followed by the X coordinate. 33 bytes
            // for P-256, 49 for P-384. aws-lc-rs emits the SEC1-*uncompressed*
            // form (`0x04 || X || Y`); the spec requires the compressed form
            // in the encryption context per
            // `spec/framework/transitive-requirements.md#ecdsa` (SEC 1 v2.0
            // §2.3.3).
            let uncompressed = key_pair.public_key().as_ref();
            debug_assert_eq!(uncompressed[0], 0x04);
            let coord_len = (uncompressed.len() - 1) / 2;
            let y_lsb = uncompressed[uncompressed.len() - 1];
            let tag = if y_lsb & 1 == 0 { 0x02 } else { 0x03 };
            let mut public_key_bytes = Vec::with_capacity(1 + coord_len);
            public_key_bytes.push(tag);
            public_key_bytes.extend_from_slice(&uncompressed[1..=coord_len]);

            // Encode the verification key as base64 (standard alphabet, with
            // padding) and store the resulting ASCII bytes in the EC.
            let base64_public_key = base64::engine::general_purpose::STANDARD
                .encode(&public_key_bytes)
                .into_bytes();

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

        let materials = self.keyring.on_encrypt(empty_materials).await?;

        // on_encrypt populates PDK; returning materials passes it through unchanged.
        //
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
            return Err(MaterialsError::new(format!(
                "Algorithm suite {suite_id:?} is not supported by commitment policy {commitment_policy:?} for decryption"
            )));
        }

        // For signing suites: extract the verification key from the EC under
        // the reserved aws-crypto-public-key. For non-signing suites: reject
        // the request if the EC unexpectedly carries that reserved key.
        let verification_key = if suite_id.has_asymmetric_signing() {
            let Some(b64_bytes) = ec.get(RESERVED_AWS_CRYPTO_PUBLIC_KEY) else {
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

        let materials = self
            .keyring
            .on_decrypt(empty_materials, request.encrypted_data_keys())
            .await?;

        // on_decrypt populates PDK; returning materials passes it through unchanged.
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

const _LEGACY_MKP_NOT_IMPLEMENTED_LEGACY: () = ();

const _LEGACY_MKP_NOT_IMPLEMENTED_LEGACY_BEHAVIOR: () = ();

const _LEGACY_MKP_NOT_IMPLEMENTED_INIT_1: () = ();

const _LEGACY_MKP_NOT_IMPLEMENTED_GEM_1: () = ();

const _LEGACY_MKP_NOT_IMPLEMENTED_GEM_2: () = ();

const _LEGACY_MKP_NOT_IMPLEMENTED_GEM_3: () = ();

const _LEGACY_MKP_NOT_IMPLEMENTED_GEM_4: () = ();

const _LEGACY_MKP_NOT_IMPLEMENTED_DM: () = ();
