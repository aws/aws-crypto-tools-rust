// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Default CMM — concrete implementation of the [`Cmm`](super::Cmm) trait
//! that wraps a single keyring.

use crate::Error;
use crate::error::Kind;
use std::borrow::Cow;
use std::collections::BTreeSet;

use async_trait::async_trait;
use aws_mpl_primitives::{
    EcdsaSignatureAlgorithm as PrimEcdsaSignatureAlgorithm, ecdsa_generate_keypair,
};
use base64::Engine;

use super::Cmm;
use super::{
    DecryptMaterialsInput, DecryptMaterialsOutput, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
};
use crate::keyring::{Keyring, SharedKeyring};
use crate::shared::IntoShared;
use crate::structures::{
    AsymmetricSignatureAlgorithm, DecryptionMaterials, EncryptionContext, EncryptionMaterials,
    SigningKey, VerificationKey,
};

/// Reserved encryption-context key under which the default CMM stores the
/// base64-encoded ECDSA verification key for signing-suite messages.
const RESERVED_AWS_CRYPTO_PUBLIC_KEY: &str = "aws-crypto-public-key";

/// Concrete CMM that uses a single keyring and resolves an algorithm suite
/// from each input's commitment policy.
///
/// On `get_encryption_materials` the default CMM:
/// - Resolves the algorithm suite from the request (or, if absent, from the
///   commitment policy's default).
/// - For signing suites: generates an ECDSA key pair via `aws-mpl-primitives`, attaches
///   the private signing key to the materials, and inserts the
///   base64-encoded SEC1-compressed public key into a copy of the input's
///   encryption context under the reserved `aws-crypto-public-key` key.
/// - Calls the wrapped keyring's `on_encrypt` to populate the plaintext data
///   key and encrypted data keys.
///
/// On `decrypt_materials` the default CMM:
/// - Validates the algorithm suite against the input's commitment policy.
/// - Merges the input's encryption context with its Reproduced
///   Encryption Context: shared keys must agree, and pairs present only in
///   the reproduced context are appended and reported as Required Encryption
///   Context Keys. See [`merge_reproduced_encryption_context`].
/// - For signing suites: extracts and base64-decodes the verification key
///   from the merged encryption context.
/// - For non-signing suites: rejects requests whose merged encryption
///   context contains the reserved `aws-crypto-public-key`.
/// - Calls the wrapped keyring's `on_decrypt` to populate the plaintext data
///   key.
#[derive(Clone)]
pub struct DefaultCmm {
    keyring: SharedKeyring,
}

impl DefaultCmm {
    /// Construct a `DefaultCmm` wrapping the given keyring.
    pub fn new(keyring: impl Keyring + 'static) -> Self {
        Self {
            keyring: keyring.into_shared(),
        }
    }
}

#[async_trait]
impl Cmm for DefaultCmm {
    fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed("default")
    }

    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, Error> {
        let commitment_policy = input.commitment_policy();

        // Resolve the algorithm suite for this request: either from the
        // commitment policy's default (when the request doesn't specify one)
        // or by validating the input's choice against the policy.
        let suite_id = match input.algorithm_suite_id() {
            None => commitment_policy.default_algorithm_suite_id(),
            Some(id) => {
                if !commitment_policy.allows_for_encrypt(id) {
                    return Err(Error::new(
                        Kind::Validation,
                        format!(
                            "algorithm suite {id:?} is not supported by commitment policy {commitment_policy:?} for encryption"
                        ),
                    ));
                }
                id
            }
        };

        let suite = suite_id.specification();

        let mut ec = input.encryption_context().clone();

        if ec.contains_key(RESERVED_AWS_CRYPTO_PUBLIC_KEY) {
            return Err(Error::new(
                Kind::Validation,
                "encryption context already contains reserved key 'aws-crypto-public-key'; refusing to overwrite",
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
            let keys = ecdsa_generate_keypair(alg)
                .expect("ECDSA keypair generation cannot fail for fixed P-256/P-384 algorithms");
            let scalar_bytes = keys.signing_key;
            let public_key_bytes = keys.verification_key;

            // The EC carries the verification key as standard base64 with padding.
            let base64_public_key =
                base64::engine::general_purpose::STANDARD.encode(&public_key_bytes);

            ec.insert(RESERVED_AWS_CRYPTO_PUBLIC_KEY, base64_public_key);

            Some(SigningKey::new(scalar_bytes))
        } else {
            None
        };

        // Required-encryption-context-keys come from the request (or empty).
        let reck = input
            .required_encryption_context_keys()
            .cloned()
            .unwrap_or_default();

        // Build empty materials carrying the resolved suite, the (possibly
        // signing-key-augmented) EC, the input's RECK, and the freshly
        // generated signing key. The keyring populates the PDK and EDK list.
        let empty_materials = EncryptionMaterials::builder()
            .algorithm_suite_id(suite_id)
            .encryption_context(ec)
            .required_encryption_context_keys(reck)
            .set_signing_key(signing_key)
            .build()?;

        let materials = self
            .keyring
            .on_encrypt()
            .materials(empty_materials)
            .send()
            .await?
            .into_materials();

        // on_encrypt populates PDK; returning materials passes it through unchanged.
        Ok(materials.into())
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, Error> {
        let suite_id = input.algorithm_suite_id();
        let commitment_policy = input.commitment_policy();

        if !commitment_policy.allows_for_decrypt(suite_id) {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "algorithm suite {suite_id:?} is not supported by commitment policy {commitment_policy:?} for decryption"
                ),
            ));
        }

        // Merge the message's encryption context with the customer-supplied
        // Reproduced Encryption Context before anything reads the context. Every
        // subsequent step — the reserved-key checks, the verification key, and
        // the context handed to the keyring as AAD — MUST see the merged
        // context, not the message's.
        let (ec, required_encryption_context_keys) = merge_reproduced_encryption_context(
            input.encryption_context(),
            input.reproduced_encryption_context(),
        )?;

        // For signing suites: extract the verification key from the EC under
        // the reserved aws-crypto-public-key. For non-signing suites: reject
        // the request if the EC unexpectedly carries that reserved key.
        let verification_key = if suite_id.has_asymmetric_signing() {
            let Some(b64_bytes) = ec.get(RESERVED_AWS_CRYPTO_PUBLIC_KEY) else {
                return Err(Error::new(
                    Kind::Validation,
                    "signing-suite request encryption context is missing the reserved 'aws-crypto-public-key' entry",
                ));
            };
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64_bytes)
                .map_err(|e| {
                    Error::with_cause(
                        Kind::Validation,
                        "failed to base64-decode the aws-crypto-public-key value",
                        e,
                    )
                })?;
            Some(VerificationKey::new(decoded))
        } else {
            if ec.contains_key(RESERVED_AWS_CRYPTO_PUBLIC_KEY) {
                return Err(Error::new(
                    Kind::Validation,
                    "non-signing-suite request encryption context contains the reserved 'aws-crypto-public-key' entry",
                ));
            }
            None
        };

        // Build empty decryption materials. The keyring populates the PDK by
        // recovering it from one of the input's encrypted data keys.
        let empty_materials = DecryptionMaterials::builder()
            .algorithm_suite_id(suite_id)
            .encryption_context(ec)
            .required_encryption_context_keys(required_encryption_context_keys)
            .set_verification_key(verification_key)
            .build()?;

        let materials = self
            .keyring
            .on_decrypt()
            .materials(empty_materials)
            .encrypted_data_keys(input.encrypted_data_keys)
            .send()
            .await?
            .into_materials();

        // on_decrypt populates PDK; returning materials passes it through unchanged.
        Ok(materials.into())
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
///   operation fails with `Kind::EncryptionContextMismatch`.
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
) -> Result<(EncryptionContext, BTreeSet<String>), Error> {
    let mut ec = message_ec.clone();
    let mut required_keys = BTreeSet::new();

    let Some(reproduced_ec) = reproduced_ec else {
        return Ok((ec, required_keys));
    };

    for (key, value) in reproduced_ec.iter() {
        match message_ec.get(key) {
            Some(message_value) => {
                if message_value != value {
                    return Err(Error::new(
                        Kind::EncryptionContextMismatch,
                        format!(
                            "message encryption context does not match reproduced encryption context on key '{key}'",
                        ),
                    ));
                }
            }
            None => {
                ec.insert(key, value);
                required_keys.insert(key.to_owned());
            }
        }
    }

    Ok((ec, required_keys))
}
