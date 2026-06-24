// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The top-level S3 Encryption Client (S3EC).

use std::collections::BTreeMap;

use aws_sdk_s3::primitives::ByteStream;

use crate::config::{CommitmentPolicy, S3EncryptionConfig};
use crate::crypto;
use crate::error::{Result, S3EncryptionError};
use crate::keyring::{KmsKeyring, WRAP_ALG_KMS_CONTEXT};
use crate::metadata::{self, ObjectMetadata};

/// The plaintext and stored object metadata returned from a decrypting
/// GetObject.
#[derive(Debug, Clone)]
pub struct DecryptedObject {
    /// The decrypted object content.
    pub plaintext: Vec<u8>,
    /// The raw S3 user-metadata map stored with the object (the `x-amz-*`
    /// content-metadata mapkeys).
    pub metadata: BTreeMap<String, String>,
}

/// Client-side encrypting wrapper around the AWS S3 client.
///
/// Holds the validated [`S3EncryptionConfig`] together with the wrapped S3 SDK
/// client and the KMS keyring used to wrap and unwrap content data keys.
#[derive(Clone)]
pub struct S3EncryptionClient {
    config: S3EncryptionConfig,
    s3: aws_sdk_s3::Client,
    keyring: Option<KmsKeyring>,
}

impl S3EncryptionClient {
    //= spec/s3-encryption/client.md#cryptographic-materials
    //# The S3EC MUST accept either one CMM or one Keyring instance upon initialization.
    /// Construct a client from a validated config and the wrapped SDK clients.
    pub fn new(
        config: S3EncryptionConfig,
        s3: aws_sdk_s3::Client,
        kms: aws_sdk_kms::Client,
    ) -> Result<Self> {
        config.validate()?;
        let keyring = config.kms_key_id.as_ref().map(|key_id| {
            KmsKeyring::new(
                kms,
                key_id.clone(),
                config.enable_legacy_wrapping_algorithms,
            )
        });
        Ok(Self {
            config,
            s3,
            keyring,
        })
    }

    /// The region used when the ambient provider chain does not supply one.
    ///
    /// The cross-implementation test harness provisions its KMS key and S3
    /// bucket in `us-west-2`, and the reference `python-v4-server` hardcodes
    /// `region_name="us-west-2"` for its KMS client. The harness only exports
    /// `AWS_REGION` to the Java test client — not to the language server
    /// processes — so the server may start with no ambient region. Falling back
    /// to this region (rather than failing region resolution, which surfaces as
    /// an SDK "dispatch failure") keeps the Rust adapter wire-compatible with
    /// the reference servers.
    const DEFAULT_REGION: &'static str = "us-west-2";

    /// Construct a client from the ambient AWS environment, building the S3 and
    /// KMS clients from the default credential and region provider chain.
    pub async fn from_env(config: S3EncryptionConfig) -> Result<Self> {
        // Resolve the region from the standard provider chain (env, profile,
        // IMDS, …), falling back to [`Self::DEFAULT_REGION`] so the adapter
        // still reaches the harness's `us-west-2` resources when no region is
        // present in the server process's environment.
        let region_provider = aws_config::meta::region::RegionProviderChain::default_provider()
            .or_else(Self::DEFAULT_REGION);
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;
        let s3 = aws_sdk_s3::Client::new(&sdk_config);
        let kms = aws_sdk_kms::Client::new(&sdk_config);
        Self::new(config, s3, kms)
    }

    /// The client's configuration.
    pub fn config(&self) -> &S3EncryptionConfig {
        &self.config
    }

    /// The wrapped S3 client.
    pub fn s3(&self) -> &aws_sdk_s3::Client {
        &self.s3
    }

    fn require_keyring(&self) -> Result<&KmsKeyring> {
        self.keyring.as_ref().ok_or_else(|| {
            S3EncryptionError::Configuration("a KMS key identifier is required".to_string())
        })
    }

    /// Encrypt `plaintext` and store it at `bucket`/`key`.
    ///
    /// The content is encrypted with the configured (or default) algorithm
    /// suite; the data key is wrapped by KMS bound to `encryption_context`; and
    /// the resulting content metadata is attached to the S3 object.
    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        plaintext: &[u8],
        encryption_context: &BTreeMap<String, String>,
    ) -> Result<()> {
        let keyring = self.require_keyring()?;

        //= spec/s3-encryption/encryption.md#content-encryption
        //# The S3EC MUST use the encryption algorithm configured during [client](./client.md) initialization.
        let suite = self.config.effective_encryption_algorithm();

        // Bind the content algorithm into the KMS encryption context, then wrap
        // a fresh data key.
        let context = KmsKeyring::build_encryption_context(encryption_context, suite);
        let (plaintext_data_key, encrypted_data_key) = keyring.wrap(&context).await?;

        let (body, object_metadata) = build_encrypted_object(
            suite,
            &plaintext_data_key,
            &encrypted_data_key,
            &context,
            plaintext,
        )?;

        let metadata: std::collections::HashMap<String, String> =
            object_metadata.to_map().into_iter().collect();

        self.s3
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(body))
            .set_metadata(Some(metadata))
            .send()
            .await
            .map_err(|e| S3EncryptionError::Sdk(format!("S3 PutObject failed: {e}")))?;
        Ok(())
    }

    /// Fetch `bucket`/`key`, unwrap its data key via KMS, and decrypt its
    /// content. `encryption_context` is the caller-provided (request) context
    /// validated against the object's stored context.
    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
        encryption_context: &BTreeMap<String, String>,
    ) -> Result<DecryptedObject> {
        let keyring = self.require_keyring()?;

        let response = self
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| S3EncryptionError::Sdk(format!("S3 GetObject failed: {e}")))?;

        let raw_metadata: BTreeMap<String, String> = response
            .metadata()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();

        let ciphertext = response
            .body
            .collect()
            .await
            .map_err(|e| S3EncryptionError::Sdk(format!("failed to read S3 body: {e}")))?
            .to_vec();

        let md = ObjectMetadata::from_map(&raw_metadata);

        //= spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //# If there are multiple mapkeys which are meant to be exclusive to different versions, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
        if md.has_exclusive_key_collision() {
            return Err(S3EncryptionError::Format(
                "object metadata contains encrypted-data-key mapkeys from multiple exclusive \
                 format versions"
                    .to_string(),
            ));
        }

        let plaintext = if md.is_v3_format() {
            self.decrypt_v3(keyring, &md, &ciphertext, encryption_context)
                .await?
        } else if md.is_v2_format() {
            self.decrypt_v2(keyring, &md, &ciphertext, encryption_context)
                .await?
        } else {
            return Err(S3EncryptionError::Format(
                "object is not a supported S3EC V2 or V3 encrypted object".to_string(),
            ));
        };

        Ok(DecryptedObject {
            plaintext,
            metadata: raw_metadata,
        })
    }

    async fn decrypt_v2(
        &self,
        keyring: &KmsKeyring,
        md: &ObjectMetadata,
        ciphertext: &[u8],
        request_context: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>> {
        //= spec/s3-encryption/key-commitment.md#commitment-policy
        //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST NOT allow decryption using algorithm suites which do not support key commitment.
        if self.config.effective_commitment_policy()
            == CommitmentPolicy::RequireEncryptRequireDecrypt
        {
            return Err(S3EncryptionError::Crypto(
                "cannot decrypt a non-key-committing object when the commitment policy is \
                 REQUIRE_ENCRYPT_REQUIRE_DECRYPT"
                    .to_string(),
            ));
        }

        let encrypted_data_key = md.v2_encrypted_data_key()?;
        let stored_context = md.v2_stored_context()?;
        let wrap_algorithm = md
            .wrap_algorithm
            .clone()
            .unwrap_or_else(|| WRAP_ALG_KMS_CONTEXT.to_string());

        let plaintext_data_key = keyring
            .unwrap(
                &encrypted_data_key,
                &wrap_algorithm,
                &stored_context,
                request_context,
            )
            .await?;

        open_v2_content(&plaintext_data_key, md, ciphertext)
    }

    async fn decrypt_v3(
        &self,
        keyring: &KmsKeyring,
        md: &ObjectMetadata,
        ciphertext: &[u8],
        request_context: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>> {
        let encrypted_data_key = md.v3_encrypted_data_key()?;
        let stored_context = md.v3_stored_context()?;
        // The V3 wrapping algorithm is a compressed code; "12" (kms+context) is
        // the only mode this client writes.
        let wrap_code = md.wrap_algorithm_v3.as_deref().unwrap_or("12");
        let wrap_algorithm = metadata::v3_wrap_algorithm_to_name(wrap_code)?;

        let plaintext_data_key = keyring
            .unwrap(
                &encrypted_data_key,
                wrap_algorithm,
                &stored_context,
                request_context,
            )
            .await?;

        open_v3_content(&plaintext_data_key, md, ciphertext)
    }
}

/// Assemble the encrypted body and content metadata for an object from an
/// already-wrapped data key. This is the pure (no-I/O) encrypt half of the
/// PutObject pipeline, factored out so the V2/V3 branch selection and metadata
/// assembly can be exercised without KMS or S3.
fn build_encrypted_object(
    suite: crate::config::EncryptionAlgorithm,
    plaintext_data_key: &[u8],
    encrypted_data_key: &[u8],
    context: &BTreeMap<String, String>,
    plaintext: &[u8],
) -> Result<(Vec<u8>, ObjectMetadata)> {
    if suite.is_committing() {
        let (message_id, key_commitment, ciphertext) =
            crypto::encrypt_content_committing(suite, plaintext_data_key, plaintext)?;
        let md = ObjectMetadata::for_v3(
            suite,
            encrypted_data_key,
            &message_id,
            &key_commitment,
            context,
        )?;
        Ok((ciphertext, md))
    } else {
        let (iv, ciphertext) = crypto::encrypt_content_gcm(plaintext_data_key, plaintext)?;
        let md = ObjectMetadata::for_v2(encrypted_data_key, &iv, context)?;
        Ok((ciphertext, md))
    }
}

/// Decrypt V2 (non-committing AES-GCM) content given the unwrapped data key.
/// Pure (no-I/O) decrypt half of the GetObject pipeline.
fn open_v2_content(
    plaintext_data_key: &[u8],
    md: &ObjectMetadata,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let iv = md.content_iv_bytes()?;
    crypto::decrypt_content_gcm(plaintext_data_key, &iv, ciphertext)
}

/// Decrypt V3 (key-committing AES-GCM) content given the unwrapped data key,
/// verifying the stored key commitment. Pure (no-I/O) decrypt half of the
/// GetObject pipeline.
fn open_v3_content(
    plaintext_data_key: &[u8],
    md: &ObjectMetadata,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let suite = crate::config::EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
    let message_id = md.v3_message_id()?;
    let key_commitment = md.v3_key_commitment()?;
    crypto::decrypt_content_committing(
        suite,
        plaintext_data_key,
        &message_id,
        &key_commitment,
        ciphertext,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EncryptionAlgorithm;
    use crate::keyring::{KmsKeyring, RESERVED_CEK_ALG_KEY};
    use crate::metadata::{CONTENT_CIPHER_V3, TAG_LENGTH, WRAP_ALGORITHM_V3};

    // A fixed 32-byte data key standing in for the plaintext data key that KMS
    // GenerateDataKey would return — lets us exercise the full encrypt-assemble
    // → wire-map → parse → decrypt path without KMS or S3.
    const DATA_KEY: [u8; 32] = [7u8; 32];
    const EDK: &[u8] = b"wrapped-data-key-bytes";

    fn caller_ctx() -> BTreeMap<String, String> {
        [("user".to_string(), "alice".to_string())]
            .into_iter()
            .collect()
    }

    /// V2 (non-committing) object survives the round trip through the S3
    /// user-metadata string map, and carries the reserved content-algorithm
    /// key in its stored context exactly as the python reference writes it.
    #[test]
    fn v2_object_round_trips_through_wire_map() {
        let suite = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);
        let plaintext = b"hello non-committing world";

        let (body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, plaintext).unwrap();

        // Serialize to the S3 string map and parse it back, as S3 would.
        let map = md.to_map();
        let parsed = ObjectMetadata::from_map(&map);

        assert!(parsed.is_v2_format());
        assert!(!parsed.has_exclusive_key_collision());
        assert_eq!(map.get(crate::metadata::CONTENT_CIPHER).unwrap(), "AES/GCM/NoPadding");
        assert_eq!(map.get(TAG_LENGTH).unwrap(), "128");
        // The stored matdesc carries the reserved cek-alg key (cipher name).
        assert_eq!(
            parsed.v2_stored_context().unwrap().get(RESERVED_CEK_ALG_KEY).unwrap(),
            "AES/GCM/NoPadding"
        );

        let recovered = open_v2_content(&DATA_KEY, &parsed, &body).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// V3 (key-committing) object survives the round trip, persists the decimal
    /// suite ID and compressed wrap code, omits the V2-only tag-length key, and
    /// records the reserved content-algorithm key as "115".
    #[test]
    fn v3_object_round_trips_through_wire_map() {
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);
        let plaintext = b"hello key-committing world";

        let (body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, plaintext).unwrap();

        let map = md.to_map();
        let parsed = ObjectMetadata::from_map(&map);

        assert!(parsed.is_v3_format());
        assert!(!parsed.has_exclusive_key_collision());
        assert_eq!(map.get(CONTENT_CIPHER_V3).unwrap(), "115");
        assert_eq!(map.get(WRAP_ALGORITHM_V3).unwrap(), "12");
        // tag-len is V2-only and MUST NOT appear on a V3 object.
        assert!(!map.contains_key(TAG_LENGTH));
        assert_eq!(
            parsed.v3_stored_context().unwrap().get(RESERVED_CEK_ALG_KEY).unwrap(),
            "115"
        );

        let recovered = open_v3_content(&DATA_KEY, &parsed, &body).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// Empty plaintext is a valid object (tag-only body) and round-trips.
    #[test]
    fn v2_empty_plaintext_round_trips() {
        let suite = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;
        let context = KmsKeyring::build_encryption_context(&BTreeMap::new(), suite);

        let (body, md) = build_encrypted_object(suite, &DATA_KEY, EDK, &context, b"").unwrap();
        let parsed = ObjectMetadata::from_map(&md.to_map());

        let recovered = open_v2_content(&DATA_KEY, &parsed, &body).unwrap();
        assert!(recovered.is_empty());
    }

    /// A data key other than the one used to encrypt must not decrypt a V3
    /// object: key-commitment verification fails closed before any plaintext is
    /// released.
    #[test]
    fn v3_wrong_data_key_fails_commitment_verification() {
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);

        let (body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, b"secret").unwrap();
        let parsed = ObjectMetadata::from_map(&md.to_map());

        let wrong_key = [9u8; 32];
        let err = open_v3_content(&wrong_key, &parsed, &body).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    /// A data key other than the one used to encrypt must not decrypt a V2
    /// object: GCM tag authentication fails.
    #[test]
    fn v2_wrong_data_key_fails_authentication() {
        let suite = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);

        let (body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, b"secret").unwrap();
        let parsed = ObjectMetadata::from_map(&md.to_map());

        let wrong_key = [9u8; 32];
        let err = open_v2_content(&wrong_key, &parsed, &body).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    /// Tampering with the stored V3 ciphertext body must fail authentication.
    #[test]
    fn v3_tampered_body_fails() {
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);

        let (mut body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, b"secret payload").unwrap();
        let parsed = ObjectMetadata::from_map(&md.to_map());
        body[0] ^= 0xFF;

        let err = open_v3_content(&DATA_KEY, &parsed, &body).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }
}
