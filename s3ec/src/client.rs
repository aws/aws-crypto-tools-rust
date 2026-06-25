// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The top-level S3 Encryption Client (S3EC).

use std::collections::BTreeMap;

use aws_sdk_s3::primitives::ByteStream;

use crate::config::{CommitmentPolicy, S3EncryptionConfig};
use crate::crypto;
use crate::error::{Result, S3EncryptionError};
use crate::keyring::{
    AesKeyring, KmsKeyring, RsaKeyring, WRAP_ALG_AES_GCM, WRAP_ALG_KMS_CONTEXT,
    WRAP_ALG_RSA_OAEP_SHA1,
};
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

/// The content-data-key keyring a client is configured with: an AWS KMS
/// keyring, a raw AES keyring, or a raw RSA keyring. The harness configures
/// exactly one.
#[derive(Clone)]
pub enum Keyring {
    /// AWS KMS keyring (the `kms+context` / legacy `kms` wrapping algorithms).
    Kms(KmsKeyring),
    /// Raw AES keyring (the `AES/GCM` wrapping algorithm).
    Aes(AesKeyring),
    /// Raw RSA keyring (the `RSA-OAEP-SHA1` wrapping algorithm).
    Rsa(RsaKeyring),
}

/// Client-side encrypting wrapper around the AWS S3 client.
///
/// Holds the validated [`S3EncryptionConfig`] together with the wrapped S3 SDK
/// client and the keyring used to wrap and unwrap content data keys.
#[derive(Clone)]
pub struct S3EncryptionClient {
    config: S3EncryptionConfig,
    s3: aws_sdk_s3::Client,
    keyring: Option<Keyring>,
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
        let keyring = if let Some(key_id) = config.kms_key_id.as_ref() {
            Some(Keyring::Kms(KmsKeyring::new(
                kms,
                key_id.clone(),
                config.enable_legacy_wrapping_algorithms,
            )))
        } else if let Some(key) = config.aes_wrapping_key.as_ref() {
            Some(Keyring::Aes(AesKeyring::new(key.clone())))
        } else {
            config
                .rsa_wrapping_key
                .as_ref()
                .map(|key| Keyring::Rsa(RsaKeyring::new(key.clone())))
        };
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

    fn require_keyring(&self) -> Result<&Keyring> {
        self.keyring.as_ref().ok_or_else(|| {
            S3EncryptionError::Configuration(
                "a KMS key identifier or a raw AES wrapping key is required".to_string(),
            )
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

        // Wrap a fresh data key and assemble the encrypted object. The KMS
        // keyring binds the content algorithm into the KMS encryption context;
        // the raw AES keyring wraps locally and stores no encryption context.
        let (body, object_metadata) = match keyring {
            Keyring::Kms(kms) => {
                let context = KmsKeyring::build_encryption_context(encryption_context, suite);
                let (plaintext_data_key, encrypted_data_key) = kms.wrap(&context).await?;
                build_encrypted_object(
                    suite,
                    &plaintext_data_key,
                    &encrypted_data_key,
                    &context,
                    plaintext,
                )?
            }
            Keyring::Aes(aes) => {
                let (plaintext_data_key, encrypted_data_key) = aes.wrap(suite)?;
                build_encrypted_object_raw_aes(
                    suite,
                    &plaintext_data_key,
                    &encrypted_data_key,
                    plaintext,
                )?
            }
            Keyring::Rsa(rsa) => {
                let (plaintext_data_key, encrypted_data_key) = rsa.wrap(suite)?;
                build_encrypted_object_raw_rsa(
                    suite,
                    &plaintext_data_key,
                    &encrypted_data_key,
                    plaintext,
                )?
            }
        };

        let metadata: std::collections::HashMap<String, String> =
            object_metadata.to_map().into_iter().collect();

        //= spec/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //# Instruction File writes MUST be optionally configured during client creation or on each PutObject request.
        if self.config.instruction_file_put_enabled {
            return self
                .put_object_with_instruction_file(bucket, key, body, &object_metadata)
                .await;
        }

        //= spec/s3-encryption/data-format/metadata-strategy.md#object-metadata
        //# By default, the S3EC MUST store content metadata in the S3 Object Metadata.
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

    /// Store an encrypted object together with a sidecar instruction file.
    ///
    /// The content metadata is split: the instruction-file portion is
    /// serialized to a JSON string and stored in the `<key>.instruction`
    /// object, while the object-metadata portion (empty for V1/V2; the
    /// content-related mapkeys for V3) is attached to the encrypted object.
    async fn put_object_with_instruction_file(
        &self,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        object_metadata: &ObjectMetadata,
    ) -> Result<()> {
        let (object_map, instruction_map) = object_metadata.split_for_instruction_file();

        // The instruction file is written first so that, once the encrypted
        // object is visible, its instruction file already exists for readers.
        self.write_instruction_file(
            bucket,
            key,
            metadata::DEFAULT_INSTRUCTION_FILE_SUFFIX,
            &instruction_map,
        )
        .await?;

        let metadata: std::collections::HashMap<String, String> = object_map.into_iter().collect();
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

    /// Serialize a content-metadata map to a sidecar instruction-file S3 object
    /// at `<key><suffix>`.
    ///
    /// The instruction object carries the S3EC instruction-file user-metadata
    /// marker (which the cross-implementation harness asserts) and its body is
    /// the JSON-serialized metadata map.
    async fn write_instruction_file(
        &self,
        bucket: &str,
        key: &str,
        suffix: &str,
        instruction_map: &BTreeMap<String, String>,
    ) -> Result<()> {
        //= spec/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //# The content metadata stored in the Instruction File MUST be serialized to a JSON string.
        let instruction_json = serde_json::to_string(instruction_map).map_err(|e| {
            S3EncryptionError::Format(format!("failed to serialize instruction file: {e}"))
        })?;

        let instruction_key = format!("{key}{suffix}");
        let instruction_marker: std::collections::HashMap<String, String> = [(
            metadata::INSTRUCTION_FILE_MARKER.to_string(),
            suffix.to_string(),
        )]
        .into_iter()
        .collect();

        //= spec/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //# The serialized JSON string MUST be the only contents of the Instruction File.
        self.s3
            .put_object()
            .bucket(bucket)
            .key(&instruction_key)
            .body(ByteStream::from(instruction_json.into_bytes()))
            .set_metadata(Some(instruction_marker))
            .send()
            .await
            .map_err(|e| {
                S3EncryptionError::Sdk(format!("S3 PutObject (instruction file) failed: {e}"))
            })?;
        Ok(())
    }

    /// Fetch `bucket`/`key`, unwrap its data key via KMS, and decrypt its
    /// content. `encryption_context` is the caller-provided (request) context
    /// validated against the object's stored context.
    ///
    /// `range`, when present, is an HTTP `Range` header value (`bytes=start-end`
    /// or `bytes=start-`) requesting a subset of the object's plaintext. The
    /// returned plaintext is the corresponding `[start, end]` slice (inclusive,
    /// clamped to the object length).
    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
        encryption_context: &BTreeMap<String, String>,
        instruction_file_suffix: Option<&str>,
        range: Option<&str>,
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

        // Decryption metadata starts from the object metadata. When the object
        // metadata does not carry a complete decryptable envelope, the metadata
        // was written to a sidecar instruction file; fetch it and merge.
        let mut decrypt_map = raw_metadata.clone();
        let mut md = ObjectMetadata::from_map(&decrypt_map);

        let object_metadata_is_decryptable =
            md.is_v1_format() || md.is_v2_format() || md.is_v3_format();
        if !self.config.disable_instruction_file && !object_metadata_is_decryptable {
            //= spec/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //# The S3EC SHOULD support providing a custom Instruction File suffix on GetObject requests, regardless of whether or not re-encryption is supported.
            let suffix =
                instruction_file_suffix.unwrap_or(metadata::DEFAULT_INSTRUCTION_FILE_SUFFIX);
            let instruction_key = format!("{key}{suffix}");
            let instruction_metadata = self
                .fetch_instruction_file(bucket, &instruction_key)
                .await?;

            // The V3 object-metadata-exclusive mapkeys MUST NOT appear in the
            // instruction file. Their presence means the instruction file has
            // been tampered with (commitment/message-id relocated out of the
            // object metadata), so reject before merging or decrypting.
            validate_instruction_file_metadata(&instruction_metadata)?;

            for (k, v) in instruction_metadata {
                decrypt_map.insert(k, v);
            }
            md = ObjectMetadata::from_map(&decrypt_map);
        }

        //= spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //# If there are multiple mapkeys which are meant to be exclusive to different versions, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
        if md.has_exclusive_key_collision() {
            return Err(S3EncryptionError::Format(
                "object metadata contains encrypted-data-key mapkeys from multiple exclusive \
                 format versions"
                    .to_string(),
            ));
        }

        // A ranged GetObject requests a `[start, end]` subset of the object's
        // plaintext. An invalid/absent range header decrypts the whole object.
        let parsed_range = range.and_then(parse_byte_range);

        let plaintext = if md.is_v3_format() {
            self.decrypt_v3(keyring, &md, &ciphertext, encryption_context, parsed_range)
                .await?
        } else if md.is_v2_format() {
            self.decrypt_v2(keyring, &md, &ciphertext, encryption_context, parsed_range)
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

    /// Fetch and parse a sidecar instruction file as a content-metadata map.
    ///
    /// The instruction file's body is a JSON object string mapping S3EC
    /// content-metadata mapkeys to their stored values.
    async fn fetch_instruction_file(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<BTreeMap<String, String>> {
        let response = self
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                S3EncryptionError::Sdk(format!("S3 GetObject (instruction file) failed: {e}"))
            })?;

        let body = response
            .body
            .collect()
            .await
            .map_err(|e| {
                S3EncryptionError::Sdk(format!("failed to read instruction file body: {e}"))
            })?
            .to_vec();

        serde_json::from_slice(&body).map_err(|e| {
            S3EncryptionError::Format(format!("failed to parse instruction file JSON: {e}"))
        })
    }

    async fn decrypt_v2(
        &self,
        keyring: &Keyring,
        md: &ObjectMetadata,
        ciphertext: &[u8],
        request_context: &BTreeMap<String, String>,
        range: Option<(usize, usize)>,
    ) -> Result<Vec<u8>> {
        // The V2 metadata format is shared by the non-committing AES-GCM suite
        // and the legacy AES-CBC suite; determine which from the content cipher.
        let content_alg = md.v2_content_algorithm()?;

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

        //= spec/s3-encryption/decryption.md#legacy-decryption
        //# The S3EC MUST NOT decrypt objects encrypted using legacy unauthenticated algorithm suites unless specifically configured to do so.
        //
        //= spec/s3-encryption/decryption.md#cbc-decryption
        //# If an object is encrypted with ALG_AES_256_CBC_IV16_NO_KDF and [legacy unauthenticated algorithm suites](#legacy-decryption) is NOT enabled,
        //# the S3EC MUST throw an error which details that client was not configured to decrypt objects with ALG_AES_256_CBC_IV16_NO_KDF.
        if content_alg.is_legacy() && !self.config.enable_legacy_unauthenticated_modes {
            return Err(S3EncryptionError::Crypto(
                "client was not configured to decrypt objects with \
                 ALG_AES_256_CBC_IV16_NO_KDF; enable legacy unauthenticated modes to allow it"
                    .to_string(),
            ));
        }

        let encrypted_data_key = md.v2_encrypted_data_key()?;
        let stored_context = md.v2_stored_context()?;
        let wrap_algorithm = md
            .wrap_algorithm
            .clone()
            .unwrap_or_else(|| WRAP_ALG_KMS_CONTEXT.to_string());

        let plaintext_data_key = self
            .unwrap_data_key(
                keyring,
                &wrap_algorithm,
                content_alg,
                &encrypted_data_key,
                &stored_context,
                request_context,
            )
            .await?;

        match range {
            Some((start, end)) => open_v2_content_range(&plaintext_data_key, md, ciphertext, start, end),
            None => open_v2_content(&plaintext_data_key, md, ciphertext),
        }
    }

    async fn decrypt_v3(
        &self,
        keyring: &Keyring,
        md: &ObjectMetadata,
        ciphertext: &[u8],
        request_context: &BTreeMap<String, String>,
        range: Option<(usize, usize)>,
    ) -> Result<Vec<u8>> {
        // Resolve the content-encryption suite from the stored `x-amz-c` value
        // and reject any unknown/tampered value before doing any KMS work. The
        // suite ID is bound into the key-derivation inputs and the GCM AAD, so
        // ignoring `x-amz-c` would let a mutated value decrypt successfully.
        let suite = md.v3_content_algorithm()?;

        let encrypted_data_key = md.v3_encrypted_data_key()?;
        let stored_context = md.v3_stored_context()?;
        // The V3 wrapping algorithm is a compressed code: "12" (kms+context) or
        // "02" (AES/GCM).
        let wrap_code = md.wrap_algorithm_v3.as_deref().unwrap_or("12");
        let wrap_algorithm = metadata::v3_wrap_algorithm_to_name(wrap_code)?;

        let plaintext_data_key = self
            .unwrap_data_key(
                keyring,
                wrap_algorithm,
                suite,
                &encrypted_data_key,
                &stored_context,
                request_context,
            )
            .await?;

        match range {
            Some((start, end)) => {
                open_v3_content_range(suite, &plaintext_data_key, md, ciphertext, start, end)
            }
            None => open_v3_content(suite, &plaintext_data_key, md, ciphertext),
        }
    }

    /// Unwrap an encrypted data key with the configured keyring, dispatching on
    /// the wrapping algorithm recorded in the object metadata. A KMS keyring
    /// rejects an `AES/GCM`-wrapped key (and vice versa) so a client never
    /// silently decrypts an object wrapped for a different key provider.
    async fn unwrap_data_key(
        &self,
        keyring: &Keyring,
        wrap_algorithm: &str,
        suite: crate::config::EncryptionAlgorithm,
        encrypted_data_key: &[u8],
        stored_context: &BTreeMap<String, String>,
        request_context: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>> {
        match keyring {
            Keyring::Kms(kms) => {
                if wrap_algorithm == WRAP_ALG_AES_GCM {
                    return Err(S3EncryptionError::Crypto(format!(
                        "object was wrapped with {wrap_algorithm} but the client is configured \
                         with a KMS keyring"
                    )));
                }
                kms.unwrap(
                    encrypted_data_key,
                    wrap_algorithm,
                    stored_context,
                    request_context,
                )
                .await
            }
            Keyring::Aes(aes) => {
                if wrap_algorithm != WRAP_ALG_AES_GCM {
                    return Err(S3EncryptionError::Crypto(format!(
                        "object was wrapped with {wrap_algorithm} but the client is configured \
                         with a raw AES keyring"
                    )));
                }
                aes.unwrap(encrypted_data_key, suite)
            }
            Keyring::Rsa(rsa) => {
                if wrap_algorithm != WRAP_ALG_RSA_OAEP_SHA1 {
                    return Err(S3EncryptionError::Crypto(format!(
                        "object was wrapped with {wrap_algorithm} but the client is configured \
                         with a raw RSA keyring"
                    )));
                }
                rsa.unwrap(encrypted_data_key, suite)
            }
        }
    }

    /// Read the current content metadata of an encrypted object for
    /// re-encryption: the S3 object metadata merged with the source instruction
    /// file (at the default suffix). Mirrors the read half of
    /// [`Self::get_object`] but stops once the decryptable metadata is
    /// assembled — re-encryption never reads or rewrites the object content.
    async fn read_reencrypt_source_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<ObjectMetadata> {
        let response = self
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| S3EncryptionError::Sdk(format!("S3 GetObject failed: {e}")))?;

        let mut decrypt_map: BTreeMap<String, String> = response
            .metadata()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let mut md = ObjectMetadata::from_map(&decrypt_map);

        // The source object was written with an instruction file, so its data
        // key lives in the sidecar rather than the object metadata; fetch and
        // merge it (always at the default suffix, as the reference does).
        let object_metadata_is_decryptable =
            md.is_v1_format() || md.is_v2_format() || md.is_v3_format();
        if !self.config.disable_instruction_file && !object_metadata_is_decryptable {
            let instruction_key =
                format!("{key}{}", metadata::DEFAULT_INSTRUCTION_FILE_SUFFIX);
            let instruction_metadata = self
                .fetch_instruction_file(bucket, &instruction_key)
                .await?;
            validate_instruction_file_metadata(&instruction_metadata)?;
            for (k, v) in instruction_metadata {
                decrypt_map.insert(k, v);
            }
            md = ObjectMetadata::from_map(&decrypt_map);
        }

        if md.has_exclusive_key_collision() {
            return Err(S3EncryptionError::Format(
                "object metadata contains encrypted-data-key mapkeys from multiple exclusive \
                 format versions"
                    .to_string(),
            ));
        }
        Ok(md)
    }

    //= spec/s3-encryption/client.md#optional-api-operations
    //# - ReEncryptInstructionFile MAY be implemented by the S3EC.
    //
    //= spec/s3-encryption/data-format/metadata-strategy.md#instruction-file
    //# The S3EC MAY support re-encryption/key rotation via Instruction Files.
    /// Re-encrypt an object's instruction file under a new raw keyring, rotating
    /// the wrapping key without rewriting the (unchanged) object content.
    ///
    /// The object's existing data key is decrypted with the client's configured
    /// keyring and re-wrapped under `new_*_wrapping_key`; the resulting
    /// instruction file is written at `instruction_file_suffix` (a custom suffix
    /// is only valid for an RSA destination keyring). Exactly one of
    /// `new_aes_wrapping_key` / `new_rsa_wrapping_key` must be set.
    pub async fn re_encrypt(
        &self,
        bucket: &str,
        key: &str,
        new_aes_wrapping_key: Option<Vec<u8>>,
        new_rsa_wrapping_key: Option<Vec<u8>>,
        instruction_file_suffix: Option<&str>,
        enforce_rotation: bool,
    ) -> Result<()> {
        // Re-encryption rewrites the instruction file, so instruction-file
        // writes must be enabled (mirrors the reference, which rejects
        // otherwise).
        if !self.config.instruction_file_put_enabled {
            return Err(S3EncryptionError::Configuration(
                "instruction file put operations must be enabled to re-encrypt instruction files"
                    .to_string(),
            ));
        }
        let current_keyring = self.require_keyring()?;
        let new_keyring = Keyring::raw(new_aes_wrapping_key, new_rsa_wrapping_key)?;

        //= spec/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //# The S3EC MUST NOT support providing a custom Instruction File suffix on ordinary writes; custom suffixes MUST only be used during re-encryption.
        // The harness sends the suffix without its leading dot; the reference
        // prepends one. A custom (non-default) suffix is only valid for an RSA
        // destination keyring.
        let dest_suffix = match instruction_file_suffix {
            Some(s) if !s.is_empty() => format!(".{s}"),
            _ => metadata::DEFAULT_INSTRUCTION_FILE_SUFFIX.to_string(),
        };
        if dest_suffix != metadata::DEFAULT_INSTRUCTION_FILE_SUFFIX
            && !matches!(new_keyring, Keyring::Rsa(_))
        {
            return Err(S3EncryptionError::Configuration(
                "custom instruction file suffix is only applicable for RSA keyring".to_string(),
            ));
        }

        let md = self.read_reencrypt_source_metadata(bucket, key).await?;

        // Re-encryption operates on the V3 key-committing format (the format the
        // raw keyrings write); resolve and validate the suite from `x-amz-c`.
        if !md.is_v3_format() {
            return Err(S3EncryptionError::Format(
                "re-encrypt is only supported for V3 key-committing objects".to_string(),
            ));
        }
        let suite = md.v3_content_algorithm()?;

        // Decrypt the existing data key with the client's current keyring.
        //= spec/s3-encryption/client.md#optional-api-operations
        //# - ReEncryptInstructionFile MUST decrypt the instruction file's encrypted data key for the given object using the client's CMM.
        let encrypted_data_key = md.v3_encrypted_data_key()?;
        let stored_context = md.v3_stored_context()?;
        let wrap_code = md.wrap_algorithm_v3.as_deref().unwrap_or("12");
        let wrap_algorithm = metadata::v3_wrap_algorithm_to_name(wrap_code)?;
        let empty_context = BTreeMap::new();
        let plaintext_data_key = self
            .unwrap_data_key(
                current_keyring,
                wrap_algorithm,
                suite,
                &encrypted_data_key,
                &stored_context,
                &empty_context,
            )
            .await?;

        // Re-wrap the same data key under the new keyring (EncryptDataKey only).
        //= spec/s3-encryption/client.md#optional-api-operations
        //# - ReEncryptInstructionFile MUST re-encrypt the plaintext data key with a provided keyring.
        let (new_encrypted_data_key, new_wrap_algorithm) = match &new_keyring {
            Keyring::Aes(aes) => (
                aes.encrypt_data_key(&plaintext_data_key, suite)?,
                WRAP_ALG_AES_GCM,
            ),
            Keyring::Rsa(rsa) => (
                rsa.encrypt_data_key(&plaintext_data_key, suite)?,
                WRAP_ALG_RSA_OAEP_SHA1,
            ),
            Keyring::Kms(_) => {
                return Err(S3EncryptionError::Configuration(
                    "re-encrypt requires a raw AES or RSA keyring, not a KMS keyring".to_string(),
                ))
            }
        };

        // When rotation is enforced, the old keyring MUST NOT be able to decrypt
        // the newly-wrapped data key (a stronger check than comparing material
        // descriptions).
        if enforce_rotation
            && self
                .unwrap_data_key(
                    current_keyring,
                    new_wrap_algorithm,
                    suite,
                    &new_encrypted_data_key,
                    &empty_context,
                    &empty_context,
                )
                .await
                .is_ok()
        {
            return Err(S3EncryptionError::Crypto(
                "re-encryption failed due to enforced rotation: the old keyring can still \
                 decrypt the newly encrypted data key"
                    .to_string(),
            ));
        }

        // Preserve the original message id and key commitment: the object
        // content and its commitment are unchanged, only the data-key wrap
        // moves to the new keyring.
        let message_id = md.v3_message_id()?;
        let key_commitment = md.v3_key_commitment()?;
        let new_md = match &new_keyring {
            Keyring::Aes(_) => ObjectMetadata::for_v3_raw_aes(
                suite,
                &new_encrypted_data_key,
                &message_id,
                &key_commitment,
            )?,
            Keyring::Rsa(_) => ObjectMetadata::for_v3_raw_rsa(
                suite,
                &new_encrypted_data_key,
                &message_id,
                &key_commitment,
            )?,
            Keyring::Kms(_) => unreachable!("KMS destination rejected above"),
        };

        // Write only the instruction-file portion: the object metadata
        // (`x-amz-c`/`x-amz-d`/`x-amz-i`) already lives on the unchanged object.
        let (_object_map, instruction_map) = new_md.split_for_instruction_file();
        self.write_instruction_file(bucket, key, &dest_suffix, &instruction_map)
            .await?;
        Ok(())
    }
}

impl Keyring {
    /// Build a raw keyring (AES or RSA) from supplied wrapping-key material,
    /// for re-encrypting an instruction file under a new key. Exactly one of
    /// `aes_wrapping_key` / `rsa_wrapping_key` must be set.
    fn raw(
        aes_wrapping_key: Option<Vec<u8>>,
        rsa_wrapping_key: Option<Vec<u8>>,
    ) -> Result<Self> {
        match (aes_wrapping_key, rsa_wrapping_key) {
            (Some(aes), None) => Ok(Keyring::Aes(AesKeyring::new(aes))),
            (None, Some(rsa)) => Ok(Keyring::Rsa(RsaKeyring::new(rsa))),
            (Some(_), Some(_)) => Err(S3EncryptionError::Configuration(
                "re-encrypt accepts at most one of a raw AES or RSA wrapping key".to_string(),
            )),
            (None, None) => Err(S3EncryptionError::Configuration(
                "re-encrypt requires a raw AES or RSA wrapping key".to_string(),
            )),
        }
    }
}

/// Reject a fetched instruction file that carries any V3 object-metadata-exclusive
/// mapkey. These keys (`x-amz-c`, `x-amz-d`, `x-amz-i`) bind the content cipher,
/// key commitment, and message id; the V3 format mandates they live only in the
/// object metadata. Finding them in the instruction file means it has been
/// tampered with to relocate the commitment, which must fail closed.
fn validate_instruction_file_metadata(
    instruction_metadata: &BTreeMap<String, String>,
) -> Result<()> {
    //= spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //# - The V3 message format MUST NOT store the mapkey "x-amz-c" and its value in the Instruction File.
    //
    //= spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //# - The V3 message format MUST NOT store the mapkey "x-amz-d" and its value in the Instruction File.
    //
    //= spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //# - The V3 message format MUST NOT store the mapkey "x-amz-i" and its value in the Instruction File.
    let forbidden: Vec<&str> = [
        metadata::CONTENT_CIPHER_V3,
        metadata::KEY_COMMITMENT_V3,
        metadata::MESSAGE_ID_V3,
    ]
    .into_iter()
    .filter(|k| instruction_metadata.contains_key(*k))
    .collect();
    if !forbidden.is_empty() {
        return Err(S3EncryptionError::Format(format!(
            "instruction file is tampered: it contains object-metadata-exclusive \
             mapkeys {forbidden:?}"
        )));
    }
    Ok(())
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

/// Assemble the encrypted body and content metadata for a raw-AES-wrapped
/// object. Like [`build_encrypted_object`] but emits raw-AES metadata
/// (`AES/GCM` wrapping algorithm, no KMS encryption context) and takes no
/// encryption context, since raw keyrings do not persist one.
fn build_encrypted_object_raw_aes(
    suite: crate::config::EncryptionAlgorithm,
    plaintext_data_key: &[u8],
    encrypted_data_key: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, ObjectMetadata)> {
    if suite.is_committing() {
        let (message_id, key_commitment, ciphertext) =
            crypto::encrypt_content_committing(suite, plaintext_data_key, plaintext)?;
        let md = ObjectMetadata::for_v3_raw_aes(
            suite,
            encrypted_data_key,
            &message_id,
            &key_commitment,
        )?;
        Ok((ciphertext, md))
    } else {
        let (iv, ciphertext) = crypto::encrypt_content_gcm(plaintext_data_key, plaintext)?;
        let md = ObjectMetadata::for_v2_raw_aes(encrypted_data_key, &iv)?;
        Ok((ciphertext, md))
    }
}

/// Assemble the encrypted body and content metadata for a raw-RSA-wrapped
/// object. Like [`build_encrypted_object_raw_aes`] but emits raw-RSA metadata
/// (`RSA-OAEP-SHA1` wrapping algorithm, V3 code "22", no KMS encryption
/// context).
fn build_encrypted_object_raw_rsa(
    suite: crate::config::EncryptionAlgorithm,
    plaintext_data_key: &[u8],
    encrypted_data_key: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, ObjectMetadata)> {
    if suite.is_committing() {
        let (message_id, key_commitment, ciphertext) =
            crypto::encrypt_content_committing(suite, plaintext_data_key, plaintext)?;
        let md = ObjectMetadata::for_v3_raw_rsa(
            suite,
            encrypted_data_key,
            &message_id,
            &key_commitment,
        )?;
        Ok((ciphertext, md))
    } else {
        let (iv, ciphertext) = crypto::encrypt_content_gcm(plaintext_data_key, plaintext)?;
        let md = ObjectMetadata::for_v2_raw_rsa(encrypted_data_key, &iv)?;
        Ok((ciphertext, md))
    }
}

/// Decrypt V2 content given the unwrapped data key. The V2 metadata format is
/// shared by the non-committing AES-GCM suite and the legacy AES-CBC suite, so
/// the content cipher (`x-amz-cek-alg`) selects the primitive. Pure (no-I/O)
/// decrypt half of the GetObject pipeline.
fn open_v2_content(
    plaintext_data_key: &[u8],
    md: &ObjectMetadata,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let iv = md.content_iv_bytes()?;
    match md.v2_content_algorithm()? {
        crate::config::EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf => {
            crypto::decrypt_content_gcm(plaintext_data_key, &iv, ciphertext)
        }
        crate::config::EncryptionAlgorithm::AlgAes256CbcIv16NoKdf => {
            crypto::decrypt_content_cbc(plaintext_data_key, &iv, ciphertext)
        }
        other => Err(S3EncryptionError::Format(format!(
            "unexpected V2 content algorithm: {other:?}"
        ))),
    }
}

/// Decrypt V3 (key-committing AES-GCM) content given the unwrapped data key,
/// verifying the stored key commitment. Pure (no-I/O) decrypt half of the
/// GetObject pipeline.
fn open_v3_content(
    suite: crate::config::EncryptionAlgorithm,
    plaintext_data_key: &[u8],
    md: &ObjectMetadata,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
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

/// GCM authentication tag length (bytes) appended to authenticated content.
const GCM_TAG_LEN: usize = 16;

/// Strip the trailing GCM authentication tag from an authenticated ciphertext,
/// returning the content body (which, for the stream-cipher suites, has the
/// same length and byte offsets as the plaintext).
fn content_body_without_tag(ciphertext: &[u8]) -> Result<&[u8]> {
    let len = ciphertext
        .len()
        .checked_sub(GCM_TAG_LEN)
        .ok_or_else(|| S3EncryptionError::Format("ciphertext too short to contain a GCM tag".to_string()))?;
    Ok(&ciphertext[..len])
}

/// Parse an HTTP `Range` header value of the form `bytes=start-end` or
/// `bytes=start-` into an inclusive `(start, end)` plaintext byte range.
///
/// An open-ended range (`bytes=start-`) yields `end = usize::MAX`, which the
/// range decryptor clamps to the object length. Returns `None` for any value
/// that is not a single well-formed byte range, in which case the caller
/// decrypts the whole object (mirroring the reference client, which makes no
/// range adjustment for an unparseable range).
fn parse_byte_range(range: &str) -> Option<(usize, usize)> {
    let spec = range.strip_prefix("bytes=")?;
    let (start_str, end_str) = spec.split_once('-')?;
    let start: usize = start_str.parse().ok()?;
    let end: usize = if end_str.is_empty() {
        usize::MAX
    } else {
        end_str.parse().ok()?
    };
    if start > end {
        return None;
    }
    Some((start, end))
}

/// Decrypt an inclusive plaintext byte range of V2 content given the unwrapped
/// data key.
///
/// For the authenticated AES-GCM suite the whole-object tag cannot be verified
/// over a sub-range, so the corresponding CTR suite decrypts the range. The
/// legacy AES-CBC suite has no CTR counterpart in scope; its content is
/// decrypted in full and the requested slice returned.
fn open_v2_content_range(
    plaintext_data_key: &[u8],
    md: &ObjectMetadata,
    ciphertext: &[u8],
    start: usize,
    end_inclusive: usize,
) -> Result<Vec<u8>> {
    let iv = md.content_iv_bytes()?;
    match md.v2_content_algorithm()? {
        crate::config::EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf => {
            //= spec/s3-encryption/decryption.md#ranged-gets
            //# If the object was encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF, then ALG_AES_256_CTR_IV16_TAG16_NO_KDF MUST be used to decrypt the range of the object.
            let body = content_body_without_tag(ciphertext)?;
            crypto::decrypt_range_ctr(plaintext_data_key, &iv, body, start, end_inclusive)
        }
        crate::config::EncryptionAlgorithm::AlgAes256CbcIv16NoKdf => {
            let plaintext = crypto::decrypt_content_cbc(plaintext_data_key, &iv, ciphertext)?;
            Ok(slice_plaintext(&plaintext, start, end_inclusive))
        }
        other => Err(S3EncryptionError::Format(format!(
            "unexpected V2 content algorithm: {other:?}"
        ))),
    }
}

/// Decrypt an inclusive plaintext byte range of V3 (key-committing) content,
/// verifying the stored key commitment before releasing any plaintext.
fn open_v3_content_range(
    suite: crate::config::EncryptionAlgorithm,
    plaintext_data_key: &[u8],
    md: &ObjectMetadata,
    ciphertext: &[u8],
    start: usize,
    end_inclusive: usize,
) -> Result<Vec<u8>> {
    let message_id = md.v3_message_id()?;
    let key_commitment = md.v3_key_commitment()?;
    let body = content_body_without_tag(ciphertext)?;
    crypto::decrypt_range_committing(
        suite,
        plaintext_data_key,
        &message_id,
        &key_commitment,
        body,
        start,
        end_inclusive,
    )
}

/// Return the inclusive `[start, end]` slice of an already-decrypted plaintext,
/// clamped to the available bytes.
fn slice_plaintext(plaintext: &[u8], start: usize, end_inclusive: usize) -> Vec<u8> {
    if plaintext.is_empty() || start >= plaintext.len() {
        return Vec::new();
    }
    let end = end_inclusive.min(plaintext.len() - 1);
    plaintext[start..=end].to_vec()
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

        let recovered = open_v3_content(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey, &DATA_KEY, &parsed, &body).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// A raw-AES key-committing object survives the full local pipeline:
    /// generate+wrap the data key with the AES keyring, assemble the V3
    /// raw-AES metadata + body, round-trip through the S3 string map, then
    /// unwrap and decrypt — all without KMS or S3. Verifies the raw-AES wire
    /// format (AES/GCM wrap code "02", no KMS encryption context).
    #[test]
    fn raw_aes_v3_object_round_trips_through_wire_map() {
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let keyring = AesKeyring::new(vec![0x5Au8; 32]);
        let plaintext = b"hello raw aes committing world";

        let (plaintext_dk, wrapped_dk) = keyring.wrap(suite).unwrap();
        let (body, md) =
            build_encrypted_object_raw_aes(suite, &plaintext_dk, &wrapped_dk, plaintext).unwrap();

        let map = md.to_map();
        let parsed = ObjectMetadata::from_map(&map);

        assert!(parsed.is_v3_format());
        assert_eq!(map.get(CONTENT_CIPHER_V3).unwrap(), "115");
        // Raw AES records the AES/GCM wrap code, and stores no KMS context.
        assert_eq!(map.get(WRAP_ALGORITHM_V3).unwrap(), "02");
        assert!(!map.contains_key(crate::metadata::ENCRYPTION_CONTEXT_V3));

        let recovered_dk = keyring
            .unwrap(&parsed.v3_encrypted_data_key().unwrap(), suite)
            .unwrap();
        assert_eq!(recovered_dk, plaintext_dk);

        let recovered = open_v3_content(suite, &recovered_dk, &parsed, &body).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// A raw-RSA key-committing object survives the full local pipeline:
    /// generate+wrap the data key with the RSA keyring, assemble the V3 raw-RSA
    /// metadata + body, round-trip through the S3 string map, then unwrap and
    /// decrypt — all without KMS or S3. Verifies the raw-RSA wire format
    /// (RSA-OAEP-SHA1 wrap code "22", no KMS encryption context).
    #[test]
    fn raw_rsa_v3_object_round_trips_through_wire_map() {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};

        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let pkcs8 = PrivateDecryptingKey::generate(KeySize::Rsa2048)
            .unwrap()
            .as_der()
            .unwrap()
            .as_ref()
            .to_vec();
        let keyring = RsaKeyring::new(pkcs8);
        let plaintext = b"hello raw rsa committing world";

        let (plaintext_dk, wrapped_dk) = keyring.wrap(suite).unwrap();
        let (body, md) =
            build_encrypted_object_raw_rsa(suite, &plaintext_dk, &wrapped_dk, plaintext).unwrap();

        let map = md.to_map();
        let parsed = ObjectMetadata::from_map(&map);

        assert!(parsed.is_v3_format());
        assert_eq!(map.get(CONTENT_CIPHER_V3).unwrap(), "115");
        // Raw RSA records the RSA-OAEP-SHA1 wrap code, and stores no KMS context.
        assert_eq!(map.get(WRAP_ALGORITHM_V3).unwrap(), "22");
        assert!(!map.contains_key(crate::metadata::ENCRYPTION_CONTEXT_V3));

        let recovered_dk = keyring
            .unwrap(&parsed.v3_encrypted_data_key().unwrap(), suite)
            .unwrap();
        assert_eq!(recovered_dk, plaintext_dk);

        let recovered = open_v3_content(suite, &recovered_dk, &parsed, &body).unwrap();
        assert_eq!(recovered, plaintext);
    }
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
        let err = open_v3_content(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey, &wrong_key, &parsed, &body).unwrap_err();
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

        let err = open_v3_content(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey, &DATA_KEY, &parsed, &body).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    /// A legacy AES-CBC object reuses the V2 metadata format (`x-amz-key-v2`,
    /// 16-byte `x-amz-iv`, `x-amz-cek-alg = AES/CBC/PKCS5Padding`) and decrypts
    /// through the shared V2 content path. This is the legacy read path the old
    /// (CryptoMode.EncryptionOnly) S3 encryption client produces.
    #[test]
    fn v2_cbc_object_round_trips_through_wire_map() {
        use crate::metadata::{CONTENT_CIPHER, CONTENT_CIPHER_CBC, CONTENT_IV, ENCRYPTED_DATA_KEY_V2};
        use aws_lc_rs::cipher::{PaddedBlockEncryptingKey, UnboundCipherKey, AES_256};
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        let plaintext = b"legacy CBC content payload";

        // Produce a CBC fixture exactly as an old client would.
        let unbound = UnboundCipherKey::new(&AES_256, &DATA_KEY).unwrap();
        let enc = PaddedBlockEncryptingKey::cbc_pkcs7(unbound).unwrap();
        let mut body = plaintext.to_vec();
        let ctx = enc.encrypt(&mut body).unwrap();
        let iv = <&[u8]>::try_from(&ctx).unwrap().to_vec();
        assert_eq!(iv.len(), 16);

        let map = BTreeMap::from([
            (ENCRYPTED_DATA_KEY_V2.to_string(), BASE64.encode(EDK)),
            (CONTENT_IV.to_string(), BASE64.encode(&iv)),
            (CONTENT_CIPHER.to_string(), CONTENT_CIPHER_CBC.to_string()),
        ]);
        let parsed = ObjectMetadata::from_map(&map);

        // It is classified as V2 format and reports the CBC content algorithm.
        assert!(parsed.is_v2_format());
        assert_eq!(
            parsed.v2_content_algorithm().unwrap(),
            EncryptionAlgorithm::AlgAes256CbcIv16NoKdf
        );

        // The shared V2 content path routes to CBC and recovers the plaintext.
        let recovered = open_v2_content(&DATA_KEY, &parsed, &body).unwrap();
        assert_eq!(recovered, plaintext);
    }

    // Reconstruct the decryption-time metadata map exactly as `get_object`
    // does for an instruction-file object: start from the object metadata,
    // then merge the instruction-file portion over it.
    fn merge_instruction_file(
        object_map: &BTreeMap<String, String>,
        instruction_map: &BTreeMap<String, String>,
    ) -> BTreeMap<String, String> {
        let mut merged = object_map.clone();
        for (k, v) in instruction_map {
            merged.insert(k.clone(), v.clone());
        }
        merged
    }

    /// A V2 (non-committing) object written with an instruction file stores ALL
    /// of its content metadata in the instruction file (none in the object
    /// metadata), and round-trips once the instruction file is merged back.
    #[test]
    fn v2_instruction_file_split_round_trips() {
        let suite = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);
        let plaintext = b"instruction-file V2 payload";

        let (body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, plaintext).unwrap();
        let (object_map, instruction_map) = md.split_for_instruction_file();

        // V1/V2: nothing in object metadata, everything in the instruction file.
        assert!(object_map.is_empty());
        assert!(instruction_map.contains_key(crate::metadata::ENCRYPTED_DATA_KEY_V2));
        assert!(instruction_map.contains_key(crate::metadata::CONTENT_IV));

        // The object metadata alone is not a decryptable envelope.
        assert!(!ObjectMetadata::from_map(&object_map).is_v2_format());

        // After merging the instruction file, the object decrypts.
        let merged = merge_instruction_file(&object_map, &instruction_map);
        let parsed = ObjectMetadata::from_map(&merged);
        assert!(parsed.is_v2_format());
        assert_eq!(open_v2_content(&DATA_KEY, &parsed, &body).unwrap(), plaintext);
    }

    /// A V3 (key-committing) object written with an instruction file keeps the
    /// content-related mapkeys (`x-amz-c`, `x-amz-d`, `x-amz-i`) in the object
    /// metadata and writes the data-key-related mapkeys (`x-amz-3`, `x-amz-w`,
    /// `x-amz-t`) to the instruction file, and round-trips once merged.
    #[test]
    fn v3_instruction_file_split_round_trips() {
        use crate::metadata::{
            CONTENT_CIPHER_V3 as C, ENCRYPTED_DATA_KEY_V3, ENCRYPTION_CONTEXT_V3, KEY_COMMITMENT_V3,
            MESSAGE_ID_V3, WRAP_ALGORITHM_V3 as W,
        };
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);
        let plaintext = b"instruction-file V3 payload";

        let (body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, plaintext).unwrap();
        let (object_map, instruction_map) = md.split_for_instruction_file();

        // Content-related mapkeys stay in object metadata.
        assert!(object_map.contains_key(C));
        assert!(object_map.contains_key(KEY_COMMITMENT_V3));
        assert!(object_map.contains_key(MESSAGE_ID_V3));
        assert!(!object_map.contains_key(ENCRYPTED_DATA_KEY_V3));

        // Data-key-related mapkeys go to the instruction file.
        assert!(instruction_map.contains_key(ENCRYPTED_DATA_KEY_V3));
        assert!(instruction_map.contains_key(W));
        assert!(instruction_map.contains_key(ENCRYPTION_CONTEXT_V3));
        // The "x-amz-c"/"x-amz-d"/"x-amz-i" keys MUST NOT be in the instruction file.
        assert!(!instruction_map.contains_key(C));
        assert!(!instruction_map.contains_key(KEY_COMMITMENT_V3));
        assert!(!instruction_map.contains_key(MESSAGE_ID_V3));

        // The object metadata alone (missing x-amz-3) is not decryptable.
        assert!(!ObjectMetadata::from_map(&object_map).is_v3_format());

        // After merging the instruction file, the object decrypts.
        let merged = merge_instruction_file(&object_map, &instruction_map);
        let parsed = ObjectMetadata::from_map(&merged);
        assert!(parsed.is_v3_format());
        assert_eq!(
            open_v3_content(
                EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey,
                &DATA_KEY,
                &parsed,
                &body
            )
            .unwrap(),
            plaintext
        );
    }

    /// A well-formed V3 instruction file (data-key mapkeys only) passes the
    /// tamper validation.
    #[test]
    fn instruction_file_without_object_exclusive_keys_is_accepted() {
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);
        let (_body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, b"payload").unwrap();
        let (_object_map, instruction_map) = md.split_for_instruction_file();

        assert!(validate_instruction_file_metadata(&instruction_map).is_ok());
    }

    /// An instruction file that carries a V3 object-metadata-exclusive mapkey
    /// (here `x-amz-d`, the key commitment) is rejected as tampered. This is the
    /// `bad-both-meta-and-instruction` / `bad-only-instruction` decrypt case:
    /// the commitment MUST NOT be sourced from the instruction file.
    #[test]
    fn instruction_file_with_relocated_commitment_is_rejected() {
        use crate::metadata::{KEY_COMMITMENT_V3, MESSAGE_ID_V3};
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);
        let (_body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, b"payload").unwrap();
        let (object_map, mut instruction_map) = md.split_for_instruction_file();

        // Relocate the commitment and message id into the instruction file, as
        // the cross-language tamper fixture does.
        instruction_map.insert(
            KEY_COMMITMENT_V3.to_string(),
            object_map.get(KEY_COMMITMENT_V3).unwrap().clone(),
        );
        instruction_map.insert(
            MESSAGE_ID_V3.to_string(),
            object_map.get(MESSAGE_ID_V3).unwrap().clone(),
        );

        let err = validate_instruction_file_metadata(&instruction_map).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Format(_)));
    }

    /// An HTTP `Range` header parses into an inclusive `(start, end)` plaintext
    /// byte range; an open-ended range yields `usize::MAX` for clamping, and a
    /// malformed range parses to `None` (whole-object decrypt).
    #[test]
    fn byte_range_parsing() {
        assert_eq!(parse_byte_range("bytes=0-5"), Some((0, 5)));
        assert_eq!(parse_byte_range("bytes=10-1000"), Some((10, 1000)));
        assert_eq!(parse_byte_range("bytes=7-"), Some((7, usize::MAX)));
        // Malformed / unsupported forms decrypt the whole object.
        assert_eq!(parse_byte_range("bytes=5-3"), None);
        assert_eq!(parse_byte_range("bytes=abc"), None);
        assert_eq!(parse_byte_range("0-5"), None);
        assert_eq!(parse_byte_range("bytes=0-5,7-9"), None);
    }

    /// A ranged read of a V2 (non-committing AES-GCM) object returns exactly the
    /// requested inclusive plaintext slice, decrypting only the range via the
    /// CTR suite after the trailing GCM tag is stripped. End-beyond-length is
    /// clamped to the object length (the "include tag" harness case).
    #[test]
    fn v2_ranged_read_returns_requested_slice() {
        let suite = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);
        let plaintext: Vec<u8> = (0u8..=200).collect();

        let (body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, &plaintext).unwrap();
        let parsed = ObjectMetadata::from_map(&md.to_map());

        for (start, end) in [(0usize, 5usize), (5, 10), (17, 33), (10, 100_000)] {
            let got = open_v2_content_range(&DATA_KEY, &parsed, &body, start, end).unwrap();
            let clamped_end = end.min(plaintext.len() - 1);
            assert_eq!(got, plaintext[start..=clamped_end], "range [{start}, {end}]");
        }
    }

    /// A ranged read of a V3 (key-committing) object returns the requested
    /// plaintext slice and still verifies the stored key commitment: a mutated
    /// commitment fails closed before any plaintext is released.
    #[test]
    fn v3_ranged_read_slice_and_commitment_check() {
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let context = KmsKeyring::build_encryption_context(&caller_ctx(), suite);
        let plaintext: Vec<u8> = (0u8..=200).collect();

        let (body, md) =
            build_encrypted_object(suite, &DATA_KEY, EDK, &context, &plaintext).unwrap();
        let parsed = ObjectMetadata::from_map(&md.to_map());

        let got = open_v3_content_range(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey, &DATA_KEY, &parsed, &body, 5, 10).unwrap();
        assert_eq!(got, plaintext[5..=10]);

        // Mutate the stored commitment (x-amz-d); the ranged read must reject it.
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;
        let mut map = md.to_map();
        let d = map.get(crate::metadata::KEY_COMMITMENT_V3).unwrap().clone();
        let mut bytes = BASE64.decode(&d).unwrap();
        bytes[0] ^= 0xFF;
        map.insert(
            crate::metadata::KEY_COMMITMENT_V3.to_string(),
            BASE64.encode(&bytes),
        );
        let tampered = ObjectMetadata::from_map(&map);
        let err = open_v3_content_range(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey, &DATA_KEY, &tampered, &body, 5, 10).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    /// End-to-end re-encryption of an instruction file from a raw-AES keyring to
    /// a raw-RSA keyring (the AES => RSA custom-suffix case), exercised through
    /// the pure crypto + metadata pieces `re_encrypt` composes (no S3/KMS):
    ///
    /// 1. Encrypt content with a raw-AES committing keyring and split the
    ///    metadata into object metadata (`x-amz-c`/`x-amz-d`/`x-amz-i`) and the
    ///    AES instruction file.
    /// 2. Re-encrypt: unwrap the data key with the AES keyring, re-wrap it under
    ///    the RSA keyring, and rebuild the instruction file preserving the
    ///    message id and key commitment.
    /// 3. Decrypt the object using the unchanged object metadata merged with the
    ///    NEW (RSA) instruction file, and confirm the original plaintext is
    ///    recovered — the commitment still validates because the data key is
    ///    preserved across the re-wrap.
    #[test]
    fn reencrypt_instruction_file_aes_to_rsa_round_trips() {
        use crate::keyring::{AesKeyring, RsaKeyring};
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let plaintext = b"rotate my wrapping key without rewriting the object";

        // 1. Original raw-AES committing object.
        let aes = AesKeyring::new(vec![0x11u8; 32]);
        let (data_key, edk_aes) = aes.wrap(suite).unwrap();
        let (message_id, key_commitment, body) =
            crypto::encrypt_content_committing(suite, &data_key, plaintext).unwrap();
        let md_aes =
            ObjectMetadata::for_v3_raw_aes(suite, &edk_aes, &message_id, &key_commitment).unwrap();
        let (object_map, _aes_instruction) = md_aes.split_for_instruction_file();

        // 2. Re-encrypt: unwrap with AES, re-wrap the SAME data key under RSA.
        let recovered_dk = aes.unwrap(&edk_aes, suite).unwrap();
        assert_eq!(recovered_dk, data_key);
        let rsa_pkcs8 = {
            use aws_lc_rs::encoding::AsDer;
            use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
            PrivateDecryptingKey::generate(KeySize::Rsa2048)
                .unwrap()
                .as_der()
                .unwrap()
                .as_ref()
                .to_vec()
        };
        let rsa = RsaKeyring::new(rsa_pkcs8);
        let edk_rsa = rsa.encrypt_data_key(&recovered_dk, suite).unwrap();
        let md_rsa =
            ObjectMetadata::for_v3_raw_rsa(suite, &edk_rsa, &message_id, &key_commitment).unwrap();
        let (_rsa_object_map, rsa_instruction) = md_rsa.split_for_instruction_file();

        // The rebuilt instruction file carries no object-metadata-exclusive keys.
        assert!(validate_instruction_file_metadata(&rsa_instruction).is_ok());

        // 3. Decrypt: unchanged object metadata + the NEW RSA instruction file.
        let mut merged = object_map;
        for (k, v) in rsa_instruction {
            merged.insert(k, v);
        }
        let md = ObjectMetadata::from_map(&merged);
        assert!(md.is_v3_format());

        let dk_for_decrypt = rsa.unwrap(&md.v3_encrypted_data_key().unwrap(), suite).unwrap();
        assert_eq!(dk_for_decrypt, data_key);
        let decrypted = open_v3_content(suite, &dk_for_decrypt, &md, &body).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// A raw keyring is built from exactly one supplied wrapping key; supplying
    /// both, or neither, is a configuration error.
    #[test]
    fn raw_keyring_requires_exactly_one_key() {
        assert!(matches!(
            Keyring::raw(Some(vec![0u8; 32]), None),
            Ok(Keyring::Aes(_))
        ));
        assert!(matches!(
            Keyring::raw(None, Some(vec![0u8; 8])),
            Ok(Keyring::Rsa(_))
        ));
        assert!(Keyring::raw(Some(vec![0u8; 32]), Some(vec![0u8; 8])).is_err());
        assert!(Keyring::raw(None, None).is_err());
    }
}
