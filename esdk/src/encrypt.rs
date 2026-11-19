// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypt operation — obtains encryption materials from a keyring/CMM,
//! derives a data key, encrypts the plaintext (framed or nonframed),
//! and serializes the result into an encrypted message.

use std::num::NonZeroU32;

use crate::encrypt_gate;
use crate::error::Error;
use crate::error::{Kind, err, val_err};
use crate::key_derivation;
use crate::materials;
use crate::message::encryption_context::write_empty_ec_or_write_aad;
use crate::message::header_types::{
    ContentType, HeaderAuth, HeaderBody, MessageId, MessageType, V1HeaderBody, V2HeaderBody,
};
use crate::message::serializable_types::{get_encrypt_key_length, get_iv_length};
use crate::message::{DigestWriter, body, footer, header, serialize_functions};
use crate::secret::{self, MessageKey, PublicBytes};
use crate::shapes::{
    AlgorithmSuiteId, Ciphertext, CommitmentPolicy, EncryptInput, EncryptOutput,
    EncryptStreamInput, EncryptStreamOutput, EncryptionContext, MaterialSource, Sink, Source,
};
use crate::suites::{algorithm_suite_id_from_bytes, get_ecdsa_alg, get_esdk_algorithm_suite_id};
use aws_crypto_mpl::types::AlgorithmSuite;
use aws_crypto_mpl::types::EncryptedDataKey;
use aws_crypto_mpl::types::EncryptionMaterials;
use aws_crypto_mpl::types::RequiredEncryptionContextKeys;
use aws_crypto_mpl::types::SigningKey;
use aws_mpl_primitives::ecdsa_sign_digest;
use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// VR-018: encrypt-side header length checks. `build_v2_header_body` and
// `build_header_auth_tag` are the unverified adapters: they read the expected
// lengths from the suite and map the rejections to errors.
// ---------------------------------------------------------------------------
/// Why `check_v2_suite_data` rejected the suite data, in check order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SuiteDataLenError {
    /// No suite data (the commitment key) was given for a committing suite.
    Missing,
    /// The suite data is not the suite's `algorithm_suite_data_length()`.
    LengthMismatch,
}

/// The V2 suite data check: the suite data must be present and exactly
/// `expected_len` bytes. On success, returns the same suite data.
fn check_v2_suite_data(suite_data: Option<PublicBytes>, expected_len: usize) -> (r: Result<
    PublicBytes,
    SuiteDataLenError,
>)
    ensures
        (r matches Err(SuiteDataLenError::Missing)) <==> suite_data is None,
        (r matches Err(SuiteDataLenError::LengthMismatch)) <==> (suite_data matches Some(sd) && sd@.len()
            != expected_len),
        r matches Ok(sd) ==> (suite_data == Some(sd) && sd@.len() == expected_len),
{
    let Some(sd) = suite_data else {
        return Err(SuiteDataLenError::Missing);
    };
    if sd.len() != expected_len {
        return Err(SuiteDataLenError::LengthMismatch);
    }
    Ok(sd)
}

/// Whether the derived data key is the suite's encryption key length
/// `expected_len`.
fn data_key_len_ok(data_key: &MessageKey, expected_len: usize) -> (ok: bool)
    ensures
        ok <==> data_key@.len() == expected_len,
{
    data_key.len() == expected_len
}

} // verus!

/// AES-GCM IV length in bytes (used for body frames; header IV length varies by suite).
const IV_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes.
const AUTH_TAG_LEN: usize = 16;

/// Best-effort capacity hint for the ciphertext buffer, to minimize
/// reallocations. Total encrypted content equals `plaintext_len`, plus fixed
/// per-frame and header overhead.
fn estimated_ciphertext_capacity(plaintext_len: usize, frame_length: NonZeroU32) -> usize {
    let frame_length_usize = usize::try_from(frame_length.get()).unwrap_or(usize::MAX);
    let frames = plaintext_len.div_ceil(frame_length_usize).max(1);
    // Sequence number field + IV + authentication tag per frame.
    let per_frame_overhead = 4 + IV_LEN + AUTH_TAG_LEN;
    // Sequence number end + encrypted content length fields on the final frame.
    let final_frame_extra = 8;
    let header_overhead = 1024_usize;
    plaintext_len
        .saturating_add(frames.saturating_mul(per_frame_overhead))
        .saturating_add(final_frame_extra)
        .saturating_add(header_overhead)
}

/// Intermediate state produced by [`step_get_encryption_materials`] and consumed by subsequent steps.
struct EncryptionMaterialsResult {
    materials: EncryptionMaterials,
    derived_data_keys: key_derivation::DerivedKeys,
    message_id: MessageId,
}

/// Encrypt `input.plaintext`. Called by [`Client::encrypt`](crate::Client::encrypt).
pub(crate) async fn encrypt(input: &EncryptInput<'_>) -> Result<EncryptOutput, Error> {
    let mut cursor = std::io::Cursor::new(input.plaintext);

    let total_size = estimated_ciphertext_capacity(input.plaintext.len(), input.frame_length);
    let mut ciphertext: Vec<u8> = Vec::with_capacity(total_size);
    let Ok(plaintext_len) = u64::try_from(input.plaintext.len()) else {
        return Err(val_err("plaintext too large"));
    };
    let out = internal_encrypt(
        &mut cursor,
        &mut ciphertext,
        Some(plaintext_len),
        input.material_source(),
        &input.encryption_context,
        input.algorithm_suite_id,
        input.frame_length,
        input.max_encrypted_data_keys,
        input.commitment_policy,
    )
    .await?;

    Ok(EncryptOutput {
        //= spec/client-apis/encrypt.md#output
        //# - Encrypt operation output MUST include an [encrypted message](#encrypted-message) value.
        //
        //= spec/client-apis/encrypt.md#encrypted-message
        //# This MUST be a sequence of bytes
        //# and conform to the [message format specification](../data-format/message.md).
        ciphertext: Ciphertext::new(ciphertext),
        //= spec/client-apis/encrypt.md#output
        //# - Encrypt operation output MUST include an [encryption context](#encryption-context) value.
        encryption_context: out.encryption_context,
        //= spec/client-apis/encrypt.md#output
        //# - Encrypt operation output MUST include an [algorithm suite](#algorithm-suite) value.
        //
        //= spec/client-apis/encrypt.md#algorithm-suite-1
        //# This algorithm suite MUST be [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum).
        algorithm_suite_id: out.algorithm_suite_id,
    })
}

/// Encrypt a plaintext stream into a ciphertext stream. Called by [`Client::encrypt_stream`](crate::Client::encrypt_stream).
//= spec/client-apis/streaming.md#overview
//# The AWS Encryption SDK MAY provide APIs that enable streamed [encryption](encrypt.md)
//# and [decryption](decrypt.md).
//
//= spec/client-apis/streaming.md#overview
//# APIs that support streaming of the encrypt or decrypt operation SHOULD allow customers
//# to be able to process arbitrarily large inputs with a finite amount of working memory.
//
//= spec/client-apis/encrypt.md#plaintext
//# This input MAY be [streamed](streaming.md) to this operation.
//
//= spec/client-apis/encrypt.md#encrypted-message
//= reason=each frame is written to the output without buffering the full ciphertext
//# This operation MAY [stream](streaming.md) the encrypted message.
//
//= spec/client-apis/encrypt.md#plaintext
//= type=exception
//= reason=We stream without holding the full plaintext in memory, so this SHOULD-NOT antecedent does not apply
//# If an implementation requires holding the input entire plaintext in memory in order to perform this operation,
//# that implementation SHOULD NOT provide an API that allows this input to be streamed.
pub(crate) async fn encrypt_stream<R, W>(
    mut plaintext: R,
    mut ciphertext: W,
    input: &EncryptStreamInput,
) -> Result<EncryptStreamOutput, Error>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let output = internal_encrypt(
        &mut plaintext,
        &mut ciphertext,
        input.plaintext_length_bound,
        input.material_source(),
        &input.encryption_context,
        input.algorithm_suite_id,
        input.frame_length,
        input.max_encrypted_data_keys,
        input.commitment_policy,
    )
    .await?;
    serialize_functions::flush_sink(&mut ciphertext).await?;
    Ok(output)
}

#[expect(clippy::too_many_arguments)]
async fn internal_encrypt(
    plaintext: &mut dyn Source,
    // ciphertext is the output buffer for this function
    ciphertext: &mut dyn Sink,
    plaintext_len: Option<u64>,
    input_source: Option<MaterialSource>,
    encryption_context: &EncryptionContext,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    frame_length: NonZeroU32,
    max_encrypted_data_keys: Option<std::num::NonZeroUsize>,
    commitment_policy: CommitmentPolicy,
) -> Result<EncryptStreamOutput, Error> {
    let source = input_source.as_ref().map(MaterialSource::resource);
    encrypt_steps(
        plaintext,
        ciphertext,
        plaintext_len,
        input_source,
        encryption_context,
        algorithm_suite_id,
        frame_length,
        max_encrypted_data_keys,
        commitment_policy,
    )
    .await
    .map_err(|e| materials::name_material_source(e, source.as_ref()))
}

/// The encrypt steps; [`internal_encrypt`] names the material source in their errors.
#[expect(clippy::too_many_arguments)]
async fn encrypt_steps(
    plaintext: &mut dyn Source,
    ciphertext: &mut dyn Sink,
    plaintext_len: Option<u64>,
    input_source: Option<MaterialSource>,
    encryption_context: &EncryptionContext,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    frame_length: NonZeroU32,
    max_encrypted_data_keys: Option<std::num::NonZeroUsize>,
    commitment_policy: CommitmentPolicy,
) -> Result<EncryptStreamOutput, Error> {
    //= spec/client-apis/encrypt.md#behavior
    //= reason=Every step uses ?; any failure returns Err to the caller
    //# If any of these steps fails, this operation MUST halt and indicate a failure to the caller.
    //
    //= spec/client-apis/encrypt.md#encryption-context
    //# If the input encryption context contains any entries with a key beginning with `aws-crypto-`,
    //# the encryption operation MUST fail.
    validate_encryption_context(encryption_context)?;

    //= spec/client-apis/encrypt.md#behavior
    //= type=implication
    //# - Encrypt operation Step 1 MUST be [Get the encryption materials](#get-the-encryption-materials)
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# To construct the [encrypted message](#encrypted-message),
    //# some fields MUST be constructed using information obtained
    //# from a set of valid [encryption materials](../framework/structures.md#encryption-materials).
    let mat_result = step_get_encryption_materials(
        plaintext_len,
        input_source,
        encryption_context,
        algorithm_suite_id,
        max_encrypted_data_keys,
        commitment_policy,
    )
    .await?;

    let mut sig_digest = DigestWriter::from_suite(&mat_result.materials.algorithm_suite())?;

    //= spec/client-apis/encrypt.md#behavior
    //= type=implication
    //# - Encrypt operation step 2 MUST be [Construct the header](#construct-the-header)
    //
    //= spec/client-apis/encrypt.md#construct-the-header
    //= type=implication
    //= reason=Header serialization precedes body encryption in the function body
    //# Before encrypting input plaintext,
    //# this operation MUST serialize the [message header body](../data-format/message-header.md).
    //
    //= spec/data-format/message.md#structure
    //# - The message MUST begin with [Message Header](message-header.md)
    let header = step_construct_header(
        &mat_result,
        mat_result.materials.encryption_context(),
        mat_result.materials.required_encryption_context_keys(),
        mat_result.materials.encrypted_data_keys(),
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# The frame length used in the procedures described below MUST be the input [frame length](#frame-length),
        //# if supplied.
        //
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# If no input frame length is supplied, the default frame length MUST be used.
        frame_length,
        ciphertext,
        &mut sig_digest,
    )
    .await?;

    //= spec/client-apis/encrypt.md#behavior
    //= type=implication
    //= reason=encrypt_and_serialize_body is called third in the function body
    //# - Encrypt operation step 3 MUST be [Construct the body](#construct-the-body)
    //
    //= spec/data-format/message.md#structure
    //# - The [Message Body](message-body.md) MUST follow the Message Header
    step_construct_body(
        plaintext,
        &header,
        &mat_result.derived_data_keys.data_key,
        ciphertext,
        &mut sig_digest,
        plaintext_len,
    )
    .await?;

    //= spec/client-apis/encrypt.md#behavior
    //= type=implication
    //# - Encrypt operation step 4 MUST be [Construct the signature](#construct-the-signature)
    if mat_result
        .materials
        .algorithm_suite()
        .asymmetric_signature_algorithm()
        .is_some()
    {
        //= spec/client-apis/encrypt.md#behavior
        //# - If the [encryption materials gathered](#get-the-encryption-materials) has a algorithm suite
        //# including a [signature algorithm](../framework/algorithm-suites.md#signature-algorithm),
        //# the Encrypt operation MUST perform this step.
        step_construct_signature(
            &header,
            &mat_result.materials,
            //= spec/client-apis/encrypt.md#construct-the-signature
            //= type=implication
            //= reason=sig_digest was fed header in step 2 and body in step 3
            //# Note that the message header and message body MAY have already been input during previous steps.
            sig_digest,
            ciphertext,
        )
        .await?;
    } else {
        //= spec/client-apis/encrypt.md#behavior
        //# - If the materials do not have an algorithm suite including a signature algorithm,
        //# the Encrypt operation MUST NOT construct a signature.
    }

    let suite_id = algorithm_suite_id_from_bytes(header.suite.id())?;

    //= spec/client-apis/encrypt.md#behavior
    //= reason=Ok follows the last write; no bytes appended after footer
    //# Any data that is not specified within the [message format](../data-format/message.md)
    //# MUST NOT be added to the output message.
    //
    //= spec/client-apis/streaming.md#outputs
    //= reason=all bytes are written to the output before Ok is returned
    //# Operations MUST NOT indicate completion or success until an end to the output has been indicated.
    Ok(EncryptStreamOutput {
        encryption_context: header.encryption_context,
        algorithm_suite_id: suite_id,
    })
}

/// Step 1: [Get the encryption materials](spec/client-apis/encrypt.md#get-the-encryption-materials)
///
/// Validates the input algorithm suite against the commitment policy, obtains encryption
/// materials from the CMM, validates EDK count, generates a message ID, and derives keys.
async fn step_get_encryption_materials(
    plaintext_len: Option<u64>,
    input_source: Option<MaterialSource>,
    encryption_context: &EncryptionContext,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    max_encrypted_data_keys: Option<std::num::NonZeroUsize>,
    commitment_policy: CommitmentPolicy,
) -> Result<EncryptionMaterialsResult, Error> {
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# The CMM used MUST be the input CMM, if supplied.
    let cmm = materials::create_cmm_from_input(input_source)?;

    //= spec/client-apis/encrypt.md#algorithm-suite
    //# The [algorithm suite](../framework/algorithm-suites.md) that MUST be used for encryption.
    //
    //= spec/client-apis/encrypt.md#algorithm-suite
    //= type=implication
    //= reason=AlgorithmSuiteId enum only contains ESDK-supported suites
    //# This algorithm suite MUST be [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum).
    if let Some(id) = algorithm_suite_id {
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# If an [input algorithm suite](#algorithm-suite) is provided
        //# that is not supported by the [commitment policy](client.md#commitment-policy)
        //# configured in the [client](client.md) encrypt MUST yield an error.
        let policy = aws_crypto_mpl::types::CommitmentPolicy::Esdk(commitment_policy);
        if !policy.allows_for_encrypt(aws_crypto_mpl::types::AlgorithmSuiteId::Esdk(id)) {
            return Err(val_err(
                "input algorithm suite is not supported by the configured commitment policy for encryption",
            ));
        }
    }

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# This operation MUST obtain this set of [encryption materials](../framework/structures.md#encryption-materials)
    //# by calling [Get Encryption Materials](../framework/cmm-interface.md#get-encryption-materials) on a [CMM](../framework/cmm-interface.md).
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# The call to [Get Encryption Materials](../framework/cmm-interface.md#get-encryption-materials)
    //# on that CMM MUST be constructed as follows:
    let materials = materials::get_encryption_materials(
        cmm,
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# - Algorithm Suite: If provided, this MUST be the [input algorithm suite](#algorithm-suite).
        algorithm_suite_id,
        encryption_context.clone(),
        plaintext_len,
        commitment_policy,
    )
    .await?;

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# If the number of [encrypted data keys](../framework/structures.md#encrypted-data-keys) on the [encryption materials](../framework/structures.md#encryption-materials)
    //# is greater than the [maximum number of encrypted data keys](client.md#maximum-number-of-encrypted-data-keys) configured in the [client](client.md) encrypt MUST yield an error.
    header::validate_max_encrypted_data_keys(
        max_encrypted_data_keys,
        materials.encrypted_data_keys(),
    )?;

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //# The [algorithm suite](../framework/algorithm-suites.md) used in all aspects of this operation
    //# MUST be the algorithm suite in the [encryption materials](../framework/structures.md#encryption-materials)
    //# returned from the [Get Encryption Materials](../framework/cmm-interface.md#get-encryption-materials) call.
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= reason=Code uses materials.algorithm_suite regardless of input
    //# Note that the algorithm suite in the retrieved encryption materials MAY be different
    //# from the [input algorithm suite](#algorithm-suite).
    //
    let algorithm_suite =
        get_esdk_algorithm_suite_id(materials.algorithm_suite_id())?.specification();

    let message_id = header::generate_message_id(&algorithm_suite)?;

    let derived_data_keys = key_derivation::derive_keys(
        &message_id,
        //= spec/client-apis/encrypt.md#get-the-encryption-materials
        //# The data key used as input for all encryption described below MUST be a data key derived from the plaintext data key
        //# included in the [encryption materials](../framework/structures.md#encryption-materials).
        //
        //= spec/framework/transitive-requirements.md#hkdf-encryption-key
        //= type=implication
        //= reason=materials.plaintext_data_key is set by the keyring/CMM in the preceding generate-data-key step; the IKM passed to derive_keys is that provider-supplied value by data dependency
        //# - The input keying material MUST be the data key generated by the key provider.
        //
        //= spec/framework/transitive-requirements.md#hkdf-commit-key
        //= type=implication
        //= reason=materials.plaintext_data_key is set by the keyring/CMM in the preceding generate-data-key step; the IKM passed to derive_keys is that provider-supplied value by data dependency
        //# - The input keying material MUST be the data key generated by the key provider.
        &secret::data_key_from_encryption_materials(&materials)?,
        &algorithm_suite,
    )?;

    Ok(EncryptionMaterialsResult {
        materials,
        derived_data_keys,
        message_id,
    })
}

/// Step 2: [Construct the header](spec/client-apis/encrypt.md#construct-the-header)
async fn step_construct_header(
    mat_result: &EncryptionMaterialsResult,
    encryption_context: &EncryptionContext,
    required_encryption_context_keys: &RequiredEncryptionContextKeys,
    encrypted_data_keys: &[EncryptedDataKey],
    frame_length: NonZeroU32,
    ciphertext: &mut dyn Sink,
    sig_digest: &mut DigestWriter,
) -> Result<header::HeaderInfo, Error> {
    //= spec/client-apis/encrypt.md#authentication-tag
    //= type=implication
    //= reason=build_header_for_encrypt builds the complete header (body + auth tag) before returning
    //# The serialized bytes MUST NOT be released until the entire message header has been serialized.
    let header = build_header_for_encrypt(
        &mat_result.message_id,
        &mat_result.materials.algorithm_suite(),
        encryption_context,
        required_encryption_context_keys,
        encrypted_data_keys,
        frame_length.get(),
        &mat_result.derived_data_keys,
    )?;

    //= spec/client-apis/encrypt.md#authentication-tag
    //= type=implication
    //= reason=write_header flushes complete header before body begins
    //# If this operation is streaming the encrypted message and
    //# the entire message header has been serialized,
    //# the serialized message header MUST be released.
    header::write_header(&header, ciphertext, sig_digest).await?;

    //= spec/client-apis/encrypt.md#authentication-tag
    //# The encrypted message output by the Encrypt operation MUST have a message header equal
    //# to the message header calculated in this step.
    //
    //= spec/client-apis/encrypt.md#authentication-tag
    //= type=implication
    //= reason=Header written directly to output; inequality structurally impossible
    //# If the message headers are not equal, the Encrypt operation MUST fail.
    Ok(header)
}

/// Step 3: [Construct the body](spec/client-apis/encrypt.md#construct-the-body)
async fn step_construct_body(
    plaintext: &mut dyn Source,
    header: &header::HeaderInfo,
    data_key: &MessageKey,
    ciphertext: &mut dyn Sink,
    sig_digest: &mut DigestWriter,
    max_plaintext_length: Option<u64>,
) -> Result<(), Error> {
    //= spec/client-apis/encrypt.md#construct-the-body
    //# The encrypted message output by the Encrypt operation MUST have a message body equal
    //# to the message body calculated in this step.
    //
    //= spec/client-apis/encrypt.md#construct-the-body
    //= type=implication
    //= reason=The body is written directly to the output buffer by encrypt_and_serialize_body, making inequality structurally impossible
    //# If the message bodies are not equal, the Encrypt operation MUST fail.
    body::encrypt_and_serialize_body(
        plaintext,
        header,
        data_key,
        ciphertext,
        sig_digest,
        max_plaintext_length,
    )
    .await
}

/// Step 4: [Construct the signature](spec/client-apis/encrypt.md#construct-the-signature)
async fn step_construct_signature(
    header: &header::HeaderInfo,
    materials: &EncryptionMaterials,
    sig_digest: DigestWriter,
    ciphertext: &mut dyn Sink,
) -> Result<(), Error> {
    //= spec/client-apis/encrypt.md#construct-the-signature
    //# If the [algorithm suite](../framework/algorithm-suites.md) contains a [signature algorithm](../framework/algorithm-suites.md#signature-algorithm),
    //# this operation MUST calculate a signature over the message,
    //# and the output [encrypted message](#encrypted-message) MUST contain a [message footer](../data-format/message-footer.md).
    let suite_signs = header.suite.asymmetric_signature_algorithm().is_some();
    if suite_signs {
        let ecdsa_params = get_ecdsa_alg(&header.suite)?;

        //= spec/client-apis/encrypt.md#construct-the-signature
        //# To calculate a signature, this operation MUST use the [signature algorithm](../framework/algorithm-suites.md#signature-algorithm)
        //# specified by the [algorithm suite](../framework/algorithm-suites.md), with the following input:
        let mut signature_bytes = vec![0u8; aws_mpl_primitives::signature_len(ecdsa_params)];
        // `signing_key_gate` returns a `SigningKeyPresent` token only when the
        // suite signs and the materials have a signing key (VR-019). The key
        // for signing is read only through that token.
        let Some(signing) = encrypt_gate::signing_key_gate(
            suite_signs,
            materials.signing_key().map(SigningKey::as_bytes),
        ) else {
            return Err(err(
                Kind::InvalidMaterials,
                "encryption materials must contain a signing key for signature algorithm",
            ));
        };
        ecdsa_sign_digest(
            ecdsa_params,
            //= spec/client-apis/encrypt.md#construct-the-signature
            //# - the signature key MUST be the [signing key](../framework/structures.md#signing-key) in the [encryption materials](../framework/structures.md#encryption-materials)
            encrypt_gate::signing_key(&signing),
            //= spec/client-apis/encrypt.md#construct-the-signature
            //# - the input to sign MUST be the concatenation of the serialization of the [message header](../data-format/message-header.md) and [message body](../data-format/message-body.md)
            sig_digest.context.ok_or_else(|| {
                err(
                    Kind::Internal,
                    "signature digest context must be present for signing",
                )
            })?,
            &mut signature_bytes,
        )?;

        //= spec/client-apis/encrypt.md#construct-the-signature
        //# The encrypted message output by this operation MUST have a message footer equal
        //# to the message footer calculated in this step.
        //
        //= spec/data-format/message-footer.md#overview
        //# When an [algorithm suite](../framework/algorithm-suites.md) includes a [signature algorithm](../framework/algorithm-suites.md#signature-algorithm),
        //# the [message](message.md) MUST contain a footer.
        //
        //= spec/data-format/message.md#structure
        //# If the [message header](message-header.md) contains an [algorithm suite](../framework/algorithm-suites.md) in the
        //# [algorithm suite ID](message-header.md#algorithm-suite-id) field that contains a
        //# [signature algorithm](../framework/algorithm-suites.md#signature-algorithm), the message MUST also contain a
        //# [message footer](message-footer.md) serialized after the [message body](message-body.md).
        let mut footer_bytes = Vec::new();
        footer::write_footer(
            //= spec/data-format/message-footer.md#signature
            //= type=implication
            //= reason=ciphertext is the concatenation of header and body
            //# This signature MUST be calculated over both the [message header](message-header.md) and the [message body](message-body.md),
            //# in the order of serialization.
            &mut footer_bytes,
            signature_bytes.as_ref(),
        )?;
        serialize_functions::write_to_sink(ciphertext, &footer_bytes).await?;
    } else {
        //= spec/data-format/message.md#structure
        //# If the algorithm suite does not contain a signature algorithm, the message MUST NOT contain a message footer.
    }

    //= spec/client-apis/encrypt.md#construct-the-signature
    //= reason=step_construct_signature writes directly to the output buffer; returning Ok(()) releases all serialized bytes
    //# Once the entire message footer has been serialized,
    //# this operation MUST release any previously unreleased serialized bytes from previous steps
    //# and MUST release the message footer.
    Ok(())
}

const RESERVED_ENCRYPTION_CONTEXT: &str = "aws-crypto-";

fn validate_encryption_context(ec: &EncryptionContext) -> Result<(), Error> {
    for (key, _) in ec.iter() {
        if key.starts_with(RESERVED_ENCRYPTION_CONTEXT) {
            return Err(val_err(
                "encryption context keys must not begin with the reserved prefix 'aws-crypto-'",
            ));
        }
    }
    Ok(())
}

fn build_header_for_encrypt(
    message_id: &MessageId,
    suite: &AlgorithmSuite,
    encryption_context: &EncryptionContext,
    required_encryption_context_keys: &RequiredEncryptionContextKeys,
    encrypted_data_keys: &[EncryptedDataKey],
    frame_length: u32,
    derived_data_keys: &key_derivation::DerivedKeys,
) -> Result<header::HeaderInfo, Error> {
    //= spec/client-apis/encrypt.md#authentication-tag
    //# The encryption context to only authenticate MUST be the [encryption context](../framework/structures.md#encryption-context)
    //# in the [encryption materials](../framework/structures.md#encryption-materials)
    //# filtered to only contain key value pairs listed in
    //# the [encryption material's](../framework/structures.md#encryption-materials)
    //# [required encryption context keys](../framework/structures.md#required-encryption-context-keys)
    //# serialized according to the [encryption context serialization specification](../framework/structures.md#serialization).
    let mut stored_encryption_context = EncryptionContext::new();
    let mut required_encryption_context_map = EncryptionContext::new();
    for (key, value) in encryption_context.iter() {
        if required_encryption_context_keys.contains(key) {
            required_encryption_context_map.insert(key, value);
        } else {
            stored_encryption_context.insert(key, value);
        }
    }

    let body: HeaderBody = build_header_body(
        message_id,
        suite,
        &stored_encryption_context,
        encrypted_data_keys,
        frame_length,
        derived_data_keys
            .commitment_key
            .as_ref()
            .map(PublicBytes::from_commitment),
    )?;

    let mut serialized_req_encryption_context = Vec::new();
    write_empty_ec_or_write_aad(
        &mut serialized_req_encryption_context,
        &required_encryption_context_map,
    )?;

    let mut raw_header = Vec::new();
    header::write_header_body(&mut raw_header, &body)?;

    //= spec/client-apis/encrypt.md#authentication-tag
    //# After serializing the message header body,
    //# this operation MUST calculate an [authentication tag](../data-format/message-header.md#authentication-tag)
    //# over the message header body.
    let header_auth = build_header_auth_tag(
        suite,
        &derived_data_keys.data_key,
        &raw_header,
        &serialized_req_encryption_context,
    )?;

    Ok(header::HeaderInfo {
        suite: *suite,
        body,
        encryption_context: encryption_context.clone(),
        header_auth,
        raw_header,
    })
}

fn build_header_body(
    message_id: &MessageId,
    suite: &AlgorithmSuite,
    encryption_context: &EncryptionContext,
    encrypted_data_keys: &[EncryptedDataKey],
    frame_length: u32,
    suite_data: Option<PublicBytes>,
) -> Result<HeaderBody, Error> {
    //= spec/client-apis/encrypt.md#construct-the-header
    //# The [message format version](../data-format/message-header.md#supported-versions) MUST be the value associated with the [algorithm suite](../framework/algorithm-suites.md#supported-algorithm-suites).
    //
    // Key commitment and message format version are independent columns of the
    // supported-suites table that happen to agree for every suite defined today.
    // No suite declares a version outside 1 or 2, so the final arm is unreachable.
    match suite.message_format_version() {
        2 => build_v2_header_body(
            message_id,
            suite,
            encryption_context,
            encrypted_data_keys,
            frame_length,
            suite_data,
        ),
        1 => build_v1_header_body(
            message_id,
            suite,
            encryption_context,
            encrypted_data_keys,
            frame_length,
        ),
        v => Err(err(
            Kind::Internal,
            format!("algorithm suite declares unsupported message format version {v}"),
        )),
    }
}

/// Build a Header Body Version 2.0 for a committing algorithm suite.
fn build_v2_header_body(
    message_id: &MessageId,
    suite: &AlgorithmSuite,
    encryption_context: &EncryptionContext,
    encrypted_data_keys: &[EncryptedDataKey],
    frame_length: u32,
    suite_data: Option<PublicBytes>,
) -> Result<HeaderBody, Error> {
    // `check_v2_suite_data` (VR-018) is the verified check; this maps its
    // rejections to errors.
    let sd = match check_v2_suite_data(suite_data, suite.algorithm_suite_data_length()) {
        Ok(sd) => sd,
        Err(SuiteDataLenError::Missing) => {
            return Err(err(
                Kind::Internal,
                "suite data must be present for a committing algorithm suite",
            ));
        }
        Err(SuiteDataLenError::LengthMismatch) => {
            return Err(err(
                Kind::Internal,
                "suite data length must match the commitment key output length for a committing suite",
            ));
        }
    };
    //= spec/client-apis/encrypt.md#v2-header
    //# The serialization order MUST follow the [Header Body Version 2.0](../data-format/message-header.md#header-body-version-20) specification.
    Ok(HeaderBody::V2Body(V2HeaderBody {
        algorithm_suite: *suite,
        message_id: message_id.clone(),
        encryption_context: encryption_context.clone(),
        encrypted_data_keys: encrypted_data_keys.into(),
        //= spec/client-apis/encrypt.md#nonframed-message-body-encryption
        //# Implementations of the AWS Encryption SDK MUST NOT encrypt using the nonframed content type.
        content_type: ContentType::Framed,
        frame_length,
        suite_data: sd.into_vec(),
    }))
}

/// Build a Header Body Version 1.0 for a non-committing algorithm suite.
fn build_v1_header_body(
    message_id: &MessageId,
    suite: &AlgorithmSuite,
    encryption_context: &EncryptionContext,
    encrypted_data_keys: &[EncryptedDataKey],
    frame_length: u32,
) -> Result<HeaderBody, Error> {
    let header_iv_length_usize = get_iv_length(suite);
    let Ok(header_iv_length) = u8::try_from(header_iv_length_usize) else {
        return Err(err(
            Kind::Internal,
            format!("IV length {header_iv_length_usize} exceeds the UInt8 IV-length field"),
        ));
    };
    Ok(HeaderBody::V1Body(V1HeaderBody {
        message_type: MessageType::TypeCustomerAed,
        algorithm_suite: *suite,
        message_id: message_id.clone(),
        encryption_context: encryption_context.clone(),
        encrypted_data_keys: encrypted_data_keys.into(),
        content_type: ContentType::Framed,
        header_iv_length,
        frame_length,
    }))
}

fn build_header_auth_tag(
    suite: &AlgorithmSuite,
    data_key: &MessageKey,
    raw_header: &[u8],
    serialized_req_encryption_context: &[u8],
) -> Result<HeaderAuth, Error> {
    let key_length = get_encrypt_key_length(suite);
    // `data_key_len_ok` (VR-018) is the verified check.
    if !data_key_len_ok(data_key, key_length) {
        return Err(err(
            Kind::Internal,
            format!(
                "incorrect data key length: got {}, expected {}",
                data_key.len(),
                key_length
            ),
        ));
    }

    //= spec/client-apis/encrypt.md#authentication-tag
    //# - The IV MUST have a value of 0.
    let iv = vec![0; get_iv_length(suite)];
    let mut auth_tag = Vec::new();

    //= spec/client-apis/encrypt.md#authentication-tag
    //# The value of this MUST be the output of the [authenticated encryption algorithm](../framework/algorithm-suites.md#encryption-algorithm)
    //# specified by the [algorithm suite](../framework/algorithm-suites.md), with the following inputs:
    secret::seal(
        body::get_alg_suite(suite)?,
        &iv,
        //= spec/client-apis/encrypt.md#authentication-tag
        //# - The cipherkey MUST be the derived data key
        data_key,
        //= spec/client-apis/encrypt.md#authentication-tag
        //= type=implication
        //= reason=Rust literal &[] is statically empty
        //# - The plaintext MUST be an empty byte array
        &[],
        //= spec/client-apis/encrypt.md#authentication-tag
        //# - The AAD MUST be the concatenation of the serialized [message header body](../data-format/message-header.md#header-body)
        //# and the serialization of encryption context to only authenticate.
        &[raw_header, serialized_req_encryption_context].concat(),
        &mut auth_tag,
    )?;

    Ok(HeaderAuth::AESMac {
        header_iv: iv,
        header_auth_tag: auth_tag,
    })
}
