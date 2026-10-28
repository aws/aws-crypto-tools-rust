// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structured encryption: encrypt and sign a set of fields, each with its own crypto action,
//! into fields plus a header and a footer; and the reverse.
//!
//! [`StructuredEncryption`] is the layer beneath the item encryptor.
//! It is public only for the test server, and is not a supported API.

mod api;
mod crypt;
mod footer;
mod header;
mod suite;
pub(crate) mod util;

use std::collections::{BTreeSet, HashMap};

use aws_crypto_mpl::cmm::{RequiredEncryptionContextCmm, SharedCmm};
use aws_crypto_mpl::types::{
    AlgorithmSuiteId as MplAlgorithmSuiteId, CommitmentPolicy, DbeCommitmentPolicy,
    EncryptedDataKey, EncryptionContext,
};
use aws_mpl_primitives::generate_random_bytes;

pub use api::{
    AuthItem, AuthenticateAction, CryptoItem, DecryptPathStructureFluentBuilder,
    DecryptPathStructureOutput, DecryptStructureFluentBuilder, DecryptStructureOutput,
    EncryptPathStructureFluentBuilder, EncryptPathStructureOutput, EncryptStructureFluentBuilder,
    EncryptStructureOutput, Path, PathSegment, ResolveAuthActionsFluentBuilder,
    ResolveAuthActionsOutput, StructureSegment, StructuredDataTerminal, StructuredEncryption,
};

use crate::error::{Error, materials_err, ser_err, val_err};
use crate::types::{AlgorithmSuiteId, CryptoAction};
use crypt::Mode;
use footer::Footer;
use header::MSGID_LEN;
pub(crate) use header::{DBE_ALGORITHM_FAMILY, PartialHeader, valid_encryption_context};
use suite::DbeSuite;
use util::{
    ATTR_PREFIX, AuthAction, AuthField, BOOLEAN, BYTES_TYPE_ID, CanonItem, CryptoField,
    FOOTER_FIELD, HEADER_FIELD, LEGEND, NULL, NUMBER, RESERVED_CRYPTO_CONTEXT_PREFIX, STRING,
    Terminal, canon_path, is_auth_attr, path_to_string,
};

/// The default DBE algorithm suite: ECDSA P-384 and HMAC-SHA-384 signatures.
pub(crate) const DEFAULT_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384;

const fn dbe_commitment_policy() -> CommitmentPolicy {
    CommitmentPolicy::Dbe(DbeCommitmentPolicy::RequireEncryptRequireDecrypt)
}

/// What the header of an encrypted structure says.
#[derive(Clone, Debug)]
#[non_exhaustive]
//= spec/structured-encryption/decrypt-path-structure.md#parsed-header
//= type=implication
//= reason=the struct always has the suite id, the stored context, the data keys, and the full context
//# This structure MUST contain the following values,
//# representing the deserialized form of the header of the input encrypted structure:
pub struct ParsedHeader {
    pub(crate) algorithm_suite_id: AlgorithmSuiteId,
    pub(crate) encrypted_data_keys: Vec<EncryptedDataKey>,
    pub(crate) stored_encryption_context: EncryptionContext,
    pub(crate) encryption_context: EncryptionContext,
}

impl ParsedHeader {
    /// The algorithm suite the structure was encrypted with.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The encrypted data keys stored in the header.
    #[must_use]
    pub fn encrypted_data_keys(&self) -> &[EncryptedDataKey] {
        &self.encrypted_data_keys
    }

    /// The encryption context stored in the header.
    #[must_use]
    pub const fn stored_encryption_context(&self) -> &EncryptionContext {
        &self.stored_encryption_context
    }

    /// The full encryption context of the materials, stored and not stored.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }
}

fn header_path() -> Vec<String> {
    vec![HEADER_FIELD.to_owned()]
}

fn footer_path() -> Vec<String> {
    vec![FOOTER_FIELD.to_owned()]
}

fn is_header_path(path: &[String]) -> bool {
    path.len() == 1 && (path[0] == HEADER_FIELD || path[0] == FOOTER_FIELD)
}

fn has_no_duplicates<'a>(paths: impl Iterator<Item = &'a Vec<String>>) -> bool {
    let mut seen = BTreeSet::new();
    paths.into_iter().all(|p| seen.insert(p))
}

/// Canonicalize `data` in `table` and sort it by canonical path.
fn for_encrypt(table: &str, data: Vec<CryptoField>) -> Vec<CanonItem> {
    let mut list: Vec<CanonItem> = data
        .into_iter()
        .map(|x| CanonItem {
            canon: canon_path(table, &x.key),
            key: x.key,
            data: x.data,
            action: x.action,
        })
        .collect();
    list.sort_by(|a, b| a.canon.cmp(&b.canon));
    list
}

const fn legend_to_action(v: u8) -> CryptoAction {
    match v {
        util::ENCRYPT_AND_SIGN_LEGEND => CryptoAction::EncryptAndSign,
        util::SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT_LEGEND => {
            CryptoAction::SignAndIncludeInEncryptionContext
        }
        _ => CryptoAction::SignOnly,
    }
}

/// Canonicalize and sort `data`, then take each signed field's action from the legend.
fn for_decrypt(table: &str, data: Vec<AuthField>, legend: &[u8]) -> Result<Vec<CanonItem>, Error> {
    let mut sorted: Vec<(Vec<u8>, AuthField)> = data
        .into_iter()
        .map(|x| (canon_path(table, &x.key), x))
        .collect();

    //= spec/structured-encryption/header.md#encrypt-legend-bytes
    //= reason=legend bytes are consumed in canonical-path order, as they were written
    //# The Encrypt Legend Bytes MUST be serialized as follows:
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut legend_pos = 0usize;
    let mut out = Vec::with_capacity(sorted.len());
    for (canon, item) in sorted {
        let action = if item.action == AuthAction::DoNotSign {
            CryptoAction::DoNothing
        } else {
            let Some(&byte) = legend.get(legend_pos) else {
                return Err(ser_err(
                    "the attribute actions do not match the item: an attribute written as unsigned is now configured as signed",
                ));
            };
            legend_pos += 1;
            legend_to_action(byte)
        };
        out.push(CanonItem {
            canon,
            key: item.key,
            data: item.data,
            action,
        });
    }
    if legend_pos != legend.len() {
        //= spec/structured-encryption/header.md#encrypt-legend-bytes
        //# The length of this serialized value (in bytes) MUST equal the number of authenticated fields indicated
        //# by the caller's [Authenticate Schema](./structures.md#authenticate-schema).
        return Err(ser_err(
            "the attribute actions do not match the item: an attribute written as signed is now configured as unsigned",
        ));
    }
    Ok(out)
}

/// The encryption context entries of the `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT` fields:
/// one `aws-crypto-attr.<name>` entry each, plus `aws-crypto-legend` saying how each is encoded.
fn v2_encryption_context<'a>(
    fields: impl Iterator<Item = (&'a [String], &'a Terminal)>,
) -> Result<EncryptionContext, Error> {
    let mut by_key: std::collections::BTreeMap<String, &Terminal> =
        std::collections::BTreeMap::new();
    for (path, data) in fields {
        //= spec/dynamodb-encryption-client/encrypt-item.md#base-context-value-version-2
        //# The key MUST be as per [Encryption Context Naming]
        //# (../structured-encryption/encrypt-path-structure.md#encryption-context-naming).
        //
        //= spec/structured-encryption/encrypt-path-structure.md#encryption-context-naming
        //# When a key-value pair is added to the encryption context,
        //# the key MUST be the concatenation of the literal
        //# "aws-crypto-attr." and the member strings of the
        //# path joined by the '.' character.
        let key = format!("{ATTR_PREFIX}{}", path_to_string(path));
        if by_key.contains_key(&key) {
            //= spec/structured-encryption/encrypt-path-structure.md#encryption-context-naming
            //# An error MUST be returned if an attempt is made to add two
            //# different attributes that produce the same encryption context key.
            return Err(val_err(format!(
                "{key} appears twice in encryption context."
            )));
        }
        by_key.insert(key, data);
    }
    if by_key.is_empty() {
        return Ok(EncryptionContext::new());
    }
    let mut ec = EncryptionContext::new();
    let mut legend = String::with_capacity(by_key.len());
    for (key, attr) in by_key {
        //= spec/dynamodb-encryption-client/encrypt-item.md#base-context-value-version-2
        //# The value MUST be :
        let (legend_char, value) = if attr.type_id == NULL {
            ('L', "null".to_owned())
        } else if attr.type_id == STRING {
            let s = String::from_utf8(attr.value.clone()).map_err(|_| {
                ser_err("an encryption context attribute has a string value that is not UTF-8")
            })?;
            ('S', s)
        } else if attr.type_id == NUMBER {
            let s = String::from_utf8(attr.value.clone()).map_err(|_| {
                ser_err("an encryption context attribute has a number value that is not UTF-8")
            })?;
            ('N', s)
        } else if attr.type_id == BOOLEAN {
            let [b] = attr.value.as_slice() else {
                return Err(ser_err(
                    "an encryption context attribute has a boolean value that is not 1 byte",
                ));
            };
            ('L', if *b == 0 { "false" } else { "true" }.to_owned())
        } else {
            ('B', attr.encode())
        };

        //= spec/structured-encryption/structures.md#sign-and-include-in-encryption-context
        //# and further that the [Terminal Data](#terminal-data) MUST be included in the encryption context.
        ec.insert(key, value);
        legend.push(legend_char);
    }

    //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= reason=one character per entry, in by_key's BTreeMap order, which is UTF-8 byte order
    //# The Legend MUST be named "aws-crypto-legend" and be a string with one character per attribute added above,
    //# with a one-to-one correspondence with the attributes sorted by their UTF8 encoding,
    //# each character designating the original type of the attribute,
    //# to allow reversing of the [encoding](../dynamodb-encryption-client/encrypt-item.md#base-context-value-version-2).
    ec.insert(LEGEND, legend);
    Ok(ec)
}

/// Add `extra` to `ec`, and wrap `cmm` so the new entries are required and never stored.
fn require_context(
    ec: &mut EncryptionContext,
    extra: &EncryptionContext,
    cmm: SharedCmm,
) -> Result<SharedCmm, Error> {
    if extra.is_empty() {
        return Ok(cmm);
    }
    if extra.keys().any(|k| ec.contains_key(k)) {
        //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
        //# An error MUST be returned if any of the entries added to the encryption context in this step
        //# have the same key as any entry already in the encryption context.
        //
        //= spec/structured-encryption/decrypt-path-structure.md#create-new-encryption-context-and-cmm
        //# An error MUST be returned if any of the entries added to the encryption context in this step
        //# have the same key as any entry already in the encryption context.
        return Err(val_err(
            "Internal Error - Structured Encryption encryption context overlaps with Item Encryptor encryption context.",
        ));
    }
    let keys: Vec<String> = extra.keys().map(str::to_owned).collect();
    for (k, v) in extra.iter() {
        ec.insert(k, v);
    }

    //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
    //# Then, this operation MUST create a [Required Encryption Context CMM](https://github.com/awslabs/private-aws-encryption-sdk-specification-staging/blob/dafny-verified/framework/required-encryption-context-cmm.md)
    //# with the following inputs:
    //
    //= spec/structured-encryption/decrypt-path-structure.md#create-new-encryption-context-and-cmm
    //# Then, this operation MUST create a [Required Encryption Context CMM](https://github.com/awslabs/private-aws-encryption-sdk-specification-staging/blob/dafny-verified/framework/required-encryption-context-cmm.md)
    //# with the following inputs:
    required_context_cmm(cmm, keys)
}

/// `cmm` wrapped in a required encryption context CMM for `keys`.
pub(crate) fn required_context_cmm(cmm: SharedCmm, keys: Vec<String>) -> Result<SharedCmm, Error> {
    let required = RequiredEncryptionContextCmm::builder()
        .underlying_cmm(cmm)
        .set_required_encryption_context_keys(Some(keys))
        .build()?;
    Ok(SharedCmm::new(required))
}

/// Encrypt and sign `data` for `table`.
/// Returns the fields with the header and footer appended, and the parsed header.
pub(crate) async fn encrypt_path_structure(
    table: &str,
    data: Vec<CryptoField>,
    cmm: SharedCmm,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
) -> Result<(Vec<CryptoField>, ParsedHeader), Error> {
    //= spec/structured-encryption/encrypt-path-structure.md#encryption-context
    //= type=exception
    //= reason=Like the reference, this rejects aws-crypto- values; the item encryptor passes aws-crypto- keys
    //# The operation MUST fail if an encryption context is provided which contains a key with the prefix `aws-crypto-`.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#behavior
    //= reason=these four input checks all run before the CMM is called
    //# All inputs MUST adhere to their requirements;
    //# otherwise this operation MUST immediately yield an error.
    if let Some(ec) = &encryption_context
        && ec
            .iter()
            .any(|(_, v)| v.starts_with(RESERVED_CRYPTO_CONTEXT_PREFIX))
    {
        return Err(val_err(format!(
            "Encryption Context must not contain members beginning with {RESERVED_CRYPTO_CONTEXT_PREFIX}"
        )));
    }
    if !data.iter().any(|k| is_auth_attr(k.action)) {
        //= spec/structured-encryption/encrypt-path-structure.md#crypto-list
        //# The Crypto List MUST include at least one [Crypto Action](./structures.md#crypto-action)
        //# that is not [DO_NOTHING](./structures.md#do_nothing).
        return Err(val_err(
            "At least one field in the Crypto Schema must be ENCRYPT_AND_SIGN, SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT or SIGN_ONLY.",
        ));
    }
    if data.iter().any(|x| is_header_path(&x.key)) {
        //= spec/structured-encryption/encrypt-path-structure.md#crypto-list
        //# This Crypto List MUST NOT already contain data located at the [header index](./header.md#header-index)
        //# or the [footer index](./footer.md#footer-index).
        return Err(val_err(format!(
            "The paths {HEADER_FIELD} and {FOOTER_FIELD} are reserved."
        )));
    }
    if !has_no_duplicates(data.iter().map(|x| &x.key)) {
        //= spec/structured-encryption/encrypt-path-structure.md#crypto-list
        //# The [paths](./structures.md#path) in the input [Crypto List](./structures.md#crypto-list) MUST be unique.
        return Err(val_err("an attribute appears more than once"));
    }

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //# This operation MUST [calculate the appropriate CMM and encryption context](#create-new-encryption-context-and-cmm).
    let mut ec = encryption_context.unwrap_or_default();
    let mut cmm = cmm;

    //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= reason=with no such field this branch is skipped, leaving cmm and ec as given
    //# If no [Crypto Action](./structures.md#crypto-action) is configured to be
    //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT Crypto Action](./structures.md#sign_and_include_in_encryption_context)
    //# then the input cmm and encryption context MUST be used unchanged.
    if data
        .iter()
        .any(|x| x.action == CryptoAction::SignAndIncludeInEncryptionContext)
    {
        //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
        //# Otherwise, this operation MUST add an [entry](../dynamodb-encryption-client/encrypt-item.md#base-context-value-version-2) to the encryption context for every
        //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT Crypto Action](./structures.md#sign_and_include_in_encryption_context)
        //# [Terminal Data](./structures.md#terminal-data)
        //# in the input record, plus the Legend.
        let extra = v2_encryption_context(
            data.iter()
                .filter(|x| x.action == CryptoAction::SignAndIncludeInEncryptionContext)
                .map(|x| (x.key.as_slice(), &x.data)),
        )?;
        cmm = require_context(&mut ec, &extra, cmm)?;
    }

    //= spec/structured-encryption/encrypt-path-structure.md#calculate-intermediate-encrypted-structured-data
    //= reason=for_encrypt maps each input field to one entry with its canonical path
    //# For every entry
    //# in the input [Crypto List](#crypto-list)
    //# there MUST be an entry with the same [canonical path](./header.md#canonical-path)
    //# in Intermediate Encrypted Structured Data.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#calculate-intermediate-encrypted-structured-data
    //# There MUST be no other entries in the Intermediate Encrypted Structured Data.
    let canon = for_encrypt(table, data);

    let encrypted_count = canon
        .iter()
        .filter(|x| x.action == CryptoAction::EncryptAndSign)
        .count();
    let encrypted_size: usize = canon
        .iter()
        .filter(|x| x.action == CryptoAction::EncryptAndSign)
        .map(|x| x.data.value.len())
        .sum();

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //# - Max Plaintext Length: This field MUST be the result of the calculation `encryptedTerminalDataNum * 2 + totalEncryptedTerminalValuesSize`
    let max_length = u64::try_from(2 * encrypted_count + encrypted_size)
        .ok()
        .filter(|n| *n < u64::try_from(i64::MAX).unwrap_or(u64::MAX))
        // No test reaches this error: the encrypted values would total about i64::MAX bytes.
        .ok_or_else(|| val_err("the item is too large to encrypt"))?;

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //# - Algorithm Suite: If provided, this is the [input algorithm suite](#algorithm-suite);
    //# otherwise, this field MUST be the algorithm suite corresponding to the enum
    //# [DBE.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#supported-algorithm-suites-enum).
    let suite_id = algorithm_suite_id.unwrap_or(DEFAULT_SUITE);

    //= spec/structured-encryption/encrypt-path-structure.md#behavior
    //= type=implication
    //= reason=each step consumes the previous one's output: materials, then crypt, then the footer over its output
    //# This operation MUST perform all the above steps,
    //# and it MUST perform them in the above order.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //# This operation MUST obtain a set of encryption materials by calling
    //# [Get Encryption Materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cmm-interface.md#get-encryption-materials)
    //# on the [CMM](#cmm) calculated above.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //# This operation MUST call Get Encryption Materials on the CMM as follows.
    let mat = cmm
        .get_encryption_materials()
        //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
        //# - Encryption Context: This MUST be the encryption context calculated above.
        .encryption_context(ec)
        //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
        //# - Commitment Policy: This MUST be
        //# [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/commitment-policy.md#esdkrequire_encrypt_require_decrypt).
        .commitment_policy(dbe_commitment_policy())
        //= spec/structured-encryption/encrypt-path-structure.md#algorithm-suite
        //# The [algorithm suite](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md) that SHOULD be used for encryption.
        //
        //= spec/structured-encryption/encrypt-path-structure.md#algorithm-suite
        //= type=implication
        //= reason=the input is a DbeAlgorithmSuiteId, which names only DBE suites
        //# This algorithm suite MUST be a
        //# [supported suite for Database Encryption (DBE)](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#supported-algorithm-suites-enum);
        //# otherwise, this operation MUST yield an error.
        .algorithm_suite_id(MplAlgorithmSuiteId::Dbe(suite_id))
        .max_plaintext_length(max_length)
        .send()
        //= spec/structured-encryption/encrypt-path-structure.md#behavior
        //# If any of these steps fails, this operation MUST halt and indicate a failure to the caller.
        .await?
        .into_encryption_materials();
    let key = mat
        .plaintext_data_key()
        .ok_or_else(|| materials_err("the materials have no plaintext data key"))?;

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= reason=the suite comes from the materials only; the header flavor and footer use it too
    //# The algorithm suite used in all aspects of this operation MUST be
    //# the algorithm suite in the
    //# [encryption materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#encryption-materials)
    //# returned from the Get Encryption Materials call.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= reason=it is not compared with the requested suite_id
    //# Note that the algorithm suite in the retrieved encryption materials MAY be different from the input algorithm suite.
    let suite = DbeSuite::new(mat.algorithm_suite_id())?;
    if !valid_encryption_context(mat.encryption_context()) {
        return Err(val_err(
            "the materials' encryption context cannot be stored: it has 65536 or more entries, or a key or value of 65536 or more bytes",
        ));
    }

    let mut msg_id = [0u8; MSGID_LEN];

    //= spec/structured-encryption/header.md#message-id
    //# Implementations MUST generate a fresh 256-bit random MessageID, from a cryptographically secure source, for each record encrypted.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#calculate-intermediate-encrypted-structured-data
    //# The process used to generate this identifier MUST use a good source of randomness
    //# to make the chance of duplicate identifiers negligible.
    generate_random_bytes(&mut msg_id)?;
    let head = PartialHeader::create(&canon, msg_id, &mat)?;

    //= spec/structured-encryption/header.md#commit-key
    //# The commit key calculation described above MUST be performed with the record's plaintext data key
    //# and the header's message id.
    let commit = crypt::commit_key(suite, key.as_bytes(), &head.msg_id)?;

    //= spec/structured-encryption/encrypt-path-structure.md#header-field
    //# The Header Field Value MUST be the full serialized [header](header.md) with commitment.
    let header_bytes = head.serialize_with_commitment(suite.commit, &commit)?;

    // No test reaches this error: it needs about 1.4 billion fields in one item.
    if u32::try_from(canon.len()).map_or(true, |n| n >= crypt::ONE_THIRD_MAX_INT) {
        return Err(val_err("the item has too many encrypted attributes"));
    }

    //= spec/structured-encryption/encrypt-path-structure.md#calculate-cipherkey-and-nonce
    //# The `FieldRootKey` MUST be generated with the plaintext data key in the encryption materials
    //# and the Message ID generated for this Encrypted Structured Data.
    let encrypted = crypt::crypt(Mode::Encrypt, suite, key.as_bytes(), &head.msg_id, canon)?;
    let footer = Footer::create(suite, &mat, &encrypted, &header_bytes)?;

    let header_suite = DbeSuite::from_flavor(head.flavor)?;

    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
    //# - For every entry in the input [Crypto List](#crypto-list)
    //# an entry MUST exist with the same [path](./structures.md#path) in the final Encrypted Structured Data.
    //
    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
    //= reason=out starts as exactly the encrypted fields; only the header and footer are added
    //# - For every entry in the final Encrypted Structured Data, other than the header and footer,
    //# an entry MUST exist with the same [path](./structures.md#path) in the input [Crypto List](#crypto-list).
    let mut out: Vec<CryptoField> = encrypted
        .into_iter()
        .map(|x| CryptoField {
            key: x.key,
            data: x.data,
            action: x.action,
        })
        .collect();

    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
    //# - The [Header Field](#header-field) MUST exist in the final Encrypted Structured Data
    out.push(CryptoField {
        key: header_path(),
        //= spec/structured-encryption/encrypt-path-structure.md#header-field
        //# The Header Field TypeID MUST be 0xFFFF
        data: Terminal::new(BYTES_TYPE_ID, header_bytes),
        action: CryptoAction::DoNothing,
    });

    //= spec/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
    //# - The [Footer Field](#footer-field) MUST exist in the final Encrypted Structured Data
    out.push(CryptoField {
        key: footer_path(),
        //= spec/structured-encryption/encrypt-path-structure.md#footer-field
        //# The Footer Field Value MUST be the serialized [footer](footer.md).
        data: footer.into_terminal(),
        action: CryptoAction::DoNothing,
    });
    let parsed = ParsedHeader {
        algorithm_suite_id: header_suite.id,
        encrypted_data_keys: head.data_keys,
        stored_encryption_context: head.enc_context,
        encryption_context: mat.encryption_context().clone(),
    };
    Ok((out, parsed))
}

/// The header or footer terminal, which must be an unsigned binary field.
fn get_binary<'a>(data: &'a [AuthField], name: &str) -> Result<&'a Terminal, Error> {
    let Some(item) = data.iter().find(|x| x.key.len() == 1 && x.key[0] == name) else {
        //= spec/structured-encryption/decrypt-path-structure.md#auth-list
        //# This Auth List MUST contain data located at the [header index](./header.md#header-index)
        //# and the [footer index](./footer.md#footer-index).
        //
        //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
        //# A footer field MUST exist with the name `aws_dbe_foot`
        return Err(ser_err(format!("the item has no {name} attribute")));
    };
    if item.data.type_id != BYTES_TYPE_ID {
        //= spec/structured-encryption/decrypt-path-structure.md#parse-the-header
        //# The [Terminal Type Id](./structures.md#terminal-type-id) on this Terminal Data MUST be `0xFFFF`.
        //
        //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
        //# The footer field TypeID MUST be 0xFFFF
        return Err(ser_err(format!(
            "the item's {name} attribute must be binary"
        )));
    }
    if item.action != AuthAction::DoNotSign {
        return Err(val_err(format!("the {name} attribute must not be signed")));
    }
    Ok(&item.data)
}

/// Verify and decrypt `data` for `table`.
/// Returns the fields without the header and footer, each with the action the header recorded.
pub(crate) async fn decrypt_path_structure(
    table: &str,
    data: Vec<AuthField>,
    cmm: SharedCmm,
    encryption_context: Option<EncryptionContext>,
) -> Result<(Vec<CryptoField>, ParsedHeader), Error> {
    //= spec/structured-encryption/decrypt-path-structure.md#behavior
    //= reason=these checks, and get_binary's below, all run before the CMM is called
    //# All inputs MUST adhere to their requirements;
    //# otherwise this operation MUST immediately yield an error.
    if !data.iter().any(|x| x.action == AuthAction::Sign) {
        //= spec/structured-encryption/decrypt-path-structure.md#auth-list
        //# The Auth List MUST include at least one [SIGN Authenticate Action](./structures.md#sign);
        //# otherwise, this operation MUST yield an error.
        return Err(val_err("at least one attribute must be signed"));
    }
    if !has_no_duplicates(data.iter().map(|x| &x.key)) {
        //= spec/structured-encryption/decrypt-path-structure.md#auth-list
        //# The Auth List MUST NOT contain duplicate Paths.
        return Err(val_err("an attribute appears more than once"));
    }

    // Parse the Header

    //= spec/structured-encryption/decrypt-path-structure.md#behavior
    //= reason=the footer is verified (?) before crypt decrypts any field; the CMM call consumes the parsed header
    //# This operation MUST perform all the above steps,
    //# and it MUST perform them in the above order.
    //
    //= spec/structured-encryption/decrypt-path-structure.md#parse-the-header
    //# Given the [input data](#auth-list),
    //# this operation MUST access the [Terminal Data](./structures.md#terminal-data)
    //# at "aws_dbe_head".
    let header_bytes = get_binary(&data, HEADER_FIELD)?.value.clone();
    let footer_bytes = get_binary(&data, FOOTER_FIELD)?.value.clone();

    //= spec/structured-encryption/decrypt-path-structure.md#parse-the-header
    //# This operation MUST deserialize the header bytes
    //# according to the [header format](./header.md).
    let head = PartialHeader::deserialize(&header_bytes)?;
    let header_suite = DbeSuite::from_flavor(head.flavor)?;
    let canon = for_decrypt(table, data, &head.legend)?;

    // Retrieve Decryption Materials

    //= spec/structured-encryption/decrypt-path-structure.md#retrieve-decryption-materials
    //# This operation MUST [calculate the appropriate CMM and encryption context](#create-new-encryption-context-and-cmm).
    let mut ec = encryption_context.unwrap_or_default();
    let mut cmm = cmm;

    //= spec/structured-encryption/decrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= reason=a version 1 header skips this branch, leaving cmm and ec as given
    //# If the version stored in the header is 1,
    //# then the input cmm and encryption context MUST be used unchanged.
    if head.version == 2 {
        //= spec/structured-encryption/decrypt-path-structure.md#create-new-encryption-context-and-cmm
        //# Otherwise, this operation MUST add an [entry](../dynamodb-encryption-client/encrypt-item.md#base-context-value-version-2) to the encryption context for every
        //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT Crypto Action](./structures.md#sign_and_include_in_encryption_context)
        //# [Terminal Data](./structures.md#terminal-data)
        //# in the input record, plus the Legend.
        let extra = v2_encryption_context(
            canon
                .iter()
                .filter(|x| x.action == CryptoAction::SignAndIncludeInEncryptionContext)
                .map(|x| (x.key.as_slice(), &x.data)),
        )?;
        cmm = require_context(&mut ec, &extra, cmm)?;
    }

    //= spec/structured-encryption/decrypt-path-structure.md#retrieve-decryption-materials
    //# This operation MUST obtain a set of decryption materials by calling
    //# [Decrypt Materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cmm-interface.md#decrypt-materials)
    //# on the [CMM](#cmm) calculated above.
    //
    //= spec/structured-encryption/decrypt-path-structure.md#retrieve-decryption-materials
    //# The call to the CMM's Decrypt Materials operation MUST be constructed as follows:
    let mat = cmm
        .decrypt_materials()
        .algorithm_suite_id(MplAlgorithmSuiteId::Dbe(header_suite.id))
        .commitment_policy(dbe_commitment_policy())
        .encrypted_data_keys(head.data_keys.clone())
        .encryption_context(head.enc_context.clone())
        //= spec/structured-encryption/decrypt-path-structure.md#encryption-context
        //= reason=the CMM checks the caller's context, as the reproduced context, against the keys' context
        //# - This MUST include any key-values pairs that were used during the original [encryption](./encrypt-path-structure.md)
        //# of the [input data](#auth-list),
        //# but not stored in the [input Structured Data's header](./header.md#encryption-context).
        //
        //= spec/structured-encryption/decrypt-path-structure.md#encryption-context
        //= reason=the CMM accepts a reproduced entry that equals the stored one
        //# - This MAY include any key-values pairs that are stored
        //# in the [input Structured Data's header](./header.md#encryption-context).
        //
        //= spec/structured-encryption/decrypt-path-structure.md#encryption-context
        //= reason=the CMM rejects a reproduced entry that differs from the stored one
        //# - This MUST NOT include any key-values pairs that were not
        //# used during the original [encryption](./encrypt-structure.md) of the [input data](#auth-list).
        .reproduced_encryption_context(ec)
        .send()
        //= spec/structured-encryption/decrypt-path-structure.md#behavior
        //# If any of these steps fails, this operation MUST halt and indicate a failure to the caller.
        .await?
        .into_decryption_materials();
    if !valid_encryption_context(mat.encryption_context()) {
        return Err(val_err(
            "the materials' encryption context cannot be stored: it has 65536 or more entries, or a key or value of 65536 or more bytes",
        ));
    }
    let key = mat
        .plaintext_data_key()
        .ok_or_else(|| materials_err("the materials have no plaintext data key"))?;

    //= spec/structured-encryption/decrypt-path-structure.md#retrieve-decryption-materials
    //= reason=the suite comes from the materials only; commitment, footer, and decryption use it
    //# The algorithm suite used in all further aspects of this operation MUST be
    //# the algorithm suite in the
    //# [decryption materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#decryption-materials)
    //# returned from the Decrypt Materials call.
    //
    //= spec/structured-encryption/decrypt-path-structure.md#retrieve-decryption-materials
    //= reason=it is not compared with the header's suite
    //# Note that the algorithm suite in the retrieved decryption materials MAY be different from the input algorithm suite.
    let suite = DbeSuite::new(mat.algorithm_suite_id())?;

    //= spec/structured-encryption/header.md#commit-key
    //# The commit key calculation described above MUST be performed with the record's plaintext data key
    //# and the header's message id.
    let commit = crypt::commit_key(suite, key.as_bytes(), &head.msg_id)?;

    //= spec/structured-encryption/decrypt-path-structure.md#parse-the-header
    //# The header field value MUST be [verified](header.md#commitment-verification)
    PartialHeader::verify_commitment(suite.commit, &commit, &header_bytes)?;

    // Verify Signatures

    //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
    //# This operation MUST deserialize the bytes in [Terminal Value](./structures.md#terminal-value)
    //# according to the [footer format](./footer.md).
    let footer = Footer::deserialize(&footer_bytes, suite.signature != suite::Signature::None)?;

    //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
    //# The footer field value MUST be [verified](footer.md#footer-verification).
    //
    //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
    //= reason=the ? returns before crypt decrypts any field
    //# Decryption MUST fail immediately if verification fails.
    footer.validate(&mat, head.data_keys.len(), &canon, &header_bytes)?;

    // Construct Decrypted Structured Data

    let decrypted = crypt::crypt(Mode::Decrypt, suite, key.as_bytes(), &head.msg_id, canon)?;

    //= spec/structured-encryption/decrypt-path-structure.md#construct-decrypted-structured-data
    //# - An entry MUST NOT exist with the key "aws_dbe_head" or "aws_dbe_foot".
    //
    //= spec/structured-encryption/decrypt-path-structure.md#construct-decrypted-structured-data
    //= reason=crypt returns one entry per input entry; only the header and footer are dropped
    //# - For every entry in the [input Auth List](#auth-list), other than the header and footer,
    //# an entry MUST exist with the same key in the output Crypto List.
    //
    //= spec/structured-encryption/decrypt-path-structure.md#construct-decrypted-structured-data
    //= reason=every output entry is an input entry; nothing is added
    //# - For every entry in the output Crypto List
    //# an entry MUST exist with the same key in the [input Auth List](#auth-list).
    let out = decrypted
        .into_iter()
        .filter(|x| !is_header_path(&x.key))
        .map(|x| CryptoField {
            key: x.key,
            data: x.data,
            action: x.action,
        })
        .collect();

    //= spec/structured-encryption/decrypt-path-structure.md#construct-decrypted-structured-data
    //# The output MUST also include a [Parsed Header](#parsed-header) that contains
    //# data that was serialized into the header included in the output Structured Data.
    let parsed = ParsedHeader {
        algorithm_suite_id: header_suite.id,
        encrypted_data_keys: head.data_keys,
        stored_encryption_context: head.enc_context,
        encryption_context: mat.encryption_context().clone(),
    };
    Ok((out, parsed))
}

/// The action the header's legend gives each field of `data`, which must hold the header and footer.
/// Needs no materials: nothing is verified or decrypted.
pub(crate) fn resolve_auth_actions(
    table: &str,
    data: Vec<AuthField>,
    header_bytes: &[u8],
) -> Result<Vec<CryptoField>, Error> {
    if !has_no_duplicates(data.iter().map(|x| &x.key)) {
        return Err(val_err("an attribute appears more than once"));
    }
    let head = PartialHeader::deserialize(header_bytes)?;
    if !data.iter().any(|x| x.key == header_path()) {
        return Err(val_err("the item has no aws_dbe_head attribute"));
    }
    if !data.iter().any(|x| x.key == footer_path()) {
        return Err(val_err("the item has no aws_dbe_foot attribute"));
    }
    let canon = for_decrypt(table, data, &head.legend)?;
    Ok(canon
        .into_iter()
        .map(|x| CryptoField {
            key: x.key,
            data: x.data,
            action: x.action,
        })
        .collect())
}

/// A structure of top-level fields and the result of encrypting or decrypting it.
#[derive(Debug)]
pub(crate) struct StructureOutput {
    /// Every field, the header and footer included after encryption.
    pub(crate) data: HashMap<String, Terminal>,
    /// The action of each signed field.
    pub(crate) schema: HashMap<String, CryptoAction>,
    pub(crate) parsed_header: ParsedHeader,
}

fn sorted_entries<V>(map: HashMap<String, V>) -> Vec<(String, V)> {
    let mut entries: Vec<(String, V)> = map.into_iter().collect();
    entries.sort_by(|a, b| util::utf16_cmp(&a.0, &b.0));
    entries
}

/// A record's fields and the action taken on each.
type FieldsAndActions = (HashMap<String, Terminal>, HashMap<String, CryptoAction>);

/// Split a list of single-member paths back into a map of fields and a map of signed actions.
fn unbuild(list: Vec<CryptoField>) -> Result<FieldsAndActions, Error> {
    let mut data = HashMap::with_capacity(list.len());
    let mut schema = HashMap::with_capacity(list.len());
    for item in list {
        let [key] = <[String; 1]>::try_from(item.key)
            .map_err(|_| crate::error::internal_err("expected a top-level field"))?;
        if data.contains_key(&key) {
            return Err(val_err(format!(
                "the attribute {key} appears more than once"
            )));
        }
        if is_auth_attr(item.action) {
            schema.insert(key.clone(), item.action);
        }
        data.insert(key, item.data);
    }
    Ok((data, schema))
}

/// Encrypt and sign a structure of top-level fields.
pub(crate) async fn encrypt_structure(
    table: &str,
    plaintext: HashMap<String, Terminal>,
    schema: &HashMap<String, CryptoAction>,
    cmm: SharedCmm,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
) -> Result<StructureOutput, Error> {
    if plaintext.len() != schema.len() || plaintext.keys().any(|k| !schema.contains_key(k)) {
        //= spec/structured-encryption/encrypt-structure.md#behavior
        //# The input [Structured Data](encrypt-path-structure.md#structured-data) and [Crypto Schema](encrypt-path-structure.md#crypto-schema)
        //# MUST refer to the same set of locations.
        return Err(val_err(
            "the item's attributes do not match the attribute actions: each attribute needs exactly one action",
        ));
    }

    //= spec/structured-encryption/encrypt-structure.md#behavior
    //# The input [Structured Data](encrypt-path-structure.md#structured-data) and [Crypto Schema](encrypt-path-structure.md#crypto-schema)
    //# MUST be combined into a single [Crypto List](encrypt-path-structure.md#crypto-list).
    let list = sorted_entries(plaintext)
        .into_iter()
        .map(|(k, data)| CryptoField {
            action: schema[&k],
            key: vec![k],
            data,
        })
        .collect();

    //= spec/structured-encryption/encrypt-structure.md#behavior
    //# Encrypt Structure MUST then behave as [Encrypt Path Structure](encrypt-path-structure.md)
    let (out, parsed_header) =
        encrypt_path_structure(table, list, cmm, algorithm_suite_id, encryption_context).await?;

    //= spec/structured-encryption/encrypt-structure.md#behavior
    //# The output [Crypto List](encrypt-path-structure.md#crypto-list) produced by [Encrypt Path Structure](encrypt-path-structure.md)
    //# MUST be split into [Structured Data](encrypt-path-structure.md#structured-data) and [Crypto Schema](encrypt-path-structure.md#crypto-schema)
    //# maps.
    let (data, schema) = unbuild(out)?;
    Ok(StructureOutput {
        data,
        schema,
        parsed_header,
    })
}

/// Verify and decrypt a structure of top-level fields.
pub(crate) async fn decrypt_structure(
    table: &str,
    encrypted: HashMap<String, Terminal>,
    schema: &HashMap<String, AuthAction>,
    cmm: SharedCmm,
    encryption_context: Option<EncryptionContext>,
) -> Result<StructureOutput, Error> {
    if encrypted.len() != schema.len() || encrypted.keys().any(|k| !schema.contains_key(k)) {
        //= spec/structured-encryption/decrypt-structure.md#behavior
        //# The input [Structured Data](decrypt-path-structure.md#structured-data) and [Authenticate Schema](decrypt-path-structure.md#authenticate-schema)
        //# MUST refer to the same set of locations.
        return Err(val_err(
            "DecryptStructure requires encryptedStructure and authenticateSchema have the same keys.",
        ));
    }

    //= spec/structured-encryption/decrypt-structure.md#behavior
    //# The input [Structured Data](decrypt-path-structure.md#structured-data) and [Authenticate Schema](decrypt-path-structure.md#authenticate-schema)
    //# MUST be combined into a single [Auth List](decrypt-path-structure.md#auth-list).
    let list = sorted_entries(encrypted)
        .into_iter()
        .map(|(k, data)| AuthField {
            action: schema[&k],
            key: vec![k],
            data,
        })
        .collect();

    //= spec/structured-encryption/decrypt-structure.md#behavior
    //# Decrypt Structure MUST then behave as [Decrypt Path Structure](decrypt-path-structure.md)
    let (out, parsed_header) = decrypt_path_structure(table, list, cmm, encryption_context).await?;

    //= spec/structured-encryption/decrypt-structure.md#behavior
    //# The output [Crypto List](decrypt-path-structure.md#crypto-list) produced by [Decrypt Path Structure](decrypt-path-structure.md)
    //# MUST be split into [Structured Data](decrypt-path-structure.md#structured-data) and [Crypto Schema](decrypt-path-structure.md#crypto-schema)
    //# maps.
    let (data, schema) = unbuild(out)?;
    Ok(StructureOutput {
        data,
        schema,
        parsed_header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(key: &[&str], action: CryptoAction) -> CryptoField {
        CryptoField {
            key: key.iter().map(|s| (*s).to_owned()).collect(),
            data: Terminal::new(BYTES_TYPE_ID, vec![]),
            action,
        }
    }

    // Port of PathsTests.TestSpecExamples.
    #[test]
    fn canonical_path_spec_example() {
        let [item] = <[CanonItem; 1]>::try_from(for_encrypt(
            "example_table",
            vec![field(&["name"], CryptoAction::SignOnly)],
        ))
        .unwrap();
        let mut expected = b"example_table".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        expected.push(b'$');
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 4]);
        expected.extend_from_slice(b"name");
        assert_eq!(item.canon, expected);
    }

    #[test]
    fn unbuild_rejects_nested_paths() {
        let err = unbuild(vec![field(&["a", "b"], CryptoAction::SignOnly)]).unwrap_err();
        assert!(matches!(err, Error::Internal(_)), "{err:?}");
        let err = unbuild(vec![
            field(&["a"], CryptoAction::SignOnly),
            field(&["a"], CryptoAction::DoNothing),
        ])
        .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "{err:?}");
    }
}
