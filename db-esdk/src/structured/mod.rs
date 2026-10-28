// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structured encryption: encrypt and sign a set of fields, each with its own crypto action,
//! into fields plus a header and a footer; and the reverse.

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

use crate::error::{Error, materials_err, ser_err, val_err};
use crate::types::{AlgorithmSuiteId, CryptoAction};
use crypt::Mode;
use footer::Footer;
use header::MSGID_LEN;
pub(crate) use header::{DBE_ALGORITHM_FAMILY, PartialHeader, valid_encryption_context};
use suite::DbeSuite;
use util::{
    ATTR_PREFIX, AuthAction, AuthItem, BOOLEAN, BYTES_TYPE_ID, CanonItem, CryptoItem, FOOTER_FIELD,
    HEADER_FIELD, LEGEND, NULL, NUMBER, RESERVED_CRYPTO_CONTEXT_PREFIX, STRING, Terminal,
    canon_path, is_auth_attr, path_to_string,
};

/// The default DBE algorithm suite: ECDSA P-384 and HMAC-SHA-384 signatures.
pub(crate) const DEFAULT_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384;

const fn dbe_commitment_policy() -> CommitmentPolicy {
    CommitmentPolicy::Dbe(DbeCommitmentPolicy::RequireEncryptRequireDecrypt)
}

/// What the header of an encrypted structure says.
#[derive(Clone, Debug)]
pub(crate) struct ParsedHeader {
    pub(crate) algorithm_suite_id: AlgorithmSuiteId,
    pub(crate) encrypted_data_keys: Vec<EncryptedDataKey>,
    pub(crate) stored_encryption_context: EncryptionContext,
    pub(crate) encryption_context: EncryptionContext,
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
fn for_encrypt(table: &str, data: Vec<CryptoItem>) -> Vec<CanonItem> {
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
fn for_decrypt(table: &str, data: Vec<AuthItem>, legend: &[u8]) -> Result<Vec<CanonItem>, Error> {
    let mut sorted: Vec<(Vec<u8>, AuthItem)> = data
        .into_iter()
        .map(|x| (canon_path(table, &x.key), x))
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut legend_pos = 0usize;
    let mut out = Vec::with_capacity(sorted.len());
    for (canon, item) in sorted {
        let action = if item.action == AuthAction::DoNotSign {
            CryptoAction::DoNothing
        } else {
            let Some(&byte) = legend.get(legend_pos) else {
                return Err(ser_err(
                    "Schema changed : something that was unsigned is now signed.",
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
        return Err(ser_err(
            "Schema changed : something that was signed is now unsigned.",
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
        let key = format!("{ATTR_PREFIX}{}", path_to_string(path));
        if by_key.contains_key(&key) {
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
        let (legend_char, value) = if attr.type_id == NULL {
            ('L', "null".to_owned())
        } else if attr.type_id == STRING {
            let s = String::from_utf8(attr.value.clone())
                .map_err(|_| ser_err("Internal Error : string was not UTF8."))?;
            ('S', s)
        } else if attr.type_id == NUMBER {
            let s = String::from_utf8(attr.value.clone())
                .map_err(|_| ser_err("Internal Error : number was not UTF8."))?;
            ('N', s)
        } else if attr.type_id == BOOLEAN {
            let [b] = attr.value.as_slice() else {
                return Err(ser_err("Internal Error : boolean was not of length 1."));
            };
            ('L', if *b == 0 { "false" } else { "true" }.to_owned())
        } else {
            ('B', attr.encode())
        };
        ec.insert(key, value);
        legend.push(legend_char);
    }
    ec.insert(LEGEND, legend);
    Ok(ec)
}

/// Add `extra` to `ec`, and wrap `cmm` so the new entries are required and never stored.
fn require_context(
    ec: &mut EncryptionContext,
    extra: EncryptionContext,
    cmm: SharedCmm,
) -> Result<SharedCmm, Error> {
    if extra.is_empty() {
        return Ok(cmm);
    }
    if extra.keys().any(|k| ec.contains_key(k)) {
        return Err(val_err(
            "Internal Error - Structured Encryption encryption context overlaps with Item Encryptor encryption context.",
        ));
    }
    let keys: Vec<String> = extra.keys().map(str::to_owned).collect();
    for (k, v) in extra.iter() {
        ec.insert(k, v);
    }
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
    data: Vec<CryptoItem>,
    cmm: SharedCmm,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
) -> Result<(Vec<CryptoItem>, ParsedHeader), Error> {
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
        return Err(val_err(
            "At least one field in the Crypto Schema must be ENCRYPT_AND_SIGN, SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT or SIGN_ONLY.",
        ));
    }
    if data.iter().any(|x| is_header_path(&x.key)) {
        return Err(val_err(format!(
            "The paths {HEADER_FIELD} and {FOOTER_FIELD} are reserved."
        )));
    }
    if !has_no_duplicates(data.iter().map(|x| &x.key)) {
        return Err(val_err("Duplicate Paths"));
    }
    let mut ec = encryption_context.unwrap_or_default();
    let mut cmm = cmm;
    if data
        .iter()
        .any(|x| x.action == CryptoAction::SignAndIncludeInEncryptionContext)
    {
        let extra = v2_encryption_context(
            data.iter()
                .filter(|x| x.action == CryptoAction::SignAndIncludeInEncryptionContext)
                .map(|x| (x.key.as_slice(), &x.data)),
        )?;
        cmm = require_context(&mut ec, extra, cmm)?;
    }
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
    let max_length = u64::try_from(2 * encrypted_count + encrypted_size)
        .ok()
        .filter(|n| *n < u64::try_from(i64::MAX).unwrap_or(u64::MAX))
        .ok_or_else(|| val_err("Encrypted Size too long."))?;
    let suite_id = algorithm_suite_id.unwrap_or(DEFAULT_SUITE);
    let mat = cmm
        .get_encryption_materials()
        .encryption_context(ec)
        .commitment_policy(dbe_commitment_policy())
        .algorithm_suite_id(MplAlgorithmSuiteId::Dbe(suite_id))
        .max_plaintext_length(max_length)
        .send()
        .await?
        .into_encryption_materials();
    let key = mat
        .plaintext_data_key()
        .ok_or_else(|| materials_err("Encryption material has no key"))?;
    let suite = DbeSuite::new(mat.algorithm_suite_id())?;
    if !valid_encryption_context(mat.encryption_context()) {
        return Err(val_err("Bad encryption context"));
    }

    let mut msg_id = [0u8; MSGID_LEN];
    generate_random_bytes(&mut msg_id)?;
    let head = PartialHeader::create(&canon, msg_id, &mat)?;
    let commit = crypt::commit_key(suite, key.as_bytes(), &head.msg_id)?;
    let header_bytes = head.serialize_with_commitment(suite.commit, &commit)?;
    if u32::try_from(canon.len()).map_or(true, |n| n >= crypt::ONE_THIRD_MAX_INT) {
        return Err(val_err("Too many encrypted fields"));
    }
    let encrypted = crypt::crypt(Mode::Encrypt, suite, key.as_bytes(), &head.msg_id, canon)?;
    let footer = Footer::create(suite, &mat, &encrypted, &header_bytes)?;

    let header_suite = DbeSuite::from_flavor(head.flavor)?;
    let mut out: Vec<CryptoItem> = encrypted
        .into_iter()
        .map(|x| CryptoItem {
            key: x.key,
            data: x.data,
            action: x.action,
        })
        .collect();
    out.push(CryptoItem {
        key: header_path(),
        data: Terminal::new(BYTES_TYPE_ID, header_bytes),
        action: CryptoAction::DoNothing,
    });
    out.push(CryptoItem {
        key: footer_path(),
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
fn get_binary<'a>(data: &'a [AuthItem], name: &str) -> Result<&'a Terminal, Error> {
    let item = data
        .iter()
        .find(|x| x.key.len() == 1 && x.key[0] == name)
        .ok_or_else(|| ser_err(format!("The field name {name} is required.")))?;
    if item.data.type_id != BYTES_TYPE_ID {
        return Err(ser_err(format!("{name} must be a binary Terminal.")));
    }
    if item.action != AuthAction::DoNotSign {
        return Err(val_err(format!("{name} must be DO_NOT_SIGN.")));
    }
    Ok(&item.data)
}

/// Verify and decrypt `data` for `table`.
/// Returns the fields without the header and footer, each with the action the header recorded.
pub(crate) async fn decrypt_path_structure(
    table: &str,
    data: Vec<AuthItem>,
    cmm: SharedCmm,
    encryption_context: Option<EncryptionContext>,
) -> Result<(Vec<CryptoItem>, ParsedHeader), Error> {
    if !data.iter().any(|x| x.action == AuthAction::Sign) {
        return Err(val_err("At least one Authenticate Action must be SIGN"));
    }
    if !has_no_duplicates(data.iter().map(|x| &x.key)) {
        return Err(val_err("Duplicate Paths"));
    }
    let header_bytes = get_binary(&data, HEADER_FIELD)?.value.clone();
    let footer_bytes = get_binary(&data, FOOTER_FIELD)?.value.clone();
    let head = PartialHeader::deserialize(&header_bytes)?;
    let header_suite = DbeSuite::from_flavor(head.flavor)?;
    let canon = for_decrypt(table, data, &head.legend)?;

    let mut ec = encryption_context.unwrap_or_default();
    let mut cmm = cmm;
    if head.version == 2 {
        let extra = v2_encryption_context(
            canon
                .iter()
                .filter(|x| x.action == CryptoAction::SignAndIncludeInEncryptionContext)
                .map(|x| (x.key.as_slice(), &x.data)),
        )?;
        cmm = require_context(&mut ec, extra, cmm)?;
    }
    let mat = cmm
        .decrypt_materials()
        .algorithm_suite_id(MplAlgorithmSuiteId::Dbe(header_suite.id))
        .commitment_policy(dbe_commitment_policy())
        .encrypted_data_keys(head.data_keys.clone())
        .encryption_context(head.enc_context.clone())
        .reproduced_encryption_context(ec)
        .send()
        .await?
        .into_decryption_materials();
    if !valid_encryption_context(mat.encryption_context()) {
        return Err(val_err("Bad encryption context"));
    }
    let key = mat
        .plaintext_data_key()
        .ok_or_else(|| materials_err("Encryption material has no key"))?;
    let suite = DbeSuite::new(mat.algorithm_suite_id())?;
    let commit = crypt::commit_key(suite, key.as_bytes(), &head.msg_id)?;
    PartialHeader::verify_commitment(suite.commit, &commit, &header_bytes)?;
    let footer = Footer::deserialize(&footer_bytes, suite.signature != suite::Signature::None)?;
    footer.validate(&mat, head.data_keys.len(), &canon, &header_bytes)?;
    let decrypted = crypt::crypt(Mode::Decrypt, suite, key.as_bytes(), &head.msg_id, canon)?;
    let out = decrypted
        .into_iter()
        .filter(|x| !is_header_path(&x.key))
        .map(|x| CryptoItem {
            key: x.key,
            data: x.data,
            action: x.action,
        })
        .collect();
    let parsed = ParsedHeader {
        algorithm_suite_id: header_suite.id,
        encrypted_data_keys: head.data_keys,
        stored_encryption_context: head.enc_context,
        encryption_context: mat.encryption_context().clone(),
    };
    Ok((out, parsed))
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

fn sorted_keys<V>(map: &HashMap<String, V>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| util::utf16_cmp(a, b));
    keys
}

/// Split a list of single-member paths back into a map of fields and a map of signed actions.
fn unbuild(
    list: Vec<CryptoItem>,
) -> Result<(HashMap<String, Terminal>, HashMap<String, CryptoAction>), Error> {
    let mut data = HashMap::with_capacity(list.len());
    let mut schema = HashMap::with_capacity(list.len());
    for item in list {
        let [key] = <[String; 1]>::try_from(item.key)
            .map_err(|_| crate::error::internal_err("expected a top-level field"))?;
        if data.contains_key(&key) {
            return Err(val_err(format!("Duplicate Key {key}")));
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
    plaintext: &HashMap<String, Terminal>,
    schema: &HashMap<String, CryptoAction>,
    cmm: SharedCmm,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
) -> Result<StructureOutput, Error> {
    if plaintext.len() != schema.len() || plaintext.keys().any(|k| !schema.contains_key(k)) {
        return Err(val_err("Crypto Keys don't match."));
    }
    let list = sorted_keys(plaintext)
        .into_iter()
        .map(|k| CryptoItem {
            key: vec![k.clone()],
            data: plaintext[k].clone(),
            action: schema[k],
        })
        .collect();
    let (out, parsed_header) =
        encrypt_path_structure(table, list, cmm, algorithm_suite_id, encryption_context).await?;
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
    encrypted: &HashMap<String, Terminal>,
    schema: &HashMap<String, AuthAction>,
    cmm: SharedCmm,
    encryption_context: Option<EncryptionContext>,
) -> Result<StructureOutput, Error> {
    if encrypted.len() != schema.len() || encrypted.keys().any(|k| !schema.contains_key(k)) {
        return Err(val_err(
            "DecryptStructure requires encryptedStructure and authenticateSchema have the same keys.",
        ));
    }
    let list = sorted_keys(encrypted)
        .into_iter()
        .map(|k| AuthItem {
            key: vec![k.clone()],
            data: encrypted[k].clone(),
            action: schema[k],
        })
        .collect();
    let (out, parsed_header) = decrypt_path_structure(table, list, cmm, encryption_context).await?;
    let (data, schema) = unbuild(out)?;
    Ok(StructureOutput {
        data,
        schema,
        parsed_header,
    })
}
