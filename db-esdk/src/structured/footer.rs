// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The footer: one HMAC recipient tag per encrypted data key, then an optional ECDSA signature,
//! both over a hash of the header, the encryption context, and every signed field.

use aws_crypto_mpl::types::{DecryptionMaterials, EncryptionContext, EncryptionMaterials};
use aws_mpl_primitives::{
    DigestAlg, EcdsaSignatureAlgorithm, constant_time_equal, digest, ecdsa_sign, ecdsa_verify, hmac,
};

use super::header::serialize_context;
use super::suite::{DbeSuite, Signature};
use super::util::{BYTES_TYPE_ID, CanonItem, Terminal, u64_len};
use crate::error::{Error, crypt_err, materials_err, ser_err};
use crate::types::CryptoAction;

const RECIPIENT_TAG_SIZE: usize = 48;
/// The ECDSA P-384 signature length the reference implementation writes.
const SIGNATURE_SIZE: usize = 103;
const CANONICAL_HASH_SIZE: usize = 48;

const ENCRYPTED: &[u8] = b"ENCRYPTED";
const PLAINTEXT: &[u8] = b"PLAINTEXT";

/// A parsed or computed footer.
#[derive(Clone, Debug)]
pub(crate) struct Footer {
    tags: Vec<Vec<u8>>,
    sig: Option<Vec<u8>>,
}

/// Append the canonical form of `item` to `out`.
fn canonical_field(item: &CanonItem, out: &mut Vec<u8>) -> Result<(), Error> {
    let value = &item.data.value;
    out.extend_from_slice(&item.canon);
    if item.action == CryptoAction::EncryptAndSign {
        if value.len() < 2 {
            return Err(ser_err(
                "an encrypted attribute is too short to hold its type",
            ));
        }
        out.extend_from_slice(&u64_len(value.len() - 2).to_be_bytes());
        out.extend_from_slice(ENCRYPTED);
    } else {
        out.extend_from_slice(&u64_len(value.len()).to_be_bytes());
        out.extend_from_slice(PLAINTEXT);
        out.extend_from_slice(&item.data.type_id);
    }
    out.extend_from_slice(value);
    Ok(())
}

/// SHA-384 of the header, the encryption context, and every signed field in canonical order.
fn canon_hash(
    data: &[CanonItem],
    header: &[u8],
    ec: &EncryptionContext,
) -> Result<[u8; CANONICAL_HASH_SIZE], Error> {
    let aad = serialize_context(ec);
    let fields: usize = data
        .iter()
        .filter(|x| x.action != CryptoAction::DoNothing)
        .map(|x| x.canon.len() + 8 + PLAINTEXT.len() + 2 + x.data.value.len())
        .sum();
    let mut record = Vec::with_capacity(header.len() + 8 + aad.len() + fields);
    record.extend_from_slice(header);
    record.extend_from_slice(&u64_len(aad.len()).to_be_bytes());
    record.extend_from_slice(&aad);
    for item in data {
        if item.action != CryptoAction::DoNothing {
            canonical_field(item, &mut record)?;
        }
    }
    let mut out = [0u8; CANONICAL_HASH_SIZE];
    digest(DigestAlg::Sha384, &record, &mut out)?;
    Ok(out)
}

fn tag(key: &[u8], hash: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; RECIPIENT_TAG_SIZE];
    hmac(DigestAlg::Sha384, key, hash, &mut out)?;
    Ok(out)
}

impl Footer {
    /// Sign `data` (the encrypted fields) and `header` with the encryption materials.
    pub(crate) fn create(
        suite: DbeSuite,
        mat: &EncryptionMaterials,
        data: &[CanonItem],
        header: &[u8],
    ) -> Result<Self, Error> {
        let hash = canon_hash(data, header, mat.encryption_context())?;
        let keys = mat
            .symmetric_signing_keys()
            .ok_or_else(|| materials_err("Encryption materials have no symmetric signing keys"))?;
        if keys.len() != mat.encrypted_data_keys().len() {
            return Err(materials_err(
                "Encryption materials do not have one symmetric signing key per encrypted data key",
            ));
        }
        let tags = keys
            .iter()
            .map(|k| tag(k.as_bytes(), &hash))
            .collect::<Result<Vec<_>, Error>>()?;
        let sig = match suite.signature {
            Signature::EcdsaP384 => {
                let key = mat
                    .signing_key()
                    .ok_or_else(|| materials_err("Encryption materials have no signing key"))?;
                let mut sig = vec![0u8; SIGNATURE_SIZE];
                ecdsa_sign(
                    EcdsaSignatureAlgorithm::EcdsaP384,
                    key.as_bytes(),
                    &hash,
                    &mut sig,
                )?;
                Some(sig)
            }
            Signature::None => None,
        };
        Ok(Self { tags, sig })
    }

    /// The footer as the terminal stored in the item.
    pub(crate) fn into_terminal(self) -> Terminal {
        let mut out = Vec::with_capacity(self.tags.len() * RECIPIENT_TAG_SIZE + SIGNATURE_SIZE);
        for t in &self.tags {
            out.extend_from_slice(t);
        }
        if let Some(sig) = &self.sig {
            out.extend_from_slice(sig);
        }
        Terminal::new(BYTES_TYPE_ID, out)
    }

    /// Parse the stored footer; `has_sig` comes from the algorithm suite.
    pub(crate) fn deserialize(data: &[u8], has_sig: bool) -> Result<Self, Error> {
        let len = data.len();
        let (tags_data, sig) = if has_sig {
            if len < RECIPIENT_TAG_SIZE + SIGNATURE_SIZE {
                return Err(ser_err("the item's footer (aws_dbe_foot) is too short"));
            }
            if !(len - SIGNATURE_SIZE).is_multiple_of(RECIPIENT_TAG_SIZE) {
                return Err(ser_err(
                    "the item's footer (aws_dbe_foot) has the wrong length for an algorithm suite with ECDSA",
                ));
            }
            let (t, s) = data.split_at(len - SIGNATURE_SIZE);
            (t, Some(s.to_vec()))
        } else {
            if !len.is_multiple_of(RECIPIENT_TAG_SIZE) {
                return Err(ser_err(
                    "the item's footer (aws_dbe_foot) has the wrong length for an algorithm suite without ECDSA",
                ));
            }
            if len < RECIPIENT_TAG_SIZE {
                return Err(ser_err("the item's footer (aws_dbe_foot) is too short"));
            }
            (data, None)
        };
        let tags = tags_data
            .chunks(RECIPIENT_TAG_SIZE)
            .map(<[u8]>::to_vec)
            .collect();
        Ok(Self { tags, sig })
    }

    /// Check a recipient tag and the signature against `data` (the still-encrypted fields).
    pub(crate) fn validate(
        &self,
        mat: &DecryptionMaterials,
        edk_count: usize,
        data: &[CanonItem],
        header: &[u8],
    ) -> Result<(), Error> {
        if edk_count != self.tags.len() {
            return Err(ser_err(
                "the item's footer (aws_dbe_foot) has a different number of recipient tags than its header has encrypted data keys",
            ));
        }
        let hash = canon_hash(data, header, mat.encryption_context())?;
        let key = mat
            .symmetric_signing_key()
            .ok_or_else(|| materials_err("Decryption materials have no symmetric signing key"))?;
        let expected = tag(key.as_bytes(), &hash)?;
        if !self.tags.iter().any(|t| constant_time_equal(&expected, t)) {
            return Err(crypt_err(
                "Signature of record does not match the signature computed when the record was encrypted.",
            ));
        }
        let has_ecdsa = mat
            .algorithm_suite()
            .asymmetric_signature_algorithm()
            .is_some();
        if self.sig.is_some() != has_ecdsa {
            return Err(crypt_err(
                "the item's footer (aws_dbe_foot) does not match the algorithm suite: one has an ECDSA signature and the other does not",
            ));
        }
        if let Some(sig) = &self.sig {
            let key = mat
                .verification_key()
                .ok_or_else(|| materials_err("Decryption materials have no verification key"))?;
            if !ecdsa_verify(
                EcdsaSignatureAlgorithm::EcdsaP384,
                key.as_bytes(),
                &hash,
                sig,
            )? {
                return Err(crypt_err(
                    "the item's ECDSA signature did not verify: the item was changed after it was written",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "footer_tests.rs"]
mod tests;
