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
    if item.action == CryptoAction::EncryptAndSign {
        if value.len() < 2 {
            return Err(ser_err(
                "an encrypted attribute is too short to hold its type",
            ));
        }

        //= spec/structured-encryption/footer.md#canonical-encrypted-field
        //= reason=the encrypted value starts with the plaintext's 2-byte type ID
        //# The canonical form of an encrypted field MUST be
        //# | Field | Length (bytes) | Interpreted as |
        //# | ----- | -------------- | -------------- |
        //# | The [canonical path](./header.md#canonical-path) of the field name | Variable | Bytes |
        //# | encrypted data length - 2 | 8 | 64-bit integer |
        //# | "ENCRYPTED" | 9 | Literal Ascii text |
        //# | TypeID | 2 | the type ID of the unencrypted Terminal |
        //# | value | Variable | the encrypted Terminal value |
        out.extend_from_slice(&item.canon);
        out.extend_from_slice(&u64_len(value.len() - 2).to_be_bytes());
        out.extend_from_slice(ENCRYPTED);
    } else {
        //= spec/structured-encryption/footer.md#canonical-plaintext-field
        //# The canonical form of a plaintext field MUST be
        //# | Field | Length (bytes) | Interpreted as |
        //# | ----- | -------------- | -------------- |
        //# | The [canonical path](./header.md#canonical-path) of the field name | Variable | Bytes |
        //# | data length | 8 | 64-bit integer |
        //# | "PLAINTEXT" | 9 | Literal Ascii text |
        //# | TypeID | 2 | the type ID of the Terminal |
        //# | value | Variable | the Terminal value |
        out.extend_from_slice(&item.canon);
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
    debug_assert!(
        data.is_sorted_by(|a, b| a.canon <= b.canon),
        "fields must be sorted by canonical path"
    );
    let aad = serialize_context(ec);
    let fields: usize = data
        .iter()
        .filter(|x| x.action != CryptoAction::DoNothing)
        .map(|x| x.canon.len() + 8 + PLAINTEXT.len() + 2 + x.data.value.len())
        .sum();
    let mut record = Vec::with_capacity(header.len() + 8 + aad.len() + fields);

    //= spec/structured-encryption/footer.md#canonical-record
    //= reason=callers for_encrypt and for_decrypt sort fields by canonical path; the debug_assert checks it
    //# The canonical form of a record MUST be
    //# | Field | Length (bytes) | Interpreted as |
    //# | ----- | -------------- | -------------- |
    //# | header | Variable | The full serialized header with commitment |
    //# | AAD Length | 8 | 64-bit integer, the length of the following AAD data |
    //# | AAD | Variable | The serialization of the Encryption Context from the Encryption Materials |
    //# | Field Data | Variable | For each [signed field](#signed-fields), ordered lexicographically by [canonical path](./header.md#canonical-path), the [canonical field](#canonical-field).
    record.extend_from_slice(header);
    record.extend_from_slice(&u64_len(aad.len()).to_be_bytes());
    record.extend_from_slice(&aad);
    for item in data {
        //= spec/structured-encryption/structures.md#do-not-sign
        //# During [Encrypt Structure](./encrypt-structure.md),
        //# DO_NOT_SIGN signifies that the [Terminal Data](#terminal-data) MUST NOT be included in the signature calculations
        //# on the footer.
        //
        //= spec/structured-encryption/structures.md#do-not-sign
        //# During [Decrypt Structure](./decrypt-structure.md),
        //# DO_NOT_SIGN signifies that the [Terminal Data](#terminal-data) MUST NOT be authenticated,
        //# and thus not be included in the verification of the signatures on the footer.
        if item.action != CryptoAction::DoNothing {
            //= spec/structured-encryption/structures.md#sign
            //# During [Encrypt Structure](./encrypt-structure.md),
            //# SIGN signifies that the [Terminal Data](#terminal-data) MUST be included in the signature calculations
            //# on the footer.
            //
            //= spec/structured-encryption/structures.md#sign
            //# During [Decrypt Structure](./decrypt-structure.md),
            //# SIGN signifies that the [Terminal Data](#terminal-data) MUST be authenticated,
            //# and thus be included in the verification of the signatures on the footer.
            canonical_field(item, &mut record)?;
        }
    }
    let mut out = [0u8; CANONICAL_HASH_SIZE];

    //= spec/structured-encryption/footer.md#hash-calculation
    //# The canonical hash of a record MUST be the SHA384 of the canonical form of the record.
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
            //= spec/structured-encryption/footer.md#recipient-tags
            //# There MUST be one Recipient Tag for each Encrypted Data Key in the [header](./header.md#encrypted-data-keys)
            return Err(materials_err(
                "Encryption materials do not have one symmetric signing key per encrypted data key",
            ));
        }

        let mut tags = Vec::with_capacity(keys.len());
        for k in keys {
            //= spec/structured-encryption/footer.md#recipient-tags
            //= reason=every DBE suite's symmetric signature algorithm is HMAC-SHA-384, which tag() uses
            //# the Recipient Tag MUST be MUST be calculated over the [Canonical Hash](#canonical-hash)
            //# using the [symmetric signature algorithm](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#algorithm-suites-signature-settings)
            //# indicated in the algorithm suite,
            //# and the
            //# [symmetric signing keys](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#symmetric-signing-keys)
            //# in the encryption materials.
            let t = tag(k.as_bytes(), &hash)?;

            //= spec/structured-encryption/footer.md#recipient-tags
            //# the HMAC values MUST have the same order as the
            //# [symmetric signing keys](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#symmetric-signing-keys)
            //# used to calculate them.
            tags.push(t);
        }

        //= spec/structured-encryption/footer.md#signature
        //= reason=the header flavor comes from the same suite: 0x01 with ECDSA, 0x00 without
        //# The signature MUST be included in the footer if the flavor
        //# in the [header](./header.md#format-flavor) is 0x01
        //# and MUST NOT be included in the footer if the flavor
        //# in the [header](./header.md#format-flavor) is 0x00.
        let sig = match suite.signature {
            Signature::EcdsaP384 => {
                let key = mat
                    .signing_key()
                    .ok_or_else(|| materials_err("Encryption materials have no signing key"))?;
                let mut sig = vec![0u8; SIGNATURE_SIZE];

                //= spec/structured-encryption/footer.md#signature
                //# The `signature`, if it exists, MUST be calculated over the [Canonical Hash](#canonical-hash),
                //# using the asymmetric signing key in the encryption materials.
                //
                //= spec/structured-encryption/footer.md#signature
                //= reason=DbeSuite::new maps the suite's asymmetric signature algorithm to Signature::EcdsaP384
                //# The `signature`, if it exists, MUST be calculated using the
                //# [asymmetric signature algorithm](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#algorithm-suites-signature-settings)
                //# indicated by the algorithm suite.
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

        //= spec/structured-encryption/footer.md#footer-format
        //# The [Terminal Value](./structures.md#terminal-value) of the footer MUST be
        for t in &self.tags {
            out.extend_from_slice(t);
        }
        if let Some(sig) = &self.sig {
            out.extend_from_slice(sig);
        }

        //= spec/structured-encryption/encrypt-path-structure.md#footer-field
        //# The Footer Field TypeID MUST be 0xFFFF
        Terminal::new(BYTES_TYPE_ID, out)
    }

    /// Parse the stored footer; `has_sig` comes from the algorithm suite.
    pub(crate) fn deserialize(data: &[u8], has_sig: bool) -> Result<Self, Error> {
        let len = data.len();

        //= spec/structured-encryption/footer.md#footer-format
        //# The [Terminal Value](./structures.md#terminal-value) of the footer MUST be
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
            //= spec/structured-encryption/footer.md#recipient-tags
            //# There MUST be one Recipient Tag for each Encrypted Data Key in the [header](./header.md#encrypted-data-keys)
            //
            //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
            //# The number of [HMACs in the footer](./footer.md#hmacs)
            //# MUST be the number of [Encrypted Data Keys in the header](./header.md#encrypted-data-keys).
            return Err(ser_err(
                "the item's footer (aws_dbe_foot) has a different number of recipient tags than its header has encrypted data keys",
            ));
        }
        let hash = canon_hash(data, header, mat.encryption_context())?;
        let key = mat
            .symmetric_signing_key()
            .ok_or_else(|| materials_err("Decryption materials have no symmetric signing key"))?;
        let expected = tag(key.as_bytes(), &hash)?;

        //= spec/structured-encryption/footer.md#recipient-tag-verification
        //= type=implication
        //= reason=constant_time_equal is the primitives library's constant-time comparison
        //# Recipient Tag comparisons MUST be constant time operations.
        if !self.tags.iter().any(|t| constant_time_equal(&expected, t)) {
            //= spec/structured-encryption/footer.md#recipient-tag-verification
            //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
            //# matches a calculated recipient tag using the provided symmetricSigningKey.
            return Err(crypt_err(
                "Signature of record does not match the signature computed when the record was encrypted.",
            ));
        }
        let has_ecdsa = mat
            .algorithm_suite()
            .asymmetric_signature_algorithm()
            .is_some();
        if self.sig.is_some() != has_ecdsa {
            //= spec/structured-encryption/footer.md#signature
            //= reason=the decryption materials' suite is the one the header flavor names
            //# The signature MUST be included in the footer if the flavor
            //# in the [header](./header.md#format-flavor) is 0x01
            //# and MUST NOT be included in the footer if the flavor
            //# in the [header](./header.md#format-flavor) is 0x00.
            return Err(crypt_err(
                "the item's footer (aws_dbe_foot) does not match the algorithm suite: one has an ECDSA signature and the other does not",
            ));
        }
        if let Some(sig) = &self.sig {
            let key = mat
                .verification_key()
                .ok_or_else(|| materials_err("Decryption materials have no verification key"))?;

            //= spec/structured-encryption/footer.md#signature-verification
            //= reason=a suite with an asymmetric signature uses ECDSA P-384; presence was matched to the suite above
            //# If the footer contains a signature, this signature MUST be verified using the
            //# [asymmetric signature algorithm](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#algorithm-suites-signature-settings)
            //# indicated by the algorithm suite.
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
