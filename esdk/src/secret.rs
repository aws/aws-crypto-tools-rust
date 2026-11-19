// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Confinement of the plaintext data key and the message encryption key (VR-011).
//!
//! This module is the only esdk code that reads the bytes of the plaintext
//! data key or of the keys derived from it. Everywhere else they are opaque:
//!
//! - [`DataKeyRef`] borrows the plaintext data key held by the encryption or
//!   decryption materials, so no second copy exists.
//! - [`MessageKey`] is the derived message encryption key (the AES-GCM key).
//! - [`CommitmentValue`] is the V2 key commitment value. It is derived from the
//!   data key, but the message format writes it to the header, so it is public
//!   by spec. It becomes plain bytes only through [`CommitmentValue::as_suite_data`]
//!   (decrypt-side comparison) and [`PublicBytes::from_commitment`] (encrypt-side
//!   header suite data): these are the declassification points.
//!
//! None of these types derives `Clone`, `PartialEq` or `Debug`, and their fields
//! are private. Outside this module, the only exec accessor on [`MessageKey`]
//! and [`DataKeyRef`] is `len()`; the key length is public by design.
//! `MessageKey::zeroed` and `CommitmentValue::zeroed` are constructors, not
//! accessors. The exception is [`CommitmentValue`], whose only exec accessor is
//! the declassification [`CommitmentValue::as_suite_data`]. These facts come from Rust privacy and
//! review of this module (which also holds the unverified TB-A adapters that
//! read the private fields directly), plus the clippy `disallowed-methods` rule
//! in `esdk/clippy.toml`, which confines esdk's calls to the mpl data-key
//! accessors to the two ingress adapters below. They are not a Verus proof:
//! Verus does not check that a function is absent.
//!
//! The types and their verified accessors sit inside `verus!`. Verus checks
//! only that each verified accessor's result satisfies its `ensures` against
//! the closed `view()`, and that a [`PublicBytes`] is always labelled
//! [`Label::Public`] (its type invariant).
//!
//! # Trusted base (TB-A)
//!
//! The functions below read secret bytes and call mpl or prim, which Verus
//! cannot see, so they live outside `verus!` and are not verified. They are
//! the audited trusted base for VR-011:
//!
//! - [`data_key_from_encryption_materials`]: encrypt-side ingress from mpl.
//! - [`data_key_from_decryption_materials`]: decrypt-side ingress from mpl.
//! - [`identity_copy`]: the identity KDF (copies the data key into a [`MessageKey`]).
//! - [`hkdf_v1`]: V1 HKDF from the data key into a [`MessageKey`].
//! - [`hkdf_v2_extract`]: V2 HKDF-Extract over the data key.
//! - [`hkdf_v2_expand_key`]: V2 HKDF-Expand into the [`MessageKey`].
//! - [`hkdf_v2_expand_commitment`]: V2 HKDF-Expand into the [`CommitmentValue`].
//! - [`seal`]: AES-GCM encryption under a [`MessageKey`].
//! - [`open`]: AES-GCM decryption under a [`MessageKey`]. It takes its
//!   ciphertext and plaintext buffer as one [`OpenBuffers`], built only by
//!   the verified [`open_buffers`], so Verus proves the plaintext buffer is
//!   exactly as long as the ciphertext at every esdk decryption (VR-016).
//!   Trusted: the body of `open` passes the two buffers to `aes_decrypt`
//!   unchanged.
//!
//! With the `test-internals` feature, `data_key_from_slice_for_tests`,
//! `expose_message_key_for_tests` and `expose_commitment_for_tests` also read or
//! build key bytes. They exist only for esdk's own integration tests and are out
//! of scope for VR-011.

use crate::error::{Error, Kind, err};
use aws_crypto_mpl::types::{DecryptionMaterials, EncryptionMaterials};
use aws_mpl_primitives::{
    AesGcm, DigestAlg, Prk, aes_decrypt, aes_encrypt, hkdf, hkdf_expand, hkdf_extract,
};
use vstd::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

verus! {

/// The secrecy label of a value. Used only in ghost code; its values are
/// erased in the cargo build, hence the `dead_code` allowance.
#[allow(
    dead_code,
    reason = "ghost-only: Verus erases every use of the variants in the cargo build"
)]
pub(crate) ghost enum Label {
    /// The value may be written to the output.
    Public,
    /// The value is, or is derived from, the plaintext data key.
    Secret,
}

/// A borrow of the plaintext data key held by the encryption or decryption
/// materials. Only this module can build one or read its bytes.
pub(crate) struct DataKeyRef<'a> {
    bytes: &'a [u8],
}

impl DataKeyRef<'_> {
    /// The key bytes, for specs only.
    pub(crate) closed spec fn view(&self) -> Seq<u8> {
        self.bytes@
    }

    /// The plaintext data key is secret.
    pub(crate) open spec fn label(&self) -> Label {
        Label::Secret
    }

    /// The key length in bytes. Lengths are public by design.
    pub(crate) fn len(&self) -> (n: usize)
        ensures
            n == self.view().len(),
    {
        self.bytes.len()
    }
}

/// The derived message encryption key: the AES-GCM key for the header
/// authentication tag and every body frame. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct MessageKey {
    bytes: Vec<u8>,
}

impl MessageKey {
    /// The key bytes, for specs only.
    pub(crate) closed spec fn view(&self) -> Seq<u8> {
        self.bytes@
    }

    /// The message key is secret.
    pub(crate) open spec fn label(&self) -> Label {
        Label::Secret
    }

    /// An all-zero key of `len` bytes, to be filled by a key derivation adapter.
    pub(crate) fn zeroed(len: usize) -> (k: Self)
        ensures
            k.view() == Seq::new(len as nat, |_i: int| 0u8),
    {
        Self { bytes: zero_vec(len) }
    }

    /// The key length in bytes. Lengths are public by design.
    pub(crate) fn len(&self) -> (n: usize)
        ensures
            n == self.view().len(),
    {
        self.bytes.len()
    }
}

/// The V2 key commitment value. Derived from the data key, but public by spec:
/// the message header carries it as suite data. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct CommitmentValue {
    bytes: Vec<u8>,
}

impl CommitmentValue {
    /// The commitment bytes, for specs only.
    pub(crate) closed spec fn view(&self) -> Seq<u8> {
        self.bytes@
    }

    /// The commitment value is derived from the data key, so it is labelled
    /// secret until it is declassified by `as_suite_data` or
    /// `PublicBytes::from_commitment`.
    pub(crate) open spec fn label(&self) -> Label {
        Label::Secret
    }

    /// An all-zero value of `len` bytes, to be filled by a key derivation adapter.
    pub(crate) fn zeroed(len: usize) -> (c: Self)
        ensures
            c.view() == Seq::new(len as nat, |_i: int| 0u8),
    {
        Self { bytes: zero_vec(len) }
    }

    /// Declassification: the commitment value as header suite data, for the
    /// decrypt-side comparison with the header.
    pub(crate) fn as_suite_data(&self) -> (s: &[u8])
        ensures
            s@ == self.view(),
    {
        self.bytes.as_slice()
    }
}

/// Bytes that may be written to the output. The only constructor is
/// [`PublicBytes::from_commitment`], so every value is the declassified
/// commitment value.
pub(crate) struct PublicBytes {
    v: Vec<u8>,
    #[allow(dead_code, reason = "ghost field: read only by the type invariant")]
    lab: Ghost<Label>,
}

impl PublicBytes {
    /// The bytes, for specs only.
    pub(crate) closed spec fn view(&self) -> Seq<u8> {
        self.v@
    }

    /// Whether the value is labelled public.
    pub(crate) closed spec fn is_public(&self) -> bool {
        self.lab@ == Label::Public
    }

    /// Every `PublicBytes` is labelled public.
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self.is_public()
    }

    /// Declassification: the commitment value, which the message format writes
    /// to the header as suite data.
    pub(crate) fn from_commitment(c: &CommitmentValue) -> (p: Self)
        ensures
            p.view() == c.view(),
            p.is_public(),
    {
        Self { v: copy_vec(&c.bytes), lab: Ghost(Label::Public) }
    }

    /// The length in bytes.
    pub(crate) fn len(&self) -> (n: usize)
        ensures
            n == self.view().len(),
    {
        self.v.len()
    }

    /// The bytes, for storing in the header.
    pub(crate) fn into_vec(self) -> (v: Vec<u8>)
        ensures
            v@ == self.view(),
    {
        self.v
    }
}

/// The two buffers for one AES-GCM decryption (VR-016): the ciphertext and
/// a plaintext buffer of exactly the same length. Only [`open_buffers`] can
/// build one, and [`open`] accepts nothing else, so every esdk decryption
/// passes `aes_decrypt` a plaintext buffer as long as its ciphertext.
pub(crate) struct OpenBuffers<'a> {
    cipher_text: &'a [u8],
    plain_text: Vec<u8>,
}

#[expect(
    single_use_lifetimes,
    clippy::elidable_lifetime_names,
    reason = "Verus needs a named lifetime on an impl that holds a type invariant"
)]
impl<'a> OpenBuffers<'a> {
    /// The ciphertext, for specs only.
    pub(crate) closed spec fn cipher(&self) -> Seq<u8> {
        self.cipher_text@
    }

    /// The length of the plaintext buffer, for specs only.
    pub(crate) closed spec fn plain_len(&self) -> nat {
        self.plain_text@.len()
    }

    /// The plaintext buffer is exactly as long as the ciphertext.
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self.plain_len() == self.cipher().len()
    }
}

/// Every `OpenBuffers` has a plaintext buffer exactly as long as its
/// ciphertext.
pub(crate) proof fn lemma_open_buffers_sized(tracked b: &OpenBuffers<'_>)
    ensures
        b.plain_len() == b.cipher().len(),
{
    use_type_invariant(b);
}

/// Pairs `cipher_text` with `plain_text` resized to the ciphertext length.
/// The caller may pass any Vec; it is reused, so no new allocation is needed
/// when it is already large enough.
pub(crate) fn open_buffers(cipher_text: &[u8], plain_text: Vec<u8>) -> (r: OpenBuffers<'_>)
    ensures
        r.cipher() == cipher_text@,
        r.plain_len() == cipher_text@.len(),
{
    let mut plain_text = plain_text;
    plain_text.resize(cipher_text.len(), 0);
    OpenBuffers { cipher_text, plain_text }
}

/// A vector of `len` zero bytes.
fn zero_vec(len: usize) -> (v: Vec<u8>)
    ensures
        v@ == Seq::new(len as nat, |_i: int| 0u8),
{
    let mut v: Vec<u8> = Vec::with_capacity(len);
    let mut i: usize = 0;
    while i < len
        invariant
            i <= len,
            v@ == Seq::new(i as nat, |_j: int| 0u8),
        decreases len - i,
    {
        v.push(0u8);
        i += 1;
        assert(v@ =~= Seq::new(i as nat, |_j: int| 0u8));
    }
    v
}

/// A copy of `src`.
fn copy_vec(src: &[u8]) -> (v: Vec<u8>)
    ensures
        v@ == src@,
{
    let mut v: Vec<u8> = Vec::with_capacity(src.len());
    let mut i: usize = 0;
    while i < src.len()
        invariant
            i <= src.len(),
            v@ == src@.subrange(0, i as int),
        decreases src.len() - i,
    {
        v.push(src[i]);
        i += 1;
        assert(v@ =~= src@.subrange(0, i as int));
    }
    assert(v@ =~= src@);
    v
}

} // verus!

// ---------------------------------------------------------------------------
// TB-A: unverified adapters. These are the only esdk functions that read the
// bytes of a `DataKeyRef`, `MessageKey` or `CommitmentValue` (apart from the
// declassifications above). Each is a thin wrapper with the error mapping its
// caller had before.
// ---------------------------------------------------------------------------

/// Ingress: borrows the plaintext data key from the encryption materials.
///
/// # Errors
///
/// `InvalidMaterials` if the materials carry no plaintext data key.
#[expect(
    clippy::disallowed_methods,
    reason = "VR-011: the single encrypt-side read of the plaintext data key"
)]
pub(crate) fn data_key_from_encryption_materials(
    materials: &EncryptionMaterials,
) -> Result<DataKeyRef<'_>, Error> {
    let pdk = materials.plaintext_data_key().ok_or_else(|| {
        err(
            Kind::InvalidMaterials,
            "encryption materials must contain a plaintext data key",
        )
    })?;
    Ok(DataKeyRef {
        bytes: pdk.as_bytes(),
    })
}

/// Ingress: borrows the plaintext data key from the decryption materials.
///
/// # Errors
///
/// `InvalidMaterials` if the materials carry no plaintext data key.
#[expect(
    clippy::disallowed_methods,
    reason = "VR-011: the single decrypt-side read of the plaintext data key"
)]
pub(crate) fn data_key_from_decryption_materials(
    materials: &DecryptionMaterials,
) -> Result<DataKeyRef<'_>, Error> {
    let pdk = materials.plaintext_data_key().ok_or_else(|| {
        err(
            Kind::InvalidMaterials,
            "decryption materials must contain a plaintext data key",
        )
    })?;
    Ok(DataKeyRef {
        bytes: pdk.as_bytes(),
    })
}

/// The identity KDF: the message key is a copy of the data key.
pub(crate) fn identity_copy(key: &DataKeyRef<'_>) -> MessageKey {
    MessageKey {
        bytes: key.bytes.to_vec(),
    }
}

/// V1 HKDF (extract and expand) from the data key into `out`, which sets the
/// output length. Mirrors `aws_mpl_primitives::hkdf`.
///
/// # Errors
///
/// As `aws_mpl_primitives::hkdf`.
pub(crate) fn hkdf_v1(
    alg: DigestAlg,
    salt: &[u8],
    key: &DataKeyRef<'_>,
    info: &[&[u8]],
    out: &mut MessageKey,
) -> Result<(), aws_mpl_primitives::Error> {
    hkdf(alg, salt, key.bytes, info, &mut out.bytes[..])
}

/// V2 HKDF-Extract with the data key as input keying material.
/// Mirrors `aws_mpl_primitives::hkdf_extract`.
pub(crate) fn hkdf_v2_extract(alg: DigestAlg, salt: &[u8], key: &DataKeyRef<'_>) -> Prk {
    hkdf_extract(alg, salt, key.bytes)
}

/// V2 HKDF-Expand into the message key `out`, which sets the output length.
/// Mirrors `aws_mpl_primitives::hkdf_expand`.
///
/// # Errors
///
/// As `aws_mpl_primitives::hkdf_expand`.
pub(crate) fn hkdf_v2_expand_key(
    prk: &Prk,
    info: &[&[u8]],
    out: &mut MessageKey,
) -> Result<(), aws_mpl_primitives::Error> {
    hkdf_expand(prk, info, &mut out.bytes[..])
}

/// V2 HKDF-Expand into the commitment value `out`, which sets the output
/// length. Mirrors `aws_mpl_primitives::hkdf_expand`.
///
/// # Errors
///
/// As `aws_mpl_primitives::hkdf_expand`.
pub(crate) fn hkdf_v2_expand_commitment(
    prk: &Prk,
    info: &[&[u8]],
    out: &mut CommitmentValue,
) -> Result<(), aws_mpl_primitives::Error> {
    hkdf_expand(prk, info, &mut out.bytes[..])
}

/// AES-GCM encryption under the message key. Mirrors
/// `aws_mpl_primitives::aes_encrypt`: `cipher_text` is extended with the
/// ciphertext followed by the tag.
///
/// # Errors
///
/// As `aws_mpl_primitives::aes_encrypt`.
pub(crate) fn seal(
    alg: AesGcm,
    iv: &[u8],
    key: &MessageKey,
    message: &[u8],
    aad: &[u8],
    cipher_text: &mut Vec<u8>,
) -> Result<(), aws_mpl_primitives::Error> {
    aes_encrypt(alg, iv, &key.bytes, message, aad, cipher_text)
}

/// AES-GCM decryption under the message key. Mirrors
/// `aws_mpl_primitives::aes_decrypt`, but takes its ciphertext and plaintext
/// buffer as one [`OpenBuffers`], whose plaintext buffer Verus proves is as
/// long as the ciphertext (VR-016). Returns the plaintext buffer.
///
/// # Errors
///
/// As `aws_mpl_primitives::aes_decrypt`.
pub(crate) fn open(
    alg: AesGcm,
    key: &MessageKey,
    bufs: OpenBuffers<'_>,
    auth_tag: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, aws_mpl_primitives::Error> {
    let OpenBuffers {
        cipher_text,
        mut plain_text,
    } = bufs;
    aes_decrypt(
        alg,
        &key.bytes,
        cipher_text,
        auth_tag,
        iv,
        aad,
        &mut plain_text[..],
    )?;
    Ok(plain_text)
}

/// Test-only: a `DataKeyRef` over caller bytes, so esdk's integration tests can
/// call the key derivation directly. Out of scope for VR-011.
#[cfg(feature = "test-internals")]
pub(crate) fn data_key_from_slice_for_tests(bytes: &[u8]) -> DataKeyRef<'_> {
    DataKeyRef { bytes }
}

/// Test-only: a copy of the message key bytes. Out of scope for VR-011.
#[cfg(feature = "test-internals")]
pub(crate) fn expose_message_key_for_tests(key: &MessageKey) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(key.bytes.clone())
}

/// Test-only: a copy of the commitment value bytes. Out of scope for VR-011.
#[cfg(feature = "test-internals")]
pub(crate) fn expose_commitment_for_tests(value: &CommitmentValue) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(value.bytes.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroed_keys_have_the_requested_length() {
        for len in [0, 16, 24, 32] {
            let k = MessageKey::zeroed(len);
            assert_eq!(k.len(), len);
            assert!(k.bytes.iter().all(|b| *b == 0));
            let c = CommitmentValue::zeroed(len);
            assert_eq!(c.as_suite_data(), vec![0u8; len].as_slice());
        }
    }

    #[test]
    fn data_key_ref_len_is_the_borrowed_length() {
        let pdk = [7u8; 32];
        let k = DataKeyRef { bytes: &pdk };
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn commitment_declassifies_to_the_same_bytes() {
        let c = CommitmentValue {
            bytes: (0u8..32).collect(),
        };
        let expected: Vec<u8> = (0u8..32).collect();
        assert_eq!(c.as_suite_data(), expected.as_slice());
        let p = PublicBytes::from_commitment(&c);
        assert_eq!(p.len(), 32);
        assert_eq!(p.into_vec(), expected);
    }

    #[test]
    fn identity_copy_copies_the_data_key() {
        let pdk: Vec<u8> = (0u8..32).collect();
        let k = identity_copy(&DataKeyRef { bytes: &pdk });
        assert_eq!(k.bytes, pdk);
    }
}
