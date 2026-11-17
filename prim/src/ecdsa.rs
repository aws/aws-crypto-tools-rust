// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::DigestAlg;
use crate::Error;
use crate::err;
use crate::serr;

use vstd::prelude::*;

use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::encoding::EcPrivateKeyRfc5915Der;
use aws_lc_rs::encoding::EcPublicKeyCompressedBin;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::EcdsaKeyPair;
use aws_lc_rs::signature::EcdsaSigningAlgorithm;
use aws_lc_rs::signature::EcdsaVerificationAlgorithm;
use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::signature::UnparsedPublicKey;

/// Gathers Digest Data
#[derive(Clone)]
pub struct DigestContext {
    context: aws_lc_rs::digest::Context,
}

impl std::fmt::Debug for DigestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DigestContext {:?}", self.context.algorithm())
    }
}

impl DigestContext {
    /// Create new `DigestContext` from the given algorithm
    ///
    /// # Errors
    ///
    /// Every [`DigestAlg`] maps to a supported digest, so this currently
    /// always returns [`Ok`]. The fallible signature is retained so a future
    /// algorithm that requires runtime availability checks does not become a
    /// breaking change.
    pub fn new(alg: DigestAlg) -> Result<Self, Error> {
        let alg = crate::get_digest_alg(alg);
        Ok(Self {
            context: aws_lc_rs::digest::Context::new(alg),
        })
    }

    /// Create new `DigestContext` from the digest paired with the given
    /// ECDSA signature algorithm
    ///
    /// # Errors
    ///
    /// Every [`EcdsaSignatureAlgorithm`] maps to a supported digest, so this
    /// currently always returns [`Ok`]. The fallible signature is retained
    /// for the same reason as [`DigestContext::new`].
    pub fn new_from_ecdsa(alg: EcdsaSignatureAlgorithm) -> Result<Self, Error> {
        let alg = get_digest_alg_from_ecdsa(alg);
        Ok(Self {
            context: aws_lc_rs::digest::Context::new(alg),
        })
    }

    /// Update with more bytes
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Length in bytes of the digest [`DigestContext::finish`] produces.
    #[must_use]
    pub fn output_len(&self) -> usize {
        self.context.algorithm().output_len()
    }

    /// Finalize and write the digest into `out`.
    ///
    /// `out` must be exactly [`DigestContext::output_len`] bytes.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if `out` is not exactly
    /// [`DigestContext::output_len`] bytes.
    pub fn finish(self, out: &mut [u8]) -> Result<(), Error> {
        // The guard and the copy live in the verified `digest_finish_core`
        // (VR-013(b)); `out` is unchanged on Err.
        if let Err(crate::OutLenMismatch { want_len }) = digest_finish_core(self.context, out) {
            return err(format!(
                "output buffer of {} bytes does not match the {want_len} byte digest",
                out.len()
            ));
        }
        Ok(())
    }

    fn digest(self) -> aws_lc_rs::digest::Digest {
        self.context.finish()
    }
}

/// Which ECDSA Algorithm to use
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EcdsaSignatureAlgorithm {
    /// 384 bit ECDSA
    #[default]
    EcdsaP384,
    /// 256 bit ECDSA
    EcdsaP256,
}

const fn get_digest_alg_from_ecdsa(
    x: EcdsaSignatureAlgorithm,
) -> &'static aws_lc_rs::digest::Algorithm {
    match x {
        EcdsaSignatureAlgorithm::EcdsaP256 => &aws_lc_rs::digest::SHA256,
        EcdsaSignatureAlgorithm::EcdsaP384 => &aws_lc_rs::digest::SHA384,
    }
}

const fn get_sign_alg(x: EcdsaSignatureAlgorithm) -> &'static EcdsaSigningAlgorithm {
    match x {
        EcdsaSignatureAlgorithm::EcdsaP256 => &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        EcdsaSignatureAlgorithm::EcdsaP384 => &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
    }
}

const fn get_ver_alg(x: EcdsaSignatureAlgorithm) -> &'static EcdsaVerificationAlgorithm {
    match x {
        EcdsaSignatureAlgorithm::EcdsaP256 => &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        EcdsaSignatureAlgorithm::EcdsaP384 => &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1,
    }
}

/// The DER-encoded signature length [`ecdsa_sign`] emits for `alg`: 71
/// bytes for P-256, 103 for P-384.
///
/// A `match` on the algorithm rather than a comparison against the
/// `aws-lc-rs` constants, so adding a curve to the `#[non_exhaustive]`
/// [`EcdsaSignatureAlgorithm`] is a compile error instead of a signing
/// operation that can never satisfy its length check.
#[must_use]
pub const fn signature_len(alg: EcdsaSignatureAlgorithm) -> usize {
    match alg {
        EcdsaSignatureAlgorithm::EcdsaP256 => 71,
        EcdsaSignatureAlgorithm::EcdsaP384 => 103,
    }
}

verus! {

// Trusted boundary: `aws-lc-rs`'s `Signature` is an external type Verus
// cannot see into, so we model it as opaque (the sanctioned way to name an
// FFI type inside `verus!` — not an escape hatch over our own proof). Nothing
// is assumed about its contents; only `as_ref`'s length, below, is used.
//
// `ExSignature` is the Verus spec handle for the external type, never a value
// the crate constructs or exposes, so the crate's Debug/docs lints do not
// apply to it.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code)]
pub struct ExSignature(aws_lc_rs::signature::Signature);

// Trusted boundary: the candidate signature's byte view. Its length is left
// unconstrained — the proof does not assume anything about how long a signed
// candidate is; it only compares that length against `want_len` at runtime
// and copies when they are equal.
pub assume_specification[ <aws_lc_rs::signature::Signature as AsRef<[u8]>>::as_ref ](
    s: &aws_lc_rs::signature::Signature,
) -> &[u8];

// `<[u8]>::copy_from_slice`. vstd carries this exact specification (in
// `vstd::std_specs::slice`), but this toolchain does not register it for a
// downstream crate, so it is restated here verbatim. The `requires` is the
// std precondition — equal destination and source lengths — which is exactly
// what makes the copy panic-free; this declaration does not weaken it.
pub assume_specification<T: Copy>[ <[T]>::copy_from_slice ](dst: &mut [T], src: &[T])
    requires
        old(dst)@.len() == src@.len(),
    ensures
        final(dst)@ == src@;

/// The verified core of [`DigestContext::finish`] (VR-013(b), pipeline
/// target VR-2026-C03).
///
/// Returns `Err` unless `out.len()` equals the context's output length, and
/// only then finalizes the digest and copies it. Verus proves the copy is in
/// bounds from the guard and the trusted length fact A5 (see
/// `aws_lc_specs`). Panic freedom of the finalize itself rests on A5: the
/// aws-lc-rs `expect("EVP_DigestFinal failed")` is trusted unreachable. On
/// `Err`, `out` is unchanged and the context is dropped without finalizing,
/// as before.
fn digest_finish_core(
    context: aws_lc_rs::digest::Context,
    out: &mut [u8],
) -> (r: Result<(), crate::OutLenMismatch>)
    ensures
        (r is Ok) <==> old(out)@.len() == crate::aws_lc_specs::spec_context_output_len(&context),
        r matches Err(e) ==> e.want_len == crate::aws_lc_specs::spec_context_output_len(&context)
            && final(out)@ == old(out)@,
        r is Ok ==> final(out)@.len() == old(out)@.len(),
{
    let want_len = context.algorithm().output_len();
    if out.len() != want_len {
        return Err(crate::OutLenMismatch { want_len });
    }
    let d = context.finish();
    out.copy_from_slice(d.as_ref());
    Ok(())
}

/// Maximum number of signing attempts made while looking for a DER
/// signature of the canonical length (see [`sign_fixed_len`]).
///
/// Each attempt succeeds with probability 1/2, which follows from the
/// encoding rather than from measurement. `r` and `s` are each encoded as a
/// DER INTEGER, and each independently takes a leading `0x00` byte exactly
/// when its high bit is set — probability 1/2 apiece. So a signature runs
/// one byte long when both take the pad (1/4), one byte short when neither
/// does (1/4), and lands on the canonical length when exactly one does
/// (1/2). An `r` or `s` whose top byte is zero shortens it further, which
/// shifts the rate by about 1/256.
///
/// At p = 1/2, exhausting 128 attempts has probability 2^-128, negligible
/// against the other failure modes of signing. The expected number of
/// attempts is 2, so a bound this loose costs nothing in practice.
///
/// Defined inside `verus!` so it can bound the verified retry loop
/// (`decreases MAX_SIGN_ATTEMPTS - attempt`); this is the single definition,
/// erased to a plain `const` for the cargo build.
const MAX_SIGN_ATTEMPTS: u32 = 128;

/// Why the verified retry core ([`sign_fixed_len_core`]) stopped without
/// writing a signature. Defined inside `verus!` so the crate [`Error`] type —
/// which Verus does not model — never enters the verified region; the
/// unverified adapter [`sign_fixed_len`] maps each variant to the [`Error`]
/// (same kind, same message) the callers had before.
enum SignCoreError {
    /// A single signing attempt (the external `aws-lc-rs` call) failed.
    Failed,
    /// No candidate of the required length appeared within [`MAX_SIGN_ATTEMPTS`].
    Exhausted,
}

/// The verified core of the bounded signing retry: call `sign_once` until it
/// yields a DER signature of exactly `signature.len()` bytes, write it into
/// `signature`, and give up after [`MAX_SIGN_ATTEMPTS`].
///
/// Two panic-freedom properties are proven in place by Verus (VR-008):
///
/// - **Termination.** The `while` loop counts `attempt` up from 0 and stops
///   at [`MAX_SIGN_ATTEMPTS`]; the `decreases MAX_SIGN_ATTEMPTS - attempt`
///   clause, with the `attempt <= MAX_SIGN_ATTEMPTS` invariant, is what Verus
///   checks to prove the bounded retry always terminates — it can run at most
///   [`MAX_SIGN_ATTEMPTS`] times.
/// - **No out-of-bounds copy.** `signature.copy_from_slice(candidate_bytes)`
///   runs only inside the `candidate_bytes.len() == want_len` guard, and
///   vstd's `copy_from_slice` specification requires the destination and
///   source lengths to be equal. The loop invariant carries `want_len ==
///   signature.len()`, so under the guard the lengths are equal and Verus
///   proves the write is in bounds. [`check_sig_len`] has already pinned
///   `signature.len()` to [`signature_len`] for the algorithm before signing
///   begins.
///
/// No crypto property is proven: `sign_once` runs the external `aws-lc-rs`
/// signing operation and its result is trusted. Only the loop bound and the
/// buffer write are machine-checked.
fn sign_fixed_len_core<F: FnMut() -> Result<aws_lc_rs::signature::Signature, SignCoreError>>(
    signature: &mut [u8],
    mut sign_once: F,
) -> Result<(), SignCoreError>
    requires
        // The closure is always callable: it takes no argument and carries no
        // precondition. This is a property of the closure, not an assumption
        // about its result — the proof never inspects what it returns.
        forall|f: F| #[trigger] call_requires(f, ()),
{
    let want_len = signature.len();
    let mut attempt: u32 = 0;
    while attempt < MAX_SIGN_ATTEMPTS
        invariant
            attempt <= MAX_SIGN_ATTEMPTS,
            want_len == signature@.len(),
            forall|f: F| #[trigger] call_requires(f, ()),
        decreases MAX_SIGN_ATTEMPTS - attempt,
    {
        // The loop invariant says the closure is callable for every value of
        // `F`; instantiating it at the current `sign_once` discharges the
        // call's precondition. No assumption is made about the result.
        assert(call_requires(sign_once, ()));
        let candidate = sign_once()?;
        let candidate_bytes: &[u8] = candidate.as_ref();
        if candidate_bytes.len() == want_len {
            // Guard gives `candidate_bytes.len() == want_len`; the invariant
            // gives `want_len == signature.len()`. So the two lengths are
            // equal and vstd's `copy_from_slice` precondition holds — the
            // write is proven in bounds.
            signature.copy_from_slice(candidate_bytes);
            return Ok(());
        }
        attempt += 1;
    }
    Err(SignCoreError::Exhausted)
}

} // verus!

/// Call `sign_once` until it produces a DER signature of exactly
/// `signature.len()` bytes, writing it into `signature` and giving up after
/// [`MAX_SIGN_ATTEMPTS`].
///
/// The DER encoding of an ECDSA signature varies in length because `r` and
/// `s` each need a leading `0x00` when their high bit is set, so a fresh
/// signature is simply retried until it lands on the canonical length.
/// This terminates only because ECDSA draws a random nonce per attempt,
/// making the attempts independent; a deterministic scheme (RFC 6979)
/// would produce the same length forever and always exhaust the retries.
///
/// This thin adapter owns only the pieces Verus does not model: it builds the
/// crate [`Error`] values (with `format!`), while the verified
/// [`sign_fixed_len_core`] owns the proven loop bound and the bounds-safe
/// copy (VR-008). No crypto property is proven: `sign_once` is trusted.
///
/// # Errors
///
/// Returns an [`Error`] if `sign_once` fails, or if no signature of
/// `signature.len()` bytes is produced within [`MAX_SIGN_ATTEMPTS`].
fn sign_fixed_len(
    signature: &mut [u8],
    mut sign_once: impl FnMut() -> Result<aws_lc_rs::signature::Signature, Error>,
) -> Result<(), Error> {
    let want_len = signature.len();
    // `sign_failure` captures the signing error so its message is preserved
    // across the verus-internal `SignCoreError` boundary.
    let mut sign_failure: Option<Error> = None;
    let result = sign_fixed_len_core(signature, || match sign_once() {
        Ok(candidate) => Ok(candidate),
        Err(e) => {
            sign_failure = Some(e);
            Err(SignCoreError::Failed)
        }
    });
    match result {
        Ok(()) => Ok(()),
        Err(SignCoreError::Failed) => {
            Err(sign_failure.unwrap_or_else(|| serr("ECDSA signing failed".to_owned())))
        }
        Err(SignCoreError::Exhausted) => err(format!(
            "no {want_len} byte DER signature produced in {MAX_SIGN_ATTEMPTS} attempts"
        )),
    }
}

/// Check that a caller-supplied signature buffer is the length `alg`
/// produces, so a wrong-sized buffer fails immediately rather than after
/// [`MAX_SIGN_ATTEMPTS`] signatures that can never match.
fn check_sig_len(alg: EcdsaSignatureAlgorithm, signature: &[u8]) -> Result<(), Error> {
    if signature.len() != signature_len(alg) {
        return err(format!(
            "signature buffer of {} bytes does not match the {} byte {:?} DER signature",
            signature.len(),
            signature_len(alg),
            alg
        ));
    }
    Ok(())
}

/// Sign the message with the key using the given algorithm, writing the
/// DER-encoded signature into `signature`.
///
/// The key must be in DER format. `signature` must be exactly
/// [`signature_len`] bytes for `alg`.
///
/// # Errors
///
/// Returns an [`Error`] if `signature` is not [`signature_len`] bytes for
/// `alg`, if `key` is not a valid DER-encoded private key for `alg`, if the
/// signing operation fails, or if no canonical-length signature is produced
/// within 128 attempts.
pub fn ecdsa_sign(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    msg: &[u8],
    signature: &mut [u8],
) -> Result<(), Error> {
    check_sig_len(alg, signature)?;
    let private_key: EcdsaKeyPair = EcdsaKeyPair::from_private_key_der(get_sign_alg(alg), key)
        .map_err(|_| serr("invalid ECDSA private key".to_owned()))?;
    let rng = SystemRandom::new();
    sign_fixed_len(signature, || {
        private_key
            .sign(&rng, msg)
            .map_err(|_| serr("ECDSA signing failed".to_owned()))
    })
}

/// Sign the accumulated digest with the key using the given algorithm,
/// writing the DER-encoded signature into `signature`.
///
/// The key must be in DER format. `signature` must be exactly
/// [`signature_len`] bytes for `alg`.
///
/// # Errors
///
/// Returns an [`Error`] if `signature` is not [`signature_len`] bytes for
/// `alg`, if `key` is not a valid DER-encoded private key for `alg`, if the
/// signing operation fails, or if no canonical-length signature is produced
/// within 128 attempts.
pub fn ecdsa_sign_digest(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    context: DigestContext,
    signature: &mut [u8],
) -> Result<(), Error> {
    check_sig_len(alg, signature)?;
    let private_key: EcdsaKeyPair = EcdsaKeyPair::from_private_key_der(get_sign_alg(alg), key)
        .map_err(|_| serr("invalid ECDSA private key".to_owned()))?;
    let digest = context.digest();
    sign_fixed_len(signature, || {
        private_key
            .sign_digest(&digest)
            .map_err(|_| serr("ECDSA signing failed".to_owned()))
    })
}

/// Verify the signature of the message using the key and algorithm
///
/// Returns `Ok(true)` when the signature verifies and `Ok(false)` when it
/// does not.
///
/// # Errors
///
/// A rejected signature, a malformed signature, and a malformed key are all
/// reported as `Ok(false)`, so this currently never returns an [`Error`].
/// The fallible signature is retained so verification can distinguish
/// operational failures from a genuine mismatch in future without a
/// breaking change.
pub fn ecdsa_verify(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, Error> {
    let public_key = UnparsedPublicKey::new(get_ver_alg(alg), key);
    match public_key.verify(msg, sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify the signature of the accumulated digest using the key and
/// algorithm
///
/// Returns `Ok(true)` when the signature verifies and `Ok(false)` when it
/// does not.
///
/// # Errors
///
/// As with [`ecdsa_verify`], failures are reported as `Ok(false)`, so this
/// currently never returns an [`Error`].
pub fn ecdsa_verify_context(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    context: DigestContext,
    sig: &[u8],
) -> Result<bool, Error> {
    let public_key = UnparsedPublicKey::new(get_ver_alg(alg), key);
    let digest = context.digest();
    match public_key.verify_digest(&digest, sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// An ECDSA key pair, in the formats the Dafny MPL's `SignatureKeyPair`
/// uses (`AwsCryptographyPrimitives/src/Signature.dfy`).
///
/// `Debug` deliberately redacts [`Self::signing_key`] so private key
/// material cannot reach logs.
#[derive(Clone)]
#[non_exhaustive]
pub struct SignatureKeyPair {
    /// The public key, as an X9.62 compressed point (`0x02`/`0x03 || X`).
    /// Exactly [`field_size`] bytes: 33 for P-256, 49 for P-384.
    pub verification_key: Vec<u8>,
    /// The private key, DER-encoded per RFC 5915 — the form
    /// [`ecdsa_sign`] and [`ecdsa_sign_digest`] accept.
    pub signing_key: Vec<u8>,
}

impl std::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("verification_key", &self.verification_key)
            .field(
                "signing_key",
                &format_args!("[REDACTED; {} bytes]", self.signing_key.len()),
            )
            .finish()
    }
}

/// Length in bytes of a compressed verification key for `alg`.
///
/// Mirrors `FieldSize` in the Dafny MPL: `1 + ceil(bits / 8)`, i.e. one
/// X9.62 tag byte plus a single field element.
#[must_use]
pub const fn field_size(alg: EcdsaSignatureAlgorithm) -> usize {
    match alg {
        EcdsaSignatureAlgorithm::EcdsaP256 => 33,
        EcdsaSignatureAlgorithm::EcdsaP384 => 49,
    }
}

/// Generate a fresh ECDSA key pair for the given signature algorithm.
///
/// The returned formats match the Dafny MPL's `ExternKeyGen`: the
/// verification key is an X9.62 compressed point and the signing key is
/// DER-encoded, so the signing key composes directly with [`ecdsa_sign`]
/// and [`ecdsa_sign_digest`], and the verification key is already in the
/// form the ESDK publishes in the encryption context
/// (`spec/framework/transitive-requirements.md#ecdsa`, SEC 1 v2.0 §2.3.3).
///
/// # Errors
///
/// Returns an [`Error`] if key generation fails, if either key cannot be
/// encoded, or if the generated verification key is not [`field_size`]
/// bytes long.
pub fn ecdsa_generate_keypair(alg: EcdsaSignatureAlgorithm) -> Result<SignatureKeyPair, Error> {
    let key_pair = EcdsaKeyPair::generate(get_sign_alg(alg))
        .map_err(|_| serr("ECDSA key generation failed".to_owned()))?;

    let compressed: EcPublicKeyCompressedBin<'static> = key_pair
        .public_key()
        .as_be_bytes()
        .map_err(|_| serr("ECDSA public-key compression failed".to_owned()))?;
    let verification_key = compressed.as_ref().to_vec();

    let der: EcPrivateKeyRfc5915Der<'static> = key_pair
        .private_key()
        .as_der()
        .map_err(|_| serr("ECDSA private-key DER encoding failed".to_owned()))?;
    let signing_key = der.as_ref().to_vec();

    // Mirrors the `KeyGen` postcondition in the Dafny MPL, which rejects a
    // verification key whose length is not `FieldSize`.
    if verification_key.len() != field_size(alg) {
        return err(format!(
            "verification key is {} bytes, expected {}",
            verification_key.len(),
            field_size(alg)
        ));
    }

    Ok(SignatureKeyPair {
        verification_key,
        signing_key,
    })
}
