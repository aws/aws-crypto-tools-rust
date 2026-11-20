// =============================================================================
// VR-2026-T05 (TM-MPL-014, priority 4.32): the KBKDF fixed-info string and the
// derivation inputs of  branch_key_wrap::derive_branch_key
//
// Run:  ~/verus/verus verus-proofs/t05_kbkdf_fixed_info.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// A proof about a RE-TYPED MODEL of the shipped code, not about the shipped code.
// `derive_branch_key` is native Rust over `Zeroizing`, `Vec<u8>`, `u32::to_be_bytes`,
// the crate's `Error`, and `aws_mpl_primitives::kbkdf_ctr_hmac` (which wraps aws-lc-rs).
// None of that compiles under Verus, so the model re-types the control flow and the
// byte construction in Verus and abstracts the primitive behind a trait contract.
// The link between model and code is the correspondence table in section 2. A human
// reviewed that table; nothing machine-checks it.
//
// The KBKDF itself is NOT proved. Its output is an UNINTERPRETED spec function
// (`kbkdf_spec`). Nothing is known about it except what the primitive's contract
// (trait `Prim`, section 3) states. PRF/HMAC-SHA-256 security and the correctness of
// aws-lc-rs are third-party TCB (threat model TM-MPL-014 "Partial").
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD 35f24c9; both
//    branch_key_wrap.rs and prim/src/lib.rs were last changed by bec2cfe)
// =============================================================================
//   mpl/src/aws_kms/branch_key_wrap.rs
//     :14-44    constants SALT_LEN, IV_LEN, VERSION_LEN, TAG_LEN, DERIVED_KEY_LEN,
//               HIERARCHY_LABEL (:40), FIXED_OVERHEAD_LEN (:44)
//     :122-144  derive_branch_key   (target; fixed-info :126-132, buffer :135,
//               kbkdf_ctr_hmac call :136, error mapping :136-142, Ok :143)
//     :157-    wrap                  (salt :163-166, iv :169-172, KDF :175,
//               prefix salt||iv||version :192-197)
//     :230-    unwrap                (length gate :236-244, salt :247-249, KDF :265)
//   prim/src/lib.rs :313-330  kbkdf_ctr_hmac(alg, ikm, info, okm) -> Result<(), Error>
//   mpl/src/structures/branch_key_materials.rs :32  branch_key() -> &[u8; 32]
//
// Only two call sites reach the KDF in mpl/src: branch_key_wrap.rs:175 (wrap) and :265
// (unwrap), both via derive_branch_key; the only call to prim::kbkdf_ctr_hmac in
// mpl/src is :136 (checked with grep at the time of writing).
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model  <->  shipped branch_key_wrap.rs)
// =============================================================================
//  shipped                                           | model (this file)
//  --------------------------------------------------+--------------------------------------------
//  :20,:24,:36,:44  SALT_LEN=16, IV_LEN=12,          | same names and values (pub const)
//    VERSION_LEN=16, TAG_LEN=16, DERIVED_KEY_LEN=32, |
//    FIXED_OVERHEAD_LEN = sum = 60                   |
//  :40  HIERARCHY_LABEL = b"aws-kms-hierarchy"       | HIERARCHY_LABEL: [u8;17] = the 17 bytes, spelled
//                                                    |   out as decimal ASCII (Verus has no support for
//                                                    |   byte-string constants). Checked against the
//                                                    |   shipped literal by script (see t05-notes.md).
//  :122-125 fn derive_branch_key(branch_key:         | fn derive_branch_key<P: Prim>(branch_key: &[u8;32],
//      &[u8;32], salt: &[u8;16]) ->                  |   salt: &[u8;16]) -> Result<[u8;32], Error>
//      Result<Zeroizing<[u8;32]>, Error>             |   `Zeroizing<..>` is dropped (identity on the
//                                                    |   value, wipes on drop; not modeled). `P` is the
//                                                    |   primitive (prim::kbkdf_ctr_hmac), see section 3.
//  :127 Vec::with_capacity(17 + 1 + 16 + 4)          | Vec::with_capacity(HIERARCHY_LABEL.len() + 1
//                                                    |   + SALT_LEN + 4)  (capacity is a hint only)
//  :128 info.extend_from_slice(HIERARCHY_LABEL)      | same (label as a slice of the const array)
//  :129 info.push(0x00)                              | same
//  :130 info.extend_from_slice(salt)                 | same (&[u8;16] coerces to &[u8])
//  :131 let output_len_bits: u32 = 256               | same
//  :132 info.extend_from_slice(&output_len_bits      | info.extend_from_slice(&u32_to_be_bytes(bits)) where
//          .to_be_bytes())                           |   u32_to_be_bytes is a model of core::u32::to_be_bytes
//                                                    |   written with shifts and masks, proved equal to the
//                                                    |   arithmetic spec `be32`. Verus has no spec for
//                                                    |   to_be_bytes, so "std's to_be_bytes is big-endian"
//                                                    |   is trusted (A_STD).
//  :135 let mut derived = Zeroizing::new([0u8;32])   | let mut derived = [0u8; 32]
//  :136 kbkdf_ctr_hmac(DigestAlg::Sha256,            | P::kbkdf_ctr_hmac(DigestAlg::Sha256, branch_key,
//          branch_key, &info, &mut *derived)         |   &info, &mut derived)   (argument order = prim
//                                                    |   signature `(alg, ikm, info, okm)`, lib.rs:313-318)
//  :136-142 .map_err(|e| Error::with_cause(          | match r { Err(_) => return Err(Error{kind:
//      Kind::Cryptographic, "..", e))?               |   ErrKind::Cryptographic}) , Ok(()) => () }
//                                                    |   (desugaring of `?`; message and cause dropped)
//  :143 Ok(derived)                                  | Ok(derived)
//  :157-197 wrap, steps 1-3 and the prefix of step 5 | fn wrap_kdf_leg<P>(branch_key, salt, iv, version):
//      (salt, iv random; derive_branch_key(bk,&salt);|   salt/iv/version are INPUTS (RNG and version parse
//      output = salt||iv||version)                   |   are out of scope; T04 owns the RNG); same call
//                                                    |   derive_branch_key(bk, salt); same prefix
//                                                    |   extend_from_slice(salt/iv/version) order.
//                                                    |   AAD (:178-182) and AES-GCM are not modeled.
//  :236-244 if ciphertext.len() < 60 { return Err }  | if ct.len() < FIXED_OVERHEAD_LEN { return Err(..) }
//  :247-249 salt = ciphertext[0..16].try_into()      | array16_from_slice(&ct[0..16]) (helper requires
//                .expect(..)                         |   len == 16; models try_into + expect; std's
//                                                    |   "TryFrom<&[T]> for [T;N] fails iff len != N" is
//                                                    |   trusted (A_STD)). iv and version slices
//                                                    |   (:250-256) are sliced in-bounds (checked), but
//                                                    |   their values do not feed the KDF and are unused.
//  :257-261 body_offset, encrypted_key_end =         | same arithmetic; `&ct[end..]` is written as
//      len - TAG_LEN, the two slices                 |   `&ct[end..ct.len()]` (vstd has no spec for
//                                                    |   RangeFrom indexing); same slice.
//  :265 derive_branch_key(materials.branch_key(),    | derive_branch_key::<P>(branch_key, &salt)?  written
//          &salt)?                                   |   as match/early return.
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED  (read before citing a result)
// =============================================================================
// The spec text is spec/framework/aws-kms/aws-kms-hierarchical-keyring.md, sections
// "Branch Key Wrapping" (:206-222) and "Branch Key Unwrapping" (:301-320).
// It says: derive a 32 byte `derivedBranchKey` with a KDF in Counter Mode with a PRF
// with HMAC SHA 256; "Use the `salt` as the salt", "Use the branch key as the `key`",
// "Use the UTF8 Encoded value "aws-kms-hierarchy" as the label"; 16 byte salt; the
// derivedBranchKey is the AES-GCM-256 cipher key; wrap and unwrap use the same
// derivation. The ciphertext layout salt(16)||IV(12)||version(16)||encrypted key||tag
// is :114-135. There is NO Appendix text on the derivation. Appendix A is the cache
// identifier; Appendix B is rotation limits.
//
//   SPEC-DERIVED (the spec states it, in words):
//     S1  PRF is HMAC-SHA-256                      -> alg == DigestAlg::Sha256
//     S2  derived key is 32 bytes                  -> out_len == 32, okm is [u8;32]
//     S3  the branch key is the KDF key            -> ikm == branch_key
//     S4  the salt is exactly 16 bytes             -> salt: &[u8;16]
//     S5  the label is the UTF-8 bytes "aws-kms-hierarchy" (17 bytes)
//     S6  unwrap derives from the salt stored in the ciphertext, with the same
//         branch key, by the same derivation as wrap (theorem_wrap_unwrap_same_kdf_input)
//     S7  the ciphertext is salt(16)||IV(12)||version(16)||encrypted key||tag(16)
//
//   CODE-DERIVED (NOT stated by the spec; taken from branch_key_wrap.rs and from the
//   NIST SP 800-108 §4.1 shape that prim/src/lib.rs:295-301 describes and that the
//   Dafny-ported known-answer tests (prim/tests/test_kbkdf_ctr_hmac.rs:241-314 vectors
//   C.1-C.5, helper `build_fixed_info` :316-326, test :338-347) use with the SAME label
//   "aws-kms-hierarchy", Sha256 and L = 32):
//     C1  the byte string passed to the primitive as `info` is
//           label || 0x00 || salt || be32(256)
//         i.e. the spec's "salt" is placed in the NIST *Context* field, the
//         separator is a single 0x00 byte, and the length field L is the 4-byte
//         big-endian OUTPUT LENGTH IN BITS.
//     C2  its total length is 17 + 1 + 16 + 4 = 38 bytes
//     C3  be32(256) = 00 00 01 00, and 256 = 8 * DERIVED_KEY_LEN
//     C4  the primitive does not add L itself (the caller supplies it in `info`).
//         This is a fact about aws-lc-rs, evidenced by the KATs, not proved.
//   The spec leaves C1-C4 open ("Use the salt as the salt" says nothing about where
//   the salt goes or about L). The theorems below state C1-C3 against the CODE, and
//   `lemma_fixed_info_is_nist_shape` ties them to the same construction that the
//   prim KAT helper uses. The KATs are ported from Dafny (TestKDF_TestVectors.dfy), so
//   they are the only evidence in this repo that the layout matches the reference
//   implementation. That evidence lives in a test of the primitive, with test-local
//   inputs, and is not part of this proof. See finding F1 in t05-notes.md.
//
// =============================================================================
// 4. TRUSTED ASSUMPTIONS (everything the result depends on besides the model's code)
// =============================================================================
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification`, or
//  `#[verifier...]` attribute is written in this file (checked by grep, outside comments).
//  A_KDF  (UNINTERPRETED, the one deliberate unconstrained item) `kbkdf_spec` is an
//         `uninterp spec fn`. The trait `Prim` states the only fact about it that is used:
//         when the primitive returns Ok, `okm == kbkdf_spec(alg, ikm, info, len)`, and the
//         output length never changes. That is a hypothesis on ANY implementation of `Prim`.
//         It holds for the real primitive iff aws-lc-rs computes a deterministic function
//         of (alg, ikm, info, len), which is not proved. Nothing about HMAC, counters or
//         PRF security is assumed or used. There is no implementation of `Prim` in
//         this file, so the contract is not shown satisfiable by construction. It is
//         consistent because `kbkdf_spec` has no axioms.
//  A_STD  core's `u32::to_be_bytes` is big-endian, and `<[u8;N]>::try_from(&[u8])` fails
//         exactly when the slice length is not N. Both are std semantics, not in vstd.
//  A_VSTD vstd's specs for `Vec::{with_capacity, push, extend_from_slice}`, slice
//         indexing by `Range`, `<[T;N]>::as_slice`, and arrays; Verus and Z3.
//  A_LBL  the 17 label bytes were transcribed by hand and compared to the shipped
//         literal by script (t05-notes.md). Verus cannot read the crate's constant.
//  A_TYP  Rust typing: `&[u8; 32]`/`&[u8; 16]` guarantee the lengths; a `&mut [u8]` keeps
//         its length across a call. (The latter is listed in the contract of `Prim`.)
//
// =============================================================================
// 5. MODEL-vs-CODE GAP
// =============================================================================
//  The shipped function is not inside `verus!`, is not compiled here, and nothing detects a
//  later edit to branch_key_wrap.rs or prim/src/lib.rs. To close the gap one needs ALL of:
//   1. derive_branch_key (and the constants) moved into `verus!`, or `cargo verus` on the crate;
//   2. `assume_specification` for `core::u32::to_be_bytes`, `Zeroizing::new`/deref, `Error::with_cause`;
//   3. `aws_mpl_primitives::kbkdf_ctr_hmac` given an `external_type_specification`/
//      `assume_specification` with exactly the contract of trait `Prim` below
//      (that is where the aws-lc-rs TCB would be written down);
//   4. the byte-string constant read by Verus instead of re-spelled.
//  Until then the evidence level is: audited model + machine-checked logic.
//
// =============================================================================
// 6. NOT COVERED
// =============================================================================
//  * The KBKDF output. HMAC-SHA-256/PRF security, aws-lc-rs correctness, and whether the
//    primitive's output depends on `info` the way NIST SP 800-108 says (TM-MPL-014 residual).
//  * Interop: that the fixed-info layout equals what other MPL implementations emit. The spec
//    does not fix it (section 3). The Dafny-ported KATs in prim/tests (same label, Sha256,
//    L=32) support it, but they call the primitive with a test-local copy of the layout, not
//    with the output of derive_branch_key, and no test compares wrap output to a Dafny/Java
//    ciphertext (checked: no such vector in mpl/tests).
//  * The random salt/IV (T04 / TM-MPL-012), AES-GCM, the AAD (`compute_aad`), version UUID
//    parsing, the order of the AAD step relative to the KDF step beyond what is written above,
//    zeroization of the derived key, timing/side channels, allocation failure.
//  * The Err message/cause text; only the error KIND (Cryptographic) is modeled.
//  * Whether `kbkdf_ctr_hmac` can actually fail for a 32-byte output and a Sha256 request.
//    The model lets it fail arbitrarily and proves the shape of the failure, not its absence.
//  * The `ikm` size: the primitive accepts any ikm length; nothing here relies on it.
//
// =============================================================================
// 7. THEOREMS (what the ensures say; see t05-notes.md for the proof-file line numbers)
// =============================================================================
//  T1  theorem_fixed_info_layout      info = label||0x00||salt||be32(256): total 38 bytes and every
//                                     field at its offset (0..17 label, 17 sep, 18..34 salt, 34..38 L)
//  T2  theorem_fixed_info_salt_injective   two 16-byte salts give the same info only if equal
//  T3  lemma_l_is_bits_of_output      be32(256) = [0,0,1,0] and 256 == 8 * DERIVED_KEY_LEN;
//      lemma_fixed_info_is_nist_shape  info == NIST fixed-info(label, salt, 32 bytes)
//  T4  derive_branch_key              exec model: on Ok the key equals
//                                       kbkdf_spec(Sha256, branch_key, fixed_info(salt), 32)
//                                     (algorithm, ikm, info, output length, argument order); every Err has
//                                     kind Cryptographic. There is no length-error path: wrong lengths
//                                     are unrepresentable (A_TYP).
//  T5  wrap_kdf_leg                   wrap: same derivation; the salt that feeds the KDF is the salt written
//                                     at bytes 0..16 of the output; prefix is salt||iv||version (44 bytes)
//  T6  unwrap_kdf_leg                 unwrap: len < 60 => Err before the primitive is reached; otherwise
//                                     all slicing is in bounds (Verus-checked) and the KDF salt is bytes
//                                     0..16 of the ciphertext
//  T7  theorem_wrap_unwrap_same_kdf_input   for any wrap output layout, unwrap's salt equals wrap's salt,
//                                     hence identical fixed-info and (under the same uninterpreted
//                                     function) identical derived key; and the output has len >= 60
//  W   witness_*                      concrete instances, so the lemmas are not vacuous
// =============================================================================
use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Model types and constants
// ============================================================

/// prim::DigestAlg (only Sha256 is used by the target; all three listed so that "Sha256" is a
/// real choice among alternatives and a wrong-algorithm mutation is expressible).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DigestAlg {
    Sha256,
    Sha384,
    Sha512,
}

/// Error kind. The shipped crate's Kind has many variants; the target produces only
/// `Kind::Cryptographic` (branch_key_wrap.rs:138 and :238).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ErrKind {
    Cryptographic,
}

/// Model of crate::Error. Message and cause are dropped.
pub struct Error {
    pub kind: ErrKind,
}

// branch_key_wrap.rs:20-44
pub const SALT_LEN: usize = 16;

pub const IV_LEN: usize = 12;

pub const VERSION_LEN: usize = 16;

pub const TAG_LEN: usize = 16;

pub const DERIVED_KEY_LEN: usize = 32;

pub const FIXED_OVERHEAD_LEN: usize = 60;  // = SALT_LEN + IV_LEN + VERSION_LEN + TAG_LEN, checked below

/// branch_key_wrap.rs:40  b"aws-kms-hierarchy"  (a 17-byte ASCII literal).
/// a w s - k m s - h i e r a r c h y
pub const HIERARCHY_LABEL: [u8; 17] = [
    97u8, 119, 115, 45, 107, 109, 115, 45, 104, 105, 101, 114, 97, 114, 99, 104, 121,
];

/// branch_key_wrap.rs:131  `let output_len_bits: u32 = 256;`
pub const OUTPUT_LEN_BITS: u32 = 256;

// ============================================================
// SECTION 2: Specification functions
// ============================================================

/// The 17 label bytes as a sequence.
pub open spec fn label() -> Seq<u8> {
    HIERARCHY_LABEL@
}

/// 4-byte big-endian encoding of x, stated arithmetically (most significant byte first).
pub open spec fn be32(x: u32) -> Seq<u8> {
    seq![
        ((x / 0x1000000u32) % 256u32) as u8,
        ((x / 0x10000u32) % 256u32) as u8,
        ((x / 0x100u32) % 256u32) as u8,
        (x % 256u32) as u8,
    ]
}

/// CODE-DERIVED (C1): the KBKDF fixed-info string, branch_key_wrap.rs:126-132.
///   label || 0x00 || salt || be32(256)
pub open spec fn fixed_info(salt: Seq<u8>) -> Seq<u8> {
    label() + seq![0x00u8] + salt + be32(OUTPUT_LEN_BITS)
}

/// NIST SP 800-108 §4.1 fixed-info, as built by the prim KAT helper `build_fixed_info`
/// (prim/tests/test_kbkdf_ctr_hmac.rs:316-326):  label || 0x00 || context || [L]_2
/// where L = 8 * okm_bytes (bits) as a 4-byte big-endian value.
pub open spec fn nist_fixed_info(label_: Seq<u8>, context: Seq<u8>, okm_bytes: u32) -> Seq<u8> {
    label_ + seq![0x00u8] + context + be32((okm_bytes * 8) as u32)
}

/// The KBKDF output of the primitive. UNINTERPRETED: it has no definition and no axiom.
/// The only facts about it used anywhere in this file come from the contract of `Prim`.
pub uninterp spec fn kbkdf_spec(alg: DigestAlg, ikm: Seq<u8>, info: Seq<u8>, out_len: nat) -> Seq<u8>;

/// The derived branch key as the spec describes it (S1, S2, S3) with the code's info (C1).
pub open spec fn derived_key_spec(branch_key: Seq<u8>, salt: Seq<u8>) -> Seq<u8> {
    kbkdf_spec(DigestAlg::Sha256, branch_key, fixed_info(salt), 32)
}

/// SPEC-DERIVED (S7, aws-kms-hierarchical-keyring.md:114-135) and wrap's assembly :192-197:
///   salt || iv || version || encrypted_key || tag
pub open spec fn wire_layout(
    salt: Seq<u8>,
    iv: Seq<u8>,
    version: Seq<u8>,
    encrypted_key: Seq<u8>,
    tag: Seq<u8>,
) -> Seq<u8> {
    salt + iv + version + encrypted_key + tag
}

/// What unwrap reads as the KDF salt: ciphertext[0..16]  (branch_key_wrap.rs:247).
pub open spec fn unwrap_salt(ct: Seq<u8>) -> Seq<u8> {
    ct.subrange(0, 16)
}

// ============================================================
// SECTION 3: Lemmas about the fixed-info string
// ============================================================

/// Constants agree: 60 = 16 + 12 + 16 + 16, and the label has 17 bytes.
pub proof fn lemma_constants()
    ensures
        FIXED_OVERHEAD_LEN == SALT_LEN + IV_LEN + VERSION_LEN + TAG_LEN,
        label().len() == 17,
{
}

/// T3 (C3). be32(256) is exactly 00 00 01 00, and 256 is 8 * DERIVED_KEY_LEN, so the length
/// field L says "32 bytes of output" in bits (NIST SP 800-108 §4.1, L in bits).
pub proof fn lemma_l_is_bits_of_output()
    ensures
        be32(OUTPUT_LEN_BITS) == seq![0x00u8, 0x00u8, 0x01u8, 0x00u8],
        OUTPUT_LEN_BITS as int == 8 * (DERIVED_KEY_LEN as int),
{
    assert(be32(OUTPUT_LEN_BITS) =~= seq![0x00u8, 0x00u8, 0x01u8, 0x00u8]);
}

/// be32 is a big-endian encoding: the four bytes read back to x. (Independent of the
/// shifts/masks in the executable model, so be32 is not just "whatever the code does".)
pub proof fn lemma_be32_value(x: u32)
    ensures
        (be32(x)[0] as int) * 16777216 + (be32(x)[1] as int) * 65536 + (be32(x)[2] as int) * 256
            + (be32(x)[3] as int) == x as int,
{
    let a = x / 0x1000000u32;
    let b = (x / 0x10000u32) % 256u32;
    let c = (x / 0x100u32) % 256u32;
    let d = x % 256u32;
    assert(a < 256) by (nonlinear_arith)
        requires
            a == x / 0x1000000u32,
    ;
    assert(((x / 0x1000000u32) % 256u32) == a) by (nonlinear_arith)
        requires
            a == x / 0x1000000u32,
            a < 256,
    ;
    assert((a as int) * 16777216 + (b as int) * 65536 + (c as int) * 256 + (d as int) == x as int)
        by (bit_vector)
        requires
            a == x / 0x1000000u32,
            b == (x / 0x10000u32) % 256u32,
            c == (x / 0x100u32) % 256u32,
            d == x % 256u32,
    ;
}

/// The target's info is the NIST fixed-info with Label = "aws-kms-hierarchy", Context = salt,
/// 32 output bytes. (Same construction as the Dafny-ported KAT helper; see section 3.)
pub proof fn lemma_fixed_info_is_nist_shape(salt: Seq<u8>)
    ensures
        fixed_info(salt) == nist_fixed_info(label(), salt, DERIVED_KEY_LEN as u32),
{
    lemma_l_is_bits_of_output();
}

/// T1. The layout theorem. For any 16-byte salt the fixed-info is 38 bytes and each field
/// sits at its offset.
pub proof fn theorem_fixed_info_layout(salt: Seq<u8>)
    requires
        salt.len() == SALT_LEN,
    ensures
        fixed_info(salt).len() == 38,
        fixed_info(salt).len() == label().len() + 1 + SALT_LEN + 4,
        fixed_info(salt).subrange(0, 17) == label(),
        fixed_info(salt)[17] == 0x00u8,
        fixed_info(salt).subrange(18, 34) == salt,
        fixed_info(salt).subrange(34, 38) == seq![0x00u8, 0x00u8, 0x01u8, 0x00u8],
        // the whole string, written out against the spec's field names
        fixed_info(salt) == label() + seq![0x00u8] + salt + seq![0x00u8, 0x00u8, 0x01u8, 0x00u8],
{
    lemma_constants();
    lemma_l_is_bits_of_output();
    let fi = fixed_info(salt);
    assert(fi.len() == 38);
    assert(fi.subrange(0, 17) =~= label());
    assert(fi.subrange(18, 34) =~= salt);
    assert(fi.subrange(34, 38) =~= be32(OUTPUT_LEN_BITS));
}

/// T2. The salt is recoverable from the info string, so distinct 16-byte salts give distinct
/// fixed-info strings (no two salts collapse to the same KDF input). This is about the info
/// string only; whether the PRF output separates them is the PRF's property (not proved).
pub proof fn theorem_fixed_info_salt_injective(s1: Seq<u8>, s2: Seq<u8>)
    requires
        s1.len() == SALT_LEN,
        s2.len() == SALT_LEN,
        fixed_info(s1) == fixed_info(s2),
    ensures
        s1 == s2,
{
    theorem_fixed_info_layout(s1);
    theorem_fixed_info_layout(s2);
    assert(fixed_info(s1).subrange(18, 34) == fixed_info(s2).subrange(18, 34));
}

// ============================================================
// SECTION 4: The primitive (prim::kbkdf_ctr_hmac) as a contract. THIS IS THE KBKDF TCB.
// ============================================================

/// Stands for `aws_mpl_primitives::kbkdf_ctr_hmac` (prim/src/lib.rs:313-330), argument order
/// (alg, ikm, info, okm) as in the shipped signature.
///
/// The contract is a HYPOTHESIS on any implementation, not a proved fact (A_KDF):
///   * the output buffer keeps its length;
///   * if the call returns Ok, the buffer holds `kbkdf_spec(alg, ikm, info, okm.len())`.
/// Nothing is said about the buffer on Err, and nothing about WHEN it returns Err
/// (the real one rejects a zero-length output and an unavailable PRF).
pub trait Prim {
    fn kbkdf_ctr_hmac(alg: DigestAlg, ikm: &[u8], info: &[u8], okm: &mut [u8]) -> (r: Result<(), Error>)
        ensures
            final(okm)@.len() == old(okm)@.len(),
            r is Ok ==> final(okm)@ == kbkdf_spec(alg, ikm@, info@, old(okm)@.len() as nat),
    ;
}

// ============================================================
// SECTION 5: Executable model of derive_branch_key
// ============================================================

/// Model of `u32::to_be_bytes` (A_STD), written with shifts and masks and PROVED equal to the
/// arithmetic `be32`. Used at branch_key_wrap.rs:132.
pub fn u32_to_be_bytes(x: u32) -> (r: [u8; 4])
    ensures
        r@ == be32(x),
{
    proof {
        assert((x >> 24u32) == x / 0x1000000u32) by (bit_vector);
        assert(((x >> 16u32) & 0xffu32) == (x / 0x10000u32) % 256u32) by (bit_vector);
        assert(((x >> 8u32) & 0xffu32) == (x / 0x100u32) % 256u32) by (bit_vector);
        assert((x & 0xffu32) == x % 256u32) by (bit_vector);
    }
    let r = [
        (x >> 24) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        (x & 0xff) as u8,
    ];
    assert(r@ =~= be32(x));
    r
}

/// T4. Model of branch_key_wrap.rs:122-144.
///
/// `ensures` (1): on Ok the 32 output bytes are `kbkdf_spec(Sha256, branch_key, fixed_info(salt), 32)`:
///   algorithm Sha256 (S1), key = the branch key (S3), info = label||0x00||salt||be32(256) (C1),
///   32 bytes out (S2), in the argument positions of the primitive's contract.
/// (2): every Err is of kind Cryptographic and comes only from the primitive's Err.
/// A wrong-length salt or branch key cannot reach this function: both are fixed-size arrays
/// (A_TYP). The only failure mode is the primitive's.
pub fn derive_branch_key<P: Prim>(branch_key: &[u8; 32], salt: &[u8; 16]) -> (r: Result<[u8; 32], Error>)
    ensures
        r is Ok ==> r->Ok_0@ == derived_key_spec(branch_key@, salt@),
        r is Ok ==> r->Ok_0@.len() == 32,
        r is Err ==> r->Err_0.kind == ErrKind::Cryptographic,
{
    proof {
        lemma_constants();
        lemma_l_is_bits_of_output();
    }
    // :127  FixedInfo: Label || 0x00 || salt || L_be32 (256-bit output).
    let mut info: Vec<u8> = Vec::with_capacity(HIERARCHY_LABEL.len() + 1 + SALT_LEN + 4);
    // :128
    info.extend_from_slice(HIERARCHY_LABEL.as_slice());
    // :129
    info.push(0x00);
    // :130
    info.extend_from_slice(salt);
    // :131-132
    let output_len_bits: u32 = OUTPUT_LEN_BITS;
    let l_bytes = u32_to_be_bytes(output_len_bits);
    info.extend_from_slice(&l_bytes);
    proof {
        // The Vec built by the five calls above is exactly the spec fixed_info(salt).
        assert(info@ =~= fixed_info(salt@));
        assert(info@.len() == 38);
    }
    // :135
    let mut derived = [0u8; 32];
    // :136
    let res = P::kbkdf_ctr_hmac(DigestAlg::Sha256, branch_key, &info, &mut derived);
    match res {
        Ok(()) => {
            // The contract of Prim ties `derived` to the uninterpreted kbkdf_spec at the
            // exact arguments passed above.
            assert(derived@ == kbkdf_spec(DigestAlg::Sha256, branch_key@, info@, 32nat));
            assert(info@ == fixed_info(salt@));
            // :143
            Ok(derived)
        },
        // :136-142 map_err(.. Kind::Cryptographic ..)?
        Err(_) => Err(Error { kind: ErrKind::Cryptographic }),
    }
}

// ============================================================
// SECTION 6: wrap / unwrap legs that feed the derivation
// ============================================================

/// Model of "copy a 16-byte slice into a [u8;16]" = `slice.try_into().expect(..)` at
/// branch_key_wrap.rs:247-249. The `requires` is the condition under which the real
/// `try_into` does not fail (A_STD), so the call sites prove the `expect` cannot fire.
pub fn array16_from_slice(s: &[u8]) -> (r: [u8; 16])
    requires
        s@.len() == 16,
    ensures
        r@ == s@,
{
    let mut a = [0u8; 16];
    let mut i: usize = 0;
    while i < 16
        invariant
            i <= 16,
            s@.len() == 16,
            a@.len() == 16,
            forall|j: int| 0 <= j < i ==> a@[j] == s@[j],
        decreases 16 - i,
    {
        a[i] = s[i];
        i += 1;
    }
    assert(a@ =~= s@);
    a
}

/// T5. wrap steps 1-3 and the salt||iv||version prefix of step 5 (branch_key_wrap.rs:163-197).
/// `salt`, `iv`, `version` are arbitrary inputs: the RNG (:164, :170) and the version UUID
/// parse (:184) are out of scope.
///
/// On Ok: the derived key is derived_key_spec(branch_key, salt) for THE SAME `salt` that is
/// written at bytes 0..16 of the output, and the prefix is salt||iv||version (44 bytes).
pub fn wrap_kdf_leg<P: Prim>(
    branch_key: &[u8; 32],
    salt: &[u8; 16],
    iv: &[u8; 12],
    version: &[u8; 16],
) -> (r: Result<([u8; 32], Vec<u8>), Error>)
    ensures
        r is Ok ==> r->Ok_0.0@ == derived_key_spec(branch_key@, salt@),
        r is Ok ==> r->Ok_0.1@ == salt@ + iv@ + version@,
        r is Ok ==> r->Ok_0.1@.len() == 44,
        r is Ok ==> r->Ok_0.1@.subrange(0, 16) == salt@,
        r is Err ==> r->Err_0.kind == ErrKind::Cryptographic,
{
    // :175  derive_branch_key(materials.branch_key(), &salt)?
    let derived = match derive_branch_key::<P>(branch_key, salt) {
        Ok(d) => d,
        Err(e) => {
            return Err(e);
        },
    };
    // :192-197
    let mut output: Vec<u8> = Vec::with_capacity(FIXED_OVERHEAD_LEN);
    output.extend_from_slice(salt);
    output.extend_from_slice(iv);
    output.extend_from_slice(version);
    proof {
        assert(output@ =~= salt@ + iv@ + version@);
        assert(output@.subrange(0, 16) =~= salt@);
    }
    Ok((derived, output))
}

/// T6. unwrap steps up to the KDF (branch_key_wrap.rs:236-265).
///
/// * ct.len() < 60: Err (Cryptographic) before the primitive is reached.
/// * ct.len() >= 60: every slice below is in bounds and every `try_into().expect` has a
///   16-byte slice (Verus checks the preconditions); the KDF salt is ct[0..16];
///   body_offset <= encrypted_key_end, so the encrypted-key slice is well formed.
/// * Ok: the derived key is derived_key_spec(branch_key, ct[0..16]) and the returned salt is ct[0..16].
pub fn unwrap_kdf_leg<P: Prim>(branch_key: &[u8; 32], ct: &[u8]) -> (r: Result<([u8; 32], [u8; 16]), Error>)
    ensures
        ct@.len() < FIXED_OVERHEAD_LEN ==> r is Err,
        r is Ok ==> ct@.len() >= FIXED_OVERHEAD_LEN,
        r is Ok ==> r->Ok_0.1@ == unwrap_salt(ct@),
        r is Ok ==> r->Ok_0.0@ == derived_key_spec(branch_key@, unwrap_salt(ct@)),
        r is Err ==> r->Err_0.kind == ErrKind::Cryptographic,
{
    // :236-244
    if ct.len() < FIXED_OVERHEAD_LEN {
        return Err(Error { kind: ErrKind::Cryptographic });
    }
    // :247-249  salt
    let salt = array16_from_slice(&ct[0..SALT_LEN]);
    // :250-252  iv (slice only; the value does not feed the KDF)
    let _iv = &ct[SALT_LEN..SALT_LEN + IV_LEN];
    // :253-256  version (slice only)
    let version_offset = SALT_LEN + IV_LEN;
    let _version = &ct[version_offset..version_offset + VERSION_LEN];
    // :257-260  body and tag
    let body_offset = version_offset + VERSION_LEN;
    let encrypted_key_end = ct.len() - TAG_LEN;
    let _encrypted_key = &ct[body_offset..encrypted_key_end];
    let _tag = &ct[encrypted_key_end..ct.len()];
    // :265  derive_branch_key(materials.branch_key(), &salt)?
    match derive_branch_key::<P>(branch_key, &salt) {
        Ok(d) => {
            assert(salt@ == unwrap_salt(ct@)) by {
                assert(salt@ =~= ct@.subrange(0, 16));
            }
            Ok((d, salt))
        },
        Err(e) => Err(e),
    }
}

// ============================================================
// SECTION 7: Cross-check theorem (wrap output consumed by unwrap)
// ============================================================

/// T7. For ANY wire layout built from a 16-byte salt, 12-byte iv, 16-byte version, any encrypted key
/// and a 16-byte tag (the layout of aws-kms-hierarchical-keyring.md:114-135 and branch_key_wrap.rs:
/// 192-197), unwrap reads back the same salt that wrap fed to the KDF. With the same branch key,
/// both sides therefore feed the primitive the same (ikm, info) and, `kbkdf_spec` being a function,
/// derive the same key. The total length is 60 + |encrypted key|, so the length gate at :236
/// accepts every well-formed wrap output.
pub proof fn theorem_wrap_unwrap_same_kdf_input(
    branch_key: Seq<u8>,
    salt: Seq<u8>,
    iv: Seq<u8>,
    version: Seq<u8>,
    encrypted_key: Seq<u8>,
    tag: Seq<u8>,
)
    requires
        salt.len() == SALT_LEN,
        iv.len() == IV_LEN,
        version.len() == VERSION_LEN,
        tag.len() == TAG_LEN,
    ensures
        wire_layout(salt, iv, version, encrypted_key, tag).len() == FIXED_OVERHEAD_LEN
            + encrypted_key.len(),
        wire_layout(salt, iv, version, encrypted_key, tag).len() >= FIXED_OVERHEAD_LEN,
        unwrap_salt(wire_layout(salt, iv, version, encrypted_key, tag)) == salt,
        fixed_info(unwrap_salt(wire_layout(salt, iv, version, encrypted_key, tag))) == fixed_info(salt),
        derived_key_spec(branch_key, unwrap_salt(wire_layout(salt, iv, version, encrypted_key, tag)))
            == derived_key_spec(branch_key, salt),
{
    lemma_constants();
    let w = wire_layout(salt, iv, version, encrypted_key, tag);
    assert(w.len() == 60 + encrypted_key.len());
    assert(w.subrange(0, 16) =~= salt);
}

// ============================================================
// SECTION 8: Witnesses (the lemmas are not vacuous)
// ============================================================

/// A concrete 16-byte salt (0x00..0x0f). The fixed-info is the explicit 38-byte string
///   "aws-kms-hierarchy" 00 | 00 01 .. 0f | 00 00 01 00
pub proof fn witness_fixed_info_concrete()
    ensures
        fixed_info(seq![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
            == seq![
                97u8, 119, 115, 45, 107, 109, 115, 45, 104, 105, 101, 114, 97, 114, 99, 104, 121,
                0,
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                0, 0, 1, 0,
            ],
{
    lemma_l_is_bits_of_output();
    assert(fixed_info(seq![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        =~= seq![
            97u8, 119, 115, 45, 107, 109, 115, 45, 104, 105, 101, 114, 97, 114, 99, 104, 121,
            0,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            0, 0, 1, 0,
        ]);
}

/// Two different salts give different fixed-info strings (T2 is not vacuous).
pub proof fn witness_distinct_salts_distinct_info()
    ensures
        fixed_info(seq![0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            != fixed_info(seq![1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
{
    let s0 = seq![0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let s1 = seq![1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert(s0.len() == 16 && s1.len() == 16);
    if fixed_info(s0) == fixed_info(s1) {
        theorem_fixed_info_salt_injective(s0, s1);
        assert(s0[0] == 0u8 && s1[0] == 1u8);
    }
}

/// A concrete minimal wire layout (empty encrypted key) passes unwrap's 60-byte gate, and the
/// 59-byte string fails it. Shows the boundary of the length gate is exact.
pub proof fn witness_length_gate_boundary()
    ensures
        FIXED_OVERHEAD_LEN == 60,
        forall|ek: Seq<u8>| ek.len() == 0 ==> (60 + ek.len() >= FIXED_OVERHEAD_LEN),
        !(59 >= FIXED_OVERHEAD_LEN),
{
}

} // verus!

fn main() {}
