// =============================================================================
// VR-2026-T04 (TM-MPL-012, priority 4.48): salt and IV draws, and the output layout, of
//   branch_key_wrap::wrap
//
// Run:  ~/verus/verus verus-proofs/t04_branch_key_wrap.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model of `wrap` (and of the parse half of
// `unwrap`). The shipped functions are native Rust over `Zeroizing`, `Vec<u8>`, the crate's
// `Error`, and `aws_mpl_primitives` (which wraps aws-lc-rs). None of that compiles under Verus.
// The model re-types the control flow and the byte assembly, and it hides every primitive
// behind a contract (trait `Prim`, code SECTION 4). Nothing here detects a later edit to mpl/ or
// prim/. The link between model and code is the correspondence table in section 2, reviewed by
// a human and not machine-checked.
//
// STATUS: PROVED at model level: `verification results:: 45 verified, 0 errors`, relative to
// the hypotheses in header section 4. No obligation is left failing on purpose (section 8).
//
// WHAT THIS FILE DOES NOT PROVE (stated first because TM-MPL-012 is about it):
//   * It does NOT prove that the salt or the IV is fresh, random, unpredictable or unique.
//   * It does NOT prove that two calls to `wrap` use different salts or different IVs.
//   Freshness comes from the random number generator inside aws-lc-rs (`rand::fill`, called by
//   prim `generate_random_bytes`). A model cannot prove it. The model ASSUMES only a weak
//   contract for the generator (A_RNG): each call fills the whole buffer or fails, and each
//   successful call is recorded once. That contract is also met by a generator that returns
//   zeros every time (`toy_generate_random_bytes`). The collision bound for random 16-byte
//   salts and 12-byte IVs (threat model Appendix B, TM-MPL-012 "Partial") stays a probabilistic
//   argument plus the yearly-rotation advice. This file does not touch it.
//   What it DOES prove is the structure around the draws: `wrap` makes two separate generator
//   calls on every call that returns Ok (a call can fail before or after the draws), in a fixed order; those exact bytes go into the KDF and the AES
//   call; those exact bytes sit at the right offsets of the output; and the output has exactly
//   60 + n bytes. Result R8 below adds one conditional lemma: IF the draws of two calls differ, THEN
//   the two outputs differ (premise H_RNG_DIFFERS; the premise is never proved).
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD d6e42d8; both
//    branch_key_wrap.rs and prim/src/lib.rs were last changed by bec2cfe)
// =============================================================================
//   mpl/src/aws_kms/branch_key_wrap.rs
//     :14-44    constants SALT_LEN, IV_LEN, VERSION_LEN, TAG_LEN, DERIVED_KEY_LEN,
//               HIERARCHY_LABEL, FIXED_OVERHEAD_LEN (= 60, :44)
//     :122-144  derive_branch_key   (copied from T05, see section 2)
//     :157-218  wrap   (salt draw :163-166, IV draw :169-172, KDF :175, AAD :178-182,
//               version :184-185, output prefix :191-197, aes_encrypt :199-207,
//               debug_assert :209-213, Ok :217)
//     :230-    unwrap  (length gate :236-244, fields :247-262, KDF :265); parse half only
//   prim/src/lib.rs
//     :122-132  generate_random_bytes(bytes) -> Result<(), Error>  (aws_lc_rs::rand::fill)
//     :175-197  aes_encrypt(alg, iv, key, message, aad, cipher_text: &mut Vec<u8>)
//     :313-330  kbkdf_ctr_hmac(alg, ikm, info, okm)
//   mpl/src/structures/branch_key_materials.rs :32  branch_key() -> &[u8; 32]
//
// Call sites of wrap in mpl/src: aws_kms/hierarchical_keyring.rs:686 and :712 (checked with
// grep). The only calls to generate_random_bytes inside branch_key_wrap.rs are :164 and :170.
// branch_key_wrap.rs contains no `static`, `thread_local`, `lazy`, `OnceLock` or `Mutex`
// (checked with grep at the time of writing).
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model  <->  shipped code)
// =============================================================================
//  shipped                                           | model (this file)
//  --------------------------------------------------+--------------------------------------------
//  :20-44 constants                                  | same names and values (pub const), copied from T05
//  :122-144 derive_branch_key                        | derive_branch_key<P>, copied from the T05 model
//                                                    |   unchanged (fixed-info, to_be_bytes model,
//                                                    |   `Zeroizing` dropped). Its contract A_KDF is the
//                                                    |   trait method `kbkdf_ctr_hmac` of `Prim`.
//  :157-160 wrap(materials, ec, plaintext_data_key)  | wrap<P>(rng, branch_key, aad, version, pt)
//    -> Result<Vec<u8>, Error>                       |   `rng`: ghost log of the global generator (below)
//                                                    |   `branch_key`: materials.branch_key(), &[u8;32]
//                                                    |   `aad`: the RESULT of compute_aad(..) (:178-182)
//                                                    |   `version`: the RESULT of uuid_str_to_16_bytes(..)
//                                                    |     (:184-185)  (both pure, H_AAD_PURE)
//  :163-166 let mut salt = [0u8;16];                 | let mut salt = [0u8; 16];
//    generate_random_bytes(&mut salt).map_err(..)?   |   match P::generate_random_bytes(rng, &mut salt)
//                                                    |     { Ok => .., Err => return Err(Cryptographic) }
//  :169-172 same for iv = [0u8;12]                   | same; a SECOND, separate call
//  :175 derive_branch_key(branch_key(), &salt)?      | derive_branch_key::<P>(branch_key, &salt) with an
//                                                    |   early return of its Err
//  :178-182 compute_aad(..)?                         | match aad { Ok(a) => a, Err(e) => return Err(e) }
//  :184-185 uuid_str_to_16_bytes(..)?                | match version { Ok(v) => v, Err(e) => return Err(e) }
//  :191-197 Vec::with_capacity(FIXED.saturating_add(n)) | Vec::with_capacity(cap), cap written as an `if`
//    ; extend salt, iv, version                      |   (capacity is a hint; vstd does not expose it)
//                                                    |   same three extend_from_slice calls, same order
//  :199-207 aes_encrypt(Aes256Gcm, &iv, &*derived,   | P::aes_encrypt(Aes256Gcm, &iv, &derived, pt,
//    pt, &aad_bytes, &mut output).map_err(..)?       |   &aad_bytes, &mut output), Err -> Cryptographic
//  :209-213 debug_assert_eq!(len diff == n + 16)     | an `assert` the verifier proves (the shipped one is
//                                                    |   compiled out in release builds)
//  :217 Ok(output)                                   | Ok(output)
//  :236-262 unwrap gate and slicing                  | unwrap_parse<P> (same arithmetic; `&ct[end..]` is
//                                                    |   written `&ct[end..ct.len()]`, as in T05)
//  generate_random_bytes (prim :128-132), a global   | trait method with a `&mut Rng` argument whose
//    generator inside aws-lc-rs                      |   ghost `log` lists every buffer handed out
//
// The code between SECTION 1 and SECTION 3, the contract `kbkdf_ctr_hmac`, `u32_to_be_bytes`,
// `derive_branch_key` and `array16_from_slice` are COPIED from t05_kbkdf_fixed_info.rs. Doc
// labels "T1" to "T4" inside the copied text are T05's result numbers, not the R-numbers of
// this file. `wire_layout` and `unwrap_salt` are copied too and are not used here.
//
// Errors: the model keeps only the error KIND. `ErrKind::Other` stands for the kind of an Err
// that comes out of compute_aad or uuid_str_to_16_bytes and is passed on unchanged by `?`.
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED
// =============================================================================
// Spec text: spec/framework/aws-kms/aws-kms-hierarchical-keyring.md, "Ciphertext" (:108-135)
// and "Branch Key Wrapping" (:206-222).
//   SPEC-DERIVED (stated by the spec):
//     S1  generate a 16 byte random salt using a secure source of randomness
//     S2  generate a 12 byte random IV using a secure source of randomness
//     S3  derive the 32 byte key from salt and branch key (as T05)
//     S4  AES-GCM-256 with the derived key as cipher key, the data key as message, the derived
//         IV as IV, a 16 byte tag, the serialized AAD as AAD
//     S5  ciphertext = salt(16) || IV(12) || version(16) || encrypted key || tag(16)
//     S6  if any step fails, OnEncrypt MUST fail
//   CODE-DERIVED (not stated by the spec): salt and IV are drawn by two separate generator
//   calls; the output Vec is built in place and `aes_encrypt` appends ciphertext and tag to it.
//   The spec says "secure source of randomness". Whether `aws_lc_rs::rand::fill` is one is a
//   fact about aws-lc-rs (A_RNG_FRESH, not used here).
//
// =============================================================================
// 4. HYPOTHESES AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and to the
//                  hypotheses below
//    ASSUMED       taken as a premise or as a contract; not proved here (A_*)
//    CODE READING  a claim about the shipped code that Verus does not see (H_*); checked by a
//                  human reading the code at the lines named
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier...]`
//  attribute is written in this file (grep outside comments, no hits). The uninterpreted spec
//  functions are `kbkdf_spec` (T05) and `seal_spec` (new); both have no axioms.
//
//  A_RNG  (ASSUMED, contract of `Prim::generate_random_bytes`). The buffer keeps its length. On
//         Ok, the call is appended to the ghost log exactly once and the buffer equals the new
//         log entry. On Err the log is unchanged. NOTHING is assumed about the VALUES. Meaning:
//         the model knows how many draws happen and which buffer holds which draw, and it knows
//         nothing about randomness.
//  A_RNG_FRESH  (NOT ASSUMED, NOT USED, NOT PROVED). That the draws are uniformly random and
//         independent. TM-MPL-012's mitigation depends on it. It is the aws-lc-rs trusted base.
//         It is named here so that nobody reads A_RNG as it.
//  A_KDF  (ASSUMED, uninterpreted `kbkdf_spec`, as in T05). On Ok the primitive's output is the
//         uninterpreted function of (alg, ikm, info, out_len). Nothing about HMAC or PRF
//         security is used. Contract copied from T05.
//  A_AES  (ASSUMED, contract of `Prim::aes_encrypt`). On Ok the Vec grows by exactly
//         `seal_spec(alg, iv, key, message, aad)`, and that has message.len() + 16 bytes. This
//         is what prim/src/lib.rs:184-196 does (extend by the message, seal in place, extend by
//         the tag) given two aws-lc-rs facts that Verus cannot see: the in-place seal keeps the
//         buffer length, and an AES-GCM tag is 16 bytes. The contract has two `requires`: the
//         key has `key_length(alg)` bytes and the IV has 12 bytes. These are the two
//         argument-shape checks at :187-189 (`UnboundKey::new`, `Nonce::try_assume_unique_for_key`).
//         `wrap` meets them by TYPE (`&[u8;12]`, a 32-byte derived key with Aes256Gcm), and
//         Verus checks that at the call. Nothing is assumed about the Vec on Err. `seal_spec`
//         has no axiom: no confidentiality, no authenticity, no nonce-misuse property is used.
//  A_STD, A_VSTD, A_TYP  as in T05: `u32::to_be_bytes` is big-endian; `TryFrom<&[T]> for [T;N]`
//         fails iff the length is not N; vstd's specs for Vec, slices, arrays; `&[u8;N]` fixes
//         the length.
//  A_ALLOC (ASSUMED). Allocation of the output Vec succeeds. Rust aborts otherwise; it does not
//         return Err. The size 60 + n is not checked against isize::MAX.
//  H_MODEL_MATCH (CODE READING). The model's control flow and byte assembly equal the shipped
//         `wrap` and the parse half of `unwrap` at the lines in section 2. Not machine-checked.
//  H_AAD_PURE (CODE READING). `compute_aad` (:61-79) and `uuid_str_to_16_bytes` (:92-111) are
//         pure functions of the materials and the encryption context: they take only `&str`,
//         `&EncryptionContext`, call no generator and read no global state. So passing their
//         results in as values changes neither which draws happen nor their order. Their Err is
//         returned unchanged by `?`.
//  H_NO_STATE (CODE READING). `wrap` reads no `static`, `thread_local` or other cross-call state.
//         `salt` and `iv` are fresh locals filled by the generator (:163-172). The only shared
//         thing is the generator, which the model makes visible as `Rng`. The log lists the
//         draws of this call chain only; draws by other threads (the aws-lc-rs generator is
//         process-global) are not modeled. This does not affect the per-call structure proved.
//  H_RNG_DIFFERS (PREMISE ONLY). "The salt draws of two calls differ, or the IV draws differ."
//         It is the antecedent of `lemma_distinct_draws_distinct_outputs` and of the last
//         `ensures` line of `wrap_twice`. It is never established, and nothing here says that
//         it holds.
//  H_WIPE (CODE READING, NOT PROVED). The derived key is wiped. `derive_branch_key` returns
//         `Zeroizing<[u8;32]>` (:122-125, :135, comment :134), `wrap` binds it as
//         `derived_branch_key` (:175) and passes `&*derived_branch_key` (:202); the binding is
//         dropped on every exit of `wrap`, success or error, and the `zeroize` crate wipes on
//         drop. Verus has no model of `Drop`, so the model drops `Zeroizing` (identity) and
//         proves nothing about wiping. Copies inside aws-lc-rs (the AES key schedule built by
//         `UnboundKey::new`, :187) are not covered.
//
// =============================================================================
// 5. MODEL-vs-CODE GAP
// =============================================================================
//  The shipped functions are not inside `verus!`, are not compiled here, and nothing detects a
//  later edit to branch_key_wrap.rs or prim/src/lib.rs. To close the gap one needs ALL of:
//   1. `wrap`, `unwrap`, `derive_branch_key` and the constants moved into `verus!`, or
//      `cargo verus` on the crate;
//   2. `assume_specification` for `Zeroizing`, `Error::with_cause`, `u32::to_be_bytes`,
//      `Vec::with_capacity` capacity, `usize::saturating_add`;
//   3. `generate_random_bytes`, `aes_encrypt` and `kbkdf_ctr_hmac` given contracts exactly as
//      in trait `Prim` (that is where the aws-lc-rs trusted base would be written down), and
//      a ghost generator log that the real global generator does not have;
//   4. `compute_aad` and `uuid_str_to_16_bytes` specified, or the pure-function claim proved.
//  Until then the evidence level is: hand-checked model + machine-checked logic.
//
// =============================================================================
// 6. NOT COVERED
// =============================================================================
//  * Termination with Ok. All `ensures` are partial correctness (`r is Ok ==> ...`). Nothing
//    proves that `wrap` returns Ok for any input; a model that always returned Err satisfies
//    them (mutant MA, see mutations.md).
//  * `unwrap` parses the version field but does not use or compare it (:254, `_version`); R6
//    and R7 show only that the layout carries it.
//  * Freshness, randomness and uniqueness of salt and IV (see the top of this file). The
//    birthday-bound argument of TM-MPL-012 and the rotation cadence.
//  * Correctness of aws-lc-rs: the generator, AES-GCM, the KBKDF. The seal and the KDF output
//    are uninterpreted. Decrypt is not modeled: the round trip proved here is the round trip of
//    the LAYOUT (R7), not of the plaintext. `unwrap`'s AAD step and `aes_decrypt` are out.
//  * Wiping of the derived key (H_WIPE) and of any other secret; timing and side channels.
//  * The content of the AAD and the version bytes; the Err message and cause text.
//  * Whether the generator, the KDF or the seal can fail at all. The model lets each fail and
//    proves the shape of the failure, not its absence.
//  * Allocation failure and the size limit of the output Vec (A_ALLOC).
//  * Interop of the layout with other MPL implementations beyond the spec text.
//
//  OBSERVATION O1 (code reading, low, not a proof obligation). On the error path of
//  `aes_encrypt`, the `output` Vec can hold a plaintext copy of the data key. `aes_encrypt`
//  appends the message first (prim :185) and seals in place afterwards, so an Err after :185
//  returns with the clear message at the tail of `output`. `wrap` then drops `output` with a
//  plain `Vec<u8>` (not `Zeroizing`), so those bytes are freed without being wiped. In `wrap`
//  the two shape checks (:187-189) cannot fail (types, A_AES), so only a failing seal reaches
//  it; which inputs make aws-lc-rs fail are not examined here. The success path is not
//  affected: the output holds ciphertext, and the capacity 60 + n equals the final length (:193),
//  so the Vec is not reallocated while it holds the clear message. The plaintext data key also
//  lives in the caller's buffer, which this function does not own. This is a hygiene point
//  about residue, not a disclosure on the returned value. The model has no memory contents, so
//  no honest expected-FAIL obligation can be written for it; it is reported here only.
//
// =============================================================================
// 7. RESULTS  (PROVED relative to the model and the hypotheses of section 4)
// =============================================================================
//  R1  wrap, log           the generator log only grows, by at most two entries (log_extends).
//                          On Ok it grows by exactly two: a 16-byte entry (the salt draw) and
//                          then a 12-byte entry (the IV draw). Two separate calls, this order.
//                          If the salt draw fails, the IV draw is never made (early return in the code;
//                          not a separate ensures).
//  R2  wrap, layout        on Ok: out == salt_draw || iv_draw || version || sealed, |out| =
//                          60 + |pt| (the 16 + n tail is A_AES, not proved; see section 8), with the draws at bytes 0..16 and 16..28, the version at
//                          28..44 and the sealed part (ciphertext || tag) at 44..60+n.
//                          theorem_out_layout states the offsets for any n (also n = 0).
//  R3  wrap, inputs        sealed == seal_spec(Aes256Gcm, iv_draw, derived_key_spec(branch_key,
//                          salt_draw), pt, aad): the SALT draw feeds the KDF (the T05
//                          derivation) and the IV draw is the AES IV. Verus accepts this only
//                          because the call passes `iv` and `derived`, and because the array
//                          written at bytes 16..28 is the one passed as the IV.
//  R4  aes preconditions   the two argument-shape `requires` of A_AES hold at the call (checked
//                          by Verus): key length 32 for Aes256Gcm, IV length 12.
//  R5  wrap, errors        every Err is Cryptographic, or the unchanged Err of the AAD or
//                          version helper. Ok implies both helpers succeeded. An Err carries
//                          only an `Error`: the partly built `output` is a local and is not
//                          returned (by type; see O1 for what it may hold). After an Err the
//                          log still extends the old log.
//  R6  unwrap_parse        len < 60 gives Err before any slicing and before the primitive;
//                          len >= 60 makes every slice and every `try_into().expect` in bounds
//                          (Verus-checked); the fields equal parse_* of the ciphertext; the tag
//                          has 16 bytes; the KDF salt is ct[0..16].
//  R7  round trip          theorem_roundtrip_layout: for the layout wrap builds, the length gate
//                          accepts it, and parse recovers salt, IV, version, the encrypted key
//                          (n bytes) and the tag (16 bytes), and the KDF input equals wrap's.
//                          Layout only; the plaintext round trip needs decrypt and is not here.
//  R8  conditional         lemma_distinct_draws_distinct_outputs and the last ensures of
//      distinctness        wrap_twice: IF the salt draws or the IV draws of two calls differ
//                          (H_RNG_DIFFERS), THEN the outputs differ. wrap_twice also proves
//                          that the two calls use four distinct log positions (not necessarily
//                          different values), call 1 the first two and call 2 the last two, and each output carries its own call's
//                          draws at bytes 0..28.
//  R9  witnesses           toy_generate_random_bytes meets the A_RNG contract (so the contract
//                          is consistent and does not force randomness); concrete layouts for
//                          n = 32 (92 bytes) and n = 0 (60 bytes); two concrete distinct salts.
//
// =============================================================================
// 8. FINDINGS AND EXPECTED-FAIL OBLIGATIONS
// =============================================================================
//  No expected-FAIL obligation is included. Every property stated here that the code can meet
//  at model level, it meets. I looked for a code gap against S1-S6 and found none: two
//  separate draws, both into the right places, the right lengths, every step's failure
//  returns Err. A failing obligation would have to be invented. The only point I found is O1
//  above, which is not expressible in a model without memory contents.
//  One caveat on R2: the length 60 + n rests on A_AES. The shipped `debug_assert_eq!` (:209)
//  that would catch a violation is compiled out in release builds.
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

/// Error kind. The shipped crate's Kind has many variants; `wrap`, `unwrap` and `derive_branch_key`
/// produce only `Kind::Cryptographic` (branch_key_wrap.rs:138, :165, :171, :209, :238).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ErrKind {
    Cryptographic,
    /// Stands for any other kind: the unchanged Err of `compute_aad` (:178) or
    /// `uuid_str_to_16_bytes` (:185). `wrap` itself produces only Cryptographic.
    Other,
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
// SECTION 4: The primitives as contracts. THIS IS THE TRUSTED BASE OF THE MODEL.
// ============================================================

/// prim::AesGcm (prim/src/lib.rs:134-143). `wrap` passes only `Aes256Gcm` (branch_key_wrap.rs:200).
/// All three are listed so that the choice is real and a wrong-algorithm mutation is expressible.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AesGcm {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
}

/// prim::AesGcm::key_length (prim/src/lib.rs:148-154).
pub open spec fn key_length(alg: AesGcm) -> nat {
    match alg {
        AesGcm::Aes128Gcm => 16,
        AesGcm::Aes192Gcm => 24,
        AesGcm::Aes256Gcm => 32,
    }
}

/// Ghost model of the random number generator behind `generate_random_bytes`
/// (prim/src/lib.rs:128-132, which calls `aws_lc_rs::rand::fill`). The shipped function has no
/// such parameter: the generator is process-global state inside aws-lc-rs. The model threads it
/// as an explicit `&mut Rng` so that the proof can SEE how many draws a call makes.
///
/// `log` records every buffer the generator has handed out, in call order. It is ghost only.
/// It says nothing about the VALUES: any byte sequences may appear in it (A_RNG).
pub struct Rng {
    pub log: Ghost<Seq<Seq<u8>>>,
}

/// The AES-GCM seal of `msg` under (alg, key, iv, aad): ciphertext followed by the 16-byte tag.
/// UNINTERPRETED: no definition and no axiom. Used only through the contract of `Prim::aes_encrypt`.
pub uninterp spec fn seal_spec(alg: AesGcm, iv: Seq<u8>, key: Seq<u8>, msg: Seq<u8>, aad: Seq<u8>) -> Seq<u8>;

/// Stands for the three `aws_mpl_primitives` functions that `wrap` and `derive_branch_key` call
/// (prim/src/lib.rs:313-330 `kbkdf_ctr_hmac`, :128-132 `generate_random_bytes`,
/// :175-197 `aes_encrypt`), argument order as in the shipped signatures.
///
/// Every contract below is a HYPOTHESIS on any implementation, not a proved fact:
///   A_KDF  `kbkdf_ctr_hmac`: the buffer keeps its length; on Ok it holds `kbkdf_spec(..)`.
///          (Copied from T05 unchanged.)
///   A_RNG  `generate_random_bytes`: the buffer keeps its length; on Ok the call is recorded in
///          the log exactly once and the buffer equals the recorded entry; on Err the log is
///          unchanged. NOTHING is said about which bytes are drawn. In particular the contract
///          is satisfied by a generator that always returns zeros (see `toy_generate_random_bytes`).
///   A_AES  `aes_encrypt`: on Ok the Vec grows by exactly `seal_spec(..)`, and that has
///          `message.len() + 16` bytes. This is what the code at prim/src/lib.rs:184-196 does
///          (extend by the message, seal in place, extend by the tag) given two aws-lc-rs facts:
///          `seal_in_place_separate_tag` keeps the buffer length, and an AES-GCM tag is 16 bytes.
///          The `requires` (key length for `alg`, IV length 12) are the two argument-shape checks
///          at :187-189 (`UnboundKey::new`, `Nonce::try_assume_unique_for_key`): the shipped
///          function returns Err when they fail, so the model asks the CALLER to establish them.
///          Nothing is said about the Vec on Err.
pub trait Prim {
    fn kbkdf_ctr_hmac(alg: DigestAlg, ikm: &[u8], info: &[u8], okm: &mut [u8]) -> (r: Result<(), Error>)
        ensures
            final(okm)@.len() == old(okm)@.len(),
            r is Ok ==> final(okm)@ == kbkdf_spec(alg, ikm@, info@, old(okm)@.len() as nat),
    ;

    fn generate_random_bytes(rng: &mut Rng, bytes: &mut [u8]) -> (r: Result<(), Error>)
        ensures
            final(bytes)@.len() == old(bytes)@.len(),
            r is Ok ==> final(rng).log@ == old(rng).log@.push(final(bytes)@),
            r is Err ==> final(rng).log@ == old(rng).log@,
    ;

    fn aes_encrypt(
        alg: AesGcm,
        iv: &[u8],
        key: &[u8],
        message: &[u8],
        aad: &[u8],
        cipher_text: &mut Vec<u8>,
    ) -> (r: Result<(), Error>)
        requires
            key@.len() == key_length(alg),
            iv@.len() == IV_LEN,
        ensures
            r is Ok ==> final(cipher_text)@ == old(cipher_text)@ + seal_spec(alg, iv@, key@, message@, aad@),
            r is Ok ==> seal_spec(alg, iv@, key@, message@, aad@).len() == message@.len() + TAG_LEN,
    ;
}

// Satisfiability of A_RNG (not of A_KDF or A_AES, which mention uninterpreted functions):
// a generator that fills zeros and records the call meets the A_RNG contract. This shows the
// contract is consistent. It also shows the contract does not force randomness.
pub fn toy_generate_random_bytes(rng: &mut Rng, bytes: &mut [u8]) -> (r: Result<(), Error>)
    ensures
        final(bytes)@.len() == old(bytes)@.len(),
        r is Ok ==> final(rng).log@ == old(rng).log@.push(final(bytes)@),
        r is Err ==> final(rng).log@ == old(rng).log@,
{
    let mut i: usize = 0;
    let n = bytes.len();
    while i < n
        invariant
            n == bytes@.len(),
            n == old(bytes)@.len(),
            i <= n,
        decreases n - i,
    {
        bytes[i] = 0u8;
        i += 1;
    }
    let ghost new_log = rng.log@.push(bytes@);
    rng.log = Ghost(new_log);
    Ok(())
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


// ============================================================
// SECTION 6: Specification of the wrap output and of the RNG log
// ============================================================

/// `new` is `old` followed by zero or more entries. (The generator only ever appends.)
pub open spec fn log_extends(old: Seq<Seq<u8>>, new: Seq<Seq<u8>>) -> bool {
    &&& old.len() <= new.len()
    &&& new.subrange(0, old.len() as int) == old
}

/// The buffer handed back by the first generator call made after `old` (the salt draw of one
/// `wrap` call), and by the second (the IV draw). Positions are fixed by the call order in
/// branch_key_wrap.rs:163-166 (salt) and :169-172 (IV).
pub open spec fn salt_draw(old: Seq<Seq<u8>>, new: Seq<Seq<u8>>) -> Seq<u8> {
    new[old.len() as int]
}

pub open spec fn iv_draw(old: Seq<Seq<u8>>, new: Seq<Seq<u8>>) -> Seq<u8> {
    new[old.len() as int + 1]
}

/// The AES-256-GCM seal that `wrap` appends: key = derived branch key (from the SALT draw),
/// IV = the IV draw, message = the plaintext data key, aad = the AAD bytes.
pub open spec fn wrap_sealed(salt: Seq<u8>, iv: Seq<u8>, branch_key: Seq<u8>, pt: Seq<u8>, aad: Seq<u8>) -> Seq<u8> {
    seal_spec(AesGcm::Aes256Gcm, iv, derived_key_spec(branch_key, salt), pt, aad)
}

/// SPEC-DERIVED (S7) layout as wrap assembles it: salt || iv || version || (ciphertext || tag).
pub open spec fn out_layout(salt: Seq<u8>, iv: Seq<u8>, version: Seq<u8>, sealed: Seq<u8>) -> Seq<u8> {
    salt + iv + version + sealed
}

/// The AAD bytes / version bytes of a helper result. The helpers themselves are not modeled
/// (H_AAD_PURE); an Err yields the empty sequence and is never used on an Ok path.
pub open spec fn ok_aad(r: Result<Vec<u8>, Error>) -> Seq<u8> {
    match r {
        Ok(v) => v@,
        Err(_) => Seq::empty(),
    }
}

pub open spec fn ok_version(r: Result<[u8; 16], Error>) -> Seq<u8> {
    match r {
        Ok(v) => v@,
        Err(_) => Seq::empty(),
    }
}

// What unwrap reads out of a ciphertext of length >= 60 (branch_key_wrap.rs:247-262).
pub open spec fn parse_salt(ct: Seq<u8>) -> Seq<u8> {
    ct.subrange(0, 16)
}

pub open spec fn parse_iv(ct: Seq<u8>) -> Seq<u8> {
    ct.subrange(16, 28)
}

pub open spec fn parse_version(ct: Seq<u8>) -> Seq<u8> {
    ct.subrange(28, 44)
}

pub open spec fn parse_encrypted_key(ct: Seq<u8>) -> Seq<u8> {
    ct.subrange(44, ct.len() as int - 16)
}

pub open spec fn parse_tag(ct: Seq<u8>) -> Seq<u8> {
    ct.subrange(ct.len() as int - 16, ct.len() as int)
}

// ============================================================
// SECTION 7: Lemmas about the log and the layout
// ============================================================

pub proof fn lemma_extends_refl(a: Seq<Seq<u8>>)
    ensures
        log_extends(a, a),
{
    assert(a.subrange(0, a.len() as int) =~= a);
}

pub proof fn lemma_extends_push(a: Seq<Seq<u8>>, x: Seq<u8>)
    ensures
        log_extends(a, a.push(x)),
        a.push(x).len() == a.len() + 1,
        a.push(x)[a.len() as int] == x,
{
    assert(a.push(x).subrange(0, a.len() as int) =~= a);
}

pub proof fn lemma_extends_trans(a: Seq<Seq<u8>>, b: Seq<Seq<u8>>, c: Seq<Seq<u8>>)
    requires
        log_extends(a, b),
        log_extends(b, c),
    ensures
        log_extends(a, c),
{
    assert(c.subrange(0, a.len() as int) =~= a) by {
        assert forall|i: int| #![auto] 0 <= i < a.len() implies c.subrange(0, a.len() as int)[i] == a[i] by {
            assert(c.subrange(0, b.len() as int)[i] == b[i]);
            assert(b.subrange(0, a.len() as int)[i] == a[i]);
        }
    }
}

/// An entry that is in `old` stays at the same index in any extension of `old`.
pub proof fn lemma_extends_index(old: Seq<Seq<u8>>, new: Seq<Seq<u8>>, k: int)
    requires
        log_extends(old, new),
        0 <= k < old.len(),
    ensures
        new[k] == old[k],
{
    assert(new.subrange(0, old.len() as int)[k] == old[k]);
}

/// The layout theorem on sequences. For a 16-byte salt, 12-byte IV, 16-byte version and a sealed
/// part of n + 16 bytes (ciphertext of n bytes, then the tag), the output has 60 + n bytes and
/// every field sits at its offset.
pub proof fn theorem_out_layout(salt: Seq<u8>, iv: Seq<u8>, version: Seq<u8>, sealed: Seq<u8>, n: nat)
    requires
        salt.len() == SALT_LEN,
        iv.len() == IV_LEN,
        version.len() == VERSION_LEN,
        sealed.len() == n + TAG_LEN,
    ensures
        out_layout(salt, iv, version, sealed).len() == FIXED_OVERHEAD_LEN + n,
        out_layout(salt, iv, version, sealed).subrange(0, 16) == salt,
        out_layout(salt, iv, version, sealed).subrange(16, 28) == iv,
        out_layout(salt, iv, version, sealed).subrange(28, 44) == version,
        out_layout(salt, iv, version, sealed).subrange(44, 44 + n as int + 16) == sealed,
        out_layout(salt, iv, version, sealed).subrange(44, 44 + n as int) == sealed.subrange(0, n as int),
        out_layout(salt, iv, version, sealed).subrange(44 + n as int, 44 + n as int + 16)
            == sealed.subrange(n as int, n as int + 16),
{
    lemma_constants();
    let o = out_layout(salt, iv, version, sealed);
    assert(o.len() == 60 + n);
    assert(o.subrange(0, 16) =~= salt);
    assert(o.subrange(16, 28) =~= iv);
    assert(o.subrange(28, 44) =~= version);
    assert(o.subrange(44, 44 + n as int + 16) =~= sealed);
    assert(o.subrange(44, 44 + n as int) =~= sealed.subrange(0, n as int));
    assert(o.subrange(44 + n as int, 44 + n as int + 16) =~= sealed.subrange(n as int, n as int + 16));
}

/// Round trip of the LAYOUT (not of the plaintext). What unwrap reads out of a wrap output is
/// exactly what wrap put in: salt, IV, version, the encrypted key (n bytes) and the tag; the
/// length gate (>= 60) accepts the output; and unwrap's KDF input equals wrap's.
/// Everything below `parse_*` is the spec of branch_key_wrap.rs:247-262.
pub proof fn theorem_roundtrip_layout(
    branch_key: Seq<u8>,
    salt: Seq<u8>,
    iv: Seq<u8>,
    version: Seq<u8>,
    sealed: Seq<u8>,
    n: nat,
)
    requires
        salt.len() == SALT_LEN,
        iv.len() == IV_LEN,
        version.len() == VERSION_LEN,
        sealed.len() == n + TAG_LEN,
    ensures
        out_layout(salt, iv, version, sealed).len() >= FIXED_OVERHEAD_LEN,
        parse_salt(out_layout(salt, iv, version, sealed)) == salt,
        parse_iv(out_layout(salt, iv, version, sealed)) == iv,
        parse_version(out_layout(salt, iv, version, sealed)) == version,
        parse_encrypted_key(out_layout(salt, iv, version, sealed)) == sealed.subrange(0, n as int),
        parse_tag(out_layout(salt, iv, version, sealed)) == sealed.subrange(n as int, n as int + 16),
        derived_key_spec(branch_key, parse_salt(out_layout(salt, iv, version, sealed)))
            == derived_key_spec(branch_key, salt),
{
    theorem_out_layout(salt, iv, version, sealed, n);
    let o = out_layout(salt, iv, version, sealed);
    assert(parse_encrypted_key(o) == o.subrange(44, 44 + n as int));
    assert(parse_tag(o) == o.subrange(44 + n as int, 44 + n as int + 16));
}

/// CONDITIONAL distinctness. This is NOT a freshness claim. If the salt draws differ, or the IV
/// draws differ, then the two output layouts differ, for ANY version and sealed parts.
/// The premise (H_RNG_DIFFERS) is the thing nobody here proves: that two calls to the real
/// generator return different bytes. The lemma only says the layout does not collapse a
/// difference in the draws (the draws sit unmodified at bytes 0..28 of the output).
pub proof fn lemma_distinct_draws_distinct_outputs(
    s1: Seq<u8>,
    i1: Seq<u8>,
    v1: Seq<u8>,
    c1: Seq<u8>,
    s2: Seq<u8>,
    i2: Seq<u8>,
    v2: Seq<u8>,
    c2: Seq<u8>,
)
    requires
        s1.len() == SALT_LEN,
        i1.len() == IV_LEN,
        s2.len() == SALT_LEN,
        i2.len() == IV_LEN,
        s1 != s2 || i1 != i2,  // H_RNG_DIFFERS (premise only)
    ensures
        out_layout(s1, i1, v1, c1) != out_layout(s2, i2, v2, c2),
{
    let o1 = out_layout(s1, i1, v1, c1);
    let o2 = out_layout(s2, i2, v2, c2);
    assert(o1.subrange(0, 16) =~= s1);
    assert(o2.subrange(0, 16) =~= s2);
    assert(o1.subrange(16, 28) =~= i1);
    assert(o2.subrange(16, 28) =~= i2);
    if o1 == o2 {
        assert(s1 == s2);
        assert(i1 == i2);
    }
}

// ============================================================
// SECTION 8: Executable model of wrap (branch_key_wrap.rs:157-218)
// ============================================================

/// Model of `wrap`. Inputs that are not modeled as code:
///   * `rng`: the global generator, as a ghost log (see `Rng`). No other state is read (H_NO_STATE).
///   * `aad`, `version`: the results of `compute_aad(..)` (:178) and `uuid_str_to_16_bytes(..)`
///     (:185). They are pure functions of the materials and the encryption context (H_AAD_PURE),
///     so they are passed in as values; their Err is passed through unchanged by `?`.
///   * `branch_key`: `materials.branch_key()`, a `&[u8; 32]`.
///
/// `ensures`, in words:
///   1. The generator log only grows, by at most two entries.
///   2. On Ok it grew by exactly two: one entry of 16 bytes (the salt draw), then one of 12 bytes
///      (the IV draw). Two separate calls, in this order, on every call that returns Ok (a
///      call can fail before or after the draws).
///   3. On Ok the output is `salt_draw || iv_draw || version || sealed`, so its length is
///      60 + |pt|, and the draws sit at bytes 0..16 and 16..28.
///   4. `sealed` is the AES-256-GCM seal under the key derived from THE SALT DRAW (T05
///      derivation), with THE IV DRAW as the IV, over the plaintext and the AAD.
///   5. Every Err is Cryptographic, unless it is the unchanged Err of the AAD or version helper.
///      On Err the caller gets no bytes: the only value returned is an `Error`.
pub fn wrap<P: Prim>(
    rng: &mut Rng,
    branch_key: &[u8; 32],
    aad: Result<Vec<u8>, Error>,
    version: Result<[u8; 16], Error>,
    plaintext_data_key: &[u8],
) -> (r: Result<Vec<u8>, Error>)
    ensures
        log_extends(old(rng).log@, final(rng).log@),
        final(rng).log@.len() <= old(rng).log@.len() + 2,
        r is Ok ==> aad is Ok && version is Ok,
        r is Ok ==> final(rng).log@.len() == old(rng).log@.len() + 2,
        r is Ok ==> salt_draw(old(rng).log@, final(rng).log@).len() == SALT_LEN,
        r is Ok ==> iv_draw(old(rng).log@, final(rng).log@).len() == IV_LEN,
        r is Ok ==> r->Ok_0@.len() == FIXED_OVERHEAD_LEN + plaintext_data_key@.len(),
        r is Ok ==> r->Ok_0@.subrange(0, 16) == salt_draw(old(rng).log@, final(rng).log@),
        r is Ok ==> r->Ok_0@.subrange(16, 28) == iv_draw(old(rng).log@, final(rng).log@),
        r is Ok ==> r->Ok_0@.subrange(28, 44) == ok_version(version),
        r is Ok ==> r->Ok_0@.subrange(44, r->Ok_0@.len() as int) == wrap_sealed(
            salt_draw(old(rng).log@, final(rng).log@),
            iv_draw(old(rng).log@, final(rng).log@),
            branch_key@,
            plaintext_data_key@,
            ok_aad(aad),
        ),
        r is Ok ==> r->Ok_0@ == out_layout(
            salt_draw(old(rng).log@, final(rng).log@),
            iv_draw(old(rng).log@, final(rng).log@),
            ok_version(version),
            wrap_sealed(
                salt_draw(old(rng).log@, final(rng).log@),
                iv_draw(old(rng).log@, final(rng).log@),
                branch_key@,
                plaintext_data_key@,
                ok_aad(aad),
            ),
        ),
        r is Err ==> r->Err_0.kind == ErrKind::Cryptographic || aad is Err || version is Err,
{
    proof {
        lemma_constants();
    }
    let ghost log0 = rng.log@;
    proof {
        lemma_extends_refl(log0);
    }
    // 1. :163-166  salt: a local array, filled by one generator call; Err is mapped to Cryptographic.
    let mut salt = [0u8; 16];
    match P::generate_random_bytes(rng, &mut salt) {
        Ok(()) => {},
        Err(_) => {
            return Err(Error { kind: ErrKind::Cryptographic });
        },
    }
    let ghost log1 = rng.log@;
    proof {
        assert(log1 == log0.push(salt@));
        lemma_extends_push(log0, salt@);
    }
    // 2. :169-172  iv: a second local array, filled by a second, separate generator call.
    let mut iv = [0u8; 12];
    match P::generate_random_bytes(rng, &mut iv) {
        Ok(()) => {},
        Err(_) => {
            proof {
                // Err: the log is the one after the salt draw, which extends log0.
                assert(rng.log@ == log1);
            }
            return Err(Error { kind: ErrKind::Cryptographic });
        },
    }
    let ghost log2 = rng.log@;
    proof {
        assert(log2 == log1.push(iv@));
        lemma_extends_push(log1, iv@);
        lemma_extends_trans(log0, log1, log2);
        assert(log2.len() == log0.len() + 2);
        assert(log2[log0.len() as int] == salt@) by {
            lemma_extends_index(log1, log2, log0.len() as int);
            assert(log1[log0.len() as int] == salt@);
        }
        assert(log2[log0.len() as int + 1] == iv@);
    }
    // 3. :175  derived key from the SALT array (T05 derivation).
    let derived = match derive_branch_key::<P>(branch_key, &salt) {
        Ok(d) => d,
        Err(e) => {
            return Err(e);
        },
    };
    // 4. :178-185  AAD and version bytes (pure helpers, passed in).
    let aad_bytes = match aad {
        Ok(a) => a,
        Err(e) => {
            return Err(e);
        },
    };
    let version_bytes = match version {
        Ok(v) => v,
        Err(e) => {
            return Err(e);
        },
    };
    // 5. :191-197  assemble the prefix. `output` is local and is returned only on Ok.
    //    The capacity is a hint (model of FIXED_OVERHEAD_LEN.saturating_add(pt.len())).
    let cap: usize = if plaintext_data_key.len() <= usize::MAX - FIXED_OVERHEAD_LEN {
        FIXED_OVERHEAD_LEN + plaintext_data_key.len()
    } else {
        usize::MAX
    };
    let mut output: Vec<u8> = Vec::with_capacity(cap);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&iv);
    output.extend_from_slice(&version_bytes);
    let pre_encrypt_len = output.len();
    proof {
        assert(output@ =~= salt@ + iv@ + version_bytes@);
        assert(pre_encrypt_len == 44);
    }
    // :199-207  the AES call: key = derived key, iv = the IV array, aad = the AAD bytes.
    //           `AesGcm::Aes256Gcm` needs a 32-byte key and a 12-byte IV: both are array types.
    match P::aes_encrypt(AesGcm::Aes256Gcm, &iv, &derived, plaintext_data_key, &aad_bytes, &mut output) {
        Ok(()) => {},
        Err(_) => {
            // :207  `?` returns; `output` is dropped and never returned.
            return Err(Error { kind: ErrKind::Cryptographic });
        },
    }
    // :209-213  debug_assert_eq!(output.len() - pre_encrypt_len, pt.len() + TAG_LEN): the model proves it.
    assert(output.len() - pre_encrypt_len == plaintext_data_key.len() + TAG_LEN);
    proof {
        let sealed = wrap_sealed(salt@, iv@, branch_key@, plaintext_data_key@, aad_bytes@);
        assert(derived@ == derived_key_spec(branch_key@, salt@));
        assert(sealed == seal_spec(AesGcm::Aes256Gcm, iv@, derived@, plaintext_data_key@, aad_bytes@));
        assert(output@ == salt@ + iv@ + version_bytes@ + sealed);
        theorem_out_layout(salt@, iv@, version_bytes@, sealed, plaintext_data_key@.len());
        assert(output@.subrange(44, output@.len() as int) =~= sealed);
        assert(salt@ == salt_draw(log0, log2));
        assert(iv@ == iv_draw(log0, log2));
    }
    // :217  Ok(output)
    Ok(output)
}

// ============================================================
// SECTION 9: Two calls: each makes its own draws; the distinctness premise is explicit
// ============================================================

/// Calls `wrap` twice on the same generator. Shows the per-call structure:
///   * four new log positions (the values at them may be equal), the first two belong to the
///     first call, the last two to the second;
///   * each output carries ITS OWN call's draws at bytes 0..28;
///   * IF the draws of the two calls differ (the antecedent, H_RNG_DIFFERS), THEN the outputs
///     differ. The antecedent is not established anywhere in this file.
pub fn wrap_twice<P: Prim>(
    rng: &mut Rng,
    branch_key: &[u8; 32],
    aad1: Result<Vec<u8>, Error>,
    version1: Result<[u8; 16], Error>,
    aad2: Result<Vec<u8>, Error>,
    version2: Result<[u8; 16], Error>,
    plaintext_data_key: &[u8],
) -> (r: Result<(Vec<u8>, Vec<u8>), Error>)
    ensures
        log_extends(old(rng).log@, final(rng).log@),
        r is Ok ==> final(rng).log@.len() == old(rng).log@.len() + 4,
        r is Ok ==> r->Ok_0.0@.subrange(0, 16) == final(rng).log@[old(rng).log@.len() as int],
        r is Ok ==> r->Ok_0.0@.subrange(16, 28) == final(rng).log@[old(rng).log@.len() as int + 1],
        r is Ok ==> r->Ok_0.1@.subrange(0, 16) == final(rng).log@[old(rng).log@.len() as int + 2],
        r is Ok ==> r->Ok_0.1@.subrange(16, 28) == final(rng).log@[old(rng).log@.len() as int + 3],
        // H_RNG_DIFFERS as an antecedent: different draws give different outputs.
        r is Ok ==> (final(rng).log@[old(rng).log@.len() as int] != final(rng).log@[old(rng).log@.len() as int + 2]
            || final(rng).log@[old(rng).log@.len() as int + 1]
            != final(rng).log@[old(rng).log@.len() as int + 3]) ==> r->Ok_0.0@ != r->Ok_0.1@,
{
    let ghost log0 = rng.log@;
    let out1 = match wrap::<P>(rng, branch_key, aad1, version1, plaintext_data_key) {
        Ok(o) => o,
        Err(e) => {
            return Err(e);
        },
    };
    let ghost log1 = rng.log@;
    let out2 = match wrap::<P>(rng, branch_key, aad2, version2, plaintext_data_key) {
        Ok(o) => o,
        Err(e) => {
            proof {
                lemma_extends_trans(log0, log1, rng.log@);
            }
            return Err(e);
        },
    };
    let ghost log2 = rng.log@;
    proof {
        lemma_extends_trans(log0, log1, log2);
        let n = log0.len() as int;
        // Entries n, n+1 were written by call 1 and survive in log2 (log2 extends log1).
        lemma_extends_index(log1, log2, n);
        lemma_extends_index(log1, log2, n + 1);
        assert(log2[n + 2] == salt_draw(log1, log2));
        assert(log2[n + 3] == iv_draw(log1, log2));
        assert(out1@.subrange(0, 16) == log1[n]);
        assert(out1@.subrange(16, 28) == log1[n + 1]);
        assert(out2@.subrange(0, 16) == log2[n + 2]);
        assert(out2@.subrange(16, 28) == log2[n + 3]);
        if log2[n] != log2[n + 2] || log2[n + 1] != log2[n + 3] {
            // out1 and out2 are out_layout(..) values with the draws at the front.
            let s1 = log2[n];
            let i1 = log2[n + 1];
            let s2 = log2[n + 2];
            let i2 = log2[n + 3];
            assert(s1.len() == SALT_LEN && i1.len() == IV_LEN);
            assert(s2.len() == SALT_LEN && i2.len() == IV_LEN);
            if out1@ == out2@ {
                assert(out1@.subrange(0, 16) == out2@.subrange(0, 16));
                assert(out1@.subrange(16, 28) == out2@.subrange(16, 28));
                assert(s1 == s2);
                assert(i1 == i2);
            }
        }
    }
    Ok((out1, out2))
}

// ============================================================
// SECTION 10: unwrap parse leg (branch_key_wrap.rs:236-265)
// ============================================================

/// Model of "copy a 12-byte slice into a [u8;12]" = `try_into().expect(..)` at :250-252.
pub fn array12_from_slice(s: &[u8]) -> (r: [u8; 12])
    requires
        s@.len() == 12,
    ensures
        r@ == s@,
{
    let mut a = [0u8; 12];
    let mut i: usize = 0;
    while i < 12
        invariant
            i <= 12,
            s@.len() == 12,
            a@.len() == 12,
            forall|j: int| 0 <= j < i ==> a@[j] == s@[j],
        decreases 12 - i,
    {
        a[i] = s[i];
        i += 1;
    }
    assert(a@ =~= s@);
    a
}

/// Fields that unwrap reads out of the ciphertext. `encrypted_key` and `tag` are borrowed slices.
pub struct Parsed<'a> {
    pub derived: [u8; 32],
    pub salt: [u8; 16],
    pub iv: [u8; 12],
    pub version: [u8; 16],
    pub encrypted_key: &'a [u8],
    pub tag: &'a [u8],
}

/// Model of unwrap up to the KDF (:236-265), with the IV, version, encrypted key and tag returned.
/// AAD construction, AES-GCM decryption and the plaintext buffer (:267-286) are NOT modeled.
///   * `ct.len() < 60`: Err, before any slicing and before the primitive.
///   * `ct.len() >= 60`: every slice is in bounds and every `try_into().expect` sees the right
///     length (Verus-checked); the fields equal the `parse_*` specs; the KDF salt is `ct[0..16]`.
pub fn unwrap_parse<'a, P: Prim>(branch_key: &[u8; 32], ct: &'a [u8]) -> (r: Result<Parsed<'a>, Error>)
    ensures
        ct@.len() < FIXED_OVERHEAD_LEN ==> r is Err,
        r is Ok ==> ct@.len() >= FIXED_OVERHEAD_LEN,
        r is Ok ==> r->Ok_0.salt@ == parse_salt(ct@),
        r is Ok ==> r->Ok_0.iv@ == parse_iv(ct@),
        r is Ok ==> r->Ok_0.version@ == parse_version(ct@),
        r is Ok ==> r->Ok_0.encrypted_key@ == parse_encrypted_key(ct@),
        r is Ok ==> r->Ok_0.tag@ == parse_tag(ct@),
        r is Ok ==> r->Ok_0.tag@.len() == TAG_LEN,
        r is Ok ==> r->Ok_0.derived@ == derived_key_spec(branch_key@, parse_salt(ct@)),
        r is Err ==> r->Err_0.kind == ErrKind::Cryptographic,
{
    // :236-244
    if ct.len() < FIXED_OVERHEAD_LEN {
        return Err(Error { kind: ErrKind::Cryptographic });
    }
    // :247-249
    let salt = array16_from_slice(&ct[0..SALT_LEN]);
    // :250-252
    let iv = array12_from_slice(&ct[SALT_LEN..SALT_LEN + IV_LEN]);
    // :253-256
    let version_offset = SALT_LEN + IV_LEN;
    let version = array16_from_slice(&ct[version_offset..version_offset + VERSION_LEN]);
    // :257-261
    let body_offset = version_offset + VERSION_LEN;
    let encrypted_key_end = ct.len() - TAG_LEN;
    let encrypted_key = &ct[body_offset..encrypted_key_end];
    let tag = &ct[encrypted_key_end..ct.len()];
    // :265
    match derive_branch_key::<P>(branch_key, &salt) {
        Ok(d) => {
            assert(salt@ == parse_salt(ct@)) by {
                assert(salt@ =~= ct@.subrange(0, 16));
            }
            Ok(Parsed { derived: d, salt, iv, version, encrypted_key, tag })
        },
        Err(e) => Err(e),
    }
}

// ============================================================
// SECTION 11: Witnesses (the lemmas are not vacuous)
// ============================================================

/// A concrete 32-byte data key (the usual size): sealed is 48 bytes, the output is 92 bytes,
/// every field is where the layout says, and the parse reads the same fields back.
pub proof fn witness_layout_32_byte_key()
    ensures
        ({
            let s = Seq::new(16, |i: int| 1u8);
            let iv = Seq::new(12, |i: int| 2u8);
            let v = Seq::new(16, |i: int| 3u8);
            let sealed = Seq::new(48, |i: int| 4u8);
            &&& out_layout(s, iv, v, sealed).len() == 92
            &&& out_layout(s, iv, v, sealed).subrange(0, 16) == s
            &&& out_layout(s, iv, v, sealed).subrange(16, 28) == iv
            &&& out_layout(s, iv, v, sealed).subrange(28, 44) == v
            &&& parse_encrypted_key(out_layout(s, iv, v, sealed)).len() == 32
            &&& parse_tag(out_layout(s, iv, v, sealed)).len() == 16
        }),
{
    let s = Seq::new(16, |i: int| 1u8);
    let iv = Seq::new(12, |i: int| 2u8);
    let v = Seq::new(16, |i: int| 3u8);
    let sealed = Seq::new(48, |i: int| 4u8);
    theorem_roundtrip_layout(seq![], s, iv, v, sealed, 32);
    let o = out_layout(s, iv, v, sealed);
    assert(o.len() == 92);
    assert(parse_encrypted_key(o).len() == 32);
    assert(parse_tag(o).len() == 16);
}

/// The empty data key: n = 0, output is exactly the 60-byte overhead (the length gate's edge).
pub proof fn witness_layout_empty_key()
    ensures
        ({
            let s = Seq::new(16, |i: int| 1u8);
            let iv = Seq::new(12, |i: int| 2u8);
            let v = Seq::new(16, |i: int| 3u8);
            let sealed = Seq::new(16, |i: int| 4u8);
            &&& out_layout(s, iv, v, sealed).len() == 60
            &&& parse_encrypted_key(out_layout(s, iv, v, sealed)).len() == 0
        }),
{
    let s = Seq::new(16, |i: int| 1u8);
    let iv = Seq::new(12, |i: int| 2u8);
    let v = Seq::new(16, |i: int| 3u8);
    let sealed = Seq::new(16, |i: int| 4u8);
    theorem_roundtrip_layout(seq![], s, iv, v, sealed, 0);
}

/// Two concrete outputs whose salt draws differ differ as layouts (the conditional lemma has a
/// satisfiable premise). This says nothing about whether the real generator ever behaves so.
pub proof fn witness_distinct_draws()
    ensures
        ({
            let s1 = Seq::new(16, |i: int| 0u8);
            let s2 = Seq::new(16, |i: int| if i == 0 { 1u8 } else { 0u8 });
            let iv = Seq::new(12, |i: int| 7u8);
            let v = Seq::new(16, |i: int| 3u8);
            let c = Seq::new(48, |i: int| 4u8);
            out_layout(s1, iv, v, c) != out_layout(s2, iv, v, c)
        }),
{
    let s1 = Seq::new(16, |i: int| 0u8);
    let s2 = Seq::new(16, |i: int| if i == 0 { 1u8 } else { 0u8 });
    let iv = Seq::new(12, |i: int| 7u8);
    let v = Seq::new(16, |i: int| 3u8);
    let c = Seq::new(48, |i: int| 4u8);
    assert(s1[0] != s2[0]);
    assert(s1 != s2);
    lemma_distinct_draws_distinct_outputs(s1, iv, v, c, s2, iv, v, c);
}

} // verus!

fn main() {}
