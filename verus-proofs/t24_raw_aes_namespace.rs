// =============================================================================
// VR-2026-T24 (TM-MPL-001): the reserved `aws-kms` key namespace check in
//   RawAesKeyringBuilder::build
//
// Run:  ~/verus/verus verus-proofs/t24_raw_aes_namespace.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model of `RawAesKeyringBuilder::build`: a
// namespace is a sequence of bytes, the check is a byte-wise prefix test against the seven
// bytes of `aws-kms`, and `build` is a spec function that returns the first failing check. The
// shipped code is native Rust, is not inside `verus!`, and is not compiled by Verus. Nothing
// here detects a later edit to mpl/. The link between model and code is the correspondence
// table in section 2, reviewed by a human. The behavior of `str::starts_with` is read from
// std (H_STD_STARTS), not proved.
//
// STATUS: PROVED relative to the model and to the hypotheses in section 4:
//     `verification results:: 19 verified, 0 errors`
// Nothing is left failing on purpose. No gap between code and spec was found (section 5).
//
// WHAT THE CODE COMPARES (code reading, mpl/src/keyring/raw_aes_keyring.rs)
//   :52   const RESERVED_KEY_NAMESPACE_PREFIX: &str = "aws-kms";
//   :360  if key_namespace.starts_with(RESERVED_KEY_NAMESPACE_PREFIX) { return Err(Validation) }
// So the test is: the namespace is, byte for byte, a string that begins with the seven bytes
// 61 77 73 2d 6b 6d 73. It is a PREFIX test (not equality), CASE-SENSITIVE (no folding), with
// NO trimming, NO Unicode normalization and NO lookalike handling. The same constant is the
// only definition of the reserved value (grep) and :360 is its only use.
//
// SPEC SENTENCES (the model is checked against both)
//   S1  spec/framework/keyring-interface.md, "key provider ID" (lines 83-86): "The key provider
//       ID ... SHOULD be equal to a UTF-8 encoding of the key namespace. This value MUST NOT be
//       or start with "aws-kms" unless this encrypted data key was produced by one of the AWS
//       KMS Keyrings." A raw AES keyring is not an AWS KMS keyring, so for it S1 is a prefix rule.
//   S2  spec/framework/raw-aes-keyring.md, change log 0.3.0 (line 22): "Raw AES keyring MUST NOT
//       accept a key namespace of "aws-kms"." This is an equality rule and sits in the change
//       log, not in a normative section.
//   The code check is S1 on the namespace. It is stricter than S2 (S2 forbids one string, the
//   code forbids every string with that prefix). It is not narrower than either sentence.
//
// WHAT IS PROVED (relative to the model and to section 4)
//   R1  theorem_reserved_namespace_rejected    every namespace that is `aws-kms` followed by any
//                                              bytes (including none) is rejected by `build`,
//                                              for every other field value, with error
//                                              ReservedNs. `aws-kms`, `aws-kms-hierarchy`,
//                                              `aws-kms-rsa`, `aws-kms-ecdh` are instances.
//       lemma_kms_provider_ids_rejected        the four AWS KMS provider IDs, typed out byte by
//                                              byte, are rejected (not derived from the constant).
//   R2  theorem_ok_implies_not_reserved        if `build` returns Ok(k), k's namespace is the
//                                              one given and no suffix t exists with
//                                              ns == "aws-kms" + t.
//   R3  theorem_build_ok_iff                   `build` is Ok exactly when all four fields are
//                                              set, the namespace is not reserved, and the key
//                                              length equals the algorithm's. The namespace
//                                              check rejects nothing else (completeness).
//       lemma_check_order                      the reserved check comes after the four
//                                              required-field checks and before the key length
//                                              check (so a reserved namespace with a wrong key
//                                              length reports ReservedNs).
//   R4  theorem_emitted_provider_id_not_kms    for a built keyring, the key provider ID of every
//                                              EDK it emits (its namespace, H_EDK_ID) has no
//                                              `aws-kms` prefix, and differs from each of the
//                                              four KMS provider IDs.
//   R5  theorem_never_attempts_kms_edks        for a built keyring, no EDK whose provider ID
//                                              starts with `aws-kms` passes the provider-ID
//                                              filter at :192 (H_DECRYPT_FILTER).
//   R6  lemma_prefix_iff_suffix, lemma_has_prefix_iff_bytes
//                                              the prefix test, "there is a suffix", and the
//                                              seven-byte test agree.
//   R7  theorem_matches_s1, theorem_stricter_than_s2
//                                              the model satisfies S1 for every namespace and
//                                              S2 for every configuration; it rejects strictly
//                                              more than S2. THE FIRST OF THESE IS A
//                                              CONSISTENCY CHECK: the model predicate is S1
//                                              written as a predicate, so it is true by
//                                              construction. It shows the model was typed from
//                                              the spec sentence, not that the code is right.
//   R8  exec fn ns_has_reserved_prefix         an executable seven-byte comparison whose result
//                                              equals the spec prefix test, for every slice.
//
// WHAT IS ACCEPTED (stated by proved witnesses and one general lemma, not by a threat claim)
//   `build` accepts any namespace that does not begin with the exact bytes 61 77 73 2d 6b 6d 73.
//   Proved accepted (lemma_accepted_witnesses): the empty string; `aws-km` (a proper prefix of
//   the reserved value); `aws_kms`; `aws-kmz`; `xaws-kms`; ` aws-kms` (leading space);
//   `my-aws-kms`; `raw-ecdh`; `AWS-KMS` and `Aws-Kms` (case variants); `aws<U+2010>kms`
//   (Unicode hyphen); and a string that starts with a Cyrillic `a` (D0 B0) then `ws-kms`.
//   theorem_case_variants_accepted: any namespace whose first seven bytes equal `aws-kms`
//   after ASCII lowercasing, but are not exactly `aws-kms`, is accepted.
//
// WHAT IS NOT SHOWN
//   * That the shipped code has these properties (model level only).
//   * That no consumer treats a case variant, a padded string or a lookalike as an AWS KMS
//     provider ID. The code and the spec sentences are case-sensitive and byte-exact. The two
//     in-crate consumers compare the provider ID with exact `!=` (raw AES :192, hierarchical
//     keyring :752; code reading, H_CONSUMERS). A consumer outside this repository that
//     compared case-insensitively would treat `AWS-KMS` as a KMS provider. That residual is
//     the documented exclusion for TM-MPL-001 ("downstream case-insensitive provider-id
//     trust", other components). It is not a gap in the code against the spec and no
//     EXPECTED_FAIL obligation is written for it.
//   * That the threat TM-MPL-001 is mitigated. The proof covers the one check, at one
//     constructor, for the keyring type that has it. It does not cover other keyring types
//     (raw RSA, raw ECDH, multi-keyring, caller-implemented `Keyring` types) or a caller who
//     writes an EDK directly. Those are not modeled.
//   * That a wrapping key, key name or key length is valid beyond the length equality.
//   * The AES-GCM wrap, the key provider information layout, or decryption.
//   * Any normative reading of S2 beyond the sentence text.
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD ad3522b)
// =============================================================================
//   mpl/src/keyring/raw_aes_keyring.rs
//     :44-52    RESERVED_KEY_NAMESPACE_PREFIX = "aws-kms" and its doc comment
//     :58-69    RawAesKeyring { inner: Arc<RawAesKeyringInner> }; private fields
//     :94-112   RawAesKeyring::name, builder, key_namespace (read-only accessors)
//     :146-184  wrap_data_key: EncryptedDataKey::builder() ... .key_provider_id(self.inner.key_namespace) (:179-181)
//     :191-195  decryptable_edk_iv: `edk.key_provider_id() != self.inner.key_namespace` -> None (:192)
//     :225-230  RawAesKeyringBuilder fields (Option<String> namespace)
//     :251-266  key_namespace / set_key_namespace store the value; no check there
//     :351-390  build: four `required` (:352-355), prefix check (:356-368, test at :360),
//               key length check (:369-379), Ok with the only RawAesKeyringInner literal (:381-382)
//     :399-420  on_encrypt (calls wrap_data_key at :410 and :415); :422- on_decrypt (filter use :449)
//   mpl/src/builder.rs :7-9              required: None -> Validation error
//   mpl/src/structures/aes_wrapping_alg.rs :12-34   key_length 16 / 24 / 32 via the prim AesGcm
//   mpl/src/aws_kms/hierarchical_keyring.rs :752, :807   exact `!=` against "aws-kms-hierarchy"
//   spec/framework/keyring-interface.md :83-86 (S1); raw-aes-keyring.md :22 (S2);
//   aws-kms-keyring.md :98, :119 ("aws-kms"); aws-kms-rsa-keyring.md :126 ("aws-kms-rsa");
//   aws-kms-ecdh-keyring.md :199 ("aws-kms-ecdh"); aws-kms-hierarchical-keyring.md :187
//   ("aws-kms-hierarchy").
//   Test (not a proof): mpl/tests/test_raw_aes_keyring.rs :769 and the four-namespace test
//   below it, plus `test_build_accepts_the_raw_ecdh_key_provider_id` (:812).
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code)
// =============================================================================
//   model                         shipped
//   ----------------------------  -----------------------------------------------------------
//   Seq<u8> (namespace)           String (UTF-8); every String is a byte sequence (A_BYTES)
//   reserved()                    RESERVED_KEY_NAMESPACE_PREFIX (:52), bytes 61 77 73 2d 6b 6d 73
//   has_prefix(s, p)              str::starts_with(&str): byte-wise prefix test (H_STD_STARTS)
//   ns_ok(ns)                     !key_namespace.starts_with(RESERVED..) at :360
//   Cfg {ns, name, key_len, alg}  the four builder fields (key_len stands for wrapping_key.len())
//   build(c)                      RawAesKeyringBuilder::build :351-390, errors in code order
//   BErr::Missing*                `required(..)?` at :352-355 (Kind::Validation)
//   BErr::ReservedNs              Err(Kind::Validation) at :361-368
//   BErr::KeyLen                  Err(Kind::Validation) at :369-379
//   Keyring {ns, key_name, alg}   RawAesKeyringInner (name, key and the zeroization omitted)
//   emitted_provider_id(k)        the key_provider_id set in wrap_data_key :180
//   attempts_edk(k, id)           the provider-ID filter in decryptable_edk_iv :192
//   alg_key_len                   AesWrappingAlg::key_length (16, 24, 32 bytes)
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED
// =============================================================================
// Spec-derived: the prefix "aws-kms" and the rule "MUST NOT be or start with" (S1), the rule
// "MUST NOT accept ... of aws-kms" (S2), the four provider ID strings. Code-derived: the check
// order, that the check is on the namespace at build time, case sensitivity (the spec sentences
// are silent on case; they name the lowercase string), the key length table and the error kind.
//
// =============================================================================
// 4. HYPOTHESES AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and to the
//                  hypotheses below
//    ASSUMED       taken as a premise or a definition; not proved here (A_*)
//    CODE READING  a claim about shipped code or std that Verus does not see (H_*); checked
//                  by a human reading the source at the lines named
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier..]`
//  attribute is written in this file, and there is no uninterpreted spec function.
//
//  A_BYTES (ASSUMED). A namespace is modeled as an arbitrary `Seq<u8>`. Every Rust `String`
//    is such a sequence (its UTF-8 bytes), so a theorem over all byte sequences covers all
//    strings and some non-strings. The theorems do not use UTF-8 validity.
//  A_SPEC_IDS (ASSUMED). The four AWS KMS provider IDs are the strings named in the spec files
//    listed in section 1. The ASCII bytes are typed in `kms_id_*` and checked by the lemma
//    `lemma_kms_provider_ids_rejected`, not derived from `reserved()`.
//  A_VSTD (ASSUMED). Verus, Z3 and the vstd `Seq` axioms.
//  H_STD_STARTS (CODE READING, std). `str::starts_with(&str)` uses the `&str` pattern, whose
//    `is_prefix_of` is `haystack.as_bytes().starts_with(self.as_bytes())`: a byte-wise slice
//    prefix test. It is false when the haystack is shorter than the prefix, it does not fold
//    case and it does not normalize. `has_prefix` models that. Read from std, not proved.
//  H_CONST (CODE READING). `RESERVED_KEY_NAMESPACE_PREFIX` is defined once (:52), has the seven
//    ASCII bytes 61 77 73 2d 6b 6d 73, and is used once, at :360 (grep).
//  H_BUILD_ORDER (CODE READING). In `build`, the four `required(..)?` calls (:352-355, in the
//    order namespace, name, wrapping key, wrapping algorithm) come first, then the prefix check
//    (:360), then the key length check (:369-379), then `Ok` (:381). `required` returns a Validation
//    error for `None` (builder.rs :7-9). The model has the same order and takes the first
//    failure. All error kinds here are `Kind::Validation`; the model keeps them apart only to
//    state the order.
//  H_ONLY_BUILD (CODE READING). The only construction of `RawAesKeyringInner` is :382, inside
//    `build`, after the check. The struct fields are private, `RawAesKeyring` has no setter,
//    and `Clone` copies the `Arc`. grep for `RawAesKeyringInner` in mpl/src, esdk/src and
//    prim/src finds only raw_aes_keyring.rs. So every `RawAesKeyring` value comes from a `build`
//    that returned Ok. (Tests in mpl/tests use the public builder. unsafe transmute or other
//    memory tricks are out of scope.)
//  H_NS_UNCHANGED (CODE READING). The namespace checked at :360 is the value moved into the
//    keyring at :384 (`key_namespace` is not modified between the two).
//  H_EDK_ID (CODE READING). `wrap_data_key` (:165-182) builds the only EDK of this file and
//    sets its key provider ID to `self.inner.key_namespace` (:180). `on_encrypt` calls it
//    (:410, :415). No other `EncryptedDataKey` is built in raw_aes_keyring.rs.
//  H_DECRYPT_FILTER (CODE READING). `decryptable_edk_iv` returns None unless
//    `edk.key_provider_id() == self.inner.key_namespace` (:192-194) (exact string equality).
//    `on_decrypt` tries only EDKs for which it returns Some (:449-456).
//  H_CONSUMERS (CODE READING). In mpl/src and esdk/src the only comparisons of a provider ID
//    with a constant are :192 (against the keyring's own namespace) and
//    hierarchical_keyring.rs :752 (against "aws-kms-hierarchy"). Both use `!=` on `&str`, which
//    is exact and case-sensitive. esdk/src serializes and parses the provider ID
//    (message/encrypted_data_keys.rs) and does not compare it with a KMS constant.
//  H_MODEL_MATCH (CODE READING). `build`, `has_prefix` and `reserved` have the same inputs,
//    operations and operation order as the lines named in section 2. Checked by reading; not
//    machine-checked.
//
// =============================================================================
// 5. FINDINGS
// =============================================================================
//  F0 (no gap). The code check (case-sensitive byte prefix) is not narrower than S1 or S2. It
//     is stricter than S2 (R7) and equal to S1 on the namespace. No EXPECTED_FAIL obligation
//     exists in this file, and none was invented.
//  O1 (observation, not a gap). Case variants, padded strings and lookalikes are accepted (see
//     "WHAT IS ACCEPTED"). The spec sentences name the lowercase string and do not ask for case
//     folding or normalization, so this is a statement about the accepted set, not a failure of
//     a requirement. Whether a downstream consumer could be fooled is outside this repository
//     (see "WHAT IS NOT SHOWN").
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Byte strings and the prefix test
// ============================================================

/// RESERVED_KEY_NAMESPACE_PREFIX = "aws-kms" (raw_aes_keyring.rs :52), as ASCII bytes.
pub open spec fn reserved() -> Seq<u8> {
    seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]
}

/// H_STD_STARTS: byte-wise prefix test, false if `s` is shorter than `p`.
pub open spec fn has_prefix(s: Seq<u8>, p: Seq<u8>) -> bool {
    p.len() <= s.len() && s.subrange(0, p.len() as int) =~= p
}

/// The seven-byte form of "starts with `aws-kms`".
pub open spec fn pre7(s: Seq<u8>) -> bool {
    &&& s.len() >= 7
    &&& s[0] == 0x61u8
    &&& s[1] == 0x77u8
    &&& s[2] == 0x73u8
    &&& s[3] == 0x2du8
    &&& s[4] == 0x6bu8
    &&& s[5] == 0x6du8
    &&& s[6] == 0x73u8
}

/// The namespace test at :360, negated: the namespace passes (is not reserved).
pub open spec fn ns_ok(ns: Seq<u8>) -> bool {
    !has_prefix(ns, reserved())
}

/// ASCII lowercase of one byte (used only to describe case variants).
pub open spec fn lower(b: u8) -> u8 {
    if 0x41u8 <= b && b <= 0x5au8 { (b + 0x20u8) as u8 } else { b }
}

// The four AWS KMS provider IDs, typed out as ASCII (A_SPEC_IDS).
pub open spec fn kms_id_kms() -> Seq<u8> {
    seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]
}

pub open spec fn kms_id_hierarchy() -> Seq<u8> {
    seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8, 0x2du8, 0x68u8, 0x69u8, 0x65u8,
        0x72u8, 0x61u8, 0x72u8, 0x63u8, 0x68u8, 0x79u8]
}

pub open spec fn kms_id_rsa() -> Seq<u8> {
    seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8, 0x2du8, 0x72u8, 0x73u8, 0x61u8]
}

pub open spec fn kms_id_ecdh() -> Seq<u8> {
    seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8, 0x2du8, 0x65u8, 0x63u8, 0x64u8,
        0x68u8]
}

// ============================================================
// SECTION 2: The builder and the keyring (H_BUILD_ORDER, H_ONLY_BUILD)
// ============================================================

pub enum Alg {
    A128,
    A192,
    A256,
}

/// AesWrappingAlg::key_length in bytes.
pub open spec fn alg_key_len(a: Alg) -> nat {
    match a {
        Alg::A128 => 16,
        Alg::A192 => 24,
        Alg::A256 => 32,
    }
}

/// The four builder fields. `key_len` is `wrapping_key.len()`; the key bytes do not matter here.
pub struct Cfg {
    pub ns: Option<Seq<u8>>,
    pub name: Option<Seq<u8>>,
    pub key_len: Option<nat>,
    pub alg: Option<Alg>,
}

/// The errors of `build`, in code order. All are `Kind::Validation` in the code.
pub enum BErr {
    MissingNs,
    MissingName,
    MissingKey,
    MissingAlg,
    ReservedNs,
    KeyLen,
}

/// RawAesKeyringInner as far as it matters here.
pub struct Keyring {
    pub ns: Seq<u8>,
    pub key_name: Seq<u8>,
    pub alg: Alg,
}

pub enum BuildOut {
    Ok(Keyring),
    Err(BErr),
}

/// RawAesKeyringBuilder::build :351-390.
pub open spec fn build(c: Cfg) -> BuildOut {
    if c.ns is None {
        BuildOut::Err(BErr::MissingNs)
    } else if c.name is None {
        BuildOut::Err(BErr::MissingName)
    } else if c.key_len is None {
        BuildOut::Err(BErr::MissingKey)
    } else if c.alg is None {
        BuildOut::Err(BErr::MissingAlg)
    } else if has_prefix(c.ns->Some_0, reserved()) {
        BuildOut::Err(BErr::ReservedNs)
    } else if c.key_len->Some_0 != alg_key_len(c.alg->Some_0) {
        BuildOut::Err(BErr::KeyLen)
    } else {
        BuildOut::Ok(Keyring { ns: c.ns->Some_0, key_name: c.name->Some_0, alg: c.alg->Some_0 })
    }
}

/// H_EDK_ID: the key provider ID of every EDK `on_encrypt` produces (:180).
pub open spec fn emitted_provider_id(k: Keyring) -> Seq<u8> {
    k.ns
}

/// H_DECRYPT_FILTER: the first filter of `decryptable_edk_iv` (:192): the provider ID equals
/// the namespace. Other filters only narrow it further.
pub open spec fn attempts_edk(k: Keyring, edk_id: Seq<u8>) -> bool {
    edk_id == k.ns
}

/// Both sentences, as predicates.
/// S1: the key provider ID must not be or start with "aws-kms" (raw AES is not a KMS keyring).
pub open spec fn spec_s1(id: Seq<u8>) -> bool {
    !(id =~= reserved()) && !has_prefix(id, reserved())
}

/// S2: a namespace of exactly "aws-kms" must not be accepted.
pub open spec fn spec_s2(c: Cfg) -> bool {
    c.ns == Some(reserved()) ==> build(c) is Err
}

// ============================================================
// SECTION 3: The prefix test (R6)
// ============================================================

proof fn lemma_reserved_bytes()
    ensures
        reserved().len() == 7,
        reserved()[0] == 0x61u8,
        reserved()[1] == 0x77u8,
        reserved()[2] == 0x73u8,
        reserved()[3] == 0x2du8,
        reserved()[4] == 0x6bu8,
        reserved()[5] == 0x6du8,
        reserved()[6] == 0x73u8,
{
}

/// The prefix test and the seven-byte test agree.
proof fn lemma_has_prefix_iff_bytes(s: Seq<u8>)
    ensures
        has_prefix(s, reserved()) <==> pre7(s),
{
    lemma_reserved_bytes();
    let r = reserved();
    if pre7(s) {
        assert forall|i: int| 0 <= i < 7 implies #[trigger] s.subrange(0, 7)[i] == r[i] by {
            assert(s.subrange(0, 7)[i] == s[i]);
            if i == 0 {
            } else if i == 1 {
            } else if i == 2 {
            } else if i == 3 {
            } else if i == 4 {
            } else if i == 5 {
            } else {
                assert(i == 6);
            }
        }
        assert(s.subrange(0, 7) =~= r);
    }
    if has_prefix(s, r) {
        assert(s.subrange(0, 7) =~= r);
        assert(s.subrange(0, 7)[0] == s[0]);
        assert(s.subrange(0, 7)[1] == s[1]);
        assert(s.subrange(0, 7)[2] == s[2]);
        assert(s.subrange(0, 7)[3] == s[3]);
        assert(s.subrange(0, 7)[4] == s[4]);
        assert(s.subrange(0, 7)[5] == s[5]);
        assert(s.subrange(0, 7)[6] == s[6]);
    }
}

/// "starts with `aws-kms`" is the same as "is `aws-kms` followed by some suffix".
proof fn lemma_prefix_iff_suffix(s: Seq<u8>)
    ensures
        has_prefix(s, reserved()) <==> exists|t: Seq<u8>| s =~= reserved() + t,
{
    lemma_reserved_bytes();
    if has_prefix(s, reserved()) {
        let t = s.subrange(7, s.len() as int);
        assert(s =~= reserved() + t) by {
            assert(s.subrange(0, 7) =~= reserved());
            assert((reserved() + t).len() == s.len());
            assert forall|i: int| 0 <= i < s.len() implies #[trigger] s[i] == (reserved() + t)[i] by {
                if i < 7 {
                    assert(s.subrange(0, 7)[i] == s[i]);
                } else {
                    assert(t[i - 7] == s[i]);
                }
            }
        }
    }
    if exists|t: Seq<u8>| s =~= reserved() + t {
        let t = choose|t: Seq<u8>| s =~= reserved() + t;
        assert(s.subrange(0, 7) =~= reserved());
    }
}

/// `reserved()` followed by any suffix has the prefix.
proof fn lemma_reserved_plus_suffix_has_prefix(t: Seq<u8>)
    ensures
        has_prefix(reserved() + t, reserved()),
{
    lemma_reserved_bytes();
    assert((reserved() + t).subrange(0, 7) =~= reserved());
}

// ============================================================
// SECTION 4: R1, the four KMS provider IDs, and R2/R3 on build
// ============================================================

/// The four KMS IDs typed out byte by byte (A_SPEC_IDS) all have the prefix.
proof fn lemma_kms_provider_ids_rejected()
    ensures
        has_prefix(kms_id_kms(), reserved()),
        has_prefix(kms_id_hierarchy(), reserved()),
        has_prefix(kms_id_rsa(), reserved()),
        has_prefix(kms_id_ecdh(), reserved()),
        !ns_ok(kms_id_kms()),
        !ns_ok(kms_id_hierarchy()),
        !ns_ok(kms_id_rsa()),
        !ns_ok(kms_id_ecdh()),
{
    lemma_has_prefix_iff_bytes(kms_id_kms());
    lemma_has_prefix_iff_bytes(kms_id_hierarchy());
    lemma_has_prefix_iff_bytes(kms_id_rsa());
    lemma_has_prefix_iff_bytes(kms_id_ecdh());
}

/// R1. For every other field value: a namespace `aws-kms` + t is rejected with ReservedNs
/// when the four fields are set, and rejected with some error in every case.
proof fn theorem_reserved_namespace_rejected(c: Cfg, t: Seq<u8>)
    requires
        c.ns == Some(reserved() + t),
    ensures
        build(c) is Err,
        (c.name is Some && c.key_len is Some && c.alg is Some) ==> build(c) == BuildOut::Err(
            BErr::ReservedNs,
        ),
{
    lemma_reserved_plus_suffix_has_prefix(t);
}

/// R2. A returned keyring has the given namespace and it is not `aws-kms` + any suffix.
proof fn theorem_ok_implies_not_reserved(c: Cfg)
    requires
        build(c) is Ok,
    ensures
        c.ns is Some,
        build(c)->Ok_0.ns == c.ns->Some_0,
        !has_prefix(build(c)->Ok_0.ns, reserved()),
        forall|t: Seq<u8>| !(build(c)->Ok_0.ns =~= #[trigger] (reserved() + t)),
{
    let ns = c.ns->Some_0;
    assert(!has_prefix(ns, reserved()));
    assert forall|t: Seq<u8>| !(ns =~= #[trigger] (reserved() + t)) by {
        if ns =~= reserved() + t {
            lemma_prefix_iff_suffix(ns);
            assert(has_prefix(ns, reserved()));
        }
    }
}

/// R3. `build` is Ok exactly when the fields are set, the namespace is not reserved, and the
/// key length is the algorithm's. The namespace check rejects nothing else.
proof fn theorem_build_ok_iff(c: Cfg)
    ensures
        build(c) is Ok <==> (c.ns is Some && c.name is Some && c.key_len is Some && c.alg is Some
            && ns_ok(c.ns->Some_0) && c.key_len->Some_0 == alg_key_len(c.alg->Some_0)),
{
}

/// The check order of H_BUILD_ORDER. A reserved namespace with a wrong key length reports
/// ReservedNs; a missing wrapping algorithm is reported before a reserved namespace.
proof fn lemma_check_order(ns: Seq<u8>, name: Seq<u8>)
    requires
        has_prefix(ns, reserved()),
    ensures
        build(Cfg { ns: Some(ns), name: Some(name), key_len: Some(1), alg: Some(Alg::A256) })
            == BuildOut::Err(BErr::ReservedNs),
        build(Cfg { ns: Some(ns), name: Some(name), key_len: Some(32), alg: None })
            == BuildOut::Err(BErr::MissingAlg),
        build(Cfg { ns: None, name: Some(name), key_len: Some(32), alg: Some(Alg::A256) })
            == BuildOut::Err(BErr::MissingNs),
{
}

// ============================================================
// SECTION 5: R4, R5 on the emitted and attempted provider IDs
// ============================================================

/// R4. Every EDK a built keyring emits has a provider ID with no `aws-kms` prefix, so it also
/// differs from the four KMS provider IDs.
proof fn theorem_emitted_provider_id_not_kms(c: Cfg)
    requires
        build(c) is Ok,
    ensures
        !has_prefix(emitted_provider_id(build(c)->Ok_0), reserved()),
        emitted_provider_id(build(c)->Ok_0) != kms_id_kms(),
        emitted_provider_id(build(c)->Ok_0) != kms_id_hierarchy(),
        emitted_provider_id(build(c)->Ok_0) != kms_id_rsa(),
        emitted_provider_id(build(c)->Ok_0) != kms_id_ecdh(),
{
    lemma_kms_provider_ids_rejected();
}

/// R5. A built keyring does not pass any EDK whose provider ID starts with `aws-kms` through
/// the provider-ID filter at :192.
proof fn theorem_never_attempts_kms_edks(c: Cfg, edk_id: Seq<u8>)
    requires
        build(c) is Ok,
        has_prefix(edk_id, reserved()),
    ensures
        !attempts_edk(build(c)->Ok_0, edk_id),
{
}

// ============================================================
// SECTION 6: What is accepted
// ============================================================

/// Any case variant of `aws-kms` that is not byte-equal is accepted: the first seven bytes
/// equal `aws-kms` after ASCII lowercasing, and at least one byte differs.
proof fn theorem_case_variants_accepted(ns: Seq<u8>, j: int)
    requires
        ns.len() >= 7,
        forall|i: int| 0 <= i < 7 ==> lower(#[trigger] ns[i]) == reserved()[i],
        0 <= j < 7,
        ns[j] != reserved()[j],
    ensures
        ns_ok(ns),
{
    lemma_reserved_bytes();
    lemma_has_prefix_iff_bytes(ns);
    // If pre7 held, ns[j] would equal reserved()[j].
    assert(ns[j] == reserved()[j] || !pre7(ns)) by {
        if pre7(ns) {
            if j == 0 {
            } else if j == 1 {
            } else if j == 2 {
            } else if j == 3 {
            } else if j == 4 {
            } else if j == 5 {
            } else {
                assert(j == 6);
            }
        }
    }
}

/// Witnesses. Each of these is accepted by the model of the check, by the seven-byte test.
proof fn lemma_accepted_witnesses()
    ensures
        // empty string
        ns_ok(Seq::<u8>::empty()),
        // "aws-km": a proper prefix of the reserved value
        ns_ok(seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8]),
        // "aws_kms"
        ns_ok(seq![0x61u8, 0x77u8, 0x73u8, 0x5fu8, 0x6bu8, 0x6du8, 0x73u8]),
        // "aws-kmz"
        ns_ok(seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x7au8]),
        // "xaws-kms"
        ns_ok(seq![0x78u8, 0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]),
        // " aws-kms" (leading space)
        ns_ok(seq![0x20u8, 0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]),
        // "my-aws-kms"
        ns_ok(
            seq![0x6du8, 0x79u8, 0x2du8, 0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8],
        ),
        // "raw-ecdh" (the raw ECDH key provider ID)
        ns_ok(seq![0x72u8, 0x61u8, 0x77u8, 0x2du8, 0x65u8, 0x63u8, 0x64u8, 0x68u8]),
        // "AWS-KMS"
        ns_ok(seq![0x41u8, 0x57u8, 0x53u8, 0x2du8, 0x4bu8, 0x4du8, 0x53u8]),
        // "Aws-Kms"
        ns_ok(seq![0x41u8, 0x77u8, 0x73u8, 0x2du8, 0x4bu8, 0x6du8, 0x73u8]),
        // "aws" U+2010 "kms" (Unicode hyphen, E2 80 90)
        ns_ok(
            seq![0x61u8, 0x77u8, 0x73u8, 0xe2u8, 0x80u8, 0x90u8, 0x6bu8, 0x6du8, 0x73u8],
        ),
        // Cyrillic a (D0 B0) then "ws-kms"
        ns_ok(seq![0xd0u8, 0xb0u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]),
{
    lemma_has_prefix_iff_bytes(Seq::<u8>::empty());
    lemma_has_prefix_iff_bytes(seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8]);
    lemma_has_prefix_iff_bytes(seq![0x61u8, 0x77u8, 0x73u8, 0x5fu8, 0x6bu8, 0x6du8, 0x73u8]);
    lemma_has_prefix_iff_bytes(seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x7au8]);
    lemma_has_prefix_iff_bytes(seq![0x78u8, 0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]);
    lemma_has_prefix_iff_bytes(seq![0x20u8, 0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]);
    lemma_has_prefix_iff_bytes(
        seq![0x6du8, 0x79u8, 0x2du8, 0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8],
    );
    lemma_has_prefix_iff_bytes(seq![0x72u8, 0x61u8, 0x77u8, 0x2du8, 0x65u8, 0x63u8, 0x64u8, 0x68u8]);
    lemma_has_prefix_iff_bytes(seq![0x41u8, 0x57u8, 0x53u8, 0x2du8, 0x4bu8, 0x4du8, 0x53u8]);
    lemma_has_prefix_iff_bytes(seq![0x41u8, 0x77u8, 0x73u8, 0x2du8, 0x4bu8, 0x6du8, 0x73u8]);
    lemma_has_prefix_iff_bytes(
        seq![0x61u8, 0x77u8, 0x73u8, 0xe2u8, 0x80u8, 0x90u8, 0x6bu8, 0x6du8, 0x73u8],
    );
    lemma_has_prefix_iff_bytes(seq![0xd0u8, 0xb0u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]);
}

/// A witness for the full pipeline: `AWS-KMS` with valid other fields is built (Ok).
proof fn lemma_case_variant_builds()
    ensures
        ({
            let ns = seq![0x41u8, 0x57u8, 0x53u8, 0x2du8, 0x4bu8, 0x4du8, 0x53u8];
            let c = Cfg { ns: Some(ns), name: Some(seq![0x6bu8]), key_len: Some(32), alg: Some(Alg::A256) };
            build(c) is Ok
        }),
{
    lemma_accepted_witnesses();
}

// ============================================================
// SECTION 7: R7, comparison with the two spec sentences
// ============================================================

/// CONSISTENCY CHECK (true by construction): for a raw AES keyring, the model predicate
/// `ns_ok` is S1 on the namespace. It shows the model was typed from S1, nothing more.
proof fn theorem_matches_s1(ns: Seq<u8>)
    ensures
        ns_ok(ns) ==> spec_s1(ns),
        spec_s1(ns) ==> ns_ok(ns),
{
    if has_prefix(ns, reserved()) {
    } else {
        assert(!(ns =~= reserved()));
    }
}

/// The model satisfies S2 for every configuration, and rejects strictly more than S2.
proof fn theorem_stricter_than_s2(c: Cfg)
    ensures
        spec_s2(c),
        // strictly more: `aws-kms-rsa` is not "aws-kms" but is rejected
        build(Cfg { ns: Some(kms_id_rsa()), name: c.name, key_len: c.key_len, alg: c.alg }) is Err,
        kms_id_rsa() != reserved(),
{
    lemma_kms_provider_ids_rejected();
    lemma_reserved_plus_suffix_has_prefix(Seq::<u8>::empty());
    assert(reserved() + Seq::<u8>::empty() =~= reserved());
    assert(kms_id_rsa().len() == 11);
    assert(reserved().len() == 7);
}

/// The model satisfies S1 for the keyring it builds, on the ID it emits.
proof fn theorem_built_keyring_satisfies_s1(c: Cfg)
    requires
        build(c) is Ok,
    ensures
        spec_s1(emitted_provider_id(build(c)->Ok_0)),
{
    let ns = c.ns->Some_0;
    assert(!has_prefix(ns, reserved()));
    assert(!(ns =~= reserved()));
}

// ============================================================
// SECTION 8: Executable model of the seven-byte test (R8)
// ============================================================

/// The comparison of `starts_with(RESERVED_KEY_NAMESPACE_PREFIX)` written as seven byte
/// comparisons after a length check. Its result equals the spec prefix test for every slice.
fn ns_has_reserved_prefix(ns: &[u8]) -> (r: bool)
    ensures
        r == has_prefix(ns@, reserved()),
{
    proof {
        lemma_has_prefix_iff_bytes(ns@);
    }
    if ns.len() < 7 {
        return false;
    }
    ns[0] == 0x61u8 && ns[1] == 0x77u8 && ns[2] == 0x73u8 && ns[3] == 0x2du8 && ns[4] == 0x6bu8
        && ns[5] == 0x6du8 && ns[6] == 0x73u8
}

/// The check of `build` as an executable function: true means the namespace is accepted.
fn ns_accepted(ns: &[u8]) -> (r: bool)
    ensures
        r == ns_ok(ns@),
{
    !ns_has_reserved_prefix(ns)
}

} // verus!
fn main() {}
