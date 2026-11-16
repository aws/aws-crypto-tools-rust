// =============================================================================
// VR-2026-T03 (priority 5.12, TM-MPL-002): `kms_ops::resolve_key_store_arn`, pinned modes
// (KmsKeyArn and KmsMrKeyArn). The Discovery and MrDiscovery arms (BUG-04 / T17) are out of scope.
//
// Run:  ~/verus/verus verus-proofs/t03_resolve_pinned_arn.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// -----------------------------------------------------------------------------
// WHAT IS THIS (read first)
//   A proof about a hand-written, re-typed MODEL of the shipped Rust. It does not verify the
//   shipped code: that code is not inside `verus!`, is not compiled by Verus, and nothing here
//   detects a later edit to mpl/. The link between model and code is the correspondence table
//   below, reviewed by a human. Read every result as "the logic of the model is machine-checked;
//   the model's fidelity to the code is audited, not checked."
//
// PROPERTY (docs/verification-targets/01-threat-driven.md, VR-2026-T03; spec
//   branch-key-store.md "AWS KMS Branch Key Decryption" :638-671 and "AWS Key ARN
//   Compatibility" :170-179; aws-kms-mrk-match-for-decrypt.md "Implementation")
//   In the pinned configurations the KMS `KeyId` is always the CONFIGURED ARN, never the ARN
//   stored in the (attacker-writable) DynamoDB record. The record ARN is only accepted when it
//   is compatible with the configured one: byte-equal (KmsKeyArn) or MRK match (KmsMrKeyArn).
//   Otherwise Err with Kind::Validation.
//
// STATUS: PROVED at model level (hypotheses H_ORACLE, H_BUILD, H_CALLER and A_STR, A_MR below).
//   `verification results:: 39 verified, 0 errors`, exit 0. Log:
//   .agents/tasks/verus-proofs-t03-t05/logs/t03_resolve_pinned_arn.log.
//   No obligation is left failing on purpose. No spec-faithful property was found false for the
//   pinned path. Two observations (O1, O2) are listed below.
//
// -----------------------------------------------------------------------------
// SOURCE MODELED (repo esdk-native-mpl, HEAD 35f24c9; mpl/ unchanged since 620771c)
//   mpl/src/key_store/kms_ops.rs
//     :88-114   resolve_key_store_arn   (match :93-104; compat check :105-112; Ok :113)
//     :162-197  decrypt_branch_key      (kms-arn lookup :172-177; resolve :179; key_id :183)
//     :271-272  reencrypt_wrapped_key   (source_key_id / destination_key_id = key_arn)
//   mpl/src/key_store/kms_config.rs
//     :86-94    is_arn_compatible       (KmsKeyArn :88; KmsMrKeyArn :89-91; Discovery :92)
//     :31-58    parse_arn               (splitn(6, ':') :32; split_once('/') :41)
//     :61-79    validate_kms_key_arn    (service :64; alias :71)
//   mpl/src/aws_kms/mrk_match.rs
//     :24-48    aws_kms_mrk_match_for_decrypt  (alias :25-27; equal :29-31; MR guard :33-35;
//                                               indexing :38-41; compare :43-47)
//     :52-58    is_multi_region_arn     :62-68  is_alias_arn
//   mpl/src/key_store/config.rs :12 (KmsConfiguration), :119-135 (KmsKeyArn), :183-200 (KmsMrKeyArn)
//   mpl/src/key_store/branch_key_store.rs :112-122 (configured_kms_key_arn), :381 (validate() in
//     build), :641-668 (version_key; resolve :663; reencrypt :678-)
//
// CORRESPONDENCE TABLE (model item  <->  shipped code)
//   model                                     code
//   ----------------------------------------  ----------------------------------------------
//   Str = Seq<char>                           String / &str (see A_STR)
//   Cfg (spec) / KmsConfiguration (exec)      KmsConfiguration (config.rs:12). The wrapper
//                                             structs KmsKeyArn{arn} / KmsMrKeyArn{arn} are
//                                             collapsed to their String; Discovery's payload
//                                             is dropped (never read by the function).
//   is_pinned(c)                              the two arms that fall out of the match,
//                                             kms_ops.rs:94-95. The other two arms return at
//                                             :96-99 and :100-103 and are the NotPinned outcome.
//   configured_arn(c)                         `configured` = configured.arn() (:94-95)
//   compat(c, rec) / ArnCompat::spec_compat   is_arn_compatible(kms_config, record_kms_arn)
//                                             (:105, kms_config.rs:86-94). KmsKeyArn: `a == stored`
//                                             (:88). KmsMrKeyArn: mrk_match(a, stored) (:89-91).
//   mrk_match                                 aws_kms_mrk_match_for_decrypt branch by branch
//                                             (comments `:25-27` etc. inside the model).
//   split_colon                               str::split(':').collect() (mrk_match.rs:38-39, :53, :63)
//   split_once_or                             split_once('/').unwrap_or((s, "")) (:40-41)
//   is_mr_arn / is_alias_arn                  is_multi_region_arn / is_alias_arn (:52-58, :62-68)
//   resolve_given(c, compat_ok)               resolve_key_store_arn :93-113, with the boolean
//                                             result of is_arn_compatible as the only record input
//   resolve(c, rec)                           resolve_given(c, compat(c, rec))
//   Resolved::Fail(Kind::Validation)          the Err at :105-112; the format! message (which
//                                             quotes both ARNs) is dropped. Error::new(
//                                             Kind::Validation, ..) is the only error site on
//                                             the pinned path; there is no `?` on it.
//   Resolved::Key(configured_arn(c))          Ok(configured.to_owned()) (:113)
//   resolve_key_store_arn<O> (exec)           the same function; `branch_key_id` is only used by
//                                             the out-of-scope arms (reject_alias_arn,
//                                             rewrite_arn_region) so it is unused in the model.
//                                             `requires is_pinned(kms_config@)` replaces the two
//                                             early-return arms; the two `assert(false)` arms are
//                                             closed by that precondition.
//   decrypt_step                              decrypt_branch_key :170-183: kms-arn lookup (:172),
//                                             resolve (:179), KMS `key_id(&resolved_key_id)` (:183).
//   splitn6 / parse_arn_ok / validate_ok      parse_arn / validate_kms_key_arn (kms_config.rs:31-79),
//                                             Ok-ness only (Section 6b).
//
// -----------------------------------------------------------------------------
// WHAT IS PROVED vs ASSUMED (the T11 dependency)
//   T03 depends softly on T11 (the MRK match). The headline property does NOT need the match:
//   theorem_a / theorem_a2 / the exec contract hold for ANY compatibility predicate, because
//   the record ARN enters `resolve_given` only as a boolean and the returned String is
//   `configured`. What needs the match is the exact Ok/Err characterization (theorem_b onward).
//   For that the file models `aws_kms_mrk_match_for_decrypt` and `is_arn_compatible` at the level
//   the property needs, and PROVES
//     * the exact Ok/Err set of the code's MRK match (lemma_mrk_match_iff): no alias on either
//       side, and byte-equal, or both MRK ARNs that agree on every colon piece except the region;
//     * the model of `split(':')` is the real one (lemma_join_split, lemma_split_pieces_colon_free,
//       lemma_split_nonempty, lemma_split_join);
//     * the code agrees with the spec text of aws-kms-mrk-match-for-decrypt.md on every non-alias
//       pair (lemma_code_vs_spec_text), and on every pair for a validated configured ARN
//       (theorem_i).
//   It ASSUMES (does not prove) the items listed under TRUSTED ASSUMPTIONS. It does NOT prove
//   the full T11 property (including its own error sites or the hierarchical-keyring call sites).
//
// -----------------------------------------------------------------------------
// TRUSTED ASSUMPTIONS (TCB)
//   * No `assume`, `admit`, `external_body`, `external`, `assume_specification` or
//     `#[verifier...]` attribute is written in this file (grep, outside comments). No
//     uninterpreted spec function is used. The base is Verus 0.2026.07.12, Z3, rustc 1.96.0, and
//     vstd: its Seq axioms and its own `assume_specification`s for `String::as_str` and
//     `str::to_owned` (used in the exec function) and `<String as PartialEq>::eq` (used only in the
//     `ByteEqCompat` witness). `String@` is vstd's view.
//   * A_STR. `String` is `Seq<char>`. Rust splits `str` at bytes, the model splits at chars.
//     The two agree because ':' and '/' are ASCII and never occur inside a multi-byte UTF-8
//     sequence. `starts_with` on bytes agrees with the char-prefix test for the same reason.
//   * A_MR. `is_mr_arn` is the CODE's identification of a multi-Region key ARN
//     (mrk_match.rs:52-58), used also for the spec text in `spec_mrk_match`. The spec's own
//     definition (aws-kms-key-arn.md) additionally requires a valid ARN (non-empty partition,
//     region, account, id). The code is looser (observation O2). So `lemma_code_vs_spec_text`
//     and `theorem_i` compare the code with the spec text instantiated at the code's MR test.
//   * H_ORACLE. The exec function is generic in the compatibility predicate (`ArnCompat`), whose
//     contract is only "deterministic function of (config, stored)". `theorem_h` says: if that
//     function equals the Section 3 model `compat`, the exec function equals `resolve`. That the
//     shipped `is_arn_compatible` equals `compat` is the audited correspondence above, not a
//     machine-checked fact. No exec implementation of the MRK match exists in this file
//     (vstd has no spec for `str::split`, `splitn`, `split_once` or `starts_with`).
//   * H_BUILD. The configuration seen by `resolve_key_store_arn` is the one `build()` validated
//     (config field private, never mutated). Only `theorem_i` uses it.
//   * H_CALLER. `decrypt_branch_key` passes only the returned value as `key_id` (:183) and
//     version_key passes the returned value to ReEncrypt as source and destination (:678-,
//     kms_ops.rs:271-272). Read, not machine-checked. `theorem_g` models the decrypt caller only.
//   * Out of the model: `format!` payloads (no panic expected, not verified), `Error::new`.
//
// -----------------------------------------------------------------------------
// MODEL-vs-CODE GAP (read before citing the result)
//   The shipped function is native Rust over &str, `Result<String, Error>` and the crate's
//   `Error`, `KmsConfiguration`. It is not compiled by Verus. To close the gap you need ALL of:
//     1. `resolve_key_store_arn`, `is_arn_compatible`, `aws_kms_mrk_match_for_decrypt`,
//        `is_multi_region_arn`, `is_alias_arn` moved inside `verus!`, or `cargo verus` on the
//        real crate (edits to mpl/, not allowed in this task);
//     2. vstd specs for `str::{split, splitn, split_once, starts_with}`, `Vec<&str>` indexing from
//        `collect()`, `String::to_owned`/`format!`, and `KmsKeyArn::arn()`;
//     3. a spec for `Error::new` / `Kind` (to state `e.kind() == Kind::Validation`);
//     4. replacing H_ORACLE by the exec instantiation of the real compatibility function.
//   Until then the evidence is: audited model + machine-checked logic. A cheaper partial closure
//   is a script that diffs the control-flow skeleton of kms_ops.rs:88-114 and mrk_match.rs:24-48
//   against this file.
//
// -----------------------------------------------------------------------------
// THEOREMS (what the contracts say; line numbers are in the README/notes)
//   theorem_a_key_id_is_configured         pinned: a call returns Ok or Err; Ok(k) => k == configured
//   theorem_a2_key_id_independent_of_record any two accepted records give the same KeyId
//   theorem_b_ok_iff_compat                Ok <==> compat; Err <==> !compat; Err kind == Validation
//   theorem_c_single_key                   KmsKeyArn: Ok <==> record == configured (byte-equal)
//   theorem_d_mrk_sound / theorem_e_mrk_complete   KmsMrKeyArn: Ok <==> neither is an alias ARN and
//                                          (byte-equal, or both MRK ARNs differing only in region)
//   theorem_f_dispatch                     NotPinned exactly for Discovery / MrDiscovery
//   theorem_g_decrypt_key_id               decrypt path: the KMS KeyId is the configured ARN, and
//                                          the KMS call happens only when the record's kms-arn is
//                                          compatible
//   theorem_h_exec_refines_model           exec function == model, under H_ORACLE
//   theorem_i_validated_config_equals_spec_text   for a validated configured ARN, the code's
//                                          compatibility test equals the spec text on every record
//   resolve_key_store_arn (exec)           contract: Ok(k) => k@ == configured && compat;
//                                          Err(e) => e.kind == Validation && !compat; for ANY oracle
//   witness_ok / witness_err / witness_byte_eq / witness_mrk_other_region_accepted /
//   witness_empty_parts_accepted           the contracts are satisfiable (Ok, Err, byte-equal,
//                                          a different-region ARN of the same MRK is accepted)
//
// OBSERVATIONS (not failures; nothing in the pinned path contradicts the spec)
//   O1  DEV-ALIAS. The code's MRK match returns false for two byte-identical alias ARNs, where the
//       spec text returns true (mrk_match.rs:10-19, :25-27; `lemma_mrk_match_identical`,
//       `lemma_code_vs_spec_text`). The deviation is documented in the code. It cannot affect the
//       pinned path behind `build`, because `validate()` rejects alias configurations
//       (`lemma_validated_not_alias`, `theorem_i`, under H_BUILD). It is stricter than the spec, never looser.
//   O2  Loose ARN validity. `is_multi_region_arn` (:52-58) and `validate_kms_key_arn` (:61-79)
//       accept an ARN whose partition, region and account are empty
//       (`witness_empty_parts_accepted`, a statement about the model of those two functions).
//       aws-kms-key-arn.md "A valid AWS KMS ARN" requires them non-empty, and branch-key-store.md
//       :157-158 requires the configured ARN to be valid. `validate_kms_key_arn` also accepts any
//       resource type other than "alias" (e.g. `foo/bar`), where the spec says `alias` or `key`
//       (read from kms_config.rs:61-79; not in the model). Consequence for T03: none. The record
//       can only match a configured ARN on its own partition, service, account and resource id,
//       and the KeyId is the configured ARN either way. It is a conformance gap in
//       configuration validation, outside this target.
//
// NOT COVERED
//   * The Discovery and MrDiscovery arms (kms_ops.rs:96-103), reject_alias_arn, rewrite_arn_region
//     (T17 / BUG-04). `Resolved::NotPinned` is the only statement about them.
//   * `version_key` (branch_key_store.rs:641-): same function, same property by H_CALLER; its
//     ReEncrypt, authentication and the rest of the flow are not modeled. `generate_wrapped_key`
//     is given `configured_arn` directly at :726.
//   * That KMS Decrypt authenticates the record (the EC carries `kms-arn` as AAD), AWS-side
//     behavior, grant tokens, timing.
//   * Panic freedom of the shipped `pa[5]` / `pb[5]` indexing (mrk_match.rs:40-45): the model
//     proves the guard fixes the piece count (`lemma_mrk_match_indices_in_range`); that the shipped
//     `split` is called on the same strings is by correspondence.
//   * The error message and the `format!` that builds it; `Error` fields other than `kind`.
//   * Rollback / replay of an authentic older record (TM-MPL-005 non-goal).
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Types and constants
// ============================================================

pub type Str = Seq<char>;

/// Spec-level view of `KmsConfiguration` (config.rs:12), with `Str` payloads. The payload of
/// `Discovery` is ignored by the function, so it is dropped. The wrapper structs
/// `KmsKeyArn { arn }` and `KmsMrKeyArn { arn }` are collapsed to their ARN.
pub enum Cfg {
    KmsKeyArn(Str),
    KmsMrKeyArn(Str),
    Discovery,
    MrDiscovery(Str),
}

/// Model of `crate::error::Kind`, restricted to the one kind the pinned path produces.
#[derive(PartialEq, Eq)]
pub enum Kind {
    Validation,
}

/// Model of `crate::Error` (message, source and resource are dropped).
pub struct Error {
    pub kind: Kind,
}

/// The outcome of the pinned path, as a spec value.
pub enum Resolved {
    /// The two early-return arms (`Discovery`, `MrDiscovery`), kms_ops.rs:96-103. Out of scope.
    NotPinned,
    /// `Ok(key_id)`.
    Key(Str),
    /// `Err(e)` with `e.kind`.
    Fail(Kind),
}

pub open spec fn s_arn() -> Str { seq!['a', 'r', 'n'] }
pub open spec fn s_kms() -> Str { seq!['k', 'm', 's'] }
/// `segments[5].starts_with("key/mrk-")` (mrk_match.rs:57)
pub open spec fn s_key_mrk() -> Str { seq!['k', 'e', 'y', '/', 'm', 'r', 'k', '-'] }
/// `segments[5].starts_with("alias/")` (mrk_match.rs:67)
pub open spec fn s_alias() -> Str { seq!['a', 'l', 'i', 'a', 's', '/'] }
pub open spec fn s_key() -> Str { seq!['k', 'e', 'y'] }
/// ATTR_KMS_ARN = "kms-arn" (attributes.rs:15)
pub open spec fn k_kms_arn() -> Str { seq!['k', 'm', 's', '-', 'a', 'r', 'n'] }

// ============================================================
// SECTION 2: Model of str::split(':') and str::split_once('/')
// ============================================================

/// `s.split(':').collect::<Vec<&str>>()`, defined char by char.
/// `"".split(':')` is `[""]`, and a leading, trailing or doubled ':' gives empty pieces.
pub open spec fn split_colon(s: Str) -> Seq<Str>
    decreases s.len(),
{
    if s.len() == 0 {
        seq![Seq::<char>::empty()]
    } else {
        let rest = split_colon(s.skip(1));
        if s[0] == ':' {
            seq![Seq::<char>::empty()].add(rest)
        } else {
            seq![seq![s[0]].add(rest[0])].add(rest.skip(1))
        }
    }
}

/// Inverse of the split: the pieces joined with ':'.
pub open spec fn join_colon(segs: Seq<Str>) -> Str
    decreases segs.len(),
{
    if segs.len() == 0 {
        Seq::<char>::empty()
    } else if segs.len() == 1 {
        segs[0]
    } else {
        segs[0].add(seq![':']).add(join_colon(segs.skip(1)))
    }
}

pub open spec fn colon_free(x: Str) -> bool {
    forall|j: int| 0 <= j < x.len() ==> #[trigger] x[j] != ':'
}

/// Index of the first '/' in `s`, if any.
pub open spec fn first_slash(s: Str) -> Option<int>
    decreases s.len(),
{
    if s.len() == 0 {
        None
    } else if s[0] == '/' {
        Some(0int)
    } else {
        match first_slash(s.skip(1)) {
            None => None,
            Some(i) => Some(i + 1),
        }
    }
}

/// `s.split_once('/').unwrap_or((s, ""))` (mrk_match.rs:40-41).
pub open spec fn split_once_or(s: Str) -> (Str, Str) {
    match first_slash(s) {
        Some(i) => (s.take(i), s.skip(i + 1)),
        None => (s, Seq::<char>::empty()),
    }
}

// ============================================================
// SECTION 3: Model of aws_kms_mrk_match_for_decrypt and is_arn_compatible
// ============================================================

/// mrk_match.rs:52-58
pub open spec fn is_mr_arn(s: Str) -> bool {
    let seg = split_colon(s);
    &&& seg.len() == 6
    &&& seg[0] == s_arn()
    &&& seg[2] == s_kms()
    &&& s_key_mrk().is_prefix_of(seg[5])
}

/// mrk_match.rs:62-68
pub open spec fn is_alias_arn(s: Str) -> bool {
    let seg = split_colon(s);
    &&& seg.len() == 6
    &&& seg[0] == s_arn()
    &&& seg[2] == s_kms()
    &&& s_alias().is_prefix_of(seg[5])
}

/// mrk_match.rs:24-48 `aws_kms_mrk_match_for_decrypt(a, b)`, branch by branch.
pub open spec fn mrk_match(a: Str, b: Str) -> bool {
    if is_alias_arn(a) || is_alias_arn(b) {
        false  // :25-27
    } else if a == b {
        true  // :29-31
    } else if !is_mr_arn(a) || !is_mr_arn(b) {
        false  // :33-35
    } else {
        let pa = split_colon(a);  // :38
        let pb = split_colon(b);  // :39
        let (rt_a, res_a) = split_once_or(pa[5]);  // :40
        let (rt_b, res_b) = split_once_or(pb[5]);  // :41
        &&& pa[1] == pb[1]  // :43 partition
        &&& pa[2] == pb[2]  // :44 service
        &&& pa[4] == pb[4]  // :45 accountId
        &&& rt_a == rt_b  // :46 resourceType
        &&& res_a == res_b  // :47 resource
    }
}

/// kms_config.rs:86-94 `is_arn_compatible(config, stored_arn)`.
pub open spec fn compat(c: Cfg, stored: Str) -> bool {
    match c {
        Cfg::KmsKeyArn(a) => a == stored,  // :88
        Cfg::KmsMrKeyArn(a) => mrk_match(a, stored),  // :89-91
        Cfg::Discovery => true,  // :92
        Cfg::MrDiscovery(_) => true,  // :92
    }
}

// ============================================================
// SECTION 4: Model of resolve_key_store_arn (pinned path)
// ============================================================

pub open spec fn is_pinned(c: Cfg) -> bool {
    c is KmsKeyArn || c is KmsMrKeyArn
}

/// `configured` (kms_ops.rs:94-95): the ARN held by the configuration.
pub open spec fn configured_arn(c: Cfg) -> Str {
    match c {
        Cfg::KmsKeyArn(a) => a,
        Cfg::KmsMrKeyArn(a) => a,
        _ => Seq::<char>::empty(),
    }
}

/// kms_ops.rs:88-114, given the boolean result of `is_arn_compatible`.
/// The record ARN enters ONLY through `compat_ok`.
pub open spec fn resolve_given(c: Cfg, compat_ok: bool) -> Resolved {
    if !is_pinned(c) {
        Resolved::NotPinned  // :96-103 early returns
    } else if !compat_ok {
        Resolved::Fail(Kind::Validation)  // :105-112
    } else {
        Resolved::Key(configured_arn(c))  // :113 `Ok(configured.to_owned())`
    }
}

/// The full model: `compat_ok` is the modeled `is_arn_compatible`.
pub open spec fn resolve(c: Cfg, rec: Str) -> Resolved {
    resolve_given(c, compat(c, rec))
}

// ============================================================
// SECTION 5: Lemmas about the split model (the model of `split` is the real one)
// ============================================================

proof fn lemma_split_nonempty(s: Str)
    ensures
        split_colon(s).len() >= 1,
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_split_nonempty(s.skip(1));
    }
}

/// Every piece is colon-free.
proof fn lemma_split_pieces_colon_free(s: Str)
    ensures
        forall|i: int| 0 <= i < split_colon(s).len() ==> colon_free(#[trigger] split_colon(s)[i]),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_split_pieces_colon_free(s.skip(1));
        lemma_split_nonempty(s.skip(1));
        let rest = split_colon(s.skip(1));
        let res = split_colon(s);
        assert forall|i: int| 0 <= i < res.len() implies colon_free(#[trigger] res[i]) by {
            if s[0] == ':' {
                if i >= 1 {
                    assert(res[i] == rest[i - 1]);
                }
            } else {
                if i == 0 {
                    assert(res[0] == seq![s[0]].add(rest[0]));
                    assert(colon_free(rest[0]));
                    assert forall|j: int| 0 <= j < res[0].len() implies res[0][j] != ':' by {
                        if j > 0 {
                            assert(res[0][j] == rest[0][j - 1]);
                        }
                    }
                } else {
                    assert(res[i] == rest.skip(1)[i - 1]);
                    assert(rest.skip(1)[i - 1] == rest[i]);
                }
            }
        }
    }
}

/// join (split s) == s
proof fn lemma_join_split(s: Str)
    ensures
        join_colon(split_colon(s)) == s,
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_join_split(s.skip(1));
        lemma_split_nonempty(s.skip(1));
        let rest = split_colon(s.skip(1));
        let res = split_colon(s);
        if s[0] == ':' {
            assert(res.len() >= 2);
            assert(res.skip(1) =~= rest);
            assert(res[0] =~= Seq::<char>::empty());
            assert(join_colon(res) =~= seq![':'].add(join_colon(rest)));
            assert(s =~= seq![':'].add(s.skip(1)));
        } else {
            if rest.len() == 1 {
                assert(res =~= seq![seq![s[0]].add(rest[0])]);
                assert(join_colon(rest) == rest[0]);
                assert(s =~= seq![s[0]].add(s.skip(1)));
            } else {
                assert(res.len() >= 2);
                assert(res[0] == seq![s[0]].add(rest[0]));
                assert(res.skip(1) =~= rest.skip(1));
                assert(join_colon(rest) =~= rest[0].add(seq![':']).add(join_colon(rest.skip(1))));
                assert(join_colon(res) =~= seq![s[0]].add(join_colon(rest)));
                assert(s =~= seq![s[0]].add(s.skip(1)));
            }
        }
    }
}

/// A colon-free string is its own single piece.
proof fn lemma_split_colon_free(x: Str)
    requires
        colon_free(x),
    ensures
        split_colon(x) == seq![x],
    decreases x.len(),
{
    if x.len() > 0 {
        let xs = x.skip(1);
        assert(colon_free(xs)) by {
            assert forall|j: int| 0 <= j < xs.len() implies xs[j] != ':' by {
                assert(xs[j] == x[j + 1]);
            }
        }
        lemma_split_colon_free(xs);
        assert(x[0] != ':');
        let rest = split_colon(xs);
        assert(rest == seq![xs]);
        assert(rest.skip(1) =~= Seq::<Str>::empty());
        assert(x =~= seq![x[0]].add(xs));
        assert(split_colon(x) =~= seq![x]);
    } else {
        assert(x =~= Seq::<char>::empty());
        assert(split_colon(x) =~= seq![x]);
    }
}

/// split (x ++ ":" ++ y) == [x] ++ split y   for colon-free x
proof fn lemma_split_at_first_colon(x: Str, y: Str)
    requires
        colon_free(x),
    ensures
        split_colon(x.add(seq![':']).add(y)) == seq![x].add(split_colon(y)),
    decreases x.len(),
{
    let whole = x.add(seq![':']).add(y);
    if x.len() == 0 {
        assert(whole =~= seq![':'].add(y));
        assert(whole.skip(1) =~= y);
        assert(split_colon(whole) =~= seq![Seq::<char>::empty()].add(split_colon(y)));
        assert(x =~= Seq::<char>::empty());
    } else {
        let xs = x.skip(1);
        assert(colon_free(xs)) by {
            assert forall|j: int| 0 <= j < xs.len() implies xs[j] != ':' by {
                assert(xs[j] == x[j + 1]);
            }
        }
        assert(whole[0] == x[0]);
        assert(x[0] != ':');
        assert(whole.skip(1) =~= xs.add(seq![':']).add(y));
        lemma_split_at_first_colon(xs, y);
        let rest = split_colon(whole.skip(1));
        assert(rest == seq![xs].add(split_colon(y)));
        assert(rest[0] == xs);
        assert(rest.skip(1) =~= split_colon(y));
        assert(split_colon(whole) =~= seq![seq![x[0]].add(xs)].add(split_colon(y)));
        assert(x =~= seq![x[0]].add(xs));
    }
}

/// split (join segs) == segs   for non-empty lists of colon-free pieces.
proof fn lemma_split_join(segs: Seq<Str>)
    requires
        segs.len() >= 1,
        forall|i: int| 0 <= i < segs.len() ==> colon_free(#[trigger] segs[i]),
    ensures
        split_colon(join_colon(segs)) == segs,
    decreases segs.len(),
{
    if segs.len() == 1 {
        lemma_split_colon_free(segs[0]);
        assert(segs =~= seq![segs[0]]);
    } else {
        let tail = segs.skip(1);
        assert forall|i: int| 0 <= i < tail.len() implies colon_free(#[trigger] tail[i]) by {
            assert(tail[i] == segs[i + 1]);
        }
        lemma_split_join(tail);
        lemma_split_at_first_colon(segs[0], join_colon(tail));
        assert(split_colon(join_colon(segs)) =~= seq![segs[0]].add(tail));
        assert(segs =~= seq![segs[0]].add(tail));
    }
}

// ============================================================
// SECTION 6: Lemmas about the MRK match (the T11 level the property needs)
// ============================================================

/// "The two ARNs agree on every colon-separated piece except the region (piece 3)."
pub open spec fn differs_only_in_region(a: Str, b: Str) -> bool {
    let pa = split_colon(a);
    let pb = split_colon(b);
    &&& pa.len() == 6
    &&& pb.len() == 6
    &&& forall|i: int| 0 <= i < 6 && i != 3 ==> #[trigger] pa[i] == pb[i]
}

/// An MRK ARN is not an alias ARN (the sixth piece starts with 'k', not 'a').
proof fn lemma_mr_not_alias(s: Str)
    requires
        is_mr_arn(s),
    ensures
        !is_alias_arn(s),
{
    let seg = split_colon(s);
    assert(s_key_mrk().is_prefix_of(seg[5]));
    assert(seg[5][0] == 'k');
    if is_alias_arn(s) {
        assert(s_alias().is_prefix_of(seg[5]));
        assert(seg[5][0] == 'a');
    }
}

/// If a piece starts with "key/mrk-" then its first '/' is at index 3.
proof fn lemma_first_slash_key_mrk(p: Str)
    requires
        s_key_mrk().is_prefix_of(p),
    ensures
        first_slash(p) == Some(3int),
        split_once_or(p).0 == s_key(),
        split_once_or(p).1 == p.skip(4),
{
    reveal_with_fuel(first_slash, 5);
    assert(p.subrange(0, 8) =~= s_key_mrk());
    assert(p[0] == 'k' && p[1] == 'e' && p[2] == 'y' && p[3] == '/');
    assert(p.skip(1)[0] == p[1]);
    assert(p.skip(1).skip(1)[0] == p[2]);
    assert(p.skip(1).skip(1).skip(1)[0] == p[3]);
    assert(p.skip(1).skip(1).skip(1).skip(1)[0] == p.skip(1).skip(1).skip(1)[1]);
    assert(p.take(3) =~= s_key());
    assert(p.skip(4) =~= p.skip(3int + 1));
}

/// A piece starting with "key/mrk-" is "key/" followed by what `split_once('/')` returns.
proof fn lemma_key_mrk_piece_eq(p: Str, q: Str)
    requires
        s_key_mrk().is_prefix_of(p),
        s_key_mrk().is_prefix_of(q),
        split_once_or(p).1 == split_once_or(q).1,
    ensures
        p == q,
{
    lemma_first_slash_key_mrk(p);
    lemma_first_slash_key_mrk(q);
    assert(p.skip(4) == q.skip(4));
    assert(p.subrange(0, 8) =~= s_key_mrk());
    assert(q.subrange(0, 8) =~= s_key_mrk());
    assert(p =~= q) by {
        assert forall|i: int| 0 <= i < p.len() implies p[i] == q[i] by {
            if i < 4 {
                assert(p[i] == s_key_mrk()[i]);
                assert(q[i] == s_key_mrk()[i]);
            } else {
                assert(p.skip(4)[i - 4] == p[i]);
                assert(q.skip(4)[i - 4] == q[i]);
            }
        }
        assert(p.len() == q.len()) by {
            assert(p.skip(4).len() == q.skip(4).len());
        }
    }
}

/// The `pa[1]`, `pa[2]`, `pa[4]`, `pa[5]` (and `pb[..]`) reads at mrk_match.rs:40-45 are only
/// reached after the `is_multi_region_arn` guard (:33), which fixes the piece count at 6. So no
/// index is out of range in the model; the shipped code computes the same `split(':')` twice.
proof fn lemma_mrk_match_indices_in_range(a: Str, b: Str)
    requires
        !is_alias_arn(a),
        !is_alias_arn(b),
        a != b,
        is_mr_arn(a),
        is_mr_arn(b),
    ensures
        split_colon(a).len() == 6,
        split_colon(b).len() == 6,
{
}

/// Exact characterization of `aws_kms_mrk_match_for_decrypt` (mrk_match.rs:24-48):
/// it returns true iff neither input is an alias ARN and either they are byte-equal,
/// or both are MRK ARNs that differ only in the region piece.
proof fn lemma_mrk_match_iff(a: Str, b: Str)
    ensures
        mrk_match(a, b) <==> (!is_alias_arn(a) && !is_alias_arn(b) && (a == b || (is_mr_arn(a)
            && is_mr_arn(b) && differs_only_in_region(a, b)))),
{
    if !is_alias_arn(a) && !is_alias_arn(b) && a != b && is_mr_arn(a) && is_mr_arn(b) {
        let pa = split_colon(a);
        let pb = split_colon(b);
        lemma_first_slash_key_mrk(pa[5]);
        lemma_first_slash_key_mrk(pb[5]);
        assert(pa[0] == pb[0]);
        if mrk_match(a, b) {
            lemma_key_mrk_piece_eq(pa[5], pb[5]);
            assert(differs_only_in_region(a, b));
        }
        if differs_only_in_region(a, b) {
            assert(pa[1] == pb[1]);
            assert(pa[2] == pb[2]);
            assert(pa[4] == pb[4]);
            assert(pa[5] == pb[5]);
            assert(mrk_match(a, b));
        }
    }
}

/// Byte-equal ARNs match unless they are aliases (spec: "identical => true"; the code
/// deviates for aliases, mrk_match.rs:10-19 and :25-27).
proof fn lemma_mrk_match_identical(a: Str)
    ensures
        mrk_match(a, a) <==> !is_alias_arn(a),
{
}

/// Reading the code's MRK match against the spec text of aws-kms-mrk-match-for-decrypt.md
/// "Implementation". `spec_mrk_match` is that text, using the code's own `is_mr_arn` for
/// "identified as a multi-Region key" (assumption A_MR).
pub open spec fn spec_mrk_match(a: Str, b: Str) -> bool {
    if a == b {
        true
    } else if !is_mr_arn(a) || !is_mr_arn(b) {
        false
    } else {
        differs_only_in_region(a, b)
    }
}

/// The code equals the spec text on every input pair with no alias. On a pair with an alias
/// the code returns false and the spec text returns true only when the two are identical
/// (the documented deviation DEV-ALIAS); when they differ, an alias is not an MRK ARN so
/// the spec text also returns false.
proof fn lemma_code_vs_spec_text(a: Str, b: Str)
    ensures
        (!is_alias_arn(a) && !is_alias_arn(b)) ==> (mrk_match(a, b) == spec_mrk_match(a, b)),
        (is_alias_arn(a) || is_alias_arn(b)) ==> !mrk_match(a, b),
        (is_alias_arn(a) || is_alias_arn(b)) ==> (spec_mrk_match(a, b) <==> a == b),
{
    lemma_mrk_match_iff(a, b);
    if is_alias_arn(a) {
        if is_mr_arn(a) {
            lemma_mr_not_alias(a);
        }
    }
    if is_alias_arn(b) {
        if is_mr_arn(b) {
            lemma_mr_not_alias(b);
        }
    }
    if (is_alias_arn(a) || is_alias_arn(b)) && a != b {
        assert(!(is_mr_arn(a) && is_mr_arn(b)));
    }
}

// ============================================================
// SECTION 6b: Model of the configuration check (kms_config.rs parse_arn / validate_kms_key_arn)
// Used only to show that a VALIDATED configured ARN is never an alias ARN, so the
// documented alias deviation (DEV-ALIAS) cannot arise through `DynamoDbKeyStore::build`
// (branch_key_store.rs:381 calls `kms_configuration.validate()?`).
// ============================================================

pub open spec fn s_alias_word() -> Str { seq!['a', 'l', 'i', 'a', 's'] }

/// `arn.splitn(6, ':')` (kms_config.rs:32): at most 6 pieces, the last holds the remainder.
pub open spec fn splitn6(s: Str) -> Seq<Str> {
    let p = split_colon(s);
    if p.len() <= 6 {
        p
    } else {
        p.take(5).push(join_colon(p.skip(5)))
    }
}

/// `parse_arn(arn).is_ok()` (kms_config.rs:31-58): 6 pieces, the first is "arn",
/// and the sixth contains a '/'.
pub open spec fn parse_arn_ok(s: Str) -> bool {
    let seg = splitn6(s);
    &&& seg.len() == 6
    &&& seg[0] == s_arn()
    &&& first_slash(seg[5]) is Some
}

/// `validate_kms_key_arn(arn).is_ok()` (kms_config.rs:61-79): parses, service is "kms",
/// resource type is not "alias".
pub open spec fn validate_ok(s: Str) -> bool {
    &&& parse_arn_ok(s)
    &&& splitn6(s)[2] == s_kms()
    &&& split_once_or(splitn6(s)[5]).0 != s_alias_word()
}

/// If a piece starts with "alias/" then its first '/' is at index 5 and the resource type is "alias".
proof fn lemma_first_slash_alias(p: Str)
    requires
        s_alias().is_prefix_of(p),
    ensures
        first_slash(p) == Some(5int),
        split_once_or(p).0 == s_alias_word(),
{
    reveal_with_fuel(first_slash, 7);
    assert(p.subrange(0, 6) =~= s_alias());
    assert(p[0] == 'a' && p[1] == 'l' && p[2] == 'i' && p[3] == 'a' && p[4] == 's' && p[5] == '/');
    assert(p.skip(1)[0] == p[1]);
    assert(p.skip(1).skip(1)[0] == p[2]);
    assert(p.skip(1).skip(1).skip(1)[0] == p[3]);
    assert(p.skip(1).skip(1).skip(1).skip(1)[0] == p[4]);
    assert(p.skip(1).skip(1).skip(1).skip(1).skip(1)[0] == p[5]);
    assert(p.take(5) =~= s_alias_word());
}

/// A configured ARN that passes `validate_kms_key_arn` is not an alias ARN in the sense
/// of `mrk_match::is_alias_arn`.
proof fn lemma_validated_not_alias(s: Str)
    requires
        validate_ok(s),
    ensures
        !is_alias_arn(s),
{
    if is_alias_arn(s) {
        let seg = split_colon(s);
        assert(splitn6(s) == seg);
        lemma_first_slash_alias(seg[5]);
        assert(split_once_or(splitn6(s)[5]).0 == s_alias_word());
    }
}

/// An MRK ARN (as identified by the code) passes `validate_kms_key_arn`.
proof fn lemma_mr_arn_validates(s: Str)
    requires
        is_mr_arn(s),
    ensures
        validate_ok(s),
{
    let seg = split_colon(s);
    assert(splitn6(s) == seg);
    lemma_first_slash_key_mrk(seg[5]);
}

// ============================================================
// SECTION 7: THEOREMS about resolve_key_store_arn (pinned modes)
// ============================================================

/// T-A (the headline property). In a pinned mode, whatever the record's `kms-arn` is,
/// a successful call returns exactly the configured ARN. It also always terminates in Ok or Err.
proof fn theorem_a_key_id_is_configured(c: Cfg, rec: Str)
    requires
        is_pinned(c),
    ensures
        resolve(c, rec) is Key || resolve(c, rec) is Fail,
        resolve(c, rec) matches Resolved::Key(k) ==> k == configured_arn(c),
{
}

/// T-A2. The returned KeyId does not depend on the record: any two accepted records
/// give the same KeyId. (The record ARN enters `resolve_given` only as a boolean.)
proof fn theorem_a2_key_id_independent_of_record(c: Cfg, rec1: Str, rec2: Str)
    requires
        is_pinned(c),
        resolve(c, rec1) is Key,
        resolve(c, rec2) is Key,
    ensures
        resolve(c, rec1) == resolve(c, rec2),
{
}

/// T-B. Exact Ok/Err characterization against the compatibility predicate, and the error kind.
proof fn theorem_b_ok_iff_compat(c: Cfg, rec: Str)
    requires
        is_pinned(c),
    ensures
        (resolve(c, rec) is Key) <==> compat(c, rec),
        (resolve(c, rec) is Fail) <==> !compat(c, rec),
        resolve(c, rec) matches Resolved::Fail(k) ==> k == Kind::Validation,
        compat(c, rec) ==> resolve(c, rec) == Resolved::Key(configured_arn(c)),
{
}

/// T-C. `KmsKeyArn`: success iff the record ARN is byte-equal to the configured ARN.
/// (So the KeyId is the record ARN too, but only because the two are the same string.)
proof fn theorem_c_single_key(c: Cfg, rec: Str)
    requires
        c is KmsKeyArn,
    ensures
        (resolve(c, rec) is Key) <==> (rec == configured_arn(c)),
        resolve(c, rec) matches Resolved::Key(k) ==> k == rec,
{
}

/// T-D. `KmsMrKeyArn`, soundness: on success the record ARN is either byte-equal to
/// the configured ARN, or both are MRK ARNs that agree on partition, service, account,
/// resource type and resource id (they differ only in the region piece). Neither is an
/// alias ARN. The KeyId is still the configured ARN, whichever case holds.
proof fn theorem_d_mrk_sound(c: Cfg, rec: Str)
    requires
        c is KmsMrKeyArn,
    ensures
        resolve(c, rec) matches Resolved::Key(k) ==> {
            &&& k == configured_arn(c)
            &&& !is_alias_arn(configured_arn(c))
            &&& !is_alias_arn(rec)
            &&& (rec == configured_arn(c) || (is_mr_arn(configured_arn(c)) && is_mr_arn(rec)
                && differs_only_in_region(configured_arn(c), rec)))
        },
{
    lemma_mrk_match_iff(configured_arn(c), rec);
}

/// T-E. `KmsMrKeyArn`, completeness: those conditions are also sufficient.
proof fn theorem_e_mrk_complete(c: Cfg, rec: Str)
    requires
        c is KmsMrKeyArn,
        !is_alias_arn(configured_arn(c)),
        !is_alias_arn(rec),
        rec == configured_arn(c) || (is_mr_arn(configured_arn(c)) && is_mr_arn(rec)
            && differs_only_in_region(configured_arn(c), rec)),
    ensures
        resolve(c, rec) == Resolved::Key(configured_arn(c)),
{
    lemma_mrk_match_iff(configured_arn(c), rec);
}

/// T-F. The `Discovery` and `MrDiscovery` arms are not pinned: `resolve` reports them as
/// NotPinned and no claim about them is made.
proof fn theorem_f_dispatch(c: Cfg, rec: Str)
    ensures
        is_pinned(c) <==> !(resolve(c, rec) is NotPinned),
{
}

/// T-I. For a `KmsMrKeyArn` whose configured ARN passes `validate_kms_key_arn` (the only
/// configurations `DynamoDbKeyStore::build` accepts), the code's compatibility test equals the
/// spec text of aws-kms-mrk-match-for-decrypt.md on EVERY record string, aliases included.
/// So DEV-ALIAS (code stricter than spec on identical alias ARNs) is unreachable for the
/// pinned modes behind `build`. Assumes H_BUILD: the configuration used by `resolve_key_store_arn`
/// is the one `build` validated (the field is private and never mutated; audited, not proved).
proof fn theorem_i_validated_config_equals_spec_text(c: Cfg, rec: Str)
    requires
        c is KmsMrKeyArn,
        validate_ok(configured_arn(c)),
    ensures
        compat(c, rec) == spec_mrk_match(configured_arn(c), rec),
{
    let cfg = configured_arn(c);
    lemma_validated_not_alias(cfg);
    lemma_code_vs_spec_text(cfg, rec);
    if is_alias_arn(rec) {
        assert(cfg != rec);
    }
}

// ============================================================
// SECTION 8: Existence (the contracts are not vacuous) and observations
// ============================================================

/// The ARN `arn:<partition>:kms:<region>:<account>:key/mrk-<id>` as a string.
pub open spec fn mrk_arn(partition: Str, region: Str, account: Str, id: Str) -> Str {
    join_colon(
        seq![
            s_arn(),
            partition,
            s_kms(),
            region,
            account,
            s_key_mrk().add(id),
        ],
    )
}

pub open spec fn mrk_arn_pieces_ok(partition: Str, region: Str, account: Str, id: Str) -> bool {
    &&& colon_free(partition)
    &&& colon_free(region)
    &&& colon_free(account)
    &&& colon_free(id)
}

proof fn lemma_mrk_arn_split(partition: Str, region: Str, account: Str, id: Str)
    requires
        mrk_arn_pieces_ok(partition, region, account, id),
    ensures
        split_colon(mrk_arn(partition, region, account, id)) == seq![
            s_arn(),
            partition,
            s_kms(),
            region,
            account,
            s_key_mrk().add(id),
        ],
        is_mr_arn(mrk_arn(partition, region, account, id)),
{
    let segs = seq![s_arn(), partition, s_kms(), region, account, s_key_mrk().add(id)];
    assert(colon_free(s_arn()));
    assert(colon_free(s_kms()));
    assert(colon_free(s_key_mrk().add(id))) by {
        assert forall|j: int| 0 <= j < s_key_mrk().add(id).len() implies s_key_mrk().add(id)[j] != ':' by {
            if j >= 8 {
                assert(s_key_mrk().add(id)[j] == id[j - 8]);
            }
        }
    }
    assert forall|i: int| 0 <= i < segs.len() implies colon_free(#[trigger] segs[i]) by {
        if i == 0 {
        } else if i == 1 {
        } else if i == 2 {
        } else if i == 3 {
        } else if i == 4 {
        } else {
        }
    }
    lemma_split_join(segs);
    assert(s_key_mrk().is_prefix_of(s_key_mrk().add(id))) by {
        assert(s_key_mrk().add(id).subrange(0, 8) =~= s_key_mrk());
    }
}

/// Witness for T-E: two different-region ARNs of the same MRK are accepted, with the
/// configured one as KeyId, and they are NOT byte-equal.
proof fn witness_mrk_other_region_accepted(
    partition: Str,
    r1: Str,
    r2: Str,
    account: Str,
    id: Str,
)
    requires
        mrk_arn_pieces_ok(partition, r1, account, id),
        mrk_arn_pieces_ok(partition, r2, account, id),
        r1 != r2,
    ensures
        mrk_arn(partition, r1, account, id) != mrk_arn(partition, r2, account, id),
        ({
            let cfg = Cfg::KmsMrKeyArn(mrk_arn(partition, r1, account, id));
            resolve(cfg, mrk_arn(partition, r2, account, id)) == Resolved::Key(
                mrk_arn(partition, r1, account, id),
            )
        }),
{
    let (p, a, i) = (partition, account, id);
    lemma_mrk_arn_split(p, r1, a, i);
    lemma_mrk_arn_split(p, r2, a, i);
    let s1 = split_colon(mrk_arn(p, r1, a, i));
    let s2 = split_colon(mrk_arn(p, r2, a, i));
    assert(s1[3] == r1);
    assert(s2[3] == r2);
    let cfg = Cfg::KmsMrKeyArn(mrk_arn(p, r1, a, i));
    lemma_mr_not_alias(mrk_arn(p, r1, a, i));
    lemma_mr_not_alias(mrk_arn(p, r2, a, i));
    lemma_mrk_match_iff(mrk_arn(p, r1, a, i), mrk_arn(p, r2, a, i));
    assert(differs_only_in_region(mrk_arn(p, r1, a, i), mrk_arn(p, r2, a, i))) by {
        assert forall|k: int| 0 <= k < 6 && k != 3 implies #[trigger] s1[k] == s2[k] by {}
    }
}

/// Observation O2. The code's MRK identification (mrk_match.rs:52-58) and the config check
/// (kms_config.rs:61-79) accept an ARN whose partition, region and account are all EMPTY.
/// aws-kms-key-arn.md "A valid AWS KMS ARN" requires each to be non-empty, and
/// branch-key-store.md:157-158 requires the configured ARN to be a valid AWS KMS Key ARN.
/// This is a proof about the MODEL of those two functions (Section 3 and 6b).
proof fn witness_empty_parts_accepted(id: Str)
    requires
        colon_free(id),
    ensures
        ({
            let s = mrk_arn(Seq::<char>::empty(), Seq::<char>::empty(), Seq::<char>::empty(), id);
            is_mr_arn(s) && validate_ok(s)
        }),
{
    let e = Seq::<char>::empty();
    assert(colon_free(e));
    lemma_mrk_arn_split(e, e, e, id);
    lemma_mr_arn_validates(mrk_arn(e, e, e, id));
}

// ============================================================
// SECTION 9: The decrypt path (decrypt_branch_key, kms_ops.rs:162-)
// ============================================================

/// What `decrypt_branch_key` does with the record, up to the KMS call.
pub enum DecryptStep {
    /// Config is Discovery or MrDiscovery (out of scope).
    NotPinned,
    /// kms_ops.rs:172-178: the record has no `kms-arn` attribute.
    MissingKmsArn,
    /// kms_ops.rs:179 `resolve_key_store_arn(..)?` returned Err.
    ResolveFailed(Kind),
    /// kms_ops.rs:181-183: `kms_client.decrypt().key_id(&resolved_key_id)` is called.
    CallKms { key_id: Str },
}

pub open spec fn decrypt_step(c: Cfg, attrs: Map<Str, Str>) -> DecryptStep {
    if !attrs.contains_key(k_kms_arn()) {
        DecryptStep::MissingKmsArn
    } else {
        match resolve(c, attrs[k_kms_arn()]) {
            Resolved::NotPinned => DecryptStep::NotPinned,
            Resolved::Fail(kd) => DecryptStep::ResolveFailed(kd),
            Resolved::Key(k) => DecryptStep::CallKms { key_id: k },
        }
    }
}

/// T-G. In a pinned mode, if `decrypt_branch_key` issues the KMS Decrypt call, the `KeyId`
/// is the configured ARN, whatever attributes the record carries; the call happens only when
/// the record's `kms-arn` is compatible. Two records that both reach KMS get the same KeyId.
proof fn theorem_g_decrypt_key_id(c: Cfg, attrs: Map<Str, Str>, attrs2: Map<Str, Str>)
    requires
        is_pinned(c),
    ensures
        decrypt_step(c, attrs) matches DecryptStep::CallKms { key_id } ==> {
            &&& key_id == configured_arn(c)
            &&& attrs.contains_key(k_kms_arn())
            &&& compat(c, attrs[k_kms_arn()])
        },
        (decrypt_step(c, attrs) is CallKms && decrypt_step(c, attrs2) is CallKms)
            ==> decrypt_step(c, attrs) == decrypt_step(c, attrs2),
{
}

// ============================================================
// SECTION 10: Executable model of resolve_key_store_arn (pinned path)
// ============================================================

/// Executable model of `KmsConfiguration` (config.rs:12) with `String` payloads.
pub enum KmsConfiguration {
    KmsKeyArn(String),
    KmsMrKeyArn(String),
    Discovery,
    MrDiscovery(String),
}

impl View for KmsConfiguration {
    type V = Cfg;

    open spec fn view(&self) -> Cfg {
        match self {
            KmsConfiguration::KmsKeyArn(a) => Cfg::KmsKeyArn(a@),
            KmsConfiguration::KmsMrKeyArn(a) => Cfg::KmsMrKeyArn(a@),
            KmsConfiguration::Discovery => Cfg::Discovery,
            KmsConfiguration::MrDiscovery(r) => Cfg::MrDiscovery(r@),
        }
    }
}

/// The compatibility predicate as an abstract component. The contract is the only thing the
/// proof knows about it: the result is a deterministic function `spec_compat(config, stored)`.
/// Section 3's `compat` is the model of the shipped implementation (kms_config.rs:86-94);
/// theorem_h below states what is needed to identify the two.
pub trait ArnCompat {
    spec fn spec_compat(c: Cfg, stored: Str) -> bool;

    fn is_arn_compatible(config: &KmsConfiguration, stored: &String) -> (b: bool)
        ensures
            b == Self::spec_compat(config@, stored@),
    ;
}

/// kms_ops.rs:88-114. `branch_key_id` is used by the shipped code only in the out-of-scope
/// arms (reject_alias_arn, rewrite_arn_region), so it is unused here.
pub fn resolve_key_store_arn<O: ArnCompat>(
    kms_config: &KmsConfiguration,
    record_kms_arn: &String,
    branch_key_id: &String,
) -> (r: Result<String, Error>)
    requires
        is_pinned(kms_config@),  // scope: KmsKeyArn or KmsMrKeyArn, as in the T03 formal_spec
    ensures
        match r {
            Ok(k) => {
                &&& k@ == configured_arn(kms_config@)
                &&& O::spec_compat(kms_config@, record_kms_arn@)
            },
            Err(e) => {
                &&& e.kind == Kind::Validation
                &&& !O::spec_compat(kms_config@, record_kms_arn@)
            },
        },
        match r {
            Ok(k) => resolve_given(kms_config@, O::spec_compat(kms_config@, record_kms_arn@))
                == Resolved::Key(k@),
            Err(e) => resolve_given(kms_config@, O::spec_compat(kms_config@, record_kms_arn@))
                == Resolved::Fail(e.kind),
        },
{
    // :93-104
    let configured: &String = match kms_config {
        KmsConfiguration::KmsKeyArn(c) => c,
        KmsConfiguration::KmsMrKeyArn(c) => c,
        KmsConfiguration::Discovery => {
            // :96-99, excluded by `requires is_pinned`
            assert(false);
            return Err(Error { kind: Kind::Validation });
        },
        KmsConfiguration::MrDiscovery(_) => {
            // :100-103, excluded by `requires is_pinned`
            assert(false);
            return Err(Error { kind: Kind::Validation });
        },
    };
    // :105-112
    if !O::is_arn_compatible(kms_config, record_kms_arn) {
        return Err(Error { kind: Kind::Validation });
    }
    // :113 `Ok(configured.to_owned())`
    Ok(configured.as_str().to_owned())
}

// ------------------------------------------------------------
// Instances of the oracle (the contract is satisfiable) and calls
// ------------------------------------------------------------

pub struct AlwaysCompat;

impl ArnCompat for AlwaysCompat {
    open spec fn spec_compat(c: Cfg, stored: Str) -> bool {
        true
    }

    fn is_arn_compatible(config: &KmsConfiguration, stored: &String) -> (b: bool) {
        true
    }
}

pub struct NeverCompat;

impl ArnCompat for NeverCompat {
    open spec fn spec_compat(c: Cfg, stored: Str) -> bool {
        false
    }

    fn is_arn_compatible(config: &KmsConfiguration, stored: &String) -> (b: bool) {
        false
    }
}

/// Byte-equality only (the `KmsKeyArn` arm of kms_config.rs:88 on a single-key configuration).
pub struct ByteEqCompat;

impl ArnCompat for ByteEqCompat {
    open spec fn spec_compat(c: Cfg, stored: Str) -> bool {
        is_pinned(c) && configured_arn(c) == stored
    }

    fn is_arn_compatible(config: &KmsConfiguration, stored: &String) -> (b: bool) {
        match config {
            KmsConfiguration::KmsKeyArn(a) => *a == *stored,
            KmsConfiguration::KmsMrKeyArn(a) => *a == *stored,
            KmsConfiguration::Discovery => false,
            KmsConfiguration::MrDiscovery(_) => false,
        }
    }
}

/// With a compatible record the call succeeds and returns the configured ARN.
pub fn witness_ok(c: &KmsConfiguration, rec: &String, id: &String) -> (r: Result<String, Error>)
    requires
        is_pinned(c@),
    ensures
        r is Ok,
        r matches Ok(k) ==> k@ == configured_arn(c@),
{
    resolve_key_store_arn::<AlwaysCompat>(c, rec, id)
}

/// With an incompatible record the call fails with a Validation error.
pub fn witness_err(c: &KmsConfiguration, rec: &String, id: &String) -> (r: Result<String, Error>)
    requires
        is_pinned(c@),
    ensures
        r is Err,
        r matches Err(e) ==> e.kind == Kind::Validation,
{
    resolve_key_store_arn::<NeverCompat>(c, rec, id)
}

/// With the byte-equality oracle, the KeyId equals the configured ARN even though the
/// record ARN is an arbitrary string, and success means the strings are equal.
pub fn witness_byte_eq(c: &KmsConfiguration, rec: &String, id: &String) -> (r: Result<String, Error>)
    requires
        is_pinned(c@),
    ensures
        r matches Ok(k) ==> k@ == configured_arn(c@) && rec@ == configured_arn(c@),
        r is Err ==> rec@ != configured_arn(c@),
{
    resolve_key_store_arn::<ByteEqCompat>(c, rec, id)
}

/// T-H. The link between the executable model (any oracle) and the full model: if the
/// oracle's contract equals the section-3 model `compat` on all inputs (hypothesis H_ORACLE,
/// the audited correspondence to kms_config.rs:86-94 and mrk_match.rs), then the executable
/// function equals `resolve`.
proof fn theorem_h_exec_refines_model<O: ArnCompat>(c: Cfg, rec: Str)
    requires
        forall|c2: Cfg, s2: Str| #[trigger] O::spec_compat(c2, s2) == compat(c2, s2),
    ensures
        resolve_given(c, O::spec_compat(c, rec)) == resolve(c, rec),
{
}

} // verus!

fn main() {}
