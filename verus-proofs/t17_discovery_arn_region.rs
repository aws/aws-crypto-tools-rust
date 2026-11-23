// =============================================================================
// VR-2026-T17 (priority 1.92, TM-MPL-007, BUG-04): the Discovery and MrDiscovery arms of
//   `kms_ops::resolve_key_store_arn`, `reject_alias_arn`, `rewrite_arn_region` and `parse_arn`
//   (mpl/src/key_store/kms_ops.rs :96-103, :118, :144; kms_config.rs :31)
//
// Run:  ~/verus/verus verus-proofs/t17_discovery_arn_region.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model of four short native Rust functions. A
// `String` is `Seq<char>`. The shipped functions use `str::splitn`, `split_once`, `format!` and
// `Result<String, Error>`, are not inside `verus!`, and are not compiled by Verus. Nothing here
// detects a later edit to mpl/. The link between model and code is the correspondence table in
// section 2, reviewed by a human.
//
// THIS FILE EXTENDS T03 BY COPYING IT. `t03_resolve_pinned_arn.rs` covered the pinned arms
// (KmsKeyArn, KmsMrKeyArn) and left Discovery and MrDiscovery out of scope. This file is a copy of
// the T03 model, cut down and extended. Copied from T03 without change of logic: the types `Str`
// and `Cfg`, `split_colon`, `join_colon`, `colon_free`, `first_slash`, `is_mr_arn`, and the lemmas
// `lemma_split_nonempty`, `lemma_split_pieces_colon_free`, `lemma_join_split`,
// `lemma_split_colon_free`, `lemma_split_at_first_colon`, `lemma_split_join`, plus the body of
// `lemma_first_slash_key_mrk` (as `lemma_key_mrk_piece`). T03's own text is not edited, and no T03
// theorem is restated. The pinned arms are not modelled here (`Resolved::PinnedNotModelled`).
// New in T17: `splitn_colon` (Rust `splitn(6, ':')`), `parse_arn`, `format_arn`, the models of
// `reject_alias_arn` and `rewrite_arn_region`, the Discovery and MrDiscovery arms, the fix model
// `resolve_fixed`, and everything in in-file SECTION 6 to SECTION 10.
//
// STATUS: PARTLY PROVED. Everything verifies except ONE obligation that Verus REJECTS ON PURPOSE
// (EXPECTED_FAIL):
//     `lemma_bug04_region_rewritten_only_for_mrk_EXPECTED_FAIL`
// It states the target property "a record that is not an MRK ARN is returned unchanged by
// MrDiscovery" (YAML VR-2026-T17: `!is_mrk(rec) ==> k == rec`). The shipped arm rewrites the region
// of every ARN it accepts, so the claim is false. The lemma is left failing: not weakened, not
// assumed, not commented out. `lemma_bug04_counterexample` proves the concrete counterexample as an
// ordinary lemma, and `lemma_bug04_claim_is_false` shows the failing statement is false and not
// merely unproved. `lemma_bug04_fix_region_rewritten_only_for_mrk` proves the same statement for
// the modelled fix (in-file SECTION 9).
// Result line:  `verification results:: 47 verified, 1 errors`  (the 1 error is the lemma above)
//
// COUNTEREXAMPLE (concrete, from BUG-04). MrDiscovery with region `us-west-2`, record `kms-arn`
//   arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab   (single-Region key)
// The model returns
//   arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
// The two strings are checked character by character against the BUG-04 reproducer text
// (`lemma_witness_strings`). The shipped function returns the same string
// (`.agents/tasks/bug-recheck/logs/recheck04.log` line 204; a run of the shipped function, not a
// proof, and not re-run for this file).
//
// NO MRK PREFIX TEST ON THIS ARM. A planning note assumed the shipped arm rewrites the Region by
// a prefix test that is not the full MRK check. The code has none. Reading kms_ops.rs shows no MRK
// test of any kind on this arm: `rewrite_arn_region` (:144-157) parses the ARN and rebuilds it with
// the new region, for every ARN `reject_alias_arn` lets through. The only MRK prefix test in mpl/ is
// `is_multi_region_arn` (mrk_match.rs :52-58, `starts_with("key/mrk-")`), a private function. Its only
// caller is `aws_kms_mrk_match_for_decrypt` in the same file (:33), which the key store reaches only for
// the pinned KmsMrKeyArn arm (kms_config.rs :89-91), never for Discovery or MrDiscovery (grep over
// mpl/src). BUG-04 says the same ("There's still no `mrk-` check"). The model follows the code, so it
// has no prefix test on the shipped arm. The prefix test appears only in the fix model, where the
// mutation set below varies it.
// =============================================================================
// WHAT IS PROVED (relative to the model, the hypotheses in section 4 and the assumptions there)
// =============================================================================
//   R1  theorem_discovery_exact        Discovery returns the record ARN verbatim exactly when it parses
//                                      and its resource type is not "alias"; otherwise InvalidMaterials.
//                                      CONSISTENCY CHECK: `resolve` is written as this case split, so the
//                                      theorem checks the YAML text against the model, not the code.
//   R2  theorem_mrdiscovery_same_accept_set   MrDiscovery accepts and rejects exactly the records that
//                                      Discovery does. The alias and malformed-ARN checks come first.
//   R3  theorem_mrdiscovery_rewrite    for every accepted record and a colon-free configured region r
//                                      (H_REGION_CFG), the result parses to the record's parts with ONLY
//                                      the region replaced (region is r; partition, service, account,
//                                      resource type and resource are the record's), it equals the record
//                                      exactly when the record's region is r, and it differs otherwise.
//                                      Built on `lemma_parse_format` (format then parse is the identity
//                                      on parts) and `lemma_parse_parts` (parse then format is the
//                                      identity on strings). This is the "region index" fact.
//   R4  theorem_mrk_region_rewritten   the MRK half of the target property, as shipped: an MRK ARN (spec
//                                      text) has its region replaced by the configured region.
//   R5  (a note in section 7, no obligation) why R3 needs H_REGION_CFG.
//   R6  lemma_bug04_region_rewritten_only_for_mrk_EXPECTED_FAIL   REJECTED ON PURPOSE (finding F1).
//       lemma_nonmrk_unchanged_iff_same_region   for a parsed, non-alias, non-MRK record the shipped arm
//                                      returns the record unchanged exactly when the record's region
//                                      already is the configured one. So the failing claim is false on
//                                      exactly the records with a different region, and nowhere else.
//   R7  lemma_bug04_fix_region_rewritten_only_for_mrk   the target property, PROVED for the fix model.
//   R8  lemma_fix_same_accept_set      the fix accepts and rejects exactly the records the shipped arm does.
//   R9  lemma_fix_agrees_where_mr_arn  where the code's MRK test holds, fix and shipped arm are equal.
//   R10 lemma_fix_rewrites_mrk         the fix still rewrites an MRK ARN (spec text) whose id has no ':'.
//   R11 lemma_fix_leaves_other_arms    Discovery and the pinned arms are the same in both models.
//   R12 lemma_is_mr_arn_iff            on every ARN `parse_arn` accepts, the code's MRK test (copied as
//                                      `is_mr_arn`) holds exactly when the spec text calls the ARN an MRK
//                                      ARN (service kms, resource type key, id starting "mrk-") AND the
//                                      resource id holds no ':'. The ':' clause is observation O2.
//   R13 splitn lemmas                  `lemma_splitn_len`, `lemma_splitn_prefix_colon_free`,
//                                      `lemma_splitn_join`, `lemma_splitn_at_colon`,
//                                      `lemma_splitn_eq_split`: the properties of the `splitn` model that
//                                      R3 and R12 use (it joins back to the string; its first five pieces
//                                      hold no ':'; it equals `split` when `split` gives at most six pieces).
//   R14 witnesses                      `lemma_bug04_counterexample`, `lemma_bug04_mrk_control`,
//                                      `lemma_lookalikes_not_rewritten_by_fix`, `lemma_alias_rejected_witness`,
//                                      `lemma_malformed_rejected_witness`, `lemma_fix_gate_misses_colon_in_resource`,
//                                      `lemma_service_not_checked_witness`, `lemma_witness_strings`: the
//                                      premises are satisfiable and the claims have concrete instances.
//                                      `lemma_words_are_the_code_words` pins the six words ("arn", "kms",
//                                      "key", "mrk-", "alias", "key/mrk-") to string literals.
//
// =============================================================================
// WHAT IS NOT PROVED / WHAT THIS DOES NOT SHOW
// =============================================================================
//   * That the shipped code has any of these properties (model level only).
//   * That TM-MPL-007 is mitigated. The model shows that an alias or an unparseable `kms-arn` is
//     rejected before any KMS call (R1, R2) and that, as shipped, the KeyId's region is the configured
//     one (R3). It does not show that the record is authentic: whoever can write the DynamoDB item
//     chooses the partition, service, account, resource type and resource of the KeyId, and under the
//     fix also the region of a non-MRK key. The spec accepts that trust for Discovery
//     (branch-key-store.md :188 and :206: "The Keystore MAY use the KMS Key ARNs already persisted"). KMS-side
//     behaviour (whether a rewritten ARN exists, `NotFoundException`, grant tokens) is not modelled.
//   * That the proposed fix is correct for the shipped code, or that it is the right fix. The fix model
//     is BUG-04 option 1 as written (A_FIX_MODEL). The spec conflict is open (finding F1).
//   * That the value returned here is the `KeyId` of the KMS call (H_CALLER). Not used by any theorem.
//   * The pinned arms (T03), `is_arn_compatible`, `aws_kms_mrk_match_for_decrypt`, `validate_kms_key_arn`
//     and the configuration builders other than the one line about `region` (H_REGION_CFG).
//   * Panic freedom of the shipped functions, error text, `Error` fields other than the kind, allocation.
//   * Byte versus char splitting (A_STR), non-ASCII input, and any ARN longer than memory.
//   * An executable model. All definitions here are spec functions. Verus has no spec for `splitn`,
//     `split_once` or `format!`, and a loop-level exec model of them was not written.
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD 0756760)
// =============================================================================
//   mpl/src/key_store/kms_ops.rs   (md5 8bb751276211f901a3336b3d77a892f3)
//     :88-114   resolve_key_store_arn: Discovery arm :96-99, MrDiscovery arm :100-103, pinned arms
//               :94-95 and :105-113 (T03)
//     :118-129  reject_alias_arn: parse :119-121, alias test :122-127
//     :132-139  malformed_record: `Error::new(Kind::InvalidMaterials, ..)`
//     :144-157  rewrite_arn_region: parse :145-147, format! :148-156
//     :179-183  decrypt_branch_key: resolve :179, `key_id(&resolved_key_id)` :183 (H_CALLER)
//   mpl/src/key_store/kms_config.rs   (md5 16d9451655ef90410522006626c894bc)
//     :31-58    parse_arn: `splitn(6, ':')` :32, count and "arn" test :33-40, `split_once('/')` :41-49,
//               ArnParts :50-57
//   mpl/src/key_store/config.rs   (md5 2f85f61e530702f23c66590810eef6d1)
//     :275-291  MrDiscovery { region }, `region()` :288;  :327-331 MrDiscoveryBuilder::build
//               (`required(self.region, "region")`, builder.rs :7: presence only)
//   mpl/src/aws_kms/mrk_match.rs   (md5 84892b5d453015a363e4203f9ad1bb43)
//     :52-58    is_multi_region_arn (private; copied as `is_mr_arn`)
//   mpl/src/key_store/branch_key_store.rs :641-668 version_key (resolve :663). Not modelled beyond the call.
//   spec/framework/branch-key-store.md :168 and :204 ("Any MRK ARN discovered will be changed to this
//     region before use", no MUST), :669 (MRDiscovery `KeyId` MUST be the record ARN "with the region
//     replaced by the configured region", no MRK qualifier), :659-661 (the `kms-arn` MUST NOT be an alias)
//   spec/framework/aws-kms/aws-kms-key-arn.md :41 (service MUST be kms), :72-83 (identifying an MRK ARN)
//   docs/mpl-bug-reports/BUG-04-mrdiscovery-rewrites-non-mrk-arn-region.md (code, reproducer, Dafny reading)
//   Tests (not proofs, not run for this step): the in-crate reproducer in
//     .agents/tasks/bug-recheck/reproducers/zz_bugrepro_04_mrdiscovery_non_mrk.rs (BUG-04, "Reproduction").
//     The integration test named in BUG-04 covers the MRK case only.
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code)
// =============================================================================
//   model                         shipped
//   ----------------------------  -----------------------------------------------------------
//   Str = Seq<char>               String / &str (A_STR)
//   Cfg                           KmsConfiguration (config.rs:12); wrapper structs collapsed to their
//                                 String; Discovery's payload dropped; MrDiscovery(r) is `region()`
//   Resolved::Key(k) / Fail       `Ok(String)` / `Err(Error)`; the error text and fields are dropped,
//                                 the kind is kept (all errors on these arms are InvalidMaterials)
//   split_colon, join_colon       str::split(':'), the pieces joined with ':' (copied from T03)
//   splitn_colon(6, s)            `arn.splitn(6, ':').collect()` (kms_config.rs:32); A_STD
//   first_slash                   `split_once('/')` (kms_config.rs:41), index of the first '/' (copied)
//   parse_arn                     parse_arn, Ok-ness and the six parts; `None` is `Err`
//   format_arn                    the `format!("arn:{}:{}:{}:{}:{}/{}", ..)` of rewrite_arn_region
//                                 (kms_ops.rs:148-156); `cons` is `x ++ ":" ++ y`
//   with_region                   the same parts with `new_region` in the third slot
//   reject_alias_ok               reject_alias_arn returns Ok(())
//   rewrite_arn_region            rewrite_arn_region (None is the parse error)
//   resolve                       resolve_key_store_arn, Discovery arm (:96-99) and MrDiscovery arm
//                                 (:100-103); `branch_key_id` is only used in error values and is dropped
//   is_mr_arn                     is_multi_region_arn (mrk_match.rs:52-58), copied from T03
//   mrk_by_spec_text              aws-kms-key-arn.md :41, :72-83; the yardstick of the property, not code
//   resolve_fixed                 NOT CODE. BUG-04 "Fix options" 1 as a model: after the alias check,
//                                 rewrite only when `is_mr_arn(record)`, otherwise return the record
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED
// =============================================================================
// Spec-derived: "the kms-arn MUST NOT be an alias" (branch-key-store.md :659-661); "Discovery ... KeyId
// MUST be the kms-arn" and the MRDiscovery sentence at :669; "Any MRK ARN discovered will be changed to
// this region" (:168, :204, no MUST); the MRK definition (aws-kms-key-arn.md :72-83). R1 reads the
// Discovery sentence back from the model. `mrk_by_spec_text` is a reading of the MRK definition.
// Code-derived: that a malformed ARN is an error before the rewrite, that the accept set is "parses and
// resource type is not alias" and nothing more (no service test), that the region is the third piece,
// that the resource keeps its first '/' and any later ':' or '/', the error kind, and everything about
// `splitn`. The spec does not say how an ARN is split.
// THE PROPERTY IS FROM NON-NORMATIVE TEXT AND FROM DAFNY PARITY. The only normative sentence about the
// MRDiscovery KeyId (:669) has no MRK qualifier, and the shipped arm follows it literally. The YAML
// property "rewritten only for MRKs" comes from :168/:204 (no MUST) and from the Dafny `replaceRegion`
// (read by BUG-04, not re-read here). So F1 is a divergence between two spec sentences, and between the
// shipped code and the other runtime, before it is a code defect. BUG-04 rates it Low and fail-closed.
//
// =============================================================================
// 4. HYPOTHESES, ASSUMPTIONS AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and the items below
//    ASSUMED       taken as a premise or a definition; not proved here (A_*)
//    CODE READING  a claim about shipped code or a crate that Verus does not see (H_*); checked by a
//                  human reading the source at the lines named
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier..]`
//  attribute is written in this file, and there is no uninterpreted spec function. The vstd axioms for
//  `Seq` are the only library facts used (A_VSTD). The one string-literal helper, `reveal_strlit`, is
//  vstd's and is used only in `lemma_witness_strings`.
//
//  H_MODEL_MATCH (CODE READING). The model functions have the same inputs, order of checks and string
//    assembly as the lines in section 2: alias check before the rewrite, parse failure and alias both an
//    error, the rewrite builds `arn:` + partition + service + region + account + `type/resource` from
//    the parsed parts, `with_source` and `about` leave the error kind unchanged (generated.rs:675-680,
//    :922-926). Checked by reading; not machine-checked.
//  H_REGION_CFG (CODE READING). The configured MrDiscovery region has no ':'. `MrDiscoveryBuilder::build`
//    checks only that a region was set (config.rs:327-331, builder.rs:7); it does not check the content.
//    R3, R4, R10 and the fix witnesses take `colon_free(r)` as a premise. R1, R2, R7, R8, R9 and R11 do
//    not. With a region that has ':' the rewritten string would split into different pieces (the proof
//    of R3 uses `lemma_parse_format`, which needs the premise). A configured region is not
//    attacker-controlled data; this is a premise of the proof, not a finding.
//  H_CALLER (CODE READING, as in T03). `decrypt_branch_key` passes only the value returned by
//    `resolve_key_store_arn` as the KMS `key_id` (:179-183), and `version_key` passes it on (:663).
//    Not machine-checked and not used by any theorem here.
//  A_STR (ASSUMED, as in T03). `String` is `Seq<char>`. Rust splits `str` at bytes; the model splits at
//    chars. They agree because ':' and '/' are ASCII and never occur inside a multi-byte UTF-8 sequence.
//    `starts_with` on bytes agrees with the char-prefix test for the same reason.
//  A_STD (ASSUMED). `splitn_colon`, `split_colon` and `first_slash` model Rust's `splitn(6, ':')`,
//    `split(':')` and `split_once('/')`, and `format_arn` models the `format!`. vstd has no spec for them.
//    The definitions follow the documented semantics (the first n-1 cuts, the rest as the last piece, the
//    first '/' only). Lemmas check the models against each other (`lemma_splitn_eq_split`,
//    `lemma_splitn_join`) but not against the Rust standard library.
//  A_MRK_SPEC (ASSUMED). `mrk_by_spec_text` is the yardstick for "is an MRK ARN": service kms, resource
//    type key, id starting "mrk-". It reads aws-kms-key-arn.md :41 and :72-83. The spec also requires a
//    non-empty partition, region and account, and a resource type of alias or key; the model does not, so
//    it classifies some ARNs the spec calls invalid. That is harmless for R6 and R7, which only use the
//    negation on ARNs the code accepts, and the concrete counterexample is a valid single-Region ARN.
//  A_FIX_MODEL (ASSUMED). `resolve_fixed` is BUG-04 option 1 as written: after the alias check, rewrite
//    only if `is_multi_region_arn` holds, else return the record ARN. The real fix is not written. The
//    predicate could instead be a new one over `ArnParts`; R12 and the observation O2 say how the two
//    would differ.
//  A_ALLOC (ASSUMED). Allocation succeeds; `format!` and `to_string` do not panic.
//  A_VSTD (ASSUMED). Verus, Z3 and the vstd `Seq` axioms.
//
// =============================================================================
// 5. FINDINGS AND OBSERVATIONS
// =============================================================================
//  F1 (finding, EXPECTED_FAIL, BUG-04, open, spec conflict). The MrDiscovery arm rewrites the region of
//    every ARN it accepts (R3), including a single-Region key. `lemma_nonmrk_unchanged_iff_same_region`
//    gives the exact set: a non-MRK record comes back unchanged only when its region already is the
//    configured one. Counterexample as stated at the top. No MRK test is on the path (see "NO MRK PREFIX TEST
//    ON THIS ARM" in the header). The shipped arm agrees with the normative sentence at :669 and disagrees with
//    :168/:204 and with the Dafny behaviour BUG-04 describes. Severity: BUG-04 rates it Low (fails
//    closed at KMS; the KMS-side failure was not run). Not re-rated here.
//  O1 (observation). An unparseable ARN never reaches the rewrite: `reject_alias_arn` errors first (R2).
//    So the EXPECTED_FAIL claim is about parseable ARNs only. BUG-04 reads the Dafny `replaceRegion` as
//    returning an unparseable ARN unchanged; the shipped arm returns an error instead. Not examined
//    further.
//  O2 (observation, proved). The fix gate `is_multi_region_arn` splits with `split(':')` and needs six
//    pieces; `parse_arn` uses `splitn(6, ':')` and lets the sixth piece hold colons. So on a record whose
//    resource id holds ':' the gate is false even when the spec text says MRK (R12,
//    `lemma_fix_gate_misses_colon_in_resource`: `...:key/mrk-1234abcd-...:x`). The shipped arm rewrites
//    it, the fix model leaves it unchanged. A KMS key id of that shape was not examined; if none exists
//    the difference has no effect.
//  O3 (observation, proved). Neither arm tests the service. An ARN with service `s3` is accepted by
//    Discovery and rewritten by MrDiscovery (`lemma_service_not_checked_witness`). The spec sentence at
//    :659-661 is about aliases only. KMS would reject such a KeyId later; not modelled.
//  O4 (observation). `MrDiscoveryBuilder::build` does not check the region content (H_REGION_CFG). An
//    empty region is accepted and R3 holds for it in the model (the result has an empty region piece).
//  O5 (observation, consequence of the fix model, proved). With the fix, a non-MRK record keeps its own
//    region in the KeyId (R7), where the shipped arm forces the configured region (R3). Both values come
//    from the record. This is the Dafny behaviour per BUG-04, not a new exposure; it is recorded because
//    R3's "the KeyId region is the configured one" is true of the shipped arm only.
//  Target-text check (YAML VR-2026-T17): "Discovery: Ok(record ARN) exactly when parse_arn succeeds and
//    resource_type is not alias" is R1. "MrDiscovery ... region rewritten only for MRK ARNs" is R6 (fails)
//    and R7 (holds for the fix). The YAML's `parse_format_round_trip` is `lemma_parse_format` (premises:
//    the first four fields hold no ':' and the resource type holds no '/'; the resource is free), and its
//    converse is `lemma_parse_parts`. The YAML's `is_mrk(rec) ==> parse(k) == parse(rec).with_region(m)` is
//    R4.
//
// =============================================================================
// 6. OVERLAP
// =============================================================================
// Mahnush_Verus (tip 8d6381e): no overlap. No `verus!` in mpl/ there, no proof of these functions, no
// T17 or BUG-04 text. Record: .agents/tasks/mpl-batch3-proofs/t17-duplicate-check.md. This repository:
// T03 (pinned arms; this file copies its split model and `is_mr_arn`), T11 (MRK match, not started
// here; `is_mr_arn` is the predicate T03 modelled, only its relation to the spec text on parsed ARNs is
// proved here), T01 (the authenticated encryption context, which carries `kms-arn`; not restated).
//
// =============================================================================
// 7. MODEL-vs-CODE GAP
// =============================================================================
// The shipped functions are not inside `verus!`, are not compiled here, and nothing detects a later edit
// to kms_ops.rs, kms_config.rs, config.rs or mrk_match.rs. To close the gap one needs the four functions
// inside `verus!` (or `cargo verus` on the crate), vstd specs for `str::splitn`, `split_once`,
// `starts_with`, `format!` and `String::to_string`, a spec for `Error` and `Kind`, and the fix written
// in mpl/ (not allowed in this task). Until then the evidence is: audited model + machine-checked logic +
// one run of the shipped function in the BUG-04 recheck.
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Types and constants (Str, Cfg, Resolved copied from T03 and extended)
// ============================================================

pub type Str = Seq<char>;

/// Spec-level view of `KmsConfiguration` (config.rs:12), copied from T03. The payload of
/// `Discovery` is dropped (never read by the function). `MrDiscovery(region)` carries the
/// configured region string, which is `MrDiscovery::region()` (config.rs:288).
pub enum Cfg {
    KmsKeyArn(Str),
    KmsMrKeyArn(Str),
    Discovery,
    MrDiscovery(Str),
}

/// Model of `crate::error::Kind`, restricted to the one kind the Discovery and MrDiscovery arms
/// produce. Every `Err` on these two arms is `malformed_record(..)` (kms_ops.rs:119-121, :123-126, :132-139),
/// which builds `Error::new(Kind::InvalidMaterials, ..)`. `with_source(e)` only sets the source
/// (generated.rs:922-926, `Error::with_source`), so the kind stays `InvalidMaterials` even though `parse_arn` itself fails
/// with `Kind::Validation` (kms_config.rs:33-40).
#[derive(PartialEq, Eq)]
pub enum Kind {
    InvalidMaterials,
}

/// The outcome of `resolve_key_store_arn`, as a spec value. T03 had `NotPinned` for the two arms
/// this file models. Here the two pinned arms are the ones left out, so the variant is renamed.
pub enum Resolved {
    /// The two pinned arms (`KmsKeyArn`, `KmsMrKeyArn`), kms_ops.rs:93-95 and :105-113. Modelled
    /// by T03, not here.
    PinnedNotModelled,
    /// `Ok(key_id)`.
    Key(Str),
    /// `Err(e)` with `e.kind`.
    Fail(Kind),
}

/// The six parts of `ArnParts` (kms_config.rs:10-23), as strings.
pub struct Parts {
    pub partition: Str,
    pub service: Str,
    pub region: Str,
    pub account: Str,
    pub rt: Str,
    pub res: Str,
}

pub open spec fn s_arn() -> Str { seq!['a', 'r', 'n'] }
pub open spec fn s_kms() -> Str { seq!['k', 'm', 's'] }
/// `segments[5].starts_with("key/mrk-")` (mrk_match.rs:57)
pub open spec fn s_key_mrk() -> Str { seq!['k', 'e', 'y', '/', 'm', 'r', 'k', '-'] }
pub open spec fn s_key() -> Str { seq!['k', 'e', 'y'] }
/// The prefix of an MRK key id (aws-kms-key-arn.md :59, :80).
pub open spec fn s_mrk() -> Str { seq!['m', 'r', 'k', '-'] }
/// `parts.resource_type == "alias"` (kms_ops.rs:122).
pub open spec fn s_alias_rt() -> Str { seq!['a', 'l', 'i', 'a', 's'] }

// ============================================================
// SECTION 2: Model of str::split(':') and the first-slash search (copied from T03)
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

pub open spec fn slash_free(x: Str) -> bool {
    forall|j: int| 0 <= j < x.len() ==> #[trigger] x[j] != '/'
}

// ============================================================
// SECTION 3: Model of str::splitn(6, ':'), parse_arn and the ARN formatting (new in T17)
// ============================================================

/// `s.splitn(n, ':').collect::<Vec<&str>>()` for n >= 1, defined char by char in the same shape as
/// `split_colon`: each ':' ends a piece and uses up one of the n - 1 cuts. When one piece is left
/// (n == 1) the rest of the string, colons included, is the last piece. The model is only used with
/// n == 6 (kms_config.rs:32). `splitn(0)` yields nothing in Rust; the model is not used there.
pub open spec fn splitn_colon(n: nat, s: Str) -> Seq<Str>
    decreases s.len(),
{
    if n <= 1 {
        seq![s]
    } else if s.len() == 0 {
        seq![Seq::<char>::empty()]
    } else if s[0] == ':' {
        seq![Seq::<char>::empty()].add(splitn_colon((n - 1) as nat, s.skip(1)))
    } else {
        let rest = splitn_colon(n, s.skip(1));
        seq![seq![s[0]].add(rest[0])].add(rest.skip(1))
    }
}

/// kms_config.rs:31-58 `parse_arn`, Ok-ness and the Ok value only (the error message is dropped).
/// `None` stands for `Err(Kind::Validation)`: not six pieces, a first piece other than "arn", or
/// no '/' in the sixth piece (:41-49).
pub open spec fn parse_arn(s: Str) -> Option<Parts> {
    let seg = splitn_colon(6, s);  // :32
    if seg.len() != 6 || seg[0] != s_arn() {  // :33
        None
    } else {
        match first_slash(seg[5]) {  // :41 `split_once('/')`
            None => None,
            Some(i) => Some(
                Parts {
                    partition: seg[1],  // :51
                    service: seg[2],  // :52
                    region: seg[3],  // :53
                    account: seg[4],  // :54
                    rt: seg[5].take(i),  // :55
                    res: seg[5].skip(i + 1),  // :56
                },
            ),
        }
    }
}

/// `x ++ ":" ++ y`
pub open spec fn cons(x: Str, y: Str) -> Str {
    x.add(seq![':']).add(y)
}

/// The sixth piece of the formatted ARN: `{resource_type}/{resource}`.
pub open spec fn rest_of(p: Parts) -> Str {
    p.rt.add(seq!['/']).add(p.res)
}

/// kms_ops.rs:148-156, the `format!("arn:{}:{}:{}:{}:{}/{}", partition, service, new_region,
/// account_id, resource_type, resource)`. `cons` is `x ++ ":" ++ y`, right-nested, which is the
/// same string as the flat concatenation.
pub open spec fn format_arn(p: Parts) -> Str {
    cons(s_arn(), cons(p.partition, cons(p.service, cons(p.region, cons(p.account, rest_of(p))))))
}

pub open spec fn with_region(p: Parts, r: Str) -> Parts {
    Parts {
        partition: p.partition,
        service: p.service,
        region: r,
        account: p.account,
        rt: p.rt,
        res: p.res,
    }
}

// ============================================================
// SECTION 4: Model of the Discovery and MrDiscovery arms (kms_ops.rs:96-103, :118, :144)
// ============================================================

/// kms_ops.rs:118-131 `reject_alias_arn` returns `Ok(())`: the ARN parses and its resource type
/// is not "alias". A parse failure and an alias are both `Err(InvalidMaterials)` (:119-121, :123-128).
pub open spec fn reject_alias_ok(arn: Str) -> bool {
    match parse_arn(arn) {
        Some(p) => p.rt != s_alias_rt(),
        None => false,
    }
}

/// kms_ops.rs:144-158 `rewrite_arn_region`: parse, then format with the new region. A parse failure
/// is `Err(InvalidMaterials)` (:145-147); the model returns `None` for it.
pub open spec fn rewrite_arn_region(arn: Str, new_region: Str) -> Option<Str> {
    match parse_arn(arn) {
        Some(p) => Some(format_arn(with_region(p, new_region))),
        None => None,
    }
}

/// kms_ops.rs:88-114 `resolve_key_store_arn`, Discovery and MrDiscovery arms as shipped. The pinned
/// arms are T03's.
pub open spec fn resolve(c: Cfg, rec: Str) -> Resolved {
    match c {
        Cfg::KmsKeyArn(_) => Resolved::PinnedNotModelled,
        Cfg::KmsMrKeyArn(_) => Resolved::PinnedNotModelled,
        Cfg::Discovery => {
            if reject_alias_ok(rec) {
                Resolved::Key(rec)  // :98 `Ok(record_kms_arn.to_string())`
            } else {
                Resolved::Fail(Kind::InvalidMaterials)  // :97 `?`
            }
        },
        Cfg::MrDiscovery(r) => {
            if !reject_alias_ok(rec) {
                Resolved::Fail(Kind::InvalidMaterials)  // :101 `?`
            } else {
                match rewrite_arn_region(rec, r) {  // :102 `return rewrite_arn_region(..)`
                    Some(k) => Resolved::Key(k),
                    None => Resolved::Fail(Kind::InvalidMaterials),
                }
            }
        },
    }
}

/// mrk_match.rs:52-58 `is_multi_region_arn`, copied from T03 (`is_mr_arn`).
pub open spec fn is_mr_arn(s: Str) -> bool {
    let seg = split_colon(s);
    &&& seg.len() == 6
    &&& seg[0] == s_arn()
    &&& seg[2] == s_kms()
    &&& s_key_mrk().is_prefix_of(seg[5])
}

// ============================================================
// SECTION 4b: The MRK classification, and the model of the proposed fix (BUG-04 option 1)
// ============================================================

/// The spec text's classification of a parsed ARN as a multi-Region key ARN
/// (aws-kms-key-arn.md :72-83: "If resource type is key and resource ID starts with mrk-" the ARN is
/// an MRK ARN), together with "The service MUST be kms" (:41). Used for the target property "the
/// region is rewritten only for MRKs". Not the code's test: the code has none on this path (BUG-04).
pub open spec fn mrk_by_spec_text(p: Parts) -> bool {
    &&& p.service == s_kms()
    &&& p.rt == s_key()
    &&& s_mrk().is_prefix_of(p.res)
}

/// The proposed fix, BUG-04 "Fix options" 1, at model level: after the alias check, rewrite only
/// when the existing predicate `is_multi_region_arn` (mrk_match.rs:52-58, copied below as `is_mr_arn`)
/// holds; otherwise return the record ARN verbatim. This is a MODEL of the proposal. No such code
/// exists in mpl/.
pub open spec fn resolve_fixed(c: Cfg, rec: Str) -> Resolved {
    match c {
        Cfg::MrDiscovery(r) => {
            if !reject_alias_ok(rec) {
                Resolved::Fail(Kind::InvalidMaterials)
            } else if !is_mr_arn(rec) {
                Resolved::Key(rec)
            } else {
                match rewrite_arn_region(rec, r) {
                    Some(k) => Resolved::Key(k),
                    None => Resolved::Fail(Kind::InvalidMaterials),
                }
            }
        },
        _ => resolve(c, rec),
    }
}

// ============================================================
// SECTION 5: Lemmas about the split model (copied from T03)
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
// SECTION 6: New lemmas (slash search, splitn, parse and format, the MRK predicate)
// ============================================================

proof fn lemma_colon_free_add(x: Str, y: Str)
    requires
        colon_free(x),
        colon_free(y),
    ensures
        colon_free(x.add(y)),
{
    assert forall|j: int| 0 <= j < x.add(y).len() implies #[trigger] x.add(y)[j] != ':' by {
        if j < x.len() {
            assert(x.add(y)[j] == x[j]);
        } else {
            assert(x.add(y)[j] == y[j - x.len()]);
        }
    }
}

/// "arn" has no ':'.
proof fn lemma_colon_free_arn()
    ensures
        colon_free(s_arn()),
{
}

/// `first_slash` finds the first '/': everything before it is slash-free, and `None` means no '/'.
proof fn lemma_first_slash_some(s: Str)
    ensures
        match first_slash(s) {
            Some(i) => 0 <= i < s.len() && s[i] == '/' && slash_free(s.take(i)),
            None => slash_free(s),
        },
    decreases s.len(),
{
    if s.len() > 0 && s[0] != '/' {
        let t = s.skip(1);
        lemma_first_slash_some(t);
        match first_slash(t) {
            Some(j) => {
                assert(t[j] == s[j + 1]);
                assert forall|k: int| 0 <= k < s.take(j + 1).len() implies #[trigger] s.take(
                    j + 1,
                )[k] != '/' by {
                    if k > 0 {
                        assert(s.take(j + 1)[k] == t.take(j)[k - 1]);
                    }
                }
            },
            None => {
                assert forall|k: int| 0 <= k < s.len() implies #[trigger] s[k] != '/' by {
                    if k > 0 {
                        assert(s[k] == t[k - 1]);
                    }
                }
            },
        }
    }
}

/// With a slash-free `x`, the first '/' of `x ++ "/" ++ y` is right after `x`.
proof fn lemma_first_slash_append(x: Str, y: Str)
    requires
        slash_free(x),
    ensures
        first_slash(x.add(seq!['/']).add(y)) == Some(x.len() as int),
    decreases x.len(),
{
    let whole = x.add(seq!['/']).add(y);
    if x.len() == 0 {
        assert(whole[0] == '/');
    } else {
        let xs = x.skip(1);
        assert(slash_free(xs)) by {
            assert forall|j: int| 0 <= j < xs.len() implies #[trigger] xs[j] != '/' by {
                assert(xs[j] == x[j + 1]);
            }
        }
        assert(whole[0] == x[0]);
        assert(x[0] != '/');
        assert(whole.skip(1) =~= xs.add(seq!['/']).add(y));
        lemma_first_slash_append(xs, y);
    }
}

proof fn lemma_splitn_len(n: nat, s: Str)
    requires
        n >= 1,
    ensures
        1 <= splitn_colon(n, s).len() <= n,
    decreases s.len(),
{
    if n >= 2 && s.len() > 0 {
        let t = s.skip(1);
        if s[0] == ':' {
            lemma_splitn_len((n - 1) as nat, t);
        } else {
            lemma_splitn_len(n, t);
        }
    }
}

/// The first n - 1 pieces of `splitn(n, ':')` hold no ':' (the last one may).
proof fn lemma_splitn_prefix_colon_free(n: nat, s: Str)
    requires
        n >= 1,
    ensures
        forall|i: int|
            0 <= i < splitn_colon(n, s).len() && i + 1 < n ==> colon_free(
                #[trigger] splitn_colon(n, s)[i],
            ),
    decreases s.len(),
{
    if n >= 2 && s.len() > 0 {
        let t = s.skip(1);
        let res = splitn_colon(n, s);
        if s[0] == ':' {
            lemma_splitn_prefix_colon_free((n - 1) as nat, t);
            lemma_splitn_len((n - 1) as nat, t);
            let rest = splitn_colon((n - 1) as nat, t);
            assert forall|i: int| 0 <= i < res.len() && i + 1 < n implies colon_free(
                #[trigger] res[i],
            ) by {
                if i >= 1 {
                    assert(res[i] == rest[i - 1]);
                } else {
                    assert(res[0] =~= Seq::<char>::empty());
                }
            }
        } else {
            lemma_splitn_prefix_colon_free(n, t);
            lemma_splitn_len(n, t);
            let rest = splitn_colon(n, t);
            assert forall|i: int| 0 <= i < res.len() && i + 1 < n implies colon_free(
                #[trigger] res[i],
            ) by {
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

/// The pieces of `splitn(n, ':')`, joined with ':', give the string back.
proof fn lemma_splitn_join(n: nat, s: Str)
    requires
        n >= 1,
    ensures
        join_colon(splitn_colon(n, s)) == s,
    decreases s.len(),
{
    if n >= 2 && s.len() > 0 {
        let t = s.skip(1);
        let res = splitn_colon(n, s);
        if s[0] == ':' {
            lemma_splitn_join((n - 1) as nat, t);
            lemma_splitn_len((n - 1) as nat, t);
            let rest = splitn_colon((n - 1) as nat, t);
            assert(res.len() >= 2);
            assert(res.skip(1) =~= rest);
            assert(res[0] =~= Seq::<char>::empty());
            assert(join_colon(res) =~= seq![':'].add(join_colon(rest)));
            assert(s =~= seq![':'].add(t));
        } else {
            lemma_splitn_join(n, t);
            lemma_splitn_len(n, t);
            let rest = splitn_colon(n, t);
            if rest.len() == 1 {
                assert(res =~= seq![seq![s[0]].add(rest[0])]);
                assert(join_colon(rest) == rest[0]);
                assert(s =~= seq![s[0]].add(t));
            } else {
                assert(res.len() >= 2);
                assert(res[0] == seq![s[0]].add(rest[0]));
                assert(res.skip(1) =~= rest.skip(1));
                assert(join_colon(rest) =~= rest[0].add(seq![':']).add(join_colon(rest.skip(1))));
                assert(join_colon(res) =~= seq![s[0]].add(join_colon(rest)));
                assert(s =~= seq![s[0]].add(t));
            }
        }
    }
}

/// splitn(n, x ++ ":" ++ y) == [x] ++ splitn(n - 1, y)   for a colon-free x and n >= 2.
proof fn lemma_splitn_at_colon(n: nat, x: Str, y: Str)
    requires
        n >= 2,
        colon_free(x),
    ensures
        splitn_colon(n, cons(x, y)) == seq![x].add(splitn_colon((n - 1) as nat, y)),
    decreases x.len(),
{
    let whole = cons(x, y);
    if x.len() == 0 {
        assert(whole =~= seq![':'].add(y));
        assert(whole.skip(1) =~= y);
        assert(splitn_colon(n, whole) =~= seq![Seq::<char>::empty()].add(
            splitn_colon((n - 1) as nat, y),
        ));
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
        assert(whole.skip(1) =~= cons(xs, y));
        lemma_splitn_at_colon(n, xs, y);
        let rest = splitn_colon(n, whole.skip(1));
        assert(rest == seq![xs].add(splitn_colon((n - 1) as nat, y)));
        assert(rest[0] == xs);
        assert(rest.skip(1) =~= splitn_colon((n - 1) as nat, y));
        assert(splitn_colon(n, whole) =~= seq![seq![x[0]].add(xs)].add(
            splitn_colon((n - 1) as nat, y),
        ));
        assert(x =~= seq![x[0]].add(xs));
    }
}

/// When `split(':')` gives at most n pieces, `splitn(n, ':')` gives the same pieces.
proof fn lemma_splitn_eq_split(n: nat, s: Str)
    requires
        n >= 1,
        split_colon(s).len() <= n,
    ensures
        splitn_colon(n, s) == split_colon(s),
    decreases s.len(),
{
    lemma_split_nonempty(s);
    if n == 1 {
        lemma_join_split(s);
        assert(split_colon(s).len() == 1);
        assert(join_colon(split_colon(s)) == split_colon(s)[0]);
        assert(split_colon(s) =~= seq![s]);
    } else if s.len() > 0 {
        let t = s.skip(1);
        lemma_split_nonempty(t);
        if s[0] == ':' {
            assert(split_colon(s) =~= seq![Seq::<char>::empty()].add(split_colon(t)));
            lemma_splitn_eq_split((n - 1) as nat, t);
        } else {
            let rest = split_colon(t);
            assert(split_colon(s) =~= seq![seq![s[0]].add(rest[0])].add(rest.skip(1)));
            assert(split_colon(s).len() == rest.len());
            lemma_splitn_eq_split(n, t);
        }
    }
}

/// Six pieces joined with ':' are the right-nested `cons` chain.
proof fn lemma_join_six(seg: Seq<Str>)
    requires
        seg.len() == 6,
    ensures
        join_colon(seg) == cons(
            seg[0],
            cons(seg[1], cons(seg[2], cons(seg[3], cons(seg[4], seg[5])))),
        ),
{
    let s1 = seg.skip(1);
    let s2 = s1.skip(1);
    let s3 = s2.skip(1);
    let s4 = s3.skip(1);
    let s5 = s4.skip(1);
    assert(s5.len() == 1 && s5[0] == seg[5]);
    assert(s4[0] == seg[4]);
    assert(s3[0] == seg[3]);
    assert(s2[0] == seg[2]);
    assert(s1[0] == seg[1]);
    assert(join_colon(s5) == seg[5]);
    assert(join_colon(s4) == cons(seg[4], seg[5]));
    assert(join_colon(s3) == cons(seg[3], cons(seg[4], seg[5])));
    assert(join_colon(s2) == cons(seg[2], cons(seg[3], cons(seg[4], seg[5]))));
    assert(join_colon(s1) == cons(seg[1], cons(seg[2], cons(seg[3], cons(seg[4], seg[5])))));
}

/// What `parse_arn(s) == Some(p)` says about the pieces: the six pieces of `splitn(6, ':')`, the
/// colon-free first five, the slash-free resource type, and `format_arn(p) == s` (so the
/// reformatting in `rewrite_arn_region` with the same region is the identity).
proof fn lemma_parse_parts(s: Str, p: Parts)
    requires
        parse_arn(s) == Some(p),
    ensures
        splitn_colon(6, s).len() == 6,
        splitn_colon(6, s)[0] == s_arn(),
        splitn_colon(6, s)[1] == p.partition,
        splitn_colon(6, s)[2] == p.service,
        splitn_colon(6, s)[3] == p.region,
        splitn_colon(6, s)[4] == p.account,
        splitn_colon(6, s)[5] == rest_of(p),
        colon_free(p.partition),
        colon_free(p.service),
        colon_free(p.region),
        colon_free(p.account),
        slash_free(p.rt),
        format_arn(p) == s,
{
    let seg = splitn_colon(6, s);
    lemma_splitn_len(6, s);
    lemma_splitn_prefix_colon_free(6, s);
    lemma_splitn_join(6, s);
    let q = seg[5];
    assert(first_slash(q) is Some);
    let i = first_slash(q)->Some_0;
    lemma_first_slash_some(q);
    assert(p.rt == q.take(i));
    assert(p.res == q.skip(i + 1));
    assert(q[i] == '/');
    assert(rest_of(p) =~= q) by {
        assert(q =~= q.take(i).add(seq![q[i]]).add(q.skip(i + 1)));
    }
    lemma_join_six(seg);
    assert(format_arn(p) == join_colon(seg));
}

/// The forward direction: formatting parts and parsing them back gives the parts, provided the
/// first four fields have no ':' and the resource type has no '/'. The resource may hold anything.
proof fn lemma_parse_format(p: Parts)
    requires
        colon_free(p.partition),
        colon_free(p.service),
        colon_free(p.region),
        colon_free(p.account),
        slash_free(p.rt),
    ensures
        parse_arn(format_arn(p)) == Some(p),
{
    lemma_colon_free_arn();
    let r5 = rest_of(p);
    let t4 = cons(p.account, r5);
    let t3 = cons(p.region, t4);
    let t2 = cons(p.service, t3);
    let t1 = cons(p.partition, t2);
    let whole = format_arn(p);
    assert(whole == cons(s_arn(), t1));
    lemma_splitn_at_colon(6, s_arn(), t1);
    lemma_splitn_at_colon(5, p.partition, t2);
    lemma_splitn_at_colon(4, p.service, t3);
    lemma_splitn_at_colon(3, p.region, t4);
    lemma_splitn_at_colon(2, p.account, r5);
    assert(splitn_colon(1, r5) =~= seq![r5]);
    let seg = splitn_colon(6, whole);
    assert(seg =~= seq![s_arn(), p.partition, p.service, p.region, p.account, r5]);
    lemma_first_slash_append(p.rt, p.res);
    assert(first_slash(r5) == Some(p.rt.len() as int));
    assert(r5.take(p.rt.len() as int) =~= p.rt);
    assert(r5.skip(p.rt.len() as int + 1) =~= p.res);
}

/// A rewrite with a colon-free region gives an ARN that parses to the same parts with only the
/// region replaced. This is the "region index" fact: the replaced piece is piece 3, and every
/// other piece is kept.
proof fn lemma_rewrite_parses(rec: Str, r: Str, p: Parts)
    requires
        parse_arn(rec) == Some(p),
        colon_free(r),
    ensures
        rewrite_arn_region(rec, r) == Some(format_arn(with_region(p, r))),
        parse_arn(format_arn(with_region(p, r))) == Some(with_region(p, r)),
{
    lemma_parse_parts(rec, p);
    lemma_parse_format(with_region(p, r));
}

// ------------------------------------------------------------
// The MRK predicate of mrk_match.rs against the spec text
// ------------------------------------------------------------

/// A piece starting with "key/mrk-" has its first '/' at index 3, a resource type "key", and a
/// resource id starting with "mrk-". Body of the first three facts copied from T03
/// `lemma_first_slash_key_mrk`.
proof fn lemma_key_mrk_piece(q: Str)
    requires
        s_key_mrk().is_prefix_of(q),
    ensures
        first_slash(q) == Some(3int),
        q.take(3) == s_key(),
        s_mrk().is_prefix_of(q.skip(4)),
{
    reveal_with_fuel(first_slash, 5);
    assert(q.subrange(0, 8) =~= s_key_mrk());
    assert(q[0] == 'k' && q[1] == 'e' && q[2] == 'y' && q[3] == '/');
    assert(q.skip(1)[0] == q[1]);
    assert(q.skip(1).skip(1)[0] == q[2]);
    assert(q.skip(1).skip(1).skip(1)[0] == q[3]);
    assert(q.skip(1).skip(1).skip(1).skip(1)[0] == q.skip(1).skip(1).skip(1)[1]);
    assert(q.take(3) =~= s_key());
    assert(q.skip(4).subrange(0, 4) =~= s_mrk());
}

/// All six pieces of the formatted string hold no ':' exactly when the resource piece holds none.
/// `split_colon` then agrees with `splitn(6)`.
proof fn lemma_split_eq_splitn_when_rest_colon_free(s: Str, p: Parts)
    requires
        parse_arn(s) == Some(p),
        colon_free(rest_of(p)),
    ensures
        split_colon(s) == splitn_colon(6, s),
{
    lemma_parse_parts(s, p);
    let seg = splitn_colon(6, s);
    lemma_splitn_len(6, s);
    lemma_splitn_prefix_colon_free(6, s);
    lemma_splitn_join(6, s);
    assert forall|i: int| 0 <= i < seg.len() implies colon_free(#[trigger] seg[i]) by {
        if i == 5 {
            assert(seg[5] == rest_of(p));
        }
    }
    lemma_split_join(seg);
}

/// The exact relation between the code's MRK test (`is_multi_region_arn`, copied as `is_mr_arn`)
/// and the spec text, on every ARN that `parse_arn` accepts: the test holds exactly when the spec
/// text calls the ARN an MRK ARN (service kms, resource type key, id starting with "mrk-") AND the
/// resource id holds no ':'. The extra condition comes from `split(':')` having to give six pieces
/// (`parse_arn` uses `splitn(6, ':')`, so its sixth piece may hold colons).
proof fn lemma_is_mr_arn_iff(rec: Str, p: Parts)
    requires
        parse_arn(rec) == Some(p),
    ensures
        is_mr_arn(rec) <==> (mrk_by_spec_text(p) && colon_free(p.res)),
{
    lemma_parse_parts(rec, p);
    let seg = splitn_colon(6, rec);
    let q = rest_of(p);
    lemma_first_slash_append(p.rt, p.res);
    if is_mr_arn(rec) {
        lemma_splitn_eq_split(6, rec);
        lemma_split_pieces_colon_free(rec);
        assert(split_colon(rec) == seg);
        assert(colon_free(seg[5]));
        assert(colon_free(q));
        assert(s_key_mrk().is_prefix_of(q));
        lemma_key_mrk_piece(q);
        assert(p.rt.len() == 3);
        assert(p.rt =~= q.take(3));
        assert(p.res =~= q.skip(4)) by {
            assert(q.skip(p.rt.len() as int + 1) =~= p.res);
        }
        assert(colon_free(p.res)) by {
            assert forall|j: int| 0 <= j < p.res.len() implies #[trigger] p.res[j] != ':' by {
                assert(p.res[j] == q[j + 4]);
            }
        }
        assert(p.service == s_kms());
        assert(p.rt == s_key());
        assert(s_mrk().is_prefix_of(p.res));
        assert(mrk_by_spec_text(p) && colon_free(p.res));
    }
    if mrk_by_spec_text(p) && colon_free(p.res) {
        assert(p.rt == s_key());
        assert(colon_free(q)) by {
            assert forall|j: int| 0 <= j < q.len() implies #[trigger] q[j] != ':' by {
                if j < 3 {
                    assert(q[j] == p.rt[j]);
                } else if j == 3 {
                    assert(q[3] == '/');
                } else {
                    assert(q[j] == p.res[j - 4]);
                }
            }
        }
        lemma_split_eq_splitn_when_rest_colon_free(rec, p);
        assert(s_key_mrk().is_prefix_of(q)) by {
            assert(q.subrange(0, 8) =~= s_key_mrk());
        }
        assert(is_mr_arn(rec));
    }
}

// ============================================================
// SECTION 7: What the shipped Discovery and MrDiscovery arms do (model level)
// ============================================================

/// R1 (YAML "Discovery"). Discovery returns the record ARN verbatim, and only when the ARN parses
/// and its resource type is not "alias"; every other ARN is an `InvalidMaterials` error. Discovery
/// never rewrites anything. CONSISTENCY CHECK: this reads the model back. `resolve` is written as
/// this case split, so the theorem checks the YAML text against the model, not the code against the
/// model.
proof fn theorem_discovery_exact(rec: Str)
    ensures
        (parse_arn(rec) is Some && parse_arn(rec)->Some_0.rt != s_alias_rt()) ==> resolve(
            Cfg::Discovery,
            rec,
        ) == Resolved::Key(rec),
        !(parse_arn(rec) is Some && parse_arn(rec)->Some_0.rt != s_alias_rt()) ==> resolve(
            Cfg::Discovery,
            rec,
        ) == Resolved::Fail(Kind::InvalidMaterials),
{
}

/// R2. MrDiscovery accepts exactly the records Discovery accepts: the region rewrite never turns
/// an accepted record into an error, and never accepts a record that Discovery rejects. The alias
/// and malformed-ARN checks come before the rewrite in both arms.
proof fn theorem_mrdiscovery_same_accept_set(rec: Str, r: Str)
    ensures
        (resolve(Cfg::MrDiscovery(r), rec) is Key) <==> (resolve(Cfg::Discovery, rec) is Key),
        (resolve(Cfg::MrDiscovery(r), rec) is Fail) <==> (resolve(Cfg::Discovery, rec) is Fail),
{
}

/// R3 (the rewrite, as shipped). For every accepted record and every colon-free configured region
/// r, MrDiscovery returns the ARN built from the record's parts with ONLY the region replaced:
/// the result parses, its region is r, and its partition, service, account, resource type and
/// resource are the record's. The result equals the record exactly when the record's region is r.
/// The theorem is stated for every accepted ARN, MRK or not: the model has no MRK test on this arm.
proof fn theorem_mrdiscovery_rewrite(rec: Str, r: Str, p: Parts)
    requires
        colon_free(r),
        parse_arn(rec) == Some(p),
        p.rt != s_alias_rt(),
    ensures
        resolve(Cfg::MrDiscovery(r), rec) == Resolved::Key(format_arn(with_region(p, r))),
        parse_arn(format_arn(with_region(p, r))) == Some(with_region(p, r)),
        parse_arn(format_arn(with_region(p, r)))->Some_0.region == r,
        (p.region == r ==> format_arn(with_region(p, r)) == rec),
        (p.region != r ==> format_arn(with_region(p, r)) != rec),
{
    lemma_rewrite_parses(rec, r, p);
    lemma_parse_parts(rec, p);
    if p.region == r {
        assert(with_region(p, r) == p);
    }
    if format_arn(with_region(p, r)) == rec {
        assert(parse_arn(format_arn(with_region(p, r))) == Some(p));
        assert(with_region(p, r) == p);
        assert(p.region == r);
    }
}

/// R4 (the MRK half of the target property, as shipped). A record that the spec text calls an MRK
/// ARN has its region replaced by the configured region. It follows from R3: "key" is not "alias".
proof fn theorem_mrk_region_rewritten(rec: Str, r: Str, p: Parts)
    requires
        colon_free(r),
        parse_arn(rec) == Some(p),
        mrk_by_spec_text(p),
    ensures
        resolve(Cfg::MrDiscovery(r), rec) == Resolved::Key(format_arn(with_region(p, r))),
        parse_arn(format_arn(with_region(p, r)))->Some_0.region == r,
{
    assert(s_key() != s_alias_rt());
    theorem_mrdiscovery_rewrite(rec, r, p);
}

// R5 (a note, no obligation). Without a colon-free region the rewrite does not keep the pieces apart.
// This is why R3 needs the hypothesis H_REGION_CFG: `MrDiscoveryBuilder::build` only checks that a
// region was given (config.rs:327-331). The premise `colon_free(p.region)` is visible in
// `lemma_parse_format` and in `theorem_mrdiscovery_rewrite`.

// ============================================================
// SECTION 8: BUG-04. The target property, which the shipped arm does not satisfy
// ============================================================

/// R6 (EXPECTED FAIL, BUG-04). The target property from the YAML for MrDiscovery:
///     !is_mrk(rec) ==> k == rec        "the region is rewritten only for MRKs"
/// A record that parses, is not an alias and is not an MRK ARN (spec text) must come back unchanged.
/// The shipped arm rewrites every accepted ARN (R3), so the claim is false whenever the record's
/// region is not the configured one (`lemma_bug04_claim_is_false` has the concrete ARN). The lemma is
/// left failing on purpose: not weakened, not assumed, not commented out.
proof fn lemma_bug04_region_rewritten_only_for_mrk_EXPECTED_FAIL(r: Str, rec: Str, p: Parts)
    requires
        colon_free(r),
        parse_arn(rec) == Some(p),
        p.rt != s_alias_rt(),
        !mrk_by_spec_text(p),
    ensures
        resolve(Cfg::MrDiscovery(r), rec) == Resolved::Key(rec),
{
}

/// For a record that parses, is not an alias and is not an MRK ARN, the shipped arm returns the
/// record unchanged exactly when the record's region already is the configured one. So the failing
/// claim above is false exactly on records with a different region, and nowhere else.
proof fn lemma_nonmrk_unchanged_iff_same_region(r: Str, rec: Str, p: Parts)
    requires
        colon_free(r),
        parse_arn(rec) == Some(p),
        p.rt != s_alias_rt(),
        !mrk_by_spec_text(p),
    ensures
        (resolve(Cfg::MrDiscovery(r), rec) == Resolved::Key(rec)) <==> (p.region == r),
{
    theorem_mrdiscovery_rewrite(rec, r, p);
}

// ============================================================
// SECTION 9: The proposed fix (BUG-04 option 1), at model level
// ============================================================

/// R7. With the fix, the target property holds: a record that parses, is not an alias and is not an
/// MRK ARN (spec text) comes back unchanged, whatever the configured region. This is the lemma
/// R6 states for the shipped arm, now proved for `resolve_fixed`.
proof fn lemma_bug04_fix_region_rewritten_only_for_mrk(r: Str, rec: Str, p: Parts)
    requires
        parse_arn(rec) == Some(p),
        p.rt != s_alias_rt(),
        !mrk_by_spec_text(p),
    ensures
        resolve_fixed(Cfg::MrDiscovery(r), rec) == Resolved::Key(rec),
{
    lemma_is_mr_arn_iff(rec, p);
    assert(!is_mr_arn(rec));
}

/// R8. The fix changes no accepted or rejected record: the same records are accepted and the same
/// are errors, for every configured region. Only the value of an accepted non-MRK record changes.
proof fn lemma_fix_same_accept_set(rec: Str, r: Str)
    ensures
        (resolve_fixed(Cfg::MrDiscovery(r), rec) is Key) <==> (resolve(
            Cfg::MrDiscovery(r),
            rec,
        ) is Key),
        (resolve_fixed(Cfg::MrDiscovery(r), rec) is Fail) <==> (resolve(
            Cfg::MrDiscovery(r),
            rec,
        ) is Fail),
{
}

/// R9. Where the code's MRK test holds, the fix and the shipped arm agree exactly.
proof fn lemma_fix_agrees_where_mr_arn(rec: Str, r: Str)
    requires
        is_mr_arn(rec),
    ensures
        resolve_fixed(Cfg::MrDiscovery(r), rec) == resolve(Cfg::MrDiscovery(r), rec),
{
}

/// R10. With the fix, an MRK ARN (spec text) whose resource id holds no ':' still gets exactly the
/// region rewrite of R3: the fix does not reject or skip a real MRK record of that shape.
proof fn lemma_fix_rewrites_mrk(rec: Str, r: Str, p: Parts)
    requires
        colon_free(r),
        parse_arn(rec) == Some(p),
        mrk_by_spec_text(p),
        colon_free(p.res),
    ensures
        resolve_fixed(Cfg::MrDiscovery(r), rec) == Resolved::Key(format_arn(with_region(p, r))),
        parse_arn(format_arn(with_region(p, r)))->Some_0.region == r,
{
    lemma_is_mr_arn_iff(rec, p);
    assert(is_mr_arn(rec));
    theorem_mrk_region_rewritten(rec, r, p);
}

/// R11. Discovery and the pinned arms are the same in `resolve_fixed` and `resolve`.
proof fn lemma_fix_leaves_other_arms(c: Cfg, rec: Str)
    requires
        !(c is MrDiscovery),
    ensures
        resolve_fixed(c, rec) == resolve(c, rec),
{
}

// ============================================================
// SECTION 10: Concrete witnesses (the contracts are satisfiable; the counterexample is real)
// ============================================================

pub open spec fn w_aws() -> Str { seq!['a', 'w', 's'] }
pub open spec fn w_east() -> Str { seq!['u', 's', '-', 'e', 'a', 's', 't', '-', '1'] }
pub open spec fn w_west() -> Str { seq!['u', 's', '-', 'w', 'e', 's', 't', '-', '2'] }
pub open spec fn w_acct() -> Str {
    seq!['1', '1', '1', '1', '2', '2', '2', '2', '3', '3', '3', '3']
}
/// "1234abcd-12ab-34cd-56ef-1234567890ab" (the key id of the BUG-04 reproducer)
pub open spec fn w_uuid() -> Str {
    seq![
        '1', '2', '3', '4', 'a', 'b', 'c', 'd', '-', '1', '2', 'a', 'b', '-', '3', '4', 'c', 'd',
        '-', '5', '6', 'e', 'f', '-', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b',
    ]
}

/// The single-Region key ARN of the BUG-04 reproducer:
/// arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
pub open spec fn w_srk() -> Parts {
    Parts {
        partition: w_aws(),
        service: s_kms(),
        region: w_east(),
        account: w_acct(),
        rt: s_key(),
        res: w_uuid(),
    }
}

/// The MRK ARN of the BUG-04 reproducer (control):
/// arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab
pub open spec fn w_mrk() -> Parts {
    Parts { res: s_mrk().add(w_uuid()), ..w_srk() }
}

proof fn lemma_w_colon_free()
    ensures
        colon_free(w_aws()),
        colon_free(s_kms()),
        colon_free(w_east()),
        colon_free(w_west()),
        colon_free(w_acct()),
        colon_free(w_uuid()),
        colon_free(s_mrk()),
        colon_free(s_mrk().add(w_uuid())),
        slash_free(s_key()),
{
    lemma_colon_free_add(s_mrk(), w_uuid());
}

/// The concrete counterexample to R6, BUG-04. The record is the single-Region key
///   arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
/// and the configured MrDiscovery region is us-west-2. The shipped arm accepts the record and
/// returns
///   arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
/// which is not the record, although the key is not an MRK. The model gives the same two ARNs as the
/// recheck run of the shipped function (`.agents/tasks/bug-recheck/logs/recheck04.log`).
proof fn lemma_bug04_counterexample()
    ensures
        ({
            let rec = format_arn(w_srk());
            let r = w_west();
            let k = format_arn(with_region(w_srk(), r));
            &&& colon_free(r)
            &&& parse_arn(rec) == Some(w_srk())
            &&& w_srk().rt != s_alias_rt()
            &&& !mrk_by_spec_text(w_srk())
            &&& resolve(Cfg::MrDiscovery(r), rec) == Resolved::Key(k)
            &&& k != rec
            &&& parse_arn(k)->Some_0.region == r
            &&& w_srk().region == w_east()
            &&& w_east() != r
            &&& resolve_fixed(Cfg::MrDiscovery(r), rec) == Resolved::Key(rec)
            &&& resolve(Cfg::Discovery, rec) == Resolved::Key(rec)
        }),
{
    lemma_w_colon_free();
    lemma_parse_format(w_srk());
    assert(s_key() != s_alias_rt());
    assert(w_uuid()[0] == '1');
    assert(!s_mrk().is_prefix_of(w_uuid()));
    theorem_mrdiscovery_rewrite(format_arn(w_srk()), w_west(), w_srk());
    lemma_bug04_fix_region_rewritten_only_for_mrk(w_west(), format_arn(w_srk()), w_srk());
    assert(w_east() != w_west());
}

/// The six words the model compares with are the spec and code words. Each is typed once as a
/// `seq!` of chars and once as a string literal here, so a typo in one of the two is caught. (A
/// typo made in both places is not.) "alias" is `kms_ops.rs` :122, "key/mrk-" is `mrk_match.rs` :57,
/// "arn" is `kms_config.rs` :33, "kms" is `mrk_match.rs` :56.
proof fn lemma_words_are_the_code_words()
    ensures
        s_arn() =~= "arn"@,
        s_kms() =~= "kms"@,
        s_key() =~= "key"@,
        s_mrk() =~= "mrk-"@,
        s_alias_rt() =~= "alias"@,
        s_key_mrk() =~= "key/mrk-"@,
{
    reveal_strlit("arn");
    reveal_strlit("kms");
    reveal_strlit("key");
    reveal_strlit("mrk-");
    reveal_strlit("alias");
    reveal_strlit("key/mrk-");
}

/// The model's ARNs are the exact strings of the BUG-04 reproducer (`BUG-04-...md`, "Reproduction").
/// This ties the part-wise witnesses above to the text: formatting the parts gives these characters.
proof fn lemma_witness_strings()
    ensures
        format_arn(w_srk()) =~= "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"@,
        format_arn(with_region(w_srk(), w_west())) =~= "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"@,
        format_arn(w_mrk()) =~= "arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab"@,
        format_arn(with_region(w_mrk(), w_west())) =~= "arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab"@,
{
    reveal_strlit("arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab");
    reveal_strlit("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab");
    reveal_strlit("arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab");
    reveal_strlit("arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab");
}

/// The claim of R6 is false: the witness meets every `requires` of the EXPECTED_FAIL lemma and
/// violates its `ensures`.
proof fn lemma_bug04_claim_is_false()
    ensures
        ({
            let rec = format_arn(w_srk());
            let r = w_west();
            let p = w_srk();
            &&& colon_free(r)
            &&& parse_arn(rec) == Some(p)
            &&& p.rt != s_alias_rt()
            &&& !mrk_by_spec_text(p)
            &&& resolve(Cfg::MrDiscovery(r), rec) != Resolved::Key(rec)
        }),
{
    lemma_bug04_counterexample();
}

/// Control: the MRK ARN of the reproducer is rewritten, by the shipped arm and by the fix alike.
proof fn lemma_bug04_mrk_control()
    ensures
        ({
            let rec = format_arn(w_mrk());
            let r = w_west();
            let k = format_arn(with_region(w_mrk(), r));
            &&& parse_arn(rec) == Some(w_mrk())
            &&& mrk_by_spec_text(w_mrk())
            &&& is_mr_arn(rec)
            &&& resolve(Cfg::MrDiscovery(r), rec) == Resolved::Key(k)
            &&& resolve_fixed(Cfg::MrDiscovery(r), rec) == Resolved::Key(k)
            &&& k != rec
        }),
{
    lemma_w_colon_free();
    lemma_parse_format(w_mrk());
    assert(w_mrk().rt == s_key());
    assert(w_mrk().service == s_kms());
    assert(s_mrk().is_prefix_of(w_mrk().res)) by {
        assert(w_mrk().res.subrange(0, 4) =~= s_mrk());
    }
    assert(colon_free(w_mrk().res));
    lemma_is_mr_arn_iff(format_arn(w_mrk()), w_mrk());
    lemma_fix_rewrites_mrk(format_arn(w_mrk()), w_west(), w_mrk());
    theorem_mrk_region_rewritten(format_arn(w_mrk()), w_west(), w_mrk());
    theorem_mrdiscovery_rewrite(format_arn(w_mrk()), w_west(), w_mrk());
    assert(w_mrk().region != w_west());
}

/// Look-alikes of an MRK id, with the region different from the configured one. Spec text: not MRK
/// ARNs. Shipped: rewritten. Fix: unchanged. These are the inputs a wrong prefix test would get wrong.
///   (a) key id "mrk" + hex with no dash: arn:aws:kms:us-east-1:111122223333:key/mrk1234abcd...
///   (b) resource type "foo" with an id that starts "mrk-": ...:foo/mrk-1234abcd...
proof fn lemma_lookalikes_not_rewritten_by_fix()
    ensures
        ({
            let ra = Parts { res: seq!['m', 'r', 'k'].add(w_uuid()), ..w_srk() };
            let rb = Parts { rt: seq!['f', 'o', 'o'], res: s_mrk().add(w_uuid()), ..w_srk() };
            let r = w_west();
            &&& !mrk_by_spec_text(ra)
            &&& !mrk_by_spec_text(rb)
            &&& resolve_fixed(Cfg::MrDiscovery(r), format_arn(ra)) == Resolved::Key(format_arn(ra))
            &&& resolve_fixed(Cfg::MrDiscovery(r), format_arn(rb)) == Resolved::Key(format_arn(rb))
            &&& resolve(Cfg::MrDiscovery(r), format_arn(ra)) != Resolved::Key(format_arn(ra))
            &&& resolve(Cfg::MrDiscovery(r), format_arn(rb)) != Resolved::Key(format_arn(rb))
        }),
{
    lemma_w_colon_free();
    let ra = Parts { res: seq!['m', 'r', 'k'].add(w_uuid()), ..w_srk() };
    let rb = Parts { rt: seq!['f', 'o', 'o'], res: s_mrk().add(w_uuid()), ..w_srk() };
    lemma_parse_format(ra);
    lemma_parse_format(rb);
    assert(ra.res[3] == '1');
    assert(!s_mrk().is_prefix_of(ra.res));
    assert(s_key() != rb.rt);
    assert(rb.rt != s_alias_rt());
    assert(ra.rt != s_alias_rt());
    lemma_bug04_fix_region_rewritten_only_for_mrk(w_west(), format_arn(ra), ra);
    lemma_bug04_fix_region_rewritten_only_for_mrk(w_west(), format_arn(rb), rb);
    theorem_mrdiscovery_rewrite(format_arn(ra), w_west(), ra);
    theorem_mrdiscovery_rewrite(format_arn(rb), w_west(), rb);
}

/// An alias ARN (even one whose name starts with "mrk-") is an error in Discovery, MrDiscovery and
/// the fix; the alias check comes first. aws-kms-key-arn.md :69-70.
proof fn lemma_alias_rejected_witness()
    ensures
        ({
            let ra = Parts { rt: s_alias_rt(), res: s_mrk().add(w_uuid()), ..w_srk() };
            let r = w_west();
            &&& resolve(Cfg::Discovery, format_arn(ra)) == Resolved::Fail(Kind::InvalidMaterials)
            &&& resolve(Cfg::MrDiscovery(r), format_arn(ra)) == Resolved::Fail(
                Kind::InvalidMaterials,
            )
            &&& resolve_fixed(Cfg::MrDiscovery(r), format_arn(ra)) == Resolved::Fail(
                Kind::InvalidMaterials,
            )
        }),
{
    lemma_w_colon_free();
    let ra = Parts { rt: s_alias_rt(), res: s_mrk().add(w_uuid()), ..w_srk() };
    assert(slash_free(s_alias_rt()));
    lemma_parse_format(ra);
}

/// The empty string is not an ARN: not six pieces. Error in all three.
proof fn lemma_malformed_rejected_witness()
    ensures
        resolve(Cfg::Discovery, Seq::<char>::empty()) == Resolved::Fail(Kind::InvalidMaterials),
        resolve(Cfg::MrDiscovery(w_west()), Seq::<char>::empty()) == Resolved::Fail(
            Kind::InvalidMaterials,
        ),
        resolve_fixed(Cfg::MrDiscovery(w_west()), Seq::<char>::empty()) == Resolved::Fail(
            Kind::InvalidMaterials,
        ),
{
    assert(splitn_colon(6, Seq::<char>::empty()) =~= seq![Seq::<char>::empty()]);
}

/// Observation O2. The fix gate `is_multi_region_arn` and the spec text differ on a resource id that
/// holds ':'. Record `arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd...:x` parses (the sixth
/// piece may hold colons), is an MRK ARN by the spec text, and is not `is_mr_arn`. The shipped arm
/// rewrites it. The fix model leaves it unchanged.
proof fn lemma_fix_gate_misses_colon_in_resource()
    ensures
        ({
            let rc = Parts { res: s_mrk().add(w_uuid()).add(seq![':', 'x']), ..w_srk() };
            let r = w_west();
            &&& parse_arn(format_arn(rc)) == Some(rc)
            &&& mrk_by_spec_text(rc)
            &&& !is_mr_arn(format_arn(rc))
            &&& resolve(Cfg::MrDiscovery(r), format_arn(rc)) == Resolved::Key(
                format_arn(with_region(rc, r)),
            )
            &&& resolve_fixed(Cfg::MrDiscovery(r), format_arn(rc)) == Resolved::Key(format_arn(rc))
            &&& format_arn(with_region(rc, r)) != format_arn(rc)
        }),
{
    lemma_w_colon_free();
    let rc = Parts { res: s_mrk().add(w_uuid()).add(seq![':', 'x']), ..w_srk() };
    lemma_parse_format(rc);
    assert(s_mrk().is_prefix_of(rc.res)) by {
        assert(rc.res.subrange(0, 4) =~= s_mrk());
    }
    assert(rc.res[s_mrk().add(w_uuid()).len() as int] == ':');
    lemma_is_mr_arn_iff(format_arn(rc), rc);
    assert(!colon_free(rc.res));
    assert(!is_mr_arn(format_arn(rc)));
    assert(s_key() != s_alias_rt());
    theorem_mrdiscovery_rewrite(format_arn(rc), w_west(), rc);
    assert(w_east() != w_west());
}

/// Observation O3. The Discovery and MrDiscovery arms test the resource type only (not "alias") and
/// that the ARN parses. They do not test the service. An ARN with service "s3" is accepted by both,
/// and MrDiscovery rewrites its region. (KMS would reject it later; not modeled.)
proof fn lemma_service_not_checked_witness()
    ensures
        ({
            let rs = Parts { service: seq!['s', '3'], ..w_srk() };
            let r = w_west();
            &&& resolve(Cfg::Discovery, format_arn(rs)) == Resolved::Key(format_arn(rs))
            &&& resolve(Cfg::MrDiscovery(r), format_arn(rs)) == Resolved::Key(
                format_arn(with_region(rs, r)),
            )
        }),
{
    lemma_w_colon_free();
    let rs = Parts { service: seq!['s', '3'], ..w_srk() };
    assert(colon_free(rs.service));
    lemma_parse_format(rs);
    assert(s_key() != s_alias_rt());
    theorem_mrdiscovery_rewrite(format_arn(rs), w_west(), rs);
}

} // verus!

fn main() {}
