// =============================================================================
// VR-2026-T12 (rank 14 of the threat-driven table, TM-MPL-017): the merge of the message's
//   encryption context with the customer-supplied Reproduced Encryption Context,
//   `merge_reproduced_encryption_context` (mpl/src/cmm/default_cmm.rs :273-304).
//
// Run:  ~/verus/verus verus-proofs/t12_merge_reproduced_ec.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written model of a 20-line function. The shipped function is
// native Rust over `EncryptionContext(BTreeMap<String, String>)` and
// `RequiredEncryptionContextKeys(BTreeSet<String>)`, outside `verus!`, and is not compiled by
// Verus. Nothing here detects a later edit to default_cmm.rs. The link between the model and the
// code is the correspondence table in section 2, reviewed by a human.
//
// STATUS: PROVED relative to the model and to the hypotheses in section 4:
//     `verification results:: 20 verified, 0 errors`
// Nothing is left failing on purpose. The code and the spec text agree on everything modeled, so
// no EXPECTED_FAIL obligation was written and none was invented (section 5, F0).
//
// HOW MUCH THIS PROOF IS WORTH (stated plainly). The function is a single loop. The characterization
// proof (lemma_fold_char) is a short induction over the loop. Part of the result is a consistency
// check against the spec text: the theorems restate the sentences of cmm-interface.md
// "Decrypt Materials" (section 3) and check that the loop model satisfies them. The parts with more
// weight are: (a) the loop never overwrites an entry of the message context (the `ec.insert` result
// is discarded in the code, so an overwrite would be silent); (b) the exact set of required keys;
// (c) the verdict and the result do not depend on the iteration order; (d) the result is the same
// map as `m.union_prefer_right(r)` and as `r.union_prefer_right(m)`, which is the formal_spec of
// the T12 YAML entry. None of this shows that the shipped code, or the system around it, is safe.
//
// =============================================================================
// WHAT THE CODE DOES (code reading, mpl/src/cmm/default_cmm.rs)
// =============================================================================
// Signature (:273-276): (message_ec: &EncryptionContext, reproduced_ec: Option<&EncryptionContext>)
//     -> Result<(EncryptionContext, RequiredEncryptionContextKeys), Error>
//   :277      let mut ec = message_ec.clone();            // result starts as a copy of the message EC
//   :278      let mut required_keys = RequiredEncryptionContextKeys::new();    // empty set
//   :280-282  no reproduced EC: return Ok((ec, required_keys)), the message EC and the empty set
//   :284      for (key, value) in reproduced_ec.iter()    // ascending key order (BTreeMap), each key once
//   :285      match message_ec.get(key)                   // lookup in the ORIGINAL message EC, not in `ec`
//   :286-295    Some(message_value): if message_value != value { return Err(EncryptionContextMismatch) }
//                  (an agreeing shared key changes nothing and adds no required key)
//   :296-299    None: ec.insert(key, value); required_keys.insert(key.to_owned())  (insert result discarded)
//   :303      Ok((ec, required_keys))
// There is one error site (:288-293), with `Kind::EncryptionContextMismatch`. The error text names the
// key and nothing else. The function takes no lock, does no I/O and has no `unsafe`.
//
// Caller (:198-201, in `decrypt_materials` :177-): `merge_...(input.encryption_context(),
// input.reproduced_encryption_context())?`. Then: the signing-suite branch reads `ec` for
// `aws-crypto-public-key` (:206-), and `ec` and the required keys go into
// `DecryptionMaterials::builder().set_encryption_context(Some(ec))
// .set_required_encryption_context_keys(Some(..)).build()?` (:235-240) before the keyring is called.
// `DecryptionMaterials::build` (structures/decryption_materials.rs :295-) fails with
// `EncryptionContextMismatch` when a required key is not in the EC (:307-316) and stores the EC
// unchanged (:348-353).
//
// Order. The doc comment of the function (:256-272) does not claim order independence, and nothing
// else in default_cmm.rs does (grep `order`: no hit). The only order statement is in
// structures/encryption_context.rs :11-12 and :74: iteration is in ascending UTF-8 byte order. The
// model therefore accepts ANY enumeration of the reproduced keys; P3 and O1 below say what is and is
// not independent of it.
//
// =============================================================================
// WHAT IS PROVED (relative to the model and to section 4). Evidence level: PROVED (model).
// =============================================================================
//   P0  theorem_t12_none               no reproduced EC  ==>  Ok((message EC, empty set)). This is
//                                      the definition of the model written back (consistency check).
//   P1  theorem_t12_ok_iff             the merge is Ok exactly when the two contexts agree on every
//                                      shared key. Any conflicting key makes it fail, whatever its
//                                      position in the iteration order.
//       theorem_t12_err_is_conflict    an error always names a real conflict: a key in both contexts
//                                      with different values, and every key before it in the
//                                      iteration order agrees (it is the FIRST conflict).
//   P2  theorem_t12_ok_result          on Ok: the result EC has domain dom(m) union dom(r); every
//                                      message entry is present with its value (no key lost or
//                                      changed); every reproduced entry is present with its value;
//                                      nothing else is present; the result is `m.union_prefer_right(r)`
//                                      and also `r.union_prefer_right(m)`. The required keys are
//                                      exactly dom(r) \ dom(m), they are all keys of the result, none
//                                      is a message key, and they are exactly the keys the merge added.
//   P3  theorem_t12_order_independent  two enumerations of the same reproduced EC give the same
//                                      verdict, and the same result EC and required keys on Ok.
//       lemma_error_key_depends_on_order  the key NAMED in the error does depend on the order (a
//                                      witness). Not a defect: see O1.
//       lemma_union_symmetric          swapping the two arguments gives the same merged EC when they
//                                      agree. The required keys are NOT symmetric (lemma_req_asymmetric).
//   P4  lemma_corollaries              empty reproduced EC; reproduced EC contained in the message EC
//                                      (nothing appended, no required key: the test at
//                                      mpl/tests/test_default_cmm.rs :499); empty message EC (every
//                                      reproduced key becomes required).
//       lemma_remerge_is_noop          a second merge of the result with the same reproduced EC changes
//                                      nothing.
//   P5  lemma_enum_exists, lemma_witness_ok, lemma_witness_conflict   the hypotheses are satisfiable
//                                      and the theorems are not vacuous: every map has an enumeration,
//                                      one concrete Ok case and one concrete Err case are computed.
//   P6  lemma_builder_check_cannot_fire   the check in `DecryptionMaterials::build` (:307-316), "every
//                                      required key is in the EC", cannot fail on the output of the
//                                      merge (model of that check; the check is code reading).
//
// =============================================================================
// WHAT IS NOT PROVED / WHAT THIS DOES NOT SHOW
// =============================================================================
//   * That the shipped code has any of these properties (model level only).
//   * That TM-MPL-017 is mitigated. The YAML threat text is "Reproduced-EC merge drops or alters bound
//     context". P2 says the MODEL of the merge drops and alters nothing of either input. It does not
//     show that the decryptor's AAD equals the encryptor's AAD. That needs: the encrypt side (what the
//     encrypting CMM keeps in the message and what it holds back), the reproduced context the caller
//     passes, the keyring's AAD construction, the ESDK header parse (T15 and VR-003 own the codec of the
//     message context), and the transition checks of C07. None is modeled here. T15 is not proved.
//   * The reproduced context is customer-supplied (the decryptor's own input), the message context is the
//     untrusted one. The model treats them symmetrically, as the spec text does.
//   * That `reproduced_ec.iter()` and `BTreeMap::{get, insert, clone}` behave as modeled (A_ITER, A_MAP).
//   * String comparison, UTF-8, string length limits, and the text of the error. Keys and values are
//     `Seq<char>` (A_STR).
//   * Everything in `decrypt_materials` other than the call at :198 and the hand-over at :235-240:
//     the commitment-policy check, the verification-key extraction, the keyring call.
//   * The spec's "The CMM MAY fail if it expects key-value pairs that do not exist in [the reproduced EC]"
//     (cmm-interface.md :161-163).
//     The code does not implement it (it is a MAY). Not a gap.
//   * Concurrency, allocation failure, panics in `clone` or `insert`.
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD cff28df; mpl/, prim/, esdk/ unchanged by this work)
// =============================================================================
//   mpl/src/cmm/default_cmm.rs (md5 31a3fd26f88d3806fc9e0f9e893d761d)
//     :35-54    type doc (decrypt_materials bullet: "Merges the input's encryption context with its Reproduced ...")
//     :177-,:198-201,:235-240   decrypt_materials, the call and the hand-over
//     :256-304  the doc comment and merge_reproduced_encryption_context
//   mpl/src/structures/encryption_context.rs (md5 27cf55faba5c8f4fbc4c391aa527defd)
//     :11-16    `EncryptionContext(BTreeMap<String,String>)`, derives Clone, PartialEq, Eq; ascending order doc :11-12
//     :31 insert (returns the previous value), :59 get, :73-74 iter (ascending key order)
//   mpl/src/structures/required_encryption_context_keys.rs (md5 cf4e99c97383ff3db2cb6b7c94d85501)
//     :26 `RequiredEncryptionContextKeys(BTreeSet<String>)`, :44 insert, :54 contains
//   mpl/src/structures/decryption_materials.rs :295-353 build (required-key subset check :307-316)
//   spec/framework/cmm-interface.md :146-182 "Decrypt Materials"
//   Tests (not proofs): mpl/tests/test_default_cmm.rs :499 (matching values), :538 (mismatch fails),
//     :564 (reproduced-only key appended), :635, :667 (disjoint), :728 (conflict does not call the keyring).
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code)
// =============================================================================
//   model                  shipped
//   ---------------------  -----------------------------------------------------------------------
//   Str, Ec, get           String / EncryptionContext as Seq<char> / Map<Seq<char>, Seq<char>>.
//                          COPIED from verus-proofs/c01_ec_roundtrip.rs :187-188 (`Str`, `Ec`) and
//                          :270 (`get`, in c01 section 2); the same three items are in t01 :241-242,
//                          :324 and t02 :133-134, :216. Copy, not import: each proof file is its own
//                          crate root, so nothing can be imported from another file. Only `Str`, `Ec`
//                          and `get` are copied, unchanged; the T02 reconstruction model is not needed.
//   m, r, keys             message_ec, *reproduced_ec (the Some case), the order in which
//                          `reproduced_ec.iter()` yields the keys (any order, covering dom(r))
//   Merged { ec, req }     the returned pair (EncryptionContext, RequiredEncryptionContextKeys)
//   merge_spec(m, None)    :280-282 return Ok((ec, required_keys)) with ec == clone of message_ec
//   merge_fold             :284-301, the loop, as a left fold over `keys`; the first Err stops it
//                          (the `return Err` at :288). Initial state :277-278 (m, empty set).
//   step                   :285-299 one iteration: `get(m, k)` is `message_ec.get(key)` on the
//                          ORIGINAL (:285); Some and different -> Err(k) (:287-293); Some and equal
//                          -> state unchanged; None -> insert into ec and into the required set
//                          (:297-298)
//   Err(k)                 Error::new(Kind::EncryptionContextMismatch, ..) naming k (:288-293).
//                          The only error site, so the kind is not modeled separately.
//   conflict, agree        the condition at :285-287 over all shared keys
//   spec_union, spec_req   cmm-interface.md :154-182, written without the loop (Verus section 2)
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED
// =============================================================================
// Spec-derived (spec/framework/cmm-interface.md "Decrypt Materials"):
//   :157-159  "For every key that exists in both ... the values MUST be equal or the operation MUST fail."
//             -> P1.
//   :172-174  "All key-value pairs that exist in [Reproduced EC] but do not exist in [the request's EC]
//             SHOULD be appended to the decryption materials." -> P2 (the reproduced entries are present).
//   :178-182  "Required Encryption Context Keys: This set MUST include all keys added ... that existed in
//             the reproduced EC but did not exist in the request's EC. All keys in this set MUST exist in
//             the decryption materials encryption context." -> P2 (exact set, subset of the result EC).
// Code-derived, with no spec sentence: that the required keys contain ONLY the added keys (the spec says
// "MUST include", not "only"); that a conflict names the first conflicting key in ascending order; that
// an absent reproduced EC returns the message EC and the empty set (the spec is silent; the T12 YAML
// states it); the Kind of the error.
// So P1 and P2 are, in part, consistency checks of the model against the spec text: `spec_union` and
// `spec_req` restate those sentences without the loop, and the proof shows the loop model equals them.
// That the model is a correct transcription of :277-303 is not machine-checked (H_MODEL_MATCH).
//
// =============================================================================
// 4. HYPOTHESES AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and to the hypotheses
//    ASSUMED       taken as a premise or a definition; not proved here (A_*)
//    CODE READING  a claim about shipped code or std that Verus does not see (H_*); checked by a human
//                  reading the source at the lines named
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier..]` attribute
//  is written in this file, and there is no uninterpreted spec function. The trusted base is Verus, Z3 and
//  the vstd axioms for Seq, Set and Map.
//
//  A_STR (ASSUMED, inherited from C01/T02). Strings are `Seq<char>`. `message_value != value` on `&str` is
//    inequality of the two character sequences. Keys that are equal as `String` are equal as `Seq<char>`
//    and conversely (String's `deep_view` is injective). Not machine-checked; vstd has no such spec for
//    `String` over `BTreeMap`.
//  A_MAP (ASSUMED). `BTreeMap::get` is `Map` lookup, `BTreeMap::insert` is `Map::insert` (overwriting),
//    `EncryptionContext::clone` is a deep copy so that `ec` starts equal to `message_ec` as a map and
//    later inserts into `ec` do not change `message_ec`, and `BTreeSet::insert` is `Set::insert`.
//    These are std contracts; vstd has no specification for `BTreeMap` or `BTreeSet` over `String`.
//  A_ITER (ASSUMED). `reproduced_ec.iter()` yields every key of the reproduced EC, in some order, with its
//    value. The model needs only that each key is yielded AT LEAST once (`enumerates`): a repeat is
//    harmless in the model (lemma_fold_char has no distinctness premise), so the BTreeMap guarantee of
//    "exactly once, ascending" is more than the proof uses. Satisfiable for every map (lemma_enum_exists).
//  H_MODEL_MATCH (CODE READING). `merge_fold` and `step` perform, in the same order, the operations of
//    :277-303: copy, lookup in the original, compare, insert into the copy and the set, return at the
//    first mismatch. Checked by reading.
//  H_LOOKUP_ORIGINAL (CODE READING). The lookup at :285 is on `message_ec`, which is a separate value
//    from `ec` (:277 clones) and is not modified (the function holds `&EncryptionContext`). The model
//    keeps `m` fixed for the same reason. Because keys are distinct this would also hold for a lookup in
//    `ec`; the proof does not use that.
//  H_ONE_ERROR_SITE (CODE READING). `return Err` at :288 is the only error exit; `?` is not used inside the
//    function; there is no panic path (`get`, `insert`, `to_owned`, `format!` do not panic in the cases
//    reached; allocation failure is outside the model).
//  H_WIRING (CODE READING). In `decrypt_materials` the pair returned by the merge is used as follows:
//    the `?` at :201 returns the error to the caller before any later step (so a conflict returns before the
//    keyring is called; the test at test_default_cmm.rs :728 checks the same); `ec` is only read between :201
//    and :235 (`get`, `contains_key`) and then moved into `set_encryption_context(Some(ec))` (:237);
//    the required keys go to :238; `build` stores both unchanged (decryption_materials.rs :348-353).
//    Whether the keyring then keeps the EC unchanged is the C07 transition check and is not used here.
//  H_BUILD_CHECK (CODE READING). `DecryptionMaterials::build` rejects a required key that is not a key of
//    the EC (decryption_materials.rs :307-316). P6 uses this only as the statement that was proved cannot
//    fire; the proof does not depend on the check existing.
//  H_ASC (CODE READING). Iteration of `EncryptionContext` is in ascending UTF-8 byte order
//    (encryption_context.rs :11-12, :74, BTreeMap). Used only to explain which conflicting key the shipped
//    code names (O1); no theorem depends on it.
// =============================================================================
// 5. FINDINGS AND OBSERVATIONS
// =============================================================================
//  F0 (no gap). The model satisfies the spec sentences it was checked against. No EXPECTED_FAIL
//    obligation exists. None was invented.
//  O1 (observation, not a gap). The verdict (Ok or Err) and, on Ok, the merged EC and the required keys are
//    independent of the iteration order (P3). The key named in an error is not: with two conflicting keys
//    the model names whichever comes first in the enumeration (lemma_error_key_depends_on_order). In the
//    shipped code the order is ascending (H_ASC), so it names the smallest conflicting key. The code does
//    not claim order independence anywhere (section 0, "Order"); what P3 shows is a property of the model.
//  O2 (observation, not a gap, no exploit claimed). The signing-suite branch of `decrypt_materials`
//    reads `aws-crypto-public-key` from the MERGED EC (:206-). By P2 that key is in the merged EC when
//    either input has it. So if the message EC lacks it and the reproduced EC carries it, the
//    verification key is taken from the reproduced EC. The reproduced EC is the decryptor's own input,
//    not message data. The spec says only "the encryption context includes the reserved key"
//    (cmm-interface.md :151-152) and does not say which EC. Nothing here shows this is wrong; it is
//    recorded so the reader of P2 knows the union also reaches that branch.
//  O3 (scope). T12 stops at the merge. The encrypt-side argument "decrypt AAD equals encrypt AAD" is the
//    T01/T15/C07 neighborhood and is not claimed.
//
// =============================================================================
// 6. OVERLAP
// =============================================================================
//  Mahnush_Verus (.agents/tasks/mpl-batch2-proofs/dup-check.md section 3, tip 8d6381e): no overlap. Nothing
//  there proves or models the merge, the union or the conflict failure. `default_cmm.rs` is identical on both
//  branches and is plain Rust there. The ESDK-side merge of the authenticate-only context
//  (esdk/src/decrypt.rs :334) and VR-003 (`read_canonical_ec`, the header parser) are different code.
//  This repository: C01/T01/T02 supply the Str/Ec/get items (copied, section 2). T15 (the codec) is not
//  proved. C07 (materials transitions) is a separate batch-2 file and is not used.
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Types (Str, Ec, get COPIED from c01_ec_roundtrip.rs :187-188, :270; unchanged)
// ============================================================

pub type Str = Seq<char>;
pub type Ec = Map<Str, Str>;

pub open spec fn get(ec: Ec, k: Str) -> Option<Str> {
    if ec.contains_key(k) { Some(ec[k]) } else { None }
}

/// The returned pair: the merged encryption context and the required encryption context keys.
pub struct Merged {
    pub ec: Ec,
    pub req: Set<Str>,
}

// ============================================================
// SECTION 2: The model of the function (default_cmm.rs :277-303)
// ============================================================

/// `key` is shared and the two values differ (:285-287).
pub open spec fn conflict(m: Ec, r: Ec, k: Str) -> bool {
    m.contains_key(k) && r.contains_key(k) && m[k] != r[k]
}

/// The two contexts agree on every shared key.
pub open spec fn agree(m: Ec, r: Ec) -> bool {
    forall|k: Str| !(#[trigger] conflict(m, r, k))
}

/// One loop iteration (:285-299). `m` is the original message EC (H_LOOKUP_ORIGINAL), `acc` the current
/// (ec, required_keys). Err(k) is `return Err(.. k ..)`.
pub open spec fn step(m: Ec, r: Ec, acc: Merged, k: Str) -> Result<Merged, Str> {
    match get(m, k) {
        Some(mv) => if mv != r[k] { Err(k) } else { Ok(acc) },
        None => Ok(Merged { ec: acc.ec.insert(k, r[k]), req: acc.req.insert(k) }),
    }
}

/// The loop at :284-301 over the enumeration `keys` of the reproduced EC, in the order the iterator
/// yields them. The initial state is `(message_ec.clone(), empty)` (:277-278). The first Err ends it.
pub open spec fn merge_fold(m: Ec, r: Ec, keys: Seq<Str>) -> Result<Merged, Str>
    decreases keys.len(),
{
    if keys.len() == 0 {
        Ok(Merged { ec: m, req: Set::empty() })
    } else {
        match merge_fold(m, r, keys.drop_last()) {
            Err(k) => Err(k),
            Ok(acc) => step(m, r, acc, keys.last()),
        }
    }
}

/// A_ITER: `keys` lists every key of `r` (a repeat would be allowed, see lemma_fold_char).
pub open spec fn enumerates(r: Ec, keys: Seq<Str>) -> bool {
    forall|k: Str| #[trigger] keys.contains(k) <==> r.contains_key(k)
}

/// The whole function (:273-304). `keys` is only used in the Some case.
pub open spec fn merge_spec(m: Ec, r: Option<Ec>, keys: Seq<Str>) -> Result<Merged, Str> {
    match r {
        None => Ok(Merged { ec: m, req: Set::empty() }),
        Some(rr) => merge_fold(m, rr, keys),
    }
}

/// The spec text, written without the loop (cmm-interface.md :157-159, :172-182; T12 YAML formal_spec).
pub open spec fn spec_union(m: Ec, r: Ec) -> Ec {
    m.union_prefer_right(r)
}

pub open spec fn spec_req(m: Ec, r: Ec) -> Set<Str> {
    r.dom().difference(m.dom())
}

// ============================================================
// SECTION 3: Characterization of the loop (induction over the enumeration)
// ============================================================

proof fn lemma_contains_drop_last(keys: Seq<Str>, x: Str)
    requires
        keys.len() > 0,
    ensures
        keys.contains(x) <==> (keys.drop_last().contains(x) || x == keys.last()),
{
    if keys.contains(x) {
        let i = choose|i: int| 0 <= i < keys.len() && keys[i] == x;
        if i < keys.len() - 1 {
            assert(keys.drop_last()[i] == x);
        }
    }
    if keys.drop_last().contains(x) {
        let i = choose|i: int| 0 <= i < keys.drop_last().len() && keys.drop_last()[i] == x;
        assert(keys[i] == x);
    }
}

/// For ANY list of keys of `r` (no distinctness, no completeness, any order) the loop returns:
///   Ok(res):  no listed key conflicts; res.ec has exactly the keys of m and the listed keys; a key of m
///             keeps m's value, every other key has r's value; res.req is the listed keys that are not in m.
///   Err(k):   k is listed and conflicts, and it is the first conflicting key in the list.
proof fn lemma_fold_char(m: Ec, r: Ec, keys: Seq<Str>)
    requires
        forall|i: int| 0 <= i < keys.len() ==> #[trigger] r.contains_key(keys[i]),
    ensures
        match merge_fold(m, r, keys) {
            Ok(res) => {
                &&& forall|k: Str| #[trigger] keys.contains(k) ==> !conflict(m, r, k)
                &&& forall|k: Str| #[trigger] res.ec.contains_key(k)
                        <==> (m.contains_key(k) || keys.contains(k))
                &&& forall|k: Str| res.ec.contains_key(k) ==> #[trigger] res.ec[k]
                        == (if m.contains_key(k) { m[k] } else { r[k] })
                &&& forall|k: Str| #[trigger] res.req.contains(k)
                        <==> (keys.contains(k) && !m.contains_key(k))
            },
            Err(k) => {
                &&& keys.contains(k)
                &&& conflict(m, r, k)
                &&& exists|i: int|
                        0 <= i < keys.len() && keys[i] == k
                        && (forall|j: int| 0 <= j < i ==> !conflict(m, r, #[trigger] keys[j]))
            },
        },
    decreases keys.len(),
{
    if keys.len() == 0 {
        assert forall|k: Str| !keys.contains(k) by {}
    } else {
        let init = keys.drop_last();
        let last = keys.last();
        assert forall|i: int| 0 <= i < init.len() implies #[trigger] r.contains_key(init[i]) by {
            assert(init[i] == keys[i]);
        }
        assert(r.contains_key(last));
        lemma_fold_char(m, r, init);
        assert forall|x: Str| keys.contains(x) <==> (init.contains(x) || x == last) by {
            lemma_contains_drop_last(keys, x);
        }
        match merge_fold(m, r, init) {
            Err(k0) => {
                let i0 = choose|i: int|
                    0 <= i < init.len() && init[i] == k0
                    && (forall|j: int| 0 <= j < i ==> !conflict(m, r, #[trigger] init[j]));
                assert(keys[i0] == k0);
                assert forall|j: int| 0 <= j < i0 implies !conflict(m, r, #[trigger] keys[j]) by {
                    assert(keys[j] == init[j]);
                }
                assert(keys.contains(k0));
            },
            Ok(acc) => {
                if m.contains_key(last) {
                    if m[last] != r[last] {
                        // Err(last): the first conflict is at the last index
                        let n = keys.len() - 1;
                        assert(keys[n] == last);
                        assert forall|j: int| 0 <= j < n implies !conflict(m, r, #[trigger] keys[j]) by {
                            assert(keys[j] == init[j]);
                            assert(init.contains(keys[j]));
                        }
                    } else {
                        assert forall|k: Str| #[trigger] keys.contains(k) implies !conflict(m, r, k) by {
                            if init.contains(k) {
                            } else {
                                assert(k == last);
                            }
                        }
                    }
                } else {
                    assert forall|k: Str| #[trigger] keys.contains(k) implies !conflict(m, r, k) by {
                        if init.contains(k) {
                        } else {
                            assert(k == last);
                        }
                    }
                }
            },
        }
    }
}

// ============================================================
// SECTION 4: The theorems about the function (P0 to P3)
// ============================================================

/// P0: no reproduced EC. The definition of the model written back (a consistency check).
proof fn theorem_t12_none(m: Ec, keys: Seq<Str>)
    ensures
        merge_spec(m, None, keys) == Ok::<Merged, Str>(Merged { ec: m, req: Set::empty() }),
{
}

/// The keys of `r` are keys of any enumeration of `r`.
proof fn lemma_enum_in_r(r: Ec, keys: Seq<Str>)
    requires
        enumerates(r, keys),
    ensures
        forall|i: int| 0 <= i < keys.len() ==> #[trigger] r.contains_key(keys[i]),
{
    assert forall|i: int| 0 <= i < keys.len() implies #[trigger] r.contains_key(keys[i]) by {
        assert(keys.contains(keys[i]));
    }
}

/// P1: Ok exactly when the contexts agree on every shared key.
proof fn theorem_t12_ok_iff(m: Ec, r: Ec, keys: Seq<Str>)
    requires
        enumerates(r, keys),
    ensures
        (merge_spec(m, Some(r), keys) is Ok) <==> agree(m, r),
        (merge_spec(m, Some(r), keys) is Err) <==> (exists|k: Str| conflict(m, r, k)),
{
    lemma_enum_in_r(r, keys);
    lemma_fold_char(m, r, keys);
    match merge_fold(m, r, keys) {
        Ok(res) => {
            assert forall|k: Str| !(#[trigger] conflict(m, r, k)) by {
                if conflict(m, r, k) {
                    assert(keys.contains(k));
                }
            }
        },
        Err(k) => {
            assert(conflict(m, r, k));
        },
    }
    if exists|k: Str| conflict(m, r, k) {
        assert(!agree(m, r));
    }
}

/// P1: an error names a real conflict, and it is the first one in the enumeration order.
proof fn theorem_t12_err_is_conflict(m: Ec, r: Ec, keys: Seq<Str>)
    requires
        enumerates(r, keys),
    ensures
        match merge_spec(m, Some(r), keys) {
            Err(k) => {
                &&& m.contains_key(k)
                &&& r.contains_key(k)
                &&& m[k] != r[k]
                &&& exists|i: int|
                        0 <= i < keys.len() && keys[i] == k
                        && (forall|j: int| 0 <= j < i ==> !conflict(m, r, #[trigger] keys[j]))
            },
            Ok(_) => true,
        },
{
    lemma_enum_in_r(r, keys);
    lemma_fold_char(m, r, keys);
}

/// P2: the result of a successful merge.
proof fn theorem_t12_ok_result(m: Ec, r: Ec, keys: Seq<Str>)
    requires
        enumerates(r, keys),
    ensures
        match merge_spec(m, Some(r), keys) {
            Ok(res) => {
                // domain: exactly the union of the two domains, nothing else
                &&& forall|k: Str| #[trigger] res.ec.contains_key(k)
                        <==> (m.contains_key(k) || r.contains_key(k))
                // no message key lost or changed
                &&& forall|k: Str| #[trigger] m.contains_key(k)
                        ==> res.ec.contains_key(k) && res.ec[k] == m[k]
                // every reproduced pair present with its value
                &&& forall|k: Str| #[trigger] r.contains_key(k)
                        ==> res.ec.contains_key(k) && res.ec[k] == r[k]
                // equals the spec union, in both argument orders
                &&& res.ec =~= spec_union(m, r)
                &&& res.ec =~= r.union_prefer_right(m)
                // required keys: exactly the reproduced keys absent from the message EC
                &&& res.req =~= spec_req(m, r)
                &&& forall|k: Str| #[trigger] res.req.contains(k)
                        ==> res.ec.contains_key(k) && !m.contains_key(k) && r.contains_key(k)
                // and exactly the keys the merge added to the message EC
                &&& res.req =~= res.ec.dom().difference(m.dom())
            },
            Err(_) => true,
        },
{
    lemma_enum_in_r(r, keys);
    lemma_fold_char(m, r, keys);
    match merge_fold(m, r, keys) {
        Ok(res) => {
            assert forall|k: Str| #[trigger] res.ec.contains_key(k)
                <==> (m.contains_key(k) || r.contains_key(k)) by {
                assert(keys.contains(k) <==> r.contains_key(k));
            }
            assert forall|k: Str| #[trigger] m.contains_key(k)
                implies res.ec.contains_key(k) && res.ec[k] == m[k] by {}
            assert forall|k: Str| #[trigger] r.contains_key(k)
                implies res.ec.contains_key(k) && res.ec[k] == r[k] by {
                assert(keys.contains(k));
                assert(!conflict(m, r, k));
            }
            assert(res.ec.dom() =~= m.dom().union(r.dom())) by {
                assert forall|k: Str| #![auto] res.ec.dom().contains(k) <==> m.dom().union(r.dom()).contains(k) by {
                    assert(res.ec.contains_key(k) <==> (m.contains_key(k) || r.contains_key(k)));
                }
            }
            assert(res.ec =~= spec_union(m, r)) by {
                assert forall|k: Str| #![auto] res.ec.dom().contains(k) <==> spec_union(m, r).dom().contains(k) by {}
                assert forall|k: Str| res.ec.dom().contains(k)
                    implies #[trigger] res.ec[k] == spec_union(m, r)[k] by {
                    assert(spec_union(m, r)[k] == if r.dom().contains(k) { r[k] } else { m[k] });
                    if r.contains_key(k) {
                        assert(keys.contains(k));
                        assert(!conflict(m, r, k));
                    }
                }
            }
            assert(res.ec =~= r.union_prefer_right(m)) by {
                assert forall|k: Str| #![auto] res.ec.dom().contains(k) <==> r.union_prefer_right(m).dom().contains(k) by {}
                assert forall|k: Str| res.ec.dom().contains(k)
                    implies #[trigger] res.ec[k] == r.union_prefer_right(m)[k] by {
                    assert(r.union_prefer_right(m)[k] == if m.dom().contains(k) { m[k] } else { r[k] });
                }
            }
            assert(res.req =~= spec_req(m, r)) by {
                assert forall|k: Str| #![auto] res.req.contains(k) <==> spec_req(m, r).contains(k) by {
                    assert(keys.contains(k) <==> r.contains_key(k));
                }
            }
            assert(res.req =~= res.ec.dom().difference(m.dom())) by {
                assert forall|k: Str| #![auto] res.req.contains(k) <==> res.ec.dom().difference(m.dom()).contains(k) by {
                    assert(keys.contains(k) <==> r.contains_key(k));
                }
            }
            assert forall|k: Str| #[trigger] res.req.contains(k)
                implies res.ec.contains_key(k) && !m.contains_key(k) && r.contains_key(k) by {
                assert(keys.contains(k));
            }
        },
        Err(_) => {},
    }
}

/// P3: the verdict and the result do not depend on the iteration order.
proof fn theorem_t12_order_independent(m: Ec, r: Ec, keys1: Seq<Str>, keys2: Seq<Str>)
    requires
        enumerates(r, keys1),
        enumerates(r, keys2),
    ensures
        (merge_spec(m, Some(r), keys1) is Ok) == (merge_spec(m, Some(r), keys2) is Ok),
        match (merge_spec(m, Some(r), keys1), merge_spec(m, Some(r), keys2)) {
            (Ok(a), Ok(b)) => a.ec =~= b.ec && a.req =~= b.req,
            _ => true,
        },
{
    theorem_t12_ok_iff(m, r, keys1);
    theorem_t12_ok_iff(m, r, keys2);
    theorem_t12_ok_result(m, r, keys1);
    theorem_t12_ok_result(m, r, keys2);
}

// ============================================================
// SECTION 5: Argument order, the key named in an error, and corollaries
// ============================================================

/// The merged EC does not depend on which context is called "message" and which "reproduced",
/// when they agree.
proof fn lemma_union_symmetric(m: Ec, r: Ec)
    requires
        agree(m, r),
    ensures
        m.union_prefer_right(r) =~= r.union_prefer_right(m),
{
    assert forall|k: Str| m.union_prefer_right(r).dom().contains(k)
        <==> r.union_prefer_right(m).dom().contains(k) by {}
    assert forall|k: Str| m.union_prefer_right(r).dom().contains(k)
        implies #[trigger] m.union_prefer_right(r)[k] == r.union_prefer_right(m)[k] by {
        assert(!conflict(m, r, k));
    }
}

proof fn lemma_witness_strs()
    ensures
        seq!['a'] != seq!['b'],
        seq!['x'] != seq!['y'],
{
    assert(seq!['a'][0] != seq!['b'][0]);
    assert(seq!['x'][0] != seq!['y'][0]);
}

/// The required keys are not symmetric: they are the keys of the second argument that the first lacks.
proof fn lemma_req_asymmetric()
    ensures
        ({
            let a = Map::<Str, Str>::empty().insert(seq!['a'], seq!['x']);
            let b = Map::<Str, Str>::empty().insert(seq!['b'], seq!['x']);
            &&& spec_req(a, b).contains(seq!['b'])
            &&& !spec_req(b, a).contains(seq!['b'])
        }),
{
    lemma_witness_strs();
}

/// O1: the KEY named in the error depends on the enumeration order. Two conflicting keys, two orders.
proof fn lemma_error_key_depends_on_order()
    ensures
        ({
            let ka = seq!['a'];
            let kb = seq!['b'];
            let m = Map::<Str, Str>::empty().insert(ka, seq!['x']).insert(kb, seq!['x']);
            let r = Map::<Str, Str>::empty().insert(ka, seq!['y']).insert(kb, seq!['y']);
            &&& enumerates(r, seq![ka, kb])
            &&& enumerates(r, seq![kb, ka])
            &&& merge_spec(m, Some(r), seq![ka, kb]) == Err::<Merged, Str>(ka)
            &&& merge_spec(m, Some(r), seq![kb, ka]) == Err::<Merged, Str>(kb)
        }),
{
    lemma_witness_strs();
    let ka = seq!['a'];
    let kb = seq!['b'];
    let m = Map::<Str, Str>::empty().insert(ka, seq!['x']).insert(kb, seq!['x']);
    let r = Map::<Str, Str>::empty().insert(ka, seq!['y']).insert(kb, seq!['y']);
    let k1 = seq![ka, kb];
    let k2 = seq![kb, ka];
    assert(enumerates(r, k1)) by {
        assert forall|k: Str| #[trigger] k1.contains(k) <==> r.contains_key(k) by {
            if k1.contains(k) {
                assert(k == k1[0] || k == k1[1]);
            }
            if r.contains_key(k) {
                assert(k == ka || k == kb);
                if k == ka { assert(k1[0] == k); } else { assert(k1[1] == k); }
            }
        }
    }
    assert(enumerates(r, k2)) by {
        assert forall|k: Str| #[trigger] k2.contains(k) <==> r.contains_key(k) by {
            if k2.contains(k) {
                assert(k == k2[0] || k == k2[1]);
            }
            if r.contains_key(k) {
                assert(k == ka || k == kb);
                if k == ka { assert(k2[1] == k); } else { assert(k2[0] == k); }
            }
        }
    }
    assert(conflict(m, r, ka));
    assert(conflict(m, r, kb));
    theorem_t12_err_is_conflict(m, r, k1);
    theorem_t12_err_is_conflict(m, r, k2);
    // first conflict in each order: index 0 is the only index with no earlier agreeing key
    match merge_spec(m, Some(r), k1) {
        Err(k) => {
            let i = choose|i: int| 0 <= i < k1.len() && k1[i] == k
                && (forall|j: int| 0 <= j < i ==> !conflict(m, r, #[trigger] k1[j]));
            if i == 1 { assert(conflict(m, r, k1[0])); }
            assert(k == ka);
        },
        Ok(_) => {
            theorem_t12_ok_iff(m, r, k1);
        },
    }
    match merge_spec(m, Some(r), k2) {
        Err(k) => {
            let i = choose|i: int| 0 <= i < k2.len() && k2[i] == k
                && (forall|j: int| 0 <= j < i ==> !conflict(m, r, #[trigger] k2[j]));
            if i == 1 { assert(conflict(m, r, k2[0])); }
            assert(k == kb);
        },
        Ok(_) => {
            theorem_t12_ok_iff(m, r, k2);
        },
    }
}

/// P4: special cases the tests exercise, and re-merging.
proof fn lemma_corollaries(m: Ec, r: Ec, keys: Seq<Str>)
    requires
        enumerates(r, keys),
    ensures
        // empty reproduced EC: the message EC and no required key
        r =~= Map::<Str, Str>::empty() ==> (merge_spec(m, Some(r), keys) is Ok
            && merge_spec(m, Some(r), keys)->Ok_0.ec =~= m
            && merge_spec(m, Some(r), keys)->Ok_0.req =~= Set::<Str>::empty()),
        // reproduced EC contained in the message EC (every reproduced pair is already there): the
        // message EC is returned unchanged, with no required key
        (forall|k: Str| #[trigger] r.contains_key(k) ==> m.contains_key(k) && m[k] == r[k])
            ==> (merge_spec(m, Some(r), keys) is Ok
                && merge_spec(m, Some(r), keys)->Ok_0.ec =~= m
                && merge_spec(m, Some(r), keys)->Ok_0.req =~= Set::<Str>::empty()),
        // empty message EC: the reproduced EC, and every reproduced key is required
        m =~= Map::<Str, Str>::empty() ==> (merge_spec(m, Some(r), keys) is Ok
            && merge_spec(m, Some(r), keys)->Ok_0.ec =~= r
            && merge_spec(m, Some(r), keys)->Ok_0.req =~= r.dom()),
{
    theorem_t12_ok_iff(m, r, keys);
    theorem_t12_ok_result(m, r, keys);
    if r =~= Map::<Str, Str>::empty() {
        assert(agree(m, r));
        let res = merge_spec(m, Some(r), keys)->Ok_0;
        assert(res.ec =~= m) by {
            assert forall|k: Str| #![auto] res.ec.contains_key(k) <==> m.contains_key(k) by {}
            assert forall|k: Str| m.contains_key(k) implies #[trigger] res.ec[k] == m[k] by {}
        }
        assert(res.req =~= Set::<Str>::empty()) by {
            assert forall|k: Str| !res.req.contains(k) by {}
        }
    }
    if forall|k: Str| #[trigger] r.contains_key(k) ==> m.contains_key(k) && m[k] == r[k] {
        assert forall|k: Str| !(#[trigger] conflict(m, r, k)) by {}
        let res = merge_spec(m, Some(r), keys)->Ok_0;
        assert(res.ec =~= m) by {
            assert forall|k: Str| #![auto] res.ec.contains_key(k) <==> m.contains_key(k) by {
                if res.ec.contains_key(k) && !m.contains_key(k) { assert(r.contains_key(k)); }
            }
            assert forall|k: Str| m.contains_key(k) implies #[trigger] res.ec[k] == m[k] by {}
        }
        assert(res.req =~= Set::<Str>::empty()) by {
            assert forall|k: Str| !res.req.contains(k) by {
                if res.req.contains(k) { assert(r.contains_key(k)); }
            }
        }
    }
    if m =~= Map::<Str, Str>::empty() {
        assert forall|k: Str| !(#[trigger] conflict(m, r, k)) by {}
        let res = merge_spec(m, Some(r), keys)->Ok_0;
        assert(res.ec =~= r) by {
            assert forall|k: Str| #![auto] res.ec.contains_key(k) <==> r.contains_key(k) by {}
            assert forall|k: Str| r.contains_key(k) implies #[trigger] res.ec[k] == r[k] by {}
        }
        assert(res.req =~= r.dom()) by {
            assert forall|k: Str| res.req.contains(k) <==> r.dom().contains(k) by {}
        }
    }
}

/// P4: merging the result with the same reproduced EC again succeeds, changes nothing and requires
/// nothing new.
proof fn lemma_remerge_is_noop(m: Ec, r: Ec, keys: Seq<Str>, keys2: Seq<Str>)
    requires
        enumerates(r, keys),
        enumerates(r, keys2),
        merge_spec(m, Some(r), keys) is Ok,
    ensures
        ({
            let res = merge_spec(m, Some(r), keys)->Ok_0;
            &&& merge_spec(res.ec, Some(r), keys2) is Ok
            &&& merge_spec(res.ec, Some(r), keys2)->Ok_0.ec =~= res.ec
            &&& merge_spec(res.ec, Some(r), keys2)->Ok_0.req =~= Set::<Str>::empty()
        }),
{
    theorem_t12_ok_result(m, r, keys);
    let res = merge_spec(m, Some(r), keys)->Ok_0;
    assert forall|k: Str| !(#[trigger] conflict(res.ec, r, k)) by {
        if r.contains_key(k) {
            assert(res.ec[k] == r[k]);
        }
    }
    theorem_t12_ok_iff(res.ec, r, keys2);
    theorem_t12_ok_result(res.ec, r, keys2);
    let res2 = merge_spec(res.ec, Some(r), keys2)->Ok_0;
    assert(res2.ec =~= res.ec) by {
        assert forall|k: Str| res2.ec.contains_key(k) <==> res.ec.contains_key(k) by {
            if r.contains_key(k) { assert(res.ec.contains_key(k)); }
        }
        assert forall|k: Str| res.ec.contains_key(k) implies #[trigger] res2.ec[k] == res.ec[k] by {}
    }
    assert(res2.req =~= Set::<Str>::empty()) by {
        assert forall|k: Str| !res2.req.contains(k) by {
            if res2.req.contains(k) {
                assert(r.contains_key(k));
                assert(res.ec.contains_key(k));
            }
        }
    }
}

// ============================================================
// SECTION 6: Non-vacuity, the builder check, a concrete Ok case
// ============================================================

pub open spec fn set_enumerates(s: Set<Str>, keys: Seq<Str>) -> bool {
    forall|k: Str| #[trigger] keys.contains(k) <==> s.contains(k)
}

/// A_ITER is satisfiable: every map has an enumeration (vstd Maps are finite, as is a BTreeMap).
proof fn lemma_enum_exists_set(s: Set<Str>)
    ensures
        exists|keys: Seq<Str>| #[trigger] set_enumerates(s, keys),
    decreases s.len(),
{
    if s.len() == 0 {
        let keys = Seq::<Str>::empty();
        assert(set_enumerates(s, keys)) by {
            assert forall|k: Str| #[trigger] keys.contains(k) <==> s.contains(k) by {
                assert(!keys.contains(k));
                assert(!s.contains(k));
            }
        }
    } else {
        let x = s.choose();
        let s2 = s.remove(x);
        lemma_enum_exists_set(s2);
        let k2 = choose|k2: Seq<Str>| #[trigger] set_enumerates(s2, k2);
        let keys = k2.push(x);
        assert(keys.drop_last() =~= k2);
        assert(keys.last() == x);
        assert(set_enumerates(s, keys)) by {
            assert forall|k: Str| #[trigger] keys.contains(k) <==> s.contains(k) by {
                lemma_contains_drop_last(keys, k);
            }
        }
    }
}

proof fn lemma_enum_exists(r: Ec)
    ensures
        exists|keys: Seq<Str>| enumerates(r, keys),
{
    lemma_enum_exists_set(r.dom());
    let keys = choose|keys: Seq<Str>| #[trigger] set_enumerates(r.dom(), keys);
    assert(enumerates(r, keys));
}

/// P6: the output of a successful merge passes the subset check of `DecryptionMaterials::build`
/// (:307-316): every required key is a key of the EC.
proof fn lemma_builder_check_cannot_fire(m: Ec, r: Ec, keys: Seq<Str>)
    requires
        enumerates(r, keys),
        merge_spec(m, Some(r), keys) is Ok,
    ensures
        ({
            let res = merge_spec(m, Some(r), keys)->Ok_0;
            forall|k: Str| #[trigger] res.req.contains(k) ==> res.ec.contains_key(k)
        }),
{
    theorem_t12_ok_result(m, r, keys);
}

/// A concrete Ok case: m = {a: x}, r = {a: x, b: y}. Result {a: x, b: y}, required {b}.
proof fn lemma_witness_ok()
    ensures
        ({
            let ka = seq!['a'];
            let kb = seq!['b'];
            let m = Map::<Str, Str>::empty().insert(ka, seq!['x']);
            let r = Map::<Str, Str>::empty().insert(ka, seq!['x']).insert(kb, seq!['y']);
            let keys = seq![ka, kb];
            &&& enumerates(r, keys)
            &&& merge_spec(m, Some(r), keys) is Ok
            &&& merge_spec(m, Some(r), keys)->Ok_0.ec.contains_key(kb)
            &&& merge_spec(m, Some(r), keys)->Ok_0.ec[kb] == seq!['y']
            &&& merge_spec(m, Some(r), keys)->Ok_0.ec[ka] == seq!['x']
            &&& merge_spec(m, Some(r), keys)->Ok_0.req.contains(kb)
            &&& !merge_spec(m, Some(r), keys)->Ok_0.req.contains(ka)
        }),
{
    lemma_witness_strs();
    let ka = seq!['a'];
    let kb = seq!['b'];
    let m = Map::<Str, Str>::empty().insert(ka, seq!['x']);
    let r = Map::<Str, Str>::empty().insert(ka, seq!['x']).insert(kb, seq!['y']);
    let keys = seq![ka, kb];
    assert(enumerates(r, keys)) by {
        assert forall|k: Str| #[trigger] keys.contains(k) <==> r.contains_key(k) by {
            if keys.contains(k) {
                assert(k == keys[0] || k == keys[1]);
            }
            if r.contains_key(k) {
                assert(k == ka || k == kb);
                if k == ka { assert(keys[0] == k); } else { assert(keys[1] == k); }
            }
        }
    }
    assert(agree(m, r)) by {
        assert forall|k: Str| !(#[trigger] conflict(m, r, k)) by {
            if m.contains_key(k) { assert(k == ka); }
        }
    }
    theorem_t12_ok_iff(m, r, keys);
    theorem_t12_ok_result(m, r, keys);
    assert(keys.contains(kb)) by { assert(keys[1] == kb); }
}

/// The concrete Err case is the one in lemma_error_key_depends_on_order; a one-key version here.
proof fn lemma_witness_conflict()
    ensures
        ({
            let ka = seq!['a'];
            let m = Map::<Str, Str>::empty().insert(ka, seq!['x']);
            let r = Map::<Str, Str>::empty().insert(ka, seq!['y']);
            let keys = seq![ka];
            &&& enumerates(r, keys)
            &&& merge_spec(m, Some(r), keys) == Err::<Merged, Str>(ka)
        }),
{
    lemma_witness_strs();
    let ka = seq!['a'];
    let m = Map::<Str, Str>::empty().insert(ka, seq!['x']);
    let r = Map::<Str, Str>::empty().insert(ka, seq!['y']);
    let keys = seq![ka];
    assert(enumerates(r, keys)) by {
        assert forall|k: Str| #[trigger] keys.contains(k) <==> r.contains_key(k) by {
            if keys.contains(k) { assert(k == keys[0]); }
            if r.contains_key(k) { assert(k == ka); assert(keys[0] == k); }
        }
    }
    assert(conflict(m, r, ka));
    theorem_t12_err_is_conflict(m, r, keys);
    theorem_t12_ok_iff(m, r, keys);
}

} // verus!
fn main() {}
