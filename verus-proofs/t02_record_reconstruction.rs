// =============================================================================
// VR-2026-T02 (TM-MPL-005): exact Ok/Err characterization of
//   record::branch_key_materials_from_authenticated_encryption_context
//
// Run:  ~/verus/verus verus-proofs/t02_record_reconstruction.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// -----------------------------------------------------------------------------
// STATUS (see the log in .agents/tasks/verus-proofs-quickwins/logs/): PARTLY PROVED.
//   * Everything verifies except one obligation: sections 1-6 and 8, and the completeness
//     lemma in section 7, are accepted by Verus.
//   * Section 7 contains ONE obligation that Verus REJECTS on purpose:
//     `lemma_g1_spec_soundness_FAILS`. It is the spec-faithful property
//     "Ok  ==>  the record has create-time and hierarchy-version"
//     (spec/framework/branch-key-store.md :677, :690, :692, and the MUST-fail
//     sentences :531, :553, :574). The shipped code does NOT enforce it
//     (audit gap G1). That is a FINDING, not a proof bug. The failing lemma is
//     left visible and is not weakened. Section 8 proves what the code does
//     satisfy, and proves, positively, that the code accepts records without
//     the two fields.
//
// -----------------------------------------------------------------------------
// WHAT IS MODELED (source of truth, repo esdk-native-mpl, HEAD 66aba1c;
// mpl/ and prim/ identical to main 620771c)
//
//   mpl/src/key_store/record.rs
//     :95-184  branch_key_materials_from_authenticated_encryption_context
//     :79-91   custom_encryption_context_from_authenticated_encryption_context
//     :188-    malformed()  (error construction only; see "not covered")
//   mpl/src/key_store/attributes.rs :11-24   attribute names and prefixes
//   mpl/src/structures/branch_key_materials.rs :173-189  BranchKeyMaterialsBuilder::build
//   mpl/src/builder.rs :7-9                              required()
//
// CORRESPONDENCE TABLE (model item  <->  shipped code)
//
//   model                         code (mpl/src/key_store/record.rs unless noted)
//   ----------------------------  ------------------------------------------------
//   Ec = Map<Str,Str>             authenticated_ec: &BTreeMap<String,String>
//                                 (String := its Seq<char> view; BTreeMap := its Map view)
//   Str = Seq<char>               String / &str. Prefix tests are byte tests in Rust;
//                                 for UTF-8 a byte-prefix test and a char-prefix test
//                                 agree, and is_empty() <=> len()==0 in both views.
//   get(ec,k)                     BTreeMap::get (:101, :121, :152)
//   step_type                     :101-106  get(ATTR_TYPE).ok_or_else(malformed)?
//                                           -> Err(MissingType)
//                                 :108-116  type != ACTIVE && !starts_with(VERSION_PREFIX)
//                                           -> Err(BadTypeValue)
//   step_version_string           :119-131  ACTIVE -> get(ATTR_VERSION)?.clone()
//                                           (missing -> Err(MissingVersionForActive));
//                                           otherwise type_attr.clone()
//   step_version                  :137-149  strip_prefix(VERSION_PREFIX)
//                                           .filter(non-empty).ok_or_else(malformed)?
//                                           -> Err(BadVersionString)
//   step_branch_key_id            :151-159  get(ATTR_BRANCH_KEY_ID)?  -> Err(MissingBranchKeyId)
//   custom_ec / custom_fold       :161-162 -> :79-91 (loop over the map, strip_prefix,
//                                 insert). Infallible (always Ok(ec)), so it adds no Err
//                                 site. custom_fold models the loop for ANY iteration order;
//                                 lemma_fold_eq_custom ties it to the comprehension custom_ec.
//   step_key                      :164-172  <[u8;32]>::try_from(slice) else Err
//                                           -> Err(BadKeyLength)
//   step_build                    :175-183  BranchKeyMaterials::builder()...build()
//                                           .map_err(malformed)  ; build() is
//                                 branch_key_materials.rs:173-189: empty branch_key_id
//                                 -> Err (-> Err(BuilderRejectedEmptyId)); empty version
//                                 -> Err (-> Err(BuilderRejectedEmptyVersion), unreachable,
//                                 proved in lemma_empty_version_unreachable). The four
//                                 required() calls cannot fail: every field is Some.
//   Materials                     BranchKeyMaterials { branch_key:[u8;32], branch_key_id,
//                                 branch_key_version, encryption_context }
//   kind_of(_) = InvalidMaterials every Err site above goes through malformed()
//                                 (Error::new(Kind::InvalidMaterials, ..)); .with_source()
//                                 (generated.rs:924) only sets the source and keeps the kind.
//   Zeroizing wrappers (:100,:173)  functionally the identity; not modeled.
//
// Error-site audit for kind_of: the target has exactly 7 error sites (:101-106, :108-116,
// :119-128, :137-148, :151-158, :164-172, :175-183). The last one covers two model
// variants (empty id / empty version, from build()). custom_encryption_context_... (:90)
// never returns Err. All 7 sites build their error with malformed(), i.e.
// Error::new(Kind::InvalidMaterials, ..). The "kind" half of theorem C is therefore true
// by construction of kind_of; the audit above is what ties it to the code.
//
// -----------------------------------------------------------------------------
// TRUSTED ASSUMPTIONS (TCB)
//   * No `assume`, `admit`, `external_body`, `assume_specification`, or uninterpreted
//     spec function is used in this file. The only trusted base is Verus itself, Z3 and
//     vstd's own axioms for Seq/Map/Set.
//   * The MODEL IS TRUSTED TO MATCH THE CODE. That is a human-reviewed claim, backed by the
//     table above, not a machine-checked refinement (see next section).
//   * The constants below are transcribed from attributes.rs :11-24 by hand. They were
//     cross-checked with grep (see t02-notes.md); Verus cannot read them from the crate.
//
// -----------------------------------------------------------------------------
// MODEL-vs-CODE GAP (read this before citing the result)
//   A proof about a re-typed model is not a proof about the shipped code. The shipped
//   function is native Rust over BTreeMap<String,String>, Vec<u8>, Zeroizing, async-free
//   but bound to the crate's Error/BranchKeyMaterials types. It is not inside `verus!`
//   and is not compiled by this file. Nothing here can detect a future edit to record.rs.
//   To close the gap one would need ALL of:
//     1. the function (and attributes.rs consts) moved inside `verus!` or checked with
//        `cargo verus` against the real crate;
//     2. specs for BTreeMap::{get,iter,insert} with `&str` borrowed lookup on `String`
//        keys (vstd has them only for Key == Q and Box<Q>, not String/str), for
//        str::{starts_with,strip_prefix,is_empty}, String::clone,
//        <[u8;32]>::try_from(&[u8]), and for Zeroizing<T> deref;
//     3. a view axiom that String::deep_view is injective (so Map<String,_> and
//        Map<Seq<char>,_> agree), which vstd does not provide;
//     4. a spec for Error::new / BranchKeyMaterialsBuilder (or the model of them used here
//        proven against their source).
//   Until then the evidence level is: audited model + machine-checked logic.
//
// NOT COVERED
//   * Any other function. In particular record_from_ddb_item
//     (branch_key_store.rs:1141-1200) and decrypt_branch_key (kms_ops.rs:172): that is
//     where "the record contains the defined fields, else MUST fail" could be enforced,
//     and T01 owns that path. kms-arn is enforced by decrypt_branch_key, not here.
//   * The message text / source / service / resource fields of the returned Error.
//   * malformed() panic-freedom (it only does get/strip_prefix/clone/format!).
//   * Zeroization of the plaintext key; allocation failure; BTreeMap ordering.
//   * That the key bytes came from a correct KMS decrypt, and rollback of an older
//     authentic record (TM-MPL-005 residual, a stated non-goal).
//   * structures.md: "Branch Key Version MUST be a version 4 UUID". The code accepts any
//     non-empty string after the prefix (observation O1 in t02-notes.md; not modeled).
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Types and constants
// ============================================================

pub type Str = Seq<char>;
pub type Ec = Map<Str, Str>;

/// The record attribute names and prefixes (attributes.rs :11-24).
pub open spec fn k_type() -> Str { seq!['t', 'y', 'p', 'e'] }
pub open spec fn k_version() -> Str { seq!['v', 'e', 'r', 's', 'i', 'o', 'n'] }
pub open spec fn k_id() -> Str {
    seq!['b', 'r', 'a', 'n', 'c', 'h', '-', 'k', 'e', 'y', '-', 'i', 'd']
}
pub open spec fn k_create_time() -> Str {
    seq!['c', 'r', 'e', 'a', 't', 'e', '-', 't', 'i', 'm', 'e']
}
pub open spec fn k_hierarchy_version() -> Str {
    seq!['h', 'i', 'e', 'r', 'a', 'r', 'c', 'h', 'y', '-', 'v', 'e', 'r', 's', 'i', 'o', 'n']
}
/// TYPE_BRANCH_ACTIVE = "branch:ACTIVE"
pub open spec fn type_active() -> Str {
    seq!['b', 'r', 'a', 'n', 'c', 'h', ':', 'A', 'C', 'T', 'I', 'V', 'E']
}
/// TYPE_BRANCH_VERSION_PREFIX = "branch:version:"
pub open spec fn version_prefix() -> Str {
    seq!['b', 'r', 'a', 'n', 'c', 'h', ':', 'v', 'e', 'r', 's', 'i', 'o', 'n', ':']
}
/// CUSTOM_EC_PREFIX = "aws-crypto-ec:"
pub open spec fn custom_prefix() -> Str {
    seq!['a', 'w', 's', '-', 'c', 'r', 'y', 'p', 't', 'o', '-', 'e', 'c', ':']
}
/// TYPE_BEACON_ACTIVE = "beacon:ACTIVE" (rejected by this function; used in a corollary)
pub open spec fn type_beacon() -> Str {
    seq!['b', 'e', 'a', 'c', 'o', 'n', ':', 'A', 'C', 'T', 'I', 'V', 'E']
}

proof fn lemma_const_lens()
    ensures
        k_type().len() == 4,
        k_version().len() == 7,
        k_id().len() == 13,
        k_create_time().len() == 11,
        k_hierarchy_version().len() == 17,
        type_active().len() == 13,
        version_prefix().len() == 15,
        custom_prefix().len() == 14,
        type_beacon().len() == 13,
{
}

/// The fixed-size branch key length (structures.md "This key MUST be 32 bytes long").
pub open spec fn key_len() -> nat { 32 }

/// The error sites of the function. Every one maps to Kind::InvalidMaterials.
#[derive(PartialEq, Eq)]
pub enum Fail {
    MissingType,                // record.rs :101-106
    BadTypeValue,               // :108-116
    MissingVersionForActive,    // :119-128
    BadVersionString,           // :137-148 (bare prefix, wrong prefix)
    MissingBranchKeyId,         // :151-158
    BadKeyLength,               // :164-172
    BuilderRejectedEmptyId,     // :175-183 via branch_key_materials.rs :174-176
    BuilderRejectedEmptyVersion, // :175-183 via branch_key_materials.rs :178-180 (unreachable)
}

#[derive(PartialEq, Eq)]
pub enum Kind {
    InvalidMaterials,
}

/// Every error site calls malformed(), which is Error::new(Kind::InvalidMaterials, ..).
pub open spec fn kind_of(f: Fail) -> Kind { Kind::InvalidMaterials }

/// BranchKeyMaterials (branch_key_materials.rs :16-21). branch_key is a [u8;32] in Rust;
/// its length is carried explicitly here.
pub struct Materials {
    pub branch_key: Seq<u8>,
    pub branch_key_id: Str,
    pub branch_key_version: Str,
    pub encryption_context: Ec,
}

// ============================================================
// SECTION 2: Specification functions (the model of the code)
// ============================================================

pub open spec fn get(ec: Ec, k: Str) -> Option<Str> {
    if ec.contains_key(k) { Some(ec[k]) } else { None }
}

/// record.rs :101-116
pub open spec fn step_type(ec: Ec) -> Result<Str, Fail> {
    match get(ec, k_type()) {
        None => Err(Fail::MissingType),
        Some(ty) => {
            if ty != type_active() && !version_prefix().is_prefix_of(ty) {
                Err(Fail::BadTypeValue)
            } else {
                Ok(ty)
            }
        },
    }
}

/// record.rs :119-131
pub open spec fn step_version_string(ec: Ec, ty: Str) -> Result<Str, Fail> {
    if ty == type_active() {
        match get(ec, k_version()) {
            None => Err(Fail::MissingVersionForActive),
            Some(v) => Ok(v),
        }
    } else {
        Ok(ty)
    }
}

/// record.rs :137-149: strip_prefix(VERSION_PREFIX).filter(|v| !v.is_empty())
pub open spec fn step_version(vs: Str) -> Result<Str, Fail> {
    if version_prefix().is_prefix_of(vs) && vs.skip(version_prefix().len() as int).len() != 0 {
        Ok(vs.skip(version_prefix().len() as int))
    } else {
        Err(Fail::BadVersionString)
    }
}

/// record.rs :151-159
pub open spec fn step_branch_key_id(ec: Ec) -> Result<Str, Fail> {
    match get(ec, k_id()) {
        None => Err(Fail::MissingBranchKeyId),
        Some(id) => Ok(id),
    }
}

/// record.rs :164-172: <[u8;32]>::try_from(slice) is Ok exactly when the length is 32.
pub open spec fn step_key(pt: Seq<u8>) -> Result<Seq<u8>, Fail> {
    if pt.len() == key_len() { Ok(pt) } else { Err(Fail::BadKeyLength) }
}

/// record.rs :175-183 with branch_key_materials.rs :173-189 (build()).
/// build() checks id (:174-176), then version (:178-180); `required()` cannot fail.
pub open spec fn step_build(key: Seq<u8>, id: Str, ver: Str, ctx: Ec) -> Result<Materials, Fail> {
    if id.len() == 0 {
        Err(Fail::BuilderRejectedEmptyId)
    } else if ver.len() == 0 {
        Err(Fail::BuilderRejectedEmptyVersion)
    } else {
        Ok(Materials {
            branch_key: key,
            branch_key_id: id,
            branch_key_version: ver,
            encryption_context: ctx,
        })
    }
}

/// record.rs :79-91 as a set comprehension: the custom EC is exactly the entries whose key
/// starts with `aws-crypto-ec:`, with that prefix stripped. (custom_fold below is the loop.)
pub open spec fn custom_ec(ec: Ec) -> Ec {
    Map::new(
        ec.dom().map_by(
            |k: Str| k.skip(custom_prefix().len() as int),
            |s: Str| custom_prefix() + s,
        ),
        |s: Str| ec[custom_prefix() + s],
    )
}

/// The loop at record.rs :84-88 over an enumeration `keys` of the map's keys, in the order
/// the iterator yields them (BTreeMap iterates in sorted order; the model accepts ANY order).
pub open spec fn custom_fold(ec: Ec, keys: Seq<Str>) -> Ec
    decreases keys.len(),
{
    if keys.len() == 0 {
        Map::empty()
    } else {
        let acc = custom_fold(ec, keys.drop_last());
        let k = keys.last();
        if custom_prefix().is_prefix_of(k) {
            acc.insert(k.skip(custom_prefix().len() as int), ec[k])
        } else {
            acc
        }
    }
}

/// The whole function (record.rs :95-184), in the order the code executes its checks.
pub open spec fn reconstruct(ec: Ec, pt: Seq<u8>) -> Result<Materials, Fail> {
    match step_type(ec) {
        Err(f) => Err(f),
        Ok(ty) => match step_version_string(ec, ty) {
            Err(f) => Err(f),
            Ok(vs) => match step_version(vs) {
                Err(f) => Err(f),
                Ok(ver) => match step_branch_key_id(ec) {
                    Err(f) => Err(f),
                    Ok(id) => {
                        let ctx = custom_ec(ec);   // :161-162, infallible
                        match step_key(pt) {
                            Err(f) => Err(f),
                            Ok(key) => step_build(key, id, ver, ctx),
                        }
                    },
                },
            },
        },
    }
}

// ---- Predicates used in the properties ----

/// The version string source: `version` for an ACTIVE record, else the `type` itself.
/// Only meaningful when `type` (and `version` for ACTIVE) are present.
pub open spec fn ver_src(ec: Ec) -> Str {
    if ec[k_type()] == type_active() { ec[k_version()] } else { ec[k_type()] }
}

pub open spec fn strict_prefix(p: Str, s: Str) -> bool {
    p.len() < s.len() && p.is_prefix_of(s)
}

/// The exact Ok-condition of the SHIPPED code. Matches the YAML formal_spec of T02
/// except for the `branch-key-id` non-empty clause (the builder rejects an empty id).
pub open spec fn code_accepts(ec: Ec, pt: Seq<u8>) -> bool {
    &&& ec.contains_key(k_type())
    &&& (ec[k_type()] == type_active() || version_prefix().is_prefix_of(ec[k_type()]))
    &&& (ec[k_type()] == type_active() ==> ec.contains_key(k_version()))
    &&& strict_prefix(version_prefix(), ver_src(ec))
    &&& ec.contains_key(k_id())
    &&& ec[k_id()].len() > 0
    &&& pt.len() == key_len()
}

/// The SPEC-FAITHFUL Ok-condition (T02 property incl. completeness clause G1):
///   branch-key-store.md :593  branch-key-id MUST NOT be empty
///   branch-key-store.md :677-692 record MUST include create-time and hierarchy-version
///   branch-key-store.md :596, :599 the EC MUST have create-time and hierarchy-version
///   branch-key-store.md :531/:553/:574 record lacks defined fields => operation MUST fail
///   branch-key-store.md :698-707 type/version rules; structures.md :395 key is 32 bytes
pub open spec fn spec_accepts(ec: Ec, pt: Seq<u8>) -> bool {
    &&& code_accepts(ec, pt)
    &&& ec.contains_key(k_create_time())
    &&& ec.contains_key(k_hierarchy_version())
}

// ============================================================
// SECTION 3: Helper lemmas on prefixes and the custom-EC extraction
// ============================================================

/// p is a prefix of s  ==>  s == p + (s without p).
proof fn lemma_prefix_split(p: Str, s: Str)
    requires
        p.is_prefix_of(s),
    ensures
        s =~= p + s.skip(p.len() as int),
{
}

/// (p + w) starts with p and stripping p yields w.
proof fn lemma_concat_prefix(p: Str, w: Str)
    ensures
        p.is_prefix_of(p + w),
        (p + w).skip(p.len() as int) =~= w,
{
}

/// Membership in custom_ec: s is a custom-EC key exactly when `aws-crypto-ec:` + s is a key
/// of the authenticated EC, and its value is that key's value.
proof fn lemma_custom_ec_member(ec: Ec, s: Str)
    ensures
        custom_ec(ec).contains_key(s) <==> ec.contains_key(custom_prefix() + s),
        custom_ec(ec).contains_key(s) ==> custom_ec(ec)[s] == ec[custom_prefix() + s],
{
    broadcast use Set::lemma_map_by_contains;
    lemma_concat_prefix(custom_prefix(), s);
    let fwd = |k: Str| k.skip(custom_prefix().len() as int);
    let rev = |x: Str| custom_prefix() + x;
    assert(fwd(rev(s)) =~= s);
    assert(ec.dom().map_by(fwd, rev).contains(s) <==> ec.dom().contains(rev(s)) && s == fwd(rev(s)));
}

/// The loop's result, for any key enumeration contained in the map: a stripped key s is
/// present exactly when `aws-crypto-ec:` + s was enumerated, with the value of that key.
proof fn lemma_fold_char(ec: Ec, keys: Seq<Str>)
    requires
        forall|i: int| 0 <= i < keys.len() ==> #[trigger] ec.contains_key(keys[i]),
    ensures
        forall|s: Str| #[trigger] custom_fold(ec, keys).contains_key(s)
            <==> keys.contains(custom_prefix() + s),
        forall|s: Str| custom_fold(ec, keys).contains_key(s)
            ==> #[trigger] custom_fold(ec, keys)[s] == ec[custom_prefix() + s],
    decreases keys.len(),
{
    if keys.len() > 0 {
        let init = keys.drop_last();
        let k = keys.last();
        assert forall|i: int| 0 <= i < init.len() implies #[trigger] ec.contains_key(init[i]) by {
            assert(init[i] == keys[i]);
        }
        lemma_fold_char(ec, init);
        let acc = custom_fold(ec, init);
        assert forall|s: Str| #[trigger] custom_fold(ec, keys).contains_key(s)
            <==> keys.contains(custom_prefix() + s) by {
            // keys == init.push(k)
            assert(keys =~= init.push(k));
            if custom_prefix().is_prefix_of(k) {
                lemma_prefix_split(custom_prefix(), k);
                let st = k.skip(custom_prefix().len() as int);
                assert(custom_fold(ec, keys) == acc.insert(st, ec[k]));
                if s == st {
                    assert(k == custom_prefix() + s);
                    assert(keys.contains(custom_prefix() + s));
                } else {
                    // custom_prefix() + s == k would force s == st
                    if custom_prefix() + s == k {
                        assert((custom_prefix() + s).skip(custom_prefix().len() as int) =~= s);
                        assert(false);
                    }
                    assert(keys.contains(custom_prefix() + s) <==> init.contains(custom_prefix() + s));
                }
            } else {
                assert(custom_fold(ec, keys) == acc);
                // custom_prefix() + s is prefixed, k is not, so they differ
                lemma_concat_prefix(custom_prefix(), s);
                if custom_prefix() + s == k {
                    assert(false);
                }
                assert(keys.contains(custom_prefix() + s) <==> init.contains(custom_prefix() + s));
            }
        }
        assert forall|s: Str| custom_fold(ec, keys).contains_key(s)
            implies #[trigger] custom_fold(ec, keys)[s] == ec[custom_prefix() + s] by {
            if custom_prefix().is_prefix_of(k) {
                lemma_prefix_split(custom_prefix(), k);
                let st = k.skip(custom_prefix().len() as int);
                if s == st {
                    assert(k == custom_prefix() + s);
                } else {
                    assert(acc.contains_key(s));
                }
            } else {
                assert(acc.contains_key(s));
            }
        }
    }
}

/// For ANY enumeration of the map's keys (every key exactly covered), the loop at
/// record.rs :84-88 produces exactly `custom_ec(ec)`: the entries whose key starts with
/// `aws-crypto-ec:`, prefix stripped, value unchanged. Because prefix-stripping is
/// injective on prefixed keys, no two entries collide and iteration order is irrelevant.
proof fn lemma_fold_eq_custom(ec: Ec, keys: Seq<Str>)
    requires
        keys.to_set() =~= ec.dom(),
    ensures
        custom_fold(ec, keys) =~= custom_ec(ec),
{
    assert forall|i: int| 0 <= i < keys.len() implies #[trigger] ec.contains_key(keys[i]) by {
        assert(keys.to_set().contains(keys[i]));
    }
    lemma_fold_char(ec, keys);
    assert forall|s: Str| #![auto] custom_fold(ec, keys).contains_key(s) <==> custom_ec(ec).contains_key(s) by {
        lemma_custom_ec_member(ec, s);
        assert(keys.contains(custom_prefix() + s) <==> ec.contains_key(custom_prefix() + s)) by {
            if ec.contains_key(custom_prefix() + s) {
                assert(keys.to_set().contains(custom_prefix() + s));
            }
            if keys.contains(custom_prefix() + s) {
                assert(keys.to_set().contains(custom_prefix() + s));
            }
        }
    }
    assert forall|s: Str| #![auto] custom_fold(ec, keys).contains_key(s)
        implies custom_fold(ec, keys)[s] == custom_ec(ec)[s] by {
        lemma_custom_ec_member(ec, s);
    }
}

/// custom_ec is exactly the spec set definition
/// (branch-key-store.md "Custom Encryption Context From Authenticated Encryption Context"):
/// every entry (k, v) of the custom EC has `aws-crypto-ec:` + k in the authenticated EC with
/// value v, and nothing else is in it.
proof fn lemma_custom_ec_exact(ec: Ec)
    ensures
        forall|s: Str| #[trigger] custom_ec(ec).contains_key(s)
            <==> ec.contains_key(custom_prefix() + s),
        forall|s: Str| custom_ec(ec).contains_key(s)
            ==> #[trigger] custom_ec(ec)[s] == ec[custom_prefix() + s],
        // an authenticated entry without the prefix never reaches the custom EC
        forall|k: Str| #![auto] ec.contains_key(k) && !custom_prefix().is_prefix_of(k)
            ==> forall|s: Str| #[trigger] custom_ec(ec).contains_key(s) ==> custom_prefix() + s != k,
{
    assert forall|s: Str| #[trigger] custom_ec(ec).contains_key(s)
        <==> ec.contains_key(custom_prefix() + s) by {
        lemma_custom_ec_member(ec, s);
    }
    assert forall|s: Str| custom_ec(ec).contains_key(s)
        implies #[trigger] custom_ec(ec)[s] == ec[custom_prefix() + s] by {
        lemma_custom_ec_member(ec, s);
    }
    assert forall|k: Str| #![auto] ec.contains_key(k) && !custom_prefix().is_prefix_of(k)
        implies forall|s: Str| #[trigger] custom_ec(ec).contains_key(s) ==> custom_prefix() + s != k by {
        assert forall|s: Str| #![auto] custom_ec(ec).contains_key(s) implies custom_prefix() + s != k by {
            lemma_concat_prefix(custom_prefix(), s);
        }
    }
}

// ============================================================
// SECTION 4: Exact Ok/Err characterization of the SHIPPED code
// ============================================================

/// THEOREM A (Ok/Err characterization, as the code behaves today):
///   reconstruct returns Ok  <==>  code_accepts.
/// code_accepts is the T02 YAML formal_spec minus the G1 clause, plus "branch-key-id is
/// non-empty" (which the builder enforces and branch-key-store.md :593 requires).
proof fn theorem_a_ok_iff_code_accepts(ec: Ec, pt: Seq<u8>)
    ensures
        reconstruct(ec, pt) is Ok <==> code_accepts(ec, pt),
{
    lemma_const_lens();
}

/// THEOREM B (output is exactly determined): when reconstruct returns Ok(m),
///   m.branch_key == pt, m.branch_key_id == ec[branch-key-id],
///   m.branch_key_version == ver_src(ec) without the 15-char prefix (and is non-empty),
///   m.encryption_context == custom_ec(ec).
proof fn theorem_b_ok_fields(ec: Ec, pt: Seq<u8>)
    requires
        reconstruct(ec, pt) is Ok,
    ensures
        ({
            let m = reconstruct(ec, pt)->Ok_0;
            &&& m.branch_key =~= pt
            &&& m.branch_key.len() == 32
            &&& m.branch_key_id == ec[k_id()]
            &&& m.branch_key_id.len() > 0
            &&& m.branch_key_version =~= ver_src(ec).skip(version_prefix().len() as int)
            &&& m.branch_key_version.len() > 0
            &&& version_prefix() + m.branch_key_version =~= ver_src(ec)
            &&& m.encryption_context =~= custom_ec(ec)
        }),
{
    lemma_const_lens();
    theorem_a_ok_iff_code_accepts(ec, pt);
    lemma_prefix_split(version_prefix(), ver_src(ec));
}

/// THEOREM C (every Err is InvalidMaterials, with the exact first failing check).
/// The error variant is determined by the FIRST failing check in code order, and its kind
/// is InvalidMaterials. (kind_of is constant by the audit in the header.)
proof fn theorem_c_error_sites(ec: Ec, pt: Seq<u8>)
    ensures
        reconstruct(ec, pt) is Err ==> kind_of(reconstruct(ec, pt)->Err_0) == Kind::InvalidMaterials,
        !ec.contains_key(k_type()) ==> reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::MissingType),
        ec.contains_key(k_type()) && ec[k_type()] != type_active()
            && !version_prefix().is_prefix_of(ec[k_type()])
            ==> reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::BadTypeValue),
        ec.contains_key(k_type()) && ec[k_type()] == type_active() && !ec.contains_key(k_version())
            ==> reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::MissingVersionForActive),
        ec.contains_key(k_type())
            && (ec[k_type()] == type_active() ==> ec.contains_key(k_version()))
            && (ec[k_type()] == type_active() || version_prefix().is_prefix_of(ec[k_type()]))
            && !strict_prefix(version_prefix(), ver_src(ec))
            ==> reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::BadVersionString),
{
    lemma_const_lens();
}

/// Further exact error sites, after the type/version checks pass.
proof fn theorem_c2_late_error_sites(ec: Ec, pt: Seq<u8>)
    requires
        ec.contains_key(k_type()),
        ec[k_type()] == type_active() || version_prefix().is_prefix_of(ec[k_type()]),
        ec[k_type()] == type_active() ==> ec.contains_key(k_version()),
        strict_prefix(version_prefix(), ver_src(ec)),
    ensures
        !ec.contains_key(k_id())
            ==> reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::MissingBranchKeyId),
        ec.contains_key(k_id()) && pt.len() != 32
            ==> reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::BadKeyLength),
        ec.contains_key(k_id()) && pt.len() == 32 && ec[k_id()].len() == 0
            ==> reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::BuilderRejectedEmptyId),
        ec.contains_key(k_id()) && pt.len() == 32 && ec[k_id()].len() > 0
            ==> reconstruct(ec, pt) is Ok,
{
    lemma_const_lens();
}

/// BuilderRejectedEmptyVersion is dead code: step_version already rejects an empty version.
proof fn lemma_empty_version_unreachable(ec: Ec, pt: Seq<u8>)
    ensures
        reconstruct(ec, pt) != Err::<Materials, Fail>(Fail::BuilderRejectedEmptyVersion),
{
    lemma_const_lens();
}

// ============================================================
// SECTION 5: Corollaries that match the unit tests (test_key_store_record.rs)
// ============================================================

/// The bare prefix "branch:version:" as `type` is rejected (strict prefix, record.rs :133-136).
proof fn corollary_bare_prefix_type_rejected(ec: Ec, pt: Seq<u8>)
    requires
        ec.contains_key(k_type()),
        ec[k_type()] == version_prefix(),
    ensures
        reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::BadVersionString),
{
    lemma_const_lens();
    assert(version_prefix() != type_active()) by {
        assert(version_prefix().len() != type_active().len());
    }
}

/// ACTIVE with a bare-prefix `version` attribute is rejected.
proof fn corollary_active_with_bare_prefix_version_rejected(ec: Ec, pt: Seq<u8>)
    requires
        ec.contains_key(k_type()),
        ec[k_type()] == type_active(),
        ec.contains_key(k_version()),
        ec[k_version()] == version_prefix(),
    ensures
        reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::BadVersionString),
{
    lemma_const_lens();
}

/// "beacon:ACTIVE" is neither ACTIVE nor prefixed: rejected as a bad type.
proof fn corollary_beacon_type_rejected(ec: Ec, pt: Seq<u8>)
    requires
        ec.contains_key(k_type()),
        ec[k_type()] == type_beacon(),
    ensures
        reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::BadTypeValue),
{
    lemma_const_lens();
    assert(type_beacon() != type_active()) by {
        assert(type_beacon()[1] == 'e');
        assert(type_active()[1] == 'r');
    }
    assert(!version_prefix().is_prefix_of(type_beacon())) by {
        // lengths: type_beacon has 13 chars, the prefix has 15
        assert(version_prefix().len() > type_beacon().len());
    }
}

/// A well-formed version record (type = prefix + w, w non-empty) with a 32-byte key and
/// non-empty id is accepted, and the version is exactly w. (Non-vacuity of Theorem A.)
proof fn corollary_version_record_accepted(ec: Ec, pt: Seq<u8>, w: Str)
    requires
        w.len() > 0,
        ec.contains_key(k_type()),
        ec[k_type()] == version_prefix() + w,
        ec.contains_key(k_id()),
        ec[k_id()].len() > 0,
        pt.len() == 32,
    ensures
        reconstruct(ec, pt) is Ok,
        (reconstruct(ec, pt)->Ok_0).branch_key_version =~= w,
{
    lemma_const_lens();
    lemma_concat_prefix(version_prefix(), w);
    assert(version_prefix() + w != type_active()) by {
        assert((version_prefix() + w).len() > 15);
    }
    theorem_b_ok_fields(ec, pt);
}

// ============================================================
// SECTION 6: What the output does NOT depend on (attributes ignored by the code)
// ============================================================

/// Adding or removing an attribute `k` that is not `type`, `version`, `branch-key-id` and
/// does not start with `aws-crypto-ec:` never changes the outcome (Ok payload or Err).
proof fn lemma_unrelated_attribute_ignored(ec: Ec, pt: Seq<u8>, k: Str, v: Str)
    requires
        k != k_type(),
        k != k_version(),
        k != k_id(),
        !custom_prefix().is_prefix_of(k),
    ensures
        reconstruct(ec.insert(k, v), pt) == reconstruct(ec.remove(k), pt),
{
    let e1 = ec.insert(k, v);
    let e2 = ec.remove(k);
    assert(get(e1, k_type()) == get(e2, k_type()));
    assert(get(e1, k_version()) == get(e2, k_version()));
    assert(get(e1, k_id()) == get(e2, k_id()));
    assert forall|s: Str| #![auto] e1.contains_key(custom_prefix() + s) <==> e2.contains_key(custom_prefix() + s) by {
        lemma_concat_prefix(custom_prefix(), s);
        if custom_prefix() + s == k {
            assert(false);
        }
    }
    assert(custom_ec(e1) =~= custom_ec(e2)) by {
        assert forall|s: Str| custom_ec(e1).contains_key(s) <==> custom_ec(e2).contains_key(s) by {
            lemma_custom_ec_member(e1, s);
            lemma_custom_ec_member(e2, s);
        }
        assert forall|s: Str| #![auto] custom_ec(e1).contains_key(s) implies custom_ec(e1)[s] == custom_ec(e2)[s] by {
            lemma_custom_ec_member(e1, s);
            lemma_custom_ec_member(e2, s);
            lemma_concat_prefix(custom_prefix(), s);
            if custom_prefix() + s == k {
                assert(false);
            }
        }
    }
    assert(custom_ec(e1) == custom_ec(e2));
}

// ============================================================
// SECTION 7: SPEC-FAITHFUL PROPERTY (G1)  --  CONTAINS ONE INTENTIONALLY FAILING OBLIGATION
// ============================================================

/// Completeness direction of the spec-faithful property: if the record satisfies the spec
/// (all required fields present, valid shape, 32-byte key), the code accepts it. PROVED.
proof fn lemma_g1_spec_completeness(ec: Ec, pt: Seq<u8>)
    requires
        spec_accepts(ec, pt),
    ensures
        reconstruct(ec, pt) is Ok,
{
    theorem_a_ok_iff_code_accepts(ec, pt);
}

/// Soundness direction of the spec-faithful property (THE G1 CLAUSE):
///   branch-key-store.md :677 "A branch key record MUST include ... create-time (:690)
///   ... hierarchy-version (:692)" and :531/:553/:574 "If the record does not contain the
///   defined fields, this operation MUST fail."
/// The authenticated EC is every record attribute except `enc` (+ tablename), so "the
/// record contains the field" is "the EC contains the field".
///
/// EXPECTED TO FAIL. The shipped code reads neither `create-time` nor `hierarchy-version`
/// on any path, so it returns Ok for records that lack them (witness in Section 8).
/// This obligation is deliberately NOT weakened, commented out, or assumed. It is the
/// FINDING G1. Verus reports it as a failed postcondition.
proof fn lemma_g1_spec_soundness_FAILS(ec: Ec, pt: Seq<u8>)
    requires
        reconstruct(ec, pt) is Ok,
    ensures
        spec_accepts(ec, pt),
{
    theorem_a_ok_iff_code_accepts(ec, pt);
    // Blocked: nothing in reconstruct() mentions create-time / hierarchy-version, so
    // Ok  ==>  code_accepts  is all that can be derived. See lemma_g1_code_ignores_fields.
}

// ============================================================
// SECTION 8: What the code DOES satisfy about G1 (clearly labeled, provable)
// ============================================================

/// LABEL: CODE BEHAVIOR (not the spec property). The outcome is independent of
/// `create-time` and `hierarchy-version`: removing or adding either field can never turn
/// an Ok into an Err or vice versa. Hence the spec clause "record lacks them => MUST fail"
/// is not enforced by this function.
proof fn lemma_g1_code_ignores_fields(ec: Ec, pt: Seq<u8>, v: Str)
    ensures
        reconstruct(ec.insert(k_create_time(), v), pt) == reconstruct(ec.remove(k_create_time()), pt),
        reconstruct(ec.insert(k_hierarchy_version(), v), pt)
            == reconstruct(ec.remove(k_hierarchy_version()), pt),
{
    lemma_const_lens();
    assert(k_create_time() != k_type());
    assert(k_create_time() != k_version());
    assert(k_create_time() != k_id());
    assert(k_hierarchy_version() != k_type());
    assert(k_hierarchy_version() != k_version());
    assert(k_hierarchy_version() != k_id());
    assert(!custom_prefix().is_prefix_of(k_create_time())) by {
        assert(custom_prefix().len() > k_create_time().len());
    }
    assert(!custom_prefix().is_prefix_of(k_hierarchy_version())) by {
        assert(custom_prefix()[0] == 'a');
        assert(k_hierarchy_version()[0] == 'h');
    }
    lemma_unrelated_attribute_ignored(ec, pt, k_create_time(), v);
    lemma_unrelated_attribute_ignored(ec, pt, k_hierarchy_version(), v);
}

/// LABEL: CODE BEHAVIOR. Concrete witness of the finding: a record with only `type`
/// ("branch:version:v") and `branch-key-id` ("k"), and a 32-byte key, is ACCEPTED, although
/// it lacks create-time and hierarchy-version, i.e. violates `spec_accepts`.
/// So `lemma_g1_spec_soundness_FAILS` is false as stated (not just unprovable).
proof fn lemma_g1_witness_accepted_without_fields()
    ensures
        exists|ec: Ec, pt: Seq<u8>|
            #![trigger reconstruct(ec, pt)]
            reconstruct(ec, pt) is Ok && !ec.contains_key(k_create_time())
                && !ec.contains_key(k_hierarchy_version()) && !spec_accepts(ec, pt),
{
    lemma_const_lens();
    let w: Str = seq!['v'];
    let id: Str = seq!['k'];
    let ec: Ec = Map::<Str, Str>::empty()
        .insert(k_type(), version_prefix() + w)
        .insert(k_id(), id);
    let pt: Seq<u8> = Seq::new(32, |i: int| 0u8);
    assert(k_type() != k_id());
    assert(ec.contains_key(k_type()));
    assert(ec.contains_key(k_id()));
    assert(ec[k_type()] == version_prefix() + w);
    assert(ec[k_id()] == id);
    assert(!ec.contains_key(k_create_time())) by {
        assert(k_create_time() != k_type());
        assert(k_create_time() != k_id());
    }
    assert(!ec.contains_key(k_hierarchy_version())) by {
        assert(k_hierarchy_version() != k_type());
        assert(k_hierarchy_version() != k_id());
    }
    assert(pt.len() == 32);
    corollary_version_record_accepted(ec, pt, w);
    assert(!spec_accepts(ec, pt));
}

} // verus!

// Verus needs an entry point when run on a single file; nothing here is executed.
fn main() {}
