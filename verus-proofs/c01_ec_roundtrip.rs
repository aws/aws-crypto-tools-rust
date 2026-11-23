// =============================================================================
// VR-2026-C01 (capability 1c, quick win): round trip between the key-store encryption-context
// BUILDERS (mpl/src/key_store/encryption_context.rs) and the record RECONSTRUCTION
// (mpl/src/key_store/record.rs), and the BUG-08 collision branch in build_base.
//
// Run:  ~/verus/verus verus-proofs/c01_ec_roundtrip.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// -----------------------------------------------------------------------------
// STATUS: PROVED, as a proof about a hand-written model (read MODEL-vs-CODE GAP below).
//   Every obligation in this file is accepted by Verus. Nothing is left failing, because the
//   builders and the reconstruction agree: the round trip holds. The audit finding T02/G1
//   (create-time / hierarchy-version not enforced on read) does not affect records written by
//   these builders, see theorem_rt_*: their output satisfies `spec_accepts`.
//
// -----------------------------------------------------------------------------
// WHAT THE THEOREMS SAY  (names are the proof fns below)
//   theorem_rt_decrypt_only / theorem_rt_active   YAML property (a).
//     For every input with a non-empty branch_key_id, a non-empty version v, a 32-byte
//     plaintext, and a custom EC enumerated in any order:
//       * the builder returns Ok(ec) (it cannot fail);
//       * reconstruct(ec, pt) is Ok(m) with m.branch_key == pt, m.branch_key_id == input id,
//         m.branch_key_version == v, m.encryption_context == the custom EC (as a map);
//       * spec_accepts(ec, pt): ec carries create-time and hierarchy-version too.
//   theorem_rt_beacon     the beacon EC builds; the branch-key reconstruction rejects it with
//                         BadTypeValue for every plaintext; the beacon read path (custom-EC
//                         extraction + branch-key-id) round-trips.
//   theorem_builders_exact_errors   the only builder failures are empty id / empty version.
//   theorem_prefix_strip_inverse    YAML property (b).
//   theorem_bug08_*, lemma_bug08_*  YAML property (c), BUG-08, see below.
//   theorem_d_record_ec_record, theorem_d2_ec_record_ec    YAML property (d) (test-utils helpers).
//   theorem_prod_roundtrip, theorem_prod_beacon   the production pair, through the stored item
//                         (create_key -> DynamoDB -> get_*), under assumption A_DDB.
//
// WHAT IS PROVABLE ABOUT BUG-08 (the collision Err at encryption_context.rs :91-102)
//   theorem_bug08_collision_iff_duplicate: in the model, for non-empty id and type,
//       build_base == Err(Collision)  <==>  the key enumeration has a repeated key
//       build_base is Ok              <==>  the key enumeration has no repeated key.
//   Therefore the branch is dead exactly under assumption A_ITER (the iterator yields each
//   key once), which a BTreeMap guarantees and which the `EncryptionContext(BTreeMap<..>)`
//   newtype enforces by construction. The proof also shows the OTHER half of the invariant:
//   no base key starts with `aws-crypto-ec:` (lemma_attr_keys_not_custom_prefixed) and
//   prefixing is injective (lemma_prefix_inj). The two situations the code comment names, "a
//   custom key that already carries the prefix" and "a duplicate after prefixing", are
//   therefore not collisions (lemma_bug08_prefixed_custom_key_ok).
//   lemma_bug08_collision_live_under_duplicates shows the branch is live in the model when the
//   enumeration repeats a key, so "dead" is a conclusion and not an artifact of the model.
//   WHAT CANNOT BE PROVED HERE: A_ITER itself, i.e. that `BTreeMap::iter` yields each key once,
//   and that `format!("{PREFIX}{k}")` is concatenation. These are properties of std, not of
//   this crate; vstd has no spec for BTreeMap::iter on String keys. If EncryptionContext ever
//   stops being a map (for example a Vec of pairs) the branch becomes reachable; the proof
//   would then no longer apply. The branch is not harmful (it returns Err), it is dead code.
//
// -----------------------------------------------------------------------------
// WHAT IS MODELED (repo esdk-native-mpl, HEAD 66aba1c; mpl/ and prim/ equal main 620771c)
//
//   mpl/src/key_store/encryption_context.rs
//     :19-37    EncryptionContextInput
//     :40-107   build_base            (collision Err :91-102)
//     :117-132  active_encryption_context
//     :137-157  decrypt_only_encryption_context
//     :160-171  beacon_key_encryption_context
//   mpl/src/key_store/record.rs
//     :95-184   branch_key_materials_from_authenticated_encryption_context  (T02 model, copied)
//     :79-91    custom_encryption_context_from_authenticated_encryption_context (T02 model, copied)
//     :37-52    encryption_context_from_item   (test-utils)
//     :61-71    to_attribute_map               (test-utils)
//   mpl/src/key_store/branch_key_store.rs
//     :132-139  build_auth_ec
//     :539-      create_key (builders called at :569-571)
//     :792-,:827-  get_active_branch_key, get_branch_key_version (reconstruction :814, :852)
//     :868-     get_beacon_key (custom-EC extraction :885, id :887-890)
//     :1089-1106  item_from_ec_and_enc       :1141-1200  record_from_ddb_item
//   mpl/src/key_store/attributes.rs :11-24   the string constants
//
// CORRESPONDENCE TABLE, BUILDERS  (model item  <->  shipped code)
//
//   model                       code (encryption_context.rs unless noted)
//   --------------------------  --------------------------------------------------------------
//   Input{id,create_time,table, EncryptionContextInput :19-37. `hier` is hierarchy_version.to_string()
//     kms_arn,hier,custom}      (opaque Str, nothing depends on it). `custom` is Option<&EncryptionContext>:
//                               None is the empty map (the loop body never runs either way).
//   enumerates(c, keys)         `custom.iter()` at :88 (structures/encryption_context.rs :74, over a
//                               BTreeMap<String,String>). keys: the yielded order, ANY order allowed;
//                               no_duplicates + to_set == dom is assumption A_ITER.
//   build_base :: id empty      :44-49  Err(Validation)            -> BErr::EmptyId
//   build_base :: type empty    :51-56  Err(Validation)            -> BErr::EmptyType
//   base_map                    :58-79  six ec.insert(..) on distinct keys: branch-key-id, type,
//                               create-time, tablename, kms-arn, hierarchy-version (inserts on
//                               distinct keys never overwrite, lemma_attr_keys_distinct)
//   (debug_assert !enc :81-84)  not an executable check in release builds. The model PROVES the
//                               asserted fact: built_facts has !r.contains_key(k_enc()).
//   insert_custom               :87-104 `for (k,v) in custom.iter() { if ec.insert(format!(PREFIX k),v)
//                               .is_some() { return Err(..) } }`. is_some() <=> acc.contains_key(new key).
//                               Recursion on drop_last == left-to-right loop, first Err stops it.
//                               Err -> BErr::Collision
//   decrypt_only_ec             :141-146 version empty -> BErr::EmptyVersion; :148 type =
//                               "branch:version:" + version; :149 build_base(..)?   (debug_assert
//                               no `version` :151-154: proved, built_facts has !contains_key(version))
//   active_ec                   :121 decrypt_only(..)?; :125 insert(type,"branch:ACTIVE");
//                               :126-129 insert(version,"branch:version:" + version)
//   beacon_ec                   :163 build_base(input, "beacon:ACTIVE")?  (debug_assert no version
//                               :165-168: proved)
//
// CORRESPONDENCE TABLE, RECONSTRUCTION AND WIRING
//   reconstruct, custom_ec,     the T02 model, copied verbatim (see the marker below) from
//   custom_fold, Materials      verus-proofs/t02_record_reconstruction.rs lines 128-575. Its own
//                               correspondence table (record.rs :95-184, :79-91) is in that file's header
//                               and is not repeated here. Copied: sections 1-3 and Theorems A, B only.
//   Rec / ec_from_item /        record.rs :19-22, :37-52 (drop `enc`, add `tablename`), :61-71 (drop
//   to_attr_map                 `tablename`, wrapped key to `enc`)
//   stored_attrs                branch_key_store.rs :1089-1106 (drops `tablename`, adds `enc`) followed
//                               by :1141-1200 (removes `enc`, echoes every String/Number attribute).
//                               Identity on other attributes under A_DDB.
//   build_auth_ec               branch_key_store.rs :132-139: attributes + tablename = logical name
//
// -----------------------------------------------------------------------------
// TRUSTED ASSUMPTIONS (TCB)
//   * No `assume`, `admit`, `external_body`, `assume_specification`, or uninterpreted spec fn is
//     used. The trusted base is Verus, Z3 and vstd's axioms for Seq/Map/Set, plus the model-fidelity
//     claims below, which are human-reviewed and NOT machine-checked.
//   * A_STR  Strings are modeled as Seq<char>. A Rust byte-prefix test and a char-prefix test agree on
//            UTF-8; `format!("{A}{B}")` is Seq concatenation; `is_empty()` is len()==0; the
//            constants were copied by hand from attributes.rs (checked by script, all 12 match,
//            see c01-notes.md). Inherited from T02.
//   * A_ITER `custom.iter()` yields each key of the custom EC exactly once (BTreeMap contract), in
//            some order. Used as the precondition `enumerates` in every theorem about the
//            builders. It is satisfiable for every map (lemma_enum_exists). Without it the
//            collision branch is live (lemma_bug08_collision_live_under_duplicates).
//   * A_DDB  Storage identity: DynamoDB returns each attribute name and value that create_key wrote
//            (Strings and the Number `hierarchy-version` as the same decimal string), and the item
//            read is the one written (no concurrent rotation). Used only by theorem_prod_*, lemma_store_roundtrip.
//   * A_NAME The reader's logical key store name equals the writer's (input.table). If they differ,
//            tablename differs and KMS Decrypt would fail on the AAD; outside this proof.
//   * A_BLD  BranchKeyMaterials::build behaves as modeled in T02 (empty id/version rejected, required()
//            cannot fail). Inherited from T02.
//   * Map/Set finiteness: vstd Sets and Maps are finite, as is a BTreeMap.
//
// -----------------------------------------------------------------------------
// MODEL-vs-CODE GAP (read this before citing the result)
//   A proof about a re-typed model is not a proof about the shipped code. The builders and the
//   reconstruction are native Rust over BTreeMap<String,String>, &str, u32::to_string, format!,
//   the crate's Error type and BranchKeyMaterials, outside `verus!`; they are not compiled by this
//   file. Nothing here detects a later edit to encryption_context.rs or record.rs. The evidence is
//   an audited model plus machine-checked logic. The mutation checks in c01-notes.md show that
//   edits to the MODEL are caught (a dropped prefix, an unprefixed version, a missing empty-id
//   check, a prefixed base key, duplicates allowed); they say nothing about edits to the code.
//   To close the gap one would need ALL of:
//     1. the builders and reconstruction moved inside `verus!` (or `cargo verus` on the real crate);
//     2. vstd specs for BTreeMap::{insert (Some/None result), iter} over String keys, with the
//        iteration-uniqueness contract (this is A_ITER), plus `format!` / String concatenation,
//        str::{starts_with, strip_prefix, is_empty}, u32::to_string, String::clone;
//     3. an injectivity axiom for String::deep_view so Map<String,_> and Map<Seq<char>,_> agree;
//     4. specs for Error::new, BranchKeyMaterialsBuilder, and Zeroizing;
//     5. for theorem_prod_*: a model of the DynamoDB read/write (A_DDB) and of fetch_record's key
//        selection. That is a service contract, not provable from this crate.
//
// NOT COVERED
//   * The KMS leg: that GenerateDataKey / ReEncrypt / Decrypt use the same EC as AAD (T01 owns it).
//     theorem_prod_* prove only the part of T01's chain between the builders and the reconstruction.
//   * fetch_record, decrypt_branch_key, kms-arn compatibility, grant tokens, the beacon key
//     materials builder, version_key (rotation), and the DDB conditional write.
//   * The text, source and resource fields of any Error; zeroization; allocation failure; panics in
//     format!/to_string; the sorted-order property of BTreeMap iteration (not needed).
//   * hierarchy_version.to_string(): opaque. `create-time` format and `kms-arn` content: opaque.
//   * structures.md "Branch Key Version MUST be a version 4 UUID": neither side checks it, and
//     create_key generates a UUID v4 (branch_key_store.rs :557). The theorems hold for any non-empty
//     version string. Not modeled.
//   * Rollback of an authentic older record (TM-MPL-005 non-goal).
//   * Test-utils helpers (property (d)) are modeled but are not on any production path.
//   * Reconstruction is not injective on whole ECs (it drops every non-prefixed attribute besides
//     type/version/id): it inverts the builders on (id, version, custom EC) only. That is the YAML property.
// =============================================================================

use vstd::prelude::*;

verus! {
// ############################################################################
// BEGIN VERBATIM COPY of verus-proofs/t02_record_reconstruction.rs lines 128-575
// (sections 1-3, and section 4 up to and including theorem_b_ok_fields). Do not edit here.
// ############################################################################

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

// ############################################################################
// END OF VERBATIM COPY FROM t02_record_reconstruction.rs. Everything below is NEW in C01.
// ############################################################################

// ============================================================
// SECTION C1: extra attribute names (attributes.rs :11-24) not needed by T02
// ============================================================

/// ATTR_KMS_ARN = "kms-arn"
pub open spec fn k_kms_arn() -> Str { seq!['k', 'm', 's', '-', 'a', 'r', 'n'] }
/// ATTR_TABLENAME = "tablename"
pub open spec fn k_tablename() -> Str { seq!['t', 'a', 'b', 'l', 'e', 'n', 'a', 'm', 'e'] }
/// ATTR_ENC = "enc"
pub open spec fn k_enc() -> Str { seq!['e', 'n', 'c'] }

proof fn lemma_const_lens2()
    ensures
        k_kms_arn().len() == 7,
        k_tablename().len() == 9,
        k_enc().len() == 3,
{
}

/// The eight attribute names used by the builders and the reconstruction are pairwise distinct.
proof fn lemma_attr_keys_distinct()
    ensures
        k_type() != k_version(), k_type() != k_id(), k_type() != k_create_time(),
        k_type() != k_hierarchy_version(), k_type() != k_kms_arn(), k_type() != k_tablename(),
        k_type() != k_enc(),
        k_version() != k_id(), k_version() != k_create_time(), k_version() != k_hierarchy_version(),
        k_version() != k_kms_arn(), k_version() != k_tablename(), k_version() != k_enc(),
        k_id() != k_create_time(), k_id() != k_hierarchy_version(), k_id() != k_kms_arn(),
        k_id() != k_tablename(), k_id() != k_enc(),
        k_create_time() != k_hierarchy_version(), k_create_time() != k_kms_arn(),
        k_create_time() != k_tablename(), k_create_time() != k_enc(),
        k_hierarchy_version() != k_kms_arn(), k_hierarchy_version() != k_tablename(),
        k_hierarchy_version() != k_enc(),
        k_kms_arn() != k_tablename(), k_kms_arn() != k_enc(),
        k_tablename() != k_enc(),
{
    lemma_const_lens();
    lemma_const_lens2();
    assert(k_version()[0] == 'v');
    assert(k_kms_arn()[0] == 'k');
}

/// None of the attribute names starts with `aws-crypto-ec:`. This is the fact that makes the
/// builders' collision check dead (BUG-08): a prefixed custom key can never equal a base key.
proof fn lemma_attr_keys_not_custom_prefixed()
    ensures
        !custom_prefix().is_prefix_of(k_type()),
        !custom_prefix().is_prefix_of(k_version()),
        !custom_prefix().is_prefix_of(k_id()),
        !custom_prefix().is_prefix_of(k_create_time()),
        !custom_prefix().is_prefix_of(k_hierarchy_version()),
        !custom_prefix().is_prefix_of(k_kms_arn()),
        !custom_prefix().is_prefix_of(k_tablename()),
        !custom_prefix().is_prefix_of(k_enc()),
{
    lemma_const_lens();
    lemma_const_lens2();
    // Only hierarchy-version (17 chars) is at least as long as the 14-char prefix.
    assert(custom_prefix()[0] == 'a');
    assert(k_hierarchy_version()[0] == 'h');
}

// ============================================================
// SECTION C2: model of the BUILDERS (encryption_context.rs)
// ============================================================

/// Why a builder fails. All four map to Kind::Validation in the code.
#[derive(PartialEq, Eq)]
pub enum BErr {
    EmptyId,       // encryption_context.rs :44-49
    EmptyType,     // :51-56 (unreachable from the three public builders)
    EmptyVersion,  // :141-146
    Collision,     // :91-102  (BUG-08)
}

/// EncryptionContextInput (encryption_context.rs :19-37). `hier` is `hierarchy_version.to_string()`:
/// the decimal rendering is opaque here because no property below depends on it.
/// `custom` is the user's custom EC; `None` is modeled as the empty map (the loop body never runs
/// for either, and the reconstruction always returns Some(ctx), possibly empty).
pub struct Input {
    pub id: Str,
    pub create_time: Str,
    pub table: Str,
    pub kms_arn: Str,
    pub hier: Str,
    pub custom: Ec,
}

/// `keys` is the order in which `custom.iter()` yields its keys (encryption_context.rs :88).
/// A BTreeMap yields every key exactly once, in sorted order. The model accepts ANY order, but
/// requires "exactly once" (assumption A_ITER in the header). It is the only thing BUG-08's
/// dead-ness rests on besides the constants.
pub open spec fn enumerates(c: Ec, keys: Seq<Str>) -> bool {
    &&& keys.no_duplicates()
    &&& keys.to_set() =~= c.dom()
}

/// encryption_context.rs :58-79: the six unconditional inserts, on pairwise distinct keys.
pub open spec fn base_map(i: Input, t: Str) -> Ec {
    Map::<Str, Str>::empty()
        .insert(k_id(), i.id)
        .insert(k_type(), t)
        .insert(k_create_time(), i.create_time)
        .insert(k_tablename(), i.table)
        .insert(k_kms_arn(), i.kms_arn)
        .insert(k_hierarchy_version(), i.hier)
}

/// The loop at encryption_context.rs :88-104, over the enumeration `keys`, left to right,
/// stopping at the first failure. Written as a recursion on `drop_last` (the result for the
/// first n keys, then key n): same order of effects as the loop.
///   `ec.insert(prefixed, val).is_some()`  ==  `acc.contains_key(prefixed)`
pub open spec fn insert_custom(i: Input, base: Ec, keys: Seq<Str>) -> Result<Ec, BErr>
    decreases keys.len(),
{
    if keys.len() == 0 {
        Ok(base)
    } else {
        match insert_custom(i, base, keys.drop_last()) {
            Err(e) => Err(e),
            Ok(acc) => {
                let nk = custom_prefix() + keys.last();
                if acc.contains_key(nk) {
                    Err(BErr::Collision)
                } else {
                    Ok(acc.insert(nk, i.custom[keys.last()]))
                }
            },
        }
    }
}

/// build_base (encryption_context.rs :40-107).
pub open spec fn build_base(i: Input, t: Str, keys: Seq<Str>) -> Result<Ec, BErr> {
    if i.id.len() == 0 {
        Err(BErr::EmptyId)
    } else if t.len() == 0 {
        Err(BErr::EmptyType)
    } else {
        insert_custom(i, base_map(i, t), keys)
    }
}

/// decrypt_only_encryption_context (encryption_context.rs :137-157).
pub open spec fn decrypt_only_ec(i: Input, v: Str, keys: Seq<Str>) -> Result<Ec, BErr> {
    if v.len() == 0 {
        Err(BErr::EmptyVersion)
    } else {
        build_base(i, version_prefix() + v, keys)
    }
}

/// active_encryption_context (encryption_context.rs :117-132): the DECRYPT_ONLY context with
/// `type` overwritten and a new `version` entry.
pub open spec fn active_ec(i: Input, v: Str, keys: Seq<Str>) -> Result<Ec, BErr> {
    match decrypt_only_ec(i, v, keys) {
        Err(e) => Err(e),
        Ok(ec) => Ok(ec.insert(k_type(), type_active()).insert(k_version(), version_prefix() + v)),
    }
}

/// beacon_key_encryption_context (encryption_context.rs :160-171).
pub open spec fn beacon_ec(i: Input, keys: Seq<Str>) -> Result<Ec, BErr> {
    build_base(i, type_beacon(), keys)
}

// ============================================================
// SECTION C3: helper lemmas (sequences, prefix injectivity)
// ============================================================

/// `aws-crypto-ec:` + s is injective in s.
proof fn lemma_prefix_inj(s: Str, t: Str)
    requires
        custom_prefix() + s == custom_prefix() + t,
    ensures
        s == t,
{
    lemma_concat_prefix(custom_prefix(), s);
    lemma_concat_prefix(custom_prefix(), t);
    assert((custom_prefix() + s).skip(custom_prefix().len() as int)
        == (custom_prefix() + t).skip(custom_prefix().len() as int));
    assert(s =~= t);
}

/// A key that does not start with the prefix is never prefix + s.
proof fn lemma_not_prefixed_ne(k: Str, s: Str)
    requires
        !custom_prefix().is_prefix_of(k),
    ensures
        custom_prefix() + s != k,
{
    lemma_concat_prefix(custom_prefix(), s);
}

proof fn lemma_contains_drop_last(keys: Seq<Str>)
    requires
        keys.len() > 0,
    ensures
        forall|s: Str| #[trigger] keys.contains(s)
            <==> (keys.drop_last().contains(s) || s == keys.last()),
{
    let init = keys.drop_last();
    assert forall|s: Str| #[trigger] keys.contains(s) <==> (init.contains(s) || s == keys.last()) by {
        if keys.contains(s) {
            let idx = choose|idx: int| 0 <= idx < keys.len() && keys[idx] == s;
            if idx < keys.len() - 1 {
                assert(init[idx] == keys[idx]);
                assert(init.contains(s));
            }
        }
        if init.contains(s) {
            let idx = choose|idx: int| 0 <= idx < init.len() && init[idx] == s;
            assert(keys[idx] == init[idx]);
            assert(keys.contains(s));
        }
        if s == keys.last() {
            assert(keys[keys.len() - 1] == s);
            assert(keys.contains(s));
        }
    }
}

proof fn lemma_no_dup_push(keys: Seq<Str>)
    requires
        keys.len() > 0,
    ensures
        keys.no_duplicates() <==> (keys.drop_last().no_duplicates()
            && !keys.drop_last().contains(keys.last())),
{
    let init = keys.drop_last();
    let last = keys.last();
    if keys.no_duplicates() {
        assert forall|a: int, b: int|
            0 <= a < init.len() && 0 <= b < init.len() && a != b implies init[a] != init[b] by {
            assert(init[a] == keys[a]);
            assert(init[b] == keys[b]);
        }
        if init.contains(last) {
            let idx = choose|idx: int| 0 <= idx < init.len() && init[idx] == last;
            assert(keys[idx] == init[idx]);
            assert(keys[keys.len() - 1] == last);
            assert(idx != keys.len() - 1);
            assert(false);
        }
    }
    if init.no_duplicates() && !init.contains(last) {
        assert forall|a: int, b: int|
            0 <= a < keys.len() && 0 <= b < keys.len() && a != b implies keys[a] != keys[b] by {
            if a < keys.len() - 1 && b < keys.len() - 1 {
                assert(init[a] == keys[a]);
                assert(init[b] == keys[b]);
            } else if a == keys.len() - 1 {
                assert(init[b] == keys[b]);
                if init[b] == last {
                    assert(init.contains(init[b]));
                }
            } else {
                assert(init[a] == keys[a]);
                if init[a] == last {
                    assert(init.contains(init[a]));
                }
            }
        }
    }
}

/// An enumeration contains exactly the keys of the map.
proof fn lemma_enum_contains(c: Ec, keys: Seq<Str>, s: Str)
    requires
        enumerates(c, keys),
    ensures
        keys.contains(s) <==> c.contains_key(s),
{
    assert(keys.to_set().contains(s) <==> c.dom().contains(s));
    assert(keys.to_set().contains(s) <==> keys.contains(s));
}

/// Every map has an enumeration (vstd Maps and Sets are finite, as is a BTreeMap), so `enumerates`
/// in the theorems is satisfiable for every custom EC that exists at runtime.
proof fn lemma_enum_exists_set(s: Set<Str>)
    ensures
        exists|keys: Seq<Str>| keys.no_duplicates() && keys.to_set() =~= s,
    decreases s.len(),
{
    if s.len() == 0 {
        assert(s =~= Set::<Str>::empty());
        let keys = Seq::<Str>::empty();
        assert(keys.no_duplicates());
        assert(keys.to_set() =~= s);
    } else {
        let x = s.choose();
        let s2 = s.remove(x);
        assert(s2.len() < s.len());
        lemma_enum_exists_set(s2);
        let k2 = choose|k2: Seq<Str>| k2.no_duplicates() && k2.to_set() =~= s2;
        let keys = k2.push(x);
        assert(keys.drop_last() =~= k2);
        assert(!k2.contains(x)) by {
            assert(k2.to_set().contains(x) <==> k2.contains(x));
            assert(!s2.contains(x));
        }
        lemma_no_dup_push(keys);
        assert(keys.last() == x);
        assert(keys.no_duplicates());
        lemma_contains_drop_last(keys);
        assert(keys.to_set() =~= s) by {
            assert forall|y: Str| keys.to_set().contains(y) <==> s.contains(y) by {
                assert(keys.to_set().contains(y) <==> keys.contains(y));
                assert(k2.to_set().contains(y) <==> k2.contains(y));
                assert(keys.contains(y) <==> (k2.contains(y) || y == x));
            }
        }
    }
}

proof fn lemma_enum_exists(c: Ec)
    ensures
        exists|keys: Seq<Str>| enumerates(c, keys),
{
    lemma_enum_exists_set(c.dom());
    let keys = choose|keys: Seq<Str>| keys.no_duplicates() && keys.to_set() =~= c.dom();
    assert(enumerates(c, keys));
}

/// custom_ec ignores an insert under a key that does not start with the prefix.
proof fn lemma_custom_ec_insert_nonprefixed(ec: Ec, k: Str, v: Str)
    requires
        !custom_prefix().is_prefix_of(k),
    ensures
        custom_ec(ec.insert(k, v)) =~= custom_ec(ec),
{
    let e2 = ec.insert(k, v);
    assert forall|s: Str| custom_ec(e2).contains_key(s) <==> custom_ec(ec).contains_key(s) by {
        lemma_custom_ec_member(e2, s);
        lemma_custom_ec_member(ec, s);
        lemma_not_prefixed_ne(k, s);
    }
    assert forall|s: Str| #![auto] custom_ec(e2).contains_key(s)
        implies custom_ec(e2)[s] == custom_ec(ec)[s] by {
        lemma_custom_ec_member(e2, s);
        lemma_custom_ec_member(ec, s);
        lemma_not_prefixed_ne(k, s);
    }
}

// ============================================================
// SECTION C4: the custom-EC loop in build_base (BUG-08 core)
// ============================================================

pub open spec fn fold_props(i: Input, base: Ec, keys: Seq<Str>, r: Ec) -> bool {
    // exactly the prefixed images of the enumerated keys are the prefixed keys of r
    &&& forall|s: Str| #[trigger] r.contains_key(custom_prefix() + s) <==> keys.contains(s)
    // ... and carry the custom value
    &&& forall|s: Str| #[trigger] keys.contains(s) ==> r[custom_prefix() + s] == i.custom[s]
    // non-prefixed keys of r are base keys
    &&& forall|x: Str| #[trigger] r.contains_key(x) && !custom_prefix().is_prefix_of(x)
        ==> base.contains_key(x)
    // base entries are preserved unchanged
    &&& forall|x: Str| #[trigger] base.contains_key(x) ==> r.contains_key(x) && r[x] == base[x]
}

/// MAIN LEMMA FOR BUG-08. For a base map none of whose keys starts with `aws-crypto-ec:`
/// and ANY key sequence (duplicates allowed):
///   * the loop returns Ok  <==>  the sequence has no duplicates;
///   * the only possible Err is Collision;
///   * when it returns Ok, the result is exactly base plus the prefixed custom entries.
proof fn lemma_insert_custom(i: Input, base: Ec, keys: Seq<Str>)
    requires
        forall|x: Str| #[trigger] base.contains_key(x) ==> !custom_prefix().is_prefix_of(x),
    ensures
        insert_custom(i, base, keys) is Ok <==> keys.no_duplicates(),
        insert_custom(i, base, keys) is Err
            ==> insert_custom(i, base, keys) == Err::<Ec, BErr>(BErr::Collision),
        keys.no_duplicates() ==> fold_props(i, base, keys, insert_custom(i, base, keys)->Ok_0),
    decreases keys.len(),
{
    if keys.len() == 0 {
        assert(insert_custom(i, base, keys) == Ok::<Ec, BErr>(base));
        assert(keys.no_duplicates());
        assert forall|s: Str| #[trigger] base.contains_key(custom_prefix() + s) <==> keys.contains(s) by {
            lemma_concat_prefix(custom_prefix(), s);
        }
    } else {
        let init = keys.drop_last();
        let last = keys.last();
        let nk = custom_prefix() + last;
        lemma_insert_custom(i, base, init);
        lemma_no_dup_push(keys);
        lemma_contains_drop_last(keys);
        lemma_concat_prefix(custom_prefix(), last);
        if insert_custom(i, base, init) is Err {
            assert(insert_custom(i, base, keys) == insert_custom(i, base, init));
            assert(!init.no_duplicates());
            assert(!keys.no_duplicates());
        } else {
            let acc = insert_custom(i, base, init)->Ok_0;
            assert(init.no_duplicates());
            assert(fold_props(i, base, init, acc));
            assert(acc.contains_key(nk) <==> init.contains(last));
            if acc.contains_key(nk) {
                assert(insert_custom(i, base, keys) == Err::<Ec, BErr>(BErr::Collision));
                assert(!keys.no_duplicates());
            } else {
                assert(keys.no_duplicates());
                let r = acc.insert(nk, i.custom[last]);
                assert(insert_custom(i, base, keys) == Ok::<Ec, BErr>(r));
                assert forall|s: Str| #[trigger] r.contains_key(custom_prefix() + s)
                    <==> keys.contains(s) by {
                    if s != last {
                        if custom_prefix() + s == nk {
                            lemma_prefix_inj(s, last);
                        }
                        assert(custom_prefix() + s != nk);
                    }
                }
                assert forall|s: Str| #[trigger] keys.contains(s)
                    implies r[custom_prefix() + s] == i.custom[s] by {
                    if s != last {
                        if custom_prefix() + s == nk {
                            lemma_prefix_inj(s, last);
                        }
                        assert(init.contains(s));
                        assert(r[custom_prefix() + s] == acc[custom_prefix() + s]);
                    }
                }
                assert forall|x: Str| #[trigger] r.contains_key(x) && !custom_prefix().is_prefix_of(x)
                    implies base.contains_key(x) by {
                    assert(x != nk);
                    assert(acc.contains_key(x));
                }
                assert forall|x: Str| #[trigger] base.contains_key(x)
                    implies r.contains_key(x) && r[x] == base[x] by {
                    assert(!custom_prefix().is_prefix_of(x));
                    assert(x != nk);
                }
            }
        }
    }
}

// ============================================================
// SECTION C5: what every built EC looks like, for any enumeration order
// ============================================================

/// Everything the three builders guarantee about the map they return. (a) the six base entries,
/// (b) no `enc`, (c) no `version`, (d) the custom EC is exactly recoverable.
pub open spec fn built_facts(i: Input, t: Str, r: Ec) -> bool {
    &&& r.contains_key(k_id()) && r[k_id()] == i.id
    &&& r.contains_key(k_type()) && r[k_type()] == t
    &&& r.contains_key(k_create_time()) && r[k_create_time()] == i.create_time
    &&& r.contains_key(k_tablename()) && r[k_tablename()] == i.table
    &&& r.contains_key(k_kms_arn()) && r[k_kms_arn()] == i.kms_arn
    &&& r.contains_key(k_hierarchy_version()) && r[k_hierarchy_version()] == i.hier
    &&& !r.contains_key(k_enc())
    &&& !r.contains_key(k_version())
    &&& custom_ec(r) =~= i.custom
}

proof fn lemma_base_map_props(i: Input, t: Str)
    ensures
        forall|x: Str| #[trigger] base_map(i, t).contains_key(x) ==> !custom_prefix().is_prefix_of(x),
        base_map(i, t).contains_key(k_id()) && base_map(i, t)[k_id()] == i.id,
        base_map(i, t).contains_key(k_type()) && base_map(i, t)[k_type()] == t,
        base_map(i, t).contains_key(k_create_time()) && base_map(i, t)[k_create_time()] == i.create_time,
        base_map(i, t).contains_key(k_tablename()) && base_map(i, t)[k_tablename()] == i.table,
        base_map(i, t).contains_key(k_kms_arn()) && base_map(i, t)[k_kms_arn()] == i.kms_arn,
        base_map(i, t).contains_key(k_hierarchy_version())
            && base_map(i, t)[k_hierarchy_version()] == i.hier,
        !base_map(i, t).contains_key(k_enc()),
        !base_map(i, t).contains_key(k_version()),
{
    lemma_attr_keys_distinct();
    lemma_attr_keys_not_custom_prefixed();
}

/// build_base: exact failure condition, and the shape of the result on success.
proof fn lemma_build_base(i: Input, t: Str, keys: Seq<Str>)
    requires
        enumerates(i.custom, keys),
    ensures
        i.id.len() == 0 ==> build_base(i, t, keys) == Err::<Ec, BErr>(BErr::EmptyId),
        i.id.len() > 0 && t.len() == 0 ==> build_base(i, t, keys) == Err::<Ec, BErr>(BErr::EmptyType),
        i.id.len() > 0 && t.len() > 0 ==> build_base(i, t, keys) is Ok,
        i.id.len() > 0 && t.len() > 0 ==> built_facts(i, t, build_base(i, t, keys)->Ok_0),
{
    if i.id.len() > 0 && t.len() > 0 {
        let base = base_map(i, t);
        lemma_base_map_props(i, t);
        lemma_attr_keys_not_custom_prefixed();
        lemma_insert_custom(i, base, keys);
        assert(keys.no_duplicates());
        let r = insert_custom(i, base, keys)->Ok_0;
        assert(build_base(i, t, keys) == Ok::<Ec, BErr>(r));
        assert(fold_props(i, base, keys, r));
        // custom EC is exactly recoverable
        assert forall|s: Str| custom_ec(r).contains_key(s) <==> i.custom.contains_key(s) by {
            lemma_custom_ec_member(r, s);
            lemma_enum_contains(i.custom, keys, s);
        }
        assert forall|s: Str| #![auto] custom_ec(r).contains_key(s)
            implies custom_ec(r)[s] == i.custom[s] by {
            lemma_custom_ec_member(r, s);
            lemma_enum_contains(i.custom, keys, s);
        }
        assert(custom_ec(r) =~= i.custom);
        assert(!r.contains_key(k_enc()));
        assert(!r.contains_key(k_version()));
    }
}

// ============================================================
// SECTION C6: THEOREMS (round trip builders -> reconstruction)
// ============================================================

/// THEOREM RT-DO (YAML property (a), DECRYPT_ONLY): a DECRYPT_ONLY EC built from an input with a
/// non-empty branch key id and non-empty version v, reconstructed with a 32-byte plaintext, yields
/// materials with exactly that id, v and the custom EC (and the key). The builder cannot fail.
/// The built EC also satisfies the spec's reconstruction preconditions, including the
/// `create-time` / `hierarchy-version` clause that T02 found unenforced (G1): an honest CreateKey
/// record is never one of the records G1 lets through.
proof fn theorem_rt_decrypt_only(i: Input, v: Str, pt: Seq<u8>, keys: Seq<Str>)
    requires
        i.id.len() > 0,
        v.len() > 0,
        pt.len() == 32,
        enumerates(i.custom, keys),
    ensures
        decrypt_only_ec(i, v, keys) is Ok,
        ({
            let ec = decrypt_only_ec(i, v, keys)->Ok_0;
            &&& reconstruct(ec, pt) is Ok
            &&& spec_accepts(ec, pt)
            &&& ({
                let m = reconstruct(ec, pt)->Ok_0;
                &&& m.branch_key =~= pt
                &&& m.branch_key_id == i.id
                &&& m.branch_key_version =~= v
                &&& m.encryption_context =~= i.custom
            })
        }),
{
    lemma_const_lens();
    lemma_const_lens2();
    let t = version_prefix() + v;
    lemma_concat_prefix(version_prefix(), v);
    assert(t.len() > 15);
    lemma_build_base(i, t, keys);
    let ec = decrypt_only_ec(i, v, keys)->Ok_0;
    assert(decrypt_only_ec(i, v, keys) == build_base(i, t, keys));
    assert(built_facts(i, t, ec));
    assert(t != type_active());
    assert(ec[k_type()] == t);
    assert(ver_src(ec) == t);
    assert(strict_prefix(version_prefix(), ver_src(ec)));
    assert(code_accepts(ec, pt));
    assert(spec_accepts(ec, pt));
    theorem_a_ok_iff_code_accepts(ec, pt);
    theorem_b_ok_fields(ec, pt);
    assert(ver_src(ec).skip(version_prefix().len() as int) =~= v);
}

/// THEOREM RT-ACT (YAML property (a), ACTIVE).
proof fn theorem_rt_active(i: Input, v: Str, pt: Seq<u8>, keys: Seq<Str>)
    requires
        i.id.len() > 0,
        v.len() > 0,
        pt.len() == 32,
        enumerates(i.custom, keys),
    ensures
        active_ec(i, v, keys) is Ok,
        ({
            let ec = active_ec(i, v, keys)->Ok_0;
            &&& reconstruct(ec, pt) is Ok
            &&& spec_accepts(ec, pt)
            &&& ({
                let m = reconstruct(ec, pt)->Ok_0;
                &&& m.branch_key =~= pt
                &&& m.branch_key_id == i.id
                &&& m.branch_key_version =~= v
                &&& m.encryption_context =~= i.custom
            })
        }),
{
    lemma_const_lens();
    lemma_const_lens2();
    lemma_attr_keys_distinct();
    lemma_attr_keys_not_custom_prefixed();
    let t = version_prefix() + v;
    lemma_concat_prefix(version_prefix(), v);
    assert(t.len() > 15);
    lemma_build_base(i, t, keys);
    let r = decrypt_only_ec(i, v, keys)->Ok_0;
    assert(decrypt_only_ec(i, v, keys) == build_base(i, t, keys));
    assert(built_facts(i, t, r));
    let e1 = r.insert(k_type(), type_active());
    let ec = e1.insert(k_version(), version_prefix() + v);
    assert(active_ec(i, v, keys) == Ok::<Ec, BErr>(ec));
    lemma_custom_ec_insert_nonprefixed(r, k_type(), type_active());
    lemma_custom_ec_insert_nonprefixed(e1, k_version(), version_prefix() + v);
    assert(custom_ec(ec) =~= i.custom);
    assert(ec[k_type()] == type_active());
    assert(ec.contains_key(k_version()) && ec[k_version()] == t);
    assert(ec.contains_key(k_id()) && ec[k_id()] == i.id);
    assert(ec.contains_key(k_create_time()));
    assert(ec.contains_key(k_hierarchy_version()));
    assert(ver_src(ec) == t);
    assert(strict_prefix(version_prefix(), ver_src(ec)));
    assert(code_accepts(ec, pt));
    assert(spec_accepts(ec, pt));
    theorem_a_ok_iff_code_accepts(ec, pt);
    theorem_b_ok_fields(ec, pt);
    assert(ver_src(ec).skip(version_prefix().len() as int) =~= v);
}

/// THEOREM RT-BEACON (YAML property (a), beacon). The beacon EC builds, and the branch-key
/// reconstruction REJECTS it with BadTypeValue for every plaintext (a beacon record is not a branch
/// key record). The production beacon read path does not call that function; it calls only the
/// custom-EC extraction (branch_key_store.rs :885) and reads `branch-key-id`
/// (:887-890); both of those round-trip exactly.
proof fn theorem_rt_beacon(i: Input, pt: Seq<u8>, keys: Seq<Str>)
    requires
        i.id.len() > 0,
        enumerates(i.custom, keys),
    ensures
        beacon_ec(i, keys) is Ok,
        ({
            let ec = beacon_ec(i, keys)->Ok_0;
            &&& reconstruct(ec, pt) == Err::<Materials, Fail>(Fail::BadTypeValue)
            &&& ec[k_id()] == i.id
            &&& custom_ec(ec) =~= i.custom
            &&& ec[k_type()] == type_beacon()
            &&& !ec.contains_key(k_version())
        }),
{
    lemma_const_lens();
    lemma_const_lens2();
    assert(type_beacon().len() == 13);
    lemma_build_base(i, type_beacon(), keys);
    let ec = beacon_ec(i, keys)->Ok_0;
    assert(built_facts(i, type_beacon(), ec));
    assert(type_beacon() != type_active()) by {
        assert(type_beacon()[1] == 'e');
        assert(type_active()[1] == 'r');
    }
    assert(!version_prefix().is_prefix_of(type_beacon())) by {
        assert(version_prefix().len() > type_beacon().len());
    }
}

/// Exact failure conditions of the three public builders. In particular `Collision` is not a
/// possible outcome. (Only the empty id / empty version checks can fail.)
proof fn theorem_builders_exact_errors(i: Input, v: Str, keys: Seq<Str>)
    requires
        enumerates(i.custom, keys),
    ensures
        decrypt_only_ec(i, v, keys) is Err <==> (v.len() == 0 || i.id.len() == 0),
        active_ec(i, v, keys) is Err <==> (v.len() == 0 || i.id.len() == 0),
        beacon_ec(i, keys) is Err <==> i.id.len() == 0,
        decrypt_only_ec(i, v, keys) != Err::<Ec, BErr>(BErr::Collision),
        active_ec(i, v, keys) != Err::<Ec, BErr>(BErr::Collision),
        beacon_ec(i, keys) != Err::<Ec, BErr>(BErr::Collision),
        v.len() == 0 ==> decrypt_only_ec(i, v, keys) == Err::<Ec, BErr>(BErr::EmptyVersion),
        v.len() > 0 && i.id.len() == 0 ==> decrypt_only_ec(i, v, keys) == Err::<Ec, BErr>(BErr::EmptyId),
{
    lemma_const_lens();
    lemma_const_lens2();
    let t = version_prefix() + v;
    lemma_concat_prefix(version_prefix(), v);
    lemma_build_base(i, t, keys);
    lemma_build_base(i, type_beacon(), keys);
    assert(type_beacon().len() == 13);
}

// ============================================================
// SECTION C7: BUG-08 -- the collision Err in build_base
// ============================================================

/// THEOREM BUG-08 (exact characterization). In the model, build_base returns Err(Collision) if and
/// only if the key enumeration repeats a key. Hence:
///  (1) the Err is unreachable whenever `custom.iter()` yields each key once (A_ITER), which is
///      what a BTreeMap guarantees and what the EncryptionContext newtype (a BTreeMap) enforces;
///  (2) it is NOT unreachable for a reason internal to the builder: the only thing keeping it dead
///      is the uniqueness of the iterated keys. (The prefix constants contribute the other half:
///      lemma_attr_keys_not_custom_prefixed.)
/// The two code comments (encryption_context.rs :89-90) name a custom key that already carries
/// the prefix and a duplicate after prefixing. Neither is a collision: prefixing is injective
/// (lemma_prefix_inj) and no base key starts with the prefix. A custom key "aws-crypto-ec:x"
/// is stored as "aws-crypto-ec:aws-crypto-ec:x".
proof fn theorem_bug08_collision_iff_duplicate(i: Input, t: Str, keys: Seq<Str>)
    requires
        i.id.len() > 0,
        t.len() > 0,
    ensures
        build_base(i, t, keys) == Err::<Ec, BErr>(BErr::Collision) <==> !keys.no_duplicates(),
        build_base(i, t, keys) is Ok <==> keys.no_duplicates(),
{
    lemma_base_map_props(i, t);
    lemma_insert_custom(i, base_map(i, t), keys);
}

/// Dead-branch corollary in the shape the YAML asks for: if the custom EC is enumerated by an
/// iterator that yields each key once, no builder returns Collision.
proof fn theorem_bug08_collision_unreachable(i: Input, t: Str, keys: Seq<Str>)
    requires
        enumerates(i.custom, keys),
    ensures
        build_base(i, t, keys) != Err::<Ec, BErr>(BErr::Collision),
{
    if i.id.len() > 0 && t.len() > 0 {
        theorem_bug08_collision_iff_duplicate(i, t, keys);
    }
}

/// Non-vacuity: the Collision branch IS live in the model when the enumeration repeats a key.
/// So "dead" is a conclusion from A_ITER, not a side effect of how the model is written.
proof fn lemma_bug08_collision_live_under_duplicates(i: Input, t: Str)
    requires
        i.id.len() > 0,
        t.len() > 0,
    ensures
        exists|keys: Seq<Str>| build_base(i, t, keys) == Err::<Ec, BErr>(BErr::Collision),
{
    let x: Str = seq!['x'];
    let keys: Seq<Str> = seq![x, x];
    assert(!keys.no_duplicates()) by {
        assert(keys[0] == keys[1]);
    }
    theorem_bug08_collision_iff_duplicate(i, t, keys);
}

/// A custom key that already carries the prefix, the case named in the code comment, is stored
/// under prefix+prefix+x without any collision and round-trips. (Instance of RT-DO; here the
/// facts are stated for the built map directly.)
proof fn lemma_bug08_prefixed_custom_key_ok(i: Input, t: Str, keys: Seq<Str>, s: Str)
    requires
        i.id.len() > 0,
        t.len() > 0,
        enumerates(i.custom, keys),
        i.custom.contains_key(s),
        custom_prefix().is_prefix_of(s),
    ensures
        build_base(i, t, keys) is Ok,
        ({
            let r = build_base(i, t, keys)->Ok_0;
            &&& r.contains_key(custom_prefix() + s)
            &&& r[custom_prefix() + s] == i.custom[s]
            &&& custom_ec(r).contains_key(s)
        }),
{
    lemma_build_base(i, t, keys);
    let r = build_base(i, t, keys)->Ok_0;
    lemma_enum_contains(i.custom, keys, s);
    lemma_base_map_props(i, t);
    lemma_insert_custom(i, base_map(i, t), keys);
    lemma_custom_ec_member(r, s);
}

// ============================================================
// SECTION C8: (b) prefix / strip are exact inverses
// ============================================================

/// YAML property (b). strip(prefix + s) == s and prefix + strip(x) == x for every prefixed x.
/// At map level: a stripped key s is in custom_ec(ec) exactly when prefix + s is in ec, so
/// re-prefixing custom_ec(ec) gives back exactly the prefixed part of ec, with the same values.
proof fn theorem_prefix_strip_inverse(ec: Ec)
    ensures
        forall|s: Str| #[trigger] (custom_prefix() + s).skip(custom_prefix().len() as int) =~= s,
        forall|x: Str| #![trigger custom_prefix().is_prefix_of(x)] custom_prefix().is_prefix_of(x)
            ==> x =~= custom_prefix() + x.skip(custom_prefix().len() as int),
        forall|x: Str| #![trigger ec.contains_key(x)] (ec.contains_key(x) && custom_prefix().is_prefix_of(x))
            <==> (exists|s: Str| custom_ec(ec).contains_key(s) && x == custom_prefix() + s),
        forall|s: Str| custom_ec(ec).contains_key(s)
            ==> #[trigger] ec[custom_prefix() + s] == custom_ec(ec)[s],
{
    assert forall|s: Str| #[trigger] (custom_prefix() + s).skip(custom_prefix().len() as int) =~= s by {
        lemma_concat_prefix(custom_prefix(), s);
    }
    assert forall|x: Str| #![trigger custom_prefix().is_prefix_of(x)] custom_prefix().is_prefix_of(x)
        implies x =~= custom_prefix() + x.skip(custom_prefix().len() as int) by {
        lemma_prefix_split(custom_prefix(), x);
    }
    assert forall|x: Str| #![trigger ec.contains_key(x)]
        (ec.contains_key(x) && custom_prefix().is_prefix_of(x))
        <==> (exists|s: Str| custom_ec(ec).contains_key(s) && x == custom_prefix() + s) by {
        if ec.contains_key(x) && custom_prefix().is_prefix_of(x) {
            let s = x.skip(custom_prefix().len() as int);
            lemma_prefix_split(custom_prefix(), x);
            assert(x == custom_prefix() + s);
            lemma_custom_ec_member(ec, s);
            assert(custom_ec(ec).contains_key(s) && x == custom_prefix() + s);
        }
        if exists|s: Str| custom_ec(ec).contains_key(s) && x == custom_prefix() + s {
            let s = choose|s: Str| custom_ec(ec).contains_key(s) && x == custom_prefix() + s;
            lemma_custom_ec_member(ec, s);
            lemma_concat_prefix(custom_prefix(), s);
        }
    }
    assert forall|s: Str| custom_ec(ec).contains_key(s)
        implies #[trigger] ec[custom_prefix() + s] == custom_ec(ec)[s] by {
        lemma_custom_ec_member(ec, s);
    }
}

// ============================================================
// SECTION C9: (d) record -> EC -> record (record.rs :37-71, test-utils only)
// ============================================================

/// EncryptedRecord (record.rs :19-22): string attributes and the separate `enc` bytes.
pub struct Rec {
    pub attrs: Ec,
    pub enc: Seq<u8>,
}

pub open spec fn rec_eq(a: Rec, b: Rec) -> bool {
    a.attrs =~= b.attrs && a.enc == b.enc
}

/// encryption_context_from_item (record.rs :37-52): all attributes except `enc`, plus `tablename`.
pub open spec fn ec_from_item(r: Rec, name: Str) -> Ec {
    r.attrs.remove(k_enc()).insert(k_tablename(), name)
}

/// to_attribute_map (record.rs :61-71): the EC minus `tablename`, wrapped key as `enc`.
pub open spec fn to_attr_map(ec: Ec, e: Seq<u8>) -> Rec {
    Rec { attrs: ec.remove(k_tablename()), enc: e }
}

/// YAML property (d): to_attribute_map(encryption_context_from_item(r, n), r.enc) == r  iff
/// r has neither a `tablename` nor an `enc` attribute.
proof fn theorem_d_record_ec_record(r: Rec, name: Str)
    ensures
        rec_eq(to_attr_map(ec_from_item(r, name), r.enc), r)
            <==> (!r.attrs.contains_key(k_tablename()) && !r.attrs.contains_key(k_enc())),
{
    lemma_attr_keys_distinct();
    let out = to_attr_map(ec_from_item(r, name), r.enc);
    // out.attrs == r.attrs minus enc minus tablename, pointwise
    assert forall|k: Str| out.attrs.contains_key(k)
        <==> (r.attrs.contains_key(k) && k != k_enc() && k != k_tablename()) by {}
    assert forall|k: Str| #![auto] out.attrs.contains_key(k) ==> out.attrs[k] == r.attrs[k] by {}
    if !r.attrs.contains_key(k_tablename()) && !r.attrs.contains_key(k_enc()) {
        assert(out.attrs =~= r.attrs);
    }
    if r.attrs.contains_key(k_tablename()) {
        assert(!out.attrs.contains_key(k_tablename()));
        assert(!(out.attrs =~= r.attrs)) by {
            assert(!out.attrs.dom().contains(k_tablename()));
            assert(r.attrs.dom().contains(k_tablename()));
        }
    }
    if r.attrs.contains_key(k_enc()) {
        assert(!out.attrs.contains_key(k_enc()));
        assert(!(out.attrs =~= r.attrs)) by {
            assert(!out.attrs.dom().contains(k_enc()));
            assert(r.attrs.dom().contains(k_enc()));
        }
    }
}

/// The other direction: EC -> record -> EC is the identity when the EC has `tablename` = name
/// and no `enc` (both hold for every built EC: built_facts).
proof fn theorem_d2_ec_record_ec(ec: Ec, e: Seq<u8>, name: Str)
    requires
        ec.contains_key(k_tablename()),
        ec[k_tablename()] == name,
        !ec.contains_key(k_enc()),
    ensures
        ec_from_item(to_attr_map(ec, e), name) =~= ec,
{
    lemma_attr_keys_distinct();
}

// ============================================================
// SECTION C10: production wiring through the stored item
//   create_key (branch_key_store.rs :539-) --> DynamoDB --> get_* (:792-:900)
// ============================================================

/// The attributes the reader sees: item_from_ec_and_enc (branch_key_store.rs :1089-1106) drops
/// `tablename` and stores the others, then inserts `enc`; record_from_ddb_item (:1141-1200)
/// removes `enc` again and echoes every other String/Number attribute verbatim (ASSUMPTION A_DDB:
/// the store returns each written attribute name and value unchanged, `hierarchy-version`
/// included as the decimal string `u32::to_string` produced).
pub open spec fn stored_attrs(ec: Ec) -> Ec {
    ec.remove(k_tablename()).remove(k_enc())
}

/// build_auth_ec (branch_key_store.rs :132-139): attributes + `tablename` = the key store's
/// logical name. (It does not filter `enc`; the record has none.)
pub open spec fn build_auth_ec(attrs: Ec, name: Str) -> Ec {
    attrs.insert(k_tablename(), name)
}

/// Writer EC -> stored item -> reader authenticated EC is the identity when the reader's logical
/// key store name equals the writer's (`tablename`) and the EC has no `enc` key.
proof fn lemma_store_roundtrip(ec: Ec, name: Str)
    requires
        ec.contains_key(k_tablename()),
        ec[k_tablename()] == name,
        !ec.contains_key(k_enc()),
    ensures
        build_auth_ec(stored_attrs(ec), name) == ec,
{
    lemma_attr_keys_distinct();
    assert(build_auth_ec(stored_attrs(ec), name) =~= ec);
}

/// THEOREM PROD-GET-BRANCH-KEY-VERSION / PROD-GET-ACTIVE: the production pair. CreateKey builds
/// the DECRYPT_ONLY and ACTIVE ECs (:569-570); the reader (get_branch_key_version :827,
/// get_active_branch_key :792) rebuilds the authenticated EC from the stored item and calls the
/// reconstruction (:814, :852). Under A_DDB and a reader whose logical key store name equals the
/// writer's (input.table), the reconstructed materials have exactly the id, version and custom EC
/// that were given to CreateKey.
proof fn theorem_prod_roundtrip(i: Input, v: Str, pt: Seq<u8>, keys: Seq<Str>)
    requires
        i.id.len() > 0,
        v.len() > 0,
        pt.len() == 32,
        enumerates(i.custom, keys),
    ensures
        decrypt_only_ec(i, v, keys) is Ok,
        active_ec(i, v, keys) is Ok,
        ({
            let d = decrypt_only_ec(i, v, keys)->Ok_0;
            let a = active_ec(i, v, keys)->Ok_0;
            let md = reconstruct(build_auth_ec(stored_attrs(d), i.table), pt);
            let ma = reconstruct(build_auth_ec(stored_attrs(a), i.table), pt);
            &&& md is Ok && ma is Ok
            &&& (md->Ok_0).branch_key_id == i.id && (ma->Ok_0).branch_key_id == i.id
            &&& (md->Ok_0).branch_key_version =~= v && (ma->Ok_0).branch_key_version =~= v
            &&& (md->Ok_0).encryption_context =~= i.custom
            &&& (ma->Ok_0).encryption_context =~= i.custom
            &&& (md->Ok_0).branch_key =~= pt && (ma->Ok_0).branch_key =~= pt
        }),
{
    theorem_rt_decrypt_only(i, v, pt, keys);
    theorem_rt_active(i, v, pt, keys);
    let t = version_prefix() + v;
    lemma_const_lens();
    lemma_concat_prefix(version_prefix(), v);
    lemma_build_base(i, t, keys);
    let d = decrypt_only_ec(i, v, keys)->Ok_0;
    let a = active_ec(i, v, keys)->Ok_0;
    assert(built_facts(i, t, d));
    lemma_store_roundtrip(d, i.table);
    // the ACTIVE EC differs from DECRYPT_ONLY only in `type` and `version`; neither is `enc`/`tablename`
    lemma_attr_keys_distinct();
    assert(a.contains_key(k_tablename()) && a[k_tablename()] == i.table);
    assert(!a.contains_key(k_enc()));
    lemma_store_roundtrip(a, i.table);
}

/// THEOREM PROD-GET-BEACON: the beacon read path (branch_key_store.rs :868-900).
/// auth EC == written EC, so the id read at :887-890 is the input id and the custom EC
/// (custom_encryption_context_from_authenticated_encryption_context) is the input custom EC.
proof fn theorem_prod_beacon(i: Input, keys: Seq<Str>)
    requires
        i.id.len() > 0,
        enumerates(i.custom, keys),
    ensures
        beacon_ec(i, keys) is Ok,
        ({
            let b = beacon_ec(i, keys)->Ok_0;
            let auth = build_auth_ec(stored_attrs(b), i.table);
            &&& auth == b
            &&& auth[k_id()] == i.id
            &&& custom_ec(auth) =~= i.custom
        }),
{
    theorem_rt_beacon(i, Seq::<u8>::empty(), keys);
    lemma_build_base(i, type_beacon(), keys);
    let b = beacon_ec(i, keys)->Ok_0;
    assert(built_facts(i, type_beacon(), b));
    lemma_store_roundtrip(b, i.table);
}

/// Non-vacuity of the `enumerates` precondition: every custom EC has an enumeration, so
/// the theorems apply to every runtime custom EC.
proof fn theorem_rt_decrypt_only_every_custom(i: Input, v: Str, pt: Seq<u8>)
    requires
        i.id.len() > 0,
        v.len() > 0,
        pt.len() == 32,
    ensures
        exists|keys: Seq<Str>| #![auto] enumerates(i.custom, keys)
            && decrypt_only_ec(i, v, keys) is Ok
            && reconstruct(decrypt_only_ec(i, v, keys)->Ok_0, pt) is Ok,
{
    lemma_enum_exists(i.custom);
    let keys = choose|keys: Seq<Str>| enumerates(i.custom, keys);
    theorem_rt_decrypt_only(i, v, pt, keys);
}

} // verus!

// Verus needs an entry point when run on a single file; nothing here is executed.
fn main() {}
