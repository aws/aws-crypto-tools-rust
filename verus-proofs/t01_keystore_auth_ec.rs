// =============================================================================
// VR-2026-T01 (rank 1, TM-MPL-005, TM-MPL-002): key-store authenticated encryption context.
//   write-time EC  ==  the EC KMS authenticates (AAD)  ==  the EC the reconstruction reads.
//
// Run:  ~/verus/verus verus-proofs/t01_keystore_auth_ec.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// -----------------------------------------------------------------------------
// THIS IS A MODEL-LEVEL PROOF. It proves properties of a hand-written Verus model of the shipped
// code. It is not a proof of the shipped Rust. The code is native Rust over BTreeMap/HashMap,
// aws_sdk_kms and aws_sdk_dynamodb, outside `verus!`, and is not compiled by this file. KMS and
// DynamoDB are modeled by assumptions (A_KMS, A_DDB), which Verus does not and cannot check.
// Read "MODEL-vs-CODE GAP" before citing a result.
//
// -----------------------------------------------------------------------------
// STATUS: PROVED at model level, under the hypotheses below. Expected result:
//     verification results:: 52 verified, 0 errors
//   Nothing is left failing and no real gap was found, so there is no intentional-FAIL
//   obligation in this file. (The audit finding T02/G1, "create-time and hierarchy-version not
//   enforced on read", does not affect T01: every theorem here holds for stored items with or
//   without those two attributes. See O4.) Observations from code reading are listed under
//   OBSERVATIONS; none of them is a failed obligation.
//
// -----------------------------------------------------------------------------
// EVIDENCE LEVELS (kept exactly as the other proofs use them)
//   proved         accepted by Verus in this file, relative to the model and to A_* and H_* below
//   assumed        A_*: a contract of an external service or of std, not checked by Verus
//   code reading   a claim that a human read the shipped code to support; not machine-checked
//
// -----------------------------------------------------------------------------
// WHAT THE THEOREMS SAY (names are the proof fns below). All evidence level: proved (model).
//   theorem_reader_builders_agree   T01-A  kms_ops::build_authenticated_encryption_context (:49) and
//                          DynamoDbKeyStore::build_auth_ec (:132) are two separate functions. For
//                          every record attribute map they return the same EC. Without an `enc` key
//                          they are the spec EC "every attribute except enc, plus tablename".
//   theorem_reader_ec_is_spec       T01-B  for ANY item record_from_ddb_item accepts, in any iteration
//                          order: the reader EC has no `enc`, has `tablename` = the reader's name,
//                          and has every other item attribute exactly (as a String). It is the spec EC.
//   theorem_three_way               T01-C  THE T01 PROPERTY. For a record written under EC `ec`
//                          (wrapped key bound to `ec`, item built from `ec`): (1) write-time EC ==
//                          the EC KMS bound; (2) the AAD the reader builds == the write-time EC;
//                          (3) the EC the reader hands to the reconstruction == the write-time EC.
//                          KMS Decrypt with that AAD returns the generated key.
//                          Via lemma_item_roundtrip, S/N/B attribute mapping is lossless
//                          (`hierarchy-version` as Number, `tablename` dropped, `enc` as Binary).
//   theorem_prod_decrypt_only / theorem_prod_active / theorem_prod_beacon_kms
//                          CreateKey wiring through KMS: GenerateDataKey for DECRYPT_ONLY and beacon,
//                          ReEncrypt DECRYPT_ONLY -> ACTIVE (source EC is the bound EC, so KMS accepts),
//                          item stored, read by get_branch_key_version / get_active_branch_key /
//                          get_beacon_key: Decrypt succeeds, reconstruction returns the id, version,
//                          custom EC given to CreateKey and the generated key.
//   theorem_version_key             T01-D  VersionKey: for ANY stored item the reader accepts, the
//                          new DECRYPT_ONLY and ACTIVE ECs are well formed (tablename = name, no enc),
//                          the ReEncrypt from DECRYPT_ONLY to ACTIVE is accepted, and both new records
//                          read back with the OLD id, the OLD custom EC, the NEW version, the new key.
//                          The old-record authentication ReEncrypt succeeds iff the stored ciphertext
//                          is bound to the reconstructed EC.
//   theorem_read_authentic          T01-E  (TM-MPL-005 / TM-MPL-002) for ANY item and reader name:
//                          if the read passes KMS Decrypt, the EC the reconstruction uses equals the
//                          EC the ciphertext is bound to, so no attribute was added, dropped or
//                          altered, the ciphertext was written for this key store name, and the
//                          materials returned are exactly reconstruct(c.aad, c.pt).
//   theorem_sn_tag_not_authenticated  O2  the S/N tag is not covered by KMS and does not matter.
//   lemma_prod_active_nonvacuous, lemma_iters_witness   the hypotheses are satisfiable.
//
// -----------------------------------------------------------------------------
// WHAT IS NEW VERSUS C01 (verus-proofs/c01_ec_roundtrip.rs, 40 verified)
//   C01 proves (model level): the builders (encryption_context.rs) compose with the record
//   reconstruction (record.rs), through the stored item treated as a SET operation
//   (`stored_attrs(ec) = ec.remove(tablename).remove(enc)`, `build_auth_ec = attrs.insert(
//   tablename, name)`). C01 does not model KMS, the AttributeValue mapping, or kms_ops.rs.
//   T01 REUSES from C01, by copy and unchanged: the builder model (build_base, decrypt_only_ec,
//   active_ec, beacon_ec, `enumerates`), `built_facts`, theorem_rt_* and theorem_builders_exact_errors,
//   and (inside C01's copy) the T02 reconstruction model. It does not re-prove them.
//   T01 ADDS (all in sections K1-K9):
//     1. THE KMS-AAD SIDE of the equality: the model of kms_ops::build_authenticated_encryption_context
//        (`kms_aad`, :49) as a separate function from build_auth_ec, with proof that the two agree
//        (T01-A) and that the AAD KMS Decrypt receives equals the write-time EC (T01-C).
//     2. A symbolic model of the three KMS calls the key store makes (GenerateDataKeyWithoutPlaintext,
//        ReEncrypt, Decrypt) under A_KMS, and the write-time half "EC given to KMS == EC the item is
//        built from" (H_SAME_EC, code reading) with the DECRYPT_ONLY -> ACTIVE ReEncrypt chain.
//     3. item_from_ec_and_enc and record_from_ddb_item as LOOPS over any iteration order, over an
//        AttributeValue model S | N | B | Other, replacing C01's set-operation shortcut. Proves the
//        S/N/B mapping is lossless and that the reader EC never contains `enc`.
//     4. VersionKey (rotation), which C01 does not cover.
//     5. The authenticity theorem (T01-E): the KMS check is exactly what rejects a substituted,
//        altered or cross-key-store record whose ciphertext is paired with attributes it was not bound to.
//   NOT carried over from C01: BUG-08 (C7), prefix/strip inverse (C8), test-utils helpers (C9),
//   and the C10 wiring (superseded by K5-K6). They are not needed for T01.
//   Copy decision: the C01 model is COPIED into this file, as the existing proofs do (C01 copies
//   T02). A cross-file import is not used: the C01 lemmas are private (`proof fn` without `pub`),
//   each proof file is its own crate root, and editing C01 is out of scope. The copied block is C01 lines 178-1306, byte for byte,
//   from the "BEGIN VERBATIM COPY" marker to the "END OF VERBATIM COPY" marker below. C01 itself
//   copies T02 lines 128-575 inside that block.
//
// -----------------------------------------------------------------------------
// WHAT IS MODELED (repo esdk-native-mpl, HEAD 4964d66; mpl/ and prim/ unchanged by this work)
//
//   mpl/src/key_store/kms_ops.rs
//     :49-76    build_authenticated_encryption_context   -> kms_aad, copy_fold
//     :162-208  decrypt_branch_key (EC built :170, set_encryption_context :185) -> kms_decrypt use
//     :222-255  generate_wrapped_key (number_of_bytes(32) :231)               -> kms_generate
//     :260-302  reencrypt_wrapped_key (source :273, destination :279)        -> kms_reencrypt
//   mpl/src/key_store/branch_key_store.rs
//     :132-139  build_auth_ec                                                  -> rec_auth_ec
//     :539-629  create_key (ECs :569-571, KMS :577-590, items :595-597)       -> theorem_prod_*
//     :641-775  version_key (old EC :671, auth ReEncrypt :678-684, new ECs :706-721,
//               KMS :725-733, items :739, :748)                                 -> theorem_version_key
//     :792-,:827-,:868-  get_active_branch_key, get_branch_key_version, get_beacon_key
//               (decrypt_branch_key then build_auth_ec then reconstruction)    -> read_auth, read_branch_key
//     :1089-1107 item_from_ec_and_enc                                          -> item_fold
//     :1141-1198 record_from_ddb_item                                          -> record_from_item, rec_fold
//   Reused models (copied, see above): encryption_context.rs :19-171 (builders), record.rs
//   :79-184 (reconstruction), attributes.rs :11-24 (constants).
//
// CORRESPONDENCE TABLE, NEW MODEL ITEMS  (model item  <->  shipped code)
//   Ct {pt, aad}               a KMS ciphertext blob (`EncryptedRecord::enc`, Vec<u8>) as the pair
//                              (plaintext it hides, EC it is bound to). Assumption A_KMS.
//   AV S/N/B/Other             aws_sdk_dynamodb::AttributeValue S / N / B / every other variant.
//                              B carries a Ct: the blob bytes are the symbolic ciphertext (A_DDB).
//   kms_generate(pt, ec)       GenerateDataKeyWithoutPlaintext with EncryptionContext = ec.
//   kms_reencrypt(c, s, d)     ReEncrypt: Ok iff c.aad == s (set equality of the EC), result bound to d.
//   kms_decrypt(c, ec)         Decrypt: Ok iff c.aad == ec. Plaintext is c.pt.
//   copy_fold / kms_aad        the `for (k, v) in record_attributes` loop (:55-57), then
//                              ec.insert("tablename", name) (:62-65). Any iteration order.
//   rec_auth_ec                record.attributes.clone() then insert("tablename", name) (:133-136).
//   spec_auth_ec               the YAML formal_spec auth_ec: attrs.remove("enc").insert("tablename", n).
//   item_fold / item_val       :1094-1104. tablename skipped (:1095), hierarchy-version -> N, else S.
//   record_from_item / rec_fold  :1141-1198. enc removed (:1145) and must be B (:1152-1163); every
//                              other attribute must be S or N (:1166-1192), first bad one fails.
//   read_auth                  decrypt_branch_key (:162) then build_auth_ec, for the three readers.
//   read_branch_key            read_auth then the reconstruction (T02 model).
//   rotate_decrypt_only /      version_key :706-712 / :714-721.
//   rotate_active
//
// -----------------------------------------------------------------------------
// ASSUMPTIONS AND HYPOTHESES
//   Trusted base: Verus, Z3, vstd's axioms for Seq/Map/Set. No `assume`, `admit`, `external_body`,
//   `assume_specification` or uninterpreted spec function is used. The A_* below are encoded as the
//   DEFINITIONS of the model (not as axioms), so Verus cannot be used to "check" them.
//   A_* are model-fidelity and external-contract assumptions (evidence level: assumed):
//   * A_KMS   AWS KMS binds the EncryptionContext given to GenerateDataKeyWithoutPlaintext and to the
//             ReEncrypt DESTINATION to the ciphertext; Decrypt and ReEncrypt-source succeed only if the
//             supplied EncryptionContext equals the bound one as a set of key/value pairs (order and
//             HashMap iteration order irrelevant); ReEncrypt keeps the plaintext; the generated key is
//             32 bytes. This is the AWS KMS service contract and AEAD integrity of the blob. It is the
//             ONLY control that stops a DynamoDB writer from changing attributes (TM-MPL-005).
//   * A_DDB   DynamoDB returns the item that create_key / version_key wrote: every S, N and B value
//             unchanged, no concurrent rotation. (A DynamoDB writer who alters the item is the threat;
//             theorem_read_authentic handles it, it does not assume A_DDB.)
//   * A_NUM   The `hierarchy-version` String is a canonical DynamoDB Number rendering, so N(s) round
//             trips as the same String s. True for u32::to_string() (create_key sets 1), and for any
//             value that DynamoDB already returned (version_key re-writes what it read). A value that
//             DynamoDB would normalize ("01", "1.0") written by another implementation would make the
//             authenticated EC differ from the EC KMS bound; the read would fail closed.
//   * A_NAME  The reader's logical key store name equals the writer's (ec[tablename] == name, in
//             H_WF). A different name makes KMS Decrypt fail (theorem_read_authentic, `tablename`).
//   * A_ITER  BTreeMap::iter / HashMap::into_iter / `for (k, v) in &map` yield every key at least
//             once. The new loops need only this (`covers`); C01's `enumerates` (also "exactly once")
//             is still used for the builder loop. Both are satisfiable (lemma_iters_witness).
//   * A_ARN   fetch_record returns the item for the requested (id, type); kms-arn resolution, alias
//             rejection, grant tokens and KMS service errors other than the EC check are not modeled
//             and are assumed to succeed (T03 owns resolve_key_store_arn).
//   * A_STR   Strings are Seq<char> (inherited from T02/C01). A_BLD: BranchKeyMaterials::build as in
//             T02 (inherited).
//   H_* are premises of the theorems (code reading or satisfiable side conditions):
//   * H_WF       the EC written has `tablename` = the key store name and no `enc` key (`wf_ec`). Proved
//                for every EC the builders produce (built_facts, ACTIVE inserts) and for every EC
//                version_key derives (lemma_rotation_facts); not an extra assumption in those theorems.
//   * H_ENUM     the loop enumerations cover the maps they iterate (`iters_ok`, A_ITER). Satisfiable.
//   * H_SAME_EC  In create_key and version_key the SAME local variable (the EC) is passed to the KMS
//                call and to item_from_ec_and_enc (:569-597, :706-748). This is code reading. The
//                model builds `c = kms_generate(pt, ec)` and `item_from_ec_and_enc(ec, kw, c)` from
//                one `ec`. A later edit that passes a different EC to the two calls is not detected.
//
// -----------------------------------------------------------------------------
// OBSERVATIONS (code reading plus the proved facts; none is a failing obligation)
//   O1  The reconstruction reads `branch-key-id`, `type`, `version` and the custom EC from
//       rec_auth_ec (:132), while KMS authenticates kms_aad (kms_ops.rs :49). They are two separately
//       written functions with no shared code. T01-A proves they agree today. If one is edited
//       alone (for example `tablename` dropped from one), the reconstruction would read attributes
//       KMS did not authenticate. A shared helper, or a unit test pinning both, would remove the
//       dependency on keeping them in step. Mutation checks (t01-mutations.txt) show the model proof
//       fails when either builder loses `tablename`.
//   O2  `AttributeValue::S(s)` and `N(s)` both become the String s. The S/N tag is not authenticated.
//       Harmless: no consumer sees the tag (theorem_sn_tag_not_authenticated).
//   O3  An item attribute named `tablename` is ignored and replaced by the reader's name in both
//       builders. Its stored value is not authenticated and not used (T01-B, T01-E).
//   O4  T01 holds for items without `create-time` / `hierarchy-version` (G1 of T02). G1 stays a T02
//       finding; T01 does not strengthen or weaken it.
//   O5  Rollback of an authentic older record is outside this property (TM-MPL-005 non-goal): an older
//       record's EC is genuine, so T01-E accepts it.
//
// -----------------------------------------------------------------------------
// MODEL-vs-CODE GAP (read this before citing the result)
//   A proof about a re-typed model is not a proof about the shipped code. The functions modeled here
//   are native Rust over BTreeMap<String,String>, HashMap<String,AttributeValue>, Vec<u8>, the
//   aws_sdk_kms client and the crate's Error type, outside `verus!`. Nothing here detects a later edit
//   to kms_ops.rs, branch_key_store.rs, record.rs or encryption_context.rs. The evidence is an audited
//   model plus machine-checked logic. Mutation checks on the MODEL (a dropped `tablename` in either
//   builder, an item that keeps `tablename`, a Decrypt that accepts any AAD, a ReEncrypt that checks
//   the wrong EC, a rotated ACTIVE EC that keeps the old type) are all rejected by Verus; see
//   t01-mutations.txt. They say nothing about edits to the code. To close the gap one would need ALL of:
//     1. the builders, item mapping and reconstruction moved inside `verus!` (or `cargo verus` on the crate);
//     2. vstd specs for BTreeMap/HashMap insert, remove, clone and iteration over String keys,
//        String::clone, str comparison, and an injectivity axiom for String::deep_view;
//     3. a spec of aws_sdk_kms::Client::{decrypt, generate_data_key_without_plaintext, re_encrypt} and of
//        aws_sdk_dynamodb::types::AttributeValue. That spec for KMS IS the A_KMS contract: it would stay an
//        axiom, because the service is outside this repo;
//     4. specs for Error::new / BranchKeyMaterialsBuilder, as in T02.
//
// NOT COVERED
//   * The cryptographic claim that KMS enforces the EC (A_KMS), AEAD integrity, and DynamoDB behavior.
//   * fetch_record key selection, kms-arn compatibility (resolve_key_store_arn), grant tokens, KMS error
//     mapping, the DynamoDB conditional writes and the optimistic lock in version_key.
//   * User-supplied KeyStore implementations (TB7). Rollback of an authentic older record.
//   * `create-time` format, `hierarchy-version` rendering, UUID format of the branch key version.
//   * The test-utils helpers record.rs :37-71 (not on any production path); C01 covers them.
//   * Zeroization, allocation failure, panics, the text of any Error.
// =============================================================================

use vstd::prelude::*;

verus! {
// ############################################################################
// BEGIN VERBATIM COPY of verus-proofs/c01_ec_roundtrip.rs lines 178-1306 (C01 sections 1-3 and 4
// from T02, C1-C6: builders, build_base, built_facts, theorem_rt_*, theorem_builders_exact_errors).
// Do not edit here. The "BEGIN/END VERBATIM COPY ... t02" and "NEW in C01" markers inside this
// block are C01's own and are kept as they are; "NEW in C01" there means new versus T02.
// ############################################################################

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

// ############################################################################
// END OF VERBATIM COPY FROM c01_ec_roundtrip.rs. Everything below is NEW in T01.
// ############################################################################

// ============================================================
// SECTION K1: abstract KMS and DynamoDB (new in T01)
// ============================================================

/// A KMS ciphertext, modeled SYMBOLICALLY: the plaintext it hides and the encryption context it is
/// bound to. The shipped code holds a `Vec<u8>` blob (`EncryptedRecord::enc`). Assumption A_KMS
/// says the blob behaves like this value.
pub struct Ct {
    pub pt: Seq<u8>,
    pub aad: Ec,
}

/// DynamoDB `AttributeValue` as the item mapping sees it (branch_key_store.rs :1089-1107, :1141-1198).
/// `S` String, `N` Number (the decimal string), `B` Binary (here the symbolic ciphertext),
/// `Other` every other variant (Bs, Bool, L, M, Null, Ns, Ss, unknown).
pub enum AV {
    S(Str),
    N(Str),
    B(Ct),
    Other,
}

#[derive(PartialEq, Eq)]
pub enum KmsErr {
    AuthFailed,
}

/// KMS GenerateDataKeyWithoutPlaintext (kms_ops.rs :222-255): the new wrapped key is bound to `ec`.
/// `pt` is the 32-byte data key (the request asks for 32 bytes, `.number_of_bytes(32)` :231).
pub open spec fn kms_generate(pt: Seq<u8>, ec: Ec) -> Ct {
    Ct { pt: pt, aad: ec }
}

/// KMS ReEncrypt (kms_ops.rs :260-302): succeeds exactly when the SOURCE context equals the bound
/// context; the result is bound to the DESTINATION context and hides the same plaintext.
pub open spec fn kms_reencrypt(c: Ct, src: Ec, dst: Ec) -> Result<Ct, KmsErr> {
    if c.aad == src { Ok(Ct { pt: c.pt, aad: dst }) } else { Err(KmsErr::AuthFailed) }
}

/// KMS Decrypt (kms_ops.rs :162-208, `set_encryption_context(Some(ec))` at :185): succeeds exactly
/// when the supplied context equals the bound context.
pub open spec fn kms_decrypt(c: Ct, ec: Ec) -> Result<Seq<u8>, KmsErr> {
    if c.aad == ec { Ok(c.pt) } else { Err(KmsErr::AuthFailed) }
}

pub open spec fn is_str_attr(v: AV) -> bool {
    v is S || v is N
}

/// `AttributeValue::S(s)` and `AttributeValue::N(n)` both become the String `s` / `n`
/// (record_from_ddb_item :1170-1181).
pub open spec fn str_of(v: AV) -> Str {
    match v {
        AV::S(s) => s,
        AV::N(s) => s,
        _ => Seq::empty(),
    }
}

/// The attribute that item_from_ec_and_enc stores for EC entry (k, v) (:1095-1102):
/// `hierarchy-version` is a Number, every other entry a String.
pub open spec fn item_val(k: Str, v: Str) -> AV {
    if k == k_hierarchy_version() { AV::N(v) } else { AV::S(v) }
}

/// `keys` enumerates at least every key of the map (the weak form of assumption A_ITER used here).
pub open spec fn covers<V>(m: Map<Str, V>, keys: Seq<Str>) -> bool {
    keys.to_set() =~= m.dom()
}

// ============================================================
// SECTION K2: the READ-side builders (the KMS-AAD side is NEW), the item mapping, the reader
// ============================================================

/// kms_ops::build_authenticated_encryption_context (kms_ops.rs :49-76): copy every record
/// attribute (loop :55-57, over the enumeration `ka` of the BTreeMap), then insert
/// `tablename` = the logical key store name (:62-65). This is the EC passed to KMS Decrypt as AAD
/// (decrypt_branch_key :162-208: built at :170, `set_encryption_context` at :185).
pub open spec fn copy_fold(attrs: Ec, ka: Seq<Str>) -> Ec
    decreases ka.len(),
{
    if ka.len() == 0 {
        Map::empty()
    } else {
        copy_fold(attrs, ka.drop_last()).insert(ka.last(), attrs[ka.last()])
    }
}

pub open spec fn kms_aad(attrs: Ec, ka: Seq<Str>, n: Str) -> Ec {
    copy_fold(attrs, ka).insert(k_tablename(), n)
}

/// DynamoDbKeyStore::build_auth_ec (branch_key_store.rs :132-139): `record.attributes.clone()`
/// then insert `tablename` = the logical key store name. This is the EC handed to the
/// reconstruction (get_active_branch_key :811, get_branch_key_version :849, get_beacon_key :884,
/// version_key :671).
pub open spec fn rec_auth_ec(attrs: Ec, n: Str) -> Ec {
    attrs.insert(k_tablename(), n)
}

/// The spec definition (YAML formal_spec of VR-2026-T01, branch-key-store.md#encryption-context):
/// every record attribute except `enc`, plus `tablename` = the logical key store name.
pub open spec fn spec_auth_ec(attrs: Ec, n: Str) -> Ec {
    attrs.remove(k_enc()).insert(k_tablename(), n)
}

/// The loop of item_from_ec_and_enc (branch_key_store.rs :1094-1104) over the enumeration `kw`
/// of the EC: skip `tablename`, store the rest (`hierarchy-version` as N, others as S).
pub open spec fn item_fold(ec: Ec, kw: Seq<Str>) -> Map<Str, AV>
    decreases kw.len(),
{
    if kw.len() == 0 {
        Map::empty()
    } else {
        let acc = item_fold(ec, kw.drop_last());
        let k = kw.last();
        if k == k_tablename() { acc } else { acc.insert(k, item_val(k, ec[k])) }
    }
}

/// item_from_ec_and_enc (:1089-1107): the item, then `enc` inserted as Binary (:1105).
pub open spec fn item_from_ec_and_enc(ec: Ec, kw: Seq<Str>, c: Ct) -> Map<Str, AV> {
    item_fold(ec, kw).insert(k_enc(), AV::B(c))
}

#[derive(PartialEq, Eq)]
pub enum RErr {
    MissingEnc,    // :1145-1150
    EncNotBinary,  // :1152-1163
    BadAttr,       // :1182-1190
}

/// The loop of record_from_ddb_item (:1166-1192) over the enumeration `kr` of the item WITHOUT
/// `enc` (the item is a HashMap; `enc` was removed at :1145). Left to right, the first
/// non-String/Number attribute fails the whole call.
pub open spec fn rec_fold(rest: Map<Str, AV>, kr: Seq<Str>) -> Result<Ec, RErr>
    decreases kr.len(),
{
    if kr.len() == 0 {
        Ok(Map::empty())
    } else {
        match rec_fold(rest, kr.drop_last()) {
            Err(e) => Err(e),
            Ok(acc) => {
                let k = kr.last();
                if is_str_attr(rest[k]) {
                    Ok(acc.insert(k, str_of(rest[k])))
                } else {
                    Err(RErr::BadAttr)
                }
            },
        }
    }
}

/// EncryptedRecord (record.rs :20-23): the String attributes (no `enc`) and the `enc` blob.
pub struct EncRecord {
    pub attrs: Ec,
    pub enc: Ct,
}

/// record_from_ddb_item (branch_key_store.rs :1141-1198).
pub open spec fn record_from_item(item: Map<Str, AV>, kr: Seq<Str>) -> Result<EncRecord, RErr> {
    if !item.contains_key(k_enc()) {
        Err(RErr::MissingEnc)
    } else {
        match item[k_enc()] {
            AV::B(c) => match rec_fold(item.remove(k_enc()), kr) {
                Err(e) => Err(e),
                Ok(a) => Ok(EncRecord { attrs: a, enc: c }),
            },
            _ => Err(RErr::EncNotBinary),
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum RdErr {
    Record(RErr),            // fetch_record -> record_from_ddb_item
    Kms(KmsErr),             // decrypt_branch_key (KMS Decrypt with the AAD)
    Reconstruct(Fail),       // branch_key_materials_from_authenticated_encryption_context
}

/// The shared prefix of the three production reads (get_active_branch_key :792, get_branch_key_version
/// :827, get_beacon_key :868): the record from the item, KMS Decrypt with `kms_aad` as AAD
/// (decrypt_branch_key, kms_ops.rs :162-208), then the authenticated EC for the caller via
/// `build_auth_ec`. Returns the plaintext key and the EC the caller will use.
/// `ka` is the enumeration of the record's attribute map in kms_ops.rs :55.
/// NOT modeled (assumption A_ARN): fetch_record's key selection, kms-arn resolution and
/// compatibility (resolve_key_store_arn), grant tokens, and KMS service errors other than the
/// EC check.
pub open spec fn read_auth(item: Map<Str, AV>, n: Str, kr: Seq<Str>, ka: Seq<Str>)
    -> Result<(Seq<u8>, Ec), RdErr>
{
    match record_from_item(item, kr) {
        Err(e) => Err(RdErr::Record(e)),
        Ok(r) => match kms_decrypt(r.enc, kms_aad(r.attrs, ka, n)) {
            Err(e) => Err(RdErr::Kms(e)),
            Ok(pt) => Ok((pt, rec_auth_ec(r.attrs, n))),
        },
    }
}

/// get_active_branch_key / get_branch_key_version: `read_auth`, then the reconstruction (T02 model).
pub open spec fn read_branch_key(item: Map<Str, AV>, n: Str, kr: Seq<Str>, ka: Seq<Str>)
    -> Result<Materials, RdErr>
{
    match read_auth(item, n, kr, ka) {
        Err(e) => Err(e),
        Ok(p) => match reconstruct(p.1, p.0) {
            Err(f) => Err(RdErr::Reconstruct(f)),
            Ok(m) => Ok(m),
        },
    }
}

// ============================================================
// SECTION K3: loop lemmas (every enumeration order)
// ============================================================

/// The copy loop reproduces the map.
proof fn lemma_copy_fold(attrs: Ec, ka: Seq<Str>)
    requires
        forall|i: int| 0 <= i < ka.len() ==> #[trigger] attrs.contains_key(ka[i]),
    ensures
        forall|k: Str| #[trigger] copy_fold(attrs, ka).contains_key(k) <==> ka.contains(k),
        forall|k: Str| #[trigger] copy_fold(attrs, ka).contains_key(k)
            ==> copy_fold(attrs, ka)[k] == attrs[k],
    decreases ka.len(),
{
    if ka.len() > 0 {
        let init = ka.drop_last();
        let last = ka.last();
        assert forall|i: int| 0 <= i < init.len() implies #[trigger] attrs.contains_key(init[i]) by {
            assert(init[i] == ka[i]);
        }
        lemma_copy_fold(attrs, init);
        lemma_contains_drop_last(ka);
        assert(copy_fold(attrs, ka) == copy_fold(attrs, init).insert(last, attrs[last]));
    }
}

/// The copy loop equals the map when the enumeration covers it.
proof fn lemma_copy_fold_eq(attrs: Ec, ka: Seq<Str>)
    requires
        covers(attrs, ka),
    ensures
        copy_fold(attrs, ka) =~= attrs,
{
    assert forall|i: int| 0 <= i < ka.len() implies #[trigger] attrs.contains_key(ka[i]) by {
        assert(ka.to_set().contains(ka[i]));
    }
    lemma_copy_fold(attrs, ka);
    assert forall|k: Str| #[trigger] copy_fold(attrs, ka).contains_key(k) <==> attrs.contains_key(k) by {
        assert(ka.to_set().contains(k) <==> ka.contains(k));
        assert(ka.to_set().contains(k) <==> attrs.dom().contains(k));
    }
}

/// item_from_ec_and_enc's loop: the stored attributes are the EC entries except `tablename`.
proof fn lemma_item_fold(ec: Ec, kw: Seq<Str>)
    requires
        forall|i: int| 0 <= i < kw.len() ==> #[trigger] ec.contains_key(kw[i]),
    ensures
        forall|k: Str| #[trigger] item_fold(ec, kw).contains_key(k)
            <==> (kw.contains(k) && k != k_tablename()),
        forall|k: Str| #[trigger] item_fold(ec, kw).contains_key(k)
            ==> item_fold(ec, kw)[k] == item_val(k, ec[k]),
    decreases kw.len(),
{
    if kw.len() > 0 {
        let init = kw.drop_last();
        let last = kw.last();
        assert forall|i: int| 0 <= i < init.len() implies #[trigger] ec.contains_key(init[i]) by {
            assert(init[i] == kw[i]);
        }
        lemma_item_fold(ec, init);
        lemma_contains_drop_last(kw);
        assert(ec.contains_key(last)) by {
            assert(kw[kw.len() - 1] == last);
        }
        if last == k_tablename() {
            assert(item_fold(ec, kw) == item_fold(ec, init));
        } else {
            assert(item_fold(ec, kw) == item_fold(ec, init).insert(last, item_val(last, ec[last])));
        }
    }
}

/// record_from_ddb_item's inner loop: Ok exactly when every enumerated attribute is a
/// String or Number; then the result is those attributes as Strings.
proof fn lemma_rec_fold(rest: Map<Str, AV>, kr: Seq<Str>)
    requires
        forall|i: int| 0 <= i < kr.len() ==> #[trigger] rest.contains_key(kr[i]),
    ensures
        rec_fold(rest, kr) is Ok <==> (forall|k: Str| #[trigger] kr.contains(k) ==> is_str_attr(rest[k])),
        rec_fold(rest, kr) is Err ==> rec_fold(rest, kr) == Err::<Ec, RErr>(RErr::BadAttr),
        rec_fold(rest, kr) is Ok ==> (forall|k: Str| #[trigger] rec_fold(rest, kr)->Ok_0.contains_key(k)
            <==> kr.contains(k)),
        rec_fold(rest, kr) is Ok ==> (forall|k: Str| #[trigger] rec_fold(rest, kr)->Ok_0.contains_key(k)
            ==> rec_fold(rest, kr)->Ok_0[k] == str_of(rest[k])),
    decreases kr.len(),
{
    if kr.len() > 0 {
        let init = kr.drop_last();
        let last = kr.last();
        assert forall|i: int| 0 <= i < init.len() implies #[trigger] rest.contains_key(init[i]) by {
            assert(init[i] == kr[i]);
        }
        lemma_rec_fold(rest, init);
        lemma_contains_drop_last(kr);
        assert(rest.contains_key(last)) by {
            assert(kr[kr.len() - 1] == last);
        }
        match rec_fold(rest, init) {
            Err(e) => {
                assert(rec_fold(rest, kr) == rec_fold(rest, init));
                // some enumerated key of `init` is not a String/Number, and it is in `kr`
                assert(!(forall|k: Str| #[trigger] kr.contains(k) ==> is_str_attr(rest[k]))) by {
                    assert(!(forall|k: Str| #[trigger] init.contains(k) ==> is_str_attr(rest[k])));
                    let k = choose|k: Str| #![auto] init.contains(k) && !is_str_attr(rest[k]);
                    assert(kr.contains(k));
                }
            },
            Ok(acc) => {
                if is_str_attr(rest[last]) {
                    assert(rec_fold(rest, kr) == Ok::<Ec, RErr>(acc.insert(last, str_of(rest[last]))));
                    assert forall|k: Str| #[trigger] kr.contains(k) implies is_str_attr(rest[k]) by {
                        if k != last {
                            assert(init.contains(k));
                        }
                    }
                } else {
                    assert(rec_fold(rest, kr) == Err::<Ec, RErr>(RErr::BadAttr));
                    assert(kr.contains(last)) by {
                        assert(kr[kr.len() - 1] == last);
                    }
                }
            },
        }
    }
}

/// record_from_ddb_item as a whole, for any enumeration `kr` of the item without `enc`.
proof fn lemma_record_from_item(item: Map<Str, AV>, kr: Seq<Str>)
    requires
        covers(item.remove(k_enc()), kr),
    ensures
        record_from_item(item, kr) is Ok <==> (
            item.contains_key(k_enc()) && item[k_enc()] is B
            && forall|k: Str| #[trigger] item.contains_key(k) && k != k_enc() ==> is_str_attr(item[k])
        ),
        record_from_item(item, kr) is Ok ==> ({
            let r = record_from_item(item, kr)->Ok_0;
            &&& item[k_enc()] == AV::B(r.enc)
            &&& (forall|k: Str| #[trigger] r.attrs.contains_key(k)
                <==> (item.contains_key(k) && k != k_enc()))
            &&& (forall|k: Str| #[trigger] r.attrs.contains_key(k) ==> r.attrs[k] == str_of(item[k]))
            &&& !r.attrs.contains_key(k_enc())
        }),
{
    if item.contains_key(k_enc()) && item[k_enc()] is B {
        let rest = item.remove(k_enc());
        assert forall|i: int| 0 <= i < kr.len() implies #[trigger] rest.contains_key(kr[i]) by {
            assert(kr.to_set().contains(kr[i]));
        }
        lemma_rec_fold(rest, kr);
        assert forall|k: Str| #[trigger] kr.contains(k) <==> (item.contains_key(k) && k != k_enc()) by {
            assert(kr.to_set().contains(k) <==> kr.contains(k));
            assert(kr.to_set().contains(k) <==> rest.dom().contains(k));
        }
        // Ok <==> all attributes are String/Number
        if rec_fold(rest, kr) is Ok {
            assert forall|k: Str| #[trigger] item.contains_key(k) && k != k_enc() implies is_str_attr(item[k]) by {
                assert(kr.contains(k));
                assert(rest[k] == item[k]);
            }
        }
        if (forall|k: Str| #[trigger] item.contains_key(k) && k != k_enc() ==> is_str_attr(item[k])) {
            assert forall|k: Str| #[trigger] kr.contains(k) implies is_str_attr(rest[k]) by {
                assert(item.contains_key(k) && k != k_enc());
                assert(rest[k] == item[k]);
            }
            assert(rec_fold(rest, kr) is Ok);
        }
        if rec_fold(rest, kr) is Ok {
            let r = record_from_item(item, kr)->Ok_0;
            assert(r.attrs == rec_fold(rest, kr)->Ok_0);
            assert forall|k: Str| #[trigger] r.attrs.contains_key(k) implies r.attrs[k] == str_of(item[k]) by {
                assert(rest[k] == item[k]);
            }
        }
    }
}

/// custom_ec ignores a removal of a key that does not start with the prefix.
proof fn lemma_custom_ec_remove_nonprefixed(ec: Ec, k: Str)
    requires
        !custom_prefix().is_prefix_of(k),
    ensures
        custom_ec(ec.remove(k)) =~= custom_ec(ec),
{
    let e2 = ec.remove(k);
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
// SECTION K4: the READ-side EC builders agree with each other and with the spec (NEW)
// ============================================================

/// THEOREM T01-A (the two reader-side builders). The EC that is passed to KMS Decrypt as AAD
/// (kms_ops.rs :49, `kms_aad`) and the EC that is handed to the reconstruction
/// (branch_key_store.rs :132, `rec_auth_ec`) are two separately written functions. For every
/// record attribute map they return the same map. When the attributes have no `enc` key they are
/// also the spec EC "every attribute except `enc`, plus `tablename`". This equality is the
/// property that makes the authenticated EC and the EC the reconstruction reads the same thing:
/// the reconstruction takes `branch-key-id`, `type`, `version` and the custom EC from
/// `rec_auth_ec`, and KMS authenticates `kms_aad`.
proof fn theorem_reader_builders_agree(attrs: Ec, ka: Seq<Str>, n: Str)
    requires
        covers(attrs, ka),
    ensures
        kms_aad(attrs, ka, n) =~= rec_auth_ec(attrs, n),
        !attrs.contains_key(k_enc()) ==> rec_auth_ec(attrs, n) =~= spec_auth_ec(attrs, n),
        !attrs.contains_key(k_enc()) ==> kms_aad(attrs, ka, n) =~= spec_auth_ec(attrs, n),
        rec_auth_ec(attrs, n).contains_key(k_tablename()) && rec_auth_ec(attrs, n)[k_tablename()] == n,
{
    lemma_copy_fold_eq(attrs, ka);
}

/// THEOREM T01-B (the reader EC for ANY stored item is the spec EC). For every item that
/// record_from_ddb_item accepts, and every enumeration order: the EC contains `tablename` = the
/// reader's logical name and every item attribute except `enc` (as the String that S or N holds),
/// nothing else, and no `enc`. This is the YAML precondition `!r.attributes.contains_key("enc")`
/// for build_auth_ec, proved from the shape of record_from_ddb_item, and the spec definition of
/// the EC. The `tablename` entry of the EC always carries the reader's name, whatever the
/// item holds under that key.
proof fn theorem_reader_ec_is_spec(item: Map<Str, AV>, n: Str, kr: Seq<Str>, ka: Seq<Str>)
    requires
        covers(item.remove(k_enc()), kr),
        ka.to_set() =~= item.dom().remove(k_enc()),
        record_from_item(item, kr) is Ok,
    ensures
        ({
            let r = record_from_item(item, kr)->Ok_0;
            &&& !r.attrs.contains_key(k_enc())
            &&& kms_aad(r.attrs, ka, n) =~= rec_auth_ec(r.attrs, n)
            &&& rec_auth_ec(r.attrs, n) =~= spec_auth_ec(r.attrs, n)
            &&& (forall|k: Str| #[trigger] rec_auth_ec(r.attrs, n).contains_key(k)
                <==> (k == k_tablename() || (item.contains_key(k) && k != k_enc())))
            &&& (forall|k: Str| #[trigger] rec_auth_ec(r.attrs, n).contains_key(k) && k != k_tablename()
                ==> rec_auth_ec(r.attrs, n)[k] == str_of(item[k]))
            &&& rec_auth_ec(r.attrs, n)[k_tablename()] == n
        }),
{
    lemma_record_from_item(item, kr);
    let r = record_from_item(item, kr)->Ok_0;
    assert(covers(r.attrs, ka)) by {
        assert(r.attrs.dom() =~= item.dom().remove(k_enc())) by {
            assert forall|k: Str| #[trigger] r.attrs.dom().contains(k)
                <==> item.dom().remove(k_enc()).contains(k) by {
                assert(r.attrs.contains_key(k) <==> (item.contains_key(k) && k != k_enc()));
            }
        }
    }
    theorem_reader_builders_agree(r.attrs, ka, n);
}

// ============================================================
// SECTION K5: write -> store -> read round trip with the KMS leg (NEW)
// ============================================================

/// The enumerations of the three loops (A_ITER, weak form), for an EC `ec` that is written:
/// `kw` iterates the EC in item_from_ec_and_enc (:1094), `kr` iterates the item without `enc`
/// in record_from_ddb_item (:1166), `ka` iterates the record attributes in kms_ops.rs :55.
/// The item without `enc` has the keys of the EC without `tablename` (lemma_item_roundtrip).
pub open spec fn iters_ok(ec: Ec, kw: Seq<Str>, kr: Seq<Str>, ka: Seq<Str>) -> bool {
    &&& covers(ec, kw)
    &&& kr.to_set() =~= ec.dom().remove(k_tablename())
    &&& ka.to_set() =~= ec.dom().remove(k_tablename())
}

/// Well-formed written EC (hypothesis H_WF): it carries `tablename` = the key store name and no `enc`.
pub open spec fn wf_ec(ec: Ec, name: Str) -> bool {
    &&& ec.contains_key(k_tablename())
    &&& ec[k_tablename()] == name
    &&& !ec.contains_key(k_enc())
}

/// Every EC has enumerations, so `iters_ok` is satisfiable for every EC that exists at runtime.
proof fn lemma_iters_witness(ec: Ec) -> (w: (Seq<Str>, Seq<Str>, Seq<Str>))
    ensures
        iters_ok(ec, w.0, w.1, w.2),
{
    lemma_enum_exists_set(ec.dom());
    lemma_enum_exists_set(ec.dom().remove(k_tablename()));
    let kw = choose|k: Seq<Str>| k.no_duplicates() && k.to_set() =~= ec.dom();
    let kx = choose|k: Seq<Str>| k.no_duplicates() && k.to_set() =~= ec.dom().remove(k_tablename());
    assert(iters_ok(ec, kw, kx, kx));
    (kw, kx, kx)
}

/// item_from_ec_and_enc followed by record_from_ddb_item (A_DDB: the item read is the item written):
/// `enc` and every EC entry except `tablename` come back, unchanged, as Strings.
proof fn lemma_item_roundtrip(ec: Ec, c: Ct, kw: Seq<Str>, kr: Seq<Str>)
    requires
        !ec.contains_key(k_enc()),
        covers(ec, kw),
        kr.to_set() =~= ec.dom().remove(k_tablename()),
    ensures
        record_from_item(item_from_ec_and_enc(ec, kw, c), kr) is Ok,
        ({
            let r = record_from_item(item_from_ec_and_enc(ec, kw, c), kr)->Ok_0;
            &&& r.enc == c
            &&& r.attrs =~= ec.remove(k_tablename())
        }),
{
    let item = item_from_ec_and_enc(ec, kw, c);
    assert forall|i: int| 0 <= i < kw.len() implies #[trigger] ec.contains_key(kw[i]) by {
        assert(kw.to_set().contains(kw[i]));
    }
    lemma_item_fold(ec, kw);
    assert(item.contains_key(k_enc()));
    assert(item[k_enc()] == AV::B(c));
    // the item without `enc` has exactly the EC keys except `tablename`
    assert forall|k: Str| #[trigger] item.contains_key(k) && k != k_enc()
        <==> (ec.contains_key(k) && k != k_tablename()) by {
        assert(kw.to_set().contains(k) <==> kw.contains(k));
        assert(kw.to_set().contains(k) <==> ec.dom().contains(k));
    }
    assert(covers(item.remove(k_enc()), kr)) by {
        assert forall|k: Str| #[trigger] kr.to_set().contains(k) <==> item.remove(k_enc()).dom().contains(k) by {
            assert(kr.to_set().contains(k) <==> (ec.contains_key(k) && k != k_tablename()));
            assert(item.remove(k_enc()).contains_key(k) <==> (item.contains_key(k) && k != k_enc()));
        }
    }
    lemma_record_from_item(item, kr);
    assert forall|k: Str| #[trigger] item.contains_key(k) && k != k_enc() implies is_str_attr(item[k]) by {
        assert(item[k] == item_val(k, ec[k]));
    }
    let r = record_from_item(item, kr)->Ok_0;
    assert forall|k: Str| #[trigger] r.attrs.contains_key(k)
        <==> (ec.remove(k_tablename()).contains_key(k)) by {
    }
    assert forall|k: Str| #![auto] r.attrs.contains_key(k) implies r.attrs[k] == ec.remove(k_tablename())[k] by {
        assert(item[k] == item_val(k, ec[k]));
    }
    assert(r.attrs =~= ec.remove(k_tablename()));
}

/// WRITE -> STORE -> READ, with the KMS Decrypt leg. A record whose wrapped key is bound to `ec`
/// (`c.aad == ec`) and is stored with item_from_ec_and_enc is read back by `read_auth`, for a
/// reader whose logical name is the writer's (`ec[tablename] == name`), and KMS Decrypt succeeds
/// with the AAD the reader builds. The reader's AAD and the EC handed to the reconstruction both
/// equal the write-time EC.
proof fn lemma_write_then_read(ec: Ec, c: Ct, name: Str, kw: Seq<Str>, kr: Seq<Str>, ka: Seq<Str>)
    requires
        wf_ec(ec, name),
        c.aad == ec,
        iters_ok(ec, kw, kr, ka),
    ensures
        ({
            let item = item_from_ec_and_enc(ec, kw, c);
            &&& record_from_item(item, kr) is Ok
            &&& ({
                let r = record_from_item(item, kr)->Ok_0;
                &&& r.enc == c
                &&& kms_aad(r.attrs, ka, name) =~= ec
                &&& rec_auth_ec(r.attrs, name) =~= ec
            })
            &&& read_auth(item, name, kr, ka) is Ok
            &&& read_auth(item, name, kr, ka)->Ok_0.0 == c.pt
            &&& read_auth(item, name, kr, ka)->Ok_0.1 =~= ec
        }),
{
    lemma_item_roundtrip(ec, c, kw, kr);
    let item = item_from_ec_and_enc(ec, kw, c);
    let r = record_from_item(item, kr)->Ok_0;
    assert(covers(r.attrs, ka)) by {
        assert(r.attrs.dom() =~= ec.dom().remove(k_tablename()));
    }
    theorem_reader_builders_agree(r.attrs, ka, name);
    assert(rec_auth_ec(r.attrs, name) =~= ec) by {
        assert(r.attrs =~= ec.remove(k_tablename()));
    }
    assert(kms_aad(r.attrs, ka, name) == ec);
    assert(kms_decrypt(r.enc, kms_aad(r.attrs, ka, name)) == Ok::<Seq<u8>, KmsErr>(c.pt));
    assert(rec_auth_ec(r.attrs, name) == ec);
}

/// THEOREM T01-C (THREE-WAY EQUALITY; the property of VR-2026-T01). For a record written under
/// EC `ec` with the wrapped key `c = kms_generate(pt, ec)`:
///   (1) write-time EC          == the EC KMS bound the key to          (c.aad == ec)
///   (2) the EC the reader builds as KMS Decrypt AAD == the write-time EC (kms_aad)
///   (3) the EC the reader hands to the reconstruction == the write-time EC (rec_auth_ec)
/// and KMS Decrypt with that AAD returns the key that was generated. Under H_WF (the EC has
/// `tablename` = the reader's name and no `enc`) and the enumerations of H_ENUM.
/// What is NEW versus C01: C01 proves (3) (builders -> reconstruction, `lemma_store_roundtrip`);
/// (1) and (2) and the item mapping with Number/String attributes and the `enc` blob are new.
proof fn theorem_three_way(ec: Ec, pt: Seq<u8>, name: Str, kw: Seq<Str>, kr: Seq<Str>, ka: Seq<Str>)
    requires
        wf_ec(ec, name),
        iters_ok(ec, kw, kr, ka),
    ensures
        ({
            let c = kms_generate(pt, ec);
            let item = item_from_ec_and_enc(ec, kw, c);
            let r = record_from_item(item, kr)->Ok_0;
            &&& record_from_item(item, kr) is Ok
            &&& c.aad == ec
            &&& kms_aad(r.attrs, ka, name) =~= ec
            &&& rec_auth_ec(r.attrs, name) =~= ec
            &&& kms_decrypt(r.enc, kms_aad(r.attrs, ka, name)) == Ok::<Seq<u8>, KmsErr>(pt)
            &&& read_auth(item, name, kr, ka) is Ok
            &&& read_auth(item, name, kr, ka)->Ok_0.0 == pt
            &&& read_auth(item, name, kr, ka)->Ok_0.1 =~= ec
        }),
{
    lemma_write_then_read(ec, kms_generate(pt, ec), name, kw, kr, ka);
}

// ============================================================
// SECTION K6: production wiring, CreateKey then Get* (NEW: through the KMS leg)
//   create_key branch_key_store.rs :539-629 builds the three ECs (:569-571), calls KMS with the
//   SAME variables (:577-590), and stores items built from the SAME variables (:595-597).
//   That sameness is code reading (hypothesis H_SAME_EC), it is not machine-checked.
// ============================================================

/// A fresh DECRYPT_ONLY record. generate_wrapped_key(d) (:577) then item_from_ec_and_enc(d, blob)
/// (:595); read by get_branch_key_version (:827). Extends C01's theorem_prod_roundtrip with the
/// KMS leg: the wrapped key is bound to `d`, the reader's Decrypt AAD equals `d`, and the plaintext
/// the reconstruction receives is the generated key.
proof fn theorem_prod_decrypt_only(i: Input, v: Str, pt: Seq<u8>, keys: Seq<Str>,
    kw: Seq<Str>, kr: Seq<Str>, ka: Seq<Str>)
    requires
        i.id.len() > 0,
        v.len() > 0,
        pt.len() == 32,
        enumerates(i.custom, keys),
        iters_ok(decrypt_only_ec(i, v, keys)->Ok_0, kw, kr, ka),
    ensures
        decrypt_only_ec(i, v, keys) is Ok,
        ({
            let d = decrypt_only_ec(i, v, keys)->Ok_0;
            let c = kms_generate(pt, d);
            let item = item_from_ec_and_enc(d, kw, c);
            let m = read_branch_key(item, i.table, kr, ka);
            &&& read_auth(item, i.table, kr, ka) is Ok
            &&& read_auth(item, i.table, kr, ka)->Ok_0.1 =~= d
            &&& m is Ok
            &&& (m->Ok_0).branch_key =~= pt
            &&& (m->Ok_0).branch_key_id == i.id
            &&& (m->Ok_0).branch_key_version =~= v
            &&& (m->Ok_0).encryption_context =~= i.custom
        }),
{
    theorem_rt_decrypt_only(i, v, pt, keys);
    let t = version_prefix() + v;
    lemma_const_lens();
    lemma_concat_prefix(version_prefix(), v);
    lemma_build_base(i, t, keys);
    let d = decrypt_only_ec(i, v, keys)->Ok_0;
    assert(built_facts(i, t, d));
    lemma_attr_keys_distinct();
    lemma_const_lens2();
    let c = kms_generate(pt, d);
    lemma_write_then_read(d, c, i.table, kw, kr, ka);
    let item = item_from_ec_and_enc(d, kw, c);
    let p = read_auth(item, i.table, kr, ka)->Ok_0;
    assert(p.1 == d);
    assert(reconstruct(p.1, p.0) == reconstruct(d, pt));
}

/// A fresh ACTIVE record. The wrapped key is first bound to `d` (generate_wrapped_key :577), then
/// ReEncrypted from source EC `d` to destination EC `a` (:579-587): the source EC is the one the key
/// was bound to, so KMS accepts it, and the new ciphertext is bound to `a`. The item is built from
/// `a` and the new ciphertext (:596); read by get_active_branch_key (:792).
proof fn theorem_prod_active(i: Input, v: Str, pt: Seq<u8>, keys: Seq<Str>,
    kw: Seq<Str>, kr: Seq<Str>, ka: Seq<Str>)
    requires
        i.id.len() > 0,
        v.len() > 0,
        pt.len() == 32,
        enumerates(i.custom, keys),
        iters_ok(active_ec(i, v, keys)->Ok_0, kw, kr, ka),
    ensures
        decrypt_only_ec(i, v, keys) is Ok,
        active_ec(i, v, keys) is Ok,
        ({
            let d = decrypt_only_ec(i, v, keys)->Ok_0;
            let a = active_ec(i, v, keys)->Ok_0;
            let c0 = kms_generate(pt, d);
            &&& kms_reencrypt(c0, d, a) is Ok
            &&& ({
                let c = kms_reencrypt(c0, d, a)->Ok_0;
                let item = item_from_ec_and_enc(a, kw, c);
                let m = read_branch_key(item, i.table, kr, ka);
                &&& c.aad == a
                &&& read_auth(item, i.table, kr, ka) is Ok
                &&& read_auth(item, i.table, kr, ka)->Ok_0.1 =~= a
                &&& m is Ok
                &&& (m->Ok_0).branch_key =~= pt
                &&& (m->Ok_0).branch_key_id == i.id
                &&& (m->Ok_0).branch_key_version =~= v
                &&& (m->Ok_0).encryption_context =~= i.custom
            })
        }),
{
    theorem_rt_active(i, v, pt, keys);
    let t = version_prefix() + v;
    lemma_const_lens();
    lemma_const_lens2();
    lemma_concat_prefix(version_prefix(), v);
    lemma_build_base(i, t, keys);
    lemma_attr_keys_distinct();
    let d = decrypt_only_ec(i, v, keys)->Ok_0;
    let a = active_ec(i, v, keys)->Ok_0;
    assert(built_facts(i, t, d));
    assert(a == d.insert(k_type(), type_active()).insert(k_version(), version_prefix() + v));
    let c0 = kms_generate(pt, d);
    assert(kms_reencrypt(c0, d, a) is Ok);
    let c = kms_reencrypt(c0, d, a)->Ok_0;
    assert(c.aad == a);
    assert(wf_ec(a, i.table));
    lemma_write_then_read(a, c, i.table, kw, kr, ka);
    let item = item_from_ec_and_enc(a, kw, c);
    let p = read_auth(item, i.table, kr, ka)->Ok_0;
    assert(p.1 == a);
    assert(reconstruct(p.1, p.0) == reconstruct(a, pt));
}

/// A fresh beacon record (:590, :597), read by get_beacon_key (:868): KMS Decrypt succeeds with the
/// reader's AAD, and the two values the beacon read path takes from the authenticated EC
/// (custom EC :885, `branch-key-id` :887-890) are the inputs.
proof fn theorem_prod_beacon_kms(i: Input, pt: Seq<u8>, keys: Seq<Str>,
    kw: Seq<Str>, kr: Seq<Str>, ka: Seq<Str>)
    requires
        i.id.len() > 0,
        enumerates(i.custom, keys),
        iters_ok(beacon_ec(i, keys)->Ok_0, kw, kr, ka),
    ensures
        beacon_ec(i, keys) is Ok,
        ({
            let b = beacon_ec(i, keys)->Ok_0;
            let c = kms_generate(pt, b);
            let item = item_from_ec_and_enc(b, kw, c);
            &&& read_auth(item, i.table, kr, ka) is Ok
            &&& read_auth(item, i.table, kr, ka)->Ok_0.0 == pt
            &&& ({
                let auth = read_auth(item, i.table, kr, ka)->Ok_0.1;
                &&& auth =~= b
                &&& auth.contains_key(k_id()) && auth[k_id()] == i.id
                &&& custom_ec(auth) =~= i.custom
            })
        }),
{
    lemma_const_lens();
    lemma_const_lens2();
    lemma_build_base(i, type_beacon(), keys);
    lemma_attr_keys_distinct();
    let b = beacon_ec(i, keys)->Ok_0;
    assert(built_facts(i, type_beacon(), b));
    let c = kms_generate(pt, b);
    lemma_write_then_read(b, c, i.table, kw, kr, ka);
}

// ============================================================
// SECTION K7: VersionKey (branch_key_store.rs :641-775): rotation preserves the equality (NEW)
// ============================================================

/// new_decrypt_only_ec (:706-712): `type` := `branch:version:<v2>`, `create-time` := ts, drop `version`.
pub open spec fn rotate_decrypt_only(old: Ec, v2: Str, ts: Str) -> Ec {
    old.insert(k_type(), version_prefix() + v2).insert(k_create_time(), ts).remove(k_version())
}

/// new_active_ec (:714-721): the new DECRYPT_ONLY EC with `version` := its `type`, then `type` := ACTIVE.
pub open spec fn rotate_active(old: Ec, v2: Str, ts: Str) -> Ec {
    let d = rotate_decrypt_only(old, v2, ts);
    d.insert(k_version(), d[k_type()]).insert(k_type(), type_active())
}

/// The two rotated ECs are well formed, and the reconstruction of each recovers the old id, the new
/// version v2 and the old custom EC (the spec says the custom EC MUST be equal across versions).
proof fn lemma_rotation_facts(old: Ec, name: Str, v2: Str, ts: Str, pt2: Seq<u8>)
    requires
        wf_ec(old, name),
        old.contains_key(k_id()),
        old[k_id()].len() > 0,
        v2.len() > 0,
        pt2.len() == 32,
    ensures
        wf_ec(rotate_decrypt_only(old, v2, ts), name),
        wf_ec(rotate_active(old, v2, ts), name),
        reconstruct(rotate_decrypt_only(old, v2, ts), pt2) is Ok,
        reconstruct(rotate_active(old, v2, ts), pt2) is Ok,
        ({
            let m = reconstruct(rotate_decrypt_only(old, v2, ts), pt2)->Ok_0;
            &&& m.branch_key =~= pt2
            &&& m.branch_key_id == old[k_id()]
            &&& m.branch_key_version =~= v2
            &&& m.encryption_context =~= custom_ec(old)
        }),
        ({
            let m = reconstruct(rotate_active(old, v2, ts), pt2)->Ok_0;
            &&& m.branch_key =~= pt2
            &&& m.branch_key_id == old[k_id()]
            &&& m.branch_key_version =~= v2
            &&& m.encryption_context =~= custom_ec(old)
        }),
{
    lemma_const_lens();
    lemma_const_lens2();
    lemma_attr_keys_distinct();
    lemma_attr_keys_not_custom_prefixed();
    lemma_concat_prefix(version_prefix(), v2);
    let t = version_prefix() + v2;
    let e1 = old.insert(k_type(), t);
    let e2 = e1.insert(k_create_time(), ts);
    let nd = e2.remove(k_version());
    assert(nd == rotate_decrypt_only(old, v2, ts));
    let na0 = nd.insert(k_version(), nd[k_type()]);
    let na = na0.insert(k_type(), type_active());
    assert(na == rotate_active(old, v2, ts));
    assert(nd[k_type()] == t);
    assert(nd.contains_key(k_id()) && nd[k_id()] == old[k_id()]);
    assert(wf_ec(nd, name));
    assert(wf_ec(na, name));
    // custom EC is untouched: every key changed is a non-prefixed attribute name
    lemma_custom_ec_insert_nonprefixed(old, k_type(), t);
    lemma_custom_ec_insert_nonprefixed(e1, k_create_time(), ts);
    lemma_custom_ec_remove_nonprefixed(e2, k_version());
    lemma_custom_ec_insert_nonprefixed(nd, k_version(), nd[k_type()]);
    lemma_custom_ec_insert_nonprefixed(na0, k_type(), type_active());
    assert(custom_ec(nd) =~= custom_ec(old));
    assert(custom_ec(na) =~= custom_ec(old));
    // DECRYPT_ONLY: type == branch:version:<v2>
    assert(t != type_active()) by {
        assert(t.len() > 15);
    }
    assert(ver_src(nd) == t);
    assert(strict_prefix(version_prefix(), ver_src(nd)));
    assert(code_accepts(nd, pt2));
    theorem_a_ok_iff_code_accepts(nd, pt2);
    theorem_b_ok_fields(nd, pt2);
    assert(ver_src(nd).skip(version_prefix().len() as int) =~= v2);
    // ACTIVE: type == ACTIVE, version == branch:version:<v2>
    assert(na.contains_key(k_version()) && na[k_version()] == t);
    assert(na[k_type()] == type_active());
    assert(ver_src(na) == t);
    assert(strict_prefix(version_prefix(), ver_src(na)));
    assert(na.contains_key(k_id()) && na[k_id()] == old[k_id()]);
    assert(code_accepts(na, pt2));
    theorem_a_ok_iff_code_accepts(na, pt2);
    theorem_b_ok_fields(na, pt2);
    assert(ver_src(na).skip(version_prefix().len() as int) =~= v2);
}

/// The old ACTIVE EC that version_key derives (:671) from ANY stored item that record_from_ddb_item accepts.
pub open spec fn old_active_ec(item0: Map<Str, AV>, kr0: Seq<Str>, name: Str) -> Ec {
    rec_auth_ec(record_from_item(item0, kr0)->Ok_0.attrs, name)
}

/// THEOREM T01-D (VersionKey keeps the three-way equality). version_key authenticates the stored
/// ACTIVE item by ReEncrypt with source == destination == the reconstructed EC (:678-684): that
/// succeeds exactly when the stored ciphertext is bound to that EC. It then derives the two new ECs
/// from the reconstructed EC (:706-721), wraps a fresh key under each (:725-736), and stores items
/// built from those ECs (:739, :748). For ANY item the reader accepts (not only honest ones):
///   * the new ECs are well formed (they carry `tablename` = the reader's name, no `enc`), because
///     the reconstructed EC always has them (theorem_reader_ec_is_spec);
///   * new records read back, with the KMS Decrypt leg, as ACTIVE and DECRYPT_ONLY records of
///     version v2, with the OLD branch-key-id and the OLD custom EC, and the new key.
/// The old record reading Ok at the authentication step is the premise of the flow: the
/// authentication holds iff `r0.enc.aad == old` (the first ensures).
proof fn theorem_version_key(item0: Map<Str, AV>, kr0: Seq<Str>, name: Str, v2: Str, ts: Str,
    pt2: Seq<u8>, kwd: Seq<Str>, krd: Seq<Str>, kad: Seq<Str>,
    kwa: Seq<Str>, kra: Seq<Str>, kaa: Seq<Str>)
    requires
        covers(item0.remove(k_enc()), kr0),
        record_from_item(item0, kr0) is Ok,
        old_active_ec(item0, kr0, name).contains_key(k_id()),
        old_active_ec(item0, kr0, name)[k_id()].len() > 0,
        v2.len() > 0,
        pt2.len() == 32,
        iters_ok(rotate_decrypt_only(old_active_ec(item0, kr0, name), v2, ts), kwd, krd, kad),
        iters_ok(rotate_active(old_active_ec(item0, kr0, name), v2, ts), kwa, kra, kaa),
    ensures
        ({
            let r0 = record_from_item(item0, kr0)->Ok_0;
            let old = old_active_ec(item0, kr0, name);
            kms_reencrypt(r0.enc, old, old) is Ok <==> r0.enc.aad == old
        }),
        ({
            let old = old_active_ec(item0, kr0, name);
            let nd = rotate_decrypt_only(old, v2, ts);
            let na = rotate_active(old, v2, ts);
            let cd = kms_generate(pt2, nd);
            &&& wf_ec(nd, name) && wf_ec(na, name)
            &&& kms_reencrypt(cd, nd, na) is Ok
            &&& ({
                let ca = kms_reencrypt(cd, nd, na)->Ok_0;
                let item_d = item_from_ec_and_enc(nd, kwd, cd);
                let item_a = item_from_ec_and_enc(na, kwa, ca);
                let md = read_branch_key(item_d, name, krd, kad);
                let ma = read_branch_key(item_a, name, kra, kaa);
                &&& ca.aad == na
                &&& md is Ok && ma is Ok
                &&& (md->Ok_0).branch_key =~= pt2 && (ma->Ok_0).branch_key =~= pt2
                &&& (md->Ok_0).branch_key_id == old[k_id()] && (ma->Ok_0).branch_key_id == old[k_id()]
                &&& (md->Ok_0).branch_key_version =~= v2 && (ma->Ok_0).branch_key_version =~= v2
                &&& (md->Ok_0).encryption_context =~= custom_ec(old)
                &&& (ma->Ok_0).encryption_context =~= custom_ec(old)
            })
        }),
{
    lemma_record_from_item(item0, kr0);
    let r0 = record_from_item(item0, kr0)->Ok_0;
    let old = old_active_ec(item0, kr0, name);
    assert(wf_ec(old, name)) by {
        assert(rec_auth_ec(r0.attrs, name).contains_key(k_tablename()));
        assert(!r0.attrs.contains_key(k_enc()));
        lemma_attr_keys_distinct();
        assert(!old.contains_key(k_enc()));
    }
    lemma_rotation_facts(old, name, v2, ts, pt2);
    let nd = rotate_decrypt_only(old, v2, ts);
    let na = rotate_active(old, v2, ts);
    let cd = kms_generate(pt2, nd);
    let ca = kms_reencrypt(cd, nd, na)->Ok_0;
    assert(kms_reencrypt(cd, nd, na) is Ok);
    lemma_write_then_read(nd, cd, name, kwd, krd, kad);
    lemma_write_then_read(na, ca, name, kwa, kra, kaa);
    let item_d = item_from_ec_and_enc(nd, kwd, cd);
    let item_a = item_from_ec_and_enc(na, kwa, ca);
    let pd = read_auth(item_d, name, krd, kad)->Ok_0;
    let pa = read_auth(item_a, name, kra, kaa)->Ok_0;
    assert(pd.1 == nd);
    assert(pa.1 == na);
    assert(reconstruct(pd.1, pd.0) == reconstruct(nd, pt2));
    assert(reconstruct(pa.1, pa.0) == reconstruct(na, pt2));
}

// ============================================================
// SECTION K8: the KMS check is what stops record substitution (NEW; TM-MPL-005, TM-MPL-002)
// ============================================================

/// THEOREM T01-E (authenticity of the read). For ANY item and ANY reader name, if the production
/// read gets past KMS Decrypt, then the EC the reconstruction uses is EXACTLY the EC the stored
/// ciphertext is bound to, and the plaintext is the one that ciphertext hides. Hence:
///   * every attribute of the item (except `enc`, `tablename`) is the attribute that was bound at
///     write time: none added, none dropped, none altered (as a String);
///   * the ciphertext was written for this logical key store name (`tablename` is bound);
///   * the materials the reader returns are exactly reconstruct(c.aad, c.pt), the materials of the
///     record that was written. A DynamoDB writer who can change attributes but cannot make KMS bind
///     a new EC cannot change them.
/// Under A_KMS (KMS enforces the EC as AAD) and A_ITER. Substitution of a different record's
/// attributes, an older record's attributes, or a record from another key store name is rejected by
/// `kms_decrypt` in the model: it needs c.aad == the reader EC.
/// An item attribute named `tablename` is not authenticated and not used: both builders overwrite it
/// with the reader's name (observation O3).
proof fn theorem_read_authentic(item: Map<Str, AV>, name: Str, kr: Seq<Str>, ka: Seq<Str>)
    requires
        covers(item.remove(k_enc()), kr),
        ka.to_set() =~= item.dom().remove(k_enc()),
        read_auth(item, name, kr, ka) is Ok,
    ensures
        item.contains_key(k_enc()),
        item[k_enc()] is B,
        ({
            let c = item[k_enc()]->B_0;
            let p = read_auth(item, name, kr, ka)->Ok_0;
            &&& p.0 == c.pt
            &&& p.1 =~= c.aad
            &&& c.aad.contains_key(k_tablename()) && c.aad[k_tablename()] == name
            &&& (forall|k: Str| #[trigger] item.contains_key(k) && k != k_enc() && k != k_tablename()
                ==> c.aad.contains_key(k) && c.aad[k] == str_of(item[k]))
            &&& (forall|k: Str| #[trigger] c.aad.contains_key(k) && k != k_tablename()
                ==> item.contains_key(k) && k != k_enc())
        }),
        read_branch_key(item, name, kr, ka) is Ok ==> ({
            let c = item[k_enc()]->B_0;
            &&& reconstruct(c.aad, c.pt) is Ok
            &&& reconstruct(c.aad, c.pt)->Ok_0 == read_branch_key(item, name, kr, ka)->Ok_0
        }),
{
    lemma_record_from_item(item, kr);
    theorem_reader_ec_is_spec(item, name, kr, ka);
    let r = record_from_item(item, kr)->Ok_0;
    let aad = kms_aad(r.attrs, ka, name);
    assert(kms_decrypt(r.enc, aad) is Ok);
    assert(r.enc.aad == aad);
    assert(item[k_enc()] == AV::B(r.enc));
    let c = r.enc;
    let p = read_auth(item, name, kr, ka)->Ok_0;
    assert(p.1 == rec_auth_ec(r.attrs, name));
    assert(aad =~= rec_auth_ec(r.attrs, name));
    assert(p.1 =~= c.aad);
    assert(c.aad == p.1);
    assert(c.aad.contains_key(k_tablename()));
    assert forall|k: Str| #[trigger] item.contains_key(k) && k != k_enc() && k != k_tablename()
        implies c.aad.contains_key(k) && c.aad[k] == str_of(item[k]) by {
        assert(rec_auth_ec(r.attrs, name).contains_key(k));
    }
    assert forall|k: Str| #[trigger] c.aad.contains_key(k) && k != k_tablename()
        implies item.contains_key(k) && k != k_enc() by {
        assert(rec_auth_ec(r.attrs, name).contains_key(k));
    }
    if read_branch_key(item, name, kr, ka) is Ok {
        assert(reconstruct(p.1, p.0) is Ok);
        assert(p.0 == c.pt);
    }
}

/// OBSERVATION T01-F (S/N tag). record_from_ddb_item turns `AttributeValue::S(s)` and
/// `AttributeValue::N(s)` into the same String, so the S-versus-N tag of an attribute is NOT part
/// of what KMS authenticates. Changing the tag of an attribute (same string) yields the same record,
/// hence the same EC, the same KMS check and the same materials. The reader never sees the tag, so
/// the malleability has no effect on the materials. (Evidence: proved in the model.)
proof fn theorem_sn_tag_not_authenticated(item: Map<Str, AV>, k: Str, s: Str, kr: Seq<Str>)
    requires
        k != k_enc(),
        covers(item.remove(k_enc()).insert(k, AV::S(s)), kr),
    ensures
        record_from_item(item.insert(k, AV::S(s)), kr) is Ok <==> record_from_item(item.insert(k, AV::N(s)), kr) is Ok,
        record_from_item(item.insert(k, AV::S(s)), kr) is Ok ==> ({
            let r1 = record_from_item(item.insert(k, AV::S(s)), kr)->Ok_0;
            let r2 = record_from_item(item.insert(k, AV::N(s)), kr)->Ok_0;
            &&& r1.attrs =~= r2.attrs
            &&& r1.enc == r2.enc
        }),
{
    let i1 = item.insert(k, AV::S(s));
    let i2 = item.insert(k, AV::N(s));
    assert(i1.remove(k_enc()) =~= item.remove(k_enc()).insert(k, AV::S(s)));
    assert(i2.remove(k_enc()) =~= item.remove(k_enc()).insert(k, AV::N(s)));
    assert(i1.dom() =~= i2.dom());
    assert(covers(i2.remove(k_enc()), kr));
    lemma_record_from_item(i1, kr);
    lemma_record_from_item(i2, kr);
    if record_from_item(i1, kr) is Ok {
        let r1 = record_from_item(i1, kr)->Ok_0;
        let r2 = record_from_item(i2, kr)->Ok_0;
        assert(r1.attrs =~= r2.attrs) by {
            assert forall|x: Str| #![auto] r1.attrs.contains_key(x) <==> r2.attrs.contains_key(x) by {}
            assert forall|x: Str| #![auto] r1.attrs.contains_key(x) implies r1.attrs[x] == r2.attrs[x] by {
                if x != k {
                    assert(i1[x] == i2[x]);
                }
            }
        }
    }
}

// ============================================================
// SECTION K9: non-vacuity witnesses
// ============================================================

/// The hypotheses of theorem_prod_active are satisfiable for every input with a non-empty id and
/// version: the builder enumeration and the three item enumerations exist, and the ReEncrypt and the
/// read succeed. (Stated from the existence lemmas, so it does not depend on a particular order.)
proof fn lemma_prod_active_nonvacuous(i: Input, v: Str, pt: Seq<u8>)
    requires
        i.id.len() > 0,
        v.len() > 0,
        pt.len() == 32,
    ensures
        exists|keys: Seq<Str>, kw: Seq<Str>, kr: Seq<Str>, ka: Seq<Str>| #![auto]
            enumerates(i.custom, keys)
            && active_ec(i, v, keys) is Ok
            && iters_ok(active_ec(i, v, keys)->Ok_0, kw, kr, ka)
            && read_branch_key(
                item_from_ec_and_enc(
                    active_ec(i, v, keys)->Ok_0, kw,
                    kms_reencrypt(kms_generate(pt, decrypt_only_ec(i, v, keys)->Ok_0),
                                  decrypt_only_ec(i, v, keys)->Ok_0, active_ec(i, v, keys)->Ok_0)->Ok_0),
                i.table, kr, ka) is Ok,
{
    lemma_enum_exists(i.custom);
    let keys = choose|keys: Seq<Str>| enumerates(i.custom, keys);
    theorem_rt_active(i, v, pt, keys);
    let a = active_ec(i, v, keys)->Ok_0;
    let w = lemma_iters_witness(a);
    let kw = w.0;
    let kr = w.1;
    let ka = w.2;
    theorem_prod_active(i, v, pt, keys, kw, kr, ka);
    let d = decrypt_only_ec(i, v, keys)->Ok_0;
    let c = kms_reencrypt(kms_generate(pt, d), d, a)->Ok_0;
    assert(enumerates(i.custom, keys) && active_ec(i, v, keys) is Ok && iters_ok(a, kw, kr, ka)
        && read_branch_key(item_from_ec_and_enc(a, kw, c), i.table, kr, ka) is Ok);
}

} // verus!

// Verus needs an entry point when run on a single file; nothing here is executed.
fn main() {}
