// =============================================================================
// VR-2026-T10 (TM-MPL-013, priority 2.88): the branch-key AAD and the UUID codec
//   branch_key_wrap::compute_aad, uuid_str_to_16_bytes (branch_key_wrap.rs), uuid_16_bytes_to_str
//   (hierarchical_keyring.rs), and the part of EncryptionContext::to_bytes that compute_aad calls
//
// Run:  ~/verus/verus verus-proofs/t10_compute_aad_uuid.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model: byte sequences are `Seq<u8>`, the
// encryption context is the list of (key, value) byte pairs that `to_bytes` iterates over, and
// the `uuid` crate is re-typed from its 1.27.0 source. The shipped functions are native Rust, are
// not inside `verus!`, and are not compiled by Verus. Nothing here detects a later edit to mpl/
// or to the `uuid` crate. The link between model and code is the correspondence table in
// section 2, reviewed by a human.
//
// STATUS: PARTLY PROVED. Everything verifies except ONE obligation that Verus REJECTS ON PURPOSE
// (EXPECTED_FAIL):
//     `lemma_aad_injective_all_inputs_EXPECTED_FAIL`
// It states "equal AADs imply equal (branch key id, version, encryption context)" for ALL inputs.
// The AAD layout has no length or separator before the branch key id (finding F1, section 5), so
// the claim is false. The lemma is left failing: not weakened, not assumed, not commented out.
// `lemma_cross_bkid_collision_witness` proves a concrete collision as an ordinary lemma, and
// `lemma_aad_injective_claim_is_false` shows the failing statement is false and not merely
// unproved. The same pair was run through the shipped `compute_aad` outside the repo (section 5).
// Result line:  `verification results:: 55 verified, 1 errors`  (the 1 error is the lemma above)
//
// =============================================================================
// WHAT IS PROVED (relative to the model and to section 4)
// =============================================================================
//   R1  theorem_compute_aad_layout   an Ok result is label(17) || id || version(16) || ser(ec),
//                                    the fields at fixed offsets. CONSISTENCY CHECK: `aad_bytes` is
//                                    written as that concatenation, so the theorem reads the offsets
//                                    back. It checks the 17/16 sizes against the spec table, not the
//                                    code against the model. Test `compute_aad_layout_for_known_inputs`
//                                    (test_aws_kms_hierarchical_keyring.rs :826) checks one input.
//   R2  theorem_compute_aad_ok_iff   Ok exactly when the version is a canonical 36-byte hyphenated
//                                    string and the context serializes; the version error comes first.
//   R3  injectivity and the exact collision set (no assumption on the inputs)
//       lemma_ser_inj                    `to_bytes` is injective on the lists it can serialize
//                                        (count, key and value lengths below 2^16), the empty list
//                                        included (it serializes to zero bytes).
//       theorem_aad_injective_fixed_bkid for a fixed branch key id, equal Ok results give the same 16
//                                        version bytes and the same entry list.
//       theorem_aad_injective_equal_length_ids   the same, with the id determined too, when the two ids
//                                        have equal length.
//       lemma_collision_iff              for |id1| <= |id2|: equal AAD <=> id1 is a prefix of id2 and
//                                        (version1 || context1) equals (rest of id2) || version2 || context2.
//       theorem_collision_needs_different_id_lengths   two different triples can share an AAD only if
//                                        the ids have different lengths.
//       lemma_cross_bkid_collision_witness   a concrete collision, id "b" with {"k":"v"} against id
//                                        "bABCDEFGH" with the empty context (section 5, F1).
//       lemma_aad_injective_all_inputs_EXPECTED_FAIL   the unconditional claim, REJECTED on purpose.
//   R4  the UUID codec (spec level)
//       lemma_roundtrip_bytes            for EVERY 16-byte input, string(bytes) is a canonical string, the
//                                        gate accepts it, and parsing returns the input (total on valid
//                                        input; this is the YAML's `uuid_round_trip`).
//       lemma_gate_accepts_exactly_canonical   the gate is Some exactly on canonical strings.
//       lemma_format_of_parse            parse then format gives the input with A-F folded to a-f.
//       lemma_string_roundtrip_iff_lowercase   the string round trip holds exactly on strings with no
//                                        uppercase hex letter.
//       lemma_parse_equal_iff_fold_equal two canonical strings give the same bytes iff they are equal
//                                        after case folding (so: injective on lowercase, not in general).
//       lemma_uppercase_is_accepted      an all-uppercase string is accepted and equals its lowercase
//                                        form in bytes (observation O1).
//       lemma_gate_rejects_simple_form   the explicit length check is what excludes the 32-digit form.
//       lemma_gate_accepts_non_v4        the gate does not test the UUID version digit (observation O3).
//       lemma_crate_hex_trick, lemma_crate_hex_value   the crate's branch-free hex test accepts exactly the
//                                        bytes `hexval` accepts and decodes them to the same value.
//       lemma_format36_alphabet          every output byte is '-' or a lowercase hex digit, never 0x00.
//   R5  theorem_wrap_unwrap_same_aad     if wrap accepted version string s and decrypt rebuilds the string
//                                        from the version bytes, compute_aad gives the same result on both
//                                        sides (relative to H_VERSION_FLOW), and that string has no A-F.
//   R6  executable models, checked by Verus against the specs: uuid_16_bytes_to_str_exec,
//       uuid_str_to_16_bytes_exec, uuid_roundtrip_exec (round trip through the two models for every
//       16-byte input), to_bytes_exec, compute_aad_exec. Verus also checks that they do no overflow,
//       out-of-range index or underflow.
//
// =============================================================================
// WHAT IS NOT PROVED / WHAT THIS DOES NOT SHOW
// =============================================================================
//   * That the shipped code has any of these properties (model level only).
//   * That TM-MPL-013 is mitigated. The AAD being a function of its inputs, injective for a fixed id,
//     and built by one function on both sides is a property of the model. Whether a cross-id
//     collision can be used depends on the AES-GCM key being different for different ids and
//     versions (H_KEY_SEPARATION below). Not proved, not examined here.
//   * `EncryptionContext::from_bytes`, the round trip `from_bytes(to_bytes(ec)) == ec`, the order and
//     duplicate rules, and the empty-key rule. That is T15 and is not started. Only the injectivity of
//     `to_bytes`, which `compute_aad` needs, is proved here, on the entry list (H_EC_LIST).
//   * That `BranchKeyMaterials` carries a version string that matches the one the key store was asked
//     for (H_VERSION_FLOW).
//   * AES-GCM, the KDF, or that an AAD mismatch makes unwrap fail. `unwrap` and `wrap` are not modeled
//     beyond the AAD and the UUID codec (T04 models `wrap`).
//   * Panic freedom of the shipped functions, error values, error text, and the `Vec::with_capacity`
//     arithmetic (A_ALLOC).
//   * That the 17 label bytes spell "aws-kms-hierarchy". They are typed twice, as `label()` and as the
//     array in `compute_aad_exec`, and Verus checks the two agree. A mutant that changes both survives
//     (t10-run.md, x01). The bytes were compared with the shipped constant by reading and by the code run
//     in section 5.
//   * The braced (38) and URN (45) forms of `Uuid::parse_str`. They are not modeled; the length check
//     excludes every length but 36 whatever the crate does there.
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD cff28df)
// =============================================================================
//   mpl/src/aws_kms/branch_key_wrap.rs   (md5 6b3ce1d284db43822c38b66b613c0002)
//     :28      VERSION_LEN = 16
//     :40      HIERARCHY_LABEL = b"aws-kms-hierarchy"  (17 bytes)
//     :61-80   compute_aad: gate :66, serialize :68, with_capacity :70-72, four extends :74-77
//     :82-110  uuid_str_to_16_bytes: doc :82-91, length check :101, `Uuid::parse_str` :106, bytes :109
//     :157-185 wrap: compute_aad :178, uuid_str_to_16_bytes :185 (the T04 call sites)
//     :230-271 unwrap: ignores the ciphertext version bytes (`_version` :254), compute_aad :269
//   mpl/src/aws_kms/hierarchical_keyring.rs   (md5 14d3f10c7ae8788f3819369909dc97a3)
//     :644-645 uuid_16_bytes_to_str = Uuid::from_bytes(*bytes).hyphenated().to_string()
//     :813, :879-896 CIPHERTEXT_VERSION_OFFSET/LEN, version bytes of an EDK to string, then
//              decrypt_edk_at_version (:905-948): key store lookup, then `branch_key_wrap::unwrap`
//   mpl/src/structures/encryption_context.rs   (md5 27cf55faba5c8f4fbc4c391aa527defd)
//     :91-137  to_bytes: empty -> empty (:92-94); count :100; entries in BTreeMap order :111-134
//     :112, :124 key and value length checks; :121, :133 `u16::to_be_bytes`
//   mpl/src/key_store/record.rs :118-178  where a materials' version string comes from (the record)
//   uuid 1.27.0 (mpl/Cargo.lock :1914-1915; source read from the cargo registry copy):
//     src/parser.rs :147-153 try_parse dispatch on length; :191 parse_simple; :231-282 parse_hyphenated
//     (dashes at 8, 13, 18, 23, then the decoder); :286 decode_hex32 (digit = c-'0' < 10,
//     alpha = (c|0x20)-'a' < 6, value alpha+10)
//     src/fmt.rs :185 nibble_to_hex, :190 format_simple, :204 format_hyphenated, :1145-1157 Display and
//     LowerHex (Display is lowercase)
//   spec/framework/aws-kms/aws-kms-hierarchical-keyring.md :324-344 (AAD section, the field table :337-342:
//     17, variable, 16, variable; the failure sentence :344); spec/framework/structures.md :402-406 (version MUST be a v4 UUID)
//   Tests (not proofs, not run for this step): mpl/tests/test_aws_kms_hierarchical_keyring.rs :826
//     compute_aad_layout_for_known_inputs, :862 compute_aad_appends_serialized_encryption_context,
//     :884 compute_aad_fails_when_encryption_context_value_too_large.
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code)
// =============================================================================
//   model                         shipped
//   ----------------------------  -----------------------------------------------------------
//   Bytes = Seq<u8>               `&[u8]`, and `&str` through `as_bytes()` (H_BYTES)
//   EcList                        the (key, value) pairs of `for (key, value) in &self.0` (H_EC_LIST)
//   label()                       HIERARCHY_LABEL, :40
//   be16, enc_entry, ser_entries  `u16::to_be_bytes` and the per-entry extends, :121-134
//   ser_ok, ser                   `to_bytes` Ok / its Ok value, :91-137 (empty case :92-94)
//   aad_bytes                     the four `extend_from_slice` calls, branch_key_wrap.rs :74-77
//   gate                          `uuid_str_to_16_bytes` without its error value, :92-110
//   crate_parse, parse32, parse36 `Uuid::parse_str`, for the 32 and 36 forms, parser.rs :147-153, :191, :231
//   canonical36, hexval           parse_hyphenated's hyphen test and decode_hex32's accept set
//   format36                      `Uuid::hyphenated().to_string()`, fmt.rs :204, :1145-1157
//   compute_aad_spec              `compute_aad`, :61-80; AadErr::Version is Kind::InvalidMaterials,
//                                 AadErr::Ec is Kind::Validation
//   *_exec                        executable re-typings of the same functions (Vec/array loops)
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED
// =============================================================================
// Spec-derived: the AAD layout (label, id, 16 version bytes, serialized context) and the field sizes
// 17 / variable / 16 / variable (aws-kms-hierarchical-keyring.md :324-342); "cannot serialize the
// context -> MUST fail" (:344). R1 is a check of the model against that text.
// Code-derived: the canonical-string accept set (the spec says nothing about the string form of the
// version, only that the value is a v4 UUID, structures.md :406), the version-gate-first error order,
// lowercase formatting, the empty-context-is-empty-bytes rule, and the u16 bounds of `to_bytes`.
// The AAD section does not say how the serialized context is encoded; it points to the structures
// serialization section, which this file does not read. The `to_bytes` model follows the code.
//
// =============================================================================
// 4. HYPOTHESES AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and the hypotheses
//    ASSUMED       taken as a premise or a definition; not proved here (A_*)
//    CODE READING  a claim about shipped code or a crate that Verus does not see (H_*); checked by a
//                  human reading the source at the lines named
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier..]`
//  attribute is written in this file, and there is no uninterpreted spec function. The only
//  `assume_specification`s relied on are vstd's (A_VSTD).
//
//  H_MODEL_MATCH (CODE READING). The model functions have the same inputs, the same order of checks
//    and the same byte assembly as the lines in section 2. Checked by reading; not machine-checked.
//  H_AAD_PURE (CODE READING, from T04; see section 6 for how T10 treats it). `compute_aad` and
//    `uuid_str_to_16_bytes` depend only on their arguments: no generator, no global, no cache, no I/O.
//    The functions they call are `Uuid::parse_str`, `to_bytes`, `Vec` operations and error
//    constructors. Read at the lines in section 1. Not machine-checked for native code.
//  H_BYTES (CODE READING). A `&str` is its UTF-8 bytes. UTF-8 validity is not modeled, except that the
//    concrete collision uses ASCII bytes only (`lemma_cross_bkid_witness_is_ascii`), so each of its fields
//    is a valid `&str`. Nothing in `compute_aad` checks the branch key id: it is any `&str`.
//  H_EC_LIST (CODE READING). `EncryptionContext` wraps a `BTreeMap<String, String>`; `to_bytes` walks it
//    in ascending key order (:111). The model takes that walk as an `EcList`. Equal maps give equal
//    lists (iteration is deterministic), and equal lists give equal maps (a map is its entries).
//    Both directions are used: R3 needs the second, R5 the first. Sortedness is not used by any proof.
//  H_UUID_PARSE (CODE READING). In uuid 1.27.0 `Uuid::parse_str` on a 36-byte input is
//    `parse_hyphenated`: hyphens at 8, 13, 18, 23 and 32 other bytes that `decode_hex32` accepts,
//    either case, with byte k = 16 * digit(2k) + digit(2k+1). `lemma_crate_hex_trick` and
//    `lemma_crate_hex_value` prove, by bit-vector reasoning, that the crate's branch-free test and
//    decode agree with `hexval`; reading the source for that is replaced by those lemmas, but the
//    transcription of `decode_hex32` into `crate_hex_test` is still reading.
//  H_UUID_FMT (CODE READING). `Uuid::from_bytes(b).hyphenated().to_string()` is the 36-byte lowercase
//    form, nibble order high then low (fmt.rs :185-234, :1145-1157).
//  H_VERSION_FLOW (CODE READING, NOT PROVED). R5 needs the version string seen by `unwrap` to parse
//    to the bytes `wrap` wrote. On decrypt the keyring turns the ciphertext version bytes into a string
//    (:894), asks the key store for that version, and `unwrap` then reads `materials.branch_key_version()`,
//    which comes from the stored RECORD (record.rs :118-178), not from the request. So the chain
//    request string -> record string is the key store's, not shown here (the T02/T18 area). R5 states the
//    consequence if the record's version string parses to the same bytes (any hex case).
//  H_KEY_SEPARATION (NOT USED, NOT PROVED). Different branch key ids or versions have different branch
//    key material and so different AES-GCM keys. The target text relies on it to call a cross-id AAD
//    collision harmless ("each AAD is used under its own branch key"). That is the target author's
//    rationale. It is not shown here and no proof in this file uses it.
//  A_ALLOC (ASSUMED). Allocation succeeds, and the sum passed to `Vec::with_capacity` (:70-72) does not
//    overflow `usize`. The model omits the capacity hint.
//  A_VSTD (ASSUMED). Verus, Z3, the vstd Seq axioms, and vstd's specs for `Vec::push`,
//    `Vec::extend_from_slice`, slices and arrays. `by (bit_vector)` for the two u8 facts.
//
// =============================================================================
// 5. FINDINGS AND OBSERVATIONS
// =============================================================================
//  F1 (finding, EXPECTED_FAIL, layout fixed by the spec). The AAD has no length or separator before
//    the branch key id, and the next field is 16 bytes taken from wherever the id ends. A longer id can
//    absorb the first bytes of the version and context of a shorter one (`lemma_collision_iff` is the
//    exact condition). Concrete pair, both accepted by the model, same bytes:
//      A: id "b",         version "41424344-4546-4748-494a-4b4c4d4e4f50", context {"k": "v"}
//      B: id "bABCDEFGH", version "494a4b4c-4d4e-4f50-0001-00016b000176", context {} (empty)
//      AAD (both) = "aws-kms-hierarchy" 62 41..48 49 4a 4b 4c 4d 4e 4f 50 00 01 00 01 6b 00 01 76 (42 bytes)
//    The two triples differ in id, in version bytes and in context. Verus proves it for the model
//    (`lemma_cross_bkid_collision_witness`). The pair was also run through the shipped `compute_aad`
//    (feature `test-utils`, a scratch crate outside the repo, output in t10-run.md): the two AADs are
//    byte-equal (CODE RUN, one input pair, not a proof). The code follows the spec table (:337-342),
//    which lists the id as "Variable" with no prefix (:339); this is a property of the specified layout,
//    not a code-versus-spec mismatch. Same family as T13 BUG-06 (no delimiter between variable fields),
//    different place: T13 is about 0x00 separators in the cache preimage; here there is no separator
//    at all, and the ambiguity needs ids of different length. Inside the context the encoding has
//    length prefixes and `lemma_ser_inj` shows it is unambiguous. Severity: not rated here. No exploit
//    is claimed. Whether the collision matters depends on H_KEY_SEPARATION. For a FIXED branch key id
//    (the configured-id case of the keyring), the AAD is injective (R3, `theorem_aad_injective_fixed_bkid`).
//    With a branch key id supplier the id comes from the supplier per call; the proof then covers
//    each call separately and says nothing across ids.
//  O1 (observation). `uuid_str_to_16_bytes` accepts upper- and lowercase hex. The AAD depends on the 16
//    bytes only, so two version strings that differ in case give the same AAD, while the key store sort
//    key is built from the string (`branch:version:` + string, branch_key_store.rs :835), which is
//    case-sensitive. What the key store does with an uppercase string is not examined. Decrypt always
//    rebuilds a lowercase string (R4, `lemma_format36_alphabet`).
//  O2 (observation). The string round trip str -> bytes -> str is not the identity on the gate's accept
//    set (R4: it is the identity exactly on lowercase strings). The YAML's round trip (bytes -> str ->
//    bytes) holds for every 16-byte input.
//  O3 (observation). The gate checks the shape, not the UUID version or variant. The spec says the
//    stored version MUST be a v4 UUID (structures.md :406). Not a gap: the gate's doc comment says it is
//    a validation of the canonical form only.
//  O4 (observation, outside T10). `unwrap` parses the version bytes out of the ciphertext and discards
//    them (`_version`, :254); its AAD uses the materials' version string. T04 notes the same.
//  O5 (scope). `lemma_format36_alphabet` is a model proof of the fact T13 labels H_VERSION_NO_NUL
//    (decrypt version strings contain no 0x00). T13 is not edited here.
//  Target-text check (YAML VR-2026-T10): "Ok exactly when canonical && serializable" is R2. "AAD is the
//    concatenation" is R1. "For a fixed bkid, (version, ec) -> AAD is injective" is R3; the version is
//    injective as 16 bytes, not as a string (O1). The YAML marks its proof as using T15; the
//    injectivity of `to_bytes` is proved here instead, and `from_bytes` stays with T15. "uuid round trip"
//    is R4. "Cross-bkid injectivity is false" is F1, confirmed.
//
// =============================================================================
// 6. HOW THIS CLOSES H_AAD_PURE OF T04, AND WHAT STAYS ASSUMED
// =============================================================================
// T04 (t04_branch_key_wrap.rs) passed the results of `compute_aad` and `uuid_str_to_16_bytes` into its
// model of `wrap` as values, on the claim H_AAD_PURE: they are pure functions of their arguments, so
// passing them in does not change which random draws happen. T10 adds, relative to its model:
//   * the value each returns, as a function of its arguments, for ALL inputs: `compute_aad_spec` and
//     `gate`, with the exact Ok set (R2, R4) and the error order;
//   * the AAD's version field is the same 16 bytes that `wrap` writes into the ciphertext
//     (`theorem_compute_aad_layout`: offset 17 + |id|, 16 bytes, equals `gate(version)`), the fact T04
//     needs when it says the layout carries the version;
//   * Verus exec functions that take only their arguments and return the specified value, so the model
//     of each function is pure by construction.
// What stays assumed: that the shipped functions are those models (H_MODEL_MATCH) and that they read
// no state (H_AAD_PURE, code reading of about 50 lines plus the three crate calls). Purity of a native
// Rust function is not something Verus checks here. So H_AAD_PURE is not discharged by proof. It is
// reduced to H_MODEL_MATCH for these two functions and to H_UUID_PARSE / H_UUID_FMT for the crate.
//
// =============================================================================
// 7. OVERLAP
// =============================================================================
// Mahnush_Verus (dup-check.md section (2), tip 8d6381e): no overlap. No proof of `compute_aad` or either
// UUID function there; the code is identical and plain Rust. Closest items: a plan row in
// docs/verus-in-crate-migration-design.md (":66, :147, :217", branch-key wrap AAD as a future `mpl-core`
// candidate), and VR-012 (big-endian integer round trip in esdk/src/message/serialize_functions.rs, a
// different codec). The ESDK AAD proofs there (VR-003 `io_stream_aligned.rs`, `body_aad_proofs.rs`) are
// about the message header and frame body, not the branch-key AAD. This repository: T04 (uses these
// functions as values; section 6), T13 (uses the version string as a cache-preimage field; O5; BUG-06 is
// a different layout), T05 (same label constant in the KDF fixed info, not the AAD), T15 (not started;
// `from_bytes` only). None is duplicated.
//
// =============================================================================
// 8. MODEL-vs-CODE GAP
// =============================================================================
// The shipped functions are not inside `verus!`, are not compiled here, and nothing detects a later edit
// to branch_key_wrap.rs, hierarchical_keyring.rs, encryption_context.rs or the `uuid` crate. To close the
// gap one needs: the functions (or the crate calls, via `assume_specification` for `Uuid::parse_str`,
// `Uuid::from_bytes`, `hyphenated().to_string()`) inside `verus!` or `cargo verus`; a view of
// `EncryptionContext` as an `EcList`; and specs for `Error`. Until then the evidence level is:
// hand-checked model + machine-checked logic + one code run for F1.
// =============================================================================
use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Byte-level definitions (the AAD layout and the EC serialization)
// ============================================================

pub type Bytes = Seq<u8>;
/// The encryption context as the list of (key, value) pairs `to_bytes` iterates over, as
/// UTF-8 bytes (H_EC_LIST, H_BYTES). Sortedness and uniqueness of keys are NOT part of this
/// type; the injectivity proofs do not need them.
pub type EcList = Seq<(Bytes, Bytes)>;

/// HIERARCHY_LABEL = b"aws-kms-hierarchy" (branch_key_wrap.rs :40). 17 bytes.
pub open spec fn label() -> Bytes {
    seq![
        0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8, 0x2du8, 0x68u8, 0x69u8, 0x65u8,
        0x72u8, 0x61u8, 0x72u8, 0x63u8, 0x68u8, 0x79u8,
    ]
}

/// u16::to_be_bytes for 0 <= n < 65536.
pub open spec fn be16(n: int) -> Bytes {
    seq![(n / 256) as u8, (n % 256) as u8]
}

/// One entry as to_bytes writes it: key_len (2) || key || val_len (2) || value
/// (encryption_context.rs :111-134).
pub open spec fn enc_entry(e: (Bytes, Bytes)) -> Bytes {
    be16(e.0.len() as int) + (e.0 + (be16(e.1.len() as int) + e.1))
}

/// Every key and value is shorter than 2^16 (the `u16::try_from` checks, :112, :124).
pub open spec fn entries_ok(ec: EcList) -> bool {
    forall|i: int|
        0 <= i < ec.len() ==> (#[trigger] ec[i]).0.len() < 65536 && ec[i].1.len() < 65536
}

/// The entries, in order, one after the other.
pub open spec fn ser_entries(ec: EcList) -> Bytes
    decreases ec.len(),
{
    if ec.len() == 0 {
        Seq::empty()
    } else {
        enc_entry(ec[0]) + ser_entries(ec.skip(1))
    }
}

/// `to_bytes` returns Ok exactly when the count and every length fit in u16 (:100, :112, :124).
pub open spec fn ser_ok(ec: EcList) -> bool {
    ec.len() < 65536 && entries_ok(ec)
}

/// `EncryptionContext::to_bytes` on Ok (:91-137): empty for an empty context (:92-94),
/// otherwise count (2) followed by the entries.
pub open spec fn ser(ec: EcList) -> Bytes {
    if ec.len() == 0 {
        Seq::empty()
    } else {
        be16(ec.len() as int) + ser_entries(ec)
    }
}

/// The AAD bytes for a parsed version v (16 bytes) and a serialized context e:
/// label || branch_key_id || v || e (branch_key_wrap.rs :66-77).
pub open spec fn aad_bytes(bkid: Bytes, v: Bytes, e: Bytes) -> Bytes {
    label() + bkid + v + e
}

// ============================================================
// SECTION 2: Byte-sequence helper lemmas
// ============================================================

/// Concatenation is cancellative on a prefix of known length.
proof fn lemma_cat_inj(x1: Bytes, y1: Bytes, x2: Bytes, y2: Bytes)
    requires
        x1.len() == x2.len(),
        x1 + y1 == x2 + y2,
    ensures
        x1 == x2,
        y1 == y2,
{
    assert((x1 + y1).len() == x1.len() + y1.len());
    assert((x2 + y2).len() == x2.len() + y2.len());
    assert(y1.len() == y2.len());
    assert(x1 =~= x2) by {
        assert forall|i: int| 0 <= i < x1.len() implies x1[i] == x2[i] by {
            assert((x1 + y1)[i] == x1[i]);
            assert((x2 + y2)[i] == x2[i]);
        }
    }
    assert(y1 =~= y2) by {
        assert forall|i: int| 0 <= i < y1.len() implies y1[i] == y2[i] by {
            assert((x1 + y1)[x1.len() + i] == y1[i]);
            assert((x2 + y2)[x2.len() + i] == y2[i]);
        }
    }
}

proof fn lemma_be16_inj(m: int, n: int)
    requires
        0 <= m < 65536,
        0 <= n < 65536,
        be16(m) == be16(n),
    ensures
        m == n,
{
    assert(be16(m)[0] == be16(n)[0]);
    assert(be16(m)[1] == be16(n)[1]);
}

// ============================================================
// SECTION 3: The EC serialization is injective (the part of T15 that T10 needs)
// ============================================================

/// ser_entries distributes over concatenation.
proof fn lemma_ser_entries_append(a: EcList, b: EcList)
    ensures
        ser_entries(a + b) == ser_entries(a) + ser_entries(b),
    decreases a.len(),
{
    if a.len() == 0 {
        assert(a + b =~= b);
    } else {
        assert((a + b)[0] == a[0]);
        assert((a + b).skip(1) =~= a.skip(1) + b);
        lemma_ser_entries_append(a.skip(1), b);
        assert(enc_entry(a[0]) + (ser_entries(a.skip(1)) + ser_entries(b)) =~= (enc_entry(a[0])
            + ser_entries(a.skip(1))) + ser_entries(b));
    }
}

/// One entry followed by a tail determines the entry and the tail.
proof fn lemma_entry_cancel(ea: (Bytes, Bytes), ra: Bytes, eb: (Bytes, Bytes), rb: Bytes)
    requires
        ea.0.len() < 65536,
        ea.1.len() < 65536,
        eb.0.len() < 65536,
        eb.1.len() < 65536,
        enc_entry(ea) + ra == enc_entry(eb) + rb,
    ensures
        ea == eb,
        ra == rb,
{
    let ka = ea.0;
    let va = ea.1;
    let kb = eb.0;
    let vb = eb.1;
    let ta = be16(va.len() as int) + (va + ra);
    let tb = be16(vb.len() as int) + (vb + rb);
    let wa = be16(ka.len() as int) + (ka + ta);
    let wb = be16(kb.len() as int) + (kb + tb);
    assert(enc_entry(ea) + ra =~= wa);
    assert(enc_entry(eb) + rb =~= wb);
    lemma_cat_inj(be16(ka.len() as int), ka + ta, be16(kb.len() as int), kb + tb);
    lemma_be16_inj(ka.len() as int, kb.len() as int);
    lemma_cat_inj(ka, ta, kb, tb);
    lemma_cat_inj(be16(va.len() as int), va + ra, be16(vb.len() as int), vb + rb);
    lemma_be16_inj(va.len() as int, vb.len() as int);
    lemma_cat_inj(va, ra, vb, rb);
}

/// Two entry lists of the same length with the same bytes are the same list.
proof fn lemma_ser_entries_inj(a: EcList, b: EcList)
    requires
        a.len() == b.len(),
        entries_ok(a),
        entries_ok(b),
        ser_entries(a) == ser_entries(b),
    ensures
        a == b,
    decreases a.len(),
{
    if a.len() == 0 {
        assert(a =~= b);
    } else {
        assert(a[0].0.len() < 65536 && a[0].1.len() < 65536);
        assert(b[0].0.len() < 65536 && b[0].1.len() < 65536);
        lemma_entry_cancel(a[0], ser_entries(a.skip(1)), b[0], ser_entries(b.skip(1)));
        assert forall|i: int| 0 <= i < a.skip(1).len() implies (#[trigger] a.skip(1)[i]).0.len() < 65536
            && a.skip(1)[i].1.len() < 65536 by {
            assert(a.skip(1)[i] == a[i + 1]);
        }
        assert forall|i: int| 0 <= i < b.skip(1).len() implies (#[trigger] b.skip(1)[i]).0.len() < 65536
            && b.skip(1)[i].1.len() < 65536 by {
            assert(b.skip(1)[i] == b[i + 1]);
        }
        lemma_ser_entries_inj(a.skip(1), b.skip(1));
        assert(a =~= b) by {
            assert forall|i: int| 0 <= i < a.len() implies a[i] == b[i] by {
                if i > 0 {
                    assert(a.skip(1)[i - 1] == a[i]);
                    assert(b.skip(1)[i - 1] == b[i]);
                }
            }
        }
    }
}

/// R1. `to_bytes` is injective on the lists it can serialize.
proof fn lemma_ser_inj(a: EcList, b: EcList)
    requires
        ser_ok(a),
        ser_ok(b),
        ser(a) == ser(b),
    ensures
        a == b,
{
    if a.len() == 0 {
        if b.len() > 0 {
            assert(ser(b).len() >= 2) by {
                assert(ser(b) == be16(b.len() as int) + ser_entries(b));
            }
        }
        assert(a =~= b);
    } else if b.len() == 0 {
        assert(ser(a).len() >= 2) by {
            assert(ser(a) == be16(a.len() as int) + ser_entries(a));
        }
    } else {
        lemma_cat_inj(be16(a.len() as int), ser_entries(a), be16(b.len() as int), ser_entries(b));
        lemma_be16_inj(a.len() as int, b.len() as int);
        lemma_ser_entries_inj(a, b);
    }
}

// ============================================================
// SECTION 4: The UUID codec (spec level)
// ============================================================

/// The hyphens of the 8-4-4-4-12 form sit at string positions 8, 13, 18, 23.
pub open spec fn is_dash(i: int) -> bool {
    i == 8 || i == 13 || i == 18 || i == 23
}

/// String position of the j-th hex digit (j in 0..32).
pub open spec fn str_pos(j: int) -> int {
    j + (if j >= 8 { 1int } else { 0int }) + (if j >= 12 { 1int } else { 0int }) + (if j >= 16 {
        1int
    } else {
        0int
    }) + (if j >= 20 { 1int } else { 0int })
}

/// Hex-digit index of a non-hyphen string position.
pub open spec fn hex_idx(i: int) -> int {
    i - (if i > 8 { 1int } else { 0int }) - (if i > 13 { 1int } else { 0int }) - (if i > 18 {
        1int
    } else {
        0int
    }) - (if i > 23 { 1int } else { 0int })
}

/// Value of an ASCII hex digit, either case; -1 for any other byte. This is the accept set of
/// `decode_hex32` in uuid 1.27.0 (H_UUID_PARSE, `lemma_crate_hex_trick`).
pub open spec fn hexval(c: u8) -> int {
    if 48 <= c <= 57 {
        c as int - 48
    } else if 97 <= c <= 102 {
        c as int - 87
    } else if 65 <= c <= 70 {
        c as int - 55
    } else {
        -1
    }
}

/// Lowercase hex digit of a nibble (`nibble_to_hex` with alpha_offset 0x27).
pub open spec fn nib_char(n: int) -> u8 {
    if n < 10 {
        (48 + n) as u8
    } else {
        (87 + n) as u8
    }
}

/// The j-th nibble of b (j in 0..32): high nibble of byte j/2 for even j, low for odd j.
pub open spec fn nibble(b: Bytes, j: int) -> int {
    if j % 2 == 0 {
        (b[j / 2] as int) / 16
    } else {
        (b[j / 2] as int) % 16
    }
}

/// `Uuid::from_bytes(b).hyphenated().to_string()` for a 16-byte b: 36 bytes, lowercase hex,
/// hyphens at 8, 13, 18, 23 (uuid 1.27.0 fmt.rs `format_hyphenated`).
pub open spec fn format36(b: Bytes) -> Bytes {
    Seq::new(36, |i: int| if is_dash(i) { 45u8 } else { nib_char(nibble(b, hex_idx(i))) })
}

/// A canonical hyphenated string: 36 bytes, hyphens at the four positions, a hex digit
/// (either case) everywhere else (`parse_hyphenated`, parser.rs).
pub open spec fn canonical36(s: Bytes) -> bool {
    &&& s.len() == 36
    &&& s[8] == 45u8
    &&& s[13] == 45u8
    &&& s[18] == 45u8
    &&& s[23] == 45u8
    &&& forall|j: int| 0 <= j < 32 ==> #[trigger] hexval(s[str_pos(j)]) >= 0
}

/// `parse_hyphenated` on a 36-byte input: byte k is 16 * digit(2k) + digit(2k + 1).
pub open spec fn parse36(s: Bytes) -> Option<Bytes> {
    if canonical36(s) {
        Some(
            Seq::new(
                16,
                |k: int| (16 * hexval(s[str_pos(2 * k)]) + hexval(s[str_pos(2 * k + 1)])) as u8,
            ),
        )
    } else {
        None
    }
}

/// `parse_simple` (32 hex digits, no hyphens), the other form `Uuid::parse_str` accepts that
/// the explicit length check at branch_key_wrap.rs :101 excludes.
pub open spec fn parse32(s: Bytes) -> Option<Bytes> {
    if s.len() == 32 && forall|j: int| 0 <= j < 32 ==> #[trigger] hexval(s[j]) >= 0 {
        Some(Seq::new(16, |k: int| (16 * hexval(s[2 * k]) + hexval(s[2 * k + 1])) as u8))
    } else {
        None
    }
}

/// `Uuid::parse_str` as modeled: the two forms of length 32 and 36. The braced (38) and URN (45)
/// forms of the real crate are NOT modeled (they return None here); the explicit length check
/// makes the gate independent of that (`lemma_gate_is_parse36`).
pub open spec fn crate_parse(s: Bytes) -> Option<Bytes> {
    if s.len() == 32 {
        parse32(s)
    } else if s.len() == 36 {
        parse36(s)
    } else {
        None
    }
}

/// `uuid_str_to_16_bytes` (branch_key_wrap.rs :92-110) with the error value dropped: reject any
/// length other than 36 (:101), otherwise `Uuid::parse_str` (:106).
pub open spec fn gate(s: Bytes) -> Option<Bytes> {
    if s.len() != 36 {
        None
    } else {
        crate_parse(s)
    }
}

/// ASCII letters A-F become a-f; every other byte is unchanged.
pub open spec fn fold_case(c: u8) -> u8 {
    if 65 <= c <= 70 {
        (c + 32) as u8
    } else {
        c
    }
}

pub open spec fn fold_str(s: Bytes) -> Bytes {
    Seq::new(s.len(), |i: int| fold_case(s[i]))
}

// ---- arithmetic facts about the position maps ----

proof fn lemma_str_pos(j: int)
    requires
        0 <= j < 32,
    ensures
        0 <= str_pos(j) < 36,
        !is_dash(str_pos(j)),
        hex_idx(str_pos(j)) == j,
{
}

proof fn lemma_hex_idx(i: int)
    requires
        0 <= i < 36,
        !is_dash(i),
    ensures
        0 <= hex_idx(i) < 32,
        str_pos(hex_idx(i)) == i,
{
}

proof fn lemma_hexval_nib_char(n: int)
    requires
        0 <= n < 16,
    ensures
        hexval(nib_char(n)) == n,
{
}

/// For a hex digit c, the lowercase hex digit of its value is c with A-F folded.
proof fn lemma_nib_char_hexval(c: u8)
    requires
        hexval(c) >= 0,
    ensures
        hexval(c) < 16,
        nib_char(hexval(c)) == fold_case(c),
{
}

proof fn lemma_nibble_range(b: Bytes, j: int)
    requires
        0 <= j < 2 * b.len(),
    ensures
        0 <= nibble(b, j) < 16,
{
}

/// The crate's branch-free hex test, in wrapping u8 arithmetic (parser.rs `decode_hex32`):
/// `digit = c - '0'` is below 10, or `alpha = (c | 0x20) - 'a'` is below 6. The wrap is written
/// as `% 256`.
pub open spec fn crate_hex_test(c: u8) -> bool {
    ((c as int - 48) % 256 < 10) || (((c | 0x20u8) as int - 97) % 256 < 6)
}

/// The branch-free test accepts exactly the bytes with hexval >= 0.
proof fn lemma_crate_hex_trick(c: u8)
    ensures
        crate_hex_test(c) <==> hexval(c) >= 0,
{
    assert(((97u8 <= (c | 0x20u8)) && ((c | 0x20u8) <= 102u8)) == ((65u8 <= c && c <= 70u8) || (97u8
        <= c && c <= 102u8))) by (bit_vector);
}

/// The value the crate's decoder assigns to an accepted byte: `digit` if below 10, else
/// `alpha + 10` (parser.rs `decode_hex32`). It equals hexval on every accepted byte.
pub open spec fn crate_nibble(c: u8) -> int {
    if (c as int - 48) % 256 < 10 {
        (c as int - 48) % 256
    } else {
        ((c | 0x20u8) as int - 97) % 256 + 10
    }
}

proof fn lemma_crate_hex_value(c: u8)
    requires
        crate_hex_test(c),
    ensures
        crate_nibble(c) == hexval(c),
{
    lemma_crate_hex_trick(c);
    assert((65u8 <= c && c <= 70u8) ==> (c | 0x20u8) == c + 32u8) by (bit_vector);
    assert((97u8 <= c && c <= 102u8) ==> (c | 0x20u8) == c) by (bit_vector);
}

// ---- R4: the codec ----

/// R4a. bytes -> string -> bytes is the identity, for every 16-byte input; the string is a
/// canonical hyphenated string, so the gate accepts it.
proof fn lemma_roundtrip_bytes(b: Bytes)
    requires
        b.len() == 16,
    ensures
        format36(b).len() == 36,
        canonical36(format36(b)),
        parse36(format36(b)) == Some(b),
        gate(format36(b)) == Some(b),
{
    let f = format36(b);
    assert(f.len() == 36);
    assert(f[8] == 45u8 && f[13] == 45u8 && f[18] == 45u8 && f[23] == 45u8);
    assert forall|j: int| 0 <= j < 32 implies #[trigger] hexval(f[str_pos(j)]) >= 0 by {
        lemma_str_pos(j);
        lemma_nibble_range(b, j);
        lemma_hexval_nib_char(nibble(b, j));
        assert(f[str_pos(j)] == nib_char(nibble(b, hex_idx(str_pos(j)))));
    }
    assert(canonical36(f));
    let out = Seq::new(
        16,
        |k: int| (16 * hexval(f[str_pos(2 * k)]) + hexval(f[str_pos(2 * k + 1)])) as u8,
    );
    assert(parse36(f) == Some(out));
    assert(out =~= b) by {
        assert forall|k: int| 0 <= k < 16 implies out[k] == b[k] by {
            lemma_str_pos(2 * k);
            lemma_str_pos(2 * k + 1);
            lemma_nibble_range(b, 2 * k);
            lemma_nibble_range(b, 2 * k + 1);
            lemma_hexval_nib_char(nibble(b, 2 * k));
            lemma_hexval_nib_char(nibble(b, 2 * k + 1));
            assert(f[str_pos(2 * k)] == nib_char(nibble(b, 2 * k)));
            assert(f[str_pos(2 * k + 1)] == nib_char(nibble(b, 2 * k + 1)));
            assert(nibble(b, 2 * k) == (b[k] as int) / 16);
            assert(nibble(b, 2 * k + 1) == (b[k] as int) % 16);
        }
    }
    assert(gate(f) == parse36(f));
}

/// The gate agrees with `parse36` on every input (the explicit length check).
proof fn lemma_gate_is_parse36(s: Bytes)
    ensures
        gate(s) == parse36(s),
{
}

/// R4b. A successful parse has 16 bytes.
proof fn lemma_parse36_len(s: Bytes)
    ensures
        parse36(s) is Some ==> parse36(s)->Some_0.len() == 16,
{
}

/// R4c. Parsing then formatting lowercases the string: the result is the input with A-F
/// folded to a-f, for every canonical string.
proof fn lemma_format_of_parse(s: Bytes)
    requires
        canonical36(s),
    ensures
        parse36(s) is Some,
        format36(parse36(s)->Some_0) == fold_str(s),
{
    let out = parse36(s)->Some_0;
    assert(out.len() == 16);
    assert(format36(out) =~= fold_str(s)) by {
        assert forall|i: int| 0 <= i < 36 implies format36(out)[i] == fold_str(s)[i] by {
            if is_dash(i) {
                assert(s[i] == 45u8);
            } else {
                lemma_hex_idx(i);
                let j = hex_idx(i);
                assert(str_pos(j) == i);
                assert(hexval(s[str_pos(j)]) >= 0);
                lemma_nib_char_hexval(s[i]);
                // nibble j of out is the digit at string position i
                let m = j / 2;
                lemma_str_pos(2 * m);
                lemma_str_pos(2 * m + 1);
                assert(hexval(s[str_pos(2 * m)]) >= 0);
                assert(hexval(s[str_pos(2 * m + 1)]) >= 0);
                assert(hexval(s[str_pos(2 * m)]) < 16 && hexval(s[str_pos(2 * m + 1)]) < 16) by {
                    lemma_nib_char_hexval(s[str_pos(2 * m)]);
                    lemma_nib_char_hexval(s[str_pos(2 * m + 1)]);
                }
                assert(out[m] == (16 * hexval(s[str_pos(2 * m)]) + hexval(s[str_pos(2 * m + 1)])) as u8);
                if j % 2 == 0 {
                    assert(j == 2 * m);
                    assert(nibble(out, j) == hexval(s[i]));
                } else {
                    assert(j == 2 * m + 1);
                    assert(nibble(out, j) == hexval(s[i]));
                }
            }
        }
    }
}

/// R4d. The string round trip holds exactly on strings without A-F: parse then format gives
/// the input back iff the input has no uppercase hex letter.
proof fn lemma_string_roundtrip_iff_lowercase(s: Bytes)
    requires
        canonical36(s),
    ensures
        format36(parse36(s)->Some_0) == s <==> fold_str(s) == s,
{
    lemma_format_of_parse(s);
}

/// R4e. Two canonical strings give the same 16 bytes iff they are equal after folding A-F to
/// a-f. So the parse is injective on lowercase strings and not on strings in general.
proof fn lemma_parse_equal_iff_fold_equal(s1: Bytes, s2: Bytes)
    requires
        canonical36(s1),
        canonical36(s2),
    ensures
        parse36(s1) == parse36(s2) <==> fold_str(s1) == fold_str(s2),
{
    lemma_format_of_parse(s1);
    lemma_format_of_parse(s2);
    let p1 = parse36(s1)->Some_0;
    let p2 = parse36(s2)->Some_0;
    lemma_roundtrip_bytes(p1);
    lemma_roundtrip_bytes(p2);
    if fold_str(s1) == fold_str(s2) {
        assert(format36(p1) == format36(p2));
        assert(parse36(format36(p1)) == Some(p1));
        assert(parse36(format36(p2)) == Some(p2));
        assert(p1 == p2);
    }
}

/// R4f. totality: every canonical string parses, and the gate accepts exactly the canonical
/// strings of length 36.
proof fn lemma_gate_accepts_exactly_canonical(s: Bytes)
    ensures
        gate(s) is Some <==> canonical36(s),
{
}

/// R4g. The explicit length check is what excludes the simple form: a 32-digit hex string is
/// accepted by `Uuid::parse_str` (modeled) and rejected by the gate.
proof fn lemma_gate_rejects_simple_form(s: Bytes)
    requires
        s.len() == 32,
        forall|j: int| 0 <= j < 32 ==> #[trigger] hexval(s[j]) >= 0,
    ensures
        crate_parse(s) is Some,
        gate(s) is None,
{
}

/// R4h. An uppercase string is accepted and gives the same bytes as its lowercase form, so the
/// accept set is wider than the strings `uuid_16_bytes_to_str` produces (observation O2).
proof fn lemma_uppercase_is_accepted()
    ensures
        ({
            let up = Seq::new(36, |i: int| if is_dash(i) { 45u8 } else { 65u8 });
            let lo = Seq::new(36, |i: int| if is_dash(i) { 45u8 } else { 97u8 });
            &&& gate(up) is Some
            &&& gate(lo) is Some
            &&& up != lo
            &&& gate(up) == gate(lo)
        }),
{
    let up = Seq::new(36, |i: int| if is_dash(i) { 45u8 } else { 65u8 });
    let lo = Seq::new(36, |i: int| if is_dash(i) { 45u8 } else { 97u8 });
    assert(canonical36(up)) by {
        assert forall|j: int| 0 <= j < 32 implies #[trigger] hexval(up[str_pos(j)]) >= 0 by {
            lemma_str_pos(j);
        }
    }
    assert(canonical36(lo)) by {
        assert forall|j: int| 0 <= j < 32 implies #[trigger] hexval(lo[str_pos(j)]) >= 0 by {
            lemma_str_pos(j);
        }
    }
    assert(up[0] != lo[0]);
    assert(fold_str(up) =~= fold_str(lo)) by {
        assert forall|i: int| 0 <= i < 36 implies fold_str(up)[i] == fold_str(lo)[i] by {}
    }
    lemma_parse_equal_iff_fold_equal(up, lo);
}

/// R4i. The gate does not check the UUID version or variant: a canonical string whose version
/// digit is 0 is accepted (observation O3; the spec's "MUST be a version 4 UUID" is a rule on the
/// stored value, not something the gate tests).
proof fn lemma_gate_accepts_non_v4()
    ensures
        ({
            let z = Seq::new(36, |i: int| if is_dash(i) { 45u8 } else { 48u8 });
            &&& gate(z) is Some
            &&& z[14] == 48u8
        }),
{
    let z = Seq::new(36, |i: int| if is_dash(i) { 45u8 } else { 48u8 });
    assert(canonical36(z)) by {
        assert forall|j: int| 0 <= j < 32 implies #[trigger] hexval(z[str_pos(j)]) >= 0 by {
            lemma_str_pos(j);
        }
    }
}

/// R4j. Every byte of `uuid_16_bytes_to_str` output is '-' or a lowercase hex digit, so none is
/// 0x00 (the fact T13 states as H_VERSION_NO_NUL, there by code reading).
proof fn lemma_format36_alphabet(b: Bytes)
    requires
        b.len() == 16,
    ensures
        forall|i: int|
            0 <= i < 36 ==> (#[trigger] format36(b)[i] == 45u8 || (48u8 <= format36(b)[i]
                <= 57u8) || (97u8 <= format36(b)[i] <= 102u8)),
        forall|i: int| 0 <= i < 36 ==> #[trigger] format36(b)[i] != 0u8,
{
    assert forall|i: int| 0 <= i < 36 implies (#[trigger] format36(b)[i] == 45u8 || (48u8
        <= format36(b)[i] <= 57u8) || (97u8 <= format36(b)[i] <= 102u8)) by {
        if !is_dash(i) {
            lemma_hex_idx(i);
            lemma_nibble_range(b, hex_idx(i));
        }
    }
}

// ============================================================
// SECTION 5: compute_aad (spec level)
// ============================================================

/// The error kinds `compute_aad` can return: the version gate (`InvalidMaterials`, first) or
/// the encryption-context serialization (`Validation`).
pub enum AadErr {
    Version,
    Ec,
}

/// `compute_aad` (branch_key_wrap.rs :61-80): version gate first (:66), then the context
/// serialization (:68), then the concatenation (:74-77).
pub open spec fn compute_aad_spec(bkid: Bytes, ver: Bytes, ec: EcList) -> Result<Bytes, AadErr> {
    match gate(ver) {
        None => Err(AadErr::Version),
        Some(v) => if ser_ok(ec) {
            Ok(aad_bytes(bkid, v, ser(ec)))
        } else {
            Err(AadErr::Ec)
        },
    }
}

/// R2. compute_aad returns Ok exactly when the version is a canonical 36-byte UUID string and
/// the context serializes; the version error is reported first.
proof fn theorem_compute_aad_ok_iff(bkid: Bytes, ver: Bytes, ec: EcList)
    ensures
        compute_aad_spec(bkid, ver, ec) is Ok <==> canonical36(ver) && ser_ok(ec),
        !canonical36(ver) ==> compute_aad_spec(bkid, ver, ec) == Result::<Bytes, AadErr>::Err(
            AadErr::Version,
        ),
        canonical36(ver) && !ser_ok(ec) ==> compute_aad_spec(bkid, ver, ec) == Result::<
            Bytes,
            AadErr,
        >::Err(AadErr::Ec),
{
}

/// R1. The layout of an Ok result: the four fields at fixed offsets (the spec table:
/// 17, variable, 16, variable).
proof fn theorem_compute_aad_layout(bkid: Bytes, ver: Bytes, ec: EcList)
    requires
        compute_aad_spec(bkid, ver, ec) is Ok,
    ensures
        ({
            let a = compute_aad_spec(bkid, ver, ec)->Ok_0;
            let n = bkid.len() as int;
            let v = parse36(ver)->Some_0;
            &&& v.len() == 16
            &&& a.len() == 17 + n + 16 + ser(ec).len()
            &&& a.subrange(0, 17) == label()
            &&& a.subrange(17, 17 + n) == bkid
            &&& a.subrange(17 + n, 33 + n) == v
            &&& a.skip(33 + n) == ser(ec)
        }),
{
    let a = compute_aad_spec(bkid, ver, ec)->Ok_0;
    let n = bkid.len() as int;
    let v = parse36(ver)->Some_0;
    assert(label().len() == 17);
    assert(a == label() + bkid + v + ser(ec));
    assert(a.subrange(0, 17) =~= label());
    assert(a.subrange(17, 17 + n) =~= bkid);
    assert(a.subrange(17 + n, 33 + n) =~= v);
    assert(a.skip(33 + n) =~= ser(ec));
}

// ---- R3: injectivity and the exact collision set ----

/// Same-length branch key ids: the AAD determines the id, the 16 version bytes and the
/// serialized context.
proof fn lemma_aad_same_len_inj(b1: Bytes, v1: Bytes, e1: Bytes, b2: Bytes, v2: Bytes, e2: Bytes)
    requires
        b1.len() == b2.len(),
        v1.len() == 16,
        v2.len() == 16,
        aad_bytes(b1, v1, e1) == aad_bytes(b2, v2, e2),
    ensures
        b1 == b2,
        v1 == v2,
        e1 == e2,
{
    assert(label() + b1 + v1 + e1 =~= label() + (b1 + (v1 + e1)));
    assert(label() + b2 + v2 + e2 =~= label() + (b2 + (v2 + e2)));
    lemma_cat_inj(label(), b1 + (v1 + e1), label(), b2 + (v2 + e2));
    lemma_cat_inj(b1, v1 + e1, b2, v2 + e2);
    lemma_cat_inj(v1, e1, v2, e2);
}

/// R3a. The exact collision set, with no assumption on the inputs: for |b1| <= |b2|, two
/// triples have the same AAD iff b1 is a prefix of b2 and the rest of b2 followed by (v2, e2)
/// is (v1, e1) read as one byte string.
proof fn lemma_collision_iff(b1: Bytes, v1: Bytes, e1: Bytes, b2: Bytes, v2: Bytes, e2: Bytes)
    requires
        b1.len() <= b2.len(),
    ensures
        aad_bytes(b1, v1, e1) == aad_bytes(b2, v2, e2) <==> (b2.take(b1.len() as int) == b1 && v1
            + e1 == b2.skip(b1.len() as int) + v2 + e2),
{
    let n1 = b1.len() as int;
    let x = b2.skip(n1);
    assert(b2.take(n1) + x =~= b2);
    if aad_bytes(b1, v1, e1) == aad_bytes(b2, v2, e2) {
        assert(label() + b1 + v1 + e1 =~= label() + (b1 + (v1 + e1)));
        assert(label() + b2 + v2 + e2 =~= label() + (b2 + (v2 + e2)));
        lemma_cat_inj(label(), b1 + (v1 + e1), label(), b2 + (v2 + e2));
        assert(b2 + (v2 + e2) =~= b2.take(n1) + (x + v2 + e2));
        lemma_cat_inj(b1, v1 + e1, b2.take(n1), x + v2 + e2);
        assert(x + (v2 + e2) =~= x + v2 + e2);
    }
    if b2.take(n1) == b1 && v1 + e1 == x + v2 + e2 {
        assert(b2 =~= b1 + x);
        assert(label() + b2 + v2 + e2 =~= label() + b1 + (x + v2 + e2));
        assert(label() + b1 + v1 + e1 =~= label() + b1 + (v1 + e1));
    }
}

/// R3b. Two different triples (id, version bytes, context bytes) can share an AAD only if the
/// branch key ids have different lengths.
proof fn theorem_collision_needs_different_id_lengths(
    b1: Bytes,
    v1: Bytes,
    e1: Bytes,
    b2: Bytes,
    v2: Bytes,
    e2: Bytes,
)
    requires
        v1.len() == 16,
        v2.len() == 16,
        aad_bytes(b1, v1, e1) == aad_bytes(b2, v2, e2),
        (b1, v1, e1) != (b2, v2, e2),
    ensures
        b1.len() != b2.len(),
{
    if b1.len() == b2.len() {
        lemma_aad_same_len_inj(b1, v1, e1, b2, v2, e2);
    }
}

/// R3c. For a fixed branch key id, compute_aad is injective in (version bytes, context): equal
/// Ok results give the same 16 version bytes and the same entry list. Version STRINGS may
/// still differ in hex case (R4e).
proof fn theorem_aad_injective_fixed_bkid(
    bkid: Bytes,
    s1: Bytes,
    ec1: EcList,
    s2: Bytes,
    ec2: EcList,
)
    requires
        compute_aad_spec(bkid, s1, ec1) is Ok,
        compute_aad_spec(bkid, s1, ec1) == compute_aad_spec(bkid, s2, ec2),
    ensures
        parse36(s1) == parse36(s2),
        parse36(s1) is Some,
        ec1 == ec2,
{
    let v1 = parse36(s1)->Some_0;
    let v2 = parse36(s2)->Some_0;
    assert(v1.len() == 16 && v2.len() == 16);
    lemma_aad_same_len_inj(bkid, v1, ser(ec1), bkid, v2, ser(ec2));
    lemma_ser_inj(ec1, ec2);
}

/// Same, for branch key ids of equal length (the id is then determined too).
proof fn theorem_aad_injective_equal_length_ids(
    b1: Bytes,
    s1: Bytes,
    ec1: EcList,
    b2: Bytes,
    s2: Bytes,
    ec2: EcList,
)
    requires
        b1.len() == b2.len(),
        compute_aad_spec(b1, s1, ec1) is Ok,
        compute_aad_spec(b1, s1, ec1) == compute_aad_spec(b2, s2, ec2),
    ensures
        b1 == b2,
        parse36(s1) == parse36(s2),
        ec1 == ec2,
{
    let v1 = parse36(s1)->Some_0;
    let v2 = parse36(s2)->Some_0;
    assert(v1.len() == 16 && v2.len() == 16);
    lemma_aad_same_len_inj(b1, v1, ser(ec1), b2, v2, ser(ec2));
    lemma_ser_inj(ec1, ec2);
}

// ---- The finding: the id has no length prefix (spec layout) ----

pub open spec fn w_v() -> Bytes {
    seq![
        0x41u8, 0x42u8, 0x43u8, 0x44u8, 0x45u8, 0x46u8, 0x47u8, 0x48u8, 0x49u8, 0x4au8, 0x4bu8,
        0x4cu8, 0x4du8, 0x4eu8, 0x4fu8, 0x50u8,
    ]
}

/// First triple: id "b", version bytes "ABCDEFGHIJKLMNOP", context {"k": "v"}.
pub open spec fn w_b1() -> Bytes {
    seq![0x62u8]
}

pub open spec fn w_ec1() -> EcList {
    seq![(seq![0x6bu8], seq![0x76u8])]
}

/// to_bytes of {"k": "v"}: count 0001, key_len 0001, 'k', val_len 0001, 'v'.
pub open spec fn w_e() -> Bytes {
    seq![0x00u8, 0x01u8, 0x00u8, 0x01u8, 0x6bu8, 0x00u8, 0x01u8, 0x76u8]
}

/// Second triple: id "b" followed by the first 8 version bytes, version bytes = the last 8
/// version bytes followed by the 8 context bytes, empty context.
pub open spec fn w_b2() -> Bytes {
    w_b1() + w_v().take(8)
}

pub open spec fn w_v2() -> Bytes {
    w_v().skip(8) + w_e()
}

pub open spec fn w_ec2() -> EcList {
    Seq::empty()
}

/// The version strings of the two triples (`uuid_16_bytes_to_str` of the version bytes).
pub open spec fn w_s1() -> Bytes {
    format36(w_v())
}

pub open spec fn w_s2() -> Bytes {
    format36(w_v2())
}

/// Every byte below 0x80, so every field is valid UTF-8 and the triple can be written as
/// `&str` arguments of the shipped `compute_aad`.
pub open spec fn ascii(s: Bytes) -> bool {
    forall|i: int| 0 <= i < s.len() ==> #[trigger] s[i] < 128u8
}

/// The serialization of the two contexts of the witness.
proof fn lemma_w_ser()
    ensures
        ser_ok(w_ec1()),
        ser(w_ec1()) == w_e(),
        ser_ok(w_ec2()),
        ser(w_ec2()) == Seq::<u8>::empty(),
{
    reveal_with_fuel(ser_entries, 2);
    assert(w_ec1().skip(1) =~= Seq::<(Bytes, Bytes)>::empty());
    assert(ser_entries(w_ec1().skip(1)) =~= Seq::<u8>::empty());
    assert(ser_entries(w_ec1()) =~= seq![0x00u8, 0x01u8, 0x6bu8, 0x00u8, 0x01u8, 0x76u8]);
    assert(ser(w_ec1()) =~= w_e());
    assert(entries_ok(w_ec1())) by {
        assert forall|i: int| 0 <= i < w_ec1().len() implies (#[trigger] w_ec1()[i]).0.len()
            < 65536 && w_ec1()[i].1.len() < 65536 by {}
    }
    assert(entries_ok(w_ec2()));
    assert(ser(w_ec2()) =~= Seq::<u8>::empty());
}

/// The byte strings of the two triples line up: b1 || V || e == (b1 || V[..8]) || (V[8..] || e).
proof fn lemma_w_bytes()
    ensures
        w_v().len() == 16,
        w_v2().len() == 16,
        w_b1() + w_v() + w_e() == w_b2() + w_v2(),
{
    let x = w_v().take(8);
    let y = w_v().skip(8);
    assert(w_v() =~= x + y);
    assert(w_b2() + w_v2() =~= w_b1() + (x + (y + w_e())));
    assert(w_b1() + w_v() + w_e() =~= w_b1() + ((x + y) + w_e()));
    assert((x + y) + w_e() =~= x + (y + w_e()));
}

/// R3d. Two different (id, version, context) triples, both accepted, with the same AAD.
proof fn lemma_cross_bkid_collision_witness()
    ensures
        ({
            let r1 = compute_aad_spec(w_b1(), w_s1(), w_ec1());
            let r2 = compute_aad_spec(w_b2(), w_s2(), w_ec2());
            &&& r1 is Ok
            &&& r1 == r2
            &&& w_b1() != w_b2()
            &&& parse36(w_s1()) != parse36(w_s2())
            &&& w_ec1() != w_ec2()
        }),
{
    lemma_w_ser();
    lemma_w_bytes();
    lemma_roundtrip_bytes(w_v());
    lemma_roundtrip_bytes(w_v2());
    assert(aad_bytes(w_b1(), w_v(), w_e()) =~= aad_bytes(w_b2(), w_v2(), Seq::empty())) by {
        assert(label() + w_b1() + w_v() + w_e() =~= label() + (w_b1() + w_v() + w_e()));
        assert(label() + w_b2() + w_v2() + Seq::<u8>::empty() =~= label() + (w_b2() + w_v2()));
    }
    assert(w_b1().len() != w_b2().len());
    assert(w_v()[8] != w_v2()[8]);
    assert(w_ec1().len() != w_ec2().len());
}

/// Every byte of the witness fields is below 0x80, so the triple is valid UTF-8 and can be
/// passed to the shipped `compute_aad` as `&str` arguments.
proof fn lemma_cross_bkid_witness_is_ascii()
    ensures
        ascii(w_b1()),
        ascii(w_b2()),
        ascii(w_ec1()[0].0),
        ascii(w_ec1()[0].1),
{
    assert forall|i: int| 0 <= i < w_b2().len() implies #[trigger] w_b2()[i] < 128u8 by {
        if i >= 1 {
            assert(w_b2()[i] == w_v()[i - 1]);
        }
    }
}

/// R3e (EXPECTED FAIL, finding F1). The claim "different (id, version, context) give different
/// AAD" for ALL inputs. The AAD layout puts no length before the branch key id, and the version
/// that follows it is 16 bytes taken from anywhere, so a longer id can absorb the start of the
/// bytes that follow a shorter id (R3a). This claim is false (R3d is a counterexample) and is
/// left failing on purpose: not weakened, not assumed, not commented out. It is provable only
/// with a precondition (fixed id, R3c, or equal-length ids) or a different layout.
proof fn lemma_aad_injective_all_inputs_EXPECTED_FAIL(
    b1: Bytes,
    s1: Bytes,
    ec1: EcList,
    b2: Bytes,
    s2: Bytes,
    ec2: EcList,
)
    requires
        compute_aad_spec(b1, s1, ec1) is Ok,
        compute_aad_spec(b1, s1, ec1) == compute_aad_spec(b2, s2, ec2),
    ensures
        b1 == b2 && parse36(s1) == parse36(s2) && ec1 == ec2,
{
}

/// The claim above is false: the witness meets every `requires` and violates the `ensures`.
proof fn lemma_aad_injective_claim_is_false()
    ensures
        ({
            let (b1, s1, ec1) = (w_b1(), w_s1(), w_ec1());
            let (b2, s2, ec2) = (w_b2(), w_s2(), w_ec2());
            &&& compute_aad_spec(b1, s1, ec1) is Ok
            &&& compute_aad_spec(b1, s1, ec1) == compute_aad_spec(b2, s2, ec2)
            &&& !(b1 == b2 && parse36(s1) == parse36(s2) && ec1 == ec2)
        }),
{
    lemma_cross_bkid_collision_witness();
}

// ============================================================
// SECTION 6: wrap and unwrap compute the same AAD (TM-MPL-013, relative to H_VERSION_FLOW)
// ============================================================

/// The AAD depends on the version string only through the 16 bytes it parses to.
proof fn lemma_aad_depends_on_version_bytes(bkid: Bytes, s1: Bytes, s2: Bytes, ec: EcList)
    requires
        gate(s1) == gate(s2),
    ensures
        compute_aad_spec(bkid, s1, ec) == compute_aad_spec(bkid, s2, ec),
{
}

/// R5. Let wrap accept the version string s (so its ciphertext carries the bytes V = gate(s)),
/// and let decrypt turn those bytes back into a string with `uuid_16_bytes_to_str`. If the
/// materials used by unwrap carry that string (H_VERSION_FLOW), compute_aad gives the same
/// result on both sides, and that result is Ok iff the context serializes.
proof fn theorem_wrap_unwrap_same_aad(bkid: Bytes, s: Bytes, ec: EcList)
    requires
        gate(s) is Some,
    ensures
        ({
            let v = gate(s)->Some_0;
            &&& v.len() == 16
            &&& gate(format36(v)) == Some(v)
            &&& compute_aad_spec(bkid, format36(v), ec) == compute_aad_spec(bkid, s, ec)
            &&& canonical36(format36(v))
            &&& forall|i: int| 0 <= i < 36 ==> !(65 <= #[trigger] format36(v)[i] <= 70)
        }),
{
    let v = gate(s)->Some_0;
    assert(v.len() == 16);
    lemma_roundtrip_bytes(v);
    assert forall|i: int| 0 <= i < 36 implies !(65 <= #[trigger] format36(v)[i] <= 70) by {
        if !is_dash(i) {
            lemma_hex_idx(i);
            lemma_nibble_range(v, hex_idx(i));
            assert(format36(v)[i] == nib_char(nibble(v, hex_idx(i))));
        }
    }
}

// ============================================================
// SECTION 7: Executable models (R6)
// ============================================================

/// The nibble character (uuid `nibble_to_hex`, lowercase).
fn nib_char_exec(n: u8) -> (r: u8)
    requires
        n < 16,
    ensures
        r == nib_char(n as int),
{
    if n < 10 {
        48 + n
    } else {
        87 + n
    }
}

/// Hex digit value of an ASCII byte, either case; None otherwise.
fn hexval_exec(c: u8) -> (r: Option<u8>)
    ensures
        match r {
            Some(n) => hexval(c) == n as int && n < 16,
            None => hexval(c) < 0,
        },
{
    if 48 <= c && c <= 57 {
        Some(c - 48)
    } else if 97 <= c && c <= 102 {
        Some(c - 87)
    } else if 65 <= c && c <= 70 {
        Some(c - 55)
    } else {
        None
    }
}

fn str_pos_exec(j: usize) -> (r: usize)
    requires
        j < 32,
    ensures
        r == str_pos(j as int),
{
    let mut p = j;
    if j >= 8 {
        p = p + 1;
    }
    if j >= 12 {
        p = p + 1;
    }
    if j >= 16 {
        p = p + 1;
    }
    if j >= 20 {
        p = p + 1;
    }
    p
}

fn hex_idx_exec(i: usize) -> (r: usize)
    requires
        i < 36,
        !is_dash(i as int),
    ensures
        r == hex_idx(i as int),
{
    let mut j = i;
    if i > 8 {
        j = j - 1;
    }
    if i > 13 {
        j = j - 1;
    }
    if i > 18 {
        j = j - 1;
    }
    if i > 23 {
        j = j - 1;
    }
    j
}

/// `uuid_16_bytes_to_str` (hierarchical_keyring.rs :644-645), as a loop over the 36 positions.
fn uuid_16_bytes_to_str_exec(b: &[u8; 16]) -> (r: Vec<u8>)
    ensures
        r@ == format36(b@),
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < 36
        invariant
            i <= 36,
            out@ == format36(b@).take(i as int),
        decreases 36 - i,
    {
        let ch: u8 = if i == 8 || i == 13 || i == 18 || i == 23 {
            45u8
        } else {
            let j = hex_idx_exec(i);
            assert(j < 32) by {
                lemma_hex_idx(i as int);
            }
            let byte = b[j / 2];
            let n = if j % 2 == 0 {
                byte / 16
            } else {
                byte % 16
            };
            nib_char_exec(n)
        };
        proof {
            let f = format36(b@);
            assert(f[i as int] == ch);
            assert(f.take(i as int + 1) =~= f.take(i as int).push(ch));
        }
        out.push(ch);
        i = i + 1;
    }
    proof {
        assert(format36(b@).take(36) =~= format36(b@));
    }
    out
}

/// `uuid_str_to_16_bytes` (branch_key_wrap.rs :92-110) on the bytes of the string, without the
/// error value: the length check (:101) and then the hyphenated parse (:106).
fn uuid_str_to_16_bytes_exec(s: &[u8]) -> (r: Option<[u8; 16]>)
    ensures
        match r {
            Some(a) => gate(s@) == Some(a@),
            None => gate(s@) is None,
        },
{
    if s.len() != 36 {
        return None;
    }
    if s[8] != 45 || s[13] != 45 || s[18] != 45 || s[23] != 45 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut k: usize = 0;
    while k < 16
        invariant
            k <= 16,
            s@.len() == 36,
            out@.len() == 16,
            forall|m: int|
                0 <= m < k ==> out@[m] == (16 * hexval(s@[str_pos(2 * m)]) + hexval(
                    s@[str_pos(2 * m + 1)],
                )) as u8,
            forall|j: int| 0 <= j < 2 * k ==> #[trigger] hexval(s@[str_pos(j)]) >= 0,
        decreases 16 - k,
    {
        let p1 = str_pos_exec(2 * k);
        let p2 = str_pos_exec(2 * k + 1);
        let h1 = hexval_exec(s[p1]);
        let h2 = hexval_exec(s[p2]);
        match (h1, h2) {
            (Some(a), Some(b)) => {
                assert(16 * (a as int) + (b as int) <= 255);
                let val: u8 = a * 16 + b;
                out[k] = val;
                k = k + 1;
            },
            _ => {
                proof {
                    assert(!canonical36(s@)) by {
                        if h1 is None {
                            assert(hexval(s@[str_pos(2 * k as int)]) < 0);
                        } else {
                            assert(hexval(s@[str_pos(2 * k as int + 1)]) < 0);
                        }
                    }
                }
                return None;
            },
        }
    }
    proof {
        assert(canonical36(s@));
        let expect = Seq::new(
            16,
            |k: int| (16 * hexval(s@[str_pos(2 * k)]) + hexval(s@[str_pos(2 * k + 1)])) as u8,
        );
        assert(out@ =~= expect);
    }
    Some(out)
}

/// R6. bytes -> string -> bytes, run through the two executable models: for every 16-byte input
/// the gate returns Some(b). This is the path ciphertext version bytes take on decrypt.
fn uuid_roundtrip_exec(b: &[u8; 16]) -> (r: Option<[u8; 16]>)
    ensures
        r is Some && r->Some_0@ == b@,
{
    let s = uuid_16_bytes_to_str_exec(b);
    proof {
        lemma_roundtrip_bytes(b@);
    }
    uuid_str_to_16_bytes_exec(s.as_slice())
}

// ---- the EC serialization, executable ----

pub open spec fn ec_view(v: Seq<(Vec<u8>, Vec<u8>)>) -> EcList {
    Seq::new(v.len(), |i: int| (v[i].0@, v[i].1@))
}

fn push_be16(out: &mut Vec<u8>, n: usize)
    requires
        n < 65536,
    ensures
        final(out)@ == old(out)@ + be16(n as int),
{
    out.push((n / 256) as u8);
    out.push((n % 256) as u8);
    proof {
        assert(out@ =~= old(out)@ + be16(n as int));
    }
}

/// `EncryptionContext::to_bytes` (encryption_context.rs :91-137).
fn to_bytes_exec(ec: &Vec<(Vec<u8>, Vec<u8>)>) -> (r: Option<Vec<u8>>)
    ensures
        match r {
            Some(x) => ser_ok(ec_view(ec@)) && x@ == ser(ec_view(ec@)),
            None => !ser_ok(ec_view(ec@)),
        },
{
    let view = Ghost(ec_view(ec@));
    if ec.len() == 0 {
        proof {
            assert(ser(view@) =~= Seq::<u8>::empty());
            assert(view@.len() == 0);
        }
        return Some(Vec::new());
    }
    if ec.len() > 65535 {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    push_be16(&mut out, ec.len());
    let mut i: usize = 0;
    while i < ec.len()
        invariant
            i <= ec.len(),
            ec.len() < 65536,
            view@ == ec_view(ec@),
            out@ == be16(ec.len() as int) + ser_entries(view@.take(i as int)),
            forall|m: int|
                0 <= m < i ==> (#[trigger] view@[m]).0.len() < 65536 && view@[m].1.len() < 65536,
        decreases ec.len() - i,
    {
        let klen = ec[i].0.len();
        if klen > 65535 {
            proof {
                assert(!entries_ok(view@)) by {
                    assert(view@[i as int].0.len() >= 65536);
                }
            }
            return None;
        }
        let vlen = ec[i].1.len();
        if vlen > 65535 {
            proof {
                assert(!entries_ok(view@)) by {
                    assert(view@[i as int].1.len() >= 65536);
                }
            }
            return None;
        }
        let ghost before = out@;
        push_be16(&mut out, klen);
        out.extend_from_slice(ec[i].0.as_slice());
        push_be16(&mut out, vlen);
        out.extend_from_slice(ec[i].1.as_slice());
        proof {
            let t = view@.take(i as int);
            let e = view@[i as int];
            assert(view@.take(i as int + 1) =~= t + seq![e]);
            lemma_ser_entries_append(t, seq![e]);
            reveal_with_fuel(ser_entries, 2);
            assert(seq![e].skip(1) =~= Seq::<(Bytes, Bytes)>::empty());
            assert(ser_entries(seq![e]) =~= enc_entry(e));
            assert(out@ =~= before + enc_entry(e));
            assert(out@ =~= be16(ec.len() as int) + ser_entries(view@.take(i as int + 1)));
        }
        i = i + 1;
    }
    proof {
        assert(view@.take(ec.len() as int) =~= view@);
        assert(entries_ok(view@));
        assert(ser_ok(view@));
    }
    Some(out)
}

/// `compute_aad` (branch_key_wrap.rs :61-80) on bytes. The `Vec::with_capacity` hint (:70-72) is
/// not modeled (A_ALLOC).
fn compute_aad_exec(bkid: &[u8], version: &[u8], ec: &Vec<(Vec<u8>, Vec<u8>)>) -> (r: Result<
    Vec<u8>,
    AadErr,
>)
    ensures
        match r {
            Ok(a) => compute_aad_spec(bkid@, version@, ec_view(ec@)) == Result::<Bytes, AadErr>::Ok(
                a@,
            ),
            Err(e) => compute_aad_spec(bkid@, version@, ec_view(ec@)) == Result::<
                Bytes,
                AadErr,
            >::Err(e),
        },
{
    let v = match uuid_str_to_16_bytes_exec(version) {
        Some(v) => v,
        None => {
            return Err(AadErr::Version);
        },
    };
    let ser_ec = match to_bytes_exec(ec) {
        Some(x) => x,
        None => {
            return Err(AadErr::Ec);
        },
    };
    let mut aad: Vec<u8> = Vec::new();
    let lab: [u8; 17] = [
        0x61, 0x77, 0x73, 0x2d, 0x6b, 0x6d, 0x73, 0x2d, 0x68, 0x69, 0x65, 0x72, 0x61, 0x72, 0x63,
        0x68, 0x79,
    ];
    aad.extend_from_slice(&lab);
    aad.extend_from_slice(bkid);
    aad.extend_from_slice(&v);
    aad.extend_from_slice(ser_ec.as_slice());
    proof {
        assert(lab@ =~= label());
        assert(aad@ =~= label() + bkid@ + v@ + ser_ec@);
    }
    Ok(aad)
}

} // verus!

fn main() {}
