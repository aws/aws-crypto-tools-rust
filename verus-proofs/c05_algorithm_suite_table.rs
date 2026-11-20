// =============================================================================
// VR-2026-C05 (capability 1a): the algorithm suite table in
//   mpl/src/structures/algorithm_suite.rs against spec/framework/algorithm-suites.md
//
// Run:  ~/verus/verus verus-proofs/c05_algorithm_suite_table.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model. The shipped code is native Rust, is not
// inside `verus!`, and is not compiled by Verus. Nothing here detects a later edit to mpl/. The
// link between model and code is the correspondence table in section 2, reviewed by a human, and
// a script that compares the copied constants with the sources (section 4, A_CODE_COPY).
//
// THIS IS A CONSISTENCY CHECK OF A CONSTANT TABLE AGAINST THE SPEC TEXT. The table has 11 rows and
// the domain is finite. Two tables that were both typed in by hand are compared, one copied from
// algorithm_suite.rs and one copied from algorithm-suites.md, and the comparison is checked by
// Verus for all 11 rows. The result is only as good as the two copies. It does not show that the
// spec is right, that the code calls the table correctly, or that any threat is mitigated. The
// repository already has 22 tests for the same facts over the same finite domain
// (mpl/tests/test_algorithm_suite_id.rs); this file restates them as lemmas over the model and
// adds a comparison with the prim and esdk length constants (hand copies too).
//
// STATUS: PROVED (model level), relative to the assumptions and hypotheses in section 4.
//   Nothing is left failing. No expected-FAIL obligation is written, because no gap between the
//   table and the spec text was found.
//
// WHAT IS PROVED (relative to the model and to section 4)
//   R1  theorem_table_refines_spec      for each of the 11 suites, the model of the shipped
//                                       `specification()` row equals the spec row: id, encryption
//                                       algorithm and mode, key length (bytes vs bits), IV length,
//                                       tag length, encryption KDF (algorithm and hash), key
//                                       commitment, commit KDF and its output length, asymmetric
//                                       and symmetric signature algorithm, message format version
//                                       and suite data length.
//   R2  theorem_ids_injective           two suites with the same id bytes are the same suite
//       theorem_ids_never_reserved      no suite has the id 00 00
//       theorem_ids_unique_across_spec  the 11 ESDK ids differ from each other, from 00 00 and
//                                       from the 7 S3EC and DBE ids of the spec table (the code
//                                       implements only ESDK, H_ONLY_ESDK)
//   R3  theorem_all_*                   `ALL` lists every suite exactly once, in strictly ascending
//                                       id order (the doc comment of `ALL` says so)
//       theorem_from_id_bytes_*         `from_id_bytes` inverts `id_bytes` on every suite, and
//                                       returns None for 00 00 and for every id no suite has
//   R4  theorem_commitment_*            commit_kdf is Some <==> message format version 2 <==>
//                                       suite data length 32; the others have version 1 and 0
//   R5  theorem_key_length_*            key length is 16, 24 or 32 and equals the key length of
//                                       the prim `AesGcm` that esdk `get_alg_suite` picks
//       theorem_vk_length_*             `verification_key_length()` is `prim::field_size` of the
//                                       matching curve, and is 1 + ceil(bits / 8)
//       theorem_no_symmetric_signing    no ESDK suite has a symmetric signature algorithm
//   R6  theorem_c05_summary             the conjunction of the above for an arbitrary suite
//
// WHAT IS NOT PROVED
//   * That the shipped code has any of these properties (model level only; A_CODE_COPY and
//     H_MODEL_MATCH).
//   * That the spec text is correct or complete. The spec table is taken as given (A_SPEC_COPY).
//   * The S3EC and DBE suites. They are not in the code (H_ONLY_ESDK). Only their ids are
//     modeled, in `spec_other_id`, to check uniqueness across formats as the spec text asks.
//   * The salt length column of the spec tables. The code table has no salt field.
//   * The KDF input and output lengths beyond what the table stores. The spec "Key Derivation
//     Input Length" is checked only against the key length (a spec-internal check, section 5).
//   * How callers use the table: that every keyring checks the data key length, that every CMM
//     picks the suite the caller asked for, or that decrypt rejects an id the header carries but
//     the table does not have. Those are other targets (C04, C07, T09).
//   * Any property of `prim::AesGcm`, `field_size` or the aws-lc-rs backend beyond the two
//     constant tables copied from prim (A_PRIM_COPY).
//   * That a threat is mitigated. This file maps to no TM-MPL threat. It is a regression guard
//     for the table, not a defense.
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD ad3522b)
// =============================================================================
//   mpl/src/structures/algorithm_suite.rs
//     :69-92     enum EsdkAlgorithmSuiteId, 11 variants (non_exhaustive), doc comments carry the ids
//     :94-106    const ALL_SUITES: [EsdkAlgorithmSuiteId; 11], listed in ascending id order
//     :116-130   exhaustive_over_algorithm_suite_id: no wildcard arm; each variant indexes ALL_SUITES
//     :134       EsdkAlgorithmSuiteId::ALL = &ALL_SUITES
//     :139-141   from_id_bytes: ALL.iter().copied().find(|id| id.id_bytes() == bytes)
//     :144-305   specification(): one AlgorithmSuite literal per variant, no wildcard arm
//     :312-314   id_bytes() = specification().id
//     :317-331   has_asymmetric_signing(), has_symmetric_signing()
//     :344-357   struct AlgorithmSuite: private fields, non_exhaustive, no public constructor
//     :378       encryption_key_length() (used by C04)
//     :410-412   key_commitment() = commit_kdf.is_some()
//     :440-446   verification_key_length(): P256 -> 33, P384 -> 49, None -> None
//     :450-451   VERIFICATION_KEY_LEN_P256 = 33, VERIFICATION_KEY_LEN_P384 = 49
//     :25-56     AlgorithmSuiteId (only `Esdk(..)`), delegates to the ESDK table
//   prim/src/lib.rs :138-154        AesGcm::key_length(): 16, 24, 32
//   prim/src/ecdsa.rs :352-357      field_size(): P256 -> 33, P384 -> 49
//   esdk/src/message/body/mod.rs :18-28   get_alg_suite: key length 16/24/32 -> Aes128/192/256Gcm
//   mpl/src/cmm/default_cmm.rs :123-128   AsymmetricSignatureAlgorithm -> PrimEcdsaSignatureAlgorithm
//   esdk/src/suites.rs :104-111           the same mapping in get_ecdsa_alg
//   mpl/src/structures/decryption_materials.rs :326-340   the use of verification_key_length()
//   mpl/tests/test_algorithm_suite_id.rs                  22 tests of the same facts (not modeled)
//   spec/framework/algorithm-suites.md (file header says Version 0.4.0):
//     "Supported Algorithm Suites"                   lines 183-212  (id, format version, data length)
//     "Algorithm Suites Encryption Key Derivation Settings"  lines 214-237  (KDF, hash, commitment)
//     "Algorithm Suites Encryption Settings"          lines 239-262  (algorithm, mode, key bits, IV, tag)
//     "Algorithm Suites Commit Key Derivation Settings"      lines 264-288  (commit KDF)
//     "Algorithm Suites Signature Settings"           lines 290-314  (signature algorithms)
//     "Structure" (Algorithm Suite ID, Key Commitment, Algorithm Suite Data)   lines 406-583
//
// Spec text this file is built from (RFC 2119 words as in the spec):
//   "The value `00 00` is reserved and MUST NOT be used as an Algorithm Suite ID in the future.
//    Algorithm Suite ID MUST be a unique hex value across all supported algorithm suites."
//                                                    (Supported Algorithm Suites, lines 185-188)
//   "A 2-byte hex value that MUST uniquely identify an algorithm suite."   (Algorithm Suite ID)
//   "The length of the input encryption key MUST equal the encryption key length specified by
//    the algorithm suite."                                                 (Encryption Algorithm)
//   "Algorithm Suite 05 78 MUST store the commit key in the suite data"  (Algorithm Suite Data;
//    the same line for 04 78)
//   "Message Format Version ... This MUST be used to branch any serialization/deserialization
//    logic"                                                            (Message Format Version)
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code or spec)
// =============================================================================
//   model                          shipped code or spec
//   -----------------------------  ---------------------------------------------------------
//   Suite (11 variants)            EsdkAlgorithmSuiteId, :69-92, same names
//   CRow, code_row(s)              AlgorithmSuite and EsdkAlgorithmSuiteId::specification, :144-305
//     id0, id1                     id: [u8; 2]
//     key_len, iv_len, tag_len     encryption_key_length, iv_length, authentication_tag_length (usize)
//     enc_kdf, commit_kdf          encryption_kdf, commit_kdf
//     asym, sym                    asymmetric_signature_algorithm, symmetric_signature_algorithm
//     fmt, data_len                message_format_version (u8), algorithm_suite_data_length (usize)
//   c_has_asym, c_has_sym          has_asymmetric_signing, has_symmetric_signing
//   c_key_commitment               AlgorithmSuite::key_commitment, :410
//   c_vk_len                       AlgorithmSuite::verification_key_length, :440-446
//   id_of(s)                       id_bytes, :312
//   all_at(i)                      ALL_SUITES[i], :94-106
//   from_id_bytes(b0, b1)          EsdkAlgorithmSuiteId::from_id_bytes, :139-141 (first match, A_FIND)
//   SRow, spec_row(s)              the five spec tables, in the spec units (hex id, bits, "1.0")
//   spec_other_id(i)               ids of the 7 S3EC and DBE rows of "Supported Algorithm Suites"
//   PAes, prim_key_length          prim::AesGcm, AesGcm::key_length
//   PCurve, prim_field_size        prim::EcdsaSignatureAlgorithm, field_size
//   get_alg_suite                  esdk body/mod.rs get_alg_suite
//   curve_of                       the match in default_cmm.rs :123-128 and suites.rs :104-111
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED
// =============================================================================
// Spec-derived: every field of `spec_row`, the 7 ids of `spec_other_id`, the reserved id 00 00, and
// the properties R2 and R4 (the spec says ids are unique, 00 00 is reserved, and that suites 04 78
// and 05 78 store a 32-byte commit key in the suite data).
// Code-derived: every field of `code_row`, the order of `ALL`, the search in `from_id_bytes`, the
// constants 33 and 49 in `verification_key_length`, and the prim and esdk tables of R5.
// Model decisions that are interpretations, not facts of either side (A_FMT, A_NA):
//   * spec "1.0" and "2.0" are compared with the code bytes 0x01 and 0x02;
//   * spec "N/A" for the suite data length is compared with the code value 0 (the spec says the
//     field "MAY be length 0").
//
// =============================================================================
// 4. HYPOTHESES, ASSUMPTIONS AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and to the
//                  items below
//    ASSUMED       taken as a premise, a definition or a hand copy; not proved here (A_*)
//    CODE READING  a claim about shipped code that Verus does not see (H_*); checked by a human
//                  reading the source at the lines named
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier..]`
//  attribute is written in this file, and there is no uninterpreted spec function.
//
//  CONSTANTS COPIED BY HAND (type "copied by hand"; each is ASSUMED to equal its source)
//  A_SPEC_COPY (ASSUMED, copied by hand). `spec_row` (11 rows x 14 fields) and `spec_other_id`
//    (7 ids) are typed in from the five tables of spec/framework/algorithm-suites.md named in
//    section 1. The ids, key bits, IV and tag bytes, KDF, hash, commitment, commit hash and
//    output bits, signature algorithms, format versions and suite data lengths are all hand
//    copies. The ESDK rows agree with the shared constants block of
//    .kiro/agents/mpl-verus-header-parsing-proofs.md (checked by script, c05-copy-check.txt).
//  A_CODE_COPY (ASSUMED, copied by hand). `code_row` (11 rows x 13 fields), the order of
//    `all_at`, and the two constants 33 and 49 in `c_vk_len` are typed in from algorithm_suite.rs
//    :94-106, :144-305 and :440-451. A script compared each row with the Rust source and found
//    them equal (.agents/tasks/mpl-four-proofs/c05-copy-check.txt, evidence: code reading with
//    script support). Verus does not see the Rust file.
//  A_PRIM_COPY (ASSUMED, copied by hand). `prim_key_length` (16, 24, 32) is typed in from
//    prim/src/lib.rs :148-154. `prim_field_size` (33, 49) is typed in from prim/src/ecdsa.rs
//    :352-357. `get_alg_suite` is typed in from esdk/src/message/body/mod.rs :18-28. `curve_of`
//    is typed in from default_cmm.rs :123-128 (the same match is at esdk/src/suites.rs :104-111).
//
//  OTHER ASSUMPTIONS
//  A_FMT (ASSUMED). The spec versions "1.0" and "2.0" correspond to the code values 0x01 and
//    0x02 (the code doc comment on `message_format_version` says "0x01 for V1, 0x02 for V2").
//  A_NA (ASSUMED). The spec value "N/A" for the suite data length corresponds to the code value 0.
//  A_INT (ASSUMED). Code fields are `usize` and `u8`. Every value is at most 49, so no operation
//    in the model overflows. The model uses `usize` and `u8` for the code side and `int` for the
//    spec side.
//  A_FIND (ASSUMED, std). `Iterator::find` returns the first element, in iteration order, for
//    which the predicate holds, and `[T]::iter` yields the elements in index order. `find_from`
//    is that definition. vstd has no specification for `Iterator::find` on a slice.
//  A_VSTD (ASSUMED). The trusted base is Verus, Z3 and the vstd axioms for Seq.
//
//  CODE READING (H_*)
//  H_MODEL_MATCH (CODE READING). `code_row` has the same values as the 11 literals of
//    `specification()` (:146-304), and `c_*` have the same bodies as the accessors. Checked by
//    reading and by the script in A_CODE_COPY; not machine-checked.
//  H_TABLE_ONLY (CODE READING). `AlgorithmSuite` has private fields and is `#[non_exhaustive]`;
//    `grep -rn "AlgorithmSuite {" mpl/src esdk/src` finds a struct literal only inside
//    `specification()` (:146-290). So every `AlgorithmSuite` value in the program comes from the
//    table, and a property of the table is a property of every suite value. A new constructor
//    elsewhere would break this.
//  H_ONLY_ESDK (CODE READING). `AlgorithmSuiteId` has the one variant `Esdk(..)` (:25-28), and
//    `EsdkAlgorithmSuiteId` has 11 variants. The S3EC and DBE rows of the spec table are not
//    implemented, so id uniqueness across formats is checked here only against the spec ids.
//  H_ALL (CODE READING). `ALL` is `&ALL_SUITES` (:134); `ALL_SUITES` has the 11 entries in the
//    order modeled by `all_at` (:94-106); `exhaustive_over_algorithm_suite_id` (:116-130) makes
//    a missing variant a compile error.
//  H_FROM_ID (CODE READING). `from_id_bytes` is `ALL.iter().copied().find(..)` on `id_bytes()`
//    (:139-141) and has no other path.
//  H_CURVE_MAP (CODE READING). The two matches that map `AsymmetricSignatureAlgorithm` to the prim
//    curve are 1:1 and total on the two variants (default_cmm.rs :123-128, suites.rs :104-111).
//  H_AES_MAP (CODE READING). `get_alg_suite` is the only mapping from a suite key length to a
//    prim `AesGcm` for message bodies (esdk/src/message/body/mod.rs :18-28). Keyrings that take
//    the key length from the suite use `Vec` buffers of that length (raw_aes_keyring.rs :536,
//    hierarchical_keyring.rs :976) and do not choose an AES variant from it.
//  H_NO_SALT (CODE READING). No consumer reads a salt length from the table (the table has none).
//
// =============================================================================
// 5. HOW THE PROOF IS BUILT
// =============================================================================
// `spec_row` and `code_row` are written separately and in different units (bits against bytes,
// hex integer against two bytes, (algorithm, hash) against one enum). `row_refines` converts the
// code row and compares every field. `theorem_table_refines_spec` is checked for each variant.
// Injectivity is proved by comparing the two id bytes (Z3 case split on the 11 variants), then
// again through strict order of the ids. `find_from` models the linear search of from_id_bytes
// and its two lemmas are proved by induction on the start index.
// Section 4 of the code also holds a spec-only check (`lemma_spec_table_consistent`). They show the spec rows
// agree with each other (key derivation input bits equal key bits, commit output 256 bits equals
// the 32-byte suite data). They say nothing about the code.
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: The code table (model of algorithm_suite.rs)
// ============================================================

/// EsdkAlgorithmSuiteId, :69-92. Same variant names as the code.
pub enum Suite {
    AlgAes128GcmIv12Tag16NoKdf,
    AlgAes192GcmIv12Tag16NoKdf,
    AlgAes256GcmIv12Tag16NoKdf,
    AlgAes128GcmIv12Tag16HkdfSha256,
    AlgAes192GcmIv12Tag16HkdfSha256,
    AlgAes256GcmIv12Tag16HkdfSha256,
    AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
    AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
    AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
    AlgAes256GcmHkdfSha512CommitKey,
    AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
}

pub enum CEnc { Aes }
pub enum CMode { Gcm }
/// KeyDerivationAlgorithm, algorithm_suite.rs.
pub enum CKdf { IdentityKdf, HkdfSha256, HkdfSha384, HkdfSha512 }
/// AsymmetricSignatureAlgorithm.
pub enum CAsym { EcdsaP256, EcdsaP384 }
/// SymmetricSignatureAlgorithm.
pub enum CSym { HmacSha384 }

/// AlgorithmSuite, :344-357 (the fields C05 is about).
pub struct CRow {
    pub id0: u8,
    pub id1: u8,
    pub enc: CEnc,
    pub mode: CMode,
    pub key_len: usize,
    pub iv_len: usize,
    pub tag_len: usize,
    pub enc_kdf: CKdf,
    pub commit_kdf: Option<CKdf>,
    pub asym: Option<CAsym>,
    pub sym: Option<CSym>,
    pub fmt: u8,
    pub data_len: usize,
}

/// A_CODE_COPY: EsdkAlgorithmSuiteId::specification, :144-305, one arm per variant.
pub open spec fn code_row(s: Suite) -> CRow {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => CRow {
            id0: 0x00, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 16, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::IdentityKdf, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes192GcmIv12Tag16NoKdf => CRow {
            id0: 0x00, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 24, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::IdentityKdf, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes256GcmIv12Tag16NoKdf => CRow {
            id0: 0x00, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::IdentityKdf, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => CRow {
            id0: 0x01, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 16, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => CRow {
            id0: 0x01, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 24, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => CRow {
            id0: 0x01, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => CRow {
            id0: 0x02, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 16, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,
            asym: Some(CAsym::EcdsaP256), sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => CRow {
            id0: 0x03, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 24, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha384, commit_kdf: None,
            asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => CRow {
            id0: 0x03, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha384, commit_kdf: None,
            asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes256GcmHkdfSha512CommitKey => CRow {
            id0: 0x04, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha512, commit_kdf: Some(CKdf::HkdfSha512),
            asym: None, sym: None, fmt: 0x02, data_len: 32,
        },
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => CRow {
            id0: 0x05, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha512, commit_kdf: Some(CKdf::HkdfSha512),
            asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x02, data_len: 32,
        },
    }
}

/// has_asymmetric_signing, :318-324.
pub open spec fn c_has_asym(c: CRow) -> bool { c.asym is Some }

/// has_symmetric_signing, :329-331.
pub open spec fn c_has_sym(c: CRow) -> bool { c.sym is Some }

/// AlgorithmSuite::key_commitment, :410-412.
pub open spec fn c_key_commitment(c: CRow) -> bool { c.commit_kdf is Some }

/// A_CODE_COPY: VERIFICATION_KEY_LEN_P256 and _P384, :450-451.
pub open spec fn vk_len_p256() -> usize { 33 }

pub open spec fn vk_len_p384() -> usize { 49 }

/// AlgorithmSuite::verification_key_length, :440-446.
pub open spec fn c_vk_len(c: CRow) -> Option<usize> {
    match c.asym {
        Some(CAsym::EcdsaP256) => Some(vk_len_p256()),
        Some(CAsym::EcdsaP384) => Some(vk_len_p384()),
        None => None,
    }
}

/// id_bytes, :312: the two id bytes of a suite.
pub open spec fn id_of(s: Suite) -> (u8, u8) {
    (code_row(s).id0, code_row(s).id1)
}

// ============================================================
// SECTION 2: The spec table (model of algorithm-suites.md)
// ============================================================

pub enum SEnc { Aes }
pub enum SMode { Gcm }
pub enum SHash { Sha256, Sha384, Sha512 }
/// Spec column "Algorithm" with "Hash Function".
pub enum SKdf { Identity, Hkdf(SHash) }
/// Spec "Asymmetric Signature Algorithm" column.
pub enum SSig { EcdsaP256Sha256, EcdsaP384Sha384 }

/// "Algorithm Suites Commit Key Derivation Settings": the commit KDF is HKDF.
pub struct SCommit {
    pub in_bits: int,
    pub out_bits: int,
    pub hash: SHash,
}

/// One ESDK row, gathered from the five spec tables, in the spec's units.
pub struct SRow {
    pub id: int,                 // "Algorithm Suite ID (hex)", read as one integer
    pub enc: SEnc,
    pub mode: SMode,
    pub key_bits: int,           // "Encryption Key Length (bits)"
    pub iv_bytes: int,           // "IV Length (bytes)"
    pub tag_bytes: int,          // "Authentication Tag Length (bytes)"
    pub kdf_in_bits: int,        // "Key Derivation Input Length (bits)"
    pub kdf: SKdf,               // "Algorithm" and "Hash Function"
    pub key_commitment: bool,    // "Key Commitment"
    pub commit: Option<SCommit>, // commit key derivation table; None for N/A rows
    pub asym: Option<SSig>,      // "Not applicable" is None
    pub sym_hmac_sha384: bool,   // "Symmetric Signature Algorithm" is HMAC with SHA-384
    pub fmt_major: int,          // "Message Format Version", 1.0 or 2.0
    pub data_len: Option<int>,   // "Algorithm Suite Data Length (bytes)", N/A is None
}

/// A_SPEC_COPY: the 11 ESDK rows of the five spec tables.
pub open spec fn spec_row(s: Suite) -> SRow {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => SRow {
            id: 0x0014, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 128, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 128, kdf: SKdf::Identity, key_commitment: false, commit: None,
            asym: None, sym_hmac_sha384: false, fmt_major: 1, data_len: None,
        },
        Suite::AlgAes192GcmIv12Tag16NoKdf => SRow {
            id: 0x0046, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 192, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 192, kdf: SKdf::Identity, key_commitment: false, commit: None,
            asym: None, sym_hmac_sha384: false, fmt_major: 1, data_len: None,
        },
        Suite::AlgAes256GcmIv12Tag16NoKdf => SRow {
            id: 0x0078, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 256, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 256, kdf: SKdf::Identity, key_commitment: false, commit: None,
            asym: None, sym_hmac_sha384: false, fmt_major: 1, data_len: None,
        },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => SRow {
            id: 0x0114, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 128, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 128, kdf: SKdf::Hkdf(SHash::Sha256), key_commitment: false, commit: None,
            asym: None, sym_hmac_sha384: false, fmt_major: 1, data_len: None,
        },
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => SRow {
            id: 0x0146, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 192, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 192, kdf: SKdf::Hkdf(SHash::Sha256), key_commitment: false, commit: None,
            asym: None, sym_hmac_sha384: false, fmt_major: 1, data_len: None,
        },
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => SRow {
            id: 0x0178, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 256, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 256, kdf: SKdf::Hkdf(SHash::Sha256), key_commitment: false, commit: None,
            asym: None, sym_hmac_sha384: false, fmt_major: 1, data_len: None,
        },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => SRow {
            id: 0x0214, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 128, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 128, kdf: SKdf::Hkdf(SHash::Sha256), key_commitment: false, commit: None,
            asym: Some(SSig::EcdsaP256Sha256), sym_hmac_sha384: false, fmt_major: 1, data_len: None,
        },
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => SRow {
            id: 0x0346, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 192, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 192, kdf: SKdf::Hkdf(SHash::Sha384), key_commitment: false, commit: None,
            asym: Some(SSig::EcdsaP384Sha384), sym_hmac_sha384: false, fmt_major: 1, data_len: None,
        },
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => SRow {
            id: 0x0378, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 256, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 256, kdf: SKdf::Hkdf(SHash::Sha384), key_commitment: false, commit: None,
            asym: Some(SSig::EcdsaP384Sha384), sym_hmac_sha384: false, fmt_major: 1, data_len: None,
        },
        Suite::AlgAes256GcmHkdfSha512CommitKey => SRow {
            id: 0x0478, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 256, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 256, kdf: SKdf::Hkdf(SHash::Sha512), key_commitment: true,
            commit: Some(SCommit { in_bits: 256, out_bits: 256, hash: SHash::Sha512 }),
            asym: None, sym_hmac_sha384: false, fmt_major: 2, data_len: Some(32),
        },
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => SRow {
            id: 0x0578, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 256, iv_bytes: 12, tag_bytes: 16,
            kdf_in_bits: 256, kdf: SKdf::Hkdf(SHash::Sha512), key_commitment: true,
            commit: Some(SCommit { in_bits: 256, out_bits: 256, hash: SHash::Sha512 }),
            asym: Some(SSig::EcdsaP384Sha384), sym_hmac_sha384: false, fmt_major: 2, data_len: Some(32),
        },
    }
}

/// A_SPEC_COPY: the ids of the 7 non-ESDK rows of "Supported Algorithm Suites" (the S3EC rows
/// 00 70 to 00 74 and the DBE rows 67 00 and 67 01), by index 0..6. Ids only; the code does not
/// implement these suites (H_ONLY_ESDK).
pub open spec fn spec_other_id(i: int) -> int {
    if i == 0 { 0x6700 }
    else if i == 1 { 0x6701 }
    else if i == 2 { 0x0070 }
    else if i == 3 { 0x0071 }
    else if i == 4 { 0x0074 }
    else if i == 5 { 0x0072 }
    else { 0x0073 }
}

/// "The value `00 00` is reserved".
pub open spec fn reserved_id() -> int { 0x0000 }

// ============================================================
// SECTION 3: The refinement relation (code row against spec row)
// ============================================================

pub open spec fn kdf_to_spec(k: CKdf) -> SKdf {
    match k {
        CKdf::IdentityKdf => SKdf::Identity,
        CKdf::HkdfSha256 => SKdf::Hkdf(SHash::Sha256),
        CKdf::HkdfSha384 => SKdf::Hkdf(SHash::Sha384),
        CKdf::HkdfSha512 => SKdf::Hkdf(SHash::Sha512),
    }
}

pub open spec fn enc_to_spec(e: CEnc) -> SEnc { SEnc::Aes }

pub open spec fn mode_to_spec(m: CMode) -> SMode { SMode::Gcm }

pub open spec fn sig_to_spec(a: CAsym) -> SSig {
    match a {
        CAsym::EcdsaP256 => SSig::EcdsaP256Sha256,
        CAsym::EcdsaP384 => SSig::EcdsaP384Sha384,
    }
}

pub open spec fn asym_to_spec(a: Option<CAsym>) -> Option<SSig> {
    match a {
        Some(x) => Some(sig_to_spec(x)),
        None => None,
    }
}

/// Key commitment: the code has it exactly when the spec says True, and then the commit KDF is
/// the spec commit HKDF with the same hash, and the spec commit output length (bits) equals the
/// suite data length (bytes) times 8 (the commit key is stored in the suite data).
pub open spec fn commit_refines(c: CRow, r: SRow) -> bool {
    match c.commit_kdf {
        None => !r.key_commitment && r.commit is None,
        Some(k) => r.key_commitment && match r.commit {
            None => false,
            Some(sc) => kdf_to_spec(k) == SKdf::Hkdf(sc.hash) && sc.out_bits == c.data_len as int * 8,
        },
    }
}

pub open spec fn data_len_refines(c: CRow, r: SRow) -> bool {
    match r.data_len {
        None => c.data_len == 0,
        Some(n) => c.data_len as int == n,
    }
}

pub open spec fn sym_refines(c: CRow, r: SRow) -> bool {
    match c.sym {
        None => !r.sym_hmac_sha384,
        Some(CSym::HmacSha384) => r.sym_hmac_sha384,
    }
}

/// The code row `c` is the spec row `r`, field by field, after the unit conversions.
pub open spec fn row_refines(c: CRow, r: SRow) -> bool {
    &&& c.id0 as int * 256 + c.id1 as int == r.id
    &&& enc_to_spec(c.enc) == r.enc
    &&& mode_to_spec(c.mode) == r.mode
    &&& c.key_len as int * 8 == r.key_bits
    &&& c.iv_len as int == r.iv_bytes
    &&& c.tag_len as int == r.tag_bytes
    &&& kdf_to_spec(c.enc_kdf) == r.kdf
    &&& commit_refines(c, r)
    &&& asym_to_spec(c.asym) == r.asym
    &&& sym_refines(c, r)
    &&& c.fmt as int == r.fmt_major
    &&& data_len_refines(c, r)
}

// ============================================================
// SECTION 4: R1, the table refines the spec
// ============================================================

/// R1: for every suite, the model of `specification()` equals the spec row.
proof fn theorem_table_refines_spec(s: Suite)
    ensures
        row_refines(code_row(s), spec_row(s)),
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

/// Spec-only check (says nothing about the code): the spec rows agree with each other.
/// The key derivation input length equals the key length, the commit key has 256 bits and is
/// 32 bytes, the suite data length is present exactly for key-committing rows, and the format
/// version is 2 exactly for key-committing rows.
proof fn lemma_spec_table_consistent(s: Suite)
    ensures
        spec_row(s).kdf_in_bits == spec_row(s).key_bits,
        spec_row(s).key_bits == 128 || spec_row(s).key_bits == 192 || spec_row(s).key_bits == 256,
        spec_row(s).key_commitment ==> spec_row(s).commit is Some,
        spec_row(s).key_commitment ==> spec_row(s).commit->Some_0.out_bits == 256,
        spec_row(s).key_commitment ==> spec_row(s).data_len == Some(32int),
        !spec_row(s).key_commitment ==> spec_row(s).data_len is None,
        spec_row(s).key_commitment <==> spec_row(s).fmt_major == 2,
        !spec_row(s).key_commitment <==> spec_row(s).fmt_major == 1,
        spec_row(s).commit is Some ==> spec_row(s).commit->Some_0.out_bits == spec_row(s).data_len->Some_0 * 8,
        spec_row(s).iv_bytes == 12,
        spec_row(s).tag_bytes == 16,
        !spec_row(s).sym_hmac_sha384,
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

// ============================================================
// SECTION 5: R2, ids are injective, never 00 00, unique across the spec table
// ============================================================

/// The id as one integer, the form the spec table uses (read as hex).
pub open spec fn id_val(s: Suite) -> int {
    code_row(s).id0 as int * 256 + code_row(s).id1 as int
}

/// Position of a suite in `ALL_SUITES` (:94-106).
pub open spec fn idx(s: Suite) -> int {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => 0,
        Suite::AlgAes192GcmIv12Tag16NoKdf => 1,
        Suite::AlgAes256GcmIv12Tag16NoKdf => 2,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 3,
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => 4,
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => 5,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => 6,
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 7,
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 8,
        Suite::AlgAes256GcmHkdfSha512CommitKey => 9,
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 10,
    }
}

/// ALL_SUITES[i], :94-106, for 0 <= i < 11.
pub open spec fn all_at(i: int) -> Suite {
    if i == 0 { Suite::AlgAes128GcmIv12Tag16NoKdf }
    else if i == 1 { Suite::AlgAes192GcmIv12Tag16NoKdf }
    else if i == 2 { Suite::AlgAes256GcmIv12Tag16NoKdf }
    else if i == 3 { Suite::AlgAes128GcmIv12Tag16HkdfSha256 }
    else if i == 4 { Suite::AlgAes192GcmIv12Tag16HkdfSha256 }
    else if i == 5 { Suite::AlgAes256GcmIv12Tag16HkdfSha256 }
    else if i == 6 { Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 }
    else if i == 7 { Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 }
    else if i == 8 { Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 }
    else if i == 9 { Suite::AlgAes256GcmHkdfSha512CommitKey }
    else { Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 }
}

/// R2: same id bytes, same suite.
proof fn theorem_ids_injective(a: Suite, b: Suite)
    requires
        id_of(a) == id_of(b),
    ensures
        a == b,
{
    assert(id_val(a) == id_val(b));
    // The ids are 11 distinct constants; Z3 splits on the constructors of `a` and `b`.
    match a {
        Suite::AlgAes128GcmIv12Tag16NoKdf => { match b { _ => {} } },
        Suite::AlgAes192GcmIv12Tag16NoKdf => { match b { _ => {} } },
        Suite::AlgAes256GcmIv12Tag16NoKdf => { match b { _ => {} } },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => { match b { _ => {} } },
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => { match b { _ => {} } },
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => { match b { _ => {} } },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => { match b { _ => {} } },
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => { match b { _ => {} } },
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => { match b { _ => {} } },
        Suite::AlgAes256GcmHkdfSha512CommitKey => { match b { _ => {} } },
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => { match b { _ => {} } },
    }
}

/// R2: no suite has the reserved id 00 00 (spec: "MUST NOT be used").
proof fn theorem_ids_never_reserved(s: Suite)
    ensures
        id_of(s) != (0u8, 0u8),
        id_val(s) != reserved_id(),
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

/// The same fact on the spec side: the spec ids are unique among the ESDK rows.
proof fn theorem_spec_ids_unique(a: Suite, b: Suite)
    requires
        spec_row(a).id == spec_row(b).id,
    ensures
        a == b,
{
    match a {
        Suite::AlgAes128GcmIv12Tag16NoKdf => { match b { _ => {} } },
        Suite::AlgAes192GcmIv12Tag16NoKdf => { match b { _ => {} } },
        Suite::AlgAes256GcmIv12Tag16NoKdf => { match b { _ => {} } },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => { match b { _ => {} } },
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => { match b { _ => {} } },
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => { match b { _ => {} } },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => { match b { _ => {} } },
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => { match b { _ => {} } },
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => { match b { _ => {} } },
        Suite::AlgAes256GcmHkdfSha512CommitKey => { match b { _ => {} } },
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => { match b { _ => {} } },
    }
}

/// R2: across the whole spec table. The 11 ESDK ids differ from each of the 7 other ids and from
/// 00 00; the 7 other ids differ from each other and from 00 00.
proof fn theorem_ids_unique_across_spec(s: Suite)
    ensures
        forall|i: int| 0 <= i < 7 ==> #[trigger] spec_other_id(i) != id_val(s),
        forall|i: int| 0 <= i < 7 ==> #[trigger] spec_other_id(i) != reserved_id(),
        forall|i: int, j: int| 0 <= i < 7 && 0 <= j < 7 && i != j ==> spec_other_id(i) != spec_other_id(j),
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

// ============================================================
// SECTION 6: R3, ALL and from_id_bytes
// ============================================================

/// Strictly ascending ids follow the index (the doc comment of `ALL`: "ascending on-wire id order").
proof fn lemma_id_val_ascends(s: Suite, t: Suite)
    requires
        idx(s) < idx(t),
    ensures
        id_val(s) < id_val(t),
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => { match t { _ => {} } },
        Suite::AlgAes192GcmIv12Tag16NoKdf => { match t { _ => {} } },
        Suite::AlgAes256GcmIv12Tag16NoKdf => { match t { _ => {} } },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => { match t { _ => {} } },
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => { match t { _ => {} } },
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => { match t { _ => {} } },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => { match t { _ => {} } },
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => { match t { _ => {} } },
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => { match t { _ => {} } },
        Suite::AlgAes256GcmHkdfSha512CommitKey => { match t { _ => {} } },
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => { match t { _ => {} } },
    }
}

/// `all_at` and `idx` are inverse: ALL lists every suite, at the position `idx`.
proof fn lemma_all_at_idx(s: Suite)
    ensures
        0 <= idx(s) < 11,
        all_at(idx(s)) == s,
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

proof fn lemma_idx_all_at(i: int)
    requires
        0 <= i < 11,
    ensures
        idx(all_at(i)) == i,
{
}

/// R3: `ALL` has 11 entries, lists every suite, lists none twice, and is strictly ascending in id.
proof fn theorem_all_complete_once_ascending()
    ensures
        forall|s: Suite| 0 <= #[trigger] idx(s) < 11 && all_at(idx(s)) == s,
        forall|i: int, j: int| 0 <= i < j < 11 ==> #[trigger] id_val(all_at(i)) < #[trigger] id_val(all_at(j)),
        forall|i: int, j: int| 0 <= i < 11 && 0 <= j < 11 && i != j ==> #[trigger] all_at(i) != #[trigger] all_at(j),
{
    assert forall|s: Suite| 0 <= #[trigger] idx(s) < 11 && all_at(idx(s)) == s by {
        lemma_all_at_idx(s);
    }
    assert forall|i: int, j: int| 0 <= i < j < 11 implies #[trigger] id_val(all_at(i)) < #[trigger] id_val(all_at(j)) by {
        lemma_idx_all_at(i);
        lemma_idx_all_at(j);
        lemma_id_val_ascends(all_at(i), all_at(j));
    }
    assert forall|i: int, j: int| 0 <= i < 11 && 0 <= j < 11 && i != j implies #[trigger] all_at(i) != #[trigger] all_at(j) by {
        lemma_idx_all_at(i);
        lemma_idx_all_at(j);
    }
}

/// A_FIND: the search of `from_id_bytes` (:139-141): first element of ALL, from index `i`, whose
/// id bytes equal `b`.
pub open spec fn find_from(b: (u8, u8), i: int) -> Option<Suite>
    decreases 11 - i,
{
    if i >= 11 {
        None
    } else if id_of(all_at(i)) == b {
        Some(all_at(i))
    } else {
        find_from(b, i + 1)
    }
}

/// EsdkAlgorithmSuiteId::from_id_bytes, :139-141.
pub open spec fn from_id_bytes(b: (u8, u8)) -> Option<Suite> { find_from(b, 0) }

/// The search finds `s` from any start index at or before its position.
proof fn lemma_find_from_finds(s: Suite, i: int)
    requires
        0 <= i <= idx(s),
        idx(s) < 11,
    ensures
        find_from(id_of(s), i) == Some(s),
    decreases idx(s) - i,
{
    lemma_all_at_idx(s);
    if i == idx(s) {
        assert(all_at(i) == s);
    } else {
        lemma_idx_all_at(i);
        // all_at(i) is a different suite, so its id bytes differ (injectivity)
        if id_of(all_at(i)) == id_of(s) {
            theorem_ids_injective(all_at(i), s);
            assert(false);
        }
        lemma_find_from_finds(s, i + 1);
    }
}

/// Anything the search returns has the id bytes asked for.
proof fn lemma_find_from_sound(b: (u8, u8), i: int, t: Suite)
    requires
        0 <= i,
        find_from(b, i) == Some(t),
    ensures
        id_of(t) == b,
    decreases 11 - i,
{
    if i >= 11 {
    } else if id_of(all_at(i)) == b {
    } else {
        lemma_find_from_sound(b, i + 1, t);
    }
}

/// R3: `from_id_bytes` inverts `id_bytes` on every suite; it only returns a suite with the id it
/// was given; it returns None for 00 00 and for every id that no suite has.
proof fn theorem_from_id_bytes_inverse(s: Suite)
    ensures
        from_id_bytes(id_of(s)) == Some(s),
{
    lemma_all_at_idx(s);
    lemma_find_from_finds(s, 0);
}

proof fn theorem_from_id_bytes_sound(b: (u8, u8), t: Suite)
    requires
        from_id_bytes(b) == Some(t),
    ensures
        id_of(t) == b,
{
    lemma_find_from_sound(b, 0, t);
}

proof fn theorem_from_id_bytes_rejects_unknown(b: (u8, u8))
    ensures
        from_id_bytes(b) is None <==> (forall|s: Suite| id_of(s) != b),
        b == (0u8, 0u8) ==> from_id_bytes(b) is None,
{
    if from_id_bytes(b) is None {
        assert forall|s: Suite| id_of(s) != b by {
            if id_of(s) == b {
                theorem_from_id_bytes_inverse(s);
                assert(false);
            }
        }
    }
    if forall|s: Suite| id_of(s) != b {
        if from_id_bytes(b) is Some {
            let t = from_id_bytes(b)->Some_0;
            theorem_from_id_bytes_sound(b, t);
            assert(false);
        }
    }
    if b == (0u8, 0u8) {
        assert forall|s: Suite| id_of(s) != b by {
            theorem_ids_never_reserved(s);
        }
    }
}

// ============================================================
// SECTION 7: R4, key commitment, format version and suite data length move together
// ============================================================

/// R4 (spec: Algorithm Suite Data: 04 78 and 05 78 store the commit key; data length 32; ESDK
/// format 2.0). commit_kdf is Some <==> format version 2 <==> suite data length 32. Otherwise
/// version 1 and length 0. The commit KDF, when present, is HKDF with SHA-512 and equals the
/// encryption KDF; the data length equals the key length.
proof fn theorem_commitment_consistent(s: Suite)
    ensures
        c_key_commitment(code_row(s)) <==> code_row(s).fmt == 0x02,
        c_key_commitment(code_row(s)) <==> code_row(s).data_len == 32,
        !c_key_commitment(code_row(s)) <==> code_row(s).fmt == 0x01,
        !c_key_commitment(code_row(s)) <==> code_row(s).data_len == 0,
        code_row(s).commit_kdf is Some ==> code_row(s).commit_kdf == Some(CKdf::HkdfSha512),
        code_row(s).commit_kdf is Some ==> code_row(s).commit_kdf == Some(code_row(s).enc_kdf),
        code_row(s).commit_kdf is Some ==> code_row(s).data_len == code_row(s).key_len,
        code_row(s).fmt == 0x01 || code_row(s).fmt == 0x02,
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

/// R5: no ESDK suite has a symmetric signature algorithm (spec Signature Settings: "Not
/// applicable" for all 11 ESDK rows). `has_symmetric_signing` is false for every suite, and
/// `has_asymmetric_signing` is true exactly for the five ECDSA suites.
proof fn theorem_no_symmetric_signing(s: Suite)
    ensures
        !c_has_sym(code_row(s)),
        c_has_asym(code_row(s)) <==> spec_row(s).asym is Some,
        c_has_asym(code_row(s)) <==> (
            s == Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256
            || s == Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384
            || s == Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384
            || s == Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384),
{
    theorem_table_refines_spec(s);
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

// ============================================================
// SECTION 8: R5, lengths agree with the prim and esdk constants (A_PRIM_COPY)
// ============================================================

/// prim::AesGcm, prim/src/lib.rs :138-143.
pub enum PAes { Aes128Gcm, Aes192Gcm, Aes256Gcm }

/// AesGcm::key_length, prim/src/lib.rs :148-154.
pub open spec fn prim_key_length(a: PAes) -> usize {
    match a {
        PAes::Aes128Gcm => 16,
        PAes::Aes192Gcm => 24,
        PAes::Aes256Gcm => 32,
    }
}

/// esdk get_alg_suite, esdk/src/message/body/mod.rs :18-28 (Err arm is None).
pub open spec fn get_alg_suite(key_len: usize) -> Option<PAes> {
    if key_len == 16 { Some(PAes::Aes128Gcm) }
    else if key_len == 24 { Some(PAes::Aes192Gcm) }
    else if key_len == 32 { Some(PAes::Aes256Gcm) }
    else { None }
}

/// prim::EcdsaSignatureAlgorithm.
pub enum PCurve { EcdsaP256, EcdsaP384 }

/// field_size, prim/src/ecdsa.rs :352-357.
pub open spec fn prim_field_size(c: PCurve) -> usize {
    match c {
        PCurve::EcdsaP256 => 33,
        PCurve::EcdsaP384 => 49,
    }
}

/// The curve size in bits, from the names P-256 and P-384.
pub open spec fn curve_bits(c: PCurve) -> int {
    match c {
        PCurve::EcdsaP256 => 256,
        PCurve::EcdsaP384 => 384,
    }
}

/// H_CURVE_MAP: default_cmm.rs :123-128, suites.rs :104-111.
pub open spec fn curve_of(a: CAsym) -> PCurve {
    match a {
        CAsym::EcdsaP256 => PCurve::EcdsaP256,
        CAsym::EcdsaP384 => PCurve::EcdsaP384,
    }
}

/// The doc comment of `field_size`: "1 + ceil(bits / 8), i.e. one X9.62 tag byte plus a single
/// field element".
proof fn lemma_field_size_formula(c: PCurve)
    ensures
        prim_field_size(c) as int == 1 + (curve_bits(c) + 7) / 8,
{
    match c {
        PCurve::EcdsaP256 => {},
        PCurve::EcdsaP384 => {},
    }
}

/// R5: the key length of every suite is 16, 24 or 32, esdk `get_alg_suite` maps it to a prim
/// `AesGcm`, and that `AesGcm` has the same key length. It also equals the spec key bits / 8.
proof fn theorem_key_length_agrees(s: Suite)
    ensures
        code_row(s).key_len == 16 || code_row(s).key_len == 24 || code_row(s).key_len == 32,
        get_alg_suite(code_row(s).key_len) is Some,
        prim_key_length(get_alg_suite(code_row(s).key_len)->Some_0) == code_row(s).key_len,
        code_row(s).key_len as int * 8 == spec_row(s).key_bits,
{
    theorem_table_refines_spec(s);
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

/// R5: `verification_key_length()` is None for a non-signing suite, and for a signing suite it is
/// `prim::field_size` of the matching curve, which is 1 + ceil(bits / 8) with the bits of the
/// spec signature algorithm (P-256 or P-384).
proof fn theorem_vk_length_agrees(s: Suite)
    ensures
        c_vk_len(code_row(s)) is None <==> !c_has_asym(code_row(s)),
        code_row(s).asym is Some ==> c_vk_len(code_row(s)) == Some(prim_field_size(curve_of(code_row(s).asym->Some_0))),
        code_row(s).asym is Some ==> c_vk_len(code_row(s)).unwrap() as int
            == 1 + (curve_bits(curve_of(code_row(s).asym->Some_0)) + 7) / 8,
        spec_row(s).asym == Some(SSig::EcdsaP256Sha256) ==> c_vk_len(code_row(s)) == Some(33usize),
        spec_row(s).asym == Some(SSig::EcdsaP384Sha384) ==> c_vk_len(code_row(s)) == Some(49usize),
{
    theorem_table_refines_spec(s);
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

// ============================================================
// SECTION 9: R6, the summary theorem
// ============================================================

/// R6: for an arbitrary suite, every property above. This is the statement C05 asks for: the
/// table equals the spec row, the id is unique and never 00 00, and the lengths agree with the
/// prim constants. Relative to the model and to section 4 of the header.
proof fn theorem_c05_summary(s: Suite)
    ensures
        row_refines(code_row(s), spec_row(s)),
        from_id_bytes(id_of(s)) == Some(s),
        id_of(s) != (0u8, 0u8),
        forall|t: Suite| id_of(t) == id_of(s) ==> t == s,
        c_key_commitment(code_row(s)) <==> (code_row(s).fmt == 0x02 && code_row(s).data_len == 32),
        !c_has_sym(code_row(s)),
        get_alg_suite(code_row(s).key_len) is Some,
        prim_key_length(get_alg_suite(code_row(s).key_len)->Some_0) == code_row(s).key_len,
        code_row(s).asym is Some ==> c_vk_len(code_row(s)) == Some(prim_field_size(curve_of(code_row(s).asym->Some_0))),
{
    theorem_table_refines_spec(s);
    theorem_from_id_bytes_inverse(s);
    theorem_ids_never_reserved(s);
    assert forall|t: Suite| id_of(t) == id_of(s) implies t == s by {
        theorem_ids_injective(t, s);
    }
    theorem_commitment_consistent(s);
    theorem_no_symmetric_signing(s);
    theorem_key_length_agrees(s);
    theorem_vk_length_agrees(s);
}

} // verus!
fn main() {}
