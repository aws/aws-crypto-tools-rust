// =============================================================================
// VR-2026-C04 (capability 1a): the plaintext data key (PDK) length invariant.
//   `check_data_key_length` (mpl/src/structures/algorithm_suite.rs :547) and every path that builds
//   or accepts a plaintext data key in mpl/.
//
// Run:  ~/verus/verus verus-proofs/c04_pdk_length_invariant.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model. The shipped code is native Rust, is not
// inside `verus!`, and is not compiled by Verus. Nothing here detects a later edit to mpl/. The
// link between model and code is the correspondence table in section 2, the path list in
// section 3 and the hypotheses in section 4, all reviewed by a human, plus a script that compares
// the copied constants and the code sites with the sources (c04-copy-check.py, a script check,
// not a proof).
//
// WHAT THE MODEL IS. A PDK is modeled by its length only (`Pdk { len }`). The contents are never
// read by any check in the code, so they are left out. Materials are modeled by the two fields
// that matter, the algorithm suite and the optional PDK (`Mat { suite, pdk }`). The suite table is
// the key-length field of the C05 table. The model has one function per code path that builds or
// accepts a PDK (section 3), and a closure theorem over sequences of those paths.
//
// STATUS: PROVED (model level), relative to the hypotheses and assumptions in section 4:
//     `verification results:: 24 verified, 0 errors`   (log: .agents/tasks/mpl-four-proofs/c04-run.txt)
// Nothing is left failing on purpose. BUG-02 is fixed on this code, the four entry points check
// the length, and no gap was found, so NO EXPECTED_FAIL obligation is written and none was
// invented. The pre-fix code (BUG-02, C04-F1 and C04-F2) is not modeled.
//
// COPIED FROM C05. The suite table (section 1 below, from `pub enum Suite` to the end of
// `code_row`, 112 lines) is a byte-for-byte copy by hand of the same block in
//     verus-proofs/c05_algorithm_suite_table.rs
// as it was when C04 was written: 1153 lines, md5 98209a4dca774c1c6227ea394897afdc,
// `verification results:: 22 verified, 0 errors`, untracked file on branch MPL-Verus, HEAD
// ad3522b. The copy is not an import: a Verus proof file is standalone. C05 copied the block by
// hand from mpl/src/structures/algorithm_suite.rs :144-305. So the table here is a copy of a
// copy. The script `.agents/tasks/mpl-four-proofs/c04-copy-check.py` checks that the block is
// identical to the C05 block and that the 11 key lengths equal the Rust source. Verus does not
// see either file. C04 uses only the `key_len` field of the table. The other fields are kept
// unchanged so that the block stays a verbatim copy.
//
// WHAT IS PROVED (relative to the model and to section 4)
//   P1  theorem_check_exact,             `check_data_key_length(s, k)` is Ok exactly when
//       theorem_check_exact_exec_agrees  `k.len == encryption_key_length(s)`; the exec form of the
//                                        check agrees with it (`check_data_key_length_exec`)
//   P2  theorem_add_data_key_exact,      the four paths that accept a caller-supplied PDK
//       theorem_build_exact              (enc/dec `add_data_key`, enc/dec `build`) return Ok exactly
//                                        when the other preconditions hold and the length is the
//                                        suite's; then the stored PDK is the one passed in. Any
//                                        other length, including 0, gives Err
//   P3  lemma_gen_pdk, lemma_raw_dec,    the producers build a PDK of the suite length: the random
//       lemma_hier_dec,                  generators (both keyrings, exec form `generate_exec`), the
//       theorem_producers_exact          raw-AES decrypt path and the hierarchical decrypt path return
//                                        Ok only with a PDK of the suite length, for any length the
//                                        decrypt step yields
//   P4  theorem_c04_closure,             for any builder state, any `other_ok`, and any finite
//                                        sequence of the modeled paths (any lengths, any order),
//                                        every materials value that is Ok has `pdk_ok`: a present
//                                        PDK has the length of the suite of the same materials, and
//                                        the suite never changes. `lemma_step_dispatch` checks that
//                                        `step` sends each `Step` to its path function (a definition
//                                        check, there to catch an edit of `step`)
//   P5  theorem_pdk_matches_spec_bits    a present PDK has `len * 8` equal to the spec "Encryption Key
//                                        Length (bits)" and to the spec "Key Derivation Input Length
//                                        (bits)" of the suite, and the length is 16, 24 or 32
//   P6  lemma_witnesses, lemma_decrypt_succeeds_on_right_length, lemma_run_witness
//                                        non-vacuity: for every suite a right-length key is
//                                        accepted and a key one byte shorter or longer, or empty,
//                                        is rejected; the type alone allows a wrong-length PDK; the
//                                        decrypt paths can succeed; a PDK is reachable
//   P7  theorem_c04_summary              the conjunction of the above for arbitrary inputs
//
// WHAT IS NOT PROVED (read this too)
//   * That the shipped code has any of these properties. The code is not inside `verus!`
//     (H_MODEL_MATCH). A later edit to mpl/ is not detected.
//   * That the model's list of paths is complete. That is H_CLOSED, code reading, with grep and
//     script support. A new constructor or a new `&mut` access to the PDK field would break it.
//   * P1 and P2 mirror the code line by line. They show that the model's check is an equality test
//     and that the four entry points call it. The check is one `!=` on two `usize` values. The
//     value of the file is in P4 (every path, any order) and in the path list of section 3, not in P1.
//   * That the PDK is random, secret, zeroized, or the right bytes. Only the length is modeled.
//   * That the spec is right. The spec columns are hand copies (A_SPEC_COLS_COPY). "Fit the
//     specification" in structures.md is read as "has the key length" (A_FIT).
//   * Anything about the ESDK consumers of the PDK (esdk/src/key_derivation.rs :79, :179), the
//     KMS, the key store, the cache, `branch_key_wrap::unwrap`, AES-GCM, or the RNG. The length
//     that a decrypt step returns is treated as an arbitrary `usize`.
//   * The wrapping side: whether the keyring wraps the right PDK, and `materials_checks`
//     transitions. They never build a PDK.
//   * That any threat is mitigated. This file maps to no TM-MPL threat. TM-MPL-006 and
//     TM-MPL-023 (completeness audit, BUG-02) are the nearest. A passing model proof is a
//     regression guard for the model, not a defense.
//   * Duplicate coverage: the existing direct tests (mpl/tests/test_encryption_materials.rs :429,
//     :456; test_decryption_materials.rs :401, :413) already cover the four entry points with one
//     wrong length. The model adds the cross-path closure and the path list.
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD ad3522b)
// =============================================================================
//   mpl/src/structures/algorithm_suite.rs
//     :378-380   AlgorithmSuite::encryption_key_length() = the `encryption_key_length` field
//     :504-544   PlaintextDataKey(Vec<u8>): derive Clone, Zeroize, ZeroizeOnDrop; From<Vec<u8>> :508;
//                new :517; as_bytes :523; len :529; no `&mut` method, no `DerefMut`
//     :547-562   check_data_key_length(suite, key): Err(InvalidMaterials) iff key.len() != expected
//     :144-305   the suite table (C05)
//   mpl/src/structures/encryption_materials.rs
//     :19-29     struct EncryptionMaterials (private fields, #[non_exhaustive])
//     :48-64     add_data_key: Err if a PDK exists; check :60; store :61
//     :71-83     add_encrypted_data_key: Err if no PDK; does not touch the PDK
//     :159-168   EncryptionMaterialsBuilder (derive Default; the only Default)
//     :281-292   builder setters `plaintext_data_key`, `set_plaintext_data_key`: store, no check
//     :358-436   build: suite required :359; check :364-367; other checks :369-420; literal :427-435
//   mpl/src/structures/decryption_materials.rs
//     :18-27     struct DecryptionMaterials
//     :45-59     add_data_key: Err if a PDK exists; check :56; store :57
//     :128-136   DecryptionMaterialsBuilder
//     :220-231   builder setters
//     :295-357   build: suite required :296; check :302-305; other checks :307-345; literal :349-356
//   mpl/src/keyring/raw_aes_keyring.rs
//     :399-420   on_encrypt: PDK present -> add_encrypted_data_key :411; absent -> generate :414,
//                add_data_key :416
//     :422-530   on_decrypt: PDK present -> Err :427; per EDK: length test :489 (continue on
//                mismatch); `add_data_key(PlaintextDataKey::new(..))?` :497, returns
//     :535-545   generate_random_data_key: `vec![0u8; suite.encryption_key_length()]` :536,
//                `generate_random_bytes(&mut bytes)` :537
//   mpl/src/aws_kms/hierarchical_keyring.rs
//     :654-732   on_encrypt: `pdk.clone()` or generate :660-663; add_data_key :727 if generated,
//                else add_encrypted_data_key :729
//     :734-802   on_decrypt: PDK present -> Err :739; per EDK `try_decrypt_edk` Ok -> add_data_key
//                :767 (`?`, returns); Err -> collect
//     :975-985   generate_random_data_key: `vec![0u8; ..]` :976, fill :977
//   prim/src/lib.rs :128   generate_random_bytes(bytes: &mut [u8]) (a slice: its length cannot change)
//   mpl/src/cmm/default_cmm.rs :158, :235   build empty materials (no PDK)
//   mpl/src/keyring/fluent_builders.rs :82, :163; cmm/fluent_builders.rs :171, :319
//                transition and completeness checks (never build or check a PDK length)
//   mpl/src/structures/materials_checks.rs   presence checks only
//   mpl/test-server/src/handlers.rs :548, :568   test server, uses the public setters and build
//   esdk/src/key_derivation.rs :79, :179   downstream re-check in the ESDK (not modeled)
//   spec/framework (file headers carry their own version numbers):
//     keyring-interface.md :147-148   "The length of the output plaintext data key MUST be equal to
//                                      the KDF input length of the algorithm suite"
//     algorithm-suites.md :95         "the algorithm suite's encryption key length MUST equal the
//                                      algorithm suite's key derivation input length"
//     algorithm-suites.md :423        "The length of the input encryption key MUST equal the
//                                      encryption key length specified by the algorithm suite"
//     structures.md :227-229          encryption materials PDK MUST fit the key derivation algorithm
//     structures.md :323-325          decryption materials PDK MUST fit the encryption algorithm
//     algorithm-suites.md :214-237, :239-262   the two table columns copied here
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code)
// =============================================================================
//   model                          shipped code
//   -----------------------------  ---------------------------------------------------------
//   Suite, CRow, code_row          EsdkAlgorithmSuiteId, AlgorithmSuite, specification() (copied from C05)
//   encryption_key_length(s)       AlgorithmSuite::encryption_key_length, algorithm_suite.rs :378
//   Pdk { len }                    PlaintextDataKey(Vec<u8>), len :529 (contents not modeled)
//   Mat { suite, pdk }             EncryptionMaterials / DecryptionMaterials (suite, plaintext_data_key)
//   Bld { suite, pdk }             EncryptionMaterialsBuilder / DecryptionMaterialsBuilder
//   check_data_key_length          check_data_key_length, algorithm_suite.rs :547-562
//   enc_add_data_key               EncryptionMaterials::add_data_key, :48-64
//   dec_add_data_key               DecryptionMaterials::add_data_key, :45-59
//   enc_add_edk                    EncryptionMaterials::add_encrypted_data_key, :71-83
//   enc_build, dec_build           the two `build` fns, :358-436 and :295-357
//   other_ok                       every other check of `build` (A_OTHER_OK)
//   gen_pdk, generate_exec         generate_random_data_key (both keyrings), raw :535, hier :975
//   raw_enc, hier_enc              raw_aes_keyring on_encrypt :399-420; hierarchical on_encrypt :654-732
//   raw_dec(m, ns)                 raw_aes_keyring on_decrypt :422-530; `ns` is the plaintext length
//                                  of each EDK that reached the length test :489
//   hier_dec(m, rs)                hierarchical on_decrypt :734-802; `rs[i]` is `Some(n)` when
//                                  `try_decrypt_edk` returned n bytes, `None` when it failed
//   CloneMat                       derive(Clone) on the materials and on PlaintextDataKey, and `pdk.clone()` :661
//   Step, run                      any sequence of the above, in any order, on one materials value
//   pdk_ok                         the invariant of the C04 property
//   spec_key_bits, spec_kdf_in_bits  the spec columns (A_SPEC_COLS_COPY)
//
// =============================================================================
// 3. PATHS THAT BUILD OR ACCEPT A PDK IN mpl/ (found by grep, then read), and what the model covers
// =============================================================================
// Search used: grep -rn "PlaintextDataKey\|plaintext_data_key\|add_data_key\|check_data_key_length"
// over mpl/src, esdk/src, prim/src, mpl/tests, mpl/test-server, esdk/tests. Struct literals of the
// two materials types appear only at encryption_materials.rs :427 and decryption_materials.rs :349.
//
// PATHS THAT ACCEPT A PDK INTO MATERIALS (the PDK field is written only here)
//   A1  EncryptionMaterials::add_data_key, :48-64, check :60                COVERED  (enc_add_data_key)
//   A2  DecryptionMaterials::add_data_key, :45-59, check :56                COVERED  (dec_add_data_key)
//   A3  EncryptionMaterialsBuilder::build, :358-436, check :364-367         COVERED  (enc_build)
//   A4  DecryptionMaterialsBuilder::build, :295-357, check :302-305         COVERED  (dec_build)
//   A5  builder setters (4 fns), store without check                         COVERED  (any `Bld`; the value
//       is only checked at build, A3 and A4)
//   A6  derive(Clone) of the materials                                       COVERED  (CloneMat)
//   A7  add_encrypted_data_key (enc), does not touch the PDK                COVERED  (enc_add_edk)
// PATHS THAT BUILD A PlaintextDataKey VALUE
//   B1  raw_aes_keyring generate_random_data_key, :535-545                  COVERED  (gen_pdk, generate_exec)
//   B2  hierarchical generate_random_data_key, :975-985                     COVERED  (same)
//   B3  raw_aes_keyring on_decrypt, `PlaintextDataKey::new` :497            COVERED  (raw_dec, any length)
//   B4  hierarchical on_decrypt, `PlaintextDataKey::new` :767               COVERED  (hier_dec, any length)
//   B5  public `PlaintextDataKey::new` :517 and `From<Vec<u8>>` :508, for   COVERED  (any `Pdk.len`; the type
//       any caller (user keyrings, tests, test server, esdk tests)                    does not enforce the length)
//   B6  derive(Clone) of PlaintextDataKey, `pdk.clone()` :661               COVERED  (same length)
// CALLERS THAT DO NOT BUILD OR CHECK A PDK
//   C1  default_cmm.rs :158, :235: build materials with no PDK              NOT MODELED (no PDK; pdk = None is
//                                                                           a `Bld` the theorems cover)
//   C2  keyring and cmm fluent_builders transition and completeness checks   NOT MODELED (presence checks only)
//   C3  esdk/src/key_derivation.rs :79 (identity KDF) and :179 (V2)          NOT MODELED (reads a PDK, re-checks
//                                                                           its length; a second check)
//   C4  branch_key_wrap::unwrap, AES-GCM, KMS, key store, cache             NOT MODELED (only the returned
//                                                                           length matters; arbitrary in B3, B4)
//   C5  the `zeroize` crate behavior of `Zeroize` / `ZeroizeOnDrop` on a Vec NOT EXAMINED. The materials give out
//                                                                           only `&PlaintextDataKey` (H_NO_MUT)
// So every path that WRITES the PDK field of a materials value (A1-A4) and every path that CREATES
// PDK bytes in mpl/ (B1-B6) is in the model. What the model does not cover is how the length of the
// decrypted bytes arises (C4) and what happens after the PDK leaves the materials (C3, C5).
//
// =============================================================================
// 4. HYPOTHESES, ASSUMPTIONS AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and the items below
//    ASSUMED       taken as a premise, a definition, an interpretation or a hand copy (A_*)
//    CODE READING  a claim about shipped code that Verus does not see (H_*); checked by a human
//                  reading the source at the lines named, with grep or the copy-check script as
//                  support where stated (a script check is not a proof)
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier..]`
//  attribute is written in this file, and there is no uninterpreted spec function. The model is
//  executable spec code plus three small exec functions (`encryption_key_length_exec`,
//  `check_data_key_length_exec`, `generate_exec`).
//
//  CONSTANTS COPIED BY HAND (each is ASSUMED to equal its source)
//  A_TABLE_COPY (ASSUMED, copied by hand, a copy of a copy). The block from `pub enum Suite` to the
//    end of `code_row` is copied verbatim from C05, which copied it from algorithm_suite.rs
//    :144-305. Script check: identical to the C05 block, and the 11 `key_len` values equal the
//    Rust source (c04-copy-check.txt). Only `key_len` is used.
//  A_SPEC_COLS_COPY (ASSUMED, copied by hand). `spec_key_bits` and `spec_kdf_in_bits` are typed in
//    from the two spec tables named in section 1 (algorithm-suites.md :214-237 and :239-262), one
//    value per ESDK suite. Script check: equal to the spec file.
//
//  OTHER ASSUMPTIONS
//  A_FIT (ASSUMED, an interpretation). structures.md says the PDK "MUST fit the specification for
//    the key derivation algorithm" (encryption materials, :227) and "fit the specification for the
//    encryption algorithm" (decryption materials, :323). This file reads both as "has the suite's
//    key length". The code uses `encryption_key_length` for both, and for the 11 suites the spec
//    KDF input length equals the key length (proved here for the two copied columns).
//  A_OTHER_OK (ASSUMED, modeling choice). `build` has other checks after the PDK check (required
//    encryption context keys, encrypted data keys without a PDK, signing key, verification key,
//    symmetric keys). Each can only return Err. None reads the PDK length or writes the PDK. The
//    model replaces all of them by one boolean `other_ok`, true or false. This is sound only if
//    no such check can turn an Err into an Ok or change the stored PDK (H_BUILD_OTHER).
//  A_ERR (ASSUMED, modeling choice). Error kinds are abstract (`MErr`). Only Ok against Err is
//    claimed. Which error kind the code returns is not modeled.
//  A_LEN (ASSUMED). A PDK length is a `usize`. `Vec::len` is at most isize::MAX, so every length
//    the code can produce is a `usize` in the model. The model allows more (any `usize`), which
//    is a superset.
//  A_VSTD (ASSUMED). The trusted base is Verus, Z3 and the vstd specifications of `Vec` and
//    `vec![x; n]` used by `generate_exec`.
//
//  CODE READING (H_*)
//  H_MODEL_MATCH (CODE READING). Each model function has the logic of the code path named in
//    section 2. Checked by reading; the check sites are also grepped by c04-copy-check.py.
//  H_CLOSED (CODE READING, grep support). The only writes to the `plaintext_data_key` field of a
//    materials value are `encryption_materials.rs :61, :432` and `decryption_materials.rs :57,
//    :353`. The fields are private to those modules and the structs are `#[non_exhaustive]`, so no
//    other code in the crate or outside it can write them. `EncryptionMaterials` and
//    `DecryptionMaterials` have no `Default`, no serde derive and no `&mut self` method. The only
//    `Default` derives are on the two builders. There is no `unsafe` in mpl/src (grep).
//    A new constructor or method would break this.
//  H_NO_MUT (CODE READING). `plaintext_data_key()` returns `Option<&PlaintextDataKey>`.
//    `PlaintextDataKey` has the field private to algorithm_suite.rs, `&self` methods `as_bytes`,
//    `len`, `is_empty`, `ct_eq`, no interior mutability and no `DerefMut`. So a holder of the
//    materials cannot change the length of the PDK inside them.
//  H_SUITE_FIXED (CODE READING). No method changes `algorithm_suite_id` after `build`: the only
//    writes are the builder setters (encryption_materials.rs :175, :183; decryption_materials.rs
//    :143, :151). `algorithm_suite()` returns `algorithm_suite_id.specification()`, so the check in
//    `add_data_key` uses the suite stored in the same value (:60, :56).
//  H_BUILD_SAME_SUITE (CODE READING). In both `build` fns the suite that is checked
//    (`algorithm_suite_id.specification()` :365, :303) is the `algorithm_suite_id` stored in the
//    literal (:428, :350).
//  H_BUILD_OTHER (CODE READING). The checks after :367 (enc) and :305 (dec) only `return Err`; the
//    literal at the end copies `self.plaintext_data_key` unchanged (:432, :353).
//  H_ENC_DEC_SAME (CODE READING). For this property the two materials types differ only in fields
//    the model ignores (encrypted data keys, signing keys, verification key). One `Mat` type
//    serves both. The model also lets a step sequence mix the encrypt and decrypt functions on one
//    value, which the types forbid. That is a superset of the real behavior.
//  H_GEN_SUITE (CODE READING). Both keyrings call `generate_random_data_key` with
//    `materials.algorithm_suite()` (raw_aes_keyring.rs :414; hierarchical_keyring.rs :662), the
//    suite of the materials that then receive the key.
//  H_FILL_SLICE (CODE READING). `generate_random_bytes(bytes: &mut [u8])` (prim/src/lib.rs :128)
//    takes a slice. A slice cannot change its length, so the buffer is still
//    `encryption_key_length` bytes after the fill (Rust typing). The values the RNG writes are
//    not modeled. An RNG error returns Err through `map_err(..)?` (:537-543, :977-983) before
//    `PlaintextDataKey::new`, so no PDK is built (model: `generate_exec` has no Err arm because
//    the PDK is only built after the fill; see A_RNG_FAIL).
//  A_RNG_FAIL (ASSUMED, modeling choice). The generators are modeled for the success case only.
//    On RNG failure the code returns Err before building a PDK, so no PDK exists to check.
//  H_VEC_LEN (CODE READING, std). `vec![0u8; n]` has length n. Verus checks this in `generate_exec`
//    through the vstd specification (A_VSTD).
//  H_RAW_DEC_LOOP (CODE READING). In raw-AES `on_decrypt` the materials are not changed until the
//    `add_data_key(..)?` at :497, which returns whatever it yields. An EDK that fails the filter,
//    the tag-size test, AES-GCM or the length test :489 is skipped (`continue`). So the outcome is
//    a function of the sequence of lengths of the EDKs that reached :489, which is `raw_dec`.
//  H_HIER_DEC_LOOP (CODE READING). In hierarchical `on_decrypt` an EDK that is filtered out or
//    whose `try_decrypt_edk` fails is skipped; the first `Ok(bytes)` is passed to
//    `add_data_key(..)?` at :767 and the function returns. That is `hier_dec`. The length of
//    `bytes` is whatever `branch_key_wrap::unwrap` returns; the model takes it as arbitrary.
//  H_NO_OTHER_PRODUCER (CODE READING). No other file in mpl/src calls `PlaintextDataKey::new` or
//    `From<Vec<u8>>` (grep: algorithm_suite.rs, raw_aes_keyring.rs :497 :544,
//    hierarchical_keyring.rs :767 :984 only). `esdk/src` has none. The esdk tests, mpl tests and the
//    test server use the public API (A5, B5).
//  H_TABLE_ONLY (CODE READING, from C05). Every `AlgorithmSuite` value comes from the table, so
//    `encryption_key_length()` is the table field.
//
// =============================================================================
// 5. HOW THE PROOF IS BUILT
// =============================================================================
// Section 3 (of the file) defines the model. Section 4 proves, for each path, a local lemma: the path returns
// Ok only with a PDK of the suite length and does not change the suite. `lemma_step_preserves`
// is the induction step over one `Step`. `lemma_run_preserves` is induction on the length of the
// step sequence. `raw_dec` and `hier_dec` are recursive specs over the list of EDKs; their
// lemmas are inductions on the list. The base case of the closure is `enc_build` or `dec_build`
// from any builder state. Section 4 also states the exact accept conditions (P1, P2). Section 5
// checks the three exec functions against the spec functions. Section 6 gives the non-vacuity
// witnesses. Section 7 is the summary theorem.
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: The suite table, COPIED from C05 (verus-proofs/c05_algorithm_suite_table.rs, A_TABLE_COPY)
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

/// AlgorithmSuite::encryption_key_length, algorithm_suite.rs :378-380: the table field.
pub open spec fn encryption_key_length(s: Suite) -> usize {
    code_row(s).key_len
}

// ============================================================
// SECTION 2: Two columns of the spec table (A_SPEC_COLS_COPY)
// ============================================================

/// A_SPEC_COLS_COPY: spec "Encryption Key Length (bits)", algorithm-suites.md :239-262, per ESDK suite.
pub open spec fn spec_key_bits(s: Suite) -> int {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => 128,
        Suite::AlgAes192GcmIv12Tag16NoKdf => 192,
        Suite::AlgAes256GcmIv12Tag16NoKdf => 256,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 128,
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => 192,
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => 256,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => 128,
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 192,
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 256,
        Suite::AlgAes256GcmHkdfSha512CommitKey => 256,
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 256,
    }
}

/// A_SPEC_COLS_COPY: spec "Key Derivation Input Length (bits)", algorithm-suites.md :214-237, per ESDK suite.
pub open spec fn spec_kdf_in_bits(s: Suite) -> int {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => 128,
        Suite::AlgAes192GcmIv12Tag16NoKdf => 192,
        Suite::AlgAes256GcmIv12Tag16NoKdf => 256,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 128,
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => 192,
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => 256,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => 128,
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 192,
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 256,
        Suite::AlgAes256GcmHkdfSha512CommitKey => 256,
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 256,
    }
}

/// The key length of every suite is 16, 24 or 32 bytes, and equals both spec columns divided by 8
/// (the C05 key-length fact, restated for the one column C04 uses).
proof fn lemma_key_len_table(s: Suite)
    ensures
        encryption_key_length(s) == 16 || encryption_key_length(s) == 24 || encryption_key_length(s) == 32,
        encryption_key_length(s) as int * 8 == spec_key_bits(s),
        encryption_key_length(s) as int * 8 == spec_kdf_in_bits(s),
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
// SECTION 3: The model of materials, the check, and every path (section 3 of the header)
// ============================================================

/// PlaintextDataKey(Vec<u8>), modeled by its length (algorithm_suite.rs :506, `len` :529).
pub struct Pdk {
    pub len: usize,
}

/// EncryptionMaterials / DecryptionMaterials, the two fields that matter (H_ENC_DEC_SAME).
pub struct Mat {
    pub suite: Suite,
    pub pdk: Option<Pdk>,
}

/// EncryptionMaterialsBuilder / DecryptionMaterialsBuilder state. Any value is a legal builder
/// state: the setters store without a check (A5).
pub struct Bld {
    pub suite: Option<Suite>,
    pub pdk: Option<Pdk>,
}

/// Error kinds, abstract (A_ERR).
pub enum MErr {
    InvalidMaterials,
    Validation,
    Cryptographic,
    NoMatchingDataKey,
    Other,
}

/// The C04 invariant: a present PDK has the encryption key length of the suite of the same
/// materials. An absent PDK satisfies it.
pub open spec fn pdk_ok(m: Mat) -> bool {
    match m.pdk {
        Some(k) => k.len == encryption_key_length(m.suite),
        None => true,
    }
}

/// check_data_key_length, algorithm_suite.rs :547-562.
pub open spec fn check_data_key_length(s: Suite, k: Pdk) -> Result<(), MErr> {
    if k.len != encryption_key_length(s) {
        Err(MErr::InvalidMaterials)
    } else {
        Ok(())
    }
}

/// EncryptionMaterials::add_data_key, encryption_materials.rs :48-64.
pub open spec fn enc_add_data_key(m: Mat, k: Pdk) -> Result<Mat, MErr> {
    if m.pdk is Some {
        Err(MErr::InvalidMaterials)
    } else {
        match check_data_key_length(m.suite, k) {
            Err(e) => Err(e),
            Ok(_) => Ok(Mat { suite: m.suite, pdk: Some(k) }),
        }
    }
}

/// DecryptionMaterials::add_data_key, decryption_materials.rs :45-59.
pub open spec fn dec_add_data_key(m: Mat, k: Pdk) -> Result<Mat, MErr> {
    if m.pdk is Some {
        Err(MErr::InvalidMaterials)
    } else {
        match check_data_key_length(m.suite, k) {
            Err(e) => Err(e),
            Ok(_) => Ok(Mat { suite: m.suite, pdk: Some(k) }),
        }
    }
}

/// EncryptionMaterials::add_encrypted_data_key, encryption_materials.rs :71-83. The list of
/// encrypted data keys is not modeled. The suite and the PDK are unchanged.
pub open spec fn enc_add_edk(m: Mat) -> Result<Mat, MErr> {
    if m.pdk is None {
        Err(MErr::InvalidMaterials)
    } else {
        Ok(m)
    }
}

/// EncryptionMaterialsBuilder::build, encryption_materials.rs :358-436. `other_ok` is every other
/// check of `build` (A_OTHER_OK, H_BUILD_OTHER). The checked suite is the stored suite (H_BUILD_SAME_SUITE).
pub open spec fn enc_build(b: Bld, other_ok: bool) -> Result<Mat, MErr> {
    match b.suite {
        None => Err(MErr::Validation),
        Some(sid) => {
            let pdk_check: Result<(), MErr> = match b.pdk {
                Some(k) => check_data_key_length(sid, k),
                None => Ok(()),
            };
            match pdk_check {
                Err(e) => Err(e),
                Ok(_) => {
                    if other_ok {
                        Ok(Mat { suite: sid, pdk: b.pdk })
                    } else {
                        Err(MErr::Other)
                    }
                },
            }
        },
    }
}

/// DecryptionMaterialsBuilder::build, decryption_materials.rs :295-357.
pub open spec fn dec_build(b: Bld, other_ok: bool) -> Result<Mat, MErr> {
    match b.suite {
        None => Err(MErr::Validation),
        Some(sid) => {
            let pdk_check: Result<(), MErr> = match b.pdk {
                Some(k) => check_data_key_length(sid, k),
                None => Ok(()),
            };
            match pdk_check {
                Err(e) => Err(e),
                Ok(_) => {
                    if other_ok {
                        Ok(Mat { suite: sid, pdk: b.pdk })
                    } else {
                        Err(MErr::Other)
                    }
                },
            }
        },
    }
}

/// The PDK a keyring generates for `s`: `vec![0u8; suite.encryption_key_length()]`, then a fill
/// that cannot change the length (H_VEC_LEN, H_FILL_SLICE). Both keyrings (B1, B2).
pub open spec fn gen_pdk(s: Suite) -> Pdk {
    Pdk { len: encryption_key_length(s) }
}

/// raw_aes_keyring on_encrypt, :399-420.
pub open spec fn raw_enc(m: Mat) -> Result<Mat, MErr> {
    match m.pdk {
        Some(_) => enc_add_edk(m),
        None => enc_add_data_key(m, gen_pdk(m.suite)),
    }
}

/// hierarchical_keyring on_encrypt, :654-732: `pdk.clone()` when present, else a generated key;
/// `add_data_key` only for a generated key.
pub open spec fn hier_enc(m: Mat) -> Result<Mat, MErr> {
    let kg: (Pdk, bool) = match m.pdk {
        Some(p) => (p, false),
        None => (gen_pdk(m.suite), true),
    };
    if kg.1 {
        enc_add_data_key(m, kg.0)
    } else {
        enc_add_edk(m)
    }
}

/// raw_aes_keyring on_decrypt, :422-530. `ns[i]` is the plaintext length of the i-th EDK that
/// reached the length test at :489 (H_RAW_DEC_LOOP). The length is arbitrary.
pub open spec fn raw_dec(m: Mat, ns: Seq<usize>) -> Result<Mat, MErr>
    decreases ns.len(),
{
    if m.pdk is Some {
        Err(MErr::InvalidMaterials)
    } else if ns.len() == 0 {
        Err(MErr::Cryptographic)
    } else if ns[0] != encryption_key_length(m.suite) {
        raw_dec(m, ns.drop_first())
    } else {
        dec_add_data_key(m, Pdk { len: ns[0] })
    }
}

/// hierarchical_keyring on_decrypt, :734-802. `rs[i]` is `Some(n)` when `try_decrypt_edk` of the
/// i-th EDK returned n bytes, `None` when the EDK was filtered out or failed (H_HIER_DEC_LOOP).
/// There is no length test before `add_data_key`.
pub open spec fn hier_dec(m: Mat, rs: Seq<Option<usize>>) -> Result<Mat, MErr>
    decreases rs.len(),
{
    if m.pdk is Some {
        Err(MErr::InvalidMaterials)
    } else if rs.len() == 0 {
        Err(MErr::NoMatchingDataKey)
    } else {
        match rs[0] {
            Some(n) => dec_add_data_key(m, Pdk { len: n }),
            None => hier_dec(m, rs.drop_first()),
        }
    }
}

/// One operation on a materials value. Every operation that can write the PDK field or create PDK
/// bytes (section 3 of the header). `EncAdd`, `DecAdd`, `EncAddEdk` take any caller input.
pub enum Step {
    EncAdd(Pdk),
    EncAddEdk,
    DecAdd(Pdk),
    CloneMat,
    RawEnc,
    HierEnc,
    RawDec(Seq<usize>),
    HierDec(Seq<Option<usize>>),
}

pub open spec fn step(m: Mat, s: Step) -> Result<Mat, MErr> {
    match s {
        Step::EncAdd(k) => enc_add_data_key(m, k),
        Step::EncAddEdk => enc_add_edk(m),
        Step::DecAdd(k) => dec_add_data_key(m, k),
        Step::CloneMat => Ok(m),
        Step::RawEnc => raw_enc(m),
        Step::HierEnc => hier_enc(m),
        Step::RawDec(ns) => raw_dec(m, ns),
        Step::HierDec(rs) => hier_dec(m, rs),
    }
}

/// Apply the steps in order; stop at the first Err.
pub open spec fn run(m: Mat, steps: Seq<Step>) -> Result<Mat, MErr>
    decreases steps.len(),
{
    if steps.len() == 0 {
        Ok(m)
    } else {
        match step(m, steps[0]) {
            Err(e) => Err(e),
            Ok(m2) => run(m2, steps.drop_first()),
        }
    }
}

// ============================================================
// SECTION 4: Local lemmas for every path, then the closure
// ============================================================

/// P1: the check is Ok exactly when the length is the suite's.
proof fn theorem_check_exact(s: Suite, k: Pdk)
    ensures
        check_data_key_length(s, k) is Ok <==> k.len == encryption_key_length(s),
        check_data_key_length(s, k) is Err <==> k.len != encryption_key_length(s),
{
}

/// P2, add_data_key paths: Ok exactly when no PDK is present and the length is right; then the
/// stored PDK is the one passed and the suite is unchanged.
proof fn theorem_add_data_key_exact(m: Mat, k: Pdk)
    ensures
        (enc_add_data_key(m, k) is Ok) <==> (m.pdk is None && k.len == encryption_key_length(m.suite)),
        (dec_add_data_key(m, k) is Ok) <==> (m.pdk is None && k.len == encryption_key_length(m.suite)),
        enc_add_data_key(m, k) matches Ok(r) ==> r == (Mat { suite: m.suite, pdk: Some(k) }),
        dec_add_data_key(m, k) matches Ok(r) ==> r == (Mat { suite: m.suite, pdk: Some(k) }),
{
}

/// P2, build paths: Ok exactly when a suite is set, `other_ok` holds and the PDK, if any, has the
/// suite's length; then the materials carry exactly the builder's suite and PDK.
proof fn theorem_build_exact(b: Bld, other_ok: bool)
    ensures
        (enc_build(b, other_ok) is Ok) <==> (b.suite is Some && other_ok && (b.pdk matches Some(k) ==> k.len
            == encryption_key_length(b.suite->Some_0))),
        (dec_build(b, other_ok) is Ok) <==> (b.suite is Some && other_ok && (b.pdk matches Some(k) ==> k.len
            == encryption_key_length(b.suite->Some_0))),
        enc_build(b, other_ok) matches Ok(r) ==> r == (Mat { suite: b.suite->Some_0, pdk: b.pdk }),
        dec_build(b, other_ok) matches Ok(r) ==> r == (Mat { suite: b.suite->Some_0, pdk: b.pdk }),
        enc_build(b, other_ok) matches Ok(r) ==> pdk_ok(r),
        dec_build(b, other_ok) matches Ok(r) ==> pdk_ok(r),
{
}

/// P3, generators: the generated PDK passes the check and has the suite length. The spec requires
/// the length of a generated key to equal the KDF input length (keyring-interface.md :147).
proof fn lemma_gen_pdk(s: Suite)
    ensures
        gen_pdk(s).len == encryption_key_length(s),
        check_data_key_length(s, gen_pdk(s)) is Ok,
        gen_pdk(s).len as int * 8 == spec_kdf_in_bits(s),
{
    lemma_key_len_table(s);
}

/// P3, raw-AES decrypt: for any list of lengths, Ok only with a PDK of the suite length, and the
/// suite is unchanged. The result is Err when materials already hold a PDK.
proof fn lemma_raw_dec(m: Mat, ns: Seq<usize>)
    requires
        pdk_ok(m),
    ensures
        raw_dec(m, ns) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite && r.pdk is Some,
        m.pdk is Some ==> raw_dec(m, ns) is Err,
    decreases ns.len(),
{
    if m.pdk is None && ns.len() > 0 && ns[0] != encryption_key_length(m.suite) {
        lemma_raw_dec(m, ns.drop_first());
    }
}

/// P3, hierarchical decrypt: for any list of results, Ok only with a PDK of the suite length, and
/// the suite is unchanged. There is no length test before `add_data_key`; the check inside it is
/// the only gate.
proof fn lemma_hier_dec(m: Mat, rs: Seq<Option<usize>>)
    requires
        pdk_ok(m),
    ensures
        hier_dec(m, rs) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite && r.pdk is Some,
        m.pdk is Some ==> hier_dec(m, rs) is Err,
    decreases rs.len(),
{
    if m.pdk is None && rs.len() > 0 && rs[0] is None {
        lemma_hier_dec(m, rs.drop_first());
    }
}

/// Liveness witness for the decrypt paths: if no PDK is present and some EDK yields the right
/// length, `raw_dec` is Ok. Without it the safety lemma would hold for a function that always fails.
proof fn lemma_decrypt_succeeds_on_right_length(m: Mat, ns: Seq<usize>, i: int)
    requires
        m.pdk is None,
        0 <= i < ns.len(),
        ns[i] == encryption_key_length(m.suite),
    ensures
        raw_dec(m, ns) is Ok,
    decreases ns.len(),
{
    if ns[0] != encryption_key_length(m.suite) {
        assert(i >= 1);
        assert(ns.drop_first()[i - 1] == ns[i]);
        lemma_decrypt_succeeds_on_right_length(m, ns.drop_first(), i - 1);
    }
}

/// The inductive step: one path from a materials value with `pdk_ok` gives `pdk_ok` and the same
/// suite. P3 for the encrypt paths and the four accept paths.
proof fn lemma_step_preserves(m: Mat, s: Step)
    requires
        pdk_ok(m),
    ensures
        step(m, s) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite,
{
    match s {
        Step::EncAdd(_) => {},
        Step::EncAddEdk => {},
        Step::DecAdd(_) => {},
        Step::CloneMat => {},
        Step::RawEnc => {},
        Step::HierEnc => {},
        Step::RawDec(ns) => { lemma_raw_dec(m, ns); },
        Step::HierDec(rs) => { lemma_hier_dec(m, rs); },
    }
}

/// Transcription check: `step` dispatches each `Step` to the path function of the same name. This
/// is true by the definition of `step`. It is here so that an edit of `step` that drops or swaps a
/// path (and so removes it from the closure) is rejected.
proof fn lemma_step_dispatch(m: Mat)
    ensures
        forall|k: Pdk| #[trigger] step(m, Step::EncAdd(k)) == enc_add_data_key(m, k),
        forall|k: Pdk| #[trigger] step(m, Step::DecAdd(k)) == dec_add_data_key(m, k),
        step(m, Step::EncAddEdk) == enc_add_edk(m),
        step(m, Step::CloneMat) == Ok::<Mat, MErr>(m),
        step(m, Step::RawEnc) == raw_enc(m),
        step(m, Step::HierEnc) == hier_enc(m),
        forall|ns: Seq<usize>| #[trigger] step(m, Step::RawDec(ns)) == raw_dec(m, ns),
        forall|rs: Seq<Option<usize>>| #[trigger] step(m, Step::HierDec(rs)) == hier_dec(m, rs),
{
}

/// Induction over any sequence of paths.
proof fn lemma_run_preserves(m: Mat, steps: Seq<Step>)
    requires
        pdk_ok(m),
    ensures
        run(m, steps) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite,
    decreases steps.len(),
{
    if steps.len() > 0 {
        lemma_step_preserves(m, steps[0]);
        match step(m, steps[0]) {
            Ok(m2) => { lemma_run_preserves(m2, steps.drop_first()); },
            Err(_) => {},
        }
    }
}

/// P3 summary: the producer and encrypt paths, stated for every suite and materials value.
proof fn theorem_producers_exact(m: Mat)
    requires
        pdk_ok(m),
    ensures
        raw_enc(m) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some,
        hier_enc(m) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some,
        m.pdk is None ==> raw_enc(m) is Ok,
        m.pdk is None ==> hier_enc(m) is Ok,
        forall|ns: Seq<usize>| #[trigger] raw_dec(m, ns) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some,
        forall|rs: Seq<Option<usize>>| #[trigger] hier_dec(m, rs) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some,
{
    assert forall|ns: Seq<usize>| #[trigger] raw_dec(m, ns) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some by {
        lemma_raw_dec(m, ns);
    }
    assert forall|rs: Seq<Option<usize>>| #[trigger] hier_dec(m, rs) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some by {
        lemma_hier_dec(m, rs);
    }
    lemma_gen_pdk(m.suite);
}

/// P4: the closure. From any builder state (any suite, any PDK of any length, any `other_ok`),
/// build, then apply any finite sequence of the modeled paths. Every Ok value has `pdk_ok` and
/// the suite chosen at build. The only inputs the proof does not constrain are the lengths.
proof fn theorem_c04_closure(b: Bld, other_ok: bool, steps: Seq<Step>)
    ensures
        enc_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite
            && m.suite == b.suite->Some_0),
        dec_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite
            && m.suite == b.suite->Some_0),
{
    theorem_build_exact(b, other_ok);
    match enc_build(b, other_ok) {
        Ok(m) => { lemma_run_preserves(m, steps); },
        Err(_) => {},
    }
    match dec_build(b, other_ok) {
        Ok(m) => { lemma_run_preserves(m, steps); },
        Err(_) => {},
    }
}

/// P5: a present PDK of a materials value that satisfies the invariant has the length the spec
/// asks for, in bits, in both spec columns, and the length is 16, 24 or 32 bytes (A_FIT).
proof fn theorem_pdk_matches_spec_bits(m: Mat)
    requires
        pdk_ok(m),
    ensures
        m.pdk matches Some(k) ==> k.len as int * 8 == spec_key_bits(m.suite),
        m.pdk matches Some(k) ==> k.len as int * 8 == spec_kdf_in_bits(m.suite),
        m.pdk matches Some(k) ==> (k.len == 16 || k.len == 24 || k.len == 32),
{
    lemma_key_len_table(m.suite);
}

// ============================================================
// SECTION 5: Exec forms of the three small functions
// ============================================================

/// `encryption_key_length()`, executable form of the table lookup.
fn encryption_key_length_exec(s: Suite) -> (r: usize)
    ensures
        r == encryption_key_length(s),
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => 16,
        Suite::AlgAes192GcmIv12Tag16NoKdf => 24,
        Suite::AlgAes256GcmIv12Tag16NoKdf => 32,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 16,
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => 24,
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => 32,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => 16,
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 24,
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 32,
        Suite::AlgAes256GcmHkdfSha512CommitKey => 32,
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 32,
    }
}

/// `check_data_key_length`, algorithm_suite.rs :547-562: `expected_len = suite.encryption_key_length();
/// if key.len() != expected_len { return Err(..) } Ok(())`.
fn check_data_key_length_exec(s: Suite, key_len: usize) -> (r: Result<(), MErr>)
    ensures
        r == check_data_key_length(s, Pdk { len: key_len }),
{
    let expected_len = encryption_key_length_exec(s);
    if key_len != expected_len {
        Err(MErr::InvalidMaterials)
    } else {
        Ok(())
    }
}

/// `generate_random_data_key`, raw_aes_keyring.rs :535-545 and hierarchical_keyring.rs :975-985,
/// success case: allocate `vec![0u8; suite.encryption_key_length()]`, fill it (not modeled; the
/// fill takes `&mut [u8]` and cannot change the length, H_FILL_SLICE), wrap it.
fn generate_exec(s: Suite) -> (r: Pdk)
    ensures
        r == gen_pdk(s),
{
    let bytes: Vec<u8> = vec![0u8; encryption_key_length_exec(s)];
    Pdk { len: bytes.len() }
}

/// P1, exec side: the exec check agrees with the spec check for every input.
proof fn theorem_check_exact_exec_agrees(s: Suite, key_len: usize)
    ensures
        check_data_key_length(s, Pdk { len: key_len }) is Ok <==> key_len == encryption_key_length(s),
{
}

// ============================================================
// SECTION 6: Non-vacuity witnesses
// ============================================================

/// For every suite: the right length is accepted by the check and by both builders, one byte
/// shorter, one byte longer and empty are rejected, and the type alone allows a wrong-length PDK
/// (it is `pdk_ok` that excludes it). So the invariant is not trivially true.
proof fn lemma_witnesses(s: Suite)
    ensures
        check_data_key_length(s, Pdk { len: encryption_key_length(s) }) is Ok,
        check_data_key_length(s, Pdk { len: (encryption_key_length(s) + 1) as usize }) is Err,
        check_data_key_length(s, Pdk { len: (encryption_key_length(s) - 1) as usize }) is Err,
        check_data_key_length(s, Pdk { len: 0 }) is Err,
        enc_build(Bld { suite: Some(s), pdk: Some(Pdk { len: encryption_key_length(s) }) }, true) is Ok,
        dec_build(Bld { suite: Some(s), pdk: Some(Pdk { len: encryption_key_length(s) }) }, true) is Ok,
        enc_build(Bld { suite: Some(s), pdk: Some(Pdk { len: (encryption_key_length(s) + 1) as usize }) }, true) is Err,
        dec_build(Bld { suite: Some(s), pdk: Some(Pdk { len: (encryption_key_length(s) - 1) as usize }) }, true) is Err,
        enc_add_data_key(Mat { suite: s, pdk: None }, Pdk { len: encryption_key_length(s) }) is Ok,
        dec_add_data_key(Mat { suite: s, pdk: None }, Pdk { len: (encryption_key_length(s) + 1) as usize }) is Err,
        !pdk_ok(Mat { suite: s, pdk: Some(Pdk { len: (encryption_key_length(s) + 1) as usize }) }),
{
    lemma_key_len_table(s);
}

/// A materials value with a PDK is reachable: build with no PDK, then a generating keyring, then
/// a second `add_data_key` is rejected. Shows `pdk_ok` is checked on a non-empty set.
proof fn lemma_run_witness(s: Suite)
    ensures
        enc_build(Bld { suite: Some(s), pdk: None }, true) is Ok,
        run(Mat { suite: s, pdk: None }, seq![Step::RawEnc]) is Ok,
        run(Mat { suite: s, pdk: None }, seq![Step::RawEnc]) matches Ok(r) ==> (r.pdk is Some && pdk_ok(r)),
        run(Mat { suite: s, pdk: None }, seq![Step::RawEnc, Step::EncAdd(Pdk { len: encryption_key_length(s) })])
            is Err,
{
    let m0 = Mat { suite: s, pdk: None };
    let k = Pdk { len: encryption_key_length(s) };
    let m1 = Mat { suite: s, pdk: Some(k) };
    let one = seq![Step::RawEnc];
    let two = seq![Step::RawEnc, Step::EncAdd(k)];
    reveal_with_fuel(run, 3);
    assert(one[0] == Step::RawEnc);
    assert(two[0] == Step::RawEnc);
    assert(step(m0, Step::RawEnc) == Ok::<Mat, MErr>(m1));
    assert(one.drop_first() =~= Seq::<Step>::empty());
    assert(two.drop_first() =~= seq![Step::EncAdd(k)]);
    assert(seq![Step::EncAdd(k)].drop_first() =~= Seq::<Step>::empty());
    assert(raw_enc(m0) == Ok::<Mat, MErr>(m1));
    assert(run(m0, one) == Ok::<Mat, MErr>(m1));
    assert(seq![Step::EncAdd(k)][0] == Step::EncAdd(k));
    assert(run(m1, seq![Step::EncAdd(k)]) is Err);
    assert(run(m0, two) is Err);
}

// ============================================================
// SECTION 7: Summary theorem
// ============================================================

/// P7: for arbitrary inputs, the model of every accept and producer path keeps `pdk_ok`.
proof fn theorem_c04_summary(s: Suite, b: Bld, other_ok: bool, steps: Seq<Step>, k: Pdk)
    ensures
        check_data_key_length(s, k) is Ok <==> k.len == encryption_key_length(s),
        enc_add_data_key(Mat { suite: s, pdk: None }, k) matches Ok(r) ==> pdk_ok(r),
        dec_add_data_key(Mat { suite: s, pdk: None }, k) matches Ok(r) ==> pdk_ok(r),
        enc_build(b, other_ok) matches Ok(r) ==> pdk_ok(r),
        dec_build(b, other_ok) matches Ok(r) ==> pdk_ok(r),
        check_data_key_length(s, gen_pdk(s)) is Ok,
        enc_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r)),
        dec_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r)),
{
    theorem_build_exact(b, other_ok);
    lemma_gen_pdk(s);
    theorem_c04_closure(b, other_ok, steps);
}

} // verus!
fn main() {}
