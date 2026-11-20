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
