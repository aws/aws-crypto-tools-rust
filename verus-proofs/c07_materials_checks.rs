// =============================================================================
// VR-2026-C07 (capability 1a/1b): the `materials_checks` transitions and the `send()` wiring
//   mpl/src/structures/materials_checks.rs (added in #167): `check_encryption_transition`,
//   `check_decryption_transition`, `check_*_materials_complete`; and the keyring and CMM
//   fluent `send()` bodies that call them.
//
// Run:  ~/verus/verus verus-proofs/c07_materials_checks.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model. The shipped code is native Rust, is not
// inside `verus!`, and is not compiled by Verus. Nothing here detects a later edit to mpl/. The
// link between model and code is the correspondence table in section 2, the wiring table in
// section 3 and the hypotheses in section 4, all reviewed by a human.
//
// STATUS: PROVED (model level), relative to the hypotheses and assumptions in section 4:
//     `verification results:: 65 verified, 0 errors`   (log: .agents/tasks/mpl-batch2-proofs/c07-run.md)
// Nothing is left failing on purpose, so NO EXPECTED_FAIL obligation is written. The one place
// where the code does not compare a field (symmetric signing keys, finding F1 below) is not a
// reachable gap with the 11 suite rows, because the materials builders keep that field empty.
// It is stated as a proved fact about the predicate (`lemma_f1_symmetric_keys_are_not_compared`),
// not as a failing proof, and not as a defect.
//
// THE BOUNDARY BETWEEN WHAT IS PROVED AND WHAT IS CODE READING (the main point of this file)
//   PROVED (model): which pairs (old, new) of materials the two transition checks accept, and
//     what an accepted pair can differ in. This covers every field the structs hold (7 for
//     encryption materials, 6 for decryption materials) and the EDK list as a multiset.
//   PROVED (model of `send`): if `send()` is written as the model says (call the keyring,
//     then run the check on the clone taken before the call, return the output only on Ok),
//     then for ANY keyring behavior an Ok result passed the check. This follows from how the
//     model of `send` is written. It shows the property is well formed, not that the shipped
//     `send` has it. The four `send` bodies were read (H_SEND_BODY).
//   CODE READING ONLY: that EVERY call path reaches one of those `send` bodies, that no other
//     path returns keyring or CMM materials to a caller, and that `Keyring::on_encrypt` and
//     friends are not called directly inside this repository. This is the wiring table in
//     section 3. The model does not contain the call graph. A proof of "every path calls the
//     check" does not exist in this file and none is claimed.
//   NOT A SEND PROOF FOR CMMs: `SharedCmm::send()` runs only the completeness check, on the
//     output alone. It has no `before` to compare with. That is T09, not proved here.
//
// WHAT IS PROVED (relative to the model and to section 4)
//   P1  theorem_contains_all_is_multiset_containment
//                                   `contains_all(new.edks, old.edks)` (the greedy matching with
//                                   `used` flags, :207-216) is true exactly when every EDK value
//                                   occurs in `new.edks` at least as often as in `old.edks`.
//                                   Repeats count. Position and order do not matter. Helper
//                                   lemmas: lemma_first_unused, lemma_avail_zero,
//                                   lemma_avail_update, lemma_avail_all_false,
//                                   lemma_contains_all_iff, lemma_count_push.
//   P2  theorem_enc_accepts_exactly, theorem_dec_accepts_exactly
//                                   the accept list of each transition check, written as a
//                                   conjunction of field conditions. The 17 `lemma_*_rejects_*`
//                                   lemmas give one rejection per rule (nine encrypt, eight
//                                   decrypt): a violation of that rule alone is enough to
//                                   reject. The decrypt list and eight of the nine encrypt rules
//                                   are the code's conjunction written again (a CONSISTENCY CHECK
//                                   against the target text, see below); the new content in P2
//                                   is the EDK rule through P1.
//   P3  theorem_enc_frame, theorem_dec_frame
//                                   an accepted pair differs only in the PDK and the EDK list
//                                   (encrypt) or only in the PDK (decrypt). All other fields are
//                                   equal, including the symmetric signing keys, which the check
//                                   does NOT read. Relative to H_BUILD_SYM (the builders keep
//                                   that field empty for these suites) and H_ALL_BUILT.
//   P4  theorem_honest_enc_accepted, theorem_honest_enc_edk_accepted, theorem_honest_dec_accepted
//                                   a keyring that uses only the public mutators `add_data_key`
//                                   and `add_encrypted_data_key` is accepted whenever its input
//                                   passes the base check.
//       theorem_enc_transitions_compose
//                                   accepted encrypt transitions compose: a then b then c, each
//                                   accepted, gives an accepted a to c.
//       theorem_dec_transition_single_use
//                                   after an accepted decrypt transition, no further decrypt
//                                   transition from the result is accepted (it has a PDK).
//   P5  theorem_send_enc_ok_implies_transition, theorem_send_dec_ok_implies_transition,
//       theorem_send_rejects_bad_keyring, theorem_cmm_send_ok_implies_complete,
//       theorem_cmm_send_dec_ok_implies_complete, theorem_default_cmm_over_send
//                                   the model of the `send` bodies, for any keyring or CMM
//                                   behavior (see the boundary above).
//   P6  theorem_c07_transition_summary
//                                   P2 and P3 in one statement. Not about `send`.
//   Observations proved as witnesses (each is a fact about the check, not a threat claim):
//       lemma_f1_symmetric_keys_are_not_compared   F1, latent, see section 6
//       lemma_transitions_do_not_read_pdk_length   O-PDK-LEN
//       lemma_noop_with_pdk_is_accepted            O-NOOP
//       lemma_transition_and_completeness_are_independent   O-COMPLETE
//       lemma_reordered_and_inserted_edks_accepted          O-EDK-ORDER
//       lemma_removing_a_duplicate_is_rejected              O-EDK-MULTISET
//       lemma_direct_call_is_not_checked           O-DIRECT (ILLUSTRATION ONLY)
//       lemma_enc_base_checks_agree, lemma_dec_base_checks_agree, lemma_base_check_is_needed_once
//                                                  O-WF-REDUNDANT
//   Non-vacuity: lemma_witnesses_accepted, lemma_witnesses_rejected, lemma_frame_applies_to_witnesses,
//       lemma_suite_flags_transcription (a second typing of the two suite flags, A_SUITE_COPY).
//
// A CONSISTENCY CHECK, STATED PLAINLY. Eight of the nine encrypt rules and all eight decrypt rules
// are plain field tests (`==`, `is_some`, `is_none`). The model transcribes them from the code,
// and P2 then restates them in the target's wording (docs/mpl-verification-targets/
// 02-capability-driven.md, property (a) and (b)). Verus checks that the two wordings agree. It
// does not check that the code does what the model says. The rejection lemmas are the same
// content in the other direction. The work that is not a transcription is: the EDK rule (P1,
// a recursive matching shown equal to a multiset test), P3 (a statement about every field of
// both structs, including the ones the check does not read), P4 (composition) and P5.
//
// WHAT IS NOT PROVED (read this too)
//   * That the shipped code has any of these properties (H_MODEL_MATCH). A later edit to mpl/ is
//     not detected.
//   * That every `send()` path runs the check. That is code reading (section 3), not modeled.
//   * That a keyring is correct: that the PDK is random or the right length, that an EDK
//     decrypts to the PDK, or that the EDK is well formed. The transition check does not look
//     at them. The length is C04. The EDK content is not modeled (abstract fields, A_EDK_ABS).
//   * That the CMM returns the materials it was asked for (suite allowed by the policy, context
//     containing the caller's keys). `SharedCmm::send()` has no request to compare (T09).
//   * That any threat is mitigated. The C07 entry has `threat_references: []`, so this file maps
//     to no TM-MPL threat. The docs name C07 as the supplier of the keyring-frame lemma that T09
//     and T12 use (suite and context unchanged by a keyring). A passing model proof is a
//     regression guard for the model, not a defense.
//   * Async behavior, panics, hangs or side effects of a keyring or CMM. A keyring behavior is
//     a pure function from input to `Option<output>` (A_SPEC_FN).
//   * Error kinds, messages and the order in which the checks fail (A_ERR). Only Ok against Err.
//   * That the 27 tests pass. They were NOT run for this proof. Their expectations were read and
//     compared with the code (section 7).
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD cff28df; mpl/ clean)
// =============================================================================
//   mpl/src/structures/materials_checks.rs   (216 lines, md5 8ebb285b325e00b5b38e631a711befdf)
//     :12        PUBLIC_KEY_CONTEXT_KEY = "aws-crypto-public-key"
//     :18-31     check_encryption_materials: signing suite needs a signing key :19-24; the context
//                holds the public key exactly when the suite signs :25-30
//     :37-50     check_decryption_materials: same with the verification key
//     :52-62     check_public_key_context: (true,false) Err, (false,true) Err, else Ok
//     :72-108    check_encryption_transition: base check of old :76 and new :77; suite :78-81;
//                encryption context :82-85; required keys :86-89; signing key (option_eq, ct_eq)
//                :90-93; new has a PDK :94-98; an old PDK equals the new one (ct_eq) :99-101;
//                new EDKs contain old EDKs (contains_all) :102-106
//     :117-150   check_decryption_transition: base check :121-122; old has no PDK :123-127; suite
//                :128-131; context :132-135; required keys :136-139; verification key (derived
//                `==`) :140-143; new has a PDK :144-148
//     :157-171   check_encryption_materials_complete: PDK :160, at least one EDK :165, base check
//     :177-186   check_decryption_materials_complete: PDK :180, base check
//     :188-196   check_unchanged
//     :198-204   option_eq
//     :207-216   contains_all (greedy matching with a `used` vector)
//   mpl/src/structures/encryption_materials.rs
//     :17-29     struct EncryptionMaterials: 7 fields (suite id, EDKs, encryption context, required
//                keys, PDK, signing key, symmetric signing keys); private, #[non_exhaustive]
//     :48-64     add_data_key; :71-83 add_encrypted_data_key; :130-132 symmetric_signing_keys()
//                (None and Some([]) both read as empty)
//     :358-436   build; the symmetric-key rule :413-425 (non-empty and no symmetric signing -> Err)
//   mpl/src/structures/decryption_materials.rs
//     :16-27     struct DecryptionMaterials: 6 fields (suite id, encryption context, required keys,
//                PDK, verification key, symmetric signing key)
//     :45-59     add_data_key; :295-357 build; the symmetric-key rule :341-347
//   mpl/src/structures/algorithm_suite.rs
//     :46-50, :53-55   has_asymmetric_signing, has_symmetric_signing
//     :144-305   suite table: asymmetric signature algorithm is Some on :243, :257, :271, :299 and
//                None on the other seven; symmetric signature algorithm is None on all 11 rows
//     :541, :607 ct_eq on PlaintextDataKey and SigningKey (aws_mpl_primitives::
//                constant_time_equal); VerificationKey derives PartialEq (:619)
//   mpl/src/structures/encrypted_data_key.rs :12-24   derive(PartialEq, Eq) over three fields
//   mpl/src/structures/encryption_context.rs :15-16   BTreeMap<String, String>, derive(PartialEq, Eq)
//   mpl/src/structures/required_encryption_context_keys.rs :25-26   BTreeSet<String>, derive(PartialEq, Eq)
//   mpl/src/keyring/fluent_builders.rs
//     :78-85     OnEncryptFluentBuilder::send: build input; `before` = clone of the input materials
//                :80; `Keyring::on_encrypt(..)?` :81; check_encryption_transition :82-83 with
//                map_err; Ok(output) :84
//     :159-166   OnDecryptFluentBuilder::send, same shape (:161, :162, :163)
//     :170-195   fluent_keyring! macro for RawAesKeyring and HierarchicalKeyring
//   mpl/src/cmm/fluent_builders.rs
//     :168-174   GetEncryptionMaterialsFluentBuilder::send: `Cmm::get_encryption_materials(..)?`
//                :170; check_encryption_materials_complete :171-172; Ok(output) :173
//     :316-322   DecryptMaterialsFluentBuilder::send, same shape (:318, :319)
//     :326-348   fluent_cmm! macro for DefaultCmm
//   mpl/src/cmm/default_cmm.rs :85-175 (encrypt), :177 on (decrypt)   DefaultCmm calls the inner keyring through
//                `.on_encrypt()...send()` :167-170 and `.on_decrypt()...send()` :244-248
//   mpl/src/shared.rs :110   Builtin<T>(pub(crate) T), the only implementor of Keyring/Cmm for built-ins
//   esdk/src/materials.rs :53 (keyring wrapped in DefaultCmm), :99-122 and :166-194 (CMM fluent calls)
//   mpl/tests/test_materials_checks.rs (585 lines, 27 `#[tokio::test]`): intended behavior, read not run
//   spec/framework/keyring-interface.md :126-127 (a keyring that attempted neither behavior MUST
//     fail and MUST NOT modify the encryption materials)
//   docs/mpl-verification-targets/02-capability-driven.md :315-350 (the C07 entry), :598 (finding)
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code)
// =============================================================================
//   model                          shipped code
//   -----------------------------  ---------------------------------------------------------
//   Suite                          EsdkAlgorithmSuiteId (11 variants, same names), standing for the
//                                  struct field type AlgorithmSuiteId (one variant Esdk(..), H_SUITE_ID)
//   signs, has_sym                 has_asymmetric_signing, has_symmetric_signing (hand copy, A_SUITE_COPY)
//   Str (nat)                      String keys and values of the context, required keys, provider id (A_STR)
//   Bytes (Seq<u8>)                Vec<u8> inside PlaintextDataKey, SigningKey, VerificationKey,
//                                  SymmetricSigningKey (A_BYTES)
//   Edk { 3 nat fields }           EncryptedDataKey, derive(PartialEq) (A_EDK_ABS)
//   EMat, DMat                     EncryptionMaterials, DecryptionMaterials, all fields
//   EMat.sym_keys: Seq<Bytes>      symmetric_signing_keys() view (None = Some([]) = empty)
//   pk_key()                       PUBLIC_KEY_CONTEXT_KEY
//   pk_ctx_ok                      check_public_key_context :52-62
//   enc_wf, dec_wf                 check_encryption_materials :18-31, check_decryption_materials :37-50
//   option_eq_ct                   option_eq with ct_eq :198-204 (ct_eq read as equality, A_CT_EQ)
//   pdk_rule                       :94-101
//   first_unused                   the `.find(..)` :210-213
//   contains_all_from, contains_all   contains_all :207-216 (each needle takes the first unused equal
//                                  entry and marks it used :214; a miss gives false)
//   cnt, count, avail              not in the code; the multiset count used to state P1
//   enc_transition_ok              check_encryption_transition :72-108 (true = Ok)
//   dec_transition_ok              check_decryption_transition :117-150
//   enc_complete, dec_complete     check_*_materials_complete :157-171, :177-186
//   enc_add_data_key, enc_add_edk, dec_add_data_key
//                                  the public mutators; `len_ok` is the C04 length check as a boolean
//   enc_built, dec_built           what `build` guarantees about the symmetric keys (H_BUILD_SYM)
//   send_enc, send_dec             the fluent `send` bodies of the keyring :78-85, :159-166
//   cmm_send_enc, cmm_send_dec     the fluent `send` bodies of the CMM :168-174, :316-322
//   spec_fn(EMat) -> Option<EMat>  any `Keyring::on_encrypt` implementation (A_SPEC_FN)
//
// =============================================================================
// 3. THE `send()` WIRING: CODE READING, NOT MODELED
// =============================================================================
// Search used: grep -rnE "\.send\(\)|fn send" over mpl/src and esdk/src; grep -rnE
// "on_encrypt|on_decrypt|get_encryption_materials|decrypt_materials" over mpl/src, esdk/src,
// esdk/examples, esdk/shims, mpl/test-server; grep -rn "handle\.0" and "Keyring::on_" / "Cmm::".
// Evidence level of every row: CODE READING (grep, then read). Where a test runs through the
// path it is named, but the tests were not run for this file.
//
//   #  path                                              check that runs on it           where
//   -- ------------------------------------------------  ------------------------------  -------------------------
//   W1 SharedKeyring::on_encrypt().send()                transition (encrypt)            keyring/fluent_builders.rs :78-85
//   W2 SharedKeyring::on_decrypt().send()                transition (decrypt)            keyring/fluent_builders.rs :159-166
//   W3 RawAesKeyring / HierarchicalKeyring               same as W1, W2 (delegates to a   keyring/fluent_builders.rs :170-195
//      `.on_encrypt()` / `.on_decrypt()`                 SharedKeyring built on Builtin)
//   W4 SharedCmm::get_encryption_materials().send()      completeness (encrypt) only      cmm/fluent_builders.rs :168-174
//   W5 SharedCmm::decrypt_materials().send()             completeness (decrypt) only      cmm/fluent_builders.rs :316-322
//   W6 DefaultCmm fluent methods                         same as W4, W5                   cmm/fluent_builders.rs :326-348
//   W7 DefaultCmm::get_encryption_materials (inner       transition (encrypt) on the     cmm/default_cmm.rs :167-170
//      keyring call)                                     inner keyring call
//   W8 DefaultCmm::decrypt_materials (inner keyring)     transition (decrypt)             cmm/default_cmm.rs :244-248
//   W9 ESDK encrypt and decrypt, `cmm....send()`         completeness (W4, W5); with a    esdk/src/materials.rs send() :122, :194
//      (a keyring becomes `DefaultCmm::new(keyring)`)    keyring input also W7, W8        (`DefaultCmm::new(keyring)` is at :53, not a send())
//   W10 esdk examples, C++ shim example, test-server     fluent `.send()` (W1 to W5)      send() lines: esdk/examples/custom_keyring.rs :35, :55;
//       handlers                                                                          custom_cmm.rs :55, :78; esdk/shims/aws-esdk-cpp/
//                                                                                         examples/custom-keyring/src/lib.rs :36, :56;
//                                                                                         mpl/test-server/src/handlers.rs :266, :283, :303, :348
//                                                                                         (the other `.send()` calls in the examples are ESDK
//                                                                                         encrypt/decrypt, not materials operations)
//   W11 direct call of the trait method on a user type   NO CHECK (the check is in send)  none in mpl/src, esdk/src, examples,
//       (`my_keyring.on_encrypt(input).await`)                                            tests or test-server (see the note below)
//   W12 `.send()` in cmc/, key_store/, kms_ops.rs,       not materials operations: n/a   cmc/fluent_builders.rs; key_store/*;
//       hierarchical_keyring.rs :602 :678 :694 :709                                      aws_kms/hierarchical_keyring.rs
//       :853 :921 :937 :952 (key store, cache, branch key
//       id supplier calls)
//
// What the table rests on (all CODE READING):
//   * The only trait-method calls `Keyring::on_encrypt(..)` and `Keyring::on_decrypt(..)` in
//     mpl/ and esdk/ are keyring/fluent_builders.rs :81 and :162. The only `Cmm::get_encryption_
//     materials(..)` and `Cmm::decrypt_materials(..)` calls are cmm/fluent_builders.rs :170 and
//     :318. The test-server `StaticKeyring` (handlers.rs :470-495) implements the trait and is
//     never called directly.
//   * `SharedKeyring(Arc<dyn Keyring>)` and `SharedCmm(Arc<dyn Cmm>)` have a private field. The
//     only uses of `handle.0` that reach the materials methods are the four lines above (grep;
//     `self.0.name()` at keyring/mod.rs :191 and cmm/mod.rs :77 reads only the name). So a holder
//     of a handle can reach the keyring or CMM only through `send()`.
//   * The built-in keyrings and the DefaultCmm do not implement `Keyring` or `Cmm` themselves.
//     The crate-private `Builtin<T>` (shared.rs :110) does. So there is no public trait-method
//     call on them (W3, W6).
//   * `Keyring` and `Cmm` are public traits, so a caller who owns a value of its own type that
//     implements the trait can call the method directly and skip the check (W11). No such call
//     exists in the crates, examples, tests or test-server at HEAD. The only direct calls found
//     are in five tracked scratch reproducers under `.agents/tasks/bug-reports/reproducers/`:
//     `zz_bugrepro_01_*.rs`, `_02_*.rs`, `_05_*.rs`, `_06_*.rs` and `_09_*.rs` (for example
//     `kr.on_encrypt(em)`), written against an older API. None is part of any crate. A custom keyring that calls ANOTHER keyring does so through
//     the fluent builder in the examples (W10). This is H_DIRECT_CALL.
//   * Therefore: every keyring call that goes through a `SharedKeyring` or a built-in keyring
//     runs the transition check. Every CMM call through a `SharedCmm` or `DefaultCmm` runs the
//     completeness check and no transition check, and the CMM check sees only the output.
//   What this does NOT show: that a future call site, a caller outside this repository that uses
//   the trait directly, or an implementor that returns the check's input by another route, will
//   keep the property. A new `Keyring::on_*` call site would break the table.
//
// =============================================================================
// 4. HYPOTHESES, ASSUMPTIONS AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and the items below
//    ASSUMED       taken as a premise, a definition, an interpretation or a hand copy (A_*)
//    CODE READING  a claim about shipped code that Verus does not see (H_*); checked by a human
//                  reading the source at the lines named, with grep as support where stated
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier..]`
//  attribute is written in this file, there is no uninterpreted spec function and there is no
//  exec function. The model is spec code, proof functions, and `fn main() {}`.
//
//  ASSUMED (A_*)
//  A_STR (ASSUMED, modeling choice). A `String` used as a context key or value, a required key or
//    a provider id is a `nat`. Only equality is used by the checks. `"aws-crypto-public-key"` is
//    the one distinguished value `pk_key()`.
//  A_BYTES (ASSUMED). A `Vec<u8>` key is a `Seq<u8>`. Only equality is used.
//  A_EDK_ABS (ASSUMED, modeling choice). An EDK is three `nat` fields. The code's equality is
//    the derived field-wise one (encrypted_data_key.rs :12), so equality on the model is the same
//    relation. The content of an EDK is never read by the checks.
//  A_CT_EQ (ASSUMED). `ct_eq` on a PDK or a signing key is byte equality. The function is
//    `aws_lc_rs::constant_time::verify_slices_are_equal` (prim/src/lib.rs :291), whose source in
//    aws-lc-rs 1.18.1 (the version in mpl/Cargo.lock) returns Err when the lengths differ and
//    otherwise defers to `CRYPTO_memcmp` (C, not read). `CRYPTO_memcmp` is taken to return 0
//    exactly when the bytes are equal. The function is not constant time in the lengths (its own
//    doc comment). Timing is not modeled.
//  A_SUITE_COPY (ASSUMED, copied by hand). `signs` and `has_sym` are typed from the rows of
//    algorithm_suite.rs :144-305. `lemma_suite_flags_transcription` types the same flags a second
//    time; a consistent error typed into both places would survive. (C05 covers the full table.)
//  A_ERR (ASSUMED, modeling choice). Errors are abstract. Only Ok against Err is claimed. The
//    error kind, the message, the attached resource and the order in which checks fail are not
//    modeled. The accept list is a conjunction, so the order does not change accept or reject.
//  A_SPEC_FN (ASSUMED, modeling choice). A keyring or CMM behavior is a pure function
//    `spec_fn(input) -> Option<output>`. `None` is any Err from it. Side effects, panics,
//    non-termination and concurrency are not modeled. The result holds for every such function.
//  A_VSTD (ASSUMED). The trusted base is Verus, Z3 and the vstd axioms for `Seq`, `Map`, `Set`.
//
//  CODE READING (H_*)
//  H_MODEL_MATCH (CODE READING). Each model function has the logic of the code path named in
//    section 2.
//  H_ALL_FIELDS (CODE READING). The seven and six fields in `EMat` and `DMat` are all the fields
//    of the two structs (encryption_materials.rs :17-29; decryption_materials.rs :16-27). Both are
//    `#[non_exhaustive]` with private fields, so no other field can be added outside the crate.
//    A new field would not be compared by the check and would break P3 until the model is updated.
//  H_SUITE_ID (CODE READING). The struct field is `AlgorithmSuiteId` (algorithm_suite.rs :22-26),
//    a `#[non_exhaustive]` enum with exactly one variant, `Esdk(EsdkAlgorithmSuiteId)`. The checks
//    compare it with the derived `==` (materials_checks.rs :79, :129) and read its signing
//    flags. The model uses `EsdkAlgorithmSuiteId` as the suite and takes the wrapper as a
//    bijection on it: two `AlgorithmSuiteId` values are equal exactly when the inner ids are
//    equal. A second variant, which `non_exhaustive` allows inside the crate, would add suites
//    the model does not have (its signing flags and its row in A_SUITE_COPY would be missing)
//    and this proof would have to be redone for it.
//  H_ALL_BUILT (CODE READING, grep support). Every value of either materials type comes from
//    `build()` (the only struct literals: encryption_materials.rs :427, decryption_materials.rs
//    :349), from `Clone`, or from the public mutators. The mutators write only the PDK and the
//    EDK list (encryption_materials.rs :61, :62, :81; decryption_materials.rs :57). No `Default`,
//    no `&mut` accessor, no interior mutability, no `unsafe` in mpl/src. Same argument as C04's
//    H_CLOSED. It makes `enc_built` and `dec_built` hold for both `old` and `new` in P3.
//  H_BUILD_SYM (CODE READING). `EncryptionMaterialsBuilder::build` returns Err when the suite has
//    no symmetric signing and `symmetric_signing_keys` is non-empty (:413-425).
//    `DecryptionMaterialsBuilder::build` returns Err when the suite has no symmetric signing and
//    `symmetric_signing_key` is set (:341-347). With `has_sym` false on all 11 rows (A_SUITE_COPY)
//    the field is empty or absent on every built value. This is what holds F1 closed.
//  H_SEND_BODY (CODE READING). The four `send` bodies are as modeled in `send_enc`, `send_dec`,
//    `cmm_send_enc`, `cmm_send_dec`: the keyring bodies take `before` as a clone of the input
//    materials before the call (:80, :161), propagate a keyring Err with `?` (:81, :162), run the
//    check on (before, output) and propagate its Err (:82-83, :163-164), and return the keyring's
//    own output on Ok (:84, :165). The CMM bodies call the CMM with `?` and run the completeness
//    check on the output alone.
//  H_NO_INTERIOR (CODE READING). The materials have no interior mutability, so the clone taken at
//    :80 equals what the keyring received, and the keyring cannot change `before` through its input.
//  H_DIRECT_CALL (CODE READING). `Keyring` and `Cmm` are `pub` traits. An implementor can call its
//    own `on_encrypt` or `get_encryption_materials` directly. Nothing in the crates does (the five
//    scratch reproducers zz_bugrepro_01, _02, _05, _06 and _09 under .agents/tasks/bug-reports/
//    reproducers are the only direct calls found; none is in a crate).
//  H_WIRING (CODE READING, grep support). The path table in section 3 is complete for mpl/ and
//    esdk/ at HEAD cff28df. It is a snapshot.
//
// =============================================================================
// 5. HOW THE PROOF IS BUILT
// =============================================================================
// Section 1 of the code defines the structs and the suite flags. Section 2 defines the base
// checks. Section 3 defines `contains_all` as the code writes it, a recursion over the needles
// where each needle takes the first unused equal entry. A second pair of functions counts values.
// Section 5 proves P1 by induction on the needle index: marking one unused entry as used lowers
// the available count of that value by one and leaves every other value unchanged
// (lemma_avail_update). Section 4 defines the two transition checks and the two completeness
// checks. Section 6 states P2. Section 7 states P3: under H_BUILD_SYM both symmetric fields are
// empty, so equal. Section 8 states P4. Section 9 holds the observations. Section 10 holds the
// non-vacuity witnesses. Section 11 models the `send` bodies (P5), then P6 is the summary. The
// summary lemma sits just before section 11.
//
// =============================================================================
// 6. FINDINGS AND OBSERVATIONS (each is code-shown; none is a failing proof)
// =============================================================================
//  F1 (LATENT; the transition check does not read the symmetric signing keys). Encryption:
//    `symmetric_signing_keys` is a field of EncryptionMaterials and `check_encryption_transition`
//    (:72-108) never reads it. Decryption: `symmetric_signing_key`, `check_decryption_transition`
//    (:117-150). The target text (02-capability-driven.md, C07 property) asks for this to be
//    listed so the owner can compare it with Dafny `Materials.dfy` (finding at :598). I did not
//    read `Materials.dfy`. Why it is latent: the check also requires the suite to be unchanged,
//    and the builders reject symmetric keys for every suite that has no symmetric signing, which
//    is all 11 rows. So both sides are empty. P3 proves "only PDK and EDKs differ" with that
//    premise (H_BUILD_SYM). `lemma_f1_symmetric_keys_are_not_compared` proves the other half: the
//    predicate by itself accepts a pair whose symmetric keys differ, and that pair is not
//    buildable today (`!enc_built(new)`). The protection is the builder, not the transition
//    check. If a suite with symmetric signing is added (the enum is `#[non_exhaustive]`, only ESDK
//    is implemented), a keyring could swap the symmetric keys and the check would accept it. No
//    test covers these two fields (test_materials_checks.rs has none). NOT written as an
//    EXPECTED_FAIL because with the 11 rows no reachable pair violates the frame.
//  O-EDK-MULTISET. The EDK rule is multiset containment, not set containment. The target text's
//    `formal_spec` writes `o.edks.to_set().subset_of(n.edks.to_set())`. The code counts repeats
//    (:207-216) and the test `on_encrypt_rejects_a_removed_encrypted_data_key` (:337) expects a
//    rejection when one of two equal EDKs is removed. The model follows the code.
//  O-EDK-ORDER. Order and position are not checked. EDKs may be reordered and may be inserted
//    anywhere, not only appended (test :250 expects acceptance of a reorder). The doc comment
//    on the check says "add encrypted data keys".
//  O-NOOP. When `old` already has a PDK, `new == old` is accepted. A keyring that adds nothing
//    passes. keyring-interface.md :126-127 says a keyring that attempted nothing MUST fail. The
//    check does not enforce that, and its own comment says only what a keyring "may" do. Not
//    written as a failing obligation. Recorded for the owner.
//  O-PDK-LEN. Neither transition reads the length of the PDK (C04 enforces it in `build` and
//    `add_data_key`). A PDK of any length, including empty, is accepted by the transition check
//    when only the PDK differs. That pair is not buildable (C04).
//  O-COMPLETE. The transition check and the completeness check are different predicates, and
//    neither implies the other (proved). A keyring result with a PDK and no EDK passes the keyring
//    check when `old` was empty-handed and `new` has no EDK; the CMM completeness check rejects it.
//    A CMM result that is complete can have any suite, since the CMM check has no `before` (T09).
//  O-DEC-SINGLE-USE. A decrypt transition from materials that already have a PDK is rejected
//    (proved, `theorem_dec_transition_single_use`). Consequence: two keyrings cannot both add a
//    PDK to the same decryption materials through `send`; a caller combining keyrings must stop
//    at the first success. This matches test :398.
//  O-WF-REDUNDANT. Both transitions run the base check on `old` and on `new`. Because the suite,
//    the signing or verification key and the context must be equal, the two base checks always
//    agree on an otherwise accepted pair (`lemma_enc_base_checks_agree`,
//    `lemma_dec_base_checks_agree`). Each is redundant given the other. They change which error
//    is reported first, not whether a pair is accepted. One is still needed
//    (`lemma_base_check_is_needed_once`). A CMM that hands the keyring invalid materials gets an
//    Err attributed to the keyring in either case (`lemma_enc_rejects_invalid_old`). This is
//    why the four mutants that drop one base check each (m11, m12, m23, m55) are equivalent mutants (c07-run.md).
//
// =============================================================================
// 7. TESTS READ AGAINST THE CODE AND THE MODEL (not run)
// =============================================================================
// mpl/tests/test_materials_checks.rs has 27 tests: 13 on encrypt transitions, 8 on decrypt
// transitions, 6 on CMM completeness. I read each against `materials_checks.rs` and the model.
// Each accept test (:226, :239, :250, :380) has an accepted witness in section 10 (or P4). Each
// reject test (:264 no PDK, :271 suite, :281 context, :294 required keys, :311 signing key, :324
// replaced PDK, :337 removed EDK, :354, :362, :372 base-check cases, :391, :398, :410, :422,
// :435, :451, :464 on the decrypt side) maps to one rule in P2. The tests exercise W1, W2, W4 and
// W5. No test sets or changes symmetric signing keys (F1) or covers a PDK of the wrong length
// through the transition (O-PDK-LEN). No expectation was found that contradicts the code. The CMM tests (:523, :536, :549, :562, :575) match
// `enc_complete` and `dec_complete`.
//
// =============================================================================
// 8. OVERLAP CHECKS
// =============================================================================
//  Against Mahnush_Verus (origin/Mahnush_Verus at 8d6381e; .agents/tasks/mpl-batch2-proofs/
//    dup-check.md, section (1)): NO OVERLAP. No `mpl/` file has Verus there, there is no
//    verus-proofs/ directory there, and nothing proves or models the materials transitions or the
//    `send()` wiring. VR-009 (esdk half, esdk/src/key_derivation.rs :31 `identity_kdf_key_len_ok`
//    and :45 `check_v2_key_lengths`) is a downstream length check on the ESDK side taking
//    unconstrained `usize` lengths. It says nothing about keyrings, before/after materials, EDKs
//    or `send()`. The only shared fact is indirect: C07 keeps the suite fixed across a keyring
//    call, so the suite VR-009 later reads is the suite the CMM chose. Neither depends on the other.
//  Against this repository:
//    C04 (c04_pdk_length_invariant.rs): C04 models a PDK by its length and every path that builds
//      or accepts one. It states that the transition checks never build a PDK. C07 does not read
//      lengths (O-PDK-LEN). No obligation is shared. The two PDK mutators are re-modeled here
//      only with `len_ok` as a boolean.
//    C05 (c05_algorithm_suite_table.rs): C05 proves the full table against the spec. C07 copies
//      two flags per row (A_SUITE_COPY) and does not import C05.
//    T09 (not proved): `SharedCmm::send()` checks completeness only. C07 proves what the
//      completeness check is (`enc_complete`) and that it has no `before`. It does not prove the
//      policy gate or anything about the CMM's request. The docs name C07 as the supplier of the
//      keyring frame lemma T09 uses: that is P3.
//    T12 (not proved): `merge_reproduced_encryption_context` is not modeled. C07 shows the
//      keyring cannot change the context after the CMM built it (P2, P3).
//    Existing tests: see section 7. They give examples. P2 and P3 quantify over all values.
//
// =============================================================================
// 9. NOT CHANGED, NOT RECORDED HERE
// =============================================================================
// No score, rank, gap or quick-win is changed by this file. The status in docs, the dashboard
// and README is recorded in a later step. mpl/, prim/ and esdk/ are untouched.
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Data model
// ============================================================

/// EsdkAlgorithmSuiteId, algorithm_suite.rs :69-92, standing for the field type AlgorithmSuiteId
/// (one variant `Esdk(..)`, H_SUITE_ID). Same variant names as the code. Only the
/// two facts the checks read are modeled per suite: `signs` and `has_sym` (section 1b).
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

/// A_STR: a String (encryption context key or value, required key, EDK provider id) is a `nat`.
/// Only equality on it is used.
pub type Str = nat;
/// A_BYTES: a `Vec<u8>` key is a `Seq<u8>`. Equality is the only operation (A_CT_EQ).
pub type Bytes = Seq<u8>;

/// EncryptedDataKey, encrypted_data_key.rs :12-24: `#[derive(PartialEq, Eq)]` over three fields
/// (`key_provider_id: String`, `key_provider_info: Vec<u8>`, `ciphertext: Vec<u8>`). A_EDK_ABS:
/// each field is a `nat`, so structural equality is the derived field-wise equality.
pub struct Edk {
    pub provider_id: nat,
    pub provider_info: nat,
    pub ciphertext: nat,
}

/// EncryptionMaterials, encryption_materials.rs :17-29. All seven fields. Field order is the
/// code's. `sym_keys` is the view of `symmetric_signing_keys()` (:130): `None` and `Some([])`
/// are both the empty sequence.
pub struct EMat {
    pub suite: Suite,
    pub edks: Seq<Edk>,
    pub ec: Map<Str, Str>,
    pub reck: Set<Str>,
    pub pdk: Option<Bytes>,
    pub sign_key: Option<Bytes>,
    pub sym_keys: Seq<Bytes>,
}

/// DecryptionMaterials, decryption_materials.rs :16-27. All six fields.
pub struct DMat {
    pub suite: Suite,
    pub ec: Map<Str, Str>,
    pub reck: Set<Str>,
    pub pdk: Option<Bytes>,
    pub ver_key: Option<Bytes>,
    pub sym_key: Option<Bytes>,
}

// ---- 1b. Per-suite facts (A_SUITE_COPY, copied by hand from algorithm_suite.rs :144-305) ----

/// `AlgorithmSuiteId::has_asymmetric_signing` (:46): `asymmetric_signature_algorithm.is_some()`.
/// Rows :243, :257, :271 and :299 are `Some(..)`. The other seven rows are `None`.
pub open spec fn signs(s: Suite) -> bool {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => false,
        Suite::AlgAes192GcmIv12Tag16NoKdf => false,
        Suite::AlgAes256GcmIv12Tag16NoKdf => false,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => false,
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => false,
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => false,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => true,
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => true,
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => true,
        Suite::AlgAes256GcmHkdfSha512CommitKey => false,
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => true,
    }
}

/// `has_symmetric_signing` (:53): `symmetric_signature_algorithm.is_some()`. All eleven rows
/// are `None` (:159, :173, :187, :201, :215, :229, :244, :258, :272, :286, :300).
pub open spec fn has_sym(s: Suite) -> bool {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => false,
        Suite::AlgAes192GcmIv12Tag16NoKdf => false,
        Suite::AlgAes256GcmIv12Tag16NoKdf => false,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => false,
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => false,
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => false,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => false,
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => false,
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => false,
        Suite::AlgAes256GcmHkdfSha512CommitKey => false,
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => false,
    }
}

/// PUBLIC_KEY_CONTEXT_KEY = "aws-crypto-public-key" (materials_checks.rs :12), one distinguished
/// `Str` (A_STR).
pub open spec fn pk_key() -> Str { 0 }

// ============================================================
// SECTION 2: The base checks (materials_checks.rs :18-65)
// ============================================================

/// `check_public_key_context(signs, has_public_key)`, :52-62. True = Ok.
pub open spec fn pk_ctx_ok(sg: bool, has_pk: bool) -> bool {
    match (sg, has_pk) {
        (true, false) => false,
        (false, true) => false,
        _ => true,
    }
}

/// `check_encryption_materials`, :18-31. True = Ok.
pub open spec fn enc_wf(m: EMat) -> bool {
    let sg = signs(m.suite);
    if sg && m.sign_key is None {
        false
    } else {
        pk_ctx_ok(sg, m.ec.dom().contains(pk_key()))
    }
}

/// `check_decryption_materials`, :37-50. True = Ok.
pub open spec fn dec_wf(m: DMat) -> bool {
    let sg = signs(m.suite);
    if sg && m.ver_key is None {
        false
    } else {
        pk_ctx_ok(sg, m.ec.dom().contains(pk_key()))
    }
}

// ============================================================
// SECTION 3: `contains_all` (materials_checks.rs :207-216), the greedy matching with `used` flags
// ============================================================

/// The `.find(|(key, used)| !**used && *key == needle)` of :210-213, from index `from`.
/// `Some(k)` is the first index `k >= from` with `!used[k] && hay[k] == needle`.
pub open spec fn first_unused(hay: Seq<Edk>, used: Seq<bool>, needle: Edk, from: int) -> Option<int>
    recommends used.len() == hay.len(), 0 <= from,
    decreases hay.len() - from,
{
    if from >= hay.len() {
        None
    } else if !used[from] && hay[from] == needle {
        Some(from)
    } else {
        first_unused(hay, used, needle, from + 1)
    }
}

/// `needles.iter().all(..)` of :209-215 from needle index `i`: each needle takes the first
/// unused equal haystack entry and marks it used (:214); a needle with no such entry gives false.
pub open spec fn contains_all_from(hay: Seq<Edk>, used: Seq<bool>, needles: Seq<Edk>, i: int) -> bool
    recommends used.len() == hay.len(), 0 <= i,
    decreases needles.len() - i,
{
    if i >= needles.len() {
        true
    } else {
        match first_unused(hay, used, needles[i], 0) {
            None => false,
            Some(k) => contains_all_from(hay, used.update(k, true), needles, i + 1),
        }
    }
}

/// `contains_all(haystack, needles)`, :207. `used = vec![false; haystack.len()]`.
pub open spec fn contains_all(hay: Seq<Edk>, needles: Seq<Edk>) -> bool {
    contains_all_from(hay, Seq::new(hay.len(), |j: int| false), needles, 0)
}

/// Number of entries of `s` equal to `x` at index `i` or later.
pub open spec fn cnt(s: Seq<Edk>, x: Edk, i: int) -> nat
    decreases s.len() - i,
{
    if i >= s.len() {
        0
    } else {
        (if s[i] == x { 1nat } else { 0nat }) + cnt(s, x, i + 1)
    }
}

/// Multiplicity of `x` in `s`.
pub open spec fn count(s: Seq<Edk>, x: Edk) -> nat {
    cnt(s, x, 0)
}

/// Number of unused entries of `hay` equal to `x` at index `from` or later.
pub open spec fn avail(hay: Seq<Edk>, used: Seq<bool>, x: Edk, from: int) -> nat
    recommends used.len() == hay.len(),
    decreases hay.len() - from,
{
    if from >= hay.len() {
        0
    } else {
        (if !used[from] && hay[from] == x { 1nat } else { 0nat }) + avail(hay, used, x, from + 1)
    }
}

// ============================================================
// SECTION 4: The two transition checks (materials_checks.rs :72-151)
// ============================================================

/// `option_eq(a, b, |a, b| a.ct_eq(b))`, :198-204, with `ct_eq` modeled as byte equality (A_CT_EQ).
pub open spec fn option_eq_ct(a: Option<Bytes>, b: Option<Bytes>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// :94-101. `new` must hold a PDK; an `old` PDK must equal it (`ct_eq`).
pub open spec fn pdk_rule(old: Option<Bytes>, new: Option<Bytes>) -> bool {
    match new {
        None => false,
        Some(nk) => match old {
            Some(ok) => ok == nk,
            None => true,
        },
    }
}

/// `check_encryption_transition(old, new)`, :72-108. True = Ok.
pub open spec fn enc_transition_ok(old: EMat, new: EMat) -> bool {
    enc_wf(old)                                           // :76
    && enc_wf(new)                                        // :77
    && new.suite == old.suite                             // :78-81
    && new.ec == old.ec                                   // :82-85
    && new.reck == old.reck                               // :86-89
    && option_eq_ct(old.sign_key, new.sign_key)           // :90-93
    && pdk_rule(old.pdk, new.pdk)                         // :94-101
    && contains_all(new.edks, old.edks)                   // :102-106
}

/// `check_decryption_transition(old, new)`, :117-150. True = Ok.
pub open spec fn dec_transition_ok(old: DMat, new: DMat) -> bool {
    dec_wf(old)                                           // :121
    && dec_wf(new)                                        // :122
    && old.pdk is None                                    // :123-127
    && new.suite == old.suite                             // :128-131
    && new.ec == old.ec                                   // :132-135
    && new.reck == old.reck                               // :136-139
    && new.ver_key == old.ver_key                         // :140-143
    && new.pdk is Some                                    // :144-148
}

/// `check_encryption_materials_complete`, :157-171. True = Ok.
pub open spec fn enc_complete(m: EMat) -> bool {
    m.pdk is Some && m.edks.len() > 0 && enc_wf(m)
}

/// `check_decryption_materials_complete`, :177-186. True = Ok.
pub open spec fn dec_complete(m: DMat) -> bool {
    m.pdk is Some && dec_wf(m)
}

// ============================================================
// SECTION 5: Lemmas on `contains_all` (P1)
// ============================================================

proof fn lemma_first_unused(hay: Seq<Edk>, used: Seq<bool>, needle: Edk, from: int)
    requires
        used.len() == hay.len(),
        0 <= from,
    ensures
        match first_unused(hay, used, needle, from) {
            None => forall|j: int| from <= j < hay.len() ==> !(!used[j] && hay[j] == needle),
            Some(k) => from <= k < hay.len() && !used[k] && hay[k] == needle,
        },
    decreases hay.len() - from,
{
    if from < hay.len() && !(!used[from] && hay[from] == needle) {
        lemma_first_unused(hay, used, needle, from + 1);
    }
}

proof fn lemma_avail_zero(hay: Seq<Edk>, used: Seq<bool>, x: Edk, from: int)
    requires
        used.len() == hay.len(),
        0 <= from,
        forall|j: int| from <= j < hay.len() ==> !(!used[j] && hay[j] == x),
    ensures
        avail(hay, used, x, from) == 0,
    decreases hay.len() - from,
{
    if from < hay.len() {
        lemma_avail_zero(hay, used, x, from + 1);
    }
}

/// Marking the unused entry `k` as used lowers the available count of `hay[k]` by one and
/// leaves every other value's count unchanged (suffix from `from`).
proof fn lemma_avail_update(hay: Seq<Edk>, used: Seq<bool>, k: int, x: Edk, from: int)
    requires
        used.len() == hay.len(),
        0 <= k < hay.len(),
        !used[k],
        0 <= from,
    ensures
        avail(hay, used.update(k, true), x, from)
            + (if from <= k && hay[k] == x { 1nat } else { 0nat })
            == avail(hay, used, x, from),
    decreases hay.len() - from,
{
    if from < hay.len() {
        lemma_avail_update(hay, used, k, x, from + 1);
    }
}

/// With nothing marked, the available count is the multiplicity.
proof fn lemma_avail_all_false(hay: Seq<Edk>, x: Edk, from: int)
    requires
        0 <= from,
    ensures
        avail(hay, Seq::new(hay.len(), |j: int| false), x, from) == cnt(hay, x, from),
    decreases hay.len() - from,
{
    if from < hay.len() {
        lemma_avail_all_false(hay, x, from + 1);
    }
}

proof fn lemma_contains_all_iff(hay: Seq<Edk>, used: Seq<bool>, needles: Seq<Edk>, i: int)
    requires
        used.len() == hay.len(),
        0 <= i,
    ensures
        contains_all_from(hay, used, needles, i)
            <==> forall|x: Edk| #[trigger] cnt(needles, x, i) <= avail(hay, used, x, 0),
    decreases needles.len() - i,
{
    if i >= needles.len() {
        assert(contains_all_from(hay, used, needles, i));
        assert forall|x: Edk| #[trigger] cnt(needles, x, i) <= avail(hay, used, x, 0) by {}
    } else {
        let nd = needles[i];
        lemma_first_unused(hay, used, nd, 0);
        match first_unused(hay, used, nd, 0) {
            None => {
                lemma_avail_zero(hay, used, nd, 0);
                assert(cnt(needles, nd, i) >= 1);
                assert(!contains_all_from(hay, used, needles, i));
                assert(!(forall|x: Edk| #[trigger] cnt(needles, x, i) <= avail(hay, used, x, 0)));
            },
            Some(k) => {
                assert(0 <= k < hay.len());
                let used2 = used.update(k, true);
                assert(used2.len() == hay.len());
                lemma_contains_all_iff(hay, used2, needles, i + 1);
                assert forall|x: Edk| #[trigger] avail(hay, used2, x, 0)
                    + (if hay[k] == x { 1nat } else { 0nat }) == avail(hay, used, x, 0) by {
                    lemma_avail_update(hay, used, k, x, 0);
                }
                assert(contains_all_from(hay, used, needles, i) == contains_all_from(hay, used2, needles, i + 1));
                assert forall|x: Edk| #[trigger] cnt(needles, x, i)
                    == (if nd == x { 1nat } else { 0nat }) + cnt(needles, x, i + 1) by {}
                if contains_all_from(hay, used2, needles, i + 1) {
                    assert forall|x: Edk| #[trigger] cnt(needles, x, i) <= avail(hay, used, x, 0) by {
                        assert(cnt(needles, x, i + 1) <= avail(hay, used2, x, 0));
                    }
                }
                if forall|x: Edk| #[trigger] cnt(needles, x, i) <= avail(hay, used, x, 0) {
                    assert forall|x: Edk| #[trigger] cnt(needles, x, i + 1) <= avail(hay, used2, x, 0) by {
                        assert(cnt(needles, x, i) <= avail(hay, used, x, 0));
                    }
                }
            },
        }
    }
}

/// P1: `contains_all(hay, needles)` is multiset containment: every value occurs in `hay` at
/// least as often as in `needles`. Repeats count. Order and position do not matter.
proof fn theorem_contains_all_is_multiset_containment(hay: Seq<Edk>, needles: Seq<Edk>)
    ensures
        contains_all(hay, needles)
            <==> forall|x: Edk| #[trigger] count(needles, x) <= count(hay, x),
{
    let used0 = Seq::new(hay.len(), |j: int| false);
    lemma_contains_all_iff(hay, used0, needles, 0);
    assert forall|x: Edk| #[trigger] avail(hay, used0, x, 0) == count(hay, x) by {
        lemma_avail_all_false(hay, x, 0);
    }
    assert(contains_all(hay, needles) == contains_all_from(hay, used0, needles, 0));
    if contains_all(hay, needles) {
        assert forall|x: Edk| #[trigger] count(needles, x) <= count(hay, x) by {
            assert(cnt(needles, x, 0) <= avail(hay, used0, x, 0));
        }
    }
    if forall|x: Edk| #[trigger] count(needles, x) <= count(hay, x) {
        assert forall|x: Edk| #[trigger] cnt(needles, x, 0) <= avail(hay, used0, x, 0) by {
            assert(count(needles, x) <= count(hay, x));
        }
    }
}

proof fn lemma_count_push(s: Seq<Edk>, e: Edk, x: Edk, i: int)
    requires
        0 <= i <= s.len(),
    ensures
        cnt(s.push(e), x, i) == cnt(s, x, i) + (if e == x { 1nat } else { 0nat }),
    decreases s.len() - i,
{
    reveal_with_fuel(cnt, 3);
    if i < s.len() {
        lemma_count_push(s, e, x, i + 1);
        assert(s.push(e)[i] == s[i]);
    } else {
        assert(s.push(e)[s.len() as int] == e);
    }
}


// ============================================================
// SECTION 6: The transition rules, exactly (P2, P3, P4)
// ============================================================

proof fn lemma_option_eq_ct(a: Option<Bytes>, b: Option<Bytes>)
    ensures
        option_eq_ct(a, b) <==> a == b,
{
}

/// O-WF-REDUNDANT. The base check on `old` and the base check on `new` give the same answer
/// whenever the transition's own rules hold, because `enc_wf` reads only the suite, the signing
/// key and the context, and the transition requires those to be equal. So each of the two base
/// checks is redundant given the other. They change the error that is reported first, not whether
/// a pair is accepted. One of them is still needed (`lemma_base_check_is_needed_once`).
proof fn lemma_enc_base_checks_agree(old: EMat, new: EMat)
    requires
        new.suite == old.suite,
        new.ec == old.ec,
        new.sign_key == old.sign_key,
    ensures
        enc_wf(old) <==> enc_wf(new),
{
}

proof fn lemma_dec_base_checks_agree(old: DMat, new: DMat)
    requires
        new.suite == old.suite,
        new.ec == old.ec,
        new.ver_key == old.ver_key,
    ensures
        dec_wf(old) <==> dec_wf(new),
{
}

/// With a PDK already present, the identity pair passes every rule except the base check, so the
/// base check alone decides it. Dropping both base checks would change which pairs are accepted.
proof fn lemma_base_check_is_needed_once(m: EMat, d: DMat)
    requires
        m.pdk is Some,
    ensures
        enc_transition_ok(m, m) <==> enc_wf(m),
        dec_transition_ok(DMat { pdk: None, ..d }, DMat { pdk: Some(seq![1u8]), ..d }) <==> dec_wf(d),
{
    theorem_enc_accepts_exactly(m, m);
}

/// P2 (encrypt). `check_encryption_transition` is Ok exactly on this list. The EDK clause is
/// multiset containment (P1), not set containment and not a prefix test.
/// THE LIST IS THE CODE'S CONJUNCTION WRITTEN AGAIN: this is a consistency check of the model
/// against the target text (property (a) in docs/mpl-verification-targets/02-capability-driven.md),
/// plus the P1 translation of `contains_all`. The new content is that translation.
proof fn theorem_enc_accepts_exactly(old: EMat, new: EMat)
    ensures
        enc_transition_ok(old, new) <==> (enc_wf(old) && enc_wf(new)
            && new.suite == old.suite && new.ec == old.ec && new.reck == old.reck
            && new.sign_key == old.sign_key
            && new.pdk is Some
            && (old.pdk is Some ==> new.pdk == old.pdk)
            && (forall|x: Edk| #[trigger] count(old.edks, x) <= count(new.edks, x))),
{
    lemma_option_eq_ct(old.sign_key, new.sign_key);
    theorem_contains_all_is_multiset_containment(new.edks, old.edks);
}

/// P2 (decrypt). A restatement of `dec_transition_ok` (consistency check against property (b)).
proof fn theorem_dec_accepts_exactly(old: DMat, new: DMat)
    ensures
        dec_transition_ok(old, new) <==> (dec_wf(old) && dec_wf(new) && old.pdk is None
            && new.suite == old.suite && new.ec == old.ec && new.reck == old.reck
            && new.ver_key == old.ver_key && new.pdk is Some),
{
}

// ---- Every rule rejects. One lemma per rule: a violation of that rule alone is enough. ----

proof fn lemma_enc_rejects_invalid_old(old: EMat, new: EMat)
    requires !enc_wf(old),
    ensures !enc_transition_ok(old, new),
{
}

proof fn lemma_enc_rejects_invalid_new(old: EMat, new: EMat)
    requires !enc_wf(new),
    ensures !enc_transition_ok(old, new),
{
}

proof fn lemma_enc_rejects_changed_suite(old: EMat, new: EMat)
    requires new.suite != old.suite,
    ensures !enc_transition_ok(old, new),
{
}

proof fn lemma_enc_rejects_changed_ec(old: EMat, new: EMat)
    requires new.ec != old.ec,
    ensures !enc_transition_ok(old, new),
{
}

proof fn lemma_enc_rejects_changed_reck(old: EMat, new: EMat)
    requires new.reck != old.reck,
    ensures !enc_transition_ok(old, new),
{
}

proof fn lemma_enc_rejects_changed_signing_key(old: EMat, new: EMat)
    requires new.sign_key != old.sign_key,
    ensures !enc_transition_ok(old, new),
{
    lemma_option_eq_ct(old.sign_key, new.sign_key);
}

proof fn lemma_enc_rejects_no_pdk(old: EMat, new: EMat)
    requires new.pdk is None,
    ensures !enc_transition_ok(old, new),
{
}

proof fn lemma_enc_rejects_replaced_pdk(old: EMat, new: EMat)
    requires old.pdk is Some, new.pdk != old.pdk,
    ensures !enc_transition_ok(old, new),
{
}

proof fn lemma_enc_rejects_removed_edk(old: EMat, new: EMat)
    requires exists|x: Edk| count(old.edks, x) > count(new.edks, x),
    ensures !enc_transition_ok(old, new),
{
    theorem_contains_all_is_multiset_containment(new.edks, old.edks);
}

proof fn lemma_dec_rejects_invalid_old(old: DMat, new: DMat)
    requires !dec_wf(old),
    ensures !dec_transition_ok(old, new),
{
}

proof fn lemma_dec_rejects_invalid_new(old: DMat, new: DMat)
    requires !dec_wf(new),
    ensures !dec_transition_ok(old, new),
{
}

proof fn lemma_dec_rejects_old_has_pdk(old: DMat, new: DMat)
    requires old.pdk is Some,
    ensures !dec_transition_ok(old, new),
{
}

proof fn lemma_dec_rejects_changed_suite(old: DMat, new: DMat)
    requires new.suite != old.suite,
    ensures !dec_transition_ok(old, new),
{
}

proof fn lemma_dec_rejects_changed_ec(old: DMat, new: DMat)
    requires new.ec != old.ec,
    ensures !dec_transition_ok(old, new),
{
}

proof fn lemma_dec_rejects_changed_reck(old: DMat, new: DMat)
    requires new.reck != old.reck,
    ensures !dec_transition_ok(old, new),
{
}

proof fn lemma_dec_rejects_changed_verification_key(old: DMat, new: DMat)
    requires new.ver_key != old.ver_key,
    ensures !dec_transition_ok(old, new),
{
}

proof fn lemma_dec_rejects_no_pdk(old: DMat, new: DMat)
    requires new.pdk is None,
    ensures !dec_transition_ok(old, new),
{
}

// ============================================================
// SECTION 7: What an accepted transition changes (P3)
// ============================================================

/// H_BUILD_SYM (CODE READING): `EncryptionMaterialsBuilder::build` (:358-436, check :413-425)
/// returns Err when the suite has no symmetric signing and `symmetric_signing_keys` is non-empty.
pub open spec fn enc_built(m: EMat) -> bool {
    !has_sym(m.suite) ==> m.sym_keys.len() == 0
}

/// H_BUILD_SYM (CODE READING): `DecryptionMaterialsBuilder::build` (:295-357, check :341-347)
/// returns Err when the suite has no symmetric signing and `symmetric_signing_key` is set.
pub open spec fn dec_built(m: DMat) -> bool {
    !has_sym(m.suite) ==> m.sym_key is None
}

proof fn lemma_no_suite_has_sym(s: Suite)
    ensures !has_sym(s),
{
}

/// P3 (encrypt). Relative to H_BUILD_SYM for `old` and `new` (both came out of `build`, H_ALL_BUILT):
/// an accepted transition changes only the PDK and the EDK list. Every other field of the seven
/// is equal, including `symmetric_signing_keys`, which the check does not compare.
proof fn theorem_enc_frame(old: EMat, new: EMat)
    requires
        enc_built(old),
        enc_built(new),
        enc_transition_ok(old, new),
    ensures
        new == (EMat {
            suite: old.suite,
            edks: new.edks,
            ec: old.ec,
            reck: old.reck,
            pdk: new.pdk,
            sign_key: old.sign_key,
            sym_keys: old.sym_keys,
        }),
        new.pdk is Some,
        old.pdk is Some ==> new.pdk == old.pdk,
        forall|x: Edk| #[trigger] count(old.edks, x) <= count(new.edks, x),
{
    theorem_enc_accepts_exactly(old, new);
    lemma_no_suite_has_sym(old.suite);
    assert(old.sym_keys =~= new.sym_keys);
}

/// P3 (decrypt). Relative to H_BUILD_SYM: an accepted transition has `old.pdk` empty and changes
/// only the PDK, which becomes present. The other five fields are equal.
proof fn theorem_dec_frame(old: DMat, new: DMat)
    requires
        dec_built(old),
        dec_built(new),
        dec_transition_ok(old, new),
    ensures
        old.pdk is None,
        new.pdk is Some,
        new == (DMat {
            suite: old.suite,
            ec: old.ec,
            reck: old.reck,
            pdk: new.pdk,
            ver_key: old.ver_key,
            sym_key: old.sym_key,
        }),
{
    lemma_no_suite_has_sym(old.suite);
}

// ============================================================
// SECTION 8: Honest keyrings are accepted; chains; the decrypt transition is single-use (P4)
// ============================================================

/// `EncryptionMaterials::add_data_key`, :48-64. `len_ok` stands for the C04 length check (:60).
pub open spec fn enc_add_data_key(m: EMat, k: Bytes, e: Edk, len_ok: bool) -> Option<EMat> {
    if m.pdk is Some {
        None
    } else if !len_ok {
        None
    } else {
        Some(EMat { pdk: Some(k), edks: m.edks.push(e), ..m })
    }
}

/// `EncryptionMaterials::add_encrypted_data_key`, :71-83.
pub open spec fn enc_add_edk(m: EMat, e: Edk) -> Option<EMat> {
    if m.pdk is None {
        None
    } else {
        Some(EMat { edks: m.edks.push(e), ..m })
    }
}

/// `DecryptionMaterials::add_data_key`, :45-59. `len_ok` stands for the C04 length check (:56).
pub open spec fn dec_add_data_key(m: DMat, k: Bytes, len_ok: bool) -> Option<DMat> {
    if m.pdk is Some {
        None
    } else if !len_ok {
        None
    } else {
        Some(DMat { pdk: Some(k), ..m })
    }
}

proof fn lemma_count_push_all(s: Seq<Edk>, e: Edk)
    ensures
        forall|x: Edk| #[trigger] count(s.push(e), x) >= count(s, x),
{
    assert forall|x: Edk| #[trigger] count(s.push(e), x) >= count(s, x) by {
        lemma_count_push(s, e, x, 0);
    }
}

/// P4: a keyring that uses only the public mutators is accepted whenever the input materials pass
/// the base check. This is the "no false rejections" half for the two mutators; a keyring that
/// builds new materials with the builder is not covered by this lemma.
proof fn theorem_honest_enc_accepted(m: EMat, k: Bytes, e: Edk, len_ok: bool)
    requires
        enc_wf(m),
        enc_add_data_key(m, k, e, len_ok) is Some,
    ensures
        enc_transition_ok(m, enc_add_data_key(m, k, e, len_ok).unwrap()),
{
    let out = enc_add_data_key(m, k, e, len_ok).unwrap();
    lemma_count_push_all(m.edks, e);
    theorem_enc_accepts_exactly(m, out);
}

proof fn theorem_honest_enc_edk_accepted(m: EMat, e: Edk)
    requires
        enc_wf(m),
        enc_add_edk(m, e) is Some,
    ensures
        enc_transition_ok(m, enc_add_edk(m, e).unwrap()),
{
    let out = enc_add_edk(m, e).unwrap();
    lemma_count_push_all(m.edks, e);
    theorem_enc_accepts_exactly(m, out);
}

proof fn theorem_honest_dec_accepted(m: DMat, k: Bytes, len_ok: bool)
    requires
        dec_wf(m),
        dec_add_data_key(m, k, len_ok) is Some,
    ensures
        dec_transition_ok(m, dec_add_data_key(m, k, len_ok).unwrap()),
{
}

/// P4: accepted encrypt transitions compose. Two keyrings run one after the other, each through
/// `send()`, are accepted from the first input to the last output.
proof fn theorem_enc_transitions_compose(a: EMat, b: EMat, c: EMat)
    requires
        enc_transition_ok(a, b),
        enc_transition_ok(b, c),
    ensures
        enc_transition_ok(a, c),
{
    theorem_enc_accepts_exactly(a, b);
    theorem_enc_accepts_exactly(b, c);
    theorem_enc_accepts_exactly(a, c);
    assert forall|x: Edk| #[trigger] count(a.edks, x) <= count(c.edks, x) by {
        assert(count(a.edks, x) <= count(b.edks, x));
        assert(count(b.edks, x) <= count(c.edks, x));
    }
}

/// P4: a decrypt transition is single-use. After an accepted `a -> b`, no `b -> c` is accepted,
/// because `b` has a PDK (:123-127). Two keyrings cannot both add the PDK to one materials value.
proof fn theorem_dec_transition_single_use(a: DMat, b: DMat, c: DMat)
    requires
        dec_transition_ok(a, b),
    ensures
        !dec_transition_ok(b, c),
{
}

// ============================================================
// SECTION 9: Boundaries of the check (observations, each a proved witness)
// ============================================================

pub open spec fn edk_n(n: nat) -> Edk {
    Edk { provider_id: n, provider_info: n, ciphertext: n }
}

pub open spec fn plain_suite() -> Suite {
    Suite::AlgAes256GcmHkdfSha512CommitKey
}

pub open spec fn sign_suite() -> Suite {
    Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
}

/// Encryption materials of a non-signing suite. As a CMM hands them to a keyring: `edks` empty, `pdk` None.
pub open spec fn enc_plain(edks: Seq<Edk>, pdk: Option<Bytes>) -> EMat {
    EMat {
        suite: plain_suite(),
        edks,
        ec: Map::<Str, Str>::empty().insert(1, 1),
        reck: Set::<Str>::empty().insert(1),
        pdk,
        sign_key: None,
        sym_keys: Seq::empty(),
    }
}

/// Encryption materials of a signing suite: the public key is in the context, a signing key is set.
pub open spec fn enc_sign(edks: Seq<Edk>, pdk: Option<Bytes>) -> EMat {
    EMat {
        suite: sign_suite(),
        edks,
        ec: Map::<Str, Str>::empty().insert(1, 1).insert(pk_key(), 7),
        reck: Set::<Str>::empty().insert(1),
        pdk,
        sign_key: Some(seq![1u8]),
        sym_keys: Seq::empty(),
    }
}

pub open spec fn dec_plain(pdk: Option<Bytes>) -> DMat {
    DMat {
        suite: plain_suite(),
        ec: Map::<Str, Str>::empty().insert(1, 1),
        reck: Set::<Str>::empty().insert(1),
        pdk,
        ver_key: None,
        sym_key: None,
    }
}

pub open spec fn dec_sign(pdk: Option<Bytes>) -> DMat {
    DMat {
        suite: sign_suite(),
        ec: Map::<Str, Str>::empty().insert(1, 1).insert(pk_key(), 7),
        reck: Set::<Str>::empty().insert(1),
        pdk,
        ver_key: Some(seq![2u8]),
        sym_key: None,
    }
}

proof fn lemma_count_empty(x: Edk)
    ensures count(Seq::<Edk>::empty(), x) == 0,
{
}

/// O-F1 (code shows it; LATENT). `check_encryption_transition` does not read `symmetric_signing_keys`
/// (:72-108) and `check_decryption_transition` does not read `symmetric_signing_key` (:117-150).
/// The proved fact is about the predicate: it accepts a pair whose symmetric keys differ.
/// Such a pair is not buildable today: `new` fails `enc_built`, because every suite row has no
/// symmetric signing (`has_sym` is false for all 11) and `build` rejects keys then (H_BUILD_SYM).
/// So the field is held equal by the builder, not by the transition check. A future suite with
/// symmetric signing would remove that protection. This is why no EXPECTED_FAIL is written: with
/// the 11 rows no reachable pair violates the frame (theorem_enc_frame).
proof fn lemma_f1_symmetric_keys_are_not_compared()
    ensures
        exists|old: EMat, new: EMat|
            enc_transition_ok(old, new) && old.sym_keys != new.sym_keys && enc_built(old) && !enc_built(new),
        exists|old: DMat, new: DMat|
            dec_transition_ok(old, new) && old.sym_key != new.sym_key && dec_built(old) && !dec_built(new),
{
    let k = seq![9u8];
    let new_pdk = Some(k);
    let old_e = EMat { sym_keys: Seq::empty(), ..enc_plain(Seq::empty(), new_pdk) };
    let new_e = EMat { sym_keys: Seq::empty().push(k), ..old_e };
    theorem_enc_accepts_exactly(old_e, new_e);
    assert(enc_wf(old_e));
    assert(enc_wf(new_e));
    assert forall|x: Edk| #[trigger] count(old_e.edks, x) <= count(new_e.edks, x) by {}
    assert(old_e.sym_keys.len() == 0);
    assert(new_e.sym_keys.len() == 1);
    assert(enc_transition_ok(old_e, new_e));
    let old_d = DMat { sym_key: None, ..dec_plain(None) };
    let new_d = DMat { pdk: new_pdk, sym_key: Some(k), ..old_d };
    assert(dec_transition_ok(old_d, new_d));
}

/// O-PDK-LEN. The transition checks never read the length of a PDK. For any PDK bytes, including
/// the empty sequence, the encrypt and the decrypt transition accept a pair that differs from the
/// input only by that PDK. The length rule is C04 (`check_data_key_length`, enforced by `build`
/// and `add_data_key`, not by the transition check).
proof fn lemma_transitions_do_not_read_pdk_length(k: Bytes)
    ensures
        enc_transition_ok(enc_plain(Seq::empty(), None), enc_plain(Seq::empty(), Some(k))),
        dec_transition_ok(dec_plain(None), dec_plain(Some(k))),
{
    theorem_enc_accepts_exactly(enc_plain(Seq::empty(), None), enc_plain(Seq::empty(), Some(k)));
    assert forall|x: Edk| #[trigger] count(Seq::<Edk>::empty(), x) <= count(Seq::<Edk>::empty(), x) by {}
}

/// O-NOOP. When `old` already has a PDK, `new == old` is accepted: a keyring that adds nothing
/// passes the transition check, and the materials may have no EDK at all. The spec says such a
/// keyring MUST fail (keyring-interface.md :126-127); the check does not enforce that.
/// The check's own comment says only what the keyring "may" do, so this is not a failing obligation.
proof fn lemma_noop_with_pdk_is_accepted(m: EMat)
    requires
        enc_wf(m),
        m.pdk is Some,
    ensures
        enc_transition_ok(m, m),
{
    theorem_enc_accepts_exactly(m, m);
}

/// O-COMPLETE. The keyring check and the CMM check are different predicates. A transition can be
/// accepted although the result has no EDK (so the CMM completeness check rejects it), and a
/// complete result can come with a changed suite (so the keyring transition check rejects it).
proof fn lemma_transition_and_completeness_are_independent()
    ensures
        exists|old: EMat, new: EMat| enc_transition_ok(old, new) && !enc_complete(new),
        exists|old: EMat, new: EMat| enc_complete(old) && enc_complete(new) && !enc_transition_ok(old, new),
{
    let m = enc_plain(Seq::empty(), Some(seq![1u8]));
    lemma_noop_with_pdk_is_accepted(m);
    assert(enc_transition_ok(m, m));
    assert(!enc_complete(m));
    let a = enc_plain(Seq::empty().push(edk_n(1)), Some(seq![1u8]));
    let b = EMat { suite: Suite::AlgAes256GcmIv12Tag16HkdfSha256, ..a };
    assert(enc_complete(a));
    assert(enc_complete(b));
    lemma_enc_rejects_changed_suite(a, b);
}

/// Computing a multiplicity on a sequence built with `push`.
proof fn lemma_count_two(a: Edk, b: Edk, x: Edk)
    ensures
        count(Seq::<Edk>::empty().push(a).push(b), x)
            == (if a == x { 1nat } else { 0nat }) + (if b == x { 1nat } else { 0nat }),
{
    lemma_count_push(Seq::<Edk>::empty().push(a), b, x, 0);
    lemma_count_push(Seq::<Edk>::empty(), a, x, 0);
}

proof fn lemma_count_three(a: Edk, b: Edk, c: Edk, x: Edk)
    ensures
        count(Seq::<Edk>::empty().push(a).push(b).push(c), x)
            == (if a == x { 1nat } else { 0nat }) + (if b == x { 1nat } else { 0nat })
            + (if c == x { 1nat } else { 0nat }),
{
    lemma_count_push(Seq::<Edk>::empty().push(a).push(b), c, x, 0);
    lemma_count_two(a, b, x);
}

/// O-EDK-ORDER. Order and position of the EDKs do not matter: [a, b] -> [c, b, a] is accepted
/// (a was moved, c was inserted at the front). tests/test_materials_checks.rs :250 agrees.
proof fn lemma_reordered_and_inserted_edks_accepted()
    ensures
        enc_transition_ok(
            enc_plain(Seq::empty().push(edk_n(1)).push(edk_n(2)), Some(seq![7u8])),
            enc_plain(Seq::empty().push(edk_n(3)).push(edk_n(2)).push(edk_n(1)), Some(seq![7u8])),
        ),
{
    let old = enc_plain(Seq::empty().push(edk_n(1)).push(edk_n(2)), Some(seq![7u8]));
    let new = enc_plain(Seq::empty().push(edk_n(3)).push(edk_n(2)).push(edk_n(1)), Some(seq![7u8]));
    theorem_enc_accepts_exactly(old, new);
    assert forall|x: Edk| #[trigger] count(old.edks, x) <= count(new.edks, x) by {
        lemma_count_two(edk_n(1), edk_n(2), x);
        lemma_count_three(edk_n(3), edk_n(2), edk_n(1), x);
    }
}

/// O-EDK-MULTISET. Repeats count: [a, a] -> [a, b] is rejected, although the sets {a} and {a, b}
/// satisfy "old is a subset of new". The target text in docs (02-capability-driven.md,
/// `formal_spec`) writes `to_set().subset_of`. The code is the multiset test. This lemma follows the code.
proof fn lemma_removing_a_duplicate_is_rejected()
    ensures
        !enc_transition_ok(
            enc_plain(Seq::empty().push(edk_n(1)).push(edk_n(1)), Some(seq![7u8])),
            enc_plain(Seq::empty().push(edk_n(1)).push(edk_n(2)), Some(seq![7u8])),
        ),
{
    let old = enc_plain(Seq::empty().push(edk_n(1)).push(edk_n(1)), Some(seq![7u8]));
    let new = enc_plain(Seq::empty().push(edk_n(1)).push(edk_n(2)), Some(seq![7u8]));
    lemma_count_two(edk_n(1), edk_n(1), edk_n(1));
    lemma_count_two(edk_n(1), edk_n(2), edk_n(1));
    assert(count(old.edks, edk_n(1)) == 2);
    assert(count(new.edks, edk_n(1)) == 1);
    lemma_enc_rejects_removed_edk(old, new);
}

// ============================================================
// SECTION 10: Non-vacuity
// ============================================================

/// Allowed transitions exist, for a signing and a non-signing suite, on both sides.
proof fn lemma_witnesses_accepted()
    ensures
        enc_transition_ok(enc_plain(Seq::empty(), None), enc_plain(Seq::empty().push(edk_n(1)), Some(seq![7u8]))),
        enc_transition_ok(enc_sign(Seq::empty(), None), enc_sign(Seq::empty().push(edk_n(1)), Some(seq![7u8]))),
        enc_transition_ok(
            enc_plain(Seq::empty().push(edk_n(1)), Some(seq![7u8])),
            enc_plain(Seq::empty().push(edk_n(1)).push(edk_n(2)), Some(seq![7u8])),
        ),
        dec_transition_ok(dec_plain(None), dec_plain(Some(seq![7u8]))),
        dec_transition_ok(dec_sign(None), dec_sign(Some(seq![7u8]))),
{
    let e1 = Seq::<Edk>::empty().push(edk_n(1));
    let e12 = e1.push(edk_n(2));
    theorem_enc_accepts_exactly(enc_plain(Seq::empty(), None), enc_plain(e1, Some(seq![7u8])));
    theorem_enc_accepts_exactly(enc_sign(Seq::empty(), None), enc_sign(e1, Some(seq![7u8])));
    theorem_enc_accepts_exactly(enc_plain(e1, Some(seq![7u8])), enc_plain(e12, Some(seq![7u8])));
    assert forall|x: Edk| #[trigger] count(Seq::<Edk>::empty(), x) <= count(e1, x) by {
        lemma_count_push(Seq::<Edk>::empty(), edk_n(1), x, 0);
    }
    assert forall|x: Edk| #[trigger] count(e1, x) <= count(e12, x) by {
        lemma_count_push(e1, edk_n(2), x, 0);
    }
}

/// One rejection for each rule, on concrete materials (each is the corresponding `lemma_*_rejects_*`
/// applied to a pair that violates only that rule).
proof fn lemma_witnesses_rejected()
    ensures
        // a signing suite whose context lacks the public key fails the base check
        !enc_wf(EMat { ec: Map::<Str, Str>::empty().insert(1, 1), ..enc_sign(Seq::empty(), None) }),
        // a non-signing suite whose context carries the public key fails the base check
        !enc_wf(EMat { ec: Map::<Str, Str>::empty().insert(1, 1).insert(pk_key(), 7), ..enc_plain(Seq::empty(), None) }),
        // a signing suite without a signing key fails the base check
        !enc_wf(EMat { sign_key: None, ..enc_sign(Seq::empty(), None) }),
        !dec_wf(DMat { ver_key: None, ..dec_sign(None) }),
        // PDK replaced
        !enc_transition_ok(enc_plain(Seq::empty(), Some(seq![7u8])), enc_plain(Seq::empty(), Some(seq![8u8]))),
        // no PDK returned
        !enc_transition_ok(enc_plain(Seq::empty(), None), enc_plain(Seq::empty(), None)),
        // decrypt: input already had a PDK
        !dec_transition_ok(dec_plain(Some(seq![7u8])), dec_plain(Some(seq![7u8]))),
{
    assert(seq![7u8][0] != seq![8u8][0]);
    assert(seq![7u8] != seq![8u8]);
    lemma_enc_rejects_replaced_pdk(
        enc_plain(Seq::empty(), Some(seq![7u8])),
        enc_plain(Seq::empty(), Some(seq![8u8])),
    );
    lemma_enc_rejects_no_pdk(enc_plain(Seq::empty(), None), enc_plain(Seq::empty(), None));
    lemma_dec_rejects_old_has_pdk(dec_plain(Some(seq![7u8])), dec_plain(Some(seq![7u8])));
}

/// The two suite flags are typed in a second time here, one assertion per row, and compared with
/// `signs` and `has_sym` (A_SUITE_COPY). A consistent error typed into both places survives.
proof fn lemma_suite_flags_transcription()
    ensures
        !signs(Suite::AlgAes128GcmIv12Tag16NoKdf),
        !signs(Suite::AlgAes192GcmIv12Tag16NoKdf),
        !signs(Suite::AlgAes256GcmIv12Tag16NoKdf),
        !signs(Suite::AlgAes128GcmIv12Tag16HkdfSha256),
        !signs(Suite::AlgAes192GcmIv12Tag16HkdfSha256),
        !signs(Suite::AlgAes256GcmIv12Tag16HkdfSha256),
        signs(Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256),
        signs(Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384),
        signs(Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384),
        !signs(Suite::AlgAes256GcmHkdfSha512CommitKey),
        signs(Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384),
        forall|s: Suite| !has_sym(s),
{
}

/// The frame theorems are not vacuous: the first accepted witness pair satisfies `enc_built` on both
/// sides, so `theorem_enc_frame` applies to it. The same for decrypt.
proof fn lemma_frame_applies_to_witnesses()
    ensures
        enc_built(enc_plain(Seq::empty(), None)),
        enc_built(enc_plain(Seq::empty().push(edk_n(1)), Some(seq![7u8]))),
        dec_built(dec_plain(None)),
        dec_built(dec_plain(Some(seq![7u8]))),
{
    lemma_witnesses_accepted();
    theorem_enc_frame(
        enc_plain(Seq::empty(), None),
        enc_plain(Seq::empty().push(edk_n(1)), Some(seq![7u8])),
    );
    theorem_dec_frame(dec_plain(None), dec_plain(Some(seq![7u8])));
}

/// P6: the transition rules in one statement, for arbitrary materials. This is the conjunction of
/// P1 to P3 and says nothing about `send()` or about which paths reach it.
proof fn theorem_c07_transition_summary(eo: EMat, en: EMat, d_old: DMat, d_new: DMat)
    ensures
        // encrypt: the accept list (P2)
        enc_transition_ok(eo, en) <==> (enc_wf(eo) && enc_wf(en)
            && en.suite == eo.suite && en.ec == eo.ec && en.reck == eo.reck
            && en.sign_key == eo.sign_key
            && en.pdk is Some
            && (eo.pdk is Some ==> en.pdk == eo.pdk)
            && (forall|x: Edk| #[trigger] count(eo.edks, x) <= count(en.edks, x))),
        // decrypt: the accept list (P2)
        dec_transition_ok(d_old, d_new) <==> (dec_wf(d_old) && dec_wf(d_new) && d_old.pdk is None
            && d_new.suite == d_old.suite && d_new.ec == d_old.ec && d_new.reck == d_old.reck
            && d_new.ver_key == d_old.ver_key && d_new.pdk is Some),
        // encrypt: accepted means only PDK and EDKs differ (P3, relative to H_BUILD_SYM)
        (enc_built(eo) && enc_built(en) && enc_transition_ok(eo, en)) ==> en == (EMat {
            suite: eo.suite,
            edks: en.edks,
            ec: eo.ec,
            reck: eo.reck,
            pdk: en.pdk,
            sign_key: eo.sign_key,
            sym_keys: eo.sym_keys,
        }),
        // decrypt: accepted means only the PDK differs (P3, relative to H_BUILD_SYM)
        (dec_built(d_old) && dec_built(d_new) && dec_transition_ok(d_old, d_new)) ==> d_new == (DMat {
            suite: d_old.suite,
            ec: d_old.ec,
            reck: d_old.reck,
            pdk: d_new.pdk,
            ver_key: d_old.ver_key,
            sym_key: d_old.sym_key,
        }),
{
    theorem_enc_accepts_exactly(eo, en);
    theorem_dec_accepts_exactly(d_old, d_new);
    if enc_built(eo) && enc_built(en) && enc_transition_ok(eo, en) {
        theorem_enc_frame(eo, en);
    }
    if dec_built(d_old) && dec_built(d_new) && dec_transition_ok(d_old, d_new) {
        theorem_dec_frame(d_old, d_new);
    }
}

// ============================================================
// SECTION 11: The `send()` wiring, as a model of what `send()` does (P5)
// ============================================================
// THIS SECTION MODELS THE TWO FLUENT `send` BODIES AND THE CMM `send` BODIES. It does NOT model
// which paths reach them. That every call reaches a `send` is CODE READING (section 3 of the header).
// The theorems below follow from how the model of `send` is written, for ANY keyring or CMM
// behavior. They are a check that the model of `send` has the shape property (d) describes.

/// `OnEncryptFluentBuilder::send`, keyring/fluent_builders.rs :78-85: clone the input as `before`, call
/// the keyring, run the transition check on (before, output), return the output on Ok.
/// `kr` is ANY keyring behavior: `None` is an Err from the keyring.
pub open spec fn send_enc(kr: spec_fn(EMat) -> Option<EMat>, input: EMat) -> Option<EMat> {
    match kr(input) {
        None => None,
        Some(out) => if enc_transition_ok(input, out) { Some(out) } else { None },
    }
}

/// `OnDecryptFluentBuilder::send`, keyring/fluent_builders.rs :159-166.
pub open spec fn send_dec(kr: spec_fn(DMat) -> Option<DMat>, input: DMat) -> Option<DMat> {
    match kr(input) {
        None => None,
        Some(out) => if dec_transition_ok(input, out) { Some(out) } else { None },
    }
}

/// `GetEncryptionMaterialsFluentBuilder::send`, cmm/fluent_builders.rs :168-174, on the output of
/// the CMM. The CMM check sees only the output: there is no `before`.
pub open spec fn cmm_send_enc(cmm_out: Option<EMat>) -> Option<EMat> {
    match cmm_out {
        None => None,
        Some(out) => if enc_complete(out) { Some(out) } else { None },
    }
}

/// `DecryptMaterialsFluentBuilder::send`, cmm/fluent_builders.rs :316-322.
pub open spec fn cmm_send_dec(cmm_out: Option<DMat>) -> Option<DMat> {
    match cmm_out {
        None => None,
        Some(out) => if dec_complete(out) { Some(out) } else { None },
    }
}

/// P5: for every keyring behavior and every input, an Ok result of the modeled `send` passed the
/// transition check, and is what the keyring returned. Together with P2 and P3 this fixes what the
/// output can differ from the input in.
proof fn theorem_send_enc_ok_implies_transition(kr: spec_fn(EMat) -> Option<EMat>, input: EMat, out: EMat)
    requires
        send_enc(kr, input) == Some(out),
    ensures
        kr(input) == Some(out),
        enc_transition_ok(input, out),
{
}

proof fn theorem_send_dec_ok_implies_transition(kr: spec_fn(DMat) -> Option<DMat>, input: DMat, out: DMat)
    requires
        send_dec(kr, input) == Some(out),
    ensures
        kr(input) == Some(out),
        dec_transition_ok(input, out),
{
}

/// P5: a keyring result that fails the transition check is turned into an Err by the modeled `send`.
proof fn theorem_send_rejects_bad_keyring(kr: spec_fn(EMat) -> Option<EMat>, input: EMat, out: EMat)
    requires
        kr(input) == Some(out),
        !enc_transition_ok(input, out),
    ensures
        send_enc(kr, input) is None,
{
}

/// P5: the modeled CMM `send` returns only complete materials. It has no transition check.
proof fn theorem_cmm_send_ok_implies_complete(cmm_out: Option<EMat>, out: EMat)
    requires
        cmm_send_enc(cmm_out) == Some(out),
    ensures
        enc_complete(out),
        out.pdk is Some,
        out.edks.len() > 0,
{
}

proof fn theorem_cmm_send_dec_ok_implies_complete(cmm_out: Option<DMat>, out: DMat)
    requires
        cmm_send_dec(cmm_out) == Some(out),
    ensures
        dec_complete(out),
        out.pdk is Some,
{
}

/// P5 (DefaultCmm over one keyring, as in default_cmm.rs :158-175): the CMM builds `empty`
/// materials, calls the keyring through `send` (:167-169) and returns the result, which the
/// SharedCmm `send` then checks. For ANY keyring behavior, an Ok result has passed both checks,
/// so (relative to H_BUILD_SYM) it differs from `empty` only in PDK and EDKs, and it has a PDK and at least one EDK.
proof fn theorem_default_cmm_over_send(kr: spec_fn(EMat) -> Option<EMat>, empty: EMat, out: EMat)
    requires
        cmm_send_enc(send_enc(kr, empty)) == Some(out),
        enc_built(empty),
        enc_built(out),
    ensures
        enc_transition_ok(empty, out),
        enc_complete(out),
        out == (EMat {
            suite: empty.suite,
            edks: out.edks,
            ec: empty.ec,
            reck: empty.reck,
            pdk: out.pdk,
            sign_key: empty.sign_key,
            sym_keys: empty.sym_keys,
        }),
{
    theorem_enc_frame(empty, out);
}

/// A keyring behavior that returns its input unchanged (`on_encrypt` that adds nothing).
pub open spec fn echo_keyring() -> spec_fn(EMat) -> Option<EMat> {
    |m: EMat| Some(m)
}

/// ILLUSTRATION ONLY (it is not evidence about the code). A call that does not go through `send` is
/// not covered by the check: the keyring behavior used directly returns materials that break a
/// transition rule (no PDK), while the modeled `send` turns the same behavior into an Err. That the
/// trait methods `Keyring::on_encrypt` and `Keyring::on_decrypt` are public and can be called
/// directly on an implementor's own type is CODE READING (H_DIRECT_CALL).
proof fn lemma_direct_call_is_not_checked()
    ensures
        (echo_keyring())(enc_plain(Seq::empty(), None)) is Some,
        !enc_transition_ok(enc_plain(Seq::empty(), None), (echo_keyring())(enc_plain(Seq::empty(), None)).unwrap()),
        send_enc(echo_keyring(), enc_plain(Seq::empty(), None)) is None,
{
    let input = enc_plain(Seq::empty(), None);
    lemma_enc_rejects_no_pdk(input, input);
}

fn main() {}

} // verus!
