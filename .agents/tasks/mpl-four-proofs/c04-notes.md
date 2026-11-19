# C04 notes (for the docs step)

Target: VR-2026-C04, the plaintext data key (PDK) length invariant (`check_data_key_length`,
`mpl/src/structures/algorithm_suite.rs:547`). Capability 1a. Score 2.80, estimated 1 week, agent route
mpl-verus-header-parsing-proofs. Score, rank, gap and quick-win are unchanged by this work.
Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `ad3522b`. Nothing under `mpl/`, `prim/`, `esdk/` or `docs/` was
changed. Nothing was committed, staged or pushed.

## 1. Result

- Proof file: `verus-proofs/c04_pdk_length_invariant.rs` (untracked, 1082 lines, md5 `5796a0cb911da211f7e14ec345a9b5b4`,
  header sections 0 to 5).
- Command: `~/verus/verus verus-proofs/c04_pdk_length_invariant.rs` (Verus 0.2026.07.12.0b42f4c), exit 0.
- Exact result line: `verification results:: 24 verified, 0 errors`
- Run log: `.agents/tasks/mpl-four-proofs/c04-run.txt`
- Status word to use: **Proved (model level, not the shipped code, under stated hypotheses).** The targets doc expected VERIFY
  (BUG-02 fixed). That is what happened. No EXPECTED_FAIL obligation was written, because no gap was found.
- What it is, plainly: a model with one function per code path that builds or accepts a PDK, and a proof that no
  sequence of those paths (any order, any lengths) produces a materials value whose PDK length differs from its suite's
  `encryption_key_length`. The check itself is one `!=` on two `usize` values; its proof (P1, P2) mirrors the code. The added
  value is the path list (section 5 below) and the closure over all paths (P4). It does not show that the shipped code has these
  properties, that the PDK is random or secret, or that any threat is mitigated. It maps to no TM-MPL threat
  (nearest: TM-MPL-006 and TM-MPL-023, BUG-02, already fixed). Direct tests already cover the four entry points with one wrong
  length (`mpl/tests/test_encryption_materials.rs:429,456`, `test_decryption_materials.rs:401,413`).
- Table copied from C05: the block from `pub enum Suite` to the end of `code_row` (112 lines) is a verbatim copy of
  `verus-proofs/c05_algorithm_suite_table.rs` (1153 lines, md5 `98209a4dca774c1c6227ea394897afdc`, `22 verified, 0 errors`,
  untracked at HEAD `ad3522b`). It is a copy of a copy: C05 copied it by hand from `algorithm_suite.rs:144-305`. The header says so.
  Only `key_len` is used. Script check: `c04-copy-check.py` (75 of 75 pass).

## 2. What is proved (all relative to the model and the items in section 3)

| Id | Theorem (in the file) | Statement |
|---|---|---|
| P1 | `theorem_check_exact`, `theorem_check_exact_exec_agrees` | `check_data_key_length(s, k)` is Ok exactly when `k.len == encryption_key_length(s)`; the exec form (`check_data_key_length_exec`) agrees. A mirror of the code. |
| P2 | `theorem_add_data_key_exact`, `theorem_build_exact` | The four accept paths (enc/dec `add_data_key`, enc/dec `build`): Ok exactly when no PDK is present (add) or a suite is set and `other_ok` holds (build), and the length is the suite's; then the stored PDK is the one passed in, and any other length (including 0) gives Err. |
| P3 | `lemma_gen_pdk`, `lemma_raw_dec`, `lemma_hier_dec`, `theorem_producers_exact` | The producers give a PDK of the suite length: both generators (exec form `generate_exec` with `vec![0u8; n]`), raw-AES decrypt for any list of decrypted lengths, hierarchical decrypt for any list of results. Both generators pass the check and have `len * 8` equal to the spec KDF input length. |
| P4 | `theorem_c04_closure` (with `lemma_step_preserves`, `lemma_run_preserves`, `lemma_step_dispatch`) | From any builder state (any suite, any PDK of any length, any `other_ok`), build, then apply any finite sequence of the eight modeled paths in any order: every Ok materials value has `pdk_ok`, and the suite is the one chosen at build. `lemma_step_dispatch` is a definition check (`step` sends each `Step` to its path function). |
| P5 | `theorem_pdk_matches_spec_bits` (with `lemma_key_len_table`) | A present PDK has `len * 8` equal to the spec "Encryption Key Length (bits)" and to the spec "Key Derivation Input Length (bits)", and the length is 16, 24 or 32. Both columns are hand copies. |
| P6 | `lemma_witnesses`, `lemma_decrypt_succeeds_on_right_length`, `lemma_run_witness` | Non-vacuity: for every suite a right-length key is accepted and a key one byte shorter or longer, or empty, is rejected; the type alone allows a wrong-length PDK; raw-AES decrypt succeeds when some EDK gives the right length; a PDK is reachable and a second `add_data_key` is rejected. |
| P7 | `theorem_c04_summary` | The conjunction of the above for arbitrary inputs. |

## 3. Hypotheses and assumptions with evidence levels

Evidence levels: PROVED (checked by Verus in the file), ASSUMED (a premise, definition, interpretation or hand copy),
CODE READING (a claim about shipped code that Verus does not see; grep and `c04-copy-check.py` support some of them, and a script check is not a proof).
No `assume`, `admit`, `external_body`, `assume_specification` or uninterpreted function is in the file.

| Name | Level | Content |
|---|---|---|
| A_TABLE_COPY | ASSUMED, copied by hand (copy of a copy) | The suite table block copied verbatim from C05, which copied it from `algorithm_suite.rs:144-305`. Script check: identical to the C05 block, and the 11 `key_len` values equal the Rust source. |
| A_SPEC_COLS_COPY | ASSUMED, copied by hand | `spec_key_bits` and `spec_kdf_in_bits`: the "Encryption Key Length (bits)" column (`algorithm-suites.md:239-262`) and the "Key Derivation Input Length (bits)" column (`:214-237`) for the 11 ESDK suites. Script check: equal to the spec file. |
| A_FIT | ASSUMED, an interpretation | `structures.md:227` (encryption materials PDK "MUST fit the specification for the key derivation algorithm") and `:323` (decryption materials PDK "fit ... the encryption algorithm") are read as "has the suite key length". The code uses `encryption_key_length` for both. |
| A_OTHER_OK | ASSUMED, modeling choice | The other checks of `build` (required EC keys, EDKs without a PDK, signing key, verification key, symmetric keys) are one boolean. Sound only if none can turn an Err into an Ok or change the stored PDK (H_BUILD_OTHER). |
| A_ERR | ASSUMED, modeling choice | Error kinds are abstract. Only Ok against Err is claimed. |
| A_LEN | ASSUMED | A PDK length is any `usize`; a superset of what `Vec::len` can give. |
| A_RNG_FAIL | ASSUMED, modeling choice | Generators are modeled for the success case. On RNG failure the code returns Err before building a PDK. |
| A_VSTD | ASSUMED | Verus, Z3 and the vstd specifications of `Vec` and `vec![x; n]`. |
| H_MODEL_MATCH | CODE READING | Each model function has the logic of the code path named in the header section 2. |
| H_CLOSED | CODE READING, grep and script support | The only writes to a materials value's `plaintext_data_key` are `encryption_materials.rs:61,432` and `decryption_materials.rs:57,353`; fields private, structs `#[non_exhaustive]`, no `Default`, no `&mut self` method, no `unsafe` in `mpl/src`. A new constructor or method would break it. |
| H_NO_MUT | CODE READING, script support | `plaintext_data_key()` returns `Option<&PlaintextDataKey>`; the type has no `&mut self` method, no interior mutability, no `DerefMut`. |
| H_SUITE_FIXED | CODE READING | No method changes `algorithm_suite_id` after `build`; `algorithm_suite()` returns the stored one. |
| H_BUILD_SAME_SUITE | CODE READING | In both `build` fns the checked suite is the stored suite. |
| H_BUILD_OTHER | CODE READING | The checks after the PDK check only `return Err`; the literal copies `self.plaintext_data_key` unchanged. |
| H_ENC_DEC_SAME | CODE READING | For this property the two materials types differ only in fields the model ignores; the model lets a step sequence mix encrypt and decrypt functions (a superset of the typed behavior). |
| H_GEN_SUITE | CODE READING, script support | Both generators are called with `materials.algorithm_suite()`. |
| H_FILL_SLICE | CODE READING, script support | `generate_random_bytes(bytes: &mut [u8])` (`prim/src/lib.rs:128`) takes a slice, so the buffer length cannot change (Rust typing). This is not an assumption about aws-lc-rs. The RNG values are not modeled. |
| H_VEC_LEN | CODE READING (std), checked in the exec model | `vec![0u8; n]` has length n. |
| H_RAW_DEC_LOOP, H_HIER_DEC_LOOP | CODE READING | The two `on_decrypt` loops change nothing until their `add_data_key(..)?` and return its result; `raw_dec` and `hier_dec` are those loops. |
| H_NO_OTHER_PRODUCER | CODE READING, script support | `PlaintextDataKey::new` / `From<Vec<u8>>` are called in `mpl/src` only at `raw_aes_keyring.rs:497,544` and `hierarchical_keyring.rs:767,984`; `esdk/src` never names the type. |
| H_TABLE_ONLY | CODE READING (from C05) | Every `AlgorithmSuite` value comes from the table. |

## 4. Code and spec locations read

- `mpl/src/structures/algorithm_suite.rs`: :69-92, :144-305, :378-380, :504-562 (`PlaintextDataKey`, `check_data_key_length`).
- `mpl/src/structures/encryption_materials.rs`: :19-29, :48-64, :71-83, :159-168, :175-183, :281-292, :358-436.
- `mpl/src/structures/decryption_materials.rs`: :18-27, :45-59, :128-136, :143-151, :220-231, :295-357.
- `mpl/src/keyring/raw_aes_keyring.rs`: :399-420, :422-530, :535-545. `mpl/src/aws_kms/hierarchical_keyring.rs`: :654-732, :734-802, :867-960, :975-985.
- `mpl/src/cmm/default_cmm.rs`: :158, :235. `mpl/src/structures/materials_checks.rs` (presence checks). `mpl/src/keyring/fluent_builders.rs`: :82, :163. `mpl/src/cmm/fluent_builders.rs`: :171, :319.
- `prim/src/lib.rs`: :128 (`generate_random_bytes`). `esdk/src/key_derivation.rs`: :79, :179 (downstream re-check, not modeled).
- `mpl/test-server/src/handlers.rs`: :548, :568 (public setters). `mpl/tests/test_encryption_materials.rs`, `test_decryption_materials.rs` (the direct tests).
- `spec/framework/keyring-interface.md`: :144-148. `algorithm-suites.md`: :90-96, :214-237, :239-262, :418-446. `structures.md`: :221-236, :317-332.
- Docs: `docs/mpl-verification-targets/02-capability-driven.md` (C04 entry at "VR-2026-C04", section 6, section 7), `docs/mpl-verification-targets.md` (rows at :212 and :237),
  `docs/mpl-bug-reports/BUG-02-plaintext-data-key-length-not-enforced.md`.

## 5. Path coverage: every place a PDK is built or accepted in `mpl/`

Search: `grep -rn "PlaintextDataKey\|plaintext_data_key\|add_data_key\|check_data_key_length"` over `mpl/src`, `esdk/src`, `prim/src`, `mpl/tests`,
`mpl/test-server`, `esdk/tests`. Struct literals of the two materials types exist only at `encryption_materials.rs:427` and `decryption_materials.rs:349`.

Paths that accept a PDK into a materials value (the only writers of the field):

| Id | Path | Model | Covered |
|---|---|---|---|
| A1 | `EncryptionMaterials::add_data_key` `:48-64`, check `:60` | `enc_add_data_key` | Covered |
| A2 | `DecryptionMaterials::add_data_key` `:45-59`, check `:56` | `dec_add_data_key` | Covered |
| A3 | `EncryptionMaterialsBuilder::build` `:358-436`, check `:364-367` | `enc_build` | Covered |
| A4 | `DecryptionMaterialsBuilder::build` `:295-357`, check `:302-305` | `dec_build` | Covered |
| A5 | the four builder setters (store, no check) | any `Bld` | Covered (the value is only checked at A3 and A4) |
| A6 | `derive(Clone)` of the materials | `CloneMat` | Covered |
| A7 | `add_encrypted_data_key` (enc), leaves the PDK alone | `enc_add_edk` | Covered |

Paths that build a `PlaintextDataKey` value:

| Id | Path | Model | Covered |
|---|---|---|---|
| B1 | raw-AES `generate_random_data_key` `:535-545` | `gen_pdk`, `generate_exec` | Covered |
| B2 | hierarchical `generate_random_data_key` `:975-985` | same | Covered |
| B3 | raw-AES `on_decrypt`, `PlaintextDataKey::new` `:497`, with the length test `:489` | `raw_dec`, any length | Covered |
| B4 | hierarchical `on_decrypt`, `PlaintextDataKey::new` `:767`, no length test before `add_data_key` | `hier_dec`, any length | Covered |
| B5 | public `PlaintextDataKey::new` `:517` and `From<Vec<u8>>` `:508` (user keyrings, tests, test server, esdk tests) | any `Pdk.len` | Covered (the type does not enforce the length) |
| B6 | `derive(Clone)` of `PlaintextDataKey`, `pdk.clone()` `hierarchical_keyring.rs:661` | `CloneMat` | Covered |

Not covered, with the reason:

| Id | Item | Reason |
|---|---|---|
| C1 | `default_cmm.rs:158,235` build materials with no PDK | No PDK there; `pdk = None` is a builder state the theorems cover. |
| C2 | transition and completeness checks (`materials_checks.rs`, fluent builders) | Presence checks only; they never build a PDK or check its length. |
| C3 | `esdk/src/key_derivation.rs:79,179` | A second check after the PDK leaves the materials (a consumer, not a constructor). |
| C4 | `branch_key_wrap::unwrap`, AES-GCM decrypt, KMS, key store, cache | Only the returned length matters; it is arbitrary in B3 and B4. |
| C5 | the `zeroize` crate behavior of `Zeroize` / `ZeroizeOnDrop` on a `Vec` | Not examined. The materials give out only `&PlaintextDataKey` (H_NO_MUT), so no length change through the materials. |

## 6. What is not shown

- That the shipped code has these properties. The code is not inside `verus!` and nothing detects an edit to `mpl/` (H_MODEL_MATCH).
- That the path list is complete. That is H_CLOSED, code reading with grep support. A new constructor or a new `&mut` access would break it.
- That the PDK is random, secret, zeroized or the right bytes. Only the length is modeled.
- That the spec is right, or that "fit the specification" means key length (A_FIT).
- The ESDK consumers (C3), the KMS, key store, cache, `unwrap`, AES-GCM and RNG values (C4).
- That any threat is mitigated. A passing model proof is a regression guard for the model.
- Low added value, stated plainly: P1 and P2 restate a one-line comparison. The four entry points are tested directly. The value is the path list and the closure P4.
- `lemma_step_dispatch` is true by the definition of `step`. It exists only to catch an edit of `step` (mutant m27).

## 7. Findings

No finding. No EXPECTED_FAIL obligation was written: all four entry points call the check, every producer builds the suite length, and
the model proves the closure. Observations that are not findings:

- O1. The `PlaintextDataKey` type does not enforce any length (`new` and `From<Vec<u8>>` are public). The invariant rests on
  the four checks plus the privacy of the materials fields (H_CLOSED), not on the type. A new materials constructor or setter in
  `mpl/src` would bypass it. `lemma_witnesses` shows the type alone allows a wrong-length PDK.
- O2. In raw-AES `on_decrypt` the length test at `:489` is redundant for the invariant, because `add_data_key` at `:497` checks again.
  It changes behavior, not safety: a wrong length skips to the next EDK (`continue`), where the check in `add_data_key` alone would
  return Err and stop the loop. The liveness witness `lemma_decrypt_succeeds_on_right_length` pins this (mutant s02).
- O3. In hierarchical `on_decrypt` there is no test before `add_data_key` (`:767`, with `?`). A wrong-length result from
  `branch_key_wrap::unwrap` for one EDK ends `on_decrypt` with Err and later EDKs are not tried. It fails closed. This is code
  reading and visible in `hier_dec`, not a proved lemma. It is the same place BUG-05 (b) discusses; BUG-05 is about a pre-lookup length check, not about the invariant.
- O4. The spec says the encryption-materials PDK must fit the KDF, and the decryption-materials PDK must fit the encryption
  algorithm. The code uses `encryption_key_length` for both. For the 11 suites the spec KDF input length equals the key length
  (proved for the two copied columns, A_SPEC_COLS_COPY).
- O5. `esdk/src/key_derivation.rs` re-checks the PDK length (`:79`, `:179`). With C04 that check is a second line of defense and not
  the only one.

## 8. Duplicate check: C04 against Mahnush_Verus

(Use as the section "C04 against Mahnush_Verus" in `docs/mpl-verification-targets.md`, same form as "T04 against Mahnush_Verus".)

Result of the duplicate check: **C04 does not duplicate anything on `Mahnush_Verus`.** Ref read: `origin/Mahnush_Verus` at `8d6381e`
(the tip used for the C03, T04, T06 and C05 records). It was read with `git grep`, `git ls-tree`, `git diff` and `git show` only. Nothing was
merged, checked out or modified. The in-crate proofs there are VR-006, VR-008, VR-009, VR-013 and VR-014.

- **No Verus in `mpl/` there.** `git grep -l 'verus!' origin/Mahnush_Verus -- mpl` returns nothing. `check_data_key_length`
  is plain Rust there, at the same place (`algorithm_suite.rs:547`), with the same four call sites (`encryption_materials.rs:60,365`,
  `decryption_materials.rs:56,303`).
- **Same code.** `git diff HEAD origin/Mahnush_Verus --stat -- mpl/src` is empty, so every `mpl` path in the C04 list is the same file there.
- **No `verus-proofs/` directory** there (`git ls-tree -r --name-only origin/Mahnush_Verus` has no such path).
- **Searches.** `git grep -n -E 'VR-2026-C04|\bC04\b|BUG-02|TM-MPL-006|TM-MPL-023' origin/Mahnush_Verus` has no hit. A search for
  `check_data_key_length` finds only the definition and the four call sites in `mpl/src/structures/`. A search for `pdk_ok` and for "data key
  length" in `docs`, `verification`, `prim`, `esdk` and `.kiro` finds only error messages and tests (`esdk/src/key_derivation.rs:133,242`,
  `esdk/src/encrypt.rs:757`) and EDK-length spec comments in `esdk/src/message/encrypted_data_keys.rs`; none is a proof of the PDK length.
  `PlaintextDataKey` appears there in `docs/threat-model.md`, `docs/verification-recommendations.md` and `docs/verus-proofs-report.md` only for zeroization
  (VR-010, deferred; its model describes a loop that no longer exists) and for the `as_bytes` confinement; neither concerns the length.
- **Overlap at the consumer level only, and complementary.** VR-009 (esdk half) proves `identity_kdf_key_len_ok` and `check_v2_key_lengths`
  in `esdk/src/key_derivation.rs` on that branch: accept iff the plaintext key length equals the suite encryption key length, with `suite_key_len`
  as an unconstrained input. That is the ESDK-side re-check of the same equality after the PDK has left the materials (path C3 in
  section 5, not modeled by C04). It says nothing about how `EncryptionMaterials` or `DecryptionMaterials` come to hold a PDK, what any
  keyring or builder does, or whether the suite value passed in came from the table. C04 is the producer and constructor side in `mpl/`. The two
  statements fit together (both sides reject a length different from `encryption_key_length`) and neither depends on the other.
  VR-013(d) proves that `fill_random_core` under `generate_random_bytes` keeps the buffer length; C04 gets the same fact from the slice type
  (H_FILL_SLICE) and does not depend on it. VR-006, VR-008, VR-013 (other parts) and VR-014 concern AES-GCM buffers, ECDSA lengths and prim wrappers, not PDK lengths.
  Note: on that branch `esdk/src/key_derivation.rs` differs from this branch (333 changed lines in `git diff HEAD origin/Mahnush_Verus --stat`),
  so the ESDK side there is not the same file as here.

## 9. Mutation checks (model only)

Record: `.agents/tasks/mpl-four-proofs/c04-mutation-run.txt`. Script: `.agents/tasks/mpl-four-proofs/c04-mutate.py`. Mutant files:
`.agents/tasks/mpl-four-proofs/mutants/c04/` (34 files). Each is a copy of the proof with one change to the model. `mpl/` was not edited.
Baseline: `24 verified, 0 errors`.

Result: **31 of 34 mutants rejected, 3 survived. All three survivors are explained. Four predictions were wrong (see below).**

- Rejected (31): enc/dec `add_data_key` skips the check; enc/dec `build` skips the check; `raw_dec` and `hier_dec` build the materials without `add_data_key`;
  `build` checks against the 256-bit suite for every suite; `build` checks only for 32-byte suites; the check compares the IV length instead
  of the key length; the check rejects only longer keys; the check rejects only shorter keys; the check has an off-by-one; the check is inverted;
  a wrong key length in the copied table (24 to 32); a non-AES key length (20) in the table and both spec columns; the generator gives one byte too many;
  the generator always gives 32 bytes; the exec generator allocates 16 bytes; the exec check uses `>`; the exec lookup is wrong for one suite;
  `enc_add_edk` changes the suite; `CloneMat` changes the length; `dec_add_data_key` drops the already-has-a-PDK guard; the invariant is weakened;
  `build` stores a PDK of length 0 after checking another; `run` ignores the steps; `step` drops `RawDec` (m27, see below); and four of the seven predicted-survivor mutants (s02 to s05).
- Survivor s01: `hier_enc` stores the generated key without `add_data_key`. The generated key has the suite length by construction, so the check on that path is
  redundant in the model. It shows that on the generation paths the length comes from `vec![0u8; suite.encryption_key_length()]` (H_VEC_LEN, H_FILL_SLICE), not from the check.
- Survivor s06: a no-op refactor of `generate_exec`. Cannot change any result.
- Survivor s07: the same wrong key length typed into the code table, both spec columns and the exec lookup. A consistent error in every copy. Verus has nothing to compare.
  The copy-check script catches it (5 failing checks). This is the copied-by-hand limit, as in C05 m21.
- Prediction differences (predicted to survive, rejected): s02 (pre-check weakened) is rejected by the liveness witness; s03 (a redundant guard removed) is rejected only because the
  hand-written induction in `lemma_hier_dec` follows the guard, a proof-script reason, not a semantic catch; s04 (`pdk_ok` removed from the closure's `ensures`) is rejected only because
  `theorem_c04_summary` restates it; s05 (consistent change of the code table and both spec columns) is rejected by the independent exec lookup.
- History of m27: on the first run the mutant that drops `RawDec` from `step` survived (the local lemma still held and the closure no longer contained the path). `lemma_step_dispatch`
  was then added, and the mutant is now rejected. The proof file changed after that run (baseline 23 to 24 verified).
- Extra: the copy-check script catches the copy-error mutants (m14, m15, m20, s05, s07). It does not catch model-logic edits.
- These checks cover edits to the model only, not edits to the shipped code.

Copy-check script: `.agents/tasks/mpl-four-proofs/c04-copy-check.py`, output `c04-copy-check.txt`: 75 of 75 checks pass. Assembler:
`c04-assemble.py` (builds the proof file from `c04-parts/` and the verbatim C05 block).

## 10. Suggested wording for the docs step (no score, rank, gap or quick-win change)

Proof status cell for C04 in the ranked table and in the "Proofs written" tables:

> `verification results:: 24 verified, 0 errors`. Proved (model level, not the shipped code, under stated hypotheses). The model has one function per code path that builds or
> accepts a plaintext data key in `mpl/` (four accept paths: enc/dec `add_data_key` and enc/dec `build`; the builder setters, `Clone`, both random generators, raw-AES and hierarchical
> `on_decrypt`, and the public `PlaintextDataKey::new`). It proves that `check_data_key_length` accepts exactly the suite key length, that the generators build the suite length, and that no sequence of the
> modeled paths, in any order and with any input length, gives a materials value whose PDK length differs from its suite's `encryption_key_length`. The suite table is copied from C05. It does NOT show that
> the shipped code has these properties, that the path list is complete (code reading), that the PDK is random or secret, that the spec is right, or that any threat is mitigated. The check is one `!=`, the four
> entry points are tested directly, and the esdk re-checks the length too (`key_derivation.rs:79,179`, not modeled). No gap found; no EXPECTED_FAIL. Not a duplicate of anything on `Mahnush_Verus`: see
> "C04 against Mahnush_Verus" in `docs/mpl-verification-targets.md`.
> Assumed (copied by hand): A_TABLE_COPY, A_SPEC_COLS_COPY. Assumed: A_FIT, A_OTHER_OK, A_ERR, A_LEN, A_RNG_FAIL, A_VSTD. Code reading: H_MODEL_MATCH, H_CLOSED, H_NO_MUT, H_SUITE_FIXED,
> H_BUILD_SAME_SUITE, H_BUILD_OTHER, H_ENC_DEC_SAME, H_GEN_SUITE, H_FILL_SLICE, H_VEC_LEN, H_RAW_DEC_LOOP, H_HIER_DEC_LOOP, H_NO_OTHER_PRODUCER, H_TABLE_ONLY.

Verus run line for `verus-proofs/README.md`: `~/verus/verus verus-proofs/c04_pdk_length_invariant.rs  # exit 0`.
Results row: `C04 | VR-2026-C04 / capability 1a | c04_pdk_length_invariant.rs | verification results:: 24 verified, 0 errors | 0 | Proved (model level)`.
Findings: none from C04 (observations O1 to O5 above, none a defect). Mutation line: "31 of 34 model mutants rejected; the 3 survivors are a redundant check on a generation path, a no-op refactor and a consistent copy error in every copy, all explained in `c04-mutation-run.txt`."
The BUG-02 history: the targets doc expected the pre-fix F1 and F2 failures to be gone. The model does not include the pre-fix code, so it does not re-prove that BUG-02 is the cause of the earlier failure.
