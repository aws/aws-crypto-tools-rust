# C05 notes (for the docs step)

Target: VR-2026-C05, the algorithm suite table. Score 2.40, estimated 1 day, agent route
mpl-verus-header-parsing-proofs. Score, rank, gap and quick-win are unchanged by this work.
Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `ad3522b`. Nothing under `mpl/`, `prim/`,
`esdk/` or `docs/` was changed. Nothing was committed.

## 1. Result

- Proof file: `verus-proofs/c05_algorithm_suite_table.rs` (untracked, 1153 lines, header sections 0 to 5).
- Command: `~/verus/verus verus-proofs/c05_algorithm_suite_table.rs` (Verus 0.2026.07.12.0b42f4c), exit 0.
- Exact result line: `verification results:: 22 verified, 0 errors`
- Run log: `.agents/tasks/mpl-four-proofs/c05-run.txt`
- Status word to use: **Proved (model level, not the shipped code, under stated hypotheses).**
- What it is, plainly: a consistency check of the suite table against the spec text. Two tables typed in by hand
  (one from `algorithm_suite.rs`, one from `algorithm-suites.md`) are compared field by field and Verus checks the
  comparison for all 11 rows. The domain is finite. The repository already has 22 tests for the same facts over the same
  domain (`mpl/tests/test_algorithm_suite_id.rs`). The proof adds the facts as lemmas over the model, plus a comparison
  with the prim and esdk length constants (also hand copies). It does not show that the spec is right, that callers use the
  table correctly, or that any threat is mitigated. C05 maps to no TM-MPL threat.

## 2. What is proved (all relative to the model and the items in section 3)

| Id | Theorem (in the file) | Statement |
|---|---|---|
| R1 | `theorem_table_refines_spec` | For each of the 11 suites the model of `specification()` equals the spec row: id, algorithm, mode, key length (bytes against bits), IV, tag, encryption KDF (algorithm and hash), key commitment, commit KDF with its hash and output length, asymmetric and symmetric signature algorithm, format version, suite data length. |
| R1 | `lemma_spec_table_consistent` | Spec side only: KDF input bits equal key bits; commit key 256 bits and 32 bytes; suite data present exactly for key-committing rows; format 2 exactly for those rows. Says nothing about the code. |
| R2 | `theorem_ids_injective` | Same id bytes imply same suite. |
| R2 | `theorem_ids_never_reserved` | No suite has `00 00`. |
| R2 | `theorem_spec_ids_unique`, `theorem_ids_unique_across_spec` | Spec ids are unique among the ESDK rows; the 11 ESDK ids differ from the 7 S3EC and DBE ids of the spec table and from `00 00`; the 7 differ from each other. |
| R3 | `theorem_all_complete_once_ascending` | `ALL` lists every suite once, in strictly ascending id order. |
| R3 | `theorem_from_id_bytes_inverse`, `_sound`, `_rejects_unknown` | `from_id_bytes(id_bytes(s)) == Some(s)`; a returned suite has the id asked for; `None` for `00 00` and for every id no suite has. |
| R4 | `theorem_commitment_consistent` | `commit_kdf` is Some, format version 2 and suite data length 32 hold together; otherwise None, 1 and 0. Commit KDF is HKDF-SHA-512 and equals the encryption KDF; data length equals key length. |
| R5 | `theorem_no_symmetric_signing` | No suite has a symmetric signature algorithm; asymmetric signing exactly for the four ECDSA suites (the spec has four ECDSA rows). |
| R5 | `theorem_key_length_agrees` | Key length is 16, 24 or 32; esdk `get_alg_suite` maps it to a prim `AesGcm`; that variant has the same key length; equals spec key bits / 8. |
| R5 | `theorem_vk_length_agrees`, `lemma_field_size_formula` | `verification_key_length()` is None for non-signing suites; for signing suites it equals `prim::field_size` of the matching curve (33 or 49) and equals 1 + ceil(bits / 8). |
| R6 | `theorem_c05_summary` | The conjunction of the above for an arbitrary suite. |

Note on the YAML property "verification_key_length == prim_field_size": proved in the model with both sides as hand copies.

## 3. Hypotheses and assumptions with evidence levels

Evidence levels: PROVED (checked by Verus in the file), ASSUMED (a premise, definition or hand copy), CODE READING
(a claim about shipped code that Verus does not see). No `assume`, `admit`, `external_body`,
`assume_specification` or uninterpreted function is in the file.

| Name | Level | Content |
|---|---|---|
| A_SPEC_COPY | ASSUMED, copied by hand | `spec_row` (11 rows x 14 fields) and `spec_other_id` (7 ids) typed from five tables of `spec/framework/algorithm-suites.md` (lines 183-212, 214-237, 239-262, 264-288, 290-314). Script check: 11 spec rows, 7 other ids, reserved-id text, and agreement with the shared constants block of `.kiro/agents/mpl-verus-header-parsing-proofs.md`. |
| A_CODE_COPY | ASSUMED, copied by hand | `code_row` (11 rows x 13 fields), the order of `all_at`, the constants 33 and 49 typed from `algorithm_suite.rs` :94-106, :144-305, :440-451. Script check: all 11 rows equal the Rust source. |
| A_PRIM_COPY | ASSUMED, copied by hand | `prim_key_length` 16/24/32 (`prim/src/lib.rs` :148-154), `prim_field_size` 33/49 (`prim/src/ecdsa.rs` :352-357), `get_alg_suite` (`esdk/src/message/body/mod.rs` :18-28), `curve_of` (`mpl/src/cmm/default_cmm.rs` :123-128, `esdk/src/suites.rs` :104-111). Script check: equal. |
| A_FMT | ASSUMED | spec "1.0" and "2.0" correspond to code 0x01 and 0x02. |
| A_NA | ASSUMED | spec "N/A" suite data length corresponds to code 0. |
| A_INT | ASSUMED | code fields are `usize` and `u8`, all values at most 49, no overflow. |
| A_FIND | ASSUMED (std) | `Iterator::find` over `slice::iter` returns the first match in index order; `find_from` is that definition. |
| A_VSTD | ASSUMED | Verus, Z3 and vstd Seq axioms. |
| H_MODEL_MATCH | CODE READING | `code_row` and the `c_*` functions have the values and bodies of the shipped code. Reading plus the copy-check script. |
| H_TABLE_ONLY | CODE READING | Every `AlgorithmSuite { .. }` struct literal is inside `specification()` (script: 11 literals, all in `algorithm_suite.rs`). Fields are private and the struct is `non_exhaustive`. A new constructor would break this. |
| H_ONLY_ESDK | CODE READING | `AlgorithmSuiteId` has one variant, `Esdk(..)`. S3EC and DBE suites are not implemented, so uniqueness across formats is checked only against the spec ids. |
| H_ALL | CODE READING | `ALL` is `&ALL_SUITES` with 11 entries in the modeled order; the no-wildcard match at :116-130 forces a new variant to be added. |
| H_FROM_ID | CODE READING | `from_id_bytes` is `ALL.iter().copied().find(..)` on `id_bytes()` and nothing else (:139-141). |
| H_CURVE_MAP | CODE READING | The curve maps are 1:1 and total. |
| H_AES_MAP | CODE READING | `get_alg_suite` is the only mapping from a suite key length to a prim `AesGcm` for message bodies. Keyrings take the length as a buffer size only. |
| H_NO_SALT | CODE READING | No consumer reads a salt length from the table (the table has none). |

## 4. Code and spec locations read

- `mpl/src/structures/algorithm_suite.rs`: :25-56, :69-92, :94-106, :116-130, :134, :139-141, :144-305, :312, :317-331, :344-357, :410, :440-451.
- `prim/src/lib.rs` :138-154; `prim/src/ecdsa.rs` :158-166 (`signature_len`, not modeled), :328, :352-357.
- `esdk/src/message/body/mod.rs` :18-28; `esdk/src/suites.rs` :104-111; `esdk/src/key_derivation.rs` :37 (`hkdf_key_len`).
- `mpl/src/cmm/default_cmm.rs` :123-128; `mpl/src/structures/decryption_materials.rs` :326-340; `mpl/src/structures/aes_wrapping_alg.rs` :22-36.
- `mpl/src/keyring/raw_aes_keyring.rs` :536; `mpl/src/aws_kms/hierarchical_keyring.rs` :976 (buffers sized from `encryption_key_length()`).
- `mpl/tests/test_algorithm_suite_id.rs` (22 tests, not modeled; same facts).
- `spec/framework/algorithm-suites.md`: Supported Algorithm Suites :183-212; Encryption Key Derivation Settings :214-237; Encryption Settings :239-262; Commit Key Derivation Settings :264-288; Signature Settings :290-314; Structure :406-583.

## 5. What is not shown

- That the shipped code has these properties. The code is not inside `verus!` and nothing detects an edit to `mpl/`.
- That the spec text is correct. The spec table is taken as given.
- S3EC and DBE suites (only their ids are modeled), and the spec salt length column (the code has no salt field).
- How callers use the table: data-key length checks (C04), CMM suite selection, decrypt handling of an unknown id (T09, C07).
- Any property of aws-lc-rs, `prim::AesGcm` or `field_size` beyond the two constant tables copied from prim.
- That a copy error is absent. Verus compares two copies. A consistent error in both survives (mutant m21). The copy-check
  script is the only thing that compares the copies with the sources, and it is a script, not a proof.

## 6. Findings

No finding. No EXPECTED_FAIL obligation was written, because the table equals the spec text for every row and the code
shows no gap. Observations that are not findings:

- O1. The table and the spec agree on all 11 ESDK rows, including the points a reader might doubt: `05 78` and `04 78` carry
  format 2 and suite data 32 and the commit KDF is HKDF-SHA-512; `02 14` is the only SHA-256 ECDSA suite; no suite has a
  symmetric signature algorithm.
- O2. The doc comment on `id_bytes` says the id is "unique across the suites of every format". Only the ESDK format exists in the
  code. Uniqueness across the other formats is proved only for the spec ids, not for code.
- O3. The spec file header says `Version 0.4.0`, but its changelog lists `0.5.0` as the newest entry. A document nit in the spec
  submodule, no effect on the proof.
- O4. Low added value, stated plainly: the 22 existing tests cover the same finite domain. The proof is a regression guard that
  restates them as lemmas and ties them to the prim and esdk constants. It would not catch an edit to the code.

## 7. Duplicate check: C05 against Mahnush_Verus

(Use as the section "C05 against Mahnush_Verus" in `docs/mpl-verification-targets.md`, same form as "T04 against Mahnush_Verus".)

Result of the duplicate check: **C05 does not duplicate anything on `Mahnush_Verus`.** Ref read: `origin/Mahnush_Verus` at `8d6381e`
(the tip used for the C03, T04 and T06 records). It was read with `git grep`, `git ls-tree`, `git diff` and `git show` only. Nothing was
merged, checked out or modified.

- **No Verus in `mpl/` there.** `git grep -l 'verus!' origin/Mahnush_Verus -- mpl` returns nothing. The files that use `verus!` are in `esdk/`,
  `prim/`, `verification/` and `docs/`; none is in `mpl/`.
- **Same code.** `git diff HEAD origin/Mahnush_Verus --stat -- mpl/src` is empty, so `algorithm_suite.rs` is the same file there.
- **No `verus-proofs/` directory** there (`git ls-tree -r --name-only origin/Mahnush_Verus` has no such path).
- **Searches.** `git grep -n -E 'VR-2026-C05|\bC05\b' origin/Mahnush_Verus` has no hit. A search for `from_id_bytes`, `id_bytes`, `ALL_SUITES`,
  `verification_key_length` and `field_size` in `verification/`, `docs/`, `prim/src` and `esdk/src` finds no proof of the suite table. The hits
  are the `field_size` definition and doc comments in `prim/src/ecdsa.rs` (`:487`, `:511`, `:530`, `:550`; plain Rust outside `verus!`),
  `docs/verification-recommendations.md:245` (lists the "`signature_len`/`field_size` invariants hold" as a target of the VR-008 row, whose proof is
  the retry loop of `sign_fixed_len`, not the constants), and header parsing code in `esdk/src/message/header_types.rs:327-345` (reads the id bytes;
  no proof). `docs/verus-in-crate-migration-design.md:65` and `docs/verification-recommendations.md:247,313,335,724` mention `algorithm_suite.rs`
  only for the removed zeroization loop (VR-010, deferred) and the secret key types.
- **Overlap at the primitive level only, and complementary.** VR-009 proves `check_v2_key_lengths` and `identity_kdf_key_len_ok` in
  `esdk/src/key_derivation.rs` (`:31`, `:45`) with `suite_key_len` as an unconstrained input, and the prim half proves the `{16, 24, 32}` HKDF output
  decision in `prim/src/hkdf.rs`. VR-013 and VR-014 prove prim wrapper behavior. VR-006 and VR-008 prove AES-GCM buffer bounds and the ECDSA retry loop.
  None states what values the suite table gives for `encryption_key_length()`, `algorithm_suite_data_length()` or `verification_key_length()`.
  C05 supplies exactly that input fact (key length is 16, 24 or 32 for every suite; suite data length 32 only for committing suites) and does not
  re-prove any of them. `prim::AesGcm::key_length` (`prim/src/lib.rs:157`), `signature_len` and `field_size` are outside `verus!` there.
  C05 does not depend on any of them being on this branch.

## 8. Mutation checks (model only)

Record: `.agents/tasks/mpl-four-proofs/c05-mutation-run.txt`. Script: `.agents/tasks/mpl-four-proofs/c05-mutate.py`. Mutant files:
`.agents/tasks/mpl-four-proofs/mutants/c05/` (23 files). Each is a copy of the proof with one change to the model. `mpl/` was not edited.

Baseline: `22 verified, 0 errors`. Result: **21 of 23 mutants rejected, 2 survived. Both survivors were predicted and are explained.**

- Rejected (21): wrong key length; duplicated id; wrong commitment flag; reserved id `00 00`; wrong format version; wrong suite data length;
  wrong KDF hash; symmetric signature present; wrong curve; wrong `verification_key_length` constant; `ALL` order swapped; `ALL` missing a suite;
  wrong prim key length copy; wrong `get_alg_suite` copy; wrong spec id; wrong IV length; S3EC id colliding with an ESDK id; `from_id_bytes`
  search skipping the first entry; wrong spec commit hash; a consistent 160-bit key length in code and spec (caught by the 16/24/32 lemma);
  an id out of ascending order.
- Survivor m21: the same wrong id typed into both the code copy and the spec copy (`00 14` to `00 15`). The model is self-consistent, so Verus
  has nothing to compare. The copy-check script catches it. This is the copied-by-hand limit.
- Survivor m22: the refinement relation was weakened (the id comparison removed from `row_refines`). Verus proves what is stated and cannot see a
  missing field. Only a reader catches it. The header (R1) lists every compared field.
- Extra: the copy-check script flagged 21 of the 23 mutants. It did not flag m18 (search start) or m22 (weakened relation);
  those are model-logic edits, not copy errors. It also flagged m21, which Verus accepts.
- These checks cover edits to the model only, not edits to the shipped code.

Copy-check script: `.agents/tasks/mpl-four-proofs/c05-copy-check.py`, output `c05-copy-check.txt`: 49 of 49 checks pass.

## 9. Suite table model that C04 will copy

C04 needs only the suite key length (the data key length that `check_data_key_length` compares against). Copy this from
`c05_algorithm_suite_table.rs` (section 1, lines 245-284 and 286-356 for `code_row`), or only the one field:

```
Suite (11 variants, names as in EsdkAlgorithmSuiteId)   id     key_len (bytes)   data_len   fmt
AlgAes128GcmIv12Tag16NoKdf                              00 14  16                0          0x01
AlgAes192GcmIv12Tag16NoKdf                              00 46  24                0          0x01
AlgAes256GcmIv12Tag16NoKdf                              00 78  32                0          0x01
AlgAes128GcmIv12Tag16HkdfSha256                         01 14  16                0          0x01
AlgAes192GcmIv12Tag16HkdfSha256                         01 46  24                0          0x01
AlgAes256GcmIv12Tag16HkdfSha256                         01 78  32                0          0x01
AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256                02 14  16                0          0x01
AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384                03 46  24                0          0x01
AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384                03 78  32                0          0x01
AlgAes256GcmHkdfSha512CommitKey                         04 78  32                32         0x02
AlgAes256GcmHkdfSha512CommitKeyEcdsaP384                05 78  32                32         0x02
```

- Model type: `pub enum Suite` with these 11 variants; `pub struct CRow { id0, id1, enc, mode, key_len: usize, iv_len, tag_len, enc_kdf,
  commit_kdf, asym, sym, fmt, data_len }`; `pub open spec fn code_row(s: Suite) -> CRow`. The accessor `encryption_key_length()` is
  `code_row(s).key_len` (shipped: `AlgorithmSuite::encryption_key_length`, :378 of `algorithm_suite.rs`).
- Reusable lemma from C05: `theorem_key_length_agrees` (key length is 16, 24 or 32 and agrees with prim `AesGcm::key_length`).
  C04 should copy the table, restate that lemma, and list the copy in its header as "copied by hand from C05, which was copied by hand
  from `algorithm_suite.rs`" with the evidence level ASSUMED. Do not import the file; earlier proofs copy models into each file.
- If C04 uses a minimal table (id and key length only), the 11 key lengths are: 16, 24, 32, 16, 24, 32, 16, 24, 32, 32, 32 in the order above.

## 10. Suggested wording for the docs step (no score, rank, gap or quick-win change)

Proof status cell for C05 in the ranked table and in the "Proofs written" tables:

> `verification results:: 22 verified, 0 errors`. Proved (model level, not the shipped code, under stated hypotheses). A consistency check of the
> suite table against the spec text: the model of `specification()` equals each of the 11 ESDK spec rows; ids are injective, never `00 00`, and
> differ from the S3EC and DBE spec ids; `ALL` is complete, duplicate-free and ascending; `from_id_bytes` inverts `id_bytes`; key commitment,
> format version 2 and suite data length 32 hold together; no suite has a symmetric signature algorithm; key lengths and verification key lengths
> agree with the prim and esdk constants. It does NOT show that the shipped code has these properties, that the spec is right, or that any
> threat is mitigated. The 22 tests in `mpl/tests/test_algorithm_suite_id.rs` already cover the same finite domain. Not a duplicate of anything on
> `Mahnush_Verus`: see "C05 against Mahnush_Verus" in `docs/mpl-verification-targets.md`.
> Assumed (copied by hand): A_SPEC_COPY, A_CODE_COPY, A_PRIM_COPY. Assumed: A_FMT, A_NA, A_INT, A_FIND, A_VSTD. Code reading: H_MODEL_MATCH, H_TABLE_ONLY,
> H_ONLY_ESDK, H_ALL, H_FROM_ID, H_CURVE_MAP, H_AES_MAP, H_NO_SALT.

Verus run line for `verus-proofs/README.md`: `~/verus/verus verus-proofs/c05_algorithm_suite_table.rs  # exit 0`. Results row: `C05 | VR-2026-C05 / capability 1a | c05_algorithm_suite_table.rs | verification results:: 22 verified, 0 errors | 0 | Proved (model level)`.
Findings: none from C05. Mutation line: "21 of 23 model mutants rejected; the 2 survivors are a consistent copy error in both tables and a weakened relation, both explained in `c05-mutation-run.txt`."
