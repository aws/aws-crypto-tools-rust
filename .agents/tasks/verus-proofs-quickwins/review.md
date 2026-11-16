# Independent review: Verus quick wins (T02, C01, C02)

Reviewer did not write the proofs. Repo `esdk-native-mpl`, HEAD `66aba1c28c31` (equals baseline). Verus 0.2026.07.12.0b42f4c.
No proof logic, spec or assert was changed. Nothing was committed or pushed.

## Verdict

| ID | Status | Verus result line (my re-run) | Exit |
|---|---|---|---|
| T02 | Partly proved | `verification results:: 21 verified, 1 errors` | 1 |
| C01 | Proved, model level, under hypotheses A_ITER (A_DDB, A_NAME for `theorem_prod_*`) | `verification results:: 40 verified, 0 errors` | 0 |
| C02 | Proved, model level | `verification results:: 21 verified, 0 errors` | 0 |

No blocking defect and no proof defect found. All findings are about model fidelity, wording and line anchors.

## 1. Re-run versus saved logs

Run from the repo root (`~/verus/verus verus-proofs/<file>.rs`), the output of all three files is byte-identical to `logs/*.log` (`diff` empty). Run from inside `verus-proofs/` the only difference is the path prefix in diagnostics. No log is missing or stale, so no new log was saved. T02 fails only in `lemma_g1_spec_soundness_FAILS` (postcondition at `:771`). C01 prints trigger-selection notes (informational, no warnings, no errors).

After my comment-only edits (line counts unchanged: 849, 1630, 720) I re-ran the three files again: same three result lines.

### Non-vacuity spot checks (scratch copies in `/tmp/mut`, not in the repo)
| Mutation | Result |
|---|---|
| T02: drop the non-empty test in `step_version` | fails (4 postconditions) |
| T02: `pt.len() >= 32` in `step_key` | `19 verified, 3 errors` |
| C01: delete the `create-time` insert in `base_map` | `39 verified, 1 errors` |
| C01: `build_base` collision test replaced by `false` | `39 verified, 1 errors` (assertion fails) |
| C02: length test `==` replaced by `>=` | `20 verified, 1 errors`, copy_from_slice precondition fails |

These show the specs are not vacuous with respect to edits of the model. They say nothing about edits of the code.

## 2. Assumption, admit, external and verifier grep

Command: `grep -nE 'assume|admit|external_body|external|assume_specification|exec_allows_no_decreases_clause|verifier::'` over `verus-proofs/*.rs`. A wider grep for `verifier`, `axiom`, `#[`, `trusted`, `uninterp`, `opaque`, `spinoff`, `rlimit`, `ensures true`, `requires false` and body-less `spec fn` was also run.

| Hit | Where | Verdict |
|---|---|---|
| `c01_ec_roundtrip.rs:119` | header comment: "No `assume`, `admit`, ..." | Comment, states absence. OK |
| `c02_sign_fixed_len.rs:15-16` | header comment: nothing is assumed/admitted/external_body | Comment. OK |
| `c02_sign_fixed_len.rs:79` | header A1: vstd `assume_specification` for `copy_from_slice` | Comment naming a vstd axiom. It is in the README TCB table and the file header. I confirmed the vstd text (`vstd/std_specs/slice.rs`): requires equal lengths, ensures `final(dst)@ == src@`. OK |
| `c02_sign_fixed_len.rs:88, 96, 126` | A3/A4/section 4 comments: "assumed" | Comments. Listed in TCB (A3, A4). OK |
| `c02_sign_fixed_len.rs:132-133` | gap-closing note: would need `external_type_specification` and `assume_specification` | Comment about future work. OK |
| `t02_record_reconstruction.rs:84` | header comment | Comment. OK |
| `t02_record_reconstruction.rs:765` | doc comment: obligation is "NOT weakened, commented out, or assumed" | Comment. OK |

There is no `assume`, `admit`, `external_body`, `external`, `assume_specification`, `exec_allows_no_decreases_clause` or `verifier::` in code. There is no uninterpreted spec function. The only body-less functions are the four `Backend` trait methods in C02 (`:583-592`). They are exec trait declarations with no contract and are listed as A4. `broadcast use Set::lemma_map_by_contains` (T02 `:402`, C01 `:456`) is a vstd lemma, listed in the README TCB.

Unlisted hit used to hide an obligation: none.

Specs checked for vacuity:
- `ensures true` appears only on the C02 closures passed to `sign_fixed_len` from `ecdsa_sign` and `ecdsa_sign_digest`. This is intentional (closure with no contract, A3/A4). The witnesses use closures with real contracts.
- No `requires` is contradictory. Each `requires` is satisfiable: `enumerates` by `lemma_enum_exists` and `theorem_rt_decrypt_only_every_custom`; the C02 `call_requires` by the witnesses.
- `decreases` are honest and structural: `custom_fold`, `insert_custom` (`keys.len()`), `lemma_enum_exists_set` (`s.len()`), `lemma_fold_char`, `lemma_insert_custom`, and the C02 `while` loop (`MAX_SIGN_ATTEMPTS - attempt`). The C02 `for` loop relies on vstd's `Range` spec, which the README states (A2) and cross-checks with `sign_fixed_len_while`.
- `lemma_g1_spec_soundness_FAILS` is a real false statement, not an artifact: `lemma_g1_witness_accepted_without_fields` proves a counterexample exists.

## 3. Model versus code

Verified by script: all 9 (T02) and 12 (C01) string constants equal `attributes.rs:11-24`. C01's copy of the T02 model is byte-identical (diff empty).

### T02 vs `mpl/src/key_store/record.rs`
Faithful. Checked in code order: `get(type)` `:101`; type check `:108-116` (`!= ACTIVE && !starts_with(prefix)`); version source `:119-131` (ACTIVE reads `version`, else clones `type`); `strip_prefix(...).filter(!is_empty)` `:137-149`; `get(branch-key-id)` `:151-158`; custom EC loop `:161-162` calling `:79-91` (insert on `BTreeMap` keys, infallible, injective strip); `<[u8;32]>::try_from` `:164-172`; `build()` `:175-183` with `branch_key_materials.rs:173-189` (id empty then version empty, `required()` cannot fail because the setters store `Some`). Error order, and the empty-id error after the key-length error, match. All 7 error sites call `malformed()` which uses `Kind::InvalidMaterials`; `with_source` (`generated.rs:924`) does not change the kind. The empty-version builder branch is unreachable, as `lemma_empty_version_unreachable` says.

Discrepancies: none in control flow. Cosmetic: header says `malformed()` is at `:188-`, correct.

### C01 vs `encryption_context.rs`, `record.rs`, `branch_key_store.rs`
Faithful. `build_base` order matches: id empty `:44-49`, type empty `:51-56`, six inserts `:58-79` on keys none of which starts with `aws-crypto-ec:`, custom loop `:87-104`. `decrypt_only` checks the version first (`:141`) then builds (`:149`). `active` overwrites `type` and adds `version = "branch:version:" + v` (`:125-129`). `beacon` uses `build_base(.., "beacon:ACTIVE")`. Auth EC: `build_auth_ec` (`branch_key_store.rs:132-139`) is attributes plus `tablename`; KMS decrypt uses the equivalent `kms_ops.rs:49-65` (not modeled, in the KMS leg owned by T01). `item_from_ec_and_enc` (`:1089-1106`) and `record_from_ddb_item` (`:1141-1198`) are modeled as identity under A_DDB.

Line-anchor discrepancies (fixed in comments and README, see section 6):
- `EncryptionContextInput` is at `encryption_context.rs:19-37` (derive at `:18`), not `:20-38`.
- The collision `if` is `:91-102` (the `Err(..)` itself `:95-101`), not `:93-103`.
- `record_from_ddb_item` ends at `:1198`, not `:1200` (not changed; cosmetic).

### C02 vs `prim/src/ecdsa.rs`
Faithful for control flow. `MAX_SIGN_ATTEMPTS = 128` `:148`; `signature_len` 71/103 `:158-163`; loop `:185`, `sign_once()?` `:186`, length test `:187`, `copy_from_slice` `:188`, `Ok` `:189`, exhaustion `Err` `:192-194`; `check_sig_len` `:200-210`; `ecdsa_sign` order check, key parse, `SystemRandom::new`, loop `:230-238`; `ecdsa_sign_digest` order check, key parse, `digest()`, loop `:259-267`. `?` is desugared with a ghost push after the call (so the Err exit is logged). Not modeled, stated in the file: `format!` payloads, `SystemRandom::new`, the aws-lc-rs calls (A4). Call counting is a ghost log whose correctness depends on the single call site (A5), which I confirmed at `:186`. `sign_fixed_len` and `check_sig_len` have no callers outside `ecdsa.rs` (grep over `prim/`, `mpl/`, `esdk/`).

### Spec text and the two specific questions

**G1 (create-time / hierarchy-version).** Spec lines checked: `branch-key-store.md:531, :553, :574` (record lacking the defined fields MUST fail), `:596, :599` (EC MUST have `create-time`, `hierarchy-version`), `:677, :690, :692` (record MUST include them). Independent check of the code: `ATTR_CREATE_TIME` and `ATTR_HIERARCHY_VERSION` occur only on write paths (`encryption_context.rs:67, :77`, `branch_key_store.rs:711` in rotation, `:1098` when typing the item). A grep across `mpl/src`, `esdk/src`, `prim/src` found no read. `record_from_ddb_item` (`:1141-1198`) checks only that `enc` exists and is binary, and that other attributes are String or Number. `decrypt_branch_key` (`kms_ops.rs:172`) requires only `kms-arn`. `fetch_record` keys on `branch-key-id` and `type`. The reconstruction ignores both. **The shipped code does not enforce the clause.** Confirmed. Mitigation: the EC is the KMS AAD, so deleting a field from an item breaks decryption; only a record written without the fields (non-conforming writer) is accepted. Rotation copies the old EC, so such a record stays without the fields. Impact low, as the README says.

**BUG-08 (build_base collision Err, `encryption_context.rs:91-102`).** `insert` returns `Some` only if the key already exists in `ec`. The six base keys are `branch-key-id`, `type`, `create-time`, `tablename`, `kms-arn`, `hierarchy-version`. None starts with `aws-crypto-ec:`, and every inserted custom key does, so a base key is never hit. Two custom keys give the same prefixed key only if they are equal, which `BTreeMap` iteration never yields (`EncryptionContext` is a private-field newtype over `BTreeMap<String,String>`, `structures/encryption_context.rs:11`; `iter()` `:74`). `build_base` is private and has three callers. So the branch is unreachable in the shipped code. What is provable: `theorem_bug08_collision_iff_duplicate` shows, at model level, that Collision is returned exactly when the enumerated key sequence repeats a key. `theorem_bug08_collision_unreachable` follows under `enumerates` (A_ITER). A_ITER itself (std `BTreeMap::iter` yields each key once) and `format!` being concatenation are not provable here. The branch would become live if `EncryptionContext` stopped being a map. The case in the code comment (custom key already carrying the prefix) is not a collision: it is stored as `aws-crypto-ec:aws-crypto-ec:x` (`lemma_bug08_prefixed_custom_key_ok`).

## 4. README honesty

- Statuses match the logs: T02 `1 errors` is labeled Partly proved; C01 and C02 `0 errors`.
- The model-versus-code gap is stated plainly at the top of the README and per target.
- Wording that overstated or was imprecise (fixed): C01 was labeled plain "Proved" although every builder theorem has the hypothesis A_ITER and `theorem_prod_*` also A_DDB and A_NAME; C02's plain-language property said "never panics" without "in the modeled code"; the README said "matched the logs" without saying how.
- Weaker properties are labeled: `lemma_g1_spec_completeness`, `lemma_g1_code_ignores_fields`, `lemma_g1_witness_accepted_without_fields` are marked as code behavior, not the spec property.
- The README's "four breaks in T02, six in C01" mutation counts were not independently re-run in full; I re-ran five mutations (section 1), all caught.

## 5. Git

- `git -C R diff --quiet HEAD -- mpl prim esdk docs`: exit 0 (no change).
- `git -C R status --porcelain`: `?? .agents/tasks/verus-proofs-quickwins/` and `?? verus-proofs/`. Both are the new, allowed paths. Baseline file shows a clean tree before setup and the same two untracked paths.
- `git rev-parse HEAD` = `66aba1c28c319dd5b6dfa2b11607300d9d0955a1`, equal to the baseline. Nothing committed, nothing pushed.

## 6. Documentation fixes made by the reviewer

1. `README.md` and `c01_ec_roundtrip.rs` comments: collision branch anchor `:93-103` to `:91-102` (README line 200 and 115, C01 header `:35, :59`, `:707`).
2. `README.md` and `c01_ec_roundtrip.rs` comments: `EncryptionContextInput` anchor `:20-38` to `:19-37` (C01 `:58, :80, :710`).
3. `README.md` C01 status (section and results table): "Proved (model level)" to "Proved (model level, under hypotheses A_ITER; A_DDB and A_NAME for `theorem_prod_*`)". Same change in `summary.md`.
4. `README.md` C02 property: "never panics" to "does not panic in the modeled code".
5. `README.md` how-to-run sentence: now says an independent reviewer re-ran the files from the repo root and the output was byte-identical.
6. `README.md` G1 section: added the independent read-path check and the rotation note.

Line counts of the three `.rs` files are unchanged (849, 1630, 720), so all cited line numbers still hold.

## 7. Proof defects found but not fixed

None. Open observations, not defects:
- Only `fetch_record`/`record_from_ddb_item`/the reconstruction were checked for G1; `get_beacon_key` does not call the reconstruction at all (`branch_key_store.rs:868-900`), so the G1 clause is also unenforced there.
- Every result still depends on the human-reviewed correspondence tables. A later edit to `record.rs`, `encryption_context.rs` or `ecdsa.rs` is not detected.
- UUID v4 version check and the T02 YAML `branch-key-id` clause remain README open items; I agree with them.
