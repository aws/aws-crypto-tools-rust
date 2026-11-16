# Proof status docs: results

Repo `esdk-native-mpl`, branch MPL-Verus, HEAD d288750. Nothing is committed or pushed.

## 1. Proof re-runs (2026-11-15, Verus 0.2026.07.12.0b42f4c, from the repo root)

Command: `~/verus/verus verus-proofs/<file>.rs 2>&1 | grep "verification results"`

| ID | File | Result line (this re-run) | Same line in the log |
|---|---|---|---|
| T02 | `t02_record_reconstruction.rs` | `verification results:: 21 verified, 1 errors` (error: `lemma_g1_spec_soundness_FAILS`, postcondition not satisfied; exit 1 expected) | yes (`.agents/tasks/verus-proofs-quickwins/logs/`) |
| C01 | `c01_ec_roundtrip.rs` | `verification results:: 40 verified, 0 errors` | yes |
| C02 | `c02_sign_fixed_len.rs` | `verification results:: 21 verified, 0 errors` | yes |
| T03 | `t03_resolve_pinned_arn.rs` | `verification results:: 39 verified, 0 errors` | yes (`.agents/tasks/verus-proofs-t03-t05/logs/`) |
| T05 | `t05_kbkdf_fixed_info.rs` | `verification results:: 33 verified, 0 errors` | yes |

Log lines are saved in `log-result-lines.txt`. The README tables (`verus-proofs/README.md`, `README-t03-t05.md`) give the same five lines and the same status words.

## 2. Canonical wording (reused verbatim in every document)

Qualifier: `model level, not the shipped code, under stated hypotheses`.

| ID | Canonical status string |
|---|---|
| T02 | `Partly proved (model level, not the shipped code, under stated hypotheses): 21 verified, 1 errors` |
| C01 | `Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors` |
| C02 | `Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors` |
| T03 | `Proved (model level, not the shipped code, under stated hypotheses): 39 verified, 0 errors` |
| T05 | `Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors` |
| other targets | `None yet` (retired: `None (retired)`) |

Proof files: `verus-proofs/t02_record_reconstruction.rs`, `c01_ec_roundtrip.rs`, `c02_sign_fixed_len.rs`, `t03_resolve_pinned_arn.rs`, `t05_kbkdf_fixed_info.rs`.

Assumptions summary (one line each):

- T02: Verus, Z3, vstd `Seq`/`Map`/`Set` axioms; A_STR (`String` is `Seq<char>`, byte and char prefix tests agree); nine hand-copied string constants; the G1 soundness obligation fails on purpose.
- C01: A_ITER (`custom.iter()` yields each key once, the precondition of every builder theorem); A_STR; A_BLD; A_DDB and A_NAME for the `theorem_prod_*` results; the T02 model is copied into the file.
- C02: A1 (vstd `assume_specification` for `<[T]>::copy_from_slice`); abstract signing closure (A3); `Backend` trait without contracts stands for aws-lc-rs (A4); ghost call log checked by hand against `ecdsa.rs:185-191` (A5).
- T03: H_ORACLE, H_BUILD, H_CALLER, A_STR, A_MR; Discovery and MrDiscovery arms out of scope (BUG-04, T17).
- T05: the KBKDF output is an uninterpreted spec function (A_KDF), so the proof shows which arguments the primitive receives, not that the derived key is correct; A_STD, A_LBL.

Score rule (stated once in each targets doc): scores, ranks, coverage gaps, feasibility, severity and the quick-wins list record the pre-proof prioritization and were not changed. A model-level proof is not a proof of the shipped code. Coverage gaps will be recalculated when a proof is linked to the shipped code (for example with `cargo verus` on the crate or by moving the logic into `verus!`).

Findings (canonical one-liners):

- G1 confirmed formally (T02): the code accepts a branch-key record that lacks `create-time` and `hierarchy-version` (`lemma_g1_code_ignores_fields`, `lemma_g1_witness_accepted_without_fields`; the spec property fails as `lemma_g1_spec_soundness_FAILS`). The code is more permissive than the spec, never stricter.
- O1 DEV-ALIAS (T03): two byte-identical alias ARNs fail the code's MRK match, where the spec text matches. A documented deviation, stricter than the spec, unreachable for any configuration `build()` accepts.
- O2 (T03): the model of ARN validity accepts an ARN with empty partition, region and account, which is looser than the spec. No effect on the T03 property (the KeyId is the configured ARN either way). A conformance gap in config validation.
- F1 (T05): the spec does not state the KBKDF fixed-info layout `"aws-kms-hierarchy" || 0x00 || salt(16) || 00 00 01 00` (38 bytes, 32-byte output). A spec gap, not a code defect.
- BUG-08 (C01): the collision `Err` branch in `build_base` is dead if and only if A_ITER holds, and live if a key repeats. Model level.
- C02: the no-partial-write claim relies on vstd's own `assume_specification` for `copy_from_slice` (listed in the TCB).

## 3. Checker outputs


Commands (repo root): `python3 .agents/tasks/docs-sync-9955ecd/check_scores.py`, `check_citations.py`, `check_fn_defs.py`, `python3 .agents/tasks/docs-proof-status/check_proof_status.py --rerun`. Saved outputs: `baseline-*.txt` (HEAD), `after-*.txt` (working tree).

| Check | Result |
|---|---|
| `check_scores.py` | `PROBLEMS: none`; output identical to the HEAD run (`diff baseline-scores.txt after-scores.txt` empty) |
| `check_citations.py` | 2091 rows before and after; no new non-OK row. Only change: two bare table-cell references in `threat-model.md` moved with the new section (`:79` to `:116`, `:96` to `:126`; same NOFILE class as before) |
| `check_fn_defs.py` | `def-ok=338 def-mismatch=113` before and after |
| `check_proof_status.py --rerun` | `PROBLEMS: none`. Canonical strings present (merged 5x3, 01 3x3, 02 2x3); ranked rows differ from HEAD only by the added column (35, 27, 8); YAML blocks differ only by `proof_status`/`proof_file` (13, 27, 8); every `N verified, M errors` in the changed docs is one of the five real lines, always with the qualifier; proof files exist; live re-run of the five proofs matches; `git diff --quiet HEAD -- mpl prim esdk verus-proofs docs/bug-reports/RECHECK-main-620771c.md` exit 0; `git status` only under `docs/` and `.agents/tasks/docs-proof-status/`; format (no HTML, diagram, footnote, emoji; balanced fences) on 11 changed md files |
| pandoc | `/opt/homebrew/bin/pandoc docs/chorus/MPL-Threat-Model.md -o docs/chorus/MPL-Threat-Model.docx` exit 0, 49110 bytes, plain text starts "MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)". `.../MPL-Bug-Reports.md -o ...docx` exit 0, 45336 bytes, starts "MPL Native Rust: Bug Reports for Engineering Discussion". Both match a fresh conversion |

## 4. Files changed (docs only)

`docs/verification-targets.md`, `docs/verification-targets/01-threat-driven.md`, `02-capability-driven.md`, `04-validation.md`, `docs/threat-model.md`, `docs/completeness-audit.md`, `docs/spec-security-analysis.md`, `docs/bug-reports/BUG-08-build-base-collision-branch-unreachable.md`, `docs/bug-reports/README.md`, `docs/chorus/MPL-Threat-Model.md`, `MPL-Bug-Reports.md` and both `.docx`.

Decisions: the "Proofs written" section sits after the Refresh section (so the Refresh-table line citations in the threat model stay valid); later line citations to the targets docs in `threat-model.md` (5) and `completeness-audit.md` (G1 and G4-1 rows) were remapped with `linemap.py`. `04-validation.md` keeps its 18 checks and gets an addendum (P1 to P9) instead of renumbering. The `completeness-audit.md` line "No proof was run" describes the audit's own run and was left. Nothing committed or pushed.
