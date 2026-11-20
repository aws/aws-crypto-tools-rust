# Verus proofs T03 and T05: summary
Repo `esdk-native-mpl`, HEAD `35f24c9`. Verus 0.2026.07.12.0b42f4c, toolchain 1.96.0, macos_aarch64.
Full documentation: `esdk-native-mpl/verus-proofs/README-t03-t05.md`. Nothing was committed or pushed. No existing file was edited. `docs/verification-targets*.md` is left for the orchestrator.
Both proofs are about re-typed models of the shipped Rust, not the shipped code. The model-to-code link is a human-reviewed correspondence table in each file header.

## Results
| ID | File | Result line (log) | Exit | Status |
|---|---|---|---|---|
| T03 (VR-2026-T03, `kms_ops::resolve_key_store_arn`, pinned modes) | `esdk-native-mpl/verus-proofs/t03_resolve_pinned_arn.rs` | `verification results:: 39 verified, 0 errors` | 0 | **Proved** (model level; H_ORACLE, H_BUILD, H_CALLER, A_STR, A_MR) |
| T05 (VR-2026-T05, `branch_key_wrap::derive_branch_key` KBKDF fixed info) | `esdk-native-mpl/verus-proofs/t05_kbkdf_fixed_info.rs` | `verification results:: 33 verified, 0 errors` | 0 | **Proved** (model level; `kbkdf_spec` is uninterpreted) |

Grep for `assume`, `admit`, `external_body`, `external`, `assume_specification` and `#[verifier...]` outside comments found nothing in either file. No obligation fails on purpose.

## T03 in short
- Headline (`resolve_key_store_arn` exec `:1142`, `theorem_a` `:829`, `theorem_a2` `:840`): in `KmsKeyArn` and `KmsMrKeyArn` modes a successful call returns exactly the configured ARN, never the record's, for any compatibility predicate. Err has kind `Validation`.
- Exact Ok/Err (`theorem_b` `:851`, `theorem_c` `:864`, `theorem_d`/`theorem_e` `:877`/`:893`): `KmsKeyArn` accepts byte-equal ARNs. `KmsMrKeyArn` accepts non-alias ARNs that are byte-equal or MRK ARNs differing only in region.
- Weaker, conditional: `theorem_g` `:1088` (decrypt caller only, H_CALLER), `theorem_h` `:1274` (H_ORACLE), `theorem_i` `:920` (H_BUILD, A_MR), `lemma_code_vs_spec_text` `:718` (non-alias pairs only), the four witnesses (satisfiability only).
- Findings: O1 (code's MRK match rejects two identical alias ARNs, spec accepts; stricter than the spec, unreachable behind `build()`), O2 (config validation accepts ARNs with empty partition, region and account, and any resource type except `alias`; no effect on T03). No spec-faithful property was false.
- Not covered: Discovery and MrDiscovery arms (T17), `version_key` beyond the call, KMS-side authentication, panic-freedom of the shipped `pa[5]`/`pb[5]` indexing, `format!` and non-`kind` error fields, rollback.

## T05 in short
- `theorem_fixed_info_layout` `:393`: info is `label ‖ 0x00 ‖ salt ‖ 00 00 01 00`, 38 bytes. `derive_branch_key` `:485`: on Ok the key is `kbkdf_spec(Sha256, branch_key, fixed_info(salt), 32)`, so algorithm, length and key/info argument order are pinned. Every Err is `Cryptographic`.
- `wrap_kdf_leg` `:566`, `unwrap_kdf_leg` `:605`, `theorem_wrap_unwrap_same_kdf_input` `:651`: wrap and unwrap feed the primitive the same salt and info. Ciphertext under 60 bytes is rejected before the primitive is called.
- Weaker: `lemma_fixed_info_is_nist_shape` `:384` (compares two spec functions in the file), `theorem_fixed_info_salt_injective` `:418` (info string only), `theorem_wrap_unwrap_same_kdf_input` (same key only relative to uninterpreted `kbkdf_spec`), `witness_fixed_info_concrete` `:685` and `witness_distinct_salts_distinct_info` `:706` (non-vacuity), `witness_length_gate_boundary` `:722` (trivial, not counted as evidence).
- **Spec-derived:** HMAC-SHA-256, 32-byte key, branch key as KDF key, 16-byte salt, label `aws-kms-hierarchy`, same derivation on wrap and unwrap, ciphertext layout (`aws-kms-hierarchical-keyring.md:206-222, :301-320, :108-136`).
- **Code-derived:** the 0x00 separator, salt in the NIST Context position, `L = be32(256)` in bits, the 38-byte total, and that the primitive does not add L itself. The spec has no text on these.
- **Third-party TCB, not proved:** KBKDF and HMAC-SHA-256 correctness and aws-lc-rs. The proof shows what the primitive is given, not what it computes.
- Findings: F1 (spec does not state the fixed-info layout; suggest `label ‖ 0x00 ‖ salt ‖ 0x00000100`), F2 (literal `256` at `branch_key_wrap.rs:131` not tied to `DERIVED_KEY_LEN`), F3 (no known-answer test for `derive_branch_key` or a wrap ciphertext). No defect found.
- Not covered: KBKDF output, interop, RNG (T04), AES-GCM and AAD, version UUID parsing, zeroization, error text, whether the primitive can fail on valid input, timing.

## Commands run
```sh
# from esdk-native-mpl/ (repo root); logs saved under .agents/tasks/verus-proofs-t03-t05/logs/
~/verus/verus verus-proofs/t03_resolve_pinned_arn.rs   # exit 0, 39 verified, 0 errors
~/verus/verus verus-proofs/t05_kbkdf_fixed_info.rs     # exit 0, 33 verified, 0 errors
```
Mutation checks (scratch copies under `/tmp`, not in the repo): T03 six breaks, T05 eleven breaks. Verus failed on every one. They cover edits to the model only.
Checks made while writing the docs: the result lines were read from the two log files, theorem line numbers from `grep -n` on the proof files, and the `assume`/`admit`/`external`/`verifier` grep was repeated (no hits). The two proofs were not re-run by this step.

## Other notes
- `.agents/tasks/verus-proofs-quickwins/summary.md` does not exist in the workspace, so the format was taken from `esdk-native-mpl/verus-proofs/README.md`.
- `t03_resolve_pinned_arn.rs`, `t05_kbkdf_fixed_info.rs` and `README-t03-t05.md` are untracked in `esdk-native-mpl`.
