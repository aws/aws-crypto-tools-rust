# Verus Verification Targets — AWS Cryptographic Material Providers Library (native Rust)

> Pipeline artifact — Stage 3, Step 3 of 4 (merge, rank, assemble). **Refreshed for HEAD `9955ecd`** (branch `MPL-Verus`; `mpl/` and `prim/` identical to `origin/main` `620771c`; `esdk/` differs from `620771c` only by #188 and #189). The `620771c` refresh (previous version analyzed `a1e23d7`) is kept in §0.1.
> Inputs: `docs/mpl-verification-targets/01-threat-driven.md` (VR-2026-T01..T27), `docs/mpl-verification-targets/02-capability-driven.md` (VR-2026-C01..C08), `docs/mpl-threat-model.md` (TM-MPL-001..026), `docs/mpl-spec-security-analysis.md`, `docs/mpl-completeness-audit.md`, `docs/mpl-bug-reports/RECHECK-main-620771c.md`, `.agents/tasks/pipeline-rerun-620771c/scope.md`, `.agents/tasks/docs-sync-9955ecd/scores.md`, `.kiro/agents/mpl-verification-recommender.md`.
> Full per-target YAML lives in the two intermediate files. This document is the consolidated, ranked view. Validation: `docs/mpl-verification-targets/04-validation.md`. Proof-status record updated at HEAD `b94c871` (adds C03, which is partly proved in-crate on branch `Mahnush_Verus` and not on this branch, the C02 / VR-008 relation and BUG-10): no score, rank, coverage gap, feasibility, severity or quick-win changed.

## Refresh (HEAD 9955ecd)

This refresh applies the "Impact on verification targets" list of `docs/mpl-threat-model.md` (second pass, TM-MPL-001..026) and `docs/mpl-completeness-audit.md` (no missed threat; gap G1; editorial item G4-1). No threat rating changed and `mpl/` and `prim/` did not change, so a score moved only where the evidence for a property changed. IDs are stable; T08 and C06 stay retired. Per-target arithmetic is in `01-threat-driven.md` (Refresh section) and the capability decision is in `02-capability-driven.md` (Refresh section).

| ID | Kind | Old score (rank) | New score (rank) | Arithmetic and change |
|---|---|---|---|---|
| T27 | **New target** (TM-MPL-025, provisional) | — | **3.78** (14) | 2 × 0.9 × 0.7 × 3 = 3.78. Key-store calls and loop iterations per decrypt are bounded by the EDK list (verifies); no constant bound exists (expected FAIL). It ties T14 (3.78); T14 has the higher severity (3 against 2), so T14 stays rank 13 and T27 is rank 14 |
| T21 | **Re-scored** (TM-MPL-018) | 1.96 (22) | **2.24** (23) | Coverage gap 0.7 → 0.8; 2 × 0.8 × 0.7 × 2 = 2.24. Properties (g) stale in-flight mark never cleared, (h) fan-out-full waiter with no deadline, (i) panic under the state lock added, all expected FAIL. It now ties T16 (2.24, severity 2); the tie goes to the lower ID, so T16 is rank 22 and T21 rank 23 |
| T25 | Citations and scope (TM-MPL-024) | 1.44 (29) | 1.44 (30) | 3 × 0.6 × 0.4 × 2 = 1.44. `lib.rs:1564-1565` → `:1570-1571`, `:1655` → `:1661`, `into_keyring_handle` `:2054` → `:2059`. Scope adds the type-erased `Keyring::adopt` path: the Rust half (non-null unique `Box`) is provable, the C++ half (`EncryptionSDK.cpp:541-547`) is a caller obligation |
| T26 | Scope (TM-MPL-015) | 3.20 (14) | 3.20 (15) | 2 × 1.0 × 0.4 × 4 = 3.20. Adds F4 (expired `LocalCmc` entries resident until read) and F5 (un-wiped private-key `Vec` on the `ecdsa_generate_keypair` error return, `prim/src/ecdsa.rs:387`, `:391-392`). The gap was already 1.0 |
| T02 | Property, completeness audit G1 (TM-MPL-005) | 6.72 (2) | 6.72 (2) | 4 × 0.6 × 0.7 × 4 = 6.72. A branch key record MUST include `create-time` and `hierarchy-version`, otherwise the operation MUST fail (`branch-key-store.md:677`, `:690`, `:692`; MUST-fail sentences `:531`, `:553`, `:574`). Added to the property; expected FAIL. No new target. Still a quick win |
| T06, T14, T19, T22, T09, T01, T03 | Text only | unchanged | unchanged | T06: after a panic under the storm-tracking lock the consequence is a persistent `Internal` error. T14: a creation time in the future counts as fresh. T19: supplier input on decrypt is the unauthenticated message EC. T22: `NoMatchingDataKey` exposes provider info through `Debug` and `encrypted_data_keys()`. T09: `SharedCmm::send()` checks completeness only. T01, T02: rollback of an authentic older record is a non-goal. T03: Discovery on the encrypt path is outside its pinned-mode scope |
| C01 to C08 | None | unchanged | unchanged | No capability target was added, removed or re-scored. A capability sibling of T21 (a) for the storm-tracking builder bounds was considered and rejected (02, R17): it duplicates T21 (a) and would score 2 × 0.9 × 0.7 × 2 = 2.52 |

Other effects:

- **Ranks.** T27 is inserted at rank 14, so every target ranked 14 or lower moves down by one. T26 is rank 15 (was 14), T25 is rank 30 (was 29), C08 is rank 33 (was 32). Ranks 1 to 13 are unchanged.
- **Counts.** 33 active targets (was 32): 26 threat-driven (T01–T07, T09–T27) and 7 capability-driven (C01–C05, C07, C08); retired T08 and C06. Agent routing: mpl-verus-header-parsing-proofs ×20, mpl-verus-zero-panic ×8 (T27 added), mpl-verus-unsafe-ffi-safety ×5.
- **Quick wins** (score > 6.0 and effort ≤ 1 week) are unchanged: T02, C01, C02. T27 (3.78) and T21 (2.24) are below the threshold.
- **Threat coverage.** Every TM-MPL-001..026 is accounted for in §4 and §6: 23 have an active target (001..018, 021..025), 3 are fully excluded (019, 020 and the new 026, test-only loopback servers). The STRIDE table (§4) now counts 26 threats; it counted 24 before (completeness audit G4-1).
- **Sections changed.** Header and §0 (new IDs), this section, §0.1 (history note), §1 (re-sorted, T27 added, T21 re-scored), §2 (T27 added; T02, T26, T25 updated; ranks), §3 (T27 row; T21, T25, T26, T02 rows), §4 (26 threats), §5 (note), §6 (TM-MPL-026, TM-MPL-025, 001..026; the TM-MPL-018 partial-exclusion line now names T27 as well as T21 and T06), §7 (new findings). `04-validation.md` was rewritten for `9955ecd` after these edits (18 checks, one mapping fix).

## Proofs written (HEAD d288750)

Eight targets have a Verus proof in `verus-proofs/` (T02, C01, C02, T03 and T05 at HEAD `d288750`; T01 and T13 at HEAD `4964d66`; T04 at HEAD `d6e42d8`; run again with `~/verus/verus verus-proofs/<file>.rs` from the repo root, Verus 0.2026.07.12.0b42f4c). Each is a proof about a hand-written, re-typed model of the shipped Rust. None verifies the shipped code: the code is not inside `verus!`, is not compiled by Verus, and nothing detects a later edit to `mpl/` or `prim/`. The link between model and code is a correspondence table in each file header, reviewed by a human. Read every status as: the logic of the model is machine-checked; the model's fidelity to the code is audited, not checked. Sources: `verus-proofs/README.md` (T02, C01, C02, T01, T13, T04) and `verus-proofs/README-t03-t05.md` (T03, T05). This section also records C03, which has a different kind of status: in-crate, on the shipped prim code, on branch `Mahnush_Verus`, not on this branch (subsection "C03: in-crate proof on branch Mahnush_Verus" below). The wording of this paragraph applies to the eight proofs in the table.

| Target | Proof file | Result line (re-run) | Status | Assumptions |
|---|---|---|---|---|
| T02 | [`t02_record_reconstruction.rs`](../verus-proofs/t02_record_reconstruction.rs) | `verification results:: 21 verified, 1 errors` | Partly proved (model level, not the shipped code, under stated hypotheses). The one error is the intentional G1 obligation `lemma_g1_spec_soundness_FAILS`. | Verus, Z3, vstd `Seq`/`Map`/`Set` axioms; A_STR (`String` is `Seq<char>`); nine hand-copied string constants. |
| C01 | [`c01_ec_roundtrip.rs`](../verus-proofs/c01_ec_roundtrip.rs) | `verification results:: 40 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). | A_ITER (`custom.iter()` yields each key once; precondition of every builder theorem); A_STR; A_BLD; A_DDB and A_NAME for the `theorem_prod_*` results; T02 model copied into the file. |
| C02 | [`c02_sign_fixed_len.rs`](../verus-proofs/c02_sign_fixed_len.rs) | `verification results:: 21 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). | vstd `assume_specification` for `copy_from_slice` (A1); abstract signing closure (A3); `Backend` trait without contracts stands for aws-lc-rs (A4); ghost call log checked by hand (A5). |
| T03 | [`t03_resolve_pinned_arn.rs`](../verus-proofs/t03_resolve_pinned_arn.rs) | `verification results:: 39 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). Discovery and MrDiscovery arms are out of scope (BUG-04, T17). | H_ORACLE, H_BUILD, H_CALLER, A_STR, A_MR. |
| T05 | [`t05_kbkdf_fixed_info.rs`](../verus-proofs/t05_kbkdf_fixed_info.rs) | `verification results:: 33 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). The KBKDF output is uninterpreted, so this shows which arguments the primitive receives, not that the derived key is correct. | A_KDF (uninterpreted `kbkdf_spec`), A_STD, A_LBL. |
| T01 | [`t01_keystore_auth_ec.rs`](../verus-proofs/t01_keystore_auth_ec.rs) | `verification results:: 52 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). KMS and DynamoDB are modeled by assumptions, so the KMS leg is proved relative to A_KMS and A_DDB, not checked. Not a duplicate of C01: see "T01 and T13 against Mahnush_Verus and C01" below. | Assumed: A_KMS, A_DDB, A_NUM, A_NAME, A_ITER, A_ARN, A_STR, A_BLD. Premises: H_WF, H_ENUM. Code reading: H_SAME_EC. The C01 and T02 models are copied into the file. |
| T13 | [`t13_cache_identifier.rs`](../verus-proofs/t13_cache_identifier.rs) | `verification results:: 42 verified, 1 errors` | Partly proved (model level, not the shipped code, under stated hypotheses). The one error is the intentional BUG-06 obligation `lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL`. | Assumed: A_DIGEST_CR (SHA-384 modeled as an injective function), H_LEN_FITS (length-prefixed fix only). Code reading: H_MODEL_MATCH, H_BYTES, H_SCOPE_PAIRING, H_VERSION_NO_NUL, H_NO_DIGEST_ERROR. |
| T04 | [`t04_branch_key_wrap.rs`](../verus-proofs/t04_branch_key_wrap.rs) | `verification results:: 45 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). What is proved is the structure around the draws: on every call that returns Ok, two separate generator calls (salt 16 bytes, then IV 12 bytes); the salt feeds the KDF and the IV feeds AES-GCM; the output is salt, IV, version, ciphertext and tag, with 60 + n bytes (the 16 + n tail rests on A_AES). It does NOT prove that the salt or the IV is fresh, random or unique: that comes from the aws-lc-rs generator, which the model assumes only as A_RNG. Not a duplicate of anything on `Mahnush_Verus`: see "T04 against Mahnush_Verus" in `docs/mpl-verification-targets.md`. | Assumed: A_RNG (each call fills the whole buffer or fails; nothing about the values), A_KDF, A_AES, A_STD, A_VSTD, A_TYP, A_ALLOC. Premise only: H_RNG_DIFFERS. Not assumed, not used, not proved: A_RNG_FRESH. Code reading: H_MODEL_MATCH, H_AAD_PURE, H_NO_STATE, H_WIPE. |

Canonical status strings (the same text is in each YAML `proof_status` field and in the `Proof status` column):

- T02: Partly proved (model level, not the shipped code, under stated hypotheses): 21 verified, 1 errors
- C01: Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors
- C02: Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors
- T03: Proved (model level, not the shipped code, under stated hypotheses): 39 verified, 0 errors
- T05: Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors
- T01: Proved (model level, not the shipped code, under stated hypotheses): 52 verified, 0 errors
- T13: Partly proved (model level, not the shipped code, under stated hypotheses): 42 verified, 1 errors
- T04: Proved (model level, not the shipped code, under stated hypotheses): 45 verified, 0 errors
- C03: Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors
- C02, relation added (the C02 status string above is unchanged): Partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): retry bound, termination, guarded copy

**Scores are unchanged.** Scores, ranks, coverage gaps, feasibility, severity and the quick-wins list in this document record the pre-proof prioritization and were not changed by these proofs. A model-level proof is not a proof of the shipped code, and re-scoring would be arbitrary. Coverage gaps will be recalculated when a proof is linked to the shipped code (for example with `cargo verus` on the crate, or by moving the logic into `verus!`). The same holds for C03: its proof is on `Mahnush_Verus`, not on this branch, so C03 stays at 5.60, rank 5, coverage gap 0.7, and is still not a quick win. The same holds for T01 and T13: T01 stays at 8.96, rank 1, coverage gap 0.8, effort 2 weeks, not a quick win; T13 stays at 4.41, rank 9, coverage gap 0.7, effort 1 week, not a quick win. The same holds for T04: T04 stays at 4.48, rank 8, coverage gap 0.7, effort 1 week, not a quick win.

### C03: in-crate proof on branch Mahnush_Verus (not on this branch)

C03 (`prim::{hmac, digest, aes_encrypt, aes_decrypt, hkdf*, kbkdf_ctr_hmac}`, `DigestContext::finish`) has a different kind of proof from the eight above. Verus checks the real prim code, not a re-typed model. The proof lives on branch `Mahnush_Verus` of aws/aws-crypto-tools-rust (PR #103) as VR-013 and VR-014. It is **not on this branch**: `prim/` here equals `main` `620771c` and has no Verus annotation. Nothing from `Mahnush_Verus` was merged, checked out or modified; it was read with `git fetch` and `git show` and re-run in a detached worktree under `/tmp` that was removed afterwards. Read no status in this subsection as saying that the code on `MPL-Verus` is verified.

| Field | Value |
|---|---|
| Status | Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors |
| Commits | `ed4a81e` ("feat(prim): verus proofs for C03 wrappers (VR-013, VR-014)") and `43b9ff7` ("docs(verus): record VR-013 / VR-014 (pipeline target VR-2026-C03, BUG-07)"). Tip read for this record: `8d6381e`. The later commits `2d22937` and `8d6381e` change docs only, and no commit after `43b9ff7` touches `prim/` |
| Result line | `verification results:: 18 verified, 0 errors` (crate aws-mpl-primitives) |
| Re-run | At `8d6381e`, from `prim/`, with `PATH="$HOME/verus:$PATH"`: `cargo verus verify` (default features) and `cargo verus verify --no-default-features --features aws-lc-sys`. Both exit 0 and both print the line above. Our earlier review gave the same count at `43b9ff7`. The default-feature run also prints `1858 verified, 0 errors` for the vstd dependency; that line is not a C03 result |
| What 18 counts | Every verified function of the prim crate on that branch (VR-006, VR-008, VR-009 prim half, VR-013, VR-014), not only C03. The base `6b51de8` gave 10, so VR-013 and VR-014 added 8. Verus counts verification obligations (functions), not properties |
| Review | Our read-only review at `43b9ff7` (`.agents/tasks/review-vr013-vr014/report.md`): verdict "Consistent with gaps". At `43b9ff7` it found prim tests (92 tests and 8 doc-tests) and clippy passing, and byte-identical behavior against the base on 1443 transcript lines (differential run on aws-lc-rs 1.19.0, not the locked 1.18.1). Those runs were not repeated at `8d6381e`; nothing under `prim/` changed |
| Not run | FIPS build, test and Verus runs (cmake is missing; the base fails the same way) and the literal `make verus` (the equivalent `cargo verus` runs were done) |

What the proof states (all in `verus!` in the shipped crate; names are the verified cores that the public functions call):

| Shipped function | Core on `Mahnush_Verus` | Proved (Verus, in-crate) |
|---|---|---|
| `hmac` | `hmac_core` (VR-013) | `Ok` iff the output buffer has the tag length; on `Err` the buffer is unchanged; the copy happens only after the guard and in bounds |
| `digest` | `digest_core` (VR-013) | Same, against the digest output length |
| `DigestContext::finish` | `digest_finish_core` (VR-013) | Same, against the context's output length |
| `kbkdf_ctr_hmac` | `kbkdf_core` (VR-013) | `Err(Unavailable)` iff the algorithm lookup returns `None`; output length kept. Wrapper logic only |
| `generate_random_bytes` | `fill_random_core` (VR-013) | Totality; length kept. Adds little beyond A12 |
| `constant_time_equal` | `ct_equal_core` (VR-013) | Totality; the result is the `Ok`-ness of the aws-lc-rs comparison. Restates A13; no equality-semantics or timing claim |
| `aes_encrypt` | `aes_encrypt_core` (VR-014) | BUG-07(a), exported postconditions: key or nonce `Err` leaves exactly `old ++ message`; seal `Err` keeps the length `old + len(message)` and the prefix `old`; `Ok` gives length `old + len(message) + 16` with prefix `old` |
| `aes_decrypt` | `aes_decrypt_core` (VR-014) | BUG-07(b), under assumption A20: `Ok` implies `len(plain) == len(cipher)`; a longer plaintext buffer ends in `Err` that is not `PlainTooShort` |

Trusted base. 20 `assume_specification` entries (A1 to A20) in `prim/src/aws_lc_specs.rs` about aws-lc-rs digest, HMAC, KBKDF, random, constant-time and AEAD calls; 15 opaque `external_body` types; 8 uninterpreted spec functions; one ghost-only `AsRef` trait proxy (it needs `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]` and a `[lints.rust] unexpected_cfgs` entry). There is no `assume`, `admit`, `#[verifier::external]` function or `unsafe`, and no `requires` was added. No `assume_specification` carries a `requires`, so every aws-lc-rs call is assumed not to panic. Our review judged A1 to A20 TRUE against the aws-lc-rs 1.18.1 source (aws-lc-sys 0.45.0); the no-panic part of A5, A7 and A8 holds only if the underlying C calls succeed; the FIPS C side (aws-lc-fips-sys) was not read. A20 is the labeled assumption for BUG-07(b).

Gaps (what the status "partly" means):

- `hkdf` and `hkdf_expand` "`Ok` implies `len(okm)` in 16, 24 or 32" and "no listed function panics for any argument" are not proved end to end. VR-009 proves only the decision functions (`hkdf_key_len_ok`, `salt_size_core`, `no_salt_slice_core`); `Salt::new`, `extract`, `expand`, `fill` and `get_len` are unmodeled.
- `DigestContext::digest` (used by `ecdsa_sign_digest` and `ecdsa_verify_context`) calls `finish`, which can `expect`. That call is unmodeled; A5's no-panic is trusted only inside `digest_finish_core`.
- Adapters outside `verus!` are unproved: the `format!` error messages, `get_aes_alg`, `get_digest_alg`, the `DigestAlg` to `KbkdfCtrHmacAlgorithmId` match, and the "authentication tag did not match" text of `aes_decrypt`.
- `constant_time_equal` and `generate_random_bytes`: the proofs add little beyond the assumptions A13 and A12.
- BUG-07(a): the key/nonce `Err` buffer (`old ++ message`) and the seal-`Err` length and prefix are exported postconditions. The `Ok`-case order `old ++ ciphertext ++ tag` is an in-body `assert`, not exported, and the `+ 16` relies on A19. The tail bytes after a seal `Err` are not described (A18 says nothing about bytes).
- BUG-07(b) is assumption-relative (A20 matches aws-lc-rs 1.18.1 `open_separate_gather`'s equality check), not proved.
- Not covered: zeroization (the proof says nothing about wiping), `DigestContext::new`, `new_from_ecdsa`, `update`, `output_len`, the ECDSA wrappers (`check_sig_len`, `ecdsa_sign*`, `ecdsa_verify*`, `ecdsa_generate_keypair`, which belong to C02) and the hand-maintained tables `DigestAlg::output_len` and `AesGcm::key_length`.

Wording note. The documents on `Mahnush_Verus` call C03 "in-crate" without "partly" and, in places, call the `Ok`-case order proved. Our review recommended wording fixes there. This record uses "partly" and "in-body assert".

### Cross-branch status (MPL-Verus and Mahnush_Verus)

The two branches have diverged (merge base `5f2dc72`; 20 commits only on `MPL-Verus`, 47 only on `Mahnush_Verus` at `8d6381e`). Nothing was merged. `mpl/` source files are identical on both (only the `Cargo.lock` files differ); `prim/` and `esdk/` differ.

| Item | On `MPL-Verus` (this branch) | On `Mahnush_Verus` (`8d6381e`) |
|---|---|---|
| T01, T02, C01, T03, T04, T05, T13 | Proofs of models in `verus-proofs/` (model level, not the shipped code) | No `verus-proofs/` directory. For T01 and T13 no proof of any kind: see "T01 and T13 against Mahnush_Verus and C01" below. For T04 no proof of `wrap` in `mpl/`; the prim functions it calls (`generate_random_bytes`, `aes_encrypt`) have in-crate proofs there (VR-013(d), VR-014): see "T04 against Mahnush_Verus" below |
| C02 | Proof of a model (21 verified, 0 errors) | VR-008: the retry bound, termination and guarded copy are proved on the real loop (`sign_fixed_len_core`). C02 is partly superseded |
| C03 | No Verus in `prim/`; no proof | Partly proved in-crate as VR-013 and VR-014 |
| VR-006 (AES-GCM buffer bounds), VR-009 prim half (`hkdf` decision functions) | Not present | In-crate in `prim/` |
| Other `esdk` in-crate proofs | Not present | In-crate (69 verified in `esdk/` at `43b9ff7`); not examined for this record |

C02 and VR-008. The retry bound (at most 128 attempts), termination and the guarded `copy_from_slice` of `sign_fixed_len` are also proved on the real loop on `Mahnush_Verus` as VR-008. So that content of C02 is superseded. C02 is not a duplicate and is not demoted. It remains the only statement of T1 as a postcondition (at most 128 closure calls), T3 (no partial write: `Err` leaves the buffer unchanged, `Ok` writes one whole candidate), T4 (which `Err` exits exist), T5 (`check_sig_len`), T6 (the `ecdsa_sign*` wrong-length contract) and the three non-vacuity witnesses. VR-008 has no `ensures`, and `check_sig_len` and `ecdsa_sign*` are outside `verus!` there. Recorded status of C02: Proved at model level (unchanged); partly superseded by VR-008 (in-crate, `Mahnush_Verus`).

### T01 and T13 against Mahnush_Verus and C01
Result of the duplicate check: **neither T01 nor T13 duplicates anything on `Mahnush_Verus`.** Ref read: `origin/Mahnush_Verus` at `8d6381e` (the tip used for the C03 record). It was read with `git grep`, `git ls-tree` and `git show` only. Nothing was merged, checked out or modified.
- **No Verus in `mpl/` there.** `git grep -l 'verus!' origin/Mahnush_Verus -- mpl` returns nothing. The only files under `mpl/` that mention `verus` at all are `mpl/Cargo.lock` and `mpl/test-server/Cargo.lock`. The key-store code (`mpl/src/key_store/branch_key_store.rs`, `kms_ops.rs`) and `mpl/src/aws_kms/cache_entry_identifier.rs` are plain Rust there, the same as here.
- **Where `verus!` is used there.** `esdk/src/key_derivation.rs`, `esdk/src/secret.rs`, `esdk/src/message/` (`header.rs`, `header_types.rs`, `serialize_functions.rs`, `v1_header_body.rs`, `body/body_aad.rs`, `body/body_decrypt.rs`, `body/body_encrypt.rs`), `prim/src/` (`aws_lc_specs.rs`, `ecdsa.rs`, `hkdf.rs`, `lib.rs`) and the model files under `verification/`. None is in `key_store/` or `aws_kms/`.
- **No `verus-proofs/` directory.** `git ls-tree -r --name-only origin/Mahnush_Verus` has no such path. The only match for `verus-proofs` is `docs/verus-proofs-report.md`.
- **The in-crate proofs there do not cover these targets.** `docs/verus-proofs-report.md` lists VR-006 (AES-GCM panic freedom), VR-008 (ECDSA fixed-length signing), VR-009 (HKDF and key-derivation lengths), VR-013 (prim wrapper length contracts) and VR-014 (AES buffer effects). None concerns key-store encryption contexts, KMS AAD or cache identifiers.
- **Searches.** `git grep -w 'T01\|T13\|BUG-06' origin/Mahnush_Verus` has no hit. `git grep -n -i 'cache_entry_identifier\|build_cache_identifier'` finds only the `mpl/src/aws_kms/` definition and call sites, the test `esdk/tests/test_error_ux.rs:231`, `:242` (it calls `build_cache_identifier`; it is not a proof), and `docs/verus-in-crate-migration-design.md:66`, `:147`. Those two lines list `cache_entry_identifier` as a candidate for a future in-crate proof. They are a plan, not a proof. `git grep` for `build_auth_ec`, `kms_aad`, `build_authenticated_encryption_context` and `item_from_ec_and_enc` (outside `docs/`) finds only `mpl/src/key_store/branch_key_store.rs` and `kms_ops.rs`.

T01 versus C01 (same branch, `verus-proofs/c01_ec_roundtrip.rs`, 40 verified, 0 errors). T01 copies the C01 model unchanged and does not re-prove it. C01 proves that the builders in `encryption_context.rs` and the record reconstruction in `record.rs` are inverses, with the stored item treated as a set operation (`stored_attrs`). C01 does not model KMS, the DynamoDB attribute mapping or `kms_ops.rs`. New in T01 (proved at model level, except where marked code reading):
1. The KMS-AAD side. `kms_ops::build_authenticated_encryption_context` (`kms_ops.rs:49`) is a separate function from `DynamoDbKeyStore::build_auth_ec` (`branch_key_store.rs:132`). T01-A proves they return the same EC for every record attribute map (under the iteration assumption A_ITER), and T01-C proves that the AAD the reader builds equals the write-time EC.
2. A symbolic model of the three KMS calls the key store makes (GenerateDataKeyWithoutPlaintext, ReEncrypt, Decrypt) under the assumption A_KMS, with the claim that one local EC goes to both the KMS call and `item_from_ec_and_enc` (H_SAME_EC, code reading).
3. `item_from_ec_and_enc` and `record_from_ddb_item` as loops over any iteration order, over an AttributeValue model (S, N, B, other). This replaces C01's set-operation shortcut. The S, N and B mapping is lossless, and the reader EC never contains `enc`.
4. `VersionKey` (rotation), which C01 does not cover.
5. The authenticity theorem T01-E: if the read passes KMS Decrypt, the EC the reconstruction uses equals the EC the ciphertext is bound to.
T01 overlaps T02 only through the T02 reconstruction model that C01 already copies. The T02 findings (G1) are unchanged.
### T04 against Mahnush_Verus
Result of the duplicate check: **T04 does not duplicate anything on `Mahnush_Verus`.** Ref read: `origin/Mahnush_Verus` at `8d6381e` (the tip used for the C03 record). It was read with `git grep`, `git ls-tree` and `git show` only. Nothing was merged, checked out or modified.
- **No Verus in `mpl/` there.** `git grep -l 'verus!' origin/Mahnush_Verus -- mpl` returns nothing. `mpl/src/aws_kms/branch_key_wrap.rs` is plain Rust there, and it draws the salt and the IV at `:164` and `:170`, the same lines as here.
- **No `verus-proofs/` directory.** `git ls-tree -r --name-only origin/Mahnush_Verus` has no such path. The files that use `verus!` are in `esdk/`, `prim/`, `verification/` and `docs/`; none is in `mpl/`.
- **Searches.** `git grep -n -E 'TM-MPL-012|VR-2026-T04|\bT04\b' origin/Mahnush_Verus` has no hit. `git grep -n -i 'branch_key_wrap'` finds the source, the call sites in `hierarchical_keyring.rs` (`:686`, `:712`), tests in `mpl/tests/test_aws_kms_hierarchical_keyring.rs` (including `wrap_two_calls_produce_distinct_ciphertexts`, `:1168`; a test, not a proof) and three documents: `docs/verification-recommendations.md:354` (lists the `try_into().expect` calls on salt, IV and version as a panic site), `docs/verus-in-crate-migration-design.md:66` and `:147` (list `branch_key_wrap` as a candidate for a future in-crate proof) and `docs/verus-proofs-report.md:651-652`, `:678` (the BUG-07 caller impact, code reading, \"no mpl-side proof\"). Those are plans, tests or code reading, not proofs of `wrap`.
- **Overlap at the primitive level only.** VR-013(d) proves in `prim/src/lib.rs` that `fill_random_core` (under `generate_random_bytes`) has no panic path and keeps the buffer length, and claims nothing about randomness (`docs/verus-proofs-report.md`, \"`generate_random_bytes` is totality only\"). That matches the length half of T04's assumption A_RNG. VR-014 proves the `Vec` effects of `aes_encrypt` on every path, including `Ok` giving old length plus message length plus 16, under its own aws-lc-rs assumptions. That is the in-crate counterpart of T04's assumption A_AES. Neither proves anything about `wrap`, the order of the two draws, the data flow into the KDF and AES, or the 60 + n output layout. T04 does not re-prove either one and does not depend on them being on this branch.
### Findings from the proofs

- **G1 confirmed formally (T02).** The code accepts a branch-key record that lacks `create-time` and `hierarchy-version`: the outcome is identical with or without them (`lemma_g1_code_ignores_fields`, `lemma_g1_witness_accepted_without_fields`), and the spec property fails as `lemma_g1_spec_soundness_FAILS`. The code is more permissive than the spec, never stricter (`lemma_g1_spec_completeness`).
- **O1, DEV-ALIAS (T03).** Two byte-identical alias ARNs fail the code's MRK match, where the spec text matches. This is a documented deviation, stricter than the spec, and unreachable for any configuration `build()` accepts (H_BUILD).
- **O2 (T03).** The model of ARN validity accepts an ARN with empty partition, region and account, which is looser than the spec. It does not affect the T03 property (the KMS `KeyId` is the configured ARN either way). It is a conformance gap in config validation.
- **F1 (T05).** The spec does not state the KBKDF fixed-info layout `"aws-kms-hierarchy" || 0x00 || salt(16) || 00 00 01 00` (38 bytes, 32-byte output). This is a spec gap, not a code defect.
- **T01: no gap found at model level.** The write-time EC, the EC KMS binds (the AAD) and the EC the reconstruction reads are equal for a record written under one EC, and KMS Decrypt with that AAD returns the generated key (T01-C, `theorem_three_way`). Nothing is left failing. The KMS leg rests on the assumption A_KMS (KMS binds the EC given at generate and at the ReEncrypt destination, and accepts Decrypt only for an equal EC), which Verus does not check. The claim that `create_key` and `version_key` pass one EC to both KMS and `item_from_ec_and_enc` (H_SAME_EC) is code reading.
- **T01, O1 (code reading plus the proved agreement).** The reconstruction reads its attributes from `build_auth_ec` (`branch_key_store.rs:132`), while KMS authenticates `build_authenticated_encryption_context` (`kms_ops.rs:49`). They are two separately written functions with no shared code. T01-A proves they agree today. An edit to one alone, for example dropping `tablename`, would let the reconstruction read attributes KMS did not authenticate. Verus rejects six mutants of the model (a dropped `tablename` in either builder, an item that keeps `tablename`, a Decrypt that accepts any AAD, a ReEncrypt that checks the wrong EC, a rotated ACTIVE EC that keeps the old type; record in `.agents/tasks/t01-t13/t01-mutations.txt`). These checks cover edits to the model only, not edits to the code.
- **T01, O2 to O5.** O2 (proved, `theorem_sn_tag_not_authenticated`): the DynamoDB S or N tag is not authenticated, and no consumer sees it. O3 (proved at model level): an item attribute named `tablename` is ignored and replaced by the reader's name in both builders. O4 (proved): T01 holds for items with or without `create-time` and `hierarchy-version`, so G1 stays a T02 finding. O5: rollback of an authentic older record is outside the property (TM-MPL-005 non-goal), because an older record's EC is genuine and T01-E accepts it.
- **BUG-06 confirmed formally (T13).** At model level the cache identifier preimage of `build_cache_identifier` is injective for the two call shapes if and only if every input field is free of `0x00` (`theorem_t13_iff`; `theorem_t13_iff_identifier` for the identifiers, under A_DIGEST_CR for the if half; the only-if half needs no assumption). The BUG-06 collisions are proved for the encrypt scope and for the decrypt scope (`lemma_bug06_witness_collides`). The spec property for all inputs, with no NUL precondition, is the intentional expected-FAIL obligation `lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL` (postcondition not satisfied at `t13_cache_identifier.rs:1019`). `lemma_bug06_failing_claim_is_false` shows the claim is false, not only unproved. The obligation is not weakened, assumed or commented out.
- **T13, fix options at model level.** The NUL-free precondition (BUG-06 fix option 1) gives injective identifiers under A_DIGEST_CR (`lemma_nul_free_precondition_gives_identifier_injectivity`). A length-prefixed encoding (fix option 2) is injective for all inputs with no NUL precondition, under A_DIGEST_CR and H_LEN_FITS (every field shorter than 2^32 bytes, which a real fix must check), and the BUG-06 pairs separate (`lemma_lp_*`, `theorem_lp_*`). This is a model of a proposed fix, not a statement about the shipped code. Encrypt and decrypt identifiers never coincide (`lemma_scope_separation`), and the pairing of scope byte and version (H_SCOPE_PAIRING, code reading) is needed for part of the proof (`lemma_pairing_is_needed`).
- **T13, limits (code reading).** The version string is a hyphenated UUID and cannot contain `0x00` (H_VERSION_NO_NUL), so in the realistic form the NUL-free condition is on the partition id, the logical key store name and the branch key id (`theorem_t13_iff_realistic`). The only-if direction builds a colliding partner as a tuple of byte fields. When the NUL is in the partition id, the partner's name takes the bytes after the NUL, which may not be valid UTF-8, so the proof does not decide that every NUL-bearing configuration has a realizable partner (H_BYTES). The ASCII BUG-06 examples do exist. The proof does not show that a deployment can be configured to collide (BUG-06 states the preconditions: a Shared cache and attacker-influenced NUL-bearing values). The layout is modeled as shipped and equals the layout the spec mandates, so the defect is in the spec text too.
- **T04: no gap found at model level.** On every call that returns Ok, `wrap` makes two separate generator calls, the 16-byte salt and then the 12-byte IV (a call can fail before or after the draws). The salt goes to the KDF and the IV to AES-GCM, and the output is `salt ‖ IV ‖ version ‖ ciphertext ‖ tag` with `60 + n` bytes (`t04_branch_key_wrap.rs`, R1 to R4; the `16 + n` tail rests on A_AES). No expected-FAIL obligation is included, because no code gap against the spec steps S1 to S6 was found. Every `ensures` is partial correctness (`r is Ok ==> ...`): nothing proves that `wrap` can return Ok.
- **T04, what is not proved (TM-MPL-012).** The proof does not show that the salt or the IV is fresh, random, unpredictable or unique, and it does not show that two calls use different salts or IVs. Freshness comes from the random number generator in aws-lc-rs (`rand::fill`, called by `generate_random_bytes`), which a model must assume. The model assumes only A_RNG: each call fills the whole buffer or fails, and each successful call is logged once, with nothing assumed about the values. A generator that returns zeros every time meets A_RNG (`toy_generate_random_bytes`). A_RNG_FRESH (uniform, independent draws) is not assumed, not used and not proved. The collision bound for random salts and IVs and the yearly rotation advice of TM-MPL-012 stay a probabilistic argument. The only distinctness result is conditional (R8): if the draws of two calls differ (H_RNG_DIFFERS, a premise that is never established), the outputs differ. `wrap_twice` shows that two calls use four distinct log positions, which does not mean four different values.
- **T04, limits.** The `60 + n` length rests on A_AES, and the shipped `debug_assert_eq!` (`branch_key_wrap.rs:209`) that would catch a violation is compiled out in release builds. `unwrap` parses the version field but never uses it (`_version`, `:254`), so R6 and R7 show only that the layout carries it, and they cover the layout, not the plaintext round trip. The ghost log covers one call chain, and the aws-lc-rs generator is process-global (H_NO_STATE, code reading). The wiping of the derived key (H_WIPE) is code reading, not proved.
- **T04, O1 (code reading, low, not a proof obligation).** If `aes_encrypt` returns Err after it has appended the message, `output` can hold a clear copy of the data key, and `wrap` drops it as a plain `Vec<u8>` without wiping it. The two argument-shape checks cannot fail in `wrap` (types), so only a failing seal reaches this; which inputs make aws-lc-rs fail was not examined. The model has no memory contents, so no honest expected-FAIL obligation can be written for it. This is the `wrap` caller impact already recorded under BUG-07(a) and T26.
- **T04, mutation checks.** Verus rejects 18 of 19 mutants of the model (swapped offsets, one generator call reused for both draws, a zero salt or a zero IV in the KDF or AES call, swapped call order, a wrong length constant, an ignored salt-draw failure and others; record in `.agents/tasks/t04-verus/mutations.md`). One survives: a `wrap` that always returns Err (MA), because every `ensures` is partial correctness. These checks cover edits to the model only, not edits to the code.
- **BUG-08 (C01).** The collision `Err` branch in `build_base` is dead if and only if A_ITER holds (a `BTreeMap` yields each key once), and live if a key repeats. Model level.
- **C02 assumption.** The no-partial-write claim relies on vstd's own `assume_specification` for `<[T]>::copy_from_slice`, listed in the proof's TCB.
- **BUG-07(a), prim side (C03, VR-014; not on this branch).** On `Mahnush_Verus` Verus proves that `aes_encrypt` appends the plaintext to the caller's buffer before the key, nonce or seal can fail: a key or nonce `Err` leaves exactly `old ++ message`, and a seal `Err` keeps the length `old + len(message)` and the prefix `old`. The `Ok`-case order `old ++ ciphertext ++ tag` is an in-body assert and the `+ 16` relies on A19. BUG-07(b) is recorded relative to A20, not proved.
- **BUG-07 caller impact (code reading, no proof; see the BUG-07 report, "Impact on callers").** mpl calls `aes_encrypt` at `RawAesKeyring::wrap_data_key` (`raw_aes_keyring.rs:163`) and `branch_key_wrap::wrap` (`branch_key_wrap.rs:199`) with a plaintext data key in a plain `Vec<u8>`. After a key or nonce `Err` the key stays in that buffer (proved in prim by VR-014 on `Mahnush_Verus`, not on this branch), and the caller drops it un-wiped (code reading). It cannot reach an EDK, a return value or an error message. The failure cannot fire today: key and IV sizes are fixed by type in `wrap`, and the raw-AES wrapping-key length is checked at `RawAesKeyringBuilder::build` (`raw_aes_keyring.rs:369-379`). Severity Low (confidentiality). In the ESDK frame scratch buffer the plaintext is user data (Informational/Low). BUG-07(b) is unreachable from in-repo callers, which size the plaintext buffer exactly. VR-014 says what prim leaves in the buffer; what the callers do with it is outside C03 and belongs to T26 (F2).
- **BUG-10 (new, Low, code reading).** `RawAesKeyring::on_decrypt` (`raw_aes_keyring.rs:471`, wrong-length `continue` at `:489-494`) drops an authenticated plaintext data key un-wiped, and `branch_key_wrap::unwrap` (`:275`) holds a plain `Vec<u8>` and returns it bare. It maps to TM-MPL-015 and T26 (sites F1 and F3, already listed as known residuals; no score changed). It is not part of BUG-07, it is not proved, and C03 does not cover it: the proof is of prim, and these buffers are in mpl.
- **C02 versus VR-008.** See "Cross-branch status": C02 is partly superseded, not a duplicate.

### Next steps for the proofs

- Link each proof to the shipped code (`cargo verus` on the crate, or move the logic into `verus!`), then recalculate its coverage gap.
- Owner decisions: enforce `create-time` and `hierarchy-version` on a read path (G1); state the KBKDF fixed-info layout in the spec (F1); decide whether config validation should reject ARNs with empty parts (O2).
- Add a CI step that runs the proof files and fails on any change to the result lines (T02 is expected to show `1 errors` until G1 is fixed).
- C03: decide how the in-crate prim proofs reach this branch (merge or port `prim/` and add Verus to the build). Not done, and an owner decision. Until then every C03 statement in these documents is about `Mahnush_Verus`, not about the code here.
- C03 on `Mahnush_Verus`: the wording and test fixes recommended by our review (`.agents/tasks/review-vr013-vr014/report.md`, "Recommended fixes") are for the owner of that branch.

## 0. Methodology notes

- **Formula.** `Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`. Every score was recomputed from its factors (see 04-validation check 5).
- **Two feasibility scales.** Threat-driven targets take Severity and Feasibility from the primary threat's rating (Critical/High/Medium/Low = 4/3/2/1; Likelihood Low → 0.4, Medium → 0.7). Capability-driven targets use the consequence of the latent defect for Severity and reachability for Feasibility (1.0 all inputs, 0.7 caller-chosen input/config, 0.4 only on regression or no in-repo caller).
- **New gap level 0.4**: near-exhaustive tests plus a runtime check that enforces the same property on the production path (used for T09, T15).
- **Combined tie-break.** Score descending, then higher severity, then origin (T before C), then target ID.
- **No `unsafe` in `mpl/src` or `prim/src`** (`\bunsafe\b` has no match). The old `PlaintextDataKey::zeroize` loop is gone, so T08 is retired. The only `unsafe` that reaches MPL objects is in the C++ shim (T25).
- **Duvet**: one annotation block (`mpl/src/cmc/entry.rs:201-205`), not checked by any config. Gaps are justified by named tests; tests never close a gap.
- **Bugs**: open BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08, 10 (BUG-10 added after the audit, by code reading); fixed BUG-02, 03, 09.
- **CVE-2026-6550 / GHSA-v638-38fc-rhfv is verified** (threat model). It concerns a shared caching CMM; the repo has none, so no score depends on it. Future-work note on T14. Content was rephrased for compliance with licensing restrictions.
- **IDs are stable.** Retired targets keep their IDs and are listed, not deleted. New IDs: T25, T26, C07, C08 (at `620771c`) and T27 (at `9955ecd`).
- **No source changes.** Findings that need a behavior change are listed in §7.

## 0.1 Refresh summary (a1e23d7 → 620771c)

History of the `620771c` refresh. Scores and ranks in this table are as of that refresh; the `9955ecd` section above lists what changed since (T21 is now 2.24).

| ID | Status | Old | New | Driver |
|---|---|---|---|---|
| T08 | **Retired** | 3.84 | — | Unsafe zeroize loop removed (a864ad8); `PlaintextDataKey` derives `Zeroize, ZeroizeOnDrop` (`algorithm_suite.rs:505`) |
| C06 | **Retired** | 1.96 | — | Integer-division unit conversion removed; check is one `Duration` compare (`hierarchical_keyring.rs:585`) |
| T25 | **New** | — | 1.44 | TM-MPL-024 (C++ shim raw handles) |
| T26 | **New** | — | 3.20 | TM-MPL-015 residual (transient / error-path secret buffers); successor of T08 |
| C07 | **New** | — | 5.04 | Materials transition checks (`materials_checks.rs`, #167) |
| C08 | **New** | — | 0.96 | Usage-counter arithmetic (`CacheEntry::record_use`, `entry.rs:206`) |
| T13 | Rescored | 2.52 | 4.41 | TM-MPL-009 Likelihood Low → Medium (BUG-06 confirmed) |
| T14 | Rescored | 2.52 | 3.78 | TM-MPL-010 Likelihood → Medium; BUG-09 fixed + regression test (gap 0.7 → 0.6) |
| T09 | Rescored | 3.20 | 2.56 | Keyring suite frame now enforced by transition checks (gap 0.5 → 0.4) |
| T15 | Rescored | 2.40 | 1.92 | BUG-03 fixed; strict `from_bytes` (gap 0.5 → 0.4) |
| T21 | Rescored | 1.68 | 1.96 | Builder spec ordering regressed; tests encode it (gap 0.6 → 0.7) |
| C04 | Rescored | 5.60 | 2.80 | BUG-02 fixed; expected outcome FAIL → VERIFY (gap 1.0 → 0.5) |
| all others | Locations / names | — | unchanged | `keystore/` → `key_store/`, builders replace `new()`/`from_raw`, `ttl: Duration`, `to_bytes`/`from_bytes` |

## 1. Combined ranked summary

| Rank | Score | Origin | Target | Property | Agent | Ref | Effort | Proof status |
|---|---|---|---|---|---|---|---|---|
| 1 | 8.96 | T | T01 key-store auth-EC builders (`kms_ops.rs:49`, `branch_key_store.rs:132`, `:1089`, `:1141`) | Write-time EC == KMS-AAD EC == reconstruction EC | mpl-verus-header-parsing-proofs | TM-MPL-005, TM-MPL-002 | 2 weeks | Proved (model level, not the shipped code, under stated hypotheses): 52 verified, 0 errors |
| 2 | 6.72 | T | T02 `record::branch_key_materials_from_authenticated_encryption_context` (`record.rs:95`) | Exact Ok/Err characterization, including the spec clause that a record MUST include `create-time` and `hierarchy-version` (expected FAIL, G1) | mpl-verus-header-parsing-proofs | TM-MPL-005 | 1 week | Partly proved (model level, not the shipped code, under stated hypotheses): 21 verified, 1 errors |
| 3 | 6.72 | C | C01 `key_store/encryption_context.rs` builders ∘ `record.rs` reconstruction | Round trip on (id, version, custom EC); collision branch dead (BUG-08) | mpl-verus-header-parsing-proofs | cap:cat1 (1c) | 1 week | Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors |
| 4 | 6.40 | C | C02 `prim::ecdsa` `sign_fixed_len` (`ecdsa.rs:180`) and callers | ≤ 128 attempts; no panic; no partial write | mpl-verus-zero-panic | cap:cat2 (2d) | 1 week | Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors. Partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): retry bound, termination, guarded copy |
| 5 | 5.60 | C | C03 `prim::{hmac, digest, aes_encrypt, aes_decrypt, hkdf*, kbkdf_ctr_hmac}`, `DigestContext::finish` | No panic; exact length contract | mpl-verus-zero-panic | cap:cat2 (2a/2d) | 1 week | Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors |
| 6 | 5.12 | T | T03 `kms_ops::resolve_key_store_arn` pinned modes (`kms_ops.rs:88`) | KeyId is always the configured ARN | mpl-verus-header-parsing-proofs | TM-MPL-002 | 1 day | Proved (model level, not the shipped code, under stated hypotheses): 39 verified, 0 errors |
| 7 | 5.04 | C | C07 `materials_checks` transitions + `send()` wiring | Keyring may only add PDK/EDKs; every `send()` checks | mpl-verus-header-parsing-proofs | cap:cat1 (1a/1b) | 1 week | None yet |
| 8 | 4.48 | T | T04 `branch_key_wrap::wrap` (`:157`) | Fresh salt + IV per call; 60+n layout | mpl-verus-unsafe-ffi-safety | TM-MPL-012 | 1 week | Proved (model level, not the shipped code, under stated hypotheses): 45 verified, 0 errors |
| 9 | 4.41 | T | T13 `build_cache_identifier` (`cache_entry_identifier.rs:35`) + keyring inputs | Injective iff fields NUL-free (BUG-06 counterexample) | mpl-verus-header-parsing-proofs | TM-MPL-009, TM-MPL-010 | 1 week | Partly proved (model level, not the shipped code, under stated hypotheses): 42 verified, 1 errors |
| 10 | 4.32 | T | T05 `branch_key_wrap::derive_branch_key` (`:122`) | KBKDF fixed-info layout, 32 B out | mpl-verus-header-parsing-proofs | TM-MPL-014 | 1 day | Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors |
| 11 | 4.20 | T | T06 `SystemTime + Duration` (`hierarchical_keyring.rs:702`, `:945`; `storm_tracking.rs:333`, `:680`) | No overflow panic (expected FAIL, BUG-01) | mpl-verus-zero-panic | TM-MPL-018, 022, 023 | 1 week | None yet |
| 12 | 3.84 | T | T07 raw-AES wrap/unwrap + `prim::aes_*` | Fresh 12 B IV; length preconditions | mpl-verus-unsafe-ffi-safety | TM-MPL-011 | 1 week | None yet |
| 13 | 3.78 | T | T14 `as_branch_key_materials` (`:1000`), `cache_entry_within_limits` (`:989`), `generate_partition_id` (`:626`) | Only BranchKey entries; exact `Duration` TTL; v4 id | mpl-verus-header-parsing-proofs | TM-MPL-010 | 1 week | None yet |
| 14 | 3.78 | T | T27 `HierarchicalKeyring::on_decrypt` EDK loop → `try_decrypt_edk` → `decrypt_edk_at_version` (`hierarchical_keyring.rs:734`, `:751-772`, `:901`) | Key-store calls and loop iterations per decrypt bounded by the EDK list (verifies); no constant bound (expected FAIL; provisional, TM-MPL-025 unconfirmed) | mpl-verus-zero-panic | TM-MPL-025, TM-MPL-018 | 1 week | None yet |
| 15 | 3.20 | T | T26 transient / error-path secret buffers | Wiped or moved to `ZeroizeOnDrop` on every exit (expected FAIL: BUG-07a, un-wiped decrypt buffers, `ecdsa_generate_keypair` error path); expired `LocalCmc` entries resident until read | mpl-verus-unsafe-ffi-safety | TM-MPL-015 | 2 weeks | None yet |
| 16 | 2.88 | T | T10 `compute_aad` (`:61`), UUID codec | AAD layout; UUID round trip | mpl-verus-header-parsing-proofs | TM-MPL-013 | 1 week | None yet |
| 17 | 2.88 | T | T11 `aws_kms_mrk_match_for_decrypt` (`mrk_match.rs:24`), `is_arn_compatible` | MRK match semantics | mpl-verus-header-parsing-proofs | TM-MPL-004 | 2 weeks | None yet |
| 18 | 2.88 | T | T12 `merge_reproduced_encryption_context` (`default_cmm.rs:273`) | Union on agreement | mpl-verus-header-parsing-proofs | TM-MPL-017 | 1 week | None yet |
| 19 | 2.80 | C | C04 PDK length invariant (`check_data_key_length`, `algorithm_suite.rs:547`) | PDK length = suite key length (expected VERIFY) | mpl-verus-header-parsing-proofs | cap:cat1 (1a) | 1 week | None yet |
| 20 | 2.56 | T | T09 commitment policy + `DefaultCmm` gates | Allow-tables match spec | mpl-verus-header-parsing-proofs | TM-MPL-006, TM-MPL-008 | 1 week | None yet |
| 21 | 2.40 | C | C05 suite table | Refines spec; ids injective | mpl-verus-header-parsing-proofs | cap:cat1 (1a) | 1 day | None yet |
| 22 | 2.24 | T | T16 malformed-input panic sites | No panic on malformed EDK/EC/ARN | mpl-verus-zero-panic | TM-MPL-023 | 1 week | None yet |
| 23 | 2.24 | T | T21 `cmc/storm_tracking.rs` (`build` `:606`) | Builder enforces spec ordering (expected FAIL); `\|inflight\| ≤ fan_out`; failed leader's mark cleared (expected FAIL); every waiter has a deadline (expected FAIL); no panic under the state lock | mpl-verus-zero-panic (+ concurrency) | TM-MPL-018 | 1 month | None yet |
| 24 | 1.92 | T | T15 `EncryptionContext::{to_bytes, from_bytes}` (`:91`, `:145`) | Canonical codec (expected VERIFY) | mpl-verus-header-parsing-proofs | TM-MPL-013, TM-MPL-017 | 2 weeks | None yet |
| 25 | 1.92 | T | T17 Discovery / MRDiscovery ARN (`kms_ops.rs:96-102`, `:118`, `:144`) | Region rewrite only for MRKs (expected FAIL, BUG-04) | mpl-verus-header-parsing-proofs | TM-MPL-007 | 1 week | None yet |
| 26 | 1.92 | T | T18 `version_key` EC derivation (`branch_key_store.rs:641`, `:706-722`) | Preserves id/arn/hv/tablename/custom EC | mpl-verus-header-parsing-proofs | TM-MPL-016 | 1 week | None yet |
| 27 | 1.92 | T | T19 hierarchical bkid binding | Only matching EDKs attempted | mpl-verus-header-parsing-proofs | TM-MPL-003 | 1 week | None yet |
| 28 | 1.68 | T | T20 raw-AES provider-info codec (`:129`, `:191`) | Round trip, total | mpl-verus-header-parsing-proofs | TM-MPL-023, 011, 001 | 1 week | None yet |
| 29 | 1.60 | T | T22 `Debug` + error `DataKeyInfo` | Independent of secret bytes | mpl-verus-unsafe-ffi-safety | TM-MPL-021 | 1 week | None yet |
| 30 | 1.44 | T | T25 C++ shim handles (`esdk/shims/aws-esdk-cpp/src/lib.rs:715`, `:728`, `:1570-1571`, `:1661`; `into_keyring_handle` `:2059`) | Every deref null-dominated; the Rust half of `Keyring::adopt` (non-null unique `Box`) is provable, the C++ half is a caller obligation | mpl-verus-unsafe-ffi-safety | TM-MPL-024 | 1 week | None yet |
| 31 | 1.26 | T | T23 `LocalCmc` (`cmc/local.rs`) | Capacity + TTL invariants | mpl-verus-zero-panic | TM-MPL-022 | 2 weeks | None yet |
| 32 | 1.20 | T | T24 `RawAesKeyringBuilder::build` (`:350`, check `:360`) | No `aws-kms` namespace | mpl-verus-header-parsing-proofs | TM-MPL-001 | 1 day | None yet |
| 33 | 0.96 | C | C08 `CacheEntry::record_use` (`entry.rs:206`) + `update_usage_metadata` | Counters never wrap; overflow evicts | mpl-verus-zero-panic | cap:cat2 (2b) | 1 day | None yet |
| — | Retired | T | T08 ~~`PlaintextDataKey::zeroize` unsafe loop~~ | code removed (a864ad8) | — | (TM-MPL-015 → T26) | — | None (retired) |
| — | Retired | C | C06 ~~grace-vs-TTL integer division~~ | code removed | — | — | — | None (retired) |

Totals: **33 active targets**, 26 threat-driven (T01–T07, T09–T27) and 7 capability-driven (C01–C05, C07, C08), plus 2 retired (T08, C06). Agent routing: mpl-verus-header-parsing-proofs ×20, mpl-verus-zero-panic ×8, mpl-verus-unsafe-ffi-safety ×5.

## 2. Detailed recommendations (YAML)

The ten highest-ranked targets plus the three threat-driven targets added or extended since `a1e23d7` (T27, T26, T25). 9 threat-driven, 4 capability-driven. `rank` is the combined rank from §1. T27 is provisional: TM-MPL-025 is unconfirmed until a reproducer exists. Full versions (with formal specs) are in 01 §3 and 02 §3.

```yaml
recommendation:
  id: VR-2026-T01
  rank: 1
  priority_score: 8.96
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/kms_ops.rs; mpl/src/key_store/branch_key_store.rs; mpl/src/key_store/record.rs
    function: >
      kms_ops::build_authenticated_encryption_context (:49); DynamoDbKeyStore::build_auth_ec (:132);
      item_from_ec_and_enc (:1089); record_from_ddb_item (:1141); record::{encryption_context_from_item (:37), to_attribute_map (:61)} (test-utils)
  property: "Builders agree with the spec auth EC (all attributes except enc, plus tablename); write→read reproduces exactly the KMS-authenticated EC."
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-005, category: Tampering, description: "Branch-key record substitution"}
    - {id: TM-MPL-002, category: Spoofing, description: "Forged record decrypts under attacker-influenced key"}
  trace_to_spec: "spec/framework/branch-key-store.md#encryption-context, #authenticating-a-keystore-item, #record-format"
  coverage_gap: 0.8
  coverage_evidence: "test_key_store_record.rs covers only test-utils helpers; production builders are reached only by live-AWS integ tests."
  scoring: {severity: 4, coverage_gap: 0.8, feasibility: 0.7, blast_radius: 4, product: "4 × 0.8 × 0.7 × 4 = 8.96"}
  quick_win: false     # 2 weeks
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 52 verified, 0 errors"
  proof_file: verus-proofs/t01_keystore_auth_ec.rs
  proof_note: "KMS and DynamoDB are modeled by assumptions (A_KMS, A_DDB), not checked. Overlaps C01 (40 verified): the C01 and T02 models are copied unchanged. New versus C01: the KMS-AAD builder as its own function, the KMS call model, the loop-based item and record mapping, VersionKey, and the authenticity theorem T01-E. No duplicate on branch Mahnush_Verus."
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T02
  rank: 2
  priority_score: 6.72
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/record.rs
    function: branch_key_materials_from_authenticated_encryption_context (:95); custom_encryption_context_from_authenticated_encryption_context (:79)
  property: "Ok iff valid type/version, branch-key-id present, 32-byte plaintext, and (G1, expected FAIL today) both `create-time` and `hierarchy-version` present; outputs exactly determined; otherwise Err(Kind::InvalidMaterials). The spec says a record MUST include those fields and the operation MUST fail without them; neither key is read on any read path today. Whether the check lives here or in record_from_ddb_item is an owner decision. Rollback of an authentic older record is a non-goal."
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-005, category: Tampering, description: "Reconstruction must not accept a mis-typed or mis-versioned record"}
  trace_to_spec: "spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context, #record-format (:677, create-time :690, hierarchy-version :692; MUST-fail sentences :531, :553, :574)"
  coverage_gap: 0.6
  coverage_evidence: "test_key_store_record.rs (23 tests, e.g. materials_branch_key_rejects_wrong_length :169). No test builds a record or EC without `create-time` or `hierarchy-version` (G1)."
  scoring: {severity: 4, coverage_gap: 0.6, feasibility: 0.7, blast_radius: 4, product: "4 × 0.6 × 0.7 × 4 = 6.72"}
  quick_win: true
  proof_status: "Partly proved (model level, not the shipped code, under stated hypotheses): 21 verified, 1 errors"
  proof_file: verus-proofs/t02_record_reconstruction.rs
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C01
  rank: 3
  priority_score: 6.72
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/encryption_context.rs; mpl/src/key_store/record.rs
    function: build_base (:40), active_encryption_context (:117), decrypt_only_encryption_context (:137), beacon_key_encryption_context (:160); record.rs (:79, :95, :37, :61)
  property: "CreateKey ECs reconstruct to exactly (id, version, custom EC); prefix/strip inverse; collision Err (:95-101) unreachable (BUG-08); record→EC→record identity off tablename/enc."
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference: {category: 1, invariant: "Key-store EC builders and the reconstruction decoder are exact inverses on (branch-key-id, version, custom EC)."}
  trace_to_spec: "spec/framework/branch-key-store.md#encryption-context, #active-encryption-context, #decrypt_only-encryption-context"
  coverage_gap: 0.8
  coverage_evidence: "Each half tested alone (test_key_store_encryption_context.rs, test_key_store_record.rs); no composition test."
  scoring: {severity: 3, coverage_gap: 0.8, feasibility: 0.7, blast_radius: 4, product: "3 × 0.8 × 0.7 × 4 = 6.72"}
  quick_win: true
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors"
  proof_file: verus-proofs/c01_ec_roundtrip.rs
  dependencies: [VR-2026-T02]
```

```yaml
recommendation:
  id: VR-2026-C02
  rank: 4
  priority_score: 6.40
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/ecdsa.rs
    function: sign_fixed_len (:180); check_sig_len (:200); ecdsa_sign (:224); ecdsa_sign_digest (:253); ecdsa_verify (:282); ecdsa_verify_context (:305)
  property: "≤ 128 sign_once calls; copy only on exact length; buffer untouched on Err; verify never Err."
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference: {category: 2, invariant: "The ECDSA retry loop terminates, never panics, and never partially writes the buffer."}
  trace_to_spec: "spec/framework/algorithm-suites.md#asymmetric-signature-algorithm; baseline assurance"
  coverage_gap: 0.8
  coverage_evidence: "prim/tests/test_ecdsa.rs; oracle not injectable, so retry exhaustion is untested."
  scoring: {severity: 2, coverage_gap: 0.8, feasibility: 1.0, blast_radius: 4, product: "2 × 0.8 × 1.0 × 4 = 6.40"}
  quick_win: true
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors"
  proof_file: verus-proofs/c02_sign_fixed_len.rs
  proof_note: "Partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): the retry bound (at most 128 attempts), termination and the guarded copy_from_slice are also proved on the real loop (sign_fixed_len_core). This target stays the only statement of T1 as a postcondition (at most 128 closure calls), T3 (no partial write: Err leaves the buffer unchanged, Ok writes one whole candidate), T4 (which Err exits exist), T5 (check_sig_len), T6 (ecdsa_sign* wrong-length contract) and the three non-vacuity witnesses. The status above is unchanged. It is not a duplicate and is not demoted."
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C03
  rank: 5
  priority_score: 5.60
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/lib.rs; prim/src/ecdsa.rs; prim/src/hkdf.rs
    function: hmac (:241), digest (:272), aes_encrypt (:175), aes_decrypt (:206), kbkdf_ctr_hmac (:313), DigestContext::finish (ecdsa.rs:82), hkdf (hkdf.rs:46), hkdf_no_salt (:76), hkdf_expand (:101)
  property: "No panic for any argument; exact Ok/Err length contract; aes_decrypt Ok ⇒ |pt| == |ct|."
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference: {category: 2, invariant: "No reachable panic path in the prim crypto wrappers."}
  trace_to_spec: "supports spec/framework/algorithm-suites.md lengths; baseline assurance"
  coverage_gap: 0.7
  coverage_evidence: "prim/tests negative-length tests; no wrong-length finish buffer, no over-long aes_decrypt buffer."
  scoring: {severity: 2, coverage_gap: 0.7, feasibility: 1.0, blast_radius: 4, product: "2 × 0.7 × 1.0 × 4 = 5.60"}
  quick_win: false
  proof_status: "Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors"
  proof_location: "Branch Mahnush_Verus of aws/aws-crypto-tools-rust (PR #103), VR-013 (hmac_core, digest_core, digest_finish_core, kbkdf_core, fill_random_core, ct_equal_core) and VR-014 (BUG-07 buffer facts in aes_encrypt_core, aes_decrypt_core). NOT on MPL-Verus: prim/ here equals main 620771c and has no Verus annotation. Commits ed4a81e (feat) and 43b9ff7 (docs); tip read 8d6381e (the later commits change docs only)."
  proof_result: "verification results:: 18 verified, 0 errors (aws-mpl-primitives), from `cargo verus verify` (default features) and `cargo verus verify --no-default-features --features aws-lc-sys` in prim/, re-run at 8d6381e; same count at 43b9ff7 in our earlier review. 18 counts every verified function in the prim crate on that branch (VR-006, VR-008, VR-009 prim half, VR-013, VR-014); the base 6b51de8 gave 10."
  proof_trusted_base: "20 assume_specification (A1-A20) about aws-lc-rs in prim/src/aws_lc_specs.rs, each assumed not to panic; no assume, admit, external fn or unsafe. All judged TRUE for aws-lc-rs 1.18.1 by our review; the FIPS C side is unchecked."
  proof_not_covered: >
    hkdf and hkdf_expand "Ok implies len(okm) in {16, 24, 32}" and "no listed function panics" end to end (VR-009 proves only the decision functions);
    DigestContext::digest's call to finish; adapters outside verus! (format! messages, get_aes_alg, the DigestAlg to KbkdfCtrHmacAlgorithmId match);
    constant_time_equal and generate_random_bytes add little beyond assumptions A13 and A12; BUG-07(a): key/nonce Err buffer = old ++ message and seal-Err length and prefix
    are exported ensures, but the Ok-case order "old ++ ciphertext ++ tag" is an in-body assert and +16 relies on A19, and seal-Err tail bytes are not described;
    BUG-07(b) is assumption-relative (A20, A-OPEN), not proved; nothing about zeroization.
  related_bugs:
    - {bug: "BUG-07(a)", evidence: "prim-side buffer facts proved in-crate on Mahnush_Verus (VR-014); caller impact is code reading", threat: TM-MPL-015, target: "T26 (F2), T07 (e)"}
    - {bug: "BUG-07(b)", evidence: "recorded, relative to assumption A20, not proved", threat: TM-MPL-023, target: C03}
    - {bug: BUG-10, evidence: "code reading", threat: TM-MPL-015, target: T26, note: "not part of C03: the buffers are in mpl, not prim"}
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T03
  rank: 6
  priority_score: 5.12
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/kms_ops.rs
    function: resolve_key_store_arn (:88; pinned arms :94-95; compat check :105); caller decrypt_branch_key (:162, call :179)
  property: "In KmsKeyArn / KmsMrKeyArn modes the KMS KeyId is always the configured ARN; Ok iff compatible, else Err(Kind::Validation)."
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-002, category: Spoofing, description: "Forged record decrypts under attacker-influenced KMS key — pinned-mode slice"}
  trace_to_spec: "spec/framework/branch-key-store.md#aws-kms-branch-key-decryption"
  coverage_gap: 0.8
  coverage_evidence: "No direct unit test (pub(crate)); predicate tested in test_key_store_kms_config.rs; end-to-end only integ."
  scoring: {severity: 4, coverage_gap: 0.8, feasibility: 0.4, blast_radius: 4, product: "4 × 0.8 × 0.4 × 4 = 5.12"}
  quick_win: false
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 39 verified, 0 errors"
  proof_file: verus-proofs/t03_resolve_pinned_arn.rs
  dependencies: [VR-2026-T11]
```

```yaml
recommendation:
  id: VR-2026-C07
  rank: 7
  priority_score: 5.04
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/materials_checks.rs; mpl/src/keyring/fluent_builders.rs; mpl/src/cmm/fluent_builders.rs
    function: check_encryption_transition (:72); check_decryption_transition (:117); check_*_materials_complete (:157, :177); send() wiring (keyring :82, :163; cmm :171, :319)
  property: "Transition Ok iff the keyring only added a PDK (when absent) and EDKs, with suite/EC/required keys/signing or verification key unchanged; every fluent send() returns Ok only after the check passes."
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference: {category: 1, invariant: "On every fluent path a keyring cannot change the suite, EC, required keys or signing/verification key."}
  trace_to_spec: "spec/framework/keyring-interface.md#onencrypt, #ondecrypt; spec/framework/cmm-interface.md"
  coverage_gap: 0.6
  coverage_evidence: "test_materials_checks.rs (27 tests, e.g. on_encrypt_rejects_a_changed_algorithm_suite :271)."
  scoring: {severity: 3, coverage_gap: 0.6, feasibility: 0.7, blast_radius: 4, product: "3 × 0.6 × 0.7 × 4 = 5.04"}
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T04
  rank: 8
  priority_score: 4.48
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: wrap (:157; salt :164; IV :170)
  property: "Fresh 16 B salt and 12 B IV per call; output = salt‖iv‖uuid(version)‖ct‖tag, |out| = 60 + |pt|; aws-lc-rs preconditions hold."
  tool: Verus
  agent: mpl-verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-012, category: Elevation of Privilege, description: "Salt/IV reuse in branch-key wrap — structural slice"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping"
  coverage_gap: 0.7
  coverage_evidence: "wrap_ciphertext_layout_lengths_match_spec (:939), wrap_two_calls_produce_distinct_ciphertexts (:1168)."
  scoring: {severity: 4, coverage_gap: 0.7, feasibility: 0.4, blast_radius: 4, product: "4 × 0.7 × 0.4 × 4 = 4.48"}
  quick_win: false
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 45 verified, 0 errors"
  proof_file: verus-proofs/t04_branch_key_wrap.rs
  proof_note: "The model proves the structure around the draws (two separate generator calls per call that returns Ok, salt to the KDF, IV to AES-GCM, 60 + n layout relative to A_AES), not that the salt or the IV is fresh or unique: freshness comes from the aws-lc-rs generator, assumed only as A_RNG (the draws may be any values). The only distinctness result is conditional: if the draws of two calls differ (H_RNG_DIFFERS, never established), the outputs differ. No expected-FAIL obligation. All ensures are partial correctness (nothing proves wrap returns Ok). No duplicate on branch Mahnush_Verus."
  dependencies: [VR-2026-T05, VR-2026-T10]
```

```yaml
recommendation:
  id: VR-2026-T13
  rank: 9
  priority_score: 4.41
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/cache_entry_identifier.rs; mpl/src/aws_kms/hierarchical_keyring.rs
    function: build_cache_identifier (:35; preimage :42-60; .expect :64); call sites (:665, :908); inputs partition id (:595-599, :626), logical name (:605)
  property: "Exact NUL-separated preimage; scope separation; injective iff partition / logical name / bkid / version are NUL-free (BUG-06 counterexample otherwise)."
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-009, category: Elevation of Privilege, description: "Cache-identifier collision (BUG-06 confirmed on main)"}
    - {id: TM-MPL-010, category: Information Disclosure / EoP, description: "Shared-cache confusion"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas, #partition-id"
  coverage_gap: 0.7
  coverage_evidence: "cache_entry_identifier_* tests (:647, :680, :708, :736, :770); no NUL case."
  scoring: {severity: 3, coverage_gap: 0.7, feasibility: 0.7, blast_radius: 3, product: "3 × 0.7 × 0.7 × 3 = 4.41"}
  quick_win: false
  proof_status: "Partly proved (model level, not the shipped code, under stated hypotheses): 42 verified, 1 errors"
  proof_file: verus-proofs/t13_cache_identifier.rs
  proof_note: "The one error is the intentional expected-FAIL obligation lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL (BUG-06, High, open). The model identifier is injective if and only if the fields are NUL-free; a length-prefixed encoding is injective for all inputs (fix option 2, model only). No duplicate on branch Mahnush_Verus."
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T05
  rank: 10
  priority_score: 4.32
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: derive_branch_key (:122; Zeroizing output :125/:135; kbkdf call :136)
  property: "Fixed-info = \"aws-kms-hierarchy\" ‖ 0x00 ‖ salt ‖ 0x00000100 (38 B); HMAC-SHA-256; 32 B output."
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-014, category: Elevation of Privilege, description: "KBKDF fixed-info / L-value misuse"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping; NIST SP 800-108 §4.1"
  coverage_gap: 0.9
  coverage_evidence: "Self-consistent round trips only; prim vectors test the primitive (test_kbkdf_ctr_hmac_raw_vectors :329)."
  scoring: {severity: 3, coverage_gap: 0.9, feasibility: 0.4, blast_radius: 4, product: "3 × 0.9 × 0.4 × 4 = 4.32"}
  quick_win: false
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors"
  proof_file: verus-proofs/t05_kbkdf_fixed_info.rs
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T27     # provisional: TM-MPL-025 is static reasoning, unconfirmed until a reproducer exists
  rank: 14
  priority_score: 3.78
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/cmc/storm_tracking.rs
    function: >
      on_decrypt (:734; EDK loop :751-772; per-EDK attempt :764); try_decrypt_edk (:867; length guard :879; version bytes :889-894);
      decrypt_edk_at_version (:901; cache id :908; cache lookup :916-924; key-store read get_branch_key_version :934-938; put :947-953);
      StormTrackingCmc::classify_and_mark (storm_tracking.rs:264); DEFAULT_STORM_FAN_OUT = 20 (:115)
  property: "(a) One decrypt call runs at most |EDK list| loop iterations and makes at most |matching EDKs| cache lookups and key-store reads (verifies). (b) Expected FAIL: no bound on key-store reads that is independent of the sender-chosen EDK count exists (up to 65,535 per message), and duplicates of the same unknown version re-read (no negative cache, no per-decrypt budget). Which bound to add is an owner decision. Excluded: wall-clock time, DynamoDB capacity and KMS cost."
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-025, category: Denial of Service, description: "Decrypt-input amplification: sender-chosen EDK count and versions drive key-store reads (provisional)"}
    - {id: TM-MPL-018, category: Denial of Service, description: "Relies on the stale in-flight mark and the no-deadline waiter (T21 (g), (h))"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt (:236-249; no bound is specified); spec/framework/storm-tracking-cryptographic-materials-cache.md#fanout"
  coverage_gap: 0.9
  coverage_evidence: "test_keyring_memory.rs :100, :113 check memory only and never reach the key store; the only several-EDK test (test_aws_kms_hierarchical_keyring.rs::on_decrypt_with_several_failing_edks_aggregates_without_a_single_cause :1998) fails before any key-store call. No test asserts a bound on key-store calls per decrypt."
  scoring: {severity: 2, coverage_gap: 0.9, feasibility: 0.7, blast_radius: 3, product: "2 × 0.9 × 0.7 × 3 = 3.78"}
  quick_win: false
  proof_status: "None yet"
  dependencies: [VR-2026-T21]   # soft
```

```yaml
recommendation:
  id: VR-2026-T26
  rank: 15
  priority_score: 3.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/keyring/raw_aes_keyring.rs; prim/src/lib.rs; mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/key_store/kms_ops.rs
    function: raw-AES on_decrypt buffer (:471, :489); wrap_data_key output Vec (:162); prim::aes_encrypt (:175, copy :185 before Err :188); branch_key_wrap::unwrap (:230); decrypt_branch_key plaintext; LocalCmc::get_fresh (local.rs:131), prune_tail (:166), CACHE_PRUNING_TAIL_SIZE (:69); prim::ecdsa_generate_keypair (ecdsa.rs:373; private-key Vec :387, error return :391-392)
  property: "Every buffer that held key plaintext is wiped or moved into a ZeroizeOnDrop owner on every exit path. Expected FAIL: raw-AES decrypt Err / wrong-length paths, BUG-07a, (F4) expired LocalCmc entries stay resident until read, pruned or evicted, and (F5) ecdsa_generate_keypair drops the private-key Vec un-wiped on its length-check error return."
  tool: Verus
  agent: mpl-verus-unsafe-ffi-safety
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-015, category: Information Disclosure, description: "Transient and error-path secret copies"}
  trace_to_spec: "spec/framework/structures.md#plaintext-data-key; baseline assurance"
  coverage_gap: 1.0
  coverage_evidence: "Zeroize tests cover types only (:248, :228); no test of transient buffers."
  scoring: {severity: 2, coverage_gap: 1.0, feasibility: 0.4, blast_radius: 4, product: "2 × 1.0 × 0.4 × 4 = 3.20"}
  quick_win: false
  proof_status: "None yet"
  related_bugs:
    - {bug: BUG-10, severity: Low, evidence: "code reading, no proof (mpl is not Verus-enabled)", threat: TM-MPL-015, target: T26, note: "RawAesKeyring::on_decrypt drops an authenticated plaintext data key un-wiped on the wrong-length path (site F1); branch_key_wrap::unwrap holds a plain Vec<u8> (site F3)"}
    - {bug: "BUG-07(a)", evidence: "prim-side facts proved in-crate on Mahnush_Verus (C03, VR-014); caller impact is code reading", threat: TM-MPL-015, target: "T26 (F2)", note: "callers wrap_data_key and branch_key_wrap::wrap drop the plaintext data key un-wiped on an aes_encrypt Err; cannot fire today"}
  scope_note: >
    Scope note only; no property, score, coverage gap, feasibility or severity changed. BUG-10 is the bug report for site F1's wrong-length continue
    (raw_aes_keyring.rs:489-494: an authenticated plaintext data key is dropped un-wiped, while the success path at :497 moves the buffer into PlaintextDataKey)
    and for F3's branch_key_wrap::unwrap buffer (:275, a bare Vec<u8> is returned). The BUG-07(a) caller impact names one caller that the function list above does not:
    branch_key_wrap::wrap (branch_key_wrap.rs:157, aes_encrypt call :199); wrap_data_key (raw_aes_keyring.rs:163) is already in F2. The failure cannot fire today:
    key and IV sizes are fixed by type in wrap, and the raw-AES wrapping-key length is checked at RawAesKeyringBuilder::build (raw_aes_keyring.rs:369-379).
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T25
  rank: 30
  priority_score: 1.44
  origin: threat-driven
  target:
    crate: aws-esdk-cpp shim (outside mpl/ and prim/)
    file: esdk/shims/aws-esdk-cpp/src/lib.rs
    function: require_handle (:715; null check :720; deref :728); nullable client handles (:1570, :1571; were :1564-1565); nullable cache handle (:1661; was :1655); into_keyring_handle (:2059; Box::into_raw :2062); C++ Keyring::adopt (EncryptionSDK.cpp:541-547)
  property: "Every raw-handle deref is dominated by a null check; null required handle → Validation error; null optional handle → core default. Non-null validity is a trusted caller precondition. Adopt path: into_keyring_handle returns a non-null unique Box (provable); C++ Keyring::adopt calls from_raw with no null, type or ownership check (type confusion, double free), which is a caller obligation outside the proof."
  tool: Verus
  agent: mpl-verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-024, category: Elevation of Privilege / Tampering, description: "Shim dereferences a dangling or forged handle to an MPL object"}
  trace_to_spec: "spec/shim/shim.md#handles-and-lifetimes"
  coverage_gap: 0.6
  coverage_evidence: "esdk/shims/aws-esdk-cpp/src/tests.rs: require_handle_rejects_null_and_borrows_non_null (:715), null keyring / key-store tests (:733, :746, :791), into_keyring_handle_boxes_the_keyring (:1624)."
  scoring: {severity: 3, coverage_gap: 0.6, feasibility: 0.4, blast_radius: 2, product: "3 × 0.6 × 0.4 × 2 = 1.44"}
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

## 3. Coverage-gap analysis

No Verus proof of the shipped code exists on this branch for any target. Eight targets (T01, T02, C01, C02, T03, T04, T05, T13) have a proof of a model, listed in "Proofs written". C03 is partly proved in-crate on branch `Mahnush_Verus`, which is not this branch (see "Proofs written"). The coverage gaps below are the pre-proof values and were not recalculated, including C03's 0.7 and C02's 0.8. Files are under `mpl/tests/` unless prefixed. "integ" = live-AWS.

| Target | Existing tests | Gap | Justification |
|---|---|---|---|
| T01 | test_key_store_record.rs; test_key_store_branch_key_store_integ.rs (integ) | 0.8 | Unit tests reach only test-utils helpers |
| T02 | test_key_store_record.rs | 0.6 | Broad branch examples; no test without `create-time` / `hierarchy-version` (G1) |
| C01 | test_key_store_encryption_context.rs; test_key_store_record.rs | 0.8 | No composition test |
| C02 | prim/tests/test_ecdsa.rs | 0.8 | Oracle not injectable |
| C03 | prim/tests/test_{hmac,digest,aes,hkdf,kbkdf_ctr_hmac,ecdsa}.rs | 0.7 | Direct negative-length tests; two gaps |
| T03 | test_key_store_kms_config.rs; integ | 0.8 | Function untested directly |
| C07 | test_materials_checks.rs (new, 27) | 0.6 | Broad examples, no field-by-field statement |
| T04 | test_aws_kms_hierarchical_keyring.rs | 0.7 | Layout, distinctness, tamper |
| T13 | test_aws_kms_hierarchical_keyring.rs | 0.7 | No NUL case (BUG-06) |
| T05 | test_aws_kms_hierarchical_keyring.rs; prim/tests/test_kbkdf_ctr_hmac.rs | 0.9 | Self-consistent only |
| T06 | test_aws_kms_hierarchical_keyring.rs; test_storm_tracking_cmc.rs | 1.0 | No large-Duration test |
| T07 | test_raw_aes_keyring.rs; prim/tests/test_aes.rs | 0.8 | No two-call IV test |
| T14 | test_aws_kms_hierarchical_keyring.rs | 0.6 | BUG-09 regression test added; no wrong-kind entry |
| T27 | test_keyring_memory.rs; test_aws_kms_hierarchical_keyring.rs | 0.9 | Tests exist but cannot detect an unbounded key-store call count |
| T26 | test_encryption_materials.rs; test_decryption_materials.rs; test_local_cmc.rs (:465) | 1.0 | Types only, no transient, error-path or expired-entry buffers |
| T10 | test_aws_kms_hierarchical_keyring.rs | 0.6 | Layout + mismatch tests |
| T11 | test_aws_kms_mrk_match.rs; test_key_store_kms_config.rs | 0.6 | Example tests |
| T12 | test_default_cmm.rs | 0.6 | Example tests |
| C04 | test_encryption_materials.rs; test_decryption_materials.rs | 0.5 | All four entry points tested (BUG-02 fix) |
| T09 | test_commitment_policy.rs; test_default_cmm.rs; test_materials_checks.rs | 0.4 | Near-exhaustive + runtime frame check |
| C05 | test_algorithm_suite_id.rs (22) | 0.5 | Finite domain; cross-crate untested |
| T16 | hierarchical, raw-AES, EC, MRK tests | 0.7 | Direct malformed-input tests |
| T21 | test_storm_tracking_cmc.rs (33) | 0.8 | Tests encode the regressed contract (:388); no test for (g) stale mark, (h) waiter deadline or (i) poison |
| T15 | test_encryption_context.rs (45) | 0.4 | Strict decoder + order/UTF-8 tests |
| T17 | test_key_store_kms_config.rs; test_key_store_branch_key_store.rs; integ | 0.8 | No non-MRK MRDiscovery test |
| T18 | test_key_store_branch_key_store.rs; integ | 0.8 | Inline derivation only via integ |
| T19 | test_aws_kms_hierarchical_keyring.rs | 0.6 | Skip-filter and supplier tests |
| T20 | test_raw_aes_keyring.rs | 0.7 | Wire format + negatives |
| T22 | test_algorithm_suite.rs; test_raw_aes_keyring.rs; others | 0.5 | Redaction test per type |
| T25 | esdk/shims/aws-esdk-cpp/src/tests.rs | 0.6 | Null checks and `into_keyring_handle` tested; dangling, forged and double-adopted handles untestable |
| T23 | test_local_cmc.rs | 0.6 | Capacity, TTL, pruning |
| T24 | test_raw_aes_keyring.rs | 0.5 | Reserved-prefix tests |
| C08 | test_local_cmc.rs (:729) | 0.6 | Overflow-deletes test |

## 4. Risk summary by STRIDE category

From `docs/mpl-threat-model.md` §7 (TM-MPL-025 listed under Denial of Service; TM-MPL-024 and TM-MPL-026 under Elevation of Privilege). "Verified" is 0: it counts threats whose target is proved against the shipped code of `MPL-Verus`. The eight proofs in "Proofs written" are model level, and the in-crate C03 proof is on `Mahnush_Verus` (C03 is a capability target and cites no threat).

| Category | Threats | Verified | With target | Fully excluded | Targets | Top-priority target |
|---|---|---|---|---|---|---|
| Spoofing | 3 (001, 002, 003) | 0 | 3 | 0 | T01, T03, T19, T20, T24 | T01 (8.96, via 002); primary-002 T03 (5.12) |
| Tampering | 5 (004, 005, 013, 016, 017) | 0 | 5 | 0 | T01, T02, T10, T11, T12, T15, T18 | T01 (8.96) |
| Repudiation | 1 (020) | 0 | 0 | 1 | — | — |
| Information Disclosure | 3 (010, 015, 021) | 0 | 3 | 0 | T13, T14, T22, T26 | T13 (4.41, via 010); primary-010 T14 (3.78) |
| Denial of Service | 4 (018, 022, 023, 025) | 0 | 4 | 0 | T06, T16, T20, T21, T23, T27 | T06 (4.20) |
| Elevation of Privilege | 10 (006, 007, 008, 009, 011, 012, 014, 019, 024, 026) | 0 | 8 | 2 (019, 026) | T04, T05, T07, T09, T13, T17, T20, T25 | T04 (4.48) |
| **Total** | **26** | **0** | **23** | **3** | 26 threat-driven targets | |

TM-MPL-017 is fully targeted (T12, T15); the other 22 targeted threats carry partial exclusions (§6). TM-MPL-019, TM-MPL-020 and TM-MPL-026 have no target.

Capability-driven targets by closest category (advisory): Tampering/integrity — C01 (6.72), C07 (5.04), C04 (2.80), C05 (2.40); DoS — C02 (6.40), C03 (5.60), C08 (0.96).

## 5. Quick wins (score > 6.0 AND effort ≤ 1 week)

| Rank | Target | Score | Effort | Origin |
|---|---|---|---|---|
| 2 | VR-2026-T02 reconstruction Ok/Err | 6.72 | 1 week | T |
| 3 | VR-2026-C01 EC builder ∘ reconstruction | 6.72 | 1 week | C |
| 4 | VR-2026-C02 ECDSA bounded retry | 6.40 | 1 week | C |

Unchanged by the `9955ecd` refresh and by the proofs in "Proofs written" (T02 partly proved, C01 and C02 proved, all at model level and not the shipped code; the list is not re-scored). T01 (8.96) needs 2 weeks. The new T27 (3.78) and the re-scored T21 (2.24) are below the threshold; T26 (3.20, 2 weeks) and T25 (1.44) also stay out. Cheap targets below threshold: T03 (5.12, 1 day), T05 (4.32, 1 day), C05 (2.40, 1 day). C03 (5.60) is not a quick win, and its partly proved in-crate status on `Mahnush_Verus` does not change the list.

## 6. Out of scope / not Verus-provable

Full table in 01 §4. Every one of TM-MPL-001..026 is accounted for by a target (§1) or by a row here; the per-threat mapping is 01 §6.

Fully excluded (no provable code slice):

| Threat | Reason |
|---|---|
| TM-MPL-019 | Duvet / process tooling; the spec floats on `master`. No code property |
| TM-MPL-020 | Audit / operational control (no audit binding between an MPL operation and its KMS/DDB calls; CloudTrail and the user agent `AwsCryptographicMPL-Rust/<version>` cover it) |
| TM-MPL-026 | Four loopback test servers (`mpl/test-server`, `prim/test-server`, `esdk/test-server`, `esdk/shims/aws-esdk-cpp/test-server`) bind `127.0.0.1` with no authentication and use ambient AWS credentials (`mpl/test-server/src/main.rs:26-27`; AWS clients built from request data at `handlers.rs:137-147`, `:425-430`). Test-only code with `publish = false` in each `Cargo.toml`; Risk Low. The control is operational (run them only on development hosts without production credentials), not a property of the library. No target needed |

Partial exclusions (the targeted slice is in §1; only the remainder is out of scope): crypto hardness, external-service semantics (KMS, DynamoDB), probabilistic bounds, allocator/OS memory, caller-supplied components (`KeyStore`, `Cmc`, `BranchKeyIdSupplier`, C++ callers of the shim) and the `zeroize` / `cxx` crates as trusted or excluded. Changes at `9955ecd`:

- **TM-MPL-025 (→ T27).** Excluded: wall-clock time per request, DynamoDB read capacity and KMS cost, and the choice of bound (EDK cap, per-decrypt budget, negative cache, de-duplication). Reason: performance, operations and an owner decision. The threat is provisional until a reproducer exists.
- **TM-MPL-024 (→ T25).** Excluded: C++ `Keyring::adopt(void*)` (`EncryptionSDK.cpp:541-547`, no null, type or ownership check) and the validity of any non-null C++-supplied pointer. Reason: caller obligation across the FFI boundary (header `EncryptionSDK.h:656-663`).
- **TM-MPL-005 (→ T01, T02).** Excluded: rollback of an older authentic ACTIVE record (plain `GetItem`, no consistent read, no highest-version memory). Reason: storage freshness; no code property separates an authentic old record.
- **TM-MPL-015 (→ T26).** Excluded: the `aws-lc-rs` DER buffer returned to `ecdsa_generate_keypair` joins the third-party internals.
- **TM-MPL-018 (→ T21, T06, T27).** Properties (g) and (h) are stated over the pure classify step; their reproducer is a concurrency test.

Capability candidates rejected: 02 §5 (R2–R17; R1 withdrawn because counter code now exists, see C08; R17 is the storm-tracking builder bounds, already T21 (a)).

## 7. Findings recorded, not changed

Each needs an owner decision.

- T06 (BUG-01): `SystemTime + Duration` overflow panics for large accepted `ttl`, `grace_interval`, `in_flight_ttl`.
- T13 (BUG-06): cache-id preimage not injective with NUL in partition id / logical name / bkid; end-to-end confirmed. Also confirmed by the T13 proof at model level: the preimage is injective if and only if the fields are NUL-free, and the unrestricted injectivity claim is the intentional expected-FAIL obligation `lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL`.
- T17 (BUG-04): MRDiscovery rewrites the region of non-MRK ARNs (fails closed).
- T21: `StormTrackingCmcBuilder::build` no longer enforces Grace Interval ≤ Grace Period, Inflight TTL ≤ Grace Period, or minimums (a). Also open: a failed leader's in-flight mark is never cleared (g), a waiter blocked by a full fan-out has no deadline (`storm_tracking.rs:313`) (h), and a panic under the state lock poisons it (i).
- T16 (BUG-05a/b): `default_cmm.rs:138` `.expect` on ECDSA keygen; 44–59-byte EDK costs one key-store lookup.
- T26 (BUG-07a): `prim::aes_encrypt` leaves plaintext in the caller's buffer on `Err`; raw-AES decrypt buffer not wiped on error paths. Also: expired `LocalCmc` entries stay resident until read (`local.rs:131`, `:166`), and `ecdsa_generate_keypair` leaves the private-key `Vec` un-wiped on its error return (`ecdsa.rs:387`, `:391-392`). BUG-10 (Low, code reading, maps to TM-MPL-015 and T26): `RawAesKeyring::on_decrypt` drops an authenticated plaintext data key un-wiped when its length is wrong (`raw_aes_keyring.rs:489-494`), and `branch_key_wrap::unwrap` holds a plain `Vec<u8>` (`:275`). The BUG-07(a) caller impact (the data key in the caller's buffer after an `aes_encrypt` `Err`) is code reading and cannot fire today.
- T27 (TM-MPL-025, unconfirmed): no bound on key-store calls per decrypt; the EDK count and versions are chosen by the ciphertext sender.
- T02 (G1): `create-time` and `hierarchy-version` are not required on any read path, although the spec says a record MUST include them. Confirmed by the T02 proof at model level: the code accepts a record without them (`lemma_g1_code_ignores_fields`, `lemma_g1_witness_accepted_without_fields`; the spec property fails as `lemma_g1_spec_soundness_FAILS`).
- T25: C++ `Keyring::adopt` has no null, type or ownership check (`EncryptionSDK.cpp:541-547`).
- C03 (BUG-07b): `aes_decrypt` guard weaker than its callee; misleading error text. Recorded, not proved: the VR-014 core states it relative to A20 on `Mahnush_Verus`. The BUG-07(a) prim-side buffer facts are proved there (partly proved, not on this branch); their caller impact is tracked in T26.
- C01(c) (BUG-08): dead collision `Err` in `build_base`. The C01 proof (model level) shows it is dead if and only if A_ITER holds, and live if a key repeats.
- T03 (O1, O2): O1 two byte-identical alias ARNs fail the code's MRK match, where the spec text matches (documented deviation, unreachable for any configuration `build()` accepts). O2 the ARN-validity model accepts empty partition, region and account, which is looser than the spec; no effect on the T03 property. Found by the T03 proof at model level.
- T04 (TM-MPL-012): the T04 proof (model level) does not show that the salt or the IV is fresh or unique; that rests on the aws-lc-rs generator, which the model assumes only as A_RNG (assumed, not proved). Its O1 (a clear copy of the data key can stay in `wrap`'s output buffer after an `aes_encrypt` Err, never wiped) is the `wrap` caller impact already listed under T26 (BUG-07(a)); code reading.
- T05 (F1): the spec does not state the KBKDF fixed-info layout. A spec gap found by the T05 proof at model level, not a code defect.
- T01 (O1): `build_auth_ec` (`branch_key_store.rs:132`) and `kms_ops::build_authenticated_encryption_context` (`kms_ops.rs:49`) are two separate functions with no shared code. The T01 proof shows they agree at model level; an edit to one alone would break the equality. Code reading plus the proved agreement; no defect found.
- C07: fields not constrained by `check_encryption_transition` (symmetric signing keys, EDK order) to be compared with Dafny `Materials.dfy`.
- Closed since a1e23d7: C04-F1/F2 (BUG-02), T15 unsorted-accept (BUG-03), T14 `ttl + 1 s` (BUG-09).
