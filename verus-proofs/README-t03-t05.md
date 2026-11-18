# Verus proofs: T03 and T05
Two Verus proofs for targets from the verification-targets pipeline. Repo `esdk-native-mpl`, HEAD `35f24c9`. This file extends `README.md` (T02, C01, C02) and does not replace it.
**What these are.** Each file is a proof about a hand-written, re-typed model of the shipped Rust. Neither verifies the shipped code. The code is not inside `verus!`, is not compiled by Verus, and nothing detects a later edit to `mpl/` or `prim/`. The link between model and code is a correspondence table in each file header that a human reviewed. Read every status below as "the logic of the model is machine-checked; the model's fidelity to the code is audited, not checked."
Neither file is part of a cargo build. They live outside `mpl/`, `prim/`, `esdk/` and `docs/`.
## How to run
Verus 0.2026.07.12.0b42f4c (release, macos_aarch64, toolchain 1.96.0). From the repo root (`esdk-native-mpl`):
```sh
~/verus/verus verus-proofs/t03_resolve_pinned_arn.rs   # exit 0
~/verus/verus verus-proofs/t05_kbkdf_fixed_info.rs     # exit 0
```
Each file ends with `fn main() {}` because Verus needs an entry point for a single file. The logs are in `.agents/tasks/verus-proofs-t03-t05/logs/` (workspace root, outside the `esdk-native-mpl` repo). Working notes: `.agents/tasks/verus-proofs-t03-t05/t03-notes.md`, `t05-notes.md`.
## Results
| ID | Target | File | Result line (from the log) | Exit | Status |
|---|---|---|---|---|---|
| T03 | VR-2026-T03 / TM-MPL-002 | `t03_resolve_pinned_arn.rs` | `verification results:: 39 verified, 0 errors` | 0 | **Proved** (model level, under H_ORACLE, H_BUILD, H_CALLER, A_STR, A_MR) |
| T05 | VR-2026-T05 / TM-MPL-014 | `t05_kbkdf_fixed_info.rs` | `verification results:: 33 verified, 0 errors` | 0 | **Proved** (model level; the KBKDF output is an uninterpreted function) |
Meaning of **Proved** here: the log shows `0 errors`, no `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier...]` appears in the proof code outside comments (grep, run again when this file was written, no hits in either file), and every external assumption is stated in the file header and below. It does not mean the shipped code is verified, and for T05 it does not mean the key derivation is correct.
No obligation is left failing on purpose in either file.
---
## T03: pinned-mode KMS key ARN resolution (VR-2026-T03 / TM-MPL-002)
**Property in plain language.** When the key store is configured with a single KMS key (`KmsKeyArn`) or a multi-Region key (`KmsMrKeyArn`), `resolve_key_store_arn` returns the configured ARN, never the ARN stored in the attacker-writable DynamoDB record. It accepts the record's ARN only when it is compatible with the configured one: byte-equal for `KmsKeyArn`, an MRK match for `KmsMrKeyArn`. Otherwise it returns `Err` with kind `Validation`. On the decrypt path the KMS `KeyId` is therefore always the configured ARN.
**Status: Proved, at model level.** `39 verified, 0 errors`. The Discovery and MrDiscovery arms are out of scope (BUG-04 / T17). The exec function excludes them with `requires is_pinned(kms_config@)`.
| Theorem / lemma | Line | Statement | Strength |
|---|---|---|---|
| `resolve_key_store_arn<O: ArnCompat>` (exec) | 1142 | For any compatibility predicate `O`: `Ok(k)` means `k@ == configured` and the record is compatible. `Err(e)` means `e.kind == Validation` and the record is not compatible. | Headline. Holds for any predicate, so it does not depend on the MRK match. |
| `theorem_a_key_id_is_configured` | 829 | Pinned modes: a successful call returns exactly the configured ARN. | Headline. Any predicate. |
| `theorem_a2_key_id_independent_of_record` | 840 | Any two accepted records give the same `KeyId`. | Headline. Any predicate. |
| `theorem_b_ok_iff_compat` | 851 | Ok iff compatible, Err iff not compatible, and the Err kind is `Validation`. | Exact, relative to the model `compat`. |
| `theorem_c_single_key` | 864 | `KmsKeyArn`: Ok iff the record ARN is byte-equal to the configured one. | Exact, model. |
| `theorem_d_mrk_sound`, `theorem_e_mrk_complete` | 877, 893 | `KmsMrKeyArn`: Ok iff neither ARN is an alias ARN and either they are byte-equal or both are MRK ARNs differing only in the region piece. | Exact, model of `aws_kms_mrk_match_for_decrypt`. |
| `theorem_f_dispatch` | 908 | `NotPinned` is exactly the Discovery and MrDiscovery arms. | Dispatch only. |
| `theorem_g_decrypt_key_id` | 1088 | Decrypt path: if the KMS call happens, its `KeyId` is the configured ARN and the record's `kms-arn` was compatible. Two records that both reach KMS get the same `KeyId`. | **Weaker.** Models the `decrypt_branch_key` caller only, and rests on H_CALLER. |
| `theorem_h_exec_refines_model` | 1274 | The exec function equals the model `resolve`, if the oracle equals the model `compat` on all inputs. | **Weaker.** Conditional on H_ORACLE. That the shipped `is_arn_compatible` equals `compat` is audited, not checked. |
| `theorem_i_validated_config_equals_spec_text` | 920 | For a configured ARN that passes `validate_kms_key_arn`, the code's compatibility test equals the spec text of `aws-kms-mrk-match-for-decrypt.md` on every record string. | **Weaker.** Rests on H_BUILD and on A_MR (the code's own MRK test). |
| `lemma_mrk_match_iff` | 668 | Exact Ok set of the modeled `aws_kms_mrk_match_for_decrypt`. | Supporting. |
| `lemma_code_vs_spec_text` | 718 | The code equals the spec text on every pair with no alias. | **Weaker.** Excludes alias pairs (see O1). |
| `lemma_join_split`, `lemma_split_join` | 451, 547 | The model of `split(':')` is correct. | Supporting. |
| `lemma_validated_not_alias` | 797 | A validated configured ARN is never an alias ARN. | Supporting. |
| `witness_ok`, `witness_err`, `witness_byte_eq`, `witness_mrk_other_region_accepted` | 1237, 1248, 1260, 1001 | The contracts are satisfiable (Ok, Err, byte-equal accepted, a different-region ARN of the same MRK accepted). | **Weaker.** Satisfiability only. They show the theorems are not vacuous and prove nothing about the code. |
**Assumptions / TCB.**
- **Tool base.** Verus, Z3, rustc 1.96.0 and vstd's `Seq` axioms. vstd's own `assume_specification`s for `String::as_str` and `str::to_owned` are used in the exec function. The one for `<String as PartialEq>::eq` is used only in the `ByteEqCompat` witness.
- **A_STR.** `String` is `Seq<char>`. Splitting on ':' and '/' agrees between bytes and chars because both are ASCII.
- **A_MR.** `is_mr_arn` is the code's own test for a multi-Region key ARN (`mrk_match.rs:52-58`). The spec's definition also requires a valid ARN, so comparison against the spec text uses the code's test.
- **H_ORACLE.** The exec function is generic over the compatibility test. vstd has no specs for `str::split`, `splitn`, `split_once` or `starts_with`, so an exec MRK match would need `external_body`. That the shipped `is_arn_compatible` equals the modeled `compat` is audited, not checked.
- **H_BUILD.** The configuration used at call time is the one `build()` validated (`branch_key_store.rs:381`, field private). Only `theorem_i` uses it.
- **H_CALLER.** `decrypt_branch_key` passes only the returned value as `key_id` (`kms_ops.rs:183`), and `version_key` passes it to ReEncrypt. Read, not checked. `theorem_g` models the decrypt caller only.
- The correspondence table in the file header is human review only.
**Model-vs-code gap.** The shipped function is native Rust over `&str`, `Result<String, Error>`, the crate's `Error` and `KmsConfiguration`. The model collapses `KmsKeyArn{arn}` and `KmsMrKeyArn{arn}` to their `String`, drops the Discovery payload, drops the `format!` message, and leaves `branch_key_id` unused (only the out-of-scope arms read it). To close the gap you need all of:
1. Move `resolve_key_store_arn`, `is_arn_compatible`, `aws_kms_mrk_match_for_decrypt`, `is_multi_region_arn` and `is_alias_arn` into `verus!`, or run `cargo verus` on the crate. Both need edits to `mpl/`.
2. Add vstd specs for `str::{split, splitn, split_once, starts_with}`, `Vec<&str>` indexing after `collect()`, `format!`, and `KmsKeyArn::arn()`.
3. Add a spec for `Error::new` and `Kind`.
4. Replace H_ORACLE with the real exec compatibility function.
A cheaper partial step is a script that diffs the control-flow skeleton of `kms_ops.rs:88-114` and `mrk_match.rs:24-48` against the proof file.
**Source.** Proof: `verus-proofs/t03_resolve_pinned_arn.rs` (header `:1-203`). Code:
- `mpl/src/key_store/kms_ops.rs`: `resolve_key_store_arn` `:88-114` (match `:93-104`, compat check `:105-112`, Ok `:113`); `decrypt_branch_key` `:162-197` (resolve `:179`, `key_id` `:183`); ReEncrypt `:271-272`.
- `mpl/src/key_store/kms_config.rs`: `is_arn_compatible` `:86-94`, `parse_arn` `:31-58`, `validate_kms_key_arn` `:61-79`.
- `mpl/src/aws_kms/mrk_match.rs`: match function `:24-48`, `is_multi_region_arn` `:52-58`, `is_alias_arn` `:62-68`.
- `mpl/src/key_store/branch_key_store.rs`: `configured_kms_key_arn` `:112-122`, `validate()` call `:381`, `version_key` `:641-668` (resolve `:663`, ReEncrypt `:678`).
- Spec: `branch-key-store.md` `:638-671` and `:170-179`; `aws-kms-mrk-match-for-decrypt.md`.
**Not covered.**
- Discovery and MrDiscovery arms, `reject_alias_arn`, `rewrite_arn_region` (BUG-04 / T17). `NotPinned` is the only statement about them.
- `version_key` beyond its call to the function.
- That KMS Decrypt authenticates the record (the EC carries `kms-arn` as AAD).
- Panic-freedom of the shipped `pa[5]` / `pb[5]` indexing (`mrk_match.rs:40-45`). `lemma_mrk_match_indices_in_range` proves only in the model that the guard fixes the piece count.
- `format!` and `Error` fields other than `kind`.
- Rollback of an authentic older record (TM-MPL-005 non-goal).
- The full T11 property (the MRK match's own error sites and the hierarchical-keyring call sites). Theorems B to E and I use the modeled match but do not prove all of T11.
---
## T05: KBKDF fixed-info string in `derive_branch_key` (VR-2026-T05 / TM-MPL-014)
**Property in plain language.** `derive_branch_key` feeds the key-derivation primitive the algorithm HMAC-SHA-256, the branch key as the KDF key, and the info string `"aws-kms-hierarchy" ‖ 0x00 ‖ salt ‖ 00 00 01 00` (38 bytes), and asks for 32 bytes. Wrap and unwrap derive from the same salt, so they feed the primitive the same input.
**This proof does not show the derived key is correct.** The KBKDF output is an uninterpreted spec function (`kbkdf_spec`, `:306`) with no axioms. The proof shows which arguments the primitive receives. It does not show what the primitive computes. KBKDF, HMAC-SHA-256 and aws-lc-rs correctness are third-party TCB and are not proved.
**Status: Proved, at model level.** `33 verified, 0 errors`.
| Theorem / lemma | Line | Statement | Strength |
|---|---|---|---|
| `theorem_fixed_info_layout` | 393 | For a 16-byte salt, info is exactly `label ‖ 0x00 ‖ salt ‖ 00 00 01 00`, 38 bytes. Label at 0..17, separator at 17, salt at 18..34, L at 34..38. | Headline. |
| `lemma_l_is_bits_of_output` | 344 | `be32(256) = 00 00 01 00`, and `256 = 8 × 32`. | Supporting. |
| `lemma_fixed_info_is_nist_shape` | 384 | The info equals the model's `nist_fixed_info(label, salt, 32)`, a spec function written after the prim KAT helper `build_fixed_info`. | **Weaker.** It compares two spec functions in this file. It does not touch the test helper or the primitive. |
| `theorem_fixed_info_salt_injective` | 418 | Equal info strings imply equal 16-byte salts. | **Weaker.** About the info string only. Whether the PRF output separates salts is not proved. |
| `derive_branch_key` (exec) | 485 | On Ok, the key is `kbkdf_spec(Sha256, branch_key, fixed_info(salt), 32)` and has length 32. This pins the algorithm, the output length and the key/info argument order. Every Err has kind `Cryptographic`. | Headline, relative to the `Prim` contract and the uninterpreted `kbkdf_spec`. |
| `wrap_kdf_leg` | 566 | On Ok, the salt fed to the KDF is the salt written at bytes 0..16 of the output, and the prefix is `salt ‖ iv ‖ version` (44 bytes). | Model of wrap steps 1 to 3 and the prefix. RNG and AES-GCM are not modeled. |
| `unwrap_kdf_leg` | 605 | A ciphertext under 60 bytes gives Err before the primitive is called. Otherwise all slicing is in bounds, the `try_into().expect` cannot fail, and the KDF salt is `ct[0..16]`. | Model of unwrap's gate, slicing and KDF salt. |
| `theorem_wrap_unwrap_same_kdf_input` | 651 | For any layout `salt16 ‖ iv12 ‖ version16 ‖ ek ‖ tag16`, the length is `60 + |ek|`, and unwrap reads the same salt wrap used. Both sides get the same info and, `kbkdf_spec` being a function, the same derived key. | **Weaker.** "Same derived key" is relative to the uninterpreted `kbkdf_spec`. |
| `u32_to_be_bytes` (exec) | 457 | The shift-and-mask model equals the arithmetic big-endian spec `be32`. | Supporting. That std's `to_be_bytes` is big-endian is A_STD. |
| `lemma_be32_value` | 354 | The four bytes of `be32(x)` read back to `x`. An independent check of `be32`. | Supporting. |
| `witness_fixed_info_concrete`, `witness_distinct_salts_distinct_info` | 685, 706 | A concrete salt gives the expected info, and two concrete salts give different info. | **Weaker.** Non-vacuity only. |
| `witness_length_gate_boundary` | 722 | 60 passes the gate, 59 fails it. | **Weaker.** Trivial arithmetic on constants. It is not counted as evidence. |
**Wrong-length salt or branch key.** Neither can reach the function. The parameters are `&[u8;16]` and `&[u8;32]`. A wrong-length plaintext branch key is rejected earlier by T02's `BadKeyLength`. The only Err from `derive_branch_key` is the primitive's, mapped to `Kind::Cryptographic` (`branch_key_wrap.rs:136-142`).
**Spec-derived vs code-derived.** The spec text is `aws-kms-hierarchical-keyring.md`, "Branch Key Wrapping" `:206-222`, "Branch Key Unwrapping" `:301-320`, and the ciphertext layout `:108-136`. It has no Appendix text on the derivation.
| Fact | Origin | Where in the proof |
|---|---|---|
| S1: PRF is HMAC-SHA-256 | **Spec** | `alg == Sha256` in `derive_branch_key` |
| S2: derived key is 32 bytes | **Spec** | output length 32, `okm` is `[u8;32]` |
| S3: the branch key is the KDF key | **Spec** | `ikm == branch_key` |
| S4: salt is 16 bytes | **Spec** | `salt: &[u8;16]` |
| S5: label is UTF-8 `aws-kms-hierarchy` (17 bytes) | **Spec** | `HIERARCHY_LABEL`, transcribed by hand (A_LBL) |
| S6: unwrap derives from the stored salt by the same derivation as wrap | **Spec** | `theorem_wrap_unwrap_same_kdf_input` |
| S7: ciphertext is `salt(16) ‖ IV(12) ‖ version(16) ‖ encrypted key ‖ tag(16)` | **Spec** | `wire_layout` |
| C1: info is `label ‖ 0x00 ‖ salt ‖ be32(256)`: salt in the NIST Context position, single 0x00 separator, L in bits | **Code** | `theorem_fixed_info_layout` |
| C2: info is 38 bytes | **Code** | `theorem_fixed_info_layout` |
| C3: `be32(256) = 00 00 01 00`, and `256 = 8 × 32` | **Code** | `lemma_l_is_bits_of_output` |
| C4: the primitive does not add L itself | **Code** (a fact about aws-lc-rs) | Not proved. Evidence: the Dafny-ported known-answer tests in `prim/tests/test_kbkdf_ctr_hmac.rs` (vectors `:241-314`, helper `:316-326`) use the same label, Sha256 and L=32. |
The spec does not state C1 to C4. "Use the `salt` as the salt" has no meaning in SP 800-108, which has no salt input. The proof states C1 to C3 against the code. See finding F1.
**Assumptions / TCB.**
- **A_KDF.** `kbkdf_spec` is an `uninterp spec fn` with no axioms. The trait `Prim` (`:443`) is the only fact about it used: on Ok, `okm == kbkdf_spec(alg, ikm, info, len)`, and the output length is kept. No `Prim` implementation exists in the file. HMAC and PRF security and aws-lc-rs correctness are third-party TCB and are not proved.
- **A_STD.** `u32::to_be_bytes` is big-endian, and `<[u8;N]>::try_from(&[u8])` fails exactly when the length is not N.
- **A_VSTD.** vstd's specs for `Vec::{with_capacity, push, extend_from_slice}`, slice indexing by `Range`, `as_slice`, and arrays; plus Verus and Z3.
- **A_LBL.** The 17 label bytes and the numeric constants were transcribed by hand. A script compared them to the source and all match.
- **A_TYP.** Rust array types give the lengths.
- The correspondence table in the file header is human review only.
**Model-vs-code gap.**
- The model drops `Zeroizing` and uses a local `Error {kind}`. Error message and cause are dropped.
- `to_be_bytes` is re-implemented, and the label is spelled as decimal ASCII.
- `&ct[end..]` is written `&ct[end..ct.len()]` because vstd has no spec for `RangeFrom` indexing.
- wrap and unwrap are modeled only up to the KDF call and the prefix. Salt, IV and version are inputs.
To close the gap you need all of:
1. `derive_branch_key` and its constants inside `verus!`, or `cargo verus` on the crate.
2. Specs for `u32::to_be_bytes`, `Zeroizing` and `Error::with_cause`.
3. An `assume_specification` for `aws_mpl_primitives::kbkdf_ctr_hmac` with exactly the `Prim` contract. That is where the aws-lc-rs TCB would be written down.
4. A way for Verus to read the byte-string constant.
**Source.** Proof: `verus-proofs/t05_kbkdf_fixed_info.rs` (header `:1-222`). Code, in `esdk-native-mpl`:
- `mpl/src/aws_kms/branch_key_wrap.rs`: `derive_branch_key` `:122-144` (fixed info `:126-132`, KDF call `:136`, error map `:136-142`); `HIERARCHY_LABEL` `:40`; wrap `:157-197` (KDF `:175`); unwrap `:230-285` (length gate `:236-244`, KDF `:265`).
- `prim/src/lib.rs:313-330`: the primitive.
- `mpl/src/structures/branch_key_materials.rs:32`: `branch_key()` returns `&[u8;32]`.
**Not covered.**
- The KBKDF output, PRF security, aws-lc-rs correctness.
- Interop with other implementations. No test compares a `derive_branch_key` or wrap output to a Dafny or Java value.
- The RNG for salt and IV (T04).
- AES-GCM and the AAD.
- Version UUID parsing.
- Zeroization.
- Error message text.
- Whether the primitive can fail on valid input. The model lets it fail arbitrarily and proves only the shape of the failure.
- Timing.
---
## Combined TCB
| Item | Kind | Used by | Notes |
|---|---|---|---|
| Verus 0.2026.07.12, Z3, rustc 1.96.0 | tool | both | |
| vstd `Seq` axioms | library spec | T03, T05 | |
| vstd `assume_specification` for `String::as_str`, `str::to_owned` | library spec | T03 | Used in the exec function. |
| vstd `assume_specification` for `<String as PartialEq>::eq` | library spec | T03 | Only the `ByteEqCompat` witness. |
| vstd `Vec`, slice and array specs | library spec | T05 | |
| A_STR: `String` is `Seq<char>`; byte and char splits agree | model fidelity | T03 | Not machine-checked. |
| A_MR: `is_mr_arn` is the code's MRK test | model fidelity | T03 | Looser than the spec (O2). |
| H_ORACLE: shipped `is_arn_compatible` equals modeled `compat` | model fidelity | T03 | Audited. Used by `theorem_h`. |
| H_BUILD: the used config is the one `build()` validated | model fidelity | T03 | Only `theorem_i`. |
| H_CALLER: callers pass only the returned value as `KeyId` | model fidelity | T03 | Read, not checked. `theorem_g`. |
| A_KDF: `kbkdf_spec` uninterpreted; `Prim` contract | unconstrained abstraction | T05 | HMAC, KBKDF and aws-lc-rs are third-party TCB. |
| A_STD: `to_be_bytes`, `try_from(&[u8])` semantics | std semantics | T05 | Not in vstd. |
| A_LBL: hand-copied label bytes and constants | model fidelity | T05 | Script comparison matched all. |
| Correspondence tables in file headers | human review | both | The only link between model and code. |
## Findings
**T03: no spec-faithful property was false for the pinned path.** Nothing is left failing.
- **O1, DEV-ALIAS.** Two byte-identical alias ARNs make the code's MRK match return false, where the spec text returns true (`mrk_match.rs:10-19, :25-27`; `lemma_mrk_match_identical` `:695`, `lemma_code_vs_spec_text` `:718`). The code documents this. It is stricter than the spec, never looser. It is unreachable for any configuration `build()` accepts, because `validate()` rejects aliases (`lemma_validated_not_alias`, `theorem_i`, under H_BUILD).
- **O2, loose ARN validity.** The model of `is_multi_region_arn` and `validate_kms_key_arn` accepts an ARN with empty partition, region and account (`witness_empty_parts_accepted`, `:1042`). `aws-kms-key-arn.md` requires these non-empty, and `branch-key-store.md:157-158` requires a valid configured ARN. `validate_kms_key_arn` also accepts any resource type except `alias`, where the spec says `alias` or `key`. I read this from `kms_config.rs:61-79`. It is not in the model. There is no effect on T03, because the `KeyId` is the configured ARN either way. It is a conformance gap in config validation, outside this target.
- **Mutation checks.** Six breaks of the model in scratch copies under `/tmp` each made Verus fail: return the record ARN, drop the account check, ignore compat, wrong `KmsKeyArn` arm, drop the alias guard, skip the exec compat check. These cover edits to the model only.
- The T03 YAML line anchors and `Kind::Validation` match HEAD.
**T05: no defect found in `derive_branch_key`.**
- **F1, spec gap.** The spec does not give the fixed-info layout. The layout exists only in code and in the prim test helper. Suggestion: state `label ‖ 0x00 ‖ salt ‖ 0x00000100` in the spec. This is not a code defect.
- **F2, observation.** The literal `256` at `branch_key_wrap.rs:131` is not tied to `DERIVED_KEY_LEN`. They agree today. Nothing in the proof detects a change to either one in the code.
- **F3, observation.** No test checks `derive_branch_key` or a wrap ciphertext against a known-answer value. The primitive-level KATs use a test-local copy of the layout. Layout drift in this function would not be caught.
- **F4.** The YAML anchors match HEAD. Wrap and unwrap reach the KDF only through `derive_branch_key`.
- **Mutation checks.** Eleven breaks of the model in scratch copies under `/tmp/t05` each made Verus fail: swapped key and info arguments, Sha384, a dropped or changed separator, L=128, salt before label, wrong unwrap salt offset, a 59-byte gate, a label typo, a swapped wrap prefix order, a wrong salt to the KDF. One earlier run of the Sha384 break passed because the text replace hit a comment. It was redone against the actual call and failed. These cover edits to the model only.
## Mapping to target IDs
| Proof file | Target ID | Threat model | Pipeline item |
|---|---|---|---|
| `t03_resolve_pinned_arn.rs` | VR-2026-T03 | TM-MPL-002 | Pinned modes return the configured ARN as KMS `KeyId`; compat Ok/Err |
| `t05_kbkdf_fixed_info.rs` | VR-2026-T05 | TM-MPL-014 | KBKDF fixed-info layout and derivation inputs |
The orchestrator records proof status in `docs/mpl-verification-targets*.md` after review. This README does not edit those files.
## Next steps
1. Review the two correspondence tables against the code. They are the only link between model and code.
2. Spec: add the fixed-info layout to `aws-kms-hierarchical-keyring.md` (F1). Consider tying `256` to `DERIVED_KEY_LEN` (F2) and adding a known-answer test for `derive_branch_key` or a wrap ciphertext (F3).
3. Decide whether config validation should reject ARNs with empty parts and non-`key` resource types (O2).
4. To turn T03 into a code proof, move the five functions into `verus!` and add the vstd `str` specs. To turn T05 into one, add the `assume_specification` for `kbkdf_ctr_hmac`.
5. Add a CI step that runs both files and fails on any change to the result lines.
