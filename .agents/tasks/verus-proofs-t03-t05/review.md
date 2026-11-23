# Independent review: T03 and T05 Verus proofs

Reviewer: separate agent from the proof authors. Repo `esdk-native-mpl`, HEAD `35f24c9`. Verus 0.2026.07.12.0b42f4c.

## Outcome
Both proofs hold at model level and the documents match the logs. One comment line in `t05_kbkdf_fixed_info.rs` cited the wrong source line and was fixed. No proof code, spec, or existing file was changed. No open issue blocks acceptance.

## 1. Re-run
| File | Command (repo root) | Exit | Result line | Saved log | README / summary |
|---|---|---|---|---|---|
| `t03_resolve_pinned_arn.rs` | `~/verus/verus verus-proofs/t03_resolve_pinned_arn.rs` | 0 | `verification results:: 39 verified, 0 errors` | identical (full `diff`) | match |
| `t05_kbkdf_fixed_info.rs` | `~/verus/verus verus-proofs/t05_kbkdf_fixed_info.rs` | 0 | `verification results:: 33 verified, 0 errors` | identical (full `diff`) | match |

No authentication or token error. The T05 run was repeated after the comment edit below. The result line and the whole output are unchanged.

## 2. Trust escapes
Searched non-comment text for `assume`, `admit`, `external`, `verifier`, `unsafe`, `axiom`, `uninterp`, `broadcast`, `opaque`, `assert(false)`, `by (...)` and `reveal`.
- **No hit** for `assume(`, `admit(`, `external_body`, `external`, `assume_specification`, `#[verifier...]` in either file. The README claim holds.
- **T03 `assert(false)` (2 hits, lines 1173 and 1178):** the `Discovery` and `MrDiscovery` arms of the exec function. They are closed by `requires is_pinned(kms_config@)`. Verus proves them, so this is not a bypass. The same scope limit is stated in the header and README.
- **T05 `uninterp spec fn kbkdf_spec` (line 306):** this is A_KDF, listed in the header, README and combined TCB. T03 has no uninterpreted function, as its header says.
- **T05 `by (nonlinear_arith)` and `by (bit_vector)`:** Z3 solver modes, checked by Verus. They are not in the TCB beyond "Verus and Z3". Not a discrepancy.
- **`#[trigger]`, `#[derive]`, `reveal_with_fuel`:** not trust attributes.
- **`requires`:** all are satisfiable. T03: `is_pinned(c@)`, `validate_ok(cfg)` (instantiated by `witness_empty_parts_accepted`), the `theorem_e` conditions (instantiated by `witness_mrk_other_region_accepted`). T05: length conditions (instantiated by the concrete witnesses). No `requires` forces a pass.
- **`decreases`:** all are structural and Verus-checked. T03: `s.len()` or `segs.len()` against `skip(1)` recursion. T05: `16 - i` against `i += 1` with `i < 16`. The decreases are honest.
- **T05 trait `Prim`:** only a hypothesis (no implementation in the file), as the header states. It is consistent because `kbkdf_spec` can be given the true KBKDF meaning. The file correctly says the contract is not shown satisfiable by construction.

## 3. Correspondence tables against the source
### T05 (`mpl/src/aws_kms/branch_key_wrap.rs`, `prim/src/lib.rs`)
| Item | Source | Model | Result |
|---|---|---|---|
| `SALT_LEN`, `IV_LEN`, `VERSION_LEN`, `TAG_LEN`, `DERIVED_KEY_LEN` | `:21`, `:24`, `:28`, `:32`, `:36` = 16, 12, 16, 16, 32 | same | OK |
| `FIXED_OVERHEAD_LEN` | `:44` = sum = 60 | 60, with a checking lemma | OK |
| Label | `:40` `b"aws-kms-hierarchy"` | 17 decimal ASCII bytes `97,119,115,45,107,109,115,45,104,105,101,114,97,114,99,104,121` | OK (decoded by hand: a w s - k m s - h i e r a r c h y) |
| Info build | `:127-132`: label, `push(0x00)`, salt, `256u32.to_be_bytes()` | `label + [0x00] + salt + be32(256)`, 38 bytes, `be32(256) = 00 00 01 00` | OK |
| Output length | `[0u8; 32]` at `:135` | 32, and `256 = 8 * 32` | OK |
| Call | `:136` `kbkdf_ctr_hmac(Sha256, branch_key, &info, &mut derived)`; primitive `prim/src/lib.rs:313-318` is `(alg, ikm, info, okm)` | same order in `Prim` and in the call | OK |
| Error | `:136-142` `Kind::Cryptographic` | `ErrKind::Cryptographic` | OK |
| Wrap | `:163-166` salt, `:169-172` iv, `:175` KDF, `:192-197` prefix `salt‖iv‖version` | `wrap_kdf_leg` | OK |
| Unwrap | `:236-244` gate `< 60`, `:247-249` salt `ct[0..16]`, `:250-260` slices, `:265` KDF | `unwrap_kdf_leg` | OK |
| Only call sites | `grep kbkdf_ctr_hmac mpl/src`: `:13` (import), `:136` | as claimed | OK |
| `branch_key()` | `branch_key_materials.rs:32` returns `&[u8; 32]` | `&[u8;32]` | OK |
| KATs | `prim/tests/test_kbkdf_ctr_hmac.rs`: label `:35`, vectors `:241-314`, helper `:316-326` (`label‖0x00‖context‖be32(8·len)`), test `:338-347` | cited as supporting evidence only | OK |
| Spec text | `aws-kms-hierarchical-keyring.md` `:212-220`, `:305-318`, `:114-135` | spec-derived list S1-S7 | OK, and the spec has no fixed-info layout (F1 stands) |

Discrepancy: the doc comment on `ErrKind` cited the unwrap length-gate error as `branch_key_wrap.rs:237`. `:237` is `return Err(Error::new(`; `Kind::Cryptographic` is on `:238`. Fixed (comment only).

### T03 (`kms_ops.rs`, `kms_config.rs`, `mrk_match.rs`)
- **`resolve_key_store_arn` `:88-114`:** `KmsKeyArn` and `KmsMrKeyArn` bind `configured = arn()` (`:94-95`). `Discovery` (`:96-99`) and `MrDiscovery` (`:100-103`) return early. `is_arn_compatible` failure gives `Err(Kind::Validation)` (`:105-112`). Success is `Ok(configured.to_owned())` (`:113`). No arm is missing. The only Err on the pinned path is the Validation one. The returned `KeyId` is the configured ARN, never the record's.
- **`is_arn_compatible` `:86-94`:** `KmsKeyArn` is `==` on `&str`, `KmsMrKeyArn` calls the MRK match, the two discovery arms return true. The model `compat` matches.
- **MRK match `mrk_match.rs:24-48`:** alias guard `:25-27`, equal `:29-31`, MR guard `:33-35`, indices `:38-41`, comparison of partition, service, account, resource type, resource and not region `:43-47`. The model `mrk_match` has the same branches in the same order. `is_multi_region_arn` (`:52-58`) uses `split(':')` with 6 pieces, `arn`, `kms`, `key/mrk-` prefix. `is_alias_arn` (`:62-68`) uses the `alias/` prefix. Both match the model. The model of `split(':')` and `split_once('/')` is proved correct by the join/split lemmas, and `"".split(':')` is `[""]` as in Rust.
- **`parse_arn` / `validate_kms_key_arn`:** `splitn(6, ':')` (`:32`), 6 segments, first `arn`, `split_once('/')` (`:41`), service `kms` (`:64`), resource type not `alias` (`:71`). The model `splitn6`, `parse_arn_ok`, `validate_ok` match, and `lemma_validated_not_alias` is sound for them.
- **Callers (H_CALLER):** the only `.key_id(` / `source_key_id` / `destination_key_id` sites in `key_store/` are `kms_ops.rs:183` (resolved id), `:230` (`generate_wrapped_key`, fed the configured ARN at `branch_key_store.rs:726`) and `:271-272` (ReEncrypt, fed `resolved_arn` at `:680` and the configured ARN elsewhere). No site takes the record's ARN directly.
- **H_BUILD:** `validate()` is called at `branch_key_store.rs:381`. The field `kms_configuration` (`:72`) is private, and I found no mutation after `build`.
- **Line anchors** in the header and README (`kms_ops.rs :88-114, :162-197, :271-272`; `branch_key_store.rs :112-122, :381, :641-668, :663, :678`; `config.rs :12, :119-135, :183-200`) all match HEAD. Cosmetic: `decrypt_branch_key` runs to `:207`, so `:162-197` covers it only through the KMS call. Left as is.
- **Spec:** `branch-key-store.md` `:638-671` ("Otherwise, it MUST BE the Keystore's configured KMS Key"), `:170-179` (compatibility) and `:157-158` (valid ARN) agree with the citations.

## 4. Document honesty
- Status "Proved" appears only for files whose log has `0 errors` (39 and 33). The header of each file says "model level".
- Weaker lemmas are labeled in the README table (T03: g, h, i, `lemma_code_vs_spec_text`, witnesses; T05: `lemma_fixed_info_is_nist_shape`, salt injectivity, same-KDF-input, witnesses, the trivial length-gate witness).
- T05 states spec-derived (S1-S7) against code-derived (C1-C4) facts, and that the spec has no fixed-info text.
- Third-party TCB (KBKDF, HMAC-SHA-256, aws-lc-rs) is stated as not proved. T03 states H_ORACLE, H_BUILD, H_CALLER, A_STR, A_MR.
- The model-vs-code gap and not-covered sections match what I read in the code. Theorem A is true by construction of the model (the returned value is `configured_arn`). The README labels it as the headline holding for any predicate, which is accurate, and the real content is in the exec function and in the correspondence.
- Theorem and lemma line numbers in the README and `summary.md` match `grep -n` for all 22 T03 items and 15 T05 items checked.
- `summary.md` says the proofs were not re-run by the docs step. That remains true for that step. This review re-ran them.

## 5. Repo state
- `git diff --quiet HEAD -- mpl prim esdk docs verus-proofs` in `esdk-native-mpl`: success.
- `git status --short` in `esdk-native-mpl`: only `?? verus-proofs/README-t03-t05.md`, `?? verus-proofs/t03_resolve_pinned_arn.rs`, `?? verus-proofs/t05_kbkdf_fixed_info.rs`.
- `/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL` is not a git repository (`fatal: not a git repository`), so `git status` cannot run there. The new files under `.agents/tasks/verus-proofs-t03-t05/` are `logs/`, `summary.md`, `t03-notes.md`, `t05-notes.md`, and this `review.md`. No other `MPL`-level file was touched by this review.
- Both proof files end with `fn main() {}`.
- Nothing was committed or pushed.

## 6. Changes made by this review
1. `esdk-native-mpl/verus-proofs/t05_kbkdf_fixed_info.rs`: comment on `ErrKind`, `branch_key_wrap.rs:138 and :237` changed to `:138 and :238`. Verus re-run: `33 verified, 0 errors`, output identical to the saved log.
2. This file.

## 7. Open issues (none blocking)
- Findings O1, O2 (T03) and F1, F2, F3 (T05) are as the authors reported. I agree with each. Their severity is unchanged.
- The model-to-code link is human review only. Nothing detects later edits to `branch_key_wrap.rs`, `kms_ops.rs`, `kms_config.rs`, `mrk_match.rs` or `prim/src/lib.rs`.
- Cosmetic: the `decrypt_branch_key :162-197` range ends at the KMS call, not at the end of the function.
