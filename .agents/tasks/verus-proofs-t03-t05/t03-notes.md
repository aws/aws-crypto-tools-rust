# T03 working notes: `resolve_key_store_arn`, pinned modes

Proof: `esdk-native-mpl/verus-proofs/t03_resolve_pinned_arn.rs`. Log: `logs/t03_resolve_pinned_arn.log`.
Repo HEAD 35f24c9, `mpl/` unchanged since 620771c. Verus 0.2026.07.12.

## Result

**Proved at model level.** `verification results:: 39 verified, 0 errors`, exit 0. No obligation left failing. No spec-faithful property was false for the pinned path.

Grep for `assume`, `admit`, `external`, `verifier` outside comments: none. No `assume_specification` written. vstd's own are used: `String::as_str`, `str::to_owned` (exec function) and `<String as PartialEq>::eq` (witness `ByteEqCompat` only).

## What was proved (proof-file lines)

| Name | Line | Statement |
|---|---|---|
| `resolve_key_store_arn<O: ArnCompat>` (exec) | 1142 | For every compatibility oracle `O`: Ok(k) means `k@ == configured` and `O::spec_compat`; Err(e) means `e.kind == Validation` and not compatible. Verus checks the body, including that `configured` is the payload of `kms_config` and not the record. |
| `theorem_a_key_id_is_configured` | 829 | Pinned: result is Ok or Err; Ok(k) implies k == configured ARN. |
| `theorem_a2_key_id_independent_of_record` | 840 | Two accepted records give the same KeyId. |
| `theorem_b_ok_iff_compat` | 851 | Ok iff compat; Err iff not compat; Err kind is Validation. |
| `theorem_c_single_key` | 864 | KmsKeyArn: Ok iff record byte-equals configured. |
| `theorem_d_mrk_sound`, `theorem_e_mrk_complete` | 877, 893 | KmsMrKeyArn: Ok iff neither ARN is an alias ARN and (byte-equal, or both MRK ARNs that differ only in the region piece). |
| `theorem_f_dispatch` | 908 | NotPinned exactly for Discovery / MrDiscovery. |
| `theorem_g_decrypt_key_id` | 1088 | Decrypt path: if the KMS call is made, KeyId is the configured ARN and the record's `kms-arn` was compatible. |
| `theorem_h_exec_refines_model` | 1274 | Exec function equals `resolve`, given H_ORACLE. |
| `theorem_i_validated_config_equals_spec_text` | 920 | For a configured ARN that passes `validate_kms_key_arn`, the code's compat equals the spec text on every record string. |
| `lemma_mrk_match_iff` | 668 | Exact Ok set of the code's `aws_kms_mrk_match_for_decrypt`. |
| `lemma_code_vs_spec_text` | 718 | Code equals spec text on non-alias pairs; alias pairs are the DEV-ALIAS deviation. |
| `lemma_join_split`, `lemma_split_join` and helpers | 451, 547 | The model of `split(':')` is the real one (join inverts split; split inverts join on colon-free pieces). |
| `lemma_validated_not_alias` | 797 | `validate_kms_key_arn` Ok implies not an alias ARN. |
| `witness_ok/err/byte_eq` (exec), `witness_mrk_other_region_accepted` | 1237, 1248, 1260, 1001 | Contracts are satisfiable: Ok, Err, byte-equal, and a different-region ARN of the same MRK that is accepted and not byte-equal. |

## Design

The headline property is structural: `resolve_given(c, compat_ok)` takes the record only as a boolean, and the Ok value is `configured_arn(c)`. So theorems A and A2 hold for any compatibility predicate and do not depend on T11. T11 (the MRK match) is needed for the exact Ok/Err set (B to E, I). I modeled `aws_kms_mrk_match_for_decrypt` branch by branch with a char-level model of `split(':')` and `split_once('/')`, and proved the model of `split` correct (L1 to L4 style lemmas) instead of leaving it abstract. The exec function is generic over `trait ArnCompat` because vstd has no specs for `str::split`, `splitn`, `split_once`, `starts_with`, so an exec MRK match could not be written without `external_body`. H_ORACLE (theorem H) is the explicit link.

The two non-pinned arms are excluded by `requires is_pinned(kms_config@)`, as in the T03 `formal_spec`. They are closed in the exec body with `assert(false)`, which holds because of that precondition. The precondition is satisfiable (witnesses).

## Sanity checks (mutations in `/tmp/t03mut`, not in the repo)

Each of these made Verus fail:

1. exec returns the record ARN instead of the configured one (2 postconditions);
2. drop the account comparison in `mrk_match` (`lemma_mrk_match_iff`);
3. `resolve_given` ignores `compat_ok` (6 errors);
4. KmsKeyArn arm uses `mrk_match` instead of equality (theorem C);
5. drop the alias guard in `mrk_match` (2 errors);
6. exec skips the `is_arn_compatible` check (2 errors).

These cover edits to the model only. They say nothing about edits to the code.

## What failed during development

- `lemma_split_colon_free`: first version missed the empty-string case and the `rest.skip(1)` fact. Fixed.
- `ByteEqCompat`: first spec used `configured_arn(c) == stored` for all variants, but `configured_arn(Discovery)` is empty, which disagreed with the exec `false`. Fixed the spec with `is_pinned(c) &&`. (A model bug, not a code finding.)

## Findings and observations

No failing spec-faithful lemma. Nothing contradicts T03's property.

- **O1, DEV-ALIAS (documented in `mrk_match.rs:10-19`).** Two identical alias ARNs: spec text returns true, code returns false. Stricter than the spec. Unreachable for a configuration accepted by `build()` because `validate()` rejects aliases (`theorem_i`, under H_BUILD: `branch_key_store.rs:381`, field private).
- **O2, loose ARN validity.** The model of `is_multi_region_arn` and `validate_kms_key_arn` accepts an ARN with empty partition, region and account (`witness_empty_parts_accepted`). `aws-kms-key-arn.md` requires them non-empty, and `branch-key-store.md:157-158` requires a valid configured ARN. `validate_kms_key_arn` also accepts any resource type except `alias` (read from `kms_config.rs:61-79`, not modeled), where the spec says `alias` or `key`. No effect on T03: the KeyId is the configured ARN either way, and a record can only match on the configured partition, service, account and resource id. This is a conformance gap in config validation, outside this target.
- **YAML check.** The T03 YAML line anchors match HEAD: fn `:88`, arms `:94-95`, compat check `:105`, Ok `:113`, call `:179`, `key_id` `:183`. The Err kind is `Validation`. `r.is_Ok() <==> compat_spec` holds as T-B. The YAML says "ReEncrypt": `version_key` passes the resolved value as source and destination (`branch_key_store.rs:678-`, `kms_ops.rs:271-272`); covered by audit only (H_CALLER).
- The Err message quotes the record ARN and the configured ARN. Not a security issue.

## Not covered

Discovery and MrDiscovery arms (T17 / BUG-04); `version_key` flow beyond the call; KMS-side authentication; panic freedom of shipped indexing (`lemma_mrk_match_indices_in_range` is a model fact); `format!`; error fields other than `kind`; rollback of an authentic older record.

## Gap to the shipped code

Audited correspondence, not machine-checked. See the file header for the table and the four steps to close it.
