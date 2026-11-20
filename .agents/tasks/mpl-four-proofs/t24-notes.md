# T24 notes (for the docs step)
Target: VR-2026-T24, `RawAesKeyringBuilder::build` reserved `aws-kms` key namespace check. Threat TM-MPL-001.
Score 1.20, estimated 1 day, agent route mpl-verus-header-parsing-proofs. Score, rank, gap and quick-win are
unchanged by this work. Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `ad3522b`. Nothing under `mpl/`, `prim/`,
`esdk/`, `docs/` or `dashboard/` was changed. Nothing was committed or staged.

## 1. Result
- Proof file: `verus-proofs/t24_raw_aes_namespace.rs` (untracked, 741 lines, header sections 0 to 5).
- Command: `~/verus/verus verus-proofs/t24_raw_aes_namespace.rs` (Verus 0.2026.07.12.0b42f4c), exit 0.
- Exact result line: `verification results:: 19 verified, 0 errors`
- Run log: `.agents/tasks/mpl-four-proofs/t24-run.txt`
- Status word to use: **Proved (model level, not the shipped code, under stated hypotheses).**
- Not a partial proof. There is no EXPECTED_FAIL obligation, because the code shows no gap against the spec (section 6).
- What it is, plainly: a model of the check as a byte-wise prefix test against the seven bytes `61 77 73 2d 6b 6d 73`,
  and of `build` as "first failing check wins". Verus proves, for all byte strings, which namespaces are rejected, what
  `build` returns, and what follows for the provider ID of emitted EDKs. R7 `theorem_matches_s1` is a consistency check
  (the model predicate is the spec sentence written as a predicate, true by construction). The prefix test is small
  and the repository already has tests for the same facts (`mpl/tests/test_raw_aes_keyring.rs` :769, the four-namespace
  test below it, `test_build_accepts_the_raw_ecdh_key_provider_id` :812). The proof adds the statement over all byte
  strings, and the exact accepted set. It does not show that the shipped code has these properties.

## 2. What the code compares (code reading)
`mpl/src/keyring/raw_aes_keyring.rs` :52 `const RESERVED_KEY_NAMESPACE_PREFIX: &str = "aws-kms";` and :360
`if key_namespace.starts_with(RESERVED_KEY_NAMESPACE_PREFIX)` returns `Err(Kind::Validation)`.
- Prefix, not equality. `aws-kms`, `aws-kms-hierarchy`, `aws-kms-rsa`, `aws-kms-ecdh`, `aws-kms-anything` are rejected.
- Case-sensitive, byte for byte. No trimming, no Unicode normalization, no lookalike handling.
- It runs at build time on the namespace that is moved into the keyring (:384). Only `build` constructs
  `RawAesKeyringInner` (:382).
- The check comes after the four `required(..)?` calls (:352-355) and before the wrapping-key length check (:369-379).

## 3. What is proved (relative to the model and the items in section 4)
| Id | Theorem (in the file) | Statement |
|---|---|---|
| R1 | `theorem_reserved_namespace_rejected` | For every suffix `t`, a namespace `aws-kms` + `t` is rejected by `build` for every other field value. With the other three fields set the error is `ReservedNs`. |
| R1 | `lemma_kms_provider_ids_rejected` | The four AWS KMS provider IDs, typed out byte by byte (not derived from the constant), are rejected. |
| R2 | `theorem_ok_implies_not_reserved` | If `build` returns Ok(k), k's namespace is the one given and it is not `aws-kms` + any suffix. |
| R3 | `theorem_build_ok_iff` | `build` is Ok exactly when the four fields are set, the namespace is not reserved, and the key length equals the algorithm's. The namespace check rejects nothing else. |
| R3 | `lemma_check_order` | A reserved namespace with a wrong key length reports `ReservedNs`; a missing algorithm is reported before a reserved namespace. |
| R4 | `theorem_emitted_provider_id_not_kms` | For a built keyring, the provider ID of every emitted EDK (its namespace) has no `aws-kms` prefix and differs from each of the four KMS IDs. Relative to H_EDK_ID. |
| R5 | `theorem_never_attempts_kms_edks` | For a built keyring, no EDK whose provider ID starts with `aws-kms` passes the filter at :192. Relative to H_DECRYPT_FILTER. |
| R6 | `lemma_has_prefix_iff_bytes`, `lemma_prefix_iff_suffix` | The prefix test, "there is a suffix" and the seven-byte test agree. |
| R7 | `theorem_matches_s1` | CONSISTENCY CHECK: the model predicate equals S1 on the namespace. True by construction. It shows the model was typed from the spec, not that the code is right. |
| R7 | `theorem_stricter_than_s2`, `theorem_built_keyring_satisfies_s1` | The model satisfies S2 for every configuration and rejects strictly more (`aws-kms-rsa`); the ID a built keyring emits satisfies S1. |
| R8 | `ns_has_reserved_prefix`, `ns_accepted` (exec) | An executable seven-byte comparison equals the spec prefix test for every slice, including slices shorter than seven bytes (no out-of-bounds read). |

## 4. Hypotheses and assumptions with evidence levels
Evidence levels: PROVED (checked by Verus in the file), ASSUMED (a premise or definition), CODE READING (a claim about
shipped code or std that Verus does not see). No `assume`, `admit`, `external_body`, `external`, `assume_specification`
or `#[verifier..]` is in the file (grep), and there is no uninterpreted spec function.
| Name | Level | Content |
|---|---|---|
| A_BYTES | ASSUMED | A namespace is an arbitrary `Seq<u8>`. Every `String` is one, so the theorems cover all strings. UTF-8 validity is not used. |
| A_SPEC_IDS | ASSUMED, copied by hand | The four AWS KMS provider IDs (`aws-kms`, `aws-kms-hierarchy`, `aws-kms-rsa`, `aws-kms-ecdh`) from `aws-kms-keyring.md` :98/:119, `aws-kms-rsa-keyring.md` :126, `aws-kms-ecdh-keyring.md` :199, `aws-kms-hierarchical-keyring.md` :187. Their tail bytes are not checked by any claim (mutant s01). |
| A_VSTD | ASSUMED | Verus, Z3 and the vstd `Seq` axioms. |
| H_STD_STARTS | CODE READING (std) | `str::starts_with(&str)` is a byte-wise slice prefix test: false if shorter, no case folding, no normalization. |
| H_CONST | CODE READING | `RESERVED_KEY_NAMESPACE_PREFIX` is defined once (:52) with bytes `61 77 73 2d 6b 6d 73` and used once (:360). |
| H_BUILD_ORDER | CODE READING | In `build`: four `required` (:352-355), prefix check (:360), key length check (:369-379), `Ok` (:381). All errors are `Kind::Validation`. |
| H_ONLY_BUILD | CODE READING | `RawAesKeyringInner` is built only at :382, fields are private, no setter, `Clone` copies the `Arc` (grep in mpl/src, esdk/src, prim/src). |
| H_NS_UNCHANGED | CODE READING | The namespace checked at :360 is the value moved into the keyring at :384. |
| H_EDK_ID | CODE READING | `wrap_data_key` (:146-184) is the only EDK construction in the file and sets the provider ID to `self.inner.key_namespace` (:179-181). `on_encrypt` calls it at :410 and :415. |
| H_DECRYPT_FILTER | CODE READING | `decryptable_edk_iv` returns None unless `edk.key_provider_id() == self.inner.key_namespace` (:192). `on_decrypt` uses it at :449-456. |
| H_CONSUMERS | CODE READING | In mpl/src and esdk/src the only provider-ID comparisons with a constant are :192 (own namespace) and `hierarchical_keyring.rs` :752 (against `"aws-kms-hierarchy"`, const at :807). Both use `!=` on `&str` (exact, case-sensitive). |
| H_MODEL_MATCH | CODE READING | `build`, `has_prefix`, `reserved` match the lines in the file header correspondence table. |

## 5. What is accepted, and what is not shown
Accepted by the check: any namespace that does not begin with the exact bytes `61 77 73 2d 6b 6d 73`.
Proved accepted (`lemma_accepted_witnesses`, `lemma_case_variant_builds`): the empty string, `aws-km`, `aws_kms`,
`aws-kmz`, `xaws-kms`, ` aws-kms` (leading space), `my-aws-kms`, `raw-ecdh`, `AWS-KMS`, `Aws-Kms`, `aws` + U+2010 + `kms`,
and a string starting with Cyrillic `a` then `ws-kms`. `theorem_case_variants_accepted` proves that every ASCII case
variant of `aws-kms` that is not byte-equal is accepted. `AWS-KMS` with a valid key builds an `Ok` keyring in the model.

Not shown:
- That the shipped code has these properties (model level only; nothing detects a later edit to `mpl/`).
- That no consumer treats a case variant, padded string or lookalike as an AWS KMS provider ID. The in-crate consumers
  compare exactly (H_CONSUMERS). A consumer outside this repository that compared case-insensitively is the documented
  TM-MPL-001 exclusion ("downstream case-insensitive provider-id trust", other components). Not mitigated or closed here.
- That TM-MPL-001 is mitigated. Only one check, at one constructor, of one keyring type is modeled. Other keyring
  types, caller-implemented `Keyring` types and direct construction of EDKs are not modeled.
- Validity of the key name or wrapping key beyond the length equality; the AES-GCM wrap; the provider-info layout; decryption.
- The empty namespace is accepted by this check. Whether that is acceptable is outside T24.

## 6. Findings
- **F0, no gap.** The code check (case-sensitive byte prefix) is not narrower than either spec sentence. Spec S1
  (`spec/framework/keyring-interface.md` :83-86, "key provider ID ... MUST NOT be or start with "aws-kms" unless this
  encrypted data key was produced by one of the AWS KMS Keyrings") is a prefix rule, and the provider ID equals the
  namespace in the code. Spec S2 (`spec/framework/raw-aes-keyring.md` :22, change log 0.3.0: "Raw AES keyring MUST NOT
  accept a key namespace of "aws-kms"") is an equality rule, and the code is stricter than it. No EXPECTED_FAIL
  obligation was written, and none was invented.
- **O1, observation (not a gap).** Case variants, padded strings and lookalikes are accepted. Both spec sentences name
  the lowercase string and do not ask for case folding or normalization. Record it as a statement about the accepted
  set. The residual (a downstream case-insensitive consumer) belongs to the existing TM-MPL-001 exclusion.
- Housekeeping: the target text gives `build` at `:350`. In the HEAD file `build` starts at :351 and the check is at
  :360 as stated. The YAML `function` line cites `:350` and `:52`; no change is needed for the status line.

## 7. Code and spec locations read
- `mpl/src/keyring/raw_aes_keyring.rs`: :44-52, :58-112, :146-195, :226-266, :351-390, :399-460.
- `mpl/src/builder.rs` :7-9; `mpl/src/structures/aes_wrapping_alg.rs` :12-34; `prim/src/lib.rs` :148.
- `mpl/src/aws_kms/hierarchical_keyring.rs` :752, :807.
- `mpl/tests/test_raw_aes_keyring.rs` :769-820 (tests, not proofs).
- Spec: `keyring-interface.md` :59-86; `raw-aes-keyring.md` :20-22, :64-69, :175-183, :212-216; the four KMS keyring spec files named in A_SPEC_IDS.

## 8. Duplicate check against `Mahnush_Verus`
Text for the docs step, in the form of the existing sections ("### T24 against Mahnush_Verus"):

Result of the duplicate check: **T24 does not duplicate anything on `Mahnush_Verus`.** Ref read: `origin/Mahnush_Verus` at `8d6381e` (the tip used for the C03, T04 and T06 records). It was read with `git grep`, `git ls-tree`, `git diff` and `git show` only. Nothing was merged, checked out or modified.
- **No Verus in `mpl/` there.** `git grep -l 'verus!' origin/Mahnush_Verus -- mpl` returns nothing. The files that use `verus!` are in `.kiro`, `docs`, `esdk` and `prim`.
- **Same code.** `git diff HEAD origin/Mahnush_Verus --stat -- mpl/src` is empty, and so is the same diff for `mpl/src/keyring/raw_aes_keyring.rs`. The reserved prefix is the same constant (`:52`) and the same check (`:360`), plain Rust, outside `verus!`.
- **No `verus-proofs/` directory** there (`git ls-tree -r --name-only origin/Mahnush_Verus` has no such path).
- **Searches.** `git grep -n -E 'TM-MPL-001|VR-2026-T24|\bT24\b' origin/Mahnush_Verus` has no hit. `git grep -n -i -E 'aws-kms.*(prefix|reserved|namespace)|(reserved|namespace).*aws-kms|key.namespace.*(reject|must not)' origin/Mahnush_Verus -- docs verification prim esdk/src .kiro` has no hit. A search for `RESERVED_KEY_NAMESPACE`, `key_namespace`, `RawAesKeyring` and `raw_aes` in `docs`, `verification`, `prim`, `esdk` and `.kiro` finds only esdk examples and README text that call `.key_namespace("my-key-namespace")`, and `docs/verus-proofs-report.md` :650-678 and `docs/verification-recommendations.md` :997, which discuss BUG-07 (plaintext data key buffers at `wrap_data_key`). One line there (`docs/verus-proofs-report.md:663`) mentions the wrapping-key length check in `RawAesKeyringBuilder::build` (cited as `raw_aes_keyring.rs:369-378`) as the reason a key or nonce error cannot fire. That is the length check, not the namespace check, and it is prose, not a proof.
- **No overlap at the primitive level either.** VR-006, VR-008, VR-009, VR-013 and VR-014 concern `prim` and `esdk` functions (AES-GCM buffer bounds, ECDSA length, HKDF decisions, the prim wrappers). None concerns a string prefix check, a provider ID or a keyring builder. T24 does not depend on any of them being on this branch.

Row for the "Item / On MPL-Verus / On Mahnush_Verus" table: `T24 | Proof of a model in verus-proofs/ (model level, not the shipped code) | No verus-proofs/ directory; no Verus in mpl/; same check at raw_aes_keyring.rs:360, no proof. Not a duplicate.`

## 9. Mutation summary
Script: `.agents/tasks/mpl-four-proofs/t24-mutate.py`. Record: `.agents/tasks/mpl-four-proofs/t24-mutation-run.txt`.
Mutants: `.agents/tasks/mpl-four-proofs/mutants/t24/` (18 files). Baseline `19 verified, 0 errors`.
Result: 18 variants, 15 rejected, 3 survived, 0 differ from the prediction made before the run.
Rejected (model edit, then which obligation fails):
- m01 prefix replaced by exact match: 8 errors (R1, R2, R3, order, R4, R5, S2, S1 lemmas).
- m02 case-insensitive compare: 2 errors (`theorem_build_ok_iff`, `lemma_case_variant_builds`).
- m03 different prefix string (`aws-kmt`): 1 error, `lemma_reserved_bytes` only. That lemma pins the seven bytes. The other lemmas follow the constant. The constant matching `:52` is code reading (H_CONST).
- m04 check dropped: 8 errors. m05 check after key length: 2 errors. m06 wrong error variant: 2 errors.
- m07 seven-byte test with a wrong byte: 1 error. m08 emitted ID is the key name: 2 errors. m09 decrypt filter as prefix: 1 error.
- m10 `ns_ok` not negated: 6 errors. m11 wrong key length table: 1 error. m12 S1 weakened: 1 error.
- m13 exec length guard too small: 1 error (out-of-bounds index). m14 exec wrong byte: 1 error. m15 an accepted witness replaced by a reserved string: 1 error.
Survivors (all predicted):
- s01 tail typo in `kms_id_ecdh`: only the first seven bytes of a KMS ID matter to any claim. The IDs are a spec copy (A_SPEC_IDS).
- s02 `lower` upper bound changed: `lower` appears only in the hypothesis of `theorem_case_variants_accepted`, which holds for any `lower`. It only describes what a case variant is.
- s03 the built keyring stores the namespace as its key name: no claim reads `key_name`.
These checks cover edits to the model only, not edits to the shipped code.

## 10. Files
- `verus-proofs/t24_raw_aes_namespace.rs` (new, untracked)
- `.agents/tasks/mpl-four-proofs/t24-run.txt`, `t24-mutate.py`, `t24-mutation-run.txt`, `t24-notes.md`, `mutants/t24/*.rs`
