# T02 working notes: record reconstruction (VR-2026-T02, TM-MPL-005)

Proof file: `verus-proofs/t02_record_reconstruction.rs`
Log: `.agents/tasks/verus-proofs-quickwins/logs/t02_record_reconstruction.log`
Result line: `verification results:: 21 verified, 1 errors` (the 1 error is the intended G1 finding).
Verus 0.2026.07.12.0b42f4c, HEAD 66aba1c. No file under mpl/, prim/, esdk/, docs/ was changed. Nothing committed.

## Approach and why
The target is native Rust over `BTreeMap<String,String>`, `Vec<u8>`, `Zeroizing`, and the crate's
`Error`/`BranchKeyMaterials`. Verus cannot check it in place. vstd has `BTreeMap`/`String` types but:
- no `get::<str>` on `String` keys (axioms exist only for `Key == Q` and `Box<Q>`),
- no specs for `str::starts_with` / `strip_prefix`,
- no axiom that `String::deep_view` is injective (needed to turn `Map<String,_>` into `Map<Seq<char>,_>`).
Closing these with `assume_specification` or `external_body` would enlarge the trusted base for little gain, so I
used a standalone spec-level model: `Str = Seq<char>`, `Ec = Map<Str,Str>`, and one spec fn per step of the code.
The TCB is therefore Verus + Z3 + vstd's Seq/Map/Set axioms only. No `assume`, `admit`, `external_body`,
`assume_specification`, or uninterpreted fn is used. The price is the model-vs-code gap (header of the file,
"MODEL-vs-CODE GAP"). The correspondence table in the header maps each model fn to record.rs line ranges.

Constants were cross-checked mechanically: a script extracted the `pub const ... = "..."` strings from
`attributes.rs` and compared them with the `seq![...]` literals in the proof file. All 9 match.

## What is proved (all accepted by Verus)
- Theorem A: `reconstruct(ec,pt) is Ok <==> code_accepts(ec,pt)`. `code_accepts` is the exact condition of the shipped
  code: `type` present; ACTIVE or `branch:version:`-prefixed; `version` present when ACTIVE; version source strictly
  extends `branch:version:`; `branch-key-id` present AND non-empty; plaintext exactly 32 bytes.
- Theorem B: on Ok(m): `m.branch_key == pt` (len 32), `m.branch_key_id == ec["branch-key-id"]` (non-empty),
  `m.branch_key_version == ver_src(ec)` minus the 15-char prefix (non-empty, `prefix + version == ver_src`),
  `m.encryption_context == custom_ec(ec)`.
- Theorem C and C2: the exact `Fail` variant for each first-failing check, in code order; every Err has kind
  InvalidMaterials (by construction of `kind_of`, tied to the code by the 7-site audit in the header).
  `BuilderRejectedEmptyVersion` is unreachable (lemma_empty_version_unreachable).
- Custom EC: `lemma_custom_ec_member` / `lemma_custom_ec_exact` (set definition from the spec), and
  `lemma_fold_eq_custom`: the loop at record.rs:84-88, modeled as `custom_fold` over ANY enumeration of the map's keys,
  equals the comprehension `custom_ec`. Prefix stripping is injective, so no collisions and order does not matter.
  (This is the "collision branch is dead" fact that C01 needs.)
- Corollaries mirroring unit tests: bare `branch:version:` as type rejected; ACTIVE with bare-prefix version rejected;
  `beacon:ACTIVE` rejected; a well-formed version record is accepted with version exactly `w`.
- `lemma_unrelated_attribute_ignored`: adding/removing any attribute that is not `type`/`version`/`branch-key-id` and
  has no `aws-crypto-ec:` prefix does not change the outcome.

## FINDING G1 (confirmed): the code does NOT enforce create-time / hierarchy-version
- `lemma_g1_spec_soundness_FAILS` states the spec-faithful direction `Ok ==> create-time and hierarchy-version present`
  (branch-key-store.md :677, :690, :692; the Encryption Context section also says the EC MUST have `create-time` :596 and `hierarchy-version` :599; MUST-fail sentences :531, :553, :574). Verus rejects it (postcondition not
  satisfied). It is left as is.
- `lemma_g1_spec_completeness` (spec-accepted records are accepted by the code) is proved: the code is more permissive
  than the spec, never stricter.
- `lemma_g1_code_ignores_fields` (proved): the outcome is identical with or without `create-time`, or with or without
  `hierarchy-version`, for every EC and key. This is the general reason the failing lemma is false.
- `lemma_g1_witness_accepted_without_fields` (proved): concrete record `{type: "branch:version:v", branch-key-id: "k"}`
  with a 32-byte key is Ok and violates `spec_accepts`.
- Sanity check that the failing lemma has the right form: in a scratch copy (/tmp/t02mut/m5.rs, not in the repo) I added
  "missing create-time or hierarchy-version => Err" to the model's `reconstruct`. `lemma_g1_spec_soundness_FAILS` then
  verified (the Theorem-A style lemmas failed, as expected, since the code behavior changed). So a fix in the code makes
  the spec-faithful lemma provable.
- Owner decision (from the YAML): enforce in this function, or in `record_from_ddb_item` (branch_key_store.rs:1141-1200),
  which is where the spec says the operation MUST fail. The model here is the pure predicate for the first option.
- Impact stays low, as the YAML says: an altered record fails KMS Decrypt (the EC is the AAD), so only a record from a
  non-conforming writer that never had the fields is accepted.

## Mutation checks (scratch copies in /tmp/t02mut, not in the repo)
Each mutation of the model made Verus fail, so the lemmas are not vacuous:
- m1 drop the non-empty-version filter: 5 errors
- m2 drop the type-value check: 3 errors
- m3 drop the empty-id rejection: 3 errors
- m4 custom_fold without the prefix test: 2 assertion failures + 1 postcondition
- m5 enforce create-time/hierarchy-version: spec-soundness lemma verifies (see above)

## Other observations (not proof failures)
- O1: structures.md "Branch Key Version MUST be a version 4 UUID". The code accepts any non-empty string after the prefix
  (the witness above uses version `v`). Not modeled; candidate for the spec/threat docs.
- O2: the T02 YAML `formal_spec` omits "branch-key-id is non-empty". The builder rejects an empty id
  (branch_key_materials.rs:174-176, mapped to InvalidMaterials) and branch-key-store.md :593 requires it. The proof's
  `code_accepts` and `spec_accepts` include it. Suggest adding it to the YAML.
- O3: the spec EC also MUST have `kms-arn` and `tablename` (branch-key-store.md :597-598). `tablename` is always injected
  by `build_auth_ec` (branch_key_store.rs:132-139); `kms-arn` is required by `decrypt_branch_key` (kms_ops.rs:172), before
  this function runs. Neither is checked here, and neither is part of the T02 property.
- O4: `record_from_ddb_item` and `build_auth_ec` are not modeled, so the record-completeness view in the YAML
  (`record_from_ddb_item ... only enc is required today`) is not proved here. That is T01's read side.

## Reuse by the C01 follow-up
Copy sections 1-3 of the proof file (types and constants, spec fns `get`/`step_*`/`custom_ec`/`custom_fold`/`reconstruct`,
and lemmas `lemma_prefix_split`, `lemma_concat_prefix`, `lemma_custom_ec_member`, `lemma_fold_char`,
`lemma_fold_eq_custom`, `lemma_custom_ec_exact`). Sections 4-6 are optional. Do not copy section 7 unless you want the
failing obligation. Keep `fn main() {}` after the `verus!` block (Verus needs an entry point for a single file).
The EC builders of C01 (encryption_context.rs) would need their own model; the target of the round trip is
`custom_ec(ec)` and the `branch-key-id` / version fields in Theorem B.

## What would close the model-vs-code gap
See the file header: move the function into `verus!` (or `cargo verus`), add specs for BTreeMap borrowed-`&str` lookup on
`String` keys, `str::starts_with`/`strip_prefix`/`is_empty`, `String::clone`, `<[u8;32]>::try_from`, `Zeroizing`, an
injectivity axiom for `String::deep_view`, and a spec for `Error::new`/`BranchKeyMaterialsBuilder`. Each is a trusted
std/third-party spec and must be listed as an assumption.
