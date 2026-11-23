# C01 working notes: EC builders ∘ reconstruction (VR-2026-C01, BUG-08)

Proof file: `verus-proofs/c01_ec_roundtrip.rs`
Log: `.agents/tasks/verus-proofs-quickwins/logs/c01_ec_roundtrip.log` (unedited, exit code 0)
Result line: `verification results:: 40 verified, 0 errors` (Verus 0.2026.07.12.0b42f4c, HEAD 66aba1c).
Nothing under mpl/, prim/, esdk/, docs/ changed. T02 proof file unchanged (sha1 3710fe19...). Nothing committed or pushed.

## Approach
Same as T02: a standalone spec-level model (`Str = Seq<char>`, `Ec = Map<Str,Str>`), because the shipped code is
native Rust over BTreeMap/format!/Error and vstd has no specs for them (see t02-notes.md).
The T02 model was usable. Lines 128-575 of `t02_record_reconstruction.rs` (sections 1-3 and Theorems A and B) are copied
verbatim between two marker comments; a script checked the copy is byte-identical. The builders are new.

Builder model: `base_map` (six inserts), `insert_custom` (the loop at encryption_context.rs :87-104, as a recursion on
`drop_last`, `is_some()` == `acc.contains_key`), `build_base`, `decrypt_only_ec`, `active_ec`, `beacon_ec`.
The loop is parameterised by `keys`, the order in which `custom.iter()` yields keys. Any order is covered.

## What is proved
- `lemma_insert_custom` (core): for a base map with no key starting `aws-crypto-ec:`, the loop returns Ok iff the key
  sequence has no duplicates, its only Err is Collision, and on Ok the result is base plus the prefixed custom entries.
- `theorem_rt_decrypt_only`, `theorem_rt_active`: YAML (a). With non-empty id, non-empty version, 32-byte key, the builder
  returns Ok, reconstruct returns Ok with the same id, version v, custom EC (as a map) and key, and `spec_accepts` holds.
- `theorem_rt_beacon`: beacon EC builds; reconstruct returns `BadTypeValue` for every plaintext; the beacon read path
  (custom-EC extraction + branch-key-id, branch_key_store.rs :885, :887-890) round-trips.
- `theorem_builders_exact_errors`: builders fail only on empty id or empty version, never with Collision.
- `theorem_prefix_strip_inverse`: YAML (b).
- `theorem_bug08_collision_iff_duplicate`, `_unreachable`, `lemma_bug08_collision_live_under_duplicates`,
  `lemma_bug08_prefixed_custom_key_ok`: YAML (c), see below.
- `theorem_d_record_ec_record`, `theorem_d2_ec_record_ec`: YAML (d): `to_attribute_map(encryption_context_from_item(r,n), r.enc) == r`
  iff r has neither `tablename` nor `enc`; and the reverse composition is the identity for ECs with `tablename` = n and no `enc`.
- `theorem_prod_roundtrip`, `theorem_prod_beacon`: production pair through `item_from_ec_and_enc` / `record_from_ddb_item` /
  `build_auth_ec`, under assumption A_DDB (store returns what was written) and A_NAME (same logical name).
- `lemma_enum_exists`: every map has an enumeration, so the `enumerates` precondition is satisfiable (not vacuous).
- Debug asserts: the two `debug_assert!` facts (no `enc`, encryption_context.rs :81-84; no `version` on DECRYPT_ONLY/beacon,
  :151-154, :165-168) are only checked in debug builds. The model proves them (`built_facts`), so they hold in release too,
  modulo the model-vs-code gap.

## BUG-08: what is provable
In the model, with non-empty id and type, `build_base == Err(Collision)  <=>  keys has a duplicate`.
So the branch is dead exactly when `custom.iter()` yields each key once (A_ITER). That holds for BTreeMap, and
`EncryptionContext` is a newtype over `BTreeMap<String,String>` (structures/encryption_context.rs :16), so it holds by type.
The other half of the invariant is machine-checked: no base attribute name starts with `aws-crypto-ec:` and prefixing is
injective. The two cases named in the code comment (key already carrying the prefix, duplicate after prefixing) are not collisions.
Not provable here: A_ITER itself (a std contract) and that `format!` is concatenation. If `EncryptionContext` stops being a
map, the branch becomes reachable and these proofs no longer apply. Status of BUG-08: confirmed dead code, harmless (it returns Err).

## Findings
- **No builder/reconstruction mismatch.** The round trip holds for every non-empty id and version and every custom EC, including empty
  keys, empty values, and keys that already start with `aws-crypto-ec:`.
- **G1 does not bite honest writers.** Every EC the builders produce carries `create-time` and `hierarchy-version`, so it satisfies
  T02's `spec_accepts`. G1 only lets through records from non-conforming writers.
- **Beacon asymmetry (observation).** `branch_key_materials_from_authenticated_encryption_context` rejects a beacon record,
  as the YAML says. The production beacon read path does not call it; it only extracts the custom EC and reads `branch-key-id`
  and relies on `fetch_record` selecting `type = beacon:ACTIVE`. Nothing there checks `type`. Not a defect by itself.
- **Version is not a UUID on either side** (carried from T02 O1). `create_key` generates a UUID v4 (:557), but builder and
  reconstruction both accept any non-empty string. The round trip does not need UUIDs.
- **YAML note.** Property (a) says "UTF-8 custom EC": the type is `String`-keyed, so that holds by type and the model needs no UTF-8 clause.
  Property (d) "iff" is correct as written.

## Mutation checks (scratch copies in /tmp/c01mut, not in the repo)
Each made Verus fail, so the lemmas are not vacuous:
- m1 loop inserts the unprefixed key: 2 assertion failures reported
- m2 ACTIVE `version` attribute without the `branch:version:` prefix: 1 error
- m3 empty-id check removed in build_base: 2 errors
- m4 a base key starting with the prefix added to base_map: 1 error (lemma_base_map_props)
- m5 `enumerates` without `no_duplicates`: 2 errors (BUG-08 dead-branch lemmas)
- m6 loop drops the custom value: 1 error
Constants: a script extracted all 12 `pub const` strings used from attributes.rs and compared them to the `seq![...]` literals. All match.
`grep` finds no `assume`, `admit`, `external_body`, `assume_specification` or `#[verifier` in the file.

## Model-versus-code gap
See the file header (MODEL-vs-CODE GAP). The proof is about a model; nothing detects an edit to encryption_context.rs or
record.rs. Closing it needs the code inside `verus!` plus specs for BTreeMap insert/iter on String keys (A_ITER), format!, strip_prefix,
u32::to_string, Error::new, the builder, Zeroizing, and a model of DynamoDB for the production section.

## Build note
`Set::finite()` is deprecated in this vstd (every Set is finite), so the file does not use it. The log contains Verus trigger-selection
notes (informational, no failures).
