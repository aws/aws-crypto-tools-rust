# Verus proofs: quick wins (T02, C01, C02)

Three Verus proofs for targets from the verification-targets pipeline. Repo `esdk-native-mpl`, HEAD `66aba1c` (`mpl/` and `prim/` equal `main` 620771c).

**What these are.** Each file is a proof about a hand-written, re-typed model of the shipped Rust. None of them verifies the shipped code. The code is not inside `verus!`, is not compiled by Verus, and nothing detects a later edit to `mpl/` or `prim/`. The link between model and code is a correspondence table in each file header that a human reviewed. Read every status below as "the logic of the model is machine-checked; the model's fidelity to the code is audited, not checked."

T03 and T05 are described in `README-t03-t05.md`. T01 and T13 were added later (HEAD `4964d66`) and are described in the sections "T01" and "T13" below. The same rules apply to them: model level, not the shipped code.

None of the files is part of a cargo build. They live outside `mpl/`, `prim/`, `esdk/` and `docs/`.

## How to run

Verus 0.2026.07.12.0b42f4c (release, macos_aarch64, toolchain 1.96.0). From the repo root:

```sh
~/verus/verus verus-proofs/t02_record_reconstruction.rs   # exit 1, expected (see T02)
~/verus/verus verus-proofs/c01_ec_roundtrip.rs            # exit 0
~/verus/verus verus-proofs/c02_sign_fixed_len.rs          # exit 0
~/verus/verus verus-proofs/t01_keystore_auth_ec.rs        # exit 0
~/verus/verus verus-proofs/t13_cache_identifier.rs        # exit 1, expected (see T13)
```

Each file ends with `fn main() {}` because Verus needs an entry point for a single file. The logs are in `.agents/tasks/verus-proofs-quickwins/logs/`. An independent reviewer re-ran all three from the repo root. The output was byte-identical to the logs (see `.agents/tasks/verus-proofs-quickwins/review.md`). The T01 and T13 run records are `.agents/tasks/t01-t13/t01-run.txt` and `t13-run.txt` (workspace root, outside the `esdk-native-mpl` repo). The same directory holds the T01 model mutation checks (`t01-mutations.txt`) and a review (`review.md`, verdict approved, no blocking findings). Both files were run again when this section was written and gave the same result lines.

## Results

| ID | Target | File | Result line (from the log) | Exit | Status |
|---|---|---|---|---|---|
| T02 | VR-2026-T02 / TM-MPL-005 | `t02_record_reconstruction.rs` | `verification results:: 21 verified, 1 errors` | 1 | **Partly proved** |
| C01 | VR-2026-C01 / capability 1c | `c01_ec_roundtrip.rs` | `verification results:: 40 verified, 0 errors` | 0 | **Proved** (model level, under hypotheses A_ITER; A_DDB and A_NAME for `theorem_prod_*`) |
| C02 | VR-2026-C02 / capability 2d | `c02_sign_fixed_len.rs` | `verification results:: 21 verified, 0 errors` | 0 | **Proved** (model level) |
| T01 | VR-2026-T01 / TM-MPL-005, TM-MPL-002 | `t01_keystore_auth_ec.rs` | `verification results:: 52 verified, 0 errors` | 0 | **Proved** (model level, relative to A_KMS, A_DDB, A_NUM, A_NAME, A_ITER, A_ARN and H_SAME_EC) |
| T13 | VR-2026-T13 / TM-MPL-009, TM-MPL-010 (BUG-06) | `t13_cache_identifier.rs` | `verification results:: 42 verified, 1 errors` | 1 | **Partly proved** (model level; the one error is the intentional BUG-06 obligation) |

Meaning of the status words:

- **Proved** here means: the log shows `0 errors`, no `assume`, `admit`, `external_body`, `assume_specification` or `#[verifier...]` appears in the proof code (checked by grep), and every external assumption is stated in the file header and in the TCB table below. It does not mean the shipped code is verified.
- **Partly proved** (T02, T13): everything verifies except one obligation that fails on purpose, and the failure is a finding.
- For T01 and T13, a grep for `assume`, `admit`, `external_body`, `assume_specification` and `#[verifier` outside comments finds nothing in either file. Both headers state the same.

---

## T02: record reconstruction (VR-2026-T02 / TM-MPL-005)

**Property in plain language.** `branch_key_materials_from_authenticated_encryption_context` accepts a stored record exactly when it is well formed. On acceptance it returns the key, id, version and custom encryption context that the record carries. Every rejection has a known cause and the error kind `InvalidMaterials`.

**Status: Partly proved.** 21 obligations verify. The one failing obligation is `lemma_g1_spec_soundness_FAILS` (`t02_record_reconstruction.rs:767`, postcondition at `:771`). It states the spec property "Ok implies the record has `create-time` and `hierarchy-version`". The code does not enforce this, so Verus is right to reject it. I left it failing and did not weaken it.

**What the theorems say** (proof file lines):

| Theorem / lemma | Line | Statement |
|---|---|---|
| `theorem_a_ok_iff_code_accepts` | 545 | `reconstruct` returns Ok exactly when: `type` is present and is `branch:ACTIVE` or starts with `branch:version:`; `version` is present when `type` is `branch:ACTIVE`; the version source strictly extends `branch:version:`; `branch-key-id` is present and non-empty; the plaintext is exactly 32 bytes. |
| `theorem_b_ok_fields` | 556 | On Ok: key equals the plaintext; id equals `ec["branch-key-id"]`; version equals the version source minus the 15-character prefix and is non-empty; encryption context equals the `aws-crypto-ec:` entries with the prefix stripped. |
| `theorem_c_error_sites`, `theorem_c2_late_error_sites` | 580, 599 | Each Err variant is the first failing check in code order. Every Err has kind `InvalidMaterials`. |
| `lemma_empty_version_unreachable` | 619 | The builder's "empty version" rejection cannot be reached. |
| `lemma_fold_eq_custom`, `lemma_custom_ec_exact` | 480, 511 | The loop at `record.rs:84-88` equals the set definition for any iteration order. Prefix stripping is injective, so the collision branch is dead. |
| `lemma_g1_spec_completeness` | 747 | A record that meets the full spec is accepted. The code is more permissive than the spec, never stricter. (Weaker than soundness; see G1.) |
| `lemma_g1_code_ignores_fields` | 786 | The outcome is identical with or without `create-time`, and with or without `hierarchy-version`, for every input. |
| `lemma_g1_witness_accepted_without_fields` | 814 | A concrete record with only `type` and `branch-key-id` and a 32-byte key is accepted. |
| unit-test corollaries (section 5, from `:627`) | 627 | Bare `branch:version:` as type, ACTIVE with a bare-prefix version, and `beacon:ACTIVE` are rejected. A well-formed record is accepted. |

**Why the kind half of Theorem C holds.** `kind_of` is `InvalidMaterials` by construction of the model. The link to the code is an audit: the target has 7 error sites (`record.rs:101-106, 108-116, 119-128, 137-148, 151-158, 164-172, 175-183`) and all call `malformed()`.

**Assumptions / TCB.** Verus, Z3 and vstd's `Seq`, `Map` and `Set` axioms, plus `Set::lemma_map_by_contains` (vstd lemma, used as `broadcast use` at `:402`). The nine string constants were transcribed by hand from `attributes.rs:11-24` and compared by script; all nine match. `Str` is `Seq<char>`, so a byte-prefix test on UTF-8 is assumed to agree with a char-prefix test.

**Model-vs-code gap.** Model: `Map<Seq<char>, Seq<char>>` and one spec function per step. Code: `BTreeMap<String,String>`, `Vec<u8>`, `Zeroizing`, the crate's `Error` and `BranchKeyMaterials`. To close the gap you need all of:

1. The function and the constants moved into `verus!`, or `cargo verus` on the real crate.
2. vstd specs for `BTreeMap::{get, iter, insert}` with `&str` lookup on `String` keys (vstd has them only for `Key == Q` and `Box<Q>`), for `str::{starts_with, strip_prefix, is_empty}`, `String::clone`, `<[u8;32]>::try_from(&[u8])` and `Zeroizing` deref.
3. An axiom that `String::deep_view` is injective.
4. A spec for `Error::new` and `BranchKeyMaterialsBuilder`, or a proof of the model against their source.

**Source.** Proof: `verus-proofs/t02_record_reconstruction.rs` (header `:1-123`, model sections 1-4 `:128-625`, G1 sections 7-8 `:742-847`). Code: `mpl/src/key_store/record.rs:95-184` (main function), `:79-91` (custom EC loop), `mpl/src/structures/branch_key_materials.rs:173-189` (builder), `mpl/src/key_store/attributes.rs:11-24`.

**Not covered.** `record_from_ddb_item` (`branch_key_store.rs:1141-1200`) and `build_auth_ec`; error message, source and resource fields; zeroization; that the key came from a correct KMS Decrypt; rollback of an older authentic record (stated non-goal of TM-MPL-005).

---

## C01: encryption-context builders and reconstruction round trip (VR-2026-C01 / capability 1c)

**Property in plain language.** The EC builders in `encryption_context.rs` and the reconstruction in `record.rs` are inverses on (branch key id, version, custom EC). The collision `Err` branch in `build_base` (BUG-08) cannot be reached.

**Status: Proved, at model level, with hypotheses.** `40 verified, 0 errors`. The builder and BUG-08 theorems hold only under A_ITER (the `enumerates` precondition). The `theorem_prod_*` results also depend on A_DDB and A_NAME. These are listed below and are not proved. The log also holds Verus trigger-selection notes. They are informational, not failures.

**What the theorems say** (proof file lines):

| Theorem | Line | Statement |
|---|---|---|
| `theorem_rt_decrypt_only`, `theorem_rt_active` | 1155, 1197 | Given a non-empty id, a non-empty version `v`, a 32-byte plaintext and a custom EC enumerated in any order, the builder returns Ok(ec). Then `reconstruct(ec, pt)` returns Ok(m) with `m.branch_key == pt`, `m.branch_key_id == id`, `m.branch_key_version == v`, `m.encryption_context == custom EC`. The EC also satisfies T02's `spec_accepts`, so it carries `create-time` and `hierarchy-version`. |
| `theorem_rt_beacon` | 1254 | The beacon EC builds. `reconstruct` rejects it with `BadTypeValue` for every plaintext. The beacon read path (custom-EC extraction and `branch-key-id`) round-trips. |
| `theorem_builders_exact_errors` | 1286 | The builders fail only on an empty id or an empty version, never with `Collision`. |
| `theorem_prefix_strip_inverse` | 1399 | `strip(prefix + s) == s`, and `prefix + strip(x) == x` for every prefixed `x`. Re-prefixing `custom_ec(ec)` gives back exactly the prefixed part of `ec`. |
| `theorem_bug08_collision_iff_duplicate` | 1323 | For non-empty id and type, `build_base` returns `Err(Collision)` if and only if the key sequence from `custom.iter()` repeats a key. |
| `theorem_bug08_collision_unreachable` | 1337 | Under `enumerates` (no repeated key), `Collision` is not returned. |
| `lemma_bug08_collision_live_under_duplicates` | 1350 | If the sequence repeats a key, the branch is reachable in the model. So "dead" is a conclusion, not an artifact of the model. |
| `lemma_bug08_prefixed_custom_key_ok` | 1368 | A custom key that already carries `aws-crypto-ec:` is stored as `aws-crypto-ec:aws-crypto-ec:x` and round-trips. It is not a collision. |
| `lemma_attr_keys_not_custom_prefixed`, `lemma_prefix_inj` | 679, 806 | No base attribute name starts with `aws-crypto-ec:`. Prefixing is injective. |
| `theorem_d_record_ec_record`, `theorem_d2_ec_record_ec` | 1464, 1496 | `to_attribute_map(encryption_context_from_item(r, n), r.enc) == r` holds iff `r` has neither `tablename` nor `enc`. The reverse composition is the identity for an EC with `tablename == n` and no `enc`. These are test-utils helpers, not on a production path. |
| `theorem_prod_roundtrip`, `theorem_prod_beacon` | 1547, 1589 | The production pair through `create_key`, the stored item, `get_active_branch_key`, `get_branch_key_version` and `get_beacon_key`. These rest on A_DDB and A_NAME below. |
| `lemma_enum_exists` | 950 | Every map has an enumeration, so the `enumerates` precondition is satisfiable. |

The two `debug_assert!` facts (no `enc` in the built EC, `encryption_context.rs:81-84`; no `version` on DECRYPT_ONLY and beacon, `:151-154, :165-168`) are proved in the model, so they also hold in release builds, modulo the gap.

**Assumptions / TCB** (named in the file header):

- **A_ITER.** `custom.iter()` yields each key of the custom EC exactly once, in some order. This is the `enumerates` precondition of every builder theorem. It holds for `BTreeMap`, and `EncryptionContext` is a newtype over `BTreeMap<String,String>`. Verus cannot check it, because vstd has no spec for `BTreeMap::iter` on `String` keys.
- **A_STR.** `String` is `Seq<char>`. `format!("{A}{B}")` is concatenation. The 12 constants were copied by hand from `attributes.rs`; a script found all 12 equal.
- **A_DDB.** DynamoDB returns each attribute that `create_key` wrote, and the item read is the one written. It is built into the model as an identity (`stored_attrs`). Only the `theorem_prod_*` and `lemma_store_roundtrip` results depend on it.
- **A_NAME.** The reader's logical key store name equals the writer's. Same scope as A_DDB.
- **A_BLD.** `BranchKeyMaterials::build` behaves as modeled in T02. Inherited from T02.
- The T02 model is copied verbatim into this file (T02 lines 128-575), between two marker comments. A script confirmed the copy is byte-identical. If T02's model changes, this copy does not follow.

**Model-vs-code gap.** The builders and the reconstruction are native Rust over `BTreeMap<String,String>`, `format!`, `u32::to_string` and the crate's `Error`. To close the gap you need all of:

1. The builders and the reconstruction moved into `verus!`, or `cargo verus` on the real crate.
2. vstd specs for `BTreeMap::{insert, iter}` over `String` keys including the iteration-uniqueness contract (A_ITER), for `format!`, `str::{starts_with, strip_prefix, is_empty}`, `u32::to_string` and `String::clone`.
3. An injectivity axiom for `String::deep_view`.
4. Specs for `Error::new`, `BranchKeyMaterialsBuilder` and `Zeroizing`.
5. For `theorem_prod_*`: a model of the DynamoDB read and write and of `fetch_record`'s key selection. That is a service contract, not something this crate can prove.

**Source.** Proof: `verus-proofs/c01_ec_roundtrip.rs` (header `:1-173`, verbatim T02 copy `:179-632`, builders and theorems from `:636`). Code: `mpl/src/key_store/encryption_context.rs:40-107` (`build_base`, collision Err at `:91-102`), `:117-132`, `:137-157`, `:160-171`; `record.rs:37-71`; `branch_key_store.rs:132-139, 539-, 792-, 827-, 868-, 1089-1106, 1141-1200`.

**Not covered.** The KMS leg (T01 owns it); `fetch_record`, `decrypt_branch_key`, rotation; error text and `Zeroizing`; rollback of an authentic older record; `hierarchy_version.to_string()` and the `create-time` / `kms-arn` formats (opaque). Reconstruction is not injective on whole ECs. It inverts the builders on (id, version, custom EC) only.

---

## C02: bounded ECDSA signing loop (VR-2026-C02 / capability 2d)

**Property in plain language.** `sign_fixed_len` calls the signing closure at most 128 times, does not panic in the modeled code, and never leaves a partly written signature. On success the buffer holds exactly one signature of the required length. On failure the buffer is unchanged.

**Status: Proved, at model level.** `21 verified, 0 errors`.

**What the theorems say.** They hold for every closure with no precondition, whatever it returns on each call (Ok of any length, or Err).

| Theorem | Line | Statement |
|---|---|---|
| `sign_fixed_len_post`, `sign_fixed_len` | 327, 362 | At most 128 closure calls (a ghost log records one entry per call). No panic in the modeled code: Verus checks overflow, and the `copy_from_slice` precondition (equal lengths) is discharged by the `candidate.len() == want_len` test. Ok: the buffer equals the first candidate of the right length, written whole. Err: the buffer is unchanged. The buffer length never changes. |
| Err exits (same post) | 327 | Err is exactly one of: the closure returned Err on call n after n-1 wrong-length candidates; or all 128 candidates had the wrong length. |
| `ecdsa_sign_post`, `ecdsa_sign`, `ecdsa_sign_digest` | 596, 636, 678 | Same bound and buffer guarantees. A 0-call Err exit is also possible (bad buffer length or rejected key). A wrong-length buffer gives Err with zero signing calls and an untouched buffer. |
| `check_sig_len` | 267 | Ok exactly when the buffer length equals `signature_len(alg)`. |
| `sign_fixed_len_while` | 434 | Cross-check: a `while` version with an explicit `decreases MAX_SIGN_ATTEMPTS - attempt`. It proves the same postcondition without relying on vstd's `Range` iterator spec. |
| `witness_ok_first_attempt`, `witness_exhaustion`, `witness_wrong_buffer_length` | 494, 512, 556 | The contracts are satisfiable: Ok after exactly 1 call; exhaustion after exactly 128 calls with the buffer unchanged; a 70-byte P-256 buffer rejected with 0 calls. |

**Assumptions / TCB** (named A1 to A6 in the header):

- **A1.** vstd's `assume_specification` for `<[T]>::copy_from_slice` (`vstd/std_specs/slice.rs:213`): requires equal lengths, and writes the whole destination. The "no partial write" claim rests on this.
- **A2.** vstd specs for `Vec`, `Result` and `Range` iteration, plus Verus and Z3.
- **A3.** The signing closure is abstract. Nothing about nonce randomness is assumed, so the 2^-128 exhaustion probability is not covered.
- **A4.** `trait Backend` stands for the aws-lc-rs calls (key parse, `sign`, `sign_digest`, `digest`, `SystemRandom::new`). Its methods have no contracts. That none of them panics or hangs is assumed, not proved.
- **A5.** The ghost log counts calls. It is only as trustworthy as the claim that `sign_once()` appears once in the shipped loop and is followed by one push. This matches `ecdsa.rs:185-191` at 66aba1c and is a manual review item. Verus's `FnMut` model cannot count calls (vstd `axiom_fn_mut_call_ensures` treats closure state as unchanged), which is why the log exists.
- **A6.** Verus treats a generic `FnMut` as leaving the closure unchanged. T1 to T4 hold regardless, because A3 lets the closure return anything.

**Model-vs-code gap.** The model deviates from `prim/src/ecdsa.rs` as follows:

- `Signature` and `Error` are local types.
- `format!` payloads are dropped.
- `?` is written out as `match`.
- `mut sign_once` is renamed to a local binding.
- A ghost `log` parameter is added.

To close the gap, do one of the following. Each needs a change in `prim/`, which this task did not touch.

- (a) Make `prim` compile under Verus, with `external_type_specification` and `assume_specification` for `aws_lc_rs::signature::Signature::as_ref`.
- (b) Share the generic loop body between `ecdsa.rs` and the proof as one source text.
- (c) Add a script that diffs the control-flow skeleton of the model against `ecdsa.rs:180-210`.

**Source.** Proof: `verus-proofs/c02_sign_fixed_len.rs` (header with correspondence table `:1-157`). Code: `prim/src/ecdsa.rs:148` (`MAX_SIGN_ATTEMPTS`), `:158-163`, `:180-195` (`sign_fixed_len`), `:200-210`, `:224-239`, `:253-268`, `:94-96`.

**Not covered.** `ecdsa_verify*` (the YAML also lists "never returns Err"); `ecdsa_generate_keypair`; `DigestContext::finish`; any panic inside aws-lc-rs; wall-clock termination of a closure that blocks; timing and side channels.

---

## T01: key-store authenticated encryption context (VR-2026-T01 / TM-MPL-005, TM-MPL-002)

**Property in plain language.** The EC written with a branch-key record, the EC that KMS binds as the AAD, and the EC that the reconstruction reads are the same EC. Targets: `kms_ops::build_authenticated_encryption_context` (`kms_ops.rs:49`), `DynamoDbKeyStore::build_auth_ec` (`branch_key_store.rs:132`), `item_from_ec_and_enc` (`:1089`) and `record_from_ddb_item` (`:1141`).

**Status: Proved, at model level, with hypotheses.** `52 verified, 0 errors`. Nothing is left failing on purpose. KMS and DynamoDB are modeled by assumptions in the definitions of the model, so Verus cannot check them.

**What is new versus C01** (`c01_ec_roundtrip.rs`, 40 verified). C01 proves that the builders in `encryption_context.rs` and the reconstruction in `record.rs` are inverses, with the stored item treated as a set operation. It does not model KMS, the DynamoDB attribute mapping or `kms_ops.rs`. T01 copies the C01 model (C01 lines 178-1306, which include the T02 model) into its file unchanged and does not re-prove it. T01 adds:

1. The KMS-AAD side: `kms_aad` as a function separate from `rec_auth_ec`, with the proof that the two agree for every record attribute map (T01-A, under A_ITER) and that the AAD the reader builds equals the write-time EC (T01-C).
2. A symbolic model of the three KMS calls (GenerateDataKeyWithoutPlaintext, ReEncrypt, Decrypt) under A_KMS, and the claim that one local EC goes to both the KMS call and `item_from_ec_and_enc` (H_SAME_EC, code reading), with the DECRYPT_ONLY to ACTIVE ReEncrypt chain.
3. `item_from_ec_and_enc` and `record_from_ddb_item` as loops over any iteration order and over an AttributeValue model (S, N, B, other). The S, N and B mapping is lossless and the reader EC never contains `enc` (T01-B).
4. `VersionKey` (rotation), which C01 does not cover (T01-D).
5. The authenticity theorem T01-E: if the read passes KMS Decrypt, the EC the reconstruction uses equals the EC the ciphertext is bound to.

**What the theorems say** (names are the proof functions in the file):

| Theorem | Statement |
|---|---|
| `theorem_reader_builders_agree` (T01-A) | `kms_aad` and `rec_auth_ec` return the same EC for every record attribute map. |
| `theorem_reader_ec_is_spec` (T01-B) | For any item `record_from_ddb_item` accepts, in any iteration order, the reader EC has no `enc`, has `tablename` equal to the reader's name, and has every other item attribute. |
| `theorem_three_way` (T01-C) | The T01 property: for a record written under EC `ec`, the write-time EC equals the EC KMS bound, the reader's AAD equals the write-time EC, and the EC given to the reconstruction equals the write-time EC. KMS Decrypt with that AAD returns the generated key. |
| `theorem_prod_decrypt_only`, `theorem_prod_active`, `theorem_prod_beacon_kms` | The `create_key` wiring through KMS and the three readers: Decrypt succeeds and the reconstruction returns the id, version, custom EC and key. |
| `theorem_version_key` (T01-D) | For any stored item the reader accepts, the rotated DECRYPT_ONLY and ACTIVE ECs are well formed, the ReEncrypt is accepted, and both new records read back with the old id and custom EC and the new version and key. |
| `theorem_read_authentic` (T01-E) | For any item and reader name: if the read passes KMS Decrypt, no attribute was added, dropped or altered, and the ciphertext was written for this key store name. |

**Assumptions and hypotheses** (evidence levels as the other proofs use them):

- Assumed (A_*, not checked by Verus): A_KMS (KMS binds the EC given at generate and at the ReEncrypt destination, and accepts Decrypt or ReEncrypt-source only for an equal EC), A_DDB (DynamoDB returns what was written), A_NUM (`hierarchy-version` is a canonical Number rendering), A_NAME (reader and writer use the same key store name), A_ITER (`BTreeMap` and `HashMap` iteration yields every key), A_ARN (`fetch_record` returns the item for the requested id and type; ARN resolution, grant tokens and KMS errors other than the EC check are not modeled), A_STR, A_BLD.
- Theorem premises: H_WF (the EC written has `tablename` and no `enc`; proved for every EC the builders and `version_key` produce) and H_ENUM (the loop enumerations cover the maps; satisfiable).
- Code reading: H_SAME_EC. A later edit that passes a different EC to the KMS call and to the item is not detected.

**Findings.** No gap found at model level.

- O1: `kms_aad` and `rec_auth_ec` are two separately written functions with no shared code. They agree today (T01-A). If one is edited alone, for example `tablename` dropped from one, the reconstruction would read attributes KMS did not authenticate. A shared helper or a unit test that pins both would remove the need to keep them in step. Verus rejects six mutants of the model (`.agents/tasks/t01-t13/t01-mutations.txt`). They cover edits to the model only.
- O2: the S or N tag is not authenticated and no consumer sees it (`theorem_sn_tag_not_authenticated`).
- O3: an item attribute named `tablename` is ignored and replaced by the reader's name in both builders.
- O4: T01 holds for items with or without `create-time` and `hierarchy-version`. G1 stays a T02 finding.
- O5: rollback of an authentic older record is outside the property (TM-MPL-005 non-goal).

**Not covered.** The claim that KMS enforces the EC (A_KMS), AEAD integrity and DynamoDB behavior; `fetch_record` key selection and `resolve_key_store_arn` (T03); grant tokens and KMS error mapping; user-supplied `KeyStore` implementations; rollback; the `create-time` format and the UUID format of the version; the test-utils helpers in `record.rs`; zeroization, panics and error text.

**Model-vs-code gap.** The shipped functions are native Rust over `BTreeMap`, `HashMap`, `aws_sdk_kms` and `aws_sdk_dynamodb`, outside `verus!`. Nothing detects a later edit to `kms_ops.rs`, `branch_key_store.rs`, `record.rs` or `encryption_context.rs`. To close the gap you need the functions inside `verus!` (or `cargo verus` on the crate), vstd specs for the map and string operations, and a spec of the KMS and DynamoDB clients, which would stay an axiom (A_KMS).

---

## T13: cache identifier (VR-2026-T13 / TM-MPL-009, TM-MPL-010; BUG-06)

**Property in plain language.** `build_cache_identifier` (`cache_entry_identifier.rs:35`) is injective over the two call shapes if and only if the input fields contain no `0x00` byte. The BUG-06 counterexample is an intentional expected-FAIL obligation. The NUL-free precondition, and a length-prefixed encoding as a proposed fix, give injectivity.

**Status: Partly proved, at model level, with hypotheses.** `42 verified, 1 errors`. The one error is `lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL` (`t13_cache_identifier.rs:1008`, postcondition at `:1019`). It states the spec property "different field tuples give different identifiers" for all inputs, with no NUL precondition. The shipped layout does not satisfy it (BUG-06, High, open), so Verus is right to reject it. It is left failing, not weakened, not assumed and not commented out. `lemma_bug06_failing_claim_is_false` proves the claim is false, not only unproved.

**What the results say** (R-numbers from the file header):

| Result | Statement |
|---|---|
| R1 `lemma_nul_free_injective` | Both tuples NUL-free: equal preimages imply equal tuples. |
| R2 `lemma_if_direction_wf` | One tuple NUL-free, the other any well-formed tuple: equal preimages imply equal tuples. Needs H_SCOPE_PAIRING. |
| R3 `lemma_partner_*` | A tuple with a `0x00` in some field has a different tuple with the same scope and shape and the same preimage. |
| R4 `theorem_t13_iff`, `theorem_t13_iff_identifier`, `theorem_t13_iff_realistic` | For a well-formed tuple: no other well-formed tuple has its preimage if and only if every field is NUL-free. Same for identifiers under A_DIGEST_CR (the only-if half needs no assumption). The realistic form excludes the version (H_VERSION_NO_NUL). |
| R5 `lemma_bug06_*` | The BUG-06 collisions for the encrypt scope and the decrypt scope, and the expected-FAIL obligation. |
| R6 `lemma_nul_free_precondition_gives_identifier_injectivity` | The NUL-free precondition (BUG-06 fix option 1) gives injective identifiers under A_DIGEST_CR. |
| R7 `lemma_lp_*`, `theorem_lp_*` | A length-prefixed encoding (fix option 2) is injective for all inputs, under A_DIGEST_CR and H_LEN_FITS. The BUG-06 pairs separate. Model of a proposed fix only. |
| R8 `lemma_scope_separation`, `lemma_pairing_is_needed` | Encrypt and decrypt identifiers never coincide. H_SCOPE_PAIRING is needed: with one scope byte a NUL-free decrypt-shaped tuple collides with an encrypt-shaped one. |

**Assumptions and hypotheses.**

- Assumed: A_DIGEST_CR (SHA-384 modeled as an arbitrary injective function `h`; real SHA-384 is not injective, so this stands for computational collision resistance, idealized) and H_LEN_FITS (every field is shorter than 2^32 bytes; only for the length-prefixed fix, which a real fix must check).
- Code reading: H_MODEL_MATCH (the preimage is the byte string that `:42-60` passes to the digest), H_BYTES (fields are byte sequences; UTF-8 validity is not modeled), H_SCOPE_PAIRING (encrypt scope 0x01 is always called with no version, decrypt scope 0x02 always with a version), H_VERSION_NO_NUL (the version is a hyphenated UUID string), H_NO_DIGEST_ERROR (the `.expect` at `:64` cannot fail).
- No `assume`, `admit`, `external_body`, `assume_specification` or uninterpreted spec function is used.

**Findings.**

- BUG-06 is confirmed at model level, with concrete collisions for both scopes. For example, partition `"tenant\0x"` with name `"L"` and partition `"tenant"` with name `"x\0L"`, both with branch key id `"bk"`, have one preimage.
- The only-if direction builds the colliding partner as a tuple of byte fields. When the NUL is in the partition id, the partner's name takes the bytes after the NUL, which may not be valid UTF-8. The proof does not decide that every NUL-bearing configuration has a realizable partner (for example a random 16-byte partition id). The ASCII examples do exist.
- The layout is modeled as shipped and equals the layout the spec mandates (`aws-kms-hierarchical-keyring.md`, Appendix A), so the defect is in the spec text too.

**Not covered.** Any other function; cache hit and miss logic, TTL and storm tracking; `HierarchicalKeyringBuilder::build`; whether a deployment can be configured so that two keyrings collide (BUG-06 states the preconditions); panic freedom (T16).

**Model-vs-code gap.** The shipped function is native Rust outside `verus!`. The link between model and code is the correspondence table in the file header. Nothing detects a later edit to `mpl/`.

---

## Combined TCB

No `assume`, `admit`, `external_body`, `assume_specification` or `#[verifier...]` is written in any of the three files (grep, outside comments). No uninterpreted spec function is used. The one deliberately unconstrained item is the `Backend` trait in C02.

| Item | Kind | Used by | Notes |
|---|---|---|---|
| Verus 0.2026.07.12, Z3, rustc 1.96.0 | tool | all | |
| vstd `Seq`, `Map`, `Set` axioms | library spec | T02, C01 | `Set::lemma_map_by_contains` is used via `broadcast use` (T02 `:402`, C01 `:456`). |
| vstd `<[T]>::copy_from_slice` `assume_specification` | library spec | C02 | Equal lengths required, whole destination written. |
| vstd `Vec`, `Result`, `Range` specs | library spec | C02 | `sign_fixed_len_while` avoids the `Range` spec. |
| vstd `FnMut` axioms (`axiom_fn_mut_call_ensures`) | library spec | C02 | Closure state unchanged across calls. |
| `trait Backend` methods, no contract | unconstrained abstraction | C02 | Stands for aws-lc-rs. No-panic and no-hang are assumed (A4). |
| Ghost call log | instrumentation | C02 | One push per `sign_once()` call. Manual check against `ecdsa.rs:185-191` (A5). |
| A_STR: `String` is `Seq<char>`; `format!` is concatenation; byte and char prefix tests agree | model fidelity | T02, C01 | Not machine-checked. |
| A_ITER: `custom.iter()` yields each key once | hypothesis | C01 | Precondition `enumerates`. Std contract of `BTreeMap`. |
| A_DDB: DynamoDB returns what was written | model fidelity | C01 | Built into `stored_attrs`. Only `theorem_prod_*` and `lemma_store_roundtrip`. |
| A_NAME: reader and writer use the same logical key store name | model fidelity | C01 | Same scope as A_DDB. |
| A_BLD: `BranchKeyMaterials::build` behaves as modeled | model fidelity | T02, C01 | Rejects empty id and empty version; `required()` cannot fail. |
| Hand-copied string constants (`attributes.rs:11-24`) | model fidelity | T02 (9), C01 (12) | Script comparison against `attributes.rs` matched all. Not tied to the crate by the build. |
| Correspondence tables in file headers | human review | all | The only link between model and code. |
| Verbatim copy of T02 model inside C01 | model fidelity | C01 | Byte-identical at time of writing. |
| A_KMS: KMS binds the EC at generate and at the ReEncrypt destination, and accepts Decrypt only for an equal EC | external service contract | T01 | Encoded in the definitions of the model, not checked. Also A_DDB, A_NUM, A_NAME, A_ITER, A_ARN (see the T01 section). |
| H_SAME_EC: one local EC goes to both the KMS call and the item | code reading | T01 | A later edit is not detected. |
| Verbatim copy of the C01 model inside T01 | model fidelity | T01 | The review diffed C01 lines 178-1306 against the T01 block: they differ only by two wrapper comment lines. |
| A_DIGEST_CR: SHA-384 is an injective function in the model | idealization | T13 | Real SHA-384 is not injective. Also H_LEN_FITS (length-prefixed fix only). |
| H_MODEL_MATCH, H_BYTES, H_SCOPE_PAIRING, H_VERSION_NO_NUL, H_NO_DIGEST_ERROR | code reading | T13 | See the T13 section. |

## Findings

**G1: create-time / hierarchy-version clause. The code does not enforce it. Confirmed by T02.**
`branch_key_materials_from_authenticated_encryption_context` accepts a record without `create-time` or `hierarchy-version`. The spec says these are required (`spec/framework/branch-key-store.md:677, :690, :692`; EC section `:596, :599`; MUST-fail sentences `:531, :553, :574`).

- The failing lemma `lemma_g1_spec_soundness_FAILS` is the spec property, unweakened.
- **Weaker lemmas, labeled as weaker and describing code behavior, not the spec:** `lemma_g1_spec_completeness` (spec-conformant records are accepted), `lemma_g1_code_ignores_fields` (the outcome ignores both fields), `lemma_g1_witness_accepted_without_fields` (concrete accepted record without them).
- In a scratch copy in `/tmp` (not in the repo), adding "missing field implies Err" to the model made the failing lemma verify. So the lemma is stated correctly, and a code fix makes it provable.
- The owner can fix it in this function or in `record_from_ddb_item` (`branch_key_store.rs:1141-1200`), where the spec says the operation MUST fail.
- Independent check by the reviewer: `ATTR_CREATE_TIME` and `ATTR_HIERARCHY_VERSION` are only written (`encryption_context.rs:67, :77`; `branch_key_store.rs:711`, `:1098`). No read path tests for them: `fetch_record` (`:148-186`), `record_from_ddb_item` (`:1141-1198`, checks only `enc` and the attribute types), `decrypt_branch_key` (`kms_ops.rs:162`, requires only `kms-arn`), and the reconstruction. Rotation (`version_key`, `:671`, `:700-715`) copies the old EC, so a record that lacks the fields keeps lacking them.
- Impact is low: an altered record fails KMS Decrypt because the EC is the AAD. Only a record from a non-conforming writer that never had the fields is accepted. C01 shows that every EC the shipped builders produce carries both fields, so G1 does not affect honest writers.

**BUG-08: collision branch in `build_base` (`encryption_context.rs:91-102`). Dead code, harmless. Proved at model level, conditional on A_ITER.**
The branch returns `Err(Collision)` if and only if `custom.iter()` repeats a key. `EncryptionContext` is a newtype over `BTreeMap`, which yields each key once. The two cases the code comment names are not collisions: a custom key already carrying the prefix is stored as `aws-crypto-ec:aws-crypto-ec:x`, and prefixing is injective. The branch would become reachable if `EncryptionContext` stopped being a map. The proof then would not apply. Not provable here: that `BTreeMap::iter` yields each key once, and that `format!` is concatenation.

**Other findings**

- **Empty `branch-key-id` (T02).** The T02 YAML property omits that an empty id is rejected. The builder rejects it (`branch_key_materials.rs:174-176`) and `branch-key-store.md:593` requires it. Both `code_accepts` and `spec_accepts` include it. The YAML should add it.
- **Version is not checked as a UUID (T02, C01).** `structures.md` says the branch key version MUST be a version 4 UUID. `create_key` generates one (`branch_key_store.rs:557`), but the builders and the reconstruction accept any non-empty string after the prefix. Not modeled. A candidate for the spec and threat documents.
- **Dead builder branch (T02).** The builder's "empty version" rejection is unreachable (`lemma_empty_version_unreachable`).
- **Beacon read path (C01).** It never checks `type`. It relies on `fetch_record` selecting `beacon:ACTIVE`. The reconstruction function would reject a beacon record anyway. This is an observation, not a defect.
- **`kms-arn` and `tablename` (T02).** The spec EC must also contain them (`branch-key-store.md:597-598`). `tablename` is injected by `build_auth_ec` (`branch_key_store.rs:132-139`). `kms-arn` is required by `decrypt_branch_key` (`kms_ops.rs:172`) before this function runs. Neither is checked in the target function.
- **No length check inside `sign_fixed_len` (C02).** It does not check `want_len` against 71 or 103. The 128-call bound holds without it. `check_sig_len` only turns a 128-signature wait into an immediate Err. The function is private and both callers run the check first. No code defect found in the C02 scope; the YAML line anchors match HEAD.
- **No builder or reconstruction mismatch (C01).** The round trip holds for empty keys, empty values and keys that already start with `aws-crypto-ec:`.

**Sanity checks that the proofs are not vacuous.** The authors broke the model in scratch copies under `/tmp`. Each of four breaks in T02 and six in C01 made Verus fail. A fifth T02 change, enforcing `create-time` and `hierarchy-version` in the model, made the G1 soundness lemma verify. C02 has three satisfiability witnesses instead of mutation checks. These checks cover edits to the model only. They say nothing about edits to the code.

## Mapping to target IDs

| Proof file | Target ID | Capability / threat model | Pipeline item |
|---|---|---|---|
| `t02_record_reconstruction.rs` | VR-2026-T02 | TM-MPL-005 | Exact Ok/Err characterization of record reconstruction; G1 |
| `c01_ec_roundtrip.rs` | VR-2026-C01 | capability 1c | Builder and reconstruction round trip; BUG-08 |
| `c02_sign_fixed_len.rs` | VR-2026-C02 | capability 2d | Bounded retry, no panic, no partial write in `sign_fixed_len` |
| `t01_keystore_auth_ec.rs` | VR-2026-T01 | TM-MPL-005, TM-MPL-002 | Write-time EC, KMS-AAD EC and reconstruction EC are equal; authenticity of a read |
| `t13_cache_identifier.rs` | VR-2026-T13 | TM-MPL-009, TM-MPL-010 | Cache identifier injective iff fields are NUL-free; BUG-06 expected FAIL |

The orchestrator records proof status in `docs/mpl-verification-targets*.md` after review. This README does not edit those files.

## Next steps

1. Review the correspondence tables against the code. This is the only link between model and code today, and all three results depend on it.
2. Decide G1: enforce `create-time` and `hierarchy-version` in `record.rs` or in `record_from_ddb_item`. After the fix, `lemma_g1_spec_soundness_FAILS` should verify against an updated model, and T02 can move to Proved.
3. Update the T02 YAML: add "non-empty `branch-key-id`" to `formal_spec`.
4. Decide whether the branch key version should be checked as a UUID v4, or the spec relaxed.
5. To turn a model proof into a code proof, start with C02. It needs the least: a shared loop body, or a skeleton-diff script. T02 and C01 need vstd specs for `BTreeMap` on `String` keys and for `str` prefix functions.
6. Add a CI step that runs the proof files and fails on any change to the result lines (T02 is expected to show `1 errors` until G1 is fixed, and T13 until BUG-06 is fixed).
7. Remaining targets from the same pipeline: `ecdsa_verify*` never returning Err, `record_from_ddb_item` completeness.
