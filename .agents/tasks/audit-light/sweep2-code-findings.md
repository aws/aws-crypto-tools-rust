# Sweep 2 (code-surface sweep): findings

Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `4807e6a`. Light audit, documentation only. No code, audited document or commit was touched. Outputs are in `.agents/tasks/audit-light/`: this file, `sweep2-code-matrix.md` (the full site map), and the scripts `sweep2_scan.sh` and `sweep2_cov.sh`.

## Result

**No gap found.** Every security-relevant site maps to an existing threat (TM-MPL-001..026) and, where the code is Verus-provable, to an existing target or an explicit exclusion row. The 14 unmapped items are all judged not a gap (reasons below). Twelve of them are in the C++ shim's ESDK plumbing, which TM-MPL-024 scopes to handle validity only. The other two are DynamoDB provisioning calls and `Uuid::new_v4()`. Items N3 and N9-N14 below are mapped sites that were re-checked as possible gaps. The known items (stale T25, T21, T26; no target for TM-MPL-025) were hit by this sweep and are mapped to those IDs, not reported again.

## What was checked

- **Code scanned.** All non-test `*.rs` under `mpl/src` and `prim/src`, plus `esdk/shims/aws-esdk-cpp/src/lib.rs` (up to the `#[cfg(test)] mod tests;` at `:2068-2069`) and `src/EncryptionSDK.cpp` for `unsafe` / FFI. Test regions excluded: `mpl/src/error.rs` ≥ 460, `mpl/src/error/generated.rs` ≥ 3423, `prim/src/error/generated.rs` ≥ 988, shim `tests.rs`.
- **Scripted enumeration** (`sweep2_scan.sh`): `.unwrap()` / `.expect(` / `panic!` family; `x[..]` indexing; binary `+ - * / %` and compound assignment; `copy_from_slice` / `try_into` / `split_at` / `from_be_bytes` / `as` casts; KMS, DynamoDB, aws-lc-rs and `uuid` calls; secret-bearing names, `Zeroize`, `Debug` impls, print and log macros; `format!` in error construction; `for` / `while` / `loop`, `with_capacity`, `vec![..]`. Additional greps: `checked_` / `saturating_` / `duration_since`, `unsafe`, `rand` / `new_v4`.
- **Hand reading** of every flagged site that the scripts could not settle: `branch_key_wrap.rs` `unwrap` (`:230-262`); `hierarchical_keyring.rs` `on_decrypt` / `try_decrypt_edk` (`:734-800`, `:867-896`) and `generate_random_data_key` (`:975-984`); `raw_aes_keyring.rs` `decryptable_edk_iv` and `on_decrypt` (`:190-215`, `:440-497`); `EncryptionContext::from_bytes` / `try_from` (`:145-262`); `mrk_match.rs` (`:24-68`); `kms_config.rs` (`:28-110`); `kms_ops.rs` (`:100-128`, `:155-275`); `branch_key_store.rs` `fetch_record`, `get_beacon_key`, `record_from_ddb_item` (`:145-180`, `:860-898`, `:1141-1200`); `default_cmm.rs` (`:98-160`, `:184-192`, `:280-292`); `materials_checks.rs` (`:60-92`, `:196-216`); `decryption_materials.rs` (`:298-340`); `storm_tracking.rs` (`:190-256`, `:355-398`, `:660-668`); `cache_entry_identifier.rs` (`:30-66`); `prim/src/lib.rs` (`:122-130`, `:175-200`); `prim/src/hkdf.rs` (`:76-86`); `prim/src/ecdsa.rs` (`:320-400`); shim `lib.rs` (`:150-170`, `:712-730`, `:1700-1735`) and `EncryptionSDK.cpp` (`:270-292`, `:538-550`).
- **Coverage test before judging.** For each unmapped item, `sweep2_cov.sh` grepped `docs/threat-model.md`, `docs/verification-targets.md`, `docs/verification-targets/01-threat-driven.md`, `docs/verification-targets/02-capability-driven.md` and `docs/spec-security-analysis.md` for the file:line and the symbol. Output is in matrix §7. Matches were then read in context: T16's function list (`01-threat-driven.md:755-764`, `:786-788`), TM-021 (`threat-model.md:422-429`), TM-025 (`:457-467`), threat-model findings F4 / F5 (`:493-494`), randomness note (`:473`), exclusion table (`01-threat-driven.md` §4), and rejected list R1-R16 (`02-capability-driven.md` §5).
- **Citations.** Every file:line in the matrix came from `sweep2_scan.sh` output or a `sed -n` / `grep -n` read in this sweep. A script then checked all 178 file:line citations in the matrix against the working tree. It found one wrong line, which was corrected (`kms_ops.rs:198-206` → `:199-207`). Two more off-by-one cites were caught by hand and fixed (`default_cmm.rs:113`, `raw_aes_keyring.rs:460`).
- **Unsafe.** No `unsafe` block exists in `mpl/src` or `prim/src`. The only match is the lint name `unsafe_op_in_unsafe_fn` at `prim/src/lib.rs:33`. The shim has four: `lib.rs:728` (`require_handle`), `:1570`, `:1571`, `:1661` (nullable `as_ref`), all under TM-MPL-024 / T25.

## Counts per category

| Category | Examined | Mapped | Unmapped | Unmapped judged a gap |
|---|---|---|---|---|
| 1. Entry points accepting untrusted input | 25 | 25 | 0 | 0 |
| 2. Panic-capable sites (expect/unwrap 14, indexing 43, arithmetic 31, copy/try_into/split_at 22) | 110 | 101 | 9 (all shim) | 0 |
| 3. External calls (KMS, DynamoDB, aws-lc-rs, uuid, ESDK from shim) | 16 | 13 | 3 | 0 |
| 4. Secret material created / held / copied / logged | 18 | 17 | 1 | 0 |
| 5. Error paths that carry data | 13 | 13 | 0 | 0 |
| 6. Loops / allocations driven by input | 17 | 16 | 1 | 0 |
| **Total** | **199** | **185** | **14** | **0** |

"Mapped" includes the 3 storm-tracking `test-utils` `.expect`s, which T16's rationale (`01-threat-driven.md:787`) explicitly scopes out, and the 2 aws-lc-rs calls covered by rejected rows R2 and R3. Rows are counted as the scan grouped them in the matrix. A site that appears in two scan buckets (for example `raw_aes_keyring.rs:469`) is counted in each.

## Candidate gaps

None.

## Items judged NOT a gap

| # | Item (file:line) | Category | One-line reason |
|---|---|---|---|
| N1 | Shim `lib.rs:164` (Tokio runtime `.unwrap()`), `:1086` (constant `FrameworkMetadata` `.expect`), `:1716` (`ChannelReader` lock `.expect`) | 2 | None of the three depends on input. The first fails only if the OS cannot start threads. The second has constant input. The third needs an earlier panic while the lock is held, and the lock covers only `rx.recv()` (`:1716-1717`), which does not panic. These are ESDK-shim plumbing outside TM-024's handle scope. Speculation: a panic in a cxx `extern "Rust"` function aborts the process, so if one did fire, the cost is availability only. |
| N2 | Shim `lib.rs:1728-1730` (`pending.len() - offset`, slice, `+=`), `:782` (`u16::from_be_bytes` on `[u8;2]`) | 2 | Safe by construction. The loop guard `:1715` ensures `offset < pending.len()`, and `n = min(..)`. `from_be_bytes` on a fixed array cannot fail. |
| N3 | `get_beacon_key` passes KMS plaintext to `BeaconKeyMaterials` without a length check (`branch_key_store.rs:868-898`). Branch keys are checked (`record.rs:164`) | 1 / 4 | The spec defines no beacon-key length (`spec/framework/structures.md` "Beacon Key", L436-449), so no MUST is violated. The plaintext comes from a KMS-authenticated record (T01 covers the auth EC at `:868`), and the consumer (DB-ESDK) is outside this repo. At most an informational note. |
| N4 | DynamoDB `DescribeTable` / `CreateTable` (`branch_key_store.rs:464`, `:506`) | 3 | Provisioning in `create_key_store`, called by the operator. Sweep 1 classed the same spec rows as LOWSEC. There is no integrity or confidentiality consequence and nothing Verus can prove (the property depends on the external service). |
| N5 | `Uuid::new_v4()` for branch-key ids and versions (`branch_key_store.rs:415`, `:556-557`, `:703`) | 3 | Already documented as non-secret (`threat-model.md:473`, `spec-security-analysis.md:214`). Uniqueness is enforced by the `attribute_not_exists` conditions (`branch_key_store.rs:604`, `:743`). Entropy quality is probabilistic, so it is not Verus-provable per the decision aid. |
| N6 | Shim calls to ESDK `encrypt` / `decrypt` (`lib.rs:1292`, `:1334`) | 3 | ESDK message layer, not MPL. The MPL calls under it are mapped. |
| N7 | ESDK plaintext returned to C++ and freed without a wipe (`lib.rs:1358`; `EncryptionSDK.cpp:285-287` `RustBufferDeleter`) | 4 | This is application message plaintext that the C++ caller receives and owns, not MPL key material (assets A1-A6). TM-015 is scoped to MPL secrets. |
| N8 | Shim loops (`lib.rs:568`, `:1470`, `:1715`, `:1922`) | 6 | ESDK streaming and error-chain plumbing. The bounds are the error-chain depth, the caller's header list, and channel chunks sent by the caller. No MPL asset. |
| N9 | Raw-AES `on_decrypt` attempts one AES-GCM per matching EDK (`raw_aes_keyring.rs:448`, alloc `:471`) | 6 | The cost is local and linear in message size, with no KMS or DDB call. TM-025 is about external reads and in-flight slots. Panic-freedom is T16, and TM-023 covers resource blow-up. |
| N10 | Error text built from record-sourced strings with `Display`: `kms_ops.rs:108`, `:125`; `branch_key_wrap.rs:102`, `:107`; `branch_key_store.rs:1185` | 5 | Changing these strings needs DynamoDB write access. TM-021 already records that errors carry resource ids and attacker-controlled text and that callers must not echo errors (`threat-model.md:429`). `default_cmm.rs:290` prints a key from the caller's reproduced EC (loop at `:284`), not a key chosen by the sender. Message-sourced EC keys are formatted with `{:?}` (`encryption_context.rs:202`, `decryption_materials.rs:311`). |
| N11 | `contains_all` is O(n·m) (`materials_checks.rs:208`) | 6 | It runs only on encrypt-path transitions, where EDKs come from the configured keyring, not from a sender. Its correctness is part of C07. |
| N12 | In-flight mark with a future timestamp is kept (`storm_tracking.rs:253-254`) | 2 / 6 | Already threat-model finding F5 (`threat-model.md:494`), under TM-018 / T21. |
| N13 | RECK ⊆ EC check in the materials builders (`decryption_materials.rs:306-316`, `encryption_materials.rs:368-378`) | 1 | Runtime-enforced and fails closed (`spec-security-analysis.md:204`). The decrypt-path property is in T12's spec (`01-threat-driven.md:669`), and C07 keeps RECK unchanged across keyrings. A separate target would add no assurance. |
| N14 | `parse_arn` uses `splitn(6, ':')` and MRK match uses `split(':')` (`kms_config.rs:32`, `mrk_match.rs:38-39`, `:53`, `:63`) | 2 | Already recorded in T11's rationale (`01-threat-driven.md:646`). A 7-segment input fails closed in MRK match. Indexing is guarded in both. |

N14 is listed for completeness. It was mapped, but it was checked as a possible inconsistency gap.

## Verus-provability note for the unmapped items

None of the 14 unmapped items calls for a target. N2 is provable (category 2a/2b, trivial), but it is ESDK-shim streaming code with no security property. N1 would need an "OS can start threads" axiom. N4-N8 depend on external services, randomness, or caller-owned memory, which the decision aid places outside Verus.
