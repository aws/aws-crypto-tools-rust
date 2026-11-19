# C08 notes (for the docs step)
Target: VR-2026-C08, `CacheEntry::record_use` and `Cmc::update_usage_metadata` (usage counters never wrap; overflow
evicts the entry). Capability category 2b (integer overflow freedom). Score 0.96, rank 7, estimated 1 day, agent route
mpl-verus-zero-panic. Score, rank, gap and quick-win are unchanged by this work. Repo `esdk-native-mpl`, branch
`MPL-Verus`, HEAD `ad3522b`. Nothing under `mpl/`, `prim/`, `esdk/`, `docs/` or `dashboard/` was changed. Nothing was
committed or staged.
## 1. Result
- Proof file: `verus-proofs/c08_cache_usage_counters.rs` (untracked, 708 lines, header sections 0 to 5).
- Command: `~/verus/verus verus-proofs/c08_cache_usage_counters.rs` (Verus 0.2026.07.12.0b42f4c), exit 0.
- Exact result line: `verification results:: 20 verified, 0 errors`
- Run log: `.agents/tasks/mpl-four-proofs/c08-run.txt`
- Status word to use: **Proved (model level, not the shipped code, under stated hypotheses).**
- Not a partial proof. There is no EXPECTED_FAIL obligation, because the code cannot wrap and cannot panic at any
  legal input (section 6). None was invented.
- What it is, plainly: a model with the real widths (`u64` counters, `u64` per-call byte count). `record_use` is
  written as an executable model with `u64::checked_add`, and Verus checks that it has no arithmetic overflow and meets
  a contract for every `u64` input. The cache is a map from identifier to counters. Verus proves what one call does,
  and what any sequence of calls does to one entry.
- How trivial it is: the "no wrap" part rests on `u64::checked_add` returning `None` exactly on overflow. That is the
  std contract (vstd carries it as an `assume_specification`, cross-checked by `checked_add_by_hand`). Given it, the
  exec result is a short argument. The claims with more content are the both-or-neither update, the exact eviction
  rule, no resurrection, and the exact-total statement over all call sequences (R3 to R5). It does not show that the
  shipped code is this model.
## 2. What the code does (code reading)
- Widths: `UsageMetadata { messages_used: u64, bytes_used: u64 }` (`mpl/src/cmc/entry.rs` :39-41);
  `UpdateUsageMetadataInput.bytes_used: u64` (`operation.rs` :364-367). No cast, no other width.
- `record_use` (`entry.rs` :206-223): lock (poison ignored, `PoisonError::into_inner`, :209-212), compute
  `messages_used.checked_add(1)` and `bytes_used.checked_add(bytes)` (:213-214), return `false` if either is `None`,
  otherwise store both (:218-219) and return `true`. Both sums are computed before any store.
- `LocalCmc::update_usage_metadata` (`local.rs` :326-342): lock `store` (poisoned: `Err(Internal)`, no change, :331-334);
  `peek` the entry; if `!entry.record_use(bytes)` then `cache.pop(id)`; return `Ok`. No entry or no store: no-op `Ok`.
- `DefaultCmc` (`default.rs` :120-125) and `StormTrackingCmc` (`storm_tracking.rs` :757-762) forward unchanged.
- Overflow handling: never computed. `checked_add` gives `None`, `record_use` returns false without writing, the entry
  is deleted. No saturation, no reset, no error to the caller. The trait doc says the same (`mod.rs` :75-79).
- Initial counters can be any `u64` pair (`UsageMetadataBuilder` :74-77, :95-98; `CacheEntryBuilder::usage_metadata`
  :296-298), including `u64::MAX`. The theorems quantify over all pairs.
## 3. What is proved (relative to the model and the items in section 4)
| Id | Theorem (in the file) | Statement |
|---|---|---|
| R1 | `theorem_record_use_spec` | `record_use` succeeds exactly when neither `messages + 1` nor `bytes + b` exceeds `u64::MAX`. On success the counters are the exact integer sums. On failure both are unchanged. |
| R1 | `theorem_overflow_cases` | Failure is exactly `messages == u64::MAX` or `b > u64::MAX - bytes`. |
| R1 | `lemma_no_partial_update` | Concrete case: bytes at `u64::MAX`, message count 0, `b = 1`. The call fails and the message count stays 0. |
| R2 | `record_use` (exec), `checked_add_by_hand` | The executable model uses `u64::checked_add` and the same match as the code. Verus checks it for every `u64` input: no arithmetic overflow, and the contract of R1 (`ensures`). `checked_add_by_hand` equals `u64::checked_add`. |
| R3 | `theorem_update_step` | One `update_usage_metadata` call on an unpoisoned cache returns Ok. An absent identifier changes nothing. A present one is evicted exactly when `record_use` fails, otherwise its counters are the exact sums. No identifier appears. "No other identifier changes" is relative to A_NO_ALIAS. |
| R3 | `lemma_poisoned_store_is_noop` | A poisoned `store` returns `Err(Internal)` and changes nothing. |
| R4 | `theorem_run_entry` | For any start counters and any sequence of `n` byte counts: the entry survives iff `messages + n <= u64::MAX` and `bytes + sum <= u64::MAX`, and then its counters are exactly `messages + n` and `bytes + sum`. So no early eviction and no late eviction. |
| R4 | `lemma_run_entry_absent_stays_absent` | After eviction (or if absent) later calls do nothing. |
| R5 | `theorem_cache_refines_entry_run` | For any calls on any identifiers, each identifier follows the single-entry run of R4 over the byte counts addressed to it. Relative to A_NO_ALIAS, A_ALL_CALLS, A_NO_PUT. |
| R5 | `theorem_no_wrap_any_calls` | Summary: for any unpoisoned cache, call sequence and identifier, a present entry survives iff the exact totals fit in `u64`, then its counters are the exact totals; an absent identifier stays absent. Relative to A_NO_ALIAS, A_ALL_CALLS, A_NO_PUT, A_LOCK_EXCL. |
| R6 | `lemma_boundary_witnesses` | Off-by-one at the maximum, both directions, both counters: `MAX-1` messages accepted then `MAX` rejected (even with 0 bytes); bytes reaching `MAX` exactly accepted, one more rejected; `MAX` bytes from zero accepted, then 1 more byte rejected. |
| R6 | `lemma_evicted_handle_is_not_frozen` | Observation O1 below. |
| R7 | `update_slot` (exec) | The `peek` / `record_use` / `pop` core on one slot equals `step_entry` for every input. |
## 4. Hypotheses and assumptions with evidence levels
Evidence levels: PROVED (checked by Verus in the file), ASSUMED (a premise or definition), CODE READING (a claim about
shipped code or std that Verus does not see). No `assume`, `admit`, `external_body`, `external`,
`assume_specification` or `#[verifier..]` is written in the file (grep), and there is no uninterpreted spec function.
The one `assume_specification` the proof uses is vstd's for `u64::checked_add`.
| Name | Level | Content |
|---|---|---|
| A_VSTD | ASSUMED | Verus, Z3, vstd `Seq` and `Map` axioms, and vstd's `assume_specification[u64::checked_add]` (None iff the sum exceeds `u64::MAX`). `checked_add_by_hand` proves a plain comparison gives the same result. |
| A_LOCK_EXCL | ASSUMED | A held `MutexGuard` gives exclusive access. The model runs calls one at a time and each call is atomic. Real concurrent calls are covered only as some serial order. |
| A_NO_ALIAS | ASSUMED (the "no other identifier changes" clause of R3; R4, R5) | No `CacheEntry` handle (original or clone) is stored under two identifiers, so distinct identifiers have distinct counter cells. The model `Map<Id, UM>` gives each identifier its own counters, which is this premise. The code does not enforce it: the map holds `CacheEntry` handles (`Arc<CacheEntryInner>` with `Mutex<UsageMetadata>`, `entry.rs` :136-146), `PutCacheEntryInput` is `Clone` and carries a `CacheEntry` by value (`operation.rs` :11-31), `put_cache_entry` does `cache.put(identifier, entry)` (`local.rs` :280-300), `get_cache_entry` returns a clone (`local.rs` :148). It is a premise about callers. R1, R2, R7 and the evict-the-addressed-slot rule do not need it. |
| A_ALL_CALLS | ASSUMED (R4, R5 only) | Every change to the counters of a cell goes through `update_usage_metadata` addressed to the identifier that holds it (with A_NO_ALIAS, `calls` lists all of them). `record_use` is `pub`, so a holder of a clone can call it directly. R1 and R2 still hold for such calls. |
| A_NO_PUT | ASSUMED (R4, R5 only) | During the sequence no `put` replaces the entry and nothing else changes the map. |
| H_STD_CHECKED_ADD | CODE READING (std) | `u64::checked_add` returns `None` exactly when the sum exceeds `u64::MAX`. |
| H_ONLY_SITES | CODE READING | The only arithmetic on the counters in `mpl/src` and `esdk/src` is `entry.rs` :213-214. The only writes are :218-219 and the builders. Fields are private and the type is `#[non_exhaustive]` (grep). |
| H_NO_PANIC_IN_GUARD | CODE READING | Between the lock (:209-212) and the return `record_use` runs two `checked_add` calls, one pattern and two stores. None can panic, so the entry mutex is not poisoned by it, and the stores are not interrupted. |
| H_STORE_FLOW | CODE READING | `update_usage_metadata` locks `store` once, runs `peek`, `record_use` and at most one `pop` under the guard, and returns `Ok(default)` on every path after the lock. |
| H_LRU_OPS | CODE READING (lru 0.18.5) | `peek(k)` changes nothing. `pop(k)` removes key `k` only. |
| H_BUILDER_ANY | CODE READING | Initial counters can be any `u64` pair. |
| H_DELEGATION | CODE READING | `DefaultCmc` and `StormTrackingCmc` add no logic. A `Cmc` implemented outside the repository is not covered. |
| H_ARC_SHARED | CODE READING | A `CacheEntry` clone shares the counters (`entry.rs` :132-138); `get_fresh` returns a clone (`local.rs` :148). A clone can also be passed to `put_cache_entry` under another identifier (`operation.rs` :11-31, `local.rs` :280-300), hence the separate premise A_NO_ALIAS. |
| H_MODEL_MATCH | CODE READING | The model functions have the same inputs and operation order as the lines in the file header table. Not machine-checked. |
## 5. What is not shown
- That the shipped code has these properties. Nothing detects a later edit to `entry.rs` or `local.rs`.
- That `u64::checked_add` is correct (A_VSTD, H_STD_CHECKED_ADD).
- Concurrency: interleavings, lock ordering (the `store` guard is held while the entry mutex is taken), deadlock freedom.
- That every change to a cell goes through `update_usage_metadata` addressed to its own identifier (A_ALL_CALLS).
- That distinct identifiers have distinct counter cells (A_NO_ALIAS). One handle can be stored under two identifiers
  through the public API and the code does not prevent it. Under such aliasing `update_usage_metadata(B)` also changes
  the counters seen through A, so the clause "no other identifier changes" of `theorem_update_step` and the
  per-identifier exact totals of R4/R5 (which count only calls addressed to that identifier) do not hold for that
  state. What still holds under aliasing: R1 and R2 (per-call no wrap, both-or-neither), evicting the addressed slot
  (R7 and the eviction clause of R3), and no wrap of the shared cell.
- LRU order, capacity, TTL, pruning, async scheduling, `put`, `get`, `delete`.
- Any usage limit policy. No in-repo code compares the counters with a maximum and there is no caching CMM. A future
  caching CMM that enforces limits is not shown correct. `2^64` messages or bytes is beyond any real workload, so this is
  a robustness property, not a statement about a likely attack.
- That any threat is mitigated. C08 has no threat reference (`threat_references: []`). No threat status changes.
- What the spec requires beyond atomicity (section 6, O2).
## 6. Findings
- **F0, no gap.** The code cannot wrap and cannot panic at any legal input (every `u64` counter pair, every `u64` byte
  count). No EXPECTED_FAIL obligation was written. Not invented.
- **O1, observation (not a wrap, not a gap).** Eviction removes the map slot. It does not freeze the shared cell. A handle
  taken earlier from `get_cache_entry` still accepts `record_use`. After a failed call the counters are unchanged, so a
  later call on that handle with fewer bytes can succeed (`lemma_evicted_handle_is_not_frozen`: counters `{0, MAX}`,
  `b = 1` fails, then `b = 0` succeeds). The counters stay exact. Whether it matters depends on a future caching CMM.
- **O2, documentation.** The only normative text on usage metadata is `spec/framework/cryptographic-materials-cache.md`
  :93 "Updating usage metadata SHOULD be atomic." The spec has no "update usage metadata" operation and no overflow rule.
  The YAML `trace_to_spec` cites `#update-usage-metadata`, which does not exist in the spec checkout (submodule
  `e833453`). The overflow-evicts behavior comes from the trait doc (`mod.rs` :75-79) and the code. The YAML text is not
  changed here.
- **O4, observation (aliasing; not a wrap, not an EXPECTED_FAIL).** The same `CacheEntry` handle can be stored under two
  identifiers through `put_cache_entry`, so a call addressed to one identifier changes the counters seen under the
  other. The model excludes this by construction (A_NO_ALIAS), so no obligation fails. The statements that depend on
  it are marked "relative to A_NO_ALIAS" in the file. Added after the proofs review (finding F1). No proved
  obligation changed.
- **O3, scope.** No in-repo code calls `update_usage_metadata` (the YAML rationale says the same). The property is for a
  future caller.
- Housekeeping: the YAML cites `entry.rs:206`, `checked_add` at `:213-214`, Duvet implication `:201-205`, `local.rs:326`,
  `mod.rs:79`. At HEAD the Duvet lines are :201-204 (the `//=` and `//#` lines) and the rest match. The test the YAML
  cites, `test_update_usage_metadata_deletes_entry_on_overflow`, is at `test_local_cmc.rs` :729 and matches.
## 7. Code and spec locations read
- `mpl/src/cmc/entry.rs`: :1-230, :296-330 (types, `record_use`, builders).
- `mpl/src/cmc/local.rs`: :55-70, :125-165, :280-342.
- `mpl/src/cmc/mod.rs` :60-100; `mpl/src/cmc/operation.rs` :355-460; `default.rs` :98-130; `storm_tracking.rs` :745-765.
- `mpl/tests/test_local_cmc.rs` :695-745; `test_shared_handles.rs` :179-181 (tests, not proofs).
- `lru-0.18.5/src/lib.rs` `peek` and `pop` (registry copy).
- Spec: `spec/framework/cryptographic-materials-cache.md` :66-105, :149-153; grep of the three cache spec files for
  "update" and "overflow".
## 8. Duplicate check against `Mahnush_Verus`
Text for the docs step, in the form of the existing sections ("### C08 against Mahnush_Verus"):
Result of the duplicate check: **C08 does not duplicate anything on `Mahnush_Verus`.** Ref read: `origin/Mahnush_Verus` at `8d6381e` (the tip used for the C03, T04, T06 records). It was read with `git grep`, `git ls-tree`, `git diff` and `git show` only. Nothing was merged, checked out or modified.
- **No Verus in `mpl/` there.** `git grep -n 'verus!' origin/Mahnush_Verus -- mpl/src mpl/tests` returns nothing. The only `verus` hits under `mpl/` are the `verus_builtin` entries in `mpl/Cargo.lock`.
- **Same code.** `git diff HEAD origin/Mahnush_Verus --stat -- mpl/src` is empty, and so is the same diff for `mpl/src/cmc`. `record_use` is at `entry.rs:206` with `checked_add` at :213-214 there too, plain Rust, outside `verus!`.
- **No `verus-proofs/` directory** there (`git ls-tree -r --name-only origin/Mahnush_Verus` has no such path; count 0).
- **Searches.** `git grep -n -E 'C08|VR-2026-C08|record_use|update_usage_metadata|UsageMetadata|usage_metadata|messages_used|bytes_used' origin/Mahnush_Verus -- . ':!mpl/src' ':!mpl/tests'` finds only `scripts/smithy-conformance/config.toml` lines 501, 515 and 751 (conformance mapping of `UsageMetadata` and `UpdateUsageMetadataInput$bytesUsed` for the Dafny-to-Rust test harness). No proof, no doc, no target mentions the usage counters. A search for `cmc`, `CacheEntry` and `usage counter` in `docs`, `verification` and `.kiro` finds only prose: `docs/threat-model.md:69, :135, :720`, `docs/verification-recommendations.md:356` (a `.expect("... lock poisoned")` note on the storm-tracking lock) and `docs/verus-in-crate-migration-design.md:68` ("CMM / cache ... Medium-Low"). None is a proof or a target for the counters.
- **No overlap at the primitive level.** VR-006, VR-008, VR-009, VR-013 and VR-014 concern `prim` and `esdk` functions (AES-GCM buffer bounds, ECDSA length, HKDF decisions, the `prim` wrappers). None concerns the cache.
- **Same technique, different counter.** `esdk/src/message/body/body_decrypt.rs` (inside `verus!` there) proves `next_expected_frame`, a `u32::checked_add(1)` on the frame sequence number. It is a different counter in a different crate, and it is in `esdk`, not `mpl`. C08 does not depend on it and does not repeat it. The shape of the argument (`checked_add` returns `None` at the maximum) is the same.
Row for the "Item / On MPL-Verus / On Mahnush_Verus" table: `C08 | Proof of a model in verus-proofs/ (model level, not the shipped code) | No verus-proofs/ directory; no Verus in mpl/; same checked_add at entry.rs:213-214, no proof. Not a duplicate.`
## 9. Mutation summary
Script: `.agents/tasks/mpl-four-proofs/c08-mutate.py`. Record: `.agents/tasks/mpl-four-proofs/c08-mutation-run.txt`.
Mutants: `.agents/tasks/mpl-four-proofs/mutants/c08/` (30 files). Baseline `20 verified, 0 errors`.
Result: 30 variants, 28 rejected, 2 survived, 0 differ from the prediction made before the run. Re-run after the
review change F1 (comment-only edit adding A_NO_ALIAS): same result, same per-mutant outcomes; baseline still `20 verified, 0 errors`.
Rejected (model edit, then which obligations fail):
- Unchecked add (guard always false, m01): 8 errors. Wrapping add in the exec model (m02): 1 error, `record_use`.
  Wrong increment (m03): 1 error, `record_use`.
- Narrower message width, u32 limit (m04): 4 errors. One bit wider byte limit (m05): 8 errors.
- Eviction on the wrong branch (m06): 1 error. No eviction on failure (m07): 1 error. Eviction flushes the whole map
  (m19): 1 error. Eviction returns an error (m20): 1 error. Absent identifier creates an entry (m18): 1 error.
- Counter reset on overflow (m08): 4 errors. Saturation on overflow (m09): 7 errors.
- Off-by-one at the maximum, messages (m10): 4 errors; bytes (m11): 5 errors.
- Partial update in the spec (m12): 4 errors; in the exec model (m13): 1 error. A counter not stored (m14, m15): 1 error each.
  `true` returned on overflow (m16): 1 error.
- Poisoned store returns Ok (m17): 1 error. Evicted entry resurrected (m21): 3 errors.
- Sum ignores bytes (m22), strict total bound (m23), `bytes_for` ignores the identifier (m24), refinement without the
  unpoisoned premise (m25): 1 to 2 errors each. Exec slot evicts on success (m26): 1 error. Off-by-one in
  `checked_add_by_hand` (m27): 1 error. Wrong boundary witness (m28): 1 error.
Survivors (both predicted):
- s01 `Id` is `Seq<u16>` instead of `Seq<u8>`: the model never reads identifier bytes, only equality and map keys.
- s02 a redundant `assert` hint in `theorem_update_step` removed: Z3 proves the same fact from the `Map::insert` axioms.
Weakness noted: an edit to the exec body of `record_use` is seen only through its own `ensures` (m02, m03, m13 to m16
fail there). The cache-level theorems use the spec `record_use_spec`; the exec function is tied to it by that `ensures`.
These checks cover edits to the model only, not edits to the shipped code.
## 10. Files
- `verus-proofs/c08_cache_usage_counters.rs` (new, untracked)
- `.agents/tasks/mpl-four-proofs/c08-run.txt`, `c08-mutate.py`, `c08-mutation-run.txt`, `c08-notes.md`, `mutants/c08/*.rs`
