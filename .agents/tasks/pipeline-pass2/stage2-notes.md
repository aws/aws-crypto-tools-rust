# Stage 2 notes, second pass at HEAD 851977d (threat model)

Output: `docs/threat-model.md`, updated in place. IDs TM-MPL-001..024 kept; two new IDs (025, 026); none retired; no existing rating changed.
Rules followed: only `docs/threat-model.md` and this file were written. Nothing under `mpl/`, `prim/`, `esdk/` was touched. Nothing was committed or pushed. `docs/chorus/`, `docs/bug-reports/`, `docs/spec-security-analysis.md` and the Stage 3 files were read at most. Stage 3 was not run.

## Method and limits
- Inputs read: `docs/threat-model.md` (previous), `docs/spec-security-analysis.md` (Stage 1, second pass), `.agents/tasks/pipeline-pass2/{scope.md,stage1-notes.md}`, `.agents/tasks/pipeline-rerun-620771c/stage2-notes.md`, `docs/bug-reports/{README.md,RECHECK-main-620771c.md}`, and the code and spec files named below.
- **No shell in this step.** So no `git`, no build, no tests. `mpl/` and `prim/` are "unchanged since 620771c" on the authority of `scope.md` (`git diff 620771c 5f2dc72` = `esdk/shims/aws-esdk-cpp/` only) and Stage 1. My own spot checks of about 150 citations against the current files all agree with that.
- Tools: `grep_search` and counted `read_file` windows. Grep prints match lines as `N:` and context lines as `N-`; the context numbers are one too high, so only `N:` lines were used as evidence. `read_file offset N` shows line `N+1` first; every counted window was cross-checked against at least one grep match line (for example `kms_config.rs` `validate`, `storm_tracking.rs:106-126`, `hierarchical_keyring.rs:560-605`). I mis-transcribed `N:` vs `N-` several times while reading long grep output, so anything not backed by a counted window was re-read before it went into the document.
- Spec files under `spec/` are git-ignored, so `grep_search` skips them; `spec/framework/storm-tracking-cryptographic-materials-cache.md` and `branch-key-store.md` were read with `read_file`.
- Advisory: re-fetched `https://github.com/advisories/GHSA-v638-38fc-rhfv` (web_fetch). Content: ESDK for Python, shared `CachingCryptoMaterialsManager`, clients with different commitment policies, weaker client encrypts first, matching ECs, default suite; fixed in 3.3.1 and 4.0.5; CVE-2026-6550. Wording in the document: VERIFIED, scoped to the Python caching CMM, not applicable to this code. Paraphrased, not quoted.
- The diffs of 41f1d51 and 5f2dc72 were not read (no git). Statements about them come from `scope.md`'s file list and the current files.

## Stage 1 discrepancies found (Stage 1 was not edited; report to the orchestrator)
| Stage 1 text | Found | Evidence |
|---|---|---|
| C8: `key_store/kms_config.rs:98` → `:99` (`validate`) | `validate` is at **`:98`**; `:99` is `match self {`. The first-pass `:98` was right and the "correction" is wrong | `grep 'pub fn validate'` match line 98; `read_file offset 94` (blank = 95, `impl` = 96, doc = 97, fn = 98) |
| N3 / body: `mpl/tests/test_keyring_memory.rs:5` (65,535 EDKs) | The sentence is at **`:4`** | `read_file offset 0 limit 20`: 1-2 license, 3 blank, 4 `//! A message can list up to 65,535` |
| N9: `lib.rs:1411-1419` (`ddb_client` retry) | The retry block is **`:1412-1416`** (comment 1412-1413, `if let` 1414, assignment 1415, `}` 1416); the function starts at `:1403` | grep `retry_config` match lines 1414, 1415 |
| `beacon_key_materials.rs:203-209` (first pass, TM-021), `branch_key_materials.rs:58`, `:196`, `algorithm_suite.rs:566`, `:614`, `:699` | Replaced in the threat model by the `impl Debug` lines (`:564`, `:612`, `:696`; `:55`, `:191`; `:57`, `:191`). Not wrong, but `beacon` `:203-209` did not point at a `Debug` impl | grep `impl .*Debug for` |

Not found wrong (spot-checked): `hierarchical_keyring.rs` 187, 547, 584-593, 595-605, 626, 654, 665, 685, 700, 702, 722, 734, 747, 752-763, 767, 783-784, 798, 867, 879, 889-894, 892, 901-960, 928, 934, 943, 945, 989-995, 1000; `branch_key_wrap.rs` 61, 92, 122, 135-136, 157, 164, 170, 230, 236, 240, 249, 252, 256; `raw_aes_keyring.rs` 31, 52, 72-80, 87, 146, 151-152, 191, 233-241, 350, 360, 370, 471, 489, 517; `kms_ops.rs` 49, 88, 94-105, 118, 144, 162, 179, 183, 187-188, 207, 239-240, 286-287; `branch_key_store.rs` 112, 132-136, 148, 155, 373, 381, 387, 397-415, 539, 556-557, 604, 641, 703, 743, 752, 792, 801, 827, 868, 1089, 1140, 1141; `record.rs` 95, 100, 164, 173; `key_store/encryption_context.rs` 40, 91-102; `client_impl.rs` 305-308, 373-376; `cache_entry_identifier.rs` 35, 42-60, 64; `mrk_match.rs` 24-28, 38-41, 52-57; `kms_config.rs` 31, 61, 86, 98; `user_agent.rs` 9, 15, 17; `default_cmm.rs` 97, 113, 123, 137-138, 184, 198, 224, 273; `commitment_policy.rs` 8-10, 43-50, 62, 77; `materials_checks.rs` 18, 37, 72, 76, 78-91, 100, 103, 117, 121, 157, 177; `keyring/fluent_builders.rs` 82, 163; `cmm/fluent_builders.rs` 171, 319; `shared.rs` 66, 110; `cmc/mod.rs` 46, 88-90, 111; `cmc/entry.rs` 26, 28, 30, 32, 201-204; `cmc/local.rs` 69, 131, 166, 280, 302; `storm_tracking.rs` 109-121, 125, 199, 213, 227, 239, 248-255, 264, 274, 310-337, 360, 388-397, 606-622, 680, 710, 721, 725, 729, 739-740, 764; `algorithm_suite.rs` 505, 541, 547, 564, 571, 612, 655, 696; `branch_key_materials.rs` 55, 191, 205-219; `beacon_key_materials.rs` 57, 191, 221-235; `structures/encryption_context.rs` 145, 202, 208; `encrypted_data_key.rs` 148-151; `prim/src/lib.rs` 33, 128, 185-188, 215, 224, 229, 291, 313; `prim/src/ecdsa.rs` 282-296, 324-326, 335, 373-392; `esdk/src/materials.rs` 130, 202; `esdk/src/decrypt.rs` 413; `esdk/src/config.rs` 35, 42; shim `lib.rs` 167, 274, 300, 372-373, 398, 401, 423-424, 715-728, 1287, 1311, 1331, 1346, 1403, 1412-1416, 1570-1571, 1661, 2050-2066; `EncryptionSDK.cpp` 541-547; `EncryptionSDK.h` 656-664; test-server `main.rs` and `Cargo.toml`.

## Rating decisions (all existing ratings kept)
- TM-009 / 010 High: `cache_entry_identifier.rs` read in full (66 lines); the preimage is exactly NUL-joined with no length prefix. The version field is hex plus hyphens (`uuid_16_bytes_to_str`, `hierarchical_keyring.rs:894`) so it cannot carry NUL. New no-NUL collision: same logical name on two physical key stores (spec-forbidden, undetectable). Kept High, likelihood Medium.
- TM-018 Medium: re-derived from `storm_tracking.rs:230-410` read in full. Stale same-key mark: `state_locked` retains `skip_key` (`:249-255`); `classify_and_mark` returns `Err(Throttling)` for a miss with `elapsed > in_flight_ttl` (`:321-323`) before any leader path, so nothing clears the mark except another key's prune. Recovery window: a call within (grace interval, in_flight_ttl] re-marks and becomes leader (`:337`). Waiter with `deadline: None` (`:313`). BUG-01(b/c) `now + ttl` at `:333` and `inflight + grace_interval` at `:680` are reached inside `classify_and_mark` / `wait_for_leader`, both under the `MutexGuard` (`:739-740`, `:388-397`), so a panic poisons the std `Mutex` and later calls return `Internal`. If a reproducer shows the wedge, severity High × likelihood Low is still Medium.
- TM-002 Medium: `get_active_branch_key` (`branch_key_store.rs:792`, `decrypt_branch_key` call `:801`) has no single-key requirement; only `configured_kms_key_arn` (`:112-121`, used by CreateKey and VersionKey) rejects Discovery. The hierarchical keyring calls `get_active_branch_key` on encrypt (`:692`). So Discovery trust applies to new encryptions as well. Kept at Likelihood Low because of the preconditions (Discovery config, DDB write, attacker key policy, no IAM scoping).
- TM-005 High: no `consistent_read` anywhere in `mpl/src` (grep, no match); `fetch_record` `GetItem` at `:155-163`. Rollback of ACTIVE to an older authentic copy is undetected. Added as a residual. A stale `GetItem` in VersionKey fails `#enc = :encOld` (`:752`), which is safe.
- TM-003 Low: supplier input on decrypt is the message EC (`hierarchical_keyring.rs:747`, `:831`); EDK info must equal the supplier's result (`:752-763`); error-type existence oracle (ResourceNotFound vs authentication failure).
- TM-011 Medium: NIST SP 800-38D 2^32 random-IV limit added as an operational residual (external knowledge, not a code finding); the keyring has no wrap counter.
- TM-015 Low: residency beyond TTL (`cmc/local.rs:69`, `:131`, `:166`); `ecdsa_generate_keypair` plain `Vec` for the private key (`ecdsa.rs:387`) dropped un-wiped on the `:391-392` error path; `SignatureKeyPair` `Clone`, no `Drop` (grep `Zeroize|impl Drop` in `prim/src` finds only `Debug` impls).
- TM-022 Low: failed lookups are never `put` (`hierarchical_keyring.rs:931-955`), so unknown versions cannot evict valid entries.
- TM-024 Medium: see below.
- Others: re-confirmed.

## New-threat screening
Added:
- **TM-025** decrypt-input amplification (Medium, provisional). Facts from code: `for edk in &encrypted_data_keys` (`hierarchical_keyring.rs:751`); filter 752-763; `try_decrypt_edk` per EDK (`:764`); version bytes at ciphertext offset 28, 16 bytes (`:889-894`); cache miss → `get_branch_key_version` (`:934`) → `.await?` (`:938`) returns before `put_cache_entry` (`:950-954`). ESDK cap `None` by default (`esdk/src/config.rs:35`, `:42`). `max 65,535 EDKs` per `test_keyring_memory.rs:4`. Duplicate-version wait: second lookup finds the first leader's mark within the 1 s grace interval, so `Wait { deadline: Some(now + in_flight_ttl) }` (`:326-334`), then `leader_permitted` after 1 s (`:390-397`). All static reasoning. Reproducers suggested:
  1. A `DefaultCmc` plus a fake key store that counts `get_branch_key_version` calls; decrypt a message with N EDKs with distinct unknown versions; assert the call count and the elapsed time.
  2. Same with N EDKs sharing one unknown version; measure elapsed (expected about N × grace interval).
  3. Fill the fan-out (20 distinct versions), then time a miss for a valid, expired key.
  4. For TM-018: build a `StormTrackingCmc`, let a leader `get` (marks) and drop it without `put`, advance the injected clock past `in_flight_ttl`, call `get` again for the same key (expect `Throttling`), then call `get` for another key and the first key again.
- **TM-026** test servers use ambient AWS credentials with request-chosen regions, tables and KMS ARNs (`mpl/test-server/src/handlers.rs:137-147`, `:425-430`); loopback bind `main.rs:26-27`; `publish = false` (`Cargo.toml:6`). Low, test-only. Not tested that a browser cannot reach it.

Folded into existing IDs (same boundary, same actor, same fix):
- C++ `Keyring::adopt(void*)` and `into_keyring_handle` into **TM-024**. Found by grepping `c_void`/`adopt` in the shim; `lib.rs:2059-2066`, `EncryptionSDK.cpp:541-547` (`rust::Box<ffi::Keyring>::from_raw(static_cast<...>(raw_handle))`, no check), header text `EncryptionSDK.h:656-664`. It predates #188/#189: per scope, `src/lib.rs` changed only by #188's +7/-1. The previous threat model did not cover it (a first-pass gap).
- Authentic-record rollback into **TM-005**; Discovery on encrypt into **TM-002**; message-driven supplier and existence oracle into **TM-003**; same-logical-name collision and future-time freshness into **TM-010**; provider info in errors into **TM-021**; `SharedCmm` policy backstop and `max_plaintext_length` into **TM-006**; spec-silent fixed info into **TM-014**.

Considered and not added:
- `Error::from_sdk` public: no attacker.
- `ecdsa_verify` returns `Ok(false)` for a malformed key: fail-closed; informational.
- #188 retry config now reaching DDB: behavior only; a caller-chosen `max_attempts` is the caller's own amplification, not an attacker's.
- #189 link and build changes: hardening (one cxx runtime, link by path); the test-server rpath to `target/<profile>` is a development convenience. No trust boundary.
- `LocalCmc` mutex poisoning: `Internal` error, fail-closed.
- Spec floating on `master` (remote master `94c2bfe`; `framework/` unchanged per scope): folded into TM-019.

## C++ shim (TM-024) conclusions after #188 and #189
- Borrowed handles: `*const T` in the bridge input structs (`lib.rs:274`, `:300`, `:372-373`, `:398`, `:401`); `require_handle` (`:715`, null check `:720`, deref `:728`); `as_ref()` (`:1570`, `:1571`, `:1661`). Rust creates only shared references and clones `Arc`s and SDK clients; no `&mut` from a handle. The keyring is cloned before `.send()` and `block_on` (`:1311`, `:1346`), so no handle reference is held across an `await` or `block_on`. `require_handle<'a, T>` returns an unbounded `'a` (`:715`).
- C++ facade keeps dependencies alive (`detail::Retained`, `EncryptionSDK.cpp` near the hierarchical keyring constructor), so a facade user cannot free a dependency early. Residual risk: raw-bridge callers, a free on another thread between the null check and the clone, and `adopt`.
- `adopt`: type-erased, unchecked, double adopt is a double free; documented as a target obligation (`lib.rs:2050-2054`, `EncryptionSDK.h:656-664`).
- Only other `unsafe` in the shim tree: `src/tests.rs:1634` (test).
- #188: retry config for the DynamoDB client, `lib.rs:1412-1416`; shifts later lines by 6. #189: build/link only; `build.rs:5-11` compiles cxx bridge plus `EncryptionSDK.cpp` into one staticlib; `CMakeLists.txt:39-53`, `Makefile:4-12` link by path; `test-server/build.rs:46-49` sets an rpath to the shim's own `target/<profile>`.

## Effect of open bugs on other threats (summary; full table in the document)
BUG-01(b/c) poison the storm-tracking lock; BUG-04 does not widen TM-002; BUG-05(b) lowers the sender's cost per EDK for TM-025; BUG-06 also reaches decrypt via supplier-chosen ids (not via the version), and colliding keyrings share in-flight marks; BUG-07 only feeds TM-015.

## Impact on verification targets (copy of the document's note, for the orchestrator)
Refresh recommended: T25 (stale shim citations, `adopt` scope), T21 (liveness properties, lock poison), T26 (two new residual sites). Optional: T06, T14, T19, T22. No refresh: T01-T05, T07-T13, T15-T18, T20, T23, T24, C01-C08. New candidate (no target yet): TM-025 bounded work per decrypt. BUG-06 is rated Low in `docs/bug-reports/` while TM-009/010 are High; the bug report was not edited.

## Verification of this step
- Files written: `docs/threat-model.md`, this file. No other write tool call.
- No code under `mpl/`, `prim/`, `esdk/` was touched. No commit, no push. Stage 3 not run.
