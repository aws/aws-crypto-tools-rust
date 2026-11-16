# MPL Native Rust: Bug Reports for Engineering Discussion

| Field | Value |
|---|---|
| Document | MPL Native Rust: Bug Reports for Engineering Discussion |
| System | AWS Cryptographic Material Providers Library (MPL), native Rust implementation |
| Repository | aws/aws-crypto-tools-rust, branch `MPL-Verus` |
| Code reviewed | `main` commit `620771c` (merged into `MPL-Verus` as `c256243`), cross-checked on `MPL-Verus` HEAD `9955ecd`. `mpl/` and `prim/` are identical in the two. The bugs were originally found at commit `a1e23d7`. |
| Status | Draft |
| Date | 2026-11-15 (bug status re-checked 2026-11-10; cross-references updated at HEAD `9955ecd`) |
| How this was produced | AI-assisted consolidation of the nine individual bug reports in `docs/bug-reports/` and of the re-check against `main` (`docs/bug-reports/RECHECK-main-620771c.md`). Severities, confidence labels and conclusions are taken from those reports. The one severity that differs from the first edition of this document is BUG-06, which is now High (raised from Low on the owner's decision after the main re-check). Threat and target references follow `docs/threat-model.md` (TM-MPL-001..026), `docs/verification-targets.md` and `docs/completeness-audit.md` as of HEAD `9955ecd`. Human review is required before any decision is made on this basis. |

## Introduction

These nine findings came out of the Verus verification-target analysis of the MPL native Rust implementation. Each one is a likely defect, or an observation that needs a decision, found while stating provable properties. They were first found and reproduced at commit `a1e23d7`, using temporary, untracked tests. No code was changed.

On 2026-11-10 all nine findings were re-checked against `main` commit `620771c`, which is merged into `MPL-Verus` as `c256243` with identical code. Where the public API had changed, the reproducers were adapted for API changes only, keeping the same inputs and observations. The result:

- Still present on `main`: BUG-01, BUG-04, BUG-05 (a) and (b), BUG-06, BUG-07 (a) and (b), BUG-08. BUG-05 (b) is still likely not a bug.
- Fixed on `main`: BUG-02, BUG-03 and BUG-09, all in commit `e9bde48` (#98). They are summarized in "Resolved on main" near the end of this document.

The open findings give fix options and questions for discussion rather than a chosen fix.

Update at HEAD `9955ecd`. After the re-check, `main` moved from `620771c` to `5f2dc72` with two esdk-only commits (#188 and #189). `git diff --stat 620771c 5f2dc72 -- mpl prim` is empty, so every status above still holds (proof in the addendum of `docs/bug-reports/RECHECK-main-620771c.md`). Two things changed in this document. First, BUG-06 is now rated High. The severity was raised from Low to High on the owner's decision after the main re-check. The finding, evidence, status and confidence of BUG-06 are unchanged, and no other bug's severity changed. Second, the threat and target references were brought up to date: the threat model now has 26 threats, TM-MPL-009 and TM-MPL-010 (the threats BUG-06 realizes) are High, and the verification targets were refreshed (new target T27 for TM-MPL-025).

About line numbers: file:line locations in the Status and Location parts of each section refer to the current code on `main` `620771c`. Each section also gives the original `a1e23d7` location. Line numbers elsewhere (for example in Impact and Fix options) come from the original reports and refer to `a1e23d7`. Some files were renamed since then; for example, `mpl/src/keystore/` is now `mpl/src/key_store/`.

Full reports, re-check and reproducers:

- Bug reports: https://github.com/aws/aws-crypto-tools-rust/tree/MPL-Verus/docs/bug-reports
- Re-check against main: https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/RECHECK-main-620771c.md
- Original reproducers (`a1e23d7` API): https://github.com/aws/aws-crypto-tools-rust/tree/MPL-Verus/.agents/tasks/bug-reports/reproducers
- Adapted reproducers (`main` API): https://github.com/aws/aws-crypto-tools-rust/tree/MPL-Verus/.agents/tasks/bug-recheck/reproducers

## Summary

| ID | Title | Component | Severity | Confidence | Spec conflict | Status on main (620771c) | Discussion priority |
|---|---|---|---|---|---|---|---|
| BUG-01 | Large accepted TTL / grace / inflight values overflow `SystemTime + Duration` and panic | Hierarchical keyring; StormTracking CMC | Low | Confirmed by test | no | Still present | 2 – Medium |
| BUG-02 | Plaintext data key length not enforced (hierarchical OnDecrypt and materials constructors) | Hierarchical keyring; materials structures | Medium | Confirmed by test | yes | Fixed on main (`e9bde48`, #98) | 7 – Resolved |
| BUG-03 | `EncryptionContext::deserialize` accepts entries not sorted by key | `structures::EncryptionContext` | Low | Confirmed by test | yes | Fixed on main (`e9bde48`, #98) | 8 – Resolved |
| BUG-04 | MRDiscovery rewrites the region of single-Region (non-MRK) KMS key ARNs | Branch key store (KMS ARN resolution) | Low | Confirmed by test | yes | Still present | 3 – Medium |
| BUG-05 | (a) Default CMM panics if ECDSA key generation fails; (b) 44–59-byte hierarchical EDK reaches the keystore | Default CMM; hierarchical keyring | Low | (a) Confirmed by code reading; (b) Confirmed by test, likely not a bug | no | (a) Still present; (b) Still present (likely not a bug) | 5 – Low |
| BUG-06 | Cache-identifier preimage not injective when fields contain NUL | Hierarchical keyring (cache identifier) | High (raised from Low on the owner's decision) | Confirmed by test | yes | Still present | 1 – High |
| BUG-07 | `prim::aes_encrypt` leaves plaintext in buffer on `Err`; `aes_decrypt` guard weaker than callee | `aws-mpl-primitives` (AES-GCM) | Low | Confirmed by test | no | Still present (a and b) | 4 – Low |
| BUG-08 | Custom-EC collision `Err` in `build_base` is dead code | Branch key store (encryption context) | Informational | Confirmed by code reading | no | Still present | 6 – Low |
| BUG-09 | `cache_entry_within_limits` admits entries up to `ttl + 1 s` | Hierarchical keyring (cache TTL) | Informational | Confirmed by test, likely not a bug | no | Fixed on main (`e9bde48`, #98) | 9 – Resolved |

How to read the table:

- Severity, confidence and spec conflict are the values from the original analysis. The re-check did not change them. The one exception is BUG-06: Severity raised Low -> High on the owner's decision after the main re-check. The BUG-06 section gives the basis and the preconditions.
- Spec conflict "yes" for BUG-03, BUG-04 and BUG-06 depends on how the spec is read, or on text where the spec contradicts itself. Each section explains which.
- "Likely not a bug" means the behavior was reproduced but matches the Dafny MPL, or has no practical impact.
- Discussion priority is a suggested order (1 = first). It weighs spec deviation, cross-runtime divergence and impact, not just severity. The order was revised after the re-check. Open bugs now come first and fixed bugs move to the end. BUG-06 moves to the top, because with BUG-02 fixed it is the open finding with the most direct impact, the re-check confirmed on `main` that keyring B was served keystore A's branch key, and its severity is now High. The other open bugs keep their original relative order.

## Cross-reference to the threat model and verification targets

Ratings are from `docs/threat-model.md` (TM-MPL-001..026, HEAD `9955ecd`). Target IDs are from `docs/verification-targets.md`. The mapping is the bug to threat to target table in `docs/completeness-audit.md` section 3b, plus the "Related IDs" of each bug report. No threat rating changed because of the BUG-06 severity decision.

| ID | Severity | Status on main | Related threats (risk) | Related targets (score) | Proof status |
|---|---|---|---|---|---|
| BUG-01 | Low | Still present | TM-MPL-018 (Medium), TM-MPL-022 (Low), TM-MPL-023 (Low) | T06 (4.20); T21 property (i) (2.24) | None yet |
| BUG-02 | Medium | Fixed on main | TM-MPL-006 (Medium), TM-MPL-023 (Low) | C04 (2.80) | None yet |
| BUG-03 | Low | Fixed on main | TM-MPL-013 (Medium), TM-MPL-017 (Medium) | T15 (1.92) | None yet |
| BUG-04 | Low | Still present | TM-MPL-007 (Medium). It fails closed and does not widen TM-MPL-002 (Medium) | T17 (1.92) | None yet |
| BUG-05 | Low | (a) Still present; (b) Still present (likely not a bug) | TM-MPL-023 (Low); (b) also TM-MPL-025 (Medium, provisional), which (b) does not cause | T16 (2.24); (b) also T27 (3.78, provisional) | None yet |
| BUG-06 | High (raised from Low on the owner's decision) | Still present | TM-MPL-009 (High), TM-MPL-010 (High), TM-MPL-003 (Low) | T13 (4.41); T19 (1.92) | None yet |
| BUG-07 | Low | Still present (a and b) | (a) TM-MPL-015 (Low); (b) TM-MPL-023 (Low); TM-MPL-011 (Medium) through T07 | (a) T26 (3.20), T07 property (e) (3.84); (b) C03 (5.60) | None yet |
| BUG-08 | Informational | Still present | TM-MPL-005 (High). Informational; no effect on that rating | C01 property (c) (6.72) | C01: Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors. The collision branch is dead if and only if A_ITER holds, and live if a key repeats |
| BUG-09 | Informational | Fixed on main | TM-MPL-010 (High). The High rating comes from BUG-06, which is open | T14 property (b) (3.78) | None yet |

## Suggested meeting agenda

| Order | ID | Topic | Decision needed |
|---|---|---|---|
| 1 | BUG-06 | Cache-identifier preimage not injective with NUL | Reject NUL in configuration values, or change the preimage via a spec change. Severity is High (raised from Low on the owner's decision after the main re-check); TM-MPL-009 and TM-MPL-010 are High |
| 2 | BUG-01 | TTL / grace / inflight overflow panic | Per-call checked addition (Dafny parity) or construction-time bounds |
| 3 | BUG-04 | MRDiscovery rewrites non-MRK ARN region | Which spec text is authoritative; align with Dafny |
| 4 | BUG-07 | `prim` AES buffer handling | Whether `prim` must leave the caller's buffer unchanged on error; fix the misleading decrypt error text |
| 5 | BUG-05 | Default CMM keygen `.expect`; short EDK keystore lookup | Propagate the keygen error; add a pre-lookup length check for (b) or leave as is |
| 6 | BUG-08 | Dead collision branch in `build_base` | Comment fix only, or debug assertion |
| 7 | BUG-02, BUG-03, BUG-09 | Fixed on `main` (`e9bde48`, #98) | None required. Optional: the remaining cross-runtime parity questions in "Resolved on main" |

## BUG-01: Large accepted TTL / grace / inflight values overflow `SystemTime + Duration` and panic

Full report: https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-01-ttl-duration-overflow-panic.md

### Summary

`HierarchicalKeyring` and `StormTrackingCmc` accept arbitrarily large time values at construction, then add them to `SystemTime::now()` with the panicking `+` operator. A valid-looking configuration such as `ttl_seconds = u64::MAX` panics on first use instead of returning an error.

| Attribute | Value |
|---|---|
| Severity | Low |
| Confidence | Confirmed by test |
| Spec conflict | no |
| Related IDs | VR-2026-T06 (primary), VR-2026-T21 (property (i), panic under the state lock, for BUG-01 b and c); TM-MPL-018 (Medium), TM-MPL-022 (Low), TM-MPL-023 (Low) |

Severity rationale: the trigger is configuration only (trusted application code), and the threshold on Unix is roughly 9.2 × 10^18 s. A "never expire" sentinel such as `u64::MAX` is still a plausible value for an application to pass, and the result is a panic, not an error.

### Status on main (620771c)

Still present. The reproducer, adapted for API changes only, gives 5 passed / 0 failed. All four calls still panic with `overflow when adding duration to instant`. The TTL is now a `Duration`, but no commit since `a1e23d7` adds an overflow check or an upper bound. Re-checked 2026-11-10.

### Location

Current code (`main` `620771c`):

- `mpl/src/aws_kms/hierarchical_keyring.rs:702` (OnEncrypt cache put) and `:945` (OnDecrypt cache put): `.expiry_time(now + self.inner.ttl)`.
- `mpl/src/aws_kms/hierarchical_keyring.rs:547`: `HierarchicalKeyringBuilder::build` only rejects a zero TTL.
- `mpl/src/cmc/storm_tracking.rs:333` (per-waiter deadline) and `:680` (`within_grace_interval`).
- `mpl/src/cmc/storm_tracking.rs:606-626`: `StormTrackingCmcBuilder::build` rejects zero values and `grace_interval > in_flight_ttl` only, with no upper bound.

```rust
698                 let now = SystemTime::now();
699                 let entry = CacheEntry::builder()
700                     .materials(CachedMaterials::BranchKey(bkm.clone()))
701                     .creation_time(now)
702                     .expiry_time(now + self.inner.ttl)
703                     .build()?;
...
333                                 deadline: Some(now + self.inner.in_flight_ttl),
...
680     now < inflight + grace_interval
```

Originally reported at `a1e23d7`: `hierarchical_keyring.rs:342`, `:585` (validation `:150`); `storm_tracking.rs:446`, `:536` (validation `ValidatedConfig::from_raw`, `:108-143`).

### Expected vs actual behavior

Expected: there is no spec requirement here; this is robustness and defense-in-depth. The spec sets a lower bound ("MUST be greater than zero") and no upper bound. The Dafny MPL guards the same addition and returns "INT64 Overflow when putting cache entry." instead of overflowing. The Dafny storm-tracking cache was not checked.

Actual:

- `HierarchicalKeyring::new(.., ttl_seconds = u64::MAX, ..)` returns `Ok`. The first `on_encrypt` or `on_decrypt` panics with `overflow when adding duration to instant`.
- `StormTrackingCmc::new` with `grace_interval = u64::MAX` returns `Ok`; the second `get_cache_entry` for the same key panics in `within_grace_interval` (BUG-01b).
- With `grace_interval = 1` and `inflight_ttl = u64::MAX`, the second `get_cache_entry` panics computing the waiter deadline (BUG-01c).
- The same path is reachable through `HierarchicalKeyring::new(.., CacheType::StormTracking(..))`, because the keyring only checks `grace_period < ttl_seconds`.

### Impact and preconditions

- Precondition: the application configures a TTL, grace interval or inflight TTL larger than about `i64::MAX − now` seconds on Unix-like targets.
- Effect: a panic on an encrypt/decrypt path. Under Tokio this kills the task and the caller gets a `JoinError`. With `panic = "abort"`, or across an FFI boundary such as the C++ shim, it ends the process. No `catch_unwind` exists in `mpl/src`, `esdk/src` or `esdk/shims`.
- Remote exploitability: none. Message data cannot influence these values.
- Platform note (expected, not tested): the Windows `SystemTime` limit is much lower, around 1.8 × 10^12 s from 1601.

### Evidence

Confidence: Confirmed by test. Re-check on `main`: reproducer `zz_bugrepro_01_ttl_overflow.rs`, adapted for API changes only (builders, `Duration::from_secs(u64::MAX)`, the `KeyStore` trait shapes), with the same inputs and the same pass condition (each call must panic). macOS. Trimmed output (`recheck01.log`):

```text
REPRO BUG-01 now+u64::MAX s checked_add = None
REPRO BUG-01 now+1e15 s checked_add is_some = true
REPRO BUG-01c StormTrackingCmc::new(inflight_ttl = u64::MAX s) is_ok = true
REPRO BUG-01b StormTrackingCmc::new(grace_interval = u64::MAX s) is_ok = true
REPRO BUG-01a HierarchicalKeyring::new(ttl_seconds = u64::MAX) is_ok = true
REPRO BUG-01c second get PANICKED: overflow when adding duration to instant
REPRO BUG-01b second get PANICKED: overflow when adding duration to instant
REPRO BUG-01a on_encrypt PANICKED: overflow when adding duration to instant
REPRO BUG-01d on_decrypt PANICKED: overflow when adding duration to instant
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The print labels are the original test's (for example `HierarchicalKeyring::new`); the adapted test calls the builders. The output matches the original run at `a1e23d7`.

### Fix options

1. Checked addition at each use site, returning an error (`MaterialsError::keyring_failed` in the keyring, `CmcError` in storm tracking). Matches Dafny. These configurations change from panicking to returning an error on every call.
2. Reject at construction with an upper bound in `HierarchicalKeyring::new` and `ValidatedConfig::from_raw`. Best UX, but adds a limit the spec does not state and needs cross-runtime agreement on a constant.
3. Saturate, treating overflow as "never expires". No error, but silently changes semantics, diverges from Dafny's fail-closed behavior, and `deadline: None` disables the per-waiter InFlightTTL check.

Recommendation: option 1 at all four sites, because it matches the Dafny reference and keeps behavior fail-closed. Option 2 can be added later if the team wants a construction-time error.

### Questions for engineers

1. Should the native Rust library match the Dafny error ("INT64 Overflow when putting cache entry") per call, or fail early in the constructors?
2. If a constructor bound is preferred, what maximum TTL / grace values should be agreed across runtimes, and should the limit account for the Windows `SystemTime` range?
3. For storm tracking, should overflow in `within_grace_interval` mean "within the interval" (saturate) or be an error?
4. Is the C++ shim built with `panic = "abort"` or otherwise relying on no panics crossing the FFI boundary?

## BUG-04: MRDiscovery rewrites the region of single-Region (non-MRK) KMS key ARNs

Full report: https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-04-mrdiscovery-rewrites-non-mrk-arn-region.md

### Summary

With `KmsConfiguration::MrDiscovery { region }`, the branch key store rewrites the region of every record's `kms-arn` to the configured region, including single-Region keys. KMS then receives a key ARN that does not exist, so the request fails. The Dafny MPL rewrites only multi-Region key (MRK) ARNs.

| Attribute | Value |
|---|---|
| Severity | Low |
| Confidence | Confirmed by test (in-crate unit test against `resolve_keystore_arn`; the end-to-end KMS failure is inferred and needs AWS) |
| Spec conflict | yes. The spec is internally inconsistent: the configuration section says MRK ARNs only, while the KMS-Decrypt section says the region is replaced unconditionally. |
| Related IDs | VR-2026-T17; TM-MPL-007 (Medium). The threat model records that this bug fails closed and does not widen TM-MPL-002 (Medium) |

Severity rationale: this is a spec-text / cross-runtime divergence. With the default KMS client, a single-Region key outside the configured region is expected to fail in both Rust and Dafny, with different errors. Outcomes differ only when the caller supplies its own KMS client. It fails closed, with no wrong-key or confidentiality impact.

### Status on main (620771c)

Still present. The in-crate test, adapted for API changes only, gives 1 passed. The single-Region `us-east-1` ARN is still rewritten to `us-west-2`. The module moved from `keystore/` to `key_store/` in `e9bde48` (#98), and `resolve_keystore_arn` is now `resolve_key_store_arn`. The logic is unchanged. Re-checked 2026-11-10.

### Location

Current code (`main` `620771c`): `mpl/src/key_store/kms_ops.rs:100-103` (the MrDiscovery arm of `resolve_key_store_arn`, `:88`) and `:144-157` (`rewrite_arn_region`). There is no `mrk-` check. An MRK predicate exists in `mpl/src/aws_kms/mrk_match.rs:52` (`is_multi_region_arn`, private to that module), but the key store path does not use it. The resolved ARN is used as the KMS `KeyId` in `decrypt_branch_key` (`kms_ops.rs:179`) and in `version_key` (`mpl/src/key_store/branch_key_store.rs:663`).

```rust
100         KmsConfiguration::MrDiscovery(mr_discovery) => {
101             reject_alias_arn(record_kms_arn, branch_key_id)?;
102             return rewrite_arn_region(record_kms_arn, mr_discovery.region(), branch_key_id);
103         }
...
148     Ok(format!(
149         "arn:{}:{}:{}:{}:{}/{}",
150         parts.partition,
151         parts.service,
152         new_region,
```

Originally reported at `a1e23d7`: `mpl/src/keystore/kms_ops.rs:104-107` and `:132-148`; `decrypt_branch_key` at `kms_ops.rs:169`; `version_key` at `branch_key_store.rs:442`. Spec line numbers (168, 204, 669) were not re-checked in the 2026-11-10 run, because `main` removed the spec submodule. They were re-read at HEAD `9955ecd` in the local `spec/framework/branch-key-store.md`: lines 168 and 204 hold the "Any MRK ARN discovered will be changed to this region before use" sentence, and line 669 holds the MRDiscovery `KeyId` sentence.

### Expected vs actual behavior

Expected: `spec/framework/branch-key-store.md` has two texts. Lines 168 and 204 (`#aws-kms-configuration`, `#mrdiscovery`, non-normative) say "Any MRK ARN discovered will be changed to this region before use." Line 669 (`#aws-kms-branch-key-decryption`, normative) says the region is replaced, with no MRK qualifier. The Rust code follows line 669 literally. The Dafny `replaceRegion` follows lines 168/204 and leaves non-MRK (or unparseable) ARNs unchanged.

Actual: with `MrDiscovery { region: "us-west-2" }` and a record `kms-arn` of a single-Region key in `us-east-1`, `rewrite_arn_region` returns the same ARN with region `us-west-2`. KMS `Decrypt` with that `KeyId` is expected to fail (for example `NotFoundException`); that step was inferred, not run.

### Impact and preconditions

- Precondition: an MRDiscovery keystore reads a record whose `kms-arn` is a single-Region key.
- Default KMS client (built in the MRDiscovery region): if the key is in the same region, the rewrite is a no-op; if in another region, both runtimes are expected to fail at KMS with different errors (not tested).
- Caller-supplied KMS client in the key's home region: Dafny would succeed and Rust would fail. This is the case where outcomes diverge, and it is an unusual configuration.
- Security: none identified. The rewritten ARN cannot name a different existing key, and `Decrypt` still binds the record's encryption context. Fails closed.
- Net: the main value of a fix is spec and Dafny parity, plus clearer errors.

### Evidence

Confidence: Confirmed by test (in-crate unit test against `resolve_key_store_arn`; the end-to-end KMS failure is inferred and needs AWS). `resolve_key_store_arn` is `pub(crate)` in a private module, so the re-check ran the reproducer `zz_bugrepro_04_mrdiscovery_non_mrk.rs`, adapted for API changes only, as an in-crate unit test in a throwaway copy of the crate under `/tmp`. The repository source was not modified. Trimmed output (`recheck04.log`):

```text
REPRO BUG-04 MRDiscovery(us-west-2), record SRK  arn:aws:kms:us-east-1:111122223333:key/1234abcd-... -> Ok("arn:aws:kms:us-west-2:111122223333:key/1234abcd-...")
REPRO BUG-04 MRDiscovery(us-west-2), record MRK  arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-... -> Ok("arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd-...")
REPRO BUG-04 Discovery,              record SRK  arn:aws:kms:us-east-1:111122223333:key/1234abcd-... -> Ok("arn:aws:kms:us-east-1:111122223333:key/1234abcd-...")
REPRO BUG-04 SRK ARN changed by MRDiscovery: true
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out
```

The output is the same as at `a1e23d7`. The original report noted that the existing integration test `test_aws_kms_hierarchical_keyring_integ.rs:815-866` covers only the MRK case; that was not re-checked on `main`.

### Fix options

1. Rewrite only MRK ARNs (Dafny behavior): return the ARN unchanged unless the resource is `key/mrk-*`, reusing or sharing `is_multi_region_arn`. Cross-runtime parity and matches lines 168/204; deviates from the literal text at line 669 until the spec is clarified.
2. Keep the current behavior and document that MRDiscovery requires MRK-backed records. No code change, but keeps the Dafny difference and the less clear KMS error.
3. Reject non-MRK ARNs under MRDiscovery with a clear `KeystoreError`. Fails fast with a clear message, but still diverges from Dafny.

Recommendation: option 1, together with a spec clarification adding the MRK qualifier to `branch-key-store.md#aws-kms-branch-key-decryption`.

### Questions for engineers

1. Which spec text is authoritative for MRDiscovery: "Any MRK ARN discovered" (lines 168/204) or the unconditional replacement at line 669? Should the spec be amended?
2. Is matching the Dafny `replaceRegion` behavior (non-MRK unchanged, unparseable unchanged) a goal for the native Rust keystore?
3. Is there an existing cross-runtime test vector with an MRDiscovery keystore and a single-Region `kms-arn` record? If not, should one be added?
4. Should the MRK predicate be shared between `mrk_match.rs` and `kms_ops.rs` rather than duplicated?

## BUG-05: (a) Default CMM panics if ECDSA key generation fails; (b) a 44–59-byte hierarchical EDK reaches the keystore before rejection

Full report: https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-05-keygen-expect-and-short-edk-keystore-lookup.md

### Summary

(a) `DefaultCmm::get_encryption_materials` calls `.expect` on the `Result` from `ecdsa_generate_keypair`, so a key-generation failure panics instead of returning `MaterialsError`. (b) `HierarchicalKeyring` fetches the branch key (from the keystore on a cache miss) for an EDK of 44–59 bytes before rejecting it as too short.

| Attribute | Value |
|---|---|
| Severity | Low |
| Confidence | (a) Confirmed by code reading; (b) Confirmed by test for the behavior. Part (b) is likely not a bug: it matches the Dafny MPL and adds no amplification beyond what any EDK of 60 bytes or more already causes. |
| Spec conflict | no |
| Related IDs | VR-2026-T16; TM-MPL-023 (Low). For (b) also TM-MPL-025 (Medium, provisional; target VR-2026-T27, added at HEAD `9955ecd`). The threat model states that (b) is not the cause of TM-MPL-025: a valid-length EDK costs the same key-store read, so (b) only lowers the sender's cost per EDK |

Severity rationale: (a) is a latent panic on a path that should be unreachable unless AWS-LC fails (RNG or self-test failure, allocation failure). (b) costs one keystore round trip per malformed EDK, then fails closed.

### Status on main (620771c)

(a) Still present, by code reading: the `.expect(..)` is unchanged and the callee still has four `Err` paths. (b) Still present, and still likely not a bug. The test, adapted for API changes only, gives 1 passed. A 43-byte EDK makes 0 key store calls; EDKs of 44, 50 and 59 bytes make 1 call each before being rejected. Only the error text changed. The BUG-02 fix on `main` checks the key length after the lookup, so it does not resolve (b). Re-checked 2026-11-10.

### Location

Current code (`main` `620771c`):

- (a) `mpl/src/cmm/default_cmm.rs:137-138`. `prim/src/ecdsa.rs:373` (`ecdsa_generate_keypair`) has four `Err` paths (`:375`, `:380`, `:386`, `:391-396`). The enclosing function already returns a `Result`.
- (b) `mpl/src/aws_kms/hierarchical_keyring.rs:879` checks only for at least 44 bytes before the key store lookup at `:934`. The 60-byte minimum is enforced afterwards in `branch_key_wrap::unwrap` (`mpl/src/aws_kms/branch_key_wrap.rs:236`).

```rust
137             let keys = ecdsa_generate_keypair(alg)
138                 .expect("ECDSA keypair generation cannot fail for fixed P-256/P-384 algorithms");
```

Originally reported at `a1e23d7`: (a) `default_cmm.rs:114-115`, `prim/src/ecdsa.rs:370-400`; (b) `hierarchical_keyring.rs:536-542` and `:570-572`, `branch_key_wrap.rs:231-236`.

### Expected vs actual behavior

Expected: no spec requirement for either part; this is robustness and defense-in-depth.

- (a) The spec requires the Default CMM to generate a signing key but does not say how failure is reported. The Dafny Default CMM propagates it as an error.
- (b) The spec orders the steps as: find branch key materials (cache, then keystore), then unwrap. It does not require a full-length check first. The Dafny keyring has the same order as Rust.

Actual:

- (a) By code reading: if `ecdsa_generate_keypair` returns `Err` for a signing suite, `.expect` panics and the caller sees a panic, not `MaterialsError`.
- (b) By test: a 44–59-byte EDK with a matching provider id and branch key id causes one `get_branch_key_version` call, then `unwrap` rejects it ("ciphertext too short: N < 60"). A 43-byte EDK is rejected with 0 keystore calls.

### Impact and preconditions

- (a) Precondition: AWS-LC key generation, compression or encoding fails (entropy failure, FIPS self-test failure, or allocation failure). Cannot be triggered by message data. Effect: a panic on the encrypt path; under Tokio it kills the task, and with `panic = "abort"` or across FFI it ends the process.
- (b) Precondition: an attacker can get a crafted EDK into a message a victim decrypts with a hierarchical keyring, and knows or matches the branch key id. Effect: one cache lookup and, on a miss, one keystore call (DynamoDB `GetItem` + KMS `Decrypt`) before failing. A garbage EDK of 60 bytes or more has the same effect, so rejecting 44–59 earlier removes no attack capability.

### Evidence

Confidence: (a) Confirmed by code reading. It was not reproduced, because it needs a forced AWS-LC failure that cannot be injected without changing `prim/src`. (b) Confirmed by test, likely not a bug. Re-check on `main`: reproducer `zz_bugrepro_05_short_edk_lookup.rs`, adapted for API changes only. The error text is now read through `Display` and the `source()` chain, because a single failed candidate EDK is returned directly. Trimmed output (`recheck05.log`):

```text
REPRO BUG-05b ciphertext_len=43: on_decrypt is_err=true keystore get_branch_key_version calls=0 inner_error=Some("Cryptographic: encrypted data key ciphertext too short to contain the branch key version: 43 bytes (need at least 44)")
REPRO BUG-05b ciphertext_len=44: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Cryptographic: ciphertext too short: 44 < 60")
REPRO BUG-05b ciphertext_len=59: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Cryptographic: ciphertext too short: 59 < 60")
REPRO BUG-05b ciphertext_len=60: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Cryptographic: AES-256-GCM decrypt failed <- Cryptographic: authentication tag did not match")
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Fix options

(a) keygen `.expect`:

1. Propagate the error with `.map_err(..)?` as a `MaterialsError`. Matches Dafny and needs no API change.
2. Keep the `.expect`, but document and prove the invariant, treating keygen failure as fatal by design. Diverges from Dafny and leaves a panic reachable from a C++ caller.

Recommendation for (a): option 1.

(b) short EDK:

1. Check the exact length (`60 + suite.encryption_key_length()`) in `try_decrypt_edk` before the cache/keystore step. Rejects all wrong-length EDKs with no I/O and also fixes BUG-02 C04-F1 on the hierarchical path. Differs from Dafny in ordering, not outcome.
2. Raise the pre-lookup minimum from 44 to 60. Smallest change, but only covers 44–59.
3. No change. Document that the ordering matches Dafny and a full-length garbage EDK has the same cost.

Recommendation for (b): fold it into the BUG-02 fix (option 1 here). Otherwise option 3 is acceptable; this part on its own is not worth a dedicated change. Note: BUG-02 has since been fixed on `main` with a length check after the lookup, so option 1 would now be a separate change.

### Questions for engineers

1. Is a panic acceptable anywhere on the `DefaultCmm` encrypt path, or should all primitive failures surface as `MaterialsError` as in Dafny?
2. Are there other `.expect` calls on primitive `Result`s considered "cannot fail"? The verification analysis lists `default_cmm.rs:100` at `a1e23d7` (now `default_cmm.rs:123`, provably unreachable) and `cache_entry_identifier.rs:64`.
3. For (b), is matching Dafny's step order a goal, or is rejecting before I/O preferred when the outcome is the same?
4. If the BUG-02 exact-length check is adopted, should it run before the cache/keystore lookup (which would resolve this item) or inside `unwrap`?

## BUG-06: The hierarchical keyring cache-identifier preimage is not injective when fields contain NUL bytes

Full report: https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-06-cache-identifier-not-injective-with-nul.md

### Summary

`build_cache_identifier` joins the partition ID, logical key store name, branch key ID and version with single `0x00` separators and no length prefixes. If a field contains `0x00`, two different keyring configurations produce the same SHA-384 cache identifier, so they can read each other's branch key materials from a `Shared` cache. The code follows the layout the spec mandates.

| Attribute | Value |
|---|---|
| Severity | High (raised from Low on the owner's decision after the main re-check) |
| Confidence | Confirmed by test |
| Spec conflict | yes, but the conflict is inside the spec. The code matches the mandated layout exactly, and that layout breaks the spec's own statement that keyrings with different partition IDs "CANNOT share" cache entries. |
| Related IDs | VR-2026-T13 (primary), VR-2026-T19 (hierarchical branch key ID binding, for the supplier path); TM-MPL-009 (High), TM-MPL-010 (High), TM-MPL-003 (Low) |

Severity rationale: the severity is High. Severity raised Low -> High on the owner's decision after the main re-check. It describes the outcome when the preconditions hold. The preconditions are a `Shared` cache plus the ability to pick NUL-containing configuration values (partition ID, logical key store name, or branch key ID). Those values can come from a caller-supplied string or from a branch key ID supplier (TM-MPL-003). If they hold, the impact is cross-keyring use of branch key materials, which the main re-check confirmed end to end. A default configuration does not meet the preconditions. See "Severity decision" in the Status section.

### Status on main (620771c)

Still present. The test, adapted for API changes only, gives 2 passed. Both identifier collisions are `true` and the no-NUL control is `false`. End to end, with one shared `LocalCmc`, keyring B was served keystore A's branch key: keystore B was never called, and B's EDK unwraps with A's branch key but not with B's own. `cache_entry_identifier.rs` has no commits since `a1e23d7`. Re-checked 2026-11-10.

Severity decision: Severity raised Low -> High on the owner's decision after the main re-check. The finding, evidence, status and confidence are unchanged. The basis is the evidence only:

- The main re-check showed end to end that, with one shared `LocalCmc`, keyring B was served keystore A's branch key. Keystore B was never called, and B's EDK unwraps with A's branch key but not with B's own.
- The cache-identifier preimage is not injective when fields contain NUL. Both identifier collisions are `true` on `main` and the no-NUL control is `false`. The code follows the layout the spec mandates, so the conflict is inside the spec.
- The threat model rates TM-MPL-009 and TM-MPL-010 High (Severity High, Likelihood Medium). BUG-06 realizes both.

The preconditions are unchanged and are not met by a default configuration: a `Shared` cache, plus a NUL-containing partition ID, logical key store name or branch key ID, chosen to line up with the other keyring's fields. They can be reached through a caller-supplied value, or through a branch key ID supplier that returns such a value (TM-MPL-003). With BUG-02 fixed, this is the open finding with the most direct confidentiality impact.

### Location

Current code (`main` `620771c`): `mpl/src/aws_kms/cache_entry_identifier.rs:35-66` (`build_cache_identifier`; the file is unchanged, so the line numbers are the same). It is called at `mpl/src/aws_kms/hierarchical_keyring.rs:665` (OnEncrypt) and `:908` (OnDecrypt). Inputs are still not checked for NUL. The partition ID is the caller's string (`hierarchical_keyring.rs:596`) or the 16-byte form of a random v4 UUID (`:626`). The logical key store name is read from the key store and used as returned (`:600-605`). The branch key ID comes from configuration or a supplier. The version is a UUID string and cannot contain NUL.

```rust
42     let mut buf: Vec<u8> = vec![
43         RESOURCE_ID_HIERARCHICAL_KEYRING,
44         NULL_BYTE,
45         scope_id,
46         NULL_BYTE,
47     ];
49     buf.extend_from_slice(partition_id);
50     buf.push(NULL_BYTE);
52     buf.extend_from_slice(logical_key_store_name.as_bytes());
53     buf.push(NULL_BYTE);
55     buf.extend_from_slice(branch_key_id.as_bytes());
```

Originally reported at `a1e23d7`: the same `cache_entry_identifier.rs:35-66`; call sites `hierarchical_keyring.rs:306` and `:550`; partition ID at `:196` and `:269`.

### Expected vs actual behavior

Expected: `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md` requires the fields to be separated by a single `0x00` (the code follows this). The same document says keyrings with different user-set partition IDs "CANNOT share the same cache entries", and that users must set partition ID, logical key store name and branch key ID to be the same if and only if they want to share entries. The "CANNOT share" guarantee holds only when the fields contain no `0x00`, and the spec does not forbid NUL, so the two sections conflict.

Actual:

- Keyring A (partition `"tenant\0x"`, logical name `"L"`) and keyring B (partition `"tenant"`, logical name `"x\0L"`), both with branch key ID `"bk"`, produce the same preimage and the same cache identifier.
- The same shift works for any pair of adjacent fields.
- With a shared `LocalCmc`, A populates the cache from keystore A; B then gets a cache hit, never calls keystore B, and wraps its data key under A's branch key.

### Impact and preconditions

- Preconditions: the keyrings share one `Cmc` instance (`CacheType::Shared`, same process); at least one keyring's partition ID, logical key store name, or branch key ID contains `0x00` at a position that lines up with the other's fields; both use the same branch key ID suffix (or the equivalent shifted split).
- Realistic exploitability: low. Values come from application configuration, not message bytes. The realistic case is a multi-tenant application that builds partition IDs or logical names from tenant-supplied strings without rejecting NUL, or a branch key ID supplier returning attacker-influenced strings. This bullet describes how likely the preconditions are in practice. It is not the severity: the High severity is the outcome when they hold, and the threat model rates the likelihood of TM-MPL-009 and TM-MPL-010 Medium.
- If the preconditions hold: data encrypted for one tenant can be wrapped under a branch key another tenant controls (confidentiality), or a tenant can decrypt using cached materials it has no KMS access to.
- Default random partition IDs contain `0x00` with roughly 6% probability, but colliding with one is not practical.
- The Dafny MPL builds the same preimage with no NUL check in `GetActiveCacheId` / `GetVersionCacheId`. Whether the Dafny constructor validates these inputs was not checked.

### Evidence

Confidence: Confirmed by test. Re-check on `main`: reproducer `zz_bugrepro_06_cache_id_nul.rs`, adapted for API changes only (test internals now under `__test_internals::aws_kms`, the `KeyStore` trait shapes, builders, and `SharedCmc` in place of `CacheType::Shared`). It uses the same field values and the same end-to-end scenario, with a test `KeyStore`; the real `BranchKeyStore` path needs DynamoDB and KMS and was not run. Trimmed output (`recheck06.log`):

```text
REPRO BUG-06 encrypt-scope ids equal for (p="tenant\0x", n="L") vs (p="tenant", n="x\0L"): true
REPRO BUG-06 decrypt-scope ids equal for (n="L", bkid="bk\0x") vs (n="L\0bk", bkid="x"): true
REPRO BUG-06 control (no NUL, p="tenantx") equal to first: false
REPRO BUG-06 keystore A get_active calls = 1, keystore B get_active calls = 0
REPRO BUG-06 keyring B's EDK unwraps with keystore A's branch key: true; with keystore B's own branch key: false
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Fix options

1. Reject `0x00` in caller-supplied partition IDs and logical key store names in `HierarchicalKeyring::new`, and in resolved branch key IDs before building the identifier. The preimage stays byte-identical to the spec for all realistic configurations. Behavior change for anyone using NUL, and diverges from Dafny unless Dafny adds the same check.
2. Change the preimage to length-prefixed fields. Injective for all inputs, but needs a spec change and the same change in every runtime.
3. Documentation only: state that these fields MUST NOT contain `0x00` when a `Shared` cache is used. No code change, but the guarantee rests on user discipline.

Recommendation: option 1 for caller-supplied strings, plus a spec issue that either adds the NUL restriction (codifying option 1) or moves to option 2 across runtimes.

### Questions for engineers

1. Should the spec forbid NUL in partition IDs, logical key store names and branch key IDs, or move to a length-prefixed preimage?
2. Is it acceptable for the Rust MPL to reject NUL-containing values before the Dafny MPL and other runtimes do the same?
3. Do any known integrations derive partition IDs or logical names from tenant- or request-supplied strings, or run a branch key ID supplier that passes encryption-context values through unchanged?
4. Should the default 16-byte random partition ID be made NUL-free, or is the residual risk acceptable?

## BUG-07: `prim::aes_encrypt` leaves plaintext in the caller's buffer on `Err`; `prim::aes_decrypt`'s length guard is weaker than its callee's check

Full report: https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-07-prim-aes-buffer-handling.md

### Summary

(a) `aes_encrypt` appends the plaintext to the caller's output `Vec` before validating the key and IV. On any `Err`, the plaintext stays in that buffer. (b) `aes_decrypt` only rejects `plain_text.len() < cipher_text.len()`, but aws-lc-rs requires the lengths to be equal. A longer buffer gets past the guard and fails inside aws-lc-rs with an opaque `Unspecified` error.

| Attribute | Value |
|---|---|
| Severity | Low |
| Confidence | Confirmed by test |
| Spec conflict | no |
| Related IDs | (a) VR-2026-T26, VR-2026-T07 (property (e)); TM-MPL-015 (Low). (b) VR-2026-C03; TM-MPL-023 (Low). TM-MPL-011 (Medium) stays listed through T07 |

Severity rationale: (a) is a secret-hygiene issue in a crate-level API. Every in-repo caller validates key and IV lengths first and drops the buffer on `Err`, so no path was found where the residue is returned or written out. (b) fails closed; the only effect is a less useful error message.

### Status on main (620771c)

Still present (both a and b). The original test compiled and ran unchanged (2 passed). After `Err`, the buffer still holds `"HDR:SECRET-PLAINTEXT"`, and buffers of ct + 1 and ct + 16 bytes still pass the guard. Only the error text changed. A longer decrypt buffer is now reported as `authentication tag did not match`, which is more misleading than the old `gather Unspecified`, because the tag is fine and the problem is the buffer length. Re-checked 2026-11-10.

### Location

Current code (`main` `620771c`):

- `prim/src/lib.rs:175-197` (`aes_encrypt`): the plaintext is appended at line 185, before key and nonce construction at lines 187-189.
- `prim/src/lib.rs:215` (`aes_decrypt` guard). Every callee error maps to `authentication tag did not match` at line 229.
- Callee: aws-lc-rs, now 1.18.1 in all three lock files (`prim/`, `mpl/`, `esdk/`). The callee source was not re-read at 1.18.1, but the re-check shows it still rejects a longer buffer.
- In-repo callers of `aes_encrypt`: `mpl/src/keyring/raw_aes_keyring.rs:163`, `mpl/src/aws_kms/branch_key_wrap.rs:199`, `esdk/src/message/body/body_encrypt.rs:244`, `esdk/src/encrypt.rs:776`.

```rust
184     let old_size = cipher_text.len();
185     cipher_text.extend_from_slice(message);
186     let cipher_slice = &mut cipher_text[old_size..];
187     let key = UnboundKey::new(alg, key).map_err(|_| serr("invalid AES-GCM key".to_owned()))?;
188     let nonce = Nonce::try_assume_unique_for_key(iv)
189         .map_err(|_| serr("invalid AES-GCM nonce".to_owned()))?;
...
215     if plain_text.len() < cipher_text.len() {
```

Originally reported at `a1e23d7`: `prim/src/lib.rs:197-218` (append at `:207`) and `:236` (guard); aws-lc-rs 1.17.1 `src/aead/unbound_key.rs:140`; callers at `raw_aes_keyring.rs:225`, `branch_key_wrap.rs:192`, `body_encrypt.rs:239`, `encrypt.rs:715`.

### Expected vs actual behavior

Expected: no spec requirement; this is robustness and defense-in-depth. The `aes_encrypt` rustdoc describes only the success state of the buffer. The `aes_decrypt` rustdoc lists "shorter than" as an error, which matches the guard but not the effective contract (lengths must be equal).

Actual:

- (a) With `cipher_text = b"HDR:"` and a 5-byte key for AES-256-GCM, `aes_encrypt` returns `Err` and the buffer holds `"HDR:SECRET-PLAINTEXT"`. The same happens with an 11-byte IV. A seal failure would also leave the plaintext.
- (b) A `plain_text` buffer 1 or 16 bytes longer than the ciphertext passes the guard and fails with `"gather Unspecified"` at `a1e23d7`, the same text as an authentication failure. On `main` it fails with `authentication tag did not match`. A buffer 1 byte shorter gets the descriptive guard message.

### Impact and preconditions

- (a) Matters only if a caller keeps or exposes the buffer after `Err`. By code reading, the MPL callers drop their local buffer and pass pre-validated key and IV lengths, so the `Err` path is practically unreachable for them. The ESDK frame path drops `frame_buf` on `Err`. Residual concern: a plaintext data key copy in a dropped `Vec` is not wiped, while `PlaintextDataKey` offers `zeroize()` (`mpl/src/structures/algorithm_suite.rs:434` at `a1e23d7`); that is a memory-hygiene gap, not a disclosure path. On current code the manual `zeroize` loop is gone: `PlaintextDataKey` derives `Zeroize` and `ZeroizeOnDrop` (`algorithm_suite.rs:505`), and un-wiped transient copies of this kind are tracked by VR-2026-T26 under TM-MPL-015. An external caller of `aws-mpl-primitives` that reuses or logs the buffer would expose plaintext; the crate describes itself as "Not intended for public consumption".
- (b) No security impact. In-repo callers size the buffer exactly (`raw_aes_keyring.rs:309`, `branch_key_wrap.rs:267` at `a1e23d7`; now `raw_aes_keyring.rs:471` and `branch_key_wrap.rs:275`, each `vec![0u8; encrypted_key.len()]`). A mis-sized buffer produces an error that looks like an authentication failure.
- The Dafny primitives return fresh output values, so this class of issue does not arise there (judged by API shape only).

### Evidence

Confidence: Confirmed by test. Reproducer `zz_bugrepro_07_aes_buffers.rs`, run unchanged on `main` (the `prim` API did not change). Trimmed output (`recheck07.log`):

```text
REPRO BUG-07a bad key: is_err=true err=Some("Cryptographic(CryptographicError { message: \"invalid AES-GCM key\" })")
REPRO BUG-07a buffer after Err = "HDR:SECRET-PLAINTEXT"
REPRO BUG-07a bad iv: is_err=true buffer after Err = "SECRET-PLAINTEXT"
REPRO BUG-07b plain_text len = ct len + 0: Ok(())
REPRO BUG-07b plain_text len = ct len + 1: Err("Cryptographic(CryptographicError { message: \"authentication tag did not match\" })")
REPRO BUG-07b plain_text len = ct len + 16: Err("Cryptographic(CryptographicError { message: \"authentication tag did not match\" })")
REPRO BUG-07b plain_text len = ct len - 1: Err("... plaintext buffer of 15 bytes is shorter than the 16 byte ciphertext")
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Fix options

(a) `aes_encrypt`:

1. Build `UnboundKey` and `Nonce` before extending the buffer; if sealing fails, zero the appended region and `truncate(old_size)`. The buffer is unchanged on every `Err`; negligible cost; needs careful review because every encrypt path uses it.
2. Encrypt into a separate scratch `Vec` and append only on success. Simple, but adds an allocation and copy on every call, including every ESDK frame.
3. Document that buffer contents are unspecified on `Err` and keep the T07 (e) obligation on callers.

(b) `aes_decrypt`:

1. Change the guard to `plain_text.len() != cipher_text.len()` with a descriptive message, and update the rustdoc. No change in which inputs succeed.
2. Keep the guard and document that the lengths must be equal.

Recommendation: (a) option 1 and (b) option 1. Neither changes the observable success behavior of any in-repo caller.

### Questions for engineers

1. Is `aws-mpl-primitives` internal-only (so a documented caller obligation is enough), or should its functions keep the caller's buffer unchanged on error?
2. Should plaintext copies left in prim scratch buffers be wiped (for example with `zeroize`), consistent with the zeroize-on-drop that `PlaintextDataKey` now has (`algorithm_suite.rs:505`)?
3. Is anything relying on `aes_decrypt` accepting an oversized buffer with the result then failing in aws-lc-rs? Nothing was found in-repo.

## BUG-08: The custom encryption context "collision" error in `build_base` is dead code

Full report: https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-08-build-base-collision-branch-unreachable.md

### Summary

`keystore::encryption_context::build_base` returns `Err` when inserting a prefixed custom encryption context key would overwrite an existing entry. Given how the map is built, that insert can never find an existing key, so the error branch is unreachable and the comment describing when it fires is inaccurate. This is a code-quality finding, not a behavioral defect.

| Attribute | Value |
|---|---|
| Severity | Informational |
| Confidence | Confirmed by code reading |
| Spec conflict | no |
| Related IDs | VR-2026-C01 (property (c)); cap:cat1 (1c); TM-MPL-005 (High). The threat model records BUG-08 as informational, with no effect on the TM-MPL-005 rating |

Severity rationale: behavior is correct for all inputs. The cost is a misleading comment and an untestable branch, which also makes the C01 round-trip proof slightly harder to state.

### Status on main (620771c)

Still present. By code reading, and with the test adapted for API changes only (1 passed): 10 custom entries go in and 10 prefixed entries come out, with no `Err`. The file moved from `keystore/` to `key_store/` in `e9bde48` (#98). The logic is unchanged. Re-checked 2026-11-10.

### Location

Current code (`main` `620771c`): `build_base` (`mpl/src/key_store/encryption_context.rs:40`), custom-EC loop `:86-104`, dead `Err` `:95-101`. The six base keys are inserted at `:60-79` (constants in `mpl/src/key_store/attributes.rs:11-17`), and none starts with `aws-crypto-ec:` (`attributes.rs:24`). The custom EC is now a `BTreeMap<String, String>` (`mpl/src/structures/encryption_context.rs:16`), so its keys are distinct.

```rust
89             // A custom key that already carries the prefix, or a duplicate
90             // after prefixing, would otherwise overwrite a previous entry.
91             if ec
92                 .insert(format!("{CUSTOM_EC_PREFIX}{key_str}"), val_str.to_string())
93                 .is_some()
94             {
95                 return Err(Error::new(
96                     Kind::Validation,
```

Originally reported at `a1e23d7`: `mpl/src/keystore/encryption_context.rs:109-122`.

### Expected vs actual behavior

Expected: `spec/framework/branch-key-store.md#custom-encryption-context` requires each custom attribute to be prefixed with `aws-crypto-ec:`. The code meets this. Nothing in the spec requires the collision error.

Actual (why the insert can never return `Some`). This is the original argument at `a1e23d7`, and its line numbers refer to that commit, where the insert was at line 112 (now line 92). The Location section gives the same argument for current code.

1. Before the loop, `ec` holds exactly six base keys (lines 59-78), none starting with `aws-crypto-ec:`.
2. The custom EC was a `BTreeMap<Vec<u8>, Vec<u8>>`, so its keys are distinct. On `main` it is a `BTreeMap<String, String>`, which gives the same result.
3. Strict UTF-8 decoding (lines 93-98) and prepending a fixed prefix are both injective, so distinct custom keys give distinct prefixed keys. On `main` the keys are already strings, so only the prefix step remains.
4. The comment's example, an already-prefixed key such as `aws-crypto-ec:a`, becomes `aws-crypto-ec:aws-crypto-ec:a`, which does not collide with the prefixed form of `a`.
5. Later inserts in `active_encryption_context` (lines 145-149) use unprefixed names.

### Impact and preconditions

None on behavior. Every accepted custom EC is copied without loss. The comment points readers to a failure mode that does not exist, the branch cannot be covered by tests, and a proof of C01 (c) has to establish the unreachability argument. The test `distinct_non_utf8_custom_ec_keys_do_not_collapse` (`mpl/tests/test_keystore_encryption_context.rs:234` at `a1e23d7`) showed why the strict UTF-8 check matters. It no longer exists on current code, because the custom EC is a `BTreeMap<String, String>` and the byte-level case cannot occur. The test file is now `mpl/tests/test_key_store_encryption_context.rs`, which covers the prefixing (`custom_ec_keys_are_prefixed_with_aws_crypto_ec`, `:127`) but has no test for the collision `Err`.

### Evidence

Confidence: Confirmed by code reading. Re-check on `main`: reproducer `zz_bugrepro_08_build_base_dead_branch.rs`, adapted for API changes only (new module path; `insert` takes strings). It feeds in the inputs the comment names plus every base and reserved attribute name, and shows all are accepted with no entry lost. A test cannot prove unreachability for all inputs; that rests on the code reading. Trimmed output (`recheck08.log`), identical to `a1e23d7`:

```text
REPRO BUG-08 active is_ok = true, decrypt_only is_ok = true
REPRO BUG-08 10 custom entries in, 10 prefixed entries out: ["aws-crypto-ec:a", "aws-crypto-ec:aws-crypto-ec:a", "aws-crypto-ec:branch-key-id", ...]
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Formal check (C01)
A Verus proof of a model of `build_base` and the reconstruction exists: `verus-proofs/c01_ec_roundtrip.rs`. Status: Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors. It is a proof of a re-typed model, not of the shipped code.

- `theorem_bug08_collision_iff_duplicate`: for a non-empty id and type, `build_base` returns `Err(Collision)` if and only if the key sequence from `custom.iter()` repeats a key.
- `theorem_bug08_collision_unreachable`: if no key repeats (hypothesis A_ITER), `Collision` is not returned.
- `lemma_bug08_collision_live_under_duplicates`: if a key repeats, the branch is reachable in the model. So "dead" is a conclusion that depends on A_ITER, not an artifact of the model.
- `lemma_bug08_prefixed_custom_key_ok`: a custom key that already carries `aws-crypto-ec:` is stored as `aws-crypto-ec:aws-crypto-ec:x` and round-trips; it is not a collision.

Result: the branch is dead if and only if A_ITER holds (`custom.iter()` yields each key once), and live if a key repeats. A_ITER holds for `BTreeMap`, and `EncryptionContext` is a newtype over `BTreeMap<String, String>`, but Verus cannot check it. This note does not change this bug's severity, status, confidence or evidence. Fix option 3 below refers to this proof. At model level it exists, but it does not discharge the branch in the shipped code, because the shipped code is not inside the proof.

### Fix options

1. Keep the check as defense-in-depth and fix the comment to say the branch is unreachable by construction and guards against future changes. No behavior change; the branch stays untestable.
2. Replace the runtime `Err` with `debug_assert!(prev.is_none(), ...)` and a corrected comment. No dead error path, but release builds would silently overwrite if a future change made a collision possible.
3. Leave the code and discharge the branch with the Verus C01 (c) proof. Machine-checked, but the misleading comment stays unless edited.

Recommendation: option 1 (comment fix only). If the C01 proof is pursued, option 3 can follow without further code change.

### Questions for engineers

1. Was the branch meant to guard against a specific input not considered here, such as keys from a stored record, which the input's doc comment says take a different path?
2. Do you prefer to keep an unreachable runtime check as defense-in-depth, or replace it with a debug assertion?
3. Should the base attribute names be asserted (at compile time or in a test) never to start with `aws-crypto-ec:`?

## Resolved on main

These three findings are fixed on `main` `620771c`, all in commit `e9bde48` "feat(esdk): retarget the ESDK and C++ shim onto the native Rust MPL (#98)". The re-check on 2026-11-10 ran each reproducer, adapted for API changes only, and the printed observations show the fixed behavior. The full original analysis is kept as history in each report (links in Appendix B).

| ID | Original finding (at `a1e23d7`) | Re-check evidence on `main` | Where the fix lives (`main` `620771c`) |
|---|---|---|---|
| BUG-02 | Plaintext data key length not enforced in hierarchical OnDecrypt (C04-F1) or in the materials constructors (C04-F2). Severity Medium. | F1: `on_decrypt` now returns `Err: InvalidMaterials: plaintext data key is N bytes, expected 32` for N = 5, 0 and 64. F2: both materials builders return that `Err`, so the test fails at its own `unwrap()`. | `check_data_key_length`, `mpl/src/structures/algorithm_suite.rs:547`, called from the builders (`encryption_materials.rs:365`, `decryption_materials.rs:303`) and `add_data_key` (`encryption_materials.rs:60`, `decryption_materials.rs:56`). The hierarchical OnDecrypt calls `add_data_key` at `mpl/src/aws_kms/hierarchical_keyring.rs:767`. |
| BUG-03 | `EncryptionContext::deserialize` accepted entries not sorted by key. Severity Low. | `from_bytes(unsorted)` returns `Err(Validation: encryption context keys are not in ascending order)`. A non-UTF-8 key is now also rejected. | `EncryptionContext::from_bytes` (renamed from `deserialize`), `mpl/src/structures/encryption_context.rs:145`; duplicate check `:199`, order check `:205-210`, UTF-8 check `:230`. |
| BUG-09 | `cache_entry_within_limits` admitted entries up to `ttl + 1 s` old (whole-second truncation). Severity Informational, likely not a bug. | With ttl = 1 s, entries aged 1500 ms and 1950 ms are now treated as expired (were used). In the shared-cache case at about 1.5 s, the keystore is called again. | `cache_entry_within_limits`, `mpl/src/aws_kms/hierarchical_keyring.rs:989-995`, now `elapsed <= ttl` on full `Duration`s. Regression test `on_encrypt_ttl_compares_the_full_duration`, `mpl/tests/test_aws_kms_hierarchical_keyring.rs:1547`. |

Originally reported locations at `a1e23d7`: BUG-02 `hierarchical_keyring.rs:414-423`, `encryption_materials.rs:30-89`, `decryption_materials.rs:28-81`; BUG-03 `mpl/src/structures/encryption_context.rs:109`; BUG-09 `hierarchical_keyring.rs:620-626`.

Questions that may still be relevant:

1. BUG-02: the ESDK V1 HKDF path (`esdk/src/key_derivation.rs`) had only a `debug_assert_eq!` length guard at `a1e23d7`, and it was not re-checked on `main`. Is an ESDK-side check still wanted as defense-in-depth?
2. BUG-02: the hierarchical keyring now rejects a wrong-length key after the AES-GCM open, while the Dafny MPL rejects a wrong-length EDK before it. Should an exact-length pre-check be added? This affects ordering and error text only.
3. BUG-03: how do the Dafny MPL / ESDK and other runtimes treat an unsorted or non-UTF-8 EC on read? This was not checked. The answer shows whether the strict decoder removes a cross-runtime difference or creates one.
4. BUG-09: Rust now refreshes slightly earlier than Dafny, which compares whole-second timestamps. Should the spec state the time resolution?

## Appendix A: Reproducers

The full reproducer sources are kept on GitHub rather than reproduced here. Each was a temporary, untracked test, copied into the tree for the run and removed afterwards. The original reproducers were written against commit `a1e23d7` (logs under `.agents/tasks/bug-reports/logs/`). For the re-check on `main` `620771c`, every reproducer except BUG-07 was adapted for API changes only, keeping the same inputs and observations (logs under `.agents/tasks/bug-recheck/logs/`). BUG-05 (a) and the code-reading half of BUG-08 have no runnable reproducer.

- Original reproducers: https://github.com/aws/aws-crypto-tools-rust/tree/MPL-Verus/.agents/tasks/bug-reports/reproducers
- Adapted reproducers: https://github.com/aws/aws-crypto-tools-rust/tree/MPL-Verus/.agents/tasks/bug-recheck/reproducers

| ID | Original (`a1e23d7` API) | Adapted for `main` (API only) | How it was run |
|---|---|---|---|
| BUG-01 | [zz_bugrepro_01_ttl_overflow.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-reports/reproducers/zz_bugrepro_01_ttl_overflow.rs) | [zz_bugrepro_01_ttl_overflow.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-recheck/reproducers/zz_bugrepro_01_ttl_overflow.rs) | `cd mpl && cargo test --test zz_bugrepro_01_ttl_overflow -- --nocapture` |
| BUG-02 | [zz_bugrepro_02_pdk_length.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-reports/reproducers/zz_bugrepro_02_pdk_length.rs) | [zz_bugrepro_02_pdk_length.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-recheck/reproducers/zz_bugrepro_02_pdk_length.rs) | `cd mpl && cargo test --test zz_bugrepro_02_pdk_length -- --nocapture` |
| BUG-03 | [zz_bugrepro_03_ec_unsorted.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-reports/reproducers/zz_bugrepro_03_ec_unsorted.rs) | [zz_bugrepro_03_ec_unsorted.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-recheck/reproducers/zz_bugrepro_03_ec_unsorted.rs) | `cd mpl && cargo test --test zz_bugrepro_03_ec_unsorted -- --nocapture` |
| BUG-04 | [zz_bugrepro_04_mrdiscovery_non_mrk.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-reports/reproducers/zz_bugrepro_04_mrdiscovery_non_mrk.rs) | [zz_bugrepro_04_mrdiscovery_non_mrk.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-recheck/reproducers/zz_bugrepro_04_mrdiscovery_non_mrk.rs) | In-crate unit test in a throwaway copy of the crate under `/tmp`: `cargo test --lib zz_bugrepro_04 -- --nocapture` |
| BUG-05 | [zz_bugrepro_05_short_edk_lookup.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-reports/reproducers/zz_bugrepro_05_short_edk_lookup.rs) | [zz_bugrepro_05_short_edk_lookup.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-recheck/reproducers/zz_bugrepro_05_short_edk_lookup.rs) | `cd mpl && cargo test --test zz_bugrepro_05_short_edk_lookup -- --nocapture` (part (b) only) |
| BUG-06 | [zz_bugrepro_06_cache_id_nul.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-reports/reproducers/zz_bugrepro_06_cache_id_nul.rs) | [zz_bugrepro_06_cache_id_nul.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-recheck/reproducers/zz_bugrepro_06_cache_id_nul.rs) | `cd mpl && cargo test --test zz_bugrepro_06_cache_id_nul -- --nocapture` |
| BUG-07 | [zz_bugrepro_07_aes_buffers.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-reports/reproducers/zz_bugrepro_07_aes_buffers.rs) | Not needed; the original ran unchanged | `cd prim && cargo test --test zz_bugrepro_07_aes_buffers -- --nocapture` |
| BUG-08 | [zz_bugrepro_08_build_base_dead_branch.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-reports/reproducers/zz_bugrepro_08_build_base_dead_branch.rs) | [zz_bugrepro_08_build_base_dead_branch.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-recheck/reproducers/zz_bugrepro_08_build_base_dead_branch.rs) | `cd mpl && cargo test --test zz_bugrepro_08_build_base_dead_branch -- --nocapture` |
| BUG-09 | [zz_bugrepro_09_ttl_truncation.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-reports/reproducers/zz_bugrepro_09_ttl_truncation.rs) | [zz_bugrepro_09_ttl_truncation.rs](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/.agents/tasks/bug-recheck/reproducers/zz_bugrepro_09_ttl_truncation.rs) | `cd mpl && cargo test --test zz_bugrepro_09_ttl_truncation -- --nocapture` |

## Appendix B: Full reports

| ID | Report |
|---|---|
| Index | [README.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/README.md) |
| Re-check | [RECHECK-main-620771c.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/RECHECK-main-620771c.md) |
| BUG-01 | [BUG-01-ttl-duration-overflow-panic.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-01-ttl-duration-overflow-panic.md) |
| BUG-02 | [BUG-02-plaintext-data-key-length-not-enforced.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-02-plaintext-data-key-length-not-enforced.md) |
| BUG-03 | [BUG-03-encryption-context-deserialize-accepts-unsorted.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-03-encryption-context-deserialize-accepts-unsorted.md) |
| BUG-04 | [BUG-04-mrdiscovery-rewrites-non-mrk-arn-region.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-04-mrdiscovery-rewrites-non-mrk-arn-region.md) |
| BUG-05 | [BUG-05-keygen-expect-and-short-edk-keystore-lookup.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-05-keygen-expect-and-short-edk-keystore-lookup.md) |
| BUG-06 | [BUG-06-cache-identifier-not-injective-with-nul.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-06-cache-identifier-not-injective-with-nul.md) |
| BUG-07 | [BUG-07-prim-aes-buffer-handling.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-07-prim-aes-buffer-handling.md) |
| BUG-08 | [BUG-08-build-base-collision-branch-unreachable.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-08-build-base-collision-branch-unreachable.md) |
| BUG-09 | [BUG-09-cache-ttl-check-whole-second-truncation.md](https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/BUG-09-cache-ttl-check-whole-second-truncation.md) |

## Appendix C: Editor's notes

- Severity, confidence and spec conflict agree between the README index and every individual report. The re-check changed no value. The only later change is BUG-06: Severity raised Low -> High on the owner's decision after the main re-check, shown as High in the summary table, the cross-reference table, the agenda and the BUG-06 section. No other severity changed. The discussion priority was revised after the re-check, as explained under Summary, and the BUG-06 label now reads "1 – High". The README and this document use the same order.
- Status on main agrees with `docs/bug-reports/RECHECK-main-620771c.md` (including its addendum for HEAD `9955ecd`) for every bug.
- Threat and target references (Related IDs, the cross-reference table) agree with `docs/threat-model.md` (TM-MPL-001..026), `docs/verification-targets.md` (T27 added; T08 and C06 retired) and `docs/completeness-audit.md` section 3b, and the ratings agree with the threat model's risk matrix. Where a report also lists a threat that section 3b omits (TM-MPL-017 for BUG-03, TM-MPL-022 for BUG-01, TM-MPL-011 for BUG-07), the extra ID comes from the target's own threat references.
- Confidence: the README uses short labels. For BUG-04, BUG-05 and BUG-09 the individual reports add qualifiers (BUG-04: the end-to-end KMS failure is inferred and needs AWS; BUG-05 (b): matches Dafny and adds no amplification; BUG-09: matches Dafny's whole-second granularity). The per-bug sections use the individual report's wording; the summary table keeps the README's short form. The labels themselves do not conflict.
- Titles: the summary table uses the README's shorter titles; the section headings use the individual reports' titles. For BUG-05, the README says the short EDK "reaches the keystore" and the report adds "before rejection". The meaning is the same.
- Code excerpts and test output were trimmed for readability. Elided lines are marked with `...`. In the BUG-04 output, the key UUIDs were shortened to `1234abcd-...`. The full output is in each linked report and in the re-check logs.
- Revisions: `a1e23d7` is not an ancestor of `main` `620771c`; it is an ancestor of `MPL-Verus` `c256243`, the merge of `main` into `MPL-Verus`. `git diff 620771c c256243 -- mpl prim esdk` is empty, so the code re-checked on `MPL-Verus` is the code on `main`. `main` has since moved to `5f2dc72` with esdk-only commits #188 and #189; `git diff --stat 620771c 5f2dc72 -- mpl prim` is empty.
