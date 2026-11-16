# BUG-01: Large accepted TTL / grace / inflight values overflow `SystemTime + Duration` and panic

Summary: `HierarchicalKeyring` and `StormTrackingCmc` accept arbitrarily large time values at construction, then add them to `SystemTime::now()` with the panicking `+` operator, so a valid-looking configuration such as `ttl_seconds = u64::MAX` panics on first use instead of returning an error.

- Confidence: Confirmed by test
- Spec conflict: no
- Severity: Low. The trigger is configuration only (trusted application code), and the threshold on Unix is roughly 9.2 × 10^18 s. Still, a "never expire" sentinel such as `u64::MAX` is a plausible thing for an application to pass, and the result is a panic, not an error.
- Related IDs: VR-2026-T06 (primary), VR-2026-T21 (property (i), panic under the state lock, for BUG-01 b and c); TM-MPL-018 (Medium), TM-MPL-022 (Low), TM-MPL-023 (Low). Ratings are from `docs/threat-model.md` (HEAD 9955ecd); targets are from `docs/verification-targets.md`.
- Completeness audit mapping (`docs/completeness-audit.md` section 3b): BUG-01 -> TM-MPL-018, 023 -> T06.
- Last cross-checked: HEAD 9955ecd (code == main 620771c for mpl/ and prim/)

## Status on main (620771c)

- Status: Still present.
- Re-checked: 2026-11-10, against `c256243` on `MPL-Verus` (code identical to `main` `620771c`). Details: [RECHECK-main-620771c.md](RECHECK-main-620771c.md), section BUG-01.
- Evidence: the reproducer, adapted for API changes only, gives 5 passed / 0 failed, and all four calls panic with `overflow when adding duration to instant` (`.agents/tasks/bug-recheck/logs/recheck01.log`).
- The TTL is now a `Duration` set through `HierarchicalKeyring::builder().ttl(..)`, but the unchecked additions and the missing upper bound are unchanged. No commit since `a1e23d7` adds an overflow check.

Line numbers outside the Status and Location sections refer to `a1e23d7`, where the bug was first found, and are kept as history.

## Location

Current code (`main` `620771c`):

`mpl/src/aws_kms/hierarchical_keyring.rs:702` (OnEncrypt cache put) and `:945` (OnDecrypt cache put), same code at both sites:

```rust
698                 let now = SystemTime::now();
699                 let entry = CacheEntry::builder()
700                     .materials(CachedMaterials::BranchKey(bkm.clone()))
701                     .creation_time(now)
702                     .expiry_time(now + self.inner.ttl)
703                     .build()?;
```

`HierarchicalKeyringBuilder::build` (`hierarchical_keyring.rs:535`) only rejects a zero TTL (`:547`).

`mpl/src/cmc/storm_tracking.rs:333` (per-waiter deadline) and `:680` (`within_grace_interval`):

```rust
332                             Ok(GetDecision::Wait {
333                                 deadline: Some(now + self.inner.in_flight_ttl),
334                             })
...
675 pub(crate) fn within_grace_interval(
676     inflight: SystemTime,
677     now: SystemTime,
678     grace_interval: Duration,
679 ) -> bool {
680     now < inflight + grace_interval
681 }
```

`StormTrackingCmcBuilder::build` (`storm_tracking.rs:606-626`) rejects only zero `fan_out`, `in_flight_ttl` and `sleep`, and `grace_interval > in_flight_ttl`. There is no upper bound.

Originally reported at `a1e23d7`: `hierarchical_keyring.rs:342`, `:585` (validation in `HierarchicalKeyring::new`, `:150`); `storm_tracking.rs:446`, `:536` (validation in `ValidatedConfig::from_raw`, `:108-143`).

## Expected behavior

There's no spec requirement here; this is a robustness / defense-in-depth issue. The spec sets a lower bound and no upper bound:

- `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl`: "This value MUST be greater than zero."
- `spec/framework/storm-tracking-cryptographic-materials-cache.md#consistency` constrains only the relative order of grace interval, inflight TTL and grace period.

For reference, the Dafny MPL guards the same addition and returns an error instead of overflowing (`AwsKmsHierarchicalKeyring.dfy`, both put paths): `:- Need((now as int + ttlSeconds as int) < UInt.INT64_MAX_LIMIT, ... "INT64 Overflow when putting cache entry.")` ([source](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy), main branch, read while writing this report). I did not check the Dafny storm-tracking cache.

## Actual behavior

Hierarchical keyring:

1. `HierarchicalKeyring::new(.., ttl_seconds = u64::MAX, ..)` returns `Ok`.
2. The first `on_encrypt` (or `on_decrypt`) misses the cache, fetches the branch key, then evaluates `now + Duration::from_secs(u64::MAX)` at line 342 (or 585).
3. `impl Add<Duration> for SystemTime` panics with `overflow when adding duration to instant`.

Storm-tracking cache, `grace_interval` large (BUG-01b):

1. `StormTrackingCmc::new(.., grace_period = u64::MAX, grace_interval = u64::MAX, .., inflight_ttl = u64::MAX, ..)` passes every check and returns `Ok`.
2. The first `get_cache_entry(k)` misses and marks `k` inflight.
3. The second `get_cache_entry(k)` misses, finds `k` inflight, and calls `within_grace_interval`, which panics at line 536.

Storm-tracking cache, `inflight_ttl` large (BUG-01c):

1. Same as above, but with `grace_interval = 1`.
2. The second `get_cache_entry(k)` is within the grace interval, so it computes the waiter deadline `now + self.inflight_ttl` at line 446 and panics.

The same constructor path is reachable through `HierarchicalKeyring::new(.., cache_type = CacheType::StormTracking(..))`. The keyring only checks `grace_period < ttl_seconds`, so a large TTL lets an equally large grace period through.

## Impact

- Precondition: the application configures a TTL, grace interval or inflight TTL larger than about `i64::MAX − now` seconds on Unix-like targets. The log shows that `now + 1e15 s` succeeds and `now + i64::MAX s` fails.
- Effect: a panic on an encrypt/decrypt path. Under Tokio this kills the task, and the caller gets a `JoinError`. With `panic = "abort"`, or across an FFI boundary such as the C++ shim, it takes down the process. No `catch_unwind` exists in `mpl/src`, `esdk/src` or `esdk/shims` (searched).
- Remote exploitability: none. Message data can't influence these values.
- Platform note (expected from Rust's `SystemTime` representation on Windows, but not tested): the Windows limit is much lower, around 1.8 × 10^12 s from 1601. A value like `1e13` that works on Linux would panic there.

## Reproduction / evidence

Re-check on `main` `620771c` (2026-11-10). The original reproducer no longer compiles against the current public API (6 compile errors, kept at the top of the log). It was adapted for API changes only: builders instead of positional constructors, `Duration::from_secs(u64::MAX)` instead of `ttl_seconds = u64::MAX`, the `KeyStore` trait with `*Input` / `*Output` shapes, and `SharedKeyring` fluent calls. The inputs are the same: a TTL of `u64::MAX` seconds; storm tracking (grace period, grace interval, inflight TTL) = (MAX, MAX, MAX) and (MAX, 1, MAX); fan-out 1; sleep 1 ms. The pass condition (each call must panic) is unchanged.

- Adapted reproducer: [`zz_bugrepro_01_ttl_overflow.rs`](../../.agents/tasks/bug-recheck/reproducers/zz_bugrepro_01_ttl_overflow.rs) (173 lines, not inlined here).
- Original reproducer (`a1e23d7` API): `.agents/tasks/bug-reports/reproducers/zz_bugrepro_01_ttl_overflow.rs`.
- Command: `cd mpl && cargo test --test zz_bugrepro_01_ttl_overflow -- --nocapture`. The test was copied into `mpl/tests/` for the run and deleted afterwards.

Observed output on `main` (`.agents/tasks/bug-recheck/logs/recheck01.log`, macOS; thread lines trimmed):

```text
running 5 tests
REPRO BUG-01 now+u64::MAX s checked_add = None
REPRO BUG-01 now+i64::MAX s checked_add = None
REPRO BUG-01 now+1e15 s checked_add is_some = true
test std_systemtime_add_limits ... ok
REPRO BUG-01c StormTrackingCmc::new(inflight_ttl = u64::MAX s) is_ok = true
REPRO BUG-01b StormTrackingCmc::new(grace_interval = u64::MAX s) is_ok = true
REPRO BUG-01a HierarchicalKeyring::new(ttl_seconds = u64::MAX) is_ok = true
REPRO BUG-01b first get (miss, marks inflight) = Ok(false)
thread 'storm_tracking_huge_inflight_ttl_accepted_then_waiter_deadline_panics' (6397751) panicked at /rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/time.rs:746:31:
overflow when adding duration to instant
...
REPRO BUG-01c second get PANICKED: overflow when adding duration to instant
REPRO BUG-01b second get PANICKED: overflow when adding duration to instant
...
REPRO BUG-01a on_encrypt PANICKED: overflow when adding duration to instant
REPRO BUG-01d on_decrypt PANICKED: overflow when adding duration to instant
...
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

The adapted test keeps the original print labels (for example `HierarchicalKeyring::new(ttl_seconds = u64::MAX)`), although the call it now makes is the builder. The output matches the original run at `a1e23d7` (`.agents/tasks/bug-reports/logs/bugrepro01.log`).

## Fix options

These options were written against `a1e23d7`. On `main`, the four use sites are `hierarchical_keyring.rs:702`, `:945` and `storm_tracking.rs:333`, `:680`. The constructor checks named in option 2 are now `HierarchicalKeyringBuilder::build` (`hierarchical_keyring.rs:535`) and `StormTrackingCmcBuilder::build` (`storm_tracking.rs:606`). The error type is now `aws_crypto_mpl::Error` instead of `MaterialsError` / `CmcError`.

1. Checked addition at each use site, returning an error.
   - Hierarchical keyring: `now.checked_add(..).ok_or_else(|| MaterialsError::keyring_failed("... TTL overflow ..."))`. This matches the Dafny MPL's "INT64 Overflow when putting cache entry" failure.
   - Storm tracking: `CmcError`.
   - Trade-off: these configs change from "panics" to "returns an error on every call". That's still unusable, but it no longer crashes. Cost is negligible.
2. Reject at construction. Add an upper bound in `HierarchicalKeyring::new` and `ValidatedConfig::from_raw`, for example a fixed maximum such as 100 years or `i64::MAX` seconds minus a margin.
   - Trade-off: the failure moves to construction time, which is the best UX. But it adds a limit the spec doesn't state. Picking a constant means coordinating with the other runtimes. The Dafny check is time-relative (`now + ttl < INT64_MAX`), not a fixed cap. A fixed cap also doesn't fully remove the per-call addition unless it's chosen below the platform limit (see the Windows note).
3. Saturate: treat overflow as "never expires".
   - `checked_add(..)` with a far-future fallback. `within_grace_interval` returns `true` on overflow. The waiter deadline becomes `None` on overflow.
   - Trade-off: no error at all, and it arguably matches what a user passing `u64::MAX` means. But it silently changes semantics, diverges from Dafny's fail-closed behavior, and `deadline: None` disables the per-waiter InFlightTTL check.

Recommendation: option 1 at all four sites, because it matches the Dafny reference and keeps behavior fail-closed. Option 2 can be added later if the team wants a construction-time error.

## Questions for the engineers

1. Should the native Rust library match the Dafny error ("INT64 Overflow when putting cache entry") per call, or fail early in the constructors?
2. If a constructor bound is preferred, what maximum TTL / grace values should be agreed across runtimes, and should the limit account for Windows `SystemTime` range?
3. For storm tracking, should overflow in `within_grace_interval` mean "within the interval" (saturate) or be an error?
4. Is the C++ shim built with `panic = "abort"` or otherwise relying on no panics crossing the FFI boundary? That determines how urgent this is.
