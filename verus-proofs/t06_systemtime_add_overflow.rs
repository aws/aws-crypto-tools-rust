// =============================================================================
// VR-2026-T06 (TM-MPL-018, TM-MPL-022, TM-MPL-023; BUG-01): the four
//   `SystemTime + Duration` additions in the hierarchical keyring and the
//   storm-tracking cache
//
// Run:  ~/verus/verus verus-proofs/t06_systemtime_add_overflow.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model: `SystemTime` and `Duration` are
// integers, the std `+` is a spec function, and each of the four addition sites is a spec
// function with the same inputs as the shipped line. The shipped code is native Rust, is not
// inside `verus!`, and is not compiled by Verus. Nothing here detects a later edit to mpl/. The
// link between model and code is the correspondence table in section 2, reviewed by a human.
// The std `+` is modeled from a reading of the std source (H_STD_ADD, H_STD_UNIX), and the
// platform range of `SystemTime` is ASSUMED (A_TIME_RANGE). Neither is proved here.
//
// STATUS: PARTLY PROVED: `verification results:: 28 verified, 4 errors`, relative to the
// hypotheses in header section 4. Everything verifies except FOUR obligations that Verus REJECTS ON
// PURPOSE (expected-FAIL, BUG-01, open), one per addition site:
//     lemma_bug01_site_702_no_overflow_for_any_accepted_ttl_EXPECTED_FAIL
//     lemma_bug01_site_945_no_overflow_for_any_accepted_ttl_EXPECTED_FAIL
//     lemma_bug01_site_333_no_overflow_for_any_accepted_in_flight_ttl_EXPECTED_FAIL
//     lemma_bug01_site_680_no_overflow_for_any_accepted_grace_interval_EXPECTED_FAIL
// Each states "the addition does not panic for every configuration the builder accepts" and
// is left failing. It is not weakened, not assumed and not commented out. Code SECTION 6 proves, as
// ordinary lemmas, the concrete accepted configurations that make each statement FALSE (not
// merely unproved): for example `ttl = Duration::MAX` in the keyring builder.
//
// WHAT IS PROVED (relative to the model and to the hypotheses in section 4)
//   R1  lemma_add_ok_iff           the two-step std algorithm and the one-line condition
//                                  `tn(t) + dn(d) <= tn_max` agree.
//   R2  theorem_safe_bound         (1) if `d.secs + 1 <= hi - t.secs` the addition does not
//                                  overflow, for every Duration within that bound.
//       lemma_bound_is_tight       the bound is exact on whole seconds (not only sufficient).
//       theorem_sites_safe         the same fact at each of the four sites.
//   R3  lemma_bug01_keyring_counterexample, lemma_bug01_site_333_counterexample,
//       lemma_bug01_site_680_counterexample, lemma_bug01_keyring_counterexample_i64_max
//                                  (2) concrete accepted configurations (for example
//                                  Duration::MAX) for which each of the four additions panics.
//       lemma_bug01_*_EXPECTED_FAIL      the failing obligations named above.
//   R4  theorem_poison_is_persistent, theorem_bug01_poisons_storm_cache,
//       theorem_bug01b_poisons_storm_cache   the consequence for the storm-tracking lock: a panic at
//                                  :333 or :680 poisons the state mutex, and then every later
//                                  `get_cache_entry` and `put_cache_entry` that gets past the
//                                  local cache returns Internal, for any later sequence of calls.
//                                  Relative to A_MUTEX and H_STATE_LOCKED_SITES.
//   R5  theorem_fixed_add_agrees, theorem_fixed_classify_agrees,
//       theorem_fixed_handles_counterexamples, lemma_fixed_never_poisons
//                                  (3) PROPOSED FIX, model level: `checked_add` at each site
//                                  turned into an error. It agrees with the shipped model wherever
//                                  the shipped model does not panic, returns an error exactly
//                                  where it panics, and cannot poison the lock.
//   R6  theorem_fix_validate_no_overflow   (3) PROPOSED FIX, alternative: an upper bound on the builder
//                                  values. Sound only relative to A_TIME_RANGE and A_NOW_CAP;
//                                  `lemma_fix_validate_depends_on_range` shows the dependence.
//
// WHAT IS NOT PROVED
//   * That the shipped code has any of these properties (model level only).
//   * The platform range of SystemTime (A_TIME_RANGE) and the clock value (A_NOW, A_NOW_CAP).
//   * That std's `+` is `checked_add().expect(..)` on every platform (H_STD_ADD, H_STD_UNIX are
//     from reading std 1.95.0 for Unix; Windows and other targets are not modeled).
//   * Mutex poisoning semantics (A_MUTEX, from the std documentation).
//   * Panic = unwind (H_UNWIND). With panic = "abort" there is no persistent poisoned cache;
//     the process ends.
//   * The `sleep` value (a `tokio::time::sleep` argument, not a SystemTime addition) and the
//     grace period (only used with `checked_sub`, `within_grace_period` :661-669, which cannot
//     panic). Both are code reading and are out of the model.
//   * Fix B is only a model of a bound check with an illustrative constant. The constant is an
//     owner decision (BUG-01 question 2).
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD 19deef7; the two files
//    hierarchical_keyring.rs and storm_tracking.rs were last changed by bec2cfe)
// =============================================================================
//   mpl/src/aws_kms/hierarchical_keyring.rs
//     :535-552   HierarchicalKeyringBuilder::build; only `ttl.is_zero()` is rejected (:547)
//     :584-593   with a storm cache, `grace_period >= ttl` is rejected
//     :698-702   on_encrypt miss: now = SystemTime::now(); expiry_time(now + self.inner.ttl)
//     :941-945   decrypt_edk_at_version miss: same two lines
//     :989-995   cache_entry_within_limits: `duration_since(..).unwrap_or(ZERO)`, `elapsed <= ttl`
//                (no addition)
//   mpl/src/cmc/storm_tracking.rs
//     :239-256   state_locked: lock().map_err(|_| Internal "cache lock poisoned") (:248), prune
//     :264-345   classify_and_mark; cache-miss branch :307-341, key-inflight arm :319-340
//                :320   elapsed = now.duration_since(inflight_t).unwrap_or(Duration::ZERO)
//                :322   `elapsed > in_flight_ttl` -> in_flight_ttl_exceeded
//                :326   within_grace_interval(inflight_t, now, grace_interval)
//                :333   deadline: Some(now + self.inner.in_flight_ttl)
//     :293       within_grace_interval on the cache-hit branch
//     :388-394   wait_for_leader: guard from :388 alive while within_grace_interval runs (:394)
//     :606-626   StormTrackingCmcBuilder::build: fan_out 0, in_flight_ttl 0, sleep 0 and
//                grace_interval > in_flight_ttl are rejected; no upper bound
//     :675-681   within_grace_interval: `now < inflight + grace_interval`  (the :680 addition)
//     :710-727   put_cache_entry: inner put first, then state_locked (:724)
//     :729-748   get_cache_entry: local.get_fresh(..)? first (:734), then state_locked (:739), then
//                classify_and_mark with the guard alive (:740)
//     :750-762   delete_cache_entry, update_usage_metadata: local cache only, no state lock
//   mpl/src/cmc/local.rs :131-157 get_fresh and :311-336: a SEPARATE mutex (`store`)
//   Other additions: the only `+` between SystemTime and Duration in mpl/, prim/ and esdk/ src
//   are the four sites above (grep for SystemTime and for `+ self.inner.` found no other).
//   The clock seam `StormTrackingCmcBuilder::clock` (:585-596) is `#[cfg(feature = "test-utils")]`
//   and `#[doc(hidden)]`; in production `now` is SystemTime::now (H_CLOCK).
//   BUG-01: docs/mpl-bug-reports/BUG-01-ttl-duration-overflow-panic.md (reproducer log
//   .agents/tasks/bug-recheck/logs/recheck01.log: u64::MAX and i64::MAX seconds fail,
//   1e15 seconds succeeds, the four calls panic with "overflow when adding duration to instant").
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code)
// =============================================================================
//   model                         shipped
//   ----------------------------  -----------------------------------------------------------
//   Dur {secs: u64, nanos: u32}   std::time::Duration (nanos < 1e9 is the std invariant)
//   Time {secs, nanos: int}       std::time::SystemTime (a timespec on Unix)
//   Range {lo, hi}                A_TIME_RANGE: the representable whole-second range
//   st_checked_add                SystemTime::checked_add (H_STD_UNIX)
//   st_add -> Out<Time>           SystemTime + Duration; Out::Panic is the panic (H_STD_ADD)
//   site_702, site_945            `now + self.inner.ttl` at hierarchical_keyring.rs :702, :945
//   site_333                      `now + self.inner.in_flight_ttl` at storm_tracking.rs :333
//   within_grace_interval         storm_tracking.rs :675-681; the addition is :680
//   classify_miss_inflight        storm_tracking.rs :319-340 (cache miss, key inflight)
//   k_accepts                     HierarchicalKeyringBuilder::build :546-552
//   s_accepts                     StormTrackingCmcBuilder::build :606-626
//   Storm.poisoned, Body, Op,     the storm state Mutex, the code run while its guard is held,
//     step                        and the four Cmc entry points :710-762
//
// Reachability of each site with a large Duration (H_REACH, code reading):
//   :702, :945  `ttl` is any non-zero Duration (`Duration::MAX` accepted). With a storm cache the
//               only extra check is `grace_period < ttl`, which a large ttl satisfies.
//   :333        needs an inflight entry, `elapsed <= in_flight_ttl` (:322) and a non-zero grace
//               interval that has not elapsed. in_flight_ttl may be any non-zero Duration at or
//               above grace_interval. Reached with in_flight_ttl = Duration::MAX, grace_interval
//               = 1 s (BUG-01c).
//   :680        needs an inflight entry (all three callers). grace_interval may be any Duration
//               up to in_flight_ttl, so Duration::MAX is accepted with in_flight_ttl =
//               Duration::MAX (BUG-01b).
//   fan_out is a count, `sleep` is passed to tokio::time::sleep: neither is added to a
//   SystemTime. grace_period only appears in `checked_sub` (:667).
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED
// =============================================================================
// The spec (aws-kms-hierarchical-keyring.md#cache-limit-ttl) says only "This value MUST be
// greater than zero." The storm-tracking spec constrains only the order of grace interval,
// inflight TTL and grace period. No spec text bounds these values from above. This property is
// robustness, not a spec requirement (BUG-01: "Spec conflict: no"). Everything modeled here is
// CODE-DERIVED. Dafny's MPL guards the same addition with an Err (BUG-01 report), which is the
// reference for the proposed fix, not a spec rule.
//
// =============================================================================
// 4. HYPOTHESES AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and to the
//                  hypotheses below
//    ASSUMED       taken as a premise or a definition; not proved here (A_*)
//    CODE READING  a claim about shipped code or std that Verus does not see (H_*); checked
//                  by a human reading the source at the lines named
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier..]`
//  attribute is written in this file, and there is no uninterpreted spec function.
//
//  A_TIME_RANGE (ASSUMED). The platform range of SystemTime is not fixed by the language. The
//    model takes the representable instants to be those whose whole-second count lies in
//    [lo, hi] (any nanosecond part is fine). The default instance `unix64()` is
//    [i64::MIN, i64::MAX], the 64-bit Unix timespec. It is assumed, not proved. The BUG-01 log
//    (macOS) is consistent with it (u64::MAX and i64::MAX seconds fail, 1e15 succeeds) but does
//    not establish the bound. On other platforms (BUG-01 mentions Windows, untested) the real
//    range is smaller; every theorem here that needs the range takes `r: Range` as a parameter.
//  A_NOW (ASSUMED). SystemTime::now() is a representable instant: `time_wf(r, now)`. Inflight
//    marks are earlier clock readings and satisfy the same.
//  A_NOW_CAP (ASSUMED, fix B only). The clock reads at most NOW_CAP seconds (year 3000 in
//    the instance below). Not a fact about any machine; a premise.
//  H_STD_ADD (CODE READING, std). `impl Add<Duration> for SystemTime` is
//    `self.checked_add(dur).expect("overflow when adding duration to instant")`
//    (library/std/src/time.rs at rustc 59807616e, 1.95.0, the compiler of the BUG-01 log). So
//    `+` panics exactly when `checked_add` is None. `Out::Panic` models that.
//  H_STD_UNIX (CODE READING, std, Unix only). `Timespec::checked_add_duration`
//    (library/std/src/sys/pal/unix/time.rs): secs = tv_sec.checked_add_unsigned(d.as_secs())?;
//    nsec = d.subsec_nanos() + tv_nsec; if nsec >= 1e9 { nsec -= 1e9; secs = secs.checked_add(1)? }.
//    `st_checked_add` copies this step by step. The result is None only past the upper end.
//  A_MUTEX (ASSUMED, std documentation). If a thread panics while it holds a MutexGuard,
//    the mutex becomes poisoned; `lock()` on a poisoned mutex returns Err; the flag stays set
//    unless `clear_poison` is called. A guard dropped by an `Err` return does not poison.
//  H_NO_CLEAR (CODE READING). mpl/src has no `clear_poison` and no `into_inner` on these mutexes
//    (grep, no hits), so nothing clears the flag. The model has no step that clears it.
//  H_STATE_LOCKED_SITES (CODE READING). The :333 and :680 additions run with the guard of the
//    storm state mutex alive: :333 in classify_and_mark, called at :740 with the guard from :739;
//    :680 via :293 and :326 (same call) and via :394 with the guard from :388.
//  H_NO_LOCK_KEYRING (CODE READING). At :702 and :945 no mutex guard is alive. The cache call
//    has returned (`.send().await?`) before the addition, and hierarchical_keyring.rs has no
//    Mutex. So the keyring sites do not poison anything.
//  H_LOCAL_SEPARATE (CODE READING). `LocalCmc` uses its own `store` mutex (local.rs :62). Its
//    guard is dropped when `get_fresh` returns, before the storm state lock is taken, so a panic
//    under the storm state lock does not poison the local cache.
//  H_UNWIND (CODE READING). No `panic` key appears in any Cargo.toml of this repository or in
//    .cargo/config.toml (grep), and there is no `catch_unwind` in mpl/src, esdk/src or
//    esdk/shims (grep). So the default (unwind) applies to the crates themselves. How a C++
//    host builds and links the shim is not examined (BUG-01 question 4). The persistent-poison
//    result needs unwinding and a cache instance that outlives the panicking task (a shared
//    Arc). With panic = "abort" the process ends instead.
//  H_CLOCK (CODE READING). In production the storm cache clock is SystemTime::now (:628); the
//    override is a test-utils seam.
//  H_REACH (CODE READING). See the reachability notes at the end of section 2.
//  H_MODEL_MATCH (CODE READING). The site functions have the same inputs and the same operation
//    order as the lines named in section 2. Checked by reading; not machine-checked.
//
// =============================================================================
// 5. THE LOCK CONSEQUENCE: HOW MUCH IS MODELED
// =============================================================================
// Modeled: one boolean (poisoned), the four Cmc entry points as `Op`s, and the code run under
// the guard as an abstract `Body` (Fine, Fails, Panics). `get_body_miss_inflight` computes the
// Body for the cache-miss-inflight path from the modeled additions, so a panic at :333 or :680
// is what produces `Body::Panics`. Not modeled: the other classification branches (they reach
// the same :680 addition through `within_grace_interval`), the inflight map contents, pruning,
// the wait loop's sleeping, the local cache contents. `Op::Get.local_ok` is whether the local
// cache read before the lock succeeded (:734); if it fails the call returns that error and the
// state lock is not taken. The claim is therefore "Internal whenever the local read succeeds".
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Time model and the std addition
// ============================================================

pub open spec fn ns() -> int { 1_000_000_000 }

/// std::time::Duration. Invariant: nanos < 1e9 (`dur_wf`).
pub struct Dur {
    pub secs: u64,
    pub nanos: u32,
}

/// std::time::SystemTime as (whole seconds, nanoseconds). Invariant: 0 <= nanos < 1e9.
pub struct Time {
    pub secs: int,
    pub nanos: int,
}

/// A_TIME_RANGE: representable instants have `lo <= secs <= hi`.
pub struct Range {
    pub lo: int,
    pub hi: int,
}

/// The 64-bit Unix instance: tv_sec is an i64.
pub open spec fn unix64() -> Range {
    Range { lo: -9223372036854775808, hi: 9223372036854775807 }
}

pub open spec fn dur_wf(d: Dur) -> bool { d.nanos < 1_000_000_000 }
pub open spec fn dur_zero(d: Dur) -> bool { d.secs == 0 && d.nanos == 0 }
/// Duration in nanoseconds (unbounded integer).
pub open spec fn dn(d: Dur) -> int { d.secs as int * ns() + d.nanos as int }
/// Instant in nanoseconds since the model's zero (unbounded integer).
pub open spec fn tn(t: Time) -> int { t.secs * ns() + t.nanos }
pub open spec fn dur_gt(a: Dur, b: Dur) -> bool { dn(a) > dn(b) }
pub open spec fn time_wf(r: Range, t: Time) -> bool {
    0 <= t.nanos < ns() && r.lo <= t.secs <= r.hi
}
pub open spec fn time_lt(a: Time, b: Time) -> bool { tn(a) < tn(b) }

/// Duration::MAX
pub open spec fn dur_max() -> Dur { Dur { secs: u64::MAX, nanos: 999_999_999 } }

/// H_STD_UNIX: Timespec::checked_add_duration, step by step.
pub open spec fn st_checked_add(r: Range, t: Time, d: Dur) -> Option<Time> {
    let s0 = t.secs + d.secs as int;
    let n = t.nanos + d.nanos as int;
    if s0 > r.hi {
        None
    } else if n >= ns() {
        if s0 + 1 > r.hi { None } else { Some(Time { secs: s0 + 1, nanos: n - ns() }) }
    } else {
        Some(Time { secs: s0, nanos: n })
    }
}

/// The one-line form: the sum, in nanoseconds, reaches at most the last representable instant.
pub open spec fn st_add_ok(r: Range, t: Time, d: Dur) -> bool {
    tn(t) + dn(d) <= r.hi * ns() + (ns() - 1)
}

/// Outcome of an operation that can panic.
pub enum Out<T> {
    Value(T),
    Panic,
}

/// H_STD_ADD: `SystemTime + Duration` is `checked_add(..).expect(..)`.
pub open spec fn st_add(r: Range, t: Time, d: Dur) -> Out<Time> {
    match st_checked_add(r, t, d) {
        Some(x) => Out::Value(x),
        None => Out::Panic,
    }
}

// ============================================================
// SECTION 2: The four sites and the code around them
// ============================================================

/// hierarchical_keyring.rs :702, `now + self.inner.ttl`.
pub open spec fn site_702(r: Range, now: Time, ttl: Dur) -> Out<Time> { st_add(r, now, ttl) }

/// hierarchical_keyring.rs :945, `now + self.inner.ttl`.
pub open spec fn site_945(r: Range, now: Time, ttl: Dur) -> Out<Time> { st_add(r, now, ttl) }

/// storm_tracking.rs :333, `now + self.inner.in_flight_ttl`.
pub open spec fn site_333(r: Range, now: Time, in_flight_ttl: Dur) -> Out<Time> {
    st_add(r, now, in_flight_ttl)
}

/// storm_tracking.rs :680, the addition inside `within_grace_interval`: `inflight + grace_interval`.
pub open spec fn site_680(r: Range, inflight: Time, gi: Dur) -> Out<Time> {
    st_add(r, inflight, gi)
}

/// storm_tracking.rs :675-681: `now < inflight + grace_interval`.
pub open spec fn within_grace_interval(r: Range, inflight: Time, now: Time, gi: Dur) -> Out<bool> {
    match site_680(r, inflight, gi) {
        Out::Value(x) => Out::Value(time_lt(now, x)),
        Out::Panic => Out::Panic,
    }
}

/// HierarchicalKeyringBuilder::build :546-552: only a zero ttl is rejected.
pub struct KCfg {
    pub ttl: Dur,
}

pub open spec fn k_accepts(c: KCfg) -> bool {
    dur_wf(c.ttl) && !dur_zero(c.ttl)
}

/// StormTrackingCmcBuilder::build :606-626.
pub struct SCfg {
    pub grace_period: Dur,
    pub grace_interval: Dur,
    pub in_flight_ttl: Dur,
    pub sleep: Dur,
    pub fan_out: nat,
}

pub open spec fn s_accepts(c: SCfg) -> bool {
    &&& dur_wf(c.grace_period)
    &&& dur_wf(c.grace_interval)
    &&& dur_wf(c.in_flight_ttl)
    &&& dur_wf(c.sleep)
    &&& c.fan_out != 0
    &&& !dur_zero(c.in_flight_ttl)
    &&& !dur_zero(c.sleep)
    &&& !dur_gt(c.grace_interval, c.in_flight_ttl)
}

/// The keyring with a storm cache adds `grace_period < ttl` (hierarchical_keyring.rs :583-593).
pub open spec fn ks_accepts(k: KCfg, s: SCfg) -> bool {
    k_accepts(k) && s_accepts(s) && dn(s.grace_period) < dn(k.ttl)
}

/// `now.duration_since(inflight_t).unwrap_or(Duration::ZERO)` as nanoseconds (:320).
pub open spec fn elapsed_ns(now: Time, inflight: Time) -> int {
    if tn(now) >= tn(inflight) { tn(now) - tn(inflight) } else { 0 }
}

/// What the cache-miss, key-inflight arm decides (:319-340).
pub enum MissInflight {
    ErrInFlightTtl,
    Wait { deadline: Time },
    TakeLeader,
}

/// storm_tracking.rs :319-340, in the order of the code: the :322 check, :326, then :333.
pub open spec fn classify_miss_inflight(
    r: Range,
    c: SCfg,
    inflight: Time,
    now: Time,
) -> Out<MissInflight> {
    if elapsed_ns(now, inflight) > dn(c.in_flight_ttl) {
        Out::Value(MissInflight::ErrInFlightTtl)
    } else {
        match within_grace_interval(r, inflight, now, c.grace_interval) {
            Out::Panic => Out::Panic,
            Out::Value(true) => match site_333(r, now, c.in_flight_ttl) {
                Out::Panic => Out::Panic,
                Out::Value(d) => Out::Value(MissInflight::Wait { deadline: d }),
            },
            Out::Value(false) => Out::Value(MissInflight::TakeLeader),
        }
    }
}

// ============================================================
// SECTION 3: The state lock (A_MUTEX)
// ============================================================

/// The storm-tracking state mutex (storm_tracking.rs :102).
pub struct Storm {
    pub poisoned: bool,
}

/// What the code run under the guard does.
pub enum Body {
    Fine,
    Fails,
    Panics,
}

/// The Cmc entry points. `local_ok` is the result of the local-cache step that runs before the
/// state lock (:734 `get_fresh(..)?`, :721 inner put `?`). `Other` is delete_cache_entry and
/// update_usage_metadata (:750-762): they use the local cache only.
pub enum Op {
    Get { local_ok: bool, body: Body },
    Put { local_ok: bool },
    Other { local_ok: bool },
}

pub enum Res {
    Ok,
    ErrInternal,
    ErrOther,
    Panicked,
}

/// One call. A_MUTEX: lock() on a poisoned mutex is Err (mapped to Internal at :248); a panic
/// while the guard is alive poisons; an Err return does not.
pub open spec fn step(st: Storm, op: Op) -> (Res, Storm) {
    match op {
        Op::Get { local_ok, body } => {
            if !local_ok {
                (Res::ErrOther, st)
            } else if st.poisoned {
                (Res::ErrInternal, st)
            } else {
                match body {
                    Body::Fine => (Res::Ok, st),
                    Body::Fails => (Res::ErrOther, st),
                    Body::Panics => (Res::Panicked, Storm { poisoned: true }),
                }
            }
        },
        Op::Put { local_ok } => {
            if !local_ok {
                (Res::ErrOther, st)
            } else if st.poisoned {
                (Res::ErrInternal, st)
            } else {
                (Res::Ok, st)
            }
        },
        Op::Other { local_ok } => {
            if local_ok { (Res::Ok, st) } else { (Res::ErrOther, st) }
        },
    }
}

pub open spec fn run_state(st: Storm, ops: Seq<Op>) -> Storm
    decreases ops.len(),
{
    if ops.len() == 0 {
        st
    } else {
        run_state(step(st, ops[0]).1, ops.drop_first())
    }
}

pub open spec fn op_takes_state_lock(op: Op) -> bool {
    match op {
        Op::Get { local_ok, .. } => local_ok,
        Op::Put { local_ok } => local_ok,
        Op::Other { .. } => false,
    }
}

/// The Body of a Get on the cache-miss, key-inflight path, from the modeled additions.
pub open spec fn get_body_miss_inflight(r: Range, c: SCfg, inflight: Time, now: Time) -> Body {
    match classify_miss_inflight(r, c, inflight, now) {
        Out::Panic => Body::Panics,
        Out::Value(MissInflight::ErrInFlightTtl) => Body::Fails,
        Out::Value(MissInflight::Wait { .. }) => Body::Fine,
        Out::Value(MissInflight::TakeLeader) => Body::Fine,
    }
}

// ============================================================
// SECTION 4: The addition itself (R1, R2)
// ============================================================

/// The two-step algorithm and the one-line condition agree, and a Some result is the exact sum.
proof fn lemma_add_ok_iff(r: Range, t: Time, d: Dur)
    requires
        time_wf(r, t),
        dur_wf(d),
    ensures
        st_checked_add(r, t, d) is Some <==> st_add_ok(r, t, d),
        st_checked_add(r, t, d) is Some ==> ({
            let x = st_checked_add(r, t, d)->Some_0;
            tn(x) == tn(t) + dn(d) && time_wf(r, x)
        }),
{
    assert(r.lo <= t.secs);
}

proof fn lemma_st_add_panic_iff(r: Range, t: Time, d: Dur)
    requires
        time_wf(r, t),
        dur_wf(d),
    ensures
        st_add(r, t, d) is Panic <==> !st_add_ok(r, t, d),
{
    lemma_add_ok_iff(r, t, d);
}

/// R2 (1): within the stated safe bound the addition does not overflow.
pub open spec fn within_safe_bound(r: Range, t: Time, d: Dur) -> bool {
    d.secs as int + 1 <= r.hi - t.secs
}

proof fn theorem_safe_bound(r: Range, t: Time, d: Dur)
    requires
        time_wf(r, t),
        dur_wf(d),
        within_safe_bound(r, t, d),
    ensures
        st_add(r, t, d) is Value,
{
    lemma_add_ok_iff(r, t, d);
}

/// The bound is exact on whole seconds: with a zero nanosecond part, `hi - t.secs` seconds is
/// the largest Duration that works and one second more panics.
proof fn lemma_bound_is_tight(r: Range, t: Time)
    requires
        time_wf(r, t),
        t.nanos == 0,
        t.secs >= 0,
        r.hi - t.secs + 1 <= u64::MAX as int,
    ensures
        st_add(r, t, Dur { secs: (r.hi - t.secs) as u64, nanos: 0 }) is Value,
        st_add(r, t, Dur { secs: (r.hi - t.secs + 1) as u64, nanos: 0 }) is Panic,
{
    lemma_add_ok_iff(r, t, Dur { secs: (r.hi - t.secs) as u64, nanos: 0 });
    lemma_add_ok_iff(r, t, Dur { secs: (r.hi - t.secs + 1) as u64, nanos: 0 });
}

/// The platform range matters: the same Duration can be safe on one range and overflow on a
/// smaller one (A_TIME_RANGE is a parameter, not a constant).
proof fn lemma_threshold_depends_on_range()
    ensures
        ({
            let t = Time { secs: 1_700_000_000, nanos: 0 };
            let d = Dur { secs: 10_000_000_000_000, nanos: 0 };  // 1e13 s
            let smaller = Range { lo: 0, hi: 1_800_000_000_000 };  // illustrative, not a platform
            &&& time_wf(unix64(), t)
            &&& st_add(unix64(), t, d) is Value
            &&& time_wf(smaller, t)
            &&& st_add(smaller, t, d) is Panic
        }),
{
    let t = Time { secs: 1_700_000_000, nanos: 0 };
    let d = Dur { secs: 10_000_000_000_000, nanos: 0 };
    let smaller = Range { lo: 0, hi: 1_800_000_000_000 };
    lemma_add_ok_iff(unix64(), t, d);
    lemma_add_ok_iff(smaller, t, d);
}

/// R2 per site: the safe bound at each of the four sites (the arguments are exactly the
/// arguments of the shipped lines).
proof fn theorem_sites_safe(r: Range, k: KCfg, s: SCfg, now: Time, inflight: Time)
    requires
        time_wf(r, now),
        time_wf(r, inflight),
        k_accepts(k),
        s_accepts(s),
        within_safe_bound(r, now, k.ttl),
        within_safe_bound(r, now, s.in_flight_ttl),
        within_safe_bound(r, inflight, s.grace_interval),
    ensures
        site_702(r, now, k.ttl) is Value,
        site_945(r, now, k.ttl) is Value,
        site_333(r, now, s.in_flight_ttl) is Value,
        site_680(r, inflight, s.grace_interval) is Value,
        classify_miss_inflight(r, s, inflight, now) is Value,
        get_body_miss_inflight(r, s, inflight, now) != Body::Panics,
{
    theorem_safe_bound(r, now, k.ttl);
    theorem_safe_bound(r, now, s.in_flight_ttl);
    theorem_safe_bound(r, inflight, s.grace_interval);
}

// ============================================================
// SECTION 5: Expected-FAIL obligations (BUG-01)
// ============================================================
// Each states: for EVERY configuration the builder accepts and any representable times, the
// addition does not panic. Each is false. Verus reports "postcondition not satisfied" for each.
// They are deliberately NOT weakened, NOT assumed and NOT commented out.

/// EXPECTED FAIL (BUG-01a, hierarchical_keyring.rs :702). `ttl` is any non-zero Duration.
proof fn lemma_bug01_site_702_no_overflow_for_any_accepted_ttl_EXPECTED_FAIL(
    r: Range,
    k: KCfg,
    now: Time,
)
    requires
        r == unix64(),
        time_wf(r, now),
        k_accepts(k),
    ensures
        site_702(r, now, k.ttl) is Value,
{
}

/// EXPECTED FAIL (BUG-01d, hierarchical_keyring.rs :945). Same configuration, decrypt path.
proof fn lemma_bug01_site_945_no_overflow_for_any_accepted_ttl_EXPECTED_FAIL(
    r: Range,
    k: KCfg,
    now: Time,
)
    requires
        r == unix64(),
        time_wf(r, now),
        k_accepts(k),
    ensures
        site_945(r, now, k.ttl) is Value,
{
}

/// EXPECTED FAIL (BUG-01c, storm_tracking.rs :333). Stated over the states that reach :333:
/// the :322 check passed and the grace interval has not elapsed (:326 returned true).
proof fn lemma_bug01_site_333_no_overflow_for_any_accepted_in_flight_ttl_EXPECTED_FAIL(
    r: Range,
    c: SCfg,
    inflight: Time,
    now: Time,
)
    requires
        r == unix64(),
        time_wf(r, now),
        time_wf(r, inflight),
        s_accepts(c),
        elapsed_ns(now, inflight) <= dn(c.in_flight_ttl),
        within_grace_interval(r, inflight, now, c.grace_interval) == Out::<bool>::Value(true),
    ensures
        site_333(r, now, c.in_flight_ttl) is Value,
{
}

/// EXPECTED FAIL (BUG-01b, storm_tracking.rs :680). Stated over the states that reach :680 on
/// the cache-miss path: an inflight entry exists and the :322 check passed.
proof fn lemma_bug01_site_680_no_overflow_for_any_accepted_grace_interval_EXPECTED_FAIL(
    r: Range,
    c: SCfg,
    inflight: Time,
    now: Time,
)
    requires
        r == unix64(),
        time_wf(r, now),
        time_wf(r, inflight),
        s_accepts(c),
        elapsed_ns(now, inflight) <= dn(c.in_flight_ttl),
    ensures
        site_680(r, inflight, c.grace_interval) is Value,
{
}

// ============================================================
// SECTION 6: Counterexamples (the statements above are false, not just unproved)
// ============================================================

/// A representative clock reading: 1_700_000_000 s after the Unix epoch (Nov 2023).
pub open spec fn now0() -> Time { Time { secs: 1_700_000_000, nanos: 0 } }

/// The BUG-01 "never expire" configuration for the keyring: ttl = Duration::MAX.
pub open spec fn cex_keyring() -> KCfg { KCfg { ttl: dur_max() } }

/// BUG-01c: in_flight_ttl = Duration::MAX, grace_interval = 1 s (defaults elsewhere).
pub open spec fn cex_storm_333() -> SCfg {
    SCfg {
        grace_period: Dur { secs: 10, nanos: 0 },
        grace_interval: Dur { secs: 1, nanos: 0 },
        in_flight_ttl: dur_max(),
        sleep: Dur { secs: 0, nanos: 20_000_000 },
        fan_out: 1,
    }
}

/// BUG-01b: grace_interval = in_flight_ttl = Duration::MAX.
pub open spec fn cex_storm_680() -> SCfg {
    SCfg {
        grace_period: Dur { secs: 10, nanos: 0 },
        grace_interval: dur_max(),
        in_flight_ttl: dur_max(),
        sleep: Dur { secs: 0, nanos: 20_000_000 },
        fan_out: 1,
    }
}

/// The keyring builder accepts ttl = Duration::MAX, and :702 and :945 panic for every clock
/// reading at or after the Unix epoch. This falsifies both keyring EXPECTED_FAIL lemmas.
proof fn lemma_bug01_keyring_counterexample()
    ensures
        k_accepts(cex_keyring()),
        time_wf(unix64(), now0()),
        site_702(unix64(), now0(), cex_keyring().ttl) is Panic,
        site_945(unix64(), now0(), cex_keyring().ttl) is Panic,
        forall|now: Time|
            #![trigger time_wf(unix64(), now)]
            time_wf(unix64(), now) && now.secs >= 0 ==> {
                &&& site_702(unix64(), now, cex_keyring().ttl) is Panic
                &&& site_945(unix64(), now, cex_keyring().ttl) is Panic
            },
{
    lemma_add_ok_iff(unix64(), now0(), dur_max());
    assert forall|now: Time| #![trigger time_wf(unix64(), now)]
        time_wf(unix64(), now) && now.secs >= 0 implies {
        &&& site_702(unix64(), now, cex_keyring().ttl) is Panic
        &&& site_945(unix64(), now, cex_keyring().ttl) is Panic
    } by {
        lemma_add_ok_iff(unix64(), now, dur_max());
    }
}

/// A smaller legal value also panics: ttl = i64::MAX seconds (BUG-01 log: "now+i64::MAX s
/// checked_add = None"). A round value far below Duration::MAX.
proof fn lemma_bug01_keyring_counterexample_i64_max()
    ensures
        ({
            let ttl = Dur { secs: 9223372036854775807u64, nanos: 0 };
            &&& k_accepts(KCfg { ttl })
            &&& site_702(unix64(), now0(), ttl) is Panic
        }),
{
    lemma_add_ok_iff(unix64(), now0(), Dur { secs: 9223372036854775807u64, nanos: 0 });
}

/// Contrast: 1e15 s (about 31.7 million years) is accepted and does NOT panic (BUG-01 log).
proof fn lemma_keyring_1e15_is_fine()
    ensures
        ({
            let ttl = Dur { secs: 1_000_000_000_000_000u64, nanos: 0 };
            &&& k_accepts(KCfg { ttl })
            &&& site_702(unix64(), now0(), ttl) is Value
        }),
{
    lemma_add_ok_iff(unix64(), now0(), Dur { secs: 1_000_000_000_000_000u64, nanos: 0 });
}

/// The same ttl is accepted when the keyring has a storm cache with the default grace period.
proof fn lemma_bug01_keyring_with_storm_cache_accepted()
    ensures
        ks_accepts(cex_keyring(), cex_storm_333()),
        ks_accepts(cex_keyring(), cex_storm_680()),
{
}

/// BUG-01c: the storm configuration is accepted, the state (an inflight mark at now0, a second
/// get at the same instant) reaches :333, and :333 panics. Falsifies the :333 lemma.
proof fn lemma_bug01_site_333_counterexample()
    ensures
        s_accepts(cex_storm_333()),
        time_wf(unix64(), now0()),
        elapsed_ns(now0(), now0()) <= dn(cex_storm_333().in_flight_ttl),
        within_grace_interval(unix64(), now0(), now0(), cex_storm_333().grace_interval)
            == Out::<bool>::Value(true),
        site_333(unix64(), now0(), cex_storm_333().in_flight_ttl) is Panic,
        classify_miss_inflight(unix64(), cex_storm_333(), now0(), now0()) is Panic,
{
    lemma_add_ok_iff(unix64(), now0(), cex_storm_333().grace_interval);
    lemma_add_ok_iff(unix64(), now0(), cex_storm_333().in_flight_ttl);
}

/// BUG-01b: the storm configuration is accepted, the second get finds the key inflight, passes
/// the :322 check, and :680 panics. Falsifies the :680 lemma.
proof fn lemma_bug01_site_680_counterexample()
    ensures
        s_accepts(cex_storm_680()),
        time_wf(unix64(), now0()),
        elapsed_ns(now0(), now0()) <= dn(cex_storm_680().in_flight_ttl),
        site_680(unix64(), now0(), cex_storm_680().grace_interval) is Panic,
        classify_miss_inflight(unix64(), cex_storm_680(), now0(), now0()) is Panic,
{
    lemma_add_ok_iff(unix64(), now0(), cex_storm_680().grace_interval);
}

// ============================================================
// SECTION 7: The lock consequence (R4)
// ============================================================

proof fn lemma_step_keeps_poison(st: Storm, op: Op)
    requires
        st.poisoned,
    ensures
        step(st, op).1.poisoned,
{
}

proof fn lemma_run_keeps_poison(st: Storm, ops: Seq<Op>)
    requires
        st.poisoned,
    ensures
        run_state(st, ops).poisoned,
    decreases ops.len(),
{
    if ops.len() > 0 {
        lemma_step_keeps_poison(st, ops[0]);
        lemma_run_keeps_poison(step(st, ops[0]).1, ops.drop_first());
    }
}

/// A call that takes the state lock on a poisoned mutex returns Internal and leaves the state
/// unchanged (:248).
proof fn lemma_poisoned_call_is_internal(st: Storm, op: Op)
    requires
        st.poisoned,
        op_takes_state_lock(op),
    ensures
        step(st, op).0 == Res::ErrInternal,
        step(st, op).1 == st,
{
}

/// A call whose locked body panics poisons the mutex.
proof fn lemma_panic_under_lock_poisons(st: Storm, local_ok: bool)
    requires
        !st.poisoned,
        local_ok,
    ensures
        step(st, Op::Get { local_ok, body: Body::Panics }).0 == Res::Panicked,
        step(st, Op::Get { local_ok, body: Body::Panics }).1.poisoned,
{
}

/// delete_cache_entry and update_usage_metadata do not take the state lock: their result and the
/// state do not depend on the poison flag (H_STATE_LOCKED_SITES, :750-762).
proof fn lemma_other_ops_unaffected(st1: Storm, st2: Storm, local_ok: bool)
    ensures
        step(st1, Op::Other { local_ok }).0 == step(st2, Op::Other { local_ok }).0,
        step(st1, Op::Other { local_ok }).1 == st1,
{
}

/// R4: once poisoned, EVERY later call that takes the state lock returns Internal, for any
/// sequence of calls in between. Nothing in the model clears the flag (H_NO_CLEAR).
proof fn theorem_poison_is_persistent(st: Storm, ops: Seq<Op>, i: int)
    requires
        st.poisoned,
        0 <= i < ops.len(),
        op_takes_state_lock(ops[i]),
    ensures
        run_state(st, ops.take(i)).poisoned,
        step(run_state(st, ops.take(i)), ops[i]).0 == Res::ErrInternal,
{
    lemma_run_keeps_poison(st, ops.take(i));
    lemma_poisoned_call_is_internal(run_state(st, ops.take(i)), ops[i]);
}

/// The consequence for BUG-01b and BUG-01c, end to end in the model: on a fresh cache, one get
/// that reaches :333 (or :680) with the accepted configuration panics under the lock and
/// poisons it; after that, every later get or put that gets past the local cache returns
/// Internal, whatever the calls in between.
proof fn theorem_bug01_poisons_storm_cache(ops: Seq<Op>, i: int)
    requires
        0 <= i < ops.len(),
        op_takes_state_lock(ops[i]),
    ensures
        ({
            let fresh = Storm { poisoned: false };
            let op0 = Op::Get {
                local_ok: true,
                body: get_body_miss_inflight(
                    unix64(),
                    cex_storm_333(),
                    now0(),
                    now0(),
                ),
            };
            let after = step(fresh, op0);
            &&& after.0 == Res::Panicked
            &&& after.1.poisoned
            &&& step(run_state(after.1, ops.take(i)), ops[i]).0 == Res::ErrInternal
        }),
{
    lemma_bug01_site_333_counterexample();
    let fresh = Storm { poisoned: false };
    let op0 = Op::Get {
        local_ok: true,
        body: get_body_miss_inflight(unix64(), cex_storm_333(), now0(), now0()),
    };
    assert(op0 == Op::Get { local_ok: true, body: Body::Panics });
    let after = step(fresh, op0);
    theorem_poison_is_persistent(after.1, ops, i);
}

/// Same for :680.
proof fn theorem_bug01b_poisons_storm_cache(ops: Seq<Op>, i: int)
    requires
        0 <= i < ops.len(),
        op_takes_state_lock(ops[i]),
    ensures
        ({
            let fresh = Storm { poisoned: false };
            let op0 = Op::Get {
                local_ok: true,
                body: get_body_miss_inflight(
                    unix64(),
                    cex_storm_680(),
                    now0(),
                    now0(),
                ),
            };
            let after = step(fresh, op0);
            &&& after.0 == Res::Panicked
            &&& after.1.poisoned
            &&& step(run_state(after.1, ops.take(i)), ops[i]).0 == Res::ErrInternal
        }),
{
    lemma_bug01_site_680_counterexample();
    let fresh = Storm { poisoned: false };
    let op0 = Op::Get {
        local_ok: true,
        body: get_body_miss_inflight(unix64(), cex_storm_680(), now0(), now0()),
    };
    assert(op0 == Op::Get { local_ok: true, body: Body::Panics });
    let after = step(fresh, op0);
    theorem_poison_is_persistent(after.1, ops, i);
}

// ============================================================
// SECTION 8: PROPOSED FIX A, checked addition (BUG-01 fix option 1) -- model level
// ============================================================
// Not shipped. The same sites with `checked_add(..)` turned into an error, as the Dafny MPL does
// for the keyring. Which error type to return is an owner decision (BUG-01 question 1).

pub enum Fx<T> {
    Value(T),
    OverflowErr,
}

pub open spec fn fixed_add(r: Range, t: Time, d: Dur) -> Fx<Time> {
    match st_checked_add(r, t, d) {
        Some(x) => Fx::Value(x),
        None => Fx::OverflowErr,
    }
}

pub open spec fn fixed_within_grace_interval(
    r: Range,
    inflight: Time,
    now: Time,
    gi: Dur,
) -> Fx<bool> {
    match fixed_add(r, inflight, gi) {
        Fx::Value(x) => Fx::Value(time_lt(now, x)),
        Fx::OverflowErr => Fx::OverflowErr,
    }
}

pub open spec fn fixed_classify_miss_inflight(
    r: Range,
    c: SCfg,
    inflight: Time,
    now: Time,
) -> Fx<MissInflight> {
    if elapsed_ns(now, inflight) > dn(c.in_flight_ttl) {
        Fx::Value(MissInflight::ErrInFlightTtl)
    } else {
        match fixed_within_grace_interval(r, inflight, now, c.grace_interval) {
            Fx::OverflowErr => Fx::OverflowErr,
            Fx::Value(true) => match fixed_add(r, now, c.in_flight_ttl) {
                Fx::OverflowErr => Fx::OverflowErr,
                Fx::Value(d) => Fx::Value(MissInflight::Wait { deadline: d }),
            },
            Fx::Value(false) => Fx::Value(MissInflight::TakeLeader),
        }
    }
}

/// An error return releases the guard normally: no poison.
pub open spec fn fixed_get_body(r: Range, c: SCfg, inflight: Time, now: Time) -> Body {
    match fixed_classify_miss_inflight(r, c, inflight, now) {
        Fx::OverflowErr => Body::Fails,
        Fx::Value(MissInflight::ErrInFlightTtl) => Body::Fails,
        Fx::Value(MissInflight::Wait { .. }) => Body::Fine,
        Fx::Value(MissInflight::TakeLeader) => Body::Fine,
    }
}

/// Fix A agrees with the shipped model wherever the shipped model does not panic, and returns
/// the error exactly where the shipped model panics.
proof fn theorem_fixed_add_agrees(r: Range, t: Time, d: Dur)
    ensures
        st_add(r, t, d) is Value ==> fixed_add(r, t, d) == Fx::Value(st_add(r, t, d)->Value_0),
        st_add(r, t, d) is Panic <==> fixed_add(r, t, d) is OverflowErr,
{
}

proof fn theorem_fixed_classify_agrees(r: Range, c: SCfg, inflight: Time, now: Time)
    ensures
        classify_miss_inflight(r, c, inflight, now) is Value ==> fixed_classify_miss_inflight(
            r,
            c,
            inflight,
            now,
        ) == Fx::Value(classify_miss_inflight(r, c, inflight, now)->Value_0),
        classify_miss_inflight(r, c, inflight, now) is Panic ==> fixed_classify_miss_inflight(
            r,
            c,
            inflight,
            now,
        ) is OverflowErr,
{
}

/// Fix A is total on the counterexamples above: the configurations that panicked now return the
/// error, for any clock reading.
proof fn theorem_fixed_handles_counterexamples()
    ensures
        fixed_add(unix64(), now0(), cex_keyring().ttl) is OverflowErr,
        fixed_classify_miss_inflight(unix64(), cex_storm_333(), now0(), now0()) is OverflowErr,
        fixed_classify_miss_inflight(unix64(), cex_storm_680(), now0(), now0()) is OverflowErr,
{
    lemma_bug01_keyring_counterexample();
    lemma_bug01_site_333_counterexample();
    lemma_bug01_site_680_counterexample();
}

/// With Fix A the locked body never panics (by A_MUTEX an Err return does not poison), so the
/// state lock stays healthy and later calls are not turned into Internal errors by this cause.
/// This is only about the four additions: other panics are not modeled.
proof fn lemma_fixed_never_poisons(r: Range, c: SCfg, inflight: Time, now: Time, st: Storm)
    requires
        !st.poisoned,
    ensures
        fixed_get_body(r, c, inflight, now) != Body::Panics,
        step(st, Op::Get { local_ok: true, body: fixed_get_body(r, c, inflight, now) }).1 == st,
{
}

// ============================================================
// SECTION 9: PROPOSED FIX B, upper bound in the builders (BUG-01 fix option 2) -- model level
// ============================================================
// Not shipped. The constants are illustrative (BUG-01 names "100 years" as an example); the
// real value is an owner decision. The theorem is sound only relative to A_TIME_RANGE (the
// range r) and A_NOW_CAP (the clock never reads above NOW_CAP).

pub open spec fn max_d_secs() -> int { 3_153_600_000 }          // 100 years of 365 days
pub open spec fn now_cap() -> int { 32_503_680_000 }            // 3000-01-01 UTC

pub open spec fn k_accepts_bounded(c: KCfg) -> bool {
    k_accepts(c) && c.ttl.secs as int <= max_d_secs()
}

pub open spec fn s_accepts_bounded(c: SCfg) -> bool {
    s_accepts(c) && c.grace_interval.secs as int <= max_d_secs()
        && c.in_flight_ttl.secs as int <= max_d_secs()
}

/// With the bound, none of the four additions panics, for every accepted configuration and every
/// clock reading and inflight mark up to NOW_CAP, on any range with `max_d + now_cap + 1 <= hi`.
proof fn theorem_fix_validate_no_overflow(
    r: Range,
    k: KCfg,
    s: SCfg,
    now: Time,
    inflight: Time,
)
    requires
        max_d_secs() + now_cap() + 1 <= r.hi,
        time_wf(r, now),
        time_wf(r, inflight),
        now.secs <= now_cap(),
        inflight.secs <= now_cap(),
        k_accepts_bounded(k),
        s_accepts_bounded(s),
    ensures
        site_702(r, now, k.ttl) is Value,
        site_945(r, now, k.ttl) is Value,
        site_333(r, now, s.in_flight_ttl) is Value,
        site_680(r, inflight, s.grace_interval) is Value,
        classify_miss_inflight(r, s, inflight, now) is Value,
        get_body_miss_inflight(r, s, inflight, now) != Body::Panics,
{
    theorem_sites_safe(r, k, s, now, inflight);
}

/// The premise holds on the 64-bit Unix range.
proof fn lemma_fix_validate_holds_on_unix64()
    ensures
        max_d_secs() + now_cap() + 1 <= unix64().hi,
{
}

/// The dependence on A_TIME_RANGE: on a range whose upper end is `now_cap + max_d - 1`, a
/// configuration at the bound with the clock at the cap still panics.
proof fn lemma_fix_validate_depends_on_range()
    ensures
        ({
            let r = Range { lo: 0, hi: now_cap() + max_d_secs() - 1 };
            let now = Time { secs: now_cap(), nanos: 0 };
            let k = KCfg { ttl: Dur { secs: 3_153_600_000u64, nanos: 0 } };
            &&& time_wf(r, now)
            &&& k_accepts_bounded(k)
            &&& site_702(r, now, k.ttl) is Panic
        }),
{
    let r = Range { lo: 0, hi: now_cap() + max_d_secs() - 1 };
    let now = Time { secs: now_cap(), nanos: 0 };
    let k = KCfg { ttl: Dur { secs: 3_153_600_000u64, nanos: 0 } };
    lemma_add_ok_iff(r, now, k.ttl);
}

} // verus!

fn main() {}
