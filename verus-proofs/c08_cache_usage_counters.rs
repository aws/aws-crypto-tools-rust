// =============================================================================
// VR-2026-C08 (capability 2b, integer overflow freedom): the usage counters of a cache
//   entry, `CacheEntry::record_use` and `Cmc::update_usage_metadata`
//
// Run:  ~/verus/verus verus-proofs/c08_cache_usage_counters.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model. The counters are `u64` fields, the
// shipped `checked_add` calls are written as `u64::checked_add` in an executable model, the
// entry mutex is a `&mut` borrow, and the cache is a map from identifier to counters. The
// shipped code is native Rust, is not inside `verus!`, and is not compiled by Verus. Nothing
// here detects a later edit to mpl/. The link between model and code is the correspondence
// table in section 2, reviewed by a human. The behavior of `u64::checked_add` is taken from
// vstd's `assume_specification` (A_VSTD) and from std (H_STD_CHECKED_ADD), not proved here.
//
// STATUS: PROVED relative to the model and to the hypotheses in section 4:
//     `verification results:: 20 verified, 0 errors`
// Nothing is left failing on purpose. The code cannot wrap and cannot panic at any legal input
// (every `u64` pair of counters, every `u64` byte count), so no EXPECTED_FAIL obligation was
// written and none was invented (section 5, F0).
//
// =============================================================================
// WHAT THE CODE DOES (code reading, mpl/src/cmc/entry.rs and mpl/src/cmc/local.rs)
// =============================================================================
// Integer widths. `UsageMetadata { messages_used: u64, bytes_used: u64 }` (entry.rs :39-41).
// The per-call input is `UpdateUsageMetadataInput.bytes_used: u64` (operation.rs :364-367).
// There is no other width: no cast, no `as`, no `usize`, no `i64` on these values.
//
// `CacheEntry::record_use(&self, bytes: u64) -> bool` (entry.rs :206-223):
//     lock the entry's usage mutex (poison ignored: `unwrap_or_else(PoisonError::into_inner)`)
//     let (Some(messages), Some(total_bytes)) =
//         (usage.messages_used.checked_add(1), usage.bytes_used.checked_add(bytes)) else { return false };
//     usage.messages_used = messages;  usage.bytes_used = total_bytes;  true
// Both sums are computed first. Nothing is written unless both are `Some`. So the call either
// increments `messages_used` by 1 and `bytes_used` by `bytes`, or leaves both unchanged and
// returns false.
//
// `LocalCmc::update_usage_metadata` (local.rs :326-342), the only implementation with logic:
//     lock the `store` mutex; a poisoned lock returns Err(Internal "cache lock poisoned") with
//     no change (:331-334)
//     if let Some(cache) = inner.as_mut() && let Some(entry) = cache.peek(id)
//         && !entry.record_use(input.bytes_used()) { cache.pop(id); }
//     Ok(UpdateUsageMetadataOutput::default())
// So: no store (capacity 0) or no entry for the identifier is a no-op returning Ok. A failing
// `record_use` evicts exactly that entry (`pop`), and the call still returns Ok. `peek` does not
// change recency. DefaultCmc (default.rs :120-125) and StormTrackingCmc (storm_tracking.rs
// :757-762) forward to the LocalCmc call unchanged.
//
// HOW OVERFLOW IS HANDLED: it is never computed. `checked_add` returns None, `record_use`
// returns false without writing, and `update_usage_metadata` deletes the entry. No saturation,
// no reset, no error is returned to the caller.
//
// =============================================================================
// WHAT IS PROVED (relative to the model and to section 4)
// =============================================================================
//   R1  theorem_record_use_spec       `record_use` succeeds exactly when neither `messages + 1` nor
//                                     `bytes + b` exceeds u64::MAX; on success the counters are the
//                                     exact integer sums (no wrap); on failure both are unchanged.
//       theorem_overflow_cases        failure is exactly: messages == u64::MAX, or b > u64::MAX - bytes.
//       lemma_no_partial_update       a concrete case where only the byte sum overflows and the
//                                     message count stays unchanged (both-or-neither).
//   R2  record_use (exec)             the executable model with `u64::checked_add`: Verus checks
//                                     that it has no arithmetic overflow and satisfies the R1 contract
//                                     for every u64 input. `checked_add_by_hand` agrees with
//                                     `u64::checked_add` (cross-check of A_VSTD).
//   R3  theorem_update_step           one `update_usage_metadata` call on an unpoisoned cache: returns
//                                     Ok; an absent identifier changes nothing; a present one is
//                                     evicted exactly when `record_use` fails, else its counters become
//                                     the R1 sums; no identifier appears. The clause "no other
//                                     identifier changes" holds relative to A_NO_ALIAS (section 4).
//       lemma_poisoned_store_is_noop  a poisoned store returns Err(Internal) and changes nothing.
//   R4  theorem_run_entry             over ANY sequence of byte counts, from ANY start counters, the entry
//                                     survives iff `messages + n <= MAX` and `bytes + sum <= MAX`, and
//                                     then the counters are exactly `messages + n` and `bytes + sum`.
//       lemma_run_entry_absent_stays_absent   after eviction later calls do nothing (no resurrection).
//                                     R4 counts every change to the cell (relative to A_ALL_CALLS, and
//                                     for a cache entry to A_NO_ALIAS and A_NO_PUT).
//   R5  theorem_cache_refines_entry_run   the cache model, for any sequence of calls on any identifiers,
//                                     behaves on each identifier as the single-entry run of R4 over the
//                                     byte counts addressed to it. Relative to A_NO_ALIAS, A_ALL_CALLS
//                                     and A_NO_PUT.
//       theorem_no_wrap_any_calls     the summary: for any unpoisoned cache, any entry, any call
//                                     sequence, the entry is gone iff the exact totals would pass
//                                     u64::MAX; otherwise its counters are the exact totals. An absent
//                                     identifier stays absent. Relative to A_NO_ALIAS, A_ALL_CALLS,
//                                     A_NO_PUT and A_LOCK_EXCL.
//   R6  lemma_boundary_witnesses      unit-style witnesses at the maximum: the last allowed value is
//                                     accepted, one more is rejected (off-by-one both ways), for messages
//                                     and for bytes, and u64::MAX bytes from zero is accepted.
//       lemma_evicted_handle_is_not_frozen   observation O1 (section 5).
//   R7  update_slot (exec)            the single-entry `update_usage_metadata` effect on an `Option<UM>`
//                                     equals `step_entry`, for every input.
//
// =============================================================================
// WHAT IS NOT PROVED / WHAT THIS DOES NOT SHOW
// =============================================================================
//   * That the shipped code has any of these properties (model level only). A later edit to
//     entry.rs or local.rs is not detected.
//   * That `u64::checked_add` is correct (A_VSTD, H_STD_CHECKED_ADD). The overflow guard in the
//     model IS that std call. What Verus proves about it is "if it returns None exactly on
//     overflow, then nothing wraps", which is a short argument. The parts that carry more weight
//     are R3 to R5: the both-or-neither update, the eviction rule, the no-resurrection rule and
//     the exact-total statement over all call sequences.
//   * Concurrency. The model is sequential (A_LOCK_EXCL). The locks are assumed to give
//     exclusion. Interleavings, lock ordering (the `store` guard is held while the entry mutex is
//     taken) and deadlock freedom are not examined.
//   * That every change to a cell goes through update_usage_metadata addressed to its own
//     identifier (A_ALL_CALLS). `record_use` is `pub`; a holder of a cloned `CacheEntry` can call it
//     directly. The per-call contract R1/R2 still holds for such calls (no wrap), but the
//     sum/eviction statement R4/R5 counts only calls that go through the cache.
//   * That distinct identifiers have distinct counter cells (A_NO_ALIAS). The code stores a
//     `CacheEntry` handle (an `Arc`), `PutCacheEntryInput` is `Clone` and carries the handle by
//     value, `put_cache_entry` stores it under the given identifier, and `get_cache_entry`
//     returns a clone. So the same handle can be stored under two identifiers through the public
//     API. The code does not prevent it. Under such aliasing, `update_usage_metadata(B)` also
//     changes the counters seen through A. Then the clause "no other identifier changes" of
//     theorem_update_step and the per-identifier exact totals of R4/R5 (which count only calls
//     addressed to that identifier) do NOT hold for that state. What still holds under aliasing:
//     R1 and R2 (per-call no wrap, both-or-neither), the evict-the-addressed-slot rule (R7,
//     and the eviction clause of R3 for the addressed identifier), and no wrap of the shared
//     cell, because every change to it still goes through `record_use`.
//   * LRU order, capacity, TTL, pruning, expiry, async scheduling, `put`, `get`, `delete`. They
//     are not in the model. `peek` and `pop` are modeled by H_LRU_OPS from the `lru` crate docs.
//   * Any limit policy. No in-repo code compares the counters with a maximum; there is no
//     caching CMM in the repository. Whether a future caching CMM enforces its limits correctly
//     is not shown. Unreachable-in-practice: 2^64 messages or bytes are far beyond any real
//     workload, so this is a robustness property, not a statement about a likely attack.
//   * That any threat is mitigated. C08 has no threat reference (YAML `threat_references: []`).
//   * What the spec requires. The spec has one normative sentence on this (SHOULD be atomic,
//     cryptographic-materials-cache.md :93). The overflow-evicts rule is code-derived (section 3).
//   * That `usage_metadata()` (the read) or the Debug impl is safe. They only copy under the lock.
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD ad3522b)
// =============================================================================
//   mpl/src/cmc/entry.rs
//     :39-41    UsageMetadata { messages_used: u64, bytes_used: u64 }; fields private
//     :66-125   UsageMetadataBuilder; accepts any u64 pair (:74-77, :95-98); build never fails
//     :132-138, :141-146   CacheEntry { inner: Arc<CacheEntryInner> } (sharing doc :132-133); usage_metadata: Mutex<UsageMetadata> (:145)
//     :187-193  usage_metadata(): copy under the lock
//     :195-223  record_use (doc :195-205, Duvet implication :201-204 "SHOULD be atomic"; code :206-223)
//     :296-298, :327  CacheEntryBuilder::usage_metadata, stored with `unwrap_or_default()`
//   mpl/src/cmc/local.rs
//     :148     get_fresh returns `cache.get(cache_id).cloned()` (a clone shares the Arc)
//     :326-342 update_usage_metadata
//   mpl/src/cmc/mod.rs :75-84  trait doc: "Does nothing if there is no entry. Deletes the entry if either counter would overflow."
//   mpl/src/cmc/operation.rs :361-372  UpdateUsageMetadataInput { identifier: Vec<u8>, bytes_used: u64 }
//   mpl/src/cmc/default.rs :120-125, mpl/src/cmc/storm_tracking.rs :757-762  forwarders
//   lru 0.18.5 (`Cargo.toml` :22 `lru = "0.18.5"`): `peek` is `map.get`, `pop` is `map.remove` plus unlink.
//   Tests (not proofs): mpl/tests/test_local_cmc.rs :695, :715, :729; test_shared_handles.rs :179.
//   Only `impl Cmc for` types in mpl/src and esdk/src: Builtin<LocalCmc>, Builtin<StormTrackingCmc>,
//   Builtin<DefaultCmc> (grep). The counter fields appear in no file of mpl/src or esdk/src other than
//   entry.rs, operation.rs and the fluent builders (grep for `messages_used`, `bytes_used`).
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code)
// =============================================================================
//   model                         shipped
//   ----------------------------  -----------------------------------------------------------
//   UM { messages, bytes }        UsageMetadata { messages_used: u64, bytes_used: u64 }, entry.rs :39-41
//   record_use (exec)             CacheEntry::record_use :206-223, with `&mut UM` for the mutex guard
//   record_use_spec               the same, as a function from (counters, bytes) to (counters, ok)
//   would_overflow                `checked_add(1)` is None or `checked_add(bytes)` is None (:213-214)
//   Cache.entries                 the LruCache map inside `store` (local.rs :62, :326-342)
//   Cache.poisoned                `store.lock()` is Err (:331-334)
//   update_spec                   LocalCmc::update_usage_metadata :326-342
//   step_entry, run_entry         the effect of the same call on one identifier, then over a sequence
//   Call { id, bytes }            UpdateUsageMetadataInput { identifier, bytes_used }
//   update_slot (exec)            the `if let Some(entry) = peek ... { if !record_use { pop } }` core
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED
// =============================================================================
// Spec-derived: only atomicity. spec/framework/cryptographic-materials-cache.md :93 "Updating
// usage metadata SHOULD be atomic." R1 (both-or-neither) and A_LOCK_EXCL give the model form of it.
// Code-derived: everything else. The spec has no "update usage metadata" operation and no overflow
// rule (grep for "update" and "overflow" in the three cache spec files finds only :152 and two
// storm-tracking lines). The YAML field `trace_to_spec` cites `#update-usage-metadata`; that
// heading does not exist in the spec checkout (spec submodule e833453). It is a documentation
// note, not a code gap. The "overflow evicts the entry" rule comes from the trait doc (mod.rs :75-79)
// and the implementation.
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
//  attribute is written in this file, and there is no uninterpreted spec function. The one
//  `assume_specification` that the proof relies on is in vstd (A_VSTD).
//
//  A_VSTD (ASSUMED). Verus, Z3, the vstd `Seq` and `Map` axioms, and vstd's
//    `assume_specification[u64::checked_add]` (vstd/std_specs/num.rs): the result is None when
//    x + y > u64::MAX and Some(x + y) otherwise. `checked_add_by_hand` proves that a plain
//    comparison gives the same result, so the assumption is cross-checked, not only taken.
//  A_LOCK_EXCL (ASSUMED). A held `MutexGuard` gives exclusive access to its data. The model runs
//    calls one at a time. Each call is atomic. The real code can run calls on several threads;
//    the model covers them only as some serial order.
//  A_NO_ALIAS (ASSUMED, for the clause "no other identifier changes" of R3, and for R4 and R5).
//    No `CacheEntry` handle (the original or any clone) is stored under two identifiers, so
//    distinct identifiers have distinct counter cells. The model `Map<Id, UM>` gives each
//    identifier its own counters, which is exactly this premise. The code does not enforce it:
//    the map holds `CacheEntry` handles (an `Arc<CacheEntryInner>` with a `Mutex<UsageMetadata>`,
//    entry.rs :136-146), `PutCacheEntryInput` is `Clone` and carries a `CacheEntry` by value
//    (operation.rs :11-31), `put_cache_entry` does `cache.put(identifier, entry)` (local.rs
//    :280-300), and `get_cache_entry` returns a clone (local.rs :148). So it is a premise about
//    callers. R1, R2, R7 and the evict-the-addressed-slot rule do not need it.
//  A_ALL_CALLS (ASSUMED, for R4 and R5 only). Every change to the counters of a cell goes
//    through `update_usage_metadata` addressed to the identifier that holds it (together with
//    A_NO_ALIAS, `calls` then lists all of them). `record_use` is `pub`, and the entry builder
//    lets a caller set the initial counters, so this is a premise about callers.
//  A_NO_PUT (ASSUMED, for R4 and R5 only). During the call sequence no `put` replaces the entry
//    for the identifier and no other operation changes the map. A `put` with new counters would
//    start a new run; a `delete` is an eviction by another route.
//  H_STD_CHECKED_ADD (CODE READING, std). `u64::checked_add` returns None exactly when the
//    mathematical sum exceeds u64::MAX. This is the documented std contract.
//  H_ONLY_SITES (CODE READING). The only arithmetic on `messages_used` and `bytes_used` in mpl/src
//    and esdk/src is the two `checked_add` calls at entry.rs :213-214. The only writes are
//    :218-219 and the builder (:121-122, :327). The fields are private and `UsageMetadata` is
//    `#[non_exhaustive]` (grep).
//  H_NO_PANIC_IN_GUARD (CODE READING). Between the lock (:209-212) and the return, record_use
//    runs two `checked_add` calls, one tuple pattern and two stores. None can panic. So the entry
//    mutex is not poisoned by record_use, and the stores cannot be interrupted between the two
//    writes. The lock also ignores poison (`PoisonError::into_inner`), so a poisoned entry mutex
//    does not make the call fail or panic.
//  H_STORE_FLOW (CODE READING). update_usage_metadata takes `store` once (:326-334), runs
//    `peek`, `record_use` and at most one `pop` under that guard, and returns Ok(default) on every
//    path after the lock. A poisoned `store` returns Err before any change.
//  H_LRU_OPS (CODE READING, lru 0.18.5). `peek(k)` does not change the map or the order. `pop(k)`
//    removes the key `k` and no other key.
//  H_BUILDER_ANY (CODE READING). The initial counters can be any pair of u64 values (builder
//    :74-77, :95-98, :296-298), including u64::MAX. The theorems quantify over all pairs. They do
//    not assume the counters start small.
//  H_DELEGATION (CODE READING). DefaultCmc and StormTrackingCmc add no logic to the call (see
//    the line numbers above). A `Cmc` implemented outside this repository is not covered.
//  H_ARC_SHARED (CODE READING). A `CacheEntry` clone shares the Arc and the counters
//    (entry.rs :132-138), and `get_fresh` returns a clone (local.rs :148). A clone can also be
//    passed to `put_cache_entry` under another identifier (PutCacheEntryInput is Clone,
//    operation.rs :11-31; local.rs :280-300). That is why A_NO_ALIAS is a separate premise.
//  H_MODEL_MATCH (CODE READING). The model functions have the same inputs and the same order of
//    operations as the lines named in section 2. Checked by reading; not machine-checked.
// =============================================================================
// 5. FINDINGS AND OBSERVATIONS
// =============================================================================
//  F0 (no gap). The code cannot wrap and cannot panic at any legal input. The model with the
//    real widths verifies. There is no EXPECTED_FAIL obligation. Not invented.
//  O1 (observation, not a wrap and not a gap). Eviction removes the map slot. It does not freeze
//    the shared cell. A handle taken earlier from `get_cache_entry` still accepts `record_use`, and
//    after a failed call on a message count below the maximum, a later call on that handle with
//    fewer bytes can succeed (`lemma_evicted_handle_is_not_frozen`). The counters stay exact. Whether
//    that matters depends on a future caching CMM; none exists in the repository.
//  O2 (documentation). The YAML `trace_to_spec` anchor `#update-usage-metadata` does not exist
//    in the spec checkout (section 3).
//  O3 (scope). No in-repo code calls `update_usage_metadata`. The property is robustness for a
//    future caller.
//  O4 (observation, not a wrap and not an EXPECTED_FAIL). One handle can be stored under two
//    identifiers through the public API (A_NO_ALIAS, section 4), so the counters seen under an
//    identifier can change through a call addressed to another. Per-call no wrap and
//    both-or-neither (R1, R2) still hold. The proved per-identifier totals do not cover that
//    state. No obligation fails in the model, because the model excludes aliasing by
//    construction.
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Types and the single-call specification (R1)
// ============================================================

/// UsageMetadata (entry.rs :39-41). Both counters are u64.
pub struct UM {
    pub messages: u64,
    pub bytes: u64,
}

/// The sum `messages + 1` or `bytes + b` passes u64::MAX. Integer (unbounded) arithmetic.
pub open spec fn would_overflow(u: UM, b: u64) -> bool {
    u.messages as int + 1 > u64::MAX as int || u.bytes as int + b as int > u64::MAX as int
}

/// The effect of `record_use(b)`: (new counters, returned bool). The casts `as u64` only run in
/// the no-overflow branch, where they are the identity.
pub open spec fn record_use_spec(u: UM, b: u64) -> (UM, bool) {
    if would_overflow(u, b) {
        (u, false)
    } else {
        (UM { messages: (u.messages as int + 1) as u64, bytes: (u.bytes as int + b as int) as u64 }, true)
    }
}

/// R1: exact sums on success, both unchanged on failure, success iff no overflow.
proof fn theorem_record_use_spec(u: UM, b: u64)
    ensures
        record_use_spec(u, b).1 == !would_overflow(u, b),
        record_use_spec(u, b).1 ==> ({
            let w = record_use_spec(u, b).0;
            &&& w.messages as int == u.messages as int + 1
            &&& w.bytes as int == u.bytes as int + b as int
        }),
        !record_use_spec(u, b).1 ==> record_use_spec(u, b).0 == u,
{
}

/// Failure is exactly: the message count is at the maximum, or the byte count cannot take b.
proof fn theorem_overflow_cases(u: UM, b: u64)
    ensures
        would_overflow(u, b) <==> (u.messages == u64::MAX || b as int > u64::MAX as int - u.bytes as int),
{
}

/// Both-or-neither: the byte sum overflows, the message count would not, and neither changes.
proof fn lemma_no_partial_update()
    ensures
        ({
            let u = UM { messages: 0, bytes: u64::MAX };
            let r = record_use_spec(u, 1);
            &&& !r.1
            &&& r.0.messages == 0
            &&& r.0.bytes == u64::MAX
        }),
{
}

// ============================================================
// SECTION 2: Executable model of record_use (R2)
// ============================================================

/// `checked_add` written as a comparison. It equals `u64::checked_add` (A_VSTD cross-check).
fn checked_add_by_hand(a: u64, b: u64) -> (r: Option<u64>)
    ensures
        r == a.checked_add(b),
        r is Some <==> a as int + b as int <= u64::MAX as int,
        r matches Some(s) ==> s as int == a as int + b as int,
{
    if a <= u64::MAX - b {
        Some(a + b)
    } else {
        None
    }
}

/// entry.rs :206-223. `u` stands for the locked `UsageMetadata` (A_LOCK_EXCL). Verus checks that
/// no step can overflow or panic, for every u64 input, and that the contract of R1 holds.
fn record_use(u: &mut UM, b: u64) -> (r: bool)
    ensures
        (*final(u), r) == record_use_spec(*old(u), b),
        r == !would_overflow(*old(u), b),
        r ==> final(u).messages as int == old(u).messages as int + 1,
        r ==> final(u).bytes as int == old(u).bytes as int + b as int,
        !r ==> *final(u) == *old(u),
{
    // entry.rs :213-214: both sums are computed before anything is written.
    let m = u.messages.checked_add(1);
    let t = u.bytes.checked_add(b);
    match (m, t) {
        (Some(messages), Some(total_bytes)) => {
            // entry.rs :218-219
            u.messages = messages;
            u.bytes = total_bytes;
            true
        },
        _ => false,
    }
}

// ============================================================
// SECTION 3: The cache and one update_usage_metadata call (R3)
// ============================================================

pub type Id = Seq<u8>;

/// The `store` mutex content: identifier -> counters, and whether the lock is poisoned. A cache
/// with no store (capacity 0) is the same as an empty map for this call (`as_mut()` is None).
pub struct Cache {
    pub entries: Map<Id, UM>,
    pub poisoned: bool,
}

/// UpdateUsageMetadataInput.
pub struct Call {
    pub id: Id,
    pub bytes: u64,
}

pub enum Res {
    Ok,
    ErrInternal,
}

/// local.rs :326-342.
pub open spec fn update_spec(c: Cache, call: Call) -> (Res, Cache) {
    if c.poisoned {
        (Res::ErrInternal, c)
    } else if !c.entries.contains_key(call.id) {
        (Res::Ok, c)
    } else {
        let r = record_use_spec(c.entries[call.id], call.bytes);
        if r.1 {
            (Res::Ok, Cache { entries: c.entries.insert(call.id, r.0), poisoned: c.poisoned })
        } else {
            (Res::Ok, Cache { entries: c.entries.remove(call.id), poisoned: c.poisoned })
        }
    }
}

/// R3, poisoned store: Err(Internal) and no change at all.
proof fn lemma_poisoned_store_is_noop(c: Cache, call: Call)
    requires
        c.poisoned,
    ensures
        update_spec(c, call).0 == Res::ErrInternal,
        update_spec(c, call).1 == c,
{
}

/// R3: one call on an unpoisoned cache. The clause "no other identifier changes" is relative to
/// A_NO_ALIAS: the model `Map<Id, UM>` gives each identifier its own counters, but the code can
/// store one shared `CacheEntry` handle under two identifiers, and then a call for one changes
/// what the other shows. The other clauses do not depend on A_NO_ALIAS.
proof fn theorem_update_step(c: Cache, call: Call)
    requires
        !c.poisoned,
    ensures
        update_spec(c, call).0 == Res::Ok,
        !update_spec(c, call).1.poisoned,
        // an absent identifier: nothing changes
        !c.entries.contains_key(call.id) ==> update_spec(c, call).1 == c,
        // a present identifier is evicted exactly when record_use fails
        c.entries.contains_key(call.id) ==> (
            update_spec(c, call).1.entries.contains_key(call.id)
                <==> !would_overflow(c.entries[call.id], call.bytes)),
        // otherwise its counters are the exact sums
        c.entries.contains_key(call.id) && !would_overflow(c.entries[call.id], call.bytes) ==> ({
            let u = c.entries[call.id];
            let w = update_spec(c, call).1.entries[call.id];
            &&& w.messages as int == u.messages as int + 1
            &&& w.bytes as int == u.bytes as int + call.bytes as int
        }),
        // no other identifier changes
        forall|k: Id| #![trigger c.entries.contains_key(k)] k != call.id ==> (
            update_spec(c, call).1.entries.contains_key(k) == c.entries.contains_key(k)
                && (c.entries.contains_key(k) ==> update_spec(c, call).1.entries[k] == c.entries[k])),
        // no identifier appears
        forall|k: Id| #![trigger update_spec(c, call).1.entries.contains_key(k)]
            update_spec(c, call).1.entries.contains_key(k) ==> c.entries.contains_key(k),
{
    if c.entries.contains_key(call.id) {
        let r = record_use_spec(c.entries[call.id], call.bytes);
        if r.1 {
            assert(c.entries.insert(call.id, r.0).contains_key(call.id));
        }
    } else {
        assert(update_spec(c, call).1 == c);
    }
}

// ============================================================
// SECTION 4: One entry over a sequence of calls (R4)
// ============================================================

/// The state of one identifier: Some(counters) or None (absent or evicted).
pub open spec fn get(c: Cache, id: Id) -> Option<UM> {
    if c.entries.contains_key(id) { Some(c.entries[id]) } else { None }
}

/// One call on one identifier. None stays None. Some(u) becomes Some(sum) or None (evicted).
pub open spec fn step_entry(e: Option<UM>, b: u64) -> Option<UM> {
    match e {
        None => None,
        Some(u) => {
            let r = record_use_spec(u, b);
            if r.1 { Some(r.0) } else { None }
        },
    }
}

pub open spec fn run_entry(e: Option<UM>, bs: Seq<u64>) -> Option<UM>
    decreases bs.len(),
{
    if bs.len() == 0 { e } else { run_entry(step_entry(e, bs[0]), bs.drop_first()) }
}

/// Exact sum of the byte counts, in unbounded integers.
pub open spec fn sum_bytes(bs: Seq<u64>) -> int
    decreases bs.len(),
{
    if bs.len() == 0 { 0 } else { bs[0] as int + sum_bytes(bs.drop_first()) }
}

proof fn lemma_sum_nonneg(bs: Seq<u64>)
    ensures
        sum_bytes(bs) >= 0,
    decreases bs.len(),
{
    if bs.len() > 0 {
        lemma_sum_nonneg(bs.drop_first());
    }
}

/// Once the entry is gone, later calls do nothing. Eviction is permanent for the cache.
proof fn lemma_run_entry_absent_stays_absent(bs: Seq<u64>)
    ensures
        run_entry(None, bs) is None,
    decreases bs.len(),
{
    if bs.len() > 0 {
        lemma_run_entry_absent_stays_absent(bs.drop_first());
    }
}

/// R4. For ANY start counters and ANY byte counts (n = bs.len() calls):
///   the entry survives  iff  messages + n <= MAX  and  bytes + sum <= MAX;
///   if it survives, its counters are exactly messages + n and bytes + sum (nothing wrapped).
/// So the entry is never evicted early (while the exact totals fit) and never kept after the
/// exact totals pass u64::MAX.
proof fn theorem_run_entry(u: UM, bs: Seq<u64>)
    ensures
        run_entry(Some(u), bs) is Some
            <==> (u.messages as int + bs.len() <= u64::MAX as int
            && u.bytes as int + sum_bytes(bs) <= u64::MAX as int),
        run_entry(Some(u), bs) matches Some(w) ==> (
            w.messages as int == u.messages as int + bs.len()
                && w.bytes as int == u.bytes as int + sum_bytes(bs)),
    decreases bs.len(),
{
    if bs.len() > 0 {
        lemma_sum_nonneg(bs.drop_first());
        lemma_run_entry_absent_stays_absent(bs.drop_first());
        let r = record_use_spec(u, bs[0]);
        if r.1 {
            theorem_run_entry(r.0, bs.drop_first());
        }
    }
}

// ============================================================
// SECTION 5: The cache over a sequence of calls (R5)
// ============================================================

pub open spec fn run_cache(c: Cache, calls: Seq<Call>) -> Cache
    decreases calls.len(),
{
    if calls.len() == 0 { c } else { run_cache(update_spec(c, calls[0]).1, calls.drop_first()) }
}

/// The byte counts addressed to `id`, in call order.
pub open spec fn bytes_for(calls: Seq<Call>, id: Id) -> Seq<u64>
    decreases calls.len(),
{
    if calls.len() == 0 {
        Seq::empty()
    } else if calls[0].id == id {
        seq![calls[0].bytes] + bytes_for(calls.drop_first(), id)
    } else {
        bytes_for(calls.drop_first(), id)
    }
}

/// One call, seen on one identifier: it is `step_entry` on that identifier and nothing on the others.
proof fn lemma_update_simulates(c: Cache, call: Call, id: Id)
    requires
        !c.poisoned,
    ensures
        !update_spec(c, call).1.poisoned,
        get(update_spec(c, call).1, id)
            == if call.id == id { step_entry(get(c, id), call.bytes) } else { get(c, id) },
{
    theorem_update_step(c, call);
    if call.id == id && c.entries.contains_key(id) {
        let r = record_use_spec(c.entries[id], call.bytes);
        if r.1 {
            assert(c.entries.insert(id, r.0).contains_key(id));
        }
    }
}

/// R5: for any calls on any identifiers, each identifier follows the single-entry run of R4.
/// Relative to A_NO_ALIAS (no handle stored under two identifiers; the code does not enforce
/// it), A_ALL_CALLS and A_NO_PUT.
proof fn theorem_cache_refines_entry_run(c: Cache, calls: Seq<Call>, id: Id)
    requires
        !c.poisoned,
    ensures
        !run_cache(c, calls).poisoned,
        get(run_cache(c, calls), id) == run_entry(get(c, id), bytes_for(calls, id)),
    decreases calls.len(),
{
    if calls.len() > 0 {
        let c1 = update_spec(c, calls[0]).1;
        lemma_update_simulates(c, calls[0], id);
        theorem_cache_refines_entry_run(c1, calls.drop_first(), id);
        if calls[0].id == id {
            let bs = bytes_for(calls, id);
            let rest = bytes_for(calls.drop_first(), id);
            assert(bs =~= seq![calls[0].bytes] + rest);
            assert(bs[0] == calls[0].bytes);
            assert(bs.drop_first() =~= rest);
        }
    }
}

/// R5 summary. For any unpoisoned cache, any call sequence, any identifier:
///  (a) an entry present at the start survives iff the exact totals (n calls addressed to it, sum of
///      their byte counts) do not pass u64::MAX;
///  (b) if it survives, its counters are exactly start + n and start + sum;
///  (c) an identifier that was absent is absent at the end.
/// Relative to A_NO_ALIAS, A_ALL_CALLS, A_NO_PUT and A_LOCK_EXCL. Under aliasing (one handle
/// under two identifiers) the totals per identifier do not hold; per-call no wrap (R1) still does.
proof fn theorem_no_wrap_any_calls(c: Cache, calls: Seq<Call>, id: Id)
    requires
        !c.poisoned,
    ensures
        c.entries.contains_key(id) ==> (
            run_cache(c, calls).entries.contains_key(id)
                <==> (c.entries[id].messages as int + bytes_for(calls, id).len() <= u64::MAX as int
                && c.entries[id].bytes as int + sum_bytes(bytes_for(calls, id)) <= u64::MAX as int)),
        c.entries.contains_key(id) && run_cache(c, calls).entries.contains_key(id) ==> ({
            let u = c.entries[id];
            let w = run_cache(c, calls).entries[id];
            &&& w.messages as int == u.messages as int + bytes_for(calls, id).len()
            &&& w.bytes as int == u.bytes as int + sum_bytes(bytes_for(calls, id))
        }),
        !c.entries.contains_key(id) ==> !run_cache(c, calls).entries.contains_key(id),
{
    theorem_cache_refines_entry_run(c, calls, id);
    lemma_run_entry_absent_stays_absent(bytes_for(calls, id));
    if c.entries.contains_key(id) {
        theorem_run_entry(c.entries[id], bytes_for(calls, id));
    }
}

// ============================================================
// SECTION 6: Witnesses at the maximum (R6)
// ============================================================

/// Off-by-one at the maximum, in both directions, for both counters (the cases of
/// mpl/tests/test_local_cmc.rs :729 and their neighbours).
proof fn lemma_boundary_witnesses()
    ensures
        // message count: MAX - 1 is accepted and gives MAX; MAX is rejected, even with zero bytes
        record_use_spec(UM { messages: (u64::MAX - 1) as u64, bytes: 0 }, 0).1,
        record_use_spec(UM { messages: (u64::MAX - 1) as u64, bytes: 0 }, 0).0.messages == u64::MAX,
        !record_use_spec(UM { messages: u64::MAX, bytes: 0 }, 0).1,
        // byte count: reaching MAX exactly is accepted; one more is rejected
        record_use_spec(UM { messages: 0, bytes: (u64::MAX - 5) as u64 }, 5).1,
        record_use_spec(UM { messages: 0, bytes: (u64::MAX - 5) as u64 }, 5).0.bytes == u64::MAX,
        !record_use_spec(UM { messages: 0, bytes: (u64::MAX - 5) as u64 }, 6).1,
        // u64::MAX bytes from zero is accepted, then a one-byte message is rejected
        record_use_spec(UM { messages: 0, bytes: 0 }, u64::MAX).1,
        !record_use_spec(record_use_spec(UM { messages: 0, bytes: 0 }, u64::MAX).0, 1).1,
{
}

/// O1: a failed call leaves the shared cell unchanged, so a handle that still points at it can
/// succeed later. The slot is evicted; the cell is not frozen.
proof fn lemma_evicted_handle_is_not_frozen()
    ensures
        ({
            let u = UM { messages: 0, bytes: u64::MAX };
            let first = record_use_spec(u, 1);
            let second = record_use_spec(first.0, 0);
            &&& !first.1
            &&& first.0 == u
            &&& second.1
            &&& second.0.messages == 1
            &&& second.0.bytes == u64::MAX
        }),
{
}

// ============================================================
// SECTION 7: Executable model of the single-entry call (R7)
// ============================================================

/// The `peek` / `record_use` / `pop` core of local.rs :336-340 for one slot: None is "no entry".
fn update_slot(slot: Option<UM>, b: u64) -> (r: Option<UM>)
    ensures
        r == step_entry(slot, b),
        r is Some ==> !would_overflow(slot->Some_0, b),
        slot is Some && !would_overflow(slot->Some_0, b) ==> r is Some,
{
    match slot {
        None => None,
        Some(mut u) => {
            let ok = record_use(&mut u, b);
            if ok {
                Some(u)
            } else {
                // local.rs :339 `cache.pop(input.identifier())`
                None
            }
        },
    }
}

} // verus!

fn main() {}
