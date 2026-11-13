# Design Doc — Binding the Verus Proofs to Shipped ESDK Code

**Status:** Draft for team discussion

**Author:** Mahnush

**Date:** September 2026

**Scope:** How to convert the current out-of-crate Verus *models* into verification of *actual shipped* code, across (1) the ESDK parsing/message layer and (2) the Material Providers Library (MPL) — its cryptographic-materials structures and keyring/CMM/keystore logic.

**Related:** `docs/verus-proofs-report.md`, `docs/verification-recommendations.md`, `docs/threat-model.md`, `verification/README.md`, `.kiro/steering/verus-verification.md`

> **Update (this revision):** extended beyond the ESDK message layer to cover a planned Verus verification effort for the **MPL and MPL primitives** (`mpl/` = `aws-crypto-mpl`, and the primitives in `prim/`). See §2.5 (MPL scope & layering), the MPL rows added to the options in §§3–5, and the MPL-specific open questions in §8.

> **Status (2026-11-12, branch `verus-in-crate-esdk`):** **Option A was chosen and is being implemented** for the ESDK. The §2 evidence below predates the `main` merge (`a891e52`) and no longer matches the code: `SafeRead`/`SafeWrite` are gone, the readers are now `async fn`s over `&mut dyn Source` (tokio `AsyncRead`, `esdk/src/shapes.rs`) that mirror bytes into `&mut Tee` (`dyn Write + Send`), `esdk` no longer depends on `aws-mpl-legacy`, and `cargo-verus` verifies `esdk` while building its dependencies (`aws-lc-rs`, `tokio`, `aws-sdk-*`, `mpl`, `prim`) with plain rustc. The approach in use is pure synchronous `verus!` cores called by the unverified async adapters; `make -C esdk verus` reports `19 verified, 0 errors`. The verified fn list and the trusted boundaries are in `docs/verus-proofs-report.md` ("In-crate proofs"). The rest of this doc is left as written.

---

## 1. Problem statement

We have Verus proofs for the ESDK message layer — 71 obligations, 0 errors, covering header parsing (VR-003), frame sequence (VR-004), frame layout (VR-005), header-auth ordering (VR-002), EDK count (VR-007), zeroization (VR-010), and AES-GCM buffer bounds (VR-006, non-FFI part). They live in `verification/`, run via `make -C verification verify`.

**The gap:** every proof is a **faithful, self-contained model** of a function — the same executable body plus `requires`/`ensures`, written in a standalone file that imports nothing from the `esdk` crate. The proofs are therefore *not* verifying the shipped code. Two concrete consequences:

1. **Drift risk.** If someone edits `esdk/src/message/serialize_functions.rs`, the Verus models still print "verified, 0 errors" while silently modeling stale source. Today the only defense is manual file comparison (which we did after the last `main` merge — see `docs/verus-proofs-report.md`).
2. **Weaker headline.** The honest claim is "we have verified models of the ESDK parser," not "the ESDK parser is verified."

**Goal:** close the drift risk and strengthen the claim, with a change that (a) an AWS-owned repo's review process would accept, and (b) respects the Verus soundness invariants (no `assume`/`external_body`/`admit` to fake a pass).

**Additional goal (MPL):** the same approach should extend to the Material Providers Library. The MPL is where several of the highest-severity threats live — key commitment (VR-001, the CVE-2020-8897 class), branch-key wrapping/unwrapping, MRK matching, and the cache-entry identifier byte layout. Today there are **no** MPL proofs at all. This doc now treats "which MPL logic is Verus-tractable, and through which seam" as a first-class question alongside the ESDK parsing layer.

---

## 2. Why "just wrap it in `verus!`" does not work

Investigation of the coupling (files/lines below) shows a true in-crate wrap is blocked by three compounding facts:

1. **Verus compiles at crate granularity.** It invokes rustc over the crate root (`esdk/src/lib.rs`), so verifying one module means compiling the *entire* `esdk` crate.
2. **`esdk`'s heavy deps are unconditional.** `aws-lc-rs`, `tokio`, `aws-sdk-kms`, `aws-sdk-dynamodb`, and the Dafny-backed `aws-mpl-legacy` are plain dependencies in `esdk/Cargo.toml` (not behind any feature). No feature combination drops them, and there is **no workspace root** — `esdk` builds standalone. Verus cannot build this dependency set.
3. **Every reader/writer is coupled to trait objects.** All `read_*`/`write_*` in `serialize_functions.rs` take `&mut dyn SafeRead` / `&mut dyn SafeWrite` (`std::io::Read`/`Write` + `Send + Sync + Debug`). Verus cannot model `dyn` trait objects or `std::io`. Even the surrounding modules pull in MPL: `types.rs` (which *defines* the traits) imports `aws_mpl_legacy::*`, `message/mod.rs` imports `aws_mpl_legacy::primitives::DigestContext`, and `error.rs` has `From` impls over `aws_mpl_legacy` error types.

**Evidence (exact locations):**
- `esdk/src/message/serialize_functions.rs` — all 15 `read_*`/`write_*` fns take `dyn SafeRead`/`dyn SafeWrite`; imports `crate::error::{Error, ErrorKind, ser_err}`, `crate::types::{SafeRead, SafeWrite}`.
- `esdk/src/types.rs:185,199` — `SafeWrite: std::io::Write + Send + Sync + Debug`, `SafeRead: std::io::Read + Send + Sync + Debug`, with blanket impls; module top imports `aws_mpl_legacy::{CryptographicMaterialsManagerRef, KeyringRef, dafny::...}`.
- `esdk/src/message/mod.rs:22` — `use aws_mpl_legacy::primitives::DigestContext;`
- `esdk/Cargo.toml:15–24` — `aws-lc-rs`, `tokio` unconditional; features `default/fips/track/kms/legacy/ddb` do not drop them.
- No `cfg(verus...)`/`verus_keep_ghost` gates exist in shipping source (only in `.kiro` prose).

**Conclusion:** binding proofs to shipped code requires a *structural* change that isolates the pure byte logic from the trait objects and the heavy dep graph. The three options below differ in how far that isolation goes.

---

## 2.5 MPL scope and layering (new)

The plan extends verification to the **Material Providers Library**. In this repo that is the native `mpl/` crate (`aws-crypto-mpl`) plus the primitives crate `prim/` (`aws-mpl-primitives`). The MPL is where the highest-severity threats concentrate (key commitment, branch-key wrap/unwrap, MRK matching), so it is high-value — but it has the **same crate-granularity build blocker** as `esdk`, and a heavy dep graph of its own.

**MPL dep graph (`mpl/Cargo.toml`):** `aws-config`, `aws-sdk-kms`, `aws-sdk-dynamodb`, `tokio`, `lru`, `time`, `uuid`, `base64`, and `aws-mpl-primitives` (`prim/`, which wraps `aws-lc-rs`). None Verus-buildable. So, exactly as with `esdk`, wrapping any `mpl/` module in `verus!` compiles the whole crate and fails. `prim/`, by contrast, depends **only on `aws-lc-rs`** — its logic is FFI wrappers, so the crypto is out of scope but the surrounding length/bounds logic is the same partial story as VR-006.

**Layering — from most to least Verus-tractable.** The key insight is that the MPL splits cleanly into pure-logic vs. I/O-bound layers:

| MPL layer | Files | Verus tractability | Notes |
|-----------|-------|--------------------|-------|
| **Materials structures** | `mpl/src/structures/*` (algorithm_suite, encryption_context, encrypted_data_key, {encryption,decryption,branch_key,beacon_key}_materials, commitment_policy, error) | **High** — mostly pure data + invariants | Prime targets: field/length invariants, encryption-context (de)serialization/canonicalization, EDK structure. Includes the `write_volatile` zeroization already proven (VR-010) in `algorithm_suite.rs`. |
| **Byte-layout / matching / KDF logic** | `mpl/src/aws_kms/{cache_entry_identifier, mrk_match, branch_key_wrap}.rs` | **High–Medium** — pure functions over bytes/strings | `cache_entry_identifier` byte layout (the crate already has a std digest oracle test for it), MRK ARN matching, branch-key wrap/unwrap AAD construction & fixed-size slicing (the `.expect(...)` sites in the threat model). |
| **Key commitment** | `mpl` commit-key derivation + the ESDK-side `validate_suite_data` constant-time compare | **Medium** — logic modelable; HKDF primitive is FFI | This is **VR-001**, the CVE-2020-8897 class. The extract-then-two-expands *structure* and the constant-time comparison decision are modelable; the HKDF math itself is `aws-lc-rs` (out of scope). |
| **CMM / cache** | `mpl/src/cmm/*`, `mpl/src/cmc/*` (default CMM, local + storm-tracking cache, LRU) | **Medium–Low** | Cache eligibility/TTL decisions and the storm-tracking state machine are modelable as pure logic; the `lru`/`time`/concurrency parts are not. |
| **Keyring / keystore I/O** | `mpl/src/keyring/*`, `mpl/src/keystore/*`, `mpl/src/aws_kms/hierarchical_keyring.rs`, `kms_ops.rs`, `kms_config.rs` | **Low** | Dominated by `aws-sdk-kms`/`aws-sdk-dynamodb`/`tokio` async I/O — out of Verus scope, same as the aws-lc-rs FFI. Only surrounding bounds/validation logic is provable. |

**Important prioritization caveat.** The native `mpl/` crate is **not currently on the ESDK dependency path** — the shipping ESDK still routes CMM/keyring work through the Dafny-backed `unsafe-unreviewed-mpl` (`aws-mpl-legacy`). So MPL proofs today verify the *native replacement* MPL, not what the ESDK actually executes end-to-end. That is fine and forward-looking (the native MPL is the intended future), but the team should decide whether MPL verification tracks the native `mpl/` (bet on the future) or must also address the legacy Dafny shim (which is an external, non-auditable artifact — see `docs/threat-model.md` §12.2 / RR5). **Recommendation: target native `mpl/`; treat the Dafny shim as out of scope / trusted, and note the residual explicitly.**

**Consequence for the options.** The same three structural options apply to the MPL, with one addition: because the *materials structures* are pure data types, the cleanest MPL seam is often not "extract a crate" but "verify the structures and their pure helpers directly once the crate can be Verus-built" — which still requires solving the crate-granularity/dep-graph problem (Option A-style) unless the pure logic is extracted (Option B-style into e.g. `mpl-core`).

---

## 3. Option A — Thread Verus through `esdk` in place

**Idea.** Introduce a slice-based reader/writer core *inside* `esdk`, reroute the `dyn` functions through it, and put `verus! {}` around the core, verified as part of the `esdk` crate build (via `cargo-verus`).

**What it requires.**
- A `&[u8]`+cursor reader and `&mut Vec<u8>` writer core in `serialize_functions.rs`; the `dyn SafeRead`/`dyn SafeWrite` functions become thin adapters that read into a buffer then delegate.
- An `Error` path Verus can handle (the current `Error` carries `Arc<Backtrace>` and `Arc<dyn Error>` — not Verus-friendly), likely a plain error enum behind the seam.
- Making the *whole `esdk` crate* Verus-buildable — i.e. getting `aws-lc-rs`/`tokio`/`aws-mpl-legacy` past `cargo-verus`, or gating them out of the verified build. This is the hard, possibly infeasible part.

**Pros.**
- Proofs bind directly to the shipped functions in their real module — the strongest form of "the parser is verified."
- No new crate boundary.

**Cons / risks.**
- **Likely infeasible without also making the entire crate's dependency graph Verus-buildable**, which includes the Dafny-backed MPL and aws-lc-rs. This is a large, uncertain yak-shave.
- Largest blast radius on shipping code; every reviewer of `esdk` is affected.
- Risk of pressure to reach for `#[cfg(not(verus_keep_ghost))]` or `external_body` to hide the un-buildable deps — which the soundness invariants forbid and which would produce a green-but-meaningless result.

**Effort:** High / uncertain (weeks; may hit a wall on the dep graph).
**Assurance:** Highest *if* achievable.
**Applies to MPL?** In principle — thread Verus through `mpl/` in place. Same verdict, more so: `mpl/`'s dep graph (`aws-config`, `aws-sdk-*`, `tokio`, `lru`, `time`, `uuid`, `prim`→`aws-lc-rs`) is at least as un-buildable as `esdk`'s, so this is high/uncertain for MPL too.

**Recommendation:** Not first. Only pursue if Option B proves insufficient.

---

## 4. Option B — Extract a dependency-free `esdk-wire` crate (recommended)

**Idea.** Move the pure byte-parsing core into a new, tiny crate with **no** `aws-lc-rs`/`tokio`/MPL dependencies. `esdk` depends on it; the Verus proofs depend on the *same* source. The `dyn SafeRead`/`dyn SafeWrite` functions in `esdk` become thin adapters over the new crate.

```
                    ┌─────────────────────────┐
                    │  esdk-wire (new crate)   │
                    │  - ByteReader (&[u8]+cur)│   <-- verus! {} here; std-only
                    │  - read_u8/16/32/64, ...  │       (no aws-lc-rs/tokio/MPL)
                    │  - length-prefixed reads  │
                    │  - big-endian spec fns    │
                    └───────────┬──────────────┘
                        depends on │ (source of truth)
              ┌──────────────────┴───────────────────┐
              ▼                                        ▼
   ┌────────────────────┐                   ┌────────────────────┐
   │  esdk crate         │                   │  verification/     │
   │  serialize_functions│                   │  Verus proofs run  │
   │  = dyn adapters that│                   │  against esdk-wire │
   │  read into a buf,   │                   │  (the SAME source) │
   │  then call esdk-wire│                   └────────────────────┘
   └────────────────────┘
```

**What it requires.**
- New crate `esdk-wire` (std-only): the `ByteReader` (`&[u8]` + cursor), the fixed-width and length-prefixed readers, and the big-endian `spec_u32_be`/`spec_u64_be` source-of-truth. This is essentially promoting today's `verification/io_stream_aligned.rs` model into shipping source.
- A self-contained error type in `esdk-wire` (plain enum, no `Backtrace`/`dyn`); `esdk` maps it into `crate::error::Error` at the adapter boundary.
- `esdk`'s `serialize_functions.rs` reworked: the `dyn SafeRead` functions read the required bytes into a scratch buffer (they already do, into fixed arrays / `Vec`), then call the `esdk-wire` parser on the slice. The `raw`-mirror behavior stays in the `esdk` adapter.
- Verus runs over `esdk-wire` — which *is* buildable because it's std-only — so the proofs bind to shipped code.

**Pros.**
- **Removes the drift caveat for real:** the verified code is the shipped `esdk-wire` code, not a mirror. A change to the wire core that violates a contract fails `cargo-verus`.
- **Contained blast radius:** the new crate is small and dependency-free; `esdk`'s change is mechanical (delegate instead of inline).
- Aligns with the existing native-MPL direction (the repo already splits `prim`/`mpl`/`esdk`); a `esdk-wire` primitive-parsing crate fits that structure.
- No soundness shortcuts needed — the core is genuinely Verus-buildable.

**Cons / risks.**
- Still modifies shipping `esdk` source (the adapter rewrite) — needs review and thorough tests to prove behavioral equivalence (byte-for-byte identical parsing).
- Introduces a new crate to the build/release matrix.
- The `raw`-mirror and streaming (`dyn SafeRead`) semantics must be preserved exactly at the adapter layer; the split must not change where EOF vs. error is produced.
- UTF-8 validation and any `String` handling stay on the `esdk` side or are modeled with the one documented `from_utf8` trusted boundary (as today).

**Applies to MPL?** Yes, and this is the recommended MPL path too — an analogous `mpl-core` (std-only) crate holding the **materials structures** (`structures/*`) and the pure byte-layout/matching/KDF-structure helpers (`cache_entry_identifier`, `mrk_match`, `branch_key_wrap` AAD/slicing, commit-key derivation structure). `mpl/` then depends on `mpl-core` and keeps the `aws-sdk-*`/`tokio` I/O as thin adapters, exactly as `esdk` would delegate to `esdk-wire`. The materials structures are pure data types, so much of `mpl-core` needs no adapter at all — it can be verified directly. The two extracted cores (`esdk-wire`, `mpl-core`) could even share a common Verus-buildable byte-primitives crate to avoid duplicating the `ByteReader`/big-endian source-of-truth.

**Effort:** Medium (days) for ESDK; **Medium–Large** for MPL (more surface: structures + KDF + cache logic).
**Assurance:** High — verifies shipped code for the parsing layer (bulk of VR-003/004/005) and, via `mpl-core`, the materials structures + key-commitment logic (VR-001, VR-010) and byte-layout/matching helpers.
**Recommendation:** **Preferred** for both ESDK and MPL. The seam is exactly what the current `ByteReader` was designed to become; `mpl-core` is the MPL analogue.

---

## 5. Option C — Fidelity test harness (low-risk, lands now)

**Idea.** Keep the proofs out-of-crate, but add conventional `#[test]`s in `esdk` that exercise the *real* `serialize_functions` readers against the exact byte sequences and expected outcomes the Verus models specify. CI then catches drift between model and shipped code without in-crate Verus.

**What it requires.**
- A test module in `esdk` with vectors derived from the Verus specs: e.g. big-endian round-trips (`read_u32` of `[0x00,0x00,0x01,0x00]` == 256), EOF-returns-Err on truncated input, `count == 0`/`count > max` rejection, non-UTF-8 rejection, sequential-frame enforcement, empty-EC short-circuit.
- A short doc note linking each test group to the Verus obligation it guards.

**Pros.**
- **Zero structural change; lands today; no shipping-logic modification** (tests only).
- Catches the most likely drift (someone changing a reader's behavior) via normal CI.
- Complements A/B rather than competing — worth doing regardless.

**Cons / risks.**
- **Lower assurance:** tests check specific inputs, not *all* inputs. It is not a proof and does not remove the "it's a model" caveat — it only reduces the chance that drift goes unnoticed.
- Duplicates intent between the models and the tests; both must be kept in sync with the specs.

**Applies to MPL?** Yes — the MPL already has a precedent for this: `mpl/` ships a dev-dependency `aws-lc-rs` used purely as a "digest oracle for the cache-identifier byte-layout assertions" (`mpl/Cargo.toml`). Extending those with vectors derived from the (future) MPL Verus specs — cache-entry-identifier layout, MRK matching, EDK/encryption-context structure, commit-key derivation structure — is a natural, low-risk drift guard for MPL too.

**Effort:** Low (hours–1 day) per layer.
**Assurance:** Medium-low (drift detection, not verification).
**Recommendation:** Do this **now, regardless** — it's cheap insurance and a good bridge while B is reviewed. For MPL, lean on the existing cache-identifier test precedent.

---

## 6. Comparison

| | A: in-place Verus | B: extracted core crate | C: fidelity tests |
|---|---|---|---|
| Verifies *shipped* code? | Yes (if feasible) | **Yes** (the core crate) | No (drift detection) |
| Removes "it's a model" caveat? | Yes | **Yes** (extracted layer) | No |
| Modifies shipping source? | Yes, extensive | Yes, contained | No (tests only) |
| Feasibility risk | **High** (crate dep graph) | Low–Medium | None |
| Blast radius / review load | Large | Medium | Small |
| Soundness-shortcut temptation | High (deps unbuildable) | None | N/A |
| Effort (ESDK) | High/uncertain | Medium (days) | Low (hours) |
| Effort (MPL) | High/uncertain | Medium–Large | Low (per layer) |
| Covers MPL? | In principle (harder deps) | **Yes** (`mpl-core`: structures + KDF/commit + layout helpers) | Yes (drift guard) |
| CI integration | `cargo-verus` on crate | `cargo-verus` on `esdk-wire` / `mpl-core` | normal `cargo test` |

---

## 7. Recommendation

Same strategy for both ESDK and MPL: **C now, B as the primary migration, A only if B can't reach.**

1. **Now:** Option C — add the fidelity test harness for both ESDK readers and the MPL cache-identifier / structure layout (building on the existing MPL digest-oracle test). Low-risk, immediate drift protection, useful under any long-term choice.
2. **Next (primary):** Option B — extract std-only cores and rewire the heavy crates as adapters, so the Verus proofs bind to shipped code:
   - `esdk-wire` ← the byte parsing/serialization core.
   - `mpl-core` ← the materials structures + pure byte-layout/matching/KDF-structure helpers.
   - Optionally a shared byte-primitives crate underneath both (the `ByteReader`/big-endian source-of-truth).
3. **Only if needed:** Option A — reserve for logic that genuinely cannot leave `esdk`/`mpl`, accepting the dep-graph feasibility risk.

### Proposed phasing (MPL-aware)

| Phase | Work | Options | Targets |
|-------|------|---------|---------|
| 0 | Fidelity tests (ESDK readers + MPL cache-id/structures) | C | Drift guard for VR-003/004/005 + MPL layout |
| 1 | Extract `esdk-wire`; rewire `serialize_functions` | B | Bind VR-003/004/005 to shipped code |
| 2 | Extract `mpl-core` structures; verify materials/EDK/EC structures + zeroization | B | VR-010 + materials-structure invariants (shipped) |
| 3 | MPL byte-layout/matching helpers: cache-entry-identifier, MRK match, branch-key-wrap AAD/slicing | B | Panic-freedom + layout correctness (shipped) |
| 4 | Key commitment: commit-key derivation *structure* + constant-time compare | B (+ trusted HKDF boundary) | **VR-001** (CVE-2020-8897 class) |
| 5 | Decrypt/CMM orchestration ordering once seams exist | B/A | VR-002 end-to-end; CMM cache-eligibility logic |

Phases 2–4 are the MPL additions. They are independent of Phase 1 (different crate), so ESDK and MPL migration can proceed in parallel once the shared byte-primitives decision (§8 Q1) is made.

**Non-negotiables under any option** (from the Verus soundness invariants): no `assume`/`admit`/`external_body`/`external` to force a pass; success requires actual `0 errors`; the documented `std::str::from_utf8` boundary and the aws-lc-rs/HKDF FFI boundaries are the only accepted trust anchors and must stay flagged; the verified type/function must be the shipped one (no `cfg`-gated divergent definitions). For MPL specifically: proofs target the **native `mpl/`**, and the Dafny-backed legacy MPL (`aws-mpl-legacy`) remains an explicitly-noted out-of-scope trusted artifact.

---

## 8. Open questions for the team

1. **Crate boundary (B):** are new `esdk-wire` and `mpl-core` crates acceptable in the release matrix, or should the cores live as modules in existing dependency-light crates (e.g. `prim`)? Should both share one byte-primitives crate to avoid duplicating the `ByteReader`/big-endian source-of-truth?
2. **Error type:** acceptable to introduce a plain wire-error enum in each core and map to `crate::error::Error` / `mpl` errors at the boundary? Any objection to losing `Backtrace` inside the cores?
3. **Equivalence bar:** what evidence is required that the adapter rewrites are byte-for-byte behavior-preserving — differential tests against the current implementation, fuzzing, or both? (Applies to both `esdk` readers and MPL structure/layout helpers.)
4. **Scope:** how far to push — parsing layer (VR-003/004/005) only, or through key-commitment (VR-001), decrypt/CMM orchestration (VR-002), and the MPL materials/keyring logic per the Phase table in §7?
5. **CI:** add `cargo-verus`/`make verify` as a required check, and on which crate(s) — `esdk-wire`, `mpl-core`, both?
6. **Toolchain policy:** pin the Verus version (currently `0.2026.07.12`, Rust `1.96.0`) in CI; who owns upgrades?
7. **MPL target — native vs legacy (new):** MPL proofs would target the native `mpl/` (`aws-crypto-mpl`), which is **not yet on the ESDK dependency path** (the shipping ESDK uses the Dafny-backed `unsafe-unreviewed-mpl`). Is verifying the native MPL — the intended future — the right bet, with the legacy Dafny shim documented as out-of-scope/trusted? Or is there a requirement to also cover what the ESDK executes today?
8. **MPL scope boundaries (new):** confirm the crypto/I/O trust boundaries for MPL — HKDF/AES via `aws-lc-rs` (FFI, out of scope), KMS/DynamoDB via `aws-sdk-*` + `tokio` (out of scope). Proofs cover the surrounding structure/layout/decision logic only; is that assurance level acceptable for the key-commitment and branch-key-wrap threats?

---

## Appendix — current proof inventory (for reference)

| File | Obligations | Target |
|------|-------------|--------|
| `verification/body_aad_proofs.rs` | 4 | VR-005 |
| `verification/edk_count_proofs.rs` | 4 | VR-007 |
| `verification/zeroize_proofs.rs` | 4 | VR-010 |
| `verification/frame_layout_proofs.rs` | 7 | VR-005 |
| `verification/header_parse_proofs.rs` | 7 | VR-003 |
| `verification/frame_sequence_proofs.rs` | 5 | VR-004 |
| `verification/io_stream_model.rs` | 8 | infra |
| `verification/io_stream_aligned.rs` | 24 | infra + VR-003/004/005 |
| `verification/header_auth_ordering_proofs.rs` | 5 | VR-002 |
| `verification/aes_gcm_bounds_proofs.rs` | 3 | VR-006 (non-FFI) |
| **Total** | **71** | 0 errors |

Run: `make -C verification verify` (Verus `0.2026.07.12`, toolchain `1.96.0`).

**MPL status:** the inventory above is **ESDK-only**. There are currently **no MPL proofs** — MPL verification is the planned work described in §2.5 and the Phase 2–4 table in §7. The one MPL-adjacent proof so far is `zeroize_proofs.rs` (VR-010), which models `PlaintextDataKey::zeroize` in `mpl/src/structures/algorithm_suite.rs`; it is the natural first `mpl-core` target once that seam exists.
