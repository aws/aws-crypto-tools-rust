# Design Doc — Binding the Verus Proofs to Shipped ESDK Code

**Status:** Draft for team discussion
**Author:** (Verus verification effort)
**Date:** September 2026
**Scope:** How to convert the current out-of-crate Verus *models* into verification of the *actual shipped* ESDK parsing code.
**Related:** `docs/verus-proofs-report.md`, `docs/verification-recommendations.md`, `verification/README.md`, `.kiro/steering/verus-verification.md`

---

## 1. Problem statement

We have Verus proofs for the ESDK message layer — 71 obligations, 0 errors, covering header parsing (VR-003), frame sequence (VR-004), frame layout (VR-005), header-auth ordering (VR-002), EDK count (VR-007), zeroization (VR-010), and AES-GCM buffer bounds (VR-006, non-FFI part). They live in `verification/`, run via `make -C verification verify`.

**The gap:** every proof is a **faithful, self-contained model** of a function — the same executable body plus `requires`/`ensures`, written in a standalone file that imports nothing from the `esdk` crate. The proofs are therefore *not* verifying the shipped code. Two concrete consequences:

1. **Drift risk.** If someone edits `esdk/src/message/serialize_functions.rs`, the Verus models still print "verified, 0 errors" while silently modeling stale source. Today the only defense is manual file comparison (which we did after the last `main` merge — see `docs/verus-proofs-report.md`).
2. **Weaker headline.** The honest claim is "we have verified models of the ESDK parser," not "the ESDK parser is verified."

**Goal:** close the drift risk and strengthen the claim, with a change that (a) an AWS-owned repo's review process would accept, and (b) respects the Verus soundness invariants (no `assume`/`external_body`/`admit` to fake a pass).

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

**Effort:** Medium (days). Mostly mechanical once the crate boundary is drawn; the risk is in equivalence testing, not novelty.
**Assurance:** High — verifies shipped code for the parsing layer, which is the bulk of VR-003/004/005.
**Recommendation:** **Preferred.** Best assurance-per-risk; the seam is exactly what the current `ByteReader` was designed to become.

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

**Effort:** Low (hours–1 day).
**Assurance:** Medium-low (drift detection, not verification).
**Recommendation:** Do this **now, regardless** — it's cheap insurance and a good bridge while B is reviewed.

---

## 6. Comparison

| | A: in-place Verus | B: `esdk-wire` crate | C: fidelity tests |
|---|---|---|---|
| Verifies *shipped* code? | Yes (if feasible) | **Yes** (the wire crate) | No (drift detection) |
| Removes "it's a model" caveat? | Yes | **Yes** (parsing layer) | No |
| Modifies shipping source? | Yes, extensive | Yes, contained | No (tests only) |
| Feasibility risk | **High** (crate dep graph) | Low–Medium | None |
| Blast radius / review load | Large | Medium | Small |
| Soundness-shortcut temptation | High (deps unbuildable) | None | N/A |
| Effort | High/uncertain | Medium (days) | Low (hours) |
| CI integration | `cargo-verus` on `esdk` | `cargo-verus` on `esdk-wire` | normal `cargo test` |

---

## 7. Recommendation

1. **Now:** Option C — add the fidelity test harness. Low-risk, immediate drift protection, useful under any long-term choice.
2. **Next (primary):** Option B — extract `esdk-wire` and rewire `serialize_functions` as adapters, so the Verus proofs bind to shipped code. This is the real "migration" and the best assurance-per-risk.
3. **Only if needed:** Option A — reserve for cases B cannot reach (e.g. verifying logic that genuinely cannot leave `esdk`), accepting the dep-graph feasibility risk.

**Non-negotiables under any option** (from the Verus soundness invariants): no `assume`/`admit`/`external_body`/`external` to force a pass; success requires actual `0 errors`; a single documented `external_body` boundary for `std::str::from_utf8` is the only accepted trust anchor and must stay flagged; the verified type/function must be the shipped one (no `cfg`-gated divergent definitions).

---

## 8. Open questions for the team

1. **Crate boundary (B):** is a new `esdk-wire` crate acceptable in the release matrix, or should the core live as a module in an existing dependency-light crate (e.g. alongside `prim`)?
2. **Error type:** acceptable to introduce a plain wire-error enum in the core and map to `crate::error::Error` at the boundary? Any objection to losing `Backtrace` inside the core?
3. **Equivalence bar:** what evidence is required that the adapter rewrite is byte-for-byte behavior-preserving — differential tests against the current implementation, fuzzing, or both?
4. **Scope:** stop at the parsing layer (VR-003/004/005), or also target key-commitment (VR-001) and the decrypt orchestration (VR-002) once the seam exists?
5. **CI:** add `cargo-verus`/`make verify` as a required check, and on which crate(s)?
6. **Toolchain policy:** pin the Verus version (currently `0.2026.07.12`, Rust `1.96.0`) in CI; who owns upgrades?

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
