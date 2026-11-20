# ESDK Verification Developers Guide

A practical guide for engineers working on the native-Rust AWS Encryption SDK
(`aws-esdk`) in this repository who need the formal Verus proofs to stay honest
and stay green. It covers three jobs: changing ESDK code without breaking a
proof, adding a proof for code you wrote, and running the agents that derive or
re-sync the verification targets.

The one rule that runs through every section: **the guide must obey the ladder
it teaches.** A compiler check, a clippy lint, a standalone model, and a trusted
boundary are each worth something, but none of them is a Verus proof of shipped
code. Never call them one.

---

## Who should read what

| You are… | Read | Skip unless curious |
|----------|------|---------------------|
| **(1) Changing ESDK code**, need existing proofs to keep passing | §1 (ladder), §2 (orientation), §3 (did-I-break-it), §4 (soundness rules) | §5–§7 |
| **(2) Adding a proof** for code you wrote | §1–§4, then §5 (add-a-proof), §6 (agents) | §7 if you are not re-scoping a target |
| **(3) Maintainer** deriving or re-syncing targets | all of it, especially §6 (agents), §7 (targets & drift), §9 (review/CI) | — |

A type-(1) reader gets the full value of this guide from §1–§4 alone.

> **Counts in this guide are a snapshot.** Every "N verified, 0 errors" below is
> a value read from tool output at the time of writing, not a fact derived from
> the code. They go stale the moment code changes. Before you cite a count,
> re-run the command and read the latest line. §2 lists the commands.

---

## 1. What "verified" means here — the honesty ladder

This is the most important section. "Verified" is not one thing in this
repository. There are four distinct levels of assurance, and they are not
interchangeable. The authoritative, live account of what sits at each level is
[`docs/verus-proofs-report.md`](./verus-proofs-report.md); this section is the
map, that file is the territory.

**Level 1 — In-crate Verus proof (shipped code).** Verus checks a `verus! { }`
block inside the shipped crate, so the thing proven *is* the code that ships.
The strongest claim available here. Example: **VR-003**, the big-endian decoders
and bounded-length readers in `esdk/src/message/serialize_functions.rs`
(`be_u16`, `be_u32`, `be_u64`, `bounded_len_u32`, `bounded_len_u64`,
`next_chunk_end`) — each proven against its spec function, and the shipped
readers call these exact cores. Same level: VR-004, VR-005, VR-007, the esdk
half of VR-009, VR-012, VR-001 property (a), and the three `prim` cores (VR-006,
VR-008, VR-009 prim half).

**Level 2 — Model-only Verus proof.** Verus checks a self-contained model in
`verification/`, which imports nothing from the crates and can drift from them.
It proves a property about a *model* of the code, not about the shipped path.
Example: **VR-001 property (b)** (commitment-before-frame ordering,
`verification/commitment_ordering_proofs.rs`) and **VR-002** (header-auth tag
ordering, `verification/header_auth_ordering_proofs.rs`). Both model the decrypt
pipeline as a small state machine. They are *not* proofs about the shipped async
`decrypt_steps`, which runs over `dyn Source` with `.await` — and Verus cannot
verify async code or trait objects. What stays trusted is that `decrypt_steps`
is the real pipeline and that its async frame loop runs after the synchronous
commitment step returns.

**Level 3 — Compiler / clippy-enforced.** The Rust compiler (privacy) or a
clippy lint enforces the property; Verus does not. Example: **VR-011**
(data-key non-disclosure). Outside `esdk/src/secret.rs`, esdk code cannot read
the bytes of a `DataKeyRef` or `MessageKey` — the fields are private, the types
derive no `Clone`/`PartialEq`/`Debug`, and a clippy `disallowed-methods` rule
(`esdk/clippy.toml`) gates the mpl data-key accessors. Verus here covers *only*
the secret types' accessors and the commitment-value declassification (the
`secret.rs` rows in the proofs report). Verus does not check that a function is
absent; the confinement itself is compiler- and lint-checked, never call it
Verus-proven.

**Level 4 — Trusted / TCB.** The property is assumed, not proven, because it is
outside what Verus can reason about here. Example: the **constant-time**
behaviour of the commitment comparison (VR-001 property c) rests on the
`aws_lc_rs::constant_time::verify_slices_are_equal` API contract — Verus does
not model timing. Same level: all **aws-lc-rs crypto** (AES-GCM, ECDSA, HKDF,
digests), reached through `aws-mpl-primitives`; the AES-GCM key length and IV
validity, which `aws-lc-rs` enforces internally; and the `external_type_specification` /
`assume_specification` boundaries in the `prim` proofs.

| Level | Who enforces it | Proves the *shipped* code? | Example |
|-------|-----------------|---------------------------|---------|
| 1 In-crate Verus | Verus, in `verus!` in the shipped crate | Yes | VR-003 decoders (`serialize_functions.rs`) |
| 2 Model-only Verus | Verus, over a standalone model | No — a model of it | VR-001b / VR-002 ordering |
| 3 Compiler / clippy | rustc privacy + clippy lint | The named property, not by Verus | VR-011 confinement |
| 4 Trusted / TCB | nobody (assumed) | No | constant-time, aws-lc-rs crypto |

When you describe your own work, say which level it sits at. Collapsing levels —
"I proved the data key never leaks" when the truth is Level 3 confinement — is
the single easiest way to make this whole effort dishonest.

---

## 2. 60-second orientation

**Where proofs live.**

| Location | What it holds |
|----------|---------------|
| `esdk/src/` | In-crate `verus!` blocks for shipped esdk code (Level 1) |
| `prim/src/` | In-crate `verus!` blocks for the three `prim` panic-point cores (VR-006, VR-008, VR-009 prim half) |
| `verification/` | Standalone models (Level 2); import nothing from the crates, can drift |
| `docs/` | The artifacts: `verus-proofs-report.md`, `verification-recommendations.md`, `threat-model.md` |
| `.kiro/agents/`, `.kiro/skills/verus/`, `.kiro/steering/` | The tooling: agents, the verus skill, the steering file |

**The three commands.**

| Command | Checks |
|---------|--------|
| `make -C esdk verus` | The `verus!` blocks in `esdk`. Runs twice: default features, then `--no-default-features --features aws-lc-sys`. |
| `make -C prim verus` | The `verus!` blocks in `prim`. Both feature sets. |
| `make -C verification verify` | Every standalone model file in `verification/`. |

**A proof counts only at `0 errors`.** A rising "N verified" number means
nothing on its own — the success line must read `N verified, 0 errors`. This is
non-negotiable (verus skill invariant #2).

**The touch-src cache gotcha.** `cargo-verus` caches results. A cached `esdk`
run prints *no* `verification results::` line. If you changed esdk code and want
a fresh check, `touch esdk/src/lib.rs` first to force a re-check. For `esdk`,
`vstd` is verified first (`1858 verified, 0 errors`) and the `aws-esdk` line you
care about is the **second** `verification results::` line.

**Snapshot counts (re-read from tool output; do not trust these numbers blind):**

```
make -C esdk verus          →  aws-esdk:            69 verified, 0 errors  (both feature sets)
make -C prim verus          →  aws-mpl-primitives:  18 verified, 0 errors  (both feature sets)
make -C verification verify →  11 files:            78 verified, 0 errors  total
```

These were confirmed by a live run at the time of writing. Treat them as a
starting point to reproduce, not as ground truth.

---

## 3. "I changed ESDK code — did I break a proof?" (the common path)

The verified cores **are** the shipped code: there is one definition of each
function, and it lives inside `verus!`. If you edit one, you are editing the
proof's subject.

**Check your change:**

1. From the repo root, `touch esdk/src/lib.rs` (defeat the cache).
2. `make -C esdk verus`. Read the **second** `verification results::` line (the
   `aws-esdk` one); it must say `… 0 errors`. The Makefile runs both feature
   sets, so you will see two `aws-esdk` lines — both must be `0 errors`.
3. If you touched `prim`, also run `make -C prim verus` (both feature sets).
4. The standalone models in `verification/` do not import the crates, so your
   esdk change cannot break them mechanically — but it can make them *stale*
   (describing code that no longer behaves that way). Run
   `make -C verification verify` if you touched something a model mirrors, and
   see §7 on drift.

**Which files have `verus!` blocks** (where a break can happen): in `esdk`,
under `esdk/src/message/` — `serialize_functions.rs`, `header.rs`,
`header_types.rs`, `v1_header_body.rs`, `body/body_decrypt.rs`,
`body/body_aad.rs`, `body/body_encrypt.rs` — plus `esdk/src/key_derivation.rs`
and `esdk/src/secret.rs`. In `prim`: `prim/src/ecdsa.rs`, `prim/src/lib.rs`,
`prim/src/hkdf.rs`. The full per-function table is in
[`docs/verus-proofs-report.md`](./verus-proofs-report.md) ("In-crate proofs").

**When a proof goes red.** Verus points at the failing postcondition,
precondition, assertion, or bound. You have exactly two honest options:

- **Fix the code.** The proof encodes a property the code is supposed to have.
  If the proof now fails, the usual reason is that your change violated that
  property — fix the code so the property holds again.
- **Correctly update the proof.** If the *intended behaviour* changed, update
  the `ensures`/`requires` to describe the new correct behaviour, and make sure
  it still verifies and still says something real (see §4).

**Never weaken the proof to get green.** Do not add `assume(...)`, `admit()`,
`#[verifier::external_body]`, `#[verifier::external]`, delete a failing
`assert`/`invariant`/`ensures`, or hide the exec code behind
`#[cfg(not(verus_keep_ghost))]`. Those make the proof pass while proving nothing.
If you cannot prove it, leave it failing and say why — an honest red is worth
more than a dishonest green.

---

## 4. The non-negotiable soundness rules

These come from the verus skill (`.kiro/skills/verus/SKILL.md`, the "ABSOLUTE
INVARIANTS") and the steering file (`.kiro/steering/verus-verification.md`).
They are not style preferences.

- **No forced passes.** No `assume(...)`, `admit()`,
  `#[verifier::external_body]`, or `#[verifier::external]` to silence a failing
  obligation. (`esdk` has exactly one `external_body`, the `utf8_check` wrapper
  around `std::str::from_utf8`, used as a documented trusted boundary — not to
  bypass a proof.)
- **One definition per function and per type.** No `cfg`-gated duplicate
  struct/trait definitions. If Verus sees one definition and cargo compiles
  another, every proof about that type is meaningless. Move an enum into `verus!`
  unchanged; never duplicate it.
- **No hiding exec code behind `cfg`.** `#[cfg(not(verus_keep_ghost))]` to
  exclude exec code from verification while still compiling it is forbidden
  (skill invariant #11). The only sanctioned use is a small external-crate call
  Verus cannot model, kept as narrow as possible and documented.
- **`external_type_specification` / `assume_specification` are the sanctioned
  trusted-boundary mechanism, not escape hatches.** They model a genuine
  external contract (an `aws-lc-rs` opaque type, a std method vstd does not
  spec). The `prim` VR-008 proof uses exactly this for the aws-lc-rs `Signature`
  and for `copy_from_slice`. Using them to wave away an obligation on *your own*
  code is the opposite of their purpose.
- **Obligations must be real, not tautologies.** A proof that passes at
  `0 errors` while proving nothing is worse than no proof. The lesson is on
  record: an early attempt at the `prim` `sign_fixed_len` core passed but its
  obligations were tautological — the fix was to put the real retry loop inside
  `verus!` with a genuine `decreases MAX_SIGN_ATTEMPTS - attempt` and prove the
  guarded `copy_from_slice` in bounds. The repo's defence against this is
  **mutation testing**: deliberately break the code or spec (move a split index,
  accept an extra length, drop a precondition) and confirm Verus goes red. If a
  mutation does *not* break the proof, the obligation was vacuous. The proofs
  report records these mutation tests per core.

**How this is caught in review.** Reviewers do a behavioural/semantic read, not
a count check (§9): they confirm the target function really sits in a `verus!`
block, that its `requires` are satisfiable by real callers, that no `ensures`
was bent to match a bug, and that load-bearing obligations were mutation-tested.
A higher "N verified" with a silently-excluded function is treated as a
regression, not progress (skill invariant #13).

---

## 5. "I want to prove new code" (the add-a-proof path)

**First, load the verus skill.** Before writing any proof, load
`.kiro/skills/verus/SKILL.md` — it carries the invariants above, the function
modes (`spec`/`proof`/`exec`), `requires`/`ensures`, `Seq<u8>` buffer modelling,
loop invariants, and the debugging workflow. The steering file
`.kiro/steering/verus-verification.md` carries the repo-specific idioms.

**The pattern used throughout: verified core + trusted adapter.** Verus cannot
verify `async fn` or `dyn` trait objects, and a verified fn cannot call or name
a type declared outside `verus!` (mpl types, the esdk `Error`, prim fns). So the
decision/layout logic goes into a pure synchronous **core** inside `verus!`, and
a thin **adapter** outside `verus!` does the I/O, builds the `Error`, and calls
external crates. Two concrete examples:

- **T1, `prim/src/ecdsa.rs`:** `sign_fixed_len_core` holds the real retry loop
  inside `verus!` (termination + in-bounds copy proven); the `sign_fixed_len`
  adapter builds the `Error` and owns the `aws-lc-rs` signing closure.
- **VR-001a, `esdk/src/message/header.rs`:** `suite_data_check` is the verified
  accept/reject decision; `validate_suite_data` is the caller that reads the
  bytes and performs the (trusted, constant-time) comparison.

**In-crate vs model-only — the decision.** Prove it in-crate (Level 1) if the
property can be carved into a synchronous core inside `verus!`. Fall back to a
model (Level 2) only when the property lives in async/`dyn` shipped code that
Verus cannot touch. This is exactly why VR-001b and VR-002 (ordering properties
that live in the async `decrypt_steps` sequence of `.await?` calls) are
model-only: a sync core could only ever prove `Ok ⇒ Ok`. If you go model-only,
say so and never present it as covering the shipped path.

**Picking and routing a target — the provability gate.** Before writing
anything, run the candidate through `.kiro/agents/verus-capabilities.md`. It
answers three questions: is this Verus-provable at all; is it provable *in place
here* (the "provable AND present" gate); and which of the four categories and
which proof agent it belongs to. If the decision aid says "No" or "not here"
(crypto hardness, constant-time, external-service policy, probabilistic secrecy,
absence-of-code, shipped async ordering, anything inside `mpl`), it is not a
Verus target — record it as out of scope with the reason.

**In-crate constraints (from the steering file and verus-capabilities).** Pull
the full list from the source; the ones that bite most often:

- **No `to_be_bytes`.** vstd does not model it. Use the verified encoders
  `u32_to_be` / `u64_to_be` in `serialize_functions.rs`, backed by the
  `spec_u32_to_be` / `spec_u64_to_be` spec functions.
- **Sync cores inside `verus!`, async adapters outside.** Readers are
  `async fn`s over `&mut dyn Source` that mirror bytes into `&mut Tee`; keep them
  as thin unverified adapters.
- **Traits declared in `verus!` but implemented outside get their `ensures`
  trusted silently** — give such traits `requires` only, no `ensures`, unless a
  named trusted assumption is approved.
- **A `pub`/`pub(crate)` fn's `ensures` cannot read a private field.** Add a
  `closed spec fn view(&self)` and write the `ensures` against `self.view()`
  (this is how `secret.rs` does it).
- **One definition per type; no `#[cfg(not(verus_keep_ghost))]` on exec code.**
- **Avoid `as` casts in exec code** (they trip clippy `cast_*`); use
  `u16::from(u8)` × multipliers, `usize::try_from(...)`, and write a const shift
  like `1 << 20` as `1_048_576`.
- **Doc-comment every new item** (`missing_docs` is on) and add a
  `#[cfg(test)] mod tests` for new cores.

---

## 6. Using the agents

The agents live in `.kiro/agents/`. Also relevant: the **verus skill**
(`.kiro/skills/verus/SKILL.md`, load it before writing proofs) and the
**steering file** (`.kiro/steering/verus-verification.md`, auto-included for
`verification/**`).

| Agent | For | When to invoke |
|-------|-----|----------------|
| `verus-capabilities` | Triage / provability gate; the four proof categories mapped onto esdk | First, for *any* candidate — decide if it is provable here and route it |
| `verus-header-parsing-proofs` | Writing proofs: header/body parsing, layout, round-trip, decisions | Functional-correctness targets (VR-001a, VR-003, VR-004, VR-005, VR-007, VR-012) |
| `verus-zero-panic` | Writing proofs: absence of panics (bounds, arithmetic, `unwrap`) | Panic-freedom targets (VR-006, VR-008, VR-009 panic points) |
| `verus-unsafe-ffi-safety` | Writing proofs: `unsafe`/FFI-boundary safety | Rarely — there is no in-crate `unsafe`; documents the trusted aws-lc-rs/shim boundary |
| `spec-analyzer` | Deriving targets: extract security properties from `spec/` + Duvet | Pipeline Step 1 (specification ingestion) |
| `threat-model-generator` | Deriving targets: STRIDE + attack trees | Pipeline Step 2 (threat modelling) |
| `verification-recommender` | Deriving targets: gate, score, route into the ranked VR list | Pipeline Step 3 (and the capability-driven Stage 2′) |
| `ai-verification-pipeline` | The full three-stage re-derivation methodology | A ground-up re-derivation (no baseline, or the architecture changed fundamentally) |
| `ai-verification-update` | The incremental delta/drift re-sync between full passes | The common maintenance case: code moved, proofs added, docs need to catch up |

**Which one do I want?**

- *Can I even prove this?* → `verus-capabilities`.
- *I know what to prove, write it.* → one of the three `verus-*` proof agents, by
  domain (parsing vs panic vs unsafe). Load the verus skill first.
- *Where do targets come from?* → `spec-analyzer` → `threat-model-generator` →
  `verification-recommender` (plus the capability-driven Stage 2′ sweep).
- *Re-derive everything from scratch* → `ai-verification-pipeline`.
- *Just catch the docs up to what changed* → `ai-verification-update`. This is
  the one you reach for most.

---

## 7. Adding or re-scoping a target, keeping docs honest

**Target numbering.** New targets continue the existing sequence — `VR-012`,
`VR-013`, … (YAML id `VR-2026-012`, …); VR-001…VR-011 keep their ids and none is
reused. Every target carries an `origin` field: `threat-driven` (traces to a
threat in `docs/threat-model.md`) or `capability-driven` (traces to a Verus
capability category and the code invariant it establishes, e.g. VR-012). Triage
every proposed target through `verus-capabilities.md` before adding it.

**The `ai-verification-update` drift flow.** This is how the docs stay in sync
without re-deriving everything:

1. **Baseline.** Read the recorded baseline commit from the docs themselves (the
   "Revised … against `<sha>`" lines). If the three docs cite different
   baselines, use the oldest and note the skew.
2. **Diff.** Compute the delta with `git` against the current tip
   (`git log --oneline <baseline>..HEAD`, `git diff --stat`, and the per-area
   diffs over `esdk/src mpl/src prim/src spec/ verification/`). Never infer the
   delta from memory.
3. **Re-read proof status from live tool output**, never from code: `make -C esdk
   verus` (both feature sets, touch first), `make -C prim verus`, `make -C
   verification verify`.
4. **Propose** a drift report (`.agents/tasks/<task>/verification-drift.md`):
   threat-model drift, per-target drift, new proposed targets with their
   capability triage and score, a proof-status reconciliation (live counts vs
   what the docs claim), and open questions a human must decide.
5. **Get human approval and stop.** Do not touch `docs/` until approved; apply
   only the approved items (partial approval is normal).
6. **Apply and bump the baseline marker.** Edit the docs, update the "Revised …
   against `<sha>`" line to the current tip so the next pass starts here, and
   re-run the relevant command to confirm the numbers you wrote match tool
   output.

**The honesty rule for docs.** A doc claim must match live tool output and must
never overclaim. Never upgrade a model-only, compiler/clippy-checked, or trusted
property to "Verus-proven" in prose. When the docs and the code disagree, trust
the code and the live output and flag the doc as stale — do not quietly rewrite
the code description to match a doc.

---

## 8. Known boundaries and deliberate non-goals

These are settled calls. They are recorded where noted so they are not
re-litigated.

| Boundary / non-goal | Status | Recorded in |
|---------------------|--------|-------------|
| **Constant-time + crypto** (AES-GCM, ECDSA, HKDF, digests) | Trusted (aws-lc-rs); Verus does not model timing or crypto hardness | `docs/verus-proofs-report.md`; VR-001c, `verus-capabilities.md` decision aid |
| **`mpl` crate** | Out of scope — not Verus-checked, treated as a trusted contract | `ai-verification-pipeline.md` layout table; `verus-capabilities.md` |
| **Async ordering** (VR-001b, VR-002) | Model-only — the order lives in async `decrypt_steps`; Verus cannot verify async/`dyn` | `verification/{commitment_ordering,header_auth_ordering}_proofs.rs`; proofs report |
| **VR-010 zeroization** | Deferred — the model describes a `write_volatile` loop removed in `a864ad87`; zeroization now comes from `#[derive(Zeroize, ZeroizeOnDrop)]` | `verification/zeroize_proofs.rs`; recommendations VR-010 row |
| **VR-011 confinement** | Compiler + clippy-enforced, not Verus; Verus covers only the `secret.rs` accessors/declassification | `esdk/clippy.toml`; proofs report VR-011 section; recommendations VR-2026-011 |
| **u16 codec asymmetry** (decoder exists, encoder does not) | By design, not a bug — only u32/u64 encoders were needed by a proof, so only those have a round-trip lemma | the note above `u32_to_be` in `esdk/src/message/serialize_functions.rs`; `verus-capabilities.md` §1c |

---

## 9. Review and CI

**How a proof change is reviewed.** The review in this project is
behavioural/semantic, not a glance at the verified count. A reviewer confirms:

- the target function actually sits inside a `verus! { }` block (not silently
  excluded while a nearby count rose);
- no soundness escape hatch was used (`assume`/`admit`/`external_body`/`external`,
  a `cfg`-hidden exec body, a duplicated type definition);
- `requires` clauses are satisfiable by the real callers (not over-constrained
  into vacuity);
- no `ensures` was changed to match buggy behaviour;
- load-bearing obligations were mutation-tested, so they are not tautologies;
- the proven-vs-trusted split in the docs is accurate and nothing overclaims.

**CI — not yet decided (TBD).** Whether `make -C esdk verus`, `make -C prim
verus`, or `make -C verification verify` runs in CI is an open question, not a
settled fact. Today the proofs are checked **locally only** — no workflow under
`.github/workflows/` runs Verus (see `docs/verus-in-crate-migration-design.md`,
answer to §8 Q5). Wiring it up would need the Verus toolchain (`~/verus`, a
pinned `vstd`) on the CI image, and a decision on required-vs-advisory. This is
raised as **PR #103, open question 2**. Do not assume or state that CI runs the
proofs; it does not, yet.

(What CI *does* run on the Rust side, per the workflow and clippy config, is
`cargo clippy --all-targets -- -D warnings`, the feature-powerset clippy, rustdoc
with `-D warnings`, and cargo-deny — including the clippy `disallowed-methods`
rule that enforces VR-011 confinement. That is Level 3 enforcement, not a Verus
proof.)

---

## Sources

Everything above is grounded in the following repository artifacts; consult them
for the authoritative, live detail:

- [`docs/verus-proofs-report.md`](./verus-proofs-report.md) — authoritative proof status, per-target and per-file
- [`docs/verification-recommendations.md`](./verification-recommendations.md) — the ranked VR-001…VR-012 targets, scores, and honest scope
- [`docs/threat-model.md`](./threat-model.md) — the threat model the threat-driven targets trace to
- `.kiro/skills/verus/SKILL.md` — the verus skill and its absolute invariants
- `.kiro/steering/verus-verification.md` — repo-specific Verus idioms and ground rules
- `.kiro/agents/` — the agents (`verus-capabilities`, the three `verus-*` proof agents, `spec-analyzer`, `threat-model-generator`, `verification-recommender`, `ai-verification-pipeline`, `ai-verification-update`)
- `docs/verus-in-crate-migration-design.md` and PR #103 — the CI open question
