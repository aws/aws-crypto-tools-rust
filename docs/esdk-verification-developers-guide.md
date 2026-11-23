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
| **(2) Adding a proof** for code you wrote | §1–§4, then §5 (add-a-proof), §6 (agents), §10 (recipe R1) | §7 if you are not re-scoping a target |
| **(3) Maintainer** deriving or re-syncing targets | all of it, especially §6 (agents), §7 (targets & drift), §9 (review/CI), §10 (toolkit) | — |

A type-(1) reader gets the full value of this guide from §1–§4 alone.

> **Counts in this guide are a snapshot.** Every "N verified, 0 errors" below is
> a value read from tool output, not a fact derived from the code. This guide
> was checked against commit `9964b20b` (branch `Mahnush_Verus`), and its counts
> come from a live run of the §2 commands there. They go stale the moment code
> changes. Before you cite a count, re-run the command and read the result line
> by the rule in §2.

---

## 1. What "verified" means here — the honesty ladder

This is the most important section. "Verified" is not one thing in this
repository. The verus skill (`.kiro/skills/verus/SKILL.md`, "Honesty ladder")
defines the one list of evidence levels; every agent, doc and commit message
uses it. The authoritative, live account of what sits at each level is
[`docs/verus-proofs-report.md`](./verus-proofs-report.md) (section 3, "Target
coverage"); this section is the map, that file is the territory.

Earlier versions of this guide used four groups: in-crate Verus proof,
model-only Verus proof, compiler/clippy-enforced, and trusted. The skill's
ladder keeps those four distinctions and splits them further:

| Level | Label | What it means | Example in this repo |
|---|---|---|---|
| 1 | `verus_in_crate` | Verus proves the `ensures` of a shipped function inside `verus!` | VR-003 decoders in `esdk/src/message/serialize_functions.rs` |
| 2 | `verus_gate_compiler_order` | Verus proves a token is created only when a check passed; the compiler enforces that the guarded step cannot run without the token | the decrypt-order tokens in `esdk/src/decrypt_gate.rs` |
| 3 | `compiler_lint` | Rust types, field privacy or a clippy lint rule something out | VR-011 confinement (`esdk/clippy.toml`) |
| 4 | `model_only` | Proven on a standalone model in `verification/` that imports nothing from the crates | the VR-003 EDK list loop, the VR-005 `ct ‖ tag` append |
| 5 | `tested` | Tests exercise the property; they sample inputs, they do not prove | test names cited per target in the proofs report |
| 6 | `code_reading` | Someone read the code and found it holds; no tool checks it | the VR-020 adapter around `required_ec_entries` |
| 7 | `trusted` | Assumed, written down as a TCB row with a source | constant time (VR-001 (c)), aws-lc-rs crypto, T-cmp |
| 8 | `assumed_labeled` | A trusted assumption about third-party behavior that its docs do not fully state | A-OPEN (row A20, VR-014) |
| 9 | `deferred` / `not_started` | No current evidence | VR-010 zeroization (the model describes removed code) |

Rules from the skill: only level 1 and the gate part of level 2 may be called
"Verus-proven". One target can sit on several levels; report each part at its
own level. When a target moves up a level, check every doc that cites it.

**Level 1, in-crate Verus proof (shipped code).** Verus checks a `verus! { }`
block inside the shipped crate, so the thing proven *is* the code that ships.
Example: **VR-003**, the big-endian decoders and bounded-length readers in
`esdk/src/message/serialize_functions.rs` (`be_u16`, `be_u32`, `be_u64`,
`bounded_len_u32`, `bounded_len_u64`, `next_chunk_end`). Same level: VR-001
property (a), VR-004, VR-005 (layout), VR-007 (the count decision), the esdk
half of VR-009, VR-012, VR-017, VR-018, VR-020 (relative to T-cmp) and the
`secret.rs` accessors of VR-011. In `prim`: VR-006, VR-008, the prim half of
VR-009, VR-013 and VR-014 (a); VR-013 and VR-014 rest on the trusted rows in
`prim/src/aws_lc_specs.rs` (see "Trust boundary" below).

**Level 2, Verus-proven gate with compiler-enforced order (Stage 2 typestate
tokens).** Verus cannot verify `async fn` or `dyn` trait objects, so the order
of `.await` steps in `decrypt_steps` cannot be proven directly. Instead a small
synchronous gate inside `verus!` mints a token only when its check passed, and
the guarded step takes the token as an argument. Verus proves the gate; the
compiler enforces the order, because only the gate module can build a token.
The gates (profile `typestate_gates`):

| Module | Tokens | Targets |
|---|---|---|
| `esdk/src/decrypt_gate.rs` | `CommitmentAccepted`, `HeaderVerified` | VR-001 (b) commitment before frame decryption; VR-002 header tag before any frame |
| `esdk/src/decrypt_gate.rs` | `SignatureVerified`, `HeldFinalPlaintext`, `SignaturePresence`, `SignatureRequired` | VR-015 final plaintext held until the signature verifies; VR-015 (b) signature presence matches the suite |
| `esdk/src/encrypt_gate.rs` | `SigningKeyPresent` | VR-019 encrypt signing-key check, one direction only (finding VR-019 F1) |
| `esdk/src/secret.rs` | `OpenBuffers` | VR-016 every esdk AES-GCM decryption gets a plaintext buffer as long as its ciphertext |

What stays trusted at level 2: the unverified callers pass the real check
results, the guarded step is the only path (for example frames are decrypted
only through `step_decrypt_body`), and a token is not tied to one message. The
earlier standalone ordering models `verification/commitment_ordering_proofs.rs`
and `verification/header_auth_ordering_proofs.rs` are superseded history.

**Level 3, compiler / clippy-enforced.** Example: **VR-011** (data-key
non-disclosure). Outside `esdk/src/secret.rs`, esdk code cannot read the bytes
of a `DataKeyRef` or `MessageKey`: the fields are private, the types derive no
`Clone`/`PartialEq`/`Debug`, and a clippy `disallowed-methods` rule
(`esdk/clippy.toml`) gates the mpl data-key accessors. Verus covers only the
secret types' accessors and the commitment-value declassification. Never call
the confinement itself Verus-proven.

**Level 4, model-only.** Verus checks a model in `verification/` that can drift
from the code. What is still only here: the EDK list loop (VR-003,
`io_stream_aligned.rs`), the frame `ct ‖ tag` append (VR-005,
`frame_layout_proofs.rs`), and the VR-010 model, which describes a
`write_volatile` loop removed in `a864ad87` (deferred).

**Levels 7 and 8, trusted.** Constant time of the commitment comparison
(VR-001 (c)) rests on the aws-lc-rs `verify_slices_are_equal` contract; Verus
does not model timing. All aws-lc-rs crypto (AES-GCM, ECDSA, HKDF, digests) is
trusted. The written-down rows are in the "Trust boundary" paragraph below.

**Trust boundary (`prim/src/aws_lc_specs.rs` and T-cmp).** VR-013 and VR-014
call aws-lc-rs from inside `verus!` through `assume_specification`s, never
`external_body` on a function. The TCB table in the proofs report ("TCB table
(trusted specs and laws)") lists every row: T-ty, T-AsRef and T-uf (naming
only), A1 to A20 (`assume_specification` rows; A1 to A13 for VR-013, A14 to A20
for the AES calls of VR-014), and A-OPEN, the labeled assumption on row A20
(`LessSafeKey::open_separate_gather`, level 8). The VR-008 specs (`ExSignature`,
`Signature::as_ref`, `copy_from_slice`) are in `prim/src/ecdsa.rs`. The one
esdk row is **T-cmp** (VR-020, `esdk/src/decrypt.rs`): the
`requires obeys_cmp::<String>()` of `required_ec_entries`, which says `String`
comparison obeys the laws that vstd's `BTreeMap` / `BTreeSet` specs need. The
owner of every TCB row is the agent named in profile `tcb.owner_agent`
(`verus-unsafe-ffi-safety`); each row needs the user's approval.

When you describe your own work, say which level each part sits at.
Collapsing levels ("I proved the data key never leaks" when the truth is
level 3 confinement) is the easiest way to make this whole effort dishonest.

---

## 2. 60-second orientation

**Where proofs live.**

| Location | What it holds |
|----------|---------------|
| `esdk/src/` | In-crate `verus!` blocks for shipped esdk code (levels 1 and 2), including the gate modules `decrypt_gate.rs`, `encrypt_gate.rs` and `secret.rs`, and `decrypt.rs` (VR-020, T-cmp) |
| `prim/src/` | In-crate `verus!` blocks for `aws-mpl-primitives`: VR-006, VR-008, VR-009 prim half, VR-013, VR-014 (`lib.rs`, `ecdsa.rs`, `hkdf.rs`), and the trust boundary `aws_lc_specs.rs` (rows A1 to A20, A-OPEN) |
| `verification/` | Standalone models (level 4); import nothing from the crates, can drift |
| `docs/` | The artifacts: `verus-proofs-report.md`, `verification-recommendations.md`, `threat-model.md` |
| `.kiro/agents/`, `.kiro/skills/verus/`, `.kiro/steering/` | The tooling: agents, the verus skill, the steering file |
| `.kiro/verification-profile/`, `.kiro/verification-toolkit/`, `.kiro/workflows/` | The library profile, the toolkit (recipes, templates) and the R1 workflow (§10) |

**The three commands.**

| Command | Checks |
|---------|--------|
| `make -C esdk verus` | The `verus!` blocks in `esdk`. Runs twice: default features, then `--no-default-features --features aws-lc-sys`. |
| `make -C prim verus` | The `verus!` blocks in `prim`. Both feature sets. |
| `make -C verification verify` | Every standalone model file in `verification/`. |

**A proof counts only at `0 errors`.** A rising "N verified" number means
nothing on its own; the line must read `N verified, 0 errors`.

**Which line to read (profile `crates[].result_line`).** Read the first
`verification results::` line after `Checking aws-esdk v...` (or
`Checking aws-mpl-primitives v...` for prim). Never pick a line by position:
vstd (`1858 verified, 0 errors`) and, in the esdk run, aws-mpl-primitives
print their own lines first only when they are not cached. A cached crate
prints no line at all, so `touch esdk/src/lib.rs` (or `prim/src/lib.rs`)
first to force a re-check. The aws-mpl-primitives line inside esdk's run is
not the standalone prim run; compare like with like.

**Snapshot counts at `9964b20b`** (live run after `touch`ing each crate; re-run before you
cite them):

```
make -C esdk verus          →  aws-esdk:            99 verified, 0 errors  (both feature sets)
make -C prim verus          →  aws-mpl-primitives:  18 verified, 0 errors  (both feature sets)
make -C verification verify →  11 files:            78 verified, 0 errors  total
```

These are Verus obligation counts, not function counts. No tool prints a
function count.

---

## 3. "I changed ESDK code — did I break a proof?" (the common path)

The verified cores **are** the shipped code: there is one definition of each
function, and it lives inside `verus!`. If you edit one, you are editing the
proof's subject.

**Check your change:**

1. From the repo root, `touch esdk/src/lib.rs` (defeat the cache).
2. `make -C esdk verus`. After each `Checking aws-esdk v...` line, read the
   first `verification results::` line; it must say `… 0 errors`. The Makefile
   runs both feature sets, so there are two such lines, and both must be
   `0 errors`.
3. If you touched `prim`, also run `make -C prim verus` (both feature sets).
4. The standalone models in `verification/` do not import the crates, so your
   esdk change cannot break them mechanically — but it can make them *stale*
   (describing code that no longer behaves that way). Run
   `make -C verification verify` if you touched something a model mirrors, and
   see §7 on drift.

**Which files have `verus!` blocks** (where a break can happen; from
`grep -rl 'verus! *{' esdk/src prim/src` at `9964b20b`): in `esdk`, under
`esdk/src/message/` — `serialize_functions.rs`, `header.rs`,
`header_types.rs`, `v1_header_body.rs`, `body/body_decrypt.rs`,
`body/body_aad.rs`, `body/body_encrypt.rs` — plus `esdk/src/key_derivation.rs`,
`esdk/src/secret.rs`, `esdk/src/decrypt.rs`, `esdk/src/decrypt_gate.rs`,
`esdk/src/encrypt.rs` and `esdk/src/encrypt_gate.rs`. In `prim`:
`prim/src/ecdsa.rs`, `prim/src/lib.rs`, `prim/src/hkdf.rs` and
`prim/src/aws_lc_specs.rs`. A change to a gate module or to a caller that
holds a token can break the level 2 order, which the compiler then reports. The full per-function table is in
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
  obligation. (At `9964b20b`, `esdk/src` has no `external_body`. In `prim`,
  every `external_body` sits on the wrapper struct of an
  `external_type_specification`, which the reviewer's soundness grep allows.
  The `utf8_check` wrapper around `std::str::from_utf8` is in the standalone
  model `verification/io_stream_aligned.rs`, a documented trusted boundary.)
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

**In-crate, gate, or model — the decision.** Prove it in-crate (level 1) if the
property can be carved into a synchronous core inside `verus!`. If the property
is an order of async steps, express it as a typestate token (level 2,
`verus-capabilities.md` Category 1e): a sync gate inside `verus!` mints the
token only when the check passed, and the guarded step takes the token. This is
how the decrypt and encrypt orders (VR-001 (b), VR-002, VR-015, VR-015 (b),
VR-016, VR-019) are covered today. Fall back to a standalone model (level 4)
only when neither a core nor a token can express the property. If you do, say
so and never present it as covering the shipped path.

**Picking and routing a target — the provability gate.** Before writing
anything, run the candidate through `.kiro/agents/verus-capabilities.md`. It
answers three questions: is this Verus-provable at all; is it provable *in place
here* (the "provable AND present" gate); and which of the four categories and
which proof agent it belongs to. If the decision aid says "No" or "not here"
(crypto hardness, constant-time, external-service policy, probabilistic secrecy,
absence-of-code, an async order no token can express, anything inside `mpl`),
it is not a Verus target — record it as out of scope with the reason. A design
that needs a new trusted spec or law (a new TCB row) stops for the user's
approval before any code is written (recipe R1 gate G1, §10).

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
| `verus-capabilities` | Triage / provability gate; the proof categories (including 1e, typestate tokens) mapped onto esdk | First, for *any* candidate — decide if it is provable here and route it |
| `verus-header-parsing-proofs` | Writing proofs: header/body parsing, layout, round-trip, decisions, typestate gates (Category 1e) | VR-001, VR-002, VR-003, VR-004, VR-005, VR-007, VR-011 (accessors), VR-012, VR-015, VR-016, VR-019, VR-020 (profile `targets[].agent`) |
| `verus-zero-panic` | Writing proofs: absence of panics (bounds, arithmetic, `unwrap`) and wrapper length contracts | VR-006, VR-008, VR-009, VR-013, VR-014, VR-017, VR-018 |
| `verus-unsafe-ffi-safety` | `unsafe`/FFI-boundary safety; owns the TCB list (profile `tcb.owner_agent`) | When a design needs a new TCB row (it signs off with the user's approval); VR-010 (deferred). There is no in-crate `unsafe` |
| `verus-proof-reviewer` | Reviewing one proven target: checklist C1–C13, read-only on code | Recipe R1 step 6 (§10); it writes `review.md` and `verdict.json` |
| `spec-analyzer` | Deriving targets: extract security properties from `spec/` + Duvet | Pipeline Step 1 (specification ingestion) |
| `threat-model-generator` | Deriving targets: STRIDE + attack trees | Pipeline Step 2 (threat modelling) |
| `verification-recommender` | Deriving targets: gate, score, route into the ranked VR list | Pipeline Step 3 (and the capability-driven Stage 2′) |
| `ai-verification-pipeline` | The full three-stage re-derivation methodology | A ground-up re-derivation (no baseline, or the architecture changed fundamentally) |
| `ai-verification-update` | The incremental delta/drift re-sync between full passes | The common maintenance case: code moved, proofs added, docs need to catch up |

**Which one do I want?**

- *Can I even prove this?* → `verus-capabilities`.
- *I know what to prove, write it.* → one of the three `verus-*` proof agents, by
  domain (parsing vs panic vs unsafe). Load the verus skill first. For a change
  to shipped code, run it through recipe R1 (§10), which also runs the reviewer.
- *Is this proof sound and honestly described?* → `verus-proof-reviewer`.
- *Where do targets come from?* → `spec-analyzer` → `threat-model-generator` →
  `verification-recommender` (plus the capability-driven Stage 2′ sweep).
- *Re-derive everything from scratch* → `ai-verification-pipeline`.
- *Just catch the docs up to what changed* → `ai-verification-update`. This is
  the one you reach for most.

---

## 7. Adding or re-scoping a target, keeping docs honest

**Target numbering.** Targets VR-001…VR-020 exist; none is reused. The next
free id is in profile `ids.next_free` (today `VR-021`, YAML id `VR-2026-021`);
confirm it with the command in profile `ids.next_free_check` before you take it.
Ids in the YAML recommendations have the form `VR-2026-NNN`. Do not confuse
them with the MPL-Verus ids `VR-2026-Cxx` / `VR-2026-Txx` (profile
`ids.external_ids`; VR-2026-C03 is implemented by VR-013 and VR-014). There is
no VR-2026-008 YAML block; that is a known gap (profile `ids.known_gaps`), not
a missing proof. Findings are numbered `VR-0NN Fk`, never a bare `Fk`. Every
target carries an `origin` field: `threat-driven` (traces to a threat in
`docs/threat-model.md`) or `capability-driven` (traces to a Verus capability
category and the code invariant it establishes, e.g. VR-012, VR-020). Triage
every proposed target through `verus-capabilities.md` before adding it, and
record each part of a new target with its ladder level in profile `targets[]`.

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
   against `<sha>`" line (profile `artifacts.baseline_markers`) to the current
   tip so the next pass starts here, and re-run the relevant command to confirm
   the numbers you wrote match tool output. Move a marker only in a doc you
   edited, and make it name only what you rechecked; keep older notes as
   history.

**Counts in docs.** Every count comes from a named tool run (a
`verification results::` line, a test summary, a `grep -c`). No tool prints a
number of exec fns or proof fns; if a doc gives one, label it "by reading the
code".

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
| **Async ordering** (VR-001 (b), VR-002, VR-015, VR-015 (b), VR-016, VR-019) | Level 2: Verus proves the gate that mints each token; the compiler enforces the order. Still trusted: callers pass the real check results, the guarded step is the only path, a token is not tied to one message. VR-019 covers one direction only (finding VR-019 F1). The old ordering models are superseded history | `esdk/src/decrypt_gate.rs`, `esdk/src/encrypt_gate.rs`, `esdk/src/secret.rs`; profile `typestate_gates`; proofs report |
| **aws-lc-rs trust boundary** (VR-013, VR-014) | Trusted: `assume_specification` rows A1–A20 in `prim/src/aws_lc_specs.rs`; A-OPEN (row A20, `LessSafeKey::open_separate_gather`) is a labeled assumption (level 8), so BUG-07(b) is not proven at the aws-lc-rs level | proofs report "TCB table (trusted specs and laws)"; profile `tcb` |
| **T-cmp** (VR-020) | Trusted: `obeys_cmp::<String>()`, the `requires` of `required_ec_entries`; vstd proves this law for integer keys, not for `String`. Approved by the user, signed off by the TCB owner | `esdk/src/decrypt.rs`; proofs report TCB table |
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

For a change made through recipe R1 (§10), this review is written down: the
`verus-proof-reviewer` agent runs checklist C1–C13 and the run does not ask to
merge until its verdict is `APPROVED`.

---

## 10. The verification toolkit

The toolkit is the generic method (agents, skill, steering, recipes, templates,
workflow); everything specific to the ESDK sits in the library profile. The
toolkit overview is `.kiro/verification-toolkit/README.md`.

**The library profile.** `.kiro/verification-profile/verification-profile.yaml`,
with the appendices `domain.md`, `idioms.md` and `targets.md` in the same
directory. It holds the crates and their verify commands, feature sets and
result-line rule, the TCB (`tcb`), the typestate gates (`typestate_gates`),
the id rules (`ids`), every target with the level of each part (`targets`),
the maintained docs and baseline markers (`artifacts`), the CI checks and the
local limits. Agents read it first. Its schema is
`.kiro/verification-toolkit/verification-profile.template.yaml`: the same
top-level keys with empty values and one comment per key naming its readers.
The profile holds no counts; counts live only in the proofs report.

**Recipe R1: prove one target.** The spec is
`.kiro/verification-toolkit/recipes/R1-prove-target.md`; when it and the
workflow file disagree, the spec wins. It takes one target from a feasibility
check to a reviewed local commit:

| Step | What happens |
|---|---|
| 0 setup | task directory, worktree on a new task branch from `base_sha`, profile and schema checks, `decisions.md` |
| 1 feasibility | baseline Verus runs, spec facts, scratch design, id check; verdict `GO, clean`, `GO, needs approval`, `FINDING, paused` or `NO-GO`; gate **G1** |
| 2 prove | the proof agent implements the design; final cache-busted run; local commit |
| 3 mutations | at least one mutation per new obligation, each reverted; tree clean, no commit |
| 4 CI parity | verify, models, tests, lints and the profile's CI checks on HEAD; "Not run locally" list |
| 5 docs | maintained docs, status oracle and the profile's `targets[]` / `ids` entries; local docs commit |
| 6 review loop | `fix`, then `review` by `verus-proof-reviewer`; at most 2 iterations; gate **G2** |
| 7 merge gate | gate **G3a**: ask before `git merge --ff-only` into `base_branch` |
| 8 push gate | gate **G3b**: ask again, separately, before any push or PR-body edit |

The gates: **G1** stops for the user when the verdict is not `GO, clean`, the
change is intrusive, it needs a behavior or API change, the design needs a new
TCB row or trusted assumption, or a finding appears. **G2** ends the review
loop only on `"verdict": "APPROVED"` in `verdict.json`. **G3a** and **G3b**
ask before merge and before push; a yes to one is not a yes to the other.
Nothing is merged or pushed without asking. Every user decision is recorded
word for word in `decisions.md` and is not re-decided later.

**Running the workflow.** `.kiro/workflows/verus-prove-target.workflow.json` is
the machine-readable form of R1. Kiro finds it in `.kiro/workflows/`. Start it
with these seven inputs:

| Input | Value |
|---|---|
| `target_id` | an existing profile `targets[].id`, or `new` |
| `target_description` | one line: what is to be proven |
| `base_branch` | the branch the work starts from (for example `Mahnush_Verus`) |
| `base_sha` | the full sha of `base_branch` now (`git rev-parse <base_branch>`) |
| `profile_path` | `<worktree_path>/.kiro/verification-profile/verification-profile.yaml` |
| `task_dir` | absolute path of a task-notes directory inside the workspace, never committed (for example under `.agents/tasks/`) |
| `worktree_path` | absolute path of the worktree to create; convention `<repo root>/.worktrees/<basename of task_dir>` |

Every step runs as the bundled `wf-coder` agent except `review`, which runs as
`verus-proof-reviewer`. The workflow was validated by its first run (task
`r1-validate-vr020`, VR-020); the spec section "Workflow file" lists what that
run confirmed and the two points still open (artifacts declared inside the
`repeat` seen by later steps, and `captureOutput`; nothing depends on either).

**The reviewer.** `.kiro/agents/verus-proof-reviewer.md` reviews one proven
target and edits no code. Its checklist C1–C13 covers scope, the soundness grep
on added lines, that the proof reaches the shipped code, the mutation log, one
definition per item, behavior preserved, honesty-ladder claims, TCB rows, live
counts, CI parity, docs and ids, git state, and recorded decisions. It writes
`<task dir>/review.md` and `<task dir>/verdict.json`; the verdict is `APPROVED`
if and only if no finding is `blocker` or `major`.

**The templates.** In `.kiro/verification-toolkit/templates/`:
`T-feasibility.md` (the step 1 note, `feasibility.md`), `T-mutations-log.md`
(the step 3 log, `logs/mutations.md`) and `T-review.md` (the step 6 review,
`review.md`, and the shape of `verdict.json`).

---

## Sources

Everything above is grounded in the following repository artifacts; consult them
for the authoritative, live detail:

- [`docs/verus-proofs-report.md`](./verus-proofs-report.md) — authoritative proof status, per-target and per-file, and the TCB table
- [`docs/verification-recommendations.md`](./verification-recommendations.md) — the ranked VR-001…VR-020 targets, scores, and honest scope
- [`docs/threat-model.md`](./threat-model.md) — the threat model the threat-driven targets trace to
- `.kiro/skills/verus/SKILL.md` — the verus skill, its absolute invariants and the honesty ladder
- `.kiro/steering/verus-verification.md` — repo-specific Verus idioms and ground rules
- `.kiro/agents/` — the agents (`verus-capabilities`, the three `verus-*` proof agents, `verus-proof-reviewer`, `spec-analyzer`, `threat-model-generator`, `verification-recommender`, `ai-verification-pipeline`, `ai-verification-update`)
- `.kiro/verification-profile/` — the ESDK library profile and its appendices
- `.kiro/verification-toolkit/` — the toolkit README, the profile schema, recipe R1 and the templates
- `.kiro/workflows/verus-prove-target.workflow.json` — the R1 workflow
- `docs/verus-in-crate-migration-design.md` and PR #103 — the CI open question
