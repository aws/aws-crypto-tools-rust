---
name: ai-verification-pipeline
description: Reference methodology for the AI-driven formal verification pipeline. Defines the three-stage approach (Specification Ingestion → Threat Modeling → Verification Targets), plus the parallel capability-driven path (Stage 2'), used by all agents in this folder. Not an executable agent — serves as the shared methodology document that threat-model-generator, spec-analyzer, verification-recommender, verus-capabilities, and the Verus proof agents follow.
tools: ["read", "web"]
---

# AI-Driven Formal Verification Pipeline

**From Specification → Threat Model → Verification Targets**

This document defines the systematic, repeatable approach for leveraging AI agents to produce specification-grounded threat models and prioritized formal verification targets for the **native-Rust AWS Encryption SDK (ESDK)** in this repository.

## Repository Layout

| Crate / item | Path | Role |
|--------------|------|------|
| `aws-esdk` | `esdk/` | The Encryption SDK: client, encrypt/decrypt, message format (`esdk/src/message/`), key derivation, secret types (`esdk/src/secret.rs`). **Primary verification target. Verus-checked** (`verus!` blocks, `make -C esdk verus`). Typestate gates in `esdk/src/decrypt_gate.rs` and `esdk/src/encrypt_gate.rs`. |
| `aws-crypto-mpl` | `mpl/` | The Material Providers Library: keyrings, CMMs, material structures. A dependency, treated as a trusted contract here; not Verus-checked. |
| `aws-mpl-primitives` | `prim/` | Safe wrappers over `aws-lc-rs` (AES-GCM, HKDF, ECDSA, HMAC, digest, RNG). The cryptographic boundary. **Verus-checked** (`verus!` blocks, `make -C prim verus`); the trusted aws-lc-rs specs are in `prim/src/aws_lc_specs.rs`. |
| Spec | `spec/` (repo root) | The ESDK specification, checked out by `scripts/resolve-spec.sh` (not a submodule; may be absent locally). Tracked documents are listed in `esdk/.duvet/config.toml`. |
| Duvet annotations | `//=` / `//#` comments in `esdk/src` and `esdk/tests` | Requirement-to-code traceability. |
| Standalone models | `verification/` | Self-contained Verus models (`make -C verification verify`); see `verification/README.md`. |
| C++ shim | `esdk/shims/aws-esdk-cpp/` | C++ bindings; holds the only shipped-path `unsafe`. |

## Pipeline Overview

There are **two entry paths** into verification targets, which merge at Step 3:

```
                         THREAT-DRIVEN PATH
┌─────────────────────┐     ┌────────────────────┐     ┌────────────────────────┐
│ Step 1:             │     │ Step 2:            │     │ Step 3:                │
│ Specification       │ ──► │ AI-Generated       │ ──► │ Risk-Based Verification│
│ Ingestion           │     │ Threat Models      │     │ Recommendations        │
└─────────────────────┘     └────────────────────┘     └───────────▲────────────┘
        │                                                           │
        │                    CAPABILITY-DRIVEN PATH                 │
        └────────────────────────────────────────────────────────► │
             Step 2': Capability-Driven Target Discovery ───────────┘
             (verus-capabilities sweeps the code for provable
              properties independent of any specific threat)
```

**Threat-driven** targets answer "what attack are we defending against?": they start from a threat and find the code to prove. **Capability-driven** targets answer "what can we prove here that is worth proving regardless of a named threat?": they start from Verus's capabilities (`verus-capabilities`) and the code, and hold as baseline assurance. Both feed the same Step 3 scoring, the same provability gate (`verus-capabilities.md`) and the same proof agents.

## Design Principles

1. **Human-in-the-loop:** AI augments expert judgment, never replaces it
2. **Incremental:** Pipeline runs continuously as specs and code evolve
3. **Auditable:** Every recommendation traces back to a specification requirement. Threat-driven targets also trace to a threat; capability-driven targets trace to a Verus capability category and the code invariant they establish.
4. **Tool-dependent:** Recommendations map to the Verus verification tool for Rust
5. **Specification-grounded:** Threats are derived from the formal ESDK spec and its Duvet annotations, not documentation summaries
6. **No overclaiming:** A property counts as verified only when Verus prints `0 errors` for it, with no `assume`, `admit`, `external_body` or `external` used to force the pass. Every claim carries its level from the **honesty ladder** in the `verus` skill (`.kiro/skills/verus/SKILL.md`, "Honesty ladder").

## Stage 1: Specification Ingestion

### Establishing Scope and Threat Mindset

Before ingestion, define:
- **System type:** Client-side encryption library (not a managed service)
- **In scope:** SDK cryptographic operations (encrypt/decrypt), message format (header, body, footer), key derivation and key commitment, commitment-policy enforcement at the ESDK boundary, the key-management interfaces the ESDK calls (CMM, keyring) as contracts, and data-key handling inside `esdk`
- **Out of scope:** Underlying KMS security, application business logic, and the internals of the MPL keyrings/CMMs and `aws-lc-rs`, which are treated as trusted dependencies
- **Threat mindset:** Application-level cryptography — local compute, memory management, KMS interaction

### Input Sources

- Standards Documents: RFC 8446, FIPS 140-3, SP 800-56A/B, SP 800-38D (GCM), RFC 5869 (HKDF)
- ESDK Specification (source of truth): `spec/` — the `esdk/.duvet/config.toml` set (`spec/data-format/*`, `spec/client-apis/*`, `spec/framework/transitive-requirements.md`) plus `spec/framework/algorithm-suites.md`
- Duvet Annotations: the inline `//=` / `//#` comments in `esdk/src` and `esdk/tests`. Use them to locate the code that realizes a requirement and whether a test (`type=test`) or implication covers it
- Dependency contracts: the native `mpl/src` and `prim/src` code the ESDK calls (material getters, `aes_encrypt` / `aes_decrypt`, HKDF, ECDSA)
- Source Code: the implementation in `esdk/src` as an implicit specification
- Existing Proofs: the in-crate `verus!` proofs in `esdk/src` and `prim/src` and the standalone models in `verification/` (see `docs/verus-proofs-report.md`). There are no in-repo Dafny proofs

**Critical:** Feed the agent the formal specification (`spec/`) and the Duvet annotations — not just documentation. The spec is the source of truth.

### Extraction Outputs

| Output | Format | Consumer |
|--------|--------|----------|
| Structured requirements | JSON/YAML | Threat model generator |
| Requirement → code map | Markdown table (from Duvet annotations) | Verification recommender |
| State machines | DOT/TLA+ fragments | Protocol verification |
| Pre/post-conditions | Verus `requires`/`ensures` sketches | Code-level verification |
| Traceability matrix | Markdown table | Audit and compliance |
| Gap report | Structured findings | Engineering prioritization |

## Stage 2: AI-Generated Threat Models

### Research Known Vulnerabilities First

Before generating new threats, ground the model in demonstrated exploitability:
- CVEs with root cause analysis
- AWS Security Bulletins
- Academic literature on primitives used (AES-GCM non-commitment, HKDF misuse, Invisible Salamanders)
- Related vulnerabilities in sibling libraries (S3 Encryption Client, Database Encryption SDK)

### STRIDE: The "What" of Threat Modeling

| STRIDE Category | Crypto-Specific Manifestation |
|----------------|-------------------------------|
| **S**poofing | Key impersonation, certificate forgery |
| **T**ampering | Ciphertext manipulation, MAC forgery |
| **R**epudiation | Deniable encryption misuse, log gaps |
| **I**nformation Disclosure | Key leakage, plaintext recovery |
| **D**enial of Service | Resource exhaustion, algorithmic complexity |
| **E**levation of Privilege | Algorithm downgrade, key privilege escalation |

### Threat Categories to Cover

- Cryptographic threats: Algorithm downgrade, key commitment bypass, non-committing ciphertext
- Key management threats: Wrapping key compromise, credential theft enabling KMS access
- Application-level threats: Host compromise, memory exposure, dependency supply chain
- Operational threats: Replay/reordering, DoS via malformed messages, side-channel attacks

### Attack Trees: The "How" of Threat Modeling

For each STRIDE threat, decompose into concrete exploitation paths:
1. Take each STRIDE threat as a root goal
2. Decompose into sub-goals using known attack patterns from literature
3. Annotate leaf nodes with: Feasibility, Detectability, Existing mitigation (cite the spec section and, where present, the Duvet-annotated code/test)

### Adversary Models

| Adversary Level | Capabilities | Relevant Attacks |
|----------------|--------------|-----------------|
| Network (Dolev-Yao) | Intercept, inject, replay messages | Protocol-level attacks |
| Local | Read process memory, timing measurements | Side-channel attacks |
| Insider | Access to key material, configuration | Operational misuse |
| Supply Chain | Modify dependencies, build artifacts | Backdoor injection |

### Validation Against the Specification

Cross-check generated threats against what the spec already enforces:
- Threats the SDK already mitigates by design — document as residual risk if misconfigured
- Threats the SDK cannot mitigate — application/operational responsibility
- Threats where mitigation has known gaps — e.g., backward-compatibility downgrades

### Quality Checks

For each generated threat, verify:
- Does it have a concrete attack scenario, not just a category label?
- Are likelihood and impact calibrated to the specific system (not generic)?
- Do mitigations reference specific SDK configuration options or operational controls?
- Are real CVEs cited where applicable?

## Stage 2': Capability-Driven Target Discovery

This stage runs **in parallel** with threat modeling, not after it. Many valuable proofs are not tied to a single threat: they are baseline guarantees that make the whole library sounder, such as panic-freedom of parsing and layout cores, round-trip fidelity of the big-endian codecs, arithmetic safety, and the secret-type invariants. A purely threat-driven pipeline would never scope these, because no attacker "causes" them; their absence is a latent defect.

### Where these targets come from

Driven by `verus-capabilities`, not by the threat model. Sweep the code and the capability map for provable properties:

1. **Enumerate provable surfaces** using the four Verus categories in `verus-capabilities.md`:
   - *Functional correctness:* decision cores in `esdk/src/message/`, `esdk/src/key_derivation.rs` and `prim/src`. Many are done: the round-trip lemmas in `esdk/src/message/serialize_functions.rs` (VR-012) and the key-commitment decision behind `validate_suite_data` (VR-001 (a)) are in-crate. Check the report before scoping
   - *Ordering (Category 1e):* an order between async steps that can be written as a token minted by a sync verified gate (done: VR-001 (b), VR-002, VR-015, VR-019)
   - *Zero-panic:* indexing, slicing and arithmetic sites in `esdk/src` and `prim/src` that can be extracted into synchronous `verus!` cores (`clippy::indexing_slicing` is off in `esdk/src/lib.rs`); input-dependent `.expect` sites (re-check each before citing it)
   - *Low-level & unsafe:* none in-crate (no `unsafe` in `esdk/src`, `mpl/src`, `prim/src`); the C++ shim's pointer validity is trusted, not provable
   - *Concurrency:* not applicable in `esdk` (async/tokio is not verifiable; no hand-written lock protocol)
2. **Filter with the decision aid** in `verus-capabilities.md`: keep only properties that are Verus-provable **and** provable in place here. Discard crypto hardness, external-service policy, probabilistic properties, timing, absence-of-code/confinement, an async order that cannot be written as a token, and anything that would need Verus inside `mpl` (record those as out of scope or model-only, with the reason).
3. **Skip what is already proven:** check the target table in `docs/verus-proofs-report.md` §3 (VR-001…VR-019 at `578b1faa`) first.
4. **Prefer quick wins and blast radius:** a small sync core called on every encrypt or decrypt protects every caller.

### How capability-driven targets are justified

Because there is no threat to cite, a capability-driven target traces to:
- the **Verus capability category** it exercises (1–4), and
- the **code invariant** it establishes (e.g. "for all `x: u32`, decoding the big-endian bytes of `x` yields `x`"), and
- optionally the **spec requirement** it supports (e.g. `spec/data-format/message-header.md` big-endian field encoding).

Its severity in the Step 3 formula is set from the **consequence of the latent defect** (a panic → DoS; a wrong length or layout → interop failure or tampering acceptance), and its `Coverage_Gap` and `Feasibility` are assessed the same way as threat-driven targets.

### Quality checks

- Is the property genuinely input-universal (holds for ALL inputs), not just the tested cases?
- Is it provable **in place** under the in-crate constraints (sync, inside `verus!`, no calls to items outside `verus!` unless they have a trusted spec), or as a typestate gate (Category 1e)? If not, say "model only" and do not present it as covering shipped code.
- Does it establish a standing invariant rather than patching one attack path?
- Would proving it reduce the coverage gap for *multiple* threat-driven targets? (If so, promote it.)

## Stage 3: Risk-Based Verification Recommendations

### Prioritization Formula

```
Priority Score = Severity × Coverage_Gap × Feasibility × Blast_Radius
```

| Factor | Scale | Description |
|--------|-------|-------------|
| Severity | 1–4 | Critical=4, High=3, Medium=2, Low=1. For **threat-driven** targets this is the threat severity; for **capability-driven** targets it is the consequence of the latent defect the proof rules out. |
| Coverage_Gap | 0–1 | 1 = no existing verification; 0 = fully proven in-crate. Model-only proofs reduce the gap for the shipped code only partly. Duvet `type=test` annotations lower the gap but never close it — tests are not proofs. |
| Feasibility | 0–1 | For threat-driven targets: feasibility of the attack (higher = more urgent). For capability-driven targets: likelihood the latent defect is reachable on some input (`1.0` for an all-inputs property such as panic-freedom). |
| Blast_Radius | 1–4 | Number of services/customers affected. Cores on every encrypt/decrypt path score high. |

Every candidate, from either path, first passes the provability gate in `verus-capabilities.md`. Non-provable or not-here candidates are recorded as out of scope with the reason, not scored.

### Verification Tool Mapping

| Property Type | Recommended Tool | When to Use |
|--------------|-----------------|-------------|
| Memory Safety | Verus (Rust) | Buffer bounds, null derefs, use-after-free |
| Functional Correctness | Verus | Algorithm matches spec, state machine compliance |
| Serialization Correctness | Verus | Message format compliance, round-trip fidelity |
| Panic Freedom | Verus | No runtime panics on any input |
| FFI Safety | Verus | Unsafe block soundness, pointer validity (no in-crate `unsafe` today; see `verus-capabilities.md`) |

### Output Format

Each recommendation includes the fields below. **Historical sample:** this VR-002 entry was written before VR-002 was proven in-crate (`3195f86f`). VR-002 is now a Verus-proven gate with a compiler-enforced order (the `HeaderVerified` token in `esdk/src/decrypt_gate.rs`). Copy the shape, not the status or the rationale.
```yaml
recommendation:
  id: VR-2026-002
  target:
    crate: aws-esdk
    file: esdk/src/decrypt.rs
    function: decrypt_steps → header auth verification (esdk/src/message/header_auth.rs)
  property: "Header auth tag MUST be verified before any frame is decrypted"
  formal_spec: "∀ msg: decrypt(msg) → verified(msg.header.tag) precedes decrypt(frame_i) ∀ i"
  tool: Verus
  estimated_effort: 2 engineer-weeks
  origin: threat-driven
  threat_reference: T1
  trace_to_spec: "spec/client-apis/decrypt.md §Verify the header"
  priority_score: 12.0
  rationale: "(historical, before 3195f86f) High severity tampering threat. Proven on a model only (verification/header_auth_ordering_proofs.rs); the shipped async order is not Verus-verifiable."
```

A **capability-driven** recommendation has the same shape but carries a `capability_reference` instead of a `threat_reference`. The example below is a **historical sample** to show the shape. It was a candidate when written; it is now VR-012, proven in-crate (`b30bb367`):

```yaml
recommendation:
  id: VR-2026-012
  target:
    crate: aws-esdk
    file: esdk/src/message/serialize_functions.rs
    function: u32_to_be / be_u32 (and the u64 pair)
  property: "For all x, decoding the big-endian bytes produced for x yields x"
  formal_spec: "∀ x: u32. spec_be_u32(bytes(spec_u32_to_be(x))) == x"
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  origin: capability-driven
  capability_reference:
    category: 1   # Functional correctness, 1c round-trip (see verus-capabilities.md)
    invariant: "the verified big-endian encoders and decoders are exact inverses"
  threat_reference: null  # no specific threat — baseline assurance
  trace_to_spec: "spec/data-format/message-header.md (big-endian integer fields); not a single clause"
  priority_score: 4.0
  scoring:
    severity: 2        # consequence: a mismatched encoder/decoder breaks interop or header auth
    coverage_gap: 0.5  # each side is verified against its spec fn; the link is not
    feasibility: 1.0   # must hold for ALL inputs
    blast_radius: 4    # every message header and body AAD
  quick_win: true
  rationale: "Cheap, sync, in-crate lemma that links two already-verified cores."
```

### Continuous Re-Prioritization

The pipeline runs continuously:
- On spec change: New requirements trigger STRIDE re-analysis
- On code change: Modified functions re-evaluated against the threat model **and** re-swept with `verus-capabilities` for newly introduced provable surfaces (new indexing/arithmetic, new codec, new `unsafe`), and re-run `make -C esdk verus` and `make -C prim verus` so recorded counts stay current
- On new CVE: Emerging attack patterns update feasibility scores
- On proof completion: Coverage gaps recalculated, next target promoted — from either the threat-driven or capability-driven queue

## Agent Mapping to Pipeline Stages

| Pipeline Stage | Agent | Role |
|---------------|-------|------|
| Step 1: Specification Ingestion | `spec-analyzer` | Extract security properties from `spec/` + Duvet annotations |
| Step 2: Threat Modeling | `threat-model-generator` | STRIDE + attack trees |
| Step 2': Capability-Driven Discovery | `verification-recommender` using `verus-capabilities` | Sweep the code for provable baseline targets |
| Step 3: Prioritization | `verification-recommender` | Gate, score and assign targets to the Verus agents |
| Step 3 (reference) | `verus-capabilities` | Decide whether a property is Verus-provable here, pick the proof category, and route to the proof agent |
| Step 3a: Header Parsing Proofs | `verus-header-parsing-proofs` | Prove parsing correctness |
| Step 3b: Zero-Panic Proofs | `verus-zero-panic` | Prove absence of panics in serialization |
| Step 3c: FFI Safety Proofs | `verus-unsafe-ffi-safety` | Prove unsafe block memory safety; own the TCB list of trusted specs |

## Output Checklist

Before finalizing any output, verify:
- ☐ Scope and exclusions are clearly stated
- ☐ Application-level cryptography mindset is articulated (not generic cloud security)
- ☐ System description matches the formal specification (not just marketing docs)
- ☐ Each threat has: description, STRIDE category, likelihood, impact, mitigations
- ☐ At least one real CVE or security bulletin is referenced
- ☐ Risk summary table is present with clear ratings
- ☐ Verification recommendations are prioritized and actionable with tool mappings
- ☐ Backward-compatibility mechanisms are called out as potential downgrade vectors
- ☐ Trust boundaries are explicitly identified
- ☐ Each verification target is tagged `threat-driven` or `capability-driven`
- ☐ Threat-driven targets trace to a threat and a specification requirement (cite the Duvet annotation where one exists)
- ☐ Capability-driven targets trace to a Verus capability category and the code invariant they establish (spec citation optional but preferred)
- ☐ The capability-driven sweep (Stage 2') was run, not just threat modeling, and every candidate passed the `verus-capabilities.md` provability gate
- ☐ Nothing is described as verified without a `0 errors` Verus result; every claim carries its honesty-ladder level (`verus` skill)
