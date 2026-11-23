---
name: mpl-ai-verification-pipeline
description: Reference methodology for the AI-driven formal verification pipeline. Defines the three-stage approach (Specification Ingestion → Threat Modeling → Verification Targets) used by all agents in this folder. Not an executable agent — serves as the shared methodology document that mpl-threat-model-generator, mpl-spec-analyzer, and Verus proof agents follow.
tools: ["read", "web"]
---

# AI-Driven Formal Verification Pipeline

**From Specification → Threat Model → Verification Targets**

This document defines the systematic, repeatable approach for leveraging AI agents to produce specification-grounded threat models and prioritized formal verification targets for the **AWS Cryptographic Material Providers Library (MPL)** — the native-Rust implementation in this repository.

## Repository Layout

This repo (`aws-crypto-tools-rust`, branch `aws-crypto-rust/esdk-native-mpl`) contains:

| Crate | Path | Role |
|-------|------|------|
| `aws-crypto-mpl` | `mpl/` | The Material Providers Library: keyrings, CMMs, key stores, caches, and material structures. Primary verification target. |
| `aws-mpl-primitives` | `prim/` | Thin, safe wrappers over `aws-lc-rs` for AES-GCM, HMAC, digest, HKDF, KBKDF-CTR, ECDSA, and RNG. The cryptographic boundary. |
| spec (submodule) | `spec/` → `aws-encryption-sdk-specification` | The formal MPL specification. Framework specs live under `spec/framework/`. |
| Duvet annotations | inline `//= spec/... //# ...` comments in `mpl/src` and `mpl/tests` | Requirement-to-code traceability (see the `duvet/mpl-annotations` branch). |

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
             (mpl-verus-capabilities sweeps the code for provable
              properties independent of any specific threat)
```

**Threat-driven** targets answer "what attack are we defending against?" — they start from a threat and find the code to prove. **Capability-driven** targets answer "what can we cheaply prove here that is worth proving regardless of a named threat?" — they start from Verus's capabilities (`mpl-verus-capabilities`) and the code, and hold as baseline assurance. Both feed the same Step-3 scoring and the same proof agents.

## Design Principles

1. **Human-in-the-loop:** AI augments expert judgment, never replaces it
2. **Incremental:** Pipeline runs continuously as specs and code evolve
3. **Auditable:** Every recommendation traces back to a specification requirement. Threat-driven targets also trace to a threat; capability-driven targets trace to a Verus capability category and the code invariant they establish.
4. **Tool-dependent:** Recommendations map to the Verus verification tool for Rust
5. **Specification-grounded:** Threats are derived from the formal MPL spec and its Duvet annotations, not documentation summaries

## Stage 1: Specification Ingestion

### Establishing Scope and Threat Mindset

Before ingestion, define:
- **System type:** Client-side key-management library (the Material Providers Library) — it produces and manages the data keys, wrapping keys, and material structures that a higher-level encryption SDK consumes. It is not a managed service.
- **In scope:** Keyring operations (`on_encrypt`/`on_decrypt`), the CMM (`get_encryption_materials`/`decrypt_materials`), the branch-key store and its KMS/DynamoDB interactions, the cryptographic-materials caches (local + storm-tracking), branch-key derivation and wrapping, encryption-context canonicalization, and the crypto primitives in `prim/`.
- **Out of scope:** The security of AWS KMS and DynamoDB themselves, the correctness of `aws-lc-rs`/`aws-lc`, message-format serialization (that belongs to the ESDK, not the MPL), and application business logic.
- **Threat mindset:** Application-level key management — local compute, secret-material lifetime in memory, KMS/DDB interaction, and cache poisoning/confusion. Not generic cloud security.

### Input Sources

- MPL Framework Specifications (source of truth): the `spec/framework/*.md` documents that the Duvet config enumerates —
  - `algorithm-suites.md`, `structures.md`, `commitment-policy.md`
  - `keyring-interface.md`, `raw-aes-keyring.md`, `aws-kms/aws-kms-hierarchical-keyring.md`, `aws-kms/aws-kms-mrk-match-for-decrypt.md`
  - `cmm-interface.md`, `default-cmm.md`
  - `cryptographic-materials-cache.md`, `local-cryptographic-materials-cache.md`, `storm-tracking-cryptographic-materials-cache.md`
  - `branch-key-store.md`
- Duvet Annotations: the inline `//= spec/...` / `//# ...` comments in `mpl/src/**/*.rs` and `mpl/tests/**/*.rs`. These already map RFC 2119 requirements to implementation and test sites — use them to locate the exact code that realizes a requirement and whether a test (`type=test`) or implication (`type=implication`) covers it.
- Standards Documents: NIST SP 800-108 (KBKDF counter mode, used for branch-key derivation), SP 800-38D (AES-GCM), SP 800-56A (ECDH where relevant), RFC 5869 (HKDF), SEC 1 v2.0 (ECDSA key encoding).
- The Dafny MPL as a reference specification: this native-Rust code mirrors the Dafny MPL's structures (e.g. `SignatureKeyPair`, `FieldSize`, `PlaintextDataKey`). Dafny pre/post-conditions are useful as an oracle for expected behavior.
- Source Code: the implementations in `mpl/src/` and `prim/src/` as implicit specifications.

**Critical:** Feed the agent the formal specification (`spec/framework/*.md`) and the Duvet annotations — not just documentation. The spec is the source of truth; the annotations are the pre-built traceability index into the code.

### Extraction Outputs

| Output | Format | Consumer |
|--------|--------|----------|
| Structured requirements | JSON/YAML | Threat model generator |
| Requirement → code map | Markdown table (from Duvet annotations) | Verification recommender |
| Pre/post-conditions | Verus `requires`/`ensures` sketches | Code-level verification |
| Traceability matrix | Markdown table | Audit and compliance |
| Gap report | Structured findings | Engineering prioritization |

## Stage 2: AI-Generated Threat Models

### Research Known Vulnerabilities First

Before generating new threats, ground the model in demonstrated exploitability:
- CVEs with root cause analysis
- AWS Security Bulletins
- Academic literature on the primitives and patterns used (AES-GCM key-commitment / Invisible Salamanders, HKDF/KBKDF misuse, KMS key-policy confusion, MRK cross-region matching pitfalls, cache-timing and cache-poisoning attacks)
- Related vulnerabilities in sibling libraries (AWS Encryption SDK, S3 Encryption Client, Database Encryption SDK, which consume the MPL)

### STRIDE: The "What" of Threat Modeling

| STRIDE Category | MPL-Specific Manifestation |
|----------------|-------------------------------|
| **S**poofing | Wrapping-key impersonation, KMS key-ARN confusion, MRK mismatch accepted on decrypt |
| **T**ampering | Branch-key record tampering, encryption-context alteration escaping the AAD, cache entry substitution |
| **R**epudiation | Missing/ambiguous key-id binding, gaps in what is authenticated in a branch-key record |
| **I**nformation Disclosure | Plaintext data key or branch key leaking via memory (failed zeroization), logs, or over-sized buffers |
| **D**enial of Service | Cache stampede / storm on cold key, unbounded cache growth, KMS throttling amplification |
| **E**levation of Privilege | Algorithm-suite downgrade, commitment-policy bypass, wrapping a data key under a weaker suite than requested |

### Threat Categories to Cover

- Cryptographic threats: algorithm-suite downgrade, non-committing suite selection, KBKDF/HKDF misuse, AES-GCM nonce handling in raw-AES keyring, key-commitment bypass
- Key management threats: branch-key store record integrity, KMS key-id/ARN validation, MRK matching for decrypt, wrapping-key compromise
- Cache threats: cache poisoning, cross-tenant entry confusion, TTL/expiry bypass, storm-tracking correctness under concurrency
- Application-level threats: host compromise, secret material persisting in memory (zeroization failure), dependency supply chain
- Operational threats: KMS/DDB error handling leaking information, DoS via malformed inputs or cache pressure

### Attack Trees: The "How" of Threat Modeling

For each STRIDE threat, decompose into concrete exploitation paths:
1. Take each STRIDE threat as a root goal
2. Decompose into sub-goals using known attack patterns from literature
3. Annotate leaf nodes with: Feasibility, Detectability, Existing mitigation (cite the spec section and, where present, the Duvet-annotated code/test)

### Adversary Models

| Adversary Level | Capabilities | Relevant Attacks |
|----------------|--------------|-----------------|
| Network (Dolev-Yao) | Intercept, inject, replay to/from KMS/DDB | Record tampering, replay of stale branch-key records |
| Local | Read process memory, timing measurements | Secret-material exposure, cache-timing side channels |
| Insider | Access to key material, KMS policy, DDB table | Operational misuse, key-policy confusion |
| Supply Chain | Modify dependencies, build artifacts | Backdoor injection via `aws-lc-rs` or transitive deps |

### Validation Against the Specification

Cross-check generated threats against what the spec and code already enforce:
- Threats the MPL already mitigates by design — document as residual risk if misconfigured (cite the Duvet-annotated requirement)
- Threats the MPL cannot mitigate — application/operational responsibility (e.g. KMS policy)
- Threats where mitigation has known gaps — e.g. suite-downgrade or commitment-policy edges

### Quality Checks

For each generated threat, verify:
- Does it have a concrete attack scenario, not just a category label?
- Are likelihood and impact calibrated to the MPL specifically (not generic)?
- Do mitigations reference specific spec sections, config options, or Duvet-annotated code/tests?
- Are real CVEs cited where applicable?

## Stage 2': Capability-Driven Target Discovery

This stage runs **in parallel** with threat modeling, not after it. It exists because many high-value proofs are not tied to any single threat — they are baseline guarantees that make the whole library sounder: total panic-freedom of the crypto primitives, memory-safe secret zeroization, round-trip fidelity of the record/encryption-context codecs, and cache-arithmetic safety. A purely threat-driven pipeline would never scope these, because no attacker "causes" them — their absence is simply a latent defect.

### Where these targets come from

Driven by `mpl-verus-capabilities`, not by the threat model. Sweep the code and the capability map for provable properties:

1. **Enumerate provable surfaces** using the four Verus categories in `mpl-verus-capabilities.md`:
   - *Functional correctness:* codec round-trips (`keystore/record.rs`, `keystore/encryption_context.rs`), suite-table correctness, KBKDF fixed-info layout
   - *Zero-panic:* every `prim` crypto call, every `copy_from_slice`/`try_into`/slice/index/arithmetic site in `mpl/src` and `prim/src`
   - *Low-level & unsafe:* the `PlaintextDataKey::zeroize` block; aws-lc-rs safe-wrapper preconditions
   - *Concurrency:* the storm-tracking cache single-inflight invariant
2. **Filter with the decision aid** in `mpl-verus-capabilities.md`: keep only properties that are Verus-provable **and** present in this repo; discard crypto-hardness, external-service, and probabilistic properties.
3. **Prefer quick wins and blast radius:** a single zero-panic proof over a `prim` function protects every MPL caller of it. These are cheap, high-coverage, and worth doing even with no threat attached.

### How capability-driven targets are justified

Because there is no threat to cite, a capability-driven target traces to:
- the **Verus capability category** it exercises (1–4), and
- the **code invariant** it establishes (e.g. "for all inputs, `prim::hmac` returns without panicking"), and
- optionally the **spec requirement** it supports (e.g. `structures.md` "plaintext data key SHOULD offer an interface to zero").

Its severity in the Step-3 formula is set from the **consequence of the latent defect** (a panic → DoS = Medium/High; a residual secret in memory → Info Disclosure = High), and its `Coverage_Gap` and `Feasibility` are assessed the same way as threat-driven targets. Blast radius is often high because one primitive underpins many callers.

### Quality checks

- Is the property genuinely input-universal (holds for ALL inputs), not just the tested cases?
- Does it establish a standing invariant rather than patching one attack path?
- Would proving it reduce the coverage gap for *multiple* future threat-driven targets? (If so, promote it — it is foundational.)

## Stage 3: Risk-Based Verification Recommendations

### Prioritization Formula

```
Priority Score = Threat_Severity × Coverage_Gap × Feasibility × Blast_Radius
```

| Factor | Scale | Description |
|--------|-------|-------------|
| Severity | 1–4 | Critical=4, High=3, Medium=2, Low=1. For **threat-driven** targets this is the threat severity; for **capability-driven** targets it is the consequence of the latent defect the proof rules out (e.g. panic → DoS, residual secret → info disclosure). |
| Coverage_Gap | 0–1 | 1 = no existing verification; 0 = fully proven. Duvet `type=test` annotations reduce (but do not zero) the gap — tests are not proofs. |
| Feasibility | 0–1 | For threat-driven targets: feasibility of the attack. For capability-driven targets: likelihood the latent defect is actually reachable on some input (a `1.0` for total panic-freedom, since it must hold for all inputs). |
| Blast_Radius | 1–4 | Number of downstream SDKs/customers affected. Capability-driven proofs over shared primitives often score high here — one `prim` proof protects every caller. |

Both entry paths use the same formula and the same proof agents; they differ only in where the target and its severity originate.

### Verification Tool Mapping

| Property Type | Recommended Tool | When to Use |
|--------------|-----------------|-------------|
| Memory Safety / secret zeroization | Verus (Rust) | Bounds of the `PlaintextDataKey::zeroize` volatile-write loop, no residual key material |
| Functional Correctness | Verus | Algorithm-suite selection, MRK matching, KBKDF fixed-info construction, cache key-identity matches spec |
| Parsing / serialization correctness | Verus | Branch-key record encode/decode round-trip, cache-entry identifier byte layout, encryption-context canonical serialization |
| Panic Freedom | Verus | No runtime panics in `prim` crypto calls (`copy_from_slice`, length checks) or MPL length/index handling on any input |
| Safe-wrapper preconditions (aws-lc-rs) | Verus | Length invariants that must hold before calling `aes_encrypt`/`hmac`/`digest`/`kbkdf_ctr_hmac`/`ecdsa_sign` so they never error/panic |

### Output Format

Each recommendation includes:
```yaml
recommendation:
  id: VR-2026-001
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: wrap_key / unwrap_key
  property: "The branch-key wrapping AAD MUST bind the branch-key-id and version so a record cannot be substituted"
  formal_spec: "∀ record: unwrap(record) succeeds → aad(record) binds (branch_key_id, version)"
  tool: Verus
  estimated_effort: 2 engineer-weeks
  origin: threat-driven
  threat_reference: TM-MPL-007
  trace_to_spec: "spec/framework/branch-key-store.md#record-format"
  priority_score: 12.0
  rationale: "High severity tampering threat; Duvet shows tests but no proof of the AAD binding."
```

A **capability-driven** recommendation has the same shape but carries a `capability_reference` (the Verus category and code invariant) instead of a `threat_reference`:

```yaml
recommendation:
  id: VR-2026-014
  target:
    crate: aws-mpl-primitives
    file: prim/src/lib.rs
    function: hmac / digest / aes_decrypt
  property: "For all inputs, these functions return Ok/Err and never panic (the length-checked copy_from_slice is total)"
  formal_spec: "∀ inputs: !panics(hmac(..)) ∧ !panics(digest(..)) ∧ !panics(aes_decrypt(..))"
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 1 week
  origin: capability-driven
  capability_reference:
    category: 2  # Zero-Panic Guarantees
    invariant: "no reachable panic path in the prim crypto wrappers"
  threat_reference: null  # no specific threat — baseline assurance
  trace_to_spec: "supports structures.md length requirements; not a single spec clause"
  priority_score: 8.0
  scoring:
    severity: 2   # consequence of the defect: a panic is a DoS
    coverage_gap: 1.0
    feasibility: 1.0   # must hold for ALL inputs
    blast_radius: 4    # every MPL caller of these primitives
  quick_win: true
  rationale: "High blast radius, well-known proof pattern, no threat needed — a panic here is a latent DoS across every caller."
```

### Continuous Re-Prioritization

The pipeline runs continuously:
- On spec change: New requirements trigger STRIDE re-analysis
- On code change: Modified functions re-evaluated against the threat model **and** re-swept by `mpl-verus-capabilities` for newly-introduced provable surfaces (new `unsafe`, new indexing/arithmetic, new codec)
- On new CVE: Emerging attack patterns update feasibility scores
- On proof completion: Coverage gaps recalculated, next target promoted — from either the threat-driven or capability-driven queue

## Agent Mapping to Pipeline Stages

| Pipeline Stage | Agent | Role |
|---------------|-------|------|
| Step 1: Specification Ingestion | `mpl-spec-analyzer` | Extract security properties from `spec/framework` + Duvet annotations |
| Step 2: Threat Modeling | `mpl-threat-model-generator` | STRIDE + attack trees for the MPL |
| Step 3: Prioritization | `mpl-verification-recommender` | Score and assign targets to the Verus agents |
| Step 3 (reference) | `mpl-verus-capabilities` | Decide whether a property is Verus-provable in this repo, pick the proof category, and route to the right proof agent |
| Step 3a: Parsing/Serialization Proofs | `mpl-verus-header-parsing-proofs` | Prove correctness of MPL record/identifier/encryption-context (de)serialization |
| Step 3b: Zero-Panic Proofs | `mpl-verus-zero-panic` | Prove absence of panics in `prim` crypto and MPL length/index handling |
| Step 3c: Memory/Secret Safety Proofs | `mpl-verus-unsafe-ffi-safety` | Prove the `zeroize` unsafe block and aws-lc-rs safe-wrapper preconditions |

## Output Checklist

Before finalizing any output, verify:
- ☐ Scope and exclusions are clearly stated (MPL key management, not ESDK message format)
- ☐ Application-level key-management mindset is articulated (not generic cloud security)
- ☐ System description matches the formal MPL specification (not just marketing docs)
- ☐ Each threat has: description, STRIDE category, likelihood, impact, mitigations
- ☐ At least one real CVE or security bulletin is referenced
- ☐ Risk summary table is present with clear ratings
- ☐ Verification recommendations are prioritized and actionable with tool mappings
- ☐ Algorithm-suite / commitment-policy downgrade paths are called out as vectors
- ☐ Trust boundaries (KMS, DynamoDB, cache) are explicitly identified
- ☐ Each verification target is tagged `threat-driven` or `capability-driven`
- ☐ Threat-driven targets trace to a threat and a specification requirement (cite the Duvet annotation where one exists)
- ☐ Capability-driven targets trace to a Verus capability category and the code invariant they establish (spec citation optional but preferred)
- ☐ Capability-driven sweep (Stage 2') was run, not just threat modeling — baseline zero-panic / zeroization / codec-round-trip targets are present
