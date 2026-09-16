---
name: ai-verification-pipeline
description: Reference methodology for the AI-driven formal verification pipeline. Defines the three-stage approach (Specification Ingestion → Threat Modeling → Verification Targets) used by all agents in this folder. Not an executable agent — serves as the shared methodology document that threat-model-generator, spec-analyzer, and Verus proof agents follow.
tools: ["read", "web"]
---

# AI-Driven Formal Verification Pipeline

**From Specification → Threat Model → Verification Targets**

This document defines the systematic, repeatable approach for leveraging AI agents to produce specification-grounded threat models and prioritized formal verification targets for AWS cryptographic libraries.

## Pipeline Overview

```
┌─────────────────────┐     ┌────────────────────┐     ┌────────────────────────┐
│ Step 1:             │     │ Step 2:            │     │ Step 3:                │
│ Specification       │ ──► │ AI-Generated       │ ──► │ Risk-Based Verification│
│ Ingestion           │     │ Threat Models      │     │ Recommendations        │
└─────────────────────┘     └────────────────────┘     └────────────────────────┘
```

## Design Principles

1. **Human-in-the-loop:** AI augments expert judgment, never replaces it
2. **Incremental:** Pipeline runs continuously as specs and code evolve
3. **Auditable:** Every recommendation traces back to a specification requirement and threat
4. **Tool-dependent:** Recommendations map to Verus verification tool for Rust
5. **Specification-grounded:** Threats are derived from the formal spec, not documentation summaries

## Stage 1: Specification Ingestion

### Establishing Scope and Threat Mindset

Before ingestion, define:
- **System type:** Client-side encryption library (not a managed service)
- **In scope:** SDK cryptographic operations, key management interfaces, caching, message format
- **Out of scope:** Underlying KMS security, application business logic
- **Threat mindset:** Application-level cryptography — local compute, memory management, KMS interaction

### Input Sources

- Standards Documents: RFC 8446, FIPS 140-3, SP 800-56A/B, SP 800-38D (GCM)
- AWS Protocol Specifications: AWS Encryption SDK message format, KMS API contracts
- Smithy Models (API contracts): Operations, configuration options
- Dafny Formal Specifications: Compliance annotations, pre/post conditions, invariants
- Key Derivation Logic: HKDF usage, commitment key derivation
- Source Code: Existing implementations as implicit specifications
- Existing Proofs: Previously verified properties and their assumptions

**Critical:** Feed the agent the formal specification (Smithy models, Dafny specs) — not just documentation. The spec is the source of truth.

### Extraction Outputs

| Output | Format | Consumer |
|--------|--------|----------|
| Structured requirements | JSON/YAML | Threat model generator |
| State machines | DOT/TLA+ fragments | Protocol verification |
| Pre/post-conditions | Dafny/ACSL annotations | Code-level verification |
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
3. Annotate leaf nodes with: Feasibility, Detectability, Existing mitigation

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

## Stage 3: Risk-Based Verification Recommendations

### Prioritization Formula

```
Priority Score = Threat_Severity × Coverage_Gap × Feasibility × Blast_Radius
```

| Factor | Scale | Description |
|--------|-------|-------------|
| Threat_Severity | 1–4 | Critical=4, High=3, Medium=2, Low=1 |
| Coverage_Gap | 0–1 | 1 = no existing verification; 0 = fully proven |
| Feasibility | 0–1 | Feasibility of the attack (higher = more urgent) |
| Blast_Radius | 1–4 | Number of services/customers affected |

### Verification Tool Mapping

| Property Type | Recommended Tool | When to Use |
|--------------|-----------------|-------------|
| Memory Safety | Verus (Rust) | Buffer bounds, null derefs, use-after-free |
| Functional Correctness | Verus / Dafny | Algorithm matches spec, state machine compliance |
| Serialization Correctness | Verus | Message format compliance, round-trip fidelity |
| Panic Freedom | Verus | No runtime panics on any input |
| FFI Safety | Verus | Unsafe block soundness, pointer validity |

### Output Format

Each recommendation includes:
```yaml
recommendation:
  id: VR-2026-001
  target:
    library: aws-encryption-sdk
    file: src/header_auth.rs
    function: verify_header_tag()
  property: "Header auth tag MUST be verified before any frame is decrypted"
  formal_spec: "∀ msg: decrypt(msg) → verified(msg.header.tag) = true"
  tool: Verus
  estimated_effort: 2 engineer-weeks
  threat_reference: TM-ESDK-014
  trace_to_spec: "AWS Encryption SDK Spec §3.2"
  priority_score: 12.0
  rationale: "High severity tampering threat with no existing verification coverage."
```

### Continuous Re-Prioritization

The pipeline runs continuously:
- On spec change: New requirements trigger STRIDE re-analysis
- On code change: Modified functions re-evaluated against existing threat model
- On new CVE: Emerging attack patterns update feasibility scores
- On proof completion: Coverage gaps recalculated, next target promoted

## Agent Mapping to Pipeline Stages

| Pipeline Stage | Agent | Role |
|---------------|-------|------|
| Step 1: Specification Ingestion | `spec-analyzer` | Extract security properties from specs |
| Step 2: Threat Modeling | `threat-model-generator` | STRIDE + attack trees |
| Step 3a: Header Parsing Proofs | `verus-header-parsing-proofs` | Prove parsing correctness |
| Step 3b: Zero-Panic Proofs | `verus-zero-panic` | Prove absence of panics in serialization |
| Step 3c: FFI Safety Proofs | `verus-unsafe-ffi-safety` | Prove unsafe block memory safety |

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
- ☐ Each verification target traces to a threat and a specification requirement
