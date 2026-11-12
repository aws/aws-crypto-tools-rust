# AWS Encryption SDK — Formal Threat Model

**Version:** 2.0.0  
**Date:** September 2026  
**Scope:** AWS Encryption SDK (Rust implementation — `aws-esdk` crate, v2.0.0)  
**Code Baseline:** commit `d8c1c3d` ("feat(esdk-cpp): C++ shim types, raw AES keyring round trip (#66)")  
**Methodology:** STRIDE + Attack Trees + Risk-Based Verification Prioritization  
**Classification:** Internal  
**Pipeline Reference:** `.kiro/agents/ai-verification-pipeline.md`

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope and Exclusions](#2-scope-and-exclusions)
3. [System Overview](#3-system-overview)
4. [Assets](#4-assets)
5. [Adversary Models](#5-adversary-models)
6. [Trust Boundaries](#6-trust-boundaries)
7. [Data Flow Diagrams](#7-data-flow-diagrams)
8. [Threat Identification (STRIDE)](#8-threat-identification-stride)
9. [Attack Trees](#9-attack-trees)
10. [Threat Analysis and Mitigations](#10-threat-analysis-and-mitigations)
11. [Known Vulnerabilities and Precedents](#11-known-vulnerabilities-and-precedents)
12. [Rust Implementation Considerations](#12-rust-implementation-considerations)
13. [Residual Risks](#13-residual-risks)
14. [Verification Recommendations (Prioritized)](#14-verification-recommendations-prioritized)
15. [Recommendations](#15-recommendations)
16. [References](#16-references)

---

## 1. Executive Summary

The AWS Encryption SDK (ESDK) is a client-side encryption library that enables applications to
encrypt and decrypt data using envelope encryption. This threat model analyzes the security
properties of the ESDK as specified in the formal specification and as implemented in this
repository: a **hand-written, native Rust** workspace (`aws-esdk` v2.0.0) whose cryptographic
primitives are thin wrappers over `aws-lc-rs`. The ESDK message layer is native Rust; the
Material Providers Library (CMM, keyrings, commitment-policy enforcement) is currently supplied
through the `aws-mpl-native` shim (`aws_mpl_legacy`), which delegates keyring/CMM behavior to an
external, Dafny-transpiled `aws-mpl-legacy` v0.2.0 crate for legacy interop. There is **no Dafny
transpilation in this repository** — no `implementation_from_dafny.rs`, no `.dfy` sources, and no
`dafny_runtime` dependency in-tree.

The SDK's primary security goals are:

- **Confidentiality** of plaintext data
- **Integrity** of encrypted messages (header, body, footer)
- **Authenticity** via asymmetric signatures (optional, per algorithm suite)
- **Key commitment** to prevent ciphertext that decrypts to multiple plaintexts

This document identifies threats across the encryption/decryption lifecycle, evaluates their
severity using the prioritization formula `Severity × Coverage_Gap × Feasibility × Blast_Radius`,
and maps mitigations to specification requirements and formal verification targets.

---

## 2. Scope and Exclusions

### In Scope

- SDK cryptographic operations (encrypt, decrypt, key derivation)
- Key management interfaces (CMM, Keyring, KMS interaction)
- Message format parsing and serialization
- Caching CMM (CMC / storm-tracking cache) and branch key store
- Memory management of key material (zeroization of `Secret` / `PlaintextDataKey`)
- Boundary with the `aws-lc-rs` cryptographic backend (safe Rust API; `aws-lc-sys`/`aws-lc-fips-sys` are pulled transitively via `aws-lc-rs` features)

### Out of Scope

- Underlying AWS KMS service security (assumed secure)
- Application business logic above the SDK
- Network transport security (assumed TLS)
- Physical security of compute environment
- AWS IAM policy correctness (separate domain)

### Threat Mindset

Application-level cryptography: this is a **client-side library** running inside the user's
application process on local compute. Threats focus on memory management, local compute
environments, and interaction with Key Management Services — not generic cloud security.

---

## 3. System Overview

### 3.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Caller Application                         │
├─────────────────────────────────────────────────────────────┤
│                     ESDK Client                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Encrypt    │  │   Decrypt    │  │ Commitment Policy│  │
│  └──────┬───────┘  └──────┬───────┘  └──────────────────┘  │
│         │                  │                                 │
│  ┌──────▼──────────────────▼───────┐                        │
│  │  Cryptographic Materials Manager │                        │
│  │  (Default CMM / Caching CMM)     │                        │
│  └──────────────┬──────────────────┘                        │
│                 │                                            │
│  ┌──────────────▼──────────────────┐                        │
│  │          Keyring                 │                        │
│  │  ┌─────┐ ┌─────┐ ┌───────────┐ │                        │
│  │  │ KMS │ │ Raw │ │Hierarchical│ │                        │
│  │  │     │ │AES/ │ │           │ │                        │
│  │  │     │ │RSA  │ │           │ │                        │
│  │  └──┬──┘ └──┬──┘ └─────┬─────┘ │                        │
│  └─────┼────────┼──────────┼───────┘                        │
├─────────┼────────┼──────────┼───────────────────────────────┤
│         │        │          │    Cryptographic Primitives     │
│         │        │          │  (prim/ wrappers over aws-lc-rs)│
└─────────┼────────┼──────────┼───────────────────────────────┘
          │        │          │
          ▼        ▼          ▼
    ┌──────────┐  ┌────┐  ┌──────────┐
    │ AWS KMS  │  │Local│  │ DynamoDB │
    │ Service  │  │Keys │  │Key Store │
    └──────────┘  └────┘  └──────────┘
```

### 3.1a Repository Layout (crates)

The workspace is four hand-written Rust crates (there is no single root `Cargo.toml`; each crate builds independently):

| Directory | Package (crate) | Version / Edition | Role |
|-----------|-----------------|-------------------|------|
| `esdk/` | `aws-esdk` | 2.0.0 / 2024 | The ESDK proper: `encrypt()`/`decrypt()`, message-format (de)serialization, key derivation. |
| `prim/` | `aws-mpl-primitives` | 0.1.0 / 2024 | Thin, hand-written wrappers over `aws-lc-rs`: AES-GCM, HMAC, digest, random, HKDF, KBKDF, ECDSA. |
| `mpl/` | `aws-crypto-mpl` | 0.1.0 / 2024 | Native MPL (default CMM, Raw AES keyring, KMS Hierarchical keyring, branch-key store, CMC). **Not yet wired into the ESDK dependency path.** |
| `unsafe-unreviewed-mpl/mpl` | `aws-mpl-native` (lib `aws_mpl_legacy`) | 0.2.0 / 2021 | The MPL crate the ESDK actually links against. Keyring/CMM/commitment entry points are largely `not_implemented()` stubs; real behavior comes from the external Dafny-transpiled `aws-mpl-legacy` v0.2.0 registry crate re-exported as `aws_mpl_legacy::dafny`. |
| `unsafe-unreviewed-mpl/prim` | `aws-mpl-primitives` (legacy) | 0.1.0 | Broader legacy primitives (`ecdh.rs`, `aes_kdf_ctr.rs`, memory tracker) used by the `aws-mpl-native` shim. |
| `spec/` | — (git submodule) | — | The `awslabs/aws-encryption-sdk-specification` used as the source of truth (referenced in code doc-comments as `spec/...`). |

**Key gotcha for this threat model:** the ESDK (`esdk/`) depends on `aws-mpl-native`
(`unsafe-unreviewed-mpl/mpl`, aliased `aws_mpl_legacy`), **not** the top-level native `mpl/`
crate. So for the shipping ESDK, CMM/keyring/commitment-policy logic is still routed through the
Dafny-backed legacy library, while the native `mpl/` (`aws-crypto-mpl`) is a parallel,
in-progress replacement.

### 3.2 Encrypted Message Format

```
┌────────────────────────────────────────────────┐
│                  Message                         │
├────────────────────────────────────────────────┤
│  Header                                         │
│  ├─ Version                                     │
│  ├─ Algorithm Suite ID                          │
│  ├─ Message ID (random)                         │
│  ├─ Encryption Context (AAD)                    │
│  ├─ Encrypted Data Keys                         │
│  ├─ Frame Length                                 │
│  ├─ Algorithm Suite Data (commit key)           │
│  └─ Header Authentication Tag                   │
├────────────────────────────────────────────────┤
│  Body (Framed)                                  │
│  ├─ Frame 1: SeqNum + IV + Ciphertext + Tag    │
│  ├─ Frame 2: SeqNum + IV + Ciphertext + Tag    │
│  ├─ ...                                         │
│  └─ Final Frame: 0xFFFF + SeqNum + ... + Tag   │
├────────────────────────────────────────────────┤
│  Footer (if algorithm suite has signature)      │
│  └─ ECDSA Signature over Header + Body         │
└────────────────────────────────────────────────┘
```

### 3.3 Key Hierarchy

```
Wrapping Key (KMS CMK / Raw AES / Raw RSA / Branch Key)
    │
    ▼
Plaintext Data Key (generated per message)
    │
    ├──[HKDF]──▶ Derived Encryption Key (AES-GCM cipherkey)
    │
    └──[HKDF]──▶ Commit Key (stored in header for verification)
```

---

## 4. Assets

| ID | Asset | Confidentiality | Integrity | Availability |
|----|-------|----------------|-----------|--------------|
| A1 | Plaintext data | Critical | Critical | High |
| A2 | Plaintext data key | Critical | Critical | High |
| A3 | Derived encryption key | Critical | Critical | High |
| A4 | Signing key (ECDSA private key) | Critical | Critical | Medium |
| A5 | Encryption context | Low (public) | Critical | Medium |
| A6 | Encrypted message (ciphertext) | Low | Critical | High |
| A7 | KMS CMK / wrapping keys | Critical | Critical | High |
| A8 | Branch keys (hierarchical keyring) | Critical | Critical | High |
| A9 | AWS credentials (IAM) | Critical | Critical | High |
| A10 | Commit key | Medium | Critical | Medium |

---

## 5. Adversary Models

| Adversary Level | Capabilities | Relevant Attacks |
|----------------|--------------|-----------------|
| Network (Dolev-Yao) | Intercept, inject, replay messages on untrusted channel | Frame reordering, EDK substitution, message replay |
| Local | Read process memory, timing measurements, core dumps | Side-channel attacks, key extraction from RAM |
| Insider | Access to some key material, SDK configuration | Operational misuse, discovery keyring abuse |
| Supply Chain | Modify dependencies, build artifacts | Backdoor injection via compromised crates |

### Legitimate Actors

| Actor | Description | Capabilities |
|-------|-------------|--------------|
| Encryptor | Application performing encryption | Has access to CMM/keyring, plaintext |
| Decryptor | Application performing decryption | Has access to CMM/keyring, ciphertext |
| KMS Administrator | Manages KMS key policies | Controls who can use wrapping keys |
| SDK Operator | Configures ESDK client | Sets commitment policy, max EDK count |

### Threat Actors

| Actor | Adversary Model | Capabilities |
|-------|----------------|--------------|
| Network Attacker | Dolev-Yao | Can observe, modify, replay messages in transit |
| Malicious Insider | Insider | May have access to some keys but not all |
| Compromised Keyring | Local/Insider | Can provide malicious key material |
| Ciphertext Attacker | Dolev-Yao | Can modify, reorder, splice ciphertexts |
| Supply Chain Attacker | Supply Chain | Can inject malicious code into crypto operations |

---

## 6. Trust Boundaries

| ID | Boundary | From (Trusted) | To (Untrusted) | Data Crossing |
|----|----------|-----------------|-----------------|---------------|
| TB1 | Application ↔ ESDK | Caller code | ESDK library | Plaintext, encryption context |
| TB2 | ESDK ↔ AWS KMS | ESDK process | AWS KMS service (network) | Data key encrypt/decrypt requests |
| TB3 | ESDK ↔ Local Keys | ESDK process | Filesystem / HSM | Raw wrapping key material |
| TB4 | Encrypt Host ↔ Decrypt Host | Encryptor | Network / storage | Encrypted message bytes |
| TB5 | ESDK ↔ DynamoDB (Keystore) | ESDK process | DynamoDB service | Branch key material |
| TB6 | Process Memory ↔ OS | ESDK runtime | Operating system | Key material in RAM |

---

## 7. Data Flow Diagrams

### 7.1 Encrypt Data Flow

```
                    TB1                         TB2
 ┌──────────┐       │       ┌──────────┐       │      ┌──────────┐
 │  Caller  │───────┼──────▶│   ESDK   │───────┼─────▶│ AWS KMS  │
 │          │ plaintext     │  Client  │  GenerateDataKey        │
 │          │ enc context   │          │◀──────┼──────│          │
 │          │◀──────┼───────│          │ plaintext DK │          │
 │          │  encrypted    │          │ encrypted DK │          │
 │          │  message      │          │              │          │
 └──────────┘       │       └──────────┘       │      └──────────┘
                    │              │            │
                    │              ▼            │
                    │       ┌──────────┐       │
                    │       │  Crypto  │       │
                    │       │Primitives│       │
                    │       │(aws-lc)  │       │
                    │       └──────────┘       │
```

**Data Flow Steps:**
1. Caller provides plaintext + encryption context + keyring/CMM
2. ESDK calls CMM.GetEncryptionMaterials()
3. CMM calls Keyring.OnEncrypt() → generates plaintext data key + encrypts it
4. For KMS keyring: network call to KMS GenerateDataKey
5. ESDK derives encryption key from plaintext data key (HKDF)
6. ESDK derives commit key (if committing suite)
7. ESDK constructs header with algorithm suite, message ID, EC, EDKs, commit key
8. ESDK computes header auth tag (AES-GCM with derived key, AAD = header body)
9. ESDK encrypts plaintext in frames (AES-GCM with per-frame IV = sequence number)
10. If signing suite: ESDK computes ECDSA signature over header + body
11. ESDK returns encrypted message to caller

### 7.2 Decrypt Data Flow

```
                    TB1                         TB2
 ┌──────────┐       │       ┌──────────┐       │      ┌──────────┐
 │  Caller  │───────┼──────▶│   ESDK   │───────┼─────▶│ AWS KMS  │
 │          │ encrypted     │  Client  │  Decrypt(EDK)           │
 │          │ message       │          │◀──────┼──────│          │
 │          │◀──────┼───────│          │ plaintext DK │          │
 │          │ plaintext     │          │              │          │
 │          │               │          │              │          │
 └──────────┘       │       └──────────┘       │      └──────────┘
```

**Data Flow Steps:**
1. Caller provides encrypted message + keyring/CMM
2. ESDK parses message header (algorithm suite, EDKs, EC, commit key)
3. ESDK validates commitment policy allows this algorithm suite (spec requirement; **note:** the linked MPL shim's `validate_commitment_policy_on_decrypt` currently returns `Ok(())` — see §12.2 and the recommendations doc)
4. ESDK validates EDK count is > 0 and ≤ maximum configured
5. ESDK calls CMM.DecryptMaterials() → calls Keyring.OnDecrypt() with EDKs
6. For KMS keyring: network call to KMS Decrypt with EDK ciphertext
7. ESDK derives encryption key and commit key from plaintext data key
8. ESDK verifies commit key matches value in header (key commitment check)
9. ESDK verifies header auth tag
10. ESDK decrypts each frame, verifying per-frame auth tags
11. If signing suite: ESDK verifies ECDSA signature in footer
12. ESDK returns plaintext to caller

---

## 8. Threat Identification (STRIDE)

### 8.1 Spoofing

| ID | Threat | Target | Entry Point |
|----|--------|--------|-------------|
| S1 | KMS endpoint spoofing | TB2 | DNS hijacking, TLS downgrade |
| S2 | Forged encrypted message (impersonate encryptor) | TB4 | Network/storage access |
| S3 | Malicious keyring returning attacker-controlled data key | TB1 | Compromised dependency or plugin |
| S4 | Credential theft allowing unauthorized KMS calls | TB2 | Leaked IAM credentials |

### 8.2 Tampering

| ID | Threat | Target | Entry Point |
|----|--------|--------|-------------|
| T1 | Message header modification (algorithm suite downgrade) | A6 | TB4 |
| T2 | Frame reordering or deletion | A6 | TB4 |
| T3 | Frame splicing across messages | A6 | TB4 |
| T4 | EDK substitution (swap encrypted data key) | A6 | TB4 |
| T5 | Encryption context modification | A5 | TB4 |
| T6 | Auth tag truncation or modification | A6 | TB4 |
| T7 | Footer signature removal | A6 | TB4 |
| T8 | Commit key manipulation | A10 | TB4 |

### 8.3 Repudiation

| ID | Threat | Target | Entry Point |
|----|--------|--------|-------------|
| R1 | Encryptor denies creating message (no signature) | A6 | Algorithm suite without ECDSA |
| R2 | Message forgery by decryptor with key access | A6 | Shared symmetric key material |
| R3 | Streaming plaintext consumed before signature verified | A1 | Streaming API misuse |

### 8.4 Information Disclosure

| ID | Threat | Target | Entry Point |
|----|--------|--------|-------------|
| I1 | Plaintext data key leaked from memory | A2 | TB6, memory dump, core dump |
| I2 | Encryption context reveals sensitive metadata | A5 | Header stored in cleartext |
| I3 | Frame length reveals plaintext size | A1 | Ciphertext length analysis |
| I4 | Timing side-channels in crypto operations | A2 | TB6, local process observation |
| I5 | Key material persists in memory after use | A2, A3 | TB6, memory forensics |
| I6 | Error messages reveal internal state | A2 | Application logs |

### 8.5 Denial of Service

| ID | Threat | Target | Entry Point |
|----|--------|--------|-------------|
| D1 | Excessive EDKs forcing many KMS Decrypt calls | Availability | TB4 (crafted message) |
| D2 | Extremely large frame count exhausting memory | Availability | TB4 (crafted message) |
| D3 | Malformed header causing parsing loops | Availability | TB4 (crafted message) |
| D4 | KMS throttling via EDK flood | Availability, Cost | TB4 |
| D5 | Cache poisoning in Caching CMM | A2 | TB1 (compromised cache) |

### 8.6 Elevation of Privilege

| ID | Threat | Target | Entry Point |
|----|--------|--------|-------------|
| E1 | Algorithm suite downgrade (bypass commitment) | A1 | TB4, misconfiguration |
| E2 | Discovery keyring decrypts with unintended KMS key | A1 | Misconfiguration |
| E3 | Non-committing suite allows multi-plaintext attack | A1 | Legacy compatibility |
| E4 | Caching CMM serves stale/compromised materials | A2 | Time-based attack |
| E5 | Bypassing max EDK limit via message parsing race | A9 | TB4, implementation bug |

---

## 9. Attack Trees

Attack trees decompose STRIDE threats into concrete exploitation paths, showing how an attacker achieves each goal.

### Attack Tree 1: Recover Plaintext (Information Disclosure)

```
Root Goal: Recover AES-GCM plaintext
├── AND: Obtain nonce reuse
│   ├── OR: Counter overflow
│   │   ├── Encrypt > 2^32 frames with same derived key
│   │   └── Implementation wraps 32-bit sequence number
│   ├── OR: Predictable IV generation
│   │   └── Weak RNG seeding (aws-lc-rs rand::fill failure)
│   └── OR: State reset after crash
│       └── Volatile counter not persisted (N/A — IV = seq num per spec)
├── AND: Observe two ciphertexts with same (key, nonce)
│   └── Network eavesdropping (Dolev-Yao attacker)
└── AND: XOR ciphertexts to recover plaintext XOR
    └── Known-plaintext or crib-dragging
```

**Feasibility:** Low — IV is derived from sequential frame number, not random. Would require >2^32 frames.  
**Existing Mitigation:** Spec limits frames to 2^32 - 1 per message (sequence number is u32).

### Attack Tree 2: Process Data with Tampered Header (Tampering)

```
Root Goal: Decrypt data using wrong algorithm/key commitment
├── OR: Skip header authentication
│   ├── Exception handling bypasses tag check (implementation bug)
│   ├── Streaming mode processes frames before header verified
│   └── Custom CMM returns key before header validation completes
└── OR: Forge valid authentication tag
    ├── Collision in AES-GCM-256 tag (infeasible: 2^128 work)
    └── Obtain header encryption key (requires KMS compromise — out of scope)
```

**Feasibility:** Medium for streaming bypass; Infeasible for tag forgery.  
**Existing Mitigation:** Spec MUST verify header tag before processing frames (decrypt.md §Verify the header).

### Attack Tree 3: Multi-Plaintext via Non-Committing Suite (Elevation of Privilege)

```
Root Goal: Craft ciphertext decryptable to two different plaintexts
├── AND: Use non-committing algorithm suite (no key commitment)
│   ├── Victim uses FORBID_ENCRYPT_ALLOW_DECRYPT policy
│   └── OR: Attacker controls key material
│       ├── Compromised raw AES keyring
│       └── Attacker is one of multiple recipients in multi-keyring
├── AND: Construct ambiguous ciphertext (Invisible Salamanders technique)
│   └── Exploit AES-GCM's lack of key commitment property
└── AND: Victim decrypts with attacker-chosen key
    └── Discovery keyring without filters accepts any EDK
```

**Feasibility:** Low (requires non-default commitment policy + key material control).  
**Existing Mitigation:** Default policy is `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`; committing suites derive and verify commit key.

### Attack Tree 4: Denial of Service via Malformed Message (DoS)

```
Root Goal: Crash or exhaust resources of decrypting application
├── OR: Excessive EDKs
│   ├── Message with 65535 EDKs → 65535 KMS Decrypt calls
│   └── Cost amplification + latency timeout
├── OR: Malformed header causing parser panic
│   ├── Invalid UTF-8 in encryption context keys
│   ├── AAD length field > actual remaining bytes
│   └── EDK count = 0 (spec violation)
└── OR: Memory exhaustion
    ├── Frame length = 2^32 - 1 with huge claimed content
    └── Extremely deep encryption context (many key-value pairs)
```

**Feasibility:** High (easy to craft malformed messages).  
**Existing Mitigation:** `max_encrypted_data_keys` config (but defaults to unlimited). Parser validates field lengths.

---

## 10. Threat Analysis and Mitigations

### 10.1 Critical Threats

#### T1: Message Header Modification

| Attribute | Value |
|-----------|-------|
| Severity | Critical |
| Likelihood | Medium (requires message access) |
| Risk | High |

**Attack:** Attacker modifies the algorithm suite ID in the header to downgrade to a weaker suite
or modifies the encryption context.

**Mitigation (Spec):**
- Header authentication tag (AES-GCM) computed over the entire header body (encrypt.md §Construct the header)
- Commitment policy rejects disallowed algorithm suites before processing (decrypt.md §Get the decryption materials)
- Encryption context is included in the header AAD

**Mitigation (Implementation):**
- Header auth tag verification occurs before any plaintext is released
- Verification failure causes immediate halt

**Residual Risk:** None if implemented correctly. The header auth tag is computed/verified over
the full header via the AES-GCM path, and the commitment policy is checked before decryption.
There is currently **no formal (Verus) proof** of this ordering at the Rust level — see
[Verification Recommendations](#14-verification-recommendations-prioritized).

---

#### E3: Non-Committing Suite Multi-Plaintext Attack

| Attribute | Value |
|-----------|-------|
| Severity | Critical |
| Likelihood | Low (requires specific conditions) |
| Risk | Medium |

**Attack:** Without key commitment, an attacker who controls the key material can craft a
ciphertext that decrypts to different plaintexts depending on which data key is used.

**Mitigation (Spec):**
- Default commitment policy is `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` (client.md §Initialization)
- Committing algorithm suites (04 78, 05 78) derive a commit key stored in the header
- On decrypt, the derived commit key MUST equal the stored commit key (decrypt.md §Get the decryption materials)

**Mitigation (Implementation):**
- Commit key comparison is performed before any frame decryption via `validate_suite_data` in `esdk/src/message/header.rs`, using a constant-time compare (`aws_lc_rs::constant_time::verify_slices_are_equal`)
- `FORBID_ENCRYPT_ALLOW_DECRYPT` only exists for backward compatibility with pre-commitment messages
- **Gap:** commitment-policy *enforcement* (`validate_commitment_policy_on_encrypt`/`_on_decrypt` in `unsafe-unreviewed-mpl/mpl/src/commitment.rs`) currently returns `Ok(())` — the effective control today is the commit-key comparison in `validate_suite_data`, not policy gating

**Residual Risk:** Systems that explicitly configure `FORBID_ENCRYPT_ALLOW_DECRYPT` remain vulnerable to this attack class (a conscious spec trade-off). Additionally, because policy enforcement is currently stubbed, algorithm-suite restrictions derived from the commitment policy are not applied at this layer — see the Critical implementation recommendation in §15.2.

---

#### S2: Forged Encrypted Message

| Attribute | Value |
|-----------|-------|
| Severity | High |
| Likelihood | Medium |
| Risk | High |

**Attack:** Attacker with network/storage access creates a message that appears legitimate.

**Mitigation (Spec):**
- AES-GCM authentication tags on header and every frame
- ECDSA signature in footer (algorithm suites with signature)
- Key commitment binds the message to a specific data key

**Mitigation (Implementation):**
- All auth tag verifications use constant-time comparison (aws-lc-rs)
- Signature verification uses the verification key from decryption materials

**Residual Risk:** Without a signing algorithm suite, anyone with access to the data key material
can forge messages. Use `05 78` (ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384) for non-repudiation.

---

#### T2/T3: Frame Reordering and Cross-Message Splicing

| Attribute | Value |
|-----------|-------|
| Severity | High |
| Likelihood | Medium |
| Risk | High |

**Attack:** Attacker reorders frames within a message or splices frames from a different message.

**Mitigation (Spec):**
- Each frame's AAD includes: Message ID + sequence number + content length (message-body-aad.md)
- Sequence numbers MUST be sequential (1, 2, 3, ...) — gaps cause failure
- Message ID is random per message — cross-message splicing fails AAD verification
- Final frame is explicitly marked (0xFFFF sentinel)

**Residual Risk:** None if AAD construction is correct.

---

#### D1: Excessive Encrypted Data Keys (DoS)

| Attribute | Value |
|-----------|-------|
| Severity | Medium |
| Likelihood | High (easy to craft) |
| Risk | Medium |

**Attack:** Attacker crafts a message with thousands of EDKs, forcing the decryptor to make
many expensive KMS API calls, causing cost amplification and latency.

**Mitigation (Spec):**
- Client configuration: `maximum number of encrypted data keys` (client.md §Initialization)
- Decrypt MUST fail as soon as EDK count exceeds limit during parsing (decrypt.md §Parse the header)

**Mitigation (Implementation):**
- Count is checked during header deserialization, before any KMS calls

**Residual Risk:** If no limit is configured (the default), the system is vulnerable. Operators SHOULD set a reasonable maximum.

---

### 10.2 Medium Threats

#### I1: Plaintext Data Key Leaked from Memory

| Attribute | Value |
|-----------|-------|
| Severity | Critical (if exploited) |
| Likelihood | Low |
| Risk | Medium |

**Attack:** Memory dump, core dump, or swap file exposes the plaintext data key.

**Mitigation (Spec):**
- Plaintext data key SHOULD be stored as immutable data (structures.md §Plaintext Data Key)
- Plaintext data key SHOULD offer an interface to zero the key after use

**Mitigation (Implementation — Rust):**
- Rust's ownership model prevents accidental copies
- `zeroize` crate can be used for explicit key zeroing on drop
- No garbage collector means deterministic deallocation

**Residual Risk:** OS-level memory access (ptrace, /proc/mem) can still read process memory. Mitigation requires OS-level hardening (disable core dumps, encrypted swap, mlock).

---

#### R3: Streaming Plaintext Released Before Signature Verification

| Attribute | Value |
|-----------|-------|
| Severity | High |
| Likelihood | Medium (API misuse) |
| Risk | Medium |

**Attack:** Application processes streaming plaintext from frames before the footer signature
is verified. If signature verification later fails, the application has already acted on
potentially tampered data.

**Mitigation (Spec):**
- Plaintext from final frame MUST NOT be released until signature verification completes (decrypt.md §Decrypt the message body)
- All released plaintext MUST NOT be considered signed until operation finishes (decrypt.md §Security Considerations)
- ESDK MUST provide a configuration to fail immediately if signed suite is used during streaming

**Mitigation (Implementation):**
- Callers MUST roll back any processing if verification fails
- SDK should document this constraint prominently

**Residual Risk:** Application-level responsibility. The SDK cannot enforce how callers handle streamed output.

---

#### E2: Discovery Keyring Over-Permissiveness

| Attribute | Value |
|-----------|-------|
| Severity | Medium |
| Likelihood | Medium (misconfiguration) |
| Risk | Medium |

**Attack:** A discovery keyring with no filter attempts to decrypt with any KMS key the caller
has access to, potentially decrypting messages not intended for this application.

**Mitigation (Spec):**
- Discovery keyrings support account ID and partition filters
- MRK-aware discovery keyrings further restrict by region/key ARN patterns

**Residual Risk:** Users who deploy discovery keyrings without filters accept broader decryption scope. This is a configuration choice, not a vulnerability.

---

### 10.3 Low Threats

#### I3: Ciphertext Length Reveals Plaintext Size

| Attribute | Value |
|-----------|-------|
| Severity | Low |
| Likelihood | High (always observable) |
| Risk | Low |

**Attack:** Frame count and final frame size reveal the approximate plaintext length.

**Mitigation:** Padding is not specified. Applications that need length-hiding must pad plaintext before encryption.

**Residual Risk:** Accepted. Length-hiding is outside ESDK scope.

---

#### I4: Timing Side-Channels

| Attribute | Value |
|-----------|-------|
| Severity | Medium |
| Likelihood | Low |
| Risk | Low |

**Attack:** Variable-time operations during tag comparison or key derivation leak information.

**Mitigation (Implementation):**
- aws-lc-rs uses constant-time operations for AEAD tag verification
- HKDF and ECDSA implementations in aws-lc are reviewed for timing resistance
- Rust's release builds with optimizations don't introduce data-dependent branches

**Residual Risk:** Microarchitectural side channels (Spectre, etc.) are outside application-level control.

---

## 11. Known Vulnerabilities and Precedents

Threats in this model are grounded in demonstrated exploitability:

| ID | Vulnerability | Source | Relevance to ESDK |
|----|---------------|--------|-------------------|
| CVE-2020-8897 | Key commitment bypass in AWS Encryption SDK (all languages) | AWS Security Bulletin | Directly applicable — led to addition of committing algorithm suites (04 78, 05 78) |
| Invisible Salamanders | Non-committing AEAD allows multi-plaintext ciphertexts | Grubbs et al. (2020) | Motivated `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` default policy |
| AWS-2025-032 | Key commitment issues in S3 encryption clients | AWS Security Bulletin | Sibling library; same underlying primitive vulnerability |
| GCM Nonce Reuse | AES-GCM catastrophic failure on IV reuse | Joux (2006), NIST SP 800-38D | ESDK mitigates via deterministic IV = frame sequence number |
| Bleichenbacher '98 | RSA PKCS#1 v1.5 padding oracle | Bleichenbacher (1998) | Relevant to Raw RSA Keyring if OAEP not enforced |
| Timing attacks on AES | Cache-timing side channels in table-based AES | Bernstein (2005) | Mitigated by aws-lc-rs using hardware AES-NI / constant-time implementations |

### Backward-Compatibility Downgrade Vectors

| Mechanism | Risk | Mitigation |
|-----------|------|------------|
| `FORBID_ENCRYPT_ALLOW_DECRYPT` commitment policy | Allows decryption of non-committing messages → multi-plaintext attack surface | Only use during migration; transition to `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` |
| Algorithm suites without KDF (Identity KDF: `00 14`, `00 46`, `00 78`) | Raw data key used directly as encryption key — no key separation | Legacy only; spec recommends HKDF-based suites |
| Non-framed content type (`0x01`) | MUST NOT be used for encryption (appendix in encrypt.md) but MUST be supported for decryption | Decrypt-only backward compat; no length limit on single body |
| Discovery keyring without filters | Attempts decryption with any accessible KMS key | Use account/partition filters |

---

## 12. Rust Implementation Considerations

### 12.1 Memory Safety

| Consideration | Assessment |
|---------------|------------|
| Buffer overflows | Eliminated by Rust's borrow checker and bounds checking |
| Use-after-free | Prevented by ownership model |
| Data races | Prevented by `Send`/`Sync` traits; the CMC uses a `std::sync::Mutex` (`mpl/src/cmc/storm_tracking.rs`), not lock-free `unsafe` |
| Unsafe code | Minimal in-tree (see §12.2); crypto FFI is confined to `aws-lc-rs`, audited separately |
| Panic surface | `esdk/src/lib.rs` intentionally does **not** enable `clippy::indexing_slicing` or `clippy::panic`; serialization uses slice indexing, so panic-freedom is a verification target rather than a compiler guarantee |

### 12.2 Native Rust Implementation and In-Tree `unsafe`

The ESDK, primitives, and native MPL crates in this repository are **hand-written native Rust**,
not Dafny-transpiled. Dafny enters only as an external legacy dependency (`aws-mpl-legacy` v0.2.0,
re-exported as `aws_mpl_legacy::dafny`) that the `aws-mpl-native` shim delegates keyring/CMM work
to; `esdk/src/legacy_compat.rs` is the type-conversion boundary between the Dafny-transpiled types
and the native `suites` types.

In-tree `unsafe` is small and localized:

| Location | Count | What it does |
|----------|-------|--------------|
| `mpl/src/structures/algorithm_suite.rs` | 1 | `core::ptr::write_volatile` zeroization loop over a `Vec`'s own length (bounds-safe by construction) |
| `esdk/shims/aws-esdk-cpp/src/lib.rs` | 1 | `&*ptr` dereference of a non-null raw pointer to return a C++ FFI handle (shim, not core library) |
| `unsafe-unreviewed-mpl/prim/src/use_memory_tracker.rs` | 3 items | `unsafe impl GlobalAlloc` (debug memory tracker; non-shipping) |
| `prim/src/*`, `esdk/src/*` | 0 | No `unsafe` in the crypto primitives or the ESDK message layer |

There are **no** raw `aws-lc-sys` FFI calls (no `EC_POINT`/`EC_GROUP`), no `from_raw_parts`,
no `set_len`, and no `unsafe impl Send/Sync` in production code. Test/benchmark harnesses
(`esdk/performance-tests/src/alloc.rs`, `esdk/tests/test_resource_leaks.rs`) define their own
counting/leak-detection allocators with `unsafe`, but these are not part of the shipped library.

Risks:
- The Dafny-backed legacy MPL (`aws-mpl-legacy` v0.2.0) is an external binary/registry artifact; its keyring/CMM logic is not auditable from this repository's source.
- The native `mpl/` (`aws-crypto-mpl`) keyrings/CMM are hand-written and require review; note they are **not yet on the ESDK dependency path**.
- Native primitive wrappers (`prim/src/lib.rs`, `prim/src/ecdsa.rs`, `prim/src/hkdf.rs`) are manually written over `aws-lc-rs` and require review, though they contain no `unsafe`.

### 12.3 Dependency Supply Chain

Versions reflect `esdk/Cargo.toml` (and `prim/Cargo.toml`) as of commit `d8c1c3d` (September 2026).

| Dependency | Version | Role | Risk |
|------------|---------|------|------|
| `aws-lc-rs` | 1.15.4 (`default-features = false`) | All cryptographic primitives (safe Rust API) | Wraps C code; FIPS-validated variant available via feature |
| `aws-lc-sys` | via `aws-lc-rs/aws-lc-sys` feature (default) | Native crypto backend (non-FIPS) | C code via FFI; not pinned directly in this manifest |
| `aws-lc-fips-sys` | via `aws-lc-rs/fips` feature | Native crypto backend (FIPS) | C code via FFI; enabled by the `fips` feature |
| `aws-mpl-legacy` (`aws-mpl-native`) | local path (`unsafe-unreviewed-mpl/mpl`, v0.2.0) | MPL shim → external Dafny-transpiled MPL | Delegates keyring/CMM to external Dafny crate |
| `aws-sdk-kms` | 1.98.0 | KMS API calls | AWS-maintained; version-pinned |
| `aws-sdk-dynamodb` | 1.103.0 | Branch key store access | AWS-maintained; version-pinned |
| `aws-smithy-types` | 1.3.6 | Smithy type support | AWS-maintained |
| `tokio` | 1.49.0 | Async runtime | Widely audited; large attack surface |
| `async-trait` | 0.1.89 | Async trait support (keyring/CMM traits) | Widely used |
| `zeroize` | 1.8.2 | Zeroizing key material on drop | Well-audited |
| `rand` (dev) | 0.9.2 | Random in examples/tests | Dev-dependency only |
| `pem` (dev) | 3.0.6 | PEM parsing in examples/tests | Dev-dependency only |
| `aws-config` (dev) | 1.8.12 | Example credential loading | Dev-dependency only |

Note: this manifest does **not** declare `dafny_runtime` or `dashmap`; the earlier baseline's
entries for those (and the direct `aws-lc-sys 0.44` / `aws-lc-fips-sys 0.14.1` pins) do not apply
to this codebase.

### 12.4 FIPS Compliance

`esdk/Cargo.toml` (and `prim/Cargo.toml`) expose feature flags that select the crypto backend
through `aws-lc-rs`:
- `default = ["aws-lc-rs/aws-lc-sys"]`: non-FIPS backend
- `fips = ["aws-lc-rs/fips"]`: FIPS 140-3 validated module

Threat: If the FIPS boundary is incorrectly drawn (e.g., key material passes through non-FIPS code paths), compliance claims are invalidated.

---

## 13. Residual Risks

| ID | Risk | Severity | Justification for Acceptance |
|----|------|----------|------------------------------|
| RR1 | Non-committing suites allow multi-plaintext attacks | Critical | Legacy backward compatibility; mitigated by default commitment policy |
| RR2 | Streaming plaintext misuse by callers | High | Application responsibility; documented in spec |
| RR3 | Ciphertext length leaks plaintext size | Low | Industry standard; padding is caller responsibility |
| RR4 | Memory exposure via OS-level access | Medium | Requires privileged OS access; mitigated by deployment hardening |
| RR5 | Legacy Dafny-backed MPL (external `aws-mpl-legacy` v0.2.0) is not auditable in-repo | Low | Used only for keyring/CMM interop; native `mpl/` replacement is in progress; integration tests provide coverage |
| RR6 | Discovery keyring decrypts unintended messages | Medium | Configuration choice; filters available |
| RR7 | No maximum message size enforcement in SDK | Low | Application-level concern |

---

## 14. Verification Recommendations (Prioritized)

Using the prioritization formula: `Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`

All targets reference real files in this repository. There is currently **no formal (Verus)
verification** of any kind for this codebase, so every coverage gap is 1.0. For full scoring and
agent assignments see `docs/verification-recommendations.md`.

| Priority | Score | Target | Property to Verify | Tool | Threat ID | Agent | File |
|----------|-------|--------|-------------------|------|-----------|-------|------|
| 1 | 16.0 | Key commitment check | Derived commit key == stored commit key (constant-time) before any decryption | Verus | E1/E3, T8 | `verus-header-parsing-proofs` | `esdk/src/message/header.rs` (`validate_suite_data`), `esdk/src/key_derivation.rs` (`derive_key_v2`) |
| 2 | 12.0 | Header auth tag ordering | Header tag verified before any frame is processed, in all paths | Verus | T1, T6 | `verus-header-parsing-proofs` | `esdk/src/decrypt.rs`, `esdk/src/message/header_auth.rs` |
| 3 | 10.8 | Header/EDK parsing safety | Malformed input returns `Err`, never panics; EDK count > 0 and ≤ max before KMS calls | Verus | D1, D3 | `verus-header-parsing-proofs` | `esdk/src/message/header.rs` (`read_header_body`, `validate_max_encrypted_data_keys`), `encrypted_data_keys.rs` |
| 4 | 9.6 | Frame sequence validation | Sequential frame numbers enforced (no gaps/reordering); final-frame handling correct | Verus | T2, T3 | `verus-header-parsing-proofs` | `esdk/src/message/body/body_decrypt.rs` |
| 5 | 9.0 | Frame construction / body serialization | Frame iteration and slicing never exceed buffer bounds; no panic | Verus | D2 | `verus-zero-panic` | `esdk/src/message/body/body_encrypt.rs` |
| 6 | 9.0 | AES-GCM panic freedom | All slice accesses (nonce, tag, ciphertext) in-bounds; wrappers never panic | Verus | D1 | `verus-zero-panic` | `prim/src/lib.rs` (`aes_encrypt`, `aes_decrypt`) |
| 7 | 6.0 | Key-material zeroization | `Secret`/`PlaintextDataKey` bytes are zeroed on drop; `write_volatile` loop is in-bounds | Verus | I1, I5 | `verus-unsafe-ffi-safety` | `mpl/src/structures/algorithm_suite.rs`, `unsafe-unreviewed-mpl/mpl/src/lib.rs` |
| 8 | 4.8 | Data-key non-disclosure (VR-011, information flow) | Plaintext data key and keys derived from it are never written directly to the output stream or returned to the caller; they reach output only as AES-GCM input or, for the data key, as an EDK from the keyring. Keyrings/CMMs, AES-GCM ciphertext strength, and public key-byte accessors are out of scope. Best done after the in-crate Verus work (Option A) | Verus | I1, I5, S3 | unassigned | `esdk/src/encrypt.rs`, `esdk/src/decrypt.rs`, `esdk/src/key_derivation.rs`, `esdk/src/message/body/*` |

### Verification Target Format (per recommendation)

```yaml
recommendation:
  id: VR-2026-001
  target:
    library: aws-esdk
    file: esdk/src/message/header.rs
    function: validate_suite_data (key commitment verification)
  property: "The derived commit key MUST equal the stored suite data (commit key), compared in constant time, before any frame is decrypted"
  formal_spec: "∀ msg: decrypt(msg) → verified_commit_key(msg.header.suite_data) = true"
  tool: Verus
  estimated_effort: 2 engineer-weeks
  threat_reference: E1/E3, T8
  trace_to_spec: "spec/client-apis/decrypt.md §Get the decryption materials; spec/client-apis/key-derivation.md#hkdf-commit-key"
  priority_score: 16.0
  rationale: "Critical elevation-of-privilege threat (CVE-2020-8897 class) with no existing
              Verus verification. Commitment-policy enforcement is currently a stub in the
              linked MPL shim (validate_commitment_policy_on_* return Ok(())), so the Rust-level
              commit-key comparison in validate_suite_data is the effective control."
```

---

## 15. Recommendations

### 15.1 Configuration Recommendations

| Priority | Recommendation | Rationale |
|----------|---------------|-----------|
| Critical | Use commitment policy `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` | Prevents multi-plaintext attacks |
| Critical | Set `maximum number of encrypted data keys` to a reasonable value (e.g., 5) | Prevents EDK-flood DoS |
| High | Use algorithm suite `05 78` (AES-256-GCM + HKDF + Commit + ECDSA) | Provides maximum security including non-repudiation |
| High | Use discovery keyring filters (account ID, partition) | Limits unintended decryption scope |
| Medium | Do not put sensitive data in encryption context | EC is stored in cleartext |
| Medium | Implement rollback logic for streaming decrypt consumers | Handles signature verification failure |

### 15.2 Implementation Recommendations

| Priority | Recommendation | Rationale |
|----------|---------------|-----------|
| Critical | Implement real commitment-policy enforcement (the linked shim's `validate_commitment_policy_on_encrypt`/`_on_decrypt` in `unsafe-unreviewed-mpl/mpl/src/commitment.rs` currently return `Ok(())`) | Without enforcement, algorithm-suite/commitment restrictions are not applied at this layer |
| High | Audit the in-tree `unsafe` (zeroization in `mpl/src/structures/algorithm_suite.rs`; FFI handle in the C++ shim) and the external Dafny-backed MPL | Small but present unsafe surface; external MPL is not auditable in-repo |
| High | Confirm zeroization for plaintext data key on drop (`Secret` and `PlaintextDataKey` implement zeroizing `Drop`) | Reduces key exposure window |
| High | Pin all dependency versions exactly | Prevents supply chain attacks via version range exploitation |
| Medium | Fuzz the message parser with arbitrary bytes | Validates robustness against malformed input |
| Medium | Add integration tests with corrupted ciphertexts | Validates all auth tag / signature checks fire correctly |
| Medium | Measure and verify constant-time tag comparison | Confirms no timing oracle |
| Low | Consider mlock for key material pages | Prevents swap-to-disk of secrets |

### 15.3 Operational Recommendations

| Priority | Recommendation | Rationale |
|----------|---------------|-----------|
| High | Rotate KMS CMKs per organizational policy | Limits blast radius of key compromise |
| High | Monitor KMS Decrypt call patterns for anomalies | Detects EDK-flood attacks or unauthorized decryption |
| Medium | Use branch key rotation for hierarchical keyring | Limits long-lived key exposure |
| Medium | Enable CloudTrail logging for all KMS operations | Provides audit trail for key usage |
| Low | Disable core dumps in production | Prevents key material leakage via crash dumps |

---

## 16. References

The formal specification is the `spec/` git submodule
(`awslabs/aws-encryption-sdk-specification`, pinned at `92c0524`); the ESDK source doc-comments
reference it with `spec/...` paths. Initialize it with `git submodule update --init spec` to read
the files locally.

| Document | Location |
|----------|----------|
| ESDK Specification — Client | `spec/client-apis/client.md` |
| ESDK Specification — Encrypt | `spec/client-apis/encrypt.md` |
| ESDK Specification — Decrypt | `spec/client-apis/decrypt.md` |
| ESDK Specification — Key Derivation | `spec/client-apis/key-derivation.md` |
| ESDK Specification — Streaming | `spec/client-apis/streaming.md` |
| ESDK Specification — Algorithm Suites | `spec/framework/algorithm-suites.md` |
| ESDK Specification — Keyring Interface | `spec/framework/keyring-interface.md` |
| ESDK Specification — Structures | `spec/framework/structures.md` |
| ESDK Specification — Commitment Policy | `spec/framework/commitment-policy.md` |
| ESDK Specification — Message Format | `spec/data-format/message.md` |
| ESDK Specification — Message Header | `spec/data-format/message-header.md` |
| ESDK Specification — Message Body AAD | `spec/data-format/message-body-aad.md` |
| ESDK Specification — Message Footer | `spec/data-format/message-footer.md` |
| NIST SP 800-38D (AES-GCM) | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf |
| RFC 5869 (HKDF) | https://tools.ietf.org/html/rfc5869 |
| Key Commitment Paper | Grubbs et al., "Invisible Salamanders" (2020) |

---

## Appendix A: Threat Risk Matrix

```
              │ Low Impact │ Medium Impact │ High Impact │ Critical Impact │
─────────────┼────────────┼──────────────┼─────────────┼─────────────────┤
High         │            │ D1 (DoS)     │             │                 │
Likelihood   │            │              │             │                 │
─────────────┼────────────┼──────────────┼─────────────┼─────────────────┤
Medium       │ I3         │ E2, R3       │ T1, T2, S2  │ E3              │
Likelihood   │            │              │ T3, T4      │                 │
─────────────┼────────────┼──────────────┼─────────────┼─────────────────┤
Low          │ I4         │ I1, D3       │ S1, S3      │                 │
Likelihood   │            │              │             │                 │
─────────────┼────────────┼──────────────┼─────────────┼─────────────────┤
```

## Appendix B: STRIDE Coverage Summary

| Category | Threats Identified | Critical/High | Mitigated by Spec | Residual |
|----------|-------------------|---------------|-------------------|----------|
| Spoofing | 4 | 2 | 4 | 0 |
| Tampering | 8 | 5 | 8 | 0 |
| Repudiation | 3 | 2 | 2 | 1 (RR2) |
| Information Disclosure | 6 | 1 | 4 | 2 (RR3, RR4) |
| Denial of Service | 5 | 1 | 3 | 2 (RR7) |
| Elevation of Privilege | 5 | 3 | 4 | 1 (RR1) |
| **Total** | **31** | **14** | **25** | **6** |
