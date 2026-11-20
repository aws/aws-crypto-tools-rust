# AWS Encryption SDK — Formal Threat Model

**Version:** 2.0.0  
**Date:** September 2026  
**Scope:** AWS Encryption SDK (Rust implementation — `aws-esdk` crate, v2.0.0)  
**Code Baseline:** commit `d8c1c3d` ("feat(esdk-cpp): C++ shim types, raw AES keyring round trip (#66)")  
**Revised:** November 2026, against `2fb844fa` (branch `Mahnush_Verus`). Rechecked at that commit: the MPL dependency path (§1, §3.1a), commitment-policy enforcement (§7.2, E3, §15.2), key zeroization (I1, §15.2), in-tree `unsafe` (§12.2), the dependency table (§12.3), FIPS features (§12.4), the spec source (§16) and the verification status (§14). The verification status reflects the in-crate prim proofs (VR-006/008/009 prim half) and VR-001 properties (a) in-crate and (b) model-only; VR-001 (b) and VR-002 were later moved in-crate on branch `vr001b-vr002-stage2` (§14, T1/E3 residual risk). The threat analysis in the other sections is the `d8c1c3d` analysis and was not re-audited.  
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
primitives are thin wrappers over `aws-lc-rs`. The ESDK message layer is native Rust, and so is
the Material Providers Library (CMM, keyrings, key store, cache): `esdk/Cargo.toml` depends on the
in-repo `aws-crypto-mpl` (`mpl/`) and `aws-mpl-primitives` (`prim/`). There is no Dafny code or
Dafny-transpiled dependency on this path: no `.dfy` sources, no `dafny_runtime`, no
`aws-mpl-legacy`. (History: at the `d8c1c3d` baseline the ESDK linked a Dafny-backed legacy MPL
shim in `unsafe-unreviewed-mpl/`; the ESDK was retargeted onto the native MPL in `e9bde488` (#98),
and `unsafe-unreviewed-mpl/` was removed in `cdd5980` (#107).)

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
- Memory management of key material (zeroization of `PlaintextDataKey` and the other secret key types in `mpl/src/structures/`)
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

The library is three hand-written Rust crates (there is no single root `Cargo.toml`; each crate builds independently). `xtask/` is a build-helper crate and is not part of the library.

| Directory | Package (crate) | Version / Edition | Role |
|-----------|-----------------|-------------------|------|
| `esdk/` | `aws-esdk` | 2.0.0 / 2024 | The ESDK proper: `encrypt()`/`decrypt()`, message-format (de)serialization, key derivation. Depends on `mpl/` and `prim/` by path. Also holds the C++ shim (`esdk/shims/aws-esdk-cpp/`). |
| `prim/` | `aws-mpl-primitives` | 0.1.0 / 2024 | Thin, hand-written wrappers over `aws-lc-rs`: AES-GCM, HMAC, digest, random, HKDF, KBKDF, ECDSA. |
| `mpl/` | `aws-crypto-mpl` | 0.1.0 / 2024 | Native MPL (default CMM, Raw AES keyring, KMS Hierarchical keyring, branch-key store, CMC). This is the MPL the ESDK links against. |

The specification (`awslabs/aws-encryption-sdk-specification`, referenced in code doc-comments as
`spec/...`) is not vendored: `scripts/resolve-spec.sh` checks out the ref in
`scripts/spec-source.json` into `spec/` when `make duvet` runs.

History: the `d8c1c3d` baseline also had `unsafe-unreviewed-mpl/` (`aws-mpl-native`, lib
`aws_mpl_legacy`, a shim over the Dafny-transpiled `aws-mpl-legacy` v0.2.0), and the ESDK linked
that shim instead of `mpl/`. The ESDK moved to the native MPL in `e9bde488` (#98) and the directory
was removed in `cdd5980` (#107). The spec was a git submodule until `6ef7d800` (#91).

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
3. ESDK validates commitment policy allows this algorithm suite (`CommitmentPolicy::allows_for_decrypt` on the parsed suite in `esdk/src/decrypt.rs`, again on the materials' suite in `esdk/src/materials.rs`; the default CMM also checks it in `mpl/src/cmm/default_cmm.rs`)
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
**Verification (VR-017, branch `verus-encrypt-limits-and-lengths`):** the "implementation wraps the
32-bit sequence number" leaf is now Verus-proven not to happen on encrypt. `EncryptFrameSeq`
(`esdk/src/message/body/body_encrypt.rs`) starts at 1, adds exactly 1 per regular frame, refuses
the regular frame that would be numbered `u32::MAX`, and gives the final frame the next number, so
no two frames of a message get the same number (and so the same IV). For frame lengths of 1 to 16
bytes this guard, not the 2^36 - 32 plaintext limit, is what stops the counter (also proven).
Still unverified: the async loop that passes each number to `construct_frame`.

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
The ordering (verify header before decrypting the body, VR-002) now holds for the shipped decrypt
path. `step_decrypt_body` needs a `HeaderVerified` token, which only `esdk/src/decrypt_gate.rs`
can create. Verus proves the token is created only when the header tag check returned `Ok`, and
the compiler enforces that frames cannot be decrypted without it. Still trusted: that the real tag
check result is passed in, that aws-lc-rs AES-GCM accepts only a valid tag, and that frames are
decrypted only through `step_decrypt_body`. The earlier model
(`verification/header_auth_ordering_proofs.rs`) is superseded — see
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
- Commitment-policy enforcement is implemented: `CommitmentPolicy::allows_for_encrypt` / `allows_for_decrypt` (`mpl/src/structures/commitment_policy.rs`) are checked by the ESDK on the input suite (`esdk/src/encrypt.rs`), the parsed suite (`esdk/src/decrypt.rs`) and the materials' suite (`esdk/src/materials.rs`), and by the default CMM (`mpl/src/cmm/default_cmm.rs`). (History: at the `d8c1c3d` baseline the linked legacy shim's `validate_commitment_policy_on_*` returned `Ok(())`; that shim was removed in `cdd5980`.)

**Residual Risk:** Systems that explicitly configure `FORBID_ENCRYPT_ALLOW_DECRYPT` remain vulnerable to this attack class (a conscious spec trade-off). The commit-key comparison decision is now Verus-proven (VR-001, property (a): accept iff the header suite data equals the derived value and the lengths agree); its placement before frame decryption (property (b)) now holds for the shipped decrypt path: a `CommitmentAccepted` token (`esdk/src/decrypt_gate.rs`) is Verus-proven to be created only when the check passed (or the suite does not commit), and the compiler enforces that frames cannot be decrypted without it. Still trusted: that the unverified callers pass the real comparison result and `has_commitment` value, and that frames are decrypted only through `step_decrypt_body`. The earlier model (`verification/commitment_ordering_proofs.rs`) is superseded. Its constant-time execution (property (c)) is trusted to aws-lc-rs. The policy checks remain unproven.

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
- `PlaintextDataKey`, `SigningKey` and `SymmetricSigningKey` (`mpl/src/structures/algorithm_suite.rs`) derive `Zeroize` and `ZeroizeOnDrop` from the `zeroize` crate, so their bytes are zeroed on drop; branch keys, beacon keys and the Raw AES wrapping key are also zeroized on drop with the `zeroize` crate. (History: the earlier hand-written `unsafe` `write_volatile` loop in `PlaintextDataKey::zeroize` was removed in `a864ad87`, #131.)
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

**Verification (VR-015, branch `signature-release-gate`):** the SDK side of the first spec
mitigation is now checked in-crate. The final plaintext (final frame, the last full frame before
an empty final frame, or a non-framed body) is held in a `HeldFinalPlaintext` and can only be
written to the caller through `release`, which needs a `SignatureVerified` token
(`esdk/src/decrypt_gate.rs`). Verus proves the token is created only when the signature check
returned `true` for a signed suite with a verification key, or the suite is unsigned and there is
no key; the compiler enforces that the final plaintext cannot be written before the token exists.
Since VR-015 (b) (branch `sizing-and-sigpresence`), the check that the key is present exactly
when the suite is signed is the verified `signature_presence_gate`, and step 5 needs the
`SignaturePresence` token it mints, so a CMM that drops the verification key for a signed suite
cannot make decrypt skip the signature check. Still trusted: aws-lc-rs signature verification;
that the callers pass the real check result, suite flag and key-present flag; that the decryption
materials do not change between the presence check and step 5; and that the final plaintext
reaches the caller only through the gated write. ("No verification key means unsigned suite" is
no longer trusted.) Regular non-final frames are still
released before the signature, as the spec allows, so the residual risk above (callers acting on
streamed frames before the operation finishes) is unchanged.

**Encrypt side (VR-019, branch `verus-encrypt-signing-key-presence`; also relevant to R1):** the
encrypt signing step gets the signing key only through a `SigningKeyPresent` token
(`esdk/src/encrypt_gate.rs`). Verus proves that `signing_key_gate` makes the token iff the suite
signs and the encryption materials have a signing key, and that the token holds exactly that key.
The compiler enforces that `ecdsa_sign_digest` cannot get the key any other way. This is the
counterpart of VR-015 (b), but it covers one direction only (finding F3). esdk rejects a signing
suite with no signing key only in `step_construct_signature`, after the header and body are
written, and it does not reject a non-signing suite whose materials have a signing key. Both the
reverse direction and early rejection rely on the MPL (`GetEncryptionMaterials::send` /
`check_encryption_materials` and `EncryptionMaterialsBuilder::build`), which is trusted code
reading. So the residual risk that a misbehaving CMM makes encrypt omit the signature for a
signing suite, or sign for a non-signing suite, now rests on the MPL checks plus the proven esdk
gate in step 4. Also trusted: that `encrypt_steps` runs step 4 for every signing suite and that
step 4 writes the footer.

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

The ESDK, primitives, and MPL crates in this repository are **hand-written native Rust**, and the
ESDK depends only on the in-repo `mpl/` and `prim/` for MPL work. Some MPL comments cite the Dafny
MPL as the reference behavior (for example `mpl/src/structures/materials_checks.rs`, "Ported from
`Materials.dfy`"), but no Dafny code is compiled or linked.

In-tree `unsafe` (at `5ea2a804`) is confined to the C++ shim:

| Location | Count | What it does |
|----------|-------|--------------|
| `esdk/shims/aws-esdk-cpp/src/lib.rs` | 4 `unsafe` expressions | `&*ptr` dereference of a non-null raw pointer to return a C++ FFI handle; `as_ref()` on caller-supplied raw pointers for the KMS client, DynamoDB client and cache (shim, not core library) |
| `esdk/src/*`, `mpl/src/*`, `prim/src/*` | 0 | No `unsafe` in the ESDK, the MPL or the crypto primitives (`unsafe_op_in_unsafe_fn` in the `lib.rs` lint lists is a lint name, not an `unsafe` block) |

There are **no** raw `aws-lc-sys` FFI calls (no `EC_POINT`/`EC_GROUP`), no `from_raw_parts`,
no `set_len`, and no `unsafe impl Send/Sync` in `esdk/src`, `mpl/src` or `prim/src`. Test,
benchmark and test-server code (`esdk/performance-tests/src/alloc.rs`, `esdk/tests/test_resource_leaks.rs`,
`esdk/tests/test_body_allocation.rs`, `mpl/tests/test_keyring_memory.rs`,
`esdk/shims/aws-esdk-cpp/src/tests.rs`, `esdk/shims/aws-esdk-cpp/test-server/src/seam.rs` and
`esdk/shims/aws-esdk-cpp/examples/custom-keyring/src/lib.rs`) uses `unsafe` for counting
allocators and FFI test harnesses, but these are not part of the shipped library.

(History: at the `d8c1c3d` baseline the list also had a `core::ptr::write_volatile` zeroization
loop in `mpl/src/structures/algorithm_suite.rs`, removed in `a864ad87` (#131), and an `unsafe impl
GlobalAlloc` in `unsafe-unreviewed-mpl/prim/src/use_memory_tracker.rs`, removed with that
directory in `cdd5980` (#107).)

Risks:
- The native `mpl/` (`aws-crypto-mpl`) keyrings/CMM/key store/cache are hand-written, are on the ESDK dependency path, and require review.
- Native primitive wrappers (`prim/src/lib.rs`, `prim/src/ecdsa.rs`, `prim/src/hkdf.rs`) are manually written over `aws-lc-rs` and require review, though they contain no `unsafe`.
- The C++ shim's raw-pointer handling is the only in-tree `unsafe` on a shipped path.

### 12.3 Dependency Supply Chain

Versions are the requirement strings in `esdk/Cargo.toml` and `mpl/Cargo.toml` at `5ea2a804`
(not lockfile versions).

| Dependency | Declared in | Version | Role | Risk |
|------------|-------------|---------|------|------|
| `aws-crypto-mpl` | `esdk` | local path (`mpl/`) | Native MPL: CMM, keyrings, key store, cache | In-repo, hand-written; requires review |
| `aws-mpl-primitives` | `esdk`, `mpl` | local path (`prim/`) | Wrappers over `aws-lc-rs` | In-repo, hand-written; requires review |
| `aws-lc-rs` | `esdk` (`prim` too) | 1.18.1 (`default-features = false`) | All cryptographic primitives (safe Rust API) | Wraps C code; FIPS-validated variant available via feature |
| `aws-lc-sys` | via `aws-lc-rs/aws-lc-sys` feature (default) | — | Native crypto backend (non-FIPS) | C code via FFI; not pinned directly |
| `aws-lc-fips-sys` | via `aws-lc-rs/fips` feature | — | Native crypto backend (FIPS) | C code via FFI; enabled by the `fips` feature |
| `aws-sdk-kms` | `mpl` (optional, `kms` feature) | 1.123.0 | KMS API calls | AWS-maintained |
| `aws-sdk-dynamodb` | `mpl` (optional, `ddb` feature) | 1.130.0 | Branch key store access | AWS-maintained |
| `aws-config` | `mpl` (optional, `default-aws-sdk-clients`); `esdk` dev | 1.12.0 | Default AWS SDK client construction | AWS-maintained |
| `aws-smithy-types` | `esdk`, `mpl` | 1.8.1 | Smithy type support | AWS-maintained |
| `aws-smithy-runtime-api` | `mpl` (`client` feature); `esdk` dev, `mpl` dev (`http-1x` feature) | 1.19.0 | Smithy runtime types (SDK client/error plumbing) | AWS-maintained |
| `aws-smithy-http-client` (dev) | `esdk` | 1.5.0 (`rustls-aws-lc`) | HTTP client for examples/tests | Dev-dependency only |
| `aws-types` | `esdk`, `mpl` | 1.6.0 | AWS SDK shared types | AWS-maintained |
| `tokio` | `esdk`, `mpl` (optional) | 1.49 | Async runtime | Widely audited; large attack surface |
| `async-trait` | `mpl` | 0.1.92 | Async trait support (keyring/CMM traits) | Widely used |
| `zeroize` | `esdk` 1.9.0; `mpl` 1.9.0 with `derive` | 1.9.0 | Zeroizing key material on drop | Well-audited |
| `lru`, `time`, `uuid`, `base64` | `mpl` | 0.18.5, 0.3.55, 1.27.0, 0.23.1 | Cache, timestamps, IDs, encoding | Widely used |
| `vstd` | `esdk` | =0.0.0-2026-06-14-0213 | Verus specs and proofs; the `verus!` blocks compile to plain Rust under rustc | Verification library; adds no runtime crypto |
| `rand` (dev) | `esdk` | 0.10.3 | Random in examples/tests | Dev-dependency only |
| `pem` (dev) | `esdk` | 4.0.0 | PEM parsing in examples/tests | Dev-dependency only |

Note: no manifest declares `dafny_runtime`, `dashmap` or `aws-mpl-legacy`. (History: at the
`d8c1c3d` baseline `esdk` depended on `aws-mpl-legacy`, a path dependency on
`unsafe-unreviewed-mpl/mpl`; it was dropped in `e9bde488` (#98).)

### 12.4 FIPS Compliance

`esdk/Cargo.toml`, `mpl/Cargo.toml` and `prim/Cargo.toml` expose feature flags that select the
crypto backend through `aws-lc-rs`; the `esdk` features forward to `prim` and `mpl`:
- `aws-lc-sys` (in `default`): non-FIPS backend (`aws-lc-rs/aws-lc-sys`)
- `fips`: FIPS 140-3 validated module (`aws-lc-rs/fips`)

Threat: If the FIPS boundary is incorrectly drawn (e.g., key material passes through non-FIPS code paths), compliance claims are invalidated.

---

## 13. Residual Risks

| ID | Risk | Severity | Justification for Acceptance |
|----|------|----------|------------------------------|
| RR1 | Non-committing suites allow multi-plaintext attacks | Critical | Legacy backward compatibility; mitigated by default commitment policy |
| RR2 | Streaming plaintext misuse by callers | High | Application responsibility; documented in spec |
| RR3 | Ciphertext length leaks plaintext size | Low | Industry standard; padding is caller responsibility |
| RR4 | Memory exposure via OS-level access | Medium | Requires privileged OS access; mitigated by deployment hardening |
| RR5 | Native MPL keyring/CMM/key store logic (`mpl/`) has no formal verification | Medium | In-repo and reviewable; covered by unit and integration tests. (History: this row was "the Dafny-backed legacy MPL is not auditable in-repo"; that dependency was removed in `cdd5980`.) |
| RR6 | Discovery keyring decrypts unintended messages | Medium | Configuration choice; filters available |
| RR7 | No maximum message size enforcement in SDK | Low | Application-level concern |

---

## 14. Verification Recommendations (Prioritized)

Using the prioritization formula: `Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`

All targets reference real files in this repository. Scores below are the original ranking. For
the current coverage gaps, full scoring and agent assignments see
`docs/verification-recommendations.md`.

**Verification status on branch `verus-encrypt-signing-key-presence`** (in-crate counts; the model
results are unchanged since `5ea2a804`). Verus checks two things:

- **In-crate (shipped `esdk` code).** `make -C esdk verus` verifies the `verus!` blocks in
  `esdk/src/message/`, `esdk/src/key_derivation.rs`, `esdk/src/secret.rs` and
  `esdk/src/decrypt_gate.rs`, `esdk/src/encrypt.rs` and `esdk/src/encrypt_gate.rs` (54 exec fns,
  11 proof fns): `97 verified,
  0 errors` for both the default features and `--no-default-features --features aws-lc-sys` (40 at
  `5ea2a804`, 45 after VR-009, 57 after VR-011, 69 after VR-012, 73 after the VR-001 (b) / VR-002
  tokens, 77 after VR-015, 81 after VR-016, 94 after VR-017 / VR-018). This
  covers parts of VR-003 (big-endian decoding, bounded readers, header-field decisions, the 0x41
  Base64 hint), VR-004 (regular- and final-frame sequence checks, frames-start-at-1 lemmas),
  VR-005 (body AAD, IV, frame prefix layout), VR-007 (EDK count check), the esdk half of VR-009
  (key-derivation length checks), the secret-type accessors of VR-011, the VR-012 codec lemmas, and
  the decrypt-order tokens of VR-001 (b) and VR-002, the VR-015 signature release gate
  (threat R3) with its presence check (VR-015 (b)), and VR-016 (every esdk AES-GCM decryption
  gets a plaintext buffer as long as its ciphertext, so BUG-07(b) is unreachable from esdk),
  VR-017 (encrypt-side MAX_DATA budget and frame sequence numbers; Attack Tree 1) and VR-018
  (encrypt-side suite-data and data-key length checks), and VR-019 (the encrypt signing-key
  check, one direction only; threat R3/R1). The async readers and loops around these cores
  are unverified glue.
- **Decrypt order (VR-001 (b), VR-002), Verus plus the compiler.** Verus proves that the
  `CommitmentAccepted` and `HeaderVerified` tokens in `esdk/src/decrypt_gate.rs` are created only
  when the commitment check and the header tag check passed. The compiler enforces the order: only
  `decrypt_gate` can build a token, and `step_decrypt_body` cannot be called without a
  `&HeaderVerified`. Trusted: the unverified callers pass the real check results, aws-lc-rs, frames
  are decrypted only through `step_decrypt_body`, and a token is not tied to one message.
- **VR-011 confinement (compiler- and lint-checked, not Verus).** esdk code outside
  `esdk/src/secret.rs` cannot read the bytes of the plaintext data key or the derived message key
  (Rust privacy, plus clippy `disallowed-methods` in `esdk/clippy.toml`). VR-011 as a whole is not
  Verus-proven.
- **Model only (standalone files in `verification/`).** `make -C verification verify`: 11 files,
  78 verified, 0 errors. The EDK list loop, the frame `ct ‖ tag` append and VR-010
  (zeroization) are checked only here. The VR-002, VR-001 (b) and VR-006 models
  (`header_auth_ordering_proofs.rs`, `commitment_ordering_proofs.rs`,
  `aes_gcm_bounds_proofs.rs`) are superseded by in-crate proofs and kept as history.
  The VR-010 model describes a `write_volatile` loop that no longer exists (removed in
  `a864ad87`); it is deferred and unchanged.
- **VR-001 (key commitment):** the commitment equality/length decision in `validate_suite_data`
  is Verus-proven in-crate (property a); the check-before-frame-decryption order (property b) is
  in-crate through the tokens above; constant time (property c) is trusted to aws-lc-rs.
- **Done (in-crate):** VR-008 (ECDSA length) and the prim half of VR-009 (HKDF length,
  `prim/src/hkdf.rs`) are proven in-crate since Verus was enabled in `prim`.

The fn-by-fn list and the reasons each model-only property is not in-crate are in
`docs/verus-proofs-report.md` ("In-crate proofs") and `verification/README.md`.

| Priority | Score | Target | Property to Verify | Tool | Threat ID | Agent | File |
|----------|-------|--------|-------------------|------|-----------|-------|------|
| 1 | 16.0 | Key commitment check | Derived commit key == stored commit key (constant-time) before any decryption | Verus | E1/E3, T8 | `verus-header-parsing-proofs` | `esdk/src/message/header.rs` (`validate_suite_data`), `esdk/src/key_derivation.rs` (`derive_key_v2`) |
| 2 | 12.0 | Header auth tag ordering | Header tag verified before any frame is processed, in all paths | Verus | T1, T6 | `verus-header-parsing-proofs` | `esdk/src/decrypt.rs`, `esdk/src/message/header_auth.rs` |
| 3 | 10.8 | Header/EDK parsing safety | Malformed input returns `Err`, never panics; EDK count > 0 and ≤ max before KMS calls | Verus | D1, D3 | `verus-header-parsing-proofs` | `esdk/src/message/header.rs` (`read_header_body`, `validate_max_encrypted_data_keys`), `encrypted_data_keys.rs` |
| 4 | 9.6 | Frame sequence validation | Sequential frame numbers enforced (no gaps/reordering); final-frame handling correct | Verus | T2, T3 | `verus-header-parsing-proofs` | `esdk/src/message/body/body_decrypt.rs` |
| 5 | 9.0 | Frame construction / body serialization | Frame iteration and slicing never exceed buffer bounds; no panic | Verus | D2 | `verus-zero-panic` | `esdk/src/message/body/body_encrypt.rs` |
| 6 | 9.0 | AES-GCM panic freedom | All slice accesses (nonce, tag, ciphertext) in-bounds; wrappers never panic | Verus | D1 | `verus-zero-panic` | `prim/src/lib.rs` (`aes_encrypt`, `aes_decrypt`) |
| 7 | 6.0 | Key-material zeroization | `PlaintextDataKey` (and the other secret key types) bytes are zeroed on drop. Zeroization now comes from `#[derive(Zeroize, ZeroizeOnDrop)]`; the existing model covers the removed `write_volatile` loop and is deferred | Verus | I1, I5 | `verus-unsafe-ffi-safety` | `mpl/src/structures/algorithm_suite.rs` |
| 8 | 4.8 | Data-key non-disclosure (VR-011, information flow) | The plaintext data key and the derived message encryption key are never written directly to the output stream or returned to the caller; they reach output only through AES-GCM or, for the data key, as an EDK from the keyring. The V2 commitment value is derived from the data key but public by spec (header suite data), so it is a declassification. **Status (branch `vr011-confinement`):** confined to `esdk/src/secret.rs`, checked by the compiler (privacy) and clippy (`esdk/clippy.toml`), not by Verus. Verus covers only the secret types' accessors and the commitment declassification. Trusted: the TB-A adapters (`data_key_from_encryption_materials`, `data_key_from_decryption_materials`, `identity_copy`, `hkdf_v1`, `hkdf_v2_extract`, `hkdf_v2_expand_key`, `hkdf_v2_expand_commitment`, `seal`, `open`), aws-lc-rs, keyrings/CMMs. Out of scope: mpl key types and accessors, the ECDSA signing key, the `test-internals` feature. Not done: a verified encrypt/decrypt flow | Rust compiler + clippy; Verus (secret-type API only) | I1, I5, S3 | unassigned | `esdk/src/secret.rs`, `esdk/clippy.toml`; callers in `esdk/src/encrypt.rs`, `esdk/src/decrypt.rs`, `esdk/src/key_derivation.rs`, `esdk/src/message/body/*` |

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
              Verus verification. The commit-key comparison in validate_suite_data and the
              commitment-policy checks (CommitmentPolicy::allows_for_encrypt/_decrypt, called
              from esdk and the default CMM) are both unproven."
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
| Done | Commitment-policy enforcement is implemented (`CommitmentPolicy::allows_for_encrypt`/`_decrypt`, checked in `esdk/src/encrypt.rs`, `decrypt.rs`, `materials.rs` and `mpl/src/cmm/default_cmm.rs`). (History: at `d8c1c3d` this was the Critical item "implement real enforcement", because the legacy shim returned `Ok(())`.) | Keep the checks covered by tests. The commit-key comparison decision is Verus-proven (VR-001, property (a)); the policy checks themselves remain unproven |
| High | Audit the in-tree `unsafe` (raw-pointer handling in the C++ shim, `esdk/shims/aws-esdk-cpp/src/lib.rs`) | Small but present unsafe surface |
| High | Keep zeroization on drop for the plaintext data key and other secrets (`PlaintextDataKey`, `SigningKey`, `SymmetricSigningKey` derive `Zeroize`/`ZeroizeOnDrop`) | Reduces key exposure window |
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

The formal specification is `awslabs/aws-encryption-sdk-specification`; the ESDK source
doc-comments reference it with `spec/...` paths. It is not a submodule (since `6ef7d800`, #91):
`scripts/resolve-spec.sh` checks out the ref in `scripts/spec-source.json` (currently `master`)
into `spec/`, and `make -C esdk duvet` runs it.

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
