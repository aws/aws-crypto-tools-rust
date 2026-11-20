# ESDK profile appendix: domain

Library-specific domain tables and context for the native-Rust AWS Encryption SDK (ESDK). Read with `.kiro/verification-profile/verification-profile.yaml`. The text below is copied verbatim from the agent files at `4054fd89`; each block names its source. This file stays with the library when the toolkit is copied out.

## Message format and constants

One copy of the shared constants for all proof agents.

Source: `.kiro/agents/verus-header-parsing-proofs.md` §Shared Constants. The block in `.kiro/agents/verus-zero-panic.md` §Shared Constants is identical except for its heading, which names the other two agents ("Consistent with verus-header-parsing-proofs and verus-unsafe-ffi-safety agents"); the Rust code is byte-identical.

> ## Shared Constants (Consistent with verus-zero-panic and verus-unsafe-ffi-safety agents)
>
> These constants MUST match across all Verus agents:

```rust
// Algorithm Suite IDs (ESDK)
spec const SUITE_AES_128_GCM_IV12_TAG16_NO_KDF: u16 = 0x0014;
spec const SUITE_AES_192_GCM_IV12_TAG16_NO_KDF: u16 = 0x0046;
spec const SUITE_AES_256_GCM_IV12_TAG16_NO_KDF: u16 = 0x0078;
spec const SUITE_AES_128_GCM_IV12_TAG16_HKDF_SHA256: u16 = 0x0114;
spec const SUITE_AES_192_GCM_IV12_TAG16_HKDF_SHA256: u16 = 0x0146;
spec const SUITE_AES_256_GCM_IV12_TAG16_HKDF_SHA256: u16 = 0x0178;
spec const SUITE_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256: u16 = 0x0214;
spec const SUITE_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384: u16 = 0x0346;
spec const SUITE_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384: u16 = 0x0378;
spec const SUITE_AES_256_GCM_HKDF_SHA512_COMMIT_KEY: u16 = 0x0478;
spec const SUITE_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384: u16 = 0x0578;

// Cryptographic lengths
spec const AES_GCM_IV_LEN: nat = 12;
spec const AES_GCM_TAG_LEN: nat = 16;
spec const AES_128_KEY_LEN: nat = 16;
spec const AES_192_KEY_LEN: nat = 24;
spec const AES_256_KEY_LEN: nat = 32;
spec const COMMIT_KEY_LEN: nat = 32;

// Message format constants
spec const MSG_ID_LEN_V1: nat = 16;
spec const MSG_ID_LEN_V2: nat = 32;
spec const HEADER_VERSION_1: u8 = 0x01;
spec const HEADER_VERSION_2: u8 = 0x02;
spec const MSG_TYPE_CUSTOMER_AED: u8 = 0x80;
spec const CONTENT_TYPE_NON_FRAMED: u8 = 0x01;
spec const CONTENT_TYPE_FRAMED: u8 = 0x02;
spec const FINAL_FRAME_SENTINEL: u32 = 0xFFFF_FFFF;
spec const MAX_FRAME_LEN: nat = 0xFFFF_FFFF;  // 2^32 - 1
spec const MAX_FRAMES: nat = 0xFFFF_FFFF;     // 2^32 - 1
```

Source: `.kiro/agents/verus-unsafe-ffi-safety.md` §Shared Constants. Its cryptographic-length block repeats the six lengths above; it adds the digest and maximum-size constants.

> ## Shared Constants (Consistent with verus-header-parsing-proofs and verus-zero-panic agents)
>
> These constants MUST match across all Verus agents. They remain useful as the shape of the safe-wrapper length preconditions, even though no raw pointer uses them today:

```rust
// Cryptographic lengths
spec const AES_GCM_IV_LEN: nat = 12;
spec const AES_GCM_TAG_LEN: nat = 16;
spec const AES_128_KEY_LEN: nat = 16;
spec const AES_192_KEY_LEN: nat = 24;
spec const AES_256_KEY_LEN: nat = 32;
spec const COMMIT_KEY_LEN: nat = 32;

// Digest / HMAC output lengths
spec const HMAC_SHA256_LEN: nat = 32;
spec const HMAC_SHA384_LEN: nat = 48;
spec const HMAC_SHA512_LEN: nat = 64;

// Maximum buffer sizes (prevent allocation overflow)
spec const MAX_PLAINTEXT_LEN: nat = 0xF_FFFF_FFE0;  // 2^36 - 32
spec const MAX_AAD_LEN: nat = 0xFFFF;  // 2^16 - 1 (from encryption context serialization)
```

## Header field tables

Source: `.kiro/agents/verus-header-parsing-proofs.md` §Key AWS Encryption SDK Header Fields to Prove.

For **Version 1.0** headers (version byte = 0x01):
| Offset | Field | Length | Constraint |
|--------|-------|--------|------------|
| 0 | Version | 1 | Must be 0x01 |
| 1 | Type | 1 | Must be 0x80 |
| 2 | Algorithm Suite ID | 2 | Must be valid ESDK suite |
| 4 | Message ID | 16 | Random bytes |
| 20 | AAD Length | 2 | Key-value pairs length |
| 22+ | AAD | Variable | Sorted key-value pairs |
| var | EDK Count | 2 | Must be >= 1 |
| var | EDKs | Variable | Provider ID + info + ciphertext |
| var | Content Type | 1 | 0x01 or 0x02 |
| var | Reserved | 4 | Must be 0x00000000 |
| var | IV Length | 1 | Must match algorithm suite |
| var | Frame Length | 4 | 0 if non-framed |

For **Version 2.0** headers (version byte = 0x02):
| Offset | Field | Length | Constraint |
|--------|-------|--------|------------|
| 0 | Version | 1 | Must be 0x02 |
| 1 | Algorithm Suite ID | 2 | Must be 0x0478 or 0x0578 |
| 3 | Message ID | 32 | Random bytes |
| 35 | AAD Length | 2 | Key-value pairs length |
| 37+ | AAD | Variable | Sorted key-value pairs |
| var | EDK Count | 2 | Must be >= 1 |
| var | EDKs | Variable | Provider ID + info + ciphertext |
| var | Content Type | 1 | Must be 0x02 (framed only) |
| var | Frame Length | 4 | Must be > 0 |
| var | Algorithm Suite Data | 32 | Commit key |

## Spec-conformance skeletons

Source: `.kiro/agents/verus-header-parsing-proofs.md` §Verus Patterns You Must Use, "Proving Spec Conformance".

```rust
verus! {

// Ghost model of a valid header per the ESDK specification
spec fn valid_header_v1(header: HeaderV1) -> bool {
    &&& header.version == 0x01
    &&& header.msg_type == 0x80
    &&& (header.algorithm_suite_id == 0x0014
        || header.algorithm_suite_id == 0x0046
        || header.algorithm_suite_id == 0x0078
        || header.algorithm_suite_id == 0x0114
        || header.algorithm_suite_id == 0x0146
        || header.algorithm_suite_id == 0x0178
        || header.algorithm_suite_id == 0x0214
        || header.algorithm_suite_id == 0x0346
        || header.algorithm_suite_id == 0x0378)
    &&& header.message_id@.len() == 16
    &&& header.content_type == 0x01 || header.content_type == 0x02
    &&& header.reserved == spec_seq_of_zeros(4)
    &&& header.iv_length > 0
}

spec fn valid_header_v2(header: HeaderV2) -> bool {
    &&& header.version == 0x02
    &&& (header.algorithm_suite_id == 0x0478
        || header.algorithm_suite_id == 0x0578)
    &&& header.message_id@.len() == 32
    &&& header.content_type == 0x02  // framed only in v2
    &&& header.algorithm_suite_data@.len() == 32  // commit key
}

}
```

## Spec topics

Source: `.kiro/agents/spec-analyzer.md` intro.

> Your target is the **native-Rust AWS Encryption SDK (ESDK)** in this repository — the `aws-esdk` crate (`esdk/`), its message format, encrypt/decrypt flows, key derivation and key commitment, and the secret types that hold data keys.

Source: `.kiro/agents/spec-analyzer.md` §Where the Specification Lives.

- **Formal spec:** the `spec/` tree at the repository root. It is checked out by `scripts/resolve-spec.sh` (it is **not** a git submodule, and may be absent locally — the script resolves it on demand). The ESDK documents are under `spec/data-format/` and `spec/client-apis/`.
- **Tracked documents:** the Duvet config at `esdk/.duvet/config.toml` enumerates exactly the spec documents this crate is traced against — the `data-format/*` set (`message-header.md`, `message-body.md`, `message-body-aad.md`, `message-footer.md`, `message.md`), the `client-apis/*` set (`client.md`, `encrypt.md`, `decrypt.md`, `streaming.md`) and `framework/transitive-requirements.md`. Use this set as the authoritative list of what the ESDK is held to.
- **Duvet annotations:** inline `//=` / `//#` comments in `esdk/src/**/*.rs` and `esdk/tests/**/*.rs`. These are a pre-built index mapping RFC 2119 requirements to the code and tests that realize them. Use them to find which requirements are already implemented (`type=implication`) or tested (`type=test`), and to jump straight to the relevant code.

Source: `.kiro/agents/spec-analyzer.md` §Your Process, step 1 (Discover Specifications).

- The ESDK markdown specs under `spec/data-format/` and `spec/client-apis/` (source of truth)
- The Duvet annotations in `esdk/src` and `esdk/tests` (requirement → code map), anchored on the document set in `esdk/.duvet/config.toml`
- README files and developer guides in `esdk/`
- Configuration types (client config, commitment policy, algorithm-suite selection)

Source: `.kiro/agents/spec-analyzer.md` §Your Process, step 2 (Extract Security Properties), the ESDK-specific topics.

- **Message header / body / footer layout:** the byte layout of the header, framed and non-framed body, and the footer (signature) — field order, lengths, big-endian integer fields, and reserved/version bytes
- **Key commitment:** the algorithm-suite data and the accept/reject decision that binds a message to exactly one data key (commitment-policy enforcement, suite-downgrade prevention)
- **HKDF key derivation:** derivation of the data-encryption key (and commitment key) from the plaintext data key — inputs, output lengths, and which suite selects which derivation
- **Frame sequencing:** sequence numbers starting at 1, monotonic framing, final-frame handling, and rejection of out-of-order or duplicate frames
- **EDK count limits:** the maximum number of encrypted data keys accepted on decrypt
- **Streaming release of plaintext:** when plaintext may be released to the caller relative to authentication (header-auth before body, body-auth before release), and the risk of releasing unauthenticated plaintext
- **Signature:** the ECDSA signature over the message for signing suites, and what it does and does not authenticate
- **Security properties:** state each as "for all messages / inputs, the ESDK MUST …" (e.g. header auth tag verified before any frame is decrypted). Tie each to the spec clause and, where present, the Duvet-annotated code or test that realizes it.
- **Data flows:** trace what crosses each boundary — plaintext and data keys between the caller, the ESDK, the MPL keyring/CMM interfaces, and `aws-lc-rs` (through `prim`); and the serialized message bytes between the ESDK and the caller's `Source` / `Sink`.
- **Trust boundaries:** mark where the ESDK stops trusting its input — the attacker-controlled ciphertext/message bytes on decrypt, the caller-supplied `Source` / `Sink`, the KMS/CMM/keyring responses, and the C++ shim handles — and what each boundary is allowed to assume.

Source: `.kiro/agents/spec-analyzer.md` §Your Process, step 3 (Map the Architecture).

- Components and their responsibilities: the `Client` (encrypt/decrypt entry points), `encrypt` / `decrypt` flows, `message::*` (header, header-auth, body, footer serialization and parsing), `key_derivation`, and the `secret` types that confine data keys
- Interfaces between components (Client → encrypt/decrypt → message serialization + key derivation; CMM / keyring as called contracts)
- External dependencies (the MPL keyrings/CMMs via `mpl`, `aws-lc-rs` via the `prim` crate, AWS KMS, and the caller's streaming `Source` / `Sink`)
- Configuration options that affect security posture (commitment policy, algorithm-suite selection, signing vs non-signing suites)

Source: `.kiro/agents/spec-analyzer.md` §Your Process, step 4 (Identify Security Invariants), the ESDK-specific items.

- What defaults are configured (default commitment policy, default suite)?
- What backward-compatibility constraints exist (V1 vs V2 messages, legacy suites)?

Source: `.kiro/agents/spec-analyzer.md` §Rules, the ESDK-specific items.

- Read the actual specification documents under `spec/data-format/` and `spec/client-apis/` — never infer spec requirements. If `spec/` is absent locally, note that it is resolved by `scripts/resolve-spec.sh` and work from the Duvet annotations that cite it
- Be precise about algorithm parameters (key sizes, IV/nonce lengths, tag lengths, HKDF output lengths, frame sizes, EDK count limits, big-endian field widths)
- Distinguish between mandatory security properties and optional/configurable ones (commitment policy, suite selection, signing vs non-signing suites)
- Stay within ESDK scope: the **message format** (header/body/footer), encrypt/decrypt, key derivation and commitment, frame sequencing, EDK limits, streaming release and the signature. The MPL (keyrings, CMMs, key stores, caches) and `aws-lc-rs` are **dependencies** — treat their interfaces as contracts; do not analyze their internals here

## Threat-model context

Source: `.kiro/agents/threat-model-generator.md` intro.

> Your target is the **native-Rust AWS Encryption SDK (ESDK)** in this repository — a client-side encryption library (`esdk/`) that produces and consumes the encrypted message format, built on the Material Providers Library (`mpl/`) and safe crypto primitives (`prim/`).

Source: `.kiro/agents/threat-model-generator.md` §ESDK Context.

- **Formal spec:** `spec/` at the repo root, checked out by `scripts/resolve-spec.sh` (not a submodule; may be absent locally). The tracked document set is listed in `esdk/.duvet/config.toml` (`spec/data-format/*` for the message header/body/footer layout, `spec/client-apis/*` for encrypt/decrypt, `spec/framework/algorithm-suites.md` and `spec/framework/transitive-requirements.md`).
- **Duvet annotations:** inline `//= spec/...` / `//# ...` comments in `esdk/src` and `esdk/tests` map requirements to code/tests — cite them when documenting existing mitigations. `type=test` means tested, not proven.
- **Components:** `Client` (`esdk/src/client.rs`), `encrypt` (`esdk/src/encrypt.rs`), `decrypt` (`esdk/src/decrypt.rs`), the `message::*` submodules (`esdk/src/message/` — `header`, `header_auth`, `header_types`, `v1_header_body`, `v2_header_body`, `encrypted_data_keys`, `encryption_context`, `footer`, `serialize_functions`, `serializable_types`, and `body/{body_encrypt,body_aad,body_decrypt}`), key derivation (`esdk/src/key_derivation.rs`), and the secret types (`esdk/src/secret.rs`).
- **Trust boundaries:** the MPL keyrings and CMMs (`mpl/`, the key-management interfaces the ESDK calls as contracts); `aws-lc-rs`, reached only through the safe `prim` wrappers; AWS KMS (reached through the MPL keyrings); the C++ shim at `esdk/shims/aws-esdk-cpp` (the only shipped-path `unsafe`); and the caller's `Source` / `Sink` in the streaming paths.
- **Scope:** the message format and the ESDK's cryptographic operations (encrypt/decrypt, key derivation, key commitment, commitment-policy enforcement at the ESDK boundary, data-key handling inside `esdk`). The MPL internals (keyrings, CMMs, caches), `aws-lc-rs`, and KMS are trusted dependencies — keep key-management internals out of scope.

Source: `.kiro/agents/threat-model-generator.md` §Your Process, step 1 (Gather Context).

- Architecture (`Client`, encrypt/decrypt paths, the `message::*` serialization and parsing submodules, key derivation, secret types)
- The `spec/data-format` and `spec/client-apis` documents and the Duvet annotations that map them to code
- Cryptographic operations (AES-GCM authenticated encryption, key commitment, HKDF key derivation, ECDSA signing, the algorithm suites)
- External dependencies and integrations (MPL keyrings/CMMs, `aws-lc-rs` through `prim`, KMS, the C++ shim)
- Data flows (plaintext in, ciphertext/message out, streaming reads/writes over `Source` / `Sink`, the EDKs and encryption context in the header)
- Configuration options that affect security (commitment policy, suite selection, V1 vs V2 message format, EDK/frame limits)

Source: `.kiro/agents/threat-model-generator.md` §Your Process, step 2 (Identify Assets), the ESDK-specific items.

- Sensitive data (plaintext, data keys, derived keys)
- Integrity-critical data (message header and its auth tag, encryption context, frame sequence, footer signature)

Source: `.kiro/agents/threat-model-generator.md` §Rules, the ESDK-specific items.

- Always read the `spec/data-format` and `spec/client-apis` documents before generating threats — do not guess
- Focus on threats relevant to the ESDK specifically, not generic security advice, and keep MPL key-management internals and `aws-lc-rs` out of scope (they are trusted dependencies)
- For the ESDK, pay special attention to: key commitment (non-committing ciphertext / "Invisible Salamanders"), header-auth ordering (verify the header tag before decrypting any frame), frame sequence and the final frame, EDK count limits, release of unauthenticated plaintext in streaming, legacy suites and commitment-policy enforcement on decrypt of legacy messages, and data-key confinement inside `esdk`

## Pipeline Stage 1 scope

Source: `.kiro/agents/ai-verification-pipeline.md` §Stage 1, "Establishing Scope and Threat Mindset".

- **System type:** Client-side encryption library (not a managed service)
- **In scope:** SDK cryptographic operations (encrypt/decrypt), message format (header, body, footer), key derivation and key commitment, commitment-policy enforcement at the ESDK boundary, the key-management interfaces the ESDK calls (CMM, keyring) as contracts, and data-key handling inside `esdk`
- **Out of scope:** Underlying KMS security, application business logic, and the internals of the MPL keyrings/CMMs and `aws-lc-rs`, which are treated as trusted dependencies
- **Threat mindset:** Application-level cryptography — local compute, memory management, KMS interaction

Source: `.kiro/agents/ai-verification-pipeline.md` §Stage 1, "Input Sources".

- Standards Documents: RFC 8446, FIPS 140-3, SP 800-56A/B, SP 800-38D (GCM), RFC 5869 (HKDF)
- ESDK Specification (source of truth): `spec/` — the `esdk/.duvet/config.toml` set (`spec/data-format/*`, `spec/client-apis/*`, `spec/framework/transitive-requirements.md`) plus `spec/framework/algorithm-suites.md`
- Duvet Annotations: the inline `//=` / `//#` comments in `esdk/src` and `esdk/tests`. Use them to locate the code that realizes a requirement and whether a test (`type=test`) or implication covers it
- Dependency contracts: the native `mpl/src` and `prim/src` code the ESDK calls (material getters, `aes_encrypt` / `aes_decrypt`, HKDF, ECDSA)
- Source Code: the implementation in `esdk/src` as an implicit specification
- Existing Proofs: the in-crate `verus!` proofs in `esdk/src` and `prim/src` and the standalone models in `verification/` (see `docs/verus-proofs-report.md`). There are no in-repo Dafny proofs

Source: `.kiro/agents/ai-verification-pipeline.md` §Stage 2, "Research Known Vulnerabilities First", the ESDK-specific items.

- Academic literature on primitives used (AES-GCM non-commitment, HKDF misuse, Invisible Salamanders)
- Related vulnerabilities in sibling libraries (S3 Encryption Client, Database Encryption SDK)
