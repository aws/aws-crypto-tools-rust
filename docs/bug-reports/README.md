# Bug reports: MPL native Rust

These nine reports came out of the Verus verification-target analysis of the AWS Cryptographic Material Providers Library (MPL) native Rust implementation (`docs/verification-targets.md`, `docs/verification-targets/01-threat-driven.md`, `docs/verification-targets/02-capability-driven.md`, `docs/threat-model.md`). Each one is a likely defect, or an observation that needs a decision, found while stating provable properties. No code was changed: everything under `mpl/src`, `prim/src` and `esdk/src` is as it is at `HEAD a1e23d7`. The reproducers were temporary, untracked tests. Each report includes its reproducer in full and the output from its saved log, and gives fix options and questions for discussion instead of a chosen fix.

| ID | Title | Component | Severity | Confidence | Spec conflict | Discussion priority |
|---|---|---|---|---|---|---|
| [BUG-01](BUG-01-ttl-duration-overflow-panic.md) | Large accepted TTL / grace / inflight values overflow `SystemTime + Duration` and panic | Hierarchical keyring; StormTracking CMC | Low | Confirmed by test | no | 3 – Medium |
| [BUG-02](BUG-02-plaintext-data-key-length-not-enforced.md) | Plaintext data key length not enforced (hierarchical OnDecrypt and materials constructors) | Hierarchical keyring; materials structures | Medium | Confirmed by test | yes | 1 – High |
| [BUG-03](BUG-03-encryption-context-deserialize-accepts-unsorted.md) | `EncryptionContext::deserialize` accepts entries not sorted by key | `structures::EncryptionContext` | Low | Confirmed by test | yes | 5 – Medium |
| [BUG-04](BUG-04-mrdiscovery-rewrites-non-mrk-arn-region.md) | MRDiscovery rewrites the region of single-Region (non-MRK) KMS key ARNs | Branch key store (KMS ARN resolution) | Low | Confirmed by test | yes | 4 – Medium |
| [BUG-05](BUG-05-keygen-expect-and-short-edk-keystore-lookup.md) | (a) Default CMM panics if ECDSA key generation fails; (b) 44–59-byte hierarchical EDK reaches the keystore | Default CMM; hierarchical keyring | Low | (a) Confirmed by code reading; (b) Confirmed by test, likely not a bug | no | 7 – Low |
| [BUG-06](BUG-06-cache-identifier-not-injective-with-nul.md) | Cache-identifier preimage not injective when fields contain NUL | Hierarchical keyring (cache identifier) | Low | Confirmed by test | yes | 2 – Medium |
| [BUG-07](BUG-07-prim-aes-buffer-handling.md) | `prim::aes_encrypt` leaves plaintext in buffer on `Err`; `aes_decrypt` guard weaker than callee | `aws-mpl-primitives` (AES-GCM) | Low | Confirmed by test | no | 6 – Low |
| [BUG-08](BUG-08-build-base-collision-branch-unreachable.md) | Custom-EC collision `Err` in `build_base` is dead code | Branch key store (encryption context) | Informational | Confirmed by code reading | no | 9 – Low |
| [BUG-09](BUG-09-cache-ttl-check-whole-second-truncation.md) | `cache_entry_within_limits` admits entries up to `ttl + 1 s` | Hierarchical keyring (cache TTL) | Informational | Confirmed by test, likely not a bug | no | 8 – Low |

How to read the table:
- Spec conflict "yes" for BUG-03, BUG-04 and BUG-06 depends on how the spec is read, or on text where the spec contradicts itself. Each report explains which.
- "Likely not a bug" means the behavior was reproduced but matches the Dafny MPL, or has no practical impact.
- Discussion priority is a suggested order (1 = first). It weighs spec deviation, cross-runtime divergence and impact, not just severity.
