# Specification Security Analysis: AWS Cryptographic Material Providers Library (native-Rust MPL)

> Pipeline artifact, Stage 1 (Specification Ingestion). Produced by the `spec-analyzer` agent against `esdk-native-mpl`.
>
> - Code analyzed: `mpl/`, `prim/` (and the MPL-facing parts of `esdk/`) identical to `origin/main` `620771c` (branch `MPL-Verus`, HEAD `eb1ec23`, merge `c256243`).
> - Previous analysis: `a1e23d7`. `a1e23d7` is not an ancestor of `620771c`; "changes since" means `git log a1e23d7..HEAD -- mpl prim` (20 commits).
> - Spec used: the local `spec/` checkout at `e8334535`. See [Spec revision](#spec-revision-and-duvet-status) for why and for the limitation.
> - Every `file:line` below was re-checked against current code. Paths are relative to the repo root.

Scope: key management only. That covers keyrings (`on_encrypt`/`on_decrypt`), CMM materials, branch-key derivation (KBKDF) and wrapping, the key store's record integrity and authenticated encryption context, KMS ARN and MRK matching, algorithm-suite selection and commitment policy, the caches (local, storm-tracking, default), materials-transition checks, and secret lifetime and zeroization. ESDK message-format serialization is out of scope. The C++ shim and ESDK appear only as callers of the MPL.

## Changes since previous analysis (a1e23d7 -> 620771c)

`git diff --stat a1e23d7 HEAD -- mpl prim`: 141 files, +32298 / −8753. Most of the line count is generated error code, test servers and tests. The changes that matter for security:

| # | Change (commit / PR) | Where now | Why it matters for security |
|---|---|---|---|
| 1 | Module and type reshape (#98 `e9bde48`, #137 `21a785c`, #163 `bec2cfe`). `keystore/` → `key_store/`. `BranchKeyStore` → `DynamoDbKeyStore`. `structures` is private; public shapes are re-exported from `types::` | `mpl/src/lib.rs:4-15`, `mpl/src/types.rs:6-24`, `mpl/src/key_store/mod.rs:26-46` | Every old citation moved. The public surface is narrower: internals sit behind `types::` and `__test_internals` (feature `test-utils`, `mpl/src/lib.rs:34-43`) |
| 2 | One method per operation on handles (#137). `SharedKeyring`, `SharedCmm`, `SharedCmc`, `SharedKeyStore`, `SharedBranchKeyIdSupplier` wrap `Arc<dyn Trait>`. Each operation is a fluent builder ending in `send()`. Built-ins implement the trait only through the crate-private `Builtin<T>` wrapper | `mpl/src/shared.rs:62-104`, `:110`; `mpl/src/keyring/fluent_builders.rs:170-195` | Gives one choke point per operation, which is where #3 hooks in. The handle's inner `Arc` is private, so outside callers cannot skip `send()` on a handle or on a built-in |
| 3 | Materials checks on by default (#167 `9646828`). Ported from Dafny `Materials.dfy` | `mpl/src/structures/materials_checks.rs:18,37,72,117,157,177`; run in `keyring/fluent_builders.rs:82`, `:163` and `cmm/fluent_builders.rs:171`, `:319` | New runtime enforcement of C04-class invariants. A keyring may only add a PDK or EDKs. It must not change the suite, EC, required keys or signing/verification key. CMM output must be complete |
| 4 | Pluggable `KeyStore`, `Cmc` and `BranchKeyIdSupplier` traits are public (#137, #98) | `mpl/src/key_store/mod.rs:172`, `mpl/src/cmc/mod.rs:46`, `mpl/src/aws_kms/hierarchical_keyring.rs:187` | New trust boundary. The hierarchical keyring now accepts any key store and any cache. Neither `SharedKeyStore` nor `SharedCmc` checks what they return (`key_store/client_impl.rs:305-308`, `:373-376`) |
| 5 | Zeroize on drop and constant-time compare (#131 `a864ad8`, #158 `daac26c`) | `PlaintextDataKey`, `SigningKey`, `SymmetricSigningKey` derive `Zeroize, ZeroizeOnDrop` (`structures/algorithm_suite.rs:505`, `:571`, `:655`); `ct_eq` at `:541`, `:607`, `:691`. `BranchKeyMaterials` and builder (`structures/branch_key_materials.rs:206-219`). `BeaconKeyMaterials` (`beacon_key_materials.rs:211-235`). Raw AES wrapping key (`keyring/raw_aes_keyring.rs:72-78`, `:234-239`). Derived branch wrapping key `Zeroizing` (`aws_kms/branch_key_wrap.rs:122-143`). Decrypted branch key `Zeroizing` (`key_store/record.rs:99-100`) | Closes most of the previous "secrets not zeroized on drop" trade-off. The `unsafe write_volatile` loop is gone; `mpl/src` and `prim/src` have no `unsafe` blocks |
| 6 | `FORBID_ENCRYPT_ALLOW_DECRYPT` default suite changed to `HKDF_SHA384_ECDSA_P384` (`03 78`) (#153 `72dfdc7`) | `mpl/src/structures/commitment_policy.rs:43-58` (comment `:46-48`) | Deliberate deviation from `commitment-policy.md`, which says the default MUST be `ALG_AES_256_GCM_IV12_TAG16_NO_KDF`. The new default is stronger (KDF + signature). It matches Dafny `Defaults.dfy` |
| 7 | BUG-02, BUG-03, BUG-09 fixed (#98) | PDK length `check_data_key_length` (`structures/algorithm_suite.rs:547`; callers `encryption_materials.rs:60`, `:365`, `decryption_materials.rs:56`, `:303`). EC order check (`structures/encryption_context.rs:145`, `:205`). TTL full-`Duration` compare (`aws_kms/hierarchical_keyring.rs:989`) | Data keys of the wrong length can no longer enter materials. Unsorted EC bytes are rejected. The cache TTL check is exact |
| 8 | Hierarchical keyring TTL is a `Duration`. The default cache is now `DefaultCmc` (storm-tracking, capacity 1000), not a local LRU | `aws_kms/hierarchical_keyring.rs:354`, `:547`, `:567-582`, grace-vs-TTL `:585` | Sub-second TTLs are possible. With the default cache (grace period 10 s, `cmc/storm_tracking.rs:111`) any TTL ≤ 10 s now fails `build()`. There is still no upper bound (BUG-01) |
| 9 | Storm-tracking config validation moved into `StormTrackingCmcBuilder::build` | `mpl/src/cmc/storm_tracking.rs:606-628` (ordering check `:622`) | **Regression against spec.** `build()` now checks only `fan_out ≥ 1`, `in_flight_ttl > 0`, `sleep > 0`, `grace_interval ≤ in_flight_ttl`. It no longer enforces the spec's `Inflight TTL ≤ Grace Period` or `Grace Interval ≤ Grace Period`, or grace period/interval ≥ 1. `test_durations_are_stored_exactly` (`mpl/tests/test_storm_tracking_cmc.rs:388`) accepts `grace_period = 0` with `in_flight_ttl = 30 s`. The previous analysis (and threat model TM-MPL-018) recorded `grace_interval ≤ inflight_ttl ≤ grace_period` as enforced |
| 10 | Raw AES keyring memory for many EDKs (#186 `620771c`) | EDK list attached once to the aggregate error `keyring/raw_aes_keyring.rs:517`; hierarchical `aws_kms/hierarchical_keyring.rs:784`; test `mpl/tests/test_keyring_memory.rs:100`, `:113` | Removes O(n²) memory in the attacker-controlled EDK count. `DataKeyInfo` carries provider id and info, never ciphertext (`structures/encrypted_data_key.rs:147-150`) |
| 11 | Optional SDK features (#136 `18873bc`) | `mpl/Cargo.toml` features `kms`, `ddb`, `default-aws-sdk-clients`, `rt-tokio`, `test-utils`, `aws-lc-sys`, `fips`. Key store modules gated `key_store/mod.rs:26-39`. No-tokio cache path `aws_kms/hierarchical_keyring.rs:575-581`. Client requirement `key_store/branch_key_store.rs:396-414`. ESDK uses `default-features = false` (`esdk/Cargo.toml:19-20`) | Code paths depend on the feature set. Any verification claim must name the feature set it covers. `fips` routes `prim` to AWS-LC FIPS |
| 12 | ESDK and C++ shim retargeted onto the native MPL (#98). `unsafe-unreviewed-mpl/` deleted (`cdd5980`) | ESDK calls the CMM through `SharedCmm` fluent builders (`esdk/src/materials.rs:99`, `:166`). Shim `#[cxx::bridge]` `esdk/shims/aws-esdk-cpp/src/lib.rs:167`; `unsafe` at `:728`, `:1564-1565`, `:1655` | The ESDK always passes through the materials checks. The only `unsafe` code that reaches MPL users is in the shim (raw handle derefs), outside `mpl/` and `prim/` |
| 13 | KMS user agent (#100 `bf03949`) | `mpl/src/aws_kms/user_agent.rs:15-18`, applied on every KMS call in `key_store/kms_ops.rs` | Metadata only. `.expect` on static framework metadata (`user_agent.rs:18`) |
| 14 | Single error model (`Error` + `Kind`) with retry kind, service and resource | `mpl/src/error.rs`, `mpl/src/error/generated.rs` | Errors carry resource ids (branch key id, KMS ARN, table) and SDK sources. The key store reports attribute names and types, never values (`key_store/branch_key_store.rs:1140-1141`) |
| 15 | `prim` error messages and length guards | `prim/src/lib.rs`, `ecdsa.rs:200` (`check_sig_len`), `hkdf.rs` | `aes_decrypt` failure text is now "authentication tag did not match" (`prim/src/lib.rs:229`). BUG-07(a) and (b) unchanged |

Previously reported items that are still open: BUG-01 (`SystemTime + Duration` overflow), BUG-04 (MRDiscovery rewrites non-MRK region), BUG-05a (`.expect` on ECDSA keygen), BUG-05b (44–59-byte EDK reaches the key store), BUG-06 (NUL-joined cache id), BUG-07 (prim AES edge cases) and BUG-08 (dead collision branch). Locations are in [Constraints and Trade-offs](#constraints-and-trade-offs).

## Spec revision and Duvet status

- Since #91 (`6ef7d80`) the spec is not a submodule. `scripts/spec-source.json` sets `url = aws-encryption-sdk-specification.git` and `ref = "master"`. The repo does not pin a revision; it floats on `master`, and `/spec/` is git-ignored.
- Spec used for this analysis: the local `spec/` checkout at `e8334535` ("feat(shim): make key store KMS and DynamoDB clients optional"). Stage 0 also cloned current `master` (`877edcc`, 2026-11-02) read-only into `.agents/tasks/pipeline-rerun-620771c/spec-pinned/`. Under `framework/` the two differ only in `transitive-requirements.md`, an ESDK-level HKDF section. Every MPL-relevant document (`algorithm-suites.md`, `structures.md`, `commitment-policy.md`, `keyring-interface.md`, `raw-aes-keyring.md`, `aws-kms/*`, `cmm-interface.md`, `default-cmm.md`, `cryptographic-materials-cache.md`, `local-…`, `storm-tracking-…`, `branch-key-store.md`) is byte-identical.
- Limitation: because `master` floats, this equivalence holds only as of that fetch. A later spec change will not show up here.
- Duvet: the spec-analyzer definition expects `mpl/.duvet/config.toml`, but that file does not exist. The only Duvet configs are `esdk/.duvet/config.toml` and `esdk/shims/aws-esdk-cpp/.duvet/config.toml`, and neither covers any MPL framework spec. `mpl/src` + `mpl/tests` + `prim/` contain exactly one annotation block: `mpl/src/cmc/entry.rs:201-205` (`cryptographic-materials-cache.md#usage-metadata`, `type=implication`, "Updating usage metadata SHOULD be atomic"). CI checks no MPL requirement. ESDK, by contrast, has about 2100 `//=` lines.
- So the requirement → code map below was built by reading `spec/framework/*.md` and the code. It is not derived from Duvet. The traceability gap is unchanged from the previous run.

## Architecture Overview

```
   ESDK client / C++ shim
        │  SharedCmm::get_encryption_materials().…send()  /  decrypt_materials().…send()
        ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │ SharedCmm fluent send()  ── check_*_materials_complete (output)   │  cmm/fluent_builders.rs:171,:319
   │   └─ DefaultCmm (Builtin)                                         │  cmm/default_cmm.rs
   │       suite + commitment policy; ECDSA keypair; pubkey → EC       │
   │       reproduced-EC merge on decrypt                              │
   └──────────┬────────────────────────────────────────────────────────┘
              │ SharedKeyring::on_encrypt()/on_decrypt().…send()
              ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │ SharedKeyring fluent send() ── check_*_transition(before, after)  │  keyring/fluent_builders.rs:82,:163
   │   ├─ RawAesKeyring (Builtin)  AES-GCM; AAD = serialized EC        │
   │   ├─ HierarchicalKeyring (Builtin)                                │
   │   │     bkid: static | SharedBranchKeyIdSupplier(EC)              │
   │   │     cache_id = SHA-384(0x02‖0‖scope‖0‖partition‖0‖lksn‖0‖bkid[‖0‖ver])
   │   │     ┌─────────────┐ miss ┌──────────────────────────────┐     │
   │   │     │ SharedCmc   │─────▶│ SharedKeyStore               │     │
   │   │     │ DefaultCmc= │      │  └ DynamoDbKeyStore (Builtin)│──► AWS KMS (Decrypt/GDKwoP/ReEncrypt, EC as AAD)
   │   │     │ StormTrack→ │◀─────│     auth-EC binding          │──► Amazon DynamoDB (GetItem/TransactWriteItems)
   │   │     │ LocalCmc    │ put  └──────────────────────────────┘     │
   │   │     └─────────────┘   BranchKeyMaterials (32B key, zeroize-on-drop)
   │   │     branch_key_wrap: KBKDF-CTR-HMAC-SHA256 → 32B (Zeroizing); AES-256-GCM
   │   └─ user Keyring impls (trait)                                   │
   └───────────────────────────────────────────────────────────────────┘
              │ all primitive crypto
              ▼
   aws-mpl-primitives (prim) → aws-lc-rs (aws-lc-sys | fips)
```

Public API shape (current):
- Components are built with SDK-style builders. Required fields go through `required()` (`mpl/src/builder.rs:7`), setters append one item at a time (`grant_tokens`, `encrypted_data_keys`, required EC keys), `set_*` takes an `Option`, `get_*` returns `&Option<_>`. Validation happens in `build()`.
- Each operation is called on a handle as a fluent builder ending in `send()`. Trait implementors write the trait. Callers only see the fluent method (`mpl/src/shared.rs:12-16`).
- Smithy-conformant shapes: `*Input`/`*Output` with builders (`keyring/types.rs`, `cmm/types.rs`, `key_store/shapes.rs`, `cmc/operation.rs`). `key_store::operation::<op>::builders` mirrors the AWS SDK layout (`key_store/mod.rs:64-169`).

## Component Inventory

| Component | File | Role | Security properties |
|---|---|---|---|
| `prim` (`aws-mpl-primitives`) | `prim/src/lib.rs`, `ecdsa.rs`, `hkdf.rs` | The only crypto primitive surface | AES-GCM seal/open (`lib.rs:175`, `:206`), HMAC (`:241`), digest (`:272`), `constant_time_equal` (`:291`), KBKDF (`:313`), CSPRNG `generate_random_bytes` (`:128`), HKDF (`hkdf.rs:46`, `:76`, `:89`, `:101`), ECDSA sign/verify/keygen (`ecdsa.rs:224`, `:253`, `:282`, `:373`). Output-buffer lengths are checked. No `unsafe` (only the lint name at `lib.rs:33`) |
| Shared handles | `mpl/src/shared.rs` | `Arc<dyn Trait>` handle + `IntoShared` | Inner `Arc` is private. Built-ins implement traits only as `Builtin<T>` (`:110`), so the fluent `send()` path is the only external entry |
| `Keyring` trait + `SharedKeyring` | `keyring/mod.rs:150`, `:176-185`; `keyring/fluent_builders.rs` | Wrap/unwrap contract | `send()` runs `check_encryption_transition` / `check_decryption_transition` (`fluent_builders.rs:82`, `:163`) |
| Materials checks | `structures/materials_checks.rs` | Dafny `Materials.dfy` port | Signing suite ⇔ signing/verification key ⇔ `aws-crypto-public-key` in EC (`:18`, `:37`, `:52`). Transition: suite, EC, RECK, signing key (`ct_eq`) and verification key unchanged; PDK added only if absent and unchanged otherwise (`ct_eq`); EDKs only appended, multiset containment (`:72`, `:117`, `:207-216`). CMM output complete (`:157`, `:177`) |
| `RawAesKeyring` | `keyring/raw_aes_keyring.rs` | Local AES-GCM wrapping | `build()` rejects a namespace starting `aws-kms` (`:360`) and a key length ≠ alg (`:370`). Wrapping key zeroized on drop (`:72-78`). EC serialized as AAD before encrypting (`:399-406`). 12-byte random IV (`:146`). Provider-info strict parse (`:191`). Decrypted length = suite key length (`:489`). Errors aggregated, EDK list attached once (`:517`) |
| `HierarchicalKeyring` | `aws_kms/hierarchical_keyring.rs` | Branch-key hierarchy | `build()`: TTL > 0 (`:547`), static bkid XOR supplier (`:554-566`), grace < TTL (`:585`), default `DefaultCmc` capacity 1000 (`:354`, `:567-582`), partition id = 16-byte v4 UUID from `prim` CSPRNG (`:626`), logical name read once from `get_key_store_info` (`:600-605`). `on_encrypt` `:654`, `on_decrypt` `:734` (filters on provider id, UTF-8 provider info, bkid equality `:752-763`), `try_decrypt_edk` `:867`, cache TTL check `:989`, cache-kind check `:1000` |
| `branch_key_wrap` | `aws_kms/branch_key_wrap.rs` | Pure wrap/unwrap | AAD `compute_aad` `:61`. Strict 36-char UUID parse `:92`. KBKDF `derive_branch_key` `:122` returns `Zeroizing<[u8;32]>`. `wrap` `:157`, `unwrap` `:230`, 60-byte minimum `:236` |
| `cache_entry_identifier` | `aws_kms/cache_entry_identifier.rs:35` | Cache id | SHA-384 over NUL-separated fields (`:42-61`). `.expect` on a fixed-length digest (`:64`). File unchanged since `a1e23d7` |
| MRK match | `aws_kms/mrk_match.rs:24` | MRK equality for decrypt | Rejects alias (`:26`). Byte-equal, else region-insensitive MRK compare (`is_multi_region_arn` `:52`) |
| `DefaultCmm` | `cmm/default_cmm.rs` | Suite/policy, signing key, EC merge | Encrypt policy check `:97`. Reserved key refused `:113`. ECDSA keygen `:137-138`. Keyring via fluent `:166-171`. Decrypt policy check `:184`. Merge `:198`, fn `:273`. Non-signing suite with reserved key rejected `:224`. Keyring via fluent `:243-249` |
| `SharedCmm` | `cmm/fluent_builders.rs` | CMM handle | Output completeness checks `:171`, `:319` |
| `KeyStore` trait + `SharedKeyStore` | `key_store/mod.rs:172`; `key_store/client_impl.rs` | Pluggable key store | No output validation in `send()` (`client_impl.rs:117-424`) |
| `DynamoDbKeyStore` | `key_store/branch_key_store.rs` | DDB+KMS key store | `build()` `:373`: `kms_configuration.validate()` `:381`, table name 3–255 `:387-388`, client resolution `:396-414`. Auth EC `:132`. `create_key` `:539` (atomic, `attribute_not_exists`). `version_key` `:641` (ReEncrypt-to-self authentication, optimistic lock `:752`). `get_active_branch_key` `:792`, `get_branch_key_version` `:827`, `get_beacon_key` `:868`. DDB codec `:1089`, `:1141` |
| `kms_ops` | `key_store/kms_ops.rs` | KMS helpers | `build_authenticated_encryption_context` `:49`. `resolve_key_store_arn` `:88` (MrDiscovery arm `:100`). `reject_alias_arn` `:118`. `rewrite_arn_region` `:144`. `decrypt_branch_key` `:162`. EC passed as KMS AAD on Decrypt, GDKwoP and ReEncrypt |
| `kms_config` / `config` | `key_store/kms_config.rs:31`, `:61`, `:86`, `:98`; `key_store/config.rs:12` | ARN parse/validate/compat | Non-`kms` service and alias rejected. MRK-aware compatibility |
| `record` | `key_store/record.rs:95` | Record → materials | Plaintext branch key wrapped in `Zeroizing` (`:99-100`). Strict `type`/`version` checks. Version must be a non-empty suffix |
| `LocalCmc` | `cmc/local.rs` | LRU + TTL | `prune_tail` `:166`, `put_cache_entry` `:280` |
| `StormTrackingCmc` | `cmc/storm_tracking.rs` | Stampede protection | `build()` `:606`. Lock-poison mapped to `Internal` (`state_locked` `:239`). Classification `classify_and_mark` `:264-345`. `wait_for_leader` `:360`. `within_grace_period` `:661`, `within_grace_interval` `:675` |
| `DefaultCmc` | `cmc/default.rs` | Storm-tracking with defaults, capacity required | Delegates to `StormTrackingCmc` (`:98-130`) |
| `CachedMaterials` | `cmc/entry.rs:24-33` | Four kinds: Encryption, Decryption, BranchKey, BeaconKey | Only BranchKey is produced in this crate. No caching CMM exists |
| Structures | `structures/*.rs` | Materials, suites, EC, RECK | Builders enforce RECK ⊆ EC (`encryption_materials.rs:368-377`, `decryption_materials.rs:306-315`), PDK length, key presence per suite, and verification-key length. Secret newtypes are zeroized and redact `Debug` |

## Cryptographic Operations

| Operation | Algorithm | Key material | Purpose |
|---|---|---|---|
| Data-key wrap (raw AES) | AES-128/192/256-GCM, 12-byte random IV, 16-byte tag | Local wrapping key (16/24/32 B, length checked at `build()`) | Wrap PDK. AAD = serialized EC. Provider info = `key_name ‖ u32(128) ‖ u32(12) ‖ iv` (`raw_aes_keyring.rs:129`) |
| Branch-key derivation | KBKDF-CTR-HMAC-SHA256 (SP 800-108 §4.1). Fixed info `"aws-kms-hierarchy" ‖ 0x00 ‖ salt(16) ‖ 0x00000100` | 32-byte branch key (`&[u8;32]`) | One 32-byte `derivedBranchKey` per wrap, wiped on drop (`branch_key_wrap.rs:122-143`) |
| Data-key wrap (hierarchical) | AES-256-GCM, 12-byte random IV, 16-byte tag | `derivedBranchKey` | AAD = `"aws-kms-hierarchy"(17) ‖ bkid ‖ version(16) ‖ serialized EC` (`:61-80`). Wire layout `salt ‖ iv ‖ version ‖ ct ‖ tag` |
| Branch-key protection at rest | KMS `GenerateDataKeyWithoutPlaintext` (32 B), `ReEncrypt`, `Decrypt`, EC as KMS AAD | KMS key (single or discovery) | Store and recover branch and beacon keys (`kms_ops.rs:162`, `:222`, `:260`) |
| Randomness | `aws-lc-rs` CSPRNG via `prim::generate_random_bytes` | n/a | PDK, salt, IV, partition id. Key store branch-key ids and versions use `Uuid::new_v4()` (`branch_key_store.rs:556-557`, `:703`; uuid crate entropy, non-secret) |
| Signing key pair | ECDSA P-256/SHA-256 or P-384/SHA-384. DER private key, SEC1-compressed public key (33/49 B) | Fresh per encrypt | CMM attaches the signing key and puts the base64 public key in the EC |
| Cache id | SHA-384 (48 B) | n/a | Domain-separated key for the cache |
| Secret compare | `aws-lc-rs` `verify_slices_are_equal` | PDK, signing keys | Used by the transition checks (`materials_checks.rs:91`, `:100`) |
| Suite KDF | HKDF-SHA256/384/512 or identity, per suite | n/a | MPL exposes the parameters. Message-level derivation belongs to the ESDK |

The suite table (`structures/algorithm_suite.rs`) covers the 11 ESDK suites. All use AES-GCM with a 12-byte IV and 16-byte tag. The commit-key suites (`04 78`, `05 78`) use HKDF-SHA512. DBE and S3EC suites are intentionally not implemented.

## Key Hierarchy

1. AWS KMS key: the root of trust; it never leaves KMS.
2. Branch key: 32 bytes from KMS `GenerateDataKeyWithoutPlaintext`, stored wrapped in DynamoDB and bound to an authenticated EC. That EC holds `branch-key-id`, `type`, `version`, `create-time`, `kms-arn`, `hierarchy-version`, `tablename` = logical key store name, and `aws-crypto-ec:*` custom pairs. Records: ACTIVE, one `branch:version:<v>` per version, and a beacon record. In memory it is `BranchKeyMaterials`, zeroized on drop, including every cache clone.
3. `derivedBranchKey`: 32 bytes from KBKDF(branch key, 16-byte random salt), one per wrap or unwrap. It is never stored and is wiped on drop.
4. Plaintext data key: random per message (or supplied by the caller), wrapped by `derivedBranchKey` or the raw AES wrapping key. `PlaintextDataKey` is zeroized on drop.

Rotation guidance (spec Appendix B) is unchanged: the 16-byte salt keeps AES-GCM key/IV reuse negligible, and annual rotation is recommended.

## Trust Boundaries

| Boundary | From | To | Data crossing |
|---|---|---|---|
| Client → CMM/keyring | Untrusted request, or message fields parsed by the ESDK | In-process MPL | EC, suite id, commitment policy, reproduced EC, EDK list (count, provider id, info and ciphertext all attacker-controlled on decrypt), caller PDK |
| MPL → user-supplied components (new) | MPL | User `Keyring`, `Cmm`, `Cmc`, `KeyStore`, `BranchKeyIdSupplier` | Materials, cache ids and entries, branch key ids. Keyring and CMM output is checked by `send()`. Key store, cache and supplier output is not |
| MPL → AWS KMS | In-process | KMS | Wrapped blob, EC as AAD, grant tokens, key ARN, user agent. Plaintext branch key comes back |
| MPL → DynamoDB | In-process | DDB | Branch-key items (attributes + `enc`). Records come back (tamper-evident only through the KMS AAD) |
| Keyring ↔ cache | In-process | In-process, possibly shared across keyrings | `BranchKeyMaterials` (plaintext 32-byte key) for the TTL. Cache-id domain separation is the isolation control |
| MPL → `prim` → aws-lc | Safe Rust | FFI (aws-lc-sys or FIPS) | Keys, plaintexts, IVs, AAD |
| C++ → shim → MPL (new) | C++ caller | Rust | Raw handle pointers (null-checked, `unsafe` deref at `esdk/shims/aws-esdk-cpp/src/lib.rs:720-728`), optional KMS/DDB clients and cache (`:1564-1565`, `:1655`) |

The most security-relevant boundary is still the keyring ↔ cache one. The cache may be shared, and with #4 it may now be a user implementation. Isolation then depends on (a) partition id and logical key store name in the cache id, and (b) the cache returning only what was put under that id. Only the material kind is checked (`as_branch_key_materials`, `hierarchical_keyring.rs:1000`).

## Data Flows

Encrypt (ESDK → DefaultCmm → hierarchical):
1. The ESDK calls `SharedCmm::get_encryption_materials().…send()` (`esdk/src/materials.rs:166`).
2. The CMM resolves the suite: the policy default (`commitment_policy.rs:43`), or the request's suite checked with `allows_for_encrypt` (`default_cmm.rs:97`). It refuses an EC that already holds `aws-crypto-public-key` (`:113`). For signing suites it generates an ECDSA key pair (`:137-138`, `.expect`) and inserts the base64 public key.
3. Empty `EncryptionMaterials` are built (RECK ⊆ EC enforced) and passed to `SharedKeyring::on_encrypt().send()` (`:166-171`).
4. Keyring: resolves the bkid (static or supplier with the EC), generates a PDK if none is present (`hierarchical_keyring.rs:975`), computes the encrypt-scope cache id (`:665`) and gets an entry from the cache. It uses the entry if `elapsed ≤ ttl` (`:989`). Otherwise it calls `get_active_branch_key` (`:692`), puts `expiry = now + ttl` (`:702`, BUG-01) and wraps.
5. Wrap: fresh salt and IV → KBKDF → AES-256-GCM with AAD built from **bkm's** bkid and version plus the EC. EDK = { `"aws-kms-hierarchy"`, provider info = **resolved** bkid (`:722`), ciphertext }.
6. `send()` runs `check_encryption_transition` (`fluent_builders.rs:82`). The CMM `send()` then runs `check_encryption_materials_complete` (`cmm/fluent_builders.rs:171`).

Decrypt:
1. The ESDK calls `SharedCmm::decrypt_materials().…send()` (`esdk/src/materials.rs:99`).
2. The CMM checks `allows_for_decrypt` (`default_cmm.rs:184`) and merges the reproduced EC (`:198`, `:273`). A mismatch is `EncryptionContextMismatch`. Reproduced-only keys are appended and become RECK. For signing suites it decodes the verification key from the merged EC. For non-signing suites the reserved key is rejected (`:224`).
3. Keyring `on_decrypt` (`hierarchical_keyring.rs:734`) refuses materials that already hold a PDK. It skips EDKs whose provider id is not the hierarchy id, whose provider info is not UTF-8, or whose bkid differs from the resolved one (`:752-763`).
4. `try_decrypt_edk` (`:867`): needs ≥ 44 bytes (`:879`) and reads the version at offset 28. Decrypt-scope cache id (`:908`). On a miss: `get_branch_key_version` (`:934`), put (`:945`). `unwrap` needs ≥ 60 bytes (`branch_key_wrap.rs:236`), re-derives the key and rebuilds the AAD from bkm and the decryption EC.
5. The first success adds the PDK (length checked). If nothing matched, `NoMatchingDataKey` carries the EDK list (`:784`). If attempts failed, `all_failed` aggregates (`:798`).
6. `check_decryption_transition` (`fluent_builders.rs:163`), then `check_decryption_materials_complete` (`cmm/fluent_builders.rs:319`).

Key store reads (`DynamoDbKeyStore`): GetItem by `(branch-key-id, type)` → `resolve_key_store_arn` (config-compatible ARN; Discovery uses the record ARN with alias rejected; MrDiscovery rewrites the region, BUG-04) → KMS Decrypt with the auth EC (record attributes + `tablename`) → `branch_key_materials_from_authenticated_encryption_context` (`record.rs:95`).

CreateKey / VersionKey: these need a single-key config (`branch_key_store.rs:112`). CreateKey writes DECRYPT_ONLY, ACTIVE (ReEncrypt from DECRYPT_ONLY) and beacon in one transaction with `attribute_not_exists`. VersionKey authenticates ACTIVE by ReEncrypt-to-self with the rebuilt EC (`InvalidCiphertextException` → `Cryptographic`). It then writes the new version and overwrites ACTIVE under `#enc = :encOld` (`:752`).

## Security Configuration Options

| Option | Default | Impact |
|---|---|---|
| Commitment policy | Per request (CMM input) | Gates encrypt and decrypt suites. `FORBID_ENCRYPT_ALLOW_DECRYPT` default suite is now `03 78` (spec says `00 14`). The other two policies default to `05 78` |
| Algorithm suite | Policy default | Key size, KDF, signing, commitment |
| `RawAesKeyringBuilder` | All four fields required | Key length must match `AesWrappingAlg`. Namespace must not start with `aws-kms` |
| `ttl` (hierarchical) | Required, `Duration` > 0, no upper bound | Plaintext branch-key residency in the cache. Huge values panic (BUG-01). Must be > the cache's grace period |
| `cache` (hierarchical) | `DefaultCmc` (storm-tracking, capacity 1000, grace period 10 s) with `rt-tokio`; required without it | A shared or user cache spans keyrings and relies on cache-id separation and on the cache behaving honestly |
| `partition_id` | 16-byte v4 UUID from `prim` CSPRNG | Caller strings are used as raw UTF-8 bytes. Strings containing NUL can collide (BUG-06) |
| `key_store` | Required, any `SharedKeyStore` | Its `logical_key_store_name` feeds the cache id. A user key store controls it |
| `KmsConfiguration` | Required | `KmsKeyArn` (byte-equal), `KmsMrKeyArn` (MRK match), `Discovery` (record ARN, no alias), `MrDiscovery` (record ARN with region rewritten, BUG-04) |
| `kms_client` / `ddb_client` | Built from default AWS config with `default-aws-sdk-clients`, else required | Credential and region source |
| Storm-tracking knobs | grace period 10 s, grace interval 1 s, fan-out 20, in-flight TTL 10 s (spec 20 s), sleep 20 ms (`storm_tracking.rs:109-121`) | `build()` no longer enforces the spec's ordering (change #9) |
| Cargo features | `aws-lc-sys, kms, ddb, default-aws-sdk-clients, rt-tokio` | `fips` switches the crypto backend. Without `kms`+`ddb` there is no built-in key store. Without `rt-tokio` there is no storm-tracking or default cache |

## Security Invariants

Spec text is quoted from the local `spec/framework` at `e8334535`. Status is based on reading the current code. Duvet coverage is "none" for every row except where noted.

Keyrings:
- Raw AES: "MUST use the serialized encryption context as the additional authenticated data (AAD)". Enforced (`raw_aes_keyring.rs:403-406`, `:436-439`).
- Raw AES: "MUST NOT accept a key namespace of 'aws-kms'". Enforced as a prefix check (`:360`).
- Raw AES OnDecrypt: an existing PDK means it "MUST fail and MUST NOT modify"; "If no decryption succeeds, the keyring MUST fail". Enforced (`:427-433`, `:526-529`).
- Hierarchical wrap: 16-byte random salt, 12-byte random IV, KBKDF-CTR-HMAC-SHA256 → 32 bytes, AES-256-GCM, 16-byte tag, AAD as specified. Enforced (`branch_key_wrap.rs:157-218`).
- Hierarchical EDK: provider id "MUST be UTF8 Encoded `aws-kms-hierarchy`". Provider info "MUST be the UTF8 Encoded AWS DDB response `branch-key-id`". **Partial:** the code writes the *resolved* bkid (`hierarchical_keyring.rs:722`), not `bkm.branch_key_id()`. The two are equal for `DynamoDbKeyStore`. A user key store that returns another key's materials would make the EDK undecryptable rather than mis-attributed.
- Hierarchical cache: "MUST use the formulas specified in Appendix A". Implemented (`cache_entry_identifier.rs:35`). Not injective when a field contains NUL (BUG-06).
- Hierarchical cache: `time.now() - cacheEntryCreationTime <= ttlSeconds`, else "MUST treat the cache entry as expired". Enforced (`:989`, BUG-09 fixed).
- Hierarchical init: "The Grace Period MUST be less than the cache limit TTL" (`:585`). TTL "MUST be greater than zero" (`:547`). "If no `cache` is provided, a `DefaultCache` MUST be configured with entry capacity of 1000" (`:354`, `:568-575`). Partition id "MUST be set to the 16 byte representation of a v4 UUID" (`:626`).
- Hierarchical OnDecrypt: "MUST yield an error that includes all the collected errors". Enforced (`:798`).
- Keyring interface, as enforced by `send()` and stricter than the spec text (Dafny-derived): a keyring may only add a PDK or EDKs. The spec is weak here, which is why the check was ported from Dafny (`materials_checks.rs:5`).

CMM / commitment policy:
- `allows_for_encrypt` / `allows_for_decrypt` match the `commitment-policy.md` tables (`commitment_policy.rs:62`, `:77`).
- Default suite: **deviation** for `FORBID_ENCRYPT_ALLOW_DECRYPT` (`03 78` instead of the spec's `00 14`; documented at `:46-48`). The other two policies meet "`05 78` MUST be the default".
- Reproduced EC: shared keys MUST agree, and reproduced-only pairs are appended as RECK (`default_cmm.rs:273-303`).
- Materials: RECK ⊆ EC; EDKs empty without a PDK; signing/verification keys present iff the suite signs; verification-key length matches the suite; PDK length = suite key length (new). Enforced in the builders and in `add_data_key`.
- CMM output: GetEncryptionMaterials output has a PDK and ≥ 1 EDK; DecryptMaterials output has a PDK. Enforced by `SharedCmm::send()`.

Key store:
- KMS Decrypt/ReEncrypt/GDKwoP MUST bind the authenticated EC (all attributes except `enc`, plus `tablename`). Enforced (`kms_ops.rs:49`, `:185`, `branch_key_store.rs:132`).
- The branch key MUST be 32 bytes, and `type`/`version` are validated strictly (`record.rs:95` and following).
- The config ARN MUST be `kms` and MUST NOT be an alias (`kms_config.rs:61`, `:98`). The record ARN MUST be compatible (`kms_ops.rs:105-113`). Discovery MUST reject alias record ARNs (`:96-99`). MrDiscovery rewrites the region without an MRK check (BUG-04).
- VersionKey authenticates ACTIVE before rotating, with an optimistic lock (`branch_key_store.rs:641`, `:752`).

Caches:
- Storm tracking "Grace Interval MUST be ≤ Grace Period", "Inflight TTL MUST be ≤ Grace Period", "Grace Interval MUST be ≤ Inflight TTL", and grace period / grace interval "at least 1". **Only the third is enforced** (`storm_tracking.rs:622`). The spec's default in-flight TTL of 20 s is deliberately replaced by 10 s (`:117-119`).
- Storm-tracking behaviors (within grace period/interval formulas, fan-out, in-flight TTL failure, PutCacheEntry clears in-flight) are implemented (`:264-345`, `:661`, `:675`, `:710`).
- "Updating usage metadata SHOULD be atomic": implemented under one lock (`entry.rs:201-206`, the only Duvet annotation).

Primitives:
- KBKDF/HMAC/digest/AES/ECDSA output-buffer lengths are checked and return errors, not panics (`prim/src/lib.rs:241-260`, `:272-285`; `ecdsa.rs:200`).

## Constraints and Trade-offs

- **Duvet gap unchanged.** There is no MPL Duvet config and one annotation in the whole crate, so all MUSTs above are traced by hand.
- **Materials checks cover only the fluent path.** Every built-in and ESDK path goes through `send()`. A user's own `Keyring`/`Cmm` called directly through its trait by the user's code skips the checks; that is the user's choice and does not cross an MPL boundary. The checks do not re-validate PDK length (the builder does) or bind EDK content to the keyring.
- **User key stores and caches are trusted.** `SharedKeyStore` and `SharedCmc` pass results through unchecked. A key store controls `logical_key_store_name` (cache-id separation) and the returned `BranchKeyMaterials` (bkid/version are not compared with the request). A cache controls which entry comes back for an id. Only the material kind is checked. Integrity of wrapped data keys still rests on the AAD binding, so lying here causes failures or wrong-key wraps, not silent plaintext disclosure, unless the attacker also controls the materials.
- **Storm-tracking config regression** (change #9). Bad settings (grace period 0, in-flight TTL > grace period) are accepted. The impact is availability and caching efficiency, not confidentiality. Also check that any verification target written against the old `from_raw` contract is updated.
- **Secret lifetime, improved but not total.** Still not zeroized: the `Vec<u8>` returned by `branch_key_wrap::unwrap` until it is wrapped in `PlaintextDataKey`; the raw AES decrypt buffer on the error and wrong-length paths (`raw_aes_keyring.rs:471`, `:489-495`); the KMS SDK response `Blob` before `Zeroizing` takes over (`kms_ops.rs:199-208`); and `Vec` reallocations. The cache still holds plaintext branch keys for the whole TTL (by design).
- **Panics remaining in non-test code**: `default_cmm.rs:123`, `:137-138` (BUG-05a); `user_agent.rs:18`; fixed-size `try_into().expect` (`branch_key_wrap.rs:249`, `:252`, `:256`, `hierarchical_keyring.rs:892`, unreachable after length checks); `cache_entry_identifier.rs:64`; `SystemTime + Duration` at `hierarchical_keyring.rs:702`, `:945`, `storm_tracking.rs:333`, `:680` (BUG-01, reachable with large configured durations).
- **Open bug locations**: BUG-04 `key_store/kms_ops.rs:100`, `:144`. BUG-05b `hierarchical_keyring.rs:879` vs `branch_key_wrap.rs:236`. BUG-06 `cache_entry_identifier.rs:42-61`. BUG-07a `prim/src/lib.rs:185-187` (plaintext copied into the output before key/nonce validation). BUG-07b `:215` vs `:228`. BUG-08 `key_store/encryption_context.rs:91`, `:95`.
- **Spec deviations** (documented in code): FORBID default suite; storm in-flight TTL default; hierarchical EDK provider info from the resolved bkid; table-name length check (not in the spec, `branch_key_store.rs:384-388`).
- **Feature-dependent behavior**: verification must name the feature set. ESDK builds the MPL with `default-features = false` and re-enables features through its own.
- **CVE context (CVE-2026-6550 / GHSA-v638-38fc-rhfv, ESDK Python)**: a shared caching CMM served non-committing materials across commitment policies. This crate has no caching CMM (`mpl/src/cmm/` = `default_cmm.rs`, `fluent_builders.rs`, `mod.rs`, `types.rs`), but `CachedMaterials::Encryption`/`Decryption` exist (`cmc/entry.rs:26`, `:28`). A future caching CMM must bind the commitment policy (or suite) into its cache id. The hierarchical keyring caches only branch keys, which do not depend on the policy.
- **Spec silent / ambiguous areas**: what a keyring must verify about key store output; storm-tracking behavior with zero durations; whether `EncryptionContext::from_bytes` must reject empty keys (`test_deserialize_accepts_empty_key_length_currently_unenforced`, `mpl/tests/test_encryption_context.rs:468`); and the on-wire branch-key version being authenticated only through AAD and KDF.

## Concise Summary (for threat modeling and verification recommendation)

Key components: `prim` (crypto choke point), the shared-handle layer with materials checks, `RawAesKeyring`, `HierarchicalKeyring` + `branch_key_wrap`, `DefaultCmm`, `DynamoDbKeyStore` + `kms_ops`/`record`, and `LocalCmc`/`StormTrackingCmc`/`DefaultCmc`.

Trust boundaries: client → CMM (untrusted EC/suite/EDKs, now including EDK-count memory), MPL → KMS/DDB, keyring ↔ cache (plaintext branch key for the TTL, shared or user-supplied), MPL → user components (new), and C++ → shim (new, raw handles).

Most security-critical invariants to verify:
1. Hierarchical AAD `"aws-kms-hierarchy" ‖ bkid ‖ version(16) ‖ EC` and KBKDF fixed info `label ‖ 0x00 ‖ salt ‖ 0x00000100`.
2. Key store auth-EC binding on every KMS call, 32-byte branch key, VersionKey authentication + optimistic lock, and ARN/MRK resolution (BUG-04 open).
3. Cache-id injectivity and domain separation (BUG-06 open), now also under user-supplied key stores and caches.
4. Materials transition checks: `send()` accepts a keyring result iff it only adds a PDK/EDKs. Commitment-policy gating, with the documented FORBID default deviation.
5. Storm-tracking config consistency (regressed) and the state machine.
6. Secret lifetime: zeroize-on-drop now covers PDK, signing keys, branch/beacon keys, wrapping keys and the derived key. Remaining gaps are listed above.
7. `prim` length checks and the absence of panics (BUG-01, BUG-05a, BUG-07).
