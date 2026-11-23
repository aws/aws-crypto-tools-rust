# Sweep 2 (code-surface sweep): site → threat / target matrix

Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `4807e6a` (working tree clean apart from `.agents/tasks/audit-light/`). Documentation only; nothing under `mpl/`, `prim/`, `esdk/` or `docs/` was touched and nothing was committed.

## How this was produced

- Scope: every `*.rs` under `mpl/src` and `prim/src`, plus `esdk/shims/aws-esdk-cpp/src/lib.rs` and `src/EncryptionSDK.cpp` (for `unsafe` / FFI only).
- Test code excluded: `mpl/src/error.rs` from line 460 (`#[cfg(all(test, feature = "kms"))] mod tests`), `mpl/src/error/generated.rs` from 3423, `prim/src/error/generated.rs` from 988, and the shim's `tests.rs` (declared `#[cfg(test)] mod tests;` at `lib.rs:2068-2069`). No other `cfg(test)` region exists in the scanned files. The storm-tracking `.expect`s at `storm_tracking.rs:199`, `:213`, `:227` are `#[cfg(feature = "test-utils")]` accessors; they are listed but marked test-only.
- Scripts (in this directory): `sweep2_scan.sh <panic|index|arith|copy|ext|secret|err|loop>` greps the non-test code and prints `LABEL<TAB>file:line<TAB>text`. `sweep2_cov.sh <ERE>...` counts hits in the five audited documents (threat model, verification-targets index, 01, 02, spec-security-analysis). Every `file:line` below came out of `sweep2_scan.sh` or a `sed -n` / `grep -n` read in this sweep.
- Raw scan sizes (non-test, before hand filtering): panic 14, index 44, arith 39 non-generated (36 more in `error/generated.rs`, all trait bounds), copy 22, ext 69 (incl. `use`/type lines), secret 154, err 92 (`format!` sites), loop 56.
- Hand filtering removed false positives: trait bounds (`Send + Sync`), `const` definitions, string literals, `format_description!` at `branch_key_store.rs:1077`, generated error types, and `use` lines.
- Known items not reported as findings (per the brief): stale T25, T21, T26 and the missing TM-MPL-025 target. Rows that touch them are mapped to those IDs.

Legend: **M** = mapped (threat and/or target, or an explicit exclusion row in the target docs). **U** = unmapped (no threat or target names it). `T16` etc. are VR-2026 ids.

## 1. Public entry points that accept untrusted input

| # | Site | Untrusted input | Threat | Target | Status |
|---|---|---|---|---|---|
| E1 | `HierarchicalKeyring::on_decrypt` `aws_kms/hierarchical_keyring.rs:734` (EDK loop `:751`) | EDK list, message EC | TM-003, 023, 025 | T19, T16 (025: known, no target) | M |
| E2 | `try_decrypt_edk` `hierarchical_keyring.rs:867` (guard `:879`, slice `:890`) | EDK ciphertext version bytes | TM-023, 025 | T16, T19 | M |
| E3 | `decrypt_edk_at_version` `hierarchical_keyring.rs:901` | sender-chosen version → cache id / key-store read | TM-009, 010, 025 | T13, T14, T19 | M |
| E4 | `resolve_branch_key_id` `hierarchical_keyring.rs:831` | message EC to `BranchKeyIdSupplier` | TM-003 | T19 | M |
| E5 | `RawAesKeyring::on_decrypt` `keyring/raw_aes_keyring.rs:422` (loop `:448`) | EDK list | TM-001, 011, 023 | T20, T16, T07 | M |
| E6 | `decryptable_edk_iv` `raw_aes_keyring.rs:191` (`:198`, `:201-214`) | provider id / info | TM-001, 023 | T20, T16 | M |
| E7 | `DefaultCmm::decrypt_materials` `cmm/default_cmm.rs:177` (policy gate `:184`, merge `:273-303`) | message EC, suite id, reproduced EC | TM-006, 008, 017 | T09, T12 | M |
| E8 | `DefaultCmm::get_encryption_materials` `default_cmm.rs:85` (reserved key `:113`) | caller EC, requested suite | TM-006 | T09, C07 | M |
| E9 | `EncryptionContext::from_bytes` `structures/encryption_context.rs:145` | serialized EC bytes | TM-013, 017, 023 | T15, T16 | M |
| E10 | `TryFrom<BTreeMap<Vec<u8>,Vec<u8>>> for EncryptionContext` `encryption_context.rs:246` | raw EC bytes (UTF-8 check) | TM-013 | T15 (codec family) | M |
| E11 | `aws_kms_mrk_match_for_decrypt` `aws_kms/mrk_match.rs:24` | record / EDK ARNs | TM-004 | T11, T16 | M |
| E12 | `parse_arn` `key_store/kms_config.rs:31` | record `kms-arn` | TM-007 | T17 | M |
| E13 | `is_arn_compatible` `kms_config.rs:86` | record `kms-arn` | TM-004 | T11 | M |
| E14 | `resolve_key_store_arn` `key_store/kms_ops.rs:88` (`:105`) | record `kms-arn` | TM-002, 007 | T03, T17 | M |
| E15 | `decrypt_branch_key` `kms_ops.rs:162` | DDB record attributes + `enc` | TM-002, 005 | T03, T01 | M |
| E16 | `record_from_ddb_item` `key_store/branch_key_store.rs:1141` (loop `:1166`) | DDB item | TM-005 | T01 | M |
| E17 | `branch_key_materials_from_authenticated_encryption_context` `key_store/record.rs:95` (`:164`) | authenticated EC, KMS plaintext | TM-005 | T02 | M |
| E18 | `get_beacon_key` `branch_key_store.rs:868` | DDB beacon record, KMS plaintext | TM-005, 002 | T01 (auth EC at `:868`) | M (length: see findings N3) |
| E19 | `version_key` `branch_key_store.rs:641` (`:692`, `:719`, `:768`) | ACTIVE record from DDB | TM-016 | T18, T03, T16 | M |
| E20 | `build_cache_identifier` `aws_kms/cache_entry_identifier.rs:35` | partition id, logical name, bkid, version | TM-009, 010 | T13 | M |
| E21 | `Cmc` impls: `LocalCmc` `cmc/local.rs:280`, `:302`, `:311`, `:326`; `StormTrackingCmc` `cmc/storm_tracking.rs:710`, `:729`, `:750`, `:757` | cache ids | TM-010, 018, 022 | T23, T21, C08 | M |
| E22 | `branch_key_wrap::unwrap` `aws_kms/branch_key_wrap.rs:230` (guard `:236`) | EDK ciphertext | TM-013, 023 | T10, T16 | M |
| E23 | Shim handles: `require_handle` `esdk/shims/aws-esdk-cpp/src/lib.rs:715` (`unsafe` `:728`); nullable `as_ref` `:1570`, `:1571`, `:1661`; C++ `Keyring::adopt` `src/EncryptionSDK.cpp:541-547` | C++ raw pointers | TM-024 | T25 (adopt not in T25: known stale) | M |
| E24 | `prim::ecdsa_verify` `prim/src/ecdsa.rs:282`, `ecdsa_verify_context` `:305` | message signature, verification key | TM-023 | C02, C03 | M |
| E25 | `prim::aes_decrypt` `prim/src/lib.rs:206` | ciphertext, tag | TM-023 | C03, T07 | M |

## 2. Panic-capable sites

### 2a. `.expect()` / `.unwrap()` / `panic!` family (14)

| Site | Why it cannot / can fire | Threat | Target | Status |
|---|---|---|---|---|
| `branch_key_wrap.rs:249`, `:252`, `:256` | exact-length `try_into` after guard `:236` | TM-023 | T16 | M |
| `hierarchical_keyring.rs:892` | 16-byte `try_into` after guard `:879` | TM-023 | T16 | M |
| `cache_entry_identifier.rs:64` | digest into exact-size buffer | TM-023 | T16 | M |
| `aws_kms/user_agent.rs:17` | constant framework metadata | TM-023 | T16 | M |
| `default_cmm.rs:123` | `has_asymmetric_signing()` ⇒ `Some` | TM-023 | T16, C05 | M |
| `default_cmm.rs:138` | ECDSA keygen `.expect` (BUG-05a) | TM-023 | T16 (expected-unprovable) | M |
| `storm_tracking.rs:199`, `:213`, `:227` | `test-utils` accessors only | — | T16 rationale excludes them | M (excluded) |
| shim `lib.rs:164` | Tokio runtime build `.unwrap()` (OS thread failure) | — | — | U |
| shim `lib.rs:1086` | constant framework metadata `.expect` | — | — | U |
| shim `lib.rs:1716` | `ChannelReader` mutex poisoned `.expect` | — | — | U |

### 2b. Unchecked indexing / slicing (43 after removing `branch_key_store.rs:1077`)

| Site | Guard | Threat | Target | Status |
|---|---|---|---|---|
| `branch_key_wrap.rs:247`, `:250`, `:254`, `:259`, `:260` | `len >= 60` at `:236` | TM-023 | T16 | M |
| `mrk_match.rs:40`, `:41`, `:43`, `:44`, `:45` | `is_multi_region_arn` ⇒ 6 segments | TM-004, 023 | T16, T11 | M |
| `mrk_match.rs:55-57`, `:65-67` (6) | `segments.len() == 6 &&` short-circuit | TM-004 | T11, T16 | M |
| `branch_key_store.rs:719` | `BTreeMap` index on `ATTR_TYPE` | TM-016, 023 | T16, T18 | M |
| `kms_config.rs:33`, `:41`, `:46`, `:51`, `:52`, `:53`, `:54` | `segments.len() != 6 ||` at `:33` | TM-007 | T17 (`parse_arn`) | M |
| `algorithm_suite.rs:118-128` (11) | constant index into 11-entry `ALL_SUITES` | TM-006 | C05 | M |
| `encryption_context.rs:154`, `:172`, `:179`, `:188`, `:195` | `len < 2`, `offset + 2 > len`, `end > len` | TM-013, 023 | T16, T15 | M |
| `prim/src/hkdf.rs:84` | `sz = default_salt_size(alg) <= MAX_SALT_SIZE` | TM-023 | C03 | M |
| `prim/src/lib.rs:186` | `old_size` is the pre-extend length | TM-023 | C03 | M |
| shim `lib.rs:1729` | `n = min(buf.len(), pending.len() - offset)` | — | — | U |

### 2c. Unchecked arithmetic (31 relevant)

| Site | Note | Threat | Target | Status |
|---|---|---|---|---|
| `branch_key_wrap.rs:71`, `:127`, `:193` (saturating) | capacity sums of small lengths | TM-013, 012 | T10, T04 | M |
| `branch_key_wrap.rs:210-211` | inside `debug_assert_eq!` (debug only) | TM-012 | T04 | M |
| `branch_key_wrap.rs:250`, `:253`, `:254`, `:257`, `:258` | constants; `len - 16` after guard | TM-023 | T16 | M |
| `hierarchical_keyring.rs:879`, `:885`, `:890` | constants | TM-023 | T16 | M |
| `hierarchical_keyring.rs:702`, `:945` | `SystemTime + ttl` (BUG-01 a/d) | TM-018, 022, 023 | T06 | M |
| `storm_tracking.rs:333`, `:680` | `SystemTime + Duration` under lock (BUG-01 b/c) | TM-018, 023 | T06 | M |
| `raw_aes_keyring.rs:136`, `:198` | sums of small lengths | TM-023 | T20 | M |
| `raw_aes_keyring.rs:469` | `len - 16` after `< TAG_LENGTH` check at `:460` | TM-023 | T16 | M |
| `encryption_context.rs:166`, `:172`, `:173`, `:175`, `:182`, `:188`, `:189`, `:191`, `:220` | `usize` offsets ≤ len + 2 | TM-023 | T16 (`:166-197`), T15 | M |
| shim `lib.rs:1728`, `:1729`, `:1730` | `pending.len() - offset` under loop guard `:1715` | — | — | U |

Checked separately and safe by construction: `storm_tracking.rs:253` (`duration_since(..).map_or(true, ..)`, TM threat-model F5), `:320` (`unwrap_or(ZERO)`), `:667` (`checked_sub`), `hierarchical_keyring.rs:992` (`unwrap_or(ZERO)`, TM F4 / T14), `cmc/entry.rs:213-214` (`checked_add`, C08). No `as` integer casts exist in the scanned code. `EncryptionContext::to_bytes` uses `u16::try_from` (`encryption_context.rs:100`, `:112`, `:124`).

### 2d. `copy_from_slice` / `try_into` / `split_at` / `from_be_bytes` (22)

| Site | Threat | Target | Status |
|---|---|---|---|
| `branch_key_wrap.rs:248`, `:251`, `:255`; `hierarchical_keyring.rs:891` | TM-023 | T16 | M |
| `record.rs:164` (`<[u8;32]>::try_from`, `else` branch) | TM-005 | T02 | M |
| `raw_aes_keyring.rs:201`, `:206`, `:207`, `:208`, `:212`, `:213`, `:214` (after length check `:198`) | TM-023, 001 | T16, T20 | M |
| `raw_aes_keyring.rs:469` | TM-023 | T16 | M |
| `encryption_context.rs:154`, `:172`, `:188` | TM-023 | T16 | M |
| `prim/src/ecdsa.rs:90`, `:188` | TM-023 | C02, C03 | M |
| `prim/src/lib.rs:260`, `:285` | TM-023 | C03 | M |
| shim `lib.rs:782` (`u16::from_be_bytes` on a `[u8;2]`) | — | — | U |
| shim `lib.rs:1729` (dup of 2b) | — | — | U |

## 3. External calls

| # | Site | Call | Threat | Target | Status |
|---|---|---|---|---|---|
| X1 | `branch_key_store.rs:155` | DDB `GetItem` (`fetch_record`) | TM-005, 025 | T01 | M |
| X2 | `branch_key_store.rs:464`, `:506` | DDB `DescribeTable`, `CreateTable` (`create_key_store`) | — | — | U |
| X3 | `branch_key_store.rs:612` (condition `:604`) | DDB `TransactWriteItems` (CreateKey) | TM-016 | T18, C01 | M |
| X4 | `branch_key_store.rs:768` (conditions `:743`, `:752`) | DDB `TransactWriteItems` (VersionKey) | TM-016 | T18 | M |
| X5 | `kms_ops.rs:182` | KMS `Decrypt` | TM-002, 007 | T03, T17, T01 | M |
| X6 | `kms_ops.rs:229` | KMS `GenerateDataKeyWithoutPlaintext` | TM-002, 016 | T18 (EC), T01 | M |
| X7 | `kms_ops.rs:269` | KMS `ReEncrypt` | TM-016, 002 | T18, T03 | M |
| X8 | `prim/src/lib.rs:187-196`, `:223-232` | aws-lc-rs AES-GCM | TM-011, 012 | C03, T07, T04 | M |
| X9 | `prim/src/lib.rs:241-260`, `:272-285` | aws-lc-rs HMAC, digest | TM-009, 014 | C03 | M |
| X10 | `prim/src/lib.rs:313-326` | aws-lc-rs KBKDF-CTR-HMAC | TM-014 | T05, C03 | M |
| X11 | `prim/src/hkdf.rs:46-110` | aws-lc-rs HKDF | (ESDK consumer) | C03 | M |
| X12 | `prim/src/ecdsa.rs:231`, `:260`, `:374` | aws-lc-rs ECDSA sign / keygen | TM-023, 015 | C02, T16, T26 | M |
| X13 | `prim/src/lib.rs:129` | aws-lc-rs `rand::fill` | TM-011, 012 | excluded (R3, probabilistic) | M |
| X14 | `prim/src/lib.rs:292` | aws-lc-rs `constant_time` | — | excluded (R2) | M |
| X15 | `branch_key_store.rs:415`, `:556`, `:557`, `:703` | `uuid::Uuid::new_v4()` | none (TM line 473 notes "not secret") | — | U |
| X16 | shim `lib.rs:1292`, `:1334` | ESDK `encrypt` / `decrypt` | — (ESDK) | — | U |

## 4. Secret material created, held, copied or logged

| # | Site | What | Threat | Target | Status |
|---|---|---|---|---|---|
| S1 | `algorithm_suite.rs:505` | `PlaintextDataKey` (`Clone, Zeroize, ZeroizeOnDrop`) | TM-015 | R11 (by design), C04 | M |
| S2 | `algorithm_suite.rs:571`, `:655` | `SigningKey`, `SymmetricSigningKey` | TM-015 | R11 | M |
| S3 | `branch_key_materials.rs:205-219` | branch key zeroize | TM-015 | R11 | M |
| S4 | `beacon_key_materials.rs:213-235` | beacon key + HMAC keys zeroize | TM-015 | R11 | M |
| S5 | `raw_aes_keyring.rs:68-78`, `:229-239`, `:353`, `:386` | wrapping key (inner, builder, build) | TM-015 | R11 | M |
| S6 | `branch_key_wrap.rs:135` | derived key `Zeroizing` | TM-015 | R11 | M |
| S7 | `kms_ops.rs:199-207` | KMS `Decrypt` plaintext `Vec` | TM-015 | T26 ("KMS plaintext") | M |
| S8 | `record.rs:100`, `:173` | `Zeroizing` branch key | TM-015 | T02, R11 | M |
| S9 | `branch_key_wrap.rs:275` | `unwrap` output buffer | TM-015 | T26 | M |
| S10 | `raw_aes_keyring.rs:471` | raw-AES decrypt buffer | TM-015 | T26 | M |
| S11 | `prim/src/lib.rs:185-186` | `aes_encrypt` copies plaintext before key check (BUG-07a) | TM-015 | T26 | M |
| S12 | `prim/src/ecdsa.rs:384-392` | keygen DER private key `Vec` on error path | TM-015 | T26 (known stale) | M |
| S13 | `default_cmm.rs:139`, `:145` | signing key moved into `SigningKey` | TM-015 | R11 | M |
| S14 | `hierarchical_keyring.rs:975-984`; `raw_aes_keyring.rs:535-544` | PDK generation straight into `PlaintextDataKey` | TM-015 | C04 | M |
| S15 | `Debug` impls: `algorithm_suite.rs:564`, `:612`, `:696`; `branch_key_materials.rs:55`, `:191`; `beacon_key_materials.rs:57`, `:191`; `raw_aes_keyring.rs:80`, `:241`; `prim/src/ecdsa.rs:26`, `:335`; `hierarchical_keyring.rs:370`; `cmc/entry.rs:148`; `cmc/local.rs:41`, `:193`; `storm_tracking.rs:81`, `:418`; `branch_key_store.rs:94`; `encryption_context.rs:18`; `required_encryption_context_keys.rs:28`; `prim/src/error.rs:410` | redaction | TM-021 | T22 | M |
| S16 | `cmc/local.rs` (`:131`, `:166`) | branch keys resident past TTL until read | TM-015 | T26 (known stale) | M |
| S17 | shim `lib.rs:1627` | `wrapping_key.to_vec()` moves into zeroizing builder | TM-015 | R11 | M |
| S18 | shim `lib.rs:1358`; `EncryptionSDK.cpp:285-287` (`RustBufferDeleter`) | ESDK message plaintext handed to C++ and freed without wipe | — (ESDK data, not MPL key material) | — | U |

## 5. Error paths that carry data

| # | Site | Data carried | Threat | Target | Status |
|---|---|---|---|---|---|
| R1 | `hierarchical_keyring.rs:784`; `raw_aes_keyring.rs:517`; `prim/src/error.rs:406-418` | EDK provider id/info (`DataKeyInfo`), never ciphertext | TM-021 | T22 | M |
| R2 | `hierarchical_keyring.rs:798`; `raw_aes_keyring.rs:513`, `:526` | `all_failed` collected errors | TM-021 | T22 | M |
| R3 | `encryption_context.rs:202` (`{key:?}`); `decryption_materials.rs:311`, `encryption_materials.rs:373` (`{key:?}`) | EC key text (Debug-escaped) | TM-021 | T22 (area) | M |
| R4 | `kms_ops.rs:108`, `:125`; `kms_config.rs:36`, `:44`, `:67`, `:74` | record / config ARN text | TM-021 ("errors carry resource ids") | T22 (area) | M |
| R5 | `branch_key_wrap.rs:102`, `:107` | record version string | TM-021 | — | M |
| R6 | `branch_key_store.rs:1157`, `:1185` | DDB attribute name and type, never value | TM-021 | — | M |
| R7 | `branch_key_store.rs:166`, `:175`, `:622`, `:692`, `:778`; `kms_ops.rs:193` | branch key id | TM-021, TM-003 (existence oracle) | — | M |
| R8 | `mpl/src/error.rs:191-198`; `branch_key_store.rs:993`; `kms_ops.rs:215` | AWS SDK error cause | TM-021 (excluded part: SDK error-cause contents) | — | M |
| R9 | `raw_aes_keyring.rs:451`, `:461`, `:483`, `:490` | key namespace (config), EDK index, lengths | TM-021 | — | M |
| R10 | `default_cmm.rs:100`, `:187`, `:290` | suite id, policy, caller's reproduced-EC key | TM-021, 006, 017 | T09, T12 | M |
| R11 | `materials_checks.rs:54`, `:57`, `:192` | field names | TM-021 | C07 | M |
| R12 | `prim/src/lib.rs:130`, `:216`, `:249`, `:278`, `:325`; `prim/src/ecdsa.rs:85`, `:192`, `:202`, `:392`; `prim/src/hkdf.rs:36` | lengths / algorithm names only | TM-021 | C03 | M |
| R13 | shim `lib.rs:545`, `:558` (`{e:#}`), `:724`, `:766`, `:817`, `:841`, `:947`, `:957`, `:964`, `:1133`, `:1472-1483` | MPL/ESDK error chain text and C++ input values to C++ | TM-021 (what applications log), TM-024 | T22 | M |

## 6. Loops and allocations driven by input

| # | Site | Bound | Threat | Target | Status |
|---|---|---|---|---|---|
| L1 | `hierarchical_keyring.rs:751` | EDK count (uncapped by default) | TM-025 | known: no target | M |
| L2 | `raw_aes_keyring.rs:448`, alloc `:471` | EDK count; one local AES-GCM per matching EDK, alloc = EDK ciphertext length | TM-023 | T16 (panic only) | M |
| L3 | `encryption_context.rs:165` | `count ≤ 65535`, input length | TM-023 | T16, T15 | M |
| L4 | `encryption_context.rs:111`, `:248`, `:301` | EC size | TM-013 | T15 | M |
| L5 | `default_cmm.rs:284` | reproduced EC size (caller) | TM-017 | T12 | M |
| L6 | `branch_key_store.rs:1094`, `:1166`; `kms_ops.rs:55`; `record.rs:84` | DDB item size | TM-005 | T01, T02 | M |
| L7 | `decryption_materials.rs:307`; `encryption_materials.rs:369`; `required_encryption_context_keys.rs:134` | RECK size | TM-017 | C07, T12 | M |
| L8 | `materials_checks.rs:208` (`contains_all`, O(n·m)) | EDKs on the encrypt path (keyring output) | TM-006 (frame) | C07 | M |
| L9 | `storm_tracking.rs:365` (`wait_for_leader`) | grace interval / in-flight TTL | TM-018, 025 | T21 | M |
| L10 | `cmc/local.rs:179` | entry capacity | TM-022 | T23 | M |
| L11 | `prim/src/ecdsa.rs:185` | `MAX_SIGN_ATTEMPTS` | TM-023 | C02 | M |
| L12 | `mpl/src/error_chain.rs:41`, `:73` | `source()` chain | — | rejected R6 | M |
| L13 | shim `lib.rs:568`, `:1470`, `:1715`, `:1922` | error chain, header list, channel chunks | — (ESDK streaming) | — | U |
| L14 | `branch_key_store.rs:599-600`, `:762` | fixed 3 / 2 items | TM-016 | T18, C01 | M |
| L15 | `cache_entry_identifier.rs:42` | config + EDK-derived fields | TM-009 | T13 | M |
| L16 | `branch_key_wrap.rs:70`, `:127`, `:193`, `:275` | EC / EDK size | TM-013, 012, 023 | T10, T04, T16 | M |
| L17 | `prim/src/error.rs:416` | provider info length | TM-021 | T22 | M |

## 7. Coverage greps used before calling anything a gap

`sweep2_cov.sh` output (hits in TM / VT-index / VT01 / VT02 / SSA):

```
branch_key_wrap.rs:2[45][0-9]                  2 0 1 0 1
hierarchical_keyring.rs:(88|89)[0-9]           3 0 0 0 2
cache_entry_identifier.rs:6[0-9]               1 0 0 0 1
user_agent                                     5 0 3 0 5
default_cmm.rs:1[23][0-9]                      3 1 1 1 2
lib.rs:16[0-9]|TOKIO_RUNTIME                   2 0 0 0 1
lib.rs:1086|FrameworkMetadata                  0 0 0 0 0
lib.rs:17[0-3][0-9]|ChannelReader|stream reader poisoned   0 0 0 0 0
mrk_match.rs:4[01]|pa\[5\]                     0 0 2 0 0
encryption_context.rs:1[5-9][0-9]|from_bytes   4 3 12 1 1
peek_inflight|mark_inflight|test-utils         1 3 4 3 4
kms_config.rs:(3|4|5)[0-9]|parse_arn           0 0 9 1 1
get_beacon_key|beacon                          8 1 5 4 7
new_v4|Uuid                                    1 0 0 0 1
splitn|split\(.:.\)                            1 0 1 0 0
storm_tracking.rs:25[0-9]|map_or\(true         1 0 0 0 0
RustBufferDeleter|into_plaintext|EncryptionSDK.cpp:28      0 0 0 0 0
EncryptionSDK.cpp:54[0-9]|adopt               18 0 0 0 0
create_key_store                               0 0 0 0 0
```
