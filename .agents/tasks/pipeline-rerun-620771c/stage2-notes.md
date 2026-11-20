# Stage 2 notes: threat model re-run (a1e23d7 -> 620771c)

- Output: `docs/threat-model.md`, updated in place. IDs TM-MPL-001..023 kept, none renumbered or deleted. One new threat, TM-MPL-024. None retired.
- Inputs read: `.kiro/agents/ai-verification-pipeline.md`, `docs/spec-security-analysis.md` (Stage 1), `scope.md`, `docs/bug-reports/RECHECK-main-620771c.md`, `docs/bug-reports/README.md`, `BUG-06` report, previous `docs/threat-model.md`.
- Spec read for the sections the changed ratings depend on: `framework/storm-tracking-cryptographic-materials-cache.md` (constraints, lines 136-138; "at least 1", lines 59/71/92), `framework/aws-kms/aws-kms-hierarchical-keyring.md` (NUL separator lines 422/472; Partition ID "CANNOT share" 539/543; logical name 547), `framework/branch-key-store.md` (MRDiscovery 168/204; KeyId rule 669). Copies read at `esdk/spec/framework/` (same text in `esdk/shims/aws-esdk-cpp/spec/framework/`).
- Rule followed: no change under `mpl/`, `prim/`, `esdk/`; nothing committed or pushed. No shell was available in this step, so "grep -n / sed -n" checks were done with the workspace grep tool (match-line numbers) and file reads with offsets. The grep tool prints context-line numbers off by one; only match lines (`N:`) were used, and several were cross-checked by reading the file at an offset (prim/src/lib.rs:185-188, hierarchical_keyring.rs:879, raw_aes_keyring.rs:146, materials_checks.rs:72-103).

## Locations verified this step (current HEAD)

| Item | file:line |
|---|---|
| Hierarchical: TTL zero check | `mpl/src/aws_kms/hierarchical_keyring.rs:547` |
| Hierarchical: default `DefaultCmc` | `:567-573` (no-tokio error `:575-580`) |
| Hierarchical: grace >= TTL rejected only if cache reports a grace period | `:585-586`; trait default `None` at `mpl/src/cmc/mod.rs:88-90` |
| Hierarchical: partition id raw bytes / random UUID | `:596`, `generate_partition_id` `:626` |
| Hierarchical: logical name taken from key store as returned | `:600-605` |
| Hierarchical: on_encrypt, cache id, unchecked expiry add, EDK provider info | `:654`, `:665`, `:702`, `:722` |
| Hierarchical: on_decrypt filters, add_data_key, NoMatchingDataKey EDK list, all_failed | `:734`, `:752-763` (read), `:767`, `:784`, `:798` |
| Hierarchical: try_decrypt_edk, 44-byte check, expect, decrypt cache id, key store call, expiry add | `:867`, `:879`, `:892`, `:908`, `:934`, `:945` |
| Hierarchical: PDK gen, TTL compare (BUG-09 fix), kind check | `:975`, `:989-995`, `:1000` |
| Supplier trait | `hierarchical_keyring.rs:187` |
| Cache id | `mpl/src/aws_kms/cache_entry_identifier.rs:35`, NUL joins `:42-60`, expect `:64` |
| branch_key_wrap | `compute_aad :61`, `uuid_str_to_16_bytes :92`, `derive_branch_key :122` (Zeroizing `:125`, `:135`), `wrap :157` (salt `:164`, IV `:170`), `unwrap :230`, too-short `:240`, expects `:249/:252/:256` |
| MRK match | `mpl/src/aws_kms/mrk_match.rs:24`, alias reject `:25`, `is_multi_region_arn :52` (`key/mrk-` `:57`), `is_alias_arn :62` |
| kms_ops | auth EC `:49`; `resolve_key_store_arn :88`; configured ARN `:95-96`; Discovery `:96-99`; MrDiscovery `:100-103`; compat `:105`; `reject_alias_arn :118`; `rewrite_arn_region :144`; `decrypt_branch_key :162`; resolve call `:179`; user agent `:187-188`, `:239-240`, `:286-287`; Blob `into_inner` `:207` |
| Key store | `build :373`, `validate :381`, `create_key :539`, `version_key :641`, conditions `:604`, `:743`, `:752`, `get_active_branch_key :792`, `get_branch_key_version :827`, materials from auth EC `:814`, `:852`, codec `:1089`, `:1141` |
| Key store trait / unchecked handle send | `mpl/src/key_store/mod.rs:172`; `mpl/src/key_store/client_impl.rs:305-308` (get_active), `:373-376` (get_version; pass-through call `:375`) |
| record | `mpl/src/key_store/record.rs:95`, Zeroizing `:100`, 32-byte check `:164`, `:173` |
| build_base dead branch (BUG-08) | `mpl/src/key_store/encryption_context.rs:40`, `:92-102` |
| DefaultCmm | `get_encryption_materials :85`, policy `:97`, reserved key `:113`, expect `:123`, keygen expect `:138`, keyring `:167`, `decrypt_materials :177`, policy `:184`, merge call `:198`, reserved key non-signing `:224`, keyring `:244`, merge fn `:273` |
| Commitment policy | `mpl/src/structures/commitment_policy.rs:43` default, FORBID deviation comment `:46-47`, `03 78` `:49-50`, `allows_for_encrypt :62`, `allows_for_decrypt :77` |
| ESDK re-check of CMM output vs policy | `esdk/src/materials.rs:130`, `:202`; `esdk/src/decrypt.rs:413` |
| Materials checks | `mpl/src/structures/materials_checks.rs:18`, `:37`, `:72` (suite `:78-81`, EC `:82-85`, RECK `:86-89`, signing key `:91`, PDK `:100`, EDKs `:103`), `:117`, `:157`, `:177` |
| Checks wired in send() | `mpl/src/keyring/fluent_builders.rs:82`, `:163`; `mpl/src/cmm/fluent_builders.rs:171`, `:319` |
| Builtin wrapper | `mpl/src/shared.rs:110` |
| Secrets zeroize / redaction | `algorithm_suite.rs:505` (PDK), `:571` (SigningKey), `:655` (SymmetricSigningKey); `ct_eq :541/:607/:691`; `check_data_key_length :547`; Debug `:566/:614/:699`. `branch_key_materials.rs:58`, `:196`, Drop `:205-219`. `beacon_key_materials.rs:203-235`. Raw AES wrapping key Drop `raw_aes_keyring.rs:72-78`, builder `:233-239`, Debug `:87` |
| Raw AES | prefix const `:52`, prefix check `:360`, key length `:370`, provider info `:129`, `wrap_data_key :146` (IV `:151-152`), `on_encrypt :399`, AAD `:405`, `on_decrypt :422`, decrypt buffer `:471`, length check `:489`, EDK list once `:517` |
| DataKeyInfo has no ciphertext | `mpl/src/structures/encrypted_data_key.rs:148-151` |
| EC from_bytes strict (BUG-03 fix) | `mpl/src/structures/encryption_context.rs:145`, duplicate `:202`, order `:208` |
| Storm tracking | defaults `:110-121`; test accessors expect `:199/:213/:227`; `state_locked :239` -> Internal `:248`; `classify_and_mark :264`; fan-out `:274`, `:310`; deadline `:333`; `wait_for_leader :360`; `build :606` (checks `:613`, `:616`, `:620-621`, `:622`); `within_grace_period :661`; `within_grace_interval :675`, add `:680`; `put_cache_entry :710`; `grace_period()` `:764`, `:772-774` |
| LocalCmc | `prune_tail :166`, `put_cache_entry :280`, `get_cache_entry :302` |
| CachedMaterials kinds | `mpl/src/cmc/entry.rs:24-33` (Encryption `:26`, Decryption `:28`); only Duvet annotation `:201-204`, `record_use :206`, checked_add `:213-214` |
| prim | `generate_random_bytes :128`; `aes_encrypt :175`, copy `:185`, slice `:186`, key Err `:187`, nonce `:188`; `aes_decrypt :206`, guard `:215`, callee `:229`; `hmac :241`; `digest :272`; `constant_time_equal :291`; `kbkdf_ctr_hmac :313`; lint name only `:33` |
| No `unsafe` in mpl/src, prim/src | `\bunsafe\b` grep: 0 matches |
| Shim unsafe | `esdk/shims/aws-esdk-cpp/src/lib.rs:715` `require_handle` (annotation `:717-719`), null check `:720`, deref `:728`; `:1564-1565`; `:1655`; `#[cxx::bridge]` `:167` |
| Hierarchical: get_active call / version string | `hierarchical_keyring.rs:692-696`; `uuid_16_bytes_to_str` call `:894` |
| Key store error redaction comment | `key_store/branch_key_store.rs:1140` |
| Test servers bind loopback | `mpl/test-server/src/main.rs:27`, `prim/test-server/src/main.rs:24` (`127.0.0.1`) |
| User agent | `mpl/src/aws_kms/user_agent.rs:9` (`AwsCryptographicMPL-Rust`), expect `:17` |
| Duvet configs | only `esdk/.duvet/config.toml`, `esdk/shims/aws-esdk-cpp/.duvet/config.toml`; no `mpl/.duvet`. `//= spec` in mpl+prim src/tests: 1 (`entry.rs:201`) |
| Tests cited | `test_materials_checks.rs:271`; `test_encryption_materials.rs:248`, `:429`; `test_decryption_materials.rs:228`, `:401`; `test_encryption_context.rs:68`; `test_storm_tracking_cmc.rs:388` (grace_period = 0 accepted); `test_aws_kms_hierarchical_keyring.rs:1547`; `test_keyring_memory.rs:100`, `:113` |

Not re-verified by me (taken from Stage 1 / scope, marked as such where cited): RECK ⊆ EC builder lines; test-count table; spec revision hashes; ESDK annotation count (~2100).

## CVE

Scope notes verified CVE-2026-6550 / GHSA-v638-38fc-rhfv with URLs. I repeated a web search this step: the GitHub Advisory Database entry (https://github.com/advisories/GHSA-v638-38fc-rhfv) and AWS bulletin 2026-017-aws (https://aws.amazon.com/security/security-bulletins/2026-017-aws/) both describe a key-commitment bypass through a shared key cache in the AWS Encryption SDK for Python. So the "unverified" note is replaced by "verified" with sources. It does not apply to current MPL code (no caching CMM).

## Rating decisions

Risk matrix (same as previous version, made explicit): Critical×Medium = High; High×Medium = High; Critical×Low = Medium; High×Low = Medium; Medium×Medium = Medium; Medium×Low = Low; Low×any = Low.

- TM-009 Medium -> High (likelihood Low -> Medium). Previous rating assumed the identifier was injective and rated collision as needing SHA-384 breaks or a hypothetical separator flaw. BUG-06 is now a confirmed open defect on main with end-to-end evidence (keyring B served key store A's branch key; key store B never called). The cryptographic barrier is gone; what remains is a config precondition the MPL does not check (`hierarchical_keyring.rs:596`, `:600-605`). Likelihood Medium is conditional on the deployment the spec's Partition ID section is written for (shared cache, tenant-influenced partition id / logical name / bkid). This differs from BUG-06's bug severity Low (which weighs typical deployments); documented in the threat model so reviewers can revert.
- TM-010 Medium -> High (likelihood Low -> Medium). BUG-06 is a concrete realization of this exact threat. The previous residual "no cross-check that a cached suite's commitment matches policy" is withdrawn: the hierarchical keyring caches only `CachedMaterials::BranchKey` (`:701`, `:944`), which is policy-independent; no caching CMM exists. BUG-09 fix (exact TTL) noted as a mitigation gain.
- TM-015 Medium -> Low (severity High -> Medium). Long-lived secrets are now zeroized on drop (list above). Remaining residue: transient buffers (raw AES decrypt buffer on error/wrong-length path `:471`, `:489`; `unwrap` output Vec before `PlaintextDataKey`; KMS SDK `Blob` `kms_ops.rs:207`; BUG-07a plaintext left in a dropped output `Vec` on `aes_encrypt` Err, `prim/src/lib.rs:185-187`; Vec reallocation copies). Cache holding branch keys for TTL is by design.
- TM-018 unchanged Medium, but mitigation text corrected: `build()` no longer enforces the spec's Inflight TTL <= Grace Period, Grace Interval <= Grace Period, or "at least 1" for grace period/interval (`storm_tracking.rs:606-628`; `test_storm_tracking_cmc.rs:388`). BUG-01b/c panics. Hot-path lock-poison panic removed (`:248`). Did not raise: impact is availability and the defaults are valid.
- TM-006 unchanged Medium; strengthened by transition checks, PDK length (BUG-02 fix), ESDK re-check of policy. Not lowered: the allow tables are still unproven and have no Duvet trace. BUG-02 did not drive any previous rating, so lowering a rating on it would be invented.
- TM-007 unchanged Medium; BUG-04 confirmed open. Fail-closed effect (KMS call to a non-existent/different key ARN); KMS-side behavior not run (needs AWS).
- TM-023 unchanged Low; BUG-02 fixed, #186 O(n²) memory fixed, BUG-05a/b, BUG-01a/d, BUG-07b recorded.
- TM-019 unchanged Medium; status refined (configs, 1 annotation, spec floats on `master`).
- Others: location / wording updates only.

## New-threat screening

Added: TM-MPL-024, C++ shim raw-handle deref into native MPL objects (new for the native MPL in e9bde48; `unsafe` at shim `lib.rs:728`, `:1564-1565`, `:1655`). High × Low = Medium. Outside `mpl/`/`prim/` but the only `unsafe` that reaches MPL objects holding keys.

Considered, not added:
- Pluggable `KeyStore` / `Cmc` / supplier traits: not new. The RECHECK adaptation notes show the old `Keystore` trait (with a fake returning a logical name) and `CacheType::Shared(Arc<dyn Cmc>)` existed at a1e23d7. Folded into TM-005/009/010 residuals (unchecked results, `grace_period()` default `None`).
- Materials checks only on the fluent path: a mitigation; bypass needs the caller's own direct trait call.
- Optional cargo features: configuration, no attacker. Noted in section 9.
- Test servers: bind `127.0.0.1`, not shipped. Flag only.
- Spec floating on `master` (#91): folded into TM-019.
- EDK-count memory amplification: pre-existing surface, fixed by #186; folded into TM-023.
- Caching CMM / CVE-2026-6550 class: no caching CMM in code; future note under TM-008/010.

## Verification

- Files written by this step: `docs/threat-model.md`, this file. Nothing under `mpl/`, `prim/`, `esdk/` was touched. No commit, no push.
- Could not run `git diff --quiet` (no shell tool in this step); the only write tools used targeted the two files above.
