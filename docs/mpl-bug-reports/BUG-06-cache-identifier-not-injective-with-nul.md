# BUG-06: The hierarchical keyring cache-identifier preimage is not injective when fields contain NUL bytes

Summary: `build_cache_identifier` joins the partition ID, logical key store name, branch key ID and version with single `0x00` separators and no length prefixes. If a field contains `0x00`, two different keyring configurations produce the same SHA-384 cache identifier, so they can read each other's branch key materials from a `Shared` cache. The code follows the layout the spec mandates.

- Confidence: Confirmed by test
- Spec conflict: yes, but the conflict is inside the spec. The code matches the mandated layout in Appendix A exactly, and that layout breaks the spec's own statement that keyrings with different partition IDs "CANNOT share" cache entries.
- Severity: High. Severity raised Low -> High on the owner's decision after the main re-check. This applies to the outcome when the preconditions hold. The preconditions are a `Shared` cache plus the ability to pick NUL-containing configuration values (partition ID, logical key store name, or branch key ID). Those values can come from a caller-supplied string or from a branch key ID supplier. If they hold, the impact is cross-keyring use of branch key materials, which the main re-check confirmed end to end. See "Severity decision" below.
- Related IDs: VR-2026-T13 (primary), VR-2026-T19 (hierarchical branch key ID binding, for the supplier path); TM-MPL-009 (High), TM-MPL-010 (High), TM-MPL-003 (Low). Ratings are from `docs/mpl-threat-model.md` (HEAD 9955ecd); targets are from `docs/mpl-verification-targets.md`.
- Completeness audit mapping (`docs/mpl-completeness-audit.md` section 3b): BUG-06 -> TM-MPL-009, 010, 003 -> T13, T19.
- Last cross-checked: HEAD 9955ecd (code == main 620771c for mpl/ and prim/)

## Status on main (620771c)

- Status: Still present.
- Re-checked: 2026-11-10, against `c256243` on `MPL-Verus` (code identical to `main` `620771c`). Details: [RECHECK-main-620771c.md](RECHECK-main-620771c.md), section BUG-06.
- Evidence: the test, adapted for API changes only, gives 2 passed. Both identifier collisions are `true` and the no-NUL control is `false`. End to end, with one shared `LocalCmc`, keyring B was served keystore A's branch key: keystore B was never called, and B's EDK unwraps with A's branch key but not with B's own (`.agents/tasks/bug-recheck/logs/recheck06.log`).
- `cache_entry_identifier.rs` has no commits since `a1e23d7` (`git diff a1e23d7 HEAD` on the file is empty). `HierarchicalKeyringBuilder::build` still accepts a partition ID containing NUL and uses the key store's logical name as returned.

Severity decision: Severity raised Low -> High on the owner's decision after the main re-check. The finding, evidence, status and confidence are unchanged. The basis is the evidence only:

- The main re-check showed end to end that, with one shared `LocalCmc`, keyring B was served keystore A's branch key. Keystore B was never called, and B's EDK unwraps with A's branch key but not with B's own.
- The cache-identifier preimage is not injective when fields contain NUL. Both identifier collisions are `true` on `main` and the no-NUL control is `false`. The code follows the layout the spec mandates, so the conflict is inside the spec.
- The threat model rates TM-MPL-009 and TM-MPL-010 High (Severity High, Likelihood Medium). BUG-06 realizes both.

The preconditions are unchanged and are not met by a default configuration: a `Shared` cache, plus a NUL-containing partition ID, logical key store name or branch key ID, chosen to line up with the other keyring's fields. They can be reached through a caller-supplied value, or through a branch key ID supplier that returns such a value (TM-MPL-003). BUG-02 is now fixed, so this is the open finding with the most direct confidentiality impact.

Line numbers outside the Status and Location sections refer to `a1e23d7`, where the bug was first found, and are kept as history.

## Location

Current code (`main` `620771c`): `mpl/src/aws_kms/cache_entry_identifier.rs:35-66` (`build_cache_identifier`). The file is unchanged since `a1e23d7`, so the line numbers are the same:

```rust
42     let mut buf: Vec<u8> = vec![
43         RESOURCE_ID_HIERARCHICAL_KEYRING,
44         NULL_BYTE,
45         scope_id,
46         NULL_BYTE,
47     ];
49     buf.extend_from_slice(partition_id);
50     buf.push(NULL_BYTE);
52     buf.extend_from_slice(logical_key_store_name.as_bytes());
53     buf.push(NULL_BYTE);
55     buf.extend_from_slice(branch_key_id.as_bytes());
57     if let Some(version) = branch_key_version {
58         buf.push(NULL_BYTE);
59         buf.extend_from_slice(version.as_bytes());
60     }
```

The call sites are `mpl/src/aws_kms/hierarchical_keyring.rs:665` (OnEncrypt) and `:908` (OnDecrypt). The inputs still aren't checked for NUL anywhere:

- The partition ID is `s.into_bytes()` of the caller's string (`hierarchical_keyring.rs:596`), or the 16-byte form of a random v4 UUID (`generate_partition_id`, `:626`), which can contain `0x00`.
- The logical key store name is read from the key store's `get_key_store_info` output and used as returned (`hierarchical_keyring.rs:600-605`).
- The branch key ID comes from the keyring configuration or a branch key ID supplier. The version is a 36-character hyphenated UUID string, so it can't contain NUL.

Originally reported at `a1e23d7`: the same `cache_entry_identifier.rs:35-66`; call sites `hierarchical_keyring.rs:306` and `:550`; partition ID at `:196` and `:269`; logical name in `mpl/src/keystore/config.rs`; branch key ID resolved at `:299` and `:398`.

## Expected behavior

`spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials` (and `#decryption-materials`, which uses the same wording):

> All the above fields must be separated by a single NULL_BYTE `0x00`.

The code follows this. The same document, `#partition-id-2` (the "Partition ID" subsection of Shared Cache Considerations), says:

> If the Partition ID is set by the user and is different for two Hierarchical Keyrings (or another Material Provider),
> they CANNOT share the same cache entries in the cache.

and `#shared-cache-considerations` says:

> Users MUST make sure that all of Partition ID, Logical Key Store Name of the Key Store for the Hierarchical Keyring
> and Branch Key ID are set to be the same for two Hierarchical Keyrings if and only they want the keyrings to share
> cache entries.

The "CANNOT share" guarantee holds only when the fields contain no `0x00`. The spec doesn't forbid NUL in any of these fields, so the two sections conflict for NUL-containing inputs. The spec's related MUST, "Users MUST NEVER have two different physical Key Stores with the same Logical Key Store Name" (`#logical-key-store-name`), isn't violated in this reproducer, because the two logical names differ.

## Actual behavior

1. Keyring A uses partition ID `"tenant\0x"` and logical name `"L"`. Keyring B uses partition ID `"tenant"` and logical name `"x\0L"`. Both use branch key ID `"bk"`.
2. Both preimages are `02 00 01 00 "tenant" 00 "x" 00 "L" 00 "bk"`, so the cache identifiers are equal.
3. The same shift works for any pair of adjacent fields. For example, logical name `"L"` with branch key ID `"bk\0x"` collides with logical name `"L\0bk"` with branch key ID `"x"` in the decrypt scope.
4. Both keyrings share a `LocalCmc` as `CacheType::Shared`. A calls OnEncrypt, which fetches A's branch key from keystore A and caches it. B then calls OnEncrypt, gets a cache hit, never calls keystore B, and wraps its data key under A's branch key.

## Impact

- Preconditions: (i) the keyrings share one `Cmc` instance (`CacheType::Shared`), which means they're in the same process; (ii) at least one keyring's partition ID, logical key store name, or branch key ID contains `0x00` at a position chosen to line up with the other keyring's fields; (iii) both keyrings use the same branch key ID suffix (or the equivalent shifted split).
- Realistic exploitability: low. The values come from application configuration, not from message bytes. The realistic case is a multi-tenant application that builds partition IDs or logical names from tenant-supplied strings without rejecting NUL. A branch key ID supplier that returns attacker-influenced strings derived from the encryption context is a second path. This bullet describes how likely the preconditions are in practice. It is not the severity: the High severity above is the outcome when they hold, and the threat model rates the likelihood of TM-MPL-009 and TM-MPL-010 Medium.
- If those preconditions hold, the consequences are as follows. The keyring that hits the other's entry wraps data keys under, or unwraps with, branch key materials its own keystore never returned. Depending on direction, that means data encrypted for one tenant is wrapped under a branch key another tenant controls (a confidentiality issue), or a tenant decrypts using cached materials it has no KMS access to. In the reverse direction, the entry's owner sees messages its own keystore can't decrypt later. The spec already says a shared cache gives access to materials a keyring "MAY or MAY NOT have direct access to". This finding is that the partition boundary meant to prevent that can be crossed.
- Default random partition IDs contain `0x00` with roughly 6% probability (1 − (255/256)^16). To collide with one, the other keyring would need to know those random bytes, and its logical name, which is a Rust `String`, would have to carry the tail as valid UTF-8. I consider that not practical.
- The Dafny MPL builds the same preimage in `GetActiveCacheId` / `GetVersionCacheId`, with no NUL check in those methods ([AwsKmsHierarchicalKeyring.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy)). I didn't check whether the Dafny constructor validates partition IDs or logical names.

## Reproduction / evidence

Re-check on `main` `620771c` (2026-11-10). The original reproducer no longer compiles against the current API (7 compile errors, kept at the top of the log). It was adapted for API changes only:

- The test internals moved to `aws_crypto_mpl::__test_internals::aws_kms` (`build_cache_identifier`, `unwrap`, `SCOPE_ID_ENCRYPT`, `SCOPE_ID_DECRYPT`).
- The fake implements the `KeyStore` trait with `*Input` / `*Output` shapes, and keeps the same logical names, key bytes and `get_active_branch_key` counter.
- Keyrings are built with `HierarchicalKeyring::builder()` and called through `SharedKeyring`.
- `LocalCmc::new(1000, 1)` became `LocalCmc::builder().entry_capacity(1000).entry_pruning_tail_size(1)`, shared through `SharedCmc` instead of `CacheType::Shared`.

The `build_cache_identifier` arguments, partition IDs, logical names and the end-to-end scenario are identical.

- Adapted reproducer: [`zz_bugrepro_06_cache_id_nul.rs`](../../.agents/tasks/bug-recheck/reproducers/zz_bugrepro_06_cache_id_nul.rs) (127 lines, not inlined here).
- Original reproducer (`a1e23d7` API): `.agents/tasks/bug-reports/reproducers/zz_bugrepro_06_cache_id_nul.rs`.
- Command: `cd mpl && cargo test --test zz_bugrepro_06_cache_id_nul -- --nocapture`. The test was copied into `mpl/tests/` for the run and deleted afterwards.

The reproducer uses a test `KeyStore`. The real `BranchKeyStore` path needs DynamoDB and KMS, so it wasn't run.

Observed output on `main` (`.agents/tasks/bug-recheck/logs/recheck06.log`):

```text
running 2 tests
REPRO BUG-06 encrypt-scope ids equal for (p="tenant\0x", n="L") vs (p="tenant", n="x\0L"): true
REPRO BUG-06 decrypt-scope ids equal for (n="L", bkid="bk\0x") vs (n="L\0bk", bkid="x"): true
REPRO BUG-06 control (no NUL, p="tenantx") equal to first: false
test identifier_collides_when_fields_contain_nul ... ok
REPRO BUG-06 keystore A get_active calls = 1, keystore B get_active calls = 0
REPRO BUG-06 keyring B's EDK unwraps with keystore A's branch key: true; with keystore B's own branch key: false
test shared_cache_serves_other_keyrings_branch_key ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

The output is the same as the original run at `a1e23d7` (`.agents/tasks/bug-reports/logs/bugrepro06.log`).

## Fix options

These options were written against `a1e23d7` and still apply on `main`. The constructor named in option 1 is now `HierarchicalKeyringBuilder::build` (`mpl/src/aws_kms/hierarchical_keyring.rs:535`).

1. Reject `0x00` in caller-supplied partition IDs and logical key store names in `HierarchicalKeyring::new`, and in resolved branch key IDs before building the identifier.
   - Pros: the preimage stays byte-identical to the spec for every input that's accepted today without NUL, which covers all realistic configurations. Nothing changes for current users, and the cost is a byte scan per field.
   - Cons: it's a behavior change for anyone using NUL (rejected at construction, or at OnEncrypt/OnDecrypt for supplier-provided IDs). It also diverges from the Dafny MPL unless Dafny adds the same check. The default random partition ID isn't covered. It could be regenerated until it's NUL-free, but that changes its distribution slightly, and the residual risk there is already negligible.
2. Change the preimage to length-prefixed fields (for example, a u16 or u32 big-endian length before each variable field).
   - Pros: the encoding becomes injective for all inputs, with no input restrictions.
   - Cons: it needs a spec change and the same change in every runtime. Cache identifiers aren't persisted, so the compatibility cost mostly falls on any cross-runtime shared cache implementation, which I'm not aware of in practice. It still diverges from the current spec text until the spec is updated.
3. Documentation only. State in the rustdoc and the spec that these fields MUST NOT contain `0x00` when a `Shared` cache is used.
   - Pros: no code or behavior change.
   - Cons: the guarantee rests on user discipline. That's the same weakness the logical-name MUST already has.

Recommendation: option 1 for caller-supplied strings, plus a spec issue that either adds the NUL restriction (codifying option 1) or moves to option 2 across runtimes.

## Questions for the engineers

1. Should the spec forbid NUL in partition IDs, logical key store names and branch key IDs, or move to a length-prefixed preimage?
2. Is it acceptable for the Rust MPL to reject NUL-containing values before the Dafny MPL and the other runtimes do the same?
3. Do any known integrations derive partition IDs or logical names from tenant- or request-supplied strings, or run a branch key ID supplier that passes encryption-context values through unchanged?
4. Should the default 16-byte random partition ID be made NUL-free, or is the residual risk acceptable as is?
