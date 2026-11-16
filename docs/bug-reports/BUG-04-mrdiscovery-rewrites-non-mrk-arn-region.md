# BUG-04: MRDiscovery rewrites the region of single-Region (non-MRK) KMS key ARNs

Summary: With `KmsConfiguration::MrDiscovery { region }`, the branch key store rewrites the region of every record's `kms-arn` to the configured region, including single-Region keys. KMS then receives a key ARN that doesn't exist, so the request fails. The Dafny MPL rewrites only multi-Region key (MRK) ARNs.

- Confidence: Confirmed by test (in-crate unit test against `resolve_keystore_arn`; the end-to-end KMS failure is inferred and needs AWS)
- Spec conflict: yes. The spec is internally inconsistent: the configuration section says MRK ARNs only, while the KMS-Decrypt section says the region is replaced unconditionally.
- Severity: Low. This is a spec-text / cross-runtime divergence. With the default KMS client, a single-Region key outside the configured region is expected to fail in both Rust and Dafny, with different errors. The outcomes differ only when the caller supplies its own KMS client. It fails closed, and there's no wrong-key or confidentiality impact (see Impact).
- Related IDs: VR-2026-T17; TM-MPL-007 (Medium). `docs/threat-model.md` records that this bug fails closed and does not widen TM-MPL-002 (Medium). Ratings are from `docs/threat-model.md` (HEAD 9955ecd); targets are from `docs/verification-targets.md`.
- Completeness audit mapping (`docs/completeness-audit.md` section 3b): BUG-04 -> TM-MPL-007 -> T17.
- Last cross-checked: HEAD 9955ecd (code == main 620771c for mpl/ and prim/)

## Status on main (620771c)

- Status: Still present.
- Re-checked: 2026-11-10, against `c256243` on `MPL-Verus` (code identical to `main` `620771c`). Details: [RECHECK-main-620771c.md](RECHECK-main-620771c.md), section BUG-04.
- Evidence: the in-crate test, adapted for API changes only, gives 1 passed. The single-Region `us-east-1` ARN is still rewritten to `us-west-2` (`SRK ARN changed by MRDiscovery: true`) (`.agents/tasks/bug-recheck/logs/recheck04.log`).
- The module moved from `mpl/src/keystore/` to `mpl/src/key_store/` in `e9bde48` (#98), and `resolve_keystore_arn` is now `resolve_key_store_arn`. The logic is unchanged. The KMS-side failure needs AWS and was not run, as before.

Line numbers outside the Status and Location sections refer to `a1e23d7`, where the bug was first found, and are kept as history. Spec line references (for example `branch-key-store.md` lines 168, 204 and 669) were not re-checked in the 2026-11-10 run, because `main` removed the spec submodule (`6ef7d80`, #91). They were re-read at HEAD 9955ecd in the local `spec/framework/branch-key-store.md` (revision `e8334535`, and `framework/` is unchanged at spec `94c2bfe`): lines 168 and 204 hold the "Any MRK ARN discovered will be changed to this region before use" sentence, and line 669 holds the MRDiscovery `KeyId` sentence.

## Location

Current code (`main` `620771c`): `mpl/src/key_store/kms_ops.rs:100-103` (the MrDiscovery arm of `resolve_key_store_arn`, `:88`) and `:144-157` (`rewrite_arn_region`):

```rust
100         KmsConfiguration::MrDiscovery(mr_discovery) => {
101             reject_alias_arn(record_kms_arn, branch_key_id)?;
102             return rewrite_arn_region(record_kms_arn, mr_discovery.region(), branch_key_id);
103         }
...
144 fn rewrite_arn_region(arn: &str, new_region: &str, branch_key_id: &str) -> Result<String, Error> {
145     let parts = parse_arn(arn).map_err(|e| {
146         malformed_record(branch_key_id, "record kms-arn is malformed").with_source(e)
147     })?;
148     Ok(format!(
149         "arn:{}:{}:{}:{}:{}/{}",
150         parts.partition,
151         parts.service,
152         new_region,
```

There's still no `mrk-` check. An MRK predicate exists elsewhere (`mpl/src/aws_kms/mrk_match.rs:52`, `is_multi_region_arn`, private to that module), but the key store path doesn't use it.

The resolved ARN is used as the KMS `KeyId`:

- `decrypt_branch_key` (`kms_ops.rs:162`) calls `resolve_key_store_arn` at `:179`. `decrypt_branch_key` is used by `get_active_branch_key`, `get_branch_key_version` and `get_beacon_key` (`branch_key_store.rs:801`, `:839`, `:874`).
- `version_key` (`branch_key_store.rs:641`) calls `resolve_key_store_arn` at `:663`. Under Discovery / MRDiscovery it still fails first, at `:644`, through `configured_kms_key_arn` (`:112-122`).

Originally reported at `a1e23d7`: `mpl/src/keystore/kms_ops.rs:104-107` (`resolve_keystore_arn`, `:84`) and `:132-148` (`rewrite_arn_region`); `decrypt_branch_key` at `kms_ops.rs:169`; callers at `branch_key_store.rs:555/577/599`; `version_key` at `branch_key_store.rs:442`, with the Discovery check at `:190`.

## Expected behavior

`spec/framework/branch-key-store.md` has two different texts.

- `#aws-kms-configuration` (line 168) and `#mrdiscovery` (line 204): "Any MRK ARN discovered will be changed to this region before use." This is non-normative (no MUST), but it's specific to MRK ARNs.
- `#aws-kms-branch-key-decryption` (line 669): "If the KMS Configuration is MRDiscovery, `KeyId` MUST be the `kms-arn` attribute value of the AWS DDB response item, with the region replaced by the configured region." This is normative and has no MRK qualifier.

The current Rust code follows line 669 literally.

The Dafny MPL follows lines 168/204: `KMSKeystoreOperations.dfy` `replaceRegion` returns the ARN unchanged when `!IsMultiRegionAwsKmsArn(parsed.value)` (or when parsing fails), and `GetArn` uses it for `mrDiscovery` ([source](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographyKeyStore/src/KMSKeystoreOperations.dfy), `main` branch, read while writing this report).

## Actual behavior

1. The keystore is configured `MrDiscovery { region: "us-west-2" }`.
2. A record's `kms-arn` is the single-Region key `arn:aws:kms:us-east-1:111122223333:key/1234abcd-...`.
3. `reject_alias_arn` passes, because it isn't an alias.
4. `rewrite_arn_region` returns `arn:aws:kms:us-west-2:111122223333:key/1234abcd-...`.
5. KMS `Decrypt` is called with that `KeyId`. A single-Region key ID exists only in its home region, so this is expected to fail with a KMS error such as `NotFoundException`. That step is inferred; it wasn't run because it needs AWS.

## Impact

- Precondition: an MRDiscovery keystore reads a record whose `kms-arn` is a single-Region key.
- Default KMS client. Without a caller-supplied client, `BranchKeyStore` builds one in the MRDiscovery region (`branch_key_store.rs:763-771` at `a1e23d7`, `region_from_kms_config`), as the spec's `#kms-client` section requires. On current code the default clients are built at `branch_key_store.rs:396-405`, and `region_from_kms_config` is at `branch_key_store.rs:1114`, with an `MrDiscovery` arm that returns the configured region (`:1118`).
  - If the single-Region key is in that same region, the rewrite is a no-op and both runtimes behave identically.
  - If it's in another region, Rust sends a non-existent ARN, while Dafny sends the original ARN to a client in a different region. Both are expected to fail at KMS (not tested; needs AWS). Only the error differs.
- Caller-supplied KMS client (`KeystoreConfig::kms_client`, `config.rs:28` at `a1e23d7`; on current code `DynamoDbKeyStoreBuilder::kms_client`, `branch_key_store.rs:322`) in the single-Region key's home region. Here Dafny would succeed and Rust would fail. This is the case where observable outcomes diverge. It's an unusual configuration, since it pairs an MRDiscovery region with a client in a different region.
- Security: none identified. The rewritten ARN can't name a different existing key: non-MRK key IDs are region-unique UUIDs without the `mrk-` prefix. And `Decrypt` still binds the record's encryption context. The behavior fails closed.
- Net: the main value of a fix is spec and Dafny parity, plus clearer errors, rather than restoring a commonly used path.

## Reproduction / evidence

`resolve_key_store_arn` is `pub(crate)`, and `kms_ops` is a private module (`mod kms_ops`, `mpl/src/key_store/mod.rs:36`), so an integration test can't reach it. The re-check ran the reproducer as an in-crate unit test in a throwaway copy of `mpl/` and `prim/` under `/tmp/bugrecheck04`. The only change to that copy was appending `#[cfg(test)] #[path = "zz_bugrepro_04.rs"] mod zz_bugrepro_04;` to its `kms_ops.rs`. The copy was deleted afterwards, and the repository source wasn't modified.

The original module no longer compiles against `main` (2 compile errors: `unresolved import super::resolve_keystore_arn` and `crate::keystore`). It was adapted for API changes only, with the same ARNs, region and observations. Adapted reproducer: [`zz_bugrepro_04_mrdiscovery_non_mrk.rs`](../../.agents/tasks/bug-recheck/reproducers/zz_bugrepro_04_mrdiscovery_non_mrk.rs). Command: `cargo test --lib zz_bugrepro_04 -- --nocapture`, run in the copy.

```rust
use super::resolve_key_store_arn;
use crate::key_store::config::{Discovery, KmsConfiguration, MrDiscovery};

const SRK_EAST: &str = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
const MRK_EAST: &str = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
const BKID: &str = "bk";

fn mr_discovery(region: &str) -> KmsConfiguration {
    KmsConfiguration::MrDiscovery(MrDiscovery::builder().region(region).build().unwrap())
}

#[test]
fn mrdiscovery_rewrites_region_of_single_region_key() {
    let out = resolve_key_store_arn(&mr_discovery("us-west-2"), SRK_EAST, BKID);
    println!("REPRO BUG-04 MRDiscovery(us-west-2), record SRK  {SRK_EAST} -> {:?}", out.as_ref().map_err(|e| e.to_string()));
    // Control: an MRK record is expected to be rewritten.
    let out_mrk = resolve_key_store_arn(&mr_discovery("us-west-2"), MRK_EAST, BKID);
    println!("REPRO BUG-04 MRDiscovery(us-west-2), record MRK  {MRK_EAST} -> {:?}", out_mrk.as_ref().map_err(|e| e.to_string()));
    // Control: Discovery leaves the record ARN unchanged.
    let disc = KmsConfiguration::Discovery(Discovery::builder().build().unwrap());
    let out_disc = resolve_key_store_arn(&disc, SRK_EAST, BKID);
    println!("REPRO BUG-04 Discovery,              record SRK  {SRK_EAST} -> {:?}", out_disc.as_ref().map_err(|e| e.to_string()));
    println!(
        "REPRO BUG-04 SRK ARN changed by MRDiscovery: {}",
        out.as_deref().ok() != Some(SRK_EAST)
    );
}
```

The header comment of the adapted file is omitted above. It records the same API changes.

Observed output on `main` (`.agents/tasks/bug-recheck/logs/recheck04.log`):

```text
running 1 test
REPRO BUG-04 MRDiscovery(us-west-2), record SRK  arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab -> Ok("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
REPRO BUG-04 MRDiscovery(us-west-2), record MRK  arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab -> Ok("arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab")
REPRO BUG-04 Discovery,              record SRK  arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab -> Ok("arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
REPRO BUG-04 SRK ARN changed by MRDiscovery: true
test key_store::kms_ops::zz_bugrepro_04::mrdiscovery_rewrites_region_of_single_region_key ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out; finished in 0.00s
```

The output is the same as the original run at `a1e23d7` (`.agents/tasks/bug-reports/logs/bugrepro04.log`). The KMS-side failure for the rewritten single-Region ARN wasn't reproduced; it needs AWS credentials and real keys. The original report noted that the existing integration test `test_aws_kms_hierarchical_keyring_integ.rs:815-866` covers only the MRK case; that was not re-checked on `main`.

## Fix options

These options were written against `a1e23d7` and still apply on `main`. The code is now `rewrite_arn_region` and the MrDiscovery arm in `mpl/src/key_store/kms_ops.rs:100-103`, and the error type is `aws_crypto_mpl::Error` instead of `KeystoreError`.

1. Rewrite only MRK ARNs (the Dafny behavior). In `rewrite_arn_region`, or in the `MrDiscovery` arm, return the ARN unchanged unless the resource is `key/mrk-*`. Reuse or share `is_multi_region_arn` from `mrk_match.rs`.
   - Pros: cross-runtime parity, and it matches spec lines 168/204.
   - Cons: deviates from the literal text at line 669 until the spec is clarified. Negligible cost.
2. Keep the current behavior and document it. Follow line 669 literally and document that MRDiscovery requires MRK-backed records.
   - Pros: no code change.
   - Cons: keeps the difference from Dafny, which is observable with a caller-supplied KMS client, and keeps the less clear KMS error.
3. Reject non-MRK ARNs under MRDiscovery with a clear `KeystoreError`, such as "MRDiscovery requires an MRK kms-arn".
   - Pros: fails fast with a clear message instead of an opaque KMS error.
   - Cons: still diverges from Dafny, which passes the ARN through and can succeed with a caller-supplied client in the key's home region.

Recommendation: option 1, together with a spec clarification adding the MRK qualifier to `branch-key-store.md#aws-kms-branch-key-decryption`.

## Questions for the engineers

1. Which spec text is authoritative for MRDiscovery: "Any MRK ARN discovered" (lines 168/204) or the unconditional replacement at line 669? Should the spec be amended?
2. Is matching the Dafny `replaceRegion` behavior (non-MRK unchanged, unparseable unchanged) a goal for the native Rust keystore?
3. Is there an existing cross-runtime test vector with an MRDiscovery keystore and a single-Region `kms-arn` record? If not, should one be added?
4. Should the MRK predicate be shared between `mrk_match.rs` and `kms_ops.rs` rather than duplicated?
