# Implementation Summary: mpl-client

## Files Modified

| File | Action |
|------|--------|
| `.duvet/config.toml` | Created — duvet infrastructure config |
| `compliance/spec/framework/commitment-policy/*.toml` | Generated — 6 TOML files via `duvet extract` |
| `mpl/src/commitment_policy.rs` | Created — ESDK, DBE, and union CommitmentPolicy enums with annotations |
| `mpl/src/lib.rs` | Modified — added `commitment_policy` module + re-exports |
| `mpl/src/client.rs` | Modified — added `commitment_policy` field to config, builder setter, `build()` validation |
| `mpl/src/error.rs` | Modified — removed `#[non_exhaustive]` from variant, added module doc |
| `mpl/tests/test_mpl_client.rs` | Rewritten — fixed dead `let _` line, added annotated tests |
| `.duvet/snapshot.txt` | Generated — duvet coverage snapshot |

## Requirements Covered (implementation + test)

1. **`supported-format-commitment-policy-enum`** (MUST): "The Material Providers Library MUST provide a distinct commitment policy ENUM for each format."
   - Implementation: `EsdkCommitmentPolicy` + `DbeCommitmentPolicy` enums in `commitment_policy.rs`
   - Test: `test_esdk_commitment_policy_enum_variants` in `test_mpl_client.rs`

2. **`supported-commitment-policy-enum`** (MUST): "The Material Providers Library also MUST provide a union ENUM for all distinct commitment policy ENUMs called the Commitment Policy ENUM."
   - Implementation: `CommitmentPolicy` enum in `commitment_policy.rs`
   - Test: `test_commitment_policy_union_enum` in `test_mpl_client.rs`

## Todo-Tracked Follow-ups (12 behavioral MUSTs)

All marked `type=todo` with `tracking-issue=commitment-policy-behavior`:

- `esdk-forbid-encrypt-allow-decrypt`: 3 MUSTs (default algorithm suite, Get Encryption Materials, Decrypt Materials)
- `esdk-require-encrypt-allow-decrypt`: 3 MUSTs (default algorithm suite, Get Encryption Materials, Decrypt Materials)
- `esdk-require-encrypt-require-decrypt`: 3 MUSTs (default algorithm suite, Get Encryption Materials, Decrypt Materials)
- `dbe-require-encrypt-require-decrypt`: 3 MUSTs (default algorithm suite, Get Encryption Materials, Decrypt Materials)

These depend on `algorithm-suites.md` and `cmm-interface.md` which are not implemented in this crate yet.

## Additional Fixes (from Round 1 review findings)

- **Dead code fixed**: `let _ = MaterialProviders::default()` replaced with assertion that verifies the default config
- **Error::InvalidConfig wired up**: `build()` validates DBE commitment policy; `Error::InvalidConfig` is constructable and tested
- **Config field added**: `MaterialProvidersConfig.commitment_policy` is a real field with a safe default (`ESDK.REQUIRE_ENCRYPT_REQUIRE_DECRYPT`)

## Verification Results

```
$ cargo check
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.17s

$ cargo clippy -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.13s

$ cargo test
running 8 tests
test test_builder_dbe_valid_policy ... ok
test test_builder_commitment_policy_setter ... ok
test test_esdk_commitment_policy_enum_variants ... ok
test test_commitment_policy_union_enum ... ok
test test_builder_invalid_config_error ... ok
test test_mpl_builder ... ok
test test_mpl_builder_with_config ... ok
test test_mpl_default_uses_default_config ... ok
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ duvet report
  Extracted requirements from 1 specifications
  Scanned 17 sources
  Parsed 46 annotations
  Matched 58 references
```

## Proposed Commit Message

```
feat(mpl): add commitment-policy enums with duvet coverage

- Set up duvet infrastructure (.duvet/config.toml + compliance TOMLs)
- Implement EsdkCommitmentPolicy, DbeCommitmentPolicy, and CommitmentPolicy union enums
- Add commitment_policy field to MaterialProvidersConfig with safe default
- Wire Error::InvalidConfig into build() validation
- Add type=test annotations for both MUST ENUM requirements
- Mark 12 behavioral MUSTs as type=todo (depend on algorithm-suites/cmm-interface)
- Fix dead test statement and improve test coverage
```

## Round 2 (MAY handling)

### What was done

The single remaining "Not implemented" requirement — the MAY requirement in `supported-commitment-policy-enum` — was annotated using the `implementation` + `test` route:

- **Quote**: `This means that different formats MAY have duplicate Format Commitment Policy ENUM.`
- **Rationale**: The union design already satisfies this: both `EsdkCommitmentPolicy::RequireEncryptRequireDecrypt` and `DbeCommitmentPolicy::RequireEncryptRequireDecrypt` carry the same format-level enum name. The `CommitmentPolicy` union allows both to coexist as `Esdk(RequireEncryptRequireDecrypt)` and `Dbe(RequireEncryptRequireDecrypt)`.

### Changes

| File | Change |
|------|--------|
| `mpl/src/commitment_policy.rs` | Added plain implementation annotation for the MAY quote co-located with the existing MUST annotation on the `CommitmentPolicy` union enum |
| `mpl/tests/test_mpl_client.rs` | Added `test_duplicate_format_commitment_policy_enum_across_formats` with `type=test` annotation |

### Verification

```
$ duvet query --check implementation --check test
  Not implemented: 0
  TODO: 24
  Fully implemented: 6
  Tests: Fully tested: 3

$ cargo check — OK
$ cargo test — 9 tests pass
$ cargo clippy -- -D warnings — OK
```
