# Implementation Notes — mpl-client

## Output Root
Real source tree: `mpl/src/` and `mpl/tests/`

## Integration Obligation
Code must compile with the existing crate structure.

## File Count
- New: `mpl/src/commitment_policy.rs` (enum definitions + annotations)
- Modified: `mpl/src/lib.rs` (add module + re-export)
- Modified: `mpl/src/client.rs` (add field + validation)
- Modified: `mpl/tests/test_mpl_client.rs` (fix dead line + add tests)

## Plan

### Requirements to implement (exact quotes from TOMLs):

1. `supported-format-commitment-policy-enum.toml` [[spec]] level=MUST:
   "The Material Providers Library MUST provide\na distinct commitment policy ENUM for each format."
   → Define `EsdkCommitmentPolicy` and `DbeCommitmentPolicy` enums

2. `supported-commitment-policy-enum.toml` [[spec]] level=MUST:
   "The Material Providers Library also MUST provide\na union ENUM for all distinct commitment policy ENUMs\ncalled the Commitment Policy ENUM."
   → Define `CommitmentPolicy` enum wrapping both

### Requirements to mark as todo (behavioral, out of scope):

3. esdk-forbid-encrypt-allow-decrypt: 3 behavioral MUSTs
4. esdk-require-encrypt-allow-decrypt: 3 behavioral MUSTs
5. esdk-require-encrypt-require-decrypt: 3 behavioral MUSTs
6. dbe-require-encrypt-require-decrypt: 3 behavioral MUSTs

### Config + validation:
- Add `commitment_policy: CommitmentPolicy` field to `MaterialProvidersConfig`
- Default to `CommitmentPolicy::Esdk(EsdkCommitmentPolicy::RequireEncryptRequireDecrypt)`
- Validate in `build()` (DBE only allows RequireEncryptRequireDecrypt — already true by enum, but validate anyway)

### Test fixes:
- Fix dead `let _ = MaterialProviders::default()` line
- Add type=test annotations for the two ENUM requirements
- Add error-path test for InvalidConfig
