# aws-crypto-test-vectors

`aws-crypto-test-vectors` is a CLI runner that generates and consumes test-vector
manifests for the AWS Crypto Tools Rust crates (`mpl`).

It is modeled after the Dafny-based
[`TestVectorsAwsCryptographicMaterialProviders`](https://github.com/aws/aws-cryptographic-material-providers-library/tree/main/TestVectorsAwsCryptographicMaterialProviders)
tool that ships with the MPL. The manifest format is byte-compatible with the
JSON produced by that tool so cross-language test artifacts can be exchanged.

This crate is intended for internal development and CI use only. **Do not take a
standalone dependency on this library.**

## Building

```bash
cd test-vectors
cargo build
```

## CLI

The `test-vectors` binary provides four subcommands. Every command that touches
a project takes a `--project` flag selecting which crate's vectors to operate
on (currently only `mpl`).

### `list`

List the projects registered in this build.

```bash
cargo run --bin test-vectors -- list
```

### `encrypt-manifest`

Generate an encrypt manifest describing every test vector the selected project
knows how to produce. Writes `manifest.json` and `keys.json` into `--output`.

```bash
cargo run --bin test-vectors -- encrypt-manifest \
    --project mpl \
    --output ./vectors/mpl-encrypt/
```

### `encrypt`

Read an encrypt manifest, run each encrypt test vector, and emit a decrypt
manifest capturing the produced ciphertexts and expected decrypt results.

```bash
cargo run --bin test-vectors -- encrypt \
    --project mpl \
    --manifest-path ./vectors/mpl-encrypt/ \
    --decrypt-manifest-output ./vectors/mpl-decrypt/
```

### `decrypt`

Read a decrypt manifest and verify every decrypt test vector.

```bash
cargo run --bin test-vectors -- decrypt \
    --project mpl \
    --manifest-path ./vectors/mpl-decrypt/
```

Any subcommand accepts an optional `--test-name` to restrict execution to a
single vector by UUID.

## Checked-in manifests

Reference manifests produced by this crate live under
[`manifests/`](./manifests/):

```
manifests/
├── encrypt/
│   ├── manifest.json    # awses-mpl-encrypt, 11 hierarchy vectors, one per ESDK suite
│   └── keys.json        # keys the vectors reference (currently just static-branch-key-1)
└── decrypt/
    ├── manifest.json    # awses-mpl-decrypt, produced by running encrypt/ end-to-end
    └── keys.json        # byte-identical copy of encrypt/keys.json
```

Regenerate at any time with:

```bash
cd test-vectors
cargo run --bin test-vectors -- encrypt-manifest \
    --project mpl --output ./manifests/encrypt/
cargo run --bin test-vectors -- encrypt \
    --project mpl \
    --manifest-path ./manifests/encrypt/ \
    --decrypt-manifest-output ./manifests/decrypt/
cargo run --bin test-vectors -- decrypt \
    --project mpl --manifest-path ./manifests/decrypt/
```

> **Note — regeneration stability.**
>
> * The **encrypt manifest** is fully byte-stable across regeneration. Vector
>   IDs are v5 UUIDs derived from the vector's canonical JSON under a fixed
>   project namespace (see `manifest::vector_uuid`), so re-running
>   `encrypt-manifest` produces byte-identical `encrypt/manifest.json`.
> * The **decrypt manifest** keeps the same set of vector UUIDs across
>   regeneration, but the emitted `encryptedDataKeys[*].ciphertext` and
>   `result.plaintextDataKey` change on every run — AES-GCM chooses a random
>   IV per encryption and the branch-key wrap picks a fresh data key. Each
>   emitted decrypt manifest is one valid execution of the corresponding
>   encrypt vector, not a canonical fixture.

## Manifest Format

The manifest format mirrors the JSON schema produced by the MPL Dafny tool:

```json
{
  "manifest": { "version": 4, "type": "awses-mpl-encrypt" },
  "keys":     "file://keys.json",
  "tests": {
    "<uuid>": {
      "type": "positive-keyring",
      "description": "...",
      "algorithmSuiteId": "0478",
      "encryptKeyDescription": { "type": "aws-kms-hierarchy", "key": "static-branch-key-1" },
      "decryptKeyDescription": { "type": "aws-kms-hierarchy", "key": "static-branch-key-1" },
      "encryptionContext": {}
    }
  }
}
```

Decrypt manifests use `type = "awses-mpl-decrypt"`, include a top-level `client`
field, and each vector carries the `encryptedDataKeys` and expected `result`
required to verify decryption.

The concrete Rust types live under `src/manifest/` and round-trip through
`serde_json` with insertion-ordered maps (`indexmap::IndexMap`) so generated
output remains diff-friendly.

## Adding a New Project

1. Create a module under `src/projects/<name>.rs`.
2. Implement the `Project` trait from `src/projects/mod.rs`.
3. Register it in `Registry::default()` inside `src/projects/mod.rs`.

The trait has three hooks matching the CLI subcommands: `generate_manifest`,
`run_encrypt`, and `run_decrypt`. Each may return
`TestVectorError::NotImplemented` while the project's implementation is being
brought up — the CLI surfaces this cleanly to the caller.
