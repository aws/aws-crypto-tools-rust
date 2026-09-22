# esdk-cpp-test-server

The ESDK TestServer **C++-shim Language_Server**: a hand-rolled rpcv2Cbor HTTP
server that speaks the same commons contract as the Rust Language_Server
(`../esdk-test-server`) but runs every crypto operation through the
[`aws-esdk-cpp`](../esdk/shims/aws-esdk-cpp) C++ facade
(`aws/esdk/EncryptionSDK.h`). It is what proves the C++ shim interoperates with
the other languages' ESDKs.

## Layout

- rpcv2Cbor transport, wire model, and error shape are reused from the Rust
  Language_Server crate (`aws-esdk-test-server`).
- `src/seam.cpp` is a C ABI over the `Aws::Esdk::` facade; `src/seam.rs` wraps it.
- `src/backend.rs` builds a hierarchical keyring through the shim and forwards
  `Encrypt`/`Decrypt` on `spawn_blocking` (the shim drives its own runtime).

The C++ facade currently exposes only the AWS KMS Hierarchical keyring, so the
server accepts the Default CMM wrapping an `AwsKmsHierarchical` keyring and
rejects other keyrings.

## Build and test

`build.rs` builds the `aws-esdk-cpp` shim (its cdylib + generated cxx bridge),
compiles the seam, and links against the cdylib.

```
make build-server   # cargo build --release
make test           # unit + integration tests
```

The `hierarchical_round_trip` integration test needs AWS credentials and a
provisioned key store, supplied via `ESDK_TEST_*` env vars
(`ESDK_TEST_KMS_KEY_ARN`, `ESDK_TEST_DDB_TABLE`, `ESDK_TEST_LOGICAL_KEYSTORE`,
`ESDK_TEST_BRANCH_KEY_ID`, `ESDK_TEST_REGION`); it SKIPs when they are unset.

## Cross-language run

`make test-server` clones commons at the branch in `commons-configuration.json`
and delegates to its orchestrator, which launches this server and runs the Java
Tests matrix against it. Needs AWS credentials and a JDK 21+.
