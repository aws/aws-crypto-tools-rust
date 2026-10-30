# ESDK C++ Performance Benchmark

Performance benchmark for the C++ shim over the native Rust AWS Encryption SDK,
exercising encrypt/decrypt through `Aws::Esdk::Client` with a selectable
keyring.

## What it measures

- **Throughput**: operations per second, bytes/s, and latency (P50/P95/P99).
- **Memory**: peak resident-memory delta and efficiency ratio during an operation.
- **Concurrency**: parallel throughput across multiple worker threads.

Payload sizes are 1 KiB, 1 MiB, and 50 MiB, matching the Rust benchmark
scenarios so both plot on the same CloudWatch series. Results carry language
`rust-cpp`.

## Keyrings

Selected with `--keyring`:

- `hierarchical` (default): AWS KMS Hierarchical Keyring
  (`Aws::Esdk::HierarchicalKeyring`) backed by the shared AWS Crypto Tools test
  key store (DynamoDB + KMS) in `us-west-2`. Warmup iterations prime the
  branch-key cache so measured runs reflect the SDK crypto path rather than the
  initial KMS/DynamoDB round trip. Requires AWS credentials and the environment
  variables below.
- `raw-aes`: Raw AES Keyring (`Aws::Esdk::RawAesKeyring`) with a fixed 256-bit
  wrapping key. Wraps data keys locally, so it needs no AWS resources or
  credentials.

## Prerequisites

- A C++17 compiler, Rust (stable), and Go (to build `aws-lc-sys`).
- For the hierarchical keyring only:
  - AWS credentials for the account hosting the test key store (CI assumes the
    public ESDK CI role via GitHub OIDC).
  - The key store coordinates, supplied through environment variables. When any
    required variable is unset the benchmark prints `SKIP` and exits 0:

    ```
    ESDK_TEST_KMS_KEY_ARN       KMS key ARN backing the key store
    ESDK_TEST_DDB_TABLE         DynamoDB table name of the key store
    ESDK_TEST_LOGICAL_KEYSTORE  logical key store name
    ESDK_TEST_BRANCH_KEY_ID     branch key id provisioned in the key store
    ESDK_TEST_REGION            (optional) AWS region, e.g. us-west-2
    ```

## Run

```bash
# Full run (hierarchical keyring)
make run

# Raw AES keyring
make run ARGS="--keyring raw-aes"

# Quick run (reduced iterations; used by CI)
make run ARGS="--quick"
```

Results are written to `results/raw-data/cpp_results.json`. In CI they are also
published to CloudWatch Logs, one log stream per keyring.

## Command line

- `--output`: results output path (default `results/raw-data/cpp_results.json`).
- `--keyring`: keyring to benchmark, `hierarchical` (default) or `raw-aes`.
- `--quick`: quick mode (reduced warmup and measurement iterations).
