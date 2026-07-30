# ESDK C++ Hierarchical Keyring Performance Benchmark

Performance benchmark for the C++ shim over the native Rust AWS Encryption SDK,
exercising encrypt/decrypt through an AWS KMS Hierarchical Keyring
(`Aws::Esdk::EncryptionSDK` and `Aws::Esdk::HierarchicalKeyring`).

## What it measures

- **Throughput**: operations per second, bytes/s, and latency (P50/P95/P99).
- **Memory**: peak resident-memory delta and efficiency ratio during an operation.
- **Concurrency**: parallel throughput across multiple worker threads.

The payload size is 50 MiB, matching the Rust benchmark so both plot on the
same CloudWatch series. Results carry language `rust-cpp`.

## Keyring

The benchmark uses an AWS KMS Hierarchical Keyring backed by the shared AWS
Crypto Tools test key store (DynamoDB + KMS) in `us-west-2`. Warmup iterations
prime the branch-key cache so measured runs reflect the SDK crypto path rather
than the initial KMS/DynamoDB round trip.

## Prerequisites

- A C++17 compiler, Rust (stable), and Go (to build `aws-lc-sys`).
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
# Full run
make run

# Quick run (reduced iterations; used by CI)
make run ARGS="--quick"
```

Results are written to `results/raw-data/cpp_results.json`. In CI they are also
published to CloudWatch Logs.

## Command line

- `--output`: results output path (default `results/raw-data/cpp_results.json`).
- `--quick`: quick mode (reduced warmup and measurement iterations).
