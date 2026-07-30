# ESDK Rust Hierarchical Keyring Performance Benchmark

Performance benchmark for the native Rust AWS Encryption SDK (`aws-esdk`),
exercising encrypt/decrypt through an AWS KMS Hierarchical Keyring.

## What it measures

- **Throughput**: operations per second, MiB/s, and latency (P50/P95/P99).
- **Memory**: peak memory delta and efficiency ratio during an operation.
- **Concurrency**: parallel throughput across multiple workers.

The single payload size under test is configured in
[`config/test-scenarios.yaml`](config/test-scenarios.yaml). It is a
list, so additional sizes can be added; it defaults to one 50 MiB entry.

## Keyring

The benchmark uses an AWS KMS Hierarchical Keyring backed by the shared AWS
Crypto Tools test key store (DynamoDB + KMS) in `us-west-2`. Warmup iterations
prime the branch-key cache so measured runs reflect the SDK crypto path rather
than the initial KMS/DynamoDB round trip.

## Prerequisites

- Rust (stable).
- AWS credentials for the account hosting the test key store (CI assumes the
  public ESDK CI role via GitHub OIDC).

## Run

```bash
# Full run
cargo run --release

# Quick run (reduced iterations; used by CI)
cargo run --release -- --quick
```

Results are written to `results/raw-data/rust_results.json`. In CI they
are also published to CloudWatch Logs.

## Command line

- `--config`: path to the YAML config (default `config/test-scenarios.yaml`).
- `--output`: results output path (default `results/raw-data/rust_results.json`).
- `--quick`: quick mode (requires a `quick_config` section in the YAML).

Set `RUST_LOG=debug` for verbose logging.
