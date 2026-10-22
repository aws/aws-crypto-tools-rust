# ESDK TestServer — Rust Language_Server

A hand-rolled [rpcv2Cbor](https://smithy.io/2.0/additional-specs/protocols/smithy-rpc-v2.html)
HTTP server that implements the ESDK TestServer Smithy contract and delegates
each operation to the AWS Encryption SDK for Rust (`aws-esdk`) built from this
repository's head.

## Embedded reference to the commons TestServer

The single source of truth for the wire contract — the Smithy model, the one
generated Test_Client, and the one Tests suite — lives in the commons repo:

- Repository: [`aws/aws-crypto-tools-commons`](https://github.com/aws/aws-crypto-tools-commons)
- Model: `esdk/test-server/model/esdk-test-server.smithy`
- Tests: `esdk/test-server/tests`
- Integration branch (during bootstrap): `kessplas/esdk-test-server`

This repo hosts only the Rust Language_Server; it consumes the commons contract.
The commons Configuration_Set carries a `rust` entry pointing back at this repo's
`main` head, closing the loop described in the TestServer factoring design.

## What it speaks

- `POST /service/ESDKTestServer/operation/{Operation}`
- Header `smithy-protocol: rpc-v2-cbor`, `Content-Type: application/cbor`
- CBOR map request/response bodies; errors as a CBOR map `{__type, message}`
- Operations: `CreateClient`, `Encrypt`, `Decrypt`, `EncryptStream`, `DecryptStream`

## Running

```bash
make run-server PORT=8092        # foreground
# or, orchestrated:
make start-server PORT=8092
make wait-for-server PORT=8092
make stop-server PORT=8092
make check                       # fmt + clippy + build + test (the CI gate)
```

## Keyrings

The server supports the Raw AES and AWS KMS Hierarchical keyrings, both built through the MPL.
`CreateClient` returns `GenericServerError` when it rejects a keyring configuration.
`Encrypt`, `Decrypt`, and their streaming forms return `ESDKClientError` when the ESDK fails.

## Layout

`src/model.rs` (shapes), `src/wire.rs` (protocol), `src/keyring.rs`
(config→MPL mapping), `src/handlers.rs` (delegation + client registry).
