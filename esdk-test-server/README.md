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
- Operations: `CreateClient`, `Encrypt`, `Decrypt`. `EncryptStream` / `DecryptStream`
  return `GenericServerError` (this server is non-streaming).

## Running

```bash
make run-server PORT=8092        # foreground
# or, orchestrated:
make start-server PORT=8092
make wait-for-server PORT=8092
make stop-server PORT=8092
make check                       # fmt + clippy + build + test (the CI gate)
```

## Current status: offline Raw-AES, at the keyring wall

The offline Raw-AES / Default-CMM path is wired end to end. Constructing the
keyring delegates to the vendored Material Providers Library, whose
`create_raw_aes_keyring` (and every other keyring constructor) is not yet
implemented. `CreateClient` therefore surfaces an `ESDKClientError` naming the
missing constructor — asserted by `tests/keyring_wall.rs`.

Because keyring construction is not yet available, the commons Configuration_Set
entry for `rust` is marked `skip: true`; the cross-repo Java Tests round trip is
enabled (flip `skip` to `false`) once the Rust ESDK implements keyrings.

## How it was built

Following the `smithy-to-handrolled-server` skill: read the model, translate each
shape via the Smithy→Rust type table, hand-roll the rpcv2Cbor codec, route by
operation name, and delegate to the real SDK. See `src/model.rs` (shapes),
`src/wire.rs` (protocol), `src/keyring.rs` (config→MPL mapping), and
`src/handlers.rs` (delegation + client registry).
