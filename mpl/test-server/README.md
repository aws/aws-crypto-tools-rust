# MPL TestServer — Rust Language_Server

A hand-rolled [rpcv2Cbor](https://smithy.io/2.0/additional-specs/protocols/smithy-rpc-v2.html)
HTTP server that implements an MPL TestServer contract and delegates
each operation to the Material Providers Library (`aws-crypto-mpl`)
built from this repository's head.

## What it speaks

- `POST /service/MPLTestServer/operation/{Operation}`
- Header `smithy-protocol: rpc-v2-cbor`, `Content-Type: application/cbor`
- CBOR map request/response bodies; errors as a CBOR map `{__type, message}`
- Operations: `CreateRawAesKeyring`, `CreateDefaultCmm`,
  `GetEncryptionMaterials`, `DecryptMaterials`.

## Running

```bash
make run-server PORT=8093        # foreground
# or, orchestrated:
make start-server PORT=8093
make wait-for-server PORT=8093
make stop-server PORT=8093
make check                       # fmt + clippy + build + test (the CI gate)
```

## Layout

`src/model.rs` (shapes), `src/wire.rs` (protocol), `src/handlers.rs`
(multi-type registry + delegation to `aws-crypto-mpl`), `src/error.rs`
(modeled errors).
