# Primitives TestServer — Rust Language_Server

A hand-rolled [rpcv2Cbor](https://smithy.io/2.0/additional-specs/protocols/smithy-rpc-v2.html)
HTTP server that implements a Primitives TestServer contract and delegates
each operation to the cryptographic primitives crate (`aws-mpl-primitives`)
built from this repository's head.

## What it speaks

- `POST /service/PrimitivesTestServer/operation/{Operation}`
- Header `smithy-protocol: rpc-v2-cbor`, `Content-Type: application/cbor`
- CBOR map request/response bodies; errors as a CBOR map `{__type, message}`
- Operations: `AesEncrypt`, `AesDecrypt`, `GenerateRandomBytes`, `Digest`,
  `Hmac`, `Hkdf`, `KbkdfCtrHmac`, `EcdsaGenerateKeyPair`, `EcdsaSign`,
  `EcdsaVerify`.

## Running

```bash
make run-server PORT=8094        # foreground
# or, orchestrated:
make start-server PORT=8094
make wait-for-server PORT=8094
make stop-server PORT=8094
make check                       # fmt + clippy + build + test (the CI gate)
```

## Layout

`src/model.rs` (shapes), `src/wire.rs` (protocol), `src/handlers.rs`
(stateless delegation to `aws-mpl-primitives`), `src/error.rs` (modeled errors).
