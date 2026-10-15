# aws-esdk-cpp

C++ shim for the AWS Encryption SDK for Rust.

The AWS Encryption SDK is a client-side encryption library that makes it easier
to encrypt and decrypt data using industry standards and best practices. It uses
envelope encryption: your data is protected with a data key, and that data key is
protected by one or more wrapping keys held in a _keyring_. The encrypted data
keys travel alongside the ciphertext, so you don't track them separately.

This package is a thin C++ layer over the native Rust ESDK (`aws-esdk`). The C++
glue is generated with [cxx](https://cxx.rs); `cargo build` compiles the Rust
core into a static library and emits the generated C++ sources, and everything is
exposed to consumers as a single linkable target. C++ callers work entirely
through the public types in
[`include/aws/esdk/EncryptionSDK.h`](include/aws/esdk/EncryptionSDK.h) under the
`Aws::Esdk` namespace.

## Prerequisites

- A C++17 compiler.
- Rust and `cargo` to compile the Rust core.
- [Go](https://go.dev/). (A transitive crypto dependency (`aws-lc-sys`) builds it
  from source during `cargo build`.)
- CMake 3.20+, if you consume the library through CMake.
- AWS credentials, a KMS key, and a DynamoDB table for the hierarchical-keyring
  paths (see [Optional prerequisites](#optional-prerequisites)).

## Building

From this directory:

```bash
cargo build
```

That produces the static library and the cxx-generated C++ sources under
`target/`, which the `AWS::esdk` CMake target and the `Makefile` example/test
targets consume.

## Using it in a CMake project

```cmake
add_subdirectory(aws-esdk-cpp)
target_link_libraries(my_app PRIVATE AWS::esdk)
```

```cpp
#include <aws/esdk/EncryptionSDK.h>
```

See [`CMakeLists.txt`](CMakeLists.txt) for how the target is assembled.

Build the library from source together with your application, as `add_subdirectory` does.
Releases keep source compatibility, not binary compatibility:
after upgrading, rebuild everything that includes `EncryptionSDK.h`.

## Quick example

A one-shot encrypt/decrypt round trip with a Raw AES keyring:

```cpp
#include <aws/esdk/EncryptionSDK.h>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

int main() {
    // For demonstration only: a real application must source its wrapping key
    // from a secure store and never hardcode it.
    std::vector<std::uint8_t> wrapping_key(32, 0x01);
    auto keyring = Aws::Esdk::RawAesKeyring(
        "my-key-namespace", "my-key-name", wrapping_key,
        Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);

    // The encryption context is authenticated, not encrypted, and is bound to
    // the message.
    std::map<std::string, std::string> encryption_context = {{"purpose", "readme-example"}};

    Aws::Esdk::Client esdk;

    auto enc = esdk.encrypt(
        std::string_view("the quick brown fox"), keyring,
        Aws::Esdk::EncryptOptions().with_encryption_context(encryption_context));

    auto dec = esdk.decrypt(
        enc.ciphertext, keyring,
        Aws::Esdk::DecryptOptions().with_encryption_context(encryption_context));

    // dec.plaintext now holds the original bytes.
}
```

`encrypt` and `decrypt` accept the payload as a `std::vector`, a `std::string_view`, a
`std::span` (when available), or a raw pointer and length; `decrypt` also accepts
`Aws::Esdk::Bytes`. You can pass a buffer (for example an mmap'd file) without
copying it first. The streams' `write()` takes the same forms except `std::span`:
a `std::vector`, a `std::string_view`, or a raw pointer and length, and the decrypt
stream also takes `Aws::Esdk::Bytes`.

## Streaming

The shim provides streaming APIs for data too large to hold in memory,
or that does not arrive all at once:

- `encrypt_stream` / `decrypt_stream` read from a `std::istream` and write to a
  `std::ostream` in bounded memory
- `create_encrypt_stream` / `create_decrypt_stream` give you a lower-level
  `write()`/`finish()` interface to drive the operation chunk by chunk, for when
  your data is not an iostream.

Security note: streamed decrypt releases plaintext before the message is fully
verified. It returns normally only if the whole message authenticates; if it
throws, discard everything it produced. Streamed decrypt also cannot handle a
multi-frame message under a signing suite; decrypt those with the one-shot
`decrypt` instead.

## Examples

Runnable examples live under [`examples/`](examples/). Each has a build target in
the [`Makefile`](Makefile); run `make <target>` to compile it, then run the
resulting binary, for example:

```bash
make streaming_example
./streaming_example
```

`make handling_errors_example` builds an example of handling the exceptions that a
hierarchical keyring encrypt and decrypt throw.

Examples that use the hierarchical keyring need AWS credentials, a KMS key, and a
DynamoDB table; the rest run offline. The custom keyring has its own walkthrough
in [`examples/custom-keyring/README.md`](examples/custom-keyring/README.md).

## Tests and coverage

The `Makefile` drives both the Rust and C++ suites:

```bash
make test          # full local suite without credentials
make test-ci-rust  # Rust unit tests only
make test-ci-cpp   # build and run the C++ suites
```

All Rust tests are offline unit tests covering the translation layer.
The credentialed integration tests (real KMS and DynamoDB) are C++.

Line coverage is measured against the Rust core (`src/lib.rs`):

```bash
make coverage           # offline Rust unit tests
make coverage-cpp       # unions the offline tests with the credentialed C++ run
make coverage-cpp-html  # same union, as HTML
```

## Specification

This shim adheres to a written [specification](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/shim/esdk-shim.md).


The shim's source code and tests are annotated with [Duvet](https://github.com/awslabs/duvet) citations
(the `//= ` and `//# ...` comments) that tie each spec requirement to the code satisfying it.
Generate the compliance report with:

```bash
make duvet
```

It writes an HTML report under `.duvet/reports`.

## Optional prerequisites

### AWS integration

You don't need an AWS account to use the raw-AES or streaming paths.
However, the hierarchical keyring requires an AWS account, a KMS key, and a DynamoDB table.

- **To create an AWS account**, go to [Sign In or Create an AWS Account](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html).
- **To create a symmetric encryption KMS key**, see [Creating Keys](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html).

## FAQ

See the [Frequently Asked Questions](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/faq.html) page in the official documentation.

## Security

If you discover a potential security issue in this project
we ask that you notify AWS/Amazon Security via our
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).
Please **do not** create a public GitHub issue.

## License

This project is licensed under the Apache-2.0 License.
