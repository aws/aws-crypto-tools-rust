# Custom keyrings

A keyring decides how each message's data key is protected.
AWS provides a set of keyrings that meet most use cases.
If your use case is not covered by AWS-provided keyrings, 
you can implement your own.

To use a custom keyring with the C++ shim for the AWS Encryption SDK for Rust,
you must write a keyring implementation in Rust.
Your C++ code then uses it like any other keyring.

This example demonstrates creating a Rust keyring and using it from C++ code.

- `src/lib.rs` — Rust crate defining the keyring and exporting it as an extern
- `example.cpp` — C++ code adopting the keyring and using it

## Setup

1. Create a Rust crate for your keyring.
   This crate must depend on `aws-esdk-cpp` with `crate-type = ["staticlib"]`.
   See this directory's `Cargo.toml` for an example.
2. In Rust, define your keyring. See `src/lib.rs`' `RequireContextKeyring` for an example: it wraps a raw AES keyring and refuses any message whose encryption context lacks a `department` key.
3. In Rust, export your keyring.
   Convert it with `aws_esdk_cpp::into_keyring_handle` and return the pointer from an `extern "C"` function.
   See `src/lib.rs`' `custom_keyring_create` for an example.
4. In C++, call that function (here, `custom_keyring_create`)
   and pass its result to `Aws::Esdk::Keyring::adopt`.
   See `example.cpp` for an example.
5. Build. `cargo build` produces one self-contained archive — your code, the
   shim, and the core ESDK — so your C++ links a single library:

   ```
   g++ example.cpp -I<shim>/include target/debug/libcustom_keyring_example.a \
       -lpthread -ldl -std=c++17
   ```

   This is the one build difference: without a custom keyring you link the shim's
   own archive, but here you link the archive your `cargo build` produced, since
   it's what contains your keyring.

From the shim root, `make custom_keyring_example` builds and runs this example.

## Notes

### Handle Safety

* Do not adopt each keyring handle more than once. If you need multiple keyrings, create multiple handles.
  e.g., do NOT do:
  ```
  void* handle = custom_keyring_create();
  auto keyring1 = Aws::Esdk::Keyring::adopt(handle);
  auto keyring2 = Aws::Esdk::Keyring::adopt(handle);
  ```
  You MAY do:
  ```
  void* handle1 = custom_keyring_create();
  auto keyring1 = Aws::Esdk::Keyring::adopt(handle1);
  void* handle2 = custom_keyring_create();
  auto keyring2 = Aws::Esdk::Keyring::adopt(handle2);
  ```
* Everything your keyring depends on (e.g. caches, clients, key material) should be owned by the Rust keyring itself. Rust's ownership ties those lifetimes to the handle automatically so you don't need to manage them.
* Do not reference C++ objects from the Rust keyring through raw pointers. Nothing manages that lifetime. A destroyed C++ object will become a use-after-free inside your keyring.

### Why do I need to write this in Rust? Why not C++?

Writing the keyring itself in C++ is possible, but we don't recommend it.
Your shim could call back into a C++ class if you really need to
(for example, if your key material is only reachable in C++).
Even then, we'd suggest writing a Rust keyring
that makes a minimal, fast callback into that C++ code
rather than implementing the whole keyring in C++.
