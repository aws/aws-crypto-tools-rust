# Custom keyrings

A keyring decides how each message's data key is protected. The built-in
keyrings cover AWS KMS-backed hierarchies and raw AES keys; a custom keyring
puts that decision in your code — your key management, your wrapping rules.

You write the keyring in Rust, where the core ESDK lives. Your C++ code then
uses it like any other keyring. Two files show the whole path:

- `src/lib.rs` — your Rust crate defines the keyring and exports one
  `extern "C"` constructor.
- `example.cpp` — your C++ adopts the keyring and encrypts with it.

## Setup

1. Create a Rust crate that depends on `aws-esdk-cpp` with
   `crate-type = ["staticlib"]` (see this directory's `Cargo.toml`).
2. Define your keyring in Rust: anything the core ESDK accepts.
3. Export it: convert it with `aws_esdk_cpp::into_keyring_handle` and return
   the pointer from an `extern "C"` function.
4. In C++, declare that function and pass its result to
   `Aws::Esdk::Keyring::adopt`. Adopt each handle exactly once; the result
   works everywhere a keyring is accepted.

   Everything your keyring depends on (caches, clients, key material) should
   be owned by the Rust keyring itself — Rust's ownership then ties those
   lifetimes to the handle automatically. Do not reference C++ objects from
   the Rust keyring through raw pointers: nothing manages that lifetime, and
   a destroyed C++ object becomes a use-after-free inside your keyring.
5. Build. `cargo build` produces one self-contained archive — your code, the
   shim, and the core ESDK — so your C++ links a single library:

   ```
   g++ example.cpp -I<shim>/include target/debug/libcustom_keyring_example.a \
       -lpthread -ldl -std=c++17
   ```

From the shim root, `make custom_keyring_example` builds and runs this example.

## Why Rust and not C++?

Writing the keyring itself in C++ is possible — the shim could call back into
a C++ class — but we don't recommend it: every keyring call would marshal key
material across the language boundary, and your class would take on
thread-safety, lifetime, and exception-safety obligations that the Rust side
enforces at compile time. Define the keyring in Rust; call it from C++.
