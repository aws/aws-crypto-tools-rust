# Checklist 1: re-run (worktree /tmp/review-mahnush-verus @43b9ff7; base /tmp/review-mahnush-verus-base @6b51de8)
Logs: ./logs/{after,base}-*.log. All commands run in `<worktree>/prim`, `PATH="$HOME/verus:$PATH"`.

## Verus (prim/Makefile `verus` target = two cargo verus runs)
| Feature set | Base 6b51de8 | After 43b9ff7 |
|---|---|---|
| `cargo verus verify` (default) | `verification results:: 1858 verified, 0 errors` (vstd, dependency) then `verification results:: 10 verified, 0 errors` (aws-mpl-primitives) | `verification results:: 1858 verified, 0 errors` then `verification results:: 18 verified, 0 errors` |
| `cargo verus verify --no-default-features --features aws-lc-sys` | `10 verified, 0 errors` | `18 verified, 0 errors` |
Exit 0 for all four runs. The 1858 line is the vstd build, unchanged (after-verus-default.log:27; the crate line is :29). Crate delta: 10 -> 18 (+8 verified functions), 0 errors. No warnings in the Verus output.
Note: the Makefile has no `fips` verus run; none was done.

## Ordinary cargo (after)
- `cargo build`: exit 0 (after-build.log). Verus blocks compile to plain Rust.
- `cargo test`: exit 0. Unit 2; aes 12; constant_time 7; digest 6; ecdsa 17; error 17; random 1; hkdf 12; hmac 7; kbkdf 4; **test_wrapper_contracts 7 passed, 0 failed**; doc-tests 8. 0 failures.
- `cargo clippy --tests --examples` (default features): exit 0, 0 warnings (after-clippy-default.log).
- Base `cargo test`: exit 0; same suites minus test_wrapper_contracts (all pass). Base clippy default: exit 0.
- Unexpected-cfg: the new `[lints.rust] unexpected_cfgs ... cfg(verus_keep_ghost)` in prim/Cargo.toml keeps rustc quiet; no cfg warnings seen.

## Not verifiable here (environment, same on base)
- `cargo build/test --no-default-features --features fips` (and so `make clippy`/`make test` second half) fail with exit 101 in aws-lc-fips-sys build script: "Missing dependency: cmake" (after-build-fips.log:224). Base fails identically (base-build-fips.log, exit 101). Not caused by the branch. FIPS tests/clippy were therefore not run on either side.

## Answer
Yes: ordinary default-feature cargo build, test (incl. new test_wrapper_contracts, 7/7) and clippy pass on 43b9ff7 with no warnings; verified functions in aws-mpl-primitives went 10 -> 18 under both Verus feature sets. FIPS variants untestable (cmake missing).
