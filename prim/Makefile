.PHONY: clippy test verus

# The `fips` variants pass `--no-default-features` because `fips` overrides the
# backend rather than adding to it: with `default` still enabled, `aws-lc-rs`
# links `aws-lc-fips-sys` and compiles `aws-lc-sys` for nothing. These match the
# commands CI runs.

clippy:
	cargo clippy --tests --examples
	cargo clippy --tests --examples --no-default-features --features fips

test:
	cargo test
	cargo test --no-default-features --features fips

# Verify the verus! blocks in src/ with cargo-verus (installed at ~/verus).
# The aws-mpl-primitives "verification results::" line must read "N verified, 0 errors".
verus:
	PATH="$(HOME)/verus:$$PATH" cargo verus verify
	# aws-lc-rs needs a crypto backend, so the minimal build keeps aws-lc-sys (as CI does).
	PATH="$(HOME)/verus:$$PATH" cargo verus verify --no-default-features --features aws-lc-sys
