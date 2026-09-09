.PHONY: clippy test deny

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

deny:
	cargo deny --config ../deny.toml check advisories || true
	cargo deny --config ../deny.toml check bans licenses sources
