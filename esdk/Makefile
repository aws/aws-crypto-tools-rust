.PHONY: clippy test

clippy:
	cargo clippy --tests
	cargo clippy --tests --no-default-features
	cargo clippy --tests --no-default-features --features kms
	cargo clippy --tests --no-default-features --features ddb
	cargo clippy --tests --no-default-features --features legacy

test:
	cargo test
	cargo test --no-default-features
	cargo test --no-default-features --features kms
	cargo test --no-default-features --features ddb
	cargo test --no-default-features --features legacy
