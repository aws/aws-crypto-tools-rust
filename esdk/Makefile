.PHONY: clippy test duvet

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

# `duvet report` regenerates .duvet/snapshot.txt locally; in CI (CI is set),
# --ci compares coverage against the committed snapshot and fails on a drop.
duvet:
	@test -e spec || ln -s ../spec spec
	rm -rf .duvet/reports .duvet/requirements
	duvet report $(if $(CI),--ci)
