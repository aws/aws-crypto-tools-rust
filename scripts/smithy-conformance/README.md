# Smithy conformance

Checks that the public Rust API of every published crate here (`aws-mpl-primitives`,
`aws-crypto-mpl`, `aws-esdk`, and any added later) matches the Smithy models it
implements, and lints rules that keep later changes non-breaking.

```
python3 scripts/smithy-conformance/conform.py
```

Needs Python 3.11+, git, and a nightly Rust toolchain
(`rustup toolchain install nightly`) for rustdoc JSON. The pinned Smithy CLI and model
repos are downloaded to `~/.cache/smithy-conformance`.

It exits 0 when every difference from the model is accepted in `config.toml` with a
reason. It writes `report.md`, `findings.json`, and `review.html`, a page to review each
difference, to `~/.cache/smithy-conformance/run` (`--out` to change). `--reuse` skips
rebuilding what is already there.

`--crate esdk` reports and fails only on one crate (every crate is still built, to match
model services to crates). CI runs one such job per crate; `--list` prints the crates.
Each job's summary shows its result, and its artifact holds the report and review page.

To accept a difference, add a `[[deviation]]` with its finding id and reason; see
`config-format.md`. To record decisions made on `review.html`, export them and run
`apply_decisions.py config.toml <decisions.json>`.
