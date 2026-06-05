# Git hooks

This directory contains git hooks shared with all contributors. They are
not active by default — git only looks here if the repo is configured to.

## Enable

Run this once after cloning:

```bash
git config core.hooksPath .githooks
```

## Hooks

- **`pre-commit`** — runs `rustfmt` on staged Rust files and re-stages
  the formatted result, so commits never carry formatting drift. CI
  runs `cargo fmt --all -- --check`, so this hook prevents avoidable
  CI failures.
