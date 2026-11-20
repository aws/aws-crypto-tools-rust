# ESDK Verification Dashboard — Design

**Status:** built. `cargo xtask verification-status` writes
`docs/verification-status.json`, and the Verification page of the Crypto Tools
dashboard (`dashboard/verification/` in `aws/aws-crypto-tools-commons`) shows it.

## 1. Purpose

The page lets an engineer or a manager see, at a glance, what the Verus work
has proven. It answers three questions. Do the proofs still pass? How much of
the shipped code do they cover? What do they actually prove, in plain words?

Other verified projects report the same three things. AWS-LC lists each
algorithm with a mark for whether its SAW proof passes. The CBMC proofs in
aws-c-common and s2n-tls list each proof with pass or fail and how much code
it reaches. The Verify Rust std effort counts the functions that have proofs
and tracks that count over time. None of them lead with threat lists or proof
target ids, so this page does not either.

It is a report over existing artifacts, not a verifier. It never runs or
re-reads proofs beyond Verus's own pass/fail output.

## 2. Non-goals

The page is not a live service. It has no server and no on-demand
re-verification; running proofs in CI is the still-open PR #103 Q2. It does
not edit proofs or targets, and it does not replace
`docs/verus-proofs-report.md`, which stays the full written record.

## 3. What the page shows

**Status.** One line at the top: every Verus run passed, or how many errors
there were, or which runs could not be read. It names the Verus version and
the commit the status file was written at.

**Count.** One card per Verus-enabled crate (`esdk`, `prim`): the fns inside
`verus!` blocks over all fns that ship, and the same for fn lines. Verus
checks only code inside `verus!`, so this is the share of shipped code Verus
checks. Spec and proof fns are left out because they are not compiled into the
library. A small line under each card shows the fn count across earlier
versions of the status file. A third card shows how many model files in
`verification/` pass.

**Claims.** One plain sentence per proof, grouped by area, each with a mark.
A check mark means Verus proves it about the code that ships. A half circle
means Verus proves it about a copy of the code in `verification/`, not the
code that ships. An empty circle means the proofs rely on it but no tool
checks it, such as the correctness of aws-lc-rs or the async code calling the
proven checks in the right order. Each proven claim links to the fns that
prove it.

**By file.** How the count was made. Each `.rs` file under `esdk/src` and
`prim/src` shows its share of fn lines that Verus checks. Clicking a file shows
its source with each line colored: proven (has `requires` or `ensures`), no
panic only, spec and proof, trusted (`external_body` or
`assume_specification`), or not checked. This is read from the source, not
from running tests, so it is not test line coverage.

## 4. How it is built

`docs/verification-claims.toml` holds the claims. A proven claim names its fns
as `path::name`, a model claim names its files in `verification/`, and an
assumed claim names nothing.

`cargo xtask verification-status` builds the status file. It runs
`make -C esdk verus`, `make -C prim verus` and `make -C verification verify`
and reads each `verification results:: N verified, M errors` line. It reads
every source file of the two crates with `xtask/src/proof_coverage.rs`, which
finds the `verus!` blocks and sorts each fn by kind. Then it checks every
claim against the code. Generation fails if a proven claim names a fn that does
not exist or sits outside `verus!`, or a model claim names a file that did not
pass. A claim therefore cannot outlive its proof. Fns inside `verus!` that no
claim names are listed on the page, so a new proof is noticed.

If a Verus run cannot be read, its count is written as unavailable, never as an
old number. The status file is committed so the dashboard can read it with no
toolchain. The page fetches it from `main`, or from a pasted PR, through the
GitHub API in the browser.

Run the generator with Verus installed at `~/verus`, at the version the report
names. A CI job can come later, once PR #103 Q2 is settled.
