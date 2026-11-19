# MPL verification dashboard (prototype)

A static page that shows the state of the Verus verification work on the native Rust
AWS Cryptographic Material Providers Library (MPL), branch `MPL-Verus`.

Open `dashboard/verification-dashboard.html` by double-click. It needs no server and no network.

## How to read it

1. Start with the orange box. Every proof on this branch checks a hand-written model of the code. None checks the shipped code.
2. The executive view gives totals by honesty level, the High-risk threats, and the open bugs with the proofs that relate to them.
3. The target table lists all 33 active targets in recorded rank order. Click a target ID to open its plain-English card.
4. Each card says what part of the library the target covers, what could go wrong, what the proof checks (or would check), what it does not show, and the result in one sentence.
5. A proof marked STALE changed after its result was recorded. Re-run it before relying on the number.
6. A check that fails on purpose (T02, T06, T13) is the evidence of a bug or spec gap. It is not a broken proof. The page explains each one.
7. The glossary at the bottom explains model-level proof, expected failure, assumptions (A_ names), hypotheses (H_ names) and the honesty levels.

## Files

| File | What it is |
|---|---|
| `verification-dashboard.html` | The page. Self-contained: inline CSS and a little inline JavaScript for filters. |
| `verification-status.json` | The single data source. The HTML is rendered from this file only. |
| `generate_dashboard.py` | Generator and renderer. Python 3, standard library only. |
| `plain-english.json` | Hand-written plain-English text, with the doc section each card was written from. No numbers or scores. |
| `proof-runs.json` | The recorded Verus runs: result, failing obligations, file hash and time. |
| `verify_dashboard.py` | Checks the outputs against the docs and a fresh Verus run. |
| `DESIGN.md` | Design note: what was taken from the Mahnush_Verus design, and what was changed or left out. |

## How to regenerate

Run these from the repository root.

```sh
# Rebuild the JSON and HTML from docs/, verus-proofs/ and the recorded runs
python3 dashboard/generate_dashboard.py

# Run Verus on all proof files first, record the results, then rebuild
python3 dashboard/generate_dashboard.py --run-verus

# Check everything (runs Verus again; add --no-verus to skip that part)
python3 dashboard/verify_dashboard.py
```

Verus is found through `VERUS_BIN`, then `~/verus/verus`, then `PATH`.

Options of the generator: `--timestamp T` fixes the timestamp for reproducible output, `--strict` exits with code 2 when any result is stale, missing or unexpected, `--render-only` rebuilds the HTML from the existing JSON, and `--out-dir D` writes somewhere else.

The generator fails with a message if a plain-English card is missing, if a cited doc section cannot be found, or if the docs table shapes change.

## What is read from where

| Data | Source |
|---|---|
| Rank, score, effort, proof status text | `docs/mpl-verification-targets.md`, section 1 (ranked table) |
| Coverage gap, quick win, related threats, proof file | The YAML blocks in `docs/mpl-verification-targets/01-threat-driven.md` and `02-capability-driven.md` |
| Threat titles and risk ratings | `docs/mpl-threat-model.md` |
| Bug status and target links | `docs/mpl-bug-reports/README.md` |
| Proof results | `dashboard/proof-runs.json`, written by `--run-verus` |
| Plain-English text | `dashboard/plain-english.json` (reviewed by hand against the docs it cites) |

Scores, ranks, gaps and quick wins are copied. They are never recomputed.

## Honesty and staleness

- The page shows the commit the docs and proofs were read from, the generation time, the Verus version and the time of the recorded runs. The commit is the one before the dashboard files were committed.
- A proof result is STALE when the SHA-256 of the proof file differs from the hash recorded at the run.
- If a docs statement and the recorded run disagree, the page shows a disagreement banner and uses the weaker reading.
- The page never says the shipped code is verified. Nothing detects a change to `mpl/` or `prim/` that the model copies. That link is reviewed by a person.
- The only field that changes between two runs on the same commit is `generated.timestamp_utc`.

## Updating the text

When a doc changes, run the generator. If a cited section moved or was renamed, it stops and names the locator. Edit `plain-english.json`, then have the card text reviewed against the cited source lines, which the JSON stores as `card.sources` with line numbers.
