# MPL verification dashboard: design note

Status: prototype, built on branch `MPL-Verus`. It follows the ESDK design in
`docs/verification-dashboard-design.md` on branch `Mahnush_Verus`. That file is a design only.
It was read with `git show`. Nothing was merged or checked out from that branch.

## 1. Purpose

Show, on one page, what the Verus work on the MPL has and has not established, at what level,
for executives and reviewers. The page reports on existing artifacts. It does not run proofs
for the reader, it does not edit docs or proofs, and it is not a source of truth.

Non-goals: no server, no live status, no CI hook, no change to scores, ranks, gaps or quick wins.

## 2. What was adopted, changed or left out

| Part of the reference design | Decision | Why |
|---|---|---|
| Purpose: a reporting view over existing artifacts, not a verifier | Adopted | Same need. |
| Non-goals: no server, not an editor, not a replacement for the prose docs | Adopted | Keeps the page honest and cheap to maintain. |
| Honesty ladder as the core concept, with the rule that a level is never shown as an upgrade of another | Adopted | The MPL has the same risk: a model proof can be mistaken for a proof of the code. |
| Ladder levels in_crate, model_only, compiler_lint, trusted, deferred, not_started | Changed to five levels: in_crate, in_crate_other_branch, model_proved, model_partly, not_started | See section 4. |
| A target may split across levels and the page shows the split | Adopted, in a different form | MPL targets do not split by sub-property. The split is shown as proof hypotheses (assumed, premise, code reading) and as the "does not show" text of each card. |
| `verification-status.json` as the only input of the renderer | Adopted | The HTML is rendered from the dict that is saved as the JSON, and nothing else. |
| Generator, then renderer, as two stages | Adopted, in one script | `generate_dashboard.py` has a build step and a render step. `--render-only` runs the second alone. |
| Self-contained HTML, inline CSS and JS, no network | Adopted | Opens by double-click. |
| Commit the JSON and HTML | Adopted | A reader needs no toolchain. |
| Generation timestamp and snapshot caveat on the page | Adopted, extended | The page also shows the commit, the Verus version, the time of the Verus runs and a stale count. |
| Counts come from live runs at generation time. If the tool is missing, fail or mark unavailable, never fall back to stale numbers | Changed | Results are recorded runs in `proof-runs.json`. Each is stored with the SHA-256 of the proof file. If the file changed, the result is marked STALE (not hidden, not refreshed silently). `--run-verus` makes them live. `--strict` fails on stale or missing results. With no recorded run the page shows "not run". |
| Status oracle: the prose report is the oracle, the YAML status lags | Changed | On the MPL the oracle for a model proof is the Verus run. The docs table is compared with it, and any difference is shown as a disagreement. The weaker reading is used. |
| Count tiles for esdk, prim, verification models | Changed | No crate is verified on this branch. Tiles show targets by level, High threats with a related proof, open bugs, and intentional failing checks. |
| Origin filter (threat-driven or capability-driven) | Adopted | Same two origins. |
| Target table columns | Adopted, extended | Added plain-English title, rank, score, gap, effort, bugs, proof file and result. |
| Plain-English description per target | New | Requested for executives. Not in the reference. |
| Executive view first | New | Requested. |
| Glossary | New | Requested. |
| Generator as a Rust `xtask` | Left out | A Python 3 standard-library script was requested. The reference listed it as the cheaper alternative. |
| `make dashboard` target and output under `docs/` | Left out | New files only, under `dashboard/`. No build file was changed. |
| Per-file Verus counts for crates (`make -C esdk verus`) | Left out | No Verus build of a crate exists on this branch. Per-proof results are shown instead. |
| CI integration | Left out | Same open question as in the reference. Not decided here. |
| Levels compiler_lint, trusted, deferred | Left out | See section 4. |

## 3. Open points and how they were decided

### 3.1 Parse the docs, or keep a mapping file for the plain-English text?

Both, split by kind of data.

- **Facts are parsed.** Rank, score, effort, proof status, coverage gap, quick win, related
  threats, proof file, threat titles and ratings, bug status and bug-to-target links come from the
  docs tables and YAML blocks. Nothing is typed in twice. If a table changes shape, the generator
  stops with an error.
- **Plain-English text is hand-maintained** in `plain-english.json`. The docs are long prose with
  many caveats. Automatic summaries would drop caveats and could overclaim. The text is short and
  is meant to be reviewed.
- **Each card cites its sources.** `card.sources` in the JSON lists the doc, the locator text and the
  line number. The generator stops if a locator is not found, so a renamed section is noticed.
  This proves the cited text exists. It does not prove the card is accurate. A reviewer must read
  the card against the cited lines.
- The plain text holds no scores, ranks or counts. The one-sentence result of each card is
  generated from the recorded Verus numbers.

### 3.2 Which honesty levels does the MPL need?

| Level | Meaning | Targets now |
|---|---|---|
| in_crate | Verus checks the shipped code on this branch | 0 |
| in_crate_other_branch | Verus partly checks the shipped code, on `Mahnush_Verus` only, under 20 assumed aws-lc-rs facts | 1 (C03) |
| model_proved | Verus checks a model, no failing check | 6 |
| model_partly | Verus checks a model, one or more checks fail on purpose | 3 |
| not_started | No proof | 23 |

Reasons:

- `in_crate` is kept at 0 so the page says plainly that nothing on this branch reaches that level.
- `in_crate_other_branch` is needed for C03. The docs say C03 is partly proved in-crate on `Mahnush_Verus`,
  under 20 assumed aws-lc-rs facts, and not here. The label carries "partly". It must not be shown at the same level as a proof on this branch, and it must not
  be hidden.
- `model_proved` and `model_partly` follow the docs wording "Proved" and "Partly proved" at model
  level. The split matters because a failing check is evidence of a bug or spec gap.
- `compiler_lint` is not used: the MPL docs do not give that evidence level to any target.
- `trusted` is not a level here. Trusted assumptions (A_ names) sit inside each proof and are
  listed per proof as assumed, premise or code reading, which are the evidence labels the docs use.
- `deferred` is not used. The only retired targets (T08, C06) are listed apart and not counted.

The evidence labels inside a proof are kept as the docs state them: proved, assumed, code reading.

### 3.3 Colour and layout

Light page, white panels, one accent blue. Level colours: green (in_crate), teal
(in_crate_other_branch), blue (model_proved), amber (model_partly), grey (not_started). Amber was
chosen for model_partly because those results need explanation. Red is used for STALE, for
disagreement banners and for the High risk rating. A level is never coloured green unless Verus checks the shipped code.

Layout order: provenance bar, "read this first" box, executive view (tiles, level bar, High
threats, open bugs), honesty levels, the 33-row target table with filters, the plain-English cards,
the proofs, threats, bugs, retired targets, glossary, rules and sources. Cards are `<details>`
elements, so the page works without JavaScript. JavaScript only drives the filters and "open all".

## 4. Data flow

```
docs/*.md, verus-proofs/*.md      dashboard/plain-english.json     dashboard/proof-runs.json
           |                                  |                              ^
           +--------------+-------------------+                              | --run-verus
                          v                                                  | (verus on each proof file)
              generate_dashboard.py: build_status() ---------------------------+
                          |
                          v
          verification-status.json   <- the single data source
                          |
                          v   render_html() reads only this dict
          verification-dashboard.html
```

## 5. Staleness and honesty rules

1. The page shows the commit the docs and proofs were read from, the generation time, the Verus
   version and the time of the Verus runs.
2. A proof result is STALE if the SHA-256 of the proof file differs from the hash stored with the
   run. A stale result is shown with a red badge and a card warning, and counted in the header.
3. Level, result and "docs agree" are computed, not typed. A difference between the docs and the
   recorded run, an unexpected failing obligation, or an expected failing obligation that did not
   fail, is shown as a disagreement.
4. The word "verified" is not applied to the shipped code anywhere. The page says that no proof
   checks the shipped code. The Verus output line is quoted as the tool wrote it.
5. No threat is called mitigated or secure. A High threat with a related model proof is shown as
   "has a related model proof", with the sentence that this does not mean the threat is handled.
6. Scores, ranks, gaps and quick wins are copied from the docs. Where the YAML score and the table
   score differ, the page shows a disagreement and uses the table value.

## 6. Known limits

- The SHA-256 check detects a change to the proof file. It does not detect a change to `mpl/` or
  `prim/` that the model copies. Nothing does. The docs say this link is reviewed by a person.
- The recorded runs are only as fresh as the last `--run-verus`. `verify_dashboard.py` runs Verus
  again and compares.
- Plain-English cards are hand-written. They need a human review against the cited lines.
- Failing obligations are mapped to function names by searching backward from the error line for
  the nearest `fn`. This is reliable for the current files.
- A threat counts as having a related proof when a target listed for it has a current model proof.
  Capability targets cite no threat in the docs, so they do not count for any threat.

## 7. How this was checked

`python3 dashboard/verify_dashboard.py` checks, among other things: all 33 targets appear in the
JSON, the table and as cards; rank and score equal an independent parse of the docs table; no card
field is empty; the nine results equal a fresh Verus run; two generator runs differ only in the
timestamp; the HTML has no network references; a changed proof hash gives STALE; no banned claim
wording is present; no tracked file changed.
