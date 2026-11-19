#!/usr/bin/env python3
"""Rebuild the MPL verification dashboard.

Reads docs/ and verus-proofs/ in the repo, combines them with the hand-written
plain-English text in dashboard/plain-english.json and the recorded Verus runs
in dashboard/proof-runs.json, and writes:

    dashboard/verification-status.json   the single data source
    dashboard/verification-dashboard.html  a self-contained static page

Run from anywhere:  python3 dashboard/generate_dashboard.py
Refresh the Verus runs first:  python3 dashboard/generate_dashboard.py --run-verus

Python 3 standard library only. The only field that changes between two runs on
the same commit is generated.timestamp_utc (declared in the JSON).
"""

import argparse
import datetime
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

DASH = Path(__file__).resolve().parent
REPO = DASH.parent
SCHEMA_VERSION = 1

DOC_TARGETS = "docs/mpl-verification-targets.md"
DOC_THREAT = "docs/mpl-threat-model.md"
DOC_BUGS = "docs/mpl-bug-reports/README.md"
DOC_T01 = "docs/mpl-verification-targets/01-threat-driven.md"
DOC_C02 = "docs/mpl-verification-targets/02-capability-driven.md"
SOURCE_DOCS = [
    DOC_TARGETS,
    DOC_T01,
    DOC_C02,
    DOC_THREAT,
    DOC_BUGS,
    "verus-proofs/README.md",
    "verus-proofs/README-t03-t05.md",
]
PLAIN_FILE = DASH / "plain-english.json"
RUNS_FILE = DASH / "proof-runs.json"
STATUS_FILE = DASH / "verification-status.json"
HTML_FILE = DASH / "verification-dashboard.html"

MODEL_LEVELS = ("model_proved", "model_partly")
LEVEL_ORDER = ["in_crate", "in_crate_other_branch", "model_proved", "model_partly", "not_started"]
NONDETERMINISTIC = ["generated.timestamp_utc"]


class GenError(Exception):
    pass


# ---------------------------------------------------------------- helpers


def read_text(rel):
    return (REPO / rel).read_text(encoding="utf-8")


def sha256_file(rel):
    return hashlib.sha256((REPO / rel).read_bytes()).hexdigest()


def run(args, cwd=REPO, check=True):
    p = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True)
    if check and p.returncode != 0:
        raise GenError("command failed: %s\n%s" % (" ".join(args), p.stderr.strip()))
    return p


def split_row(line):
    """Split a Markdown table row on unescaped pipes."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    return [c.strip() for c in re.split(r"(?<!\\)\|", line)]


def section(text, start, end=None):
    m = re.search(start, text, re.M)
    if not m:
        raise GenError("section not found: %s" % start)
    rest = text[m.end():]
    if end:
        e = re.search(end, rest, re.M)
        if e:
            rest = rest[:e.start()]
    return rest


def clean_md(s):
    s = s.replace("\\|", "|")
    s = re.sub(r"\*\*(.+?)\*\*", r"\1", s)
    return s.strip()


def find_line(rel, locator):
    """1-based line number of the first line containing locator, or None."""
    for i, line in enumerate(read_text(rel).split("\n"), 1):
        if locator in line:
            return i
    return None


# ---------------------------------------------------------------- git


def git_info():
    head = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    short = run(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    dirty = run(["git", "status", "--porcelain", "--", "docs", "verus-proofs"]).stdout.strip()
    dirty_paths = sorted(l[3:] for l in dirty.split("\n") if l.strip())
    return {
        "commit": head,
        "commit_short": short,
        "branch": branch,
        "sources_clean": not dirty_paths,
        "dirty_paths": dirty_paths,
    }


# ---------------------------------------------------------------- doc parsers


def parse_ranked(md):
    body = section(md, r"^## 1\. Combined ranked summary", r"^## 2\. ")
    active, retired = {}, {}
    for line in body.split("\n"):
        if not line.startswith("|"):
            continue
        cells = split_row(line)
        if len(cells) != 9:
            continue
        m = re.match(r"^([TC]\d{2})\b\s*(.*)$", cells[3])
        if not m:
            continue
        tid, name = m.group(1), m.group(2)
        if re.fullmatch(r"\d+", cells[0]):
            active[tid] = {
                "rank": int(cells[0]),
                "score": cells[1],
                "origin": "threat-driven" if cells[2] == "T" else "capability-driven",
                "technical_name": clean_md(name).replace("`", ""),
                "property_doc": clean_md(cells[4]),
                "agent": cells[5],
                "refs_doc": cells[6],
                "effort": cells[7],
                "proof_status_doc": clean_md(cells[8]),
            }
        elif cells[1] == "Retired":
            retired[tid] = {"technical_name": clean_md(name).replace("`", ""), "origin": "threat-driven" if cells[2] == "T" else "capability-driven"}
    return active, retired


def parse_yaml_blocks(rel):
    text = read_text(rel)
    out = {}
    for m in re.finditer(r"```yaml\n(.*?)```", text, re.S):
        fields, key = {}, None
        for ln in m.group(1).split("\n"):
            km = re.match(r"^  ([a-z_]+):\s*(.*)$", ln)
            if km:
                key = km.group(1)
                fields[key] = [km.group(2)]
            elif key and (ln.startswith("    ") or not ln.strip()):
                fields[key].append(ln)
        if "id" not in fields:
            continue
        tid = fields["id"][0].split()[0].replace("VR-2026-", "")
        flat = lambda k: re.sub(r"\s+", " ", " ".join(fields.get(k, []))).strip()
        rec = {"yaml_doc": rel}
        if "priority_score" in fields:
            rec["priority_score"] = flat("priority_score").split()[0]
        pm = re.search(r'product:\s*"([^"]+)"', flat("scoring"))
        if pm:
            rec["scoring_product"] = pm.group(1)
        if "coverage_gap" in fields:
            rec["coverage_gap"] = flat("coverage_gap").split()[0]
        if "quick_win" in fields:
            rec["quick_win"] = flat("quick_win").split()[0] == "true"
        if "estimated_effort" in fields:
            rec["effort_yaml"] = flat("estimated_effort")
        rec["threats"] = re.findall(r"id:\s*(TM-MPL-\d{3})", flat("threat_references"))
        pf = flat("proof_file")
        if pf:
            rec["proof_file"] = pf.strip('"')
        out[tid] = rec
    return out


def parse_doc_proof_rows(md):
    body = section(md, r"^## Proofs written", r"^Canonical status strings")
    rows = {}
    for line in body.split("\n"):
        if not line.startswith("| "):
            continue
        cells = split_row(line)
        if len(cells) != 5 or not re.fullmatch(r"[TC]\d{2}", cells[0]) or not cells[1].startswith("[`"):
            continue
        fm = re.match(r"\[`([^`]+)`\]", cells[1])
        rm = re.search(r"(\d+) verified, (\d+) errors", cells[2])
        rows[cells[0]] = {
            "file": "verus-proofs/" + fm.group(1),
            "result_line": cells[2].strip("`"),
            "verified": int(rm.group(1)),
            "errors": int(rm.group(2)),
            "status": clean_md(cells[3]),
            "assumptions_cell": clean_md(cells[4]),
        }
    return rows


def parse_threats(tm):
    titles = {}
    for line in tm.split("\n"):
        if not line.startswith("| TM-MPL-"):
            continue
        cells = split_row(line)
        if len(cells) == 3 and re.fullmatch(r"TM-MPL-\d{3}", cells[0]) and cells[0] not in titles:
            titles[cells[0]] = {"title": clean_md(cells[1]), "component": clean_md(cells[2]).replace("`", "")}
    ratings = {}
    lines = tm.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("| ID | STRIDE | Severity | Likelihood | Risk"):
            header = split_row(line)
            risk_idx = max(j for j, h in enumerate(header) if h.startswith("Risk"))
            risk_name = header[risk_idx]
            for row in lines[i + 2:]:
                if not row.startswith("| TM-MPL-"):
                    break
                c = split_row(row)
                ratings[c[0]] = {
                    "stride": c[1],
                    "severity": clean_md(c[2]),
                    "likelihood": clean_md(c[3]),
                    "risk": clean_md(c[risk_idx]),
                    "rating_note": clean_md(c[-1]),
                    "risk_column": risk_name,
                }
            break
    if len(titles) != 26 or len(ratings) != 26:
        raise GenError("expected 26 threats, found %d titles and %d ratings" % (len(titles), len(ratings)))
    out = []
    for tid in sorted(titles):
        rec = {"id": tid}
        rec.update(titles[tid])
        rec.update(ratings[tid])
        out.append(rec)
    return out


def parse_bugs(readme):
    bugs = []
    for line in readme.split("\n"):
        if not line.startswith("| [BUG-"):
            continue
        c = split_row(line)
        if len(c) != 10:
            raise GenError("bug row has %d cells: %s" % (len(c), line[:60]))
        bid = re.match(r"\[(BUG-\d+)\]", c[0]).group(1)
        status = clean_md(c[6])
        bugs.append({
            "id": bid,
            "title_doc": clean_md(c[1]),
            "component": clean_md(c[2]),
            "severity": clean_md(c[3]),
            "confidence": clean_md(c[4]),
            "spec_conflict": clean_md(c[5]),
            "status_doc": status,
            "open": "Still present" in status,
            "threats": sorted(set(re.findall(r"TM-MPL-\d{3}", c[7]))),
            "targets": sorted(set(re.findall(r"\b([TC]\d{2})\b", c[8]))),
            "priority_doc": clean_md(c[9]),
        })
    if len(bugs) != 10:
        raise GenError("expected 10 bugs, found %d" % len(bugs))
    return bugs


# ---------------------------------------------------------------- Verus


def find_verus():
    cands = []
    if os.environ.get("VERUS_BIN"):
        cands.append(os.environ["VERUS_BIN"])
    cands.append(str(Path.home() / "verus" / "verus"))
    w = shutil.which("verus")
    if w:
        cands.append(w)
    for c in cands:
        if c and os.access(c, os.X_OK):
            return c
    return None


def verus_version(binary):
    p = run([binary, "--version"], check=False)
    lines = [l.strip() for l in p.stdout.split("\n") if l.strip()]
    ver = ""
    extra = []
    for l in lines:
        if l.startswith("Version:"):
            ver = l.split(":", 1)[1].strip()
        elif l.startswith(("Profile:", "Platform:", "Toolchain:")):
            extra.append(l.split(":", 1)[1].strip())
    return ver, ", ".join(extra)


def enclosing_fn(rel, line_no):
    lines = read_text(rel).split("\n")
    for i in range(min(line_no, len(lines)) - 1, -1, -1):
        m = re.search(r"\bfn\s+(\w+)\s*[(<]", lines[i])
        if m:
            return m.group(1)
    return "?"


def run_verus_file(binary, rel):
    p = run([binary, rel], check=False)
    out = p.stdout + "\n" + p.stderr
    rm = None
    for m in re.finditer(r"verification results:: (\d+) verified, (\d+) errors", out):
        rm = m
    if not rm:
        raise GenError("no result line from Verus for %s:\n%s" % (rel, out[-800:]))
    failing = []
    kind = None
    for ln in out.split("\n"):
        km = re.match(r"^(error|warning|note)(\[[^\]]*\])?:\s*(.*)$", ln)
        if km:
            kind = km.group(1) if not km.group(3).startswith("aborting") else None
            continue
        am = re.match(r"^\s*-->\s+(\S+?):(\d+):\d+", ln)
        if am and kind == "error" and am.group(1) == rel:
            lno = int(am.group(2))
            failing.append({"function": enclosing_fn(rel, lno), "line": lno})
    return {
        "verified": int(rm.group(1)),
        "errors": int(rm.group(2)),
        "exit_code": p.returncode,
        "result_line": rm.group(0),
        "failing_obligations": failing,
    }


def record_runs(binary, proof_files):
    ver, extra = verus_version(binary)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    head = git_info()
    runs = {}
    for rel in proof_files:
        print("  verus %s" % rel, flush=True)
        r = run_verus_file(binary, rel)
        r["sha256"] = sha256_file(rel)
        r["run_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        runs[rel] = r
        print("    -> %s" % r["result_line"], flush=True)
    data = {
        "verus_version": ver,
        "verus_platform": extra,
        "command": "verus <file> (run from the repo root)",
        "recorded_at": now,
        "recorded_on_commit": head["commit_short"],
        "runs": runs,
    }
    RUNS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return data


def load_runs():
    if RUNS_FILE.exists():
        return json.loads(RUNS_FILE.read_text(encoding="utf-8"))
    return {"verus_version": "unknown", "verus_platform": "", "recorded_at": None, "recorded_on_commit": None, "runs": {}}


# ---------------------------------------------------------------- assembly


def doc_level(status_doc):
    s = status_doc
    if s.startswith("None"):
        return "not_started"
    if s.startswith("Partly proved (model level"):
        return "model_partly"
    if s.startswith("Proved (model level"):
        return "model_proved"
    if s.startswith("Partly proved (in-crate") and "Mahnush_Verus" in s and "not on this branch" in s:
        return "in_crate_other_branch"
    raise GenError("unrecognised proof status text: %s" % s[:80])


def check_sources(sources):
    out = []
    for s in sources:
        line = find_line(s["doc"], s["locator"])
        if line is None:
            raise GenError("locator not found: %s in %s" % (s["locator"], s["doc"]))
        out.append({"doc": s["doc"], "locator": s["locator"], "line": line})
    return out


def build_status(timestamp, plain, runs_data, check_files=True):
    md = read_text(DOC_TARGETS)
    ranked, retired_rows = parse_ranked(md)
    y01 = parse_yaml_blocks(DOC_T01)
    y02 = parse_yaml_blocks(DOC_C02)
    yaml_all = dict(y01)
    yaml_all.update(y02)
    doc_proofs = parse_doc_proof_rows(md)
    threats = parse_threats(read_text(DOC_THREAT))
    bugs = parse_bugs(read_text(DOC_BUGS))
    threat_by_id = {t["id"]: t for t in threats}
    runs = runs_data.get("runs", {})
    drift = []

    if len(ranked) != 33:
        raise GenError("expected 33 active targets, found %d" % len(ranked))
    ptargets = plain["targets"]
    if set(ptargets) != set(ranked):
        raise GenError("plain-english targets differ from docs: %s" % sorted(set(ptargets) ^ set(ranked)))

    bug_targets = {}
    for b in bugs:
        for t in b["targets"]:
            bug_targets.setdefault(t, []).append(b["id"])

    targets = []
    proofs = []
    for tid in sorted(ranked, key=lambda k: ranked[k]["rank"]):
        r = ranked[tid]
        y = yaml_all.get(tid, {})
        pt = ptargets[tid]
        # recorded scores: the ranked table is the source; the YAML is cross-checked, never used to recompute
        if y.get("priority_score") and y["priority_score"] != r["score"]:
            drift.append("%s: score %s in the ranked table, %s in the YAML" % (tid, r["score"], y["priority_score"]))
        threats_t = []
        for x in y.get("threats", []) + re.findall(r"TM-MPL-\d{3}", r["refs_doc"]):
            if x not in threats_t:
                threats_t.append(x)
        threats_t.sort()
        proof_file = y.get("proof_file")
        level_doc = doc_level(r["proof_status_doc"])
        level = level_doc
        run_rec = None
        state = None
        failing_names = []
        expected = []
        unexpected = []
        missing_expected = []
        doc_row = doc_proofs.get(tid)
        if proof_file and tid in plain["proofs"]:
            expected = plain["proofs"][tid]["expected_failures"]
            run_rec = runs.get(proof_file)
            cur_sha = sha256_file(proof_file)
            if run_rec is None:
                state = "not_run"
            elif run_rec["sha256"] != cur_sha:
                state = "stale"
            else:
                state = "current"
            if run_rec is not None:
                run_level = "model_partly" if run_rec["errors"] > 0 else "model_proved"
                if run_level != level_doc:
                    drift.append("%s: docs say %s, the recorded Verus run says %s" % (tid, level_doc, run_level))
                    level = "model_partly" if "model_partly" in (run_level, level_doc) else run_level
                failing_names = [f["function"] for f in run_rec["failing_obligations"]]
                if len(failing_names) != run_rec["errors"]:
                    drift.append("%s: Verus reported %d errors but %d failing obligations were located" % (tid, run_rec["errors"], len(failing_names)))
                unexpected = sorted(set(failing_names) - set(expected))
                missing_expected = sorted(set(expected) - set(failing_names))
                if unexpected:
                    drift.append("%s: unexpected failing obligations: %s" % (tid, ", ".join(unexpected)))
                if missing_expected:
                    drift.append("%s: expected failing obligations not seen: %s" % (tid, ", ".join(missing_expected)))
            if doc_row and run_rec is not None and (doc_row["verified"], doc_row["errors"]) != (run_rec["verified"], run_rec["errors"]):
                drift.append("%s: docs record %d/%d, the recorded run has %d/%d" % (
                    tid, doc_row["verified"], doc_row["errors"], run_rec["verified"], run_rec["errors"]))
        elif level_doc in MODEL_LEVELS:
            raise GenError("%s is a model proof in the docs but has no proof_file in the YAML" % tid)

        # result sentence (generated from the numbers, never typed in)
        result = result_sentence(tid, level, state, run_rec, plain, doc_row, r)
        card_notes = list(pt.get("notes", []))
        checks_label = "What the proof checks" if level != "not_started" else "What a proof would check"
        not_shown = pt["not_shown"]
        if level == "not_started":
            not_shown = "No proof exists yet, so nothing here is machine-checked. " + not_shown
        for fld in ("title", "area", "risk", "checks", "not_shown"):
            if not str(pt.get(fld, "")).strip():
                raise GenError("empty card field %s for %s" % (fld, tid))
        srcs = [dict(s) for s in pt["sources"]]
        srcs.append({"doc": DOC_TARGETS, "locator": "## 1. Combined ranked summary"})
        srcs = check_sources(srcs)
        target = {
            "id": tid,
            "origin": r["origin"],
            "rank": r["rank"],
            "score": r["score"],
            "coverage_gap": y.get("coverage_gap"),
            "scoring_product": y.get("scoring_product"),
            "quick_win": y.get("quick_win"),
            "effort": r["effort"],
            "agent": r["agent"],
            "technical_name": r["technical_name"],
            "title": pt["title"],
            "threats": threats_t,
            "threats_note": "" if threats_t else "none cited in the targets docs",
            "bugs": sorted(bug_targets.get(tid, [])),
            "level": level,
            "proof": None,
            "card": {
                "area": pt["area"],
                "risk": pt["risk"],
                "checks_label": checks_label,
                "checks": pt["checks"],
                "not_shown": not_shown,
                "result": result,
                "notes": card_notes,
                "expected_failure_explanation": plain["proofs"].get(tid, {}).get("failure_explanation", ""),
                "sources": srcs,
            },
            "docs_proof_status": r["proof_status_doc"],
        }
        if proof_file:
            target["proof"] = {"file": proof_file, "state": state}
            hyps = []
            for name in plain["proofs"][tid]["hypotheses"]:
                h = plain["hypotheses"][name]
                hyps.append({"name": name, "kind": h["kind"], "text": h["text"]})
            proof_text = read_text(proof_file) + "\n" + (doc_row["assumptions_cell"] if doc_row else "")
            for h in hyps:
                if not re.search(r"\b%s\b" % re.escape(h["name"]), proof_text) and not re.search(r"\b%s\b" % re.escape(h["name"]), read_text("verus-proofs/README.md") + read_text("verus-proofs/README-t03-t05.md")):
                    raise GenError("hypothesis %s for %s not found in the proof file or its docs" % (h["name"], tid))
            proofs.append({
                "target": tid,
                "file": proof_file,
                "state": state,
                "file_sha256_now": sha256_file(proof_file),
                "file_sha256_at_run": run_rec["sha256"] if run_rec else None,
                "run_at": run_rec["run_at"] if run_rec else None,
                "verified": run_rec["verified"] if run_rec else None,
                "errors": run_rec["errors"] if run_rec else None,
                "exit_code": run_rec["exit_code"] if run_rec else None,
                "verus_output_line": run_rec["result_line"] if run_rec else None,
                "failing_obligations": run_rec["failing_obligations"] if run_rec else [],
                "expected_failures": expected,
                "unexpected_failures": unexpected,
                "expected_failures_not_seen": missing_expected,
                "docs_result_line": doc_row["result_line"] if doc_row else None,
                "docs_match_run": bool(doc_row and run_rec and (doc_row["verified"], doc_row["errors"]) == (run_rec["verified"], run_rec["errors"])),
                "level": level,
                "failure_explanation": plain["proofs"][tid].get("failure_explanation", ""),
                "hypotheses": hyps,
            })
        targets.append(target)

    tmap = {t["id"]: t for t in targets}

    # C03 sentence needs the doc numbers
    c03 = tmap["C03"]
    if c03["level"] != "in_crate_other_branch":
        raise GenError("C03 is expected to be in_crate_other_branch")

    # threats with related targets
    for th in threats:
        rel = [t for t in targets if th["id"] in t["threats"]]
        th["related_targets"] = [{"id": t["id"], "level": t["level"], "state": (t["proof"] or {}).get("state")} for t in rel]
        th["bugs"] = sorted(b["id"] for b in bugs if th["id"] in b["threats"])
    # bugs with relations
    for b in bugs:
        pb = plain["bugs"][b["id"]]
        rel = dict(pb["relation"])
        tgt = rel.get("target")
        status = ""
        if rel["kind"] == "confirmed_by_model_proof":
            p = next(p for p in proofs if p["target"] == tgt)
            seen = sorted(set(p["expected_failures"]) & set(f["function"] for f in p["failing_obligations"]))
            if p["state"] == "current" and len(seen) == len(p["expected_failures"]) and p["expected_failures"]:
                status = "confirmed (current run)"
            elif p["state"] == "stale":
                status = "confirmation is stale: re-run the proof"
            else:
                status = "not reproduced in the recorded run"
        b["plain"] = pb["plain"]
        b["proof_relation"] = {"kind": rel["kind"], "target": tgt, "text": rel["text"], "status": status}
        b["sources"] = check_sources(pb["sources"])

    # threats in High risk
    high = []
    for th in threats:
        if th["risk"] != "High":
            continue
        rel = th["related_targets"]
        covered = [x for x in rel if x["level"] in MODEL_LEVELS and x["state"] == "current"]
        without = [x["id"] for x in rel if x["level"] not in MODEL_LEVELS]
        high.append({
            "id": th["id"],
            "title": th["title"],
            "plain": plain["high_threats_plain"][th["id"]],
            "severity": th["severity"],
            "likelihood": th["likelihood"],
            "risk": th["risk"],
            "related_targets": rel,
            "has_current_model_proof": bool(covered),
            "targets_with_current_model_proof": [x["id"] for x in covered],
            "related_targets_without_proof": without,
        })
    for tid in plain["high_threats_plain"]:
        if tid not in [h["id"] for h in high]:
            raise GenError("plain text given for %s but it is not rated High in the docs" % tid)

    # executive
    level_counts = {k: 0 for k in LEVEL_ORDER}
    for t in targets:
        level_counts[t["level"]] += 1
    open_bugs = [b for b in bugs if b["open"]]
    fixed_bugs = [b for b in bugs if not b["open"]]
    intentional = [p for p in proofs if p["errors"]]
    executive = {
        "active_targets": len(targets),
        "threat_driven": sum(1 for t in targets if t["origin"] == "threat-driven"),
        "capability_driven": sum(1 for t in targets if t["origin"] == "capability-driven"),
        "retired_targets": len(retired_rows),
        "level_counts": level_counts,
        "targets_with_model_proof_on_this_branch": level_counts["model_proved"] + level_counts["model_partly"],
        "targets_with_proof_in_shipped_code_on_this_branch": level_counts["in_crate"],
        "targets_with_proof_on_other_branch_only": level_counts["in_crate_other_branch"],
        "targets_without_proof": level_counts["not_started"],
        "high_threat_count": len(high),
        "high_threats_with_current_model_proof": sum(1 for h in high if h["has_current_model_proof"]),
        "threat_count": len(threats),
        "bugs_open": [b["id"] for b in open_bugs],
        "bugs_fixed": [b["id"] for b in fixed_bugs],
        "open_bugs_confirmed_by_model_proof": [b["id"] for b in open_bugs if b["proof_relation"]["kind"] == "confirmed_by_model_proof" and b["proof_relation"]["status"].startswith("confirmed")],
        "open_bugs_with_no_proof_on_this_branch": [b["id"] for b in open_bugs if b["proof_relation"]["kind"] in ("none", "other_branch")],
        "proofs_with_intentional_failures": [p["target"] for p in intentional],
        "intentional_failing_checks": sum(p["errors"] for p in intentional),
        "stale_proofs": [p["target"] for p in proofs if p["state"] == "stale"],
        "proofs_not_run": [p["target"] for p in proofs if p["state"] == "not_run"],
        "unexpected_failures": [p["target"] for p in proofs if p["unexpected_failures"]],
        "docs_drift": drift,
        "scope_statement": "Every proof on this branch checks a hand-written model of the code. None checks the shipped code.",
    }

    sources = []
    for rel in SOURCE_DOCS:
        sources.append({"path": rel, "sha256": sha256_file(rel)})
    for t in targets:
        if t["proof"]:
            sources.append({"path": t["proof"]["file"], "sha256": sha256_file(t["proof"]["file"])})
    sources.append({"path": "dashboard/plain-english.json", "sha256": hashlib.sha256(PLAIN_FILE.read_bytes()).hexdigest()})

    retired = []
    for tid in sorted(retired_rows):
        retired.append({"id": tid, "technical_name": retired_rows[tid]["technical_name"], "plain": plain["retired"][tid]})

    g = git_info()
    g.update({
        "timestamp_utc": timestamp,
        "generator": "dashboard/generate_dashboard.py",
        "schema_version": SCHEMA_VERSION,
        "commit_meaning": "the commit whose docs/ and verus-proofs/ were read; the dashboard files are committed after it",
    })
    status = {
        "generated": g,
        "declared_nondeterministic_fields": NONDETERMINISTIC,
        "verus": {
            "version": runs_data.get("verus_version"),
            "platform": runs_data.get("verus_platform"),
            "runs_recorded_at": runs_data.get("recorded_at"),
            "runs_recorded_on_commit": runs_data.get("recorded_on_commit"),
            "command": "~/verus/verus verus-proofs/<file>.rs, run from the repo root",
        },
        "scope_statement": executive["scope_statement"],
        "evidence_labels": plain["evidence_labels"],
        "honesty_levels": plain["honesty_levels"],
        "page_rules": plain["page_rules"],
        "executive": executive,
        "high_threats": high,
        "targets": targets,
        "proofs": proofs,
        "threats": threats,
        "bugs": bugs,
        "retired_targets": retired,
        "glossary": plain["glossary"],
        "sources": sources,
    }
    return status


def result_sentence(tid, level, state, run_rec, plain, doc_row, ranked_row):
    if level == "not_started":
        return "No proof exists yet, so there is no result."
    if level == "in_crate_other_branch":
        m = re.search(r"(\d+) verified, (\d+) errors", ranked_row["proof_status_doc"])
        tpl = plain["c03_other_branch"]["sentence_template"]
        res = "%s passing checks and %s failing checks" % (m.group(1), m.group(2)) if m else "a result"
        return tpl.format(result=res)
    if run_rec is None:
        return "No recorded Verus run exists for this proof. Run the generator with --run-verus."
    v, e = run_rec["verified"], run_rec["errors"]
    clause = plain["proofs"][tid].get("result_clause", "")
    if e == 0:
        base = "Verus reports %d passing checks and 0 failing checks on a model of this code" % v
    else:
        base = "Verus reports %d passing checks and %d failing %s on a model of this code" % (
            v, e, "check" if e == 1 else "checks")
    sent = base + ", not on the shipped code" + ("; " + clause if clause else "") + "."
    if state == "stale":
        sent = "STALE, re-run needed: the proof file changed after this result was recorded. Last recorded result: " + sent[0].lower() + sent[1:]
    elif state == "not_run":
        sent = "No recorded run."
    return sent


# ---------------------------------------------------------------- renderer
# The renderer reads only the status dict (what is in verification-status.json).

LEVEL_CLASS = {
    "in_crate": "lv-incrate",
    "in_crate_other_branch": "lv-other",
    "model_proved": "lv-model",
    "model_partly": "lv-partly",
    "not_started": "lv-none",
}

CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--ink:#1d2430;--mute:#5b6470;--line:#d9dee5;--accent:#1c5fb5;
--green:#1b7f3b;--teal:#0b7285;--blue:#1c5fb5;--amber:#b35c00;--grey:#5b6470;--red:#b42318;
--blue-bg:#e7f0fc;--amber-bg:#fff1e0;--grey-bg:#eceff3;--teal-bg:#e3f4f7;--green-bg:#e3f4e8;--red-bg:#fdecea}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif}
header.top{background:#fff;border-bottom:1px solid var(--line);padding:18px 28px}
header.top h1{margin:0 0 2px;font-size:24px}
header.top .sub{color:var(--mute)}
main{max-width:1240px;margin:0 auto;padding:18px 28px 60px}
nav.toc{position:sticky;top:0;z-index:5;background:#fff;border-bottom:1px solid var(--line);padding:8px 28px;font-size:13px}
nav.toc a{margin-right:14px;color:var(--accent);text-decoration:none}
section{margin:28px 0}
h2{font-size:20px;margin:0 0 10px;border-bottom:2px solid var(--line);padding-bottom:4px}
h3{font-size:16px;margin:18px 0 6px}
.prov{display:flex;flex-wrap:wrap;gap:8px 22px;margin-top:10px;font-size:13px;color:var(--mute)}
.prov b{color:var(--ink)}
code{font:12.5px/1.4 ui-monospace,Menlo,Consolas,monospace;background:#eef1f5;padding:1px 4px;border-radius:3px}
.banner{border:2px solid var(--amber);background:var(--amber-bg);padding:12px 16px;border-radius:6px;margin:14px 0;font-size:15px}
.banner.stale{border-color:var(--red);background:var(--red-bg)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:12px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.tile .n{font-size:30px;font-weight:700;line-height:1.1}
.tile .l{color:var(--mute);font-size:13px}
.tile.warn .n{color:var(--amber)}
.chip{display:inline-block;border-radius:10px;padding:1px 9px;font-size:12px;font-weight:600;white-space:nowrap;border:1px solid transparent}
.lv-incrate{background:var(--green-bg);color:var(--green);border-color:var(--green)}
.lv-other{background:var(--teal-bg);color:var(--teal);border-color:var(--teal)}
.lv-model{background:var(--blue-bg);color:var(--blue);border-color:var(--blue)}
.lv-partly{background:var(--amber-bg);color:var(--amber);border-color:var(--amber)}
.lv-none{background:var(--grey-bg);color:var(--grey);border-color:#b8c0cc}
.badge-stale{background:var(--red-bg);color:var(--red);border-color:var(--red)}
.badge-ok{background:var(--green-bg);color:var(--green);border-color:var(--green)}
.badge-open{background:var(--amber-bg);color:var(--amber);border-color:var(--amber)}
.badge-fixed{background:var(--green-bg);color:var(--green);border-color:var(--green)}
.badge-high{background:var(--red-bg);color:var(--red);border-color:var(--red)}
.badge-med{background:var(--amber-bg);color:var(--amber);border-color:var(--amber)}
.badge-low{background:var(--grey-bg);color:var(--grey);border-color:#b8c0cc}
table{border-collapse:collapse;width:100%;background:var(--panel);border:1px solid var(--line);font-size:13px}
th,td{border:1px solid var(--line);padding:6px 8px;vertical-align:top;text-align:left}
th{background:#eef1f5;position:sticky;top:34px}
tr.hidden{display:none}
.ladder{display:flex;height:26px;border-radius:5px;overflow:hidden;border:1px solid var(--line);margin:8px 0}
.ladder div{display:flex;align-items:center;justify-content:center;color:#fff;font-size:12px;font-weight:600}
.ladder .lv-incrate{background:var(--green)}.ladder .lv-other{background:var(--teal)}
.ladder .lv-model{background:var(--blue)}.ladder .lv-partly{background:var(--amber)}.ladder .lv-none{background:#8a94a3}
.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}
.legend .chip{white-space:normal}
.legend div{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:13px}
.controls{margin:8px 0;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.controls button{border:1px solid var(--line);background:#fff;border-radius:14px;padding:3px 11px;cursor:pointer;font-size:13px}
.controls button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.controls input{border:1px solid var(--line);border-radius:4px;padding:4px 8px;font-size:13px}
details.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:8px 0}
details.card>summary{cursor:pointer;padding:9px 12px;font-weight:600;list-style:none}
details.card>summary .id{display:inline-block;min-width:44px;color:var(--accent)}
details.card[open]>summary{border-bottom:1px solid var(--line);background:#fafbfc}
.cardbody{padding:8px 14px 12px}
.cardbody dt{font-weight:700;margin-top:10px;color:#2b3645}
.cardbody dd{margin:2px 0 0 0}
.box{border:1px solid var(--amber);background:var(--amber-bg);border-radius:6px;padding:8px 12px;margin:10px 0}
.box.flag{border-color:var(--red);background:var(--red-bg)}
.src{font-size:12px;color:var(--mute);margin-top:10px}
.small{font-size:12px;color:var(--mute)}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
dl.gl dt{font-weight:700;margin-top:8px}dl.gl dd{margin:0}
ul.tight{margin:4px 0;padding-left:20px}
.tag{white-space:nowrap;display:inline-block;border:1px solid var(--line);background:#fff;border-radius:4px;padding:0 5px;margin:1px 2px 1px 0;font-size:12px;text-decoration:none;color:var(--ink)}
a{color:var(--accent)}
footer{color:var(--mute);font-size:12px;margin-top:40px}
@media print{nav.toc,.controls{display:none}details.card{break-inside:avoid}}
"""

JS = """
(function(){
  var rows=[].slice.call(document.querySelectorAll('#targets-table tbody tr'));
  var state={level:'all',origin:'all',q:''};
  function apply(){
    rows.forEach(function(r){
      var ok=(state.level==='all'||r.dataset.level===state.level)&&
             (state.origin==='all'||r.dataset.origin===state.origin)&&
             (state.q===''||r.textContent.toLowerCase().indexOf(state.q)>=0);
      r.classList.toggle('hidden',!ok);
    });
  }
  [].forEach.call(document.querySelectorAll('[data-filter]'),function(b){
    b.addEventListener('click',function(){
      var kind=b.dataset.filter,val=b.dataset.value;
      state[kind]=val;
      [].forEach.call(document.querySelectorAll('[data-filter="'+kind+'"]'),function(o){o.classList.toggle('on',o===b);});
      apply();
    });
  });
  var q=document.getElementById('q');
  if(q){q.addEventListener('input',function(){state.q=q.value.toLowerCase();apply();});}
  var all=document.getElementById('toggle-cards');
  if(all){all.addEventListener('click',function(){
    var cards=[].slice.call(document.querySelectorAll('details.card'));
    var open=cards.some(function(c){return !c.open;});
    cards.forEach(function(c){c.open=open;});
    all.textContent=open?'Close all cards':'Open all cards';
  });}
  [].forEach.call(document.querySelectorAll('a.cardlink'),function(a){
    a.addEventListener('click',function(){
      var el=document.querySelector(a.getAttribute('href'));
      if(el&&el.tagName==='DETAILS'){el.open=true;}
    });
  });
})();
"""


def e(s):
    return html.escape(str(s), quote=True)


def level_info(status):
    return {l["key"]: l for l in status["honesty_levels"]}


def chip_level(status, key):
    li = level_info(status)[key]
    return '<span class="chip %s" title="%s">%s</span>' % (LEVEL_CLASS[key], e(li["text"]), e(li["label"]))


def risk_badge(risk):
    cls = {"High": "badge-high", "Medium": "badge-med"}.get(risk, "badge-low")
    return '<span class="chip %s">%s</span>' % (cls, e(risk))


def state_badge(state):
    if state == "current":
        return '<span class="chip badge-ok" title="The proof file is unchanged since the recorded run.">current</span>'
    if state == "stale":
        return '<span class="chip badge-stale" title="The proof file changed after the recorded run.">STALE</span>'
    if state == "not_run":
        return '<span class="chip badge-stale">not run</span>'
    return ""


def threat_chips(status, ids):
    tm = {t["id"]: t for t in status["threats"]}
    out = []
    for i in ids:
        t = tm[i]
        out.append('<a class="tag" href="#thr-%s" title="%s (risk %s)">%s</a>' % (e(i), e(t["title"]), e(t["risk"]), e(i.replace("TM-MPL-", "TM-"))))
    return " ".join(out)


def bug_chips(status, ids):
    bm = {b["id"]: b for b in status["bugs"]}
    out = []
    for i in ids:
        b = bm[i]
        cls = "badge-open" if b["open"] else "badge-fixed"
        out.append('<a class="tag" href="#bug-%s" title="%s">%s <span class="chip %s">%s</span></a>' % (
            e(i), e(b["plain"]), e(i), cls, "open" if b["open"] else "fixed"))
    return " ".join(out)


def render_html(status):
    g = status["generated"]
    ex = status["executive"]
    li = level_info(status)
    proofs = {p["target"]: p for p in status["proofs"]}
    parts = []
    A = parts.append
    A("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
    A("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
    A("<title>MPL Verification Dashboard (prototype)</title>")
    A("<style>%s</style></head><body>" % CSS)

    # header
    A('<header class="top"><h1>MPL Verification Dashboard <span class="small">(prototype)</span></h1>')
    A('<div class="sub">AWS Cryptographic Material Providers Library, native Rust. Branch <code>%s</code>.</div>' % e(g["branch"]))
    stale_n = len(ex["stale_proofs"]) + len(ex["proofs_not_run"])
    A('<div class="prov">')
    A('<span>Data read from commit <b><code>%s</code></b>%s</span>' % (e(g["commit_short"]), "" if g["sources_clean"] else ' <b style="color:#b42318">(docs or proofs have uncommitted changes)</b>'))
    A('<span>Generated <b>%s</b></span>' % e(g["timestamp_utc"]))
    A('<span>Verus <b>%s</b> (%s)</span>' % (e(status["verus"]["version"]), e(status["verus"]["platform"])))
    A('<span>Proofs last run <b>%s</b></span>' % e(status["verus"]["runs_recorded_at"]))
    A('<span>Stale or missing proof results: <b>%d</b></span>' % stale_n)
    A('</div></header>')
    A('<nav class="toc"><a href="#exec">Executive view</a><a href="#levels">Honesty levels</a><a href="#targets">Target table</a>'
      '<a href="#cards">Plain-English cards</a><a href="#proofs">Proofs</a><a href="#threats">Threats</a><a href="#bugs">Bugs</a>'
      '<a href="#glossary">Glossary</a><a href="#rules">Rules and sources</a></nav>')
    A('<main>')

    # banner
    A('<div class="banner"><b>Read this first.</b> %s A passing model proof does not mean a threat is handled. '
      'It means only what the card for that target says it checks.</div>' % e(status["scope_statement"]))
    if stale_n:
        A('<div class="banner stale"><b>Stale results.</b> %d proof result(s) are stale or missing. '
          'Re-run the generator with <code>--run-verus</code>.</div>' % stale_n)
    if ex["unexpected_failures"] or ex["docs_drift"]:
        A('<div class="banner stale"><b>Disagreement found.</b><ul class="tight">%s</ul></div>' % "".join("<li>%s</li>" % e(d) for d in ex["docs_drift"]))

    # executive
    A('<section id="exec"><h2>Executive view</h2>')
    A('<div class="tiles">')
    A('<div class="tile"><div class="n">%d</div><div class="l">active targets (%d from the threat model, %d from a capability sweep). %d more are retired.</div></div>' % (
        ex["active_targets"], ex["threat_driven"], ex["capability_driven"], ex["retired_targets"]))
    A('<div class="tile"><div class="n">%d</div><div class="l">targets with a model proof on this branch (%d with a failing check on purpose)</div></div>' % (
        ex["targets_with_model_proof_on_this_branch"], ex["level_counts"]["model_partly"]))
    A('<div class="tile warn"><div class="n">%d</div><div class="l">targets with a proof of the shipped code on this branch</div></div>' % ex["targets_with_proof_in_shipped_code_on_this_branch"])
    A('<div class="tile"><div class="n">%d</div><div class="l">target partly proved in the shipped code on another branch only (C03, branch Mahnush_Verus, under 20 assumed aws-lc-rs facts)</div></div>' % ex["targets_with_proof_on_other_branch_only"])
    A('<div class="tile"><div class="n">%d</div><div class="l">targets with no proof yet</div></div>' % ex["targets_without_proof"])
    A('<div class="tile"><div class="n">%d of %d</div><div class="l">High-risk threats have at least one related model proof (not a statement that they are handled)</div></div>' % (
        ex["high_threats_with_current_model_proof"], ex["high_threat_count"]))
    A('<div class="tile"><div class="n">%d</div><div class="l">open bugs (%d fixed). %d confirmed by a model proof: %s</div></div>' % (
        len(ex["bugs_open"]), len(ex["bugs_fixed"]), len(ex["open_bugs_confirmed_by_model_proof"]), e(", ".join(ex["open_bugs_confirmed_by_model_proof"]) or "none")))
    A('<div class="tile"><div class="n">%d</div><div class="l">intentional failing checks in %d proofs (%s). Each is evidence of a bug or spec gap.</div></div>' % (
        ex["intentional_failing_checks"], len(ex["proofs_with_intentional_failures"]), e(", ".join(ex["proofs_with_intentional_failures"]))))
    A('</div>')

    # ladder bar
    A('<h3>Targets by honesty level</h3><div class="ladder">')
    for key in LEVEL_ORDER:
        n = ex["level_counts"][key]
        if n:
            A('<div class="%s" style="flex:%d" title="%s">%d</div>' % (LEVEL_CLASS[key], n, e(li[key]["label"]), n))
    A('</div><div class="small">')
    A(" ".join('%s %d' % (chip_level(status, k), ex["level_counts"][k]) for k in LEVEL_ORDER))
    A('</div>')

    # High threats
    A('<h3>The %d High-risk threats</h3>' % ex["high_threat_count"])
    A('<table><thead><tr><th>Threat</th><th>In plain words</th><th>Related targets and their level</th><th>What this means</th></tr></thead><tbody>')
    for h in status["high_threats"]:
        rt = "<br>".join('<a class="cardlink" href="#card-%s">%s</a> %s %s' % (
            e(x["id"]), e(x["id"]), chip_level(status, x["level"]), state_badge(x["state"]) if x["state"] else "") for x in h["related_targets"])
        meaning = []
        if h["has_current_model_proof"]:
            meaning.append("At least one related target has a model proof (%s)." % e(", ".join(h["targets_with_current_model_proof"])))
        else:
            meaning.append("No related target has a current model proof.")
        if h["related_targets_without_proof"]:
            meaning.append("Related targets with no proof: %s." % e(", ".join(h["related_targets_without_proof"])))
        meaning.append("This does not mean the threat is handled.")
        A('<tr><td><a href="#thr-%s"><b>%s</b></a><br>%s<br><span class="small">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
            e(h["id"]), e(h["id"]), risk_badge(h["risk"]), e(h["title"]), e(h["plain"]), rt, " ".join(meaning)))
    A('</tbody></table>')

    # Bugs
    A('<h3>Open bugs and the proofs that relate to them</h3>')
    A('<table><thead><tr><th>Bug</th><th>In plain words</th><th>Severity</th><th>Which proof, and what it shows</th></tr></thead><tbody>')
    for b in status["bugs"]:
        if not b["open"]:
            continue
        rel = b["proof_relation"]
        who = ""
        if rel["target"]:
            who = '<a class="cardlink" href="#card-%s">%s</a>: ' % (e(rel["target"]), e(rel["target"]))
        stat = (" <b>(%s)</b>" % e(rel["status"])) if rel["status"] else ""
        A('<tr><td><a href="#bug-%s"><b>%s</b></a></td><td>%s</td><td>%s</td><td>%s%s%s</td></tr>' % (
            e(b["id"]), e(b["id"]), e(b["plain"]), e(b["severity"]), who, e(rel["text"]), stat))
    A('</tbody></table>')
    A('<p class="small">Fixed bugs (%s) are listed in the bug section. Open means the docs say the code on main still has the problem.</p>' % e(", ".join(ex["bugs_fixed"])))
    A('</section>')

    # honesty levels
    A('<section id="levels"><h2>Honesty levels</h2><p>Each target has one level. A level is never shown as better than the evidence. '
      'The levels run from strongest to weakest.</p><div class="legend">')
    for key in LEVEL_ORDER:
        l = li[key]
        A('<div>%s <b>%d</b><br>%s</div>' % (chip_level(status, key), ex["level_counts"][key], e(l["text"])))
    A('</div>')
    A('<p class="small">Evidence labels used inside the proofs: <b>proved</b> means checked by Verus on a model. '
      '<b>assumed</b> means taken as true, not checked. <b>code reading</b> means a person read the shipped code and judged that it matches.</p></section>')

    # table
    A('<section id="targets"><h2>All %d active targets</h2>' % ex["active_targets"])
    A('<p class="small">Rank, score, coverage gap and quick win are the values recorded in <code>docs/mpl-verification-targets.md</code>. '
      'They are copied, not recomputed, and no proof changed them.</p>')
    A('<div class="controls"><span class="small">Level:</span><button class="on" data-filter="level" data-value="all">All</button>')
    for key in LEVEL_ORDER:
        A('<button data-filter="level" data-value="%s">%s</button>' % (key, e(li[key]["label"])))
    A('<span class="small">Origin:</span><button class="on" data-filter="origin" data-value="all">All</button>'
      '<button data-filter="origin" data-value="threat-driven">Threat model</button>'
      '<button data-filter="origin" data-value="capability-driven">Capability sweep</button>'
      '<input id="q" type="search" placeholder="Search"></div>')
    A('<table id="targets-table"><thead><tr><th>Rank</th><th>ID</th><th>What it covers (plain English)</th><th>Score</th><th>Gap</th>'
      '<th>Effort</th><th>Threats</th><th>Bugs</th><th>Proof file and result</th><th>Honesty level</th></tr></thead><tbody>')
    for t in status["targets"]:
        p = proofs.get(t["id"])
        if p:
            if p["verified"] is None:
                res = "no recorded run"
            else:
                res = "%d passed, %d failed%s" % (p["verified"], p["errors"], " (intentional)" if p["errors"] and not p["unexpected_failures"] else "")
            pc = '<span class="mono">%s</span><br>%s %s' % (e(p["file"].split("/")[-1]), e(res), state_badge(p["state"]))
        elif t["level"] == "in_crate_other_branch":
            pc = '<span class="small">partly proved on branch Mahnush_Verus, under 20 assumed aws-lc-rs facts; not on this branch</span>'
        else:
            pc = '<span class="small">none yet</span>'
        qw = "quick win" if t["quick_win"] else ""
        A('<tr data-level="%s" data-origin="%s"><td>%d</td><td><a class="cardlink" href="#card-%s"><b>%s</b></a><br><span class="small">%s</span></td>'
          '<td>%s<br><span class="small">%s</span></td><td>%s</td><td>%s</td><td>%s<br><span class="small">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
              e(t["level"]), e(t["origin"]), t["rank"], e(t["id"]), e(t["id"]), "T" if t["origin"] == "threat-driven" else "C",
              e(t["title"]), e(t["technical_name"][:150] + ("..." if len(t["technical_name"]) > 150 else "")), e(t["score"]), e(t["coverage_gap"] or ""), e(t["effort"]), e(qw),
              threat_chips(status, t["threats"]) or '<span class="small">none cited</span>',
              bug_chips(status, t["bugs"]) or '<span class="small">none</span>', pc, chip_level(status, t["level"])))
    A('</tbody></table></section>')

    # cards
    A('<section id="cards"><h2>Plain-English cards</h2><div class="controls"><button id="toggle-cards" type="button">Open all cards</button></div>')
    for t in status["targets"]:
        c = t["card"]
        p = proofs.get(t["id"])
        stale = p and p["state"] != "current"
        A('<details class="card" id="card-%s" data-level="%s"><summary><span class="id">%s</span> %s %s %s</summary><div class="cardbody">' % (
            e(t["id"]), e(t["level"]), e(t["id"]), e(t["title"]), chip_level(status, t["level"]), state_badge(p["state"]) if p else ""))
        A('<p class="small">Rank %d, score %s, %s. Related threats: %s. Related bugs: %s.</p>' % (
            t["rank"], e(t["score"]), e(t["origin"]), threat_chips(status, t["threats"]) or e(t["threats_note"]) or "none",
            bug_chips(status, t["bugs"]) or "none"))
        A('<dl>')
        A('<dt>What part of the library this is</dt><dd>%s</dd>' % e(c["area"]))
        A('<dt>What could go wrong</dt><dd>%s</dd>' % e(c["risk"]))
        A('<dt>%s</dt><dd>%s</dd>' % (e(c["checks_label"]), e(c["checks"])))
        A('<dt>%s</dt><dd>%s</dd>' % ("What the proof does NOT show" if t["level"] != "not_started" else "What is not covered or not known", e(c["not_shown"])))
        A('<dt>Result</dt><dd>%s</dd>' % e(c["result"]))
        A('</dl>')
        if c["expected_failure_explanation"]:
            A('<div class="box"><b>Why a failing check is the right result here.</b> %s</div>' % e(c["expected_failure_explanation"]))
        if p and (p["unexpected_failures"] or p["expected_failures_not_seen"]):
            A('<div class="box flag"><b>Unexpected result.</b> The recorded run does not match the expected failing checks. '
              'Unexpected: %s. Expected but not seen: %s.</div>' % (e(", ".join(p["unexpected_failures"]) or "none"), e(", ".join(p["expected_failures_not_seen"]) or "none")))
        if stale:
            A('<div class="box flag"><b>%s.</b> The proof file changed after the last recorded run, or there is no run. Re-run before relying on this result.</div>' % ("STALE" if p["state"] == "stale" else "NOT RUN"))
        if c["notes"]:
            A('<p><b>Findings and observations recorded in the docs</b></p><ul class="tight">%s</ul>' % "".join("<li>%s</li>" % e(n) for n in c["notes"]))
        if p and p["hypotheses"]:
            A('<details><summary class="small">Assumptions and hypotheses behind this proof (%d)</summary><ul class="tight">%s</ul></details>' % (
                len(p["hypotheses"]), "".join('<li><code>%s</code> <i>%s</i>: %s</li>' % (e(h["name"]), e(h["kind"].replace("_", " ")), e(h["text"])) for h in p["hypotheses"])))
        A('<p class="src">Written from: %s</p>' % "; ".join("<code>%s</code> line %d (%s)" % (e(s["doc"]), s["line"], e(s["locator"])) for s in c["sources"]))
        A('</div></details>')
    A('</section>')

    # proofs
    A('<section id="proofs"><h2>Proofs</h2><p>%d proof files live in <code>verus-proofs/</code>. Each one checks a model. '
      'The "Verus output line" is the tool\'s own wording, shown as recorded. A result is STALE if the file hash differs from the hash at the run.</p>' % len(status["proofs"]))
    A('<table><thead><tr><th>Target</th><th>File</th><th>Checks passed / failed</th><th>Verus output line</th><th>Recorded run</th><th>State</th><th>Docs agree</th></tr></thead><tbody>')
    for p in status["proofs"]:
        A('<tr><td><a class="cardlink" href="#card-%s">%s</a></td><td class="mono">%s</td><td>%s / %s%s</td><td class="mono">%s</td><td>%s<br><span class="small mono">sha256 %s</span></td><td>%s</td><td>%s</td></tr>' % (
            e(p["target"]), e(p["target"]), e(p["file"]),
            e(p["verified"]), e(p["errors"]), " (intentional)" if p["errors"] and not p["unexpected_failures"] else "",
            e(p["verus_output_line"] or ""), e(p["run_at"] or "not run"), e((p["file_sha256_at_run"] or p["file_sha256_now"])[:12]),
            state_badge(p["state"]), "yes" if p["docs_match_run"] else "NO"))
    A('</tbody></table>')
    A('<h3>Proofs with an intentional failing check</h3>')
    for p in status["proofs"]:
        if p["errors"]:
            fl = "".join("<li><code>%s</code> (line %d)</li>" % (e(f["function"]), f["line"]) for f in p["failing_obligations"])
            A('<div class="box"><b>%s: %d failing check(s) on purpose.</b> %s<ul class="tight">%s</ul></div>' % (e(p["target"]), p["errors"], e(p["failure_explanation"]), fl))
    A('<h3>Assumptions and hypotheses, by kind</h3><p class="small"><b>assumed</b>: taken as true, not checked. <b>premise</b>: a condition a theorem is stated under. '
      '<b>code reading</b>: a person read the shipped code. <b>not assumed</b>: named so it is clear it is not used.</p>')
    A('<table><thead><tr><th>Target</th><th>Assumed</th><th>Premise</th><th>Code reading</th></tr></thead><tbody>')
    for p in status["proofs"]:
        def col(kind):
            names = [h["name"] for h in p["hypotheses"] if h["kind"] == kind]
            if kind == "assumed":
                names += [h["name"] + " (not assumed)" for h in p["hypotheses"] if h["kind"] == "not_assumed"]
            return " ".join("<code>%s</code>" % e(n) for n in names) or "none"
        A('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (e(p["target"]), col("assumed"), col("premise"), col("code_reading")))
    A('</tbody></table></section>')

    # threats
    A('<section id="threats"><h2>Threats (%d)</h2><p class="small">Ratings are from <code>docs/mpl-threat-model.md</code> (column %s). '
      'Targets with no proof are shown too.</p>' % (len(status["threats"]), e(status["threats"][0]["risk_column"])))
    A('<table><thead><tr><th>ID</th><th>Threat</th><th>Severity</th><th>Likelihood</th><th>Risk</th><th>Related targets</th><th>Bugs</th></tr></thead><tbody>')
    for t in status["threats"]:
        rt = " ".join('<a class="cardlink tag" href="#card-%s" title="%s">%s</a>' % (e(x["id"]), e(li[x["level"]]["label"]), e(x["id"])) for x in t["related_targets"]) or '<span class="small">none (excluded or no target)</span>'
        A('<tr id="thr-%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
            e(t["id"]), e(t["id"]), e(t["title"]), e(t["severity"]), e(t["likelihood"]), risk_badge(t["risk"]), rt, bug_chips(status, t["bugs"]) or ""))
    A('</tbody></table></section>')

    # bugs
    A('<section id="bugs"><h2>Bug reports (%d)</h2>' % len(status["bugs"]))
    A('<table><thead><tr><th>Bug</th><th>In plain words</th><th>Severity</th><th>Status on main</th><th>Related targets</th><th>Proof relation</th></tr></thead><tbody>')
    for b in status["bugs"]:
        rel = b["proof_relation"]
        A('<tr id="bug-%s"><td><b>%s</b></td><td>%s</td><td>%s</td><td><span class="chip %s">%s</span><br><span class="small">%s</span></td><td>%s</td><td>%s%s</td></tr>' % (
            e(b["id"]), e(b["id"]), e(b["plain"]), e(b["severity"]), "badge-open" if b["open"] else "badge-fixed", "open" if b["open"] else "fixed",
            e(b["status_doc"]), " ".join('<a class="cardlink tag" href="#card-%s">%s</a>' % (e(x), e(x)) for x in b["targets"]),
            e(rel["text"]), (" <b>(%s)</b>" % e(rel["status"])) if rel["status"] else ""))
    A('</tbody></table></section>')

    # retired
    A('<section id="retired"><h2>Retired targets</h2><p class="small">Listed so the IDs stay stable. They are not counted.</p><ul>')
    for r in status["retired_targets"]:
        A('<li><b>%s</b> %s. %s</li>' % (e(r["id"]), e(r["technical_name"]), e(r["plain"])))
    A('</ul></section>')

    # glossary
    A('<section id="glossary"><h2>Glossary</h2><dl class="gl">')
    for gl in status["glossary"]:
        A('<dt>%s</dt><dd>%s</dd>' % (e(gl["term"]), e(gl["text"])))
    A('</dl></section>')

    # rules
    A('<section id="rules"><h2>Rules this page follows, and where the data comes from</h2><ul>')
    for r in status["page_rules"]:
        A('<li>%s</li>' % e(r))
    A('</ul>')
    A('<p>Data file: <code>dashboard/verification-status.json</code>. Rebuild with <code>python3 dashboard/generate_dashboard.py</code>. '
      'Refresh the proof runs with <code>--run-verus</code>. Fields that change between runs on one commit: %s.</p>' % e(", ".join(status["declared_nondeterministic_fields"])))
    A('<p class="small">The commit above is %s.</p>' % e(g["commit_meaning"]))
    A('<table><thead><tr><th>Source file</th><th>sha256 (first 16)</th></tr></thead><tbody>')
    for s in status["sources"]:
        A('<tr><td class="mono">%s</td><td class="mono">%s</td></tr>' % (e(s["path"]), e(s["sha256"][:16])))
    A('</tbody></table>')
    A('<footer>Prototype. Modeled on the design in docs of branch Mahnush_Verus (verification-dashboard-design.md); see dashboard/DESIGN.md.</footer></section>')
    A('</main><script>%s</script></body></html>\n' % JS)
    return "".join(parts)


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-verus", action="store_true", help="run Verus on every proof file first and record the results")
    ap.add_argument("--render-only", action="store_true", help="rebuild the HTML from the existing JSON, nothing else")
    ap.add_argument("--timestamp", help="fixed UTC timestamp (for reproducible output)")
    ap.add_argument("--strict", action="store_true", help="exit 2 if any proof result is stale, missing or unexpected")
    ap.add_argument("--out-dir", help="write the JSON and HTML here instead of dashboard/ (used by the verify script)")
    args = ap.parse_args()

    out_dir = Path(args.out_dir) if args.out_dir else DASH
    out_dir.mkdir(parents=True, exist_ok=True)
    status_path = out_dir / STATUS_FILE.name
    html_path = out_dir / HTML_FILE.name

    if args.render_only:
        status = json.loads(status_path.read_text(encoding="utf-8"))
        html_path.write_text(render_html(status), encoding="utf-8")
        print("wrote %s" % html_path)
        return 0

    plain = json.loads(PLAIN_FILE.read_text(encoding="utf-8"))
    if args.run_verus:
        binary = find_verus()
        if not binary:
            print("error: Verus not found. Set VERUS_BIN or install it at ~/verus/verus.", file=sys.stderr)
            return 1
        files = sorted({y["proof_file"] for y in list(parse_yaml_blocks(DOC_T01).values()) + list(parse_yaml_blocks(DOC_C02).values()) if y.get("proof_file")})
        print("running Verus (%s) on %d files" % (binary, len(files)))
        runs_data = record_runs(binary, files)
    else:
        runs_data = load_runs()
        if not runs_data["runs"]:
            print("warning: no recorded Verus runs; proof results will show as not run", file=sys.stderr)

    ts = args.timestamp or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        status = build_status(ts, plain, runs_data)
    except GenError as ex:
        print("error: %s" % ex, file=sys.stderr)
        return 1
    status_path.write_text(json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    html_path.write_text(render_html(status), encoding="utf-8")
    ex = status["executive"]
    print("wrote %s and %s" % (status_path, html_path))
    print("targets: %d; levels: %s" % (ex["active_targets"], ex["level_counts"]))
    print("stale: %s; not run: %s; drift: %d" % (ex["stale_proofs"] or "none", ex["proofs_not_run"] or "none", len(ex["docs_drift"])))
    for d in ex["docs_drift"]:
        print("  drift: %s" % d)
    if args.strict and (ex["stale_proofs"] or ex["proofs_not_run"] or ex["unexpected_failures"] or ex["docs_drift"]):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
