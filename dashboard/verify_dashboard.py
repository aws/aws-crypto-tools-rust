#!/usr/bin/env python3
"""Check the MPL verification dashboard against the repo. Python 3 standard library only.

Run from anywhere:  python3 dashboard/verify_dashboard.py
Add --no-verus to skip the fresh Verus runs (all other checks still run).

Checks:
  1  all 33 active targets are in the JSON, in the HTML table and as HTML cards
  2  score and rank equal the values in docs/mpl-verification-targets.md (independent parse)
  3  no plain-English card field is empty; every card cites sources with line numbers
  4  the nine proof results equal a fresh Verus run (unless --no-verus)
  5  the JSON is current: a rebuild gives the same data (commit and timestamp fields excluded)
  6  the generator is deterministic: two runs differ only in the declared timestamp field
  7  the HTML makes no network or external resource references
  8  the HTML parses, and every JSON target id is present
  9  no banned claim wording; the model-level statement is present
  10 staleness rule: a changed proof hash marks the result STALE
  11 no tracked file was changed (only new files under dashboard/)
"""

import argparse
import copy
import html.parser
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

DASH = Path(__file__).resolve().parent
REPO = DASH.parent
sys.path.insert(0, str(DASH))
import generate_dashboard as gd  # noqa: E402

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, (": " + detail) if detail else ""))
    return ok


def independent_ranked():
    """Parse the ranked table with a separate, simple regex (not the generator's parser)."""
    text = (REPO / "docs/mpl-verification-targets.md").read_text(encoding="utf-8")
    start = text.index("## 1. Combined ranked summary")
    end = text.index("## 2. Detailed recommendations")
    out = {}
    for line in text[start:end].split("\n"):
        m = re.match(r"^\| (\d+) \| ([0-9.]+) \| ([TC]) \| ([TC]\d\d) ", line)
        if m:
            out[m.group(4)] = (int(m.group(1)), m.group(2))
    return out


class IdCollector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.tags = []
        self.row_ids = []
        self.errors = []
        self._in_tbody_table = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append((tag, a))
        if "id" in a:
            self.ids.add(a["id"])

    def error(self, message):  # pragma: no cover
        self.errors.append(message)


def strip_volatile(status):
    s = copy.deepcopy(status)
    for k in ("timestamp_utc", "commit", "commit_short", "sources_clean", "dirty_paths"):
        s["generated"].pop(k, None)
    s["verus"].pop("runs_recorded_on_commit", None)
    return s


def run_gen(out_dir, ts):
    p = subprocess.run([sys.executable, str(DASH / "generate_dashboard.py"), "--out-dir", str(out_dir), "--timestamp", ts],
                       capture_output=True, text=True, cwd=str(REPO))
    return p.returncode, p.stdout + p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-verus", action="store_true")
    args = ap.parse_args()

    status = json.loads((DASH / "verification-status.json").read_text(encoding="utf-8"))
    page = (DASH / "verification-dashboard.html").read_text(encoding="utf-8")
    ranked = independent_ranked()

    # 1
    ids = [t["id"] for t in status["targets"]]
    check("1 JSON has 33 active targets matching the docs table", len(ids) == 33 and set(ids) == set(ranked), "%d in JSON, %d in docs" % (len(ids), len(ranked)))
    col = IdCollector()
    col.feed(page)
    missing_cards = [i for i in ids if "card-" + i not in col.ids]
    check("1 every target has a card in the HTML", not missing_cards, str(missing_cards))
    rows = re.findall(r'<tr data-level="[^"]+" data-origin="[^"]+"><td>(\d+)</td><td><a class="cardlink" href="#card-([TC]\d\d)"', page)
    check("1 every target has a row in the HTML table", sorted(r[1] for r in rows) == sorted(ids), "%d rows" % len(rows))

    # 2
    bad = []
    for t in status["targets"]:
        if (t["rank"], t["score"]) != ranked.get(t["id"]):
            bad.append((t["id"], t["rank"], t["score"], ranked.get(t["id"])))
    check("2 score and rank equal docs/mpl-verification-targets.md", not bad, str(bad))
    ranks = sorted(t["rank"] for t in status["targets"])
    check("2 ranks are 1..33 with no gap", ranks == list(range(1, 34)))
    check("2 quick wins are exactly T02, C01, C02 as the docs say", sorted(t["id"] for t in status["targets"] if t["quick_win"]) == ["C01", "C02", "T02"])

    # 3
    empty = []
    for t in status["targets"]:
        c = t["card"]
        for f in ("area", "risk", "checks", "not_shown", "result"):
            if not str(c.get(f, "")).strip():
                empty.append((t["id"], f))
        if not str(t["title"]).strip() or not c["sources"] or any(not s.get("line") for s in c["sources"]):
            empty.append((t["id"], "title/sources"))
    check("3 no plain-English card field is empty, every card cites sources with line numbers", not empty, str(empty))
    nopf = [t for t in status["targets"] if t["level"] == "not_started"]
    check("3 targets with no proof say so plainly", all("No proof exists yet" in t["card"]["result"] for t in nopf) and len(nopf) == 23, "%d targets" % len(nopf))
    failing_expl = [t["id"] for t in status["targets"] if t["card"]["expected_failure_explanation"]]
    check("3 T02, T06, T13 explain the intentional failures", sorted(failing_expl) == ["T02", "T06", "T13"], str(failing_expl))

    # 4
    if args.no_verus:
        print("SKIP  4 fresh Verus run (--no-verus)")
    else:
        binary = gd.find_verus()
        if not binary:
            check("4 Verus found", False, "set VERUS_BIN")
        else:
            ver, _ = gd.verus_version(binary)
            check("4 Verus version equals the recorded one", ver == status["verus"]["version"], "%s vs %s" % (ver, status["verus"]["version"]))
            mism = []
            for p in status["proofs"]:
                r = gd.run_verus_file(binary, p["file"])
                got = (r["verified"], r["errors"], sorted(f["function"] for f in r["failing_obligations"]))
                rec = (p["verified"], p["errors"], sorted(f["function"] for f in p["failing_obligations"]))
                print("      %s %s -> %d verified, %d errors" % (p["target"], p["file"], r["verified"], r["errors"]))
                if got != rec:
                    mism.append((p["target"], got, rec))
            check("4 nine proof results equal a fresh Verus run", len(status["proofs"]) == 9 and not mism, str(mism))

    # 5, 6
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2, tempfile.TemporaryDirectory() as d3:
        rc1, o1 = run_gen(d1, "2000-01-01T00:00:00Z")
        rc2, o2 = run_gen(d2, "2000-01-01T00:00:00Z")
        rc3, o3 = run_gen(d3, "2001-02-03T04:05:06Z")
        check("6 the generator runs cleanly", rc1 == rc2 == rc3 == 0, (o1 + o2 + o3)[-300:] if (rc1 or rc2 or rc3) else "")
        j1 = (Path(d1) / "verification-status.json").read_bytes()
        j2 = (Path(d2) / "verification-status.json").read_bytes()
        h1 = (Path(d1) / "verification-dashboard.html").read_bytes()
        h2 = (Path(d2) / "verification-dashboard.html").read_bytes()
        check("6 same timestamp gives byte-identical JSON and HTML", j1 == j2 and h1 == h2)
        j3 = (Path(d3) / "verification-status.json").read_text(encoding="utf-8")
        h3 = (Path(d3) / "verification-dashboard.html").read_text(encoding="utf-8")
        n1 = j1.decode("utf-8").replace("2000-01-01T00:00:00Z", "<TS>")
        n3 = j3.replace("2001-02-03T04:05:06Z", "<TS>")
        check("6 two runs differ only in the timestamp field", n1 == n3 and h1.decode("utf-8").replace("2000-01-01T00:00:00Z", "<TS>") == h3.replace("2001-02-03T04:05:06Z", "<TS>"))
        fresh = json.loads(j1.decode("utf-8"))
        check("5 committed JSON is current with docs and proofs", strip_volatile(fresh) == strip_volatile(status))

    # 7
    ext = re.findall(r"https?://|//cdn|@import|url\(|<link\b|<img\b|<iframe\b|<script[^>]*\bsrc=|\bxmlns=", page)
    check("7 HTML has no network or external resource references", not ext, str(ext))
    check("7 grep for http(s) finds nothing", not re.search(r"https?:", page))

    # 8
    pc = IdCollector()
    pc.feed(page)
    missing = [i for i in ids if ("card-" + i) not in pc.ids]
    check("8 HTML parses and every target id appears", not pc.errors and not missing and all(i in page for i in ids))

    # 9
    banned = [w for w in (r"\bmitigated\b", r"\bsecure\b", r"\bsecurely\b", r"code is verified", r"verified code", r"fully verified", r"formally verified", r"\bis safe\b", r"\bnow safe\b") if re.search(w, page, re.I)]
    check("9 no banned claim wording", not banned, str(banned))
    check("9 model-level statement present", "None checks the shipped code" in page and status["executive"]["targets_with_proof_in_shipped_code_on_this_branch"] == 0)
    check("9 no em-dash or en-dash in page text", "\u2014" not in page and "\u2013" not in page)
    bad_words = [w for w in ("master", "slave", "whitelist", "blacklist") if re.search(r"\b%s\b" % w, page, re.I)]
    check("9 inclusive language", not bad_words, str(bad_words))
    check("9 level counts add up to 33", sum(status["executive"]["level_counts"].values()) == 33)

    # 10
    plain = json.loads((DASH / "plain-english.json").read_text(encoding="utf-8"))
    runs = json.loads((DASH / "proof-runs.json").read_text(encoding="utf-8"))
    runs2 = copy.deepcopy(runs)
    first = sorted(runs2["runs"])[0]
    runs2["runs"][first]["sha256"] = "0" * 64
    st2 = gd.build_status("2000-01-01T00:00:00Z", plain, runs2)
    stale_ids = st2["executive"]["stale_proofs"]
    hp = gd.render_html(st2)
    check("10 a changed proof file marks its result STALE", len(stale_ids) == 1 and "STALE" in hp, str(stale_ids))
    check("10 current build has no stale or missing results", not status["executive"]["stale_proofs"] and not status["executive"]["proofs_not_run"])
    check("10 no unexpected failures and no docs drift", not status["executive"]["unexpected_failures"] and not status["executive"]["docs_drift"], str(status["executive"]["docs_drift"]))

    # 11
    p = subprocess.run(["git", "status", "--porcelain"], cwd=str(REPO), capture_output=True, text=True)
    changed_tracked = [l for l in p.stdout.split("\n") if l and not l.startswith("??")]
    check("11 no tracked file is modified", not changed_tracked, str(changed_tracked))

    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d passed, %d failed" % (len(RESULTS), len(RESULTS) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
