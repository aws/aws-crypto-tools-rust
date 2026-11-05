#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Write a one-file HTML page for reviewing every deviation with a person.

Usage: review_html.py <config.toml> <findings.json> <out.html>

Each deviation, rename and out-of-scope entry becomes a card showing caller
code two ways: strictly following the Smithy model, and what the crate does.
An entry may carry hand-written `example_strict` / `example_ours` code (for
shape changes a signature can't show); otherwise the code is generated from
the findings' real signatures. The cards are plain HTML; a small optional
script adds search, filters and approve/reject buttons.
"""

import html
import json
import re
import sys
import tomllib
from collections import defaultdict

NUMBERS = {"i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "usize", "isize"}


def plainest(expected):
    """The simplest spelling of what the model wants, from the checker's expected list."""
    opts = [o.strip() for o in expected.split("|") if o.strip()]
    owned = [o for o in opts if not o.startswith("&") and not o.startswith("impl ")] or opts
    return min(owned, key=len) if owned else ""


def value(ty, member):
    """A short example argument of type `ty`, so a call reads like real code."""
    t = re.sub(r"^impl (Into|IntoShared)<(.*)>$", r"\2", ty.strip())
    if t.startswith("Option<"):
        return f"Some({value(t[7:-1], member)})"
    if t in NUMBERS:
        return {"frame_length": "4096", "max_encrypted_data_keys": "3"}.get(member, "100") + f"  /* {t} */"
    if t == "Duration":
        return "Duration::from_secs(60)"
    if t in ("String", "&str"):
        return f'"{member}"'
    if t in ("Vec<u8>", "&[u8]", "Blob", "Secret"):
        return "key_bytes  /* Vec<u8> */"
    if re.fullmatch(r"\[u8; \d+\]", t):
        return "[0u8; 32]"
    if t.startswith(("BTreeSet<", "Vec<")) and "String" in t:
        kind = "BTreeSet" if t.startswith("BTree") else "vec!"
        return 'BTreeSet::from(["key".to_string()])' if kind == "BTreeSet" else 'vec!["key".to_string()]'
    if t.startswith("Shared"):
        return f"{member}  /* {t} */"
    return f"{member}  /* {t} */"


def caller(f):
    """(strict, ours) caller code for one finding, or None to leave it out."""
    t, m, obs, exp, check = f["rust_type"], f["rust_member"], f["observed"], f["expected"], f["check"]
    if not t:
        return None
    var = re.sub(r"(Fluent)?Builder$", "", t)
    var = re.sub(r"(?<!^)([A-Z])", r"_\1", var).lower()
    if check == "setter_type":
        if m.startswith(("set_", "get_")):
            return None  # same story as the plain setter
        want = " ; ".join(plainest(e) for e in exp.split(" ; ")) if " ; " in exp else plainest(exp)
        return (f"{t}::default().{m}({value(want, m)})", f"{t}::default().{m}({value(obs, m)})")
    if check in ("getter_type", "member_type", "list_getter_option"):
        if m.startswith("get_"):
            return None
        want = plainest(exp) or "&[T]"
        return (f"let x: {want} = {var}.{m}();", f"let x: {obs} = {var}.{m}();")
    if check == "variant_type":
        return (f"{t}::{m}({value(plainest(exp), m.lower())})", f"{t}::{m}({obs.strip(chr(91) + chr(93)).strip(chr(39))}::builder()...build()?)")
    if check in ("type_missing", "trait_missing", "handle_missing", "client_missing", "config_missing"):
        return (f"use ...::{t};", f"// no {t}")
    if check in ("member_missing", "getter_missing", "builder_method_missing", "operation_input_missing",
                 "variant_missing", "operation_missing"):
        if m.startswith(("set_", "get_")):
            return None
        return (f"{var}.{m}(..)", f"// {t} has no {m}")
    if check == "builder_missing":
        return (f"{t}::builder()...build()?", f"// {t} has no builder; only the library makes one")
    if check in ("member_extra", "variant_extra"):
        return (f"// the model has no {m}", f"{var}.{m}(..)")
    if check == "lint.renamed_reexport":
        return (f"use aws_esdk::types::{obs};", f"use {f['subject']};  // same type, other name")
    if check.startswith("lint."):
        return (f"// {f['message']}", f"{t}::{m}  // {obs}" if m else f"{t}  // {obs}")
    return None


def main():
    cfg_path, findings_path, out = sys.argv[1:4]
    cfg = tomllib.load(open(cfg_path, "rb"))
    findings = json.load(open(findings_path))
    by_entry = defaultdict(list)
    for f in findings:
        if f.get("deviation"):
            by_entry[f["deviation"]].append(f)

    cards = []

    def card(kind, entry, generated):
        strict, ours = entry.get("example_strict"), entry.get("example_ours")
        rows, seen = [], set()
        for pair in generated:
            if pair and pair not in seen:
                seen.add(pair)
                rows.append(pair)
        cards.append({"kind": kind, "id": entry.get("id") or entry.get("shape") or entry.get("rust"),
                      "reason": entry["reason"], "status": entry.get("status", "accepted"),
                      "why": entry.get("what_differs", ""), "justification": entry.get("justification", ""),
                      "later": entry.get("later", ""), "later_why": entry.get("later_why", ""),
                      "strict": strict, "ours": ours, "rows": rows})

    open_ = [f for f in findings if not f["accepted"]]
    for f in open_:
        cards.append({"kind": "open finding", "id": f["id"], "reason": f["message"], "status": "open",
                      "why": "", "justification": "", "later": "", "later_why": "", "strict": None, "ours": None, "rows": [p for p in [caller(f)] if p]})
    for d in cfg.get("deviation", []):
        card("deviation", d, [caller(f) for f in by_entry.get(d["id"], [])])
    for r in cfg.get("rename", []):
        model_name = r["shape"].split("#", 1)[1].replace("$", ".")
        card("rename", r, [(model_name, r["rust"])])
    for o in cfg.get("out_of_scope", []):
        name = o["shape"].split("#", 1)[1]
        card("out of scope", o, [(f"{name}  // available", f"// {name} is not ported yet")])
    for m in cfg.get("mirror", []):
        card("mirror", dict(m, id=m["rust"]), [("// no such operation in the model",
                                                 f"{m['rust']}  // checked like {m['like'].split('#')[1]}")])

    order = {"open": 0, "proposed": 1, "deferred": 2, "accepted": 3}
    cards.sort(key=lambda c: (order.get(c["status"], 9), c["kind"] != "deviation"))
    body = "\n".join(card_html(i, c) for i, c in enumerate(cards))
    counts = defaultdict(int)
    for c in cards:
        counts[c["status"]] += 1
    summary = " · ".join(f"{counts[s]} {s}" for s in ("open", "proposed", "deferred", "accepted") if counts[s])
    open(out, "w").write(PAGE.replace("__CARDS__", body).replace("__SUMMARY__", html.escape(summary)))
    print(f"{len(cards)} cards ({summary}) -> {out}")


def card_html(i, c):
    """One card as plain HTML, so it shows even where scripts don't run."""
    e = html.escape
    if c["strict"] or c["ours"]:
        main = (f'<div class="pair"><div><h4>Strictly following the Smithy model</h4><pre class="strict">{e(c["strict"] or "")}</pre></div>'
                f'<div><h4>What we do</h4><pre class="ours">{e(c["ours"] or "")}</pre></div></div>')
        extra = c["rows"]
    else:
        head = c["rows"][:4]
        main = (f'<div class="pair"><div><h4>Strictly following the Smithy model</h4><pre class="strict">'
                f'{e(chr(10).join(s for s, _ in head))}</pre></div>'
                f'<div><h4>What we do</h4><pre class="ours">{e(chr(10).join(o for _, o in head))}</pre></div></div>')
        extra = c["rows"][4:]
    more = ""
    if extra:
        lines = "".join(f'<tr><td><code>{e(s)}</code></td><td><code>{e(o)}</code></td></tr>' for s, o in extra)
        more = f'<details><summary>{len(extra)} more places this applies</summary><table>{lines}</table></details>'
    why = (f'<p class="why"><b>What differs:</b> {e(c["why"])}</p>' if c["why"] else "")
    why += (f'<p class="why"><b>Why we do it this way:</b> {e(c["justification"])}</p>' if c["justification"] else "")
    why += (f'<p class="why"><b>Switching to Smithy after release:</b> {e(c["later"])}. {e(c["later_why"])}</p>'
            if c["later"] else "")
    later = (f'<span class="later {"brk" if c["later"] == "breaking" else "ok"}">'
             f'{"breaking later" if c["later"] == "breaking" else "can change later"}</span>' if c["later"] else "")
    return (f'<details class="card" data-status="{e(c["status"])}" data-kind="{e(c["kind"])}" data-id="{e(c["id"])}"'
            f' data-later="{e(c["later"])}">'
            f'<summary><span class="badge {e(c["status"])}">{e(c["status"])}</span>'
            f'<span class="badge">{e(c["kind"])}</span>{later}<span class="reason">{e(c["reason"])}</span>'
            f'<span class="vote"></span></summary>{main}{why}{more}<div class="id">{e(c["id"])}</div></details>')


PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Smithy conformance review</title>
<style>
body{font:15px/1.45 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1d2330}
header{position:sticky;top:0;background:#fff;border-bottom:1px solid #ddd;padding:10px 16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;z-index:1}
h1{font-size:17px;margin:0 12px 0 0}
input,select,button{font:inherit;font-size:13px;padding:3px 8px}
main{padding:16px 24px;max-width:none;margin:0}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;margin:0 0 14px;padding:12px 16px}
.card.approved{border-left:6px solid #2e7d32}.card.rejected{border-left:6px solid #c62828}
.card.approved .badge:first-child::after{content:" → accepted"}.card.rejected .badge:first-child::after{content:" → rejected"}
summary{display:flex;gap:6px;align-items:center;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸";color:#889;width:12px}details[open]>summary::before{content:"▾"}
.reason{font-weight:600}
.why{margin:8px 0 0;font-size:14px}
.later{font-size:12px;padding:1px 8px;border-radius:9px;white-space:nowrap}
.later.brk{background:#c62828;color:#fff}.later.ok{background:#dcefdc}
.vote{margin-left:auto;white-space:nowrap}
.pair{margin-top:10px}
.rejected-s{background:#ffd9d9}
h4{font-size:12px;color:#556;margin:0 0 4px;font-weight:600}
.badge{font-size:12px;padding:1px 8px;border-radius:9px;background:#e8eaf0}
.accepted{background:#dcefdc}.proposed{background:#fff1c4}.deferred{background:#e3e8ff}.open{background:#ffd9d9}
.pair{display:flex;flex-direction:column;gap:10px}
pre{margin:0;padding:8px 10px;border-radius:6px;font:13px/1.45 ui-monospace,monospace;white-space:pre;overflow-x:auto}
pre.strict{background:#eef4ff}pre.ours{background:#fff6e8}
details{margin-top:8px;font-size:13px}
table{width:100%;border-collapse:collapse;margin-top:4px;table-layout:fixed}
td{padding:3px 6px;border-bottom:1px solid #f0f0f0;vertical-align:top;word-break:break-word}
.id{font:11px ui-monospace,monospace;color:#99a;margin-top:8px}
.hide{display:none}
</style></head><body>
<header><h1>Smithy conformance review</h1><span>__SUMMARY__</span><span id="tools"></span></header>
<main>
__CARDS__
</main>
<script>
// Optional: search, filters, approve/reject. The cards above need no script.
const votes = JSON.parse(localStorage.getItem('conformance-votes') || '{}');
const cards = [...document.querySelectorAll('.card')];
document.getElementById('tools').innerHTML = '<input id="q" placeholder="search" size="22"> ' +
  '<select id="st"><option value="">all statuses</option><option>open</option><option>proposed</option><option>deferred</option><option>accepted</option><option>rejected</option></select> ' +
  '<select id="lt"><option value="">breaking or not</option><option value="breaking">breaking later</option><option value="not breaking">can change later</option></select> ' +
  '<button id="exp">export decisions</button> <span id="nv"></span>';
function paint(){
  const q = document.getElementById('q').value.toLowerCase(), st = document.getElementById('st').value,
        lt = document.getElementById('lt').value;
  for (const c of cards) {
    c.classList.toggle('hide', !((!q || c.textContent.toLowerCase().includes(q)) && (!st || c.dataset.status === st) && (!lt || c.dataset.later === lt)));
    c.classList.toggle('approved', votes[c.dataset.id] === 'approved');
    c.classList.toggle('rejected', votes[c.dataset.id] === 'rejected');
  }
  document.getElementById('nv').textContent = Object.values(votes).filter(Boolean).length + ' decided (saved in this browser)';
}
for (const c of cards) {
  for (const choice of ['approved', 'rejected']) {
    const b = document.createElement('button'); b.textContent = choice === 'approved' ? 'approve' : 'reject';
    b.onclick = (ev) => { ev.preventDefault(); votes[c.dataset.id] = votes[c.dataset.id] === choice ? '' : choice;
      localStorage.setItem('conformance-votes', JSON.stringify(votes)); paint(); };
    b.title = choice === 'approved' ? 'mark accepted' : 'mark rejected: fix the code instead';
    c.querySelector('.vote').appendChild(b);
  }
}
['q','st','lt'].forEach(id => document.getElementById(id).oninput = paint);
document.getElementById('exp').onclick = () => {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(votes, null, 1)], {type: 'application/json'}));
  a.download = 'conformance-decisions.json'; a.click();
};
paint();
</script></body></html>
"""

if __name__ == "__main__":
    main()
