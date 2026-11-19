#!/usr/bin/env python3
"""C08 model mutation set. Run from the repo root:
    python3 .agents/tasks/mpl-four-proofs/c08-mutate.py
Each mutant is a copy of verus-proofs/c08_cache_usage_counters.rs with ONE deliberate change to
the MODEL (never to mpl/). The mutant is written to .agents/tasks/mpl-four-proofs/mutants/c08/,
run with ~/verus/verus, and compared with its prediction. Writes c08-mutation-run.txt.
These checks cover edits to the model only, not edits to the shipped code.
"""
import os, re, subprocess
ROOT = os.getcwd()
SRC = os.path.join(ROOT, "verus-proofs/c08_cache_usage_counters.rs")
OUT = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/mutants/c08")
REC = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/c08-mutation-run.txt")
VERUS = os.path.expanduser("~/verus/verus")
os.makedirs(OUT, exist_ok=True)
base = open(SRC).read()


def sub(text, old, new, count=1):
    n = text.count(old)
    if n != count:
        raise SystemExit(f"anchor found {n} times, expected {count}: {old!r}")
    return text.replace(old, new)


def run_verus(path):
    p = subprocess.run([VERUS, path], capture_output=True, text=True, cwd=ROOT)
    out = p.stdout + p.stderr
    m = re.search(r"verification results:: (\d+) verified, (\d+) errors", out)
    return out, ((int(m.group(1)), int(m.group(2))) if m else None), p.returncode


def failing_fns(out, text):
    lines = text.split("\n")
    names = []
    for m in re.finditer(r"-->\s+\S*?:(\d+):\d+", out):
        ln = int(m.group(1))
        for k in range(ln - 1, -1, -1):
            mm = re.match(r"\s*(?:pub )?(?:proof |open spec )?fn (\w+)", lines[k])
            if mm:
                names.append(mm.group(1))
                break
    seen = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return seen


OVF = "    u.messages as int + 1 > u64::MAX as int || u.bytes as int + b as int > u64::MAX as int"
MSG = "u.messages as int + 1 > u64::MAX as int ||"
BYT = "u.bytes as int + b as int > u64::MAX as int"
UNCH = "    if would_overflow(u, b) {\n        (u, false)"

M = []  # (id, predicted, description, function text -> text)


def add(mid, pred, desc, fn):
    M.append((mid, pred, desc, fn))


add("m01_unchecked_add", "reject",
    "would_overflow is always false (the overflow guard is gone; the spec cast `as u64` wraps)",
    lambda t: sub(t, OVF, "    false"))
add("m02_exec_wrapping_add_bytes", "reject",
    "record_use (exec): `bytes.checked_add(b)` replaced by `Some(bytes.wrapping_add(b))`",
    lambda t: sub(t, "    let t = u.bytes.checked_add(b);", "    let t = Some(u.bytes.wrapping_add(b));"))
add("m03_exec_wrong_increment", "reject",
    "record_use (exec): `messages.checked_add(1)` replaced by `checked_add(2)`",
    lambda t: sub(t, "    let m = u.messages.checked_add(1);", "    let m = u.messages.checked_add(2);"))
add("m04_narrower_message_width", "reject",
    "would_overflow: the message counter limit is u32::MAX instead of u64::MAX (narrower width)",
    lambda t: sub(t, MSG, "u.messages as int + 1 > u32::MAX as int ||"))
add("m05_wider_byte_width", "reject",
    "would_overflow: the byte limit is u64::MAX + 1 (one bit too wide; the spec cast wraps)",
    lambda t: sub(t, BYT, "u.bytes as int + b as int > u64::MAX as int + 1"))
add("m06_evict_on_success", "reject",
    "update_spec: the branches are swapped, so the entry is evicted when record_use succeeds",
    lambda t: sub(t, "        if r.1 {\n            (Res::Ok, Cache { entries: c.entries.insert",
                  "        if !r.1 {\n            (Res::Ok, Cache { entries: c.entries.insert"))
add("m07_no_eviction_on_failure", "reject",
    "update_spec: on failure the entry is kept (inserted unchanged) instead of removed",
    lambda t: sub(t, "entries: c.entries.remove(call.id), poisoned", "entries: c.entries.insert(call.id, r.0), poisoned"))
add("m08_reset_on_overflow", "reject",
    "record_use_spec: on overflow the counters are reset to zero (not left unchanged)",
    lambda t: sub(t, UNCH, "    if would_overflow(u, b) {\n        (UM { messages: 0, bytes: 0 }, false)"))
add("m09_saturate_on_overflow", "reject",
    "record_use_spec: on overflow the counters saturate at u64::MAX and the call reports success",
    lambda t: sub(t, UNCH, "    if would_overflow(u, b) {\n        (UM { messages: u64::MAX, bytes: u64::MAX }, true)"))
add("m10_off_by_one_messages", "reject",
    "would_overflow: `messages + 1 >= u64::MAX` (rejects one value too early)",
    lambda t: sub(t, MSG, "u.messages as int + 1 >= u64::MAX as int ||"))
add("m11_off_by_one_bytes", "reject",
    "would_overflow: `bytes + b >= u64::MAX` (rejects exactly u64::MAX too early)",
    lambda t: sub(t, BYT, "u.bytes as int + b as int >= u64::MAX as int"))
add("m12_partial_update_spec", "reject",
    "record_use_spec: on overflow the message count is still incremented (partial update)",
    lambda t: sub(t, UNCH, "    if would_overflow(u, b) {\n        (UM { messages: if u.messages < u64::MAX { (u.messages + 1) as u64 } else { u.messages }, bytes: u.bytes }, false)"))
add("m13_partial_update_exec", "reject",
    "record_use (exec): messages is stored before the byte sum is checked (partial update)",
    lambda t: sub(t, """    match (m, t) {
        (Some(messages), Some(total_bytes)) => {
            // entry.rs :218-219
            u.messages = messages;
            u.bytes = total_bytes;
            true
        },
        _ => false,
    }""", """    match m {
        Some(messages) => {
            u.messages = messages;
            match t {
                Some(total_bytes) => {
                    u.bytes = total_bytes;
                    true
                },
                None => false,
            }
        },
        None => false,
    }"""))
add("m14_exec_message_not_stored", "reject",
    "record_use (exec): the new message count is not stored (counter not updated)",
    lambda t: sub(t, "            u.messages = messages;\n            u.bytes = total_bytes;", "            u.messages = u.messages;\n            u.bytes = total_bytes;"))
add("m15_exec_bytes_not_stored", "reject",
    "record_use (exec): the new byte total is not stored (counter not updated)",
    lambda t: sub(t, "            u.bytes = total_bytes;\n            true", "            u.bytes = u.bytes;\n            true"))
add("m16_exec_true_on_overflow", "reject",
    "record_use (exec): returns true when a sum overflows (no eviction signal)",
    lambda t: sub(t, "        _ => false,\n    }", "        _ => true,\n    }"))
add("m17_poisoned_store_returns_ok", "reject",
    "update_spec: a poisoned store returns Ok instead of Err(Internal)",
    lambda t: sub(t, "(Res::ErrInternal, c)", "(Res::Ok, c)"))
add("m18_absent_id_creates_entry", "reject",
    "update_spec: an absent identifier gets a new entry {1, bytes}",
    lambda t: sub(t, "        (Res::Ok, c)\n    } else {\n        let r",
                  "        (Res::Ok, Cache { entries: c.entries.insert(call.id, UM { messages: 1, bytes: call.bytes }), poisoned: c.poisoned })\n    } else {\n        let r"))
add("m19_eviction_flushes_cache", "reject",
    "update_spec: a failed record_use empties the whole map (evicts the wrong entries)",
    lambda t: sub(t, "entries: c.entries.remove(call.id), poisoned", "entries: Map::empty(), poisoned"))
add("m20_eviction_returns_error", "reject",
    "update_spec: eviction returns Err(Internal) instead of Ok",
    lambda t: sub(t, "(Res::Ok, Cache { entries: c.entries.remove(call.id)", "(Res::ErrInternal, Cache { entries: c.entries.remove(call.id)"))
add("m21_evicted_entry_resurrected", "reject",
    "step_entry: an absent entry becomes Some({0,0}) on a call (an evicted entry comes back)",
    lambda t: sub(t, "        None => None,\n        Some(u) => {\n            let r = record_use_spec(u, b);",
                  "        None => Some(UM { messages: 0, bytes: 0 }),\n        Some(u) => {\n            let r = record_use_spec(u, b);"))
add("m22_sum_ignores_bytes", "reject",
    "sum_bytes: the first byte count is dropped from the sum",
    lambda t: sub(t, "bs[0] as int + sum_bytes(bs.drop_first())", "0 + sum_bytes(bs.drop_first())"))
add("m23_total_bound_strict", "reject",
    "theorem_run_entry: the message total bound is `<` instead of `<=`",
    lambda t: sub(t, "<==> (u.messages as int + bs.len() <= u64::MAX as int", "<==> (u.messages as int + bs.len() < u64::MAX as int"))
add("m24_bytes_for_ignores_id", "reject",
    "bytes_for: every call is counted for every identifier",
    lambda t: sub(t, "    } else if calls[0].id == id {", "    } else if true {"))
add("m25_refine_without_unpoisoned", "reject",
    "theorem_cache_refines_entry_run: the `!c.poisoned` premise is dropped",
    lambda t: sub(t, "proof fn theorem_cache_refines_entry_run(c: Cache, calls: Seq<Call>, id: Id)\n    requires\n        !c.poisoned,\n    ensures",
                  "proof fn theorem_cache_refines_entry_run(c: Cache, calls: Seq<Call>, id: Id)\n    ensures"))
add("m26_exec_slot_evicts_on_success", "reject",
    "update_slot (exec): keeps the slot on failure and drops it on success",
    lambda t: sub(t, "            if ok {\n                Some(u)\n            } else {", "            if !ok {\n                Some(u)\n            } else {"))
add("m27_hand_checked_add_off_by_one", "reject",
    "checked_add_by_hand: `a < MAX - b` instead of `a <= MAX - b`",
    lambda t: sub(t, "    if a <= u64::MAX - b {", "    if a < u64::MAX - b {"))
add("m28_witness_wrong_boundary", "reject",
    "lemma_boundary_witnesses: the accepted byte witness is `MAX - 5` plus 6 (should be rejected, claimed accepted)",
    lambda t: sub(t, "        record_use_spec(UM { messages: 0, bytes: (u64::MAX - 5) as u64 }, 5).1,\n", "        record_use_spec(UM { messages: 0, bytes: (u64::MAX - 5) as u64 }, 6).1,\n"))
# predicted survivors
add("s01_identifier_type_changed", "survive",
    "Id is Seq<u16> instead of Seq<u8> (the model never reads the identifier bytes)",
    lambda t: sub(t, "pub type Id = Seq<u8>;", "pub type Id = Seq<u16>;"))
add("s02_redundant_hint_removed", "survive",
    "theorem_update_step: the hint `assert(c.entries.insert(call.id, r.0).contains_key(call.id))` is removed",
    lambda t: sub(t, "        if r.1 {\n            assert(c.entries.insert(call.id, r.0).contains_key(call.id));\n        }\n", ""))

lines = []
base_out, base_res, base_rc = run_verus(SRC)
lines.append(f"BASELINE: {base_res[0]} verified, {base_res[1]} errors (exit {base_rc}) for verus-proofs/c08_cache_usage_counters.rs")
rej = sur = diff = 0
survivors = []
for mid, pred, desc, fn in M:
    text = fn(base)
    path = os.path.join(OUT, mid + ".rs")
    open(path, "w").write(text)
    out, res, rc = run_verus(path)
    if res is None:
        status = "REJECTED"
        detail = "no result line (compile error)"
        first = [l for l in out.split("\n") if l.startswith("error")][:1]
        detail += " " + (first[0] if first else "")
    else:
        status = "SURVIVED" if res[1] == 0 else "REJECTED"
        detail = f"{res[0]} verified, {res[1]} errors"
    fails = failing_fns(out, text) if status == "REJECTED" else []
    lines.append(f"{mid} [predicted: {pred}] {desc}")
    lines.append(f"    -> {detail}  {status}")
    if fails:
        lines.append(f"    failing: {fails}")
    if status == "REJECTED":
        rej += 1
    else:
        sur += 1
        survivors.append(mid)
    if (pred == "reject") != (status == "REJECTED"):
        diff += 1
        lines.append("    DIFFERS FROM PREDICTION")
lines.append(f"SUMMARY: {len(M)} mutants, {rej} rejected, {sur} survived, {diff} differ from prediction")
lines.append("SURVIVORS: " + (", ".join(survivors) if survivors else "none"))
open(REC, "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
