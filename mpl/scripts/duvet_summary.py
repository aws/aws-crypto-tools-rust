#!/usr/bin/env python3
"""Duvet coverage summary from snapshot.txt + requirement TOMLs.

Usage:
    python3 scripts/duvet_summary.py                    # all specs
    python3 scripts/duvet_summary.py message-header     # one spec (fuzzy match)
    python3 scripts/duvet_summary.py encrypt            # one spec (fuzzy match)
"""

import os
import re
import sys
from pathlib import Path

DUVET_DIR = Path(__file__).resolve().parent.parent / ".duvet"
REQUIREMENTS_DIR = DUVET_DIR / "requirements"
SNAPSHOT_FILE = DUVET_DIR / "snapshot.txt"


def parse_tomls(spec_dir: Path) -> list[dict]:
    """Parse all [[spec]] entries from TOMLs in a directory. Returns list of requirements."""
    requirements = []
    for toml_file in sorted(spec_dir.glob("*.toml")):
        target = None
        in_quote = False
        quote_lines = []
        level = None

        with open(toml_file) as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("target = "):
                    target = line.split('"')[1]
                elif line == "[[spec]]":
                    if quote_lines:
                        requirements.append({
                            "target": target,
                            "level": level,
                            "lines": [l for l in quote_lines if l],
                        })
                    quote_lines = []
                    level = None
                    in_quote = False
                elif line.startswith("level = "):
                    level = line.split('"')[1]
                elif line == "quote = '''":
                    in_quote = True
                    quote_lines = []
                elif line == "'''" and in_quote:
                    in_quote = False
                elif in_quote:
                    quote_lines.append(line)

        # Last entry in file
        if quote_lines:
            requirements.append({
                "target": target,
                "level": level,
                "lines": [l for l in quote_lines if l],
            })

    return requirements


def parse_snapshot(spec_name: str) -> dict[str, list[tuple[str, str]]]:
    """Parse snapshot for a spec. Returns {section: [(status, text), ...]}."""
    sections = {}
    current_section = None
    found_spec = False

    with open(SNAPSHOT_FILE) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("SPECIFICATION:"):
                if found_spec:
                    break  # hit next spec
                if spec_name in line:
                    found_spec = True
                continue
            if not found_spec:
                continue
            if line.startswith("  SECTION:"):
                m = re.search(r"#([\w-]+)", line)
                if m:
                    current_section = m.group(1)
                    sections.setdefault(current_section, [])
            elif line.strip().startswith("TEXT["):
                m = re.match(r"\s*TEXT\[([^\]]*)\]:\s*(.*)", line)
                if m and current_section:
                    status = m.group(1)
                    text = m.group(2)
                    sections[current_section].append((status, text))

    return sections


def match_requirement(req: dict, snapshot_sections: dict) -> str:
    """Determine coverage status of a requirement by matching its lines in the snapshot.

    Categories (mutually exclusive):
      'complete'    - all lines have both implementation AND test (explicit, not implication)
      'implication' - all lines are implication (counts as both impl+test)
      'impl_only'   - all lines have implementation but at least one lacks test
      'test_only'   - all lines have test but at least one lacks implementation
      'none'        - at least one line has no coverage at all
    """
    # Extract section from target
    section = req["target"].split("#")[-1] if "#" in req["target"] else None
    if not section or section not in snapshot_sections:
        return "none"

    snapshot_lines = snapshot_sections[section]
    req_lines = req["lines"]

    if not req_lines:
        return "none"

    # Find the first line of this requirement in the snapshot
    first_line = req_lines[0]
    start_idx = None
    for i, (status, text) in enumerate(snapshot_lines):
        if text.strip() == first_line.strip():
            start_idx = i
            break

    if start_idx is None:
        # Try partial match (snapshot may truncate)
        for i, (status, text) in enumerate(snapshot_lines):
            if first_line.strip().startswith(text.strip()) or text.strip().startswith(first_line.strip()):
                start_idx = i
                break

    if start_idx is None:
        return "none"

    # Collect statuses for all lines of this requirement
    statuses = []
    for j in range(len(req_lines)):
        idx = start_idx + j
        if idx < len(snapshot_lines):
            statuses.append(snapshot_lines[idx][0])
        else:
            statuses.append("")

    # Classify: implication and exception are their own categories, both count as complete
    all_implication = all("implication" in s for s in statuses)
    if all_implication:
        return "implication"

    all_exception = all("exception" in s for s in statuses)
    if all_exception:
        return "exception"

    # For non-implication/exception lines: check explicit implementation and test
    has_impl = all("implementation" in s for s in statuses)
    has_test = all("test" in s for s in statuses)

    if has_impl and has_test:
        return "complete"
    elif has_impl:
        return "impl_only"
    elif has_test:
        return "test_only"
    else:
        return "none"


def find_spec_dirs(filter_name: str = None) -> list[tuple[str, Path]]:
    """Find spec requirement directories, optionally filtered by name."""
    results = []
    for spec_dir in sorted(REQUIREMENTS_DIR.rglob("*")):
        if not spec_dir.is_dir():
            continue
        if not any(spec_dir.glob("*.toml")):
            continue
        # Derive spec name from path
        rel = spec_dir.relative_to(REQUIREMENTS_DIR)
        name = str(rel).replace("/", "-")
        if filter_name and filter_name not in str(rel):
            continue
        results.append((str(rel), spec_dir))
    return results


def summarize_spec(spec_path: str, spec_dir: Path):
    """Print coverage summary for one spec."""
    requirements = parse_tomls(spec_dir)
    if not requirements:
        return

    # Derive the spec filename for snapshot lookup
    # spec_path is like "spec/data-format/message-header"
    # snapshot uses the .md filename in the SPECIFICATION line
    parts = spec_path.split("/")
    spec_name = parts[-1]  # e.g. "message-header"

    snapshot_sections = parse_snapshot(spec_name)

    counts = {"complete": 0, "impl_only": 0, "test_only": 0, "implication": 0, "exception": 0, "none": 0}
    for req in requirements:
        status = match_requirement(req, snapshot_sections)
        counts[status] += 1

    total = len(requirements)
    complete = counts["complete"] + counts["implication"] + counts["exception"]
    has_impl = counts["complete"] + counts["impl_only"]  # explicit implementation (not implication/exception)
    has_test = counts["complete"] + counts["test_only"]  # explicit test (not implication/exception)

    print(f"{spec_path.replace('spec/', '')} ({total} requirements)")
    print(f"  implementation + test:   {counts['complete']:3d}")
    print(f"  implication:             {counts['implication']:3d}")
    print(f"  exception:               {counts['exception']:3d}")
    print(f"  implementation only:     {counts['impl_only']:3d}")
    print(f"  test only:               {counts['test_only']:3d}")
    print(f"  no coverage:             {counts['none']:3d}")
    print(f"  ───────────────────────────")
    print(f"  total implementation:    {has_impl:3d}  (excludes implication/exception)")
    print(f"  total test:              {has_test:3d}  (excludes implication/exception)")
    print(f"  fully covered:           {complete:3d} ({100*complete//total}%)")
    print(f"  gaps:                    {total - complete:3d} ({100*(total-complete)//total}%)")
    print()


def main():
    if not SNAPSHOT_FILE.exists():
        print("Error: .duvet/snapshot.txt not found. Run 'make duvet' first.", file=sys.stderr)
        sys.exit(1)

    filter_name = sys.argv[1] if len(sys.argv) > 1 else None
    spec_dirs = find_spec_dirs(filter_name)

    if not spec_dirs:
        print(f"No specs found matching '{filter_name}'", file=sys.stderr)
        sys.exit(1)

    for spec_path, spec_dir in spec_dirs:
        summarize_spec(spec_path, spec_dir)


if __name__ == "__main__":
    main()
