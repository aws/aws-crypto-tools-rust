# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Print `git diff <base>...HEAD`, with lines that were only moved shown as unchanged.

diff-cover counts every added line as new code, so moving code into a new file
would make its old untested lines fail the patch-coverage check.
Git's --color-moved finds the moved lines; this script turns each moved `+`
line into a context line, which keeps diff-cover's line numbers right.

Usage: diff_without_moved_lines.py <base-ref>
"""

import re
import subprocess
import sys

# Git colors moved added lines with color.diff.newMoved, set to blue below.
# Other added lines keep the default green.
MOVED = "\x1b[34m"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

base = sys.argv[1]
diff = subprocess.run(
    [
        "git",
        "-c", "color.diff.newMoved=blue",
        "diff",
        "--color=always",
        "--color-moved=plain",
        "--color-moved-ws=allow-indentation-change",
        f"{base}...HEAD",
    ],
    check=True,
    capture_output=True,
    text=True,
).stdout

for line in diff.splitlines():
    plain = ANSI.sub("", line)
    if line.startswith(MOVED) and plain.startswith("+") and not plain.startswith("+++"):
        plain = " " + plain[1:]
    print(plain)
