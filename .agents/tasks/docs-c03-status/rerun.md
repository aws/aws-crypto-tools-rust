# C03 re-run of prim Verus verification (VR-013 / VR-014)

## Tip read
- Ref: refs/remotes/origin/Mahnush_Verus (fetched read-only from aws/aws-crypto-tools-rust)
- Full sha: 8d6381eb82daee55ecf32911d6ef8b48690d68b9 (short 8d6381e)
- Subject: docs(verus): record MPL impact of BUG-07 and an on_decrypt wiping finding
- 43b9ff7 is an ancestor of this tip.
- Run at: 8d6381e, detached worktree /tmp/c03-status-check, directory prim/, PATH="$HOME/verus:$PATH"

## Result lines (full output: rerun-default.log, rerun-aws-lc-sys.log)
1. `cargo verus verify` (default features), exit 0
   - dependency vstd: `verification results:: 1858 verified, 0 errors`
   - aws-mpl-primitives: `verification results:: 18 verified, 0 errors`
2. `cargo verus verify --no-default-features --features aws-lc-sys`, exit 0
   - aws-mpl-primitives: `verification results:: 18 verified, 0 errors`

## Does the number differ from 18?
No. 18 at 8d6381e, same as the 43b9ff7 review result.

`git log --oneline 43b9ff7..origin/Mahnush_Verus -- prim` output: (empty)
No commit after 43b9ff7 touches prim/. The commits 2d22937 and 8d6381e are docs only.

## Main repo before / after
| | before | after |
|---|---|---|
| `git status --porcelain` | `?? .agents/tasks/docs-c03-status/` (the notes dir this task created; tree otherwise clean) | `?? .agents/tasks/docs-c03-status/` |
| branch | MPL-Verus | MPL-Verus |
| HEAD | b94c8719dc4e9ccd6ad35dc9d6755e23581b5586 | b94c8719dc4e9ccd6ad35dc9d6755e23581b5586 |

The fetch only added refs/remotes/origin/Mahnush_Verus. No tracked file changed, nothing was committed or pushed.
Worktree removed with `git worktree remove --force /tmp/c03-status-check` and `git worktree prune`. `git worktree list` shows only the main repo and /tmp/c03-status-check no longer exists.
