# Notes 6: cleanup of throwaway review worktrees

Repo: `/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl` (referred to as `$R`).

## Before cleanup

```
$ git -C $R worktree list
/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl e3abf2d [MPL-Verus]
/private/tmp/review-mahnush-verus                          43b9ff7 (detached HEAD)
/private/tmp/review-mahnush-verus-base                     6b51de8 (detached HEAD)

$ ls -d /tmp/review-*
/tmp/review-base-copy  /tmp/review-mahnush-verus  /tmp/review-mahnush-verus-base
/tmp/review-tip-copy   /tmp/review-vr013-harness
```

Path confirmation: `review-base-copy` and `review-tip-copy` have no `.git`, were created at the same
timestamp as the two worktrees (11:10:15), and are referenced in `notes-4-behavior.md` as this review's
tip/base copies. `review-vr013-harness` is referenced there as the differential harness. All three were
created by this review, so they were deleted.

## Commands run

```
git -C $R worktree remove --force /tmp/review-mahnush-verus        # rc=0
git -C $R worktree remove --force /tmp/review-mahnush-verus-base   # rc=0
git -C $R worktree prune                                           # rc=0
rm -rf /tmp/review-vr013-harness /tmp/review-base-copy /tmp/review-tip-copy
ls -d /tmp/review-*     # "no matches found" (nothing left)
```

## After cleanup

```
$ git -C $R status --porcelain=v1 -b
## MPL-Verus
?? .agents/tasks/review-vr013-vr014/

$ git -C $R rev-parse HEAD
e3abf2db6bc3678876ff303ec84a377a81714544

$ git -C $R worktree list
/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl e3abf2d [MPL-Verus]

$ git -C $R rev-parse origin/Mahnush_Verus
43b9ff7751eea2199f37344505861f1e78b0967c

$ git -C $R branch -a | grep -i verus
* MPL-Verus
  remotes/origin/MPL-Verus
  remotes/origin/Mahnush_Verus
```

## Comparison with baseline (`baseline-git-status.txt`)

Baseline: `## MPL-Verus`, `?? .agents/tasks/review-vr013-vr014/`, HEAD `e3abf2db6bc3678876ff303ec84a377a81714544`.

- Status: identical.
- HEAD: identical.
- `origin/Mahnush_Verus` is still `43b9ff7...`.
- No local branch `Mahnush_Verus` exists (only local branch is `MPL-Verus`).
- Only one worktree remains (the main repo).
