#!/bin/sh
# Manual spot checks for citations the heuristic script cannot resolve (context shown for reading).
cd "$(dirname "$0")/../../.." || exit 1
P=.agents/tasks/docs-sync-9955ecd/ctx.py
V=docs/verification-targets.md
A=docs/verification-targets/01-threat-driven.md
B=docs/verification-targets/02-capability-driven.md
python3 $P $A 882 mpl/src/structures/materials_checks.rs:97
python3 $P $A 883 mpl/src/structures/materials_checks.rs:184
python3 $P $A 965 mpl/src/key_store/branch_key_store.rs:101-108
python3 $P $A 966 mpl/src/key_store/branch_key_store.rs:199 mpl/src/key_store/branch_key_store.rs:213
python3 $P $A 1033 mpl/src/aws_kms/hierarchical_keyring.rs:313
python3 $P $B 443 mpl/src/aws_kms/hierarchical_keyring.rs:178-190
python3 $P $B 501 mpl/src/key_store/encryption_context.rs:95-101
python3 $P $B 502 prim/src/lib.rs:215
python3 $P $B 473 esdk/shims/aws-esdk-cpp/src/lib.rs:715 esdk/shims/aws-esdk-cpp/src/lib.rs:1661
python3 $P $V 398 prim/src/ecdsa.rs:228 prim/src/ecdsa.rs:248
