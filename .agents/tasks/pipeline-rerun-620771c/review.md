# Independent review: pipeline re-run for main 620771c
Reviewer checked at 2026-11-14 ~00:52 UTC. Chorus docs not touched (user decision).

## Verdict: APPROVED. No blockers. No document fixes were needed.

## Code untouched
`git diff --quiet HEAD -- mpl prim esdk` exits 0. `git status` shows only the six in-scope docs modified plus untracked task dir and `docs/.DS_Store`.

## CVE check (mandatory)
Occurrences: spec-security-analysis.md:234; threat-model.md:13, 36, 57, 292, 314, 434, 448; verification-targets.md:16; 01-threat-driven.md:30, 512, 1240; 04-validation.md:25.
Fetched at ~2026-11-14 00:51 UTC:
| URL | Result | Content |
|---|---|---|
| https://github.com/advisories/GHSA-v638-38fc-rhfv | HTTP 200 | "AWS Encryption SDK for Python: Key commitment policy bypass via shared key cache", CVE-2026-6550 |
| https://aws.amazon.com/security/security-bulletins/2026-017-aws/ | HTTP 200 | Bulletin 2026-017-AWS, published 04/20/2026: CVE-2026-6550, key commitment policy bypass via shared key cache in ESDK for Python; algorithm downgrade in caching layer, before 3.3.1 / 4.0.5 |
| https://github.com/aws/aws-encryption-sdk-python/security/advisories/GHSA-v638-38fc-rhfv | HTTP 200 | Same title, repo advisory GHSA-v638-38fc-rhfv |
| https://nvd.nist.gov/vuln/detail/CVE-2026-6550 | HTML page HTTP 403 (bot block). NVD API `services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-6550` HTTP 200 | CVE-2026-6550, published 2026-04-20, same description (algorithm downgrade in caching layer of ESDK Python, bypass key commitment policy via shared key cache) |
Conclusion: advisory id, product (ESDK for Python) and the shared-key-cache commitment bypass are all supported. **VERIFIED kept.** The docs' claim that it does not apply to this crate matches code: `mpl/src/cmm/` has only default_cmm.rs, fluent_builders.rs, mod.rs, types.rs.

## Citation spot-check (30 sampled, all correct)
cmc/entry.rs:26,28; cmc/mod.rs:88-90; aws_kms/hierarchical_keyring.rs:585,700,943; structures/commitment_policy.rs:43-58; lib.rs:34 (`__test_internals`); cmc/default.rs:98; aws_kms/branch_key_wrap.rs:236; key_store/kms_ops.rs:94-96; shim lib.rs:167, 715, 720, 728, 1564, 1565, 1655, 2054-2057; a1e23d7 algorithm_suite.rs:439 (old `unsafe` loop present; absent on HEAD). Earlier mechanical sweep in verification-evidence.md (1,304 citations, 7 fixes) is credible and consistent with my samples.

## Scores / IDs / ratings
Recomputed T01 4×0.8×0.7×4=8.96, C07 3×0.6×0.7×4=5.04, T26 2×1.0×0.4×4=3.20, T25 3×0.6×0.4×2=1.44, T?? 4.32 and 5.12: all correct and match rank tables. Statuses match RECHECK (open 01,04,05a,05b,06,07,08; fixed 02,03,09); TM-MPL-015 residual Low and T26 S=2 consistent with RECHECK BUG-07. TM-MPL-001..023 retained, "Retired: none". TM-MPL-024 justified: shim `unsafe` derefs at lib.rs:728/1564/1565/1655 are real new surface (retargeted in e9bde48). T08 retired (unsafe loop gone) and T25/T26/C07/C08 justified in docs.

## Fixes made by reviewer
None.

## Findings
None blocking.
