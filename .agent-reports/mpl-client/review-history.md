# Review History: mpl-client

## Round 1 — findings to address (merged from 3 reviewers)

### BLOCKERS
1. [annotations + code + tests] No duvet infrastructure and ZERO `//=` annotations
   across the crate. Set up `.duvet/config.toml` + `compliance/` extraction, then add
   `implementation` + `type=test` annotations for the requirements implemented this round.
2. [code] No spec requirements implemented. Implement the commitment-policy ENUM
   requirements (per-format ENUM + union ENUM) per the work item scope.
3. [code] `MaterialProvidersConfig` is empty. Add a real `commitment_policy` field.
4. [tests] Zero `type=test` annotations. Add meaningful tests with annotations.

### WARNINGS
5. [code + tests] Dead code: `Error::InvalidConfig` is defined but never constructed.
   Wire it into `build()` validation and add an error-path test (assert on error kind,
   not bare `is_err()`).
6. [tests] `test_mpl_default_uses_default_config` has a dead `let _ = MaterialProviders::default()`
   statement that asserts nothing — fix or remove it.

### INFO / scoping notes
7. The behavioral commitment-policy MUSTs (default algorithm suite, Get/Decrypt Materials
   support) depend on algorithm-suites + cmm-interface, which are out of scope this round.
   Mark them `type=todo` with a tracking note — do not fabricate.
8. [code] Consider brief `//!` module doc comments on each source file.
