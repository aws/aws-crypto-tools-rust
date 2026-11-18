# MPL Threat Model Summary

## About this document

- This is a short summary of the threat model for the Amazon Web Services (AWS) Cryptographic Material Providers Library (MPL).
- It is written for executives and application security (AppSec) reviewers.
- The full threat model is `docs/mpl-threat-model.md` (26 threats). The bug list is `docs/mpl-bug-reports/README.md` (10 bugs). This summary restates them in plain words. If they differ, the full documents are correct.
- Code state: branch MPL-Verus. The library code (`mpl/` and `prim/`) is identical to upstream main.
- Exploit steps and code locations are left out on purpose. They are in the full model.

## Summary

The MPL makes, wraps and caches the keys that the AWS Encryption SDK (ESDK) and related clients use to protect data.

**Verdict.** Most threats have a safeguard in the code. Three threats are rated High, and each still has an open gap. Two of them are one problem: keyrings that share a cache can end up using each other's branch keys (BUG-06, confirmed and open). The third is that an older, genuine key record can be put back in the database without being noticed.

**Top risks.**

- Cache mix-up between keyrings.
- Swapped or replayed branch key records.
- Stalls and crashes in cache refresh.
- Unbounded work when decrypting a message (unconfirmed).
- Wrong-Region key lookups in discovery mode.

**Decisions we need.**

- Choose how to fix BUG-06 and assign an owner.
- Decide whether to bound the work done per decrypted message, after the risk is confirmed by a test.
- Decide whether users of shared caches must be told now.
- Decide whether to add automatic spec-to-code tracing for the MPL (TM-MPL-019).

| Count | High | Medium | Low | Total |
|---|---|---|---|---|
| Threats by rating | 3 | 14 | 9 | 26 |

| Bugs | Found | Fixed | Open |
|---|---|---|---|
| Count | 10 | 3 | 7 |

The seven open bugs are: one High (BUG-06), five Low and one Informational.

## What this library does and what we protect

The MPL creates and protects the data keys used to encrypt data. It does not encrypt messages itself. Callers are the ESDK, a C++ shim, and other AWS encryption clients outside this repository.

**Main parts.**

- **Keyrings.** The raw Advanced Encryption Standard (AES) keyring wraps data keys with a local key. It uses AES in Galois/Counter Mode (AES-GCM) with a fresh initialization vector (IV) for each wrap. The IV must never repeat under one key. The hierarchical keyring wraps data keys with branch keys kept in a key store.
- **Cryptographic materials manager (CMM).** The default CMM picks the algorithm suite, applies the commitment policy and creates signing keys.
- **Key store.** It reads and writes branch key records in Amazon DynamoDB.
- **Cache.** It keeps branch keys in memory for a time limit, so fewer calls go to AWS Key Management Service (KMS).
- **Crypto wrapper.** It wraps the aws-lc-rs crypto library for encryption, key derivation, signing and random numbers.

**Where AWS services fit.** KMS is the root of trust for branch keys. DynamoDB stores the branch key records. We do not trust DynamoDB for integrity. KMS checks each record, so tampering is detected.

**Flow when the hierarchical keyring encrypts.**

- The caller asks the CMM for encryption materials.
- The CMM checks the algorithm suite and commitment policy, then calls the keyring.
- The keyring looks up the branch key in the cache. On a miss, it reads the record from DynamoDB and asks KMS to decrypt it.
- The keyring derives a one-time key from the branch key and wraps the data key with it.
- The result is an encrypted data key (EDK) that goes into the message.

On decrypt, the EDKs come from the message. The sender of that message is not trusted.

**What we protect.**

- Data keys (the keys that encrypt the message data).
- Branch keys and beacon keys, including the copies held in the cache.
- The raw AES wrapping key.
- Signing keys, which use the Elliptic Curve Digital Signature Algorithm (ECDSA).
- Branch key records stored in DynamoDB (integrity).
- The encryption context and the algorithm suite and commitment policy settings (integrity).

## What we checked and what we did not

**Scope.** We checked the MPL key management code (`mpl/`) and its crypto wrapper (`prim/`). We used the threat categories of STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege). Each threat is rated by likelihood and impact (see Appendix C). The C++ shim and the test servers are covered only where they touch MPL objects.

**Key assumptions.**

- Network traffic to KMS and DynamoDB is protected by Transport Layer Security (TLS).
- The process, the local AES wrapping key and the in-process cache are trusted.
- KMS is the trusted root of trust. DynamoDB is not trusted for integrity.
- Key stores, caches and branch key suppliers written by users are trusted code. The MPL does not check their results.
- The sender of a ciphertext is not trusted.

**Out of scope.**

- Message format concerns. The ESDK is treated only as a caller.
- The AWS KMS and DynamoDB services themselves. We did not test KMS-side behavior.
- The correctness of the crypto library. The proofs and tests treat it as trusted.
- Conformance with the Dafny version of the MPL. No claim is made.

## The risks that matter most

Five items follow. They are the High threats, plus Medium threats that have an open bug or are unconfirmed.

### 1. Cache mix-up between keyrings

- **What could go wrong.** Two keyrings that share a cache can end up with the same cache entry name when a name field contains a zero byte. One keyring then uses the other's branch key. Data of one tenant can become readable by holders of the other tenant's key store access.
- **Who is affected.** Services that share a cache and take tenant names from outside input.
- **Rating.** High. Likelihood Medium.
- **Protects us today.** The default cache partition identifier (ID) is random. Sharing is opt-in. The cache returns only branch key entries. Entries past their time limit are fetched again.
- **Still open.** Nothing rejects zero bytes in the name fields. BUG-06 is open.
- **What is being done.** Two fix options are written down. Rejecting zero bytes is a code change. Adding length prefixes needs a spec change and breaks cache ID compatibility with other implementations. No owner or date is recorded.
- **IDs.** TM-MPL-009, TM-MPL-010. BUG-06.

### 2. Swapped or replayed branch key records

- **What could go wrong.** A person with write access to the DynamoDB table could put an older genuine active record back. The keyring then encrypts under an older branch key version. No key is disclosed, but key rotation is undone. Nothing detects this.
- **Rating.** High. Likelihood Medium.
- **Protects us today.** Every record field is bound into the KMS encryption context. A record cannot be moved to another branch key ID or version without failing the KMS check.
- **Still open.** There is no freshness check. Key stores written by users are not checked. A record that lacks the creation time and hierarchy version fields is accepted, with low impact.
- **IDs.** TM-MPL-005. BUG-08 (informational, a check that can never trigger).

### 3. Stalls and crashes in cache refresh

- **What could go wrong.** The cache feature that limits parallel key refreshes (storm tracking) can stall. A failed refresh can leave a stale in-progress mark, so later requests for the same key get throttling errors for a time. A very large configured time value makes the code crash and breaks that cache for as long as it lives.
- **Rating.** Medium. Likelihood Medium.
- **Protects us today.** Parallel refreshes are limited. A damaged lock returns an error instead of a crash. The cache is written before the in-progress mark is cleared.
- **Still open.** Setting validation does not enforce the spec's ordering of time values. The stalls were found by code reading and were not run. BUG-01 is open.
- **IDs.** TM-MPL-018. BUG-01.

### 4. Unbounded work when decrypting a message (unconfirmed)

- **What could go wrong.** The sender of a message controls how many EDKs it holds and which key versions they name. Each EDK can cause one DynamoDB read. One message can slow requests and use up read capacity. No secret is exposed.
- **Rating.** Medium. Likelihood Medium. This threat is provisional and unconfirmed. The first effect follows from the code. The others need a test.
- **Protects us today.** Only EDKs that name the configured key are tried. Failed lookups cannot push good entries out of the cache. A memory growth problem is fixed.
- **Still open.** There is no default cap on EDK count, no short-term caching of failures and no overall deadline.
- **IDs.** TM-MPL-025. BUG-05(b) is related but is not the cause.

### 5. Wrong-Region key lookups in discovery mode

- **What could go wrong.** In discovery mode the key store decrypts a record with the key named in the record. Alias names are rejected. In multi-Region discovery mode, the Region of single-Region key names is also rewritten. The result is a KMS call to a key that does not exist or is a different key. It fails closed.
- **Who is affected.** Users of the discovery modes.
- **Rating.** Medium. Likelihood Low.
- **Protects us today.** Alias names are rejected. Single-key settings send the configured key name to KMS.
- **Still open.** BUG-04 is open. The string parsing of key names is not verified.
- **IDs.** TM-MPL-007. BUG-04.

## All threats at a glance

| Number | Threat in plain words | Rating | Status |
|---|---|---|---|
| TM-MPL-001 | Raw AES keyring can pose as an AWS KMS keyring | Low | Mitigated |
| TM-MPL-002 | Forged key record decrypts under a key the attacker influences | Medium | Partly mitigated |
| TM-MPL-003 | Branch key supplier returns an attacker-chosen branch key ID | Low | Partly mitigated |
| TM-MPL-004 | Key name matching accepts a key that should not match | Medium | Mitigated |
| TM-MPL-005 | Key record swapped, or an older record replayed | High | Partly mitigated |
| TM-MPL-006 | Weaker algorithm suite or commitment policy bypass | Medium | Partly mitigated |
| TM-MPL-007 | Discovery mode decrypts under an alias or wrong-Region key | Medium | Partly mitigated |
| TM-MPL-008 | Non-committing suite reused where key commitment is expected | Medium | Mitigated |
| TM-MPL-009 | Cache name collision returns the wrong branch key | High | Open |
| TM-MPL-010 | Shared cache gives one keyring another keyring's branch key | High | Open |
| TM-MPL-011 | Same AES-GCM IV used twice in the raw AES keyring | Medium | Partly mitigated |
| TM-MPL-012 | Same salt or IV used twice when wrapping with a branch key | Medium | Partly mitigated |
| TM-MPL-013 | Authenticated data for branch key wrapping built inconsistently | Medium | Mitigated |
| TM-MPL-014 | Key derivation input built wrongly, weakening branch keys | Medium | Mitigated |
| TM-MPL-015 | Secret keys not wiped, or kept longer than needed | Low | Partly mitigated |
| TM-MPL-016 | Rotation race overwrites the active branch key record | Low | Mitigated |
| TM-MPL-017 | Encryption context merge drops or alters bound values | Medium | Mitigated |
| TM-MPL-018 | Cache refresh control misconfigured or faulty (stall, crash) | Medium | Partly mitigated |
| TM-MPL-019 | No automatic tracing of spec requirements to code | Medium | Open |
| TM-MPL-020 | A KMS or DynamoDB call cannot be tied to one MPL operation | Low | Partly mitigated |
| TM-MPL-021 | Secrets or attacker text leak through logs and errors | Low | Partly mitigated |
| TM-MPL-022 | Cache exhaustion forces a storm of KMS calls | Low | Mitigated |
| TM-MPL-023 | Bad input or extreme settings cause a crash or resource blow-up | Low | Partly mitigated |
| TM-MPL-024 | C++ shim uses a dangling, forged or double-owned handle | Medium | Partly mitigated |
| TM-MPL-025 | Sender-chosen EDK count drives key store reads (unconfirmed) | Medium | Open |
| TM-MPL-026 | Test servers let any local process use the host's AWS credentials | Low | Partly mitigated |

**Status words.** Mitigated: a safeguard is in the code and no known gap needs action. Partly mitigated: a safeguard exists, but an open bug, a known gap or a user action remains. Open: the main problem has no fix yet. A gap in proof coverage alone does not change the status (see How sure are we).

## What already protects us

- Long-lived secret keys are wiped from memory when dropped, and secrets are compared in constant time. The `mpl/` and `prim/` code contains no `unsafe` Rust.
- Each branch key record is authenticated by KMS. All record fields are bound into the KMS encryption context, so a record cannot be altered or moved to another ID or version.
- In single-key settings, the configured key name is always the one sent to KMS. Alias names are rejected in discovery modes.
- The default CMM rejects algorithm suites that the commitment policy does not allow. A check runs on every keyring call. The ESDK checks the result again.
- Every wrap of a data key uses a fresh random IV. Every branch key wrap also uses a fresh salt and so a new derived key. The wrapping uses AES-GCM.
- The data key length must match the algorithm suite. Encryption contexts are decoded strictly (sorted, no duplicates, valid text). Lengths are checked before data is read.
- The default cache uses a random partition ID. Failed lookups are not cached. Storm tracking limits parallel refreshes.
- Error messages never carry EDK ciphertext or record values. Secret types print as redacted text.

## Known problems found

The bugs came from the analysis for formal verification. Three are fixed and seven are open. Severity is as stated in the bug list. It uses Informational for findings with no direct security effect.

| ID | Problem in plain words | Severity | Status | Related threats |
|---|---|---|---|---|
| BUG-01 | Very large time settings overflow and crash the program | Low | Open | TM-MPL-018, TM-MPL-022, TM-MPL-023 |
| BUG-02 | Data key length was not checked in the hierarchical keyring | Medium | Fixed | TM-MPL-006, TM-MPL-023 |
| BUG-03 | Encryption context decoder accepted unsorted entries | Low | Fixed | TM-MPL-013, TM-MPL-017 |
| BUG-04 | Multi-Region discovery rewrites the Region of single-Region key names | Low | Open | TM-MPL-007 |
| BUG-05 | (a) Key generation failure crashes the default CMM. (b) A very short EDK reaches the key store (likely not a bug) | Low | Open | TM-MPL-023, TM-MPL-025 |
| BUG-06 | Cache entry name is not unique when fields contain zero bytes | High | Open | TM-MPL-009, TM-MPL-010, TM-MPL-003 |
| BUG-07 | AES helper leaves plaintext in a buffer on error. Its decrypt length guard is weaker than the function it calls | Low | Open | TM-MPL-015, TM-MPL-023 |
| BUG-08 | A collision check in the key store encryption context can never trigger | Informational | Open | TM-MPL-005 |
| BUG-09 | Cache time limit check admitted entries up to one second too long | Informational | Fixed | TM-MPL-010 |
| BUG-10 | Raw AES decrypt drops a data key without wiping it when its length is wrong | Low | Open | TM-MPL-015 |

**What the open bugs mean together.** One open bug is High: BUG-06, which realizes the two High cache threats. The other six open bugs are Low or Informational. Most need an unusual setting or an attacker who is already inside the process. BUG-04 fails closed. Details are in `docs/mpl-bug-reports/`.

## What we recommend and what needs a decision

No owners or dates are named in the source. Every item below is "Owner: to be assigned".

| Action | Why | Decision or owner |
|---|---|---|
| Reject zero bytes in the cache name fields, or add length prefixes through a spec change. Add a regression test. | BUG-06, TM-MPL-009, TM-MPL-010 (High) | Decide which fix. Owner: to be assigned. |
| Bound the work per decrypted message: count distinct key versions, cache failures briefly, set an overall deadline. First confirm the risk with two tests. | TM-MPL-025 (unconfirmed) | Decide the default cap. Owner: to be assigned. |
| Alert if the active key record version goes backwards. Limit DynamoDB write access to the key store table. | Rollback is not detected (TM-MPL-005) | Decide if this stays an operator duty. Owner: to be assigned. |
| Fix storm tracking: clear the in-progress mark when a refresh fails, give waiters a deadline, use checked time arithmetic, restore the spec's ordering of time values. | TM-MPL-018, BUG-01 | Owner: to be assigned. |
| Prefer single-key settings over discovery modes. If discovery is needed, scope the KMS decrypt permission in Identity and Access Management (IAM). Rewrite the Region only for multi-Region key names. | TM-MPL-002, TM-MPL-007, BUG-04 | Owner: to be assigned. |
| Add automatic spec-to-code tracing for the MPL and pin the spec revision. | TM-MPL-019 | Owner: to be assigned. |
| Add a null check and type tag to the C++ shim function that adopts a keyring pointer. | TM-MPL-024 | Owner: to be assigned. The shim is outside `mpl/` and `prim/`. |
| Fix the small items: return an error instead of crashing on key generation failure, clear the buffer on AES error, wipe the transient copies of secrets. | BUG-05(a), BUG-07, BUG-10, TM-MPL-015 | Owner: to be assigned. |

**Guidance for users of the library.**

- Use only validated values without zero bytes for partition IDs and logical key store names. Never reuse a logical key store name across key stores.
- Set the ESDK limit on EDKs per message to a small number if you decrypt third-party data. Set request timeouts.
- Do not return MPL errors as-is to the sender of a ciphertext.
- Rotate branch keys about once a year. Rotate a raw AES wrapping key before about 4 billion wraps.
- Turn on AWS CloudTrail for the KMS keys and the DynamoDB table. Watch DynamoDB read throttling on the key store table.
- Run the test servers only on development hosts without production credentials.

**Top residual risks.**

| Risk | What reduces it | What is left | Why not fixed now | Tracking and customer notice |
|---|---|---|---|---|
| Cache mix-up (TM-MPL-009, TM-MPL-010) | Random default partition ID, opt-in sharing, user guidance | Zero bytes in name fields are not rejected | Length prefixes need a spec change. The code change is not yet made. | Tracked as BUG-06. Customer notice: decision needed. |
| Key record rollback (TM-MPL-005) | KMS binding of all record fields. Operator practice: restricted write access, version alerts | An older genuine record is accepted | Not stated in the source | Tracked in the threat model. Customer notice: decision needed. |
| Decrypt amplification (TM-MPL-025) | Matching-EDK filter, optional EDK limit in the ESDK | No default cap, no deadline, no failure caching | Not yet confirmed by a test | Tracked in the threat model as provisional. Customer notice: not decided. |
| Storm tracking (TM-MPL-018) | Parallel refresh limit, error instead of crash on a damaged lock | Stalls and crashes with large settings | Not stated in the source | Tracked as BUG-01. Customer notice: not decided. |

## How sure are we

- Most bugs were confirmed by running a test. BUG-05(a), BUG-08 and BUG-10 rest on code reading. The stalls in TM-MPL-018 were found by code reading and were not run.
- Formal proofs exist for a few areas. These are the key name sent to KMS in single-key settings, parts of key record handling, the key derivation input layout and the signing retry limit. The proofs cover a hand-written model of the code, not the shipped code. Nothing detects a later code edit. Most threats have no proof yet.
- For part of the crypto wrapper (buffer handling and length checks), proofs cover the real code on a separate branch, not this code state.
- TM-MPL-025 is unconfirmed. Only its first effect follows directly from the code.
- A separate completeness check found no missing threat. It found one small gap: the code does not require two record fields that the spec requires. The impact is low.
- This document and the full threat model were produced with artificial intelligence (AI) help. The full model had an independent check of its code citations. This summary was checked by script against the full model and the bug list.
- The ratings apply to the code state given in About this document.

## Where to read more

- `docs/mpl-threat-model.md`: the full threat model with per-threat analysis, residual risks, recommendations and the risk matrix.
- `docs/mpl-bug-reports/README.md`: the bug list with severity, confidence and status. The folder `docs/mpl-bug-reports/` holds one report per bug.
- `docs/mpl-verification-targets.md`: the plan for formal proofs and what each one would show.

## Appendix A: Glossary

| Term | Meaning |
|---|---|
| AES-GCM | Advanced Encryption Standard in Galois/Counter Mode. A standard way to encrypt data and detect tampering. |
| Algorithm suite | A named set of crypto algorithms used to encrypt a message. |
| Branch key | A key kept in the key store. Data keys are wrapped under keys derived from it. |
| Branch key record | The stored form of a branch key in DynamoDB, protected by KMS. |
| Cache | In-memory store of branch keys for a time limit, to reduce KMS calls. |
| CMM | Cryptographic materials manager. Chooses the algorithm suite and gets key material from a keyring. |
| Commitment policy | A setting that says whether messages must use key commitment. |
| Data key | The key that encrypts the message data. |
| DynamoDB | Amazon DynamoDB. The database that holds branch key records. |
| EDK | Encrypted data key. A data key wrapped by a keyring, stored in the message. |
| Encryption context | Extra named values bound to a ciphertext. Decrypt fails if they differ. |
| IV, nonce | Initialization vector. A value that must be unique for every encryption under one key. |
| Key commitment | A property that makes a ciphertext decrypt under only one key. |
| Key store | The MPL part that creates and reads branch key records. |
| KMS | AWS Key Management Service. The root of trust for branch keys. |
| Keyring | A component that wraps and unwraps data keys. |
| STRIDE | A list of threat types: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege. |
| Wrapping key | A key used to encrypt (wrap) another key. |
| Zeroize | Overwrite secret data in memory with zeros when it is no longer needed. |

## Appendix B: Threat table in AWS template form

| Threat Number | Priority | Threat | STRIDE | Affected Assets | Mitigations | Comments | Status |
|---|---|---|---|---|---|---|---|
| TM-MPL-001 | Low | Raw AES keyring EDK poses as an AWS KMS keyring | Spoofing | EDKs, provider ID | Builder rejects names starting with aws-kms | Exact-byte check | Mitigated |
| TM-MPL-002 | Medium | Forged key record decrypts under a key the attacker influences | Spoofing | Branch key records, KMS key choice | Single-key settings send the configured key name | Discovery modes trust the record by spec, also on encrypt. Use single-key settings or scope IAM. | Partly mitigated |
| TM-MPL-003 | Low | Supplier returns an attacker-chosen branch key ID | Spoofing | Branch key ID, cache | Supplier is trusted code. A wrong ID fails authentication on decrypt. | On decrypt the supplier input is the unauthenticated message context | Partly mitigated |
| TM-MPL-004 | Medium | Key name matching accepts a non-matching key | Tampering | Key names, KMS key choice | Aliases rejected. Match on exact bytes or Region-only difference for multi-Region keys. | String parsing not verified | Mitigated |
| TM-MPL-005 | High | Key record swapped or older record replayed | Tampering | Branch key records | All fields bound into KMS encryption context. 32-byte key check. | Rollback not detected. User key stores unchecked. | Partly mitigated |
| TM-MPL-006 | Medium | Weaker algorithm suite or commitment policy bypass | Elevation of privilege | Algorithm suite, commitment policy | CMM allow tables, per-call checks, ESDK re-check | A user-written CMM has no policy backstop inside the MPL | Partly mitigated |
| TM-MPL-007 | Medium | Discovery mode decrypts under alias or wrong-Region key | Elevation of privilege | Branch key records, KMS keys | Aliases rejected in discovery modes | BUG-04 open, fails closed | Partly mitigated |
| TM-MPL-008 | Medium | Non-committing suite reused where commitment is expected | Elevation of privilege | Algorithm suite, commitment policy | Committing suites are the default under require policies | No caching CMM exists. A future one must bind the policy into its cache name. | Mitigated |
| TM-MPL-009 | High | Cache name collision returns the wrong branch key | Elevation of privilege | Cache entries, branch keys | Random default partition ID, entry kind check | BUG-06 open. See Threat Analysis TM-MPL-009. | Open |
| TM-MPL-010 | High | Shared cache gives one keyring another's branch key | Information disclosure, Elevation of privilege | Cache entries, branch keys | Random default partition ID, opt-in sharing, exact time limit | Same root cause and fix as TM-MPL-009 | Open |
| TM-MPL-011 | Medium | Same AES-GCM IV used twice in raw AES keyring | Elevation of privilege | Wrapping key, EDKs | Fresh random 12-byte IV per wrap | No counter. Rotate key before about 4 billion wraps. | Partly mitigated |
| TM-MPL-012 | Medium | Same salt or IV used twice in branch key wrap | Elevation of privilege | Branch keys, derived keys | Fresh 16-byte salt and 12-byte IV per wrap | Random values only. Rotate branch keys about yearly. | Partly mitigated |
| TM-MPL-013 | Medium | Branch key wrapping authenticated data built inconsistently | Tampering | Encryption context, wrapped keys | Same construction on wrap and unwrap. Strict decoding. | Empty context keys are accepted | Mitigated |
| TM-MPL-014 | Medium | Key derivation input built wrongly | Elevation of privilege | Branch keys | Counter-mode derivation. Derived key wiped after use. | Spec does not give the fixed-input layout | Mitigated |
| TM-MPL-015 | Low | Secret keys not wiped or kept too long | Information disclosure | Data keys, branch keys, wrapping and signing keys | Wipe on drop. No unsafe code. | Transient copies remain. Expired cache entries stay until read. BUG-07, BUG-10. | Partly mitigated |
| TM-MPL-016 | Low | Rotation race overwrites active record | Tampering | Branch key records | KMS check before rotation. One conditional transaction. | None | Mitigated |
| TM-MPL-017 | Medium | Encryption context merge drops or alters values | Tampering | Encryption context | Merge fails on differing values. Per-call checks. | None | Mitigated |
| TM-MPL-018 | Medium | Cache refresh control faulty or misconfigured | Denial of service | Cache, availability | Parallel limit. Lock damage returns an error. | BUG-01 open. Spec ordering not enforced. See Threat Analysis TM-MPL-018. | Partly mitigated |
| TM-MPL-019 | Medium | No automatic spec-to-code tracing | Elevation of privilege | Whole library | None in code | No MPL tracing config. Spec revision floats. | Open |
| TM-MPL-020 | Low | Call to KMS or DynamoDB not tied to one MPL operation | Repudiation | Audit trail | CloudTrail. MPL name in KMS request metadata. | Cannot attribute to one message | Partly mitigated |
| TM-MPL-021 | Low | Secrets or attacker text leak through logs and errors | Information disclosure | Secret keys, error text | Redacted output. Errors never carry EDK ciphertext. | Do not return errors as-is to a sender | Partly mitigated |
| TM-MPL-022 | Low | Cache exhaustion forces a storm of KMS calls | Denial of service | Cache, KMS capacity | Default cache with storm tracking. Failed lookups not cached. | None | Mitigated |
| TM-MPL-023 | Low | Bad input or extreme settings crash the program | Denial of service | Availability | Length checks, strict decoding, memory fix | BUG-01, BUG-05, BUG-07 open | Partly mitigated |
| TM-MPL-024 | Medium | C++ shim uses a bad handle | Elevation of privilege, Tampering | Keys reachable from C++ | Null checks on borrowed handles. Typed bindings. | No checks when adopting a keyring pointer | Partly mitigated |
| TM-MPL-025 | Medium | Sender-chosen EDK count drives key store reads | Denial of service | Key store read capacity, latency | Only matching EDKs tried. Failures do not evict. | Provisional. No cap, no deadline. | Open |
| TM-MPL-026 | Low | Test servers use host AWS credentials for any local process | Elevation of privilege, Information disclosure | Ambient AWS credentials | Loopback only. Not published. | No authentication. Test use only. | Partly mitigated |

## Appendix C: How ratings work

Each threat gets an impact level and a likelihood level. The matrix below turns the pair into a rating of High, Medium or Low. The full model calls impact "Severity". It uses four impact levels (Low, Medium, High, Critical) and three likelihood levels (Low, Medium, High). Ratings in this document are the final risk rating, and only High, Medium and Low appear as ratings.

| Impact \ Likelihood | Low | Medium | High |
|---|---|---|---|
| Critical | Medium | High | High |
| High | Medium | High | High |
| Medium | Low | Medium | High |
| Low | Low | Low | Medium |

- **High:** impact is High or Critical and likelihood is Medium or High, or impact is Medium and likelihood is High.
- **Medium:** impact is Critical or High and likelihood is Low, impact is Medium and likelihood is Medium, or impact is Low and likelihood is High.
- **Low:** impact is Medium and likelihood is Low, or impact is Low and likelihood is Low or Medium.
