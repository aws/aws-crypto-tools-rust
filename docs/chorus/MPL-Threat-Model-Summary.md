# MPL Threat Model Summary

## About this document

- This is a plain-language summary of the threat model for the Amazon Web Services (AWS) Cryptographic Material Providers Library (MPL).
- The full threat model is `docs/mpl-threat-model.md` (26 threats). The bug list is `docs/mpl-bug-reports/README.md` (10 bugs). This summary restates them in plain words. If they differ, the full documents are correct.
- This summary carries all of the full model's system overview, assets, actors, trust boundaries, data flows and threat list. It leaves out the per-threat analysis, which stays in the full model.
- Code state: branch MPL-Verus. The library code (`mpl/` and `prim/`) is identical to upstream main.
- Exploit steps and code locations are left out on purpose. They are in the full model.
- IDs match the full model so reviewers can trace each item: assets A1 to A14, threat actors TA1 to TA9, trust boundaries TB1 to TB9, threats TM-MPL-001 to TM-MPL-026, and bugs BUG-01 to BUG-10.

## Summary

The MPL makes, wraps and caches the keys that the AWS Encryption SDK (ESDK) and related clients use to protect data.

**Verdict.** Most threats have a safeguard in the code. Three threats are rated High, and each still has an open gap. Two of them are one problem: keyrings that share a cache can end up using each other's branch keys (BUG-06, confirmed and open). The third is that an older, genuine key record can be put back in the database without being noticed.

**Top risks.**

- Cache mix-up between keyrings.
- Swapped or replayed branch key records.
- Stalls and crashes in cache refresh.
- Unbounded work when decrypting a message (unconfirmed).
- Wrong-Region key lookups in discovery mode.

| Count | High | Medium | Low | Total |
|---|---|---|---|---|
| Threats by rating | 3 | 14 | 9 | 26 |

| Bugs | Found | Fixed | Open |
|---|---|---|---|
| Count | 10 | 3 | 7 |

The seven open bugs are: one High (BUG-06), five Low and one Informational.

## What this library does

The MPL creates and protects the data keys used to encrypt data. It does not encrypt messages itself. Its security rests on six things. Keys are wrapped with the Advanced Encryption Standard (AES). New keys are derived from branch keys. AWS Key Management Service (KMS) is the root of trust. Amazon DynamoDB stores key records in a way that shows tampering. An in-memory cache reduces KMS calls. The cryptographic materials manager enforces strict rules for choosing algorithms.

### Who calls it

- The ESDK in this repository.
- A C++ shim, which is a thin layer that lets C++ programs use the Rust library.
- Other AWS encryption clients outside this repository: the AWS Database Encryption SDK and the Amazon Simple Storage Service (S3) Encryption Client.

### Main parts

- **Cryptographic materials manager (CMM).** The caller asks the CMM for keys and settings, called materials. The default CMM picks the algorithm suite and applies the commitment policy. It creates a signing key when the suite signs messages. On decrypt, it merges the encryption context that the caller supplies again (the reproduced context).
- **CMM front end.** Every CMM call goes through a front-end step. That step checks that the materials the CMM returns are complete.
- **Keyrings.** A keyring wraps and unwraps data keys. A wrapped data key is called an encrypted data key (EDK). EDKs are stored in the message. Every keyring call goes through a front-end step that checks the change from the materials before the call to the materials after it.
- **Raw AES keyring.** It wraps data keys with a local AES key. The mode is Galois/Counter Mode (AES-GCM), which also detects tampering. Each wrap uses a fresh initialization vector (IV). The IV must never repeat under one key. The local wrapping key is wiped from memory when it is dropped.
- **Hierarchical keyring.** It wraps data keys with keys derived from branch keys kept in a key store. Each branch key has an identifier (ID) and versions.
- **Branch key wrap.** For each wrap, the hierarchical keyring derives a one-time key from the branch key. It uses a key-based key derivation function (KBKDF) with a fresh salt. It then wraps the data key with AES-256-GCM. The one-time key is wiped after use.
- **Key store.** The DynamoDB key store reads and writes branch key records in a DynamoDB table. It asks KMS to decrypt each record. It sends the record's fields to KMS as additional authenticated data (AAD), so KMS checks them.
- **Cache.** It keeps branch keys in memory for a time limit, so fewer calls go to KMS. The default cache adds storm tracking on top of a local cache. Storm tracking limits how many refreshes of the same key run at once.
- **Crypto wrapper.** The `prim` package (aws-mpl-primitives) wraps the aws-lc-rs crypto library. It offers AES-GCM, KBKDF, hashing, random numbers and constant-time comparison. It also offers the hash-based key derivation function (HKDF) and hash-based message authentication codes (HMAC). It signs with the Elliptic Curve Digital Signature Algorithm (ECDSA).
- **aws-lc-rs.** The crypto library itself. It calls C code through a foreign function interface (FFI). It can use a standard build or a build validated under the Federal Information Processing Standards (FIPS).
- **No unsafe code.** The `mpl/` and `prim/` code contains no `unsafe` Rust. aws-lc-rs is reached only through the safe wrappers in `prim`.
- **C++ shim handles.** C++ code reaches MPL objects through raw pointers called handles. Most are borrowed and checked for null. One function adopts an untyped keyring pointer and does not check it.

### Where KMS and DynamoDB fit

- KMS is the root of trust for branch keys and beacon keys. Beacon keys are the root keys for searchable encryption.
- KMS keys are named by Amazon Resource Names (ARNs). This document calls them key names.
- DynamoDB stores the branch key records. We do not trust DynamoDB for integrity.
- KMS checks every field of a record when it decrypts it. So a changed record fails, and tampering is detected.
- This check does not prove a record is the newest one. An older genuine record still passes (TM-MPL-005).

### Trust statement

- The process, the local AES wrapping key and the in-process cache are trusted.
- KMS is the trusted root of trust for branch keys and beacon keys.
- DynamoDB is not trusted for integrity. The KMS check makes its records show tampering, but not prove freshness (TM-MPL-005).
- aws-lc-rs is reached only through the safe wrappers in `prim`.
- Key stores, caches and branch key ID suppliers written by users are trusted code. The MPL does not check their results (TB7).
- C++ callers reach MPL objects through raw handles in the shim (TB8).
- The sender of a ciphertext is not trusted. That sender controls the inputs on the decrypt side (TB1, and the table of attacker-controlled inputs below).

### System diagram

The diagram restates the full model's overview in plain labels.

```
        Caller (ESDK, C++ shim, Database Encryption SDK, S3 Encryption Client)
                                    |
                  request encryption or decryption materials
                                    v
  +-------------------------------------------------------------------+
  | CMM front end: checks the returned materials are complete         |
  |   Default CMM: commitment policy and algorithm suite,             |
  |   ECDSA signing key creation, reproduced context merge            |
  +-------------------------------------------------------------------+
                                    |  keyring encrypt or decrypt call
                                    v
  +-------------------------------------------------------------------+
  | Keyring front end: checks each materials change (before, after)   |
  |   Raw AES keyring                    Hierarchical keyring         |
  +-------------------------------------------------------------------+
        |                                  |                   |
   AES-GCM (prim)                    Shared cache          Key store
   local wrapping key                default = storm       (DynamoDB key store)
   (wiped on drop)                   tracking over a        |              |
                                     local cache          AWS KMS      Amazon DynamoDB
                                     (in process)         (context     (branch key
                                          |                as AAD)      records)
                  branch key wrap (KBKDF + AES-256-GCM, derived key wiped)
                                          |
                           prim crypto wrapper (aws-mpl-primitives)
      AES-GCM, KBKDF, HKDF, HMAC, ECDSA, hashing, random numbers, constant-time compare
                                          |
         aws-lc-rs (standard or FIPS build) through FFI; no unsafe Rust in mpl/ or prim/

  C++ callers --> C++ shim --> keyrings, caches, key stores and AWS clients
      borrowed raw handles (null checked), adopted untyped keyring pointer (not checked)
```

## What we protect

The MPL protects secret keys from disclosure and protects key records and settings from silent change. The table lists every asset in the full model.

| ID | Asset | What it is | Protection needed | Notes |
|---|---|---|---|---|
| A1 | Plaintext data keys | The keys that encrypt the message data | Confidentiality | Wiped on drop. The length must match the algorithm suite. |
| A2 | Branch keys (32 bytes) | The root of the derived-key hierarchy | Confidentiality | Cached in the process for the time limit. Kept longer if the entry is not read again (TM-MPL-015). Wiped on drop. |
| A3 | Derived branch keys (32 bytes) | One-time AES-256-GCM keys, one per wrap or unwrap | Confidentiality | Wiped after use. |
| A4 | Raw AES wrapping key | A long-lived local secret | Confidentiality | Wiped on drop. |
| A5 | ECDSA signing key | Created for each encryption with a signing suite | Confidentiality and integrity | Wiped on drop. |
| A6 | Beacon keys | The root key for searchable encryption | Confidentiality | Wiped on drop. |
| A7 | Branch key records in DynamoDB | The wrapped key, its KMS key name and its context fields | Integrity | KMS binding shows tampering. No freshness guarantee. |
| A8 | Encryption context and AAD | Values bound to a ciphertext | Integrity | Binds the ciphertext to its context. Must survive the round trip. |
| A9 | Algorithm suite ID and commitment policy | The settings that pick the algorithms | Integrity | Decide whether key commitment is required. |
| A10 | Cache entries | Branch key materials plus creation and expiry times | Confidentiality, integrity and availability | Held in the process. Found by a cache ID built with the Secure Hash Algorithm (SHA-384). |
| A11 | KMS grant tokens and key names | Settings | Integrity | Decide which KMS key authorizes operations. |
| A12 | Output of the secure random number generator | IVs, salts, data keys and the partition ID | Integrity | Comes from the random byte function in `prim`. |
| A13 | Ambient AWS credentials | The credentials already present on a developer or continuous integration (CI) host | Confidentiality and integrity | Used by the loopback test servers (TM-MPL-026). |
| A14 | Key store read capacity and request time on decrypt | Database reads and latency | Availability | Spent for each EDK on decrypt (TM-MPL-025). |

**How the assets tie to the top risks.**

- The cache mix-up exposes branch keys (A2) through cache entries (A10).
- Record rollback affects the integrity of the branch key records (A7).
- Unbounded decrypt work spends key store read capacity and request time (A14).
- The test servers can misuse the ambient AWS credentials of a host (A13).
- Every secret key asset (A1 to A6) is wiped on drop. Short-lived copies can remain (TM-MPL-015).

## Who could attack it

The most important threat actors are the database tamperer (TA1), a co-tenant sharing a cache (TA3) and the sender of a ciphertext (TA8).

**Legitimate actors.**

| Actor | Role |
|---|---|
| Application caller | Asks the MPL for encryption and decryption materials. |
| AWS KMS | The root of trust. Decrypts branch key records and checks their fields. |
| Amazon DynamoDB | Stores branch key records. |
| Operators | Configure the key store and the keyrings. |

**Threat actors.**

| ID | Actor | What they can do |
|---|---|---|
| TA1 | DynamoDB tamperer | Can read and write the branch key table, but cannot use the KMS keys. The exception is an actor who also controls a KMS key whose policy admits the application role (TM-MPL-002). |
| TA2 | Malicious or confused caller | On encrypt, controls the encryption context, the reproduced context, the algorithm suite ID and the inputs to the branch key ID supplier. Its decrypt-side powers are listed under TA8. |
| TA3 | Co-tenant sharing a cache | Can influence its own partition ID, logical key store name or branch key ID. For example, these values may be built from a tenant name. |
| TA4 | In-process memory attacker | Reads freed memory, core dumps or swap space. This is an attacker who has already broken in, or who reads memory chips after power-off (a cold-boot attack). |
| TA5 | Network attacker | Sits between the MPL and KMS or DynamoDB. Transport Layer Security (TLS) is assumed, so what is left is a downgrade or denial of service. |
| TA6 | Supply chain attacker | Targets the libraries the MPL depends on: aws-lc-rs, uuid, lru, zeroize and the AWS SDK libraries. |
| TA7 | C++ caller of the shim | Passes handles that are dangling, forged or adopted twice. This can be a bug or hostile code in the same process (TM-MPL-024). |
| TA8 | Ciphertext sender | Anyone who can give the service a message to decrypt, or change a stored message. Not authenticated. Controls the inputs listed below. |
| TA9 | Local process on a developer or CI host | Can connect to the loopback address 127.0.0.1 (TM-MPL-026). |

**What the ciphertext sender (TA8) controls on decrypt.**

- The message's encryption context.
- The number of EDKs. A message can hold up to 65,535. The ESDK sets no limit by default.
- For each EDK: the provider ID, the provider info and the ciphertext. The ciphertext includes the 16 bytes that name the branch key version. They start at byte 28.
- The algorithm suite ID.

## Trust boundaries

A trust boundary is a place where data passes between parties that trust each other differently. The weakest boundaries are these. TB1 has no limit on EDK count on decrypt. TB4 has a cache ID that is not unique. TB7 does not check user components. TB8 does not check the adopted handle. TB9 has no authentication.

| ID | Boundary | What crosses it | Controls today |
|---|---|---|---|
| TB1 | Caller or ciphertext sender to the MPL interface | Materials requests, encryption context, EDKs, algorithm suite ID | CMM checks, reserved-key checks, commitment policy, and materials checks on every call. On decrypt, nothing in the MPL limits the EDK count (TM-MPL-025). |
| TB2 | MPL to AWS KMS | Calls to create a data key without plaintext, re-encrypt and decrypt | KMS authentication, the context sent as AAD, a limit on allowed key names, grant tokens. |
| TB3 | MPL to DynamoDB | Single-item reads and multi-item write transactions | The KMS binding makes records show tampering. Writes are conditional. Reads are not strongly consistent. |
| TB4 | Keyring to the in-process cache | Storing and reading cache entries | A SHA-384 cache ID (not unique when fields contain zero bytes, BUG-06), an exact time limit check, a check of the entry kind. |
| TB5 | `mpl` and `prim` to aws-lc-rs through FFI | AES-GCM, key derivation, ECDSA and random number calls | Safe wrappers in `prim`, length checks, and the aws-lc-rs nonce type that is meant to be used only once. |
| TB6 | Process memory to the operating system | Freed memory, swap space, core dumps | Secret types are wiped on drop. Debug output hides secrets. Short-lived copies remain (TM-MPL-015). |
| TB7 | MPL to components written by users | Key stores, caches, branch key ID suppliers, user keyrings and user CMMs | Keyring and CMM output is checked by the front-end step. Key store, cache and supplier output is not checked. Only the kind of a cache entry is checked. |
| TB8 | C++ code to the shim to the MPL | Raw handles to keyrings, key stores, caches and SDK clients (borrowed), and an untyped keyring pointer (adopted) | Null checks on borrowed handles only. No checks on the adopted pointer. |
| TB9 | Loopback client to a test server to the MPL | Requests in Concise Binary Object Representation (CBOR) on 127.0.0.1 that build keyrings and AWS clients | Bound to the loopback address only. No authentication. Not published. |

### Inputs an attacker controls at each boundary

Most attacker-controlled inputs have a check. The gaps are the EDK count on decrypt and zero bytes in cache ID fields. The outputs of user components, the adopted C++ pointer and the test server requests are not checked either.

| Boundary | Input the attacker controls | Where it is used | Check today | Threats |
|---|---|---|---|---|
| TB1 (decrypt) | Message encryption context (keys and values) | Context decoding, AAD, and the supplier input | Strict text, order and duplicate checks. Empty keys are accepted. | TM-MPL-013, TM-MPL-017, TM-MPL-003 |
| TB1 (decrypt) | Algorithm suite ID | The default CMM's decrypt allow list, and an ESDK check before the CMM | Policy tables | TM-MPL-006, TM-MPL-008 |
| TB1 (decrypt) | EDK count, provider ID, provider info | The hierarchical keyring's EDK filter, and the raw AES keyring's EDK selection | Provider ID and info must match. No limit on count unless the ESDK is configured with one. | TM-MPL-025, TM-MPL-023 |
| TB1 (decrypt) | EDK ciphertext length and content, including the 16 version bytes | EDK decryption and branch key unwrap | Length at least 44 bytes, then at least 60. The version is turned into standard universally unique identifier (UUID) text, so it cannot hold a zero byte. | TM-MPL-023, TM-MPL-025 |
| TB1 (encrypt) | Encryption context, partition ID, supplier output, requested suite | The cache ID, and the reserved-key check | No zero-byte check. No length limit. | TM-MPL-009, TM-MPL-010, TM-MPL-006 |
| TB1 (decrypt) | Reproduced encryption context | The reproduced context merge | Keys present in both must have equal values. | TM-MPL-017 |
| TB2 | Plaintext branch key length, error text | The 32-byte length check, and error sorting | KMS is trusted. | TM-MPL-005, TM-MPL-023 |
| TB3 | Any field of a record, including the KMS key name and the wrapped key | Record parsing, the authenticated context, and key name resolution | Strict field types. KMS checks every field. The record's key name is trusted only in discovery mode. | TM-MPL-002, TM-MPL-005, TM-MPL-007 |
| TB4 and TB7 | The cache entry returned for an ID, the key store result, the supplier's ID | Cache reads, key store results, supplier results | Entry kind check only | TM-MPL-009, TM-MPL-010 |
| TB8 | Handle values, ownership, the thread that frees them | Handle borrowing and keyring adoption in the shim | Null check on borrow only | TM-MPL-024 |
| TB9 | Region, table name, KMS key name, wrapping key, time limit | The MPL test server's request handlers | None | TM-MPL-026 |

## How data moves

On encrypt, the caller's context drives the choice of branch key and is bound into every wrapped key. On decrypt, the message sender controls the EDKs, and each matching EDK can cause one key store read. Both flows use the hierarchical keyring, which is the keyring with the most moving parts.

### Encrypt with the hierarchical keyring

1. The caller passes an encryption context and asks the CMM for encryption materials.
2. The default CMM picks the algorithm suite. It uses the policy default, or the requested suite if the commitment policy allows it for encrypt.
3. The CMM rejects context keys that are reserved for the library. For a signing suite it creates an ECDSA signing key. If key creation fails, the program crashes (BUG-05(a)).
4. The CMM calls the keyring. The keyring finds the branch key ID. The ID is either fixed in the settings or comes from the supplier, which reads the encryption context.
5. The keyring builds the cache ID. The ID is a SHA-384 hash of fixed tags, the partition ID, the logical key store name and the branch key ID, joined by zero bytes. This ID is not unique when a field contains a zero byte (BUG-06).
6. If the cache holds an entry for that ID and its age is within the time limit, the keyring uses it and skips to step 9.
7. On a cache miss, the key store reads the active branch key record from DynamoDB. It asks KMS to decrypt the record and sends the record's fields as AAD. In discovery mode, the KMS key used is the one named in the record (TM-MPL-002).
8. The keyring stores the branch key in the cache. The expiry is the current time plus the time limit. That addition is not checked, so a very large time limit crashes the program (BUG-01).
9. The keyring wraps the data key. It derives a one-time key from the branch key with KBKDF and a fresh salt. The one-time key is wiped after use. It then encrypts the data key with AES-256-GCM, a fresh IV and AAD. The AAD holds a fixed label, the branch key ID, the version and the encryption context.
10. The result is an EDK. Its provider ID is "aws-kms-hierarchy". Its provider info is the branch key ID. Its ciphertext holds the salt, the IV, the version, the wrapped key and the authentication tag.
11. The keyring front end checks the change in materials. The CMM front end checks that the final materials are complete.

```
caller context --> CMM: get encryption materials
     | Default CMM: suite = policy default or requested suite (allowed for encrypt)
     | reserved key check; ECDSA signing key creation (crashes on failure, BUG-05(a))
     v
Keyring: on encrypt
     | branch key ID = fixed setting, or supplier(context)
     | cache ID = SHA-384(tags, partition ID, logical name, branch key ID),
     |            fields joined by zero bytes                              (BUG-06)
cache hit (age <= time limit)? -- yes --> branch key wrap
     | no                                         ^
     v                                            | KBKDF(salt) -> one-time key (wiped)
Key store: get active branch key                  | AES-256-GCM(IV, AAD = label,
     | KMS decrypt(record, record fields as AAD)  |   branch key ID, version, context)
     v                                            | (in discovery mode the KMS key is
put in cache (expiry = now + time limit,          |  the record's own, TM-MPL-002)
    addition not checked, BUG-01) ----------------+
     v
EDK { provider ID = "aws-kms-hierarchy", provider info = branch key ID,
      ciphertext = salt, IV, version, wrapped key, tag }
     | keyring front end: check the change; CMM front end: check complete
```

### Decrypt with the hierarchical keyring

1. The caller passes the EDKs from the message and the reproduced encryption context. It asks the CMM for decryption materials.
2. The CMM checks that the commitment policy allows the algorithm suite for decrypt. It merges the reproduced context and sets up the signature verification key.
3. The CMM calls the keyring. The keyring keeps only EDKs whose provider ID matches, whose provider info is valid UTF-8 text (the standard text encoding), and whose branch key ID equals the configured one.
4. The keyring tries the matching EDKs one after another. For each one:
   1. It requires at least 44 bytes of ciphertext. It reads the version from the 16 bytes that start at byte 28. The full 60-byte length check comes later (BUG-05(b)).
   2. It builds the cache ID. This ID is a SHA-384 hash of fixed tags, the partition ID, the logical key store name, the branch key ID and the version, joined by zero bytes.
   3. It uses a cache entry within the time limit, or asks the key store for that branch key version. A failed key store read is not cached. The in-progress mark for that key stays set (TM-MPL-025).
   4. It unwraps the data key. It requires at least 60 bytes. It derives the one-time key with KBKDF and the salt, then opens the AES-256-GCM ciphertext with the IV and AAD.
5. The keyring adds the data key, after checking its length. The keyring front end checks the change in materials. The CMM front end checks that the final materials are complete.

```
EDKs + reproduced context --> CMM: decrypt materials
     | suite allowed for decrypt; merge reproduced context; verification key
     v
Keyring: on decrypt (filter: provider ID, UTF-8 provider info, branch key ID equal)
     | for each matching EDK, one after another:
     |   length >= 44 -> version = 16 bytes from byte 28  (60-byte check later, BUG-05(b))
     |   cache ID = SHA-384(tags, partition ID, logical name, branch key ID, version),
     |              fields joined by zero bytes
     |   cache hit (age <= time limit) or key store: get branch key version
     |      (a failed read is not cached; the in-progress mark stays, TM-MPL-025)
     |   branch key unwrap: length >= 60; KBKDF(salt) -> AES-256-GCM open(IV, AAD)
     v
add data key (length checked) -> keyring front end check -> CMM front end check
```

### What to notice in these flows

- The cache ID in step 5 of encrypt and step 4.2 of decrypt is where the cache mix-up starts (TM-MPL-009, TM-MPL-010, BUG-06).
- The key store read in step 7 of encrypt accepts the active record it reads. Nothing checks that it is the latest one. An older genuine record still passes the KMS check (TM-MPL-005).
- On decrypt, each matching EDK can cost one DynamoDB read. The reads run one after another. A message can hold up to 65,535 EDKs.
- This decrypt work happens before the message header is authenticated. So a stored message can be made slow by adding bogus EDKs to it (TM-MPL-025).
- A 44-byte EDK ciphertext is enough to cause a key store read, because the 60-byte check comes later (BUG-05(b)).
- The front-end checks at the end of both flows run on every call. They catch a keyring or CMM that returns incomplete or changed materials.

The full model has no separate diagram for key store writes. Key creation and rotation appear in the threats TM-MPL-005 and TM-MPL-016.

## What we checked and what we did not

**Scope.** We checked the MPL key management code (`mpl/`) and its crypto wrapper (`prim/`). We used the threat categories of STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege). Each threat is rated by likelihood and impact (see Appendix C). The C++ shim and the test servers are covered only where they touch MPL objects.

**Key assumptions.**

- The trust statement in "What this library does" lists what is trusted and what is not.
- Network traffic to KMS and DynamoDB is protected by TLS (TA5).

**Out of scope.**

- Message format concerns. The ESDK is treated only as a caller.
- The AWS KMS and DynamoDB services themselves. We did not test KMS-side behavior.
- The correctness of the crypto library. The proofs and tests treat it as trusted.
- Conformance with the Dafny version of the MPL. No claim is made.

## The risks that matter most

Five items follow. They are the High threats, plus Medium threats that have an open bug or are unconfirmed.

### 1. Cache mix-up between keyrings

- **What could go wrong.** Two keyrings that share a cache can end up with the same cache entry name when a name field contains a zero byte. One keyring then uses the other's branch key. Data of one tenant can become readable by holders of the other tenant's key store access.
- **Who is affected.** Services that share a cache and take tenant names from outside input (TA3).
- **Rating.** High. Likelihood Medium.
- **Protects us today.** The default cache partition ID is random. Sharing is opt-in. The cache returns only branch key entries. Entries past their time limit are fetched again.
- **Still open.** Nothing rejects zero bytes in the name fields. BUG-06 is open.
- **What is being done.** Two fix options are written down. Rejecting zero bytes is a code change. Adding length prefixes needs a spec change and breaks cache ID compatibility with other implementations. No owner or date is recorded.
- **IDs.** TM-MPL-009, TM-MPL-010. BUG-06.

### 2. Swapped or replayed branch key records

- **What could go wrong.** A person with write access to the DynamoDB table (TA1) could put an older genuine active record back. The keyring then encrypts under an older branch key version. No key is disclosed, but key rotation is undone. Nothing detects this.
- **Rating.** High. Likelihood Medium.
- **Protects us today.** Every record field is bound into the KMS encryption context. A record cannot be moved to another branch key ID or version without failing the KMS check.
- **Still open.** There is no freshness check. Key stores written by users are not checked. A record that lacks the creation time and hierarchy version fields is accepted, with low impact.
- **IDs.** TM-MPL-005. BUG-08 (informational, a check that can never trigger).

### 3. Stalls and crashes in cache refresh

- **What could go wrong.** Storm tracking can stall. A failed refresh can leave a stale in-progress mark, so later requests for the same key get throttling errors for a time. A very large configured time value makes the code crash and breaks that cache for as long as it lives.
- **Rating.** Medium. Likelihood Medium.
- **Protects us today.** Parallel refreshes are limited. A damaged lock returns an error instead of a crash. The cache is written before the in-progress mark is cleared.
- **Still open.** Setting validation does not enforce the spec's ordering of time values. The stalls were found by code reading and were not run. BUG-01 is open.
- **IDs.** TM-MPL-018. BUG-01.

### 4. Unbounded work when decrypting a message (unconfirmed)

- **What could go wrong.** The sender of a message (TA8) controls how many EDKs it holds and which key versions they name. Each EDK can cause one DynamoDB read. One message can slow requests and use up read capacity (A14). No secret is exposed.
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

## Threats by type (STRIDE)

The full model sorts each threat into one STRIDE category and names the part of the code it affects. Elevation of privilege has the most threats (ten). Repudiation has one. Ratings and status are in "All threats at a glance".

### Spoofing

Spoofing means pretending to be another party or key. All three threats here concern which key is used.

| Number | Threat in plain words | Component |
|---|---|---|
| TM-MPL-001 | The raw AES keyring makes an EDK whose provider ID pretends to be an AWS KMS keyring. | Raw AES keyring builder |
| TM-MPL-002 | A forged branch key record decrypts under a KMS key the attacker influences, so the wrong key is trusted. | Key store step that asks KMS to decrypt a branch key |
| TM-MPL-003 | A malicious branch key ID supplier, or supplier input taken from the message, returns a branch key ID the attacker chose. | Hierarchical keyring branch key ID lookup, and the branch key ID supplier |

### Tampering

Tampering means changing data or settings without being caught. These threats cover key names, key records and the encryption context.

| Number | Threat in plain words | Component |
|---|---|---|
| TM-MPL-004 | The key name and multi-Region key (MRK) matching rules accept a key name that should not match. | Multi-Region key matching, and the key name compatibility check |
| TM-MPL-005 | A key record is swapped for a valid record of another branch key ID or version, or an older active record is replayed. | DynamoDB key store, its KMS calls, and record parsing |
| TM-MPL-013 | The AAD for branch key wrap and unwrap is built inconsistently, which breaks the binding to the context. | AAD construction in branch key wrap |
| TM-MPL-016 | A race during key rotation bypasses the conditional write and overwrites the active record. | Branch key rotation in the DynamoDB key store |
| TM-MPL-017 | The merge of the encryption context with the reproduced context lets an attacker drop or change bound values. | Reproduced context merge in the default CMM |

### Repudiation

Repudiation means an action cannot be traced to who did it. The one threat here concerns the audit trail.

| Number | Threat in plain words | Component |
|---|---|---|
| TM-MPL-020 | Nothing ties an MPL operation to the KMS and DynamoDB calls it caused. | Key store and keyrings |

### Information disclosure

Information disclosure means secrets reach someone who should not see them. These threats cover memory, error text and the shared cache.

| Number | Threat in plain words | Component |
|---|---|---|
| TM-MPL-015 | Secret material (branch keys, data keys, derived keys, the wrapping key) is not wiped, or is kept after its use. | Materials structures, branch key wrap, raw AES keyring, `prim`, and the local cache |
| TM-MPL-021 | Secret bytes or attacker-supplied text leak through debug output, error text or logs. | Materials structures and the error model |
| TM-MPL-010 | A shared cache serves branch key materials to a keyring that should not have them. | Cache ID construction and the hierarchical keyring |

### Denial of service

Denial of service means making the service slow or unavailable. These threats cover the cache, bad input and the decrypt path.

| Number | Threat in plain words | Component |
|---|---|---|
| TM-MPL-018 | A wrong storm tracking setting or a logic error causes a rush of refreshes, a deadlock, in-progress time limit failures, a stuck stale mark or a crash. | Storm tracking cache |
| TM-MPL-022 | The cache fills up or keeps pushing out entries, which forces a storm of KMS calls and throttling. | Local cache and default cache |
| TM-MPL-023 | A malformed EDK or ciphertext, or an extreme setting, causes a crash or resource blow-up instead of an error. | Branch key unwrap, keyrings, and the default CMM |
| TM-MPL-025 | The EDK count and branch key versions chosen by the sender drive key store reads, in-progress slots and elapsed time. This threat is provisional and unconfirmed. | Hierarchical keyring decrypt, and the storm tracking cache |

### Elevation of privilege

Elevation of privilege means gaining access or power that was not granted. This group covers weak crypto use, wrong keys and unsafe boundaries.

| Number | Threat in plain words | Component |
|---|---|---|
| TM-MPL-006 | An attacker forces a weaker algorithm suite or bypasses the commitment policy. | Default CMM, commitment policy, and materials checks |
| TM-MPL-007 | Discovery or multi-Region discovery settings decrypt a record under an alias or a key in a Region the attacker chose. | Key store resolution of the record's key name |
| TM-MPL-009 | Two cache IDs collide, so the cache returns the wrong branch key materials. | Cache ID construction |
| TM-MPL-011 | The raw AES keyring uses the same AES-GCM IV twice. | Raw AES keyring wrap, and AES encryption in `prim` |
| TM-MPL-012 | Branch key wrap uses the same salt and IV twice through a random collision. | Branch key wrap |
| TM-MPL-014 | The KBKDF input layout or output length is wrong, which weakens branch key derivation. | Branch key derivation |
| TM-MPL-008 | A non-committing suite is used where key commitment is expected. This enables the known attack called Invisible Salamanders. | Commitment policy and the default CMM |
| TM-MPL-019 | No spec-to-code tracing (the Duvet tool) is set up for the MPL, so a spec "MUST" can quietly stop being met. | Whole library |
| TM-MPL-024 | The C++ shim reads or adopts a handle to an MPL object that is dangling, forged or owned twice. | C++ shim (the boundary) |
| TM-MPL-026 | A loopback test server without authentication uses the host's AWS credentials for any local process. | MPL test server and the three other test servers |

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

- `docs/mpl-threat-model.md`: the full threat model. Sections 2 to 7 hold the overview, assets, actors, trust boundaries, data flows and threat list that this summary restates. Sections 8 to 11 hold the per-threat analysis, design notes, residual risks and recommendations. The appendix holds the risk matrix.
- `docs/mpl-bug-reports/README.md`: the bug list with severity, confidence and status. The folder `docs/mpl-bug-reports/` holds one report per bug.
- `docs/mpl-verification-targets.md`: the plan for formal proofs and what each one would show.

## Appendix A: Glossary

| Term | Meaning |
|---|---|
| AAD | Additional authenticated data. Data that is not encrypted but is checked on decrypt. A change makes decrypt fail. |
| AES-GCM | Advanced Encryption Standard in Galois/Counter Mode. A standard way to encrypt data and detect tampering. |
| Algorithm suite | A named set of crypto algorithms used to encrypt a message. |
| Alias | A short, changeable name that points to a KMS key. |
| ARN | Amazon Resource Name. The full name of an AWS resource, such as a KMS key. Called a key name in this document. |
| aws-lc-rs | The Rust crypto library the MPL uses. |
| Beacon key | A root key for searchable encryption, protected by KMS. |
| Branch key | A key kept in the key store. Data keys are wrapped under keys derived from it. |
| Branch key ID supplier | Code that picks the branch key ID for a request, often from the encryption context. |
| Branch key record | The stored form of a branch key in DynamoDB, protected by KMS. |
| Cache | In-memory store of branch keys for a time limit, to reduce KMS calls. |
| Cache ID | The SHA-384 hash that names a cache entry. |
| CBOR | Concise Binary Object Representation. A compact binary data format used by the test servers. |
| CI | Continuous integration. Automated build and test hosts. |
| CMM | Cryptographic materials manager. Chooses the algorithm suite and gets key material from a keyring. |
| Cold-boot attack | Reading secrets from memory chips shortly after a machine is powered off. |
| Commitment policy | A setting that says whether messages must use key commitment. |
| Conditional write | A database write that succeeds only if the stored data is still as expected. |
| Constant-time comparison | A comparison whose run time does not depend on the secret values compared. |
| Core dump | A file with a copy of a process's memory, written when it crashes. |
| Data key | The key that encrypts the message data. |
| Discovery mode | A key store setting that uses the KMS key named in each record instead of a configured key. Multi-Region discovery mode also changes the key's Region. |
| Duvet | A tool that traces spec requirements to the code that meets them. |
| DynamoDB | Amazon DynamoDB. The database that holds branch key records. |
| ECDSA | Elliptic Curve Digital Signature Algorithm. Used to sign messages. |
| EDK | Encrypted data key. A data key wrapped by a keyring, stored in the message. |
| Encryption context | Extra named values bound to a ciphertext. Decrypt fails if they differ. |
| Fail closed | On an error, refuse the operation instead of continuing. |
| FFI | Foreign function interface. The way Rust code calls C code. |
| FIPS | Federal Information Processing Standards. A United States government standard for crypto modules. |
| Front-end step | The common call path that every CMM or keyring call goes through. It runs the materials checks. |
| Grant token | A KMS value that gives temporary permission to use a key. |
| Handle | A raw pointer that C++ code holds to an MPL object. |
| HKDF | Hash-based key derivation function. |
| HMAC | Hash-based message authentication code. |
| Hierarchical keyring | A keyring that wraps data keys with keys derived from branch keys. |
| IAM | AWS Identity and Access Management. Controls who may use which AWS resource. |
| In-progress mark | The note storm tracking keeps while a key refresh is running. |
| Invisible Salamanders | A known attack where one ciphertext decrypts to two different messages under two keys. Key commitment stops it. |
| IV, nonce | Initialization vector. A value that must be unique for every encryption under one key. |
| KBKDF | Key-based key derivation function. Makes new keys from an existing key. |
| Key commitment | A property that makes a ciphertext decrypt under only one key. |
| Key store | The MPL part that creates and reads branch key records. |
| Keyring | A component that wraps and unwraps data keys. |
| KMS | AWS Key Management Service. The root of trust for branch keys. |
| Logical key store name | A name for a key store that is bound into its records and its cache IDs. |
| Loopback | The network address 127.0.0.1, which only the same machine can reach. |
| MRK | Multi-Region key. A KMS key with copies in several Regions under related names. |
| Partition ID | A value in the cache ID that keeps one user's cache entries apart from another's. |
| Provider ID, provider info | Fields of an EDK that say which keyring made it and which key it used. |
| Raw AES keyring | A keyring that wraps data keys with a local AES key. |
| Reproduced context | The encryption context the caller supplies again on decrypt. |
| SHA-384 | Secure Hash Algorithm with a 384-bit output. |
| Shim | A thin layer that lets code in one language use a library written in another. |
| Signing suite | An algorithm suite that signs each message with ECDSA. |
| Storm tracking | A cache feature that limits parallel refreshes of the same key. |
| Strongly consistent read | A database read that always returns the latest write. |
| STRIDE | A list of threat types: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege. |
| Supply chain attack | An attack through a library or tool that the software depends on. |
| Swap | Disk space the operating system uses to hold memory pages. |
| Time limit | How long a cache entry may be used. Also called time to live. |
| TLS | Transport Layer Security. Protects network traffic. |
| UTF-8 | The standard way to store text as bytes. |
| UUID | Universally unique identifier. A standard 128-bit ID format. |
| Wrapping key | A key used to encrypt (wrap) another key. |
| Zero byte | A byte with the value 0. |
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
