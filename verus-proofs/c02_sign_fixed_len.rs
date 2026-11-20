// VR-2026-C02  (priority 6.40, capability category 2d)
// Bounded retry / no-panic / no-partial-write for the ECDSA signing loop.
//
// Run:   ~/verus/verus verus-proofs/c02_sign_fixed_len.rs
// This file is standalone. It is NOT part of any cargo target, so cargo never builds it.
//
// =====================================================================================
// 0. WHAT THIS FILE IS (read this first)
// =====================================================================================
// This is a proof about a RE-TYPED MODEL of the shipped code, not about the shipped
// code. The shipped functions use `aws_lc_rs` types, `&mut [u8]`, `impl FnMut`,
// `format!`, and `?`. Verus cannot compile `aws_lc_rs`, so the model re-types the
// pure control flow in Verus and abstracts everything that touches `aws_lc_rs`.
// The link between model and code is a human-checked correspondence table (section 2),
// NOT a machine-checked one. Nothing in this file is `assume`d / `admit`ted /
// `external_body`; the only trusted facts are listed in section 3.
//
// =====================================================================================
// 1. SOURCE MODELED   (repo esdk-native-mpl, HEAD 66aba1c, prim/src/ecdsa.rs)
// =====================================================================================
//   MAX_SIGN_ATTEMPTS      ecdsa.rs:148        const u32 = 128
//   signature_len          ecdsa.rs:158-163    const fn, P256 -> 71, P384 -> 103
//   sign_fixed_len         ecdsa.rs:180-195    (private) the retry loop; loop :185,
//                                              sign_once()? :186, length test :187,
//                                              copy_from_slice :188, Ok :189, err :192-194
//   check_sig_len          ecdsa.rs:200-210    (private) buffer-length guard
//   ecdsa_sign             ecdsa.rs:224-239    check :230, key parse :231-232,
//                                              SystemRandom::new :233, sign_fixed_len :234-238
//   ecdsa_sign_digest      ecdsa.rs:253-268    check :259, key parse :260-261,
//                                              context.digest() :262, sign_fixed_len :263-267
//   DigestContext::digest  ecdsa.rs:94-96      (private) `self.context.finish()`, abstracted
//
// =====================================================================================
// 2. CORRESPONDENCE TABLE (model line  <->  shipped line)
// =====================================================================================
//  shipped (prim/src/ecdsa.rs)                       | model (this file)
//  --------------------------------------------------+------------------------------------------
//  :148 const MAX_SIGN_ATTEMPTS: u32 = 128           | MAX_SIGN_ATTEMPTS, same value and type
//  :158-163 signature_len (match on alg: 71 / 103)   | signature_len + spec_signature_len, same match
//  :180-183 fn sign_fixed_len(signature: &mut [u8],  | sign_fixed_len<F: FnMut() -> Result<Signature,Error>>
//      mut sign_once: impl FnMut() -> Result<        |   (signature: &mut [u8], sign_once: F,
//      aws_lc_rs::signature::Signature, Error>)     |    log: &mut Ghost<Log>) -> Result<(), Error>
//      -> Result<(), Error>                          |   `impl FnMut` is an anonymous generic = F.
//                                                    |   EXTRA: ghost param `log` (erased; instrumentation).
//                                                    |   `mut` is moved to a local `let mut sign_once_m =
//                                                    |   sign_once;` so `ensures` can name the original.
//  :184 let want_len = signature.len();              | same
//  :185 for _ in 0..MAX_SIGN_ATTEMPTS                | for attempt in iter: 0..MAX_SIGN_ATTEMPTS (same range;
//                                                    |   the loop variable is named only to be used in a proof assert)
//  :186 let candidate = sign_once()?;                | let res = sign_once_m();  <ghost log push of res>;
//                                                    |   let candidate = match res { Ok(c) => c,
//                                                    |                               Err(e) => return Err(e) };
//                                                    |   = desugaring of `?` (From<Error> for Error is the
//                                                    |   identity). The ghost push is placed between the call
//                                                    |   and the match so the Err exit is recorded too.
//  :187 if candidate.as_ref().len() == want_len      | same, Signature::as_ref returns &bytes[..]
//  :188 signature.copy_from_slice(candidate.as_ref())| same call; Verus's vstd spec for
//                                                    |   <[T]>::copy_from_slice REQUIRES equal lengths, so
//                                                    |   the length test at :187 is what discharges it
//  :189 return Ok(())                                | same
//  :192-194 err(format!(..))                         | Err(Error)   (format! payload dropped; see sec. 4)
//  :200-210 check_sig_len                            | check_sig_len, same test `len != signature_len(alg)`
//                                                    |   (format! payload dropped)
//  :224-239 ecdsa_sign                               | ecdsa_sign<B: Backend>, same statement order:
//      check_sig_len(alg, signature)?;               |   check_sig_len(..)? (match/early return)
//      from_private_key_der(..).map_err(..)?         |   B::parse_key(alg, key)?      (abstract, sec. 3)
//      SystemRandom::new()                           |   (omitted; infallible, inside the aws-lc-rs TCB)
//      sign_fixed_len(signature, || sign(&rng,msg)   |   sign_fixed_len(signature, || -> (r: ..) ensures true
//                       .map_err(..))                |       { B::sign_msg(&k, msg) }, log)
//                                                    |   (`ensures true` is the Verus closure annotation;
//                                                    |   the closure is given NO contract, matching A3/A4)
//  :253-268 ecdsa_sign_digest                        | ecdsa_sign_digest<B: Backend>; additionally
//      context.digest()                              |   B::finish_digest(context)    (abstract)
//      sign_digest(&digest).map_err(..)              |   B::sign_digest(&k, &digest)  (abstract)
//
// =====================================================================================
// 3. TRUSTED ASSUMPTIONS (everything the result depends on besides the model's own code)
// =====================================================================================
//  A1  vstd's `assume_specification` for `<[T]>::copy_from_slice`
//      (vstd/std_specs/slice.rs:213): `requires dst.len() == src.len()`,
//      `ensures dst == src` (the whole destination is written, atomically).
//      This matches std: copy_from_slice panics on length mismatch, else memcpy.
//  A2  vstd's specs for `Vec::as_slice`/`len`, `Result` branching, `Range` iteration
//      (the for-loop termination argument), the Verus compiler and Z3.
//  A3  The signing closure is ABSTRACT. The proof holds for EVERY closure F
//      satisfying `call_requires(sign_once, ())` (no precondition), returning ANY
//      Ok(bytes of any length) or Err on every call. No statistics about the nonce are
//      assumed; the real closure's randomness (2^-128 exhaustion odds) is excluded.
//      For the shipped closures (`|| private_key.sign(&rng, msg).map_err(..)` and the
//      sign_digest variant) `call_requires` is vacuously true: they capture shared
//      references only and have no precondition. That is a reading of the shipped code,
//      not machine-checked.
//  A4  `trait Backend` stands for the aws-lc-rs calls (`EcdsaKeyPair::from_private_key_der`,
//      `.sign`, `.sign_digest`, `DigestContext::digest`, `SystemRandom::new`).
//      Their methods carry NO contract: they may return anything. "Does not panic"
//      for those calls is NOT proved here; it is assumed (they are outside Verus).
//  A5  Ghost instrumentation (`log`): a ghost sequence recording what each call of
//      sign_once returned. The model author pushes to it right next to the single call
//      site. Call counting is therefore only as trustworthy as the claim "sign_once()
//      appears once in the shipped loop body and is always followed by exactly one push",
//      which the reviewer must confirm against ecdsa.rs:185-191 (it does as of 66aba1c).
//      Verus's own FnMut modelling cannot count calls: vstd's
//      `axiom_fn_mut_call_ensures` says `mut_ref_current(f) == mut_ref_future(f)`,
//      i.e. FnMut state is treated as unchanged, so a ghost log is the only way.
//
//  A6  Verus treats the call of a generic `F: FnMut` as leaving `F` unchanged (a
//      closure's `call_ensures` is a fixed relation). The proof records, via
//      `log_from_closure`, that every logged outcome satisfies `call_ensures(sign_once, (), _)`.
//      A closure whose behavior depends on hidden mutable state (the shipped ones capture
//      shared refs only, so they have none) is therefore not distinguished from a stateful
//      one; because A3 lets the closure return ANYTHING, T1-T4 hold regardless.
//
// =====================================================================================
// 4. WHAT IS NOT COVERED
// =====================================================================================
//  * Conformance between model and shipped Rust (no machine-checked link; see below).
//  * The `format!` calls (ecdsa.rs:192-194, :202-207). They are replaced by a
//    payload-free `Err(Error)`. `format!` of `usize`/`u32`/derived-Debug values does
//    not panic in practice, but that is argued here, not verified.
//  * Any panic or hang inside aws-lc-rs (key parsing, signing, digest, RNG).
//  * `ecdsa_verify` / `ecdsa_verify_context` (the C02 YAML also lists
//    "never return Err"); `ecdsa_generate_keypair`; `DigestContext::finish`.
//    Out of scope for this task; no claim is made.
//  * The probability that a retry loop exhausts (2^-128). Only the bound is proved.
//  * Wall-clock/real-time termination: a closure that itself blocks is outside the
//    model (A3 assumes a closure call returns).
//  * Timing / side channels, and secret-memory handling.
//
//  GAP-CLOSING (what would turn this into a proof about the shipped code):
//   (a) make `prim` compile under Verus, e.g. put `sign_fixed_len` and `check_sig_len`
//       inside `verus!` in prim/src/ecdsa.rs with a ghost-log-free contract, with
//       `aws_lc_rs::signature::Signature` given an `external_type_specification` +
//       `assume_specification` for `as_ref`, and the format! calls moved behind a
//       cfg-free helper. That requires editing prim/, which this task forbids.
//   (b) alternatively extract `sign_fixed_len`'s generic body into a tiny crate
//       parameterised over a `trait CandidateSig: AsRef<[u8]>` and have both ecdsa.rs
//       and this file include the same source text (single source of truth).
//   (c) a mechanical diff check (script) between the model's control-flow skeleton
//       and ecdsa.rs:180-210.
//
// =====================================================================================
// 5. THEOREMS (what the ensures say)
// =====================================================================================
//  For every F satisfying A3, every buffer `signature`, with n = number of closure calls:
//   T1  n <= 128                                                  (sign_fixed_len, ecdsa_sign*)
//   T2  the function returns (loop has a Verus-checked termination argument) and no
//       panic occurs in the modeled code: Verus checks arithmetic overflow, the
//       copy_from_slice length precondition, and has no unwrap/index in the model.
//   T3  no partial write: Ok => the buffer now equals exactly one candidate returned
//       by sign_once, of length want_len, and it is the FIRST candidate whose length
//       matched; Err => the buffer is unchanged. The buffer length never changes.
//   T4  Err exits are exactly: (a) sign_once returned Err on call n (n >= 1) after n-1
//       length-mismatching candidates, or (b) exhaustion: n == 128 and all 128
//       candidates mismatched in length. (ecdsa_sign*: or n == 0, key rejected / bad buffer)
//   T5  check_sig_len: Ok <==> len == signature_len(alg).
//   T6  ecdsa_sign / ecdsa_sign_digest: wrong buffer length => Err, zero signing
//       calls, buffer untouched. Ok => buffer length == signature_len(alg).

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------------
// Model types (prim::Error, aws_lc_rs::signature::Signature, EcdsaSignatureAlgorithm)
// ---------------------------------------------------------------------------------

/// Model of `prim::Error`. The message payload is dropped (see section 4).
pub struct Error;

/// Model of `aws_lc_rs::signature::Signature`: an owned byte string of ANY length.
pub struct Signature {
    pub bytes: Vec<u8>,
}

impl Signature {
    /// Model of `<Signature as AsRef<[u8]>>::as_ref` (ecdsa.rs:187-188).
    pub fn as_ref(&self) -> (r: &[u8])
        ensures
            r@ == self.bytes@,
    {
        self.bytes.as_slice()
    }
}

/// ecdsa.rs:100-108 (`#[non_exhaustive]` is irrelevant inside the defining crate).
#[derive(Clone, Copy)]
pub enum EcdsaSignatureAlgorithm {
    EcdsaP384,
    EcdsaP256,
}

/// ecdsa.rs:148
pub const MAX_SIGN_ATTEMPTS: u32 = 128;

pub open spec fn spec_signature_len(alg: EcdsaSignatureAlgorithm) -> nat {
    match alg {
        EcdsaSignatureAlgorithm::EcdsaP256 => 71,
        EcdsaSignatureAlgorithm::EcdsaP384 => 103,
    }
}

/// ecdsa.rs:158-163
pub const fn signature_len(alg: EcdsaSignatureAlgorithm) -> (r: usize)
    ensures
        r == spec_signature_len(alg),
{
    match alg {
        EcdsaSignatureAlgorithm::EcdsaP256 => 71,
        EcdsaSignatureAlgorithm::EcdsaP384 => 103,
    }
}

// ---------------------------------------------------------------------------------
// Ghost instrumentation: log of what each sign_once call returned (assumption A5)
// ---------------------------------------------------------------------------------

/// One entry per call: `Some(bytes)` for Ok(candidate), `None` for Err.
pub type Log = Seq<Option<Seq<u8>>>;

pub open spec fn outcome(r: Result<Signature, Error>) -> Option<Seq<u8>> {
    match r {
        Ok(s) => Some(s.bytes@),
        Err(_) => None,
    }
}

/// Entries `from..to` of `log` are all successful candidates of the WRONG length.
pub open spec fn all_mismatch(log: Log, from: int, to: int, want: nat) -> bool {
    forall|k: int|
        #![trigger log[k]]
        from <= k < to ==> (log[k] is Some && log[k]->Some_0.len() != want)
}

/// Common frame: the log only grows by at most MAX_SIGN_ATTEMPTS entries and keeps its prefix.
pub open spec fn log_extends_within_bound(old_log: Log, new_log: Log) -> bool {
    &&& old_log.len() <= new_log.len() <= old_log.len() + 128
    &&& new_log.subrange(0, old_log.len() as int) == old_log
}

// ---------------------------------------------------------------------------------
// Sequence lemmas (pure, no assumptions)
// ---------------------------------------------------------------------------------

/// The log is unchanged: trivially extends within bound with 0 new entries.
proof fn lemma_log_unchanged(log: Log)
    ensures
        log_extends_within_bound(log, log),
{
    assert(log.subrange(0, log.len() as int) =~= log);
}

/// Pushing one entry keeps the old prefix.
proof fn lemma_push_keeps_prefix(base: Log, cur: Log, x: Option<Seq<u8>>)
    requires
        cur.subrange(0, base.len() as int) == base,
        base.len() <= cur.len(),
    ensures
        cur.push(x).subrange(0, base.len() as int) == base,
{
    assert(cur.push(x).subrange(0, base.len() as int) =~= cur.subrange(0, base.len() as int));
}

// ---------------------------------------------------------------------------------
// check_sig_len   (ecdsa.rs:200-210)
// ---------------------------------------------------------------------------------

pub fn check_sig_len(alg: EcdsaSignatureAlgorithm, signature: &[u8]) -> (r: Result<(), Error>)
    ensures
        r is Ok <==> signature@.len() == spec_signature_len(alg),  // T5
{
    if signature.len() != signature_len(alg) {  // :201
        return Err(Error);  // :202-207  (format! payload dropped)
    }
    Ok(())  // :209
}

// ---------------------------------------------------------------------------------
// sign_fixed_len  (ecdsa.rs:180-195)
// ---------------------------------------------------------------------------------

/// Every log entry in `from..to` records a value the closure is allowed to return
/// (`call_ensures`). This ties the ghost log to the abstract closure's contract.
pub open spec fn log_from_closure<F: FnMut() -> Result<Signature, Error>>(
    f: F,
    log: Log,
    from: int,
    to: int,
) -> bool {
    forall|k: int|
        #![trigger log[k]]
        from <= k < to ==> exists|x: Result<Signature, Error>|
            #![trigger outcome(x)]
            call_ensures(f, (), x) && log[k] == outcome(x)
}

/// Recording one more closure outcome keeps every entry justified by the closure's contract.
proof fn lemma_log_from_closure_push<F: FnMut() -> Result<Signature, Error>>(
    f: F,
    log: Log,
    from: int,
    x: Result<Signature, Error>,
)
    requires
        0 <= from <= log.len(),
        call_ensures(f, (), x),
        log_from_closure(f, log, from, log.len() as int),
    ensures
        log_from_closure(f, log.push(outcome(x)), from, log.len() as int + 1),
{
    let pushed = log.push(outcome(x));
    assert forall|k: int|
        #![trigger pushed[k]]
        from <= k < pushed.len() implies exists|y: Result<Signature, Error>|
            #![trigger outcome(y)]
            call_ensures(f, (), y) && pushed[k] == outcome(y) by {
        if k < log.len() {
            assert(pushed[k] == log[k]);
        } else {
            assert(pushed[k] == outcome(x));
            assert(call_ensures(f, (), x) && pushed[k] == outcome(x));
        }
    }
}

/// Postcondition shared by `sign_fixed_len` and its explicit-`decreases` cross-check variant.
/// This is the C02 `formal_spec` (docs/verification-targets/02-capability-driven.md) made precise.
pub open spec fn sign_fixed_len_post(
    old_sig: Seq<u8>,
    new_sig: Seq<u8>,
    old_log: Log,
    new_log: Log,
    r: Result<(), Error>,
) -> bool {
    let want = old_sig.len();
    let n = new_log.len() - old_log.len();
    // T1: at most 128 closure calls (and the old log is a prefix of the new one)
    &&& log_extends_within_bound(old_log, new_log)
    // the buffer length never changes
    &&& new_sig.len() == old_sig.len()
    &&& match r {
        // T3: Ok => buffer == the FIRST candidate with the right length, written whole.
        Ok(_) => {
            &&& n >= 1
            &&& new_log[old_log.len() + n - 1] is Some
            &&& new_log[old_log.len() + n - 1]->Some_0.len() == want
            &&& new_sig == new_log[old_log.len() + n - 1]->Some_0
            &&& all_mismatch(new_log, old_log.len() as int, old_log.len() + n - 1, want)
        },
        // T3/T4: Err => buffer untouched, and the Err is one of the two real exits:
        //  (a) sign_once returned Err on call n, after n-1 mismatching candidates
        //  (b) exhaustion: all 128 candidates had the wrong length
        Err(_) => {
            &&& new_sig == old_sig
            &&& ((n >= 1 && new_log[old_log.len() + n - 1] is None
                && all_mismatch(new_log, old_log.len() as int, old_log.len() + n - 1, want))
                || (n == 128
                && all_mismatch(new_log, old_log.len() as int, old_log.len() + n, want)))
        },
    }
}

pub fn sign_fixed_len<F: FnMut() -> Result<Signature, Error>>(
    signature: &mut [u8],
    sign_once: F,
    log: &mut Ghost<Log>,
) -> (r: Result<(), Error>)
    requires
        call_requires(sign_once, ()),  // A3: the closure has no precondition
    ensures
        sign_fixed_len_post(old(signature)@, final(signature)@, old(log)@, final(log)@, r),
        // every new log entry is something the closure's contract permits
        log_from_closure(sign_once, final(log)@, old(log)@.len() as int, final(log)@.len() as int),
{
    let want_len = signature.len();  // :184
    let ghost sig0 = signature@;
    let ghost log0 = log@;
    let ghost f0 = sign_once;
    let mut sign_once_m = sign_once;  // shipped :182 declares the parameter `mut`; same value, renamed so `ensures` can name the original
    for attempt in iter: 0..MAX_SIGN_ATTEMPTS  // :185  (termination: Verus's Range iterator, see T2)
        invariant
            iter.iter.end == MAX_SIGN_ATTEMPTS,
            iter.iter.start <= MAX_SIGN_ATTEMPTS,
            call_requires(sign_once_m, ()),
            sign_once_m == f0,
            sign_once == f0,
            sig0 == old(signature)@,
            log0 == old(log)@,
            signature@ == sig0,
            sig0.len() == want_len,
            log@.len() == log0.len() + iter.iter.start,
            log@.subrange(0, log0.len() as int) == log0,
            all_mismatch(log@, log0.len() as int, log0.len() + iter.iter.start, want_len as nat),
            log_from_closure(sign_once_m, log@, log0.len() as int, log@.len() as int),
        ensures
            // Normal (non-`return`) loop exit = all 128 attempts used. Checked by Verus at loop exit.
            log@.len() == log0.len() + 128,
            all_mismatch(log@, log0.len() as int, (log0.len() + 128) as int, want_len as nat),
    {
        assert(attempt == iter.iter.start && attempt < MAX_SIGN_ATTEMPTS);
        // :186  `sign_once()?`. The ghost push happens right after the call, before the
        // `?`-desugaring match, so that the Err exit is also recorded.
        let res = sign_once_m();
        proof {
            lemma_push_keeps_prefix(log0, log@, outcome(res));
            lemma_log_from_closure_push(sign_once_m, log@, log0.len() as int, res);
            log@ = log@.push(outcome(res));
        }
        let candidate = match res {
            Ok(c) => c,
            Err(e) => {
                return Err(e);
            },
        };
        if candidate.as_ref().len() == want_len {  // :187
            // :188  copy_from_slice requires dst.len() == src.len(); that is exactly the test above.
            signature.copy_from_slice(candidate.as_ref());
            return Ok(());  // :189
        }
    }
    // :192-194  err(format!(..))   -- exhaustion exit
    Err(Error)
}

// ---------------------------------------------------------------------------------
// CROSS-CHECK (not a model of shipped code): the same loop with an explicit `decreases`
// ---------------------------------------------------------------------------------
// The shipped loop is `for _ in 0..MAX_SIGN_ATTEMPTS`; Verus proves its termination from
// vstd's Range-iterator spec (assumption A2), with no user-visible `decreases`. To make the
// termination argument independent of that spec, this variant spells the same iteration as a
// `while` with a user-written, checked `decreases MAX_SIGN_ATTEMPTS - attempt`. It proves the
// same `sign_fixed_len_post`. It is a second re-typing of the shipped loop (for -> while), so it
// is evidence for T1/T2, not an additional claim about ecdsa.rs.

pub fn sign_fixed_len_while<F: FnMut() -> Result<Signature, Error>>(
    signature: &mut [u8],
    sign_once: F,
    log: &mut Ghost<Log>,
) -> (r: Result<(), Error>)
    requires
        call_requires(sign_once, ()),
    ensures
        sign_fixed_len_post(old(signature)@, final(signature)@, old(log)@, final(log)@, r),
        log_from_closure(sign_once, final(log)@, old(log)@.len() as int, final(log)@.len() as int),
{
    let want_len = signature.len();
    let ghost sig0 = signature@;
    let ghost log0 = log@;
    let ghost f0 = sign_once;
    let mut sign_once_m = sign_once;
    let mut attempt: u32 = 0;
    while attempt < MAX_SIGN_ATTEMPTS
        invariant
            attempt <= MAX_SIGN_ATTEMPTS,
            call_requires(sign_once_m, ()),
            sign_once_m == f0,
            sign_once == f0,
            sig0 == old(signature)@,
            log0 == old(log)@,
            signature@ == sig0,
            sig0.len() == want_len,
            log@.len() == log0.len() + attempt,
            log@.subrange(0, log0.len() as int) == log0,
            all_mismatch(log@, log0.len() as int, log0.len() + attempt, want_len as nat),
            log_from_closure(sign_once_m, log@, log0.len() as int, log@.len() as int),
        decreases MAX_SIGN_ATTEMPTS - attempt,
    {
        let res = sign_once_m();
        proof {
            lemma_push_keeps_prefix(log0, log@, outcome(res));
            lemma_log_from_closure_push(sign_once_m, log@, log0.len() as int, res);
            log@ = log@.push(outcome(res));
        }
        let candidate = match res {
            Ok(c) => c,
            Err(e) => {
                return Err(e);
            },
        };
        if candidate.as_ref().len() == want_len {
            signature.copy_from_slice(candidate.as_ref());
            return Ok(());
        }
        attempt = attempt + 1;
    }
    Err(Error)
}

// ---------------------------------------------------------------------------------
// Non-vacuity witnesses: the contracts are satisfiable and both outcomes are reachable.
// (Rule: no over-constrained `requires`. These callers discharge `call_requires` with real closures.)
// ---------------------------------------------------------------------------------

/// A closure that always returns a 71-byte signature: sign_fixed_len must return Ok after exactly 1 call.
fn witness_ok_first_attempt() {
    let mut buf: Vec<u8> = vec![0u8; 71];
    let mut log: Ghost<Log> = Ghost(Seq::empty());
    let r = sign_fixed_len(
        buf.as_mut_slice(),
        || -> (x: Result<Signature, Error>)
            ensures
                x is Ok && x->Ok_0.bytes@.len() == 71,
        { Ok(Signature { bytes: vec![7u8; 71] }) },
        &mut log,
    );
    proof {
        assert(r is Ok);
    }
}

/// A closure that always returns a 72-byte signature (never the canonical length): the loop
/// must exhaust, i.e. return Err after exactly 128 calls and leave the buffer unchanged.
fn witness_exhaustion() {
    let mut buf: Vec<u8> = vec![5u8; 71];
    let mut log: Ghost<Log> = Ghost(Seq::empty());
    let r = sign_fixed_len(
        buf.as_mut_slice(),
        || -> (x: Result<Signature, Error>)
            ensures
                x is Ok && x->Ok_0.bytes@.len() == 72,
        { Ok(Signature { bytes: vec![7u8; 72] }) },
        &mut log,
    );
    proof {
        assert(r is Err);
        assert(log@.len() == 128);
        assert(buf@ == Seq::new(71, |i: int| 5u8));
    }
}

/// A backend that parses every key and returns an empty signature, used only to exercise T6.
struct NullBackend;

impl Backend for NullBackend {
    type Key = ();
    type Ctx = ();
    type Digest = ();

    fn parse_key(alg: EcdsaSignatureAlgorithm, key: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn sign_msg(k: &(), msg: &[u8]) -> Result<Signature, Error> {
        Ok(Signature { bytes: Vec::new() })
    }

    fn finish_digest(ctx: ()) -> () {
        ()
    }

    fn sign_digest(k: &(), d: &()) -> Result<Signature, Error> {
        Ok(Signature { bytes: Vec::new() })
    }
}

/// T6: a 70-byte buffer for P-256 (needs 71) is rejected with zero signing calls and no write.
fn witness_wrong_buffer_length() {
    let mut buf: Vec<u8> = vec![9u8; 70];
    let mut log: Ghost<Log> = Ghost(Seq::empty());
    let r = ecdsa_sign::<NullBackend>(
        EcdsaSignatureAlgorithm::EcdsaP256,
        &[],
        &[],
        buf.as_mut_slice(),
        &mut log,
    );
    proof {
        assert(r is Err);
        assert(log@.len() == 0);
        assert(buf@ == Seq::new(70, |i: int| 9u8));
    }
}

// ---------------------------------------------------------------------------------
// The aws-lc-rs boundary (assumption A4). No contracts on purpose.
// ---------------------------------------------------------------------------------

pub trait Backend {
    type Key;
    type Ctx;
    type Digest;

    /// `EcdsaKeyPair::from_private_key_der(get_sign_alg(alg), key).map_err(..)`  (:231-232, :260-261)
    fn parse_key(alg: EcdsaSignatureAlgorithm, key: &[u8]) -> Result<Self::Key, Error>;

    /// `private_key.sign(&rng, msg).map_err(..)`  (:235-237)
    fn sign_msg(k: &Self::Key, msg: &[u8]) -> Result<Signature, Error>;

    /// `DigestContext::digest(self)`  (:94-96, called at :262)
    fn finish_digest(ctx: Self::Ctx) -> Self::Digest;

    /// `private_key.sign_digest(&digest).map_err(..)`  (:265-266)
    fn sign_digest(k: &Self::Key, d: &Self::Digest) -> Result<Signature, Error>;
}

/// Shared postcondition of ecdsa_sign / ecdsa_sign_digest (T1, T3, T4, T6).
pub open spec fn ecdsa_sign_post(
    alg: EcdsaSignatureAlgorithm,
    old_sig: Seq<u8>,
    new_sig: Seq<u8>,
    old_log: Log,
    new_log: Log,
    r: Result<(), Error>,
) -> bool {
    let want = spec_signature_len(alg);
    let n = new_log.len() - old_log.len();
    &&& log_extends_within_bound(old_log, new_log)  // T1: at most 128 closure calls
    &&& new_sig.len() == old_sig.len()
    // T6: wrong buffer length => Err, no signing call at all, buffer untouched
    &&& old_sig.len() != want ==> (r is Err && n == 0 && new_sig == old_sig)
    &&& match r {
        // T3 (no partial write): Ok => length right and the buffer is one whole, first-matching candidate
        Ok(_) => {
            &&& old_sig.len() == want
            &&& n >= 1
            &&& new_log[old_log.len() + n - 1] is Some
            &&& new_log[old_log.len() + n - 1]->Some_0.len() == want
            &&& new_sig == new_log[old_log.len() + n - 1]->Some_0
            &&& all_mismatch(new_log, old_log.len() as int, old_log.len() + n - 1, want)
        },
        // Err => buffer untouched; exits: n == 0 (buffer length / key rejected), Err from sign_once, exhaustion
        Err(_) => {
            &&& new_sig == old_sig
            &&& (n == 0
                || (n >= 1 && new_log[old_log.len() + n - 1] is None
                    && all_mismatch(new_log, old_log.len() as int, old_log.len() + n - 1, want))
                || (n == 128
                    && all_mismatch(new_log, old_log.len() as int, old_log.len() + n, want)))
        },
    }
}

// ---------------------------------------------------------------------------------
// ecdsa_sign  (ecdsa.rs:224-239)
// ---------------------------------------------------------------------------------

pub fn ecdsa_sign<B: Backend>(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    msg: &[u8],
    signature: &mut [u8],
    log: &mut Ghost<Log>,
) -> (r: Result<(), Error>)
    ensures
        ecdsa_sign_post(alg, old(signature)@, final(signature)@, old(log)@, final(log)@, r),
{
    // :230  check_sig_len(alg, signature)?;
    match check_sig_len(alg, signature) {
        Ok(()) => {},
        Err(e) => {
            proof {
                lemma_log_unchanged(log@);
            }
            return Err(e);
        },
    }
    // :231-232  from_private_key_der(..).map_err(..)?   (abstract)
    let private_key = match B::parse_key(alg, key) {
        Ok(k) => k,
        Err(e) => {
            proof {
                lemma_log_unchanged(log@);
            }
            return Err(e);
        },
    };
    // :233  SystemRandom::new()  -- omitted (infallible, aws-lc-rs TCB)
    // :234-238
    sign_fixed_len(signature, || -> (r: Result<Signature, Error>)
        ensures
            true,
        { B::sign_msg(&private_key, msg) }, log)
}

// ---------------------------------------------------------------------------------
// ecdsa_sign_digest  (ecdsa.rs:253-268)
// ---------------------------------------------------------------------------------

pub fn ecdsa_sign_digest<B: Backend>(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    context: B::Ctx,
    signature: &mut [u8],
    log: &mut Ghost<Log>,
) -> (r: Result<(), Error>)
    ensures
        ecdsa_sign_post(alg, old(signature)@, final(signature)@, old(log)@, final(log)@, r),
{
    // :259  check_sig_len(alg, signature)?;
    match check_sig_len(alg, signature) {
        Ok(()) => {},
        Err(e) => {
            proof {
                lemma_log_unchanged(log@);
            }
            return Err(e);
        },
    }
    // :260-261  from_private_key_der(..).map_err(..)?   (abstract)
    let private_key = match B::parse_key(alg, key) {
        Ok(k) => k,
        Err(e) => {
            proof {
                lemma_log_unchanged(log@);
            }
            return Err(e);
        },
    };
    // :262  let digest = context.digest();   (abstract)
    let digest = B::finish_digest(context);
    // :263-267
    sign_fixed_len(signature, || -> (r: Result<Signature, Error>)
        ensures
            true,
        { B::sign_digest(&private_key, &digest) }, log)
}

} // verus!

// Verus needs a crate root; this file is a proof-only crate.
fn main() {}
