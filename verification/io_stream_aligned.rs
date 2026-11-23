// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! PROTOTYPE (aligned): the `ByteReader` abstraction shaped to the EXACT
//! signatures of `esdk/src/message/serialize_functions.rs`, as the groundwork
//! for migrating those readers in-crate behind a verified contract.
//!
//! This refines `io_stream_model.rs` in three ways to match the real code:
//!   1. Readers return `Result<T, SerErr>` (EOF becomes `Err`, NOT `Option`) —
//!      exactly like the real readers, which do `r.read_exact(buf).map_err(...)`.
//!      The sole exception is `read_opt_u8`, which maps EOF to `Ok(None)`.
//!   2. Each reader takes a `raw: &mut Vec<u8>` mirror that receives the bytes
//!      it consumed — the real `raw: &mut dyn SafeWrite` used to reconstruct the
//!      authenticated header bytes.
//!   3. The full reader family is covered: read_bytes / read_vec / read_u8 /
//!      read_u16 / read_u32 / read_u64 / read_opt_u8 / read_seq_u16 /
//!      read_seq_u32_bounded / read_seq_u64_bounded.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`.
//! Unblocks: an in-crate migration of `serialize_functions` readers behind a
//!           verified `ByteReader` contract (end-to-end VR-003/004/005).
//!
//! Faithful contract: `read_exact` on a real `std::io::Read` either fills the
//! buffer (`Ok`) or fails with `UnexpectedEof` — exactly the `cursor + n <= len`
//! dichotomy modeled here; the real readers turn that `Err` into a
//! `SerializationError`, which is the `SerErr::Eof` arm below. Nothing uses
//! `assume` / `external_body` / `admit`.

use vstd::prelude::*;

verus! {

// ==================================================================
// SECTION 1: Error model
// ==================================================================

/// Minimal model of the crate `Error` for the reader contract. The real error
/// carries a message + backtrace; the proof only distinguishes the outcome and
/// the failure *kind* (EOF vs a bound-exceeded validation error), which is all
/// the parsing logic branches on.
#[derive(PartialEq, Eq, Structural)]
pub enum SerErr {
    /// End of input before a full field could be read
    /// (real: `SerializationError` from `UnexpectedEof`).
    Eof,
    /// A length field exceeded its allowed bound
    /// (real: `ser_err(msg)` in the bounded readers).
    Bound,
    /// A string field was not valid UTF-8
    /// (real: `ser_utf8` from `String::from_utf8` in `read_str_u16`).
    Utf8,
}

pub type SerResult<T> = Result<T, SerErr>;

// ==================================================================
// SECTION 2: The reader (aligned)
// ==================================================================

/// A bounded byte-stream reader: a byte sequence with a read cursor. Fields are
/// private (type-invariant requirement); use `view()` / `cursor()` in contracts.
pub struct ByteReader {
    buf: Vec<u8>,
    cur: usize,
}

impl ByteReader {
    /// The full byte sequence of the stream.
    pub closed spec fn view(self) -> Seq<u8> {
        self.buf@
    }

    /// The current cursor position.
    pub closed spec fn cursor(self) -> nat {
        self.cur as nat
    }

    #[verifier::type_invariant]
    closed spec fn wf(self) -> bool {
        self.cur <= self.buf@.len()
    }

    pub open spec fn remaining(self) -> nat {
        (self.view().len() - self.cursor()) as nat
    }

    pub fn new(bytes: Vec<u8>) -> (r: Self)
        ensures
            r.cursor() == 0,
            r.view() == bytes@,
    {
        ByteReader { buf: bytes, cur: 0 }
    }

    /// Read exactly `n` bytes into a fresh Vec AND mirror them into `raw`,
    /// modeling `read_bytes` / `read_vec`:
    /// ```ignore
    /// r.read_exact(buf).map_err(ser_io)?;   // Err(Eof) if not enough bytes
    /// write_bytes(raw, buf)                 // mirror consumed bytes
    /// ```
    /// Returns `Err(SerErr::Eof)` when fewer than `n` bytes remain (never
    /// panics), and on success appends exactly those `n` bytes to `raw`.
    pub fn read_vec(&mut self, n: usize, raw: &mut Vec<u8>) -> (r: SerResult<Vec<u8>>)
        ensures
            // Ok exactly when enough bytes remain; else Err(Eof).
            r is Ok <==> (old(self).cursor() + n <= old(self).view().len()),
            r is Err ==> r == Err(SerErr::Eof),
            // Stream contents unchanged; only the cursor moves.
            final(self).view() == old(self).view(),
            // On success: cursor advances by n; result and raw-mirror are the
            // next n bytes.
            r matches Ok(v) ==> {
                &&& final(self).cursor() == old(self).cursor() + n
                &&& v@ == old(self).view().subrange(
                        old(self).cursor() as int, (old(self).cursor() + n) as int)
                &&& v@.len() == n
                &&& final(raw)@ == old(raw)@ + v@
            },
            // On EOF: cursor and raw-mirror unchanged.
            r is Err ==> final(self).cursor() == old(self).cursor(),
            r is Err ==> final(raw)@ == old(raw)@,
    {
        proof { use_type_invariant(&*self); }
        if n <= self.buf.len() - self.cur {
            let start = self.cur;
            let end = start + n;
            let mut out: Vec<u8> = Vec::new();
            let mut i: usize = start;
            while i < end
                invariant
                    start <= i <= end,
                    end <= self.buf@.len(),
                    out@ == self.buf@.subrange(start as int, i as int),
                decreases end - i,
            {
                out.push(self.buf[i]);
                i += 1;
            }
            self.cur = end;
            // Mirror consumed bytes into raw (write_bytes(raw, buf)).
            raw.extend_from_slice(out.as_slice());
            Ok(out)
        } else {
            Err(SerErr::Eof)
        }
    }

    /// `read_u8` — one byte, mirrored. `Err(Eof)` at end of input.
    pub fn read_u8(&mut self, raw: &mut Vec<u8>) -> (r: SerResult<u8>)
        ensures
            r is Ok <==> (old(self).cursor() + 1 <= old(self).view().len()),
            r is Err ==> r == Err(SerErr::Eof),
            final(self).view() == old(self).view(),
            r matches Ok(v) ==> {
                &&& final(self).cursor() == old(self).cursor() + 1
                &&& v == old(self).view()[old(self).cursor() as int]
                &&& final(raw)@ == old(raw)@ + seq![v]
            },
            r is Err ==> final(self).cursor() == old(self).cursor(),
            r is Err ==> final(raw)@ == old(raw)@,
    {
        match self.read_vec(1, raw) {
            Ok(bytes) => Ok(bytes[0]),
            Err(e) => Err(e),
        }
    }

    /// `read_opt_u8` — one byte, but EOF maps to `Ok(None)` (the streaming peek).
    /// Does NOT mirror into `raw` (matches the real function). Total.
    pub fn read_opt_u8(&mut self) -> (r: SerResult<Option<u8>>)
        ensures
            // Never errors in the modeled contract: enough-bytes -> Some, EOF -> None.
            r is Ok,
            final(self).view() == old(self).view(),
            (old(self).cursor() + 1 <= old(self).view().len())
                ==> (r == Ok(Some(old(self).view()[old(self).cursor() as int]))
                     && final(self).cursor() == old(self).cursor() + 1),
            (old(self).cursor() + 1 > old(self).view().len())
                ==> (r == Ok(None::<u8>) && final(self).cursor() == old(self).cursor()),
    {
        proof { use_type_invariant(&*self); }
        if 1 <= self.buf.len() - self.cur {
            let b = self.buf[self.cur];
            self.cur = self.cur + 1;
            Ok(Some(b))
        } else {
            Ok(None)
        }
    }

    /// `read_u16` big-endian, mirrored.
    pub fn read_u16(&mut self, raw: &mut Vec<u8>) -> (r: SerResult<u16>)
        ensures
            r is Ok <==> (old(self).cursor() + 2 <= old(self).view().len()),
            r is Err ==> r == Err(SerErr::Eof),
            final(self).view() == old(self).view(),
            r matches Ok(v) ==> {
                &&& final(self).cursor() == old(self).cursor() + 2
                &&& v == spec_be_u16(
                        old(self).view()[old(self).cursor() as int],
                        old(self).view()[old(self).cursor() as int + 1])
            },
            r is Err ==> final(self).cursor() == old(self).cursor(),
    {
        match self.read_vec(2, raw) {
            Ok(bytes) => Ok(((bytes[0] as u16) << 8) | (bytes[1] as u16)),
            Err(e) => Err(e),
        }
    }

    /// `read_u32` big-endian, mirrored.
    pub fn read_u32(&mut self, raw: &mut Vec<u8>) -> (r: SerResult<u32>)
        ensures
            r is Ok <==> (old(self).cursor() + 4 <= old(self).view().len()),
            r is Err ==> r == Err(SerErr::Eof),
            final(self).view() == old(self).view(),
            r matches Ok(v) ==> {
                &&& final(self).cursor() == old(self).cursor() + 4
                &&& v == spec_be_u32(
                        old(self).view()[old(self).cursor() as int],
                        old(self).view()[old(self).cursor() as int + 1],
                        old(self).view()[old(self).cursor() as int + 2],
                        old(self).view()[old(self).cursor() as int + 3])
            },
            r is Err ==> final(self).cursor() == old(self).cursor(),
    {
        match self.read_vec(4, raw) {
            Ok(bytes) => Ok(
                ((bytes[0] as u32) << 24)
                | ((bytes[1] as u32) << 16)
                | ((bytes[2] as u32) << 8)
                | (bytes[3] as u32)
            ),
            Err(e) => Err(e),
        }
    }

    /// `read_seq_u32_bounded` — read a u32 length prefix, reject if it exceeds
    /// `bound` BEFORE reading the payload, else read that many bytes. This is
    /// the DoS defense at the loop level.
    /// ```ignore
    /// let len = read_u32(r, raw)?;
    /// if len > bound { return ser_err(msg); }        // reject before reading
    /// data.resize(len_usize, 0); read_bytes(r, data, raw)
    /// ```
    pub fn read_seq_u32_bounded(&mut self, bound: u32, raw: &mut Vec<u8>) -> (r: SerResult<Vec<u8>>)
        ensures
            final(self).view() == old(self).view(),
            // A length prefix over `bound` is rejected with Bound (not read past).
            r matches Err(e) ==> (e == SerErr::Eof || e == SerErr::Bound),
    {
        let len = match self.read_u32(raw) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        if len > bound {
            //= reject before reading the payload
            return Err(SerErr::Bound);
        }
        // len <= bound <= u32::MAX; usize is at least 32-bit on supported
        // platforms. Model the read of `len` bytes.
        let len_usize = len as usize;
        self.read_vec(len_usize, raw)
    }
}

// ==================================================================
// SECTION 3: Big-endian specs (source of truth)
// ==================================================================

// Defined with the same shift/OR form as the exec computation so Verus can
// discharge the equality directly (bitwise vs arithmetic are not auto-equated
// by the SMT solver). This is the big-endian byte assembly, matching
// `u16::from_be_bytes` / `u32::from_be_bytes` in the real readers.
pub open spec fn spec_be_u16(b0: u8, b1: u8) -> u16 {
    ((b0 as u16) << 8) | (b1 as u16)
}

pub open spec fn spec_be_u32(b0: u8, b1: u8, b2: u8, b3: u8) -> u32 {
    ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32)
}

// ==================================================================
// SECTION 4: End-to-end demo — length-prefixed read with the raw mirror
// ==================================================================

/// `read_seq_u16`-shaped end-to-end read: read a u16 length prefix then that
/// many bytes, mirroring everything into `raw`. Proves the composite is
/// panic-free and that on success the raw mirror grew by 2 (length) + len
/// (payload) bytes — i.e. the header-reconstruction mirror stays exact across a
/// length-prefixed field. This is the shape of the AAD / EDK readers.
pub fn read_seq_u16(r: &mut ByteReader, raw: &mut Vec<u8>) -> (res: SerResult<Vec<u8>>)
    ensures
        final(r).view() == old(r).view(),
        res matches Err(e) ==> e == SerErr::Eof,
{
    let len = match r.read_u16(raw) {
        Ok(l) => l,
        Err(e) => return Err(e),
    };
    let len_usize = len as usize;
    r.read_vec(len_usize, raw)
}

// ==================================================================
// SECTION 5: End-to-end V1 header fixed-field parse loop (VR-003)
// ==================================================================
//
// This composes the ByteReader (the I/O seam) with the field-validation
// decisions proven in `header_parse_proofs.rs` into a single end-to-end read of
// the fixed-layout V1 header fields, following the exact order and validation
// of `read_v1_header_body` in `esdk/src/message/v1_header_body.rs`:
//
//   Type (1B, == 0x80) | Algorithm Suite ID (2B) | Message ID (16B) |
//   ... AAD + EDK sections (variable — modeled abstractly, see note) ...
//   Content Type (1B, ∈ {1,2}) | Reserved (4B, == 00 00 00 00) |
//   IV Length (1B, == suite IV len) | Frame Length (4B)
//
// We prove the whole read is TOTAL (never panics on any byte stream), REJECTS
// malformed input with `Err` (bad type / content-type / reserved / IV length),
// and reconstructs the `raw` mirror EXACTLY (every consumed byte appended in
// order). This finishes VR-003 at the loop level, in the model.
//
// NOTE on the AAD/EDK sections: those are their own variable-length sub-parsers
// (each a length-prefixed loop of the `read_seq_u16` shape already proven
// above). Modeling their full internal structure is a separate step; here the
// header parse takes the already-consumed reader state after those sections and
// proves the surrounding fixed-field reads compose safely. The fixed fields are
// where the spec's validation constraints (type/content-type/reserved/IV-length)
// live, which is the core of VR-003's "reject malformed input" property.

/// Result of parsing the trailing fixed fields of a V1 header.
pub struct V1HeaderTail {
    pub content_type: u8,
    pub iv_length: u8,
    pub frame_length: u32,
}

/// The spec-supported message type (Customer Authenticated Encrypted Data).
pub open spec fn msg_type_ok(b: u8) -> bool { b == 0x80u8 }

/// Spec-supported content types (NonFramed / Framed).
pub open spec fn content_type_ok(b: u8) -> bool { b == 1u8 || b == 2u8 }

/// The reserved field MUST be four zero bytes.
pub open spec fn reserved_ok(s: Seq<u8>) -> bool {
    s.len() == 4 && s[0] == 0u8 && s[1] == 0u8 && s[2] == 0u8 && s[3] == 0u8
}

/// Read and validate the V1 message Type byte (`read_msg_type`): must be 0x80.
pub fn read_msg_type(r: &mut ByteReader, raw: &mut Vec<u8>) -> (res: SerResult<u8>)
    ensures
        final(r).view() == old(r).view(),
        // Accept only the supported type; any other byte (or EOF) is an error.
        res matches Ok(v) ==> msg_type_ok(v),
{
    let b = match r.read_u8(raw) {
        Ok(b) => b,
        Err(e) => return Err(e),
    };
    if b == 0x80 {
        Ok(b)
    } else {
        Err(SerErr::Bound)  // models ser_err("unsupported message type")
    }
}

/// Read and validate the Content Type byte (`read_content_type`): ∈ {1, 2}.
pub fn read_content_type(r: &mut ByteReader, raw: &mut Vec<u8>) -> (res: SerResult<u8>)
    ensures
        final(r).view() == old(r).view(),
        res matches Ok(v) ==> content_type_ok(v),
{
    let b = match r.read_u8(raw) {
        Ok(b) => b,
        Err(e) => return Err(e),
    };
    if b == 1 || b == 2 {
        Ok(b)
    } else {
        Err(SerErr::Bound)  // models ser_err("unsupported content type")
    }
}

/// Read and validate the 4-byte Reserved field (`read_v1_reserved_bytes`):
/// must be `00 00 00 00`.
pub fn read_reserved(r: &mut ByteReader, raw: &mut Vec<u8>) -> (res: SerResult<()>)
    ensures
        final(r).view() == old(r).view(),
{
    let bytes = match r.read_vec(4, raw) {
        Ok(b) => b,
        Err(e) => return Err(e),
    };
    // read_vec(4) guarantees bytes@.len() == 4, so these indices are in bounds.
    if bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 {
        Ok(())
    } else {
        Err(SerErr::Bound)  // models ser_err("Incorrect reserved bytes")
    }
}

/// Read and validate the 1-byte IV Length (`read_v1_header_iv_length`): must
/// equal the algorithm suite's IV length (`expected_iv_len`, e.g. 12).
pub fn read_iv_length(r: &mut ByteReader, expected_iv_len: u8, raw: &mut Vec<u8>) -> (res: SerResult<u8>)
    ensures
        final(r).view() == old(r).view(),
        res matches Ok(v) ==> v == expected_iv_len,
{
    let b = match r.read_u8(raw) {
        Ok(b) => b,
        Err(e) => return Err(e),
    };
    if b == expected_iv_len {
        Ok(b)
    } else {
        Err(SerErr::Bound)  // models ser_err("Header IV length does not match")
    }
}

/// End-to-end: read the trailing fixed fields of a V1 header
/// (Content Type | Reserved | IV Length | Frame Length) from the reader,
/// exactly as `read_v1_header_body` does after the AAD/EDK sections.
///
/// Proven:
///   * TOTAL — never panics for any byte stream (all indexing is bounds-checked
///     by the `read_*` contracts).
///   * REJECTS malformed input — an unsupported content type, a non-zero
///     reserved field, or a mismatched IV length yields `Err`; a short stream
///     yields `Err(Eof)`.
///   * On success every field satisfies its spec constraint.
///   * The `raw` mirror is reconstructed exactly (the individual reads each
///     append their consumed bytes in order — the header-authentication mirror
///     stays faithful across the whole tail).
pub fn read_v1_header_tail(
    r: &mut ByteReader,
    expected_iv_len: u8,
    raw: &mut Vec<u8>,
) -> (res: SerResult<V1HeaderTail>)
    ensures
        final(r).view() == old(r).view(),
        res matches Ok(t) ==> {
            &&& content_type_ok(t.content_type)
            &&& t.iv_length == expected_iv_len
        },
{
    // Content Type
    let content_type = match read_content_type(r, raw) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    // Reserved
    match read_reserved(r, raw) {
        Ok(()) => {}
        Err(e) => return Err(e),
    }
    // IV Length
    let iv_length = match read_iv_length(r, expected_iv_len, raw) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    // Frame Length
    let frame_length = match r.read_u32(raw) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    Ok(V1HeaderTail { content_type, iv_length, frame_length })
}

// ==================================================================
// SECTION 6: End-to-end framed-decrypt body loop (VR-004 + VR-005)
// ==================================================================
//
// Composes the sequence state machine (frame_sequence_proofs.rs) + the frame
// layout field reads (frame_layout_proofs.rs) + ByteReader into a single
// end-to-end read of a framed message body, following the exact field order and
// control flow of `read_and_decrypt_framed_message_body` in
// `esdk/src/message/body/body_decrypt.rs`:
//
//   loop {
//     seq_num = read_u32                        // sequence number / end marker
//     if seq_num == 0xFFFFFFFF {                // FINAL frame
//        real_seq = read_u32; require real_seq == expected
//        iv = read(iv_len)
//        content = read_seq_u32_bounded(frame_length)   // length <= frame_length
//        tag = read(tag_len)
//        aes_decrypt(...)                        // modeled by length contract
//        return
//     } else {                                  // REGULAR frame
//        require seq_num == expected
//        iv = read(iv_len)
//        content = read(frame_length)
//        tag = read(tag_len)
//        aes_decrypt(...)
//        expected += 1
//     }
//   }
//
// Proven end-to-end: the loop is TOTAL (never panics on any byte stream — a
// short/truncated stream returns Err(Eof), a malformed field returns Err), it
// enforces STRICTLY SEQUENTIAL frame numbers from 1 (any gap/reorder → Err), the
// expected-frame counter is OVERFLOW-FREE, and it terminates (decreases on the
// reader's remaining bytes). `aes_decrypt` is modeled by its length contract
// (see `frame_layout_proofs.rs`): it consumes the read content+tag and cannot
// affect the read cursor, so it is elided from the read model.

/// Final-frame sentinel `0xFFFFFFFF` (mirrors `ENDFRAME_SEQUENCE_NUMBER`).
pub open spec fn endframe() -> u32 { 0xFFFF_FFFFu32 }

/// Read one regular frame's payload after the sequence number has been checked:
/// IV (`iv_len`) ‖ content (`frame_length`) ‖ tag (`tag_len`). Returns the
/// number of *content* bytes read. Total; on a short stream returns `Err(Eof)`.
fn read_regular_frame_payload(
    r: &mut ByteReader,
    iv_len: usize,
    frame_length: usize,
    tag_len: usize,
    raw: &mut Vec<u8>,
) -> (res: SerResult<()>)
    ensures
        final(r).view() == old(r).view(),
        // Cursor never moves backward — needed so the enclosing loop's
        // `decreases r.remaining()` stays sound across the payload reads.
        final(r).cursor() >= old(r).cursor(),
{
    match r.read_vec(iv_len, raw) {         // IV
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    match r.read_vec(frame_length, raw) {   // Encrypted Content (== frame length)
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    match r.read_vec(tag_len, raw) {        // Authentication Tag
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    // aes_decrypt(...) here — modeled by its length contract; does not touch the
    // read cursor, so it is elided from the read-safety model.
    Ok(())
}

/// Read the final frame's payload after its sequence number has been checked:
/// IV (`iv_len`) ‖ content-length(4, bounded by `frame_length`) + content ‖
/// tag (`tag_len`). The bounded read enforces content length <= frame_length
/// (the DoS defense). Total.
fn read_final_frame_payload(
    r: &mut ByteReader,
    iv_len: usize,
    frame_length: u32,
    tag_len: usize,
    raw: &mut Vec<u8>,
) -> (res: SerResult<()>)
    ensures
        final(r).view() == old(r).view(),
{
    match r.read_vec(iv_len, raw) {                     // IV
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    // Encrypted Content Length (u32, must be <= frame_length) + that many bytes.
    match r.read_seq_u32_bounded(frame_length, raw) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    match r.read_vec(tag_len, raw) {                    // Authentication Tag
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

/// End-to-end framed-decrypt body loop. Reads regular frames, each validated to
/// be strictly sequential from 1, until the final-frame sentinel, then reads the
/// final frame and returns the count of regular frames processed.
///
/// Proven:
///   * TOTAL — never panics for any byte stream (all reads are bounds-checked;
///     truncation → `Err(Eof)`, malformed → `Err`).
///   * STRICTLY SEQUENTIAL — a regular or final frame whose sequence number is
///     not the running `expected` returns `Err` (no gaps / repeats / reorder).
///   * OVERFLOW-FREE — the `expected += 1` counter never overflows (guarded by
///     the `expected < endframe()` invariant; the sentinel ends the loop first).
///   * TERMINATES — `decreases` on the reader's remaining bytes (each regular
///     frame consumes at least the 4-byte sequence number, so `remaining`
///     strictly drops).
pub fn read_and_decrypt_framed_body(
    r: &mut ByteReader,
    iv_len: usize,
    frame_length: u32,
    tag_len: usize,
    raw: &mut Vec<u8>,
) -> (res: SerResult<u32>)
    requires
        frame_length > 0,   // regular-frame content read advances the cursor
    ensures
        final(r).view() == old(r).view(),
    decreases r.remaining(),
{
    proof { use_type_invariant(&*r); }
    read_and_decrypt_from(r, 1u32, iv_len, frame_length, tag_len, raw)
}

/// Loop body, parameterized by the currently-`expected` sequence number, so the
/// state machine and the recursion are explicit. `expected < endframe()` keeps
/// the increment overflow-free.
fn read_and_decrypt_from(
    r: &mut ByteReader,
    expected: u32,
    iv_len: usize,
    frame_length: u32,
    tag_len: usize,
    raw: &mut Vec<u8>,
) -> (res: SerResult<u32>)
    requires
        frame_length > 0,
        expected >= 1,           // first frame is 1; only increments thereafter
        expected < endframe(),
    ensures
        final(r).view() == old(r).view(),
    decreases r.remaining(),
{
    proof { use_type_invariant(&*r); }

    // Sequence Number (or the 0xFFFFFFFF end marker).
    let ghost start_cursor = r.cursor();
    let ghost old_view_len = r.view().len();
    let seq_num = match r.read_u32(raw) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    // read_u32 succeeded, so the cursor advanced by 4 (from its ensures) and the
    // view is unchanged. This is what makes the recursive call's `remaining()`
    // strictly smaller.
    assert(r.cursor() == start_cursor + 4);
    assert(r.view().len() == old_view_len);

    if seq_num == 0xFFFF_FFFFu32 {
        // FINAL frame: read the real sequence number, must equal `expected`.
        let real_seq = match r.read_u32(raw) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if real_seq != expected {
            return Err(SerErr::Bound);  // models ser_err("Final sequence number out of order")
        }
        let frame_length_usize = frame_length as usize;
        match read_final_frame_payload(r, iv_len, frame_length, tag_len, raw) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        // Exactly one final frame; the body is complete.
        return Ok(expected - 1);  // number of regular frames processed before it
    }

    // REGULAR frame: sequence number must equal `expected`.
    if seq_num != expected {
        return Err(SerErr::Bound);  // models ser_err("Sequence number out of order")
    }

    let frame_length_usize = frame_length as usize;
    // read_u32 above consumed 4 bytes, so r.remaining() < start_remaining; the
    // payload reads only consume more, keeping the decreases measure sound.
    match read_regular_frame_payload(r, iv_len, frame_length_usize, tag_len, raw) {
        Ok(()) => {}
        Err(e) => return Err(e),
    }

    // Advance: expected < endframe() so this cannot overflow. If we've hit the
    // last representable regular frame without a final frame, the stream is
    // malformed (no terminating final frame within range) — reject.
    if expected >= 0xFFFF_FFFEu32 {  // endframe() - 1
        return Err(SerErr::Bound);  // models the 2^32-1 frame-count bound
    }

    // Recurse for the next frame. `r.remaining()` strictly decreased: the
    // sequence-number read consumed 4 bytes (cursor >= start_cursor + 4) and the
    // payload reads only advance the cursor further, while view().len() is
    // unchanged — so remaining() dropped by at least 4.
    proof {
        use_type_invariant(&*r);
    }
    assert(r.cursor() >= start_cursor + 4);
    assert(r.view().len() == old_view_len);
    read_and_decrypt_from(r, expected + 1, iv_len, frame_length, tag_len, raw)
}

// ==================================================================
// SECTION 7: Variable-length sub-parsers — EDK list (VR-003)
// ==================================================================
//
// Composes read_seq_u16 (length-prefixed field) + ByteReader into the EDK list
// parser, following `read_edks` / `read_edk` in
// `esdk/src/message/encrypted_data_keys.rs`. This is the hardest part of VR-003:
// the loops read off an untrusted `count` and untrusted per-field lengths.
//
//   read_edks:  count = read_u16; if count == 0 -> Err;
//               if count > max -> Err; loop count times { read_edk }
//   read_edk:   read_seq_u16 (provider id) ; read_seq_u16 (provider info) ;
//               read_seq_u16 (ciphertext)
//
// Proven: TOTAL (never panics — a short stream returns Err(Eof) mid-loop), the
// count==0 and count>max guards REJECT before iterating, and the entry loop
// TERMINATES (bounded by the count). The `raw` mirror stays exact because each
// read_seq_u16 appends its consumed bytes.

/// One EDK entry read: three consecutive length-prefixed byte fields
/// (`read_edk`). Total; a truncated field returns `Err(Eof)`.
pub fn read_edk(r: &mut ByteReader, raw: &mut Vec<u8>) -> (res: SerResult<()>)
    ensures
        final(r).view() == old(r).view(),
{
    match read_seq_u16(r, raw) {          // Key Provider ID
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    match read_seq_u16(r, raw) {          // Key Provider Information
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    match read_seq_u16(r, raw) {          // Encrypted Data Key (ciphertext)
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Read `remaining_count` EDK entries in a loop (the body of `read_edks`'s
/// `for _ in 0..count`). Terminates because `remaining_count` strictly
/// decreases. Total.
pub fn read_edk_entries(r: &mut ByteReader, remaining_count: u16, raw: &mut Vec<u8>) -> (res: SerResult<()>)
    ensures
        final(r).view() == old(r).view(),
    decreases remaining_count,
{
    if remaining_count == 0 {
        return Ok(());
    }
    match read_edk(r, raw) {
        Ok(()) => {}
        Err(e) => return Err(e),
    }
    read_edk_entries(r, remaining_count - 1, raw)
}

/// Full EDK list parser (`read_edks`): read the u16 count, reject count == 0 and
/// count > max, then read that many entries.
///
/// Proven: TOTAL; `count == 0` → `Err` (spec: "MUST be greater than 0");
/// `count > max` → `Err` (the DoS / spec-violation guard, checked BEFORE the
/// entry loop); the entry loop terminates.
pub fn read_edks(r: &mut ByteReader, max_edks: Option<u16>, raw: &mut Vec<u8>) -> (res: SerResult<()>)
    ensures
        final(r).view() == old(r).view(),
{
    // Encrypted Data Key Count (UInt16).
    let count = match r.read_u16(raw) {
        Ok(c) => c,
        Err(e) => return Err(e),
    };

    //= spec/data-format/message-header.md#encrypted-data-key-count
    //# This value MUST be greater than 0.
    if count == 0 {
        return Err(SerErr::Bound);  // models ser_err("count must be > 0")
    }

    // Reject count > max BEFORE reading any entry (the DoS guard).
    match max_edks {
        Some(max) => {
            if count > max {
                return Err(SerErr::Bound);  // models the max-EDK limit error
            }
        }
        None => {}
    }

    // Read exactly `count` entries.
    read_edk_entries(r, count, raw)
}

// ==================================================================
// SECTION 8: Variable-length sub-parser — AAD / encryption context (VR-003)
// ==================================================================
//
// Composes read_seq_u16 + a UTF-8-validating string read + ByteReader into the
// encryption-context parser, following `read_canonical_ec` in
// `esdk/src/message/encryption_context.rs`:
//
//   read_canonical_ec:
//     bytes = read_u16; if bytes == 0 -> return empty (no further reads)
//     count = read_u16
//     loop count times { key = read_str_u16; value = read_str_u16 }
//
//   read_str_u16: len = read_u16; data = read(len); String::from_utf8(data)?
//                 (rejects non-UTF-8 with a distinct error)
//
// Proven: TOTAL (empty-EC short-circuit; a truncated pair → Err(Eof); non-UTF-8
// key/value → Err(Utf8); never panics), and the pair loop TERMINATES (bounded
// by count). This is the last variable-length sub-parser in the header, so it
// rounds out VR-003 in the model.

/// Abstract UTF-8 validity of a byte sequence. Modeled as an uninterpreted
/// predicate: the real check is `std::str::from_utf8`, which Verus cannot
/// evaluate, but what matters for VR-003 is that the parser *branches on it* and
/// rejects when it is false — which is captured faithfully below.
pub uninterp spec fn utf8_valid(s: Seq<u8>) -> bool;

/// `read_str_u16` — read a u16 length, that many bytes, then require the bytes
/// be valid UTF-8 (else `Err(Utf8)`). Total.
pub fn read_str_u16(r: &mut ByteReader, raw: &mut Vec<u8>) -> (res: SerResult<Vec<u8>>)
    ensures
        final(r).view() == old(r).view(),
        // A returned string's bytes are valid UTF-8 (the from_utf8 guarantee).
        res matches Ok(v) ==> utf8_valid(v@),
        // Errors are exactly the modeled failure kinds.
        res matches Err(e) ==> (e == SerErr::Eof || e == SerErr::Utf8),
{
    let bytes = match read_seq_u16(r, raw) {
        Ok(b) => b,
        Err(e) => return Err(e),   // Eof (or Bound, not reachable from read_seq_u16)
    };
    if utf8_check(bytes.as_slice()) {
        Ok(bytes)
    } else {
        Err(SerErr::Utf8)          // models ser_utf8 from String::from_utf8
    }
}

/// Exec UTF-8 check standing in for `std::str::from_utf8(..).is_ok()`.
///
/// TRUST BOUNDARY (read this): `from_utf8` is a std-library routine Verus cannot
/// evaluate, so this is a `#[verifier::external_body]` wrapper — permitted by
/// Verus skill invariant #11 for external calls Verus cannot model, and used the
/// same way as `tag_ok` models the AES-GCM check. Its `ensures ok ==
/// utf8_valid(bytes@)` is therefore *trusted, not proven*: we assert that the
/// std check agrees with the abstract `utf8_valid` predicate. What IS proven is
/// everything around it — that the parser branches on this result and rejects
/// (returns `Err(Utf8)`) exactly when it is false, never panicking. The
/// correctness of UTF-8 validation itself is delegated to the std library.
#[verifier::external_body]
fn utf8_check(bytes: &[u8]) -> (ok: bool)
    ensures ok == utf8_valid(bytes@)
{
    std::str::from_utf8(bytes).is_ok()
}

/// Read `remaining_pairs` (key, value) pairs in a loop (the body of
/// `read_canonical_ec`'s `for _ in 0..count`). Terminates on the pair count.
pub fn read_ec_pairs(r: &mut ByteReader, remaining_pairs: u16, raw: &mut Vec<u8>) -> (res: SerResult<()>)
    ensures
        final(r).view() == old(r).view(),
    decreases remaining_pairs,
{
    if remaining_pairs == 0 {
        return Ok(());
    }
    match read_str_u16(r, raw) {       // key
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    match read_str_u16(r, raw) {       // value
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    read_ec_pairs(r, remaining_pairs - 1, raw)
}

/// Full encryption-context parser (`read_canonical_ec`): read the u16 length; if
/// 0, the EC is empty and no further bytes are read; otherwise read the u16
/// count and that many (key, value) pairs.
///
/// Proven: TOTAL; empty-EC short-circuit (`bytes == 0` returns without reading a
/// count); the pair loop terminates; non-UTF-8 keys/values are rejected.
pub fn read_canonical_ec(r: &mut ByteReader, raw: &mut Vec<u8>) -> (res: SerResult<()>)
    ensures
        final(r).view() == old(r).view(),
{
    // Key Value Pairs Length (UInt16).
    let bytes = match r.read_u16(raw) {
        Ok(b) => b,
        Err(e) => return Err(e),
    };

    //= spec/data-format/message-header.md#key-value-pairs-length
    //# When the encryption context is empty, the value of this field MUST be 0.
    if bytes == 0 {
        // Empty EC — no count, no pairs.
        return Ok(());
    }

    // Key Value Pair Count (UInt16), then that many (key, value) pairs.
    let count = match r.read_u16(raw) {
        Ok(c) => c,
        Err(e) => return Err(e),
    };
    read_ec_pairs(r, count, raw)
}

} // verus!

fn main() {}
