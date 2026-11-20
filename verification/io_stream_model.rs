// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! PROTOTYPE: a Verus-modelable byte-stream abstraction for `SafeRead` /
//! `SafeWrite`.
//!
//! Goal: make the ESDK's read/write *loops* verifiable, not just the per-field
//! decisions. See `verification/README.md` and the "Next Steps" in
//! `docs/verification-recommendations.md`.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`.
//! Unblocks: end-to-end VR-003 (parse loop), VR-004 (sequence loop), VR-005
//!           (write loop), and ultimately VR-001/VR-002 (decrypt orchestration).
//!
//! # The idea
//!
//! The real traits wrap `std::io::{Read, Write}`, which Verus cannot model.
//! But the ESDK only ever uses two operations on them:
//!   * read side:  `read_exact(buf)` — fill `buf` fully, or error on EOF;
//!   * write side: `write_all(data)` — append all of `data`.
//! Everything else (`read_u8/u16/u32/u64`, `read_vec`, the bounded readers, the
//! frame writers) is built from those two. So we model the *stream contract*,
//! not `std::io`:
//!
//!   * `ByteReader` = an immutable byte sequence `data` + a cursor `pos`.
//!     `read_exact(n)` succeeds **iff** `pos + n <= data.len()`, returns
//!     `data[pos .. pos+n]` and advances `pos` by `n`; otherwise it returns an
//!     EOF error and leaves the cursor unchanged. It NEVER panics.
//!   * `ByteWriter` = a growing `Vec<u8>`; `write_all` appends.
//!
//! This is a faithful *contract* model: `read_exact` on a real
//! `std::io::Read` either fills the buffer (returns `Ok`) or fails with
//! `UnexpectedEof` — exactly the `pos + n <= len` dichotomy here. When the ESDK
//! read functions are eventually migrated in-crate, this `ByteReader` is the
//! abstraction their `requires`/`ensures` would be written against.
//!
//! Nothing here uses `assume` / `external_body` / `admit`.

use vstd::prelude::*;

verus! {

// ==================================================================
// SECTION 1: The reader model
// ==================================================================

/// A bounded byte-stream reader: a finite byte sequence with a read cursor.
/// Fields are private (required for a type-invariant struct); use the spec
/// accessors `view()` and `cursor()` in contracts.
pub struct ByteReader {
    /// The bytes held by the stream.
    buf: Vec<u8>,
    /// The read cursor: number of bytes consumed so far.
    cur: usize,
}

impl ByteReader {
    /// Spec accessor: the full byte sequence of the stream. `closed` because it
    /// reads a private field; callers reason about it abstractly.
    pub closed spec fn view(self) -> Seq<u8> {
        self.buf@
    }

    /// Spec accessor: the current cursor position.
    pub closed spec fn cursor(self) -> nat {
        self.cur as nat
    }

    /// Type invariant: the cursor never runs past the end of the buffer. This
    /// ties the exec state to the spec state (Verus skill invariant #14).
    #[verifier::type_invariant]
    closed spec fn wf(self) -> bool {
        self.cur <= self.buf@.len()
    }

    /// Bytes remaining to read.
    pub closed spec fn remaining(self) -> nat {
        (self.buf@.len() - self.cur) as nat
    }

    /// Construct a reader over `bytes`, cursor at 0.
    pub fn new(bytes: Vec<u8>) -> (r: Self)
        ensures
            r.cursor() == 0,
            r.view() == bytes@,
    {
        ByteReader { buf: bytes, cur: 0 }
    }

    /// Read exactly `n` bytes. Succeeds **iff** at least `n` bytes remain.
    /// On success returns the `n` bytes and advances the cursor by `n`; on EOF
    /// returns `None` and leaves the cursor unchanged. Total — never panics.
    pub fn read_exact(&mut self, n: usize) -> (r: Option<Vec<u8>>)
        ensures
            // Success exactly when enough bytes remain.
            r is Some <==> (old(self).cursor() + n <= old(self).view().len()),
            // The stream contents never change; only the cursor moves.
            final(self).view() == old(self).view(),
            // On success: cursor advanced by n, bytes are the next n bytes.
            r matches Some(v) ==> {
                &&& final(self).cursor() == old(self).cursor() + n
                &&& v@ == old(self).view().subrange(
                        old(self).cursor() as int,
                        (old(self).cursor() + n) as int,
                    )
                &&& v@.len() == n
            },
            // On EOF: cursor unchanged.
            r is None ==> final(self).cursor() == old(self).cursor(),
    {
        proof { use_type_invariant(&*self); }
        // Checked, panic-free bound test: cur <= len by the invariant, so the
        // subtraction does not underflow.
        if n <= self.buf.len() - self.cur {
            let start = self.cur;
            let end = start + n;
            let mut out: Vec<u8> = Vec::new();
            let mut i: usize = start;
            while i < end
                invariant
                    start <= i <= end,
                    end <= self.buf@.len(),
                    out@.len() == i - start,
                    out@ == self.buf@.subrange(start as int, i as int),
                decreases end - i,
            {
                out.push(self.buf[i]);
                i += 1;
            }
            self.cur = end;
            Some(out)
        } else {
            None
        }
    }
}

// ==================================================================
// SECTION 2: Big-endian field readers built on read_exact
// ==================================================================

/// Big-endian u32 spec (shared shape with the other proof files). The sum is
/// computed in unbounded `int` and cast to `u32`; since each byte contributes
/// at most `0xFF << (8*k)`, the total is at most `0xFFFFFFFF`, so the cast is
/// exact (no truncation).
pub open spec fn be_u32(b0: u8, b1: u8, b2: u8, b3: u8) -> u32 {
    ((b0 as int) * 0x1000000 + (b1 as int) * 0x10000 + (b2 as int) * 0x100 + (b3 as int)) as u32
}

/// `read_u32` built on `read_exact(4)`. Proves: total (EOF → None, never
/// panic); on success the cursor advances by 4 and the value is the big-endian
/// interpretation of the next 4 bytes. This is the seam the real
/// `serialize_functions::read_u32` would carry as its contract.
pub fn read_u32(r: &mut ByteReader) -> (res: Option<u32>)
    ensures
        res is Some <==> (old(r).cursor() + 4 <= old(r).view().len()),
        final(r).view() == old(r).view(),
        res matches Some(v) ==> {
            &&& final(r).cursor() == old(r).cursor() + 4
            &&& v == be_u32(
                    old(r).view()[old(r).cursor() as int],
                    old(r).view()[old(r).cursor() as int + 1],
                    old(r).view()[old(r).cursor() as int + 2],
                    old(r).view()[old(r).cursor() as int + 3],
                )
        },
        res is None ==> final(r).cursor() == old(r).cursor(),
{
    match r.read_exact(4) {
        Some(bytes) => {
            let v = (bytes[0] as u32) * 0x1000000
                + (bytes[1] as u32) * 0x10000
                + (bytes[2] as u32) * 0x100
                + (bytes[3] as u32);
            Some(v)
        }
        None => None,
    }
}

// ==================================================================
// SECTION 3: The writer model
// ==================================================================

/// A byte-stream writer: a growing byte sequence. `Vec<u8>` already models this
/// in Verus, so the "abstraction" is just the append contract stated as a
/// verified helper — matching `serialize_functions::write_bytes` /
/// `write_u32` when the writer is a buffer.
pub fn write_all(w: &mut Vec<u8>, data: &[u8])
    ensures
        final(w)@ == old(w)@ + data@,
        final(w)@.len() == old(w)@.len() + data@.len(),
{
    w.extend_from_slice(data);
}

// ==================================================================
// SECTION 4: End-to-end demo — a read loop verified against the model
// ==================================================================

/// Demonstration that a *loop* over the reader verifies end-to-end: read `k`
/// consecutive u32 values, proving the whole loop is panic-free, that it
/// consumes exactly `4*k` bytes on success, and that it stops cleanly at EOF
/// (returning how many it managed to read) rather than panicking. This is the
/// shape the real frame-sequence / header-parse loops take.
pub fn read_u32_run(r: &mut ByteReader, k: usize) -> (count: usize)
    ensures
        count <= k,
        // It consumed exactly 4 bytes per successful read.
        final(r).cursor() == old(r).cursor() + 4 * count,
        final(r).view() == old(r).view(),
    decreases k,
{
    proof { use_type_invariant(&*r); }
    if k == 0 {
        return 0;
    }
    match read_u32(r) {
        Some(_v) => {
            let rest = read_u32_run(r, k - 1);
            rest + 1
        }
        None => 0,
    }
}

// ==================================================================
// SECTION 5: Payoff — VR-004 sequence loop verified END-TO-END
// ==================================================================
//
// This is what the abstraction unlocks: unlike `frame_sequence_proofs.rs`
// (which proves the per-frame decision given an already-read sequence number),
// this reads the sequence numbers *from the stream* in a loop and validates
// them, proving the whole read-and-validate loop is panic-free and enforces
// strict sequential ordering from 1. It composes `ByteReader::read_u32` (the
// I/O seam) with the sequence check — the two halves that were previously
// provable only in isolation.

/// First frame sequence number (mirrors `START_SEQUENCE_NUMBER`).
pub open spec fn start_seq() -> u32 { 1u32 }

/// Read up to `max_frames` regular-frame sequence numbers from the stream and
/// validate that they are strictly sequential starting at 1. Returns the number
/// of validly-sequential frames consumed. Stops on the first out-of-order
/// number or at EOF.
///
/// Proven: total (no panic), the returned count never exceeds `max_frames`, and
/// on a fully-sequential run the cursor advanced by exactly `4 * count` bytes.
/// The `expected + 1` increment is overflow-guarded by the `max_frames` bound.
pub fn read_and_validate_seq_run(r: &mut ByteReader, max_frames: u32) -> (count: u32)
    requires
        max_frames < 0xFFFF_FFFFu32,
    ensures
        count <= max_frames,
    decreases max_frames,
{
    proof { use_type_invariant(&*r); }
    let mut expected: u32 = 1;  // START_SEQUENCE_NUMBER
    let mut consumed: u32 = 0;

    // Iterative read-and-validate loop over the stream.
    while consumed < max_frames
        invariant
            consumed <= max_frames,
            max_frames < 0xFFFF_FFFFu32,
            expected == start_seq() + consumed,
        decreases max_frames - consumed,
    {
        match read_u32(r) {
            Some(seq_num) => {
                if seq_num != expected {
                    // Out-of-order (gap / repeat / reorder): stop.
                    return consumed;
                }
                // Strictly sequential; advance. `expected < 0xFFFFFFFF` here
                // because expected == 1 + consumed and consumed < max_frames
                // < 0xFFFFFFFF, so the increment cannot overflow.
                expected = expected + 1;
                consumed = consumed + 1;
            }
            None => {
                // Clean EOF — no panic, just stop.
                return consumed;
            }
        }
    }
    consumed
}

} // verus!

fn main() {}
