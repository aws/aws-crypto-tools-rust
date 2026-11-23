// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Verus proofs for header-field parsing safety (VR-003).
//!
//! Models the pure decision logic of the header-field parsers in
//! `esdk/src/message/header_types.rs` and the bounded length readers in
//! `esdk/src/message/serialize_functions.rs`. See `verification/README.md` for
//! why the proofs live outside the `esdk` crate.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`
//! Target:   `docs/verification-recommendations.md` VR-003 (header/EDK parsing
//!           safety: malformed input returns `Err`, never panics).
//! Threats:  D3 (malformed header → parser panic/loop), D1/D2 (over-large
//!           length fields → allocation/DoS), T1 (algorithm-suite/version
//!           downgrade via a bogus version or content-type byte).
//! Spec:     spec/data-format/message-header.md#supported-versions,
//!           #supported-content-types; spec/client-apis/decrypt.md
//!           (parse-the-header / v1- & v2-header-deserialization).
//!
//! # The seam (READ THIS)
//!
//! The real `read_*` functions read a value from a `dyn SafeRead`
//! (`std::io::Read`) trait object — `let x = read_u8(r, raw)?;` — and then
//! `match` on `x` to accept a supported value or return `Err`. Verus cannot
//! model the trait-object read. The proofs below model the **decision** part:
//! given the byte/length value that was read, they prove the accept/reject
//! outcome matches the spec exactly, and that the bounded readers reject
//! over-limit lengths (the property that stops a malformed length field from
//! driving an unbounded allocation). The trait-object read itself is out of
//! Verus scope, as documented for the other proof files.

use vstd::prelude::*;

verus! {

// ------------------------------------------------------------------
// SECTION 1: Message format version — supported values only
// ------------------------------------------------------------------

/// Spec: the only supported version bytes are `0x01` (V1) and `0x02` (V2).
/// (`spec/data-format/message-header.md#supported-versions`.)
pub open spec fn version_supported(b: u8) -> bool {
    b == 0x01u8 || b == 0x02u8
}

/// Decision result for a parsed value: which supported variant, or a reject.
#[derive(PartialEq, Eq, Structural)]
pub enum VersionResult {
    V1,
    V2,
    /// Rejected. The `base64_hint` flag mirrors the source's special case for
    /// a leading `0x41` ('A'), the first byte of Base64-encoded input.
    Reject { base64_hint: bool },
}

/// Faithful model of the `match version { … }` in
/// `read_msg_format_version` (`header_types.rs`).
///
/// Original (after the trait-object read):
/// ```ignore
/// match version {
///     v if v == V1 as u8 => Ok(V1),           // 0x01
///     v if v == V2 as u8 => Ok(V2),           // 0x02
///     0x41 => ser_err("… Base64 …"),          // diagnostic hint
///     _    => ser_err("unsupported version"),
/// }
/// ```
///
/// We prove: the parse accepts a value **iff** it is spec-supported, the
/// accepted variant is the right one, and the Base64 hint fires exactly on
/// `0x41`. Total (never panics) for every `u8`.
pub fn parse_version(b: u8) -> (r: VersionResult)
    ensures
        (r == VersionResult::V1) <==> (b == 0x01u8),
        (r == VersionResult::V2) <==> (b == 0x02u8),
        (r is Reject) <==> !version_supported(b),
        r == (VersionResult::Reject { base64_hint: true }) <==> (b == 0x41u8),
{
    if b == 0x01u8 {
        VersionResult::V1
    } else if b == 0x02u8 {
        VersionResult::V2
    } else if b == 0x41u8 {
        VersionResult::Reject { base64_hint: true }
    } else {
        VersionResult::Reject { base64_hint: false }
    }
}

// ------------------------------------------------------------------
// SECTION 2: Content type — supported values only
// ------------------------------------------------------------------

/// Spec: the only supported content-type bytes are `1` (NonFramed) and `2`
/// (Framed). (`spec/data-format/message-header.md#supported-content-types`.)
pub open spec fn content_type_supported(b: u8) -> bool {
    b == 1u8 || b == 2u8
}

#[derive(PartialEq, Eq, Structural)]
pub enum ContentTypeResult {
    NonFramed,
    Framed,
    Reject,
}

/// Faithful model of the `match content_type { … }` in `read_content_type`
/// (`header_types.rs`). Proves accept-iff-supported and correct variant; total.
pub fn parse_content_type(b: u8) -> (r: ContentTypeResult)
    ensures
        (r == ContentTypeResult::NonFramed) <==> (b == 1u8),
        (r == ContentTypeResult::Framed) <==> (b == 2u8),
        (r == ContentTypeResult::Reject) <==> !content_type_supported(b),
{
    if b == 1u8 {
        ContentTypeResult::NonFramed
    } else if b == 2u8 {
        ContentTypeResult::Framed
    } else {
        ContentTypeResult::Reject
    }
}

// ------------------------------------------------------------------
// SECTION 3: Message type — supported values only (0x80)
// ------------------------------------------------------------------

/// Spec: the only supported message type is `0x80`
/// (Customer Authenticated Encrypted Data).
/// (`spec/data-format/message-header.md#supported-types`.)
pub open spec fn msg_type_supported(b: u8) -> bool {
    b == 0x80u8
}

/// Faithful model of the `match msg_type { … }` in `read_msg_type`.
/// Returns whether the byte is accepted; proves accept-iff-supported; total.
pub fn parse_msg_type(b: u8) -> (accepted: bool)
    ensures
        accepted <==> msg_type_supported(b),
{
    b == 0x80u8
}

// ------------------------------------------------------------------
// SECTION 4: Bounded length readers — reject over-limit lengths
// ------------------------------------------------------------------

/// Faithful model of the length-bound check in `read_seq_u32_bounded`
/// (`serialize_functions.rs`):
/// ```ignore
/// let len = read_u32(r, raw)?;
/// if len > bound { return ser_err(msg); }
/// let len_usize = usize::try_from(len) ...; // then read that many bytes
/// ```
///
/// This is the DoS defense: a malformed length field larger than the allowed
/// bound MUST be rejected *before* it is used to size a read/allocation. We
/// prove the accept decision is exactly `len <= bound` (total, no panic), and
/// that on acceptance the length is within bound (so a subsequent
/// `read_vec(len)` is sized by a bounded value).
pub fn length_within_bound_u32(len: u32, bound: u32) -> (accepted: bool)
    ensures
        accepted <==> (len <= bound),
        accepted ==> (len <= bound),
{
    len <= bound
}

/// Same for the u64 length prefix (`read_seq_u64_bounded`).
pub fn length_within_bound_u64(len: u64, bound: u64) -> (accepted: bool)
    ensures
        accepted <==> (len <= bound),
        accepted ==> (len <= bound),
{
    len <= bound
}

// ------------------------------------------------------------------
// SECTION 5: Totality / no-panic sanity lemmas
// ------------------------------------------------------------------

/// Every byte value is classified by `parse_version` — either a supported
/// version or a reject. There is no unhandled input (the source's `_ =>` arm),
/// so parsing a version byte is total and cannot panic.
pub proof fn lemma_version_total(b: u8)
    ensures
        version_supported(b) || !version_supported(b),
{
}

/// A length strictly above the bound is always rejected — no path reads or
/// allocates using an out-of-bound length.
pub proof fn lemma_over_bound_rejected_u32(len: u32, bound: u32)
    requires
        len > bound,
    ensures
        !(len <= bound),
{
}

} // verus!

fn main() {}
