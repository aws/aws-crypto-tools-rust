// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Which mutant is on, for mutation testing.
//!
//! The mutation tool builds every mutant of a library into one throwaway copy.
//! Each mutated spot runs its changed code only when `is_on(<its id>)` is true,
//! so one build and one running server can test every mutant in turn.
//! Id 0 means no mutant.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::LazyLock;

// A crate's own tests run one process per mutant and name it in TESTSERVER_MUTANT.
// A test server starts with none on and gets each one from `set`.
// A malformed value turns no mutant on, so every mutant survives and the run fails.
static ON: LazyLock<AtomicU32> = LazyLock::new(|| {
    let from_env = std::env::var("TESTSERVER_MUTANT").ok();
    AtomicU32::new(from_env.and_then(|value| value.parse().ok()).unwrap_or(0))
});

/// Whether the mutant with this id is on.
#[inline]
pub fn is_on(id: u32) -> bool {
    ON.load(Ordering::Relaxed) == id
}

/// Turns on the mutant with this id, and every other mutant off. 0 turns them all off.
pub fn set(id: u32) {
    ON.store(id, Ordering::Relaxed);
}
