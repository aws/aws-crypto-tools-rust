// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standard encryption contexts emitted into generated vectors.
//!
//! Ports the Dafny reference's `EncryptionContextUtils.dfy`. Every string below
//! is written with explicit `\u{...}` escapes and carries the reference's UTF-8
//! byte sequence in a comment, so the values cannot drift with source encoding.
//!
//! Between them these cover the constraints in
//! `spec/framework/test-vectors/complete-vectors/encryption-context.md`: an
//! empty map, small maps (1 to 10 entries), multibyte UTF-8 characters in both
//! key and value, and multibyte non-BMP characters in both key and value.

use indexmap::IndexMap;

/// `"normal"` followed by U+D000. Reference bytes:
/// `6e 6f 72 6d 61 6c ed 80 80`.
const NORMAL: &str = "normal\u{D000}";

/// U+10002, a non-BMP character. Reference bytes: `f0 90 80 82`.
const PSI: &str = "\u{10002}";

/// U+FFFD REPLACEMENT CHARACTER. Reference bytes: `ef bf bd`.
const REPLACEMENT_CHAR: &str = "\u{FFFD}";

/// One-byte UTF-8. Reference bytes: `31`.
const ASCII_1: &str = "1";
/// Two-byte UTF-8, U+00A0. Reference bytes: `c2 a0`.
const ASCII_2: &str = "\u{A0}";
/// One-byte UTF-8. Reference bytes: `55`.
const ASCII_3: &str = "U";

/// Two-byte UTF-8, U+0100. Reference bytes: `c4 80`.
const UTF8_2_1: &str = "\u{100}";
/// Two-byte UTF-8, U+0518. Reference bytes: `d4 98`.
const UTF8_2_2: &str = "\u{518}";
/// Two-byte UTF-8, U+0508. Reference bytes: `d4 88`.
const UTF8_2_3: &str = "\u{508}";

/// Three-byte UTF-8, U+0800. Reference bytes: `e0 a0 80`.
const UTF8_3_1: &str = "\u{800}";
/// Three-byte UTF-8, U+0DF4. Reference bytes: `e0 b7 b4`.
const UTF8_3_2: &str = "\u{DF4}";
/// Three-byte UTF-8, U+2230. Reference bytes: `e2 88 b0`.
const UTF8_3_3: &str = "\u{2230}";

/// Four-byte UTF-8, U+12000. Reference bytes: `f0 92 80 80`.
const UTF8_4_1: &str = "\u{12000}";
/// Four-byte UTF-8, U+13023. Reference bytes: `f0 93 80 a3`.
const UTF8_4_2: &str = "\u{13023}";
/// Four-byte UTF-8, U+13269. Reference bytes: `f0 93 89 a9`.
const UTF8_4_3: &str = "\u{13269}";

/// A named standard encryption context. `label` is folded into generated vector
/// descriptions so a failing vector names the context it used.
#[derive(Debug, Clone, Copy)]
pub struct StandardEncryptionContext {
    /// Human-readable name for this context, used in vector descriptions.
    pub label: &'static str,
    /// Key/value pairs, as `(key, value)` string pairs.
    pub entries: &'static [(&'static str, &'static str)],
}

impl StandardEncryptionContext {
    /// Materialize this context as the manifest's string-to-string map.
    #[must_use]
    pub fn to_map(self) -> IndexMap<String, String> {
        self.entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }
}

/// Every standard encryption context generated vectors are emitted against,
/// matching the composition of the Dafny reference's `AllRawAES.Tests`.
pub const STANDARD_ENCRYPTION_CONTEXTS: &[StandardEncryptionContext] = &[
    StandardEncryptionContext {
        label: "No Encryption Context",
        entries: &[],
    },
    StandardEncryptionContext {
        label: "Control Encryption Context",
        entries: &[(NORMAL, NORMAL)],
    },
    StandardEncryptionContext {
        label: "Basic Encryption Context",
        entries: &[("a", "a")],
    },
    StandardEncryptionContext {
        label: "Encryption Context With Psi",
        entries: &[(NORMAL, NORMAL), (PSI, PSI)],
    },
    StandardEncryptionContext {
        label: "Encryption Context With Replacement Character",
        entries: &[(NORMAL, NORMAL), (REPLACEMENT_CHAR, REPLACEMENT_CHAR)],
    },
    StandardEncryptionContext {
        label: "Multiple ASCII Entries",
        entries: &[(ASCII_1, ASCII_1), (ASCII_2, ASCII_2), (ASCII_3, ASCII_3)],
    },
    StandardEncryptionContext {
        label: "Multiple 2-Byte UTF8 Entries",
        entries: &[
            (UTF8_2_1, UTF8_2_1),
            (UTF8_2_2, UTF8_2_2),
            (UTF8_2_3, UTF8_2_3),
        ],
    },
    StandardEncryptionContext {
        label: "Multiple 3-Byte UTF8 Entries",
        entries: &[
            (UTF8_3_1, UTF8_3_1),
            (UTF8_3_2, UTF8_3_2),
            (UTF8_3_3, UTF8_3_3),
        ],
    },
    StandardEncryptionContext {
        label: "Multiple 4-Byte UTF8 Entries",
        entries: &[
            (UTF8_4_1, UTF8_4_1),
            (UTF8_4_2, UTF8_4_2),
            (UTF8_4_3, UTF8_4_3),
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_contexts_cover_the_spec_constraints() {
        // spec/framework/test-vectors/complete-vectors/encryption-context.md
        // requires an empty map, a small map (1..=10 entries), multibyte UTF-8
        // in key and value, and multibyte non-BMP in key and value.
        assert!(
            STANDARD_ENCRYPTION_CONTEXTS
                .iter()
                .any(|ec| ec.entries.is_empty()),
            "an empty map must be covered"
        );
        assert!(
            STANDARD_ENCRYPTION_CONTEXTS
                .iter()
                .any(|ec| (1..=10).contains(&ec.entries.len())),
            "a small map must be covered"
        );
        assert!(
            STANDARD_ENCRYPTION_CONTEXTS.iter().any(|ec| ec
                .entries
                .iter()
                .any(|(k, v)| k.chars().any(|c| c.len_utf8() > 1)
                    && v.chars().any(|c| c.len_utf8() > 1))),
            "multibyte UTF-8 in both key and value must be covered"
        );
        assert!(
            STANDARD_ENCRYPTION_CONTEXTS.iter().any(|ec| ec
                .entries
                .iter()
                .any(|(k, v)| k.chars().any(|c| u32::from(c) > 0xFFFF)
                    && v.chars().any(|c| u32::from(c) > 0xFFFF))),
            "non-BMP characters in both key and value must be covered"
        );
    }

    #[test]
    fn reference_byte_sequences_match_the_dafny_constants() {
        // Guards the \u{...} escapes above against transcription errors.
        assert_eq!(
            NORMAL.as_bytes(),
            [0x6e, 0x6f, 0x72, 0x6d, 0x61, 0x6c, 0xed, 0x80, 0x80]
        );
        assert_eq!(PSI.as_bytes(), [0xf0, 0x90, 0x80, 0x82]);
        assert_eq!(REPLACEMENT_CHAR.as_bytes(), [0xEF, 0xBF, 0xBD]);
        assert_eq!(ASCII_1.as_bytes(), [0x31]);
        assert_eq!(ASCII_2.as_bytes(), [0xc2, 0xa0]);
        assert_eq!(ASCII_3.as_bytes(), [0x55]);
        assert_eq!(UTF8_2_1.as_bytes(), [0xc4, 0x80]);
        assert_eq!(UTF8_2_2.as_bytes(), [0xd4, 0x98]);
        assert_eq!(UTF8_2_3.as_bytes(), [0xd4, 0x88]);
        assert_eq!(UTF8_3_1.as_bytes(), [0xe0, 0xa0, 0x80]);
        assert_eq!(UTF8_3_2.as_bytes(), [0xe0, 0xb7, 0xb4]);
        assert_eq!(UTF8_3_3.as_bytes(), [0xe2, 0x88, 0xb0]);
        assert_eq!(UTF8_4_1.as_bytes(), [0xf0, 0x92, 0x80, 0x80]);
        assert_eq!(UTF8_4_2.as_bytes(), [0xf0, 0x93, 0x80, 0xa3]);
        assert_eq!(UTF8_4_3.as_bytes(), [0xf0, 0x93, 0x89, 0xa9]);
    }

    #[test]
    fn every_label_is_unique() {
        let mut labels: Vec<&str> = STANDARD_ENCRYPTION_CONTEXTS
            .iter()
            .map(|ec| ec.label)
            .collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total, "vector descriptions must be unique");
    }

    #[test]
    fn to_map_round_trips_entries() {
        let ec = StandardEncryptionContext {
            label: "test",
            entries: &[("k", "v")],
        };
        let map = ec.to_map();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("k").map(String::as_str), Some("v"));
    }
}
