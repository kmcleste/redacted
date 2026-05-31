/*!
O(n) pre-filter with Aho-Corasick keyword routing.

A single AC automaton scans the input for literal keywords and maps each
match to a `DetectorHints` bitmask. Separate fast ASCII passes detect digit
runs, uppercase acronyms, and capitalized words.

The ensemble uses the bitmask to skip detector classes with no relevant
signals, cutting CPU on text that is either clean or has only one PII
category.
*/

use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;

// ---------------------------------------------------------------------------
// Hint bits
// ---------------------------------------------------------------------------

pub const HINT_STRUCTURED_PII: u32 = 1 << 0; // SSN, CC, phone, routing, account
pub const HINT_EMAIL: u32 = 1 << 1; // email address
pub const HINT_CONNECTION: u32 = 1 << 2; // connection strings / URLs
pub const HINT_SECRET: u32 = 1 << 3; // API keys, tokens, PEM blocks
pub const HINT_NER: u32 = 1 << 4; // Person, Org, Address stubs
pub const HINT_DOMAIN: u32 = 1 << 5; // NPI, policy/claim/member IDs

// ---------------------------------------------------------------------------
// DetectorHints
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
pub struct DetectorHints(pub u32);

impl DetectorHints {
    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self(u32::MAX);

    pub fn any(self) -> bool {
        self.0 != 0
    }

    pub fn has(self, bits: u32) -> bool {
        self.0 & bits != 0
    }
}

// ---------------------------------------------------------------------------
// Keyword → hint mapping
// ---------------------------------------------------------------------------

static KEYWORD_HINTS: &[(&str, u32)] = &[
    ("@", HINT_EMAIL),
    ("://", HINT_CONNECTION | HINT_SECRET),
    ("AKIA", HINT_SECRET),
    ("ABIA", HINT_SECRET),
    ("ACCA", HINT_SECRET),
    ("ASIA", HINT_SECRET),
    ("ghp_", HINT_SECRET),
    ("ghs_", HINT_SECRET),
    ("ghr_", HINT_SECRET),
    ("sk-", HINT_SECRET),
    ("-----BEGIN", HINT_SECRET),
];

static AC: Lazy<(AhoCorasick, Vec<u32>)> = Lazy::new(|| {
    let (pats, hints): (Vec<&str>, Vec<u32>) = KEYWORD_HINTS.iter().copied().unzip();
    let ac = AhoCorasick::new(pats).expect("AhoCorasick build failed");
    (ac, hints)
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan `text` and return a hint bitmask identifying which detector classes
/// have relevant signals. An empty bitmask means "definitely no PII" — skip
/// the full cascade.
pub fn scan_hints(text: &str) -> DetectorHints {
    if text.len() < 4 {
        return DetectorHints::NONE;
    }

    let (ac, hints) = &*AC;
    let mut mask = 0u32;

    // AC keyword pass — O(n) over all literal patterns at once.
    for m in ac.find_iter(text) {
        mask |= hints[m.pattern().as_usize()];
        if mask == u32::MAX {
            return DetectorHints(mask); // early-exit: all hints active
        }
    }

    // Digit run (≥4 consecutive digits) → structured PII / domain IDs.
    if has_digit_run(text) {
        mask |= HINT_STRUCTURED_PII | HINT_DOMAIN;
    }

    // Two+ consecutive uppercase → acronyms (NPI, SSN, claim IDs, AWS key body).
    if has_uppercase_seq(text) {
        mask |= HINT_STRUCTURED_PII | HINT_DOMAIN | HINT_SECRET | HINT_NER;
    }

    // Capitalized word (Uc + lc) → potential named entity.
    if has_capitalized(text) {
        mask |= HINT_NER;
    }

    DetectorHints(mask)
}

/// Returns `true` if the text is worth running the full detection cascade on.
/// Kept as a compatibility shim; prefer `scan_hints` for new call-sites.
#[inline]
pub fn should_scan(text: &str) -> bool {
    scan_hints(text).any()
}

// ---------------------------------------------------------------------------
// Fast ASCII scans (no regex heap allocation)
// ---------------------------------------------------------------------------

fn has_digit_run(text: &str) -> bool {
    let mut run = 0u8;
    for b in text.bytes() {
        if b.is_ascii_digit() {
            run += 1;
            if run >= 4 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn has_uppercase_seq(text: &str) -> bool {
    let mut run = 0u8;
    for b in text.bytes() {
        if b.is_ascii_uppercase() {
            run += 1;
            if run >= 2 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn has_capitalized(text: &str) -> bool {
    let bytes = text.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i].is_ascii_uppercase() && bytes[i + 1].is_ascii_lowercase() {
            return true;
        }
    }
    false
}
