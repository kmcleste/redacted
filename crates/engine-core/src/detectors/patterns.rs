/*!
Compiled regex patterns for the deterministic lane.

The `regex` crate uses a hybrid NFA/DFA engine with O(n) matching guarantee —
the Rust equivalent of RE2/Hyperscan for the purposes of ReDoS safety (D4).
Patterns are compiled once at startup via `once_cell::sync::Lazy`.

Rust's `regex` crate does NOT support lookahead/lookbehind. Instead, boundary
checks are performed in Rust code after a match (see `pii.rs`).
*/

use once_cell::sync::Lazy;
use regex::Regex;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Checks that the byte before `start` and after `end` is not an ASCII digit.
pub fn digit_isolated(text: &str, start: usize, end: usize) -> bool {
    let before = text.as_bytes().get(start.wrapping_sub(1)).copied();
    let after = text.as_bytes().get(end).copied();
    !matches!(before, Some(b) if b.is_ascii_digit())
        && !matches!(after, Some(b) if b.is_ascii_digit())
}

/// Checks that the byte before `start` is not an alphanumeric or `_`.
pub fn word_boundary_start(text: &str, start: usize) -> bool {
    text.as_bytes()
        .get(start.wrapping_sub(1))
        .is_none_or(|&b| !b.is_ascii_alphanumeric() && b != b'_')
}

/// Checks that the byte after `end` is not alphanumeric or `_`.
pub fn word_boundary_end(text: &str, end: usize) -> bool {
    text.as_bytes()
        .get(end)
        .is_none_or(|&b| !b.is_ascii_alphanumeric() && b != b'_')
}

pub fn word_boundary(text: &str, start: usize, end: usize) -> bool {
    word_boundary_start(text, start) && word_boundary_end(text, end)
}

/// Extract a context window `±window` bytes around `byte_pos` as a `&str`.
pub fn context_window(text: &str, byte_pos: usize, window: usize) -> &str {
    let lo_raw = byte_pos.saturating_sub(window);
    let hi_raw = (byte_pos + window).min(text.len());
    // Advance lo_raw forward to the nearest char boundary.
    let lo = (lo_raw..=byte_pos)
        .find(|&p| text.is_char_boundary(p))
        .unwrap_or(lo_raw);
    // Retreat hi_raw backward to the nearest char boundary.
    let hi = (byte_pos..=hi_raw)
        .rev()
        .find(|&p| text.is_char_boundary(p))
        .unwrap_or(hi_raw);
    &text[lo..hi]
}

// ---------------------------------------------------------------------------
// SSN
// ---------------------------------------------------------------------------

/// Formatted SSN: 123-45-6789 or 123 45 6789.
pub static SSN_FORMATTED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d{3}[-\s]\d{2}[-\s]\d{4}").unwrap());

/// Bare 9-digit run (requires context keyword in surrounding text).
pub static SSN_BARE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d{9}").unwrap());

/// Context keywords that promote a bare 9-digit run to an SSN candidate.
pub static SSN_CONTEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)social[\s\-]?security|ssn|s\.s\.n\.?|taxpayer|tin\b|itin\b|ein\b").unwrap()
});

// ---------------------------------------------------------------------------
// Credit cards
// ---------------------------------------------------------------------------

/// Visa: 13 or 16 digits starting with 4, optional formatting.
pub static CC_VISA: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|4\d{12}").unwrap());

/// Mastercard: 5[1-5] or 2[2-7] prefix.
pub static CC_MASTERCARD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:5[1-5]\d{2}|2[2-7]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}").unwrap()
});

/// Amex: 3[47], 15 digits.
pub static CC_AMEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}").unwrap());

/// Discover: 6011, 622x, 64x, 65 prefixes.
pub static CC_DISCOVER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"6(?:011|22[1-9]|[45]\d)\d[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}").unwrap()
});

// ---------------------------------------------------------------------------
// Banking
// ---------------------------------------------------------------------------

/// 9-digit sequences (ABA routing — always requires context keyword).
pub static NINE_DIGITS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d{9}").unwrap());

pub static BANK_ROUTING_CONTEXT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:routing|aba|transit|rtn|bank[\s\-]?routing)\b").unwrap());

/// 8–17 digit sequences (bank account — always requires context keyword).
pub static EIGHT_TO_17_DIGITS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d{8,17}").unwrap());

pub static BANK_ACCOUNT_CONTEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:account[\s\-]?(?:number|num|no|#)|acct[\s\-]?(?:number|num|no|#)?)\b")
        .unwrap()
});

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

/// Local-part bounded to 64 chars; domain bounded to 253 chars.
pub static EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}").unwrap()
});

// ---------------------------------------------------------------------------
// Phone
// ---------------------------------------------------------------------------

/// US phone numbers with various formatting styles.
pub static PHONE_US: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\+1[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]\d{3}[\s.\-]\d{4}").unwrap()
});

/// International E.164: +XX... (non-US, must start with non-1 country code).
pub static PHONE_INTL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\+[2-9]\d{0,2}[\s.\-]?\d{4,14}").unwrap());

// ---------------------------------------------------------------------------
// IP addresses
// ---------------------------------------------------------------------------

/// IPv4 — broad match; validated with `std::net::Ipv4Addr` in code.
pub static IPV4: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap());

/// IPv6 — full form only for now; compressed forms handled by validator.
pub static IPV6: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}").unwrap());

// ---------------------------------------------------------------------------
// VIN
// ---------------------------------------------------------------------------

/// 17 uppercase alphanumeric characters, no I/O/Q.
pub static VIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-HJ-NPR-Z0-9]{17}").unwrap());

// ---------------------------------------------------------------------------
// NPI (10 digits — Luhn-validated in code)
// ---------------------------------------------------------------------------

pub static TEN_DIGITS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d{10}").unwrap());
pub static NPI_CONTEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:npi|national[\s\-]?provider|provider[\s\-]?identifier)\b").unwrap()
});

// ---------------------------------------------------------------------------
// Domain / insurance identifiers (all require context keywords)
// ---------------------------------------------------------------------------

pub static POLICY_NUMBER: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Z]{2,4}-?\d{6,12}").unwrap());
pub static POLICY_CONTEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:policy[\s\-]?(?:number|num|no|#)|policy[\s\-]?id)\b").unwrap()
});

pub static CLAIM_ID: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Z]{2,3}-?\d{7,12}").unwrap());
pub static CLAIM_CONTEXT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:claim[\s\-]?(?:number|num|no|#|id))\b").unwrap());

pub static MEMBER_ID: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Z]{1,3}\d{6,12}").unwrap());
pub static MEMBER_CONTEXT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:member[\s\-]?(?:id|number|no|#))\b").unwrap());

// ---------------------------------------------------------------------------
// Date of birth (PHI)
// ---------------------------------------------------------------------------

pub static DOB: Lazy<Regex> = Lazy::new(|| {
    // MM/DD/YYYY or YYYY-MM-DD
    Regex::new(
        r"(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}|\
          (?:19|20)\d{2}[/\-](?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])",
    )
    .unwrap()
});
pub static DOB_CONTEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:dob|date[\s\-]?of[\s\-]?birth|born|birth[\s\-]?date)\b").unwrap()
});
