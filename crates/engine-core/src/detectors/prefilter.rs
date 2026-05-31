/*!
O(n) pre-filter: eliminates obviously clean text before running the full cascade.

Tuned for high recall (near-zero false negatives): when uncertain, return true.
*/

use once_cell::sync::Lazy;
use regex::Regex;

static DIGIT_RUN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d{4,}").unwrap());
static UPPERCASE_SEQ: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Z]{2,}").unwrap());
static CAPITALIZED: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Z][a-z]{1,}").unwrap());

/// Returns `true` if the text is worth running the full detection cascade on.
pub fn should_scan(text: &str) -> bool {
    if text.len() < 4 {
        return false;
    }

    // '@' → possible email
    if text.contains('@') {
        return true;
    }

    // "://" → possible connection string
    if text.contains("://") {
        return true;
    }

    // Secret key prefixes
    for prefix in &[
        "AKIA",
        "ABIA",
        "ACCA",
        "ASIA",
        "ghp_",
        "ghs_",
        "ghr_",
        "sk-",
        "-----BEGIN",
    ] {
        if text.contains(prefix) {
            return true;
        }
    }

    // Digit runs → possible SSN, card, phone, routing, etc.
    if DIGIT_RUN.is_match(text) {
        return true;
    }

    // Uppercase acronyms (SSN, DOB, NPI, NPI…)
    if UPPERCASE_SEQ.is_match(text) {
        return true;
    }

    // Capitalized words → possible proper names
    if CAPITALIZED.is_match(text) {
        return true;
    }

    false
}
