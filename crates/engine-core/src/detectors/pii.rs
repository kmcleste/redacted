use crate::{
    entities::{DetectedSpan, EntityType},
    validators::{
        validate_aba_routing, validate_credit_card, validate_email, validate_ip_address,
        validate_npi, validate_phone, validate_ssn, validate_vin,
    },
};

use super::{
    patterns::{self as P, context_window, digit_isolated, word_boundary, word_boundary_start},
    Detector,
};

const CONTEXT_WINDOW: usize = 150;

// ---------------------------------------------------------------------------
// SSN
// ---------------------------------------------------------------------------

pub struct SsnDetector;

impl Detector for SsnDetector {
    fn name(&self) -> &'static str { "SsnDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();
        let mut seen: std::collections::HashSet<(usize, usize)> = Default::default();

        // Formatted SSN (higher score — explicit delimiter).
        for m in P::SSN_FORMATTED.find_iter(text) {
            if validate_ssn(m.as_str()) {
                let key = (m.start(), m.end());
                if seen.insert(key) {
                    spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::Ssn, m.as_str(), 0.95));
                }
            }
        }

        // Bare 9-digit run — only when digit-isolated AND context keyword present.
        for m in P::SSN_BARE.find_iter(text) {
            let key = (m.start(), m.end());
            if seen.contains(&key) { continue; }
            if !digit_isolated(text, m.start(), m.end()) { continue; }
            if !validate_ssn(m.as_str()) { continue; }
            let ctx = context_window(text, m.start(), CONTEXT_WINDOW);
            if P::SSN_CONTEXT.is_match(ctx) {
                seen.insert(key);
                spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::Ssn, m.as_str(), 0.85));
            }
        }

        spans.sort_by_key(|s| s.start);
        spans
    }
}

// ---------------------------------------------------------------------------
// Credit card
// ---------------------------------------------------------------------------

pub struct CreditCardDetector;

impl Detector for CreditCardDetector {
    fn name(&self) -> &'static str { "CreditCardDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();
        let mut seen: std::collections::HashSet<(usize, usize)> = Default::default();

        let patterns: &[&once_cell::sync::Lazy<regex::Regex>] =
            &[&P::CC_VISA, &P::CC_MASTERCARD, &P::CC_AMEX, &P::CC_DISCOVER];

        for pat in patterns {
            for m in pat.find_iter(text) {
                let key = (m.start(), m.end());
                if seen.contains(&key) { continue; }
                if validate_credit_card(m.as_str()) {
                    seen.insert(key);
                    spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::CreditCard, m.as_str(), 0.90));
                }
            }
        }

        spans.sort_by_key(|s| s.start);
        spans
    }
}

// ---------------------------------------------------------------------------
// Bank routing
// ---------------------------------------------------------------------------

pub struct BankRoutingDetector;

impl Detector for BankRoutingDetector {
    fn name(&self) -> &'static str { "BankRoutingDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();
        for m in P::NINE_DIGITS.find_iter(text) {
            if !digit_isolated(text, m.start(), m.end()) { continue; }
            if !validate_aba_routing(m.as_str()) { continue; }
            let ctx = context_window(text, m.start(), CONTEXT_WINDOW);
            if P::BANK_ROUTING_CONTEXT.is_match(ctx) {
                spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::BankRouting, m.as_str(), 0.85));
            }
        }
        spans
    }
}

// ---------------------------------------------------------------------------
// Bank account
// ---------------------------------------------------------------------------

pub struct BankAccountDetector;

impl Detector for BankAccountDetector {
    fn name(&self) -> &'static str { "BankAccountDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();
        for m in P::EIGHT_TO_17_DIGITS.find_iter(text) {
            if !digit_isolated(text, m.start(), m.end()) { continue; }
            let ctx = context_window(text, m.start(), CONTEXT_WINDOW);
            if P::BANK_ACCOUNT_CONTEXT.is_match(ctx) {
                spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::BankAccount, m.as_str(), 0.75));
            }
        }
        spans
    }
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

pub struct EmailDetector;

impl Detector for EmailDetector {
    fn name(&self) -> &'static str { "EmailDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        P::EMAIL
            .find_iter(text)
            .filter(|m| validate_email(m.as_str()))
            .map(|m| DetectedSpan::new(m.start(), m.end(), EntityType::Email, m.as_str(), 0.95))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Phone
// ---------------------------------------------------------------------------

pub struct PhoneDetector;

impl Detector for PhoneDetector {
    fn name(&self) -> &'static str { "PhoneDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();
        let mut seen: std::collections::HashSet<(usize, usize)> = Default::default();

        for pat in &[&P::PHONE_US, &P::PHONE_INTL] {
            for m in pat.find_iter(text) {
                let key = (m.start(), m.end());
                if seen.contains(&key) { continue; }
                // The regex may eat a leading space/( — ensure the char before isn't alphanumeric.
                if !word_boundary_start(text, m.start()) {
                    // Allow the pattern to start with '(' (a paren is not a word char).
                    let first = text[m.start()..].chars().next();
                    if first != Some('(') && first != Some('+') {
                        continue;
                    }
                }
                if !validate_phone(m.as_str()) { continue; }
                seen.insert(key);
                spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::Phone, m.as_str(), 0.80));
            }
        }
        spans.sort_by_key(|s| s.start);
        spans
    }
}

// ---------------------------------------------------------------------------
// IP address
// ---------------------------------------------------------------------------

pub struct IpAddressDetector;

impl Detector for IpAddressDetector {
    fn name(&self) -> &'static str { "IpAddressDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();
        let mut seen: std::collections::HashSet<(usize, usize)> = Default::default();

        for pat in &[&P::IPV4, &P::IPV6] {
            for m in pat.find_iter(text) {
                let key = (m.start(), m.end());
                if seen.contains(&key) { continue; }
                if !word_boundary(text, m.start(), m.end()) { continue; }
                if validate_ip_address(m.as_str()) {
                    seen.insert(key);
                    spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::IpAddress, m.as_str(), 0.85));
                }
            }
        }
        spans.sort_by_key(|s| s.start);
        spans
    }
}

// ---------------------------------------------------------------------------
// VIN
// ---------------------------------------------------------------------------

pub struct VinDetector;

impl Detector for VinDetector {
    fn name(&self) -> &'static str { "VinDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        P::VIN
            .find_iter(text)
            .filter(|m| word_boundary(text, m.start(), m.end()) && validate_vin(m.as_str()))
            .map(|m| DetectedSpan::new(m.start(), m.end(), EntityType::Vin, m.as_str(), 0.90))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// NPI
// ---------------------------------------------------------------------------

pub struct NpiDetector;

impl Detector for NpiDetector {
    fn name(&self) -> &'static str { "NpiDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();
        for m in P::TEN_DIGITS.find_iter(text) {
            if !digit_isolated(text, m.start(), m.end()) { continue; }
            if !validate_npi(m.as_str()) { continue; }
            let ctx = context_window(text, m.start(), CONTEXT_WINDOW);
            if P::NPI_CONTEXT.is_match(ctx) {
                spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::Npi, m.as_str(), 0.85));
            }
        }
        spans
    }
}

// ---------------------------------------------------------------------------
// Domain identifiers (policy, claim, member)
// ---------------------------------------------------------------------------

pub struct DomainIdentifierDetector;

impl Detector for DomainIdentifierDetector {
    fn name(&self) -> &'static str { "DomainIdentifierDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();

        let matchers: &[(&once_cell::sync::Lazy<regex::Regex>, &once_cell::sync::Lazy<regex::Regex>, EntityType, f32)] = &[
            (&P::POLICY_NUMBER, &P::POLICY_CONTEXT, EntityType::PolicyNumber, 0.80),
            (&P::CLAIM_ID,      &P::CLAIM_CONTEXT,  EntityType::ClaimId,      0.80),
            (&P::MEMBER_ID,     &P::MEMBER_CONTEXT, EntityType::MemberId,     0.75),
        ];

        for (pat, ctx_pat, entity_type, score) in matchers {
            for m in pat.find_iter(text) {
                if !word_boundary(text, m.start(), m.end()) { continue; }
                let ctx = context_window(text, m.start(), CONTEXT_WINDOW);
                if ctx_pat.is_match(ctx) {
                    spans.push(DetectedSpan::new(m.start(), m.end(), *entity_type, m.as_str(), *score));
                }
            }
        }

        spans.sort_by_key(|s| s.start);
        spans
    }
}

// ---------------------------------------------------------------------------
// Date of birth (PHI)
// ---------------------------------------------------------------------------

pub struct DateOfBirthDetector;

impl Detector for DateOfBirthDetector {
    fn name(&self) -> &'static str { "DateOfBirthDetector" }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();
        for m in P::DOB.find_iter(text) {
            let ctx = context_window(text, m.start(), CONTEXT_WINDOW);
            if P::DOB_CONTEXT.is_match(ctx) {
                spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::DateOfBirth, m.as_str(), 0.85));
            }
        }
        spans
    }
}
