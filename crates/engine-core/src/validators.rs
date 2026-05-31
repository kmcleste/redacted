/*!
Validators applied after regex matching to eliminate false positives.

All validators are O(n) or O(1) with no external I/O.
*/

use std::net::IpAddr;

use ipnet::IpNet;
use once_cell::sync::Lazy;

// ---------------------------------------------------------------------------
// SSN
// ---------------------------------------------------------------------------

const SSN_INVALID_AREAS: &[u16] = &[
    0,   // 000
    666, // explicitly excluded
];

const SSN_KNOWN_INVALID: &[&str] = &[
    "078-05-1120", // Woolworth's wallet insert
    "219-09-9999",
    "123-45-6789",
    "111-11-1111",
    "222-22-2222",
    "333-33-3333",
    "444-44-4444",
    "555-55-5555",
    "777-77-7777",
    "888-88-8888",
    "999-99-9999",
];

/// Strips dashes and spaces then validates SSN structure.
pub fn validate_ssn(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }

    let area: u16 = digits[..3].parse().unwrap_or(0);
    let group: u16 = digits[3..5].parse().unwrap_or(0);
    let serial: u16 = digits[5..].parse().unwrap_or(0);

    if SSN_INVALID_AREAS.contains(&area) || (900..=999).contains(&area) {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }

    let normalized = format!("{:03}-{:02}-{:04}", area, group, serial);
    if SSN_KNOWN_INVALID.contains(&normalized.as_str()) {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Credit card — Luhn algorithm + test-card denylist
// ---------------------------------------------------------------------------

const TEST_CARDS: &[&str] = &[
    "4111111111111111",
    "4012888888881881",
    "4222222222222",
    "5500005555555559",
    "5105105105105100",
    "2223000048400011",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
    "3530111333300000",
    "3566002020360505",
];

fn luhn_checksum(digits: &str) -> bool {
    let mut total: u32 = 0;
    for (i, ch) in digits.chars().rev().enumerate() {
        let mut n = ch as u32 - b'0' as u32;
        if i % 2 == 1 {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        total += n;
    }
    total.is_multiple_of(10)
}

pub fn validate_credit_card(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    if TEST_CARDS.contains(&digits.as_str()) {
        return false;
    }
    luhn_checksum(&digits)
}

// ---------------------------------------------------------------------------
// ABA routing number check digit
// ---------------------------------------------------------------------------

pub fn validate_aba_routing(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    // Reject all-same-digit sequences (structurally invalid).
    if digits
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len()
        == 1
    {
        return false;
    }
    let d: Vec<u32> = digits.chars().map(|c| c as u32 - b'0' as u32).collect();
    let checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
    checksum.is_multiple_of(10)
}

// ---------------------------------------------------------------------------
// NPI — National Provider Identifier (Luhn with "80840" prefix)
// ---------------------------------------------------------------------------

pub fn validate_npi(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 10 {
        return false;
    }
    let prefixed = format!("80840{digits}");
    luhn_checksum(&prefixed)
}

// ---------------------------------------------------------------------------
// IP address — reserved-range denylist
// ---------------------------------------------------------------------------

static RESERVED_NETS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    [
        "192.0.2.0/24",    // TEST-NET-1
        "198.51.100.0/24", // TEST-NET-2
        "203.0.113.0/24",  // TEST-NET-3
        "127.0.0.0/8",     // Loopback
        "0.0.0.0/8",       // "This" network
        "240.0.0.0/4",     // Reserved
        "255.255.255.255/32",
        "2001:db8::/32", // IPv6 documentation
        "::1/128",       // IPv6 loopback
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
});

pub fn validate_ip_address(value: &str) -> bool {
    let addr: IpAddr = match value.trim().parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    !RESERVED_NETS.iter().any(|net| net.contains(&addr))
}

// ---------------------------------------------------------------------------
// Email — documentation domain denylist
// ---------------------------------------------------------------------------

const DOC_DOMAINS: &[&str] = &[
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.org",
    "invalid",
    "localhost",
];

pub fn validate_email(value: &str) -> bool {
    let Some(at) = value.rfind('@') else {
        return false;
    };
    let domain = value[at + 1..].to_lowercase();
    !DOC_DOMAINS.contains(&domain.as_str())
}

// ---------------------------------------------------------------------------
// Phone — 555-01xx US fiction/test range
// ---------------------------------------------------------------------------

pub fn validate_phone(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    let local = if digits.len() == 11 && digits.starts_with('1') {
        &digits[1..]
    } else {
        &digits
    };
    // US fiction range 555-01xx in both 10-digit (with area) and 7-digit (without) forms.
    let (exchange, subscriber) = match local.len() {
        10 => (&local[3..6], &local[6..10]),
        7 => (&local[0..3], &local[3..7]),
        _ => return true,
    };
    if exchange == "555" && subscriber.starts_with("01") {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// VIN — ISO 3779 check digit
// ---------------------------------------------------------------------------

fn vin_transliterate(c: char) -> Option<u32> {
    match c {
        '0'..='9' => Some(c as u32 - b'0' as u32),
        'A' => Some(1),
        'B' => Some(2),
        'C' => Some(3),
        'D' => Some(4),
        'E' => Some(5),
        'F' => Some(6),
        'G' => Some(7),
        'H' => Some(8),
        'J' => Some(1),
        'K' => Some(2),
        'L' => Some(3),
        'M' => Some(4),
        'N' => Some(5),
        'P' => Some(7),
        'R' => Some(9),
        'S' => Some(2),
        'T' => Some(3),
        'U' => Some(4),
        'V' => Some(5),
        'W' => Some(6),
        'X' => Some(7),
        'Y' => Some(8),
        'Z' => Some(9),
        _ => None,
    }
}

const VIN_WEIGHTS: &[u32] = &[8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];

pub fn validate_vin(value: &str) -> bool {
    let v: String = value.to_uppercase();
    let v = v.trim();
    if v.len() != 17 {
        return false;
    }
    if v.chars().any(|c| matches!(c, 'I' | 'O' | 'Q')) {
        return false;
    }

    let total: u32 = v
        .chars()
        .zip(VIN_WEIGHTS.iter())
        .map(|(c, &w)| vin_transliterate(c).unwrap_or(0) * w)
        .sum();

    let remainder = total % 11;
    let check = if remainder == 10 {
        'X'
    } else {
        char::from_digit(remainder, 10).unwrap()
    };
    v.chars().nth(8) == Some(check)
}
