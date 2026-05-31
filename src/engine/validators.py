"""
Validators and denylist filters applied after regex matching.

These are free precision: they reduce false positives without changing recall.
All validators are O(n) or O(1) — no backtracking, no external calls.
"""

from __future__ import annotations

import ipaddress
import re

# ---------------------------------------------------------------------------
# SSN
# ---------------------------------------------------------------------------

# SSN area numbers that are permanently invalid.
_SSN_INVALID_AREAS: frozenset[int] = frozenset(
    {
        0,    # 000
        666,  # explicitly excluded by SSA
        *range(900, 1000),  # 900-999 reserved
    }
)

# Well-known invalid SSNs distributed as examples.
_SSN_KNOWN_INVALID: frozenset[str] = frozenset(
    {
        "078-05-1120",  # Woolworth's wallet insert
        "219-09-9999",
        "123-45-6789",
        "111-11-1111",
        "222-22-2222",
        "333-33-3333",
        "444-44-4444",
        "555-55-5555",
        "666-66-6666",
        "777-77-7777",
        "888-88-8888",
        "999-99-9999",
    }
)


def validate_ssn(value: str) -> bool:
    """Return True if value is a structurally plausible SSN."""
    digits = re.sub(r"[\s\-]", "", value)
    if len(digits) != 9 or not digits.isdigit():
        return False

    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])

    if area in _SSN_INVALID_AREAS:
        return False
    if group == 0 or serial == 0:
        return False

    normalized = f"{digits[:3]}-{digits[3:5]}-{digits[5:]}"
    if normalized in _SSN_KNOWN_INVALID:
        return False

    return True


# ---------------------------------------------------------------------------
# Credit card — Luhn algorithm + test-card denylist
# ---------------------------------------------------------------------------

# Common test/documentation card numbers that pass Luhn.
_TEST_CARD_NUMBERS: frozenset[str] = frozenset(
    {
        "4111111111111111",   # Visa test
        "4012888888881881",   # Visa test
        "4222222222222",      # Visa test (13-digit)
        "5500005555555559",   # MC test
        "5105105105105100",   # MC test
        "2223000048400011",   # MC test (2-series)
        "378282246310005",    # Amex test
        "371449635398431",    # Amex test
        "6011111111111117",   # Discover test
        "6011000990139424",   # Discover test
        "3530111333300000",   # JCB test
        "3566002020360505",   # JCB test
    }
)


def _luhn_checksum(digits: str) -> bool:
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def validate_credit_card(value: str) -> bool:
    """Return True if value passes Luhn and is not a known test card."""
    digits = re.sub(r"[\s\-]", "", value)
    if not digits.isdigit():
        return False
    if len(digits) not in (13, 14, 15, 16, 17, 18, 19):
        return False
    if digits in _TEST_CARD_NUMBERS:
        return False
    return _luhn_checksum(digits)


# ---------------------------------------------------------------------------
# ABA Routing number check digit
# ---------------------------------------------------------------------------

def validate_aba_routing(value: str) -> bool:
    """Validate ABA routing number via weighted modulo-10 check."""
    digits = re.sub(r"[\s\-]", "", value)
    if len(digits) != 9 or not digits.isdigit():
        return False
    # All-zeros and repetitive sequences are invalid.
    if len(set(digits)) == 1:
        return False
    d = [int(c) for c in digits]
    checksum = (
        3 * (d[0] + d[3] + d[6])
        + 7 * (d[1] + d[4] + d[7])
        + (d[2] + d[5] + d[8])
    )
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# NPI — National Provider Identifier (Luhn with "80840" prefix)
# ---------------------------------------------------------------------------

def validate_npi(value: str) -> bool:
    """Validate a 10-digit NPI using the HIPAA NPI check-digit algorithm."""
    digits = re.sub(r"\s", "", value)
    if len(digits) != 10 or not digits.isdigit():
        return False
    prefixed = "80840" + digits
    return _luhn_checksum(prefixed)


# ---------------------------------------------------------------------------
# IP address — reserved-range denylist
# ---------------------------------------------------------------------------

_RESERVED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),     # IPv6 documentation
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
]


def validate_ip_address(value: str) -> bool:
    """Return True if value is a real (non-reserved, non-documentation) IP."""
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False

    for net in _RESERVED_NETWORKS:
        if addr in net:
            return False

    return True


# ---------------------------------------------------------------------------
# Email — documentation domain denylist
# ---------------------------------------------------------------------------

_DOCUMENTATION_DOMAINS: frozenset[str] = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "test.org",
        "invalid",
        "localhost",
    }
)


def validate_email(value: str) -> bool:
    """Return True if the email domain is not a documentation placeholder."""
    if "@" not in value:
        return False
    domain = value.rsplit("@", 1)[-1].lower()
    return domain not in _DOCUMENTATION_DOMAINS


# ---------------------------------------------------------------------------
# Phone — 555-01xx US fiction/test range
# ---------------------------------------------------------------------------

_PHONE_FICTION_RE = re.compile(r"(?:555[\-\s]?01\d\d|555[\-\s]?0100)")


def validate_phone(value: str) -> bool:
    """Return False for US TV/movie 555-01xx numbers."""
    return not bool(_PHONE_FICTION_RE.search(value))


# ---------------------------------------------------------------------------
# VIN — ISO 3779 check digit
# ---------------------------------------------------------------------------

_VIN_TRANSLITERATION: dict[str, int] = {
    **{str(i): i for i in range(10)},
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5,        "P": 7, "R": 9,
             "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def validate_vin(value: str) -> bool:
    """Validate a 17-character VIN via ISO 3779 check digit."""
    v = value.upper().strip()
    if len(v) != 17:
        return False
    if re.search(r"[IOQ]", v):
        return False

    total = 0
    for i, ch in enumerate(v):
        if ch not in _VIN_TRANSLITERATION:
            return False
        total += _VIN_TRANSLITERATION[ch] * _VIN_WEIGHTS[i]

    remainder = total % 11
    check_char = "X" if remainder == 10 else str(remainder)
    return v[8] == check_char
