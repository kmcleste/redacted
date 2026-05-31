"""
Compiled regex patterns for the deterministic detection lane.

All patterns are designed to avoid catastrophic backtracking:
- No nested quantifiers: (a+)+
- No alternation with overlapping prefixes under an outer quantifier
- Prefer exact repetition counts {n} and {m,n} over unbounded +/*

Production MUST replace stdlib `re` with `google-re2` for hard WCET guarantees
and ReDoS immunity. The shim below makes the swap a one-line config change.
"""

from __future__ import annotations

import re
import warnings

try:
    import re2 as _re  # type: ignore[import]
except ImportError:
    _re = re  # type: ignore[assignment]
    warnings.warn(
        "google-re2 not installed; using stdlib re. "
        "Install 'google-re2' for production ReDoS safety and bounded WCET.",
        ImportWarning,
        stacklevel=1,
    )


def compile(pattern: str, flags: int = 0) -> re.Pattern[str]:  # noqa: A001
    return _re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# SSN
# ---------------------------------------------------------------------------

# Formatted SSN: 123-45-6789 or 123 45 6789
SSN_FORMATTED = compile(r"\b(\d{3})[\-\s](\d{2})[\-\s](\d{4})\b")

# Bare 9-digit run (only valid with surrounding context keywords — see detector)
SSN_BARE = compile(r"(?<!\d)(\d{9})(?!\d)")

# Context keywords that promote a bare 9-digit run to SSN
SSN_CONTEXT = compile(
    r"\b(?:social[\s\-]?security|ssn|s\.s\.n\.?|taxpayer|tin|itin|ein)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Credit cards
# ---------------------------------------------------------------------------

# Visa (13 or 16 digits starting with 4)
CC_VISA = compile(r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b|\b4\d{12}\b")

# Mastercard (5[1-5] or 2[2-7] prefix, 16 digits)
CC_MASTERCARD = compile(
    r"\b(?:5[1-5]\d{2}|2[2-7]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
)

# American Express (3[47], 15 digits)
CC_AMEX = compile(r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b")

# Discover (6011, 622[1-9], 64[4-9], 65 prefixes)
CC_DISCOVER = compile(
    r"\b6(?:011|22[1-9]|[45]\d)\d[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
)

# JCB (3528-3589, 16 digits)
CC_JCB = compile(r"\b35(?:2[89]|[3-8]\d)\d[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")

# ---------------------------------------------------------------------------
# Banking
# ---------------------------------------------------------------------------

# ABA routing number: exactly 9 digits, often preceded by routing/ABA context
BANK_ROUTING = compile(r"(?<!\d)(\d{9})(?!\d)")
BANK_ROUTING_CONTEXT = compile(
    r"\b(?:routing|aba|transit|rtn|bank[\s\-]?routing)\b",
    re.IGNORECASE,
)

# Bank account numbers: 8–17 digits in account context
BANK_ACCOUNT = compile(r"(?<!\d)(\d{8,17})(?!\d)")
BANK_ACCOUNT_CONTEXT = compile(
    r"\b(?:account[\s\-]?(?:number|num|no|#)|acct[\s\-]?(?:number|num|no|#)?)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

# Safe email pattern: local-part limited to 64 chars, domain to 253 chars.
# The local part uses a bounded character class — no nested quantifiers.
EMAIL = compile(
    r"\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}\b"
)

# ---------------------------------------------------------------------------
# Phone (North American + international)
# ---------------------------------------------------------------------------

# Handles: (555) 123-4567, 555-123-4567, +1 555 123 4567, 5551234567
# Use (?<!\w) instead of \b so ( at start is matched correctly.
PHONE_US = compile(
    r"(?<!\w)(?:\+1[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\w)"
)

# International E.164-style: +XX... (non-US country codes 1-3 digits)
PHONE_INTL = compile(r"\+(?!1)(?:[1-9]\d{0,2})[\s.\-]?\d{4,14}\b")

# ---------------------------------------------------------------------------
# IP addresses
# ---------------------------------------------------------------------------

# IPv4 — each octet validated with alternation (25[0-5]|2[0-4]\d|[01]?\d\d?)
IPV4 = compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# IPv6 — simplified pattern covering full and compressed forms
IPV6 = compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|::(?:[fF]{4}:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}"
)

# ---------------------------------------------------------------------------
# VIN
# ---------------------------------------------------------------------------

# 17 alphanumeric chars, no I/O/Q. Validated via check-digit after match.
VIN = compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")

# ---------------------------------------------------------------------------
# Domain / insurance identifiers
# ---------------------------------------------------------------------------

# NPI: 10 digits (Luhn validated after match)
NPI = compile(r"\b(\d{10})\b")
NPI_CONTEXT = compile(
    r"\b(?:npi|national[\s\-]?provider|provider[\s\-]?identifier)\b",
    re.IGNORECASE,
)

# Generic policy / claim / member / group IDs (require context keywords)
POLICY_NUMBER = compile(r"\b([A-Z]{2,4}[\-]?\d{6,12})\b")
POLICY_CONTEXT = compile(r"\b(?:policy[\s\-]?(?:number|num|no|#)|policy[\s\-]?id)\b", re.IGNORECASE)

CLAIM_ID = compile(r"\b([A-Z]{2,3}[\-]?\d{7,12})\b")
CLAIM_CONTEXT = compile(r"\b(?:claim[\s\-]?(?:number|num|no|#|id))\b", re.IGNORECASE)

MEMBER_ID = compile(r"\b([A-Z]{1,3}\d{6,12})\b")
MEMBER_CONTEXT = compile(r"\b(?:member[\s\-]?(?:id|number|no|#))\b", re.IGNORECASE)

GROUP_ID = compile(r"\b([A-Z]{1,3}\d{4,10})\b")
GROUP_CONTEXT = compile(r"\b(?:group[\s\-]?(?:id|number|no|#))\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Date of birth (PHI)
# ---------------------------------------------------------------------------

DOB = compile(
    r"\b(?:0?[1-9]|1[0-2])[\-/](?:0?[1-9]|[12]\d|3[01])[\-/](?:19|20)\d{2}\b"
    r"|\b(?:19|20)\d{2}[\-/](?:0?[1-9]|1[0-2])[\-/](?:0?[1-9]|[12]\d|3[01])\b"
)
DOB_CONTEXT = compile(
    r"\b(?:dob|date[\s\-]?of[\s\-]?birth|born|birth[\s\-]?date)\b",
    re.IGNORECASE,
)
