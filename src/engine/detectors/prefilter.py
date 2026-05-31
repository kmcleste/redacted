"""
Fast pre-filter: O(n) scan to decide whether full detection is worth running.

Returns True if the text plausibly contains sensitive content.
A False negative here is a leak; tune toward high recall (very few false negatives).
"""

from __future__ import annotations

import re

# Key-shaped prefixes for secrets.
_SECRET_PREFIX_RE = re.compile(r"AKIA|ABIA|ACCA|ASIA|ghp_|ghs_|ghr_|sk-|-----BEGIN")

# Conservative digit-run threshold: 4+ consecutive digits hint at structured PII.
_DIGIT_RUN_RE = re.compile(r"\d{4,}")

# Uppercase sequences (potential entity types / acronyms like SSN, DOB, NPI…)
_UPPERCASE_RE = re.compile(r"\b[A-Z]{2,}\b")

# Capitalized word (potential proper noun / name).
_CAPITALIZED_RE = re.compile(r"\b[A-Z][a-z]{1,}\b")


def should_scan(text: str) -> bool:
    """Return True if the text warrants full detection. False-negative intolerant."""
    if not text or len(text) < 4:
        return False

    # '@' → possible email
    if "@" in text:
        return True

    # Digit runs → possible SSN, card, phone, routing, etc.
    if _DIGIT_RUN_RE.search(text):
        return True

    # Secret key prefixes
    if _SECRET_PREFIX_RE.search(text):
        return True

    # Uppercase acronyms often co-occur with PII labels (SSN, DOB, NPI…)
    if _UPPERCASE_RE.search(text):
        return True

    # Capitalized words → possible proper names
    if _CAPITALIZED_RE.search(text):
        return True

    # URL-scheme-like string → possible connection string
    if "://" in text:
        return True

    return False
