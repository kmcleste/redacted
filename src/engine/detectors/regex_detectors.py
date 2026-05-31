"""
Deterministic lane: DFA-safe regex patterns + structural validators.

Detection cascade per entity type:
  1. Regex match → candidate span
  2. Validator → precision filter (free; O(1))
  3. Context score → threshold gate for context-sensitive types (SSN bare, routing, DOB)

All patterns imported from patterns.py; validators from validators.py.
"""

from __future__ import annotations

import re

from ..entities import DetectedSpan, EntityType
from ..validators import (
    validate_aba_routing,
    validate_credit_card,
    validate_email,
    validate_ip_address,
    validate_npi,
    validate_phone,
    validate_ssn,
    validate_vin,
)
from . import patterns as P
from .base import BaseDetector

_CONTEXT_WINDOW = 150  # characters around a candidate to search for context keywords


def _has_context(text: str, match_start: int, context_re: re.Pattern[str]) -> bool:
    lo = max(0, match_start - _CONTEXT_WINDOW)
    hi = min(len(text), match_start + _CONTEXT_WINDOW)
    return bool(context_re.search(text[lo:hi]))


class SSNDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "SSNDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        seen_ranges: set[tuple[int, int]] = set()

        # Formatted SSN — always high-confidence when validated.
        for m in P.SSN_FORMATTED.finditer(text):
            raw = m.group(0)
            if validate_ssn(raw):
                r = (m.start(), m.end())
                if r not in seen_ranges:
                    seen_ranges.add(r)
                    spans.append(DetectedSpan(m.start(), m.end(), EntityType.SSN, raw, score=0.95))

        # Bare 9-digit run — only with surrounding context keywords.
        # Context presence raises confidence to match the policy threshold.
        for m in P.SSN_BARE.finditer(text):
            r = (m.start(), m.end())
            if r in seen_ranges:
                continue
            raw = m.group(0)
            if validate_ssn(raw) and _has_context(text, m.start(), P.SSN_CONTEXT):
                seen_ranges.add(r)
                spans.append(DetectedSpan(m.start(), m.end(), EntityType.SSN, raw, score=0.85))

        return sorted(spans, key=lambda s: s.start)


class CreditCardDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "CreditCardDetector"

    _PATTERNS = [P.CC_VISA, P.CC_MASTERCARD, P.CC_AMEX, P.CC_DISCOVER, P.CC_JCB]

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        seen: set[tuple[int, int]] = set()
        for pat in self._PATTERNS:
            for m in pat.finditer(text):
                r = (m.start(), m.end())
                if r in seen:
                    continue
                raw = m.group(0)
                if validate_credit_card(raw):
                    seen.add(r)
                    spans.append(
                        DetectedSpan(m.start(), m.end(), EntityType.CREDIT_CARD, raw, score=0.90)
                    )
        return sorted(spans, key=lambda s: s.start)


class BankRoutingDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "BankRoutingDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        for m in P.BANK_ROUTING.finditer(text):
            raw = m.group(0)
            if validate_aba_routing(raw) and _has_context(text, m.start(), P.BANK_ROUTING_CONTEXT):
                spans.append(
                    DetectedSpan(m.start(), m.end(), EntityType.BANK_ROUTING, raw, score=0.85)
                )
        return sorted(spans, key=lambda s: s.start)


class BankAccountDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "BankAccountDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        for m in P.BANK_ACCOUNT.finditer(text):
            if _has_context(text, m.start(), P.BANK_ACCOUNT_CONTEXT):
                spans.append(
                    DetectedSpan(
                        m.start(), m.end(), EntityType.BANK_ACCOUNT, m.group(0), score=0.75
                    )
                )
        return sorted(spans, key=lambda s: s.start)


class EmailDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "EmailDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        for m in P.EMAIL.finditer(text):
            raw = m.group(0)
            if validate_email(raw):
                spans.append(
                    DetectedSpan(m.start(), m.end(), EntityType.EMAIL, raw, score=0.95)
                )
        return sorted(spans, key=lambda s: s.start)


class PhoneDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "PhoneDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        seen: set[tuple[int, int]] = set()
        for pat in (P.PHONE_US, P.PHONE_INTL):
            for m in pat.finditer(text):
                r = (m.start(), m.end())
                if r in seen:
                    continue
                raw = m.group(0)
                if validate_phone(raw):
                    seen.add(r)
                    spans.append(
                        DetectedSpan(m.start(), m.end(), EntityType.PHONE, raw, score=0.80)
                    )
        return sorted(spans, key=lambda s: s.start)


class IPAddressDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "IPAddressDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        seen: set[tuple[int, int]] = set()
        for pat in (P.IPV4, P.IPV6):
            for m in pat.finditer(text):
                r = (m.start(), m.end())
                if r in seen:
                    continue
                raw = m.group(0)
                if validate_ip_address(raw):
                    seen.add(r)
                    spans.append(
                        DetectedSpan(m.start(), m.end(), EntityType.IP_ADDRESS, raw, score=0.85)
                    )
        return sorted(spans, key=lambda s: s.start)


class VINDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "VINDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        for m in P.VIN.finditer(text):
            raw = m.group(0)
            if validate_vin(raw):
                spans.append(
                    DetectedSpan(m.start(), m.end(), EntityType.VIN, raw, score=0.90)
                )
        return sorted(spans, key=lambda s: s.start)


class NPIDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "NPIDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        for m in P.NPI.finditer(text):
            raw = m.group(0)
            if validate_npi(raw) and _has_context(text, m.start(), P.NPI_CONTEXT):
                spans.append(
                    DetectedSpan(m.start(), m.end(), EntityType.NPI, raw, score=0.85)
                )
        return sorted(spans, key=lambda s: s.start)


class DomainIdentifierDetector(BaseDetector):
    """Detects policy #, claim ID, member ID, group ID — all require context keywords."""

    @property
    def name(self) -> str:
        return "DomainIdentifierDetector"

    _MATCHERS = [
        (P.POLICY_NUMBER, P.POLICY_CONTEXT, EntityType.POLICY_NUMBER, 0.80),
        (P.CLAIM_ID, P.CLAIM_CONTEXT, EntityType.CLAIM_ID, 0.80),
        (P.MEMBER_ID, P.MEMBER_CONTEXT, EntityType.MEMBER_ID, 0.75),
        (P.GROUP_ID, P.GROUP_CONTEXT, EntityType.GROUP_ID, 0.70),
    ]

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        for pat, ctx_pat, entity_type, score in self._MATCHERS:
            for m in pat.finditer(text):
                if _has_context(text, m.start(), ctx_pat):
                    spans.append(
                        DetectedSpan(m.start(), m.end(), entity_type, m.group(0), score=score)
                    )
        return sorted(spans, key=lambda s: s.start)


class DateOfBirthDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "DateOfBirthDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        for m in P.DOB.finditer(text):
            if _has_context(text, m.start(), P.DOB_CONTEXT):
                spans.append(
                    DetectedSpan(
                        m.start(), m.end(), EntityType.DATE_OF_BIRTH, m.group(0), score=0.85
                    )
                )
        return sorted(spans, key=lambda s: s.start)
