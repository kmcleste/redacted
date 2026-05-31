"""
Detection ensemble: orchestrates the pre-filter → deterministic → NER cascade.

Timing domains (D5):
- Hard-RT lane: deterministic detectors. Always runs, bounded WCET.
- Soft-RT lane: NER enrichment. Stubbed in Phase 1; circuit-broken on miss deadline.

Overlap resolution: when two spans overlap, the higher-scoring, longer span wins.
"""

from __future__ import annotations

from ..entities import DetectedSpan, EntityType
from ..policy import PolicyBundle, Decision, Modality
from .base import BaseDetector
from .prefilter import should_scan
from .regex_detectors import (
    BankAccountDetector,
    BankRoutingDetector,
    CreditCardDetector,
    DateOfBirthDetector,
    DomainIdentifierDetector,
    EmailDetector,
    IPAddressDetector,
    NPIDetector,
    PhoneDetector,
    SSNDetector,
    VINDetector,
)
from .secret_detectors import SecretDetector


def _resolve_overlaps(spans: list[DetectedSpan]) -> list[DetectedSpan]:
    """
    Remove overlapping spans.  Priority: higher score wins; on tie, longer span wins.
    O(n log n) — spans sorted by start, greedy sweep.
    """
    if len(spans) <= 1:
        return spans

    sorted_spans = sorted(spans, key=lambda s: (s.start, -s.score, -s.length))
    result: list[DetectedSpan] = []
    last_end = -1

    for span in sorted_spans:
        if span.start >= last_end:
            result.append(span)
            last_end = span.end
        elif span.score > result[-1].score or (
            span.score == result[-1].score and span.length > result[-1].length
        ):
            result[-1] = span
            last_end = span.end

    return result


class DetectionEnsemble:
    """
    Runs the full detection cascade and applies policy decisions.

    Args:
        policy: PolicyBundle governing which entity types to detect and at what threshold.
    """

    def __init__(self, policy: PolicyBundle | None = None) -> None:
        self._policy = policy or PolicyBundle.default()
        self._hard_rt: list[BaseDetector] = [
            SSNDetector(),
            CreditCardDetector(),
            BankRoutingDetector(),
            BankAccountDetector(),
            EmailDetector(),
            PhoneDetector(),
            IPAddressDetector(),
            VINDetector(),
            NPIDetector(),
            DomainIdentifierDetector(),
            DateOfBirthDetector(),
            SecretDetector(),
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> list[DetectedSpan]:
        """Return deduplicated, policy-filtered spans sorted by start position."""
        if not should_scan(text):
            return []

        raw: list[DetectedSpan] = []

        for detector in self._hard_rt:
            try:
                raw.extend(detector.detect(text))
            except Exception:
                # Hard-lane detector failure must not take down the pipeline (D6).
                # In production: emit a metric + alert; do NOT silently swallow.
                pass

        # Apply policy decisions (threshold + enabled flag).
        filtered = [
            span for span in raw
            if self._policy.decide(span.entity_type, span.score) == Decision.MASK
        ]

        # NER soft-RT lane: Phase 1 stub. Phase 2 adds Presidio/GLiNER here.
        # ner_spans = self._ner_lane(text)
        # filtered.extend(ner_spans)

        return _resolve_overlaps(filtered)

    def detect_with_policy(
        self, text: str, policy: PolicyBundle
    ) -> list[DetectedSpan]:
        """Same as detect() but with a request-scoped policy override."""
        original = self._policy
        self._policy = policy
        try:
            return self.detect(text)
        finally:
            self._policy = original
