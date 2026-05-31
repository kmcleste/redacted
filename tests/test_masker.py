"""Tests for the Masker."""

import pytest
from src.engine.masker import Masker
from src.engine.entities import DetectedSpan, EntityType


class TestMasker:
    masker = Masker()

    def _span(self, text: str, start: int, end: int, et: EntityType) -> DetectedSpan:
        return DetectedSpan(start, end, et, text[start:end])

    def test_single_span(self) -> None:
        text = "SSN: 575-82-8889"
        spans = [self._span(text, 5, 16, EntityType.SSN)]
        masked, mapping = self.masker.mask(text, spans)
        assert masked == "SSN: [SSN_1]"
        assert mapping == {"[SSN_1]": "575-82-8889"}

    def test_multiple_spans(self) -> None:
        text = "ssn=575-82-8889 email=user@corp.com"
        ssn_span = self._span(text, 4, 15, EntityType.SSN)
        email_span = self._span(text, 22, 35, EntityType.EMAIL)
        masked, mapping = self.masker.mask(text, [ssn_span, email_span])
        assert "[SSN_1]" in masked
        assert "[EMAIL_1]" in masked
        assert "575-82-8889" not in masked
        assert "user@corp.com" not in masked
        assert mapping["[SSN_1]"] == "575-82-8889"
        assert mapping["[EMAIL_1]"] == "user@corp.com"

    def test_consistent_placeholder_for_same_value(self) -> None:
        text = "SSN 575-82-8889 and again 575-82-8889"
        span1 = self._span(text, 4, 15, EntityType.SSN)
        span2 = self._span(text, 26, 37, EntityType.SSN)
        masked, mapping = self.masker.mask(text, [span1, span2])
        # Same original value → same placeholder.
        assert masked.count("[SSN_1]") == 2
        assert len(mapping) == 1

    def test_no_spans_returns_unchanged(self) -> None:
        text = "Nothing sensitive here."
        masked, mapping = self.masker.mask(text, [])
        assert masked == text
        assert mapping == {}

    def test_placeholder_counter_per_type(self) -> None:
        text = "a@b.com and c@d.com"
        span1 = self._span(text, 0, 7, EntityType.EMAIL)
        span2 = self._span(text, 12, 19, EntityType.EMAIL)
        _, mapping = self.masker.mask(text, [span1, span2])
        assert "[EMAIL_1]" in mapping
        assert "[EMAIL_2]" in mapping

    def test_spans_can_be_unsorted(self) -> None:
        text = "email=user@corp.com ssn=575-82-8889"
        email_span = self._span(text, 6, 19, EntityType.EMAIL)
        ssn_span = self._span(text, 24, 35, EntityType.SSN)
        masked, mapping = self.masker.mask(text, [ssn_span, email_span])  # reversed order
        assert "[EMAIL_1]" in masked
        assert "[SSN_1]" in masked
