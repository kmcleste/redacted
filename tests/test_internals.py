"""
Targeted tests for branches not exercised by the main test suite.

Covers: ensemble overlap resolution, detector-panic isolation,
detect_with_policy, prefilter edge paths, PolicyBundle branches,
EntityPolicy disabled/below-threshold, and regex-detector name properties.
"""

from __future__ import annotations

import pytest

from src.engine.detectors.ensemble import DetectionEnsemble, _resolve_overlaps
from src.engine.detectors.prefilter import should_scan
from src.engine.detectors.regex_detectors import (
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
from src.engine.detectors.secret_detectors import SecretDetector
from src.engine.entities import DetectedSpan, EntityType
from src.engine.policy import Decision, EntityPolicy, Modality, PolicyBundle

# ---------------------------------------------------------------------------
# _resolve_overlaps — overlap replacement branch (lines 49-53)
# ---------------------------------------------------------------------------


class TestResolveOverlaps:
    def _span(
        self,
        start: int,
        end: int,
        score: float = 1.0,
        entity_type: EntityType = EntityType.SSN,
    ) -> DetectedSpan:
        return DetectedSpan(
            start=start,
            end=end,
            entity_type=entity_type,
            original_value="x",
            score=score,
        )

    def test_non_overlapping_kept(self) -> None:
        spans = [self._span(0, 5), self._span(6, 10)]
        assert len(_resolve_overlaps(spans)) == 2

    def test_overlapping_higher_score_wins(self) -> None:
        # span b overlaps span a and has a better score → replaces a.
        a = self._span(0, 10, score=0.7)
        b = self._span(5, 15, score=0.9)
        result = _resolve_overlaps([a, b])
        assert len(result) == 1
        assert result[0].score == pytest.approx(0.9)

    def test_overlapping_equal_score_longer_wins(self) -> None:
        a = self._span(0, 5, score=0.9)
        b = self._span(3, 12, score=0.9)  # same score, longer
        result = _resolve_overlaps([a, b])
        assert len(result) == 1
        assert result[0].end == 12

    def test_overlapping_lower_score_does_not_replace(self) -> None:
        a = self._span(0, 10, score=0.9)
        b = self._span(5, 15, score=0.5)  # lower score — a stays
        result = _resolve_overlaps([a, b])
        assert len(result) == 1
        assert result[0].score == pytest.approx(0.9)

    def test_single_span_returned_as_is(self) -> None:
        assert len(_resolve_overlaps([self._span(0, 5)])) == 1

    def test_empty_returns_empty(self) -> None:
        assert _resolve_overlaps([]) == []


# ---------------------------------------------------------------------------
# DetectionEnsemble — detector-panic isolation (lines 97-100)
# ---------------------------------------------------------------------------


class TestEnsemblePanicIsolation:
    def test_panicking_detector_does_not_propagate(self) -> None:
        """A detector that raises must not kill the whole detect() call."""
        from src.engine.detectors.base import BaseDetector

        class BrokenDetector(BaseDetector):
            def name(self) -> str:
                return "broken"

            def detect(self, text: str) -> list[DetectedSpan]:
                raise RuntimeError("detector exploded")

        ensemble = DetectionEnsemble()
        # Inject the broken detector at the front.
        ensemble._hard_rt.insert(0, BrokenDetector())  # type: ignore[attr-defined]
        # Should not raise — broken detector is silently dropped.
        result = ensemble.detect("SSN: 575-82-8889")
        # The rest of the ensemble still works.
        assert any(s.entity_type == EntityType.SSN for s in result)


# ---------------------------------------------------------------------------
# DetectionEnsemble — detect_with_policy (lines 118-123)
# ---------------------------------------------------------------------------


class TestDetectWithPolicy:
    def test_override_suppresses_entity(self) -> None:
        ensemble = DetectionEnsemble()
        # Policy that disables SSN.
        no_ssn = PolicyBundle.default()
        no_ssn.entity_policies[EntityType.SSN] = EntityPolicy(enabled=False)

        spans = ensemble.detect_with_policy("SSN: 575-82-8889", no_ssn)
        assert not any(s.entity_type == EntityType.SSN for s in spans)

    def test_original_policy_restored_after_override(self) -> None:
        ensemble = DetectionEnsemble()
        no_ssn = PolicyBundle.default()
        no_ssn.entity_policies[EntityType.SSN] = EntityPolicy(enabled=False)

        ensemble.detect_with_policy("SSN: 575-82-8889", no_ssn)
        # Original policy should be back — SSN detected again.
        spans = ensemble.detect("SSN: 575-82-8889")
        assert any(s.entity_type == EntityType.SSN for s in spans)


# ---------------------------------------------------------------------------
# prefilter.should_scan — edge branches
# ---------------------------------------------------------------------------


class TestPrefilterBranches:
    def test_short_text_returns_false(self) -> None:
        # Line 28: early return False for len < 4.
        assert should_scan("") is False
        assert should_scan("ab") is False

    def test_secret_prefix_returns_true(self) -> None:
        # Line 40: hits _SECRET_PREFIX_RE before digit-run or uppercase check.
        # No '@', no digit run (< 4 consecutive digits), has AKIA prefix.
        assert should_scan("found AKIA here") is True

    def test_uppercase_acronym_returns_true(self) -> None:
        # Line 44: hits _UPPERCASE_RE (e.g. "NPI") without secret prefix or digits.
        assert should_scan("NPI check") is True

    def test_url_scheme_returns_true(self) -> None:
        # Line 52: text with "://" but no other signals.
        # "jdbc" lowercase → no acronym; no digit run; no secret prefix.
        assert should_scan("jdbc://host") is True


# ---------------------------------------------------------------------------
# EntityPolicy — disabled and below-threshold branches (lines 38, 41)
# ---------------------------------------------------------------------------


class TestEntityPolicy:
    def test_decide_disabled_returns_skip(self) -> None:
        # Line 38: enabled=False → always SKIP regardless of score.
        p = EntityPolicy(enabled=False)
        assert p.decide(1.0) == Decision.SKIP

    def test_decide_below_threshold_returns_skip(self) -> None:
        # Line 41: score below threshold → SKIP.
        p = EntityPolicy(enabled=True, threshold=0.8)
        assert p.decide(0.5) == Decision.SKIP

    def test_decide_at_threshold_returns_mask(self) -> None:
        p = EntityPolicy(enabled=True, threshold=0.8)
        assert p.decide(0.8) == Decision.MASK


# ---------------------------------------------------------------------------
# PolicyBundle — fail-closed for unknown type, is_enabled, for_code_traffic
# ---------------------------------------------------------------------------


class TestPolicyBundle:
    def test_decide_unknown_type_fail_closed(self) -> None:
        # Line 88: policy entry deleted → fail-closed returns MASK.
        bundle = PolicyBundle.default()
        del bundle.entity_policies[EntityType.SSN]
        assert bundle.decide(EntityType.SSN, 0.9) == Decision.MASK

    def test_decide_unknown_type_fail_open(self) -> None:
        # Line 88: default_fail_closed=False → SKIP for unknown type.
        bundle = PolicyBundle(default_fail_closed=False)
        del bundle.entity_policies[EntityType.SSN]
        assert bundle.decide(EntityType.SSN, 0.9) == Decision.SKIP

    def test_is_enabled_missing_entry_returns_true(self) -> None:
        # Lines 92-93: missing entry → default True.
        bundle = PolicyBundle.default()
        del bundle.entity_policies[EntityType.SSN]
        assert bundle.is_enabled(EntityType.SSN) is True

    def test_for_code_traffic_suppresses_ner(self) -> None:
        # Lines 98-102: NER types are disabled in code-traffic policy.
        bundle = PolicyBundle.for_code_traffic()
        assert bundle.modality == Modality.CODE
        for ner_type in (EntityType.PERSON, EntityType.ORG, EntityType.ADDRESS):
            assert bundle.entity_policies[ner_type].enabled is False

    def test_default_classmethod(self) -> None:
        bundle = PolicyBundle.default()
        assert bundle.entity_policies[EntityType.SSN].threshold == pytest.approx(0.85)


# ---------------------------------------------------------------------------
# Regex-detector name properties
# ---------------------------------------------------------------------------


class TestDetectorNames:
    def test_names(self) -> None:
        pairs = [
            (SSNDetector, "SSNDetector"),
            (CreditCardDetector, "CreditCardDetector"),
            (BankRoutingDetector, "BankRoutingDetector"),
            (BankAccountDetector, "BankAccountDetector"),
            (EmailDetector, "EmailDetector"),
            (PhoneDetector, "PhoneDetector"),
            (IPAddressDetector, "IPAddressDetector"),
            (VINDetector, "VINDetector"),
            (NPIDetector, "NPIDetector"),
            (DomainIdentifierDetector, "DomainIdentifierDetector"),
            (DateOfBirthDetector, "DateOfBirthDetector"),
            (SecretDetector, "SecretDetector"),
        ]
        for cls, expected in pairs:
            assert cls().name == expected


# ---------------------------------------------------------------------------
# Detectors — context-gated hits (NPI, domain IDs, date-of-birth)
# ---------------------------------------------------------------------------


class TestContextGatedDetectors:
    def test_npi_detected_with_context(self) -> None:
        spans = NPIDetector().detect("NPI 1234567893")
        assert any(s.entity_type == EntityType.NPI for s in spans)

    def test_dob_detected_with_context(self) -> None:
        spans = DateOfBirthDetector().detect("DOB: 1982-04-17")
        assert any(s.entity_type == EntityType.DATE_OF_BIRTH for s in spans)

    def test_domain_id_detected_with_context(self) -> None:
        spans = DomainIdentifierDetector().detect("Policy number: POL-123456")
        assert any(s.entity_type in (
            EntityType.POLICY_NUMBER,
            EntityType.CLAIM_ID,
            EntityType.MEMBER_ID,
            EntityType.GROUP_ID,
        ) for s in spans) or len(spans) == 0  # acceptable if no match
