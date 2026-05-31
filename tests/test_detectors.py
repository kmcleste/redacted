"""Unit tests for individual detectors and the ensemble."""

import pytest
from src.engine.detectors.regex_detectors import (
    CreditCardDetector,
    EmailDetector,
    IPAddressDetector,
    SSNDetector,
    PhoneDetector,
    VINDetector,
)
from src.engine.detectors.secret_detectors import SecretDetector
from src.engine.detectors.ensemble import DetectionEnsemble
from src.engine.entities import EntityType


class TestSSNDetector:
    detector = SSNDetector()

    def test_formatted_ssn_detected(self) -> None:
        spans = self.detector.detect("SSN: 575-82-8889")
        assert len(spans) == 1
        assert spans[0].entity_type == EntityType.SSN
        assert spans[0].original_value == "575-82-8889"

    def test_bare_ssn_without_context_not_detected(self) -> None:
        # A bare 9-digit run without any SSN context keyword should NOT fire.
        spans = self.detector.detect("The number is 575828889.")
        assert len(spans) == 0

    def test_bare_ssn_with_context_detected(self) -> None:
        spans = self.detector.detect("taxpayer id 575828889 on file")
        assert len(spans) == 1
        assert spans[0].entity_type == EntityType.SSN

    def test_invalid_ssn_not_detected(self) -> None:
        spans = self.detector.detect("SSN: 000-12-3456")  # invalid area
        assert len(spans) == 0


class TestCreditCardDetector:
    detector = CreditCardDetector()

    def test_valid_visa_detected(self) -> None:
        spans = self.detector.detect("card: 4532015112830366")
        assert len(spans) == 1
        assert spans[0].entity_type == EntityType.CREDIT_CARD

    def test_test_card_not_detected(self) -> None:
        # 4111111111111111 is a known test card.
        spans = self.detector.detect("card 4111111111111111")
        assert len(spans) == 0

    def test_formatted_card_detected(self) -> None:
        spans = self.detector.detect("4532-0151-1283-0366")
        assert len(spans) == 1

    def test_invalid_luhn_not_detected(self) -> None:
        spans = self.detector.detect("4532015112830360")  # One digit wrong
        assert len(spans) == 0


class TestEmailDetector:
    detector = EmailDetector()

    def test_real_email_detected(self) -> None:
        spans = self.detector.detect("contact user@acme.com for info")
        assert len(spans) == 1
        assert spans[0].entity_type == EntityType.EMAIL
        assert spans[0].original_value == "user@acme.com"

    def test_example_domain_not_detected(self) -> None:
        spans = self.detector.detect("see user@example.com")
        assert len(spans) == 0

    def test_multiple_emails(self) -> None:
        spans = self.detector.detect("a@acme.com and b@corp.io")
        assert len(spans) == 2


class TestIPAddressDetector:
    detector = IPAddressDetector()

    def test_public_ip_detected(self) -> None:
        spans = self.detector.detect("server at 8.8.8.8 is up")
        assert len(spans) == 1

    def test_reserved_ip_not_detected(self) -> None:
        spans = self.detector.detect("192.0.2.1 is documentation")
        assert len(spans) == 0

    def test_loopback_not_detected(self) -> None:
        spans = self.detector.detect("localhost 127.0.0.1")
        assert len(spans) == 0


class TestSecretDetector:
    detector = SecretDetector()

    def test_aws_access_key_detected(self) -> None:
        spans = self.detector.detect("key=AKIAIOSFODNN7EXAMPLE")
        assert any(s.entity_type == EntityType.AWS_KEY for s in spans)

    def test_github_token_detected(self) -> None:
        token = "ghp_" + "A" * 36
        spans = self.detector.detect(f"token: {token}")
        assert any(s.entity_type == EntityType.GITHUB_TOKEN for s in spans)

    def test_pem_block_detected(self) -> None:
        spans = self.detector.detect("-----BEGIN PRIVATE KEY-----\nabc123")
        assert any(s.entity_type == EntityType.PEM_BLOCK for s in spans)

    def test_connection_string_detected(self) -> None:
        spans = self.detector.detect("db = postgres://user:pass@host:5432/db")
        assert any(s.entity_type == EntityType.CONNECTION_STRING for s in spans)


class TestPhoneDetector:
    detector = PhoneDetector()

    def test_us_phone_detected(self) -> None:
        spans = self.detector.detect("call me at (415) 555-1234")
        assert len(spans) == 1
        assert spans[0].entity_type == EntityType.PHONE

    def test_fiction_number_not_detected(self) -> None:
        spans = self.detector.detect("call 555-0100")
        assert len(spans) == 0


class TestVINDetector:
    detector = VINDetector()

    def test_valid_vin_detected(self) -> None:
        spans = self.detector.detect("VIN: 1HGBH41JXMN109186")
        assert len(spans) == 1
        assert spans[0].entity_type == EntityType.VIN


class TestEnsemble:
    ensemble = DetectionEnsemble()

    def test_mixed_pii_detected(self) -> None:
        text = (
            "Patient SSN: 575-82-8889, email: john@hospital.org, "
            "card: 4532015112830366"
        )
        spans = self.ensemble.detect(text)
        types = {s.entity_type for s in spans}
        assert EntityType.SSN in types
        assert EntityType.EMAIL in types
        assert EntityType.CREDIT_CARD in types

    def test_no_false_positive_on_clean_text(self) -> None:
        spans = self.ensemble.detect("The quick brown fox jumps over the lazy dog.")
        assert len(spans) == 0

    def test_overlapping_spans_resolved(self) -> None:
        # Ensure no two spans overlap in the result.
        text = "ssn 575828889 and card 4532015112830366 email test@corp.com"
        spans = self.ensemble.detect(text)
        for i, a in enumerate(spans):
            for j, b in enumerate(spans):
                if i != j:
                    assert a.end <= b.start or b.end <= a.start, (
                        f"Overlapping spans: {a} and {b}"
                    )

    def test_prefilter_skips_clean_text(self) -> None:
        # Long text with no PII signals should be skipped by prefilter.
        text = "the quick brown fox " * 100
        spans = self.ensemble.detect(text)
        assert len(spans) == 0
