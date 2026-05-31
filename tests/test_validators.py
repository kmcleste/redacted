"""Unit tests for validators.py."""

import pytest
from src.engine.validators import (
    validate_aba_routing,
    validate_credit_card,
    validate_email,
    validate_ip_address,
    validate_npi,
    validate_phone,
    validate_ssn,
    validate_vin,
)


# ---------------------------------------------------------------------------
# SSN
# ---------------------------------------------------------------------------

class TestSSNValidator:
    @pytest.mark.parametrize("ssn", [
        "001-01-0001",
        "575-82-8889",
        "456-78-9012",
    ])
    def test_valid_ssn(self, ssn: str) -> None:
        assert validate_ssn(ssn)

    @pytest.mark.parametrize("ssn", [
        "000-01-0001",   # area 000
        "666-01-0001",   # area 666
        "900-01-0001",   # area 900-999
        "123-00-1234",   # group 00
        "123-45-0000",   # serial 0000
        "078-05-1120",   # Woolworth known-invalid
        "219-09-9999",   # known invalid
        "123-45-678",    # too short
        "abc-de-fghi",   # non-digits
    ])
    def test_invalid_ssn(self, ssn: str) -> None:
        assert not validate_ssn(ssn)


# ---------------------------------------------------------------------------
# Credit card (Luhn)
# ---------------------------------------------------------------------------

class TestCreditCardValidator:
    @pytest.mark.parametrize("cc", [
        "4532015112830366",   # Valid Visa (Luhn verified)
        "5425233430109903",   # Valid MC (Luhn verified)
        "370000000000002",    # Valid Amex (Luhn verified, not in test-card denylist)
    ])
    def test_valid_card(self, cc: str) -> None:
        assert validate_credit_card(cc)

    @pytest.mark.parametrize("cc", [
        "4111111111111111",   # Visa test card (denylist)
        "5500005555555559",   # MC test card
        "1234567890123456",   # Fails Luhn
        "4532015112830360",   # One digit off
        "1234",               # Too short
    ])
    def test_invalid_card(self, cc: str) -> None:
        assert not validate_credit_card(cc)


# ---------------------------------------------------------------------------
# ABA routing
# ---------------------------------------------------------------------------

class TestABAValidator:
    @pytest.mark.parametrize("routing", [
        "021000021",   # JPMorgan Chase
        "021200339",   # JPMorgan (NY)
        "011000138",   # BofA
    ])
    def test_valid_routing(self, routing: str) -> None:
        assert validate_aba_routing(routing)

    @pytest.mark.parametrize("routing", [
        "000000000",   # All zeros — fails checksum
        "12345678",    # 8 digits (too short)
        "1234567890",  # 10 digits (too long)
        "abcdefghi",   # Non-digits
    ])
    def test_invalid_routing(self, routing: str) -> None:
        assert not validate_aba_routing(routing)


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

class TestEmailValidator:
    def test_real_domain_valid(self) -> None:
        assert validate_email("user@company.com")

    @pytest.mark.parametrize("email", [
        "user@example.com",
        "user@example.org",
        "user@test.com",
        "user@localhost",
        "noemail",
    ])
    def test_doc_domain_invalid(self, email: str) -> None:
        assert not validate_email(email)


# ---------------------------------------------------------------------------
# IP address
# ---------------------------------------------------------------------------

class TestIPAddressValidator:
    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "172.217.12.206",
    ])
    def test_real_ip_valid(self, ip: str) -> None:
        assert validate_ip_address(ip)

    @pytest.mark.parametrize("ip", [
        "192.0.2.1",     # TEST-NET-1
        "198.51.100.1",  # TEST-NET-2
        "203.0.113.1",   # TEST-NET-3
        "127.0.0.1",     # Loopback
        "999.1.1.1",     # Invalid
        "notanip",       # Not an IP
    ])
    def test_reserved_or_invalid(self, ip: str) -> None:
        assert not validate_ip_address(ip)


# ---------------------------------------------------------------------------
# Phone
# ---------------------------------------------------------------------------

class TestPhoneValidator:
    def test_real_phone_valid(self) -> None:
        assert validate_phone("555-123-4567")

    def test_fiction_555_01xx_invalid(self) -> None:
        assert not validate_phone("555-0100")
        assert not validate_phone("555-0199")


# ---------------------------------------------------------------------------
# VIN
# ---------------------------------------------------------------------------

class TestVINValidator:
    def test_valid_vin(self) -> None:
        # Real VINs (check digit at position 9 validated)
        assert validate_vin("1HGBH41JXMN109186")

    @pytest.mark.parametrize("vin", [
        "1HGBH41JXMN10918",   # 16 chars (too short)
        "1HGBH41JXMN1091860", # 18 chars (too long)
        "1HGBH41JOMN109186",  # Contains 'O' (invalid char)
        "AAAAAAAAAAAAAAAAA",   # Wrong check digit
    ])
    def test_invalid_vin(self, vin: str) -> None:
        assert not validate_vin(vin)


# ---------------------------------------------------------------------------
# NPI
# ---------------------------------------------------------------------------

class TestNPIValidator:
    def test_valid_npi(self) -> None:
        # NPI 1234567893 has valid Luhn check with 80840 prefix
        assert validate_npi("1234567893")

    def test_invalid_npi_wrong_check_digit(self) -> None:
        assert not validate_npi("1234567890")

    def test_invalid_npi_wrong_length(self) -> None:
        assert not validate_npi("123456789")
