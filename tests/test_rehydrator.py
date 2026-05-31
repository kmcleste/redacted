"""Tests for batch rehydrator."""

from src.engine.rehydrator import BatchRehydrator


class TestBatchRehydrator:
    r = BatchRehydrator()

    def test_simple_rehydration(self) -> None:
        text = "Call [PHONE_1] for support."
        mapping = {"[PHONE_1]": "(415) 555-1234"}
        result, count = self.r.rehydrate(text, mapping)
        assert result == "Call (415) 555-1234 for support."
        assert count == 1

    def test_multiple_placeholders(self) -> None:
        text = "[SSN_1] belongs to [EMAIL_1]"
        mapping = {"[SSN_1]": "575-82-8889", "[EMAIL_1]": "user@corp.com"}
        result, count = self.r.rehydrate(text, mapping)
        assert result == "575-82-8889 belongs to user@corp.com"
        assert count == 2

    def test_unknown_placeholder_passed_through(self) -> None:
        text = "Value is [UNKNOWN_99]."
        result, count = self.r.rehydrate(text, {})
        assert result == "Value is [UNKNOWN_99]."
        assert count == 0

    def test_empty_map(self) -> None:
        text = "No placeholders here."
        result, count = self.r.rehydrate(text, {})
        assert result == text
        assert count == 0

    def test_repeated_placeholder(self) -> None:
        text = "[EMAIL_1] sent to [EMAIL_1]"
        mapping = {"[EMAIL_1]": "a@b.com"}
        result, count = self.r.rehydrate(text, mapping)
        assert result == "a@b.com sent to a@b.com"
        assert count == 2
