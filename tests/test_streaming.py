"""
Tests for the streaming rehydrator — the hard problem.

Key scenarios:
  1. Placeholder arrives in a single chunk.
  2. Placeholder split across chunk boundaries.
  3. Multiple placeholders in one chunk.
  4. Placeholder-like text that is NOT in the map (must pass through untouched).
  5. Very short chunks (one char at a time).
  6. Flush at end of stream.
"""

from src.engine.streaming import StreamingRehydrator

MAP = {
    "[SSN_1]": "575-82-8889",
    "[EMAIL_1]": "user@corp.com",
    "[CREDIT_CARD_1]": "4532-0151-1283-0366",
}


def _stream(chunks: list[str], mapping: dict[str, str]) -> str:
    r = StreamingRehydrator(mapping)
    parts = [r.feed(c) for c in chunks]
    parts.append(r.flush())
    return "".join(parts)


class TestStreamingRehydrator:

    def test_whole_placeholder_in_one_chunk(self) -> None:
        result = _stream(["SSN is [SSN_1] ok"], MAP)
        assert result == "SSN is 575-82-8889 ok"

    def test_placeholder_split_across_chunks(self) -> None:
        # "[SSN_1]" split as "[SS", "N_", "1]"
        result = _stream(["before [SS", "N_", "1] after"], MAP)
        assert result == "before 575-82-8889 after"

    def test_placeholder_split_one_char_at_a_time(self) -> None:
        full = "x[SSN_1]y"
        chunks = list(full)  # one char per chunk
        result = _stream(chunks, MAP)
        assert result == "x575-82-8889y"

    def test_multiple_placeholders_in_one_chunk(self) -> None:
        result = _stream(["[SSN_1] and [EMAIL_1]"], MAP)
        assert result == "575-82-8889 and user@corp.com"

    def test_multiple_placeholders_split_across_chunks(self) -> None:
        result = _stream(["[SSN", "_1] and [EMAIL", "_1]"], MAP)
        assert result == "575-82-8889 and user@corp.com"

    def test_unknown_placeholder_passes_through(self) -> None:
        result = _stream(["value [UNKNOWN_99] here"], MAP)
        assert result == "value [UNKNOWN_99] here"

    def test_no_placeholders(self) -> None:
        result = _stream(["hello world"], MAP)
        assert result == "hello world"

    def test_empty_stream(self) -> None:
        result = _stream([], MAP)
        assert result == ""

    def test_empty_map(self) -> None:
        result = _stream(["[SSN_1]"], {})
        assert result == "[SSN_1]"

    def test_open_bracket_at_end_flushed_as_is(self) -> None:
        # Stream ends with a '[' that never closes — flush must emit it.
        r = StreamingRehydrator(MAP)
        out = r.feed("text [")
        out += r.flush()
        assert out == "text ["

    def test_consecutive_placeholders_no_gap(self) -> None:
        result = _stream(["[SSN_1][EMAIL_1]"], MAP)
        assert result == "575-82-8889user@corp.com"

    def test_long_non_placeholder_not_buffered_forever(self) -> None:
        # A '[' followed by many chars that never close → must progress.
        noise = "[" + "A" * 200 + " rest"
        result = _stream([noise], MAP)
        assert "rest" in result

    def test_placeholder_at_very_start(self) -> None:
        result = _stream(["[EMAIL_1] is here"], MAP)
        assert result.startswith("user@corp.com")

    def test_placeholder_at_very_end(self) -> None:
        result = _stream(["here is [EMAIL_1]"], MAP)
        assert result.endswith("user@corp.com")

    def test_idempotent_on_non_pii(self) -> None:
        text = "Nothing sensitive in this string at all."
        result = _stream([text], MAP)
        assert result == text

    def test_flush_called_once_at_end(self) -> None:
        r = StreamingRehydrator(MAP)
        r.feed("part [SSN_")
        r.feed("1] done")
        result = r.flush()
        # flush() should only return the leftover buffer, not reprocess
        # (the actual substitution happens in feed())
        assert "575-82-8889" not in result  # already emitted by feed()
