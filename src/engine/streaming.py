"""
Streaming rehydrator — the hard problem (PRD §3, §5).

Challenge: a model streaming response may split a placeholder across multiple
SSE events / WebSocket frames.  E.g. "[SSN_1]" might arrive as "[SS", "N_", "1]".
Naive per-chunk string replacement corrupts it.

Solution: a bounded-lookahead state machine.
- On '[': enter IN_BRACKET mode; start buffering.
- In IN_BRACKET: accumulate until:
    a) ']' found → lookup in placeholder_map:
        - Hit  → emit substitution, resume NORMAL.
        - Miss → emit buffer as-is, resume NORMAL.
    b) Buffer exceeds max_placeholder_len without ']' → emit buffer[0], retry.
- Guaranteed to emit output and make progress; buffer is always bounded.

The matching is intentionally simple: no Aho-Corasick needed because we only
ever look for one delimiter (']') and a fixed max-length candidate.  Hyperscan
streaming mode (Phase 1 optional, Phase 2 planned) can replace this for
multi-pattern SIMD throughput when placeholder sets are very large.

Thread-safety: one StreamingRehydrator per stream session.  Do not share across goroutines/threads.
"""

from __future__ import annotations

import re

_PLACEHOLDER_CHAR_RE = re.compile(r"[A-Z_0-9]")

# Hard upper bound on a single placeholder length: "[" + type + "_" + digits + "]"
# e.g., "[CONNECTION_STRING_999]" is 23 chars. 64 gives ample headroom.
_HARD_MAX_PLACEHOLDER_LEN = 64


class StreamingRehydrator:
    """
    Processes response chunks one at a time, emitting rehydrated output.

    Usage::

        r = StreamingRehydrator({"[SSN_1]": "123-45-6789"})
        for chunk in sse_stream:
            yield r.feed(chunk)
        yield r.flush()   # always call flush() at end of stream
    """

    def __init__(self, placeholder_map: dict[str, str]) -> None:
        self._map = placeholder_map
        # Max possible placeholder length given the current map; bounded by HARD_MAX.
        self._max_len = (
            max((len(k) for k in placeholder_map), default=_HARD_MAX_PLACEHOLDER_LEN)
            if placeholder_map
            else _HARD_MAX_PLACEHOLDER_LEN
        )
        self._max_len = min(self._max_len, _HARD_MAX_PLACEHOLDER_LEN)
        self._buffer = ""
        self._in_bracket = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def feed(self, chunk: str) -> str:
        """Consume a chunk; return whatever can be safely emitted now."""
        self._buffer += chunk
        return self._drain()

    def flush(self) -> str:
        """
        End of stream: emit all buffered content as-is.
        Must be called exactly once at stream end.
        """
        remaining = self._buffer
        self._buffer = ""
        self._in_bracket = False
        return remaining

    # ------------------------------------------------------------------
    # Internal state machine
    # ------------------------------------------------------------------

    def _drain(self) -> str:
        parts: list[str] = []

        while True:
            if not self._in_bracket:
                bracket_pos = self._buffer.find("[")
                if bracket_pos == -1:
                    # No potential placeholder start — safe to emit everything.
                    parts.append(self._buffer)
                    self._buffer = ""
                    break
                else:
                    # Emit everything before '['.
                    parts.append(self._buffer[:bracket_pos])
                    self._buffer = self._buffer[bracket_pos:]
                    self._in_bracket = True

            else:
                # We're buffering a potential placeholder starting with '['.
                close_pos = self._buffer.find("]")

                if close_pos != -1:
                    candidate = self._buffer[: close_pos + 1]
                    original = self._map.get(candidate)
                    if original is not None:
                        parts.append(original)
                    else:
                        parts.append(candidate)
                    self._buffer = self._buffer[close_pos + 1 :]
                    self._in_bracket = self._buffer.startswith("[")

                elif len(self._buffer) > self._max_len:
                    # Definitely not a valid placeholder — emit first char and retry.
                    parts.append(self._buffer[0])
                    self._buffer = self._buffer[1:]
                    self._in_bracket = self._buffer.startswith("[")

                else:
                    # Need more data before we can decide.
                    break

        return "".join(parts)

    def __repr__(self) -> str:
        return (
            f"<StreamingRehydrator placeholders={len(self._map)} "
            f"buffered={len(self._buffer)} in_bracket={self._in_bracket}>"
        )
