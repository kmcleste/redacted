"""
Batch rehydrator: replaces placeholders back to original values.

Used for non-streamed (complete) response bodies.
For streaming, see streaming.py.
"""

from __future__ import annotations

import re

from .entities import RehydrateResult

# Matches any typed positional placeholder: [ENTITY_TYPE_N]
_PLACEHOLDER_RE = re.compile(r"\[([A-Z_]+)_(\d+)\]")


class BatchRehydrator:
    def rehydrate(
        self,
        text: str,
        placeholder_map: dict[str, str],
    ) -> tuple[str, int]:
        """
        Replace all placeholders in text with their original values.

        Returns:
            (rehydrated_text, number_of_substitutions)
        """
        if not placeholder_map or not text:
            return text, 0

        count = 0

        def _replace(m: re.Match[str]) -> str:
            nonlocal count
            placeholder = m.group(0)
            original = placeholder_map.get(placeholder)
            if original is not None:
                count += 1
                return original
            return placeholder  # Unknown placeholder — pass through unchanged.

        result = _PLACEHOLDER_RE.sub(_replace, text)
        return result, count
