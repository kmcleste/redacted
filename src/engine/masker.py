"""
Masker: replaces detected spans with typed positional placeholders.

Placeholder format (D3): [ENTITY_TYPE_N]
  - Typed counters beat UUIDs: better tokenization, model can reason about relationships.
  - Counters are per-type within a request.
  - Consistent within a request: same original value → same placeholder.

Returns:
  - masked_text: the text with all spans replaced.
  - placeholder_map: {placeholder: original_value} — given to Vault.
"""

from __future__ import annotations

from collections import defaultdict

from .entities import DetectedSpan, EntityType


class Masker:
    def mask(
        self,
        text: str,
        spans: list[DetectedSpan],
    ) -> tuple[str, dict[str, str]]:
        """
        Replace spans with placeholders.  Consistent: same value → same placeholder.

        Returns:
            (masked_text, {placeholder: original_value})
        """
        if not spans:
            return text, {}

        counters: dict[EntityType, int] = defaultdict(int)
        value_to_placeholder: dict[str, str] = {}
        placeholder_to_value: dict[str, str] = {}

        # Sort by position descending so we can replace right-to-left without
        # invalidating earlier offsets.
        sorted_spans = sorted(spans, key=lambda s: s.start, reverse=True)

        # Pre-assign placeholders (forward pass for consistent numbering).
        forward_spans = sorted(spans, key=lambda s: s.start)
        for span in forward_spans:
            if span.original_value not in value_to_placeholder:
                counters[span.entity_type] += 1
                placeholder = f"[{span.entity_type.value}_{counters[span.entity_type]}]"
                value_to_placeholder[span.original_value] = placeholder
                placeholder_to_value[placeholder] = span.original_value

        # Apply replacements right-to-left.
        chars = list(text)
        for span in sorted_spans:
            placeholder = value_to_placeholder[span.original_value]
            chars[span.start : span.end] = list(placeholder)

        return "".join(chars), placeholder_to_value
