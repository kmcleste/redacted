"""
Engine: the main entrypoint for the sensitive-content pipeline.

Wires together: pre-filter → detection ensemble → masker → vault → rehydrator.

The Engine is the unit that consumers (gateway adapter, standalone API) instantiate.
One Engine instance per process/trust boundary (D1).
"""

from __future__ import annotations

import uuid
from collections import defaultdict

from .detectors.ensemble import DetectionEnsemble
from .entities import DetectedSpan, EntityType, MaskResult, RehydrateResult
from .masker import Masker
from .policy import PolicyBundle
from .rehydrator import BatchRehydrator
from .streaming import StreamingRehydrator
from .vault import Vault, VaultExpiredError, VaultNotFoundError


class Engine:
    """
    Sensitive content detection, masking, and rehydration engine.

    Args:
        policy: PolicyBundle controlling detection thresholds and entity types.
                Defaults to the fail-closed baseline policy.
        vault_ttl: Seconds before a vault entry expires. Default: 300 s (5 min).
    """

    def __init__(
        self,
        policy: PolicyBundle | None = None,
        vault_ttl: float = Vault.DEFAULT_TTL,
    ) -> None:
        self._policy = policy or PolicyBundle.default()
        self._vault = Vault()
        self._vault_ttl = vault_ttl
        self._ensemble = DetectionEnsemble(self._policy)
        self._masker = Masker()
        self._rehydrator = BatchRehydrator()

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect(self, text: str) -> list[DetectedSpan]:
        """Run detection without masking. Returns sorted spans."""
        return self._ensemble.detect(text)

    # ------------------------------------------------------------------
    # Masking
    # ------------------------------------------------------------------

    def mask(
        self,
        text: str,
        correlation_id: str | None = None,
        *,
        conversation_id: str | None = None,
    ) -> MaskResult:
        """
        Detect sensitive entities and replace them with placeholders.

        Args:
            text: The input text (prompt, document chunk, etc.).
            correlation_id: Caller-supplied ID to link mask/rehydrate calls.
                            Generated if omitted.
            conversation_id: When set, the vault entry lives for the whole
                             conversation (CONVERSATION_TTL) instead of a single
                             request lifecycle.

        Returns:
            MaskResult with masked text and the correlation_id to pass to rehydrate().
        """
        if correlation_id is None:
            correlation_id = str(uuid.uuid4())

        spans = self._ensemble.detect(text)

        if not spans:
            return MaskResult(
                text=text,
                correlation_id=correlation_id,
                entity_counts={},
            )

        masked_text, placeholder_map = self._masker.mask(text, spans)

        ttl = (
            Vault.CONVERSATION_TTL if conversation_id else self._vault_ttl
        )
        vault_key = conversation_id or correlation_id
        self._vault.store(vault_key, placeholder_map, ttl=ttl)

        entity_counts: dict[str, int] = defaultdict(int)
        for span in spans:
            entity_counts[span.entity_type.value] += 1

        return MaskResult(
            text=masked_text,
            correlation_id=correlation_id,
            entity_counts=dict(entity_counts),
        )

    # ------------------------------------------------------------------
    # Rehydration — batch
    # ------------------------------------------------------------------

    def rehydrate(
        self,
        text: str,
        correlation_id: str,
        *,
        conversation_id: str | None = None,
    ) -> RehydrateResult:
        """
        Replace placeholders in text with their original values from the vault.

        Args:
            text: The text containing placeholders (LLM response, etc.).
            correlation_id: The ID returned by mask().
            conversation_id: If the mask() call used a conversation_id, pass the
                             same value here.
        """
        vault_key = conversation_id or correlation_id
        try:
            placeholder_map = self._vault.get(vault_key)
        except VaultNotFoundError:
            return RehydrateResult(text=text, correlation_id=correlation_id, rehydrated_count=0)
        except VaultExpiredError:
            return RehydrateResult(text=text, correlation_id=correlation_id, rehydrated_count=0)

        rehydrated_text, count = self._rehydrator.rehydrate(text, placeholder_map)
        return RehydrateResult(
            text=rehydrated_text,
            correlation_id=correlation_id,
            rehydrated_count=count,
        )

    # ------------------------------------------------------------------
    # Rehydration — streaming
    # ------------------------------------------------------------------

    def streaming_rehydrator(
        self,
        correlation_id: str,
        *,
        conversation_id: str | None = None,
    ) -> StreamingRehydrator:
        """
        Return a StreamingRehydrator for chunk-by-chunk rehydration.

        The caller feeds chunks into the returned object and collects output.
        Must call .flush() at end of stream.

        Example::

            r = engine.streaming_rehydrator(correlation_id)
            for chunk in sse_stream():
                yield r.feed(chunk)
            yield r.flush()
        """
        vault_key = conversation_id or correlation_id
        try:
            placeholder_map = self._vault.get(vault_key)
        except (VaultNotFoundError, VaultExpiredError):
            placeholder_map = {}

        return StreamingRehydrator(placeholder_map)

    # ------------------------------------------------------------------
    # Vault management
    # ------------------------------------------------------------------

    def delete_vault_entry(self, correlation_id: str) -> bool:
        """Purge a vault entry (right-to-erasure, D12)."""
        return self._vault.delete(correlation_id)

    def purge_expired(self) -> int:
        """Remove expired vault entries. Call from a maintenance task."""
        return self._vault.purge_expired()
