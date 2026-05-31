"""Base detector interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..entities import DetectedSpan


class BaseDetector(ABC):
    """All detectors share this interface."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def detect(self, text: str) -> list[DetectedSpan]:
        """Return all detected spans in text, sorted by start position."""
        ...
