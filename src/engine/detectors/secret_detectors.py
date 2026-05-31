"""
Secret detectors: AWS keys, GitHub tokens, PEM blocks, connection strings.

High-precision, high-priority lane — these fire regardless of modality
(D9: secrets are never suppressed by the code-traffic policy).
"""

from __future__ import annotations

import re

from ..entities import DetectedSpan, EntityType
from .base import BaseDetector

# ---------------------------------------------------------------------------
# Patterns (compiled once at import)
# ---------------------------------------------------------------------------

# AWS access key ID prefixes: AKIA (long-term), ABIA (STS), ACCA (context), ASIA (STS temp)
_AWS_ACCESS_KEY = re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b")

# AWS secret access key: 40-char base64url string following "aws_secret" context
_AWS_SECRET_CONTEXT = re.compile(
    r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret)\s*[=:]\s*([A-Za-z0-9+/]{40})"
)

# GitHub tokens
_GITHUB_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"
)

# PEM block header/footer (certificates, private keys, etc.)
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z ]{1,40}-----")

# Connection strings: postgres, mysql, mongodb, redis, amqp, smtp, mssql
_CONNECTION_STRING = re.compile(
    r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqps?|smtps?|mssql)"
    r"://[^\"'\s]{6,}"
)

# Generic high-entropy secret patterns (API keys, tokens with keyword context)
_GENERIC_SECRET = re.compile(
    r"(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?key|auth[_\-]?token)"
    r"\s*[=:\"']\s*([A-Za-z0-9+/=_\-]{16,})"
)


class SecretDetector(BaseDetector):

    @property
    def name(self) -> str:
        return "SecretDetector"

    def detect(self, text: str) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        self._find(text, _AWS_ACCESS_KEY, EntityType.AWS_KEY, spans, score=0.99)
        self._find(text, _AWS_SECRET_CONTEXT, EntityType.AWS_KEY, spans, score=0.99, group=1)
        self._find(text, _GITHUB_TOKEN, EntityType.GITHUB_TOKEN, spans, score=0.99)
        self._find(text, _PEM_BLOCK, EntityType.PEM_BLOCK, spans, score=0.99)
        self._find(text, _CONNECTION_STRING, EntityType.CONNECTION_STRING, spans, score=0.95)
        self._find(text, _GENERIC_SECRET, EntityType.GENERIC_SECRET, spans, score=0.90, group=1)
        return sorted(spans, key=lambda s: s.start)

    @staticmethod
    def _find(
        text: str,
        pattern: re.Pattern[str],
        entity_type: EntityType,
        spans: list[DetectedSpan],
        *,
        score: float,
        group: int = 0,
    ) -> None:
        for m in pattern.finditer(text):
            start = m.start(group)
            end = m.end(group)
            spans.append(
                DetectedSpan(
                    start=start,
                    end=end,
                    entity_type=entity_type,
                    original_value=m.group(group),
                    score=score,
                )
            )
