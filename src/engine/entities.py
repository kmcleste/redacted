"""Entity type definitions, span dataclasses, and result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EntityType(str, Enum):
    # Structured PII
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    BANK_ROUTING = "BANK_ROUTING"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IP_ADDRESS = "IP_ADDRESS"
    VIN = "VIN"

    # Domain / insurance identifiers
    POLICY_NUMBER = "POLICY_NUMBER"
    CLAIM_ID = "CLAIM_ID"
    MEMBER_ID = "MEMBER_ID"
    GROUP_ID = "GROUP_ID"
    NPI = "NPI"

    # PHI (HIPAA)
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    MEDICAL_RECORD = "MEDICAL_RECORD"

    # Secrets
    AWS_KEY = "AWS_KEY"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    PEM_BLOCK = "PEM_BLOCK"
    CONNECTION_STRING = "CONNECTION_STRING"
    GENERIC_SECRET = "GENERIC_SECRET"

    # NER-lane (soft real-time; not populated by deterministic detectors)
    PERSON = "PERSON"
    ADDRESS = "ADDRESS"
    ORG = "ORG"


# Entity types that belong to the secret-detector category.
SECRET_ENTITY_TYPES: frozenset[EntityType] = frozenset(
    {
        EntityType.AWS_KEY,
        EntityType.GITHUB_TOKEN,
        EntityType.PEM_BLOCK,
        EntityType.CONNECTION_STRING,
        EntityType.GENERIC_SECRET,
    }
)

# Entity types that require HIPAA / PHI handling.
PHI_ENTITY_TYPES: frozenset[EntityType] = frozenset(
    {
        EntityType.DATE_OF_BIRTH,
        EntityType.MEDICAL_RECORD,
        EntityType.NPI,
        EntityType.MEMBER_ID,
    }
)


@dataclass(frozen=True, slots=True)
class DetectedSpan:
    """A single detected sensitive entity within a text."""

    start: int
    end: int
    entity_type: EntityType
    original_value: str
    score: float = 1.0

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class MaskResult:
    """Output of the masking stage."""

    text: str
    correlation_id: str
    entity_counts: dict[str, int] = field(default_factory=dict)

    @property
    def was_masked(self) -> bool:
        return bool(self.entity_counts)


@dataclass
class RehydrateResult:
    """Output of the rehydration stage."""

    text: str
    correlation_id: str
    rehydrated_count: int = 0
