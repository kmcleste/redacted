"""
Policy engine: per-entity-type configuration, exemptions, and decisions.

Policy is evaluated as data — no logic baked into the library binary.
The control plane distributes versioned PolicyBundle objects to all data-plane
instances; they hot-reload without restarting. (Control plane is a Phase 3
concern; Phase 1 uses in-process policy loaded from config.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

from .entities import EntityType


class Decision(Enum):
    MASK = auto()    # Detect and replace with placeholder.
    SKIP = auto()    # Detected but explicitly exempted; pass through.
    FAIL_CLOSED = auto()  # Unable to evaluate; block the request.


class Modality(Enum):
    PROSE = "prose"         # Default: full PII + PHI scan.
    CODE = "code"           # Secrets prioritised; fuzzy NER suppressed.
    DOCUMENT = "document"   # Treat as prose (possibly richer content).


@dataclass
class EntityPolicy:
    enabled: bool = True
    threshold: float = 0.5
    fail_closed: bool = True

    def decide(self, score: float) -> Decision:
        if not self.enabled:
            return Decision.SKIP
        if score >= self.threshold:
            return Decision.MASK
        return Decision.SKIP


_DEFAULT_THRESHOLDS: dict[EntityType, float] = {
    EntityType.SSN: 0.85,
    EntityType.CREDIT_CARD: 0.80,
    EntityType.BANK_ROUTING: 0.75,
    EntityType.BANK_ACCOUNT: 0.70,
    EntityType.NPI: 0.80,
    EntityType.DATE_OF_BIRTH: 0.75,
    EntityType.MEDICAL_RECORD: 0.70,
    EntityType.AWS_KEY: 0.99,
    EntityType.GITHUB_TOKEN: 0.99,
    EntityType.PEM_BLOCK: 0.99,
    EntityType.CONNECTION_STRING: 0.95,
    EntityType.GENERIC_SECRET: 0.90,
    EntityType.PERSON: 0.70,
    EntityType.ORG: 0.60,
    EntityType.ADDRESS: 0.65,
}


@dataclass
class PolicyBundle:
    """
    Versioned, hot-reloadable policy data distributed by the control plane.
    Phase 1: instantiated inline; Phase 3: deserialized from signed bundle.
    """

    version: str = "0.1.0"
    default_fail_closed: bool = True
    entity_policies: dict[EntityType, EntityPolicy] = field(default_factory=dict)
    modality: Modality = Modality.PROSE

    def __post_init__(self) -> None:
        for entity_type in EntityType:
            if entity_type not in self.entity_policies:
                threshold = _DEFAULT_THRESHOLDS.get(entity_type, 0.5)
                self.entity_policies[entity_type] = EntityPolicy(
                    enabled=True,
                    threshold=threshold,
                    fail_closed=self.default_fail_closed,
                )

    def decide(self, entity_type: EntityType, score: float) -> Decision:
        policy = self.entity_policies.get(entity_type)
        if policy is None:
            return Decision.MASK if self.default_fail_closed else Decision.SKIP
        return policy.decide(score)

    def is_enabled(self, entity_type: EntityType) -> bool:
        policy = self.entity_policies.get(entity_type)
        return policy.enabled if policy else True

    @classmethod
    def for_code_traffic(cls) -> PolicyBundle:
        """Relaxed policy for confirmed code-channel traffic (D9)."""
        bundle = cls(modality=Modality.CODE)
        # Suppress fuzzy NER in code; secrets stay at max priority.
        for ner_type in (EntityType.PERSON, EntityType.ORG, EntityType.ADDRESS):
            bundle.entity_policies[ner_type] = EntityPolicy(enabled=False)
        return bundle

    @classmethod
    def default(cls) -> PolicyBundle:
        return cls()
