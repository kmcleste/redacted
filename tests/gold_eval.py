"""
Gold-set evaluation — the offline precision/recall gate (PRD §12).

Run with:  python -m tests.gold_eval

Reports per-entity-type precision, recall, F1.
Gate: recall ≥ 0.99 for SSN/CREDIT_CARD/secrets; ≥ 0.95 for EMAIL/PHONE.
CI should fail if any gated threshold is not met.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from src.engine.detectors.ensemble import DetectionEnsemble
from src.engine.entities import EntityType

# ---------------------------------------------------------------------------
# Gold dataset
# ---------------------------------------------------------------------------

@dataclass
class GoldSample:
    text: str
    expected: list[tuple[int, int, EntityType]]  # (start, end, type)
    description: str = ""


GOLD_SET: list[GoldSample] = [
    # SSN
    GoldSample(
        "Patient SSN is 575-82-8889.",
        [(15, 26, EntityType.SSN)],
        "formatted SSN with label",
    ),
    GoldSample(
        "social security 575828889",
        [(16, 25, EntityType.SSN)],
        "bare SSN with 'social security' context",
    ),
    GoldSample(
        "order 123456789 placed",  # bare digits, no SSN context
        [],
        "bare 9-digit number with no context — must NOT fire",
    ),
    # Credit card
    GoldSample(
        "Visa ending 4532015112830366",
        [(12, 28, EntityType.CREDIT_CARD)],
        "valid Visa number",
    ),
    GoldSample(
        "test card 4111111111111111",  # test card denylist
        [],
        "known test card — must NOT fire",
    ),
    # Email
    GoldSample(
        "Send results to claims@healthco.com",
        [(16, 35, EntityType.EMAIL)],
        "real email address",
    ),
    GoldSample(
        "See user@example.com",  # documentation domain
        [],
        "documentation email — must NOT fire",
    ),
    # IP
    GoldSample(
        "Server IP: 8.8.8.8",
        [(11, 18, EntityType.IP_ADDRESS)],
        "public IP",
    ),
    GoldSample(
        "192.0.2.1 is documentation",  # TEST-NET
        [],
        "reserved IP — must NOT fire",
    ),
    # Phone
    GoldSample(
        "Call (415) 832-9000",
        [(5, 19, EntityType.PHONE)],
        "US phone with area code",
    ),
    # AWS key
    GoldSample(
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        [(23, 43, EntityType.AWS_KEY)],
        "AWS access key",
    ),
    # GitHub token
    GoldSample(
        "token: ghp_" + "A" * 36,
        [(7, 7 + 4 + 36, EntityType.GITHUB_TOKEN)],
        "GitHub personal access token",
    ),
    # PEM block
    GoldSample(
        "key: -----BEGIN PRIVATE KEY-----\nABC",
        [(5, 31, EntityType.PEM_BLOCK)],
        "PEM private key header",
    ),
    # Connection string
    GoldSample(
        "DATABASE_URL=postgres://user:pass@db:5432/app",
        [(13, 45, EntityType.CONNECTION_STRING)],
        "postgres connection string",
    ),
    # Adversarial: spaced-out SSN
    GoldSample(
        "social 5 7 5 - 8 2 - 8 8 8 9",  # unusual spacing
        [],  # Difficult adversarial case; not expected to detect in Phase 1
        "adversarial: spaced-out SSN (Phase 1 baseline, may miss)",
    ),
]

# ---------------------------------------------------------------------------
# Evaluation logic
# ---------------------------------------------------------------------------

RECALL_GATES: dict[EntityType, float] = {
    EntityType.SSN: 0.99,
    EntityType.CREDIT_CARD: 0.99,
    EntityType.AWS_KEY: 0.99,
    EntityType.GITHUB_TOKEN: 0.99,
    EntityType.PEM_BLOCK: 0.99,
    EntityType.EMAIL: 0.95,
    EntityType.PHONE: 0.90,
}


@dataclass
class EntityMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def _spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def evaluate() -> dict[str, EntityMetrics]:
    ensemble = DetectionEnsemble()
    metrics: dict[str, EntityMetrics] = {}

    def _m(et: EntityType) -> EntityMetrics:
        key = et.value
        if key not in metrics:
            metrics[key] = EntityMetrics()
        return metrics[key]

    for sample in GOLD_SET:
        detected = ensemble.detect(sample.text)

        # For each expected span, check if it was detected (TP/FN).
        for exp_start, exp_end, exp_type in sample.expected:
            m = _m(exp_type)
            matched = any(
                s.entity_type == exp_type and _spans_overlap(s.start, s.end, exp_start, exp_end)
                for s in detected
            )
            if matched:
                m.tp += 1
            else:
                m.fn += 1

        # For each detected span, check if it matches an expected span (FP).
        for span in detected:
            m = _m(span.entity_type)
            matched = any(
                exp_type == span.entity_type
                and _spans_overlap(span.start, span.end, exp_start, exp_end)
                for exp_start, exp_end, exp_type in sample.expected
            )
            if not matched:
                m.fp += 1

    return metrics


def main() -> None:
    print("=" * 60)
    print("Gold-Set Evaluation Report")
    print("=" * 60)
    metrics = evaluate()
    gate_failures: list[str] = []

    all_types = sorted(metrics.keys())
    for key in all_types:
        m = metrics[key]
        et = EntityType(key)
        gate = RECALL_GATES.get(et)
        gate_str = f" [gate ≥{gate:.0%}]" if gate else ""
        status = "✓" if (gate is None or m.recall >= gate) else "✗"
        print(
            f"  {status} {key:25s}  P={m.precision:.2f}  R={m.recall:.2f}  F1={m.f1:.2f}"
            f"  (TP={m.tp} FP={m.fp} FN={m.fn}){gate_str}"
        )
        if gate and m.recall < gate:
            gate_failures.append(f"{key}: recall {m.recall:.2f} < gate {gate:.2f}")

    print()
    if gate_failures:
        print(f"FAIL — {len(gate_failures)} recall gate(s) not met:")
        for f in gate_failures:
            print(f"  {f}")
        sys.exit(1)
    else:
        print("PASS — all recall gates met.")


if __name__ == "__main__":
    main()
