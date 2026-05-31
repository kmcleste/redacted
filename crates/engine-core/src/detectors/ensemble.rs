/*!
Detection ensemble: pre-filter → hard-RT deterministic lane → soft-RT NER stub.

Overlap resolution: when spans overlap, the higher-scoring span wins; on a tie,
the longer one wins. O(n log n) — greedy sweep after sort.

Each detector is tagged with a hint bitmask (from `prefilter`). The pre-filter
scans for AC keywords + fast ASCII patterns and returns a `DetectorHints`
bitmask; detectors whose bits don't overlap with the mask are skipped entirely.
*/

use crate::{
    entities::DetectedSpan,
    policy::{Decision, PolicyBundle},
};

use super::{
    pii::*,
    prefilter::{
        scan_hints, DetectorHints, HINT_CONNECTION, HINT_DOMAIN, HINT_EMAIL, HINT_NER, HINT_SECRET,
        HINT_STRUCTURED_PII,
    },
    secrets::SecretDetector,
    Detector,
};

fn resolve_overlaps(mut spans: Vec<DetectedSpan>) -> Vec<DetectedSpan> {
    if spans.len() <= 1 {
        return spans;
    }
    // Sort: ascending start, then descending score, then descending length.
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(b.len().cmp(&a.len()))
    });

    let mut result: Vec<DetectedSpan> = Vec::with_capacity(spans.len());
    let mut last_end: usize = 0;

    for span in spans {
        if span.start >= last_end {
            last_end = span.end;
            result.push(span);
        } else if let Some(prev) = result.last_mut() {
            // Spans overlap — keep the better one.
            if span.score > prev.score || (span.score == prev.score && span.len() > prev.len()) {
                last_end = span.end;
                *prev = span;
            }
        }
    }

    result
}

pub struct DetectionEnsemble {
    policy: PolicyBundle,
    /// Each entry is (detector, hint_bits). The ensemble skips any detector
    /// whose `hint_bits` share no overlap with the pre-filter result.
    detectors: Vec<(Box<dyn Detector>, u32)>,
}

impl DetectionEnsemble {
    pub fn new(policy: PolicyBundle) -> Self {
        let detectors: Vec<(Box<dyn Detector>, u32)> = vec![
            (Box::new(SsnDetector), HINT_STRUCTURED_PII),
            (Box::new(CreditCardDetector), HINT_STRUCTURED_PII),
            (
                Box::new(BankRoutingDetector),
                HINT_STRUCTURED_PII | HINT_DOMAIN,
            ),
            (
                Box::new(BankAccountDetector),
                HINT_STRUCTURED_PII | HINT_DOMAIN,
            ),
            (Box::new(EmailDetector), HINT_EMAIL),
            (Box::new(PhoneDetector), HINT_STRUCTURED_PII),
            (
                Box::new(IpAddressDetector),
                HINT_STRUCTURED_PII | HINT_CONNECTION,
            ),
            (Box::new(VinDetector), HINT_STRUCTURED_PII | HINT_NER),
            (Box::new(NpiDetector), HINT_DOMAIN | HINT_STRUCTURED_PII),
            (
                Box::new(DomainIdentifierDetector),
                HINT_DOMAIN | HINT_STRUCTURED_PII | HINT_NER,
            ),
            (
                Box::new(DateOfBirthDetector),
                HINT_STRUCTURED_PII | HINT_NER,
            ),
            (Box::new(SecretDetector), HINT_SECRET | HINT_CONNECTION),
        ];
        Self { policy, detectors }
    }

    /// Run the full cascade and return deduplicated, policy-filtered spans.
    pub fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let hints: DetectorHints = scan_hints(text);
        if !hints.any() {
            return Vec::new();
        }

        let mut raw: Vec<DetectedSpan> = Vec::new();

        for (detector, hint_bits) in &self.detectors {
            if !hints.has(*hint_bits) {
                // Pre-filter: no relevant signals for this detector — skip.
                continue;
            }
            // Detector panics must not propagate — emit a metric in production.
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| detector.detect(text)));
            if let Ok(spans) = result {
                raw.extend(spans);
            }
        }

        // NER soft-RT lane: Phase 3 stub.
        // raw.extend(self.ner_lane(text));

        let filtered: Vec<DetectedSpan> = raw
            .into_iter()
            .filter(|s| self.policy.decide(s.entity_type, s.score) == Decision::Mask)
            .collect();

        resolve_overlaps(filtered)
    }

    pub fn policy(&self) -> &PolicyBundle {
        &self.policy
    }
}
