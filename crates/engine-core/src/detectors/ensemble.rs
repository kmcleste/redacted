/*!
Detection ensemble: pre-filter → hard-RT deterministic lane → soft-RT NER stub.

Overlap resolution: when spans overlap, the higher-scoring span wins; on a tie,
the longer one wins. O(n log n) — greedy sweep after sort.
*/

use crate::{
    entities::DetectedSpan,
    policy::{Decision, PolicyBundle},
};

use super::{
    pii::*,
    secrets::SecretDetector,
    prefilter::should_scan,
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
            .then(b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
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
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectionEnsemble {
    pub fn new(policy: PolicyBundle) -> Self {
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(SsnDetector),
            Box::new(CreditCardDetector),
            Box::new(BankRoutingDetector),
            Box::new(BankAccountDetector),
            Box::new(EmailDetector),
            Box::new(PhoneDetector),
            Box::new(IpAddressDetector),
            Box::new(VinDetector),
            Box::new(NpiDetector),
            Box::new(DomainIdentifierDetector),
            Box::new(DateOfBirthDetector),
            Box::new(SecretDetector),
        ];
        Self { policy, detectors }
    }

    /// Run the full cascade and return deduplicated, policy-filtered spans.
    pub fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        if !should_scan(text) {
            return Vec::new();
        }

        let mut raw: Vec<DetectedSpan> = Vec::new();

        for detector in &self.detectors {
            // Detector panics must not propagate — emit a metric in production.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                detector.detect(text)
            }));
            if let Ok(spans) = result {
                raw.extend(spans);
            }
        }

        // NER soft-RT lane: Phase 2 stub.
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
