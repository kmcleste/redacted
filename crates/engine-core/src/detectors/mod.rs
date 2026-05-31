pub mod ensemble;
pub mod patterns;
pub mod pii;
pub mod prefilter;
pub mod secrets;

use crate::entities::DetectedSpan;

/// Every detector implements this trait. Detectors must be `Send + Sync`
/// since the ensemble is shared across handler threads.
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, text: &str) -> Vec<DetectedSpan>;
}
