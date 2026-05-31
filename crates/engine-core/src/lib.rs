pub mod detectors;
pub mod entities;
pub mod error;
pub mod masker;
pub mod metrics;
pub mod modality;
pub mod pipeline;
pub mod policy;
pub mod rehydrator;
pub mod streaming;
pub mod validators;
pub mod vault;

// Convenience re-exports for the most common types.
pub use entities::{DetectedSpan, EntityType, MaskResult, RehydrateResult};
pub use error::{EngineError, Result};
pub use modality::{Modality, ProvenanceCtx, TrustedCodeChannels};
pub use pipeline::Engine;
pub use policy::PolicyBundle;
pub use streaming::StreamingRehydrator;
pub use vault::Vault;
