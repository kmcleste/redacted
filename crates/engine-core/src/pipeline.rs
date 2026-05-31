/*!
Engine — the public facade wiring all components together.

`Engine` is `Clone + Send + Sync` and is designed to be shared across async
handler threads (e.g., the gRPC server) behind an `Arc`.
*/

use std::{collections::HashMap, sync::Arc};

use uuid::Uuid;

use crate::{
    detectors::ensemble::DetectionEnsemble,
    entities::{DetectedSpan, EntityType, MaskResult, RehydrateResult},
    error::EngineError,
    masker::Masker,
    policy::PolicyBundle,
    rehydrator::BatchRehydrator,
    streaming::StreamingRehydrator,
    vault::{Vault, DEFAULT_TTL, CONVERSATION_TTL},
};

#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    ensemble: DetectionEnsemble,
    masker: Masker,
    rehydrator: BatchRehydrator,
    vault: Arc<Vault>,
}

impl Engine {
    pub fn new(policy: PolicyBundle) -> Self {
        Self {
            inner: Arc::new(EngineInner {
                ensemble: DetectionEnsemble::new(policy),
                masker: Masker,
                rehydrator: BatchRehydrator,
                vault: Arc::new(Vault::new()),
            }),
        }
    }

    pub fn with_default_policy() -> Self {
        Self::new(PolicyBundle::default())
    }

    // ------------------------------------------------------------------ //
    // Detection                                                            //
    // ------------------------------------------------------------------ //

    pub fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        self.inner.ensemble.detect(text)
    }

    // ------------------------------------------------------------------ //
    // Masking                                                              //
    // ------------------------------------------------------------------ //

    pub fn mask(
        &self,
        text: &str,
        correlation_id: Option<&str>,
        conversation_id: Option<&str>,
    ) -> MaskResult {
        let correlation_id = correlation_id
            .map(String::from)
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let spans = self.inner.ensemble.detect(text);

        if spans.is_empty() {
            return MaskResult {
                text: text.to_string(),
                correlation_id,
                entity_counts: HashMap::new(),
            };
        }

        let (masked_text, placeholder_map) = self.inner.masker.mask(text, &spans);

        let ttl = if conversation_id.is_some() { CONVERSATION_TTL } else { DEFAULT_TTL };
        let vault_key = conversation_id.unwrap_or(&correlation_id);
        self.inner.vault.store(vault_key, placeholder_map, ttl);

        let mut entity_counts: HashMap<EntityType, usize> = HashMap::new();
        for span in &spans {
            *entity_counts.entry(span.entity_type).or_insert(0) += 1;
        }

        MaskResult {
            text: masked_text,
            correlation_id,
            entity_counts,
        }
    }

    // ------------------------------------------------------------------ //
    // Batch rehydration                                                    //
    // ------------------------------------------------------------------ //

    pub fn rehydrate(
        &self,
        text: &str,
        correlation_id: &str,
        conversation_id: Option<&str>,
    ) -> RehydrateResult {
        let vault_key = conversation_id.unwrap_or(correlation_id);
        let map = match self.inner.vault.get(vault_key) {
            Ok(m) => m,
            Err(EngineError::VaultNotFound(_) | EngineError::VaultExpired(_)) => {
                return RehydrateResult {
                    text: text.to_string(),
                    correlation_id: correlation_id.to_string(),
                    rehydrated_count: 0,
                }
            }
            Err(e) => {
                // Crypto error — fail closed: return original text, don't crash.
                eprintln!("vault error during rehydration: {e}");
                return RehydrateResult {
                    text: text.to_string(),
                    correlation_id: correlation_id.to_string(),
                    rehydrated_count: 0,
                }
            }
        };

        let (rehydrated_text, count) = self.inner.rehydrator.rehydrate(text, &map);
        RehydrateResult {
            text: rehydrated_text,
            correlation_id: correlation_id.to_string(),
            rehydrated_count: count,
        }
    }

    // ------------------------------------------------------------------ //
    // Streaming rehydration                                                //
    // ------------------------------------------------------------------ //

    pub fn streaming_rehydrator(
        &self,
        correlation_id: &str,
        conversation_id: Option<&str>,
    ) -> StreamingRehydrator {
        let vault_key = conversation_id.unwrap_or(correlation_id);
        let map = self.inner.vault.get(vault_key).unwrap_or_default();
        StreamingRehydrator::new(map)
    }

    // ------------------------------------------------------------------ //
    // Vault management                                                     //
    // ------------------------------------------------------------------ //

    pub fn delete_vault_entry(&self, correlation_id: &str) -> bool {
        self.inner.vault.delete(correlation_id)
    }

    pub fn purge_expired(&self) -> usize {
        self.inner.vault.purge_expired()
    }
}
