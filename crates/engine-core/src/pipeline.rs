/*!
Engine — the public facade wiring all components together.

`Engine` is `Clone + Send + Sync` and designed to be shared across async
handler threads behind an `Arc`.

Hot-reload: `reload_policy` atomically swaps the detection ensembles using
`arc_swap` while keeping the in-process vault intact. All in-flight requests
complete against the old policy; new requests pick up the new one.
*/

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use uuid::Uuid;

use crate::{
    audit::{self, AuditEvent},
    detectors::ensemble::DetectionEnsemble,
    entities::{EntityType, MaskResult, RehydrateResult},
    error::EngineError,
    masker::Masker,
    metrics as eng_metrics,
    modality::{self, Modality, ProvenanceCtx, TrustedCodeChannels},
    policy::PolicyBundle,
    rehydrator::BatchRehydrator,
    streaming::StreamingRehydrator,
    vault::{Vault, CONVERSATION_TTL, DEFAULT_TTL},
};

// ---------------------------------------------------------------------------
// EngineCore — the hot-swappable part (policy + ensembles)
// ---------------------------------------------------------------------------

struct EngineCore {
    ensemble_prose: DetectionEnsemble,
    ensemble_code: DetectionEnsemble,
    masker: Masker,
    rehydrator: BatchRehydrator,
    trusted_channels: TrustedCodeChannels,
}

// ---------------------------------------------------------------------------
// Engine — public handle
// ---------------------------------------------------------------------------

/// Shared, cheaply cloneable engine handle.
///
/// Clones share the same vault and the same `ArcSwap` swap-cell, so a
/// `reload_policy` call on any clone is visible to all others immediately.
#[derive(Clone)]
pub struct Engine {
    core: Arc<ArcSwap<EngineCore>>,
    vault: Arc<Vault>,
}

impl Engine {
    pub fn new(policy: PolicyBundle) -> Self {
        Self::with_trusted_channels(policy, TrustedCodeChannels::new(std::iter::empty::<&str>()))
    }

    pub fn with_trusted_channels(
        policy: PolicyBundle,
        trusted_channels: TrustedCodeChannels,
    ) -> Self {
        let core = EngineCore {
            ensemble_prose: DetectionEnsemble::new(policy),
            ensemble_code: DetectionEnsemble::new(PolicyBundle::for_code_traffic()),
            masker: Masker,
            rehydrator: BatchRehydrator,
            trusted_channels,
        };
        Self {
            core: Arc::new(ArcSwap::from(Arc::new(core))),
            vault: Arc::new(Vault::new()),
        }
    }

    pub fn with_default_policy() -> Self {
        Self::new(PolicyBundle::default())
    }

    // ------------------------------------------------------------------ //
    // Hot-reload                                                           //
    // ------------------------------------------------------------------ //

    /// Atomically replace the detection policy. In-flight requests finish
    /// with the old policy; new requests pick up `policy` immediately.
    /// The vault is preserved across reloads.
    pub fn reload_policy(&self, policy: PolicyBundle) {
        let current = self.core.load();
        let trusted_channels = current.trusted_channels.clone();
        let new_core = EngineCore {
            ensemble_prose: DetectionEnsemble::new(policy),
            ensemble_code: DetectionEnsemble::new(PolicyBundle::for_code_traffic()),
            masker: Masker,
            rehydrator: BatchRehydrator,
            trusted_channels,
        };
        self.core.store(Arc::new(new_core));
        tracing::info!("engine policy hot-reloaded");
    }

    /// Access the shared vault (e.g., to pass to a rebuilt engine on reload).
    pub fn vault(&self) -> Arc<Vault> {
        Arc::clone(&self.vault)
    }

    // ------------------------------------------------------------------ //
    // Detection                                                            //
    // ------------------------------------------------------------------ //

    pub fn detect(&self, text: &str) -> Vec<crate::entities::DetectedSpan> {
        let _t = eng_metrics::detect_timer();
        self.core.load().ensemble_prose.detect(text)
    }

    // ------------------------------------------------------------------ //
    // Masking                                                              //
    // ------------------------------------------------------------------ //

    /// Mask `text` with the default (Prose) policy.
    pub fn mask(
        &self,
        text: &str,
        correlation_id: Option<&str>,
        conversation_id: Option<&str>,
    ) -> MaskResult {
        self.mask_impl(text, correlation_id, conversation_id, None)
    }

    /// Mask `text` with modality resolved from `provenance` (D9).
    ///
    /// A trusted code channel receiving a Code hint gets the relaxed
    /// secrets-only policy; all other combinations fall back to Prose.
    pub fn mask_with_provenance(
        &self,
        text: &str,
        correlation_id: Option<&str>,
        conversation_id: Option<&str>,
        provenance: &ProvenanceCtx,
    ) -> MaskResult {
        self.mask_impl(text, correlation_id, conversation_id, Some(provenance))
    }

    fn mask_impl(
        &self,
        text: &str,
        correlation_id: Option<&str>,
        conversation_id: Option<&str>,
        provenance: Option<&ProvenanceCtx>,
    ) -> MaskResult {
        let _t = eng_metrics::mask_timer();

        let correlation_id = correlation_id
            .map(String::from)
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let core = self.core.load();

        let resolved_modality = provenance.map_or(Modality::Prose, |ctx| {
            modality::resolve_modality(ctx, &core.trusted_channels)
        });

        let ensemble = match resolved_modality {
            Modality::Code => &core.ensemble_code,
            _ => &core.ensemble_prose,
        };

        let spans = ensemble.detect(text);

        if spans.is_empty() {
            return MaskResult {
                text: text.to_string(),
                correlation_id,
                entity_counts: HashMap::new(),
            };
        }

        // Accumulate per-entity-type counts for metrics + result.
        let mut entity_counts: HashMap<EntityType, usize> = HashMap::new();
        for span in &spans {
            *entity_counts.entry(span.entity_type).or_insert(0) += 1;
        }
        for (&et, &cnt) in &entity_counts {
            eng_metrics::record_entities_detected(et.as_str(), cnt as u64);
        }

        let (masked_text, placeholder_map) = core.masker.mask(text, &spans);

        let ttl = if conversation_id.is_some() {
            CONVERSATION_TTL
        } else {
            DEFAULT_TTL
        };
        let vault_key = conversation_id.unwrap_or(&correlation_id);
        self.vault.store(vault_key, placeholder_map, ttl);
        eng_metrics::record_vault_op("store");
        audit::emit_with_count(AuditEvent::VaultStore, vault_key, entity_counts.len());

        // Egress canary — scan the masked payload for residual PII.
        // Runs the full prose ensemble; never blocks the response.
        let canary_spans = core.ensemble_prose.detect(&masked_text);
        for span in &canary_spans {
            eng_metrics::record_canary_hit(span.entity_type.as_str());
            tracing::warn!(
                entity_type = span.entity_type.as_str(),
                "egress canary: residual PII in masked payload"
            );
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
        let _t = eng_metrics::rehydrate_timer();

        let vault_key = conversation_id.unwrap_or(correlation_id);
        let map = match self.vault.get(vault_key) {
            Ok(m) => {
                eng_metrics::record_vault_op("get");
                audit::emit(AuditEvent::VaultAccess, vault_key);
                m
            }
            Err(EngineError::VaultNotFound(_) | EngineError::VaultExpired(_)) => {
                return RehydrateResult {
                    text: text.to_string(),
                    correlation_id: correlation_id.to_string(),
                    rehydrated_count: 0,
                }
            }
            Err(e) => {
                tracing::error!("vault error during rehydration: {e}");
                return RehydrateResult {
                    text: text.to_string(),
                    correlation_id: correlation_id.to_string(),
                    rehydrated_count: 0,
                };
            }
        };

        let core = self.core.load();
        let (rehydrated_text, count, misses) = core.rehydrator.rehydrate(text, &map);
        eng_metrics::record_rehydrate_mismatches(misses as u64);

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
        let map = match self.vault.get(vault_key) {
            Ok(m) => {
                eng_metrics::record_vault_op("get");
                audit::emit(AuditEvent::VaultAccess, vault_key);
                m
            }
            Err(_) => {
                tracing::debug!("streaming_rehydrator: vault miss for {vault_key}");
                HashMap::new()
            }
        };
        StreamingRehydrator::new(map)
    }

    // ------------------------------------------------------------------ //
    // Vault management                                                     //
    // ------------------------------------------------------------------ //

    pub fn delete_vault_entry(&self, correlation_id: &str) -> bool {
        let deleted = self.vault.delete(correlation_id);
        if deleted {
            eng_metrics::record_vault_op("delete");
            audit::emit(AuditEvent::VaultDelete, correlation_id);
        }
        deleted
    }

    pub fn purge_expired(&self) -> usize {
        let count = self.vault.purge_expired();
        if count > 0 {
            eng_metrics::record_vault_op("purge");
            audit::emit_with_count(AuditEvent::VaultExpire, "batch", count);
        }
        count
    }
}
