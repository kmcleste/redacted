/*!
Modality and provenance routing (D9, §6).

Policy is a function of content modality:
- **Provenance is the primary signal** — gateway knows the consumer (API key /
  app / service account); authoritative and unspoofable from content.
- **Syntax is secondary** — structural confirmation only; never self-declaration.
- **Harm asymmetry governs ambiguity** — false positive in code = recoverable
  utility loss; false negative on a business document = a breach.  When signals
  disagree, fail toward the stricter (full PII) policy.

A trusted code channel must be allowlisted by the control plane; content alone
cannot move a request into the relaxed lane.
*/

use std::collections::HashSet;

/// The resolved modality for a single request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modality {
    /// Default: full PII + PHI + secrets scan.
    Prose,
    /// Confirmed code-channel traffic: secrets prioritised, fuzzy NER suppressed (D9).
    Code,
    /// Document uploads (HTML/PDF/Office): scan extracted text as prose.
    Document,
}

/// Request-level provenance signals supplied by the gateway.
#[derive(Debug, Default)]
pub struct ProvenanceCtx {
    /// Opaque channel identifier (e.g., "coding-agent", "support-chat").
    /// Set by the gateway from an authenticated API-key attribute; never
    /// trusted when supplied by the client payload itself.
    pub channel_id: Option<String>,
    /// Service account / application identity.
    pub app_id: Option<String>,
    /// Caller-supplied modality hint — treated as a suggestion, never as auth.
    pub hint: Option<Modality>,
}

/// Set of channel IDs that are authorised for the relaxed code-traffic policy.
/// In Phase 3 this lives in the control-plane policy bundle; here it's a local
/// allowlist loaded at startup.
pub struct TrustedCodeChannels(HashSet<String>);

impl TrustedCodeChannels {
    pub fn new(channels: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self(channels.into_iter().map(Into::into).collect())
    }

    pub fn is_trusted(&self, channel_id: &str) -> bool {
        self.0.contains(channel_id)
    }
}

/// Resolve the effective modality for a request.
///
/// Rules (in priority order):
/// 1. If `channel_id` is present and in `trusted_code_channels` AND the hint
///    confirms CODE → use Code policy.
/// 2. Any ambiguity or missing provenance → Prose (fail strict).
/// 3. Document hint without code → Document.
pub fn resolve_modality(ctx: &ProvenanceCtx, trusted: &TrustedCodeChannels) -> Modality {
    match (&ctx.channel_id, ctx.hint) {
        // Require both provenance trust AND caller hint to confirm Code.
        (Some(cid), Some(Modality::Code)) if trusted.is_trusted(cid) => Modality::Code,
        // Document hint accepted without special provenance.
        (_, Some(Modality::Document)) => Modality::Document,
        // Default: full PII scan (fail strict).
        _ => Modality::Prose,
    }
}
