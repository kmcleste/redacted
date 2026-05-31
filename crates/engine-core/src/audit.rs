/*!
Structured audit log for vault lifecycle events (D12, D15).

Events are emitted as `tracing` events with `target = "engine_audit"`.
A log shipper (e.g., Vector, Fluentd) can filter on that target to build
a durable, append-only audit trail without coupling the engine to a
specific storage backend.

Only correlation IDs and event metadata are logged — no plaintext PII
ever appears in an audit event.
*/

/// Audit event category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    VaultStore,
    VaultAccess,
    VaultDelete,
    VaultExpire,
}

impl AuditEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::VaultStore => "vault.store",
            Self::VaultAccess => "vault.access",
            Self::VaultDelete => "vault.delete",
            Self::VaultExpire => "vault.expire",
        }
    }
}

/// Emit a vault lifecycle event for `correlation_id`.
pub fn emit(event: AuditEvent, correlation_id: &str) {
    tracing::info!(
        target: "engine_audit",
        event = event.as_str(),
        correlation_id = correlation_id,
    );
}

/// Emit a vault lifecycle event with an associated item count.
pub fn emit_with_count(event: AuditEvent, correlation_id: &str, count: usize) {
    tracing::info!(
        target: "engine_audit",
        event = event.as_str(),
        correlation_id = correlation_id,
        count = count,
    );
}
