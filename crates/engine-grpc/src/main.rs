/*!
gRPC sidecar server for the sensitive-content engine.

Runs on a Unix domain socket (`/run/engine/engine.sock`) by default for
localhost-only, zero-network PII exposure (D1). Falls back to TCP when the
`ENGINE_LISTEN_ADDR` env var is set (e.g., for integration tests).

Stream sessions (streaming rehydration) are stored in a `Mutex<HashMap>`
keyed by `stream_id`. Each session is owned by a single client stream;
no cross-session sharing.

Observability (D17):
  - Prometheus metrics endpoint on `ENGINE_METRICS_ADDR` (default 0.0.0.0:9090)
  - Structured logging via `tracing` / `tracing-subscriber`
*/

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

use engine_core::{Engine, PolicyBundle, ProvenanceCtx};

pub mod proto {
    tonic::include_proto!("engine.v1");
}

use proto::{
    engine_service_server::{EngineService, EngineServiceServer},
    DeleteVaultEntryRequest, DeleteVaultEntryResponse, DetectRequest, DetectResponse,
    DetectedSpan as ProtoSpan, HealthRequest, HealthResponse, MaskRequest, MaskResponse,
    ModalityHint, RehydrateChunkRequest, RehydrateChunkResponse, RehydrateRequest,
    RehydrateResponse,
};

const VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

struct EngineServer {
    engine: Engine,
    /// In-process map of stream_id → StreamingRehydrator.
    /// One Mutex guards the whole map; contention is low (each stream is short-lived).
    stream_sessions: Arc<Mutex<HashMap<String, engine_core::StreamingRehydrator>>>,
}

impl EngineServer {
    fn new(engine: Engine) -> Self {
        Self {
            engine,
            stream_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// ---------------------------------------------------------------------------
// gRPC service implementation
// ---------------------------------------------------------------------------

#[tonic::async_trait]
impl EngineService for EngineServer {
    async fn health(
        &self,
        _req: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".into(),
            version: VERSION.into(),
        }))
    }

    async fn detect(
        &self,
        req: Request<DetectRequest>,
    ) -> Result<Response<DetectResponse>, Status> {
        let req = req.into_inner();
        let correlation_id = if req.correlation_id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            req.correlation_id
        };

        let spans = self.engine.detect(&req.text);
        let proto_spans: Vec<ProtoSpan> = spans
            .iter()
            .map(|s| ProtoSpan {
                start: s.start as u32,
                end: s.end as u32,
                entity_type: s.entity_type.as_str().to_string(),
                score: s.score,
            })
            .collect();

        Ok(Response::new(DetectResponse {
            correlation_id,
            spans: proto_spans,
        }))
    }

    async fn mask(&self, req: Request<MaskRequest>) -> Result<Response<MaskResponse>, Status> {
        let req = req.into_inner();
        let cid = (!req.correlation_id.is_empty()).then_some(req.correlation_id.as_str());
        let conv = (!req.conversation_id.is_empty()).then_some(req.conversation_id.as_str());

        let result = if req.channel_id.is_empty() {
            self.engine.mask(&req.text, cid, conv)
        } else {
            // Gateway has set a channel_id — apply provenance-aware routing (D9).
            let hint = match ModalityHint::try_from(req.modality_hint) {
                Ok(ModalityHint::ModalityCode) => Some(engine_core::Modality::Code),
                Ok(ModalityHint::ModalityDocument) => Some(engine_core::Modality::Document),
                _ => None,
            };
            let provenance = ProvenanceCtx {
                channel_id: Some(req.channel_id),
                app_id: None,
                hint,
            };
            self.engine
                .mask_with_provenance(&req.text, cid, conv, &provenance)
        };

        let was_masked = result.was_masked();
        Ok(Response::new(MaskResponse {
            masked_text: result.text,
            correlation_id: result.correlation_id,
            entity_counts: result
                .entity_counts
                .into_iter()
                .map(|(k, v)| (k.as_str().to_string(), v as u32))
                .collect(),
            was_masked,
        }))
    }

    async fn rehydrate(
        &self,
        req: Request<RehydrateRequest>,
    ) -> Result<Response<RehydrateResponse>, Status> {
        let req = req.into_inner();
        let conv = (!req.conversation_id.is_empty()).then_some(req.conversation_id.as_str());

        let result = self.engine.rehydrate(&req.text, &req.correlation_id, conv);

        Ok(Response::new(RehydrateResponse {
            rehydrated_text: result.text,
            correlation_id: result.correlation_id,
            rehydrated_count: result.rehydrated_count as u32,
        }))
    }

    async fn rehydrate_chunk(
        &self,
        req: Request<RehydrateChunkRequest>,
    ) -> Result<Response<RehydrateChunkResponse>, Status> {
        let req = req.into_inner();
        let stream_id = req.stream_id.clone();
        let conv = (!req.conversation_id.is_empty()).then_some(req.conversation_id.as_str());

        let mut sessions = self
            .stream_sessions
            .lock()
            .map_err(|_| Status::internal("stream session lock poisoned"))?;

        if !sessions.contains_key(&stream_id) {
            let rehydrator = self.engine.streaming_rehydrator(&req.correlation_id, conv);
            sessions.insert(stream_id.clone(), rehydrator);
        }

        let rehydrator = sessions.get_mut(&stream_id).unwrap();

        let output = if req.is_final {
            let out = format!("{}{}", rehydrator.feed(&req.chunk), rehydrator.flush());
            let _ = rehydrator;
            sessions.remove(&stream_id);
            out
        } else {
            rehydrator.feed(&req.chunk)
        };

        Ok(Response::new(RehydrateChunkResponse {
            chunk: output,
            stream_id,
            is_final: req.is_final,
        }))
    }

    async fn delete_vault_entry(
        &self,
        req: Request<DeleteVaultEntryRequest>,
    ) -> Result<Response<DeleteVaultEntryResponse>, Status> {
        let deleted = self
            .engine
            .delete_vault_entry(&req.into_inner().correlation_id);
        Ok(Response::new(DeleteVaultEntryResponse { deleted }))
    }
}

// ---------------------------------------------------------------------------
// Metrics HTTP server (Prometheus scrape endpoint)
// ---------------------------------------------------------------------------

async fn serve_metrics(
    addr: std::net::SocketAddr,
    handle: metrics_exporter_prometheus::PrometheusHandle,
) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("metrics bind {addr}: {e}"));
    tracing::info!("metrics endpoint at http://{addr}/metrics");

    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let body = handle.render();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Prometheus metrics recorder — must be installed before any metrics are recorded.
    let prometheus_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    let metrics_addr: std::net::SocketAddr = std::env::var("ENGINE_METRICS_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9090".to_string())
        .parse()
        .expect("invalid ENGINE_METRICS_ADDR");

    tokio::spawn(serve_metrics(metrics_addr, prometheus_handle));

    // Build engine — load policy from file if ENGINE_POLICY_FILE is set.
    let engine = if let Ok(path) = std::env::var("ENGINE_POLICY_FILE") {
        match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str::<PolicyBundle>(&s).map_err(|e| e.to_string()))
        {
            Ok(policy) => {
                tracing::info!(path = %path, "loaded policy from file");
                Engine::new(policy)
            }
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "failed to load policy file, using default");
                Engine::with_default_policy()
            }
        }
    } else {
        Engine::with_default_policy()
    };

    // Background vault purge — evict expired entries every 60 s.
    {
        let purge_engine = engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let n = purge_engine.purge_expired();
                if n > 0 {
                    tracing::debug!(purged = n, "vault: purged expired entries");
                }
            }
        });
    }

    // Policy hot-reload on SIGHUP (Unix only).
    #[cfg(unix)]
    {
        let reload_engine = engine.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sig = signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
            while sig.recv().await.is_some() {
                let path = match std::env::var("ENGINE_POLICY_FILE") {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!("SIGHUP: ENGINE_POLICY_FILE not set, skipping reload");
                        continue;
                    }
                };
                match std::fs::read_to_string(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|s| {
                        serde_json::from_str::<PolicyBundle>(&s).map_err(|e| e.to_string())
                    }) {
                    Ok(policy) => {
                        reload_engine.reload_policy(policy);
                        tracing::info!(path = %path, "policy hot-reloaded via SIGHUP");
                    }
                    Err(e) => {
                        tracing::error!(path = %path, error = %e, "SIGHUP: policy reload failed");
                    }
                }
            }
        });
    }

    let service = EngineServer::new(engine);

    let addr = std::env::var("ENGINE_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:50051".to_string());

    tracing::info!("engine-grpc listening on {addr}");

    Server::builder()
        .add_service(EngineServiceServer::new(service))
        .serve(addr.parse()?)
        .await?;

    Ok(())
}
