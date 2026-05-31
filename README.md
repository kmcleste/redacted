# Sensitive Content Detection Engine

Reversible PII, PHI, and secrets masking for LLM traffic. Detects sensitive
entities, replaces them with typed positional placeholders (`[SSN_1]`,
`[EMAIL_2]`), stores the originals in an in-process encrypted vault, and
rehydrates them on the way back out — including across streaming SSE chunks
split mid-placeholder.

---

## Contents

- [How it works](#how-it-works)
- [Entity types](#entity-types)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [HTTP API](#http-api)
- [gRPC API](#grpc-api)
- [Configuration](#configuration)
- [Observability](#observability)
- [Development](#development)
- [CI](#ci)

---

## How it works

```
  Prompt ──► mask() ──► [SSN_1] asked about [EMAIL_1] ──► LLM
                │                                           │
                └─ vault.store(correlation_id, map, ttl)   │
                                                           ▼
  Original ◄── rehydrate() ◄──────────── LLM response with [SSN_1]
```

1. **Detect** — a cascade of DFA-only regex detectors (RE2-equivalent, no
   ReDoS) runs against the input. Each detector fires only when a structural
   pattern *and* a validator (Luhn, ABA check digit, SSN area-group-serial
   rules, etc.) both agree. Context keywords gate ambiguous patterns (bare SSNs,
   routing numbers).

2. **Mask** — spans are replaced right-to-left with typed positional
   placeholders. The originals are encrypted with ChaCha20-Poly1305 and stored
   in an in-process vault keyed by `correlation_id`. The vault never crosses a
   network boundary and is never logged.

3. **Rehydrate** — placeholders are looked up in the vault and swapped back.
   Streaming rehydration handles placeholders split across SSE chunks using a
   bounded-lookahead state machine (max 64-byte buffer; no heap growth from
   adversarial input).

4. **Egress canary** — after masking, the full detector suite re-scans the
   masked payload. Any residual PII emits a `engine_canary_pii_found_total`
   metric and a warning log. It never blocks.

---

## Entity types

| Category | Types |
|---|---|
| Structured PII | `SSN`, `CREDIT_CARD`, `BANK_ROUTING`, `BANK_ACCOUNT`, `EMAIL`, `PHONE`, `IP_ADDRESS`, `VIN` |
| Insurance / domain | `POLICY_NUMBER`, `CLAIM_ID`, `MEMBER_ID`, `GROUP_ID`, `NPI` |
| PHI (HIPAA) | `DATE_OF_BIRTH`, `MEDICAL_RECORD` |
| Secrets | `AWS_KEY`, `GITHUB_TOKEN`, `PEM_BLOCK`, `CONNECTION_STRING`, `GENERIC_SECRET` |
| NER (soft-RT, Phase 3) | `PERSON`, `ADDRESS`, `ORG` |

Each type has a configurable score threshold. The default policy is
**fail-closed**: unknown entity types are masked, not skipped.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Gateway / proxy                                         │
│                                                          │
│  ┌────────────────┐      ┌───────────────────────────┐  │
│  │  engine-ffi    │      │  engine-grpc (sidecar)    │  │
│  │  C ABI / cdylib│      │  gRPC over localhost      │  │
│  │  zero-hop,     │      │  :50051 (gRPC)            │  │
│  │  in-process    │      │  :9090  (Prometheus)      │  │
│  └───────┬────────┘      └──────────┬────────────────┘  │
│          │                          │                    │
│          └──────────┬───────────────┘                    │
│                     ▼                                    │
│             engine-core (Rust lib)                       │
│             DFA detectors · vault · masker               │
│             streaming rehydrator · policy                │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  Python layer (FastAPI HTTP + offline evaluation)        │
│  :8000  POST /v1/mask  /v1/rehydrate  /v1/detect …      │
│  Gold evaluation · Presidio NER (Phase 3)               │
└─────────────────────────────────────────────────────────┘
```

| Crate / package | Language | Role |
|---|---|---|
| `crates/engine-core` | Rust | Core library — detectors, vault, masker, rehydrator |
| `crates/engine-ffi` | Rust | C ABI (`cdylib` + `staticlib`) for in-process embedding |
| `crates/engine-grpc` | Rust | Tonic gRPC sidecar + Prometheus metrics endpoint |
| `src/engine` | Python | Detection pipeline, policy, vault (Python-native) |
| `src/transport` | Python | FastAPI HTTP adapter |
| `tests/` | Python | Unit + integration tests, gold evaluation harness |

**Modality routing (D9):** the gateway sets a `channel_id` from an
authenticated API-key attribute. Only a *trusted channel* + a matching
`modality_hint` together activate the Code lane (secrets-only, NER
suppressed). Content can never self-declare into a relaxed policy.

---

## Quick start

### Docker (recommended)

```bash
# gRPC sidecar
docker run --rm -p 50051:50051 -p 9090:9090 \
  gcr.io/<project>/engine-grpc:latest

# Python HTTP API
docker run --rm -p 8000:8000 \
  gcr.io/<project>/engine-api:latest
```

### Build from source

**Prerequisites:** Rust stable (≥ 1.80), `protoc`, Python ≥ 3.11.

```bash
# Rust workspace
cargo build --release --workspace

# Run gRPC sidecar
./target/release/engine-grpc

# Python API
pip install -e "."
uvicorn transport.http:app --host 0.0.0.0 --port 8000
```

---

## HTTP API

Base URL: `http://localhost:8000`

### `POST /v1/mask`

Detect and replace sensitive entities. Returns the masked text and a
`correlation_id` needed for rehydration.

```bash
curl -s -X POST http://localhost:8000/v1/mask \
  -H 'Content-Type: application/json' \
  -d '{"text": "My SSN is 575-82-8889 and email is user@acme.com"}' | jq .
```

```json
{
  "masked_text": "My SSN is [SSN_1] and email is [EMAIL_1]",
  "correlation_id": "a3f1c2d4-...",
  "entity_counts": {"SSN": 1, "EMAIL": 1},
  "was_masked": true
}
```

### `POST /v1/rehydrate`

Swap placeholders back to originals using the vault entry created by `/mask`.

```bash
curl -s -X POST http://localhost:8000/v1/rehydrate \
  -H 'Content-Type: application/json' \
  -d '{"text": "My SSN is [SSN_1]", "correlation_id": "a3f1c2d4-..."}' | jq .
```

```json
{
  "rehydrated_text": "My SSN is 575-82-8889",
  "correlation_id": "a3f1c2d4-...",
  "rehydrated_count": 1
}
```

### `POST /v1/detect`

Detect without masking. Useful for audit / logging pipelines.

### `POST /v1/rehydrate/chunk`

Streaming rehydration for SSE/WebSocket responses. Send each chunk as it
arrives; the state machine reassembles placeholders split across chunk
boundaries.

```json
{ "chunk": "Your SSN is [SS", "correlation_id": "...", "stream_id": "s1", "is_final": false }
{ "chunk": "N_1] on file.",   "correlation_id": "...", "stream_id": "s1", "is_final": true }
```

### `DELETE /v1/vault/{correlation_id}`

Right-to-erasure: purge a vault entry immediately (GDPR Article 17 / D12).

### `GET /v1/health`

Liveness probe.

---

## gRPC API

The Rust sidecar exposes the same operations over gRPC on `:50051`. See
[`crates/engine-grpc/proto/engine.proto`](crates/engine-grpc/proto/engine.proto)
for the full schema.

**Modality routing** is available via the `MaskRequest` fields:

| Field | Description |
|---|---|
| `channel_id` | Set by the gateway from an authenticated API-key attribute |
| `modality_hint` | `MODALITY_CODE` or `MODALITY_DOCUMENT` (gateway suggestion only) |

Both fields must be set — and `channel_id` must be in the trusted-channels
allowlist — for the Code lane to activate.

---

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `ENGINE_LISTEN_ADDR` | `0.0.0.0:50051` | gRPC bind address |
| `ENGINE_METRICS_ADDR` | `0.0.0.0:9090` | Prometheus scrape endpoint |
| `RUST_LOG` | `info` | Log level (`error`/`warn`/`info`/`debug`/`trace`) |

Vault TTL defaults: 15 minutes for single-turn requests, 4 hours for
conversation-scoped entries (set `conversation_id` on the mask call).

---

## Observability

Prometheus metrics are exposed at `http://<host>:9090/metrics`.

| Metric | Type | Description |
|---|---|---|
| `engine_detect_duration_us` | histogram | Detection latency (µs) |
| `engine_mask_duration_us` | histogram | Full mask latency (µs) |
| `engine_rehydrate_duration_us` | histogram | Rehydration latency (µs) |
| `engine_entities_detected_total` | counter | Detections, labelled by `entity_type` |
| `engine_vault_ops_total` | counter | Vault ops, labelled by `operation` |
| `engine_rehydrate_mismatches_total` | counter | Placeholders present in response but absent from vault |
| `engine_fail_open_total` | counter | Detector panics caught and silently dropped |
| `engine_canary_pii_found_total` | counter | Egress canary hits, labelled by `entity_type` |

---

## Development

### Rust

```bash
# Build
cargo build --workspace

# Lint (matches CI exactly)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Test
cargo test --workspace --locked
```

### Python

```bash
pip install -e ".[dev]"

ruff check src/ tests/                               # lint
mypy --python-executable "$(which python)" src/     # types
python -m pytest tests/ --ignore=tests/gold_eval.py # tests
```

### Gold evaluation

Measures precision / recall / F1 per entity type against a labelled dataset.
Recall gates: SSN ≥ 0.99, CREDIT_CARD ≥ 0.99, AWS_KEY ≥ 0.99, EMAIL ≥ 0.95,
PHONE ≥ 0.90.

```bash
python tests/gold_eval.py --data path/to/gold.jsonl
```

---

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on every push and PR to
`main`:

| Job | Steps |
|---|---|
| **rust** | `cargo fmt --check` · `cargo clippy -D warnings` · `cargo build --locked` · `cargo test --locked` |
| **python** (3.11 + 3.12) | `ruff check` · `mypy` · `pytest --cov-fail-under=80` |
| **docker** (push to main only) | Build `engine-grpc` + `engine-api`, push to GCR tagged `:latest` + `:<sha>` |

### Docker / GCR setup

Three values must be configured in repository settings before the first push:

| Kind | Name | Value |
|---|---|---|
| Variable | `GCP_PROJECT` | GCP project ID |
| Secret | `WIF_PROVIDER` | Workload Identity provider resource name |
| Secret | `WIF_SERVICE_ACCOUNT` | Service-account email with GCR push permission |

Workload Identity Federation is used (no long-lived service account keys).
