"""Tests for the FastAPI HTTP transport layer (all endpoints + WebSocket)."""

from __future__ import annotations

import json
import warnings

import pytest
from starlette.testclient import TestClient

from src.transport import create_app
from src.transport.models import (
    DetectRequest,
    DetectResponse,
    HealthResponse,
    MaskRequest,
    MaskResponse,
    RehydrateRequest,
    RehydrateResponse,
    StreamChunkRequest,
    StreamChunkResponse,
)

# Suppress the starlette deprecation warning about httpx (cosmetic).
warnings.filterwarnings("ignore", category=DeprecationWarning, module="starlette")

SSN_TEXT = "My SSN is 575-82-8889"
EMAIL_TEXT = "Contact admin@corp.io for support"
CLEAN_TEXT = "Nothing sensitive in this message."


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_detect_request(self) -> None:
        r = DetectRequest(text="hello")
        assert r.text == "hello"
        assert r.correlation_id is None

    def test_mask_request_defaults(self) -> None:
        r = MaskRequest(text="x")
        assert r.conversation_id is None
        assert r.correlation_id is None

    def test_rehydrate_request(self) -> None:
        r = RehydrateRequest(text="[SSN_1]", correlation_id="abc")
        assert r.correlation_id == "abc"

    def test_stream_chunk_request(self) -> None:
        r = StreamChunkRequest(chunk="hi", correlation_id="cid", stream_id="s1")
        assert not r.is_final

    def test_health_response(self) -> None:
        r = HealthResponse(status="ok", version="1.0")
        assert r.status == "ok"

    def test_stream_chunk_response(self) -> None:
        r = StreamChunkResponse(chunk="out", stream_id="s1", is_final=True)
        assert r.is_final

    def test_detect_response(self) -> None:
        r = DetectResponse(correlation_id="cid", spans=[])
        assert r.spans == []

    def test_mask_response(self) -> None:
        r = MaskResponse(
            masked_text="x", correlation_id="c", entity_counts={}, was_masked=False
        )
        assert not r.was_masked

    def test_rehydrate_response(self) -> None:
        r = RehydrateResponse(rehydrated_text="x", correlation_id="c", rehydrated_count=1)
        assert r.rehydrated_count == 1


# ---------------------------------------------------------------------------
# GET /v1/health
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_ok(self, client: TestClient) -> None:
        resp = client.get("/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "version" in body


# ---------------------------------------------------------------------------
# POST /v1/detect
# ---------------------------------------------------------------------------


class TestDetect:
    def test_detect_ssn(self, client: TestClient) -> None:
        resp = client.post("/v1/detect", json={"text": SSN_TEXT})
        assert resp.status_code == 200
        body = resp.json()
        types = [s["entity_type"] for s in body["spans"]]
        assert "SSN" in types

    def test_detect_clean(self, client: TestClient) -> None:
        resp = client.post("/v1/detect", json={"text": CLEAN_TEXT})
        assert resp.status_code == 200
        assert resp.json()["spans"] == []

    def test_detect_with_correlation_id(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/detect", json={"text": SSN_TEXT, "correlation_id": "test-cid"}
        )
        assert resp.status_code == 200
        assert resp.json()["correlation_id"] == "test-cid"

    def test_detect_span_fields(self, client: TestClient) -> None:
        resp = client.post("/v1/detect", json={"text": SSN_TEXT})
        span = resp.json()["spans"][0]
        assert {"start", "end", "entity_type", "score"} <= span.keys()
        assert span["score"] > 0.0


# ---------------------------------------------------------------------------
# POST /v1/mask
# ---------------------------------------------------------------------------


class TestMask:
    def test_mask_ssn(self, client: TestClient) -> None:
        resp = client.post("/v1/mask", json={"text": SSN_TEXT})
        assert resp.status_code == 200
        body = resp.json()
        assert "[SSN_1]" in body["masked_text"]
        assert "575-82-8889" not in body["masked_text"]
        assert body["was_masked"] is True
        assert body["entity_counts"]["SSN"] == 1
        assert "correlation_id" in body

    def test_mask_email(self, client: TestClient) -> None:
        resp = client.post("/v1/mask", json={"text": EMAIL_TEXT})
        assert resp.status_code == 200
        body = resp.json()
        assert body["was_masked"] is True
        assert "admin@corp.io" not in body["masked_text"]

    def test_mask_clean_text(self, client: TestClient) -> None:
        resp = client.post("/v1/mask", json={"text": CLEAN_TEXT})
        assert resp.status_code == 200
        body = resp.json()
        assert body["was_masked"] is False
        assert body["masked_text"] == CLEAN_TEXT

    def test_mask_with_caller_correlation_id(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/mask", json={"text": SSN_TEXT, "correlation_id": "caller-cid"}
        )
        assert resp.status_code == 200
        assert resp.json()["correlation_id"] == "caller-cid"

    def test_mask_with_conversation_id(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/mask",
            json={"text": SSN_TEXT, "correlation_id": "cid1", "conversation_id": "conv1"},
        )
        assert resp.status_code == 200
        assert resp.json()["was_masked"] is True


# ---------------------------------------------------------------------------
# POST /v1/rehydrate
# ---------------------------------------------------------------------------


class TestRehydrate:
    def test_rehydrate_roundtrip(self, client: TestClient) -> None:
        mask_body = client.post("/v1/mask", json={"text": SSN_TEXT}).json()
        cid = mask_body["correlation_id"]

        rh_body = client.post(
            "/v1/rehydrate", json={"text": mask_body["masked_text"], "correlation_id": cid}
        ).json()

        assert "575-82-8889" in rh_body["rehydrated_text"]
        assert rh_body["rehydrated_count"] == 1
        assert rh_body["correlation_id"] == cid

    def test_rehydrate_unknown_cid(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/rehydrate", json={"text": "[SSN_1]", "correlation_id": "nonexistent"}
        )
        assert resp.status_code == 200
        assert resp.json()["rehydrated_text"] == "[SSN_1]"
        assert resp.json()["rehydrated_count"] == 0

    def test_rehydrate_with_conversation_id(self, client: TestClient) -> None:
        mask_body = client.post(
            "/v1/mask",
            json={"text": SSN_TEXT, "correlation_id": "cid2", "conversation_id": "conv2"},
        ).json()

        rh_body = client.post(
            "/v1/rehydrate",
            json={
                "text": mask_body["masked_text"],
                "correlation_id": "cid2",
                "conversation_id": "conv2",
            },
        ).json()

        assert "575-82-8889" in rh_body["rehydrated_text"]


# ---------------------------------------------------------------------------
# POST /v1/rehydrate/chunk
# ---------------------------------------------------------------------------


class TestRehydrateChunk:
    def test_chunk_streaming_roundtrip(self, client: TestClient) -> None:
        mask_body = client.post("/v1/mask", json={"text": SSN_TEXT}).json()
        cid = mask_body["correlation_id"]
        masked = mask_body["masked_text"]

        mid = len(masked) // 2
        chunk_a, chunk_b = masked[:mid], masked[mid:]
        stream_id = "chunk-stream-1"

        r1 = client.post(
            "/v1/rehydrate/chunk",
            json={"chunk": chunk_a, "correlation_id": cid, "stream_id": stream_id},
        )
        assert r1.status_code == 200
        assert r1.json()["stream_id"] == stream_id
        assert not r1.json()["is_final"]

        r2 = client.post(
            "/v1/rehydrate/chunk",
            json={
                "chunk": chunk_b,
                "correlation_id": cid,
                "stream_id": stream_id,
                "is_final": True,
            },
        )
        assert r2.status_code == 200
        combined = r1.json()["chunk"] + r2.json()["chunk"]
        assert "575-82-8889" in combined
        assert r2.json()["is_final"] is True


# ---------------------------------------------------------------------------
# DELETE /v1/vault/{id}
# ---------------------------------------------------------------------------


class TestVaultDelete:
    def test_delete_existing_entry(self, client: TestClient) -> None:
        cid = client.post("/v1/mask", json={"text": SSN_TEXT}).json()["correlation_id"]
        assert client.delete(f"/v1/vault/{cid}").status_code == 204

    def test_delete_nonexistent_returns_404(self, client: TestClient) -> None:
        assert client.delete("/v1/vault/does-not-exist").status_code == 404

    def test_delete_clears_vault(self, client: TestClient) -> None:
        mask_body = client.post("/v1/mask", json={"text": SSN_TEXT}).json()
        cid = mask_body["correlation_id"]
        masked = mask_body["masked_text"]

        client.delete(f"/v1/vault/{cid}")

        rh = client.post(
            "/v1/rehydrate", json={"text": masked, "correlation_id": cid}
        ).json()
        assert rh["rehydrated_count"] == 0


# ---------------------------------------------------------------------------
# WS /v1/ws/rehydrate/{stream_id}
# ---------------------------------------------------------------------------


class TestWebSocketRehydrate:
    def test_ws_roundtrip(self, client: TestClient) -> None:
        mask_body = client.post("/v1/mask", json={"text": SSN_TEXT}).json()
        cid = mask_body["correlation_id"]
        masked = mask_body["masked_text"]

        mid = len(masked) // 2
        chunk_a, chunk_b = masked[:mid], masked[mid:]

        with client.websocket_connect("/v1/ws/rehydrate/ws-1") as ws:
            ws.send_text(json.dumps({"chunk": chunk_a, "correlation_id": cid}))
            r1 = json.loads(ws.receive_text())
            assert r1["stream_id"] == "ws-1"

            ws.send_text(
                json.dumps({"chunk": chunk_b, "correlation_id": cid, "is_final": True})
            )
            r2 = json.loads(ws.receive_text())

        assert "575-82-8889" in r1["chunk"] + r2["chunk"]
        assert r2["is_final"] is True

    def test_ws_clean_passthrough(self, client: TestClient) -> None:
        with client.websocket_connect("/v1/ws/rehydrate/ws-clean") as ws:
            ws.send_text(
                json.dumps(
                    {"chunk": "hello world", "correlation_id": "fake-cid", "is_final": True}
                )
            )
            r = json.loads(ws.receive_text())
        assert r["chunk"] == "hello world"
        assert r["is_final"] is True
