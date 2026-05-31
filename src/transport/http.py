"""
HTTP + SSE transport adapter (FastAPI).

Endpoints:
  POST /v1/detect          — detect entities without masking
  POST /v1/mask            — mask sensitive entities, store vault entry
  POST /v1/rehydrate       — batch rehydrate from vault
  POST /v1/rehydrate/chunk — streaming rehydration (stateful per stream_id)
  DELETE /v1/vault/{id}   — purge vault entry (right-to-erasure)
  GET  /v1/health          — liveness probe

The vault lives inside the Engine instance, which is process-scoped (D1).
Stream rehydrator state is kept in the _stream_sessions dict, also in-process.

For SSE streaming of LLM responses, the typical integration is:
  1. Client masks the prompt → gets correlation_id.
  2. Client sends masked prompt to LLM, receives streaming response.
  3. Client posts each token/chunk to POST /v1/rehydrate/chunk.
  4. Client yields the returned chunk to its own caller.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from ..engine.pipeline import Engine
from ..engine.policy import PolicyBundle
from ..engine.streaming import StreamingRehydrator
from .models import (
    DetectedSpanResponse,
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

_VERSION = "0.1.0"


def create_app(policy: PolicyBundle | None = None) -> FastAPI:
    """
    Factory for the FastAPI application.

    Args:
        policy: Optional PolicyBundle override (useful for testing).
    """
    engine = Engine(policy=policy)
    # In-process map of stream_id → StreamingRehydrator.
    # Phase 3: replace with sidecar-scoped session store.
    stream_sessions: dict[str, StreamingRehydrator] = {}

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
        yield
        engine.purge_expired()

    app = FastAPI(
        title="Sensitive Content Engine",
        version=_VERSION,
        description="Detection, masking, and rehydration of sensitive entities in LLM traffic.",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------ #
    # Health
    # ------------------------------------------------------------------ #

    @app.get("/v1/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="ok", version=_VERSION)

    # ------------------------------------------------------------------ #
    # Detect
    # ------------------------------------------------------------------ #

    @app.post("/v1/detect", response_model=DetectResponse)
    async def detect(req: DetectRequest) -> DetectResponse:
        spans = engine.detect(req.text)
        return DetectResponse(
            correlation_id=req.correlation_id or str(uuid.uuid4()),
            spans=[
                DetectedSpanResponse(
                    start=s.start,
                    end=s.end,
                    entity_type=s.entity_type.value,
                    score=s.score,
                )
                for s in spans
            ],
        )

    # ------------------------------------------------------------------ #
    # Mask
    # ------------------------------------------------------------------ #

    @app.post("/v1/mask", response_model=MaskResponse)
    async def mask(req: MaskRequest) -> MaskResponse:
        result = engine.mask(
            req.text,
            correlation_id=req.correlation_id,
            conversation_id=req.conversation_id,
        )
        return MaskResponse(
            masked_text=result.text,
            correlation_id=result.correlation_id,
            entity_counts=result.entity_counts,
            was_masked=result.was_masked,
        )

    # ------------------------------------------------------------------ #
    # Rehydrate — batch
    # ------------------------------------------------------------------ #

    @app.post("/v1/rehydrate", response_model=RehydrateResponse)
    async def rehydrate(req: RehydrateRequest) -> RehydrateResponse:
        result = engine.rehydrate(
            req.text,
            req.correlation_id,
            conversation_id=req.conversation_id,
        )
        return RehydrateResponse(
            rehydrated_text=result.text,
            correlation_id=result.correlation_id,
            rehydrated_count=result.rehydrated_count,
        )

    # ------------------------------------------------------------------ #
    # Rehydrate — streaming chunks
    # ------------------------------------------------------------------ #

    @app.post("/v1/rehydrate/chunk", response_model=StreamChunkResponse)
    async def rehydrate_chunk(req: StreamChunkRequest) -> StreamChunkResponse:
        stream_id = req.stream_id

        if stream_id not in stream_sessions:
            stream_sessions[stream_id] = engine.streaming_rehydrator(
                req.correlation_id,
                conversation_id=req.conversation_id,
            )

        rehydrator = stream_sessions[stream_id]

        if req.is_final:
            output = rehydrator.feed(req.chunk) + rehydrator.flush()
            del stream_sessions[stream_id]
        else:
            output = rehydrator.feed(req.chunk)

        return StreamChunkResponse(
            chunk=output,
            stream_id=stream_id,
            is_final=req.is_final,
        )

    # ------------------------------------------------------------------ #
    # Vault — right-to-erasure (D12)
    # ------------------------------------------------------------------ #

    @app.delete("/v1/vault/{correlation_id}")
    async def delete_vault_entry(correlation_id: str) -> Response:
        deleted = engine.delete_vault_entry(correlation_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Vault entry not found or already expired.")
        return Response(status_code=204)

    # ------------------------------------------------------------------ #
    # WebSocket streaming rehydration
    #
    # Client sends JSON frames:
    #   {"chunk": "...", "correlation_id": "...", "is_final": false}
    #   {"chunk": "...", "conversation_id": "...", "is_final": true}
    #
    # Server replies with:
    #   {"chunk": "...", "stream_id": "...", "is_final": false}
    # ------------------------------------------------------------------ #

    @app.websocket("/v1/ws/rehydrate/{stream_id}")
    async def ws_rehydrate(websocket: WebSocket, stream_id: str) -> None:
        await websocket.accept()
        rehydrator: StreamingRehydrator | None = None
        try:
            while True:
                raw = await websocket.receive_text()
                frame: dict[str, object] = json.loads(raw)
                chunk = str(frame.get("chunk", ""))
                correlation_id = str(frame.get("correlation_id", ""))
                conversation_id_raw = frame.get("conversation_id")
                conversation_id = str(conversation_id_raw) if conversation_id_raw else None
                is_final = bool(frame.get("is_final", False))

                if rehydrator is None:
                    rehydrator = engine.streaming_rehydrator(
                        correlation_id,
                        conversation_id=conversation_id,
                    )

                if is_final:
                    output = rehydrator.feed(chunk) + rehydrator.flush()
                    if stream_id in stream_sessions:
                        del stream_sessions[stream_id]
                else:
                    output = rehydrator.feed(chunk)

                await websocket.send_text(
                    json.dumps({"chunk": output, "stream_id": stream_id, "is_final": is_final})
                )
                if is_final:
                    break
        except WebSocketDisconnect:
            pass
        except Exception:
            await websocket.close(code=1011)

    return app


# Module-level ASGI app for uvicorn / gunicorn discovery.
app = create_app()
