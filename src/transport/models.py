"""Pydantic request/response models for the HTTP transport layer."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DetectRequest(BaseModel):
    text: str = Field(..., description="Text to scan for sensitive entities.")
    correlation_id: str | None = Field(None, description="Optional caller-supplied correlation ID.")


class DetectedSpanResponse(BaseModel):
    start: int
    end: int
    entity_type: str
    score: float


class DetectResponse(BaseModel):
    correlation_id: str
    spans: list[DetectedSpanResponse]


class MaskRequest(BaseModel):
    text: str = Field(..., description="Text to mask.")
    correlation_id: str | None = Field(None, description="Caller-supplied correlation ID.")
    conversation_id: str | None = Field(
        None,
        description="Conversation ID for multi-turn consistency. Extends vault TTL.",
    )


class MaskResponse(BaseModel):
    masked_text: str
    correlation_id: str
    entity_counts: dict[str, int]
    was_masked: bool


class RehydrateRequest(BaseModel):
    text: str = Field(..., description="Text containing placeholders to rehydrate.")
    correlation_id: str = Field(..., description="Correlation ID from the mask call.")
    conversation_id: str | None = None


class RehydrateResponse(BaseModel):
    rehydrated_text: str
    correlation_id: str
    rehydrated_count: int


class StreamChunkRequest(BaseModel):
    chunk: str = Field(..., description="A single SSE/stream chunk.")
    correlation_id: str
    stream_id: str = Field(..., description="Unique ID for this stream session.")
    conversation_id: str | None = None
    is_final: bool = Field(False, description="Set True on the last chunk to flush the buffer.")


class StreamChunkResponse(BaseModel):
    chunk: str
    stream_id: str
    is_final: bool


class HealthResponse(BaseModel):
    status: str
    version: str


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
