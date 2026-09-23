"""Pydantic schemas for the audit API."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .bidi import RiskLevel


class AuditRequest(BaseModel):
    text: str = Field(..., description="Text to audit. Sent verbatim; never rewritten.")
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Optional source file name for later lookup.",
    )


class AuditCreated(BaseModel):
    id: int
    risk_level: RiskLevel
    stored: bool = True
    result: dict


class CompareRequest(BaseModel):
    before_id: int = Field(
        ..., ge=1, description="ID of the earlier audit record (baseline)."
    )
    after_id: int = Field(
        ..., ge=1, description="ID of the later audit record (regression)."
    )


class DiffAuditRequest(BaseModel):
    diff: str = Field(
        ...,
        description=(
            "Unified diff text. Only added ('+') lines inside hunks are "
            "audited; file headers, removed/context lines and '\\ No "
            "newline' markers are ignored. One record is stored per file "
            "that contains added content."
        ),
    )
