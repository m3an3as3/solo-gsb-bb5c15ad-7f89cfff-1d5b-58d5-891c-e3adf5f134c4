"""FastAPI application: Unicode bidirectional text security audit API."""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from .bidi import RiskLevel, parse_bidi
from .compare import compare_audits
from .database import count_audits, get_audit, init_db, insert_audit, query_audits
from .diffparse import DiffFormatError, audit_diff, highest_risk
from .sarif import build_sarif
from .schemas import AuditRequest, CompareRequest, DiffAuditRequest
from .verify import verify_audit_record

app = FastAPI(
    title="Unicode Bidi Text Security Audit API",
    description=(
        "Audits text for Unicode bidirectional control characters "
        "(U+202A..U+2069, marks, invisible operators). Reports codepoints, "
        "logical indices, pairing/nesting scope, unclosed-character errors "
        "and produces escaped previews of dangerous spans without modifying "
        "the original text."
    ),
    version="1.0.0",
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "bidi-audit"}


@app.post("/api/v1/audits", status_code=201)
def create_audit(payload: AuditRequest) -> dict:
    """Parse and audit one text payload, persist the record."""
    result = parse_bidi(payload.text).to_dict()
    audit_id = insert_audit(
        filename=payload.filename, text=payload.text, result=result
    )
    return {"id": audit_id, "risk_level": result["risk_level"],
            "stored": True, "result": result}


@app.post("/api/v1/audits/diff", status_code=201)
def audit_unified_diff(payload: DiffAuditRequest) -> dict:
    """Audit only the added ('+') lines of a unified diff.

    The whole diff is parsed and validated first; on any structural error
    (or a hunk whose body length disagrees with its header) a 422 is
    returned pointing at the first offending diff line and **no records are
    written**. On success one record is stored per file that has added
    content; hits are mapped back to new-file path / line / column and the
    owning diff line while the parser's logical indices are retained.
    """
    try:
        plans = audit_diff(payload.diff)
    except DiffFormatError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_unified_diff",
                "message": exc.message,
                "diff_line": exc.diff_line,
            },
        )

    files: list[dict] = []
    for plan in plans:
        result = plan["result"]
        audit_id = insert_audit(
            filename=plan["path"], text=plan["text"], result=result
        )
        files.append({
            "id": audit_id,
            "path": plan["path"],
            "stored": True,
            "added_line_count": plan["added_line_count"],
            "risk_level": plan["risk_level"],
            "result": result,
            **plan["mapped"],
        })

    return {
        "stored": True,
        "file_count": len(files),
        "risk_level": highest_risk([f["risk_level"] for f in files]),
        "files": files,
    }


@app.post("/api/v1/audits/compare")
def compare_records(payload: CompareRequest) -> dict:
    """Compare two stored audit records as a before/after regression."""
    if payload.before_id == payload.after_id:
        raise HTTPException(
            status_code=422,
            detail="before_id and after_id must reference different records",
        )
    before = get_audit(payload.before_id)
    if before is None:
        raise HTTPException(status_code=404, detail="before audit record not found")
    after = get_audit(payload.after_id)
    if after is None:
        raise HTTPException(status_code=404, detail="after audit record not found")
    return compare_audits(before, after)


@app.get("/api/v1/audits")
def list_audits(
    risk_level: Optional[RiskLevel] = Query(
        default=None, description="Filter by risk level "
        "(info|low|medium|high|critical)"
    ),
    filename: Optional[str] = Query(
        default=None, description="Case-insensitive substring match on filename"
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    rl = risk_level.value if risk_level is not None else None
    items = query_audits(risk_level=rl, filename=filename,
                         limit=limit, offset=offset)
    total = count_audits(risk_level=rl, filename=filename)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/v1/audits/{audit_id}")
def read_audit(audit_id: int) -> dict:
    record = get_audit(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="audit record not found")
    return record


@app.get(
    "/api/v1/audits/{audit_id}/verify",
    responses={404: {"description": "audit record not found"}},
)
def verify_audit(audit_id: int) -> dict:
    """Re-run the parser on the stored text and diff against the stored
    result. Read-only: the record is never repaired or rewritten."""
    record = get_audit(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="audit record not found")
    return verify_audit_record(record)


@app.get(
    "/api/v1/audits/{audit_id}/sarif",
    response_class=JSONResponse,
    responses={
        200: {
            "content": {"application/sarif+json": {}},
            "description": "SARIF 2.1.0 document for the stored audit",
        },
        404: {"description": "audit record not found"},
    },
)
def export_audit_sarif(audit_id: int) -> JSONResponse:
    """Export one stored audit as a SARIF 2.1.0 document."""
    record = get_audit(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="audit record not found")
    sarif = build_sarif(record)
    return JSONResponse(
        sarif, media_type="application/sarif+json; charset=utf-8"
    )


@app.get("/")
def root() -> dict:
    return {
        "service": "bidi-audit",
        "docs": "/docs",
        "endpoints": [
            "POST /api/v1/audits",
            "POST /api/v1/audits/diff",
            "POST /api/v1/audits/compare",
            "GET  /api/v1/audits",
            "GET  /api/v1/audits/{id}",
            "GET  /api/v1/audits/{id}/verify",
            "GET  /api/v1/audits/{id}/sarif",
            "GET  /health",
        ],
    }
