"""Report endpoint schemas (M10.B; ADR-034 G4; Task 10.4).

The manifest + PDF-delivery + executive shapes. The JSON and SARIF endpoints
return the raw generator dicts (they ARE the document — no wrapper schema).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.models.scans import ScanStatus


class PdfArtifactInfo(BaseModel):
    """PDF generation status for the manifest."""

    generated: bool
    generated_at: datetime
    size_bytes: int


class ReportManifest(BaseModel):
    """Base /report manifest (G4-L12): available formats + PDF status."""

    scan_id: UUID
    status: ScanStatus
    available_formats: list[str]
    pdf: PdfArtifactInfo | None


class PdfReportResponse(BaseModel):
    """/report/pdf delivery — presigned-GET URL in JSON (G2-L5/L8)."""

    format: str
    download_url: str
    expires_at: datetime  # absolute ISO-8601 UTC (G2.3 primary)
    expires_in: int  # seconds (3600)
    generated_at: datetime
    size_bytes: int


class ExecutiveReportResponse(BaseModel):
    """/report/executive — the Scan.executive_summary (G1-L3; read, not regen)."""

    scan_id: UUID
    executive_summary: str | None
    generated_at: datetime
