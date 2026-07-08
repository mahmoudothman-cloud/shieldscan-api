"""JSON report generator (M10.B; ADR-034 G3; Task 10.3).

A versioned, full-fidelity envelope — the complete scan as a single document
(``ai_fix_text`` inline, NO pagination, unlike the M10.A paginated API list).
Pure ``ReportContext -> dict``: no DB, no storage (DQ3 — rendered on-demand).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from app.services.reports.context import (
    ReportContext,
    ReportEvidence,
    ReportVulnerability,
)

JSON_REPORT_SCHEMA_VERSION = "1.0"


def _scalar(value: object) -> object:
    """Normalise UUID/datetime/enum to JSON-native scalars."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _evidence_dict(e: ReportEvidence) -> dict:
    return {
        "raw_finding_id": str(e.raw_finding_id),
        "tool_name": e.tool_name,
        "engine_category": _scalar(e.engine_category),
        "description": e.description,
        "code_snippet": e.code_snippet,
        "code_file": e.code_file,
        "code_line": e.code_line,
        "target_url": e.target_url,
        "parameter": e.parameter,
    }


def _vuln_dict(v: ReportVulnerability) -> dict:
    return {
        "id": str(v.id),
        "title": v.title,
        "description": v.description,
        "severity": _scalar(v.severity),
        "severity_score": v.severity_score,
        "cvss_score": v.cvss_score,
        "cwe_id": v.cwe_id,
        "finding_type": v.finding_type,
        "engine_category": _scalar(v.engine_category),
        "status": _scalar(v.status),
        "corroborated_count": v.corroborated_count,
        "correlation_cluster_id": (
            str(v.correlation_cluster_id) if v.correlation_cluster_id else None
        ),
        "target_url": v.target_url,
        "parameter": v.parameter,
        "code_file": v.code_file,
        "code_line": v.code_line,
        "mobile_os": v.mobile_os,
        "mobile_permission": v.mobile_permission,
        "mobile_component_name": v.mobile_component_name,
        "ai_fix_text": v.ai_fix_text,
        "evidence": [_evidence_dict(e) for e in v.evidence],
    }


def generate_json_report(ctx: ReportContext) -> dict:
    """Render the full-fidelity JSON report envelope (G3)."""
    return {
        "schema_version": JSON_REPORT_SCHEMA_VERSION,
        "scan": {
            "id": str(ctx.scan.id),
            "scan_type": _scalar(ctx.scan.scan_type),
            "status": _scalar(ctx.scan.status),
            "target_url": ctx.scan.target_url,
            "completed_at": _scalar(ctx.scan.completed_at),
            "executive_summary": ctx.scan.executive_summary,
        },
        "vulnerability_count": len(ctx.vulnerabilities),
        "vulnerabilities": [_vuln_dict(v) for v in ctx.vulnerabilities],
    }
