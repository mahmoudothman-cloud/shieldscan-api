"""SARIF 2.1.0 report generator (M10.B; ADR-034 G3; Task 10.3).

Emits SARIF 2.1.0 and self-validates the output against the bundled schema
via ``jsonschema`` — provable conformance (GitHub Code Scanning at Task 12
requires 2.1.0). Pure ``ReportContext -> dict`` + validation; no storage.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import jsonschema

from app.models.raw_findings import Severity
from app.services.reports.context import ReportContext, ReportVulnerability

SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_SCHEMA_PATH = Path(__file__).parent / "schemas" / "sarif-2.1.0.json"

# SPEC §8.3 Severity → SARIF result level (G3 / V-JJ-C2-SEVMAP).
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


@lru_cache(maxsize=1)
def _sarif_schema() -> dict:
    """Load + cache the bundled SARIF 2.1.0 schema."""
    return json.loads(_SCHEMA_PATH.read_text())


def _rule_id(v: ReportVulnerability) -> str:
    """Stable rule id — prefer CWE, fall back to finding_type."""
    return v.cwe_id or v.finding_type


def _location(v: ReportVulnerability) -> dict | None:
    """Physical location from the vuln's salient URI/file (SARIF locations[])."""
    uri = v.target_url or v.code_file
    if uri is None:
        return None
    physical: dict = {"artifactLocation": {"uri": uri}}
    if v.code_line is not None:
        physical["region"] = {"startLine": v.code_line}
    return {"physicalLocation": physical}


def generate_sarif_report(ctx: ReportContext) -> dict:
    """Render a SARIF 2.1.0 document and validate it against the bundled schema."""
    # Distinct rules, first-seen order.
    rules: list[dict] = []
    seen: set[str] = set()
    for v in ctx.vulnerabilities:
        rid = _rule_id(v)
        if rid not in seen:
            seen.add(rid)
            rules.append({"id": rid, "name": v.finding_type})

    results: list[dict] = []
    for v in ctx.vulnerabilities:
        result: dict = {
            "ruleId": _rule_id(v),
            "level": _SEVERITY_TO_LEVEL[v.severity],
            "message": {"text": v.title},
            "locations": [],
        }
        loc = _location(v)
        if loc is not None:
            result["locations"] = [loc]
        results.append(result)

    document = {
        "$schema": _SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": {"name": "ShieldScan", "rules": rules}},
                "results": results,
            }
        ],
    }

    # Provable conformance (G3) — raises jsonschema.ValidationError on drift.
    jsonschema.validate(instance=document, schema=_sarif_schema())
    return document
