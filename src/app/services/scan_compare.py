"""Scan comparison service (Task 4.6).

Pure DB-query function. Reads ``vulnerabilities`` rows for two scans
and partitions by ``fingerprint``:

  * **new**        — fingerprint in current_scan, NOT in baseline
  * **resolved**   — fingerprint in baseline_scan, NOT in current
  * **persisting** — fingerprint in BOTH (returns the current scan's
                     row to reflect latest observations)

Fingerprint algorithm is canonical (CLAUDE.md gotcha 4):
``SHA-256(tool_name|finding_type|target_url|parameter|code_file|code_line)``
The M9 AI pipeline populates ``vulnerabilities.fingerprint`` for each
deduplicated finding. 4.6 only READS — no schema changes.

Truncation: each category is capped at ``cap_per_category`` (default
``MAX_FINDINGS_PER_CATEGORY``). Returning a 4th value ``truncated``
signals the route handler to surface the cap to the client + emit
a logger.warning for capacity-planning visibility.

ADR-013 inheritance: read-only operation. No state writes from this
function — the route handler emits ``SCAN_COMPARED`` audit after.
"""

from __future__ import annotations

from typing import Final
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vulnerabilities import Vulnerability

# Per-category cap on the diff response. At ~300 bytes/entry × 5000
# × 3 categories ≈ 4.5 MB max response. Hardly common at MVP scale
# (typical scans have 10–500 findings), but bounded for DoS hygiene.
# Tunable via monkeypatch in tests; pagination → M10 read-side.
MAX_FINDINGS_PER_CATEGORY: Final[int] = 5000


async def compute_diff(
    db: AsyncSession,
    baseline_scan_id: UUID,
    current_scan_id: UUID,
    *,
    cap_per_category: int = MAX_FINDINGS_PER_CATEGORY,
) -> tuple[
    list[Vulnerability],
    list[Vulnerability],
    list[Vulnerability],
    bool,
]:
    """Return ``(new, resolved, persisting, truncated)``.

    Single SELECT pulls both scans' vulnerabilities — partitioning in
    Python is cheaper than two round-trips, and at MVP scale (low
    thousands of rows) the data fits in memory comfortably.

    Defensive on duplicate fingerprints within one scan (shouldn't
    happen post-M9 dedup but guarded with ``setdefault`` so first-write
    wins instead of crashing).
    """
    rows = (
        await db.execute(
            select(Vulnerability).where(
                Vulnerability.scan_id.in_([baseline_scan_id, current_scan_id])
            )
        )
    ).scalars().all()

    baseline_by_fp: dict[str, Vulnerability] = {}
    current_by_fp: dict[str, Vulnerability] = {}
    for v in rows:
        target = baseline_by_fp if v.scan_id == baseline_scan_id else current_by_fp
        # First-write-wins on duplicate fingerprint within one scan.
        target.setdefault(v.fingerprint, v)

    baseline_fps = set(baseline_by_fp.keys())
    current_fps = set(current_by_fp.keys())

    new_fps = current_fps - baseline_fps
    resolved_fps = baseline_fps - current_fps
    persisting_fps = baseline_fps & current_fps

    new = [current_by_fp[fp] for fp in new_fps]
    resolved = [baseline_by_fp[fp] for fp in resolved_fps]
    # Persisting: return the CURRENT scan's row (latest observation —
    # severity/title may have shifted; latest is more useful for
    # remediation triage than the baseline's stale snapshot).
    persisting = [current_by_fp[fp] for fp in persisting_fps]

    truncated = (
        len(new) > cap_per_category
        or len(resolved) > cap_per_category
        or len(persisting) > cap_per_category
    )
    if truncated:
        new = new[:cap_per_category]
        resolved = resolved[:cap_per_category]
        persisting = persisting[:cap_per_category]

    return new, resolved, persisting, truncated
