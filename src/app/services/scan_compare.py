"""Scan comparison on identity links (Task 4.6, reworked 2026-11-13).

The first version partitioned by ``Vulnerability.fingerprint``, which is
the first-promoted raw finding of a cluster and depends on batch order
(DRIFT-LOG 2026-11-10). This one walks the links the identity pass
writes (``previous_id`` / ``superseded_by_id`` / ``regression``,
``services.vulnerability_identity``), so the diff agrees with the
dashboard's open counts and the CLI's PR delta.

Categories, baseline *B* (older) vs current *C* (newer):

* **persisting** — a C row whose ``previous_id`` chain reaches a row of
  B (through any intermediate scans). Shown with C's row.
* **regressions** — a C row flagged ``regression`` (its previous row had
  been RESOLVED) that does not reach B.
* **new** — every other C row. ``first_seen_at`` is carried so the
  reader can tell "new since B" from "first ever seen".
* **fixed** — a B row whose forward chain (``superseded_by_id``) ends in
  a RESOLVED row that is not in C.
* **not_covered** — a B row whose chain ends OPEN outside C: C did not
  look for it (narrower scope, engine failed), so nothing can be said.
* **triaged** — a B row whose chain ends FALSE_POSITIVE / ACCEPTED_RISK:
  hidden from the diff, counted in the summary.

The baseline defaults to the project's previous finished scan of the
same type (what the identity pass auto-resolves against), and
``scope_covered`` reports whether C's effective scope covers B's — when
it does not, a large ``not_covered`` bucket is expected, not alarming.

Read-only; the route emits the SCAN_COMPARED audit row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scans import Scan, ScanStatus
from app.models.vulnerabilities import Vulnerability, VulnerabilityStatus
from app.services.vulnerability_identity import scope_covers

MAX_FINDINGS_PER_CATEGORY: Final[int] = 5000

_TERMINAL_OK = frozenset({ScanStatus.COMPLETED, ScanStatus.PARTIAL})
_TRIAGED = frozenset({VulnerabilityStatus.FALSE_POSITIVE, VulnerabilityStatus.ACCEPTED_RISK})


@dataclass
class ScanDiff:
    new: list[Vulnerability] = field(default_factory=list)
    regressions: list[Vulnerability] = field(default_factory=list)
    persisting: list[Vulnerability] = field(default_factory=list)
    fixed: list[Vulnerability] = field(default_factory=list)
    not_covered: list[Vulnerability] = field(default_factory=list)
    triaged_count: int = 0
    truncated: bool = False
    scope_covered: bool = True

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "regressions": len(self.regressions),
            "persisting": len(self.persisting),
            "fixed": len(self.fixed),
            "not_covered": len(self.not_covered),
            "triaged": self.triaged_count,
        }


async def default_baseline(db: AsyncSession, current: Scan) -> Scan | None:
    """The previous finished scan of the same type in the project."""
    return (
        await db.execute(
            select(Scan)
            .where(
                Scan.project_id == current.project_id,
                Scan.id != current.id,
                Scan.scan_type == current.scan_type,
                Scan.status.in_(_TERMINAL_OK),
                Scan.created_at < current.created_at,
                Scan.is_public.is_(False),
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def compute_diff(
    db: AsyncSession,
    baseline: Scan,
    current: Scan,
    *,
    cap_per_category: int = MAX_FINDINGS_PER_CATEGORY,
) -> ScanDiff:
    """Partition by identity links. Loads the project's vulnerability rows
    from scans created between the two (inclusive) — the chains can only
    pass through those — in one query."""
    rows = (
        (
            await db.execute(
                select(Vulnerability)
                .join(Scan, Scan.id == Vulnerability.scan_id)
                .where(
                    Vulnerability.project_id == current.project_id,
                    Scan.created_at >= baseline.created_at,
                    Scan.created_at <= current.created_at,
                )
            )
        )
        .scalars()
        .all()
    )
    by_id: dict[UUID, Vulnerability] = {v.id: v for v in rows}
    current_rows = [v for v in rows if v.scan_id == current.id]
    baseline_rows = [v for v in rows if v.scan_id == baseline.id]

    diff = ScanDiff(scope_covered=scope_covers(current.config or {}, baseline.config or {}))

    # Current side: walk previous_id back to the baseline scan.
    reached_baseline: set[UUID] = set()
    for v in current_rows:
        hop = v
        seen: set[UUID] = set()
        matched: Vulnerability | None = None
        while hop.previous_id is not None and hop.previous_id not in seen:
            seen.add(hop.previous_id)
            prev = by_id.get(hop.previous_id)
            if prev is None:
                break  # older than the baseline window: not a baseline match
            if prev.scan_id == baseline.id:
                matched = prev
                break
            hop = prev
        if matched is not None:
            reached_baseline.add(matched.id)
            diff.persisting.append(v)
        elif v.regression:
            diff.regressions.append(v)
        else:
            diff.new.append(v)

    # Baseline side: walk superseded_by_id forward to the terminal row.
    for b in baseline_rows:
        if b.id in reached_baseline:
            continue
        hop = b
        seen = set()
        while hop.superseded_by_id is not None and hop.superseded_by_id not in seen:
            seen.add(hop.superseded_by_id)
            nxt = by_id.get(hop.superseded_by_id)
            if nxt is None:
                break
            hop = nxt
        if hop.scan_id == current.id:
            # Reached C through a chain the current side did not walk
            # (possible only with data older than the window) — persisting.
            diff.persisting.append(hop)
            continue
        if hop.status == VulnerabilityStatus.RESOLVED:
            diff.fixed.append(hop)
        elif hop.status in _TRIAGED:
            diff.triaged_count += 1
        else:
            diff.not_covered.append(hop)

    for name in ("new", "regressions", "persisting", "fixed", "not_covered"):
        lst: list[Vulnerability] = getattr(diff, name)
        if len(lst) > cap_per_category:
            diff.truncated = True
            setattr(diff, name, lst[:cap_per_category])
    return diff
