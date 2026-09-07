"""Identify the nikto findings that describe an error page, not a site.

Nikto 2.1.5 cannot negotiate TLS. Given a target on port 443 it speaks
plain HTTP, receives nginx's ``400 The plain HTTP request was sent to
HTTPS port``, and parses that error page as the application (engine
Drift #71). Every finding it produced against an HTTPS target therefore
describes the error page rather than the customer's site.

The contradiction is direct, not theoretical: nikto reported "The
anti-clickjacking X-Frame-Options header is not present" for
``shieldscan.odyssey-eg.com`` while the real site returns
``x-frame-options: SAMEORIGIN``. The 400 page has no such header — and
nikto never saw anything else.

**The scope is derived from the artifact itself, not from a date.** A
finding qualifies when its ``target_url`` is a plain-``http://`` URL on
port 443, which is precisely the state that cannot occur unless the
scanner failed to negotiate TLS. That test is self-limiting: a genuine
plain-HTTP scan (port 80, or any non-443 port) does not match, and
neither will anything produced once nikto can actually speak TLS. A
timestamp cutoff would have neither property.

**Mixed-provenance vulnerabilities are never touched.** A Vulnerability
carries ``raw_finding_ids`` spanning every tool that corroborated it, so
one can be backed by both a nikto artifact and real findings from zap or
nuclei. Deleting it loses real data; deleting only the nikto ids from
the array leaves a promoted vulnerability whose score was computed from
evidence that is now gone. Neither is obviously right, so this module
identifies them, refuses to act, and leaves the call to a human. There
are none in the current data — the check exists for the run where there
are.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy import and_, any_, case, delete, func, or_, select, update

from app.models.raw_findings import RawFinding
from app.models.scans import Scan
from app.models.vulnerabilities import Vulnerability

logger = logging.getLogger(__name__)

# The artifact test. Plain HTTP on the TLS port.
#
# Expressed with ORM constructs rather than text() SQL, and not only for
# style: tests/test_rls_invariants.py forbids raw text() against a tenant
# table, because the tenant guard identifies tenant tables by ORM mapper
# and a text() statement has none. Deleting from raw_findings and
# vulnerabilities is precisely the access that must stay visible to it.
#
# LIKE rather than a regex so the predicate reads as what it means. The
# trailing match covers ":443/" mid-string and ":443" at the end, which
# are the two shapes combineSiteURI produces.


def _artifact_clause():
    """Rows produced by a scanner that failed to negotiate TLS.

    A plain-``http://`` target_url on port 443 cannot arise any other
    way. The test is self-limiting: a genuine plain-HTTP scan (port 80,
    or any other port) does not match, and neither will anything produced
    once nikto can actually speak TLS. A timestamp cutoff would have
    neither property, and would delete real plain-HTTP nikto output.
    """
    return and_(
        RawFinding.tool_name == "nikto",
        RawFinding.target_url.like("http://%"),
        or_(
            RawFinding.target_url.like("%:443/%"),
            RawFinding.target_url.like("%:443"),
        ),
    )


# Recorded on every scan whose findings are removed, so the deletion is
# attributable later. Distinct enough to grep for.
CLEANUP_REASON = (
    "nikto findings removed: produced by nikto 2.1.5 against port 443 over "
    "plain HTTP, so they described the server's 400 error page rather than "
    "the site (engine Drift #71)"
)


@dataclass
class Plan:
    """What a cleanup run would do, derived fresh each time."""

    raw_finding_ids: list[UUID] = field(default_factory=list)
    pure_vulnerability_ids: list[UUID] = field(default_factory=list)
    mixed_vulnerabilities: list[dict] = field(default_factory=list)
    scans_touched: set[UUID] = field(default_factory=set)
    target_urls: dict[str, int] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        """True when a human has to decide before anything is deleted."""
        return bool(self.mixed_vulnerabilities)


async def build_plan(db) -> Plan:
    """Derive the cleanup set. Reads only.

    The caller MUST have established the RLS tenant context for the
    organization being swept; these queries are org-scoped by policy, not
    by a WHERE clause.
    """
    plan = Plan()

    rows = (
        await db.execute(
            select(RawFinding.id, RawFinding.scan_id, RawFinding.target_url).where(
                _artifact_clause()
            )
        )
    ).all()
    for r in rows:
        plan.raw_finding_ids.append(r.id)
        plan.scans_touched.add(r.scan_id)
        plan.target_urls[r.target_url] = plan.target_urls.get(r.target_url, 0) + 1

    if not plan.raw_finding_ids:
        return plan

    # Classify every vulnerability citing at least one artifact by what
    # ELSE backs it. An outer join over the id array, because
    # raw_finding_ids carries no foreign key.
    #
    # `dangling` counts ids in the array with no surviving raw_finding
    # row — already-deleted evidence, which must not be read as "backed
    # by another tool".
    #
    # The explicit `RawFinding.id.is_not(None)` in the real_rows filter
    # states that intent but does not enforce it: on an unmatched outer
    # join row every RawFinding column is NULL, so `is_artifact` is NULL,
    # `~is_artifact` is NULL, and FILTER already drops it. Removing the
    # predicate changes no behaviour — confirmed by mutation. It stays
    # because the reader should not have to re-derive three-valued logic
    # to see that dangling ids are excluded.
    is_artifact = _artifact_clause()
    classified = (
        await db.execute(
            select(
                Vulnerability.id.label("vuln_id"),
                Vulnerability.scan_id,
                Vulnerability.title,
                Vulnerability.severity,
                func.count().filter(is_artifact).label("artifact_rows"),
                func.count()
                .filter(RawFinding.id.is_not(None), ~is_artifact)
                .label("real_rows"),  # see the note above on NULL rows
                func.count().filter(RawFinding.id.is_(None)).label("dangling_rows"),
                func.string_agg(RawFinding.tool_name.distinct(), ",").label("tools"),
            )
            .select_from(Vulnerability)
            .outerjoin(
                RawFinding, RawFinding.id == any_(Vulnerability.raw_finding_ids)
            )
            .group_by(
                Vulnerability.id,
                Vulnerability.scan_id,
                Vulnerability.title,
                Vulnerability.severity,
            )
            .having(func.count().filter(is_artifact) > 0)
        )
    ).all()

    for r in classified:
        if r.real_rows:
            plan.mixed_vulnerabilities.append(
                {
                    "vulnerability_id": r.vuln_id,
                    "scan_id": r.scan_id,
                    "severity": str(r.severity),
                    "title": r.title,
                    "artifact_rows": r.artifact_rows,
                    "real_rows": r.real_rows,
                    "dangling_rows": r.dangling_rows,
                    "tools": r.tools,
                }
            )
        else:
            plan.pure_vulnerability_ids.append(r.vuln_id)

    return plan


async def apply_plan(db, plan: Plan) -> dict[str, int]:
    """Delete the artifacts. Caller commits.

    Refuses outright when the plan is blocked. A cleanup that silently
    did the safe half would leave the operator believing it had finished.
    """
    if plan.blocked:
        raise RuntimeError(
            f"{len(plan.mixed_vulnerabilities)} vulnerability(ies) are backed by "
            "BOTH nikto artifacts and real findings from other tools. Deleting "
            "them would lose real data; stripping only the nikto ids would leave "
            "a promoted vulnerability whose score was computed from evidence "
            "that is now gone. Decide per row, then re-run."
        )

    counts = {"vulnerabilities": 0, "raw_findings": 0, "scans_annotated": 0}
    if not plan.raw_finding_ids:
        return counts

    # Vulnerabilities first: they cite raw_findings by id array, so
    # removing the evidence first would leave rows referencing nothing.
    if plan.pure_vulnerability_ids:
        res = await db.execute(
            delete(Vulnerability).where(
                Vulnerability.id.in_(plan.pure_vulnerability_ids)
            )
        )
        counts["vulnerabilities"] = res.rowcount or 0

    res = await db.execute(
        delete(RawFinding).where(RawFinding.id.in_(plan.raw_finding_ids))
    )
    counts["raw_findings"] = res.rowcount or 0

    # Record why, on every scan that lost findings. Appended rather than
    # assigned: a scan may already carry a job-failure summary, and
    # overwriting it would trade one lost explanation for another. The
    # already-contains guard makes a second run a no-op rather than a
    # second copy of the same sentence.
    if plan.scans_touched:
        res = await db.execute(
            update(Scan)
            .where(
                Scan.id.in_(plan.scans_touched),
                or_(
                    Scan.error_message.is_(None),
                    # contains(), not func.position(): PostgreSQL spells it
                    # position(sub IN str), and SQLAlchemy renders
                    # func.position(a, b) with a comma, which is a syntax
                    # error. autoescape guards a reason string that ever
                    # gains a % or _.
                    ~Scan.error_message.contains(CLEANUP_REASON, autoescape=True),
                ),
            )
            .values(
                error_message=case(
                    (
                        or_(Scan.error_message.is_(None), Scan.error_message == ""),
                        CLEANUP_REASON,
                    ),
                    else_=Scan.error_message + " | " + CLEANUP_REASON,
                )
            )
        )
        counts["scans_annotated"] = res.rowcount or 0

    logger.info(
        "nikto artifact cleanup: deleted %d vulnerability(ies) and %d "
        "raw_finding(s) across %d scan(s)",
        counts["vulnerabilities"],
        counts["raw_findings"],
        len(plan.scans_touched),
    )
    return counts
