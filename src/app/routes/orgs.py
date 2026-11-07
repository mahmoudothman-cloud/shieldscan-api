"""Organization-level endpoints (M11 pre-work).

    GET    /v1/orgs/{org_id}/summary              200 OrgSummaryResponse
    GET    /v1/orgs/{org_id}                      200 OrgResponse
    PATCH  /v1/orgs/{org_id}                      200 OrgResponse        admin or API key
    GET    /v1/orgs/{org_id}/members              200 list[MemberItem]
    POST   /v1/orgs/{org_id}/members              201 MemberInviteResponse  admin JWT only
    PATCH  /v1/orgs/{org_id}/members/{user_id}    200 MemberItem         admin JWT only
    DELETE /v1/orgs/{org_id}/members/{user_id}    204                    admin JWT only

Reads are pure aggregation and are not audited. Writes audit with the
``OrgAction`` enum. Member management is JWT-only: inviting or
removing a human is a human-in-the-loop decision (same reasoning as
project archive). Org settings PATCH follows the project pattern
(admin JWT, or any API key, which is admin-equivalent by construction).

Auth: ``require_org_membership()`` on every route — a non-member gets
404 from the dependency (existence-hiding), never a 403.

Last-admin guard: an org always keeps at least one admin. Demoting or
removing the only admin → 409 ``last_admin``.
"""

from __future__ import annotations

import secrets

import redis.asyncio as redis_asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity, get_db, get_real_ip, require_org_membership
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import RawFinding, Severity
from app.models.scans import Scan, ScanStatus
from app.models.vulnerabilities import Vulnerability, VulnerabilityStatus
from app.redis_client import get_redis
from app.routes.projects import require_admin_or_api_key
from app.schemas.orgs import (
    LastCompletedScan,
    MemberInviteRequest,
    MemberInviteResponse,
    MemberItem,
    MemberRolePatchRequest,
    OpenVulnerabilityCounts,
    OrgPatchRequest,
    OrgResponse,
    OrgSummaryResponse,
    ProjectCounts,
    ScanCounts,
)
from app.services.audit import OrgAction, audit
from app.services.auth import hash_password
from app.services.email import EmailService, get_email_service
from app.services.email_verification import issue_email_verification_token
from app.services.password_reset import issue_password_reset_token

router = APIRouter(prefix="/orgs/{org_id}", tags=["orgs"])

_NOT_FOUND = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
_INSUFFICIENT_ROLE = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_role"
)
_ALREADY_MEMBER = HTTPException(status_code=status.HTTP_409_CONFLICT, detail="already_member")
_LAST_ADMIN = HTTPException(status_code=status.HTTP_409_CONFLICT, detail="last_admin")

_ACTIVE: tuple[ScanStatus, ...] = (
    ScanStatus.QUEUED,
    ScanStatus.RECONNING,
    ScanStatus.RUNNING,
    ScanStatus.ANALYZING,
)
_FINISHED: tuple[ScanStatus, ...] = (ScanStatus.COMPLETED, ScanStatus.PARTIAL)


@router.get("/summary", response_model=OrgSummaryResponse)
async def get_org_summary(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
) -> OrgSummaryResponse:
    # Projects: live (non-archived) only; verified split drives the
    # "needs you" card.
    proj_row = (
        await db.execute(
            select(
                func.count(Project.id),
                func.count(Project.id).filter(Project.domain_verified.is_(True)),
            ).where(
                Project.organization_id == org_id,
                Project.archived_at.is_(None),
            )
        )
    ).one()
    projects_total, projects_verified = int(proj_row[0]), int(proj_row[1])

    # Scans: lifetime total, currently active, finished in the last 30 days.
    since = datetime.now(timezone.utc) - timedelta(days=30)
    scan_row = (
        await db.execute(
            select(
                func.count(Scan.id),
                func.count(Scan.id).filter(Scan.status.in_(_ACTIVE)),
                func.count(Scan.id).filter(Scan.status.in_(_FINISHED), Scan.completed_at >= since),
            ).where(Scan.organization_id == org_id)
        )
    ).one()

    # Open vulnerabilities by severity + corroborated (seen by ≥2 engines),
    # scoped to each live project's LATEST finished scan. Every scan
    # creates its own vulnerability rows and nothing links a re-found
    # issue to last week's copy yet (cross-scan dedup is the follow-up
    # logged in shieldscan-docs/DRIFT-LOG.md, 2026-11-07), so counting
    # across all scans would report one CSP gap fifty times. "What is
    # open on my current targets" is the question the dashboard asks.
    latest_scan_ids = (
        select(Scan.id)
        .join(Project, Project.id == Scan.project_id)
        .where(
            Scan.organization_id == org_id,
            Scan.status.in_(_FINISHED),
            Project.archived_at.is_(None),
        )
        .distinct(Scan.project_id)
        .order_by(
            Scan.project_id,
            Scan.completed_at.desc().nulls_last(),
            Scan.created_at.desc(),
        )
    ).scalar_subquery()
    sev_rows = (
        await db.execute(
            select(
                Vulnerability.severity,
                func.count(Vulnerability.id),
                func.count(Vulnerability.id).filter(Vulnerability.corroborated_count >= 2),
            )
            .where(
                Vulnerability.organization_id == org_id,
                Vulnerability.status == VulnerabilityStatus.OPEN,
                Vulnerability.scan_id.in_(latest_scan_ids),
            )
            .group_by(Vulnerability.severity)
        )
    ).all()
    by_sev = {sev.value: int(n) for sev, n, _ in sev_rows}
    open_counts = OpenVulnerabilityCounts(
        **{s.value: by_sev.get(s.value, 0) for s in Severity},
        total=sum(by_sev.values()),
        corroborated=sum(int(c) for _, _, c in sev_rows),
    )

    # Last finished scan with its raw→unique figure (the "noise removed" tile).
    last_row = (
        await db.execute(
            select(Scan, Project.name)
            .join(Project, Project.id == Scan.project_id)
            .where(Scan.organization_id == org_id, Scan.status.in_(_FINISHED))
            .order_by(Scan.completed_at.desc().nulls_last(), Scan.created_at.desc())
            .limit(1)
        )
    ).one_or_none()
    last: LastCompletedScan | None = None
    if last_row is not None:
        last_scan, project_name = last_row
        raw_n = (
            await db.execute(
                select(func.count(RawFinding.id)).where(RawFinding.scan_id == last_scan.id)
            )
        ).scalar_one()
        vuln_n = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == last_scan.id)
            )
        ).scalar_one()
        last = LastCompletedScan(
            id=last_scan.id,
            project_id=last_scan.project_id,
            project_name=project_name,
            status=last_scan.status.value,
            completed_at=last_scan.completed_at,
            raw_finding_count=int(raw_n),
            vulnerability_count=int(vuln_n),
        )

    return OrgSummaryResponse(
        organization_id=org_id,
        projects=ProjectCounts(
            total=projects_total,
            verified=projects_verified,
            unverified=projects_total - projects_verified,
        ),
        scans=ScanCounts(
            total=int(scan_row[0]),
            active=int(scan_row[1]),
            completed_30d=int(scan_row[2]),
        ),
        open_vulnerabilities=open_counts,
        last_completed_scan=last,
    )


# ---------------------------------------------------------------- helpers


def _actor_id(identity: AuthIdentity) -> UUID | None:
    return identity.user.id if identity.user is not None else None


async def require_admin_jwt(
    identity: AuthIdentity = Depends(require_org_membership(jwt_only=True)),
) -> AuthIdentity:
    """Admin JWT only — for member management. API keys are rejected by
    the ``jwt_only`` dependency before the role check runs."""
    if identity.role != MembershipRole.ADMIN:
        raise _INSUFFICIENT_ROLE
    return identity


async def _load_org(db: AsyncSession, org_id: UUID) -> Organization:
    org = await db.get(Organization, org_id)
    if org is None:  # pragma: no cover — membership dep already proved it exists
        raise _NOT_FOUND
    return org


async def _member_count(db: AsyncSession, org_id: UUID) -> int:
    n = (
        await db.execute(
            select(func.count(Membership.id)).where(Membership.organization_id == org_id)
        )
    ).scalar_one()
    return int(n)


async def _admin_count(db: AsyncSession, org_id: UUID) -> int:
    n = (
        await db.execute(
            select(func.count(Membership.id)).where(
                Membership.organization_id == org_id,
                Membership.role == MembershipRole.ADMIN,
            )
        )
    ).scalar_one()
    return int(n)


async def _org_response(db: AsyncSession, org: Organization, identity: AuthIdentity) -> OrgResponse:
    return OrgResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        industry=org.industry,
        country=org.country,
        company_size=org.company_size,
        created_at=org.created_at,
        member_count=await _member_count(db, org.id),
        my_role=identity.role.value if identity.role is not None else None,
    )


def _member_item(m: Membership, u: User) -> MemberItem:
    return MemberItem(
        user_id=u.id,
        email=u.email,
        full_name=u.full_name,
        role=m.role.value,
        email_verified=u.email_verified,
        joined_at=m.created_at,
    )


async def _get_membership(
    db: AsyncSession, org_id: UUID, user_id: UUID
) -> tuple[Membership, User] | None:
    row = (
        await db.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.organization_id == org_id, Membership.user_id == user_id)
        )
    ).one_or_none()
    if row is None:
        return None
    return row[0], row[1]


# ---------------------------------------------------------------- org settings


@router.get("", response_model=OrgResponse)
async def get_org(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
) -> OrgResponse:
    org = await _load_org(db, org_id)
    return await _org_response(db, org, identity)


@router.patch("", response_model=OrgResponse)
async def patch_org(
    org_id: UUID,
    body: OrgPatchRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_admin_or_api_key),
    db: AsyncSession = Depends(get_db),
) -> OrgResponse:
    org = await _load_org(db, org_id)
    changes = body.model_dump(exclude_unset=True)
    changed: list[str] = []
    for field, value in changes.items():
        if getattr(org, field) != value:
            setattr(org, field, value)
            changed.append(field)
    if changed:
        await db.flush()
        await audit(
            db,
            organization_id=org_id,
            actor_id=_actor_id(identity),
            action=OrgAction.ORG_UPDATED,
            resource_type="organization",
            resource_id=org_id,
            ip_address=get_real_ip(request),
            user_agent=request.headers.get("User-Agent"),
            details={"fields": sorted(changed)},
        )
        await db.commit()
        await db.refresh(org)
    return await _org_response(db, org, identity)


# ---------------------------------------------------------------- members


@router.get("/members", response_model=list[MemberItem])
async def list_members(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
) -> list[MemberItem]:
    rows = (
        await db.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.organization_id == org_id)
            .order_by(Membership.created_at.asc(), User.email.asc())
        )
    ).all()
    return [_member_item(m, u) for m, u in rows]


@router.post(
    "/members",
    response_model=MemberInviteResponse,
    status_code=status.HTTP_201_CREATED,
)
async def invite_member(
    org_id: UUID,
    body: MemberInviteRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_admin_jwt),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
    email_service: EmailService = Depends(get_email_service),
) -> MemberInviteResponse:
    """Add an existing account to the org, or create one and email an
    invite. A new account gets a random unusable password; the invite
    link carries a password-reset token (set password, 1h) and an
    email-verification token (24h), so one click completes onboarding.
    Email dispatch happens after commit — the membership stands even if
    SMTP hiccups (the admin can re-invite; the user can use "forgot
    password")."""
    org = await _load_org(db, org_id)
    user = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    invited_new_user = user is None

    if user is None:
        user = User(
            email=body.email,
            hashed_password=hash_password(secrets.token_urlsafe(32)),
            full_name=body.full_name or body.email.split("@", 1)[0],
            email_verified=False,
        )
        db.add(user)
        await db.flush()
    elif await _get_membership(db, org_id, user.id) is not None:
        raise _ALREADY_MEMBER

    membership = Membership(user_id=user.id, organization_id=org_id, role=body.role)
    db.add(membership)
    await db.flush()

    await audit(
        db,
        organization_id=org_id,
        actor_id=_actor_id(identity),
        action=OrgAction.MEMBER_INVITED,
        resource_type="membership",
        resource_id=membership.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "target_user_id": str(user.id),
            "role": body.role.value,
            "invited_new_user": invited_new_user,
        },
    )
    await db.commit()
    await db.refresh(membership)
    await db.refresh(user)

    inviter = identity.user.full_name if identity.user is not None else "An admin"
    if invited_new_user:
        reset_token = await issue_password_reset_token(redis, user.id)
        verify_token = await issue_email_verification_token(redis, user.id)
        await email_service.send(
            to=user.email,
            subject=f"{inviter} invited you to {org.name} on ShieldScan",
            body=(
                f"Hi {user.full_name},\n\n"
                f"{inviter} invited you to join {org.name} on ShieldScan as "
                f"{body.role.value}.\n\n"
                f"Set your password and activate your account: "
                f"https://app.shieldscan.io/accept-invite"
                f"?reset={reset_token}&verify={verify_token}\n\n"
                f"The set-password link is valid for 1 hour; if it expires, "
                f'use "Forgot password" with this email address.\n'
            ),
            template="member_invite_new",
        )
    else:
        await email_service.send(
            to=user.email,
            subject=f"You've been added to {org.name} on ShieldScan",
            body=(
                f"Hi {user.full_name},\n\n"
                f"{inviter} added you to {org.name} on ShieldScan as "
                f"{body.role.value}. Sign in to switch to it: "
                f"https://app.shieldscan.io/login\n"
            ),
            template="member_invite_existing",
        )

    item = _member_item(membership, user)
    return MemberInviteResponse(**item.model_dump(), invited_new_user=invited_new_user)


@router.patch("/members/{user_id}", response_model=MemberItem)
async def change_member_role(
    org_id: UUID,
    user_id: UUID,
    body: MemberRolePatchRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_admin_jwt),
    db: AsyncSession = Depends(get_db),
) -> MemberItem:
    found = await _get_membership(db, org_id, user_id)
    if found is None:
        raise _NOT_FOUND
    membership, user = found
    previous = membership.role
    if previous == body.role:
        return _member_item(membership, user)
    if previous == MembershipRole.ADMIN and await _admin_count(db, org_id) <= 1:
        raise _LAST_ADMIN

    membership.role = body.role
    await db.flush()
    await audit(
        db,
        organization_id=org_id,
        actor_id=_actor_id(identity),
        action=OrgAction.MEMBER_ROLE_CHANGED,
        resource_type="membership",
        resource_id=membership.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "target_user_id": str(user.id),
            "previous_role": previous.value,
            "role": body.role.value,
        },
    )
    await db.commit()
    await db.refresh(membership)
    return _member_item(membership, user)


@router.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    org_id: UUID,
    user_id: UUID,
    request: Request,
    identity: AuthIdentity = Depends(require_admin_jwt),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Remove a membership (the user account itself is untouched — it
    may belong to other orgs). Admins may remove themselves as long as
    another admin remains."""
    found = await _get_membership(db, org_id, user_id)
    if found is None:
        raise _NOT_FOUND
    membership, user = found
    if membership.role == MembershipRole.ADMIN and await _admin_count(db, org_id) <= 1:
        raise _LAST_ADMIN

    membership_id = membership.id
    previous_role = membership.role.value
    await db.delete(membership)
    await db.flush()
    await audit(
        db,
        organization_id=org_id,
        actor_id=_actor_id(identity),
        action=OrgAction.MEMBER_REMOVED,
        resource_type="membership",
        resource_id=membership_id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "target_user_id": str(user.id),
            "previous_role": previous_role,
        },
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
