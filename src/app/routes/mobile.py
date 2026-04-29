"""Mobile-upload endpoint (Task 3.3).

Single endpoint:

    POST /v1/orgs/{org_id}/projects/{project_id}/mobile-uploads
        multipart/form-data: file=<.apk|.ipa>
        201 MobileUploadResponse

Auth: ``require_org_membership()`` — JWT or API key. Cross-tenant
collapses to 404 (no existence leak).

Rate limit: 10/hour per project, scope ``mobile_upload``.

Validation order (each layer fails closed before the next reads anything
expensive):

  1. Content-Length header pre-check. If the header alone exceeds the
     hard cap, 413 BEFORE the body is read — DoS protection.
  2. Filename extension allow-list (``.apk`` / ``.ipa``). 400 if not.
  3. Body size after read (Content-Length absent or wrong). 413 if
     over cap.
  4. ZIP magic-bytes check. 400 if the file isn't a real archive.
  5. R2 upload. On endpoint outage → 503; on any other ClientError →
     500. NO DB row created on either failure.
  6. DB insert + audit. Both inside one transaction so a DB failure
     can't leave a "ghost" audit row.

Error envelope: ``{"detail": "<code>"}`` per the codebase-wide
``ErrorResponse`` standard (Task 2.3.4). Plan literal used
``{"error": {"message": ...}}`` — codebase consistency wins. See
DRIFT-LOG 2026-04-26 entry 2.

R2 key shape: ``mobile-uploads/{org_id}/{project_id}/{upload_id}{ext}``.
Filename is intentionally NOT in the key — PII hygiene + log-leak
hygiene (filenames sometimes leak internal product names). The
filename IS preserved in the DB row for forensic value.
"""

from __future__ import annotations

import logging
from uuid import UUID, uuid4

from botocore.exceptions import ClientError, EndpointConnectionError
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import (
    AuthIdentity,
    check_rate_limits,
    get_db,
    get_rate_limiter,
    get_real_ip,
    require_org_membership,
)
from app.models.mobile import MobileUpload
from app.models.projects import Project
from app.schemas.mobile import MobileUploadResponse
from app.services import r2 as r2_service
from app.services.audit import ProjectAction, audit
from app.services.mobile import (
    extract_extension,
    has_zip_magic,
    is_allowed_extension,
    platform_for_extension,
)
from app.services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


# Module-level constant so tests can monkeypatch a small cap and the
# route picks it up. Source-of-truth value comes from settings; the
# module-level binding is the patch surface.
MOBILE_UPLOAD_HARD_LIMIT_BYTES = settings.MOBILE_UPLOAD_HARD_LIMIT_MB * 1024 * 1024


router = APIRouter(
    prefix="/orgs/{org_id}/projects/{project_id}/mobile-uploads",
    tags=["mobile"],
)


_NOT_FOUND = HTTPException(status_code=404, detail="not_found")


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=MobileUploadResponse,
)
async def upload_mobile_artifact(
    org_id: UUID,
    project_id: UUID,
    request: Request,
    file: UploadFile = File(...),
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    limiter: RateLimiter = Depends(get_rate_limiter),
):
    # ---- 1. Rate limit (per-project, 10/hr).
    await check_rate_limits(
        limiter,
        [("mobile_upload", str(project_id), 10, 3600)],
    )

    # ---- 2. Content-Length pre-check (early DoS reject).
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError:
            declared = -1
        if declared > MOBILE_UPLOAD_HARD_LIMIT_BYTES:
            raise HTTPException(status_code=413, detail="file_too_large")

    # ---- 3. Extension allow-list (cheap, pre-read body).
    ext = extract_extension(file.filename or "")
    if not is_allowed_extension(ext):
        raise HTTPException(status_code=400, detail="invalid_extension")

    # ---- 4. Read + size check + magic bytes.
    content = await file.read()
    if len(content) > MOBILE_UPLOAD_HARD_LIMIT_BYTES:
        raise HTTPException(status_code=413, detail="file_too_large")
    if not has_zip_magic(content):
        raise HTTPException(status_code=400, detail="file_not_a_mobile_package")

    platform = platform_for_extension(ext)

    # ---- 5. Project lookup (only NOW that the body is validated, so we
    # avoid a DB round-trip on garbage uploads).
    project = (
        await db.execute(
            select(Project).where(
                Project.id == project_id,
                Project.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if project is None:
        raise _NOT_FOUND

    # ---- 6. R2 upload BEFORE DB insert. If R2 fails we return cleanly
    # with no MobileUpload row + no audit row.
    upload_id = uuid4()
    r2_key = f"mobile-uploads/{org_id}/{project_id}/{upload_id}{ext}"
    content_type = file.content_type or "application/octet-stream"

    try:
        await r2_service.put_object(r2_key, content, content_type)
    except EndpointConnectionError as e:
        logger.error("R2 endpoint unreachable for project %s: %s", project_id, e)
        raise HTTPException(status_code=503, detail="storage_unavailable")
    except ClientError:
        logger.exception("R2 ClientError for project %s", project_id)
        raise HTTPException(status_code=500, detail="internal_error")

    # ---- 7. Persist DB row + audit. Single transaction.
    actor_user_id = identity.user.id if identity.user is not None else None
    api_key_prefix = (
        identity.api_key.key_prefix if identity.api_key is not None else None
    )

    upload = MobileUpload(
        id=upload_id,
        organization_id=org_id,
        project_id=project_id,
        uploaded_by=actor_user_id,
        filename=file.filename or "",
        file_extension=ext,
        file_size_bytes=len(content),
        platform=platform,
        r2_key=r2_key,
    )
    db.add(upload)
    await db.flush()

    audit_details: dict = {
        "platform": platform.value,
        "size_bytes": len(content),
    }
    if api_key_prefix is not None:
        audit_details["api_key_prefix"] = api_key_prefix

    await audit(
        db,
        organization_id=org_id,
        actor_id=actor_user_id,
        action=ProjectAction.PROJECT_MOBILE_UPLOADED,
        resource_type="project",
        resource_id=project_id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details=audit_details,  # type: ignore[arg-type]
    )
    await db.commit()
    await db.refresh(upload)

    return MobileUploadResponse(
        id=upload.id,
        project_id=upload.project_id,
        uploaded_by_user_id=upload.uploaded_by,
        filename=upload.filename,
        file_extension=upload.file_extension,
        file_size_bytes=upload.file_size_bytes,
        platform=upload.platform.value,
        r2_key=upload.r2_key,
        created_at=upload.created_at,
    )
