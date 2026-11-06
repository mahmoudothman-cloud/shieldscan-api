"""End-to-end tests for /v1/orgs/{org_id}/projects/{id}/mobile-uploads (Task 3.3).

19 tests pinning the mobile-upload contract:

  1. APK happy path (JWT)
  2. IPA happy path (JWT) — platform = ios
  3. .zip extension rejected (400 invalid_extension) — DRIFT 3.3 deviation
  4. Other extension (.txt) rejected (400 invalid_extension)
  5. Bad magic bytes (.apk that's not a ZIP) → 400 file_not_a_mobile_package
  6. File body too large → 413 file_too_large
  7. Content-Length header alone too large → 413 (early reject pre-read)
  8. Audit row written on success (PROJECT_MOBILE_UPLOADED) with platform + size_bytes
  9. Rate limit: 11th request inside the hour → 429 rate_limit_exceeded
 10. R2 EndpointConnectionError → 503 storage_unavailable, no DB row, no audit
 11. R2 generic ClientError → 500 internal_error, no DB row, no audit
 12. No Authorization header → 401
 13. API-key auth: happy path (response shape)
 14. Cross-tenant project (auth'd to org B, hitting org A's project) → 404
 15. R2 key shape: drops filename, includes upload_id + extension only
 16. API-key auth → uploaded_by IS NULL, actor_id IS NULL, api_key_prefix in audit details
 17. Project not found → 404
 18. Empty file body → 400 file_not_a_mobile_package (no magic bytes)
 19. Filename traversal attempt (`../../etc/passwd.apk`) → r2_key still safe
"""

from __future__ import annotations

import io
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import APIKey, Membership, MembershipRole, Organization, User
from app.models.mobile import MobileUpload
from app.models.projects import Project
from app.services.api_keys import generate_api_key
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org


# ---------------------------------------------------------------- helpers


def _zip_blob(payload: bytes = b"\x00" * 256) -> bytes:
    """A buffer that begins with the canonical local-file ZIP signature.
    Real APK/IPA files are ZIPs, so this passes the magic-bytes check."""
    return b"PK\x03\x04" + payload


def _empty_zip_blob() -> bytes:
    """Empty-archive end-of-central-directory signature — also valid ZIP."""
    return b"PK\x05\x06" + b"\x00" * 18


@pytest_asyncio.fixture
async def project_with_owner(client, db_session):
    """Org A admin + project + JWT headers + a live API key for the same org.
    Returns (org, user, project, jwt_headers, api_key_headers, api_key_row).
    """
    org = Organization(name="Mob Org", slug=f"mob-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"mob-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("MobPass-1"),
        full_name="M",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="MobApp",
        target_url="https://example.com",
        root_domain="example.com",
    )
    db_session.add(project)

    plain, key_hash, prefix = generate_api_key("live")
    api_key = APIKey(
        organization_id=org.id,
        name="ci",
        key_prefix=prefix,
        key_hash=key_hash,
    )
    db_session.add(api_key)

    await db_session.commit()
    await db_session.refresh(project)
    await db_session.refresh(api_key)

    jwt_headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    api_key_headers = {"Authorization": f"Bearer {plain}"}
    return org, user, project, jwt_headers, api_key_headers, api_key


@pytest_asyncio.fixture
async def other_org(db_session):
    """A second org with a project — used for cross-tenant tests."""
    org = Organization(name="Other Mob", slug=f"othermob-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"oth-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("OthPass-1"),
        full_name="O",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    return org, user, headers


def _files(filename: str, content: bytes, content_type: str = "application/octet-stream"):
    return {"file": (filename, io.BytesIO(content), content_type)}


# Patch path: tests stub out the R2 put_object service function so no real
# network call happens. Default stub records args and returns None.
class _R2Recorder:
    def __init__(self):
        self.calls: list[dict] = []

    async def __call__(self, key, content, content_type):
        self.calls.append(
            {"key": key, "size": len(content), "content_type": content_type}
        )


def _patch_r2_ok():
    rec = _R2Recorder()
    return patch("app.services.r2.put_object", rec), rec


# =============================================================== 1. APK happy path


@pytest.mark.asyncio
async def test_upload_apk_happy_path(project_with_owner, client, db_session):
    org, user, project, headers, _, _ = project_with_owner
    patcher, rec = _patch_r2_ok()
    with patcher:
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("app-release.apk", _zip_blob()),
            headers=headers,
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["project_id"] == str(project.id)
    assert body["uploaded_by_user_id"] == str(user.id)
    assert body["filename"] == "app-release.apk"
    assert body["file_extension"] == ".apk"
    assert body["platform"] == "android"
    assert body["file_size_bytes"] == len(_zip_blob())
    assert body["r2_key"].startswith(f"mobile-uploads/{org.id}/{project.id}/")
    assert body["r2_key"].endswith(".apk")
    UUID(body["id"])  # well-formed
    assert len(rec.calls) == 1
    assert rec.calls[0]["key"] == body["r2_key"]


# =============================================================== 2. IPA happy path


@pytest.mark.asyncio
async def test_upload_ipa_happy_path_platform_ios(project_with_owner, client):
    org, _, project, headers, _, _ = project_with_owner
    patcher, _ = _patch_r2_ok()
    with patcher:
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("MyApp.ipa", _zip_blob()),
            headers=headers,
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["platform"] == "ios"
    assert body["file_extension"] == ".ipa"
    assert body["r2_key"].endswith(".ipa")


# =============================================================== 3. .zip rejected (DRIFT)


@pytest.mark.asyncio
async def test_upload_zip_extension_rejected(project_with_owner, client):
    """Plan literal allowed .zip; DRIFT-LOG entry pins the deviation
    (no clear MVP use case, content-sniffing for platform creates
    adversarial-input attack surface)."""
    org, _, project, headers, _, _ = project_with_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
        files=_files("bundle.zip", _zip_blob()),
        headers=headers,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_extension"


# =============================================================== 4. Wrong extension


@pytest.mark.asyncio
async def test_upload_unknown_extension_rejected(project_with_owner, client):
    org, _, project, headers, _, _ = project_with_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
        files=_files("readme.txt", b"hello"),
        headers=headers,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_extension"


# =============================================================== 5. Magic bytes mismatch


@pytest.mark.asyncio
async def test_upload_apk_with_non_zip_content_rejected(project_with_owner, client):
    org, _, project, headers, _, _ = project_with_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
        files=_files("fake.apk", b"NOTAZIPFILECONTENT" + b"\x00" * 100),
        headers=headers,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "file_not_a_mobile_package"


# =============================================================== 6. File too large (body)


@pytest.mark.asyncio
async def test_upload_body_too_large(project_with_owner, client):
    org, _, project, headers, _, _ = project_with_owner
    # Patch the byte-limit down so we don't allocate 500MB+ in tests.
    with patch("app.routes.mobile.MOBILE_UPLOAD_HARD_LIMIT_BYTES", 1024):
        big = _zip_blob(b"\x00" * 4096)  # ~4KB > 1KB cap
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("big.apk", big),
            headers=headers,
        )
    assert r.status_code == 413
    assert r.json()["detail"] == "file_too_large"


# =============================================================== 7. Content-Length early reject


@pytest.mark.asyncio
async def test_upload_content_length_header_too_large(project_with_owner, client):
    """Server should reject early when Content-Length alone exceeds the
    cap, without reading the body (DoS protection at the ingress layer)."""
    org, _, project, headers, _, _ = project_with_owner

    # Build a small multipart body but lie about its size in the header.
    boundary = "----testboundary123"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="x.apk"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + _zip_blob() + f"\r\n--{boundary}--\r\n".encode()

    fake_size = 600 * 1024 * 1024
    req_headers = {
        **headers,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(fake_size),
    }
    with patch("app.routes.mobile.MOBILE_UPLOAD_HARD_LIMIT_BYTES", 100 * 1024 * 1024):
        # Send raw content; httpx won't recompute Content-Length when given content=bytes.
        # Patch the R2 stub too so a regression that reads the body doesn't escape.
        patcher, _ = _patch_r2_ok()
        with patcher:
            r = await client.post(
                f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
                content=body,
                headers=req_headers,
            )
    assert r.status_code == 413
    assert r.json()["detail"] == "file_too_large"


# =============================================================== 8. Audit row on success


@pytest.mark.asyncio
async def test_upload_writes_audit_row(project_with_owner, client, db_session):
    org, user, project, headers, _, _ = project_with_owner
    patcher, _ = _patch_r2_ok()
    blob = _zip_blob()
    with patcher:
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("app.apk", blob),
            headers=headers,
        )
    assert r.status_code == 201

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "project.mobile.uploaded")
        )
    ).scalars().all()
    assert len(rows) == 1
    a = rows[0]
    assert a.organization_id == org.id
    assert a.actor_id == user.id
    assert a.resource_type == "project"
    assert a.resource_id == project.id
    assert a.details["platform"] == "android"
    assert a.details["size_bytes"] == len(blob)


# =============================================================== 9. Rate limit


@pytest.mark.asyncio
async def test_upload_rate_limited_after_10_per_hour(project_with_owner, client):
    org, _, project, headers, _, _ = project_with_owner
    patcher, _ = _patch_r2_ok()
    with patcher:
        for _ in range(10):
            r = await client.post(
                f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
                files=_files("a.apk", _zip_blob()),
                headers=headers,
            )
            assert r.status_code == 201, r.text
        # 11th -> 429
        r11 = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("a.apk", _zip_blob()),
            headers=headers,
        )
    assert r11.status_code == 429
    assert r11.json()["detail"] == "rate_limit_exceeded"
    assert "Retry-After" in r11.headers


# =============================================================== 10. R2 endpoint outage → 503


@pytest.mark.asyncio
async def test_upload_r2_endpoint_outage_returns_503(
    project_with_owner, client, db_session
):
    org, _, project, headers, _, _ = project_with_owner

    from botocore.exceptions import EndpointConnectionError

    async def _fail(*a, **kw):
        raise EndpointConnectionError(endpoint_url="https://r2-bucket.example.com")

    with patch("app.services.r2.put_object", _fail):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("app.apk", _zip_blob()),
            headers=headers,
        )
    assert r.status_code == 503
    assert r.json()["detail"] == "storage_unavailable"

    # NO MobileUpload row.
    rows = (
        await db_session.execute(select(MobileUpload))
    ).scalars().all()
    assert rows == []
    # NO audit row for this action.
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "project.mobile.uploaded")
        )
    ).scalars().all()
    assert audits == []


# =============================================================== 11. R2 generic ClientError → 500


@pytest.mark.asyncio
async def test_upload_r2_generic_client_error_returns_500(
    project_with_owner, client, db_session
):
    org, _, project, headers, _, _ = project_with_owner

    from botocore.exceptions import ClientError

    async def _fail(*a, **kw):
        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="PutObject",
        )

    with patch("app.services.r2.put_object", _fail):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("app.apk", _zip_blob()),
            headers=headers,
        )
    assert r.status_code == 500
    assert r.json()["detail"] == "internal_error"

    rows = (
        await db_session.execute(select(MobileUpload))
    ).scalars().all()
    assert rows == []


# =============================================================== 12. No auth header


@pytest.mark.asyncio
async def test_upload_without_auth_returns_401(project_with_owner, client):
    org, _, project, _, _, _ = project_with_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
        files=_files("a.apk", _zip_blob()),
    )
    assert r.status_code == 401


# =============================================================== 13. API key happy path


@pytest.mark.asyncio
async def test_upload_via_api_key_happy_path(project_with_owner, client):
    org, _, project, _, api_key_headers, _ = project_with_owner
    patcher, _ = _patch_r2_ok()
    with patcher:
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("app.apk", _zip_blob()),
            headers=api_key_headers,
        )
    assert r.status_code == 201, r.text
    body = r.json()
    # uploaded_by_user_id field MUST exist in the response shape so
    # clients can rely on it; null for API-key uploads.
    assert "uploaded_by_user_id" in body
    assert body["uploaded_by_user_id"] is None


# =============================================================== 14. Cross-tenant 404


@pytest.mark.asyncio
async def test_upload_cross_tenant_returns_404(project_with_owner, other_org, client):
    org, _, project, _, _, _ = project_with_owner
    _, _, other_headers = other_org
    patcher, _ = _patch_r2_ok()
    with patcher:
        # Other-org admin pointing at org's project: 404 (not 403 — no leak).
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("a.apk", _zip_blob()),
            headers=other_headers,
        )
    assert r.status_code == 404


# =============================================================== 15. R2 key shape (no filename leak)


@pytest.mark.asyncio
async def test_r2_key_does_not_include_user_filename(project_with_owner, client):
    org, _, project, headers, _, _ = project_with_owner
    patcher, rec = _patch_r2_ok()
    sneaky = "secret-internal-name-PII.apk"
    with patcher:
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files(sneaky, _zip_blob()),
            headers=headers,
        )
    assert r.status_code == 201
    key = rec.calls[0]["key"]
    assert "secret-internal-name-PII" not in key
    # Shape: mobile-uploads/{org}/{project}/{upload_id}.apk
    parts = key.split("/")
    assert parts[0] == "mobile-uploads"
    assert parts[1] == str(org.id)
    assert parts[2] == str(project.id)
    assert parts[3].endswith(".apk")
    # The upload_id segment is a UUID hex (32) — no filename smuggled in.
    UUID(parts[3].rsplit(".", 1)[0])


# =============================================================== 16. API-key NULL pin


@pytest.mark.asyncio
async def test_upload_via_api_key_writes_null_uploaded_by(
    project_with_owner, client, db_session
):
    """DRIFT-LOG entry 5: MobileUpload.uploaded_by is nullable so API-key
    uploads (which have no user actor) are first-class.
    Pinned at the test layer so a future "fix" of nullable=False breaks
    this test instead of silently breaking API-key uploads."""
    org, _, project, _, api_key_headers, api_key_row = project_with_owner
    patcher, _ = _patch_r2_ok()
    with patcher:
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("app.apk", _zip_blob()),
            headers=api_key_headers,
        )
    assert r.status_code == 201
    body = r.json()
    assert body["uploaded_by_user_id"] is None

    upload = (
        await db_session.execute(select(MobileUpload).where(MobileUpload.id == UUID(body["id"])))
    ).scalar_one()
    assert upload.uploaded_by is None

    audit_rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "project.mobile.uploaded")
        )
    ).scalars().all()
    assert len(audit_rows) == 1
    a = audit_rows[0]
    assert a.actor_id is None
    assert a.details["api_key_prefix"] == api_key_row.key_prefix


# =============================================================== 17. Project not found


@pytest.mark.asyncio
async def test_upload_project_not_found(project_with_owner, client):
    org, _, _, headers, _, _ = project_with_owner
    bogus = uuid4()
    patcher, _ = _patch_r2_ok()
    with patcher:
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{bogus}/mobile-uploads",
            files=_files("app.apk", _zip_blob()),
            headers=headers,
        )
    assert r.status_code == 404


# =============================================================== 18. Empty body rejected


@pytest.mark.asyncio
async def test_upload_empty_body_rejected(project_with_owner, client):
    org, _, project, headers, _, _ = project_with_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
        files=_files("empty.apk", b""),
        headers=headers,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "file_not_a_mobile_package"


# =============================================================== 19. Filename sanitization


@pytest.mark.asyncio
async def test_upload_filename_traversal_neutralized(project_with_owner, client, db_session):
    """Even if the client uses a path-traversal filename, the R2 key must
    NOT include the filename — so traversal can't escape the
    mobile-uploads/{org}/{project}/ prefix."""
    org, _, project, headers, _, _ = project_with_owner
    patcher, rec = _patch_r2_ok()
    with patcher:
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/mobile-uploads",
            files=_files("../../etc/passwd.apk", _zip_blob()),
            headers=headers,
        )
    assert r.status_code == 201
    key = rec.calls[0]["key"]
    assert ".." not in key
    assert "etc/passwd" not in key
    # Filename is preserved AS-IS in the DB row (audit/forensic value),
    # but the R2 key is decoupled from it. Confirm both.
    upload = (
        await db_session.execute(select(MobileUpload).where(MobileUpload.id == UUID(r.json()["id"])))
    ).scalar_one()
    assert upload.filename == "../../etc/passwd.apk"
    assert ".." not in upload.r2_key
