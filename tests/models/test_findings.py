from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.identity import Organization, User
from app.models.projects import Project
from app.models.raw_findings import (
    EngineCategory,
    MobileOS,
    RawFinding,
    Severity,
)
from app.models.scans import Scan, ScanStatus, ScanType
from app.models.vulnerabilities import (
    Vulnerability,
    VulnerabilityHistory,
    VulnerabilityStatus,
)
from tests.conftest import use_org


# ─── Structural: enums ──────────────────────────────────────────────────


def test_engine_category_has_thirteen_values_including_spa_and_discovery() -> None:
    values = {v.value for v in EngineCategory}
    expected = {
        "dast",
        "sast",
        "sca",
        "mobile",
        "infrastructure",
        "recon",
        "ssl",
        "api",
        "iac",
        "secrets",
        "container",
        "spa",
        "discovery",
    }
    assert values == expected, f"missing: {expected - values}; extra: {values - expected}"


def test_severity_enum_values() -> None:
    assert {v.value for v in Severity} == {"critical", "high", "medium", "low", "info"}


def test_mobile_os_enum_values() -> None:
    assert {v.value for v in MobileOS} == {"android", "ios"}


def test_vulnerability_status_enum_values() -> None:
    assert {v.value for v in VulnerabilityStatus} == {
        "open",
        "resolved",
        "false_positive",
        "accepted_risk",
    }


# ─── Structural: RawFinding has all required columns ────────────────────


def test_raw_finding_has_all_required_columns() -> None:
    cols = {c.name for c in inspect(RawFinding).columns}
    required = {
        # identity
        "tool_name",
        "engine_category",
        "scan_id",
        "organization_id",
        # classification
        "title",
        "description",
        "severity",
        "finding_type",
        "cwe_id",
        "owasp",
        "cvss_score",
        # web/API evidence
        "target_url",
        "parameter",
        "payload",
        "request",
        "response",
        # SAST evidence
        "code_file",
        "code_line",
        "code_snippet",
        # mobile evidence
        "mobile_os",
        "mobile_permission",
        "mobile_component_name",
        # SSL/TLS evidence
        "cipher_suite",
        "cert_subject",
        # metadata
        "raw_output_ref",
        "discovered_at",
        "fingerprint",
        # addendum (trufflehog)
        "secret_verified",
        # SPEC §7.3 schema extension (M6-close-followup, ADR-024)
        "references",
        "tags",
        "cvss_vector",
        "additional_cwes",
        # TimestampMixin
        "created_at",
        "updated_at",
    }
    missing = required - cols
    assert not missing, f"RawFinding missing columns: {missing}"


def test_secret_verified_is_nullable_with_no_default() -> None:
    col = inspect(RawFinding).columns["secret_verified"]
    assert col.nullable is True
    # NULL (non-secret finding) / TRUE (verified) / FALSE (pattern-only)
    assert col.default is None


def test_raw_finding_fingerprint_indexed() -> None:
    col = inspect(RawFinding).columns["fingerprint"]
    assert col.index is True
    assert col.nullable is False


# ─── Helpers ────────────────────────────────────────────────────────────


async def _setup_scan(db: AsyncSession) -> tuple[Organization, Scan]:
    org = Organization(name="Acme", slug="acme")
    db.add(org)
    await db.flush()
    await use_org(db, org.id)

    project = Project(
        organization_id=org.id,
        name="Acme Web",
        target_url="https://acme.test",
        root_domain="acme.test",
    )
    db.add(project)
    await db.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.RUNNING,
    )
    db.add(scan)
    await db.flush()
    return org, scan


def _base_finding_kwargs(org: Organization, scan: Scan, fingerprint: str) -> dict:
    # severity deliberately omitted — each test supplies its own.
    return {
        "organization_id": org.id,
        "scan_id": scan.id,
        "tool_name": "pytest",
        "title": "test finding",
        "description": "test",
        "finding_type": "test",
        "fingerprint": fingerprint,
    }


# ─── Functional: 4 distinct population patterns (per watch item) ───────


async def test_dast_finding_populates_web_fields_only(db_session: AsyncSession) -> None:
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-dast"),
        engine_category=EngineCategory.DAST,
        severity=Severity.HIGH,
        cwe_id="CWE-79",
        cvss_score=7.4,
        # web/API group populated
        target_url="https://acme.test/search?q=<script>",
        parameter="q",
        payload="<script>alert(1)</script>",
        request="GET /search?q=<script> HTTP/1.1\nHost: acme.test",
        response="HTTP/1.1 200 OK\n...",
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)

    # Web fields populated
    assert f.target_url and f.parameter and f.payload and f.request and f.response
    # SAST, mobile, SSL groups all NULL
    assert f.code_file is None and f.code_line is None and f.code_snippet is None
    assert (
        f.mobile_os is None
        and f.mobile_permission is None
        and f.mobile_component_name is None
    )
    assert f.cipher_suite is None and f.cert_subject is None
    assert f.secret_verified is None


async def test_sast_finding_populates_code_fields_only(db_session: AsyncSession) -> None:
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-sast"),
        engine_category=EngineCategory.SAST,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        code_file="src/routes/users.py",
        code_line=42,
        code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)

    assert f.code_file == "src/routes/users.py"
    assert f.code_line == 42
    assert f.code_snippet.startswith("cursor.execute")
    # Web, mobile, SSL groups all NULL
    assert all(
        v is None
        for v in (
            f.target_url,
            f.parameter,
            f.payload,
            f.request,
            f.response,
            f.mobile_os,
            f.mobile_permission,
            f.mobile_component_name,
            f.cipher_suite,
            f.cert_subject,
        )
    )


async def test_mobile_finding_populates_mobile_fields_only(
    db_session: AsyncSession,
) -> None:
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-mobile"),
        engine_category=EngineCategory.MOBILE,
        cwe_id="CWE-926",
        severity=Severity.HIGH,
        mobile_os=MobileOS.ANDROID,
        mobile_permission="android.permission.READ_SMS",
        mobile_component_name="com.example.app.LoginActivity",
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)

    assert f.mobile_os == MobileOS.ANDROID
    assert f.mobile_permission == "android.permission.READ_SMS"
    assert f.mobile_component_name == "com.example.app.LoginActivity"
    # Web, SAST, SSL groups all NULL
    assert all(
        v is None
        for v in (
            f.target_url,
            f.parameter,
            f.payload,
            f.request,
            f.response,
            f.code_file,
            f.code_line,
            f.code_snippet,
            f.cipher_suite,
            f.cert_subject,
        )
    )


async def test_ssl_finding_populates_ssl_fields_only(db_session: AsyncSession) -> None:
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-ssl"),
        engine_category=EngineCategory.SSL,
        cwe_id="CWE-326",
        severity=Severity.HIGH,
        cipher_suite="SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
        cert_subject="CN=expired.acme.test",
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)

    assert f.cipher_suite.startswith("SSL_CK_DES")
    assert f.cert_subject == "CN=expired.acme.test"
    # Web, SAST, mobile groups all NULL
    assert all(
        v is None
        for v in (
            f.target_url,
            f.parameter,
            f.payload,
            f.request,
            f.response,
            f.code_file,
            f.code_line,
            f.code_snippet,
            f.mobile_os,
            f.mobile_permission,
            f.mobile_component_name,
        )
    )


# ─── Functional: trufflehog verified secret ─────────────────────────────


async def test_verified_secret_sets_flag_true(db_session: AsyncSession) -> None:
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-verif-aws"),
        engine_category=EngineCategory.SECRETS,
        severity=Severity.CRITICAL,
        cwe_id="CWE-798",
        code_file="src/config.js",
        code_line=42,
        secret_verified=True,
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)
    assert f.secret_verified is True


# ─── Structural: partial index named exactly per addendum ──────────────


async def test_secret_verified_partial_index_exists(db_session: AsyncSession) -> None:
    # The index is created by Base.metadata.create_all (which our test
    # fixture calls). Verify the exact index name + partial predicate land
    # in pg_indexes.
    res = await db_session.execute(
        text(
            "SELECT indexdef FROM pg_indexes "
            "WHERE schemaname='public' "
            "AND indexname='idx_raw_findings_verified_secret'"
        )
    )
    rows = res.all()
    assert len(rows) == 1, "expected index idx_raw_findings_verified_secret to exist"
    indexdef = rows[0][0].lower()
    # Partial index predicate must be present
    assert "where" in indexdef
    assert "secret_verified" in indexdef


# ─── Vulnerability / VulnerabilityHistory / AuditLog basics ────────────


async def test_create_vulnerability_and_history(db_session: AsyncSession) -> None:
    org, scan = await _setup_scan(db_session)
    project = await db_session.get(Project, scan.project_id)
    assert project is not None

    vuln = Vulnerability(
        organization_id=org.id,
        scan_id=scan.id,
        project_id=project.id,
        title="SQL Injection",
        severity=Severity.CRITICAL,
        status=VulnerabilityStatus.OPEN,
        engine_category=EngineCategory.DAST,
        finding_type="sqli",
        cwe_id="CWE-89",
        fingerprint="vuln-fp-1",
    )
    db_session.add(vuln)
    await db_session.flush()

    history = VulnerabilityHistory(
        organization_id=org.id,
        vulnerability_id=vuln.id,
        from_status=VulnerabilityStatus.OPEN,
        to_status=VulnerabilityStatus.RESOLVED,
        notes="Fixed in PR #123",
    )
    db_session.add(history)
    await db_session.commit()
    assert history.id is not None


# ─── SPEC §7.3 schema extension (M6-close-followup, ADR-024) ────────────
# Verifies columns-ready posture: SQLAlchemy model accepts the 4 new
# fields. Ingest path tests (Pydantic schema + CompletionsConsumer
# extension) deferred to future findings-ingest task per ADR-024.


async def test_raw_finding_accepts_references_array(db_session: AsyncSession) -> None:
    """SPEC §7.3: References is Optional[list[str]]."""
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-spec73-refs"),
        engine_category=EngineCategory.DAST,
        severity=Severity.HIGH,
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            "https://example.com/advisory/2024-001",
        ],
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)
    assert f.references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "https://example.com/advisory/2024-001",
    ]


async def test_raw_finding_accepts_tags_array(db_session: AsyncSession) -> None:
    """SPEC §7.3: Tags is Optional[list[str]] (distinct from engine_category)."""
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-spec73-tags"),
        engine_category=EngineCategory.DAST,
        severity=Severity.HIGH,
        tags=["xss", "owasp-top-10", "automated"],
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)
    assert f.tags == ["xss", "owasp-top-10", "automated"]


async def test_raw_finding_accepts_cvss_vector_string(db_session: AsyncSession) -> None:
    """SPEC §7.3: CVSSVector is Optional[str] (canonical CVSS:3.1/...)."""
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-spec73-cvss"),
        engine_category=EngineCategory.DAST,
        severity=Severity.CRITICAL,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)
    assert f.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


async def test_raw_finding_accepts_additional_cwes_array(
    db_session: AsyncSession,
) -> None:
    """SPEC §7.3: AdditionalCWEs is Optional[list[str]] for multi-CWE findings.

    Load-bearing for ADR-024's M9 §8.2 forward-pin: cross-layer
    correlation must consider {primary cwe_id} ∪ additional_cwes
    intersection rather than primary cwe_id alone. Especially relevant
    for Dep-Check, which routinely emits 2-4 CWEs per CVE.
    """
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-spec73-multicwe"),
        engine_category=EngineCategory.SCA,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        additional_cwes=["CWE-20", "CWE-78"],
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)
    assert f.cwe_id == "CWE-89"
    assert f.additional_cwes == ["CWE-20", "CWE-78"]


async def test_raw_finding_new_fields_optional_when_absent(
    db_session: AsyncSession,
) -> None:
    """SPEC §7.3: All 4 new fields are nullable; absent values OK.

    Backward-compat regression guard: existing RawFinding insertions
    (created before SPEC §7.3 extension landed) must still work without
    setting any of the new fields. omitempty / Optional discipline holds
    on both sides of the wire.
    """
    org, scan = await _setup_scan(db_session)
    f = RawFinding(
        **_base_finding_kwargs(org, scan, "fp-spec73-absent"),
        engine_category=EngineCategory.DAST,
        severity=Severity.LOW,
    )
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)
    assert f.references is None
    assert f.tags is None
    assert f.cvss_vector is None
    assert f.additional_cwes is None


async def test_audit_log_is_append_only_shape(db_session: AsyncSession) -> None:
    # Append-only is enforced by convention (no UPDATE/DELETE from app code).
    # The model shape reflects that: created_at only, no updated_at column.
    cols = {c.name for c in inspect(AuditLog).columns}
    assert "created_at" in cols
    assert "updated_at" not in cols

    # Minimal insert
    org = Organization(name="Log Co", slug="logco")
    user = User(email="a@logco.test", hashed_password="x", full_name="A")
    db_session.add_all([org, user])
    await db_session.flush()
    await use_org(db_session, org.id)

    log = AuditLog(
        organization_id=org.id,
        actor_id=user.id,
        action="user.login",
        resource_type="user",
        resource_id=user.id,
        ip_address="203.0.113.5",
    )
    db_session.add(log)
    await db_session.commit()
    assert log.id is not None
