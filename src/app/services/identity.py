"""Identity orchestrator — atomic user + org + membership creation
(Sub-task 2.3.3).

Register flow sequence (per user-approved ordering — see DRIFT-LOG
2026-04-21 slug-collision retry policy):

    1. Mint email-verification token → Redis (BEFORE PG tx)
       - If Redis fails: bail early, no PG state.
    2. Open PG transaction::

          async with db.begin():
              Organization (with slug-collision retry via SAVEPOINT)
              SET app.current_org_id  (required: audit_logs is RLS'd)
              User
              Membership(role=ADMIN)
              audit(USER_REGISTERED)
              audit(EMAIL_VERIFICATION_SENT)

       - On any failure: PG rolls back; Redis token dangles but its
         24h TTL self-cleans and no user exists to use it.
    3. AFTER successful commit: email_service.send(verify_link).
       - Held outside the tx because SMTP latency (100ms–2s) must
         not hold a PG transaction open.
       - For M2 the stub can't fail; real SMTP (M12.5) will need a
         retry/dead-letter strategy at the callsite, not here.

The orchestrator is the transaction owner. Endpoints (Task 2.3.4) do
NOT call ``db.commit()``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import redis.asyncio as redis_asyncio

from slugify import slugify

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.tenant_context import set_tenant_context
from app.models.identity import Membership, MembershipRole, Organization, User
from app.services.audit import AuthAction, audit
from app.services.auth import hash_password
from app.services.email import EmailService
from app.services.email_verification import issue_email_verification_token
from app.services.plans import ensure_free_subscription


# ---------------------------------------------------------------- exceptions


class RegisterError(Exception):
    """Base class for identity-orchestrator failures."""


class EmailAlreadyRegistered(RegisterError):
    """The email is already in use. Endpoint translates to a generic
    400 — see ADDENDUM M2 envelope item 6a (no user enumeration).
    """


class SlugGenerationFailed(RegisterError):
    """Could not find an unused slug after MAX_SLUG_ATTEMPTS retries."""


# ---------------------------------------------------------------- constants

# Bcrypt 72-byte limit — enforced here so non-HTTP callers (CLI, tests,
# background jobs) get the same rejection as the HTTP register endpoint.
# See ADR-010.
MAX_PASSWORD_BYTES = 72

# 5 attempts: base slug + base-2 + base-3 + base-4 + base-5. User-visible
# organization names that collide 5 times are vanishingly rare; on the
# rare miss the caller can try a different name.
MAX_SLUG_ATTEMPTS = 5


# ---------------------------------------------------------------- helpers


@asynccontextmanager
async def _owning_tx(db: AsyncSession) -> AsyncIterator[None]:
    """Open a transaction if none is active; otherwise nest as a
    SAVEPOINT.

    Production FastAPI flows can have a SELECT (e.g. from a dep like
    ``get_current_user``) auto-begin the session before the endpoint
    body runs. A bare ``db.begin()`` at the orchestrator boundary
    would then raise ``InvalidRequestError: A transaction is already
    begun``. Nesting as a SAVEPOINT preserves the "orchestrator owns
    the outcome" contract: if our work fails, our savepoint rolls
    back; if the outer caller's tx later rolls back, ours goes too.
    """
    if db.in_transaction():
        async with db.begin_nested():
            yield
    else:
        async with db.begin():
            yield


async def _create_org_with_unique_slug(
    db: AsyncSession,
    name: str,
) -> Organization:
    """Attempt to create an Organization with a slugified name; on
    unique-constraint collision, retry with ``-2``, ``-3``, … up to
    ``MAX_SLUG_ATTEMPTS``. Each attempt runs in its own SAVEPOINT so
    a collision does not poison the outer transaction.
    """
    base_slug = slugify(name) or "org"
    for attempt in range(1, MAX_SLUG_ATTEMPTS + 1):
        candidate = base_slug if attempt == 1 else f"{base_slug}-{attempt}"
        org = Organization(name=name, slug=candidate)
        try:
            async with db.begin_nested():  # SAVEPOINT
                db.add(org)
                await db.flush()
            return org
        except IntegrityError:
            # Savepoint rolled back; try the next candidate. The outer
            # transaction is untouched.
            continue
    raise SlugGenerationFailed(
        f"could not find unused slug after {MAX_SLUG_ATTEMPTS} attempts "
        f"(base={base_slug!r})"
    )


# ---------------------------------------------------------------- orchestrator


async def register_identity(
    db: AsyncSession,
    redis: redis_asyncio.Redis,
    email_service: EmailService,
    *,
    email: str,
    password: str,
    full_name: str,
    organization_name: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> User:
    """Atomically create Org + User + Membership(ADMIN) + audit rows;
    issue an email-verification token; send the verification email
    after commit.

    Returns the created ``User``. Raises:
        EmailAlreadyRegistered:     on unique-email violation.
        SlugGenerationFailed:       5 consecutive slug collisions.
        ValueError:                 password exceeds bcrypt's 72-byte limit.

    Transaction ownership contract
    ------------------------------

    - **Fresh session (no active tx):** ``register_identity`` owns the
      transaction. Commits on success, rolls back on failure. The
      caller MUST NOT call ``commit()``.

    - **Session with an active tx:** ``register_identity`` opens a
      SAVEPOINT (via ``_owning_tx`` → ``db.begin_nested()``). Commits
      the savepoint on success, rolls back the savepoint on failure.
      The **outer** transaction's commit is the **caller's**
      responsibility. If the caller forgets to commit, this function
      appears to succeed but never persists anything.

    In practice: the normal caller is a FastAPI endpoint body, and
    FastAPI's dependency chain commits on request completion. Only
    background jobs / CLI tools that manage their own transactions
    need to commit explicitly.
    """
    # ADR-010 consequence: enforce 72-byte password limit at the
    # service boundary. HTTP endpoint also validates for a cleaner 400.
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"password exceeds bcrypt's {MAX_PASSWORD_BYTES}-byte limit"
        )

    # Defensive email normalization: HTTP callers already went through
    # the RegisterRequest @field_validator, but non-HTTP callers (CLI
    # scripts, background jobs, future admin tools) land here directly.
    # Redundant for HTTP path, load-bearing for every other caller.
    # See DRIFT-LOG 2026-04-21 email-normalization entry.
    email = email.strip().lower()

    # Transaction order (per user-approved sequencing):
    #   open tx → org (slug retry) → user (flush) → mint verify
    #   token against user.id → membership → audits → commit →
    #   send email (AFTER commit, SMTP latency).
    #
    # If Redis fails during mint: IntegrityError/RedisError propagates
    # and the outer tx rolls back — no half-registered user. If PG
    # rolls back for any other reason, the Redis key dangles but its
    # 24h TTL self-cleans and no user exists to receive the email.

    try:
        async with _owning_tx(db):
            # Org with slug-collision retry.
            org = await _create_org_with_unique_slug(db, organization_name)

            # Set tenant GUC for RLS on audit_logs + future tenant tables.
            # shieldscan_app role cannot write to audit_logs without this.
            await set_tenant_context(db, org.id)

            # Every org carries exactly one live subscription; new orgs
            # start on the live Free version (M12 slice 1).
            await ensure_free_subscription(db, org.id)

            # User.
            user = User(
                email=email,
                hashed_password=hash_password(password),
                full_name=full_name,
                email_verified=False,
            )
            db.add(user)
            try:
                await db.flush()
            except IntegrityError as e:
                # Unique email — surface a typed exception so the
                # endpoint can return a generic 400 (no user enumeration).
                raise EmailAlreadyRegistered(email) from e

            # Membership — registrant is admin of the new org.
            db.add(
                Membership(
                    user_id=user.id,
                    organization_id=org.id,
                    role=MembershipRole.ADMIN,
                )
            )

            # Verification token — Redis write inside the tx so a
            # rollback "undoes" it in spirit (the key dangles but the
            # 24h TTL self-cleans and no user exists to use it).
            token_plaintext = await issue_email_verification_token(
                redis, user.id
            )

            # Audit: registration + verification-sent (no token or hash
            # in details per retention-vs-expiry mismatch — see
            # DRIFT-LOG 2026-04-21 verification-audit-details).
            await audit(
                db,
                organization_id=org.id,
                actor_id=user.id,
                action=AuthAction.USER_REGISTERED,
                resource_type="user",
                resource_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=None,
            )
            await audit(
                db,
                organization_id=org.id,
                actor_id=user.id,
                action=AuthAction.EMAIL_VERIFICATION_SENT,
                resource_type="user",
                resource_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"method": "email"},
            )
    except EmailAlreadyRegistered:
        raise
    except IntegrityError as e:
        # Any other integrity violation we haven't typed — surface
        # opaquely rather than leaking schema details to the endpoint.
        raise RegisterError(f"integrity error during register: {e.orig}") from e

    # Step 3 — email AFTER commit (SMTP latency must not hold the tx).
    # For M2 the stub cannot fail; real SMTP (M12.5) wraps this in a
    # retry / dead-letter queue at the call site.
    await email_service.send(
        to=email,
        subject="Verify your ShieldScan email",
        body=(
            f"Hi {full_name},\n\n"
            f"Click to verify your email: "
            f"https://app.shieldscan.io/verify-email?token={token_plaintext}\n\n"
            f"Link expires in 24 hours."
        ),
        template="verify_email",
    )

    return user
