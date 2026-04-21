"""Email service abstraction (Sub-task 2.3.1).

M2 ships the ``ConsoleEmailService`` stub: outbound mail is logged to
stdout/structured logger, never delivered. Real SMTP (likely SendGrid
per IMPLEMENTATION-PLAN §2.5) lands in M12.5.

The protocol (``EmailService``) is the stable interface — swapping
the implementation in M12.5 should not touch any caller. Callers
receive an ``EmailService`` via FastAPI dependency injection
(``get_email_service``), which makes test overrides a one-liner.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SentEmail:
    """Immutable record of a dispatched email. Stubs capture these
    in memory for test assertions; the SMTP impl ignores them."""

    to: str
    subject: str
    body: str
    template: str | None
    sent_at: datetime


@runtime_checkable
class EmailService(Protocol):
    """Stable interface across stub and real impls. Keep narrow —
    every method added here must be implemented by both."""

    async def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        template: str | None = None,
    ) -> SentEmail: ...


class ConsoleEmailService:
    """Dev/M2 stub. Logs each send at INFO and keeps an in-process
    outbox so tests can assert on what was "sent" without pulling up
    an SMTP mock.

    Not thread-safe — one instance per app process, as with the
    real SMTP client (connection pool is in the transport layer).
    """

    def __init__(self) -> None:
        self._outbox: list[SentEmail] = []

    async def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        template: str | None = None,
    ) -> SentEmail:
        sent = SentEmail(
            to=to,
            subject=subject,
            body=body,
            template=template,
            sent_at=datetime.now(timezone.utc),
        )
        self._outbox.append(sent)
        logger.info(
            "[EMAIL STUB] to=%s subject=%r template=%s body=%r",
            to,
            subject,
            template,
            body,
        )
        return sent

    # --- test helpers (not part of the EmailService protocol) ---

    @property
    def outbox(self) -> list[SentEmail]:
        """All emails "sent" via this instance, in order."""
        return list(self._outbox)

    def clear(self) -> None:
        """Reset the in-memory outbox — typically used in test fixtures."""
        self._outbox.clear()


# Process-wide singleton. Endpoint dep ``get_email_service`` returns
# this; tests override the dep to inject a fresh instance.
_default_service: ConsoleEmailService | None = None


def get_email_service() -> EmailService:
    """FastAPI dependency: returns the shared email service.

    Returns an ``EmailService`` (the Protocol). Tests override this
    dep via ``app.dependency_overrides`` to inject a fresh stub
    whose outbox they can inspect.
    """
    global _default_service
    if _default_service is None:
        _default_service = ConsoleEmailService()
    return _default_service


def reset_default_service() -> None:
    """Test-only: drop the module-level singleton so the next
    ``get_email_service()`` call builds a fresh one. Keeps unit
    tests hermetic without touching ``app.dependency_overrides``."""
    global _default_service
    _default_service = None
