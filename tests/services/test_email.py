"""Tests for app.services.email — Sub-task 2.3.1.

The stub is simple by design, but we pin the contract explicitly:
  - send() records to the outbox in order
  - SentEmail timestamps are UTC-aware
  - ConsoleEmailService satisfies the EmailService Protocol
  - logs are emitted at INFO with the address + subject
  - clear() empties the outbox
  - get_email_service returns a cached singleton that tests can reset
"""

from __future__ import annotations

import logging

import pytest

from app.services.email import (
    ConsoleEmailService,
    EmailService,
    SentEmail,
    get_email_service,
    reset_default_service,
)


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_default_service()
    yield
    reset_default_service()


@pytest.mark.asyncio
async def test_send_records_to_outbox():
    svc = ConsoleEmailService()
    sent = await svc.send(to="a@b.c", subject="hi", body="body")
    assert isinstance(sent, SentEmail)
    assert sent.to == "a@b.c"
    assert sent.subject == "hi"
    assert sent.body == "body"
    assert sent.template is None
    assert len(svc.outbox) == 1
    assert svc.outbox[0] is sent


@pytest.mark.asyncio
async def test_send_preserves_order():
    svc = ConsoleEmailService()
    await svc.send(to="one@x", subject="s1", body="b1")
    await svc.send(to="two@x", subject="s2", body="b2")
    await svc.send(to="three@x", subject="s3", body="b3")
    assert [e.to for e in svc.outbox] == ["one@x", "two@x", "three@x"]


@pytest.mark.asyncio
async def test_sent_email_timestamp_is_utc_aware():
    svc = ConsoleEmailService()
    sent = await svc.send(to="a@b.c", subject="s", body="b")
    assert sent.sent_at.tzinfo is not None
    # offset == 0 proves UTC, not just "some zone".
    assert sent.sent_at.utcoffset().total_seconds() == 0


@pytest.mark.asyncio
async def test_template_arg_is_stored():
    svc = ConsoleEmailService()
    sent = await svc.send(
        to="a@b.c",
        subject="verify",
        body="click here",
        template="verify_email",
    )
    assert sent.template == "verify_email"


def test_console_service_satisfies_email_service_protocol():
    svc = ConsoleEmailService()
    # @runtime_checkable lets isinstance() verify the Protocol shape.
    assert isinstance(svc, EmailService)


@pytest.mark.asyncio
async def test_clear_empties_outbox():
    svc = ConsoleEmailService()
    await svc.send(to="a@b.c", subject="s", body="b")
    assert len(svc.outbox) == 1
    svc.clear()
    assert svc.outbox == []


@pytest.mark.asyncio
async def test_send_emits_info_log(caplog):
    svc = ConsoleEmailService()
    with caplog.at_level(logging.INFO, logger="app.services.email"):
        await svc.send(to="log@me.com", subject="subj", body="bod")
    assert any(
        "log@me.com" in rec.getMessage() and "subj" in rec.getMessage()
        for rec in caplog.records
    ), f"expected send log, got: {[r.getMessage() for r in caplog.records]}"


def test_get_email_service_returns_singleton():
    a = get_email_service()
    b = get_email_service()
    assert a is b
    assert isinstance(a, ConsoleEmailService)


def test_reset_default_service_drops_singleton():
    a = get_email_service()
    reset_default_service()
    b = get_email_service()
    assert a is not b
