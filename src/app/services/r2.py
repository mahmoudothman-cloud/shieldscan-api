"""Cloudflare R2 (S3-compatible) object storage service (Task 3.3).

Thin async wrapper over boto3's synchronous S3 client. boto3 was already
a dependency for Stripe webhooks/etc.; aioboto3 would have been a new
dependency without enough payoff at MVP scale. ``asyncio.to_thread``
runs the blocking call on the default thread pool — equivalent
concurrency profile for the upload volumes Task 3.3 expects (a handful
of uploads/hour at MVP).

Re-instantiating the client per call is intentional. boto3's client is
not async-safe, sharing one across coroutines invites subtle bugs, and
client construction is ~10ms. If profiling later shows this as a hot
spot it can be cached behind a lock — until then, simplicity wins.

NOTE: ``put_object`` reads ``content`` fully into memory before sending.
Acceptable at MVP scale (low concurrency, infrequent uploads). If
memory pressure shows up under sustained load (target: > 5 concurrent
uploads × 500MB), revisit with multipart streaming.
"""

from __future__ import annotations

import asyncio
import logging

import boto3
from botocore.config import Config

from app.config import settings

logger = logging.getLogger(__name__)


def get_r2_client():
    """Return a fresh boto3 S3 client configured for the R2 endpoint.

    Cloudflare R2 exposes an S3-compatible API at
    ``https://<account_id>.r2.cloudflarestorage.com``. ``signature_version
    s3v4`` is the only one R2 accepts. ``region_name`` is required by
    boto3 but ignored by R2 — ``"auto"`` is the documented value.
    """
    return boto3.client(
        "s3",
        endpoint_url=f"https://{settings.R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=settings.R2_ACCESS_KEY,
        aws_secret_access_key=settings.R2_SECRET_KEY,
        region_name="auto",
        config=Config(signature_version="s3v4"),
    )


async def generate_presigned_get_url(r2_key: str, expiry: int = 600) -> str:
    """Generate a pre-signed R2 GetObject URL for worker-side binary fetch.

    Per MobSF R2 pre-signed URL task (shieldscan-docs commits b25e9ba
    design + 721f788 plan + 8f71b01 SPEC ADR-013/ADR-014 addendums):
    orchestrator-as-sole-writer-of-time-bounded-access-tokens pattern
    (analog to ADR-015 credential decryption). Engine workers consume
    the returned URL via plain HTTP GET (no R2 credentials required
    worker-side per Q3 (a) preference path).

    Q2 (a) lock: default 600s expiry (10x BullMQ queue-residence buffer;
    bounded stolen-URL exposure window; aligns with ADR-015 ephemeral-
    access-token discipline). Y-PRESIGN-METHOD (a) lock: boto3 sync-
    wrapped via ``asyncio.to_thread`` mirrors existing ``put_object``
    pattern at this module; zero new dependencies (boto3
    ``generate_presigned_url`` is built-in).
    """
    client = get_r2_client()
    return await asyncio.to_thread(
        client.generate_presigned_url,
        "get_object",
        Params={"Bucket": settings.R2_BUCKET, "Key": r2_key},
        ExpiresIn=expiry,
    )


async def put_object(key: str, content: bytes, content_type: str) -> None:
    """Upload ``content`` to ``settings.R2_BUCKET`` under ``key``.

    Raises whatever ``boto3.client.put_object`` raises — typical paths:
      * ``botocore.exceptions.EndpointConnectionError`` → R2 unreachable
        (caller maps to 503 ``storage_unavailable``).
      * ``botocore.exceptions.ClientError`` → S3-protocol error (auth,
        permissions, signature) → caller maps to 500 ``internal_error``.

    Caller is responsible for not creating a DB row before this returns
    successfully — a failed upload should leave no MobileUpload trace.
    """
    client = get_r2_client()
    await asyncio.to_thread(
        client.put_object,
        Bucket=settings.R2_BUCKET,
        Key=key,
        Body=content,
        ContentType=content_type,
    )
