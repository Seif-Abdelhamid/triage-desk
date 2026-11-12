"""Webhook authenticity (HMAC-SHA256) and replay protection."""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import WebhookDelivery, utcnow

_SIG_RE = re.compile(r"^sha256=([0-9a-f]{64})$")
_DELIVERY_RE = re.compile(r"^[0-9A-Za-z-]{1,64}$")


def sign(secret: str, body: bytes) -> str:
    """The X-Hub-Signature-256 value GitHub would send for ``body``."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    """Constant-time check of X-Hub-Signature-256 over the *raw* request body.

    Fails closed: an empty secret, a missing header, the legacy SHA-1 header
    or a malformed value are all rejected.
    """
    if not secret or not header:
        return False
    match = _SIG_RE.match(header.strip())
    if match is None:
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, match.group(1))


def valid_delivery_id(delivery_id: str | None) -> bool:
    return bool(delivery_id) and _DELIVERY_RE.match(delivery_id or "") is not None


def record_delivery(session: Session, delivery_id: str, event: str) -> bool:
    """Insert the delivery id. False if it was already seen (a replay).

    Relies on the primary-key constraint, so two API replicas racing on the
    same delivery cannot both accept it.
    """
    session.add(WebhookDelivery(delivery_id=delivery_id, event=event))
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        return False
    return True


def prune_deliveries(session: Session, window_s: int, now: datetime | None = None) -> int:
    """Forget delivery ids older than the replay window. Returns rows removed.

    GitHub signatures carry no timestamp, so a delivery replayed after it has
    been pruned would verify again. Downstream handlers are idempotent
    (scans dedupe on head SHA, triage events dedupe on comment id), which is
    what makes a bounded window acceptable.
    """
    cutoff = (now or utcnow()) - timedelta(seconds=window_s)
    result = session.execute(delete(WebhookDelivery).where(WebhookDelivery.received_at < cutoff))
    return int(getattr(result, "rowcount", 0) or 0)
