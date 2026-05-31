"""RFC 6238 TOTP (time-based one-time password) generation.

Pure standard library. Accepts either a raw base32 secret or a full
``otpauth://totp/...`` URI (as exported by most 2FA apps / QR codes).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, unquote, urlparse

_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


class TOTPError(Exception):
    pass


def parse(secret_or_uri: str) -> dict:
    """Normalise user input into {secret, digits, period, algorithm, label}."""
    raw = (secret_or_uri or "").strip()
    if not raw:
        raise TOTPError("empty secret")

    if raw.lower().startswith("otpauth://"):
        u = urlparse(raw)
        q = parse_qs(u.query)
        secret = (q.get("secret") or [""])[0]
        digits = int((q.get("digits") or ["6"])[0])
        period = int((q.get("period") or ["30"])[0])
        algorithm = (q.get("algorithm") or ["SHA1"])[0].upper()
        label = unquote(u.path.lstrip("/"))
    else:
        secret, digits, period, algorithm, label = raw, 6, 30, "SHA1", ""

    secret = secret.replace(" ", "").replace("-", "").upper()
    if algorithm not in _ALGOS:
        algorithm = "SHA1"
    if digits not in (6, 7, 8):
        digits = 6
    if period <= 0:
        period = 30
    if not secret:
        raise TOTPError("no secret in URI")
    return {"secret": secret, "digits": digits, "period": period,
            "algorithm": algorithm, "label": label}


def _b32decode(secret: str) -> bytes:
    pad = "=" * ((-len(secret)) % 8)
    try:
        key = base64.b32decode(secret + pad, casefold=True)
    except Exception as exc:  # noqa: BLE001
        raise TOTPError("invalid base32 secret") from exc
    if not key:
        raise TOTPError("empty secret")
    return key


def code(secret_or_uri: str, *, at: float | None = None) -> dict:
    """Return {code, remaining, period, digits} for the current 30s window."""
    cfg = parse(secret_or_uri)
    key = _b32decode(cfg["secret"])
    now = time.time() if at is None else at
    counter = int(now // cfg["period"])
    digest = hmac.new(key, struct.pack(">Q", counter), _ALGOS[cfg["algorithm"]]).digest()
    offset = digest[-1] & 0x0F
    binary = ((digest[offset] & 0x7F) << 24
              | digest[offset + 1] << 16
              | digest[offset + 2] << 8
              | digest[offset + 3])
    value = str(binary % (10 ** cfg["digits"])).zfill(cfg["digits"])
    remaining = cfg["period"] - int(now % cfg["period"])
    return {"code": value, "remaining": remaining,
            "period": cfg["period"], "digits": cfg["digits"]}
