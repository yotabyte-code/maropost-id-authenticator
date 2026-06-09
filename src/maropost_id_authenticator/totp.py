"""RFC 6238 TOTP generation and otpauth:// parsing.

The broker holds a per-account otpauth secret captured at enrolment and
generates the same 6-digit code Microsoft/Google Authenticator would show.
Pure stdlib, no dependencies — deterministic function of (secret, time).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time as _time
from urllib.parse import parse_qs, urlparse

_ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def totp(secret: str, digits: int = 6, period: int = 30,
         algorithm: str = "SHA1", ts: float | None = None) -> str:
    """Return the TOTP code for a base32 ``secret`` at unix time ``ts``.

    ``ts`` defaults to the current time. Fails fast on an unknown algorithm
    or malformed secret rather than silently producing a wrong code.
    """
    digest = _ALGORITHMS[algorithm.upper()]
    key = base64.b32decode(secret, casefold=True)
    counter = struct.pack(">Q", int(_time.time() if ts is None else ts) // period)
    mac = hmac.new(key, counter, digest).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def parse_otpauth(url: str) -> dict:
    """Parse an ``otpauth://totp/...`` enrolment URL into TOTP parameters.

    Returns ``{secret, digits, period, algorithm}``. ``secret`` is required;
    its absence raises (no silent default for the one field that matters).
    """
    parsed = urlparse(url)
    if parsed.scheme != "otpauth":
        raise ValueError(f"not an otpauth URL: {url!r}")
    q = parse_qs(parsed.query)
    algorithm = q.get("algorithm", ["SHA1"])[0].upper()
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    return {
        "secret": q["secret"][0],
        "digits": int(q.get("digits", ["6"])[0]),
        "period": int(q.get("period", ["30"])[0]),
        "algorithm": algorithm,
    }


def seconds_remaining(period: int = 30, ts: float | None = None) -> int:
    """Seconds left in the current TOTP window — used to avoid submitting a
    code about to expire mid-login."""
    return period - int(_time.time() if ts is None else ts) % period
