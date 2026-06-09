"""RFC 6238 Appendix B test vectors for the TOTP generator.

The canonical SHA-1 seed is the ASCII string "12345678901234567890"
(base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ), 8-digit codes, 30s step.
"""
import pytest
from maropost_id_authenticator.totp import totp

SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

# (unix_time, expected_8_digit_code) from RFC 6238 Appendix B (SHA1 rows)
VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("ts,expected", VECTORS)
def test_rfc6238_sha1_vectors(ts, expected):
    assert totp(SECRET_B32, digits=8, period=30, algorithm="SHA1", ts=ts) == expected


def test_default_is_six_digits():
    code = totp(SECRET_B32, ts=59)
    assert len(code) == 6 and code.isdigit()
