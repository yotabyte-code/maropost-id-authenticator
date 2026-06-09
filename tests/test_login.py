import os
import pytest
from maropost_id_authenticator.login import build_authorize_url, acquire_session
from maropost_id_authenticator.totp import totp


def test_build_authorize_url_is_deterministic_per_store():
    url = build_authorize_url("teststore.mymaropost.com")
    assert url.startswith(
        "https://identity.maropost.com/realms/maropost/protocol/openid-connect/auth?"
    )
    # the only store-specific part is the redirect_uri
    assert "client_id=neto_ecommerce" in url
    assert "response_type=code" in url
    assert (
        "redirect_uri=https%3A%2F%2Fteststore.mymaropost.com"
        "%2F_cpanel%2Fopenid-auth-callback%2Fmaropost" in url
    )


def test_build_authorize_url_strips_scheme_and_slashes():
    a = build_authorize_url("https://shop.example.com/")
    assert "redirect_uri=https%3A%2F%2Fshop.example.com%2F_cpanel" in a


def test_acquire_session_retries_rejected_otp(monkeypatch):
    """A reused/expired code (OtpError) is retried in the next window."""
    from maropost_id_authenticator import login as L

    calls = {"n": 0}

    class S:
        store, cookie_name, cookie_value = "s", "N1_cpanel_sess", "v"

    def fake_attempt(store, email, password, totp_secret, scraper):
        calls["n"] += 1
        if calls["n"] == 1:
            raise L.OtpError("Invalid authenticator code.")
        return S()

    monkeypatch.setattr(L, "_attempt_login", fake_attempt)
    monkeypatch.setattr(L, "seconds_remaining", lambda *a, **k: 0)
    monkeypatch.setattr(L.time, "sleep", lambda *_: None)

    out = L.acquire_session("s", "e", "p", "x")
    assert out.cookie_value == "v"
    assert calls["n"] == 2  # failed once, succeeded on retry


def test_acquire_session_gives_up_after_attempts(monkeypatch):
    from maropost_id_authenticator import login as L
    monkeypatch.setattr(L, "_attempt_login",
                        lambda *a: (_ for _ in ()).throw(L.OtpError("nope")))
    monkeypatch.setattr(L, "seconds_remaining", lambda *a, **k: 0)
    monkeypatch.setattr(L.time, "sleep", lambda *_: None)
    with pytest.raises(L.OtpError):
        L.acquire_session("s", "e", "p", "x", otp_attempts=3)


def test_acquire_session_retries_network_then_succeeds(monkeypatch):
    import requests
    from maropost_id_authenticator import login as L

    calls = {"n": 0}

    class S:
        store, cookie_name, cookie_value = "s", "N1_cpanel_sess", "v"

    def fake(*a):
        calls["n"] += 1
        if calls["n"] == 1:
            raise requests.exceptions.ConnectTimeout("boom")
        return S()

    monkeypatch.setattr(L, "_attempt_login", fake)
    monkeypatch.setattr(L.time, "sleep", lambda *_: None)
    out = L.acquire_session("s", "e", "p", "x")
    assert out.cookie_value == "v" and calls["n"] == 2


def test_network_budget_separate_from_otp(monkeypatch):
    """A flaky network must not consume the OTP attempts (and vice versa)."""
    import requests
    from maropost_id_authenticator import login as L

    calls = {"n": 0}

    class S:
        store, cookie_name, cookie_value = "s", "N1_cpanel_sess", "v"

    def fake(*a):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise requests.exceptions.ReadTimeout("net")  # two network blips
        if calls["n"] == 3:
            raise L.OtpError("reused code")               # then one OTP reject
        return S()

    monkeypatch.setattr(L, "_attempt_login", fake)
    monkeypatch.setattr(L, "seconds_remaining", lambda *a, **k: 0)
    monkeypatch.setattr(L.time, "sleep", lambda *_: None)
    out = L.acquire_session("s", "e", "p", "x", otp_attempts=2, network_attempts=3)
    assert out.cookie_value == "v" and calls["n"] == 4


def test_acquire_session_rejects_bad_attempt_counts():
    from maropost_id_authenticator import login as L
    with pytest.raises(ValueError):
        L.acquire_session("s", "e", "p", "x", otp_attempts=0)


@pytest.mark.integration
def test_acquire_session_live():
    """End-to-end against the live sandbox. Requires MIDA_* env vars."""
    store = os.environ.get("MIDA_STORE")
    email = os.environ.get("MIDA_EMAIL")
    password = os.environ.get("MIDA_PASSWORD")
    secret = os.environ.get("MIDA_TOTP_SECRET")
    if not all([store, email, password, secret]):
        pytest.skip("MIDA_STORE/EMAIL/PASSWORD/TOTP_SECRET not set")

    sess = acquire_session(store, email, password, secret)
    assert "_cpanel_sess" in sess.cookie_name
    assert len(sess.cookie_value) > 8
    # the returned cookie actually authenticates cPanel
    assert sess.is_logged_in()
