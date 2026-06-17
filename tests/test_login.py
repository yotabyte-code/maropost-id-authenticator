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


class _FakeResp:
    def __init__(self, url, text):
        self.url, self.text = url, text


class _FakeScraper:
    """Returns a canned response for the /_cpanel/home validation GET."""
    def __init__(self, resp):
        self._resp = resp

    def get(self, url, timeout=None):
        return self._resp


def _session_seeing(resp):
    from maropost_id_authenticator.login import CpanelSession
    return CpanelSession(
        store="www.outbackequipment.com.au",
        scraper=_FakeScraper(resp),
        acquired_at=0.0,
    )


class _Jar:
    def __init__(self, cookies):
        self._cookies = dict(cookies)

    def get_dict(self):
        return dict(self._cookies)


class _JarScraper:
    def __init__(self, cookies):
        self.cookies = _Jar(cookies)


def test_cookie_value_reads_live_jar_not_a_snapshot():
    """Regression: cPanel silently re-mints _cpanel_sess; the jar follows the rotation.
    cookie_name/value must reflect the CURRENT jar, not a value frozen at login, or the
    broker would serve a dead cookie while is_logged_in() still considers it alive."""
    from maropost_id_authenticator.login import CpanelSession
    scraper = _JarScraper({"N1_cpanel_sess": "v1", "cf_clearance": "x"})
    sess = CpanelSession(store="s", scraper=scraper, acquired_at=0.0)
    assert sess.cookie_name == "N1_cpanel_sess"
    assert sess.cookie_value == "v1"
    assert sess.cookie == {"N1_cpanel_sess": "v1"}
    # cPanel re-mints -> jar value rotates. The session must surface the NEW value.
    scraper.cookies._cookies["N1_cpanel_sess"] = "v2-reminted"
    assert sess.cookie_value == "v2-reminted"


def test_is_logged_in_false_when_bounced_to_identity():
    """Expired session: /_cpanel/home redirects to Keycloak. Even if that page
    looks like a Cloudflare challenge, the identity bounce wins -> logged out."""
    resp = _FakeResp(
        url="https://identity.maropost.com/realms/maropost/protocol/openid-connect/auth?x=1",
        text="Just a moment...challenge-platform",  # CF-ish, must NOT fail open
    )
    assert _session_seeing(resp).is_logged_in() is False


def test_is_logged_in_true_on_cloudflare_challenge_on_cpanel():
    resp = _FakeResp(url="https://www.outbackequipment.com.au/_cpanel/home",
                     text="Just a moment...")
    assert _session_seeing(resp).is_logged_in() is True


def test_is_logged_in_true_on_authenticated_cpanel():
    resp = _FakeResp(url="https://www.outbackequipment.com.au/_cpanel/home",
                     text='<body class="netoTheme-x"><div class="netoPage">ok</div></body>')
    assert _session_seeing(resp).is_logged_in() is True


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
