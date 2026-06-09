"""Stateless Maropost Identity (Keycloak OIDC) login core.

Pure function: (store, email, password, totp_secret) -> a live cPanel
``_cpanel_sess`` cookie, obtained headlessly by driving the standard
Keycloak password + TOTP forms with cloudscraper. No browser.

This is the de-risked acquisition step proven against the OE sandbox. The
stateful broker (caching, per-account locking, refresh) wraps this; keeping
it a plain function makes it trivially testable and reusable.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlencode, urljoin

import cloudscraper
import requests
from bs4 import BeautifulSoup

from .totp import seconds_remaining, totp

AUTHORIZE = "https://identity.maropost.com/realms/maropost/protocol/openid-connect/auth"
CLIENT_ID = "neto_ecommerce"
SCOPE = "openid organization email phone profile"
# base64({"login_url":"/_cpanel"}) — constant post-login target
STATE = "eyJsb2dpbl91cmwiOiIvX2NwYW5lbCJ9"

# (connect, read) seconds. Generous enough for slow/mobile links, bounded so a
# truly stalled hop fails fast instead of hanging forever.
TIMEOUT = (15, 45)


class LoginError(Exception):
    """Base class for any failure in the OIDC login flow."""


class CloudflareError(LoginError):
    """Cloudflare served an interstitial challenge instead of the form."""


class CredentialsError(LoginError):
    """Email/password were rejected by Keycloak."""


class OtpError(LoginError):
    """The TOTP code was rejected by Keycloak."""


class NetworkError(LoginError):
    """A transient network failure talking to Maropost/Keycloak."""


class SessionCookieError(LoginError):
    """Login appeared to succeed but no _cpanel_sess cookie was set."""


def _host(store: str) -> str:
    """Normalise a store identifier to a bare host (strip scheme/path)."""
    store = store.strip()
    for prefix in ("https://", "http://"):
        if store.startswith(prefix):
            store = store[len(prefix):]
    return store.split("/")[0]


def build_authorize_url(store: str) -> str:
    """Construct the deterministic Keycloak authorize URL for a store.

    Only the redirect_uri varies between stores; everything else is constant
    across all Neto/Maropost stores, so this works whether or not the store
    has made Maropost Identity its default login.
    """
    host = _host(store)
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "redirect_uri": f"https://{host}/_cpanel/openid-auth-callback/maropost",
        "state": STATE,
    }
    return AUTHORIZE + "?" + urlencode(params)


@dataclass
class CpanelSession:
    """A live cPanel session: the one cookie consumers copy to make requests."""

    store: str
    cookie_name: str
    cookie_value: str
    scraper: "cloudscraper.CloudScraper"
    acquired_at: float

    @property
    def cookie(self) -> dict[str, str]:
        """The cookie as a ``{name: value}`` dict, ready to drop into a jar."""
        return {self.cookie_name: self.cookie_value}

    def is_logged_in(self) -> bool:
        """Verify the cookie actually authenticates cPanel (cheap GET).

        If we can't tell because Cloudflare served a challenge, assume the
        session is still alive — discarding it would needlessly burn a good
        session (and, per the single-session rule, can't be undone).
        """
        try:
            r = self.scraper.get(f"https://{_host(self.store)}/_cpanel/home", timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            return True  # transient network error: can't tell, so don't discard it
        if _looks_like_cloudflare(r.text):
            return True
        return _is_authenticated_html(r.text)


def _looks_like_cloudflare(html: str) -> bool:
    return "Just a moment" in html or "challenge-platform" in html


def _first_post_form(html: str) -> tuple[str | None, dict[str, str]]:
    """Return (action, {field: value}) for the first POST form on the page."""
    soup = BeautifulSoup(html, "lxml")
    for form in soup.find_all("form"):
        if (form.get("method") or "").lower() == "post":
            fields = {
                inp["name"]: inp.get("value", "")
                for inp in form.find_all("input")
                if inp.get("name")
            }
            return form.get("action"), fields
    return None, {}


def _alert_text(html: str) -> str | None:
    soup = BeautifulSoup(html, "lxml")
    for cls in ("input-error", "alert-error", "kc-feedback-text", "pf-c-alert__title"):
        el = soup.find(class_=cls)
        if el and el.get_text(strip=True):
            return el.get_text(strip=True)
    return None


def _is_authenticated_html(html: str) -> bool:
    """True only for a genuinely logged-in cPanel page.

    The real markers are ``div.netoPage`` (the cPanel app shell) or a
    ``netoTheme-*`` body class. The login screen is ``body.app-neto`` with a
    password input — and note its <title> also contains "Control Panel", so
    never match on that string.
    """
    soup = BeautifulSoup(html, "lxml")
    if soup.select_one("div.netoPage"):
        return True
    body = soup.find("body")
    classes = (body.get("class") or []) if body else []
    return any(c.startswith("netoTheme") for c in classes)


def _initiate_form(html: str, base_url: str) -> tuple[str | None, dict[str, str]]:
    """Find the cPanel 'Log In with Maropost' initiation form.

    Submitting it is what makes cPanel mint a pre-auth session and bind the
    OIDC state/nonce to it — without that, the callback can't establish a
    session. Matches by form id or the hidden ``tkn=maropost-login`` marker.
    """
    soup = BeautifulSoup(html, "lxml")
    form = soup.find("form", {"id": "maropost-login"})
    if not form:
        for f in soup.find_all("form"):
            if any(i.get("name") == "tkn" and i.get("value") == "maropost-login"
                   for i in f.find_all("input")):
                form = f
                break
    if not form:
        return None, {}
    data = {i["name"]: i.get("value", "") for i in form.find_all("input") if i.get("name")}
    return urljoin(base_url, form.get("action")), data


def acquire_session(
    store: str,
    email: str,
    password: str,
    totp_secret: str,
    *,
    scraper: "cloudscraper.CloudScraper | None" = None,
    otp_attempts: int = 3,
    network_attempts: int = 3,
) -> CpanelSession:
    """Log in via Maropost Identity and return a live cPanel session.

    Two INDEPENDENT retry budgets so a flaky network can't consume the OTP
    attempts (and vice-versa): a rejected TOTP code retries in the next 30s
    window; a transient network error retries after a short backoff.
    Credential/Cloudflare failures are not retried.
    """
    if otp_attempts < 1 or network_attempts < 1:
        raise ValueError("otp_attempts and network_attempts must be >= 1")
    last: LoginError | None = None
    otp_left, net_left = otp_attempts, network_attempts
    while otp_left and net_left:
        try:
            return _attempt_login(store, email, password, totp_secret, scraper)
        except OtpError as e:
            last, otp_left = e, otp_left - 1
            if otp_left:
                time.sleep(seconds_remaining() + 1)  # rejected code -> next window
        except requests.exceptions.RequestException as e:
            last, net_left = NetworkError(f"network error reaching Maropost: {e}"), net_left - 1
            if net_left:
                time.sleep(2)  # transient (timeout/handshake) -> brief backoff
    raise last  # type: ignore[misc]


def _attempt_login(store, email, password, totp_secret, scraper) -> CpanelSession:
    host = _host(store)
    s = scraper or cloudscraper.create_scraper()

    # 1. INITIATE FROM cPANEL. cPanel mints a pre-auth session and binds the
    # OIDC state/nonce to it; the callback later correlates against that. A
    # hand-built authorize URL skips this and the callback refuses to log in.
    r = s.get(f"https://{host}/_cpanel", timeout=TIMEOUT, allow_redirects=True)
    if _looks_like_cloudflare(r.text):
        raise CloudflareError("Cloudflare challenge on the cPanel landing page")
    if "identity.maropost.com" not in r.url:
        # Dual-login store: submit the "Log In with Maropost" form. (On an
        # Identity-default store, GET /_cpanel already redirected to Keycloak.)
        action, data = _initiate_form(r.text, r.url)
        if not action:
            raise LoginError("'Log In with Maropost' initiation form not found")
        r = s.post(action, data=data, timeout=TIMEOUT, allow_redirects=True)
    if "identity.maropost.com" not in r.url:
        raise LoginError(f"did not reach Maropost Identity (landed on {r.url})")

    # 2. submit credentials to the Keycloak login form
    action, fields = _first_post_form(r.text)
    if not action or "password" not in fields:
        raise LoginError("Keycloak login form not found")
    fields["username"] = email
    fields["password"] = password
    r = s.post(action, data=fields, timeout=TIMEOUT)
    action, fields = _first_post_form(r.text)
    if action and "password" in fields:
        raise CredentialsError(_alert_text(r.text) or "credentials rejected")
    if not action:
        raise LoginError("no OTP form after credentials")

    # 3. submit a fresh TOTP code. The themed OTP form carries a hidden
    # `tryAnotherWay=on` that its JS only sends when "Try Another Way" is
    # pressed; submitting it makes Keycloak branch away from OTP validation.
    fields.pop("tryAnotherWay", None)
    if seconds_remaining() < 5:
        time.sleep(5)
    fields["otp"] = totp(totp_secret)
    r = s.post(action, data=fields, timeout=TIMEOUT, allow_redirects=True)

    # 4. confirm a GENUINELY authenticated session (div.netoPage), not just
    # the presence of a _cpanel_sess cookie (the login page sets one too).
    name = next((k for k in s.cookies.get_dict() if "_cpanel_sess" in k), None)
    home = s.get(f"https://{host}/_cpanel/home", timeout=TIMEOUT)
    if not name or not _is_authenticated_html(home.text):
        raise OtpError(_alert_text(r.text)
                       or "login did not establish an authenticated cPanel session")
    return CpanelSession(
        store=host,
        cookie_name=name,
        cookie_value=s.cookies.get_dict()[name],
        scraper=s,
        acquired_at=time.time(),
    )
