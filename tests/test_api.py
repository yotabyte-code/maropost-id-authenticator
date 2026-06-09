import pytest
from fastapi.testclient import TestClient
from maropost_id_authenticator.api import create_app

TOKEN = "test-token"


class FakeSession:
    store = "teststore.mymaropost.com"
    cookie_name = "N084166_cpanel_sess"
    cookie_value = "deadbeef"


class FakeBroker:
    account_names = ["oe-sandbox"]
    refreshed = False

    def get(self, name):
        if name != "oe-sandbox":
            raise KeyError(name)
        return FakeSession()

    def refresh(self, name):
        self.refreshed = True
        return self.get(name)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("MIDA_API_TOKEN", TOKEN)
    return TestClient(create_app(broker=FakeBroker()))


def _auth():
    return {"Authorization": f"Bearer {TOKEN}"}


def test_unset_token_still_protected_with_ephemeral(monkeypatch):
    # No token configured -> a random one is synthesised, so it is NOT wide open.
    monkeypatch.delenv("MIDA_API_TOKEN", raising=False)
    monkeypatch.delenv("MIDA_API_TOKEN_FILE", raising=False)
    c = TestClient(create_app(broker=FakeBroker()))
    assert c.get("/health").status_code == 200
    assert c.get("/session/oe-sandbox").status_code == 401  # no caller knows the token


def test_health_is_minimal(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}  # no account inventory disclosed


def test_session_requires_auth(client):
    assert client.get("/session/oe-sandbox").status_code == 401
    assert client.get("/session/oe-sandbox", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_get_session_returns_cookie(client):
    r = client.get("/session/oe-sandbox", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body == {
        "store": "teststore.mymaropost.com",
        "cookie_name": "N084166_cpanel_sess",
        "cookie_value": "deadbeef",
    }


def test_unknown_account_404(client):
    assert client.get("/session/nope", headers=_auth()).status_code == 404


def test_refresh_flag_forces_refresh(monkeypatch):
    monkeypatch.setenv("MIDA_API_TOKEN", TOKEN)
    broker = FakeBroker()
    c = TestClient(create_app(broker=broker))
    c.get("/session/oe-sandbox?refresh=true", headers=_auth())
    assert broker.refreshed is True
