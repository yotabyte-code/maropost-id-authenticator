import pytest
from maropost_id_authenticator.broker import SessionBroker

ACCOUNTS = {
    "acct": {"store": "s", "email": "e", "password": "p", "totp_secret": "x"},
}


class FakeSession:
    def __init__(self):
        self.alive = True
        self.checks = 0

    def is_logged_in(self):
        self.checks += 1
        return self.alive


def make_broker(**kw):
    calls = {"n": 0, "last": None}

    def acquirer(store, email, password, totp_secret):
        calls["n"] += 1
        calls["last"] = FakeSession()
        return calls["last"]

    return SessionBroker(ACCOUNTS, acquirer=acquirer, **kw), calls


def test_unknown_account_raises():
    broker, _ = make_broker()
    with pytest.raises(KeyError):
        broker.get("nope")


def test_caches_within_ttl():
    broker, calls = make_broker(validate_ttl=1000, now=lambda: 100.0)
    a = broker.get("acct")
    b = broker.get("acct")
    assert a is b
    assert calls["n"] == 1  # acquired once, served from cache


def test_revalidates_after_ttl_when_alive():
    clock = {"t": 0.0}
    broker, calls = make_broker(validate_ttl=10, now=lambda: clock["t"])
    s = broker.get("acct")
    clock["t"] = 100.0  # past TTL
    again = broker.get("acct")
    assert again is s              # same session, not re-acquired
    assert calls["n"] == 1
    assert s.checks == 1           # but it WAS revalidated


def test_reacquires_when_session_dead():
    clock = {"t": 0.0}
    broker, calls = make_broker(validate_ttl=10, now=lambda: clock["t"])
    first = broker.get("acct")
    first.alive = False            # session invalidated externally (single-session rule)
    clock["t"] = 100.0
    second = broker.get("acct")
    assert second is not first     # re-acquired a fresh one
    assert calls["n"] == 2


def test_concurrent_get_acquires_once():
    """The whole point of the broker: N racing callers => exactly one login."""
    import threading
    import time as _t

    calls = {"n": 0}
    count_lock = threading.Lock()

    def slow_acquirer(store, email, password, totp_secret):
        with count_lock:
            calls["n"] += 1
        _t.sleep(0.05)  # widen the race window
        return FakeSession()

    broker = SessionBroker(ACCOUNTS, acquirer=slow_acquirer, validate_ttl=1000, now=lambda: 0.0)
    results = []
    start = threading.Barrier(8)

    def worker():
        start.wait()
        results.append(broker.get("acct"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert calls["n"] == 1
    assert all(r is results[0] for r in results)


def test_two_configs_sharing_a_login_share_one_session():
    """Single-session rule is per (store,email), so dup logins must not stampede."""
    accounts = {
        "app-a": {"store": "s", "email": "e", "password": "p", "totp_secret": "x"},
        "app-b": {"store": "s", "email": "e", "password": "p", "totp_secret": "x"},
    }
    calls = {"n": 0}

    def acquirer(*a):
        calls["n"] += 1
        return FakeSession()

    broker = SessionBroker(accounts, acquirer=acquirer, validate_ttl=1000, now=lambda: 0.0)
    a = broker.get("app-a")
    b = broker.get("app-b")
    assert a is b          # same underlying session
    assert calls["n"] == 1  # acquired once despite two config names
