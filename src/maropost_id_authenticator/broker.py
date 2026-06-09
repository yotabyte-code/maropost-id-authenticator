"""Stateful session broker.

Holds one live cPanel session per account, hands the *same* cookie to every
caller, and re-acquires only when needed. This is required by Maropost's
single-session-per-account rule: minting a new session invalidates the
previous one, so callers must NOT each log in independently.

Concurrency: a per-account lock serialises acquisition/validation so two
simultaneous requests for the same account can't stampede into two logins
(which would invalidate each other).

Accounts may be a static dict OR a zero-arg callable returning the dict. Pass
the callable (e.g. ``load_accounts``) so the config file is re-read live —
then `mida add`/`register` take effect with no restart.
"""
from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import Callable


class SessionBroker:
    def __init__(
        self,
        accounts: dict | Callable[[], dict],
        *,
        acquirer: Callable = None,  # type: ignore[assignment]
        validate_ttl: float = 60.0,
        now: Callable[[], float] = time.time,
    ) -> None:
        from .login import acquire_session  # local import avoids a cycle
        self._accounts_source = accounts
        self._acquirer = acquirer or acquire_session
        self._ttl = validate_ttl
        self._now = now
        self._cache: dict[tuple[str, str], tuple[object, float]] = {}
        self._locks: dict[tuple[str, str], Lock] = defaultdict(Lock)
        self._locks_guard = Lock()

    def _accounts(self) -> dict:
        src = self._accounts_source
        return src() if callable(src) else src

    def _lock(self, key: tuple[str, str]) -> Lock:
        with self._locks_guard:
            return self._locks[key]

    def _identity(self, cfg: dict) -> tuple[str, str]:
        # Single-session is per (store, email), NOT per config name. Two config
        # entries with the same login must share one cache slot + one lock.
        return (cfg["store"], cfg["email"])

    def get(self, name: str):
        """Return a live session for ``name``, acquiring/refreshing as needed."""
        accounts = self._accounts()
        if name not in accounts:
            raise KeyError(name)
        cfg = accounts[name]
        key = self._identity(cfg)
        with self._lock(key):
            cached = self._cache.get(key)
            if cached:
                session, validated_at = cached
                if self._now() - validated_at < self._ttl:
                    return session
                if session.is_logged_in():
                    self._cache[key] = (session, self._now())
                    return session
            session = self._acquirer(
                cfg["store"], cfg["email"], cfg["password"], cfg["totp_secret"]
            )
            self._cache[key] = (session, self._now())
            return session

    def refresh(self, name: str):
        """Force a fresh login for ``name``, replacing any cached session."""
        accounts = self._accounts()
        if name not in accounts:
            raise KeyError(name)
        cfg = accounts[name]
        key = self._identity(cfg)
        with self._lock(key):
            session = self._acquirer(
                cfg["store"], cfg["email"], cfg["password"], cfg["totp_secret"]
            )
            self._cache[key] = (session, self._now())
            return session

    @property
    def account_names(self) -> list[str]:
        return list(self._accounts())
