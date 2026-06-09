"""Rudimentary HTTP API for intra-container session brokering.

A consumer asks `GET /session/{account}` and gets back the live cPanel
`_cpanel_sess` cookie to copy into its own requests. Credentials stay in the
broker; the client only ever knows an account *name*.

Auth: a shared bearer token. Set MIDA_API_TOKEN (or MIDA_API_TOKEN_FILE) to a
stable value your consumers use. If unset, a random ephemeral token is generated
per process — so the service is never wide-open, but set one for real use.

Run (factory mode, so importing this module doesn't require config):
    uvicorn --factory maropost_id_authenticator.api:create_app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import hmac
import logging
import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException

from .broker import SessionBroker
from .config import load_accounts
from .login import LoginError

log = logging.getLogger("mida.api")


def _read_secret(name: str) -> str | None:
    """Read a secret from ``NAME`` or, preferably, a mounted file ``NAME_FILE``."""
    if os.environ.get(name):
        return os.environ[name]
    path = os.environ.get(f"{name}_FILE")
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    return None


def create_app(broker: SessionBroker | None = None) -> FastAPI:
    # Pass the loader (not a snapshot) so accounts.json is re-read live —
    # `mida add`/`register` take effect with no container restart.
    broker = broker or SessionBroker(load_accounts)
    token = _read_secret("MIDA_API_TOKEN")
    if not token:
        # Never run wide-open by accident, never block startup: synthesise a random
        # token. It's ephemeral (per-process), so set MIDA_API_TOKEN/_FILE for a
        # stable value your consumers can use. Value is NOT logged.
        token = secrets.token_urlsafe(32)
        log.warning("MIDA_API_TOKEN not set — using an ephemeral random token for this "
                    "run; set MIDA_API_TOKEN (or _FILE) for a stable value.")

    app = FastAPI(title="Maropost ID Authenticator", version="0.1.0")

    def require_auth(authorization: str | None = Header(default=None)) -> None:
        # constant-time compare so a near-miss token can't be recovered by timing
        if not hmac.compare_digest(authorization or "", f"Bearer {token}"):
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")

    @app.get("/health")
    def health() -> dict:
        # Deliberately minimal: do NOT disclose account inventory unauthenticated.
        return {"status": "ok"}

    @app.get("/session/{account}", dependencies=[Depends(require_auth)])
    def get_session(account: str, refresh: bool = False) -> dict:
        try:
            s = broker.refresh(account) if refresh else broker.get(account)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown account")
        except LoginError as e:
            # Log detail server-side; return a generic message to the client.
            log.warning("login failed for account=%s: %s", account, e)
            raise HTTPException(status_code=502, detail="login failed")
        log.info("served session account=%s refresh=%s", account, refresh)
        return {
            "store": s.store,
            "cookie_name": s.cookie_name,
            "cookie_value": s.cookie_value,
        }

    return app
