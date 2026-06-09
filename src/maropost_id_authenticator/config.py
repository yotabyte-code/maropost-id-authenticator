"""Server-side account configuration.

Accounts (and their secrets) live in the container, never in the client.
Source, in order of precedence:
  1. MIDA_ACCOUNTS_FILE — path to a JSON file (recommended; mount as a secret)
  2. MIDA_ACCOUNTS_JSON — inline JSON (handy for compose/env)

Shape:
  {
    "oe-sandbox": {
      "store": "yourstore.mymaropost.com",
      "email": "user@example.com",
      "password": "...",
      "totp_secret": "BASE32SECRET"
    }
  }
"""
from __future__ import annotations

import json
import os

_REQUIRED = ("store", "email", "password", "totp_secret")


def load_accounts() -> dict[str, dict]:
    path = os.environ.get("MIDA_ACCOUNTS_FILE")
    if path:
        with open(path, encoding="utf-8") as f:
            accounts = json.load(f)
    elif os.environ.get("MIDA_ACCOUNTS_JSON"):
        accounts = json.loads(os.environ["MIDA_ACCOUNTS_JSON"])
    else:
        raise RuntimeError(
            "no accounts configured: set MIDA_ACCOUNTS_FILE or MIDA_ACCOUNTS_JSON"
        )

    # Fail fast on a malformed account rather than 500-ing at request time.
    for name, cfg in accounts.items():
        missing = [k for k in _REQUIRED if not cfg.get(k)]
        if missing:
            raise RuntimeError(f"account {name!r} missing fields: {', '.join(missing)}")
    return accounts
