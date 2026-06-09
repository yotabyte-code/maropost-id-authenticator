"""`mida` command line.

Subcommands:
  mida session <store> <email> <password> <totp_secret>   mint a cookie (prints it)
  mida add <name> <store> <email> <password> <totp_secret> verify a login + save it
                                                           into accounts.json

Credentials given on argv land in shell history / process list — fine for an
operator on a trusted box, but prefer env vars / a secrets file in automation.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

from .login import LoginError, _host, acquire_session
from .totp import parse_otpauth, seconds_remaining, totp

# Paste in the browser console on the authenticator-setup screen. Decodes the
# QR to its otpauth:// string and prints it to copy.
QR_GRABBER_JS = (
    '(async()=>{const i=document.querySelector(\'img[src^="data:image/png;base64"]\');'
    "if(!i)return console.error('no QR <img> found');"
    "if(!window.jsQR){await new Promise((r,j)=>{const s=document.createElement('script');"
    "s.src='https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js';s.onload=r;s.onerror=j;"
    "document.head.appendChild(s)})}const e=new Image();e.src=i.src;await e.decode();"
    "const c=document.createElement('canvas');c.width=e.naturalWidth;c.height=e.naturalHeight;"
    "const x=c.getContext('2d');x.drawImage(e,0,0);const d=x.getImageData(0,0,c.width,c.height);"
    "const q=window.jsQR(d.data,d.width,d.height);if(!q)return console.error('QR not readable');"
    "console.log('%cotpauth:','font-weight:bold',q.data);return q.data})();"
)

# JS to open the sign-up modal from the store home page (instead of cPanel login).
SIGNUP_MODAL_JS = (
    "openMaropostModal('Let’s Get You Signed Up', 'maropostRegisterConsentForm', regStatement);"
)


def add_account(name, store, email, password, totp_secret, accounts_file,
                *, verifier=acquire_session) -> Path:
    """Verify the login works, then persist the account into ``accounts_file``.

    Verification happens FIRST: an account that can't log in is never written
    (fail fast), so the broker's config can be trusted.
    """
    verifier(store, email, password, totp_secret)  # raises LoginError on failure
    path = Path(accounts_file)
    accounts = {}
    if path.exists():
        accounts = json.loads(path.read_text(encoding="utf-8"))
    accounts[name] = {
        "store": store, "email": email,
        "password": password, "totp_secret": totp_secret,
    }
    # atomic write so a concurrent hot-reload read never sees a half-written file
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(accounts, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def _cmd_session(args) -> int:
    missing = [n for n in ("store", "email", "password", "totp_secret")
               if not getattr(args, n)]
    if missing:
        print(f"missing: {', '.join(missing)} (args or MIDA_* env vars)", file=sys.stderr)
        return 2
    try:
        s = acquire_session(args.store, args.email, args.password, args.totp_secret)
    except LoginError as e:
        print(f"login failed: {e}", file=sys.stderr)
        return 1
    if args.format == "value":
        print(s.cookie_value)
    elif args.format == "cookie":
        print(f"{s.cookie_name}={s.cookie_value}")
    else:
        print(json.dumps({"store": s.store, "name": s.cookie_name, "value": s.cookie_value}))
    return 0


def _parse_enrolment(raw: str) -> tuple[str, str | None]:
    """From an otpauth:// URL return (secret, email); from a bare secret (secret, None).

    The otpauth label carries the account, e.g.
    otpauth://totp/maropost:user%40example.com?secret=... -> email parsed from it.
    """
    raw = raw.strip()
    if not raw.startswith("otpauth://"):
        return raw, None
    secret = parse_otpauth(raw)["secret"]
    label = unquote(urlparse(raw).path.lstrip("/"))   # "maropost:user@example.com"
    email = label.split(":", 1)[-1] if label else None
    if email and "@" not in email:
        email = None  # label was an issuer-less account name, not an email
    return secret, (email or None)


def _cmd_register(args) -> int:
    """Interactive onboarding: guides the operator, then verifies + saves."""
    host = _host(args.store or input("Store base URL (e.g. yourstore.mymaropost.com): "))
    name = (args.name or input("Account name (what consumers will request): ")).strip()
    if not host or not name:
        print("store and account name are required", file=sys.stderr)
        return 2

    print(f"\n[1] Create the cPanel user — open:\n    https://{host}/_cpanel/user/view?id=New")
    print("    Set an email (use a +alias) and a password, choose a permission group, Save.")
    input("    Press Enter once the user exists... ")

    print(f"\n[2] Enrol its authenticator — open the store home page:\n    https://{host}")
    print("    Open the browser console (F12) and run:\n")
    print(f"    {SIGNUP_MODAL_JS}")
    print("\n    Follow it through; when the authenticator QR appears, paste this:\n")
    print(QR_GRABBER_JS)
    print("\n    Copy the otpauth:// string it prints.")

    secret, email = _parse_enrolment(input("\n[3] Paste the otpauth:// string (or base32 secret): "))
    if not email:
        email = input("    Email for this user: ").strip()
    else:
        print(f"    (email from otpauth: {email})")
    if not email:
        print("email is required", file=sys.stderr)
        return 2
    password = getpass.getpass("    Password for this user: ")

    # The QR secret isn't active until the Keycloak setup form is confirmed with a
    # valid code. Print one to enter there, then verify the real login.
    print("\n[4] Finish enrolment in the browser: type the code below into the\n"
          "    authenticator-setup form and Save, then come back here.")
    while True:
        print(f"    setup code: {totp(secret)}   ({seconds_remaining()}s left)")
        prompt = ("    Press Enter to verify you have completed the setup "
                  "(\"Your Maropost Identity registration has been completed "
                  "successfully.\") — or 'r' for a fresh code: ")
        if input(prompt).strip().lower() == "r":
            continue
        print("    verifying login...")
        try:
            path = add_account(name, host, email, password, secret, args.accounts_file)
        except LoginError as e:
            print(f"    not working yet: {e}")
            if input("    try again? [Y/n]: ").strip().lower() in ("", "y"):
                continue
            return 1
        break
    print(f"\n[OK] Saved '{name}' to {path}. GET /session/{name} works now (no restart).")
    print("     fetch a session cookie:")
    print(f'       curl -H "Authorization: Bearer $MIDA_API_TOKEN" http://localhost:8080/session/{name}')
    return 0


def _cmd_add(args) -> int:
    try:
        path = add_account(args.name, args.store, args.email, args.password,
                           args.totp_secret, args.accounts_file)
    except LoginError as e:
        print(f"login failed, account NOT saved: {e}", file=sys.stderr)
        return 1
    print(f"verified + saved '{args.name}' to {path}")
    print("fetch a session cookie:")
    print(f'  curl -H "Authorization: Bearer $MIDA_API_TOKEN" http://localhost:8080/session/{args.name}')
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mida", description="Maropost Identity authenticator.")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("session", help="mint a live _cpanel_sess cookie")
    ps.add_argument("store", nargs="?", default=os.environ.get("MIDA_STORE"))
    ps.add_argument("email", nargs="?", default=os.environ.get("MIDA_EMAIL"))
    ps.add_argument("password", nargs="?", default=os.environ.get("MIDA_PASSWORD"))
    ps.add_argument("totp_secret", nargs="?", default=os.environ.get("MIDA_TOTP_SECRET"))
    ps.add_argument("-f", "--format", choices=("value", "cookie", "json"), default="value")
    ps.set_defaults(func=_cmd_session)

    pa = sub.add_parser("add", help="verify a login and save it to accounts.json")
    pa.add_argument("name", help="the account name consumers will request")
    pa.add_argument("store")
    pa.add_argument("email")
    pa.add_argument("password")
    pa.add_argument("totp_secret")
    pa.add_argument("--accounts-file", dest="accounts_file",
                    default=os.environ.get("MIDA_ACCOUNTS_FILE", "accounts.json"))
    pa.set_defaults(func=_cmd_add)

    pr = sub.add_parser("register", help="interactive onboarding (guides you, then verifies + saves)")
    pr.add_argument("--name", default=None)
    pr.add_argument("--store", default=None)
    pr.add_argument("--accounts-file", dest="accounts_file",
                    default=os.environ.get("MIDA_ACCOUNTS_FILE", "accounts.json"))
    pr.set_defaults(func=_cmd_register)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
