# Maropost ID Authenticator

A small broker that logs into **Maropost Identity** (the Keycloak OIDC realm) with
username + password + TOTP, **headlessly** (plain HTTP via `cloudscraper`, no
browser), and hands the resulting cPanel **`_cpanel_sess` session cookie** to your
other apps over a tiny HTTP API.

It exists so that each app does **not** implement its own Maropost login. Credentials
and the TOTP secret live in one place (this service); consumers only ever know an
account **name** and get back a ready-to-use cookie.

## Why now — the Maropost Identity rollout

Maropost is migrating cPanel logins to **Maropost Identity** (OIDC + mandatory TOTP),
rolling out **16–26 June 2026**. After it lands, the old username/password cPanel
login (and the `cloudscraper`-against-`/_cpanel/login` approach existing automations
use) goes away — every login must go through Identity with a 2FA code.

This service is how you **prepare a machine for that switch**: stand it up, onboard
each automation's account once (capturing its TOTP secret), and point your existing
tools at it. Then whether a store is still on legacy or has flipped to Identity, your
automations keep getting a working `_cpanel_sess` cookie with no code changes on their
side. Use the **sandbox** to rehearse before the window, and the same steps on
production as each store is migrated.

## Why a service (not a library)

Maropost allows **one active session per account** — a new login *invalidates the
previous one*. So callers must not log in independently or they'd boot each other.
The broker holds one live session per account, hands the **same** cookie to all
callers, serialises logins with a per-account lock, and re-logs-in only when the
session actually dies.

```
consumer ──HTTP──> mida ──OIDC+TOTP──> identity.maropost.com ──redirect──> store/_cpanel
   (account name)        (cloudscraper)                                     sets _cpanel_sess
```

---

## Onboarding an application (first time)

Each app should get its **own** Maropost cPanel user (single-session rule — sharing
one login means two apps boot each other). Onboard **from inside the running
container** — handy when the host is remote/mobile — and it takes effect with **no
restart** (the broker re-reads `accounts.json` live).

### Guided (recommended): `mida register`

```bash
docker compose exec mida mida register
```
It walks you through it: the **link to create the cPanel user**; the **store home-page
console call** that opens the sign-up modal; a **browser-console snippet** that reads
the QR and prints the `otpauth://` string. You paste that back; it then shows a
**code to finish the authenticator setup** (the QR isn't active until Keycloak's setup
form is confirmed) and **verifies the login** before saving. Done — `GET /session/<name>`
works immediately.

### Scripted: `mida add`

If you already have the base32 secret (via "enter code manually" on the enrol screen):
```bash
docker compose exec mida mida add my-app <store> <email> <password> <totp_secret>
```
Verifies the login, then writes the account. Both commands refuse to save an account
that can't log in.

> Run on the host instead if you prefer (`uv run mida register`) — same thing,
> writing the local `accounts.json`.

## Using it (every time after)

A consumer just asks for the account by name and copies the cookie into its own
requests:

```bash
curl -H "Authorization: Bearer $MIDA_API_TOKEN" http://mida:8080/session/my-app
# {"store":"...","cookie_name":"N084166_cpanel_sess","cookie_value":"...."}
```

```python
import requests
s = requests.get("http://mida:8080/session/my-app",
                 headers={"Authorization": f"Bearer {token}"}).json()
r = requests.get(f"https://{s['store']}/_cpanel/order",
                 cookies={s["cookie_name"]: s["cookie_value"]})
```

If a consumer ever gets a cookie that bounces to login (the session was invalidated
externally within the cache window), re-request with `?refresh=true` to force a fresh
login.

### API

| Method | Path                         | Notes                                            |
|--------|------------------------------|--------------------------------------------------|
| GET    | `/health`                    | `{"status":"ok"}` — no auth, no inventory         |
| GET    | `/session/{account}`         | returns `{store, cookie_name, cookie_value}`      |
| GET    | `/session/{account}?refresh=true` | force a fresh login                          |

Auth: send `Authorization: Bearer <MIDA_API_TOKEN>`. If `MIDA_API_TOKEN` is unset the
service generates a random **ephemeral** token at startup (so it's never wide-open),
but that changes every restart — **set `MIDA_API_TOKEN` (or `MIDA_API_TOKEN_FILE`) to a
stable random value** so your consumers can use it. It's an internal tool meant for an
internal Docker network; don't publish its port.

---

## Configuration

Accounts (server-side, never on the client):
- `MIDA_ACCOUNTS_FILE` — path to a JSON file (**recommended**; mount as a secret)
- `MIDA_ACCOUNTS_JSON` — inline JSON (dev convenience; leaks via `docker inspect`/env)

Auth token:
- `MIDA_API_TOKEN` or `MIDA_API_TOKEN_FILE` (preferred). If unset, a random ephemeral
  token is generated per run — set a stable one for real use.

---

## Run locally (uv)

```bash
uv sync --extra dev
uv run pytest                       # unit suite
# live integration test (hits the sandbox):
MIDA_STORE=... MIDA_EMAIL=... MIDA_PASSWORD=... MIDA_TOTP_SECRET=... uv run pytest -m integration

# serve
MIDA_ACCOUNTS_FILE=accounts.json MIDA_API_TOKEN=secret \
  uv run uvicorn --factory maropost_id_authenticator.api:create_app --port 8080
```

### CLI

```bash
# interactive onboarding (guides you, captures the secret, verifies, saves)
uv run mida register

# scripted onboarding: verify a login and save it into accounts.json
uv run mida add <name> <store> <email> <password> <totp_secret>

# mint a cookie directly without the server (prints the session key value)
uv run mida session <store> <email> <password> <totp_secret>
#   also reads MIDA_STORE/EMAIL/PASSWORD/TOTP_SECRET
#   -f cookie -> name=value     -f json -> {store,name,value}
```

(Inside the container, prefix with `docker compose exec mida …`.)

## Run as a container

```bash
docker build -t maropost-id-authenticator .
cp docker-compose.example.yml docker-compose.yml
# provide ./accounts.json and ./api_token.txt (both gitignored)
docker compose up -d
```

The compose example runs non-root, read-only rootfs, dropped caps,
`no-new-privileges`, secrets mounted read-only, and **no published ports** (reachable
only by services on `mida-net`).

---

## Security notes

- The returned cookie **is** a live admin session — treat the API token like a
  password and don't log responses.
- Credentials + TOTP secret are held in the container. Its host is effectively a
  2FA-bypass crown jewel — isolate accordingly, restrict the accounts file to
  `0400`/non-root, keep it off swap/core-dumps.
- A leaked **TOTP secret is permanent** (it can't be expired like a session) — never
  commit `accounts.json`/`.env` (see `.gitignore`).

## Roadmap

- Per-account refresh throttle; structured access audit log.
- Optional fully-headless enrolment (drive the authenticator-setup page so even the
  console-snippet paste isn't needed).

## How it works (internals)

- **`login.py`** — stateless core. `acquire_session()` initiates from `/_cpanel`
  (so the OIDC `state` binds to a cPanel session — a hand-built authorize URL does
  **not** authenticate), submits credentials then the TOTP code to Keycloak, follows
  the callback, and returns the `_cpanel_sess` cookie. Verifies a *genuine* login via
  `div.netoPage` / `body.netoTheme-*` (the login page sets a `_cpanel_sess` too, and
  its title contains "Control Panel" — so neither is a valid success signal). Retries
  a rejected TOTP code in the next window.
- **`broker.py`** — stateful. One session per `(store, email)`, per-account lock,
  lazy revalidation after `validate_ttl`.
- **`api.py`** — the FastAPI surface. **`cli.py`** — the `mida` command.
- **`totp.py`** — RFC 6238 TOTP (stdlib only).
