# Runbook: Maropost forces a password reset

Maropost Identity can make every user set a new password and enrol MFA again. When that
happens, every account in `accounts.json` stops working at the same time. Use this runbook to
get the accounts working again.

## How to recognise it

- mida logs `login failed for account=<name>: credentials rejected` and `/session/<name>` returns
  `502`.
- In a browser, `https://<store>/_cpanel` goes to Maropost Identity, which shows
  **"Password reset required"** above the login form.
- Several accounts, often on different stores, fail within a day of each other.

Check one account without waiting for a consumer:

```bash
curl -H "Authorization: Bearer $MIDA_API_TOKEN" "http://mida:8080/session/<name>?refresh=true"
```

`200` means the account works. `502` together with `credentials rejected` means it needs the reset.
Each `refresh=true` makes one real login attempt, so do not loop it.

## 1. Stop the login attempts

Each failed request is one more failed login on the Maropost user, and too many can lock it
out. Before you start, stop every consumer that calls mida for the broken accounts:

- Stop the consumer containers, and turn off their restart policy
  (`docker update --restart=no <container>`) so they stay stopped. A consumer that crashes on a
  failed login and then restarts makes dozens of attempts an hour.
- Look for anything that starts them again on a schedule, such as `crontab -l` and systemd timers.
  A nightly `docker restart` will start a stopped consumer again.

Leave mida running. It only logs in when something asks it to.

## 2. Reset the password and enrol MFA again

Do one account at a time, **in a new private/incognito browser window for each account**. After
one account is logged in, Identity keeps an SSO session. The next store then goes to
`/_cpanel/maropost-identity-login-error` ("You don't have access to the store") and not to
the login form. Closing all private windows clears that session.

1. Open `https://<store>/_cpanel`. It goes to Maropost Identity.
2. Click **Forgot Password?**, enter the account's email, and submit.
3. Open the reset link from the email in the **same** private window.
4. Set a new password. Leave **"Sign out from other devices"** unticked, because ticking it ends
   the sessions of other consumers that still work.
5. On **Set Up Multi-Factor Authentication**, do not scan the QR with a phone. mida needs the
   secret itself. Open the browser console (F12) and run the QR snippet that `mida register` prints
   (see `QR_GRABBER_JS` in `cli.py`). Keep the `otpauth://...` string it prints.
6. Click **Continue** and enter the current 6-digit code for that secret.
   `mida register` (step 3) prints one, or use any TOTP app with the secret.
7. On the recovery codes page, save the codes somewhere safe (a password manager or a mode-600
   file outside any repo). Tick **"I have saved these codes"** and click **Complete**.

## 3. Save the new credentials into mida

Run this on the host where that account's mida runs:

```bash
docker compose exec mida mida register --name <name> --store <store>
```

- Step [1] asks you to create the user. The user already exists, so press Enter.
- Paste the `otpauth://` string and type the new password. The password prompt does not echo it.
- Press Enter at the setup-code step if you already finished enrolment in the browser.

`register` tests the login and writes `accounts.json` only when the login works. A save prints
`[OK] Saved '<name>'`. If you don't see it, nothing was written. Check that the file's modified time
changed.

Do not pass the password to `mida add` on the command line if your shell keeps history.

## 4. Check, then start the consumers again

```bash
curl -H "Authorization: Bearer $MIDA_API_TOKEN" "http://mida:8080/session/<name>?refresh=true"
```

When it returns `200`, put the restart policy back, start the consumers, and turn their schedules
back on. Watch the first run.

## Points to remember

- **One Maropost user per mida account, and one mida per user.** If two brokers (on two hosts)
  hold the same user, a reset done for one of them breaks the other at once, and a new login from
  either one can end the other's session. Before you reset an account, find every host whose
  `accounts.json` has that email.
- Check the email in `accounts.json` before you request a reset. A reset on the wrong user takes
  down whatever else uses that user.
- The old password and TOTP secret stop working when the reset completes. A backup of
  `accounts.json` from before the reset only holds dead credentials.
