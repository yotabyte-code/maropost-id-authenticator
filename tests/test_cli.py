import json
import pytest
from maropost_id_authenticator import cli
from maropost_id_authenticator.login import LoginError


class OK:
    store, cookie_name, cookie_value = "s", "n", "v"


def good_verifier(*a):
    return OK()


def bad_verifier(*a):
    raise LoginError("nope")


def test_add_writes_account(tmp_path):
    f = tmp_path / "accounts.json"
    cli.add_account("app1", "s", "e", "p", "x", f, verifier=good_verifier)
    data = json.loads(f.read_text())
    assert data["app1"] == {
        "store": "s", "email": "e", "password": "p", "totp_secret": "x",
    }


def test_add_merges_into_existing(tmp_path):
    f = tmp_path / "accounts.json"
    f.write_text(json.dumps(
        {"existing": {"store": "s2", "email": "e2", "password": "p2", "totp_secret": "x2"}}
    ))
    cli.add_account("app1", "s", "e", "p", "x", f, verifier=good_verifier)
    data = json.loads(f.read_text())
    assert set(data) == {"existing", "app1"}


def test_parse_enrolment_extracts_secret_and_email():
    url = ("otpauth://totp/maropost:user%2Bx%40example.com"
           "?secret=EXAMPLE2SECRET34&digits=6&algorithm=SHA1&period=30")
    secret, email = cli._parse_enrolment(url)
    assert secret == "EXAMPLE2SECRET34"
    assert email == "user+x@example.com"


def test_parse_enrolment_bare_secret_has_no_email():
    assert cli._parse_enrolment("EXAMPLE2SECRET34") == ("EXAMPLE2SECRET34", None)


def test_add_refuses_on_bad_login(tmp_path):
    f = tmp_path / "accounts.json"
    with pytest.raises(LoginError):
        cli.add_account("app1", "s", "e", "p", "x", f, verifier=bad_verifier)
    assert not f.exists()  # nothing written when the login can't be verified
