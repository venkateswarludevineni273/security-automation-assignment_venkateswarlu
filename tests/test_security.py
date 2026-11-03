"""Regression tests for the security fixes made in Task 3.

Each test is named after the weakness it guards against; it fails on the
original starter code and passes after remediation.
"""
import base64
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timedelta

import jwt

from tests.test_api import (  # noqa: F401  (reset_db is an autouse fixture)
    TestingSessionLocal,
    auth_headers,
    client,
    register_and_login,
    reset_db,
)

import models  # noqa: E402
from config import ALGORITHM, SECRET_KEY  # noqa: E402
from main import app  # noqa: E402

APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def make_scan(token, title="Finding", description="desc"):
    resp = client.post("/scans", json={
        "title": title, "description": description,
        "severity": "low", "affected_component": "x",
    }, headers=auth_headers(token))
    return resp.json()["id"]


# --- Authentication -------------------------------------------------------

def test_unsigned_alg_none_token_is_rejected():
    register_and_login("alice", "alice@example.com")
    forged = (
        _b64({"alg": "none", "typ": "JWT"}) + "."
        + _b64({"sub": "alice", "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())})
        + "."
    )
    assert client.get("/scans", headers=auth_headers(forged)).status_code == 401


def test_token_signed_with_wrong_key_is_rejected():
    register_and_login("alice", "alice@example.com")
    bad = jwt.encode({"sub": "alice", "exp": datetime.utcnow() + timedelta(hours=1)},
                     "some-other-key-some-other-key-some-other", algorithm=ALGORITHM)
    assert client.get("/scans", headers=auth_headers(bad)).status_code == 401


def test_token_without_expiry_is_rejected():
    register_and_login("alice", "alice@example.com")
    no_exp = jwt.encode({"sub": "alice"}, SECRET_KEY, algorithm=ALGORITHM)
    assert client.get("/scans", headers=auth_headers(no_exp)).status_code == 401


def test_expired_token_is_rejected():
    register_and_login("alice", "alice@example.com")
    old = jwt.encode({"sub": "alice", "exp": datetime.utcnow() - timedelta(minutes=1)},
                     SECRET_KEY, algorithm=ALGORITHM)
    assert client.get("/scans", headers=auth_headers(old)).status_code == 401


def test_app_refuses_to_start_without_a_strong_secret_key():
    env = {k: v for k, v in os.environ.items() if k not in ("SECRET_KEY", "SECRET_KEY_FILE")}
    for bad in (None, "short"):
        run_env = dict(env, **({"SECRET_KEY": bad} if bad else {}))
        proc = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, '.'); import config"],
                              cwd=APP_DIR, env=run_env, capture_output=True, text=True)
        assert proc.returncode != 0
        assert "RuntimeError" in proc.stderr and "SECRET_KEY" in proc.stderr


# --- Sensitive data in logs / errors --------------------------------------

def test_login_does_not_log_passwords(caplog):
    client.post("/auth/register", json={"username": "alice", "email": "a@example.com", "password": "hunter2-secret"})
    with caplog.at_level(logging.DEBUG):
        client.post("/auth/login", json={"username": "alice", "password": "hunter2-secret"})
        client.post("/auth/login", json={"username": "alice", "password": "wrong-guess-xyz"})
    assert "hunter2-secret" not in caplog.text
    assert "wrong-guess-xyz" not in caplog.text


def test_unhandled_error_does_not_leak_internals():
    @app.get("/_test_boom")
    def boom():
        raise RuntimeError("secret-internal-detail /srv/app/db.py")

    resp = client.get("/_test_boom")
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error"}
    assert "secret-internal-detail" not in resp.text
    assert "Traceback" not in resp.text


# --- Injection and access control -----------------------------------------

def test_search_is_not_vulnerable_to_sql_injection():
    token = register_and_login()
    make_scan(token, title="plain finding")
    resp = client.get("/scans/search", params={"q": "zz' OR '1'='1"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0

    union = "zz' UNION SELECT id,hashed_password,email,username,username,username,username,id,created_at FROM users--"
    resp = client.get("/scans/search", params={"q": union}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_search_treats_like_wildcards_literally():
    token = register_and_login()
    make_scan(token, title="plain finding")
    resp = client.get("/scans/search", params={"q": "%%"}, headers=auth_headers(token))
    assert resp.json()["count"] == 0


def test_search_only_returns_callers_own_scans():
    alice = register_and_login("alice", "alice@example.com")
    bob = register_and_login("bob", "bob@example.com")
    make_scan(alice, title="alice private finding")
    assert client.get("/scans/search", params={"q": "private"}, headers=auth_headers(bob)).json()["count"] == 0
    assert client.get("/scans/search", params={"q": "private"}, headers=auth_headers(alice)).json()["count"] == 1


def test_cannot_read_another_users_scan():
    alice = register_and_login("alice", "alice@example.com")
    bob = register_and_login("bob", "bob@example.com")
    scan_id = make_scan(alice)
    assert client.get(f"/scans/{scan_id}", headers=auth_headers(alice)).status_code == 200
    assert client.get(f"/scans/{scan_id}", headers=auth_headers(bob)).status_code == 404


# --- CORS -----------------------------------------------------------------

def test_cors_does_not_reflect_arbitrary_origins():
    resp = client.get("/health", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in resp.headers
    assert "access-control-allow-credentials" not in resp.headers


# --- Share link hardening (Task 1 code) -----------------------------------

def _protected_link(token, password="correct-horse"):
    scan_id = make_scan(token)
    url = client.post(f"/scans/{scan_id}/share", json={"password": password},
                      headers=auth_headers(token)).json()["share_url"]
    return url.rsplit("/share/", 1)[1]


def _failed_attempts():
    db = TestingSessionLocal()
    try:
        return db.query(models.ShareLink).one().failed_attempts
    finally:
        db.close()


def test_share_password_accepted_via_header_not_just_query_string():
    t = _protected_link(register_and_login())
    assert client.get(f"/share/{t}", headers={"X-Share-Password": "wrong-password"}).status_code == 401
    assert client.get(f"/share/{t}", headers={"X-Share-Password": "correct-horse"}).status_code == 200


def test_attempt_counter_never_exceeds_the_limit():
    t = _protected_link(register_and_login())
    for _ in range(12):
        client.get(f"/share/{t}", headers={"X-Share-Password": "nope-nope"})
    # Attempts are reserved atomically, so extra requests cannot push past 5.
    assert _failed_attempts() == 5


def test_successful_password_resets_the_failure_counter():
    t = _protected_link(register_and_login())
    for _ in range(3):
        client.get(f"/share/{t}", headers={"X-Share-Password": "nope-nope"})
    assert _failed_attempts() == 3
    assert client.get(f"/share/{t}", headers={"X-Share-Password": "correct-horse"}).status_code == 200
    assert _failed_attempts() == 0


def test_missing_password_does_not_consume_an_attempt():
    t = _protected_link(register_and_login())
    for _ in range(10):
        assert client.get(f"/share/{t}").status_code == 401
    assert _failed_attempts() == 0
