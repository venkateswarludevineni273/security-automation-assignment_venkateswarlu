"""Tests for the second hardening pass: account protections, input limits,
security headers, and share-link snapshot / list / revoke / audit logging."""
import json
import logging
from datetime import datetime, timedelta

from tests.test_api import (  # noqa: F401  (reset_db is an autouse fixture)
    TestingSessionLocal,
    auth_headers,
    client,
    register_and_login,
    reset_db,
)

import main  # noqa: E402
import models  # noqa: E402


def make_scan(token, **over):
    body = {"title": "Finding", "description": "d", "severity": "low",
            "affected_component": "x", "remediation_notes": "public note"}
    body.update(over)
    resp = client.post("/scans", json=body, headers=auth_headers(token))
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def share(token, scan_id, password=None):
    body = {"password": password} if password else None
    return client.post(f"/scans/{scan_id}/share", json=body, headers=auth_headers(token))


def tok(url):
    return url.rsplit("/share/", 1)[1]


# --- Account protections (F9, F10) ----------------------------------------

def test_weak_password_is_rejected_at_registration():
    resp = client.post("/auth/register", json={"username": "carol", "email": "c@example.com", "password": "short"})
    assert resp.status_code == 422


def test_duplicate_username_and_email_get_the_same_message():
    client.post("/auth/register", json={"username": "dave", "email": "d@example.com", "password": "password-1234"})
    dup_name = client.post("/auth/register", json={"username": "dave", "email": "other@example.com", "password": "password-1234"})
    dup_mail = client.post("/auth/register", json={"username": "other", "email": "d@example.com", "password": "password-1234"})
    assert dup_name.status_code == dup_mail.status_code == 400
    assert dup_name.json() == dup_mail.json()


def _disable(username):
    db = TestingSessionLocal()
    try:
        db.query(models.User).filter(models.User.username == username).one().is_active = 0
        db.commit()
    finally:
        db.close()


def test_disabled_user_cannot_log_in():
    register_and_login("erin", "erin@example.com")
    _disable("erin")
    resp = client.post("/auth/login", json={"username": "erin", "password": "password123"})
    assert resp.status_code == 401


def test_disabled_user_existing_token_stops_working_immediately():
    token = register_and_login("frank", "frank@example.com")
    assert client.get("/scans", headers=auth_headers(token)).status_code == 200
    _disable("frank")
    assert client.get("/scans", headers=auth_headers(token)).status_code == 401


# --- Input limits (F11) ----------------------------------------------------

def test_list_limit_is_capped():
    token = register_and_login()
    assert client.get("/scans?limit=101", headers=auth_headers(token)).status_code == 422
    assert client.get("/scans?limit=0", headers=auth_headers(token)).status_code == 422
    assert client.get("/scans?skip=-1", headers=auth_headers(token)).status_code == 422
    assert client.get("/scans?limit=100", headers=auth_headers(token)).status_code == 200


def test_oversized_fields_are_rejected():
    token = register_and_login()
    resp = client.post("/scans", json={"title": "t" * 201, "severity": "low", "affected_component": "x"},
                       headers=auth_headers(token))
    assert resp.status_code == 422
    resp = client.post("/scans", json={"title": "t", "description": "d" * 10001, "severity": "low",
                                       "affected_component": "x"}, headers=auth_headers(token))
    assert resp.status_code == 422


# --- Security headers ------------------------------------------------------

def test_security_headers_are_set():
    resp = client.get("/health")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert "max-age" in resp.headers["strict-transport-security"]


# --- Share links: snapshot (S4) -------------------------------------------

def test_shared_view_is_a_snapshot_not_live():
    token = register_and_login()
    scan_id = make_scan(token)
    t = tok(share(token, scan_id).json()["share_url"])

    client.patch(f"/scans/{scan_id}", json={"remediation_notes": "INTERNAL: added after sharing"},
                 headers=auth_headers(token))

    data = client.get(f"/share/{t}").json()
    assert data["remediation_notes"] == "public note"
    # A new link taken afterwards does show the new note.
    t2 = tok(share(token, scan_id).json()["share_url"])
    assert client.get(f"/share/{t2}").json()["remediation_notes"] == "INTERNAL: added after sharing"


# --- Share links: list and revoke (S3, S5) --------------------------------

def test_owner_can_list_links_and_response_has_no_token():
    token = register_and_login()
    scan_id = make_scan(token)
    url = share(token, scan_id, password="correct-horse").json()["share_url"]
    resp = client.get(f"/scans/{scan_id}/shares", headers=auth_headers(token))
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["password_protected"] is True
    assert rows[0]["expired"] is False and rows[0]["locked"] is False
    assert tok(url) not in resp.text


def test_list_shows_locked_state():
    token = register_and_login()
    scan_id = make_scan(token)
    t = tok(share(token, scan_id, password="correct-horse").json()["share_url"])
    for _ in range(5):
        client.get(f"/share/{t}", params={"password": "nope-nope-1"})
    rows = client.get(f"/scans/{scan_id}/shares", headers=auth_headers(token)).json()
    assert rows[0]["locked"] is True


def test_non_owner_cannot_list_links():
    alice = register_and_login("alice", "alice@example.com")
    bob = register_and_login("bob", "bob@example.com")
    scan_id = make_scan(alice)
    share(alice, scan_id)
    assert client.get(f"/scans/{scan_id}/shares", headers=auth_headers(bob)).status_code == 404


def test_owner_can_revoke_a_link_immediately():
    token = register_and_login()
    scan_id = make_scan(token)
    t = tok(share(token, scan_id).json()["share_url"])
    link_id = client.get(f"/scans/{scan_id}/shares", headers=auth_headers(token)).json()[0]["id"]
    assert client.get(f"/share/{t}").status_code == 200

    assert client.delete(f"/shares/{link_id}", headers=auth_headers(token)).status_code == 204
    assert client.get(f"/share/{t}").status_code == 404


def test_non_owner_cannot_revoke_a_link():
    alice = register_and_login("alice", "alice@example.com")
    bob = register_and_login("bob", "bob@example.com")
    scan_id = make_scan(alice)
    t = tok(share(alice, scan_id).json()["share_url"])
    link_id = client.get(f"/scans/{scan_id}/shares", headers=auth_headers(alice)).json()[0]["id"]

    assert client.delete(f"/shares/{link_id}", headers=auth_headers(bob)).status_code == 404
    assert client.get(f"/share/{t}").status_code == 200  # still alive


def test_revoke_requires_authentication():
    assert client.delete("/shares/1").status_code in (401, 403)


def test_expired_links_are_purged_on_next_share():
    token = register_and_login()
    scan_id = make_scan(token)
    share(token, scan_id)
    db = TestingSessionLocal()
    try:
        db.query(models.ShareLink).update({"expires_at": datetime.utcnow() - timedelta(hours=1)})
        db.commit()
    finally:
        db.close()
    share(token, scan_id)  # creating a new link purges the expired one
    db = TestingSessionLocal()
    try:
        assert db.query(models.ShareLink).count() == 1
    finally:
        db.close()


# --- Audit logging ---------------------------------------------------------

def test_audit_log_records_events_but_never_secrets(caplog):
    token = register_and_login()
    scan_id = make_scan(token)
    with caplog.at_level(logging.INFO):
        url = share(token, scan_id, password="correct-horse").json()["share_url"]
        t = tok(url)
        client.get(f"/share/{t}", params={"password": "wrong-pass-12"})
        client.get(f"/share/{t}", params={"password": "correct-horse"})
    # Only the application's own log lines (the test client logs its own requests).
    text = "\n".join(r.getMessage() for r in caplog.records if r.name == "main")
    assert "share_link_created" in text
    assert "share_link_password_failed" in text
    assert "share_link_accessed" in text
    for secret in (t, "correct-horse", "wrong-pass-12"):
        assert secret not in text


# --- Notify authentication -------------------------------------------------

def test_notify_call_carries_the_bearer_token(monkeypatch):
    seen = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen["headers"] = headers

    monkeypatch.setattr(main.httpx, "post", fake_post)
    monkeypatch.setattr(main, "NOTIFY_API_TOKEN", "abc123")
    main._fire_notify("scan.created", {"id": 1})
    assert seen["headers"] == {"Authorization": "Bearer abc123"}


def test_notify_call_sends_no_header_when_unconfigured(monkeypatch):
    seen = {}
    monkeypatch.setattr(main.httpx, "post", lambda url, json=None, headers=None, timeout=None: seen.update(h=headers))
    monkeypatch.setattr(main, "NOTIFY_API_TOKEN", None)
    main._fire_notify("scan.created", {"id": 1})
    assert seen["h"] == {}


def test_access_log_redacts_share_token_and_password():
    from log_redaction import RedactShareSecrets

    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1,
        '%s - "%s %s HTTP/%s" %d',
        ("10.0.0.1:5000", "GET", "/share/SECRETTOKEN123?password=hunter2hunter2&x=1", "1.1", 200), None,
    )
    assert RedactShareSecrets().filter(record) is True
    line = record.getMessage()
    assert "SECRETTOKEN123" not in line and "hunter2hunter2" not in line
    assert "/share/[redacted]" in line and "password=[redacted]" in line
    assert "x=1" in line  # unrelated query parameters are untouched


def test_redaction_filter_is_installed_on_the_access_logger():
    from log_redaction import RedactShareSecrets

    assert any(isinstance(f, RedactShareSecrets) for f in logging.getLogger("uvicorn.access").filters)
