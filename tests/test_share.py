"""Tests for the Shared Report Link feature (POST /scans/{id}/share, GET /share/{token}).

The DB override and per-test reset fixture live in test_api.py; they are
imported here so both files share one test database.
"""
from datetime import datetime, timedelta

from tests.test_api import (  # noqa: F401  (reset_db is an autouse fixture)
    TestingSessionLocal,
    auth_headers,
    client,
    register_and_login,
    reset_db,
)

import models  # noqa: E402  (app/ is on sys.path via test_api)


def make_scan(token, title="Reflected XSS in search"):
    resp = client.post("/scans", json={
        "title": title,
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
        "remediation_notes": "Encode output",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    return resp.json()["id"]


def share(token, scan_id, password=None):
    body = {"password": password} if password is not None else None
    return client.post(f"/scans/{scan_id}/share", json=body, headers=auth_headers(token))


def token_from_url(url):
    return url.rsplit("/share/", 1)[1]


def expire_link(token_value):
    """Move a link's expiry into the past directly in the DB."""
    from sharing import hash_share_token

    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).filter(
            models.ShareLink.token_hash == hash_share_token(token_value)
        ).one()
        link.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Creating links
# ---------------------------------------------------------------------------

def test_owner_can_create_share_link():
    token = register_and_login()
    scan_id = make_scan(token)
    resp = share(token, scan_id)
    assert resp.status_code == 201
    assert resp.json()["share_url"].startswith("http://localhost:8000/share/")


def test_create_share_requires_authentication():
    token = register_and_login()
    scan_id = make_scan(token)
    resp = client.post(f"/scans/{scan_id}/share")
    assert resp.status_code in (401, 403)


def test_cannot_share_someone_elses_scan():
    alice = register_and_login("alice", "alice@example.com")
    bob = register_and_login("bob", "bob@example.com")
    scan_id = make_scan(alice)
    resp = share(bob, scan_id)
    # Same response as a missing scan, so ids cannot be enumerated.
    assert resp.status_code == 404


def test_share_nonexistent_scan_returns_404():
    token = register_and_login()
    assert share(token, 9999).status_code == 404


def test_each_link_gets_a_unique_token():
    token = register_and_login()
    scan_id = make_scan(token)
    a = token_from_url(share(token, scan_id).json()["share_url"])
    b = token_from_url(share(token, scan_id).json()["share_url"])
    assert a != b
    assert len(a) >= 43  # 32 random bytes, base64url encoded


def test_short_password_rejected():
    token = register_and_login()
    scan_id = make_scan(token)
    assert share(token, scan_id, password="short").status_code == 422


def test_share_url_ignores_host_header():
    token = register_and_login()
    scan_id = make_scan(token)
    resp = client.post(
        f"/scans/{scan_id}/share",
        headers={**auth_headers(token), "Host": "evil.example.com"},
    )
    assert resp.status_code == 201
    assert "evil.example.com" not in resp.json()["share_url"]


# ---------------------------------------------------------------------------
# Reading links (public, no auth)
# ---------------------------------------------------------------------------

def test_public_can_read_unprotected_link_without_auth():
    token = register_and_login()
    scan_id = make_scan(token)
    url = share(token, scan_id).json()["share_url"]

    resp = client.get(f"/share/{token_from_url(url)}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Reflected XSS in search"
    assert data["remediation_notes"] == "Encode output"


def test_public_view_does_not_expose_internal_fields():
    token = register_and_login()
    scan_id = make_scan(token)
    url = share(token, scan_id).json()["share_url"]

    data = client.get(f"/share/{token_from_url(url)}").json()
    assert "owner_id" not in data
    assert "id" not in data


def test_shared_response_is_not_cacheable():
    token = register_and_login()
    scan_id = make_scan(token)
    url = share(token, scan_id).json()["share_url"]

    resp = client.get(f"/share/{token_from_url(url)}")
    assert resp.headers["cache-control"] == "no-store"


def test_unknown_token_returns_404():
    assert client.get("/share/not-a-real-token").status_code == 404


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

def test_link_expires_after_24_hours():
    token = register_and_login()
    scan_id = make_scan(token)
    url = share(token, scan_id).json()["share_url"]

    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).one()
        ttl = link.expires_at - link.created_at
    finally:
        db.close()
    assert timedelta(hours=23, minutes=59) < ttl <= timedelta(hours=24, seconds=5)

    assert client.get(f"/share/{token_from_url(url)}").status_code == 200
    expire_link(token_from_url(url))
    assert client.get(f"/share/{token_from_url(url)}").status_code == 404


def test_expired_protected_link_is_404_even_with_correct_password():
    token = register_and_login()
    scan_id = make_scan(token)
    url = share(token, scan_id, password="correct-horse").json()["share_url"]
    t = token_from_url(url)
    expire_link(t)
    assert client.get(f"/share/{t}", params={"password": "correct-horse"}).status_code == 404


# ---------------------------------------------------------------------------
# Password protection
# ---------------------------------------------------------------------------

def test_protected_link_requires_password():
    token = register_and_login()
    scan_id = make_scan(token)
    t = token_from_url(share(token, scan_id, password="correct-horse").json()["share_url"])

    assert client.get(f"/share/{t}").status_code == 401


def test_protected_link_rejects_wrong_password():
    token = register_and_login()
    scan_id = make_scan(token)
    t = token_from_url(share(token, scan_id, password="correct-horse").json()["share_url"])

    assert client.get(f"/share/{t}", params={"password": "wrong-password"}).status_code == 401


def test_protected_link_accepts_correct_password():
    token = register_and_login()
    scan_id = make_scan(token)
    t = token_from_url(share(token, scan_id, password="correct-horse").json()["share_url"])

    resp = client.get(f"/share/{t}", params={"password": "correct-horse"})
    assert resp.status_code == 200
    assert resp.json()["title"] == "Reflected XSS in search"


def test_link_locks_after_too_many_wrong_passwords():
    token = register_and_login()
    scan_id = make_scan(token)
    t = token_from_url(share(token, scan_id, password="correct-horse").json()["share_url"])

    for _ in range(5):
        assert client.get(f"/share/{t}", params={"password": "nope-nope"}).status_code == 401
    # Locked: even the correct password is now refused.
    assert client.get(f"/share/{t}", params={"password": "correct-horse"}).status_code == 429


# ---------------------------------------------------------------------------
# Storage and lifecycle
# ---------------------------------------------------------------------------

def test_token_and_password_are_not_stored_in_plaintext():
    token = register_and_login()
    scan_id = make_scan(token)
    url = share(token, scan_id, password="correct-horse").json()["share_url"]
    t = token_from_url(url)

    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).one()
        assert link.token_hash != t
        assert t not in link.token_hash
        assert link.password_hash != "correct-horse"
        assert link.password_hash.startswith("$2")  # bcrypt
    finally:
        db.close()


def test_deleting_scan_revokes_its_links():
    token = register_and_login()
    scan_id = make_scan(token)
    t = token_from_url(share(token, scan_id).json()["share_url"])
    assert client.get(f"/share/{t}").status_code == 200

    assert client.delete(f"/scans/{scan_id}", headers=auth_headers(token)).status_code == 204
    assert client.get(f"/share/{t}").status_code == 404
