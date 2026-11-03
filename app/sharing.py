"""Helpers for the Shared Report Link feature.

Design notes (see README, "Shared Report Link"):
  * The share token is 256 bits from the OS CSPRNG (secrets.token_urlsafe).
  * Only a SHA-256 digest of the token is stored. A leaked database therefore
    does not leak usable links. SHA-256 (not bcrypt) is correct here because
    the token is high-entropy and random, so there is nothing to brute-force,
    and we need a fast deterministic digest to look the row up by.
  * The optional link password is low-entropy and human-chosen, so it is
    stored with bcrypt (via the existing auth helpers), never in plaintext.
"""
import hashlib
import secrets
from datetime import timedelta

SHARE_LINK_TTL = timedelta(hours=24)
MAX_FAILED_PASSWORD_ATTEMPTS = 5


def generate_share_token() -> str:
    """Return a new URL-safe token with 256 bits of entropy."""
    return secrets.token_urlsafe(32)


def hash_share_token(token: str) -> str:
    """Return the hex SHA-256 digest used to store and look up a token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
