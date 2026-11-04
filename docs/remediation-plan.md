# Remediation Plan

Fixes were made in two passes. Pass 1 (commit `Remediate critical/high findings (Task 3)`) fixed everything rated critical or high in the Python API. Pass 2 (commits `Harden API accounts, inputs and share links`, `Harden notification service`, `Image publish, packaging-tool removal, ingress rate limits`) fixed everything else that could be fixed in code or CI. Each fix has a regression test (65 Python tests, 21 Node tests).

## 1. What was fixed

| Finding | Severity | Fix | Code |
|---------|----------|-----|------|
| F1 Forged login tokens accepted | Critical | Algorithm pinned to HS256, `"none"` removed, `exp` and `sub` required | `app/auth.py` |
| F2 Secrets in source | Critical | Read from environment or mounted file; app refuses to start without a 32+ character key; notify key removed from source too. **Rotation still required, see R1** | `app/config.py`, `notify/src/config.js` |
| F3 SQL injection in search | High | Bound parameters, wildcards escaped, results scoped to the caller | `app/database.py` |
| F4 Users can read each other's scans | High | Owner enforced on read and search | `app/main.py` |
| F5 Passwords in logs | High | Password removed from log lines | `app/main.py` |
| F6 Vulnerable Python dependencies | High | `python-jose` replaced with PyJWT; unused packages removed; rest upgraded. pip-audit **67 to 0** | `requirements.txt` |
| N1 Notify service open and SSRF | High | Bearer token on every route (fails closed); https-only webhook URLs; private, loopback, link-local and metadata addresses refused at registration **and** at connect time; payloads HMAC-signed instead of sending a shared key; no redirects | `notify/src/*` |
| N2 Vulnerable npm dependencies | High | axios 1.21.0, express 4.22.3, `uuid` dropped. npm audit **11 to 0**; CI now fails on high or critical | `notify/package.json` |
| C1 Fixable critical OS CVEs in the image | High | `apt-get upgrade` in the runtime stage | `Dockerfile` |
| F7 Open CORS | Medium | Opt-in allowlist, credentials off | `app/main.py` |
| F8 / N3 Stack traces to clients | Medium | Generic 500 (API and notify) | both services |
| F10 Disabled users still work | Medium | `is_active` checked at login and on every request | `app/auth.py`, `app/main.py` |
| F9 (part) Weak passwords, user enumeration | Medium | 10-character minimum; one generic duplicate message; ingress rate limit in the Helm chart | `app/main.py`, `helm/` |
| F11 Unbounded input | Low | Page size 1-100, text field length limits | `app/main.py` |
| S1 Password-guess lock could be raced | Medium | Attempt reserved atomically before the password is checked | `app/main.py` |
| S2 Password in URL | Low | `X-Share-Password` header preferred; access log redacts token and password | `app/main.py`, `app/log_redaction.py` |
| S4 Shared page showed live data | Low | Snapshot taken when the link is created | `app/main.py` |
| S5 No list, revoke or purge, no audit | Low | List and revoke endpoints, expired links purged, audit log lines without secrets | `app/main.py` |
| C4 Packaging tools in the image | Low | `pip`, `setuptools`, `wheel` removed; re-scan shows 0 Python-package findings | `Dockerfile` |
| Security headers | Low | `nosniff`, frame deny, no-referrer, HSTS | `app/main.py` |
| No published image | n/a | CI publishes the image to the GitHub container registry from `main` and records its digest | `.github/workflows/ci.yml` |

**Against the requirement** (at least 3 critical/high fixes, at least one in the Task 1 code): eight critical or high findings were fixed. The fixes in the Task 1 code (S1, S2, S4, S5) are rated Medium and Low; my review of the share feature found no High-severity flaw, and I did not inflate a rating to fit the requirement.

## 2. What is not fixed, and why

Effort is for one engineer including tests and review. "Residual risk" is what remains *today*, after the compensating controls listed.

### R1 - Rotate every secret that was ever committed (F2) - **do this first**
- **Runbook:** step-by-step in [`secret-rotation.md`](secret-rotation.md), written against the chart's real secret paths, with a check that old tokens are rejected.
- **Why not done:** rotation happens in the systems that hold the secrets (the secrets manager and whatever uses these values), not in code, and I cannot rotate what I do not control.
- **Residual risk: Critical until done.** The old JWT signing key, DB password, admin API key and notify service key are public in git history (the repository is public). Removing them from the latest commit does not help.
- **Effort:** 2-4 hours. Generate new values in the secrets manager, redeploy, and invalidate old sessions (changing the signing key does this automatically). Optionally rewrite history, but treat the values as burned regardless.
- **Compensating controls:** the old signing key verifies nothing once a new one is deployed. The admin API key, DB password and old notify key are no longer used by the code.

### R5 - Replace SQLite with a managed database (F12)
- **Why not done:** an architecture change, not a fix; larger than the time budget and it needs a migration plan. Note also that `create_all` does not alter existing tables, so an existing database needs the new `share_links.snapshot` column added or recreated.
- **Residual risk: Medium.** No encryption at rest by the application, no automatic backups, and the service cannot run more than one replica.
- **Effort:** 3-5 days (PostgreSQL, Alembic migrations, connection config from the secrets manager, backup policy).
- **Compensating controls:** the Helm chart uses a persistent volume (encrypt the storage class), `Recreate` strategy and a single replica so the file is never written by two pods.

### R2 - Per-account login throttling (rest of F9)
- **Why not done:** a correct lockout needs shared state across replicas and a product decision. A quick in-memory counter would be bypassed by a second replica and would let an attacker lock real users out.
- **Residual risk: Medium to Low.** Password guessing is limited only by the front door's rate limit (set in the chart, not yet running anywhere) and by bcrypt's slowness. There is no password breach check or complexity rule beyond length.
- **Effort:** 1-2 days.
- **Compensating controls:** ingress rate limit (`limit-rps` 10, `limit-connections` 20), 10-character minimum, bcrypt.

### R6 - Notification service: what remains
- **Residual risk: Low to Medium.** The service now authenticates callers, blocks internal destinations and no longer leaks a key, but: one shared token (no per-caller identity); webhooks are held in memory and lost on restart; traffic between the API and the service is plain HTTP inside the cluster; the chart does not deploy the service, so its own NetworkPolicy does not exist yet.
- **Effort:** 1-2 days (per-caller tokens or mTLS, persistent registry, a NetworkPolicy and Deployment for the service, destination allowlist configured in production).
- **Compensating controls:** the SSRF guard, the optional `NOTIFY_ALLOWED_HOSTS` allowlist, and the API's NetworkPolicy.

### R8 - Share-link abuse limits (S2 remainder, S3)
- **Residual risk: Low.** The query-string password is still accepted because the brief specifies it; proxy or ingress logs outside this service may record it. A holder of a link can still use up its 5 password attempts, but the owner can now see that (`locked`), revoke the link and issue a new one.
- **Effort:** half a day. Per-IP throttling with a cooldown instead of a hard lock; drop the query-string password once clients move to the header.
- **Compensating controls:** 256-bit links cannot be guessed; 24-hour expiry; header preferred; log redaction; owner revoke.

### R9 - Items outside the code
| Item | Residual risk | Effort | Compensating control |
|------|---------------|--------|----------------------|
| 2 CRITICAL and 36 HIGH OS-package CVEs with no upstream fix (`libsqlite3-0`, `zlib1g`, others) | Low to Medium | 0 today; 1 day to move to a distroless base | Mostly in code the app never runs; CI fails the build the day a fix exists |
| Image pinned by tag, not digest (Checkov I2) | Low | 1 hour | CI records each build's digest; deploy with `image.digest` |
| Checkov "default namespace" (I1) | None (a rendering artefact) | none | The chart is installed with `-n <namespace>` |
| Chart never installed on a real cluster | Medium until tested | half a day | CI renders and scans it; the image is built, started and health-checked in CI |
| Audit log is plain log lines, not a tamper-evident store | Medium | 1 day | Lines contain ids, usernames and outcomes only, never tokens or passwords |
| Tokens last 30 minutes and cannot be revoked early (disabled users are blocked immediately) | Low | 1 day | Short lifetime |
| No dynamic (running-app) testing; Semgrep not run | Medium | half a day | Add to CI |

## 3. Suggested order of work

1. **R1** rotate secrets *(same day)*
2. Install the chart in a test cluster and confirm the secret, network policy and rate limit work
3. **R5** database, then **R2** login throttling
4. **R6** finish the notification service before it is deployed
5. **R8, R9** housekeeping
