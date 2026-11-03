# Remediation Plan

## 1. What was fixed in this submission

Everything below is visible in commit `Remediate critical/high findings (Task 3)`; each fix has a regression test in `tests/test_security.py` (14 of the 16 tests fail against the original code).

| Finding | Severity | Fix | Code |
|---------|----------|-----|------|
| F1 Forged login tokens accepted | Critical | Algorithm pinned to HS256, `"none"` removed, `exp` and `sub` required | `app/auth.py` |
| F2 Secrets in source | Critical | Read from environment or mounted file; app refuses to start without a 32+ character key | `app/config.py` |
| F3 SQL injection in search | High | Bound parameters, wildcards escaped, results scoped to the caller | `app/database.py`, `app/main.py` |
| F4 Users can read each other's scans | High | Owner enforced on read and search | `app/main.py` |
| F5 Passwords in logs | High | Password removed from log lines | `app/main.py` |
| F6 Vulnerable Python dependencies | High | `python-jose` replaced with PyJWT; unused `python-multipart` and `cryptography` removed; rest upgraded. pip-audit: **67 to 0** | `requirements.txt` |
| F7 Open CORS | Medium | Opt-in allowlist, credentials off | `app/main.py` |
| F8 Stack traces to clients | Medium | Generic 500; detail logged server-side | `app/main.py` |
| S1 Password-guess lock could be raced *(new feature)* | Medium | Atomic reservation of each attempt before checking | `app/main.py` |
| S2 Share password in URL *(new feature)* | Low | `X-Share-Password` header accepted and preferred | `app/main.py` |

**Against the requirement** (at least 3 critical/high fixes, at least one in the Task 1 code): six critical/high findings were fixed (F1-F6; F2 only in part, see R1). Two fixes are in the Task 1 code (S1, S2), but they are rated Medium and Low. My review of the share feature found no High-severity flaw, and I did not inflate a rating to fit the requirement.

## 2. What was not fixed, and why

Effort is for one engineer including tests and review. "Residual risk" is what remains *today*, after the compensating controls listed.

### R1 - Rotate every secret that was ever committed (F2) - **do this first**
- **Why not done here:** rotation happens in the systems that hold the secrets (the secrets manager, the notify service's consumers), not in code, and I cannot rotate what I do not control.
- **Residual risk: Critical until done.** The old JWT signing key, DB password, admin API key and notify key are public in git history (the repository is public). Removing them from the latest commit does not help.
- **Effort:** 2-4 hours. Generate new values in the secrets manager, redeploy, and invalidate old sessions (changing the signing key does this automatically). Optionally rewrite history, but treat the values as burned regardless.
- **Compensating controls:** the old signing key no longer verifies anything once a new one is deployed. The admin API key and DB password are not used by the current code.

### R2 - Login brute-force protection, password policy, user enumeration (F9)
- **Why not done:** needs a product decision (lockout rules, policy) and shared state (a cache) to be correct across replicas. A quick in-memory counter would be bypassed by the second replica and would add denial-of-service risk by locking real users out.
- **Residual risk: Medium.** An attacker can guess passwords at network speed.
- **Effort:** 1-2 days (password rules, per-account and per-IP throttling with exponential back-off, generic registration errors).
- **Compensating controls:** bcrypt makes each guess slow for the server; the ingress controller can apply a rate limit (`nginx.ingress.kubernetes.io/limit-rps`) immediately at no code cost.

### R3 - Enforce `is_active` (F10)
- **Why not done:** deliberately left small and separate; it needs a decision on how offboarding works (is there an admin endpoint to disable a user?).
- **Residual risk: Medium.** Disabled accounts keep working.
- **Effort:** 2-3 hours (check the flag in login and in `get_current_user`, add tests).
- **Compensating controls:** access tokens last 30 minutes. User deletion at the database level removes access.

### R4 - Input size limits and a maximum page size (F11)
- **Residual risk: Low.** **Effort:** 1-2 hours (`Field(max_length=...)`, `limit` capped to 100).
- **Compensating controls:** authentication required; the pod has CPU/memory limits and the ingress can cap request body size.

### R5 - Replace SQLite with a managed database (F12)
- **Why not done:** an architecture change, not a fix; larger than the time budget and it needs a migration plan.
- **Residual risk: Medium.** No encryption at rest by the application, no automatic backups, and the service cannot run more than one replica.
- **Effort:** 3-5 days (PostgreSQL, Alembic migrations, connection config from the secrets manager, backup policy).
- **Compensating controls:** the Helm chart uses a persistent volume (encrypt the storage class), `Recreate` strategy and a single replica so the file is never written by two pods.

### R6 - Notification service: authentication, SSRF protection, error handling, own secret (N1, N3, N4, F2-notify)
- **Why not done:** the brief states this service needs no changes, and a correct fix is a design task (service-to-service authentication, an allowlist of webhook destinations, egress policy), not a patch.
- **Residual risk: High while internal-only; Critical if exposed.** Anyone who can reach port 3001 can make the server call arbitrary URLs and receive its service key.
- **Effort:** 2-3 days. Require a per-caller token on every route; accept only `https://` webhook URLs on an allowlist, resolve DNS and block private/link-local addresses; stop sending the shared key to user-supplied URLs (sign payloads instead); move the key to the secrets manager; generic error responses.
- **Compensating controls:** not deployed by the Helm chart and not internet-facing. When deployed, apply a NetworkPolicy that admits only the API pod and denies all egress except DNS and approved webhook destinations.

### R7 - Upgrade npm dependencies (N2)
- **Why not done:** same scope reason as R6. `express` 4 and `axios` 0.x upgrades can change behaviour; they deserve their own tests.
- **Residual risk: Medium** given the internal-only exposure (the 1 critical advisory, IP spoofing via `proxy-addr`, requires the app to trust forwarded headers, which it does not).
- **Effort:** 2-4 hours: `npm audit fix`, `axios` to 1.x, `express` to the current 4.x/5.x, run the existing tests.
- **Compensating controls:** the CI job already runs `npm audit` and uploads the report; Dependabot is configured for `/notify`.

### R8 - Share-link management and abuse limits (S2 remainder, S3, S4, S5)
- **Residual risk: Low.** A holder of a link can use up its 5 password attempts; shared pages reflect later edits; no list/revoke endpoints; expired rows linger.
- **Effort:** 1 day. `GET /scans/{id}/shares`, `DELETE /shares/{id}` (owner only), snapshot the scan at share time, a nightly purge of expired links, optional per-IP throttling on `/share/*`.
- **Compensating controls:** 256-bit links cannot be guessed; links expire in 24 hours; owners can delete the scan, which deletes its links; response is `no-store`.

### R9 - Items outside the code
| Item | Residual risk | Effort | Compensating control |
|------|---------------|--------|----------------------|
| TLS and security headers (HSTS etc.) | Medium until the ingress terminates TLS | 2 hours | Ingress template requires TLS |
| Image digest pinning, signed images | Low | 3 hours | Dependabot proposes updates; Trivy scans every build |
| Audit logging of share-link creation and access | Medium | 1 day | Request logs exist; no structured audit trail |
| Findings from the container/IaC scans that remain open | see `findings.md` section 5 | see there | see there |

## 3. Suggested order of work

1. **R1** rotate secrets *(same day)*
2. **R6 and R7** make the notification service safe before it is ever exposed or deployed beside the API
3. **R2 and R3** account hardening
4. **R5** database
5. **R4, R8, R9** hardening and housekeeping
