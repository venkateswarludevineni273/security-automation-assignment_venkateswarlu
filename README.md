# Security Automation Engineer — Take-Home Assignment

Welcome. This assignment is designed to reflect the real work of a Lead Security Automation Engineer: extending an existing service, identifying and assessing security risks, remediating them with code, and deploying it securely. There are no trick questions — we are evaluating your depth of knowledge, your judgment under constraints, and your ability to communicate risk.

**Estimated time: 4–6 hours.** We respect your time. If you find yourself going significantly over, scope down rather than rushing.

---

## Background

**VulnTracker** is a two-service system for managing vulnerability scan results:

- **`app/`** — Python/FastAPI REST API. Security teams use it to log findings, track remediation, and share reports with stakeholders.
- **`notify/`** — Node.js/Express notification service. Intended to dispatch webhook events to registered endpoints when scan records are created or updated.

Both services are working but imperfect internal prototypes. Neither has gone through a formal security review. The Python API calls the notification service in the background whenever a scan is created or updated — start both services to see the full flow.

---

## Getting Started

**Create your own repository for this assignment.** Do not fork — your solution must be in a fresh repo. You may use the starter code as a base, but your work must be in your own repo.

```bash
# 1. Clone the assignment repo locally
git clone https://github.com/cloudtriquetra/asa-assignment.git
cd asa-assignment

# 2. Point it at your own new GitHub repo (create one first at github.com)
git remote set-url origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

From here, work on your own repo and share its URL when you submit.

**Requirements:** Python 3.11 (exactly — see CI), Node.js 20+, Docker

**Python API (`app/`)**

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

The API must be started from inside the `app/` directory — the modules use bare imports and won't resolve from the repo root:

```bash
cd app
uvicorn main:app --reload
```

Available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

Run the Python test suite from the **repo root**:

```bash
pytest tests/ -v
```

**Notification Service (`notify/`)**

```bash
cd notify
npm install
npm start
```

Available at `http://localhost:3001`.

Run the Node.js test suite (stop the notify service first if it is running — the test suite starts its own server on the same port):

```bash
cd notify
npm test
```

---

## Your Tasks

### Task 1 — Extend the App _(~1–1.5 hrs)_

Implement the **"Shared Report Link"** feature:

> As a VulnTracker user, I want to share a specific scan result with an external stakeholder (e.g. a customer or auditor) via a unique link. The link must expire after **24 hours** and must support **optional password protection**.

Add the following endpoints to the app:

| Method | Path                     | Auth          | Description                                                                                                              |
| ------ | ------------------------ | ------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `POST` | `/scans/{scan_id}/share` | Bearer token  | Generate a share token for a scan. Accepts optional `password` in the request body. Returns `{ "share_url": "..." }`     |
| `GET`  | `/share/{token}`         | None (public) | Return the scan data if the token is valid and not expired. If password-protected, require a `password` query parameter. |

Implementation choices are yours. We will read and evaluate the code you write here — including the security properties of your implementation. For the `share_url` value, use the incoming request's host, or hard-code `http://localhost:8000` for the prototype — document whichever you choose.

---

### Task 2 — Security Analysis _(~1.5 hrs)_

#### 2a. Run the required scans

You must run **all four** of the following scan categories. Select an appropriate open-source or free-tier tool for each — your tool choices are part of the evaluation.

| Scan type                                      | What it covers                                                                         |
| ---------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Static Application Security Testing (SAST)** | Source code — identify insecure coding patterns, injection risks, hardcoded secrets    |
| **Dependency / SCA vulnerability scan**        | Third-party packages — known CVEs in pinned dependencies                               |
| **Container image scan**                       | The Docker image you build — OS packages, installed libraries, misconfigurations       |
| **Infrastructure-as-Code (IaC) security scan** | Your Helm chart or Terraform — misconfigurations, insecure defaults, policy violations. Complete Task 4 first, then run this scan. |

Save the raw JSON output of each tool to the `reports/` directory, named clearly by scan type:

```
reports/
├── sast.<tool>.json
├── sca.<tool>.json
├── container.<tool>.json
└── iac.<tool>.json
```

#### 2b. Prioritised findings

Write a `docs/findings.md` with a table of security findings, sourced from your scans and your own manual review. For each finding:

- Tool and scan type that detected it (or "manual")
- Severity (your assessment — justify it)
- Business impact in the context of _this specific application_
- Whether it is in the starter code or in your new feature

**Do not copy-paste tool output.** We are evaluating your ability to interpret findings and apply business context to prioritisation — not your ability to run a command.

---

### Task 3 — Remediate _(~1 hr)_

- Fix **at least 3 critical or high severity findings** in code. Show the changes clearly (they will be visible in your git diff / PR).
- At least one fix must be in the code you wrote in Task 1.
- For findings you do not fix, document why in `docs/remediation-plan.md`: what is the residual risk, what effort would remediation require, and what compensating controls (if any) exist?

---

### Task 4 — Containerisation and Deployment Artifacts _(~30–45 min)_

#### Dockerfile (mandatory)

Write a production-grade `Dockerfile` for the **Python FastAPI service** (`app/`). It must:

- Use a minimal, pinned base image
- Run as a non-root user
- Include a `HEALTHCHECK`
- Not embed secrets or credentials

The container image must build successfully and the app must be reachable via `docker run`. Include build and run instructions in your README.

#### Infrastructure

Add either a `terraform/` or `helm/` directory (your choice) that could deploy this service to a Kubernetes cluster or cloud environment. Your deployment must:

- Source secrets from a secrets manager (not hardcoded in manifests or env vars)
- Restrict network ingress to only what is required
- Define resource limits and security contexts

---

### Task 5 — Executive Summary _(~30 min)_

Write `docs/executive-summary.md` as if you are presenting to a CISO who has 5 minutes.

Cover:

1. The overall security posture of the application before and after your work
2. The top 3 residual risks and the reason they were not fully remediated
3. Your recommended next steps if this were a real production service

No jargon. No tool names in the first paragraph. Your audience cares about business risk, not CVE numbers.

---

## Submission

Push your completed solution to your own GitHub repository and share the URL with us. Your repository must contain:

```
/
├── app/                        # extended Python API code
├── notify/                     # Node.js notification service (no changes required)
├── Dockerfile                  # mandatory (may cover one or both services)
├── reports/
│   ├── sast.<tool>.json
│   ├── sca.<tool>.json
│   ├── container.<tool>.json
│   └── iac.<tool>.json
├── terraform/  OR  helm/
├── docs/
│   ├── findings.md
│   ├── remediation-plan.md
│   └── executive-summary.md
├── tests/                      # updated if you added Python tests
└── README.md                   # update with Docker build/run instructions
```

CI must pass (green) on your repo before submission.

---

## What We Are Looking For

We are not grading on volume. We are grading on judgment.

- **Security depth**: Did you find the real issues? Did you prioritise them correctly for this application?
- **Implementation security**: Does your new feature introduce, or avoid, new vulnerabilities?
- **Remediation quality**: Are your fixes correct and complete? Are your deferral reasons honest?
- **Deployment security**: Does your container and infrastructure configuration reflect real-world security practices?
- **Communication**: Would a non-technical executive understand your summary?

Good luck. If anything in the brief is ambiguous, document your assumption and proceed.

---

## Shared Report Link (Task 1)

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/scans/{scan_id}/share` | Bearer token (scan owner only) | Optional JSON body `{"password": "..."}` (8-72 chars). Returns `{"share_url": "..."}` |
| GET | `/share/{token}` | None | If the link is protected, send the password in the `X-Share-Password` header (preferred) or as `?password=...` |
| GET | `/scans/{scan_id}/shares` | Bearer token (owner only) | Lists the scan's links: id, created, expires, password-protected, expired, locked. Never returns a token. |
| DELETE | `/shares/{share_id}` | Bearer token (owner only) | Revokes a link immediately |

**`share_url` base:** built from the `SHARE_BASE_URL` environment variable, defaulting to `http://localhost:8000`. It is deliberately *not* taken from the request's `Host` header, because that header is client-controlled (host-header injection).

**Security properties**
- Token: 256 bits from `secrets.token_urlsafe(32)`; only its SHA-256 digest is stored, so a database leak does not leak usable links.
- Password: optional, stored as a bcrypt hash. Each attempt is reserved with one atomic database update, so parallel requests cannot exceed 5 guesses; after 5 wrong attempts the link is locked. The owner can see `locked` and revoke the link.
- Expiry: 24 hours, enforced server-side. Unknown, expired and revoked tokens return the same 404. Expired links are purged the next time a link is created.
- Authorisation: only the scan's owner can create, list or revoke links; non-owners get the same 404 as a missing record.
- The public response is a **snapshot** taken when the link was created, so later edits to the scan (for example internal notes) never reach the viewer. It omits `owner_id` and the internal `id`, and sends `Cache-Control: no-store`.
- Deleting a scan deletes its links.
- Audit log: link creation, access, failed password, lock and revoke are logged with ids only. The access log redacts `/share/<token>` and `?password=`.

**Known limitations (prototype):** the `?password=` query string is still accepted because the assignment specifies it, so proxy or ingress logs outside this service may record it; someone holding a link can still use up its 5 attempts (the owner can then revoke it and issue a new one); there is no per-IP throttling; the audit trail is ordinary log lines, not a tamper-evident store. Databases created before the `snapshot` column existed need that column added, or to be recreated (`create_all` does not alter existing tables). Details: `docs/remediation-plan.md` (R5, R8, R9).

---

## Configuration (environment variables)

No secrets live in the repository. The API **refuses to start** without a signing key.

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `SECRET_KEY` or `SECRET_KEY_FILE` | **yes** | - | JWT signing key, at least 32 chars. `_FILE` reads it from a mounted file (preferred with a secrets manager). Generate: `openssl rand -hex 32` |
| `DATABASE_URL` | no | `sqlite:///./vulntracker.db` | SQLAlchemy URL (the image uses `sqlite:////data/vulntracker.db`) |
| `SHARE_BASE_URL` | no | `http://localhost:8000` | Base URL used to build share links |
| `CORS_ALLOWED_ORIGINS` | no | *(none)* | Comma-separated browser origins allowed to call the API |
| `NOTIFY_SERVICE_URL` | no | `http://localhost:3001` | Notification service |
| `NOTIFY_API_TOKEN` or `NOTIFY_API_TOKEN_FILE` | no | *(none)* | Bearer token the notification service requires on every call. Without it the API sends no `Authorization` header and the notification service refuses the call (the API logs a warning and carries on). |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | no | `30` | Login token lifetime |

Local development and tests (tests set their own throwaway key):

```bash
pip install -r requirements-dev.txt      # runtime deps + pytest
pytest tests/ -v
export SECRET_KEY=$(openssl rand -hex 32)
cd app && uvicorn main:app --reload
```

## Docker (Task 4)

The image is a multi-stage build on a pinned `python:3.11.14-slim-bookworm`, runs as non-root (UID 10001), has a `HEALTHCHECK`, and contains no secrets.

```bash
# build (from the repo root)
docker build -t vulntracker-api:latest .

# run - the secret is supplied at run time, never baked into the image
docker run --rm -p 8000:8000 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -v vulntracker-data:/data \
  vulntracker-api:latest

curl http://localhost:8000/health        # {"status":"ok","service":"vulntracker-api"}
docker ps                                 # STATUS shows (healthy) after ~15s
```

To check the hardening yourself: `docker run --rm --entrypoint id vulntracker-api:latest` prints a non-zero UID, and running the image without `SECRET_KEY` exits immediately with an explanatory error.

## Kubernetes / Helm (Task 4)

`helm/vulntracker/` deploys the API with:

- **Secrets from a secrets manager:** an `ExternalSecret` (External Secrets Operator) pulls the signing key from AWS Secrets Manager / Vault / GCP Secret Manager and it is mounted as a read-only **file** (`SECRET_KEY_FILE`), not an environment variable. No secret value is in the chart.
- **Restricted ingress:** a `NetworkPolicy` allows traffic only from the ingress controller namespace on port 8000, and egress only to DNS (plus the notify service if enabled). The Service is `ClusterIP`; the optional Ingress requires TLS.
- **Limits and security contexts:** CPU/memory/ephemeral-storage requests and limits; non-root UID 10001, read-only root filesystem, all capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp, no service-account token mounted.

```bash
helm lint helm/vulntracker
helm template vt helm/vulntracker                       # render and inspect
helm install vt helm/vulntracker -n vulntracker --create-namespace \
  --set image.repository=<registry>/vulntracker-api --set image.tag=<tag> \
  --set shareBaseUrl=https://vulntracker.example.com
```

Prerequisites: External Secrets Operator with a `ClusterSecretStore` named `vulntracker-secret-store` (configurable in `values.yaml`) that can read `vulntracker/prod/jwt-signing-key`. The replica count stays at 1 because SQLite is a single-writer database (see `docs/remediation-plan.md`).

## Security scanning in CI

`.github/workflows/ci.yml` runs SAST (Bandit), SCA (pip-audit, npm audit), container scan (Trivy, after building the image and smoke-testing it) and IaC scan (Checkov on the Helm chart and Dockerfile) on every push. Reports in `reports/` are the raw tool output; `reports/post-remediation/` is the SAST/SCA output after the Task 3 fixes. See `docs/findings.md`.
