# syntax=docker/dockerfile:1

# ---- build stage: resolve and install dependencies into a venv -------------
# Pinned to an exact Python patch release on Debian slim. For fully
# reproducible builds, also pin the digest (python:<tag>@sha256:...);
# Dependabot (see .github/dependabot.yml) proposes tag/digest bumps.
FROM python:3.11.18-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY requirements.txt .
# Install the app's dependencies, then remove the packaging tools: nothing in
# the running container installs packages, and pip/setuptools/wheel (and the
# libraries vendored inside them) are attack surface with known CVEs.
RUN pip install -r requirements.txt \
 && pip uninstall -y pip setuptools wheel

# ---- runtime stage: only the venv and the app, no build tooling ------------
FROM python:3.11.18-slim-bookworm AS runtime

# Links the published image to this repository on GitHub.
LABEL org.opencontainers.image.source="https://github.com/venkateswarludevineni273/security-automation-assignment_venkateswarlu"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    DATABASE_URL="sqlite:////data/vulntracker.db"

# Pull in Debian security patches released since the base image was built
# (e.g. openssl, gnutls, perl-base). The apt cache is removed in the same layer
# so it does not bloat the image.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# Same reasoning for the base image's own copies of the packaging tools.
RUN /usr/local/bin/python -m pip uninstall -y pip setuptools wheel

# Unprivileged user with a fixed numeric UID/GID (Kubernetes runAsNonRoot can
# verify a numeric ID, not a name). /data is the only writable path.
RUN groupadd --system --gid 10001 app \
 && useradd  --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data && chown app:app /data

COPY --from=builder /opt/venv /opt/venv

# The modules use bare imports, so the app runs from inside this directory.
# Code is root-owned and read-only to the app user.
WORKDIR /srv/app
COPY app/ ./

USER 10001:10001
EXPOSE 8000

# No curl in the slim image; use the Python standard library instead.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

# No secrets are baked in. SECRET_KEY (or SECRET_KEY_FILE) must be supplied at
# run time; the app refuses to start without it.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
