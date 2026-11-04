// All secrets come from the environment (or a secrets manager that injects it).
// Nothing secret lives in source control.
const list = (v) => (v || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

module.exports = {
  PORT: process.env.PORT || 3001,
  PYTHON_API_URL: process.env.PYTHON_API_URL || 'http://localhost:8000',

  // Bearer token every caller must present (the Python API sends it).
  // No default: without it the service refuses to start and rejects all calls.
  API_TOKEN: process.env.NOTIFY_API_TOKEN || '',

  // Secret used to sign outgoing webhook bodies (HMAC-SHA256). It is never
  // sent to receivers, so a hostile destination cannot harvest it.
  SIGNING_SECRET: process.env.NOTIFY_SIGNING_SECRET || '',

  // Optional comma-separated allowlist of destination hostnames. When set,
  // webhooks may only point at these hosts.
  ALLOWED_HOSTS: list(process.env.NOTIFY_ALLOWED_HOSTS),

  MAX_WEBHOOKS: 100,
  RETRY_ATTEMPTS: 3,
  TIMEOUT_MS: 5000,
};
