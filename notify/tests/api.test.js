// The service refuses to run without a token, so set one before loading it.
const TOKEN = 'test-token-0123456789abcdef';
process.env.NOTIFY_API_TOKEN = TOKEN;
process.env.NOTIFY_SIGNING_SECRET = 'test-signing-secret';

const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../src/index');
const config = require('../src/config');
const { isBlockedIp, safeLookup, validateWebhookUrl } = require('../src/ssrf');
const { dispatch, sign } = require('../src/dispatcher');

const BASE_URL = `http://localhost:${config.PORT}`;
let server;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(config.PORT, resolve);
  });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

const authHeader = { Authorization: `Bearer ${TOKEN}` };

async function call(method, path, { body, headers = authHeader, raw } = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
  return { status: res.status, body: json, text };
}

const post = (path, body, opts) => call('POST', path, { body, ...opts });
const get = (path, opts) => call('GET', path, opts);
const del = (path, opts) => call('DELETE', path, opts);

// --- Original behaviour (now with authentication) -------------------------

test('GET /health returns ok without authentication', async () => {
  const { status, body } = await get('/health', { headers: {} });
  assert.equal(status, 200);
  assert.equal(body.status, 'ok');
});

test('POST /webhooks registers a webhook', async () => {
  const { status, body } = await post('/webhooks', {
    url: 'https://example.com/hook',
    events: ['scan.created'],
  });
  assert.equal(status, 201);
  assert.ok(body.id);
  assert.equal(body.url, 'https://example.com/hook');
});

test('POST /webhooks rejects missing url', async () => {
  const { status } = await post('/webhooks', { events: ['scan.created'] });
  assert.equal(status, 400);
});

test('POST /webhooks rejects empty events array', async () => {
  const { status } = await post('/webhooks', { url: 'https://example.com', events: [] });
  assert.equal(status, 400);
});

test('GET /webhooks lists registered webhooks', async () => {
  const { status, body } = await get('/webhooks');
  assert.equal(status, 200);
  assert.ok(Array.isArray(body.webhooks));
});

test('DELETE /webhooks/:id removes a webhook', async () => {
  const { body } = await post('/webhooks', {
    url: 'https://example.com/deleteme',
    events: ['scan.updated'],
  });
  const { status } = await del(`/webhooks/${body.id}`);
  assert.equal(status, 204);
});

test('DELETE /webhooks/:id returns 404 for unknown id', async () => {
  const { status } = await del('/webhooks/non-existent-id');
  assert.equal(status, 404);
});

test('POST /notify requires event and payload', async () => {
  const { status } = await post('/notify', { event: 'scan.created' });
  assert.equal(status, 400);
});

// --- Authentication (N1) ----------------------------------------------------

test('every route except /health rejects requests without a token', async () => {
  for (const [method, path, body] of [
    ['POST', '/webhooks', { url: 'https://example.com', events: ['x'] }],
    ['GET', '/webhooks'],
    ['DELETE', '/webhooks/abc'],
    ['POST', '/notify', { event: 'x', payload: {} }],
  ]) {
    const { status } = await call(method, path, { body, headers: {} });
    assert.equal(status, 401, `${method} ${path}`);
  }
});

test('a wrong token is rejected', async () => {
  const { status } = await get('/webhooks', { headers: { Authorization: 'Bearer wrong-token-value-123' } });
  assert.equal(status, 401);
});

test('a non-bearer scheme is rejected', async () => {
  const { status } = await get('/webhooks', { headers: { Authorization: `Basic ${TOKEN}` } });
  assert.equal(status, 401);
});

// --- SSRF protection (N1) ---------------------------------------------------

test('webhook registration rejects non-https and dangerous destinations', async () => {
  const bad = [
    'http://example.com/hook', // not https
    'https://169.254.169.254/latest/meta-data/', // cloud metadata
    'https://127.0.0.1/', 'https://10.0.0.5/', 'https://192.168.1.10/', 'https://172.16.0.1/',
    'https://[::1]/', 'https://localhost/', 'https://service.internal/',
    'https://user:pass@example.com/', // credentials in URL
    'https://2130706433/', // decimal form of 127.0.0.1
    'ftp://example.com/', 'not a url',
  ];
  for (const url of bad) {
    const { status } = await post('/webhooks', { url, events: ['scan.created'] });
    assert.equal(status, 400, url);
  }
});

test('isBlockedIp blocks private, loopback, link-local and mapped addresses', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.5.5', '172.31.255.255', '192.168.0.1',
    '169.254.169.254', '0.0.0.0', '100.64.0.1', '224.0.0.1', '::1', '::', 'fd00::1', 'fe80::1',
    '::ffff:127.0.0.1', '::ffff:7f00:1']) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
  for (const ip of ['93.184.216.34', '8.8.8.8', '172.32.0.1', '2606:2800:220:1:248:1893:25c8:1946']) {
    assert.equal(isBlockedIp(ip), false, ip);
  }
});

test('safeLookup refuses a hostname that resolves to a loopback address', async () => {
  const err = await new Promise((resolve) => safeLookup('localhost', {}, (e) => resolve(e)));
  assert.ok(err, 'expected an error');
  assert.equal(err.code, 'EBLOCKED');
});

test('validateWebhookUrl honours the host allowlist', () => {
  assert.equal(validateWebhookUrl('https://hooks.example.com/x', ['hooks.example.com']).ok, true);
  assert.equal(validateWebhookUrl('https://evil.example.org/x', ['hooks.example.com']).ok, false);
});

test('dispatch refuses a dangerous destination without making a request', async () => {
  const r = await dispatch({ id: '1', url: 'https://localhost:9/' }, { event: 'x' });
  assert.equal(r.success, false);
  assert.equal(r.error, 'delivery blocked');
});

test('dispatch failures return a generic error, not internal network detail', async () => {
  // example.invalid never resolves; the raw error would name the host/port.
  const r = await dispatch({ id: '2', url: 'https://nonexistent.invalid/' }, { event: 'x' });
  assert.equal(r.success, false);
  assert.equal(r.error, 'delivery failed');
});

// --- No shared secret sent to receivers; payloads are signed (N1) ---------

test('payload signature is a valid HMAC and the service key is not sent', () => {
  const crypto = require('node:crypto');
  const sig = sign('{"a":1}');
  const expected = 'sha256=' + crypto.createHmac('sha256', 'test-signing-secret').update('{"a":1}').digest('hex');
  assert.equal(sig, expected);
  assert.ok(!require('node:fs').readFileSync(require.resolve('../src/dispatcher'), 'utf8').includes('X-Service-Key'));
});

// --- Error handling (N3) ----------------------------------------------------

test('malformed JSON returns a generic 400 with no stack trace', async () => {
  const r = await call('POST', '/webhooks', { raw: '{not json' });
  assert.equal(r.status, 400);
  assert.deepEqual(r.body, { error: 'invalid JSON' });
  assert.ok(!r.text.includes('stack') && !r.text.includes('node_modules'));
});

test('oversized bodies are rejected', async () => {
  const r = await call('POST', '/notify', { raw: JSON.stringify({ event: 'x', payload: 'a'.repeat(200 * 1024) }) });
  assert.equal(r.status, 413);
});

// --- Secrets (F2-notify) ----------------------------------------------------

test('no secret is hardcoded in the service source', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  for (const f of ['config.js', 'dispatcher.js', 'index.js', 'ssrf.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', f), 'utf8');
    assert.ok(!/k3y|d3adb33f|pr0d/.test(src), `${f} contains a hardcoded key`);
  }
});
