const crypto = require('node:crypto');
const express = require('express');
const { dispatch } = require('./dispatcher');
const config = require('./config');
const { validateWebhookUrl } = require('./ssrf');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

// Compare tokens in constant time (hash first so lengths match).
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Every route except /health requires the shared bearer token.
function requireAuth(req, res, next) {
  if (!config.API_TOKEN) {
    return res.status(503).json({ error: 'service is not configured' });
  }
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
  if (!m || !safeEqual(m[1], config.API_TOKEN)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// In-memory webhook registry
const webhooks = new Map();


// Register a webhook endpoint to receive VulnTracker events
app.post('/webhooks', requireAuth, (req, res) => {
  const { url, events, metadata } = req.body || {};

  if (!url) return res.status(400).json({ error: 'url is required' });
  if (!Array.isArray(events) || events.length === 0) {
    return res.status(400).json({ error: 'events must be a non-empty array' });
  }
  if (events.length > 20 || events.some((e) => typeof e !== 'string' || e.length === 0 || e.length > 64)) {
    return res.status(400).json({ error: 'events must be at most 20 short strings' });
  }
  if (metadata !== undefined && (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata))) {
    return res.status(400).json({ error: 'metadata must be an object' });
  }
  const check = validateWebhookUrl(url, config.ALLOWED_HOSTS);
  if (!check.ok) return res.status(400).json({ error: check.reason });
  if (webhooks.size >= config.MAX_WEBHOOKS) {
    return res.status(429).json({ error: 'too many webhooks registered' });
  }

  const webhook = {
    id: crypto.randomUUID(),
    url,
    events,
    metadata: Object.assign({}, metadata),
    createdAt: new Date().toISOString(),
  };

  webhooks.set(webhook.id, webhook);
  res.status(201).json(webhook);
});


// List all registered webhooks
app.get('/webhooks', requireAuth, (req, res) => {
  res.json({ webhooks: Array.from(webhooks.values()), count: webhooks.size });
});


// Delete a webhook registration
app.delete('/webhooks/:id', requireAuth, (req, res) => {
  if (!webhooks.has(req.params.id)) {
    return res.status(404).json({ error: 'Webhook not found' });
  }
  webhooks.delete(req.params.id);
  res.status(204).send();
});


// Trigger event notifications — called by the Python API on scan create/update
// Requires the shared bearer token; network position alone is not trusted.
app.post('/notify', requireAuth, async (req, res) => {
  const { event, payload } = req.body || {};

  if (!event || !payload) {
    return res.status(400).json({ error: 'event and payload are required' });
  }

  const matching = Array.from(webhooks.values()).filter(w => w.events.includes(event));

  const results = await Promise.all(
    matching.map(w => dispatch(w, { event, payload, timestamp: new Date().toISOString() }))
  );

  res.json({ event, dispatched: matching.length, results });
});


// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vulntracker-notify' });
});


// Global error handler
// Detail goes to the server log only; clients get nothing useful to an attacker.
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'invalid JSON' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'request body too large' });
  }
  console.error(err);
  res.status(500).json({ error: 'internal server error' });
});


if (require.main === module) {
  if (!config.API_TOKEN || config.API_TOKEN.length < 16) {
    console.error('NOTIFY_API_TOKEN must be set to a random value of at least 16 characters');
    process.exit(1);
  }
  app.listen(config.PORT, () => {
    console.log(`Notification service running on http://localhost:${config.PORT}`);
  });
}

module.exports = app;
