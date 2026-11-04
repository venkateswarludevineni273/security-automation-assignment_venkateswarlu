const crypto = require('node:crypto');
const https = require('node:https');
const axios = require('axios');
const config = require('./config');
const { safeLookup, validateWebhookUrl } = require('./ssrf');

// Connections go through safeLookup so private/loopback/link-local addresses
// are refused even if a hostname resolves to one.
const agent = new https.Agent({ lookup: safeLookup });

function sign(body) {
  if (!config.SIGNING_SECRET) return null;
  return 'sha256=' + crypto.createHmac('sha256', config.SIGNING_SECRET).update(body).digest('hex');
}

async function dispatch(webhook, payload) {
  // Defence in depth: re-validate even though registration already did.
  if (!validateWebhookUrl(webhook.url, config.ALLOWED_HOSTS).ok) {
    return { webhookId: webhook.id, success: false, error: 'delivery blocked', attempt: 0 };
  }

  const body = JSON.stringify(payload);
  const headers = { 'Content-Type': 'application/json' };
  const signature = sign(body);
  if (signature) headers['X-VulnTracker-Signature'] = signature;

  for (let attempt = 1; attempt <= config.RETRY_ATTEMPTS; attempt++) {
    try {
      await axios.post(webhook.url, body, {
        timeout: config.TIMEOUT_MS,
        headers,
        httpsAgent: agent,
        maxRedirects: 0, // a redirect could point at an internal address
        proxy: false,
        maxContentLength: 1024 * 1024,
      });
      return { webhookId: webhook.id, success: true, attempt };
    } catch (err) {
      // Never retry a blocked destination.
      if (err.code === 'EBLOCKED') {
        return { webhookId: webhook.id, success: false, error: 'delivery blocked', attempt };
      }
      if (attempt === config.RETRY_ATTEMPTS) {
        // Generic message: raw errors (e.g. "connect ECONNREFUSED 10.0.0.5:80")
        // would let a caller map the internal network.
        return { webhookId: webhook.id, success: false, error: 'delivery failed', attempt };
      }
    }
  }
}

module.exports = { dispatch, sign };
