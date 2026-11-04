// Server-side request forgery protection for webhook destinations.
//
// A webhook URL is attacker-influenced input that the server will call from
// inside the network. Two layers stop it reaching internal systems:
//   1. validateWebhookUrl(): rejects non-https, credentials, localhost-style
//      names and literal private IPs when the webhook is registered.
//   2. safeLookup(): a DNS lookup used for the actual connection that refuses
//      private/loopback/link-local addresses. Checking at connect time (not
//      just at registration) also defeats DNS tricks such as rebinding.
const dns = require('node:dns');
const net = require('node:net');

function isBlockedIp(ip) {
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
    if (mapped) return isBlockedIp(mapped[1]);
    if (v.startsWith('::ffff:')) return true; // IPv4-mapped in hex form
    if (v === '::' || v === '::1') return true;
    if (/^f[cd]/.test(v)) return true; // unique local fc00::/7
    if (/^fe[89ab]/.test(v)) return true; // link-local fe80::/10
    if (/^ff/.test(v)) return true; // multicast
    return false;
  }
  if (!net.isIPv4(ip)) return true; // unknown format: fail closed
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127) return true; // this-host, private, loopback
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  if (a === 192 && b === 0 && c === 0) return true; // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast and reserved
  return false;
}

function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    if (addresses.some((a) => isBlockedIp(a.address))) {
      const e = new Error('destination address is not allowed');
      e.code = 'EBLOCKED';
      return callback(e);
    }
    if (options.all) return callback(null, addresses);
    return callback(null, addresses[0].address, addresses[0].family);
  });
}

function validateWebhookUrl(raw, allowedHosts = []) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) {
    return { ok: false, reason: 'url must be a string of at most 2048 characters' };
  }
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, reason: 'url is not valid' };
  }
  if (u.protocol !== 'https:') return { ok: false, reason: 'url must use https' };
  if (u.username || u.password) return { ok: false, reason: 'url must not contain credentials' };

  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (net.isIP(host) && isBlockedIp(host)) {
    return { ok: false, reason: 'destination address is not allowed' };
  }
  if (host === 'localhost' || /\.(localhost|local|internal|lan|home)$/.test(host)) {
    return { ok: false, reason: 'destination host is not allowed' };
  }
  if (allowedHosts.length > 0 && !allowedHosts.includes(host)) {
    return { ok: false, reason: 'destination host is not on the allowlist' };
  }
  return { ok: true, url: u };
}

module.exports = { isBlockedIp, safeLookup, validateWebhookUrl };
