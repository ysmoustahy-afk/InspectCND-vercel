'use strict';
const crypto = require('crypto');

/* ===== Upstash Redis (REST, zero dependency) ===== */
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(...command) {
  const r = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + UPSTASH_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(command)
  });
  const data = await r.json();
  if (data.error) throw new Error(data.error);
  return data.result;
}
async function kvGetJSON(key) {
  const v = await redis('GET', key);
  return v ? JSON.parse(v) : null;
}
async function kvSetJSON(key, value) {
  await redis('SET', key, JSON.stringify(value));
}
async function kvKeys(pattern) {
  return (await redis('KEYS', pattern)) || [];
}

/* ===== Helpers (auth) ===== */
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || token.indexOf('.') === -1) return null;
  const idx = token.lastIndexOf('.');
  const body = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expectedSig = b64url(crypto.createHmac('sha256', secret).update(body).digest());
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(body).toString('utf8')); } catch (e) { return null; }
  if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
  return payload;
}
async function getSecret() {
  let secret = await redis('GET', 'meta:app-secret');
  if (!secret) {
    secret = crypto.randomBytes(32).toString('hex');
    await redis('SET', 'meta:app-secret', secret);
  }
  return secret;
}
function getBearerToken(req) {
  const h = req.headers && (req.headers.authorization || req.headers.Authorization);
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(String(h).trim());
  return m ? m[1] : null;
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
}

module.exports = async function (req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(200).json({}); return; }

  const token = getBearerToken(req);
  const secret = await getSecret();
  const user = token ? verifyToken(token, secret) : null;
  if (!user) { res.status(401).json({ error: 'Session expirée, reconnectez-vous.' }); return; }

  if (req.method === 'GET') {
    const id = req.query && req.query.id;
    if (id) {
      const r = await kvGetJSON('report:' + id);
      if (!r) { res.status(404).json({ error: 'PV introuvable' }); return; }
      res.status(200).json(r);
      return;
    }
    const keys = await kvKeys('report:*');
    const list = [];
    for (const k of keys) {
      const r = await kvGetJSON(k);
      if (r) list.push(r);
    }
    res.status(200).json(list);
    return;
  }

  if (req.method === 'POST') {
    const body = req.body || {};
    if (!body.id) { res.status(400).json({ error: 'id manquant' }); return; }
    body.updatedAtMs = Date.now();
    body.updatedBy = user.nom;
    if (!body.createdAtMs) body.createdAtMs = Date.now();
    if (!body.createdBy) body.createdBy = user.nom;
    await kvSetJSON('report:' + body.id, body);
    res.status(200).json({ ok: true, id: body.id });
    return;
  }

  res.status(405).json({ error: 'Méthode non autorisée' });
};
