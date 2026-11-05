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

/* ===== Helpers (auth) — identiques à reports.js / personnel.js ===== */
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
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
}

/* En-tête affiché en haut de chaque PV (société, adresse, logo).
   Modifiable depuis l'appli (écran Paramètres, réservé à l'administrateur) :
   utile si cette application est redéployée pour une autre société. */
const DEFAULT_SETTINGS = {
  orgName: 'Alstom Crespin S.A.S',
  orgAddress1: '1 Place des Ateliers',
  orgAddress2: '59154 CRESPIN, France',
  logoDataUrl: ''
};

module.exports = async function (req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(200).json({}); return; }

  const token = getBearerToken(req);
  const secret = await getSecret();
  const user = token ? verifyToken(token, secret) : null;
  if (!user) { res.status(401).json({ error: 'Session expirée, reconnectez-vous.' }); return; }

  if (req.method === 'GET') {
    const s = await kvGetJSON('meta:org-settings');
    res.status(200).json(Object.assign({}, DEFAULT_SETTINGS, s || {}));
    return;
  }

  if (req.method === 'POST') {
    if (!user.isAdmin) { res.status(403).json({ error: 'Réservé à l’administrateur.' }); return; }
    const body = req.body || {};
    const next = {
      orgName: String(body.orgName || '').trim(),
      orgAddress1: String(body.orgAddress1 || '').trim(),
      orgAddress2: String(body.orgAddress2 || '').trim(),
      logoDataUrl: typeof body.logoDataUrl === 'string' ? body.logoDataUrl : ''
    };
    await kvSetJSON('meta:org-settings', next);
    res.status(200).json(Object.assign({}, DEFAULT_SETTINGS, next));
    return;
  }

  res.status(405).json({ error: 'Méthode non autorisée' });
};
