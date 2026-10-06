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
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const check = crypto.scryptSync(String(password), salt, 64).toString('hex');
  const a = Buffer.from(check, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function signToken(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret).update(body).digest();
  return body + '.' + b64url(sig);
}
async function getSecret() {
  let secret = await redis('GET', 'meta:app-secret');
  if (!secret) {
    secret = crypto.randomBytes(32).toString('hex');
    await redis('SET', 'meta:app-secret', secret);
  }
  return secret;
}

const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 jours

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
}

module.exports = async function (req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(200).json({}); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Méthode non autorisée' }); return; }

  const body = req.body || {};
  const nom = String(body.nom || '').trim();
  const password = String(body.password || '');
  if (!nom || !password) { res.status(400).json({ error: 'Nom et mot de passe requis' }); return; }
  if (password.length < 4) { res.status(400).json({ error: 'Le mot de passe doit faire au moins 4 caractères' }); return; }

  const key = 'account:' + nom.toLowerCase();
  const existing = await kvGetJSON(key);

  let account;
  if (!existing) {
    const allKeys = await kvKeys('account:*');
    const isFirstEver = !allKeys || allKeys.length === 0;
    if (!isFirstEver) { res.status(401).json({ error: 'Nom ou mot de passe incorrect' }); return; }
    const { salt, hash } = hashPassword(password);
    account = { nom, niveau: '', certif: '', contact: '', salt, hash, isAdmin: true, createdAtMs: Date.now() };
    await kvSetJSON(key, account);
  } else {
    if (!verifyPassword(password, existing.salt, existing.hash)) { res.status(401).json({ error: 'Nom ou mot de passe incorrect' }); return; }
    account = existing;
  }

  const secret = await getSecret();
  const token = signToken({ nom: account.nom, isAdmin: !!account.isAdmin, exp: Date.now() + TOKEN_TTL_MS }, secret);
  res.status(200).json({
    token,
    nom: account.nom,
    isAdmin: !!account.isAdmin,
    niveau: account.niveau || '',
    certif: account.certif || ''
  });
};
