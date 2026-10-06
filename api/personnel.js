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
async function kvDel(key) {
  await redis('DEL', key);
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
async function requireAuth(req) {
  const token = getBearerToken(req);
  if (!token) return null;
  const secret = await getSecret();
  return verifyToken(token, secret);
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
}

module.exports = async function (req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(200).json({}); return; }

  const user = await requireAuth(req);
  if (!user) { res.status(401).json({ error: 'Session expirée, reconnectez-vous.' }); return; }

  if (req.method === 'GET') {
    const keys = await kvKeys('account:*');
    const list = [];
    for (const k of keys) {
      const acc = await kvGetJSON(k);
      if (acc) list.push({ nom: acc.nom, niveau: acc.niveau || '', certif: acc.certif || '', contact: acc.contact || '', isAdmin: !!acc.isAdmin });
    }
    list.sort(function (a, b) { return a.nom.localeCompare(b.nom); });
    res.status(200).json(list);
    return;
  }

  // Au-delà de la lecture, seul l'administrateur peut gérer les comptes.
  if (!user.isAdmin) { res.status(403).json({ error: 'Réservé à l’administrateur.' }); return; }

  if (req.method === 'POST') {
    const body = req.body || {};
    const nom = String(body.nom || '').trim();
    if (!nom) { res.status(400).json({ error: 'Nom requis' }); return; }
    const key = 'account:' + nom.toLowerCase();
    const existing = await kvGetJSON(key);

    let salt, hash;
    if (body.password) {
      if (String(body.password).length < 4) { res.status(400).json({ error: 'Le mot de passe doit faire au moins 4 caractères' }); return; }
      const h = hashPassword(body.password);
      salt = h.salt; hash = h.hash;
    } else if (existing) {
      salt = existing.salt; hash = existing.hash;
    } else {
      res.status(400).json({ error: 'Un mot de passe est requis pour créer ce compte' });
      return;
    }

    const account = {
      nom,
      niveau: String(body.niveau || ''),
      certif: String(body.certif || ''),
      contact: String(body.contact || ''),
      salt, hash,
      isAdmin: !!body.isAdmin,
      createdAtMs: (existing && existing.createdAtMs) || Date.now()
    };
    await kvSetJSON(key, account);
    res.status(200).json({ ok: true });
    return;
  }

  if (req.method === 'DELETE') {
    const nom = String((req.query && req.query.nom) || '').trim();
    if (!nom) { res.status(400).json({ error: 'Nom requis' }); return; }
    if (nom.toLowerCase() === user.nom.toLowerCase()) { res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte.' }); return; }
    await kvDel('account:' + nom.toLowerCase());
    res.status(200).json({ ok: true });
    return;
  }

  res.status(405).json({ error: 'Méthode non autorisée' });
};
