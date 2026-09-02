/*
 * ShowUpp — backend server
 * -------------------------------------------------------------
 * One file, on purpose: easy to read, easy to deploy.
 *
 * What it does:
 *   - Accounts (sign up / log in) with securely hashed passwords
 *   - Auth tokens (JWT) so a logged-in user stays logged in
 *   - Rounds (groups) + membership
 *   - Real-time group messaging over WebSockets
 *   - Stores everything in a SQLite file (showupp.db)
 *
 * For a first launch with friends this is plenty. When you grow,
 * the same shape moves to Postgres + a bigger host with small changes.
 *
 * NOTE ON PHONE VERIFICATION:
 *   Real SMS codes cost money and need a service (e.g. Twilio).
 *   To keep testing free, this uses email + password instead.
 *   Swapping in real SMS later is a contained change.
 */

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// --- Config ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@showupp.app';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme123';
const ADMIN_NAME = process.env.ADMIN_NAME || 'ShowUpp Admin';

// --- Database setup (Neon Postgres) ---
// All data lives in Neon, separate from the app host, so it survives restarts/deploys.
const db = require('./db-pg');

// All schema creation and migrations run inside init(), called before the server listens.
async function initDb() {
await db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    email      TEXT UNIQUE NOT NULL,
    pass_hash  TEXT NOT NULL,
    name       TEXT NOT NULL,
    city       TEXT,
    origin     TEXT,
    interests  TEXT,
    created_at BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS rounds (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    emoji      TEXT,
    category   TEXT,
    blurb      TEXT,
    host_id    TEXT NOT NULL,
    created_at BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS memberships (
    round_id  TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    joined_at BIGINT NOT NULL,
    PRIMARY KEY (round_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id        TEXT PRIMARY KEY,
    round_id  TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    body      TEXT NOT NULL,
    created_at BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS friendships (
    user_id    TEXT NOT NULL,
    friend_id  TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, friend_id)
  );

  CREATE TABLE IF NOT EXISTS gallery_reactions (
    owner_id   TEXT NOT NULL,
    pic_index  INTEGER NOT NULL,
    reactor_id TEXT NOT NULL,
    reaction   TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (owner_id, pic_index, reactor_id)
  );

  CREATE TABLE IF NOT EXISTS birthday_notifs (
    user_id   TEXT NOT NULL,
    friend_id TEXT NOT NULL,
    year      INTEGER NOT NULL,
    PRIMARY KEY (user_id, friend_id, year)
  );

  CREATE TABLE IF NOT EXISTS friend_requests (
    from_id    TEXT NOT NULL,
    to_id      TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (from_id, to_id)
  );

  CREATE TABLE IF NOT EXISTS blocks (
    user_id    TEXT NOT NULL,
    blocked_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, blocked_id)
  );

  CREATE TABLE IF NOT EXISTS reports (
    id          TEXT PRIMARY KEY,
    reporter_id TEXT NOT NULL,
    reported_id TEXT,
    context     TEXT,
    reason      TEXT,
    created_at  BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT PRIMARY KEY,
    is_group   INTEGER DEFAULT 0,
    title      TEXT,
    created_by TEXT,
    created_at BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conversation_members (
    conv_id   TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    last_read BIGINT DEFAULT 0,
    PRIMARY KEY (conv_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS dm_messages (
    id         TEXT PRIMARY KEY,
    conv_id    TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    body       TEXT NOT NULL,
    kind       TEXT DEFAULT 'text',
    media_url  TEXT,
    created_at BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    type       TEXT,
    title      TEXT,
    body       TEXT,
    link       TEXT,
    read       INTEGER DEFAULT 0,
    created_at BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS reset_tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    used       INTEGER DEFAULT 0,
    created_at BIGINT NOT NULL
  );
`);

// --- Safe migrations: Postgres supports ADD COLUMN IF NOT EXISTS, so these are idempotent ---
await db.exec(`
  ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS lang TEXT DEFAULT 'en';
  ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin INTEGER DEFAULT 0;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended INTEGER DEFAULT 0;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS premium INTEGER DEFAULT 0;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS is_private INTEGER DEFAULT 0;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS lat REAL;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS lng REAL;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS relationship TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS incognito INTEGER DEFAULT 0;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS read_receipts INTEGER DEFAULT 1;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS gallery TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS dob TEXT;

  ALTER TABLE conversations ADD COLUMN IF NOT EXISTS avatar TEXT;
  ALTER TABLE conversations ADD COLUMN IF NOT EXISTS description TEXT;

  ALTER TABLE users ADD COLUMN IF NOT EXISTS gender TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS show_age INTEGER DEFAULT 0;

  ALTER TABLE messages ADD COLUMN IF NOT EXISTS reactions TEXT;
  ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to TEXT;
  ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_preview TEXT;
  ALTER TABLE messages ADD COLUMN IF NOT EXISTS kind TEXT DEFAULT 'text';
  ALTER TABLE messages ADD COLUMN IF NOT EXISTS media_url TEXT;
  ALTER TABLE messages ADD COLUMN IF NOT EXISTS ephemeral INTEGER DEFAULT 0;
  ALTER TABLE messages ADD COLUMN IF NOT EXISTS seen_by TEXT;
  ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted INTEGER DEFAULT 0;
  ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited INTEGER DEFAULT 0;

  ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS reactions TEXT;
  ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS reply_to TEXT;
  ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS reply_preview TEXT;
  ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS deleted INTEGER DEFAULT 0;
  ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS edited INTEGER DEFAULT 0;

  ALTER TABLE memberships ADD COLUMN IF NOT EXISTS last_read BIGINT DEFAULT 0;

  ALTER TABLE rounds ADD COLUMN IF NOT EXISTS lat REAL;
  ALTER TABLE rounds ADD COLUMN IF NOT EXISTS lng REAL;
  ALTER TABLE rounds ADD COLUMN IF NOT EXISTS place TEXT;
  ALTER TABLE rounds ADD COLUMN IF NOT EXISTS photo TEXT;
  ALTER TABLE rounds ADD COLUMN IF NOT EXISTS link TEXT;
  ALTER TABLE rounds ADD COLUMN IF NOT EXISTS event_at BIGINT;

  ALTER TABLE memberships ADD COLUMN IF NOT EXISTS rsvp TEXT;

  CREATE TABLE IF NOT EXISTS round_reactions (
    round_id TEXT NOT NULL, user_id TEXT NOT NULL, type TEXT NOT NULL,
    created_at BIGINT, PRIMARY KEY (round_id, user_id, type)
  );
  CREATE TABLE IF NOT EXISTS saved_rounds (
    round_id TEXT NOT NULL, user_id TEXT NOT NULL, created_at BIGINT,
    PRIMARY KEY (round_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS moments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    text TEXT,
    photo TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
  );
  ALTER TABLE moments ADD COLUMN IF NOT EXISTS media TEXT;

  CREATE TABLE IF NOT EXISTS categories (
    name TEXT PRIMARY KEY, emoji TEXT, created_by TEXT, approved INTEGER DEFAULT 0, created_at BIGINT
  );
  CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    source      TEXT DEFAULT 'community',
    source_id   TEXT,
    title       TEXT NOT NULL,
    description TEXT,
    category    TEXT,
    emoji       TEXT,
    photo       TEXT,
    link        TEXT,
    place       TEXT,
    lat         REAL,
    lng         REAL,
    starts_at   BIGINT,
    ends_at     BIGINT,
    posted_by   TEXT,
    approved    INTEGER DEFAULT 1,
    created_at  BIGINT NOT NULL
  );
  -- Manager-configured accounts for paid/partner event providers (e.g. Ticketmaster).
  -- Credentials are entered in the Manager panel instead of env vars, so an owner can
  -- add/remove providers without a server redeploy.
  CREATE TABLE IF NOT EXISTS event_sources (
    id          TEXT PRIMARY KEY,
    provider    TEXT NOT NULL,
    label       TEXT,
    api_key     TEXT,
    enabled     INTEGER DEFAULT 1,
    created_by  TEXT,
    created_at  BIGINT NOT NULL
  );
`);

  // Seed the admin/owner account
  {
    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').get(ADMIN_EMAIL.toLowerCase());
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    if (existing) {
      await db.prepare('UPDATE users SET pass_hash = ?, is_admin = 1 WHERE id = ?').run(hash, existing.id);
    } else {
      await db.prepare(`INSERT INTO users (id,email,pass_hash,name,username,city,origin,interests,created_at,is_admin)
                  VALUES (?,?,?,?,?,?,?,?,?,1)`).run(
        crypto.randomUUID(), ADMIN_EMAIL.toLowerCase(), hash, ADMIN_NAME, 'admin',
        '', '', JSON.stringify([]), Date.now());
      console.log('Seeded admin account:', ADMIN_EMAIL);
    }
  }

  // Seed a few starter Rounds so the app isn't empty on first run
  {
    const row = await db.prepare('SELECT COUNT(*) AS c FROM rounds').get();
    const count = row ? Number(row.c) : 0;
    if (count === 0) {
      const systemHost = 'system';
      const seed = [
        ['Sunday Sancocho & Domino Nights', '🍳', 'Food', 'Cook, play dominoes, swap stories. Newcomers welcome — just come hungry.'],
        ['Global Book Club', '📚', 'Book Club', 'One book a month, honest conversation, new friends.'],
        ['Weekend Wanderers', '✈️', 'Travel', 'Plan trips together and explore as a group.'],
        ['Newborns & Coffee', '👶', 'New Parents', 'New parents meeting up for walks and cafecito.'],
        ['Foreign Film Fridays', '🎬', 'Movies', 'Watch a film, then talk it over.'],
        ['Saturday Morning Fútbol', '⚽', 'Sports', 'Friendly pickup games every weekend.']
      ];
      const nowTs = Date.now();
      for (const [title, emoji, category, blurb] of seed) {
        await db.prepare('INSERT INTO rounds (id, title, emoji, category, blurb, host_id, created_at) VALUES (?,?,?,?,?,?,?)')
          .run(crypto.randomUUID(), title, emoji, category, blurb, systemHost, nowTs);
      }
      console.log('Seeded starter Rounds.');
    }
  }

  console.log('Database ready (Neon Postgres).');
} // end initDb

// --- Helpers ---
const id = () => crypto.randomUUID();
const now = () => Date.now();

function makeToken(user) {
  return jwt.sign({ uid: user.id, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
}

async function authFromToken(token) {
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return await db.prepare('SELECT id, email, name, username, avatar, city, origin, interests, is_admin, lang FROM users WHERE id = ?').get(payload.uid);
  } catch {
    return null;
  }
}

// Express middleware that requires a valid Bearer token
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const user = token ? await authFromToken(token) : null;
  if (!user) return res.status(401).json({ error: 'Please log in again.' });
  req.user = user;
  next();
}

function ageFromDob(dob) {
  if (!dob) return null;
  const d = new Date(dob);
  if (isNaN(d.getTime())) return null;
  const now = new Date();
  let age = now.getFullYear() - d.getFullYear();
  const m = now.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < d.getDate())) age--;
  return (age >= 0 && age < 130) ? age : null;
}
function publicUser(u) {
  const age = ageFromDob(u.dob);
  return {
    id: u.id,
    name: u.name,
    username: u.username || '',
    avatar: u.avatar || '',
    city: u.city,
    origin: u.origin,
    interests: u.interests ? JSON.parse(u.interests) : [],
    bio: u.bio || '',
    gallery: u.gallery ? JSON.parse(u.gallery) : [],
    premium: !!u.premium,
    isPrivate: !!u.is_private,
    relationship: u.relationship || '',
    gender: u.gender || '',
    showAge: !!u.show_age,
    // Age is only exposed publicly when the person chose to show it.
    age: u.show_age ? age : null,
    isAdmin: !!u.is_admin,
    lang: u.lang || 'en'
  };
}

// --- App ---
const app = express();
app.use(express.json({ limit: '16mb' }));
// Serve the front-end (index.html) from /public
app.use(express.static(path.join(__dirname, 'public')));

// Health check (useful for hosts)
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ---- Auth ----
// Quick check whether an email is already registered (used during signup)
app.post('/api/check-email', async (req, res) => {
  const { email } = req.body || {};
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  const existing = await db.prepare('SELECT id FROM users WHERE email = ?').get(String(email).toLowerCase());
  res.json({ available: !existing });
});

app.post('/api/signup', async (req, res) => {
  const { email, password, name, phone, city, origin, interests, lang, dob, gender } = req.body || {};
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }
  if (String(password).length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  // Age gate — ShowUpp is strictly 18+. Enforced on the server so it can't be bypassed.
  const birth = dob ? new Date(dob) : null;
  if (!birth || isNaN(birth.getTime())) {
    return res.status(400).json({ error: 'A valid date of birth is required.' });
  }
  const nowD = new Date();
  let age = nowD.getFullYear() - birth.getFullYear();
  const mm = nowD.getMonth() - birth.getMonth();
  if (mm < 0 || (mm === 0 && nowD.getDate() < birth.getDate())) age--;
  if (age < 18) {
    return res.status(403).json({ error: 'You must be 18 or older to use ShowUpp.' });
  }
  if (age > 120) {
    return res.status(400).json({ error: 'Please enter a valid date of birth.' });
  }
  const existing = await db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'That email is already registered. Try logging in.' });

  const user = {
    id: id(),
    email: email.toLowerCase(),
    pass_hash: bcrypt.hashSync(String(password), 10),
    name: String(name).trim(),
    phone: phone ? String(phone).replace(/[^0-9+ ]/g, '').trim().slice(0, 24) : '',
    city: city || '',
    origin: origin || '',
    interests: JSON.stringify(Array.isArray(interests) ? interests : []),
    lang: (lang && ['en', 'es'].includes(lang)) ? lang : 'en',
    dob: String(dob).slice(0, 10),
    gender: gender ? String(gender).slice(0, 40) : '',
    created_at: now()
  };
  await db.prepare(`INSERT INTO users (id,email,pass_hash,name,phone,city,origin,interests,lang,dob,gender,created_at)
              VALUES (@id,@email,@pass_hash,@name,@phone,@city,@origin,@interests,@lang,@dob,@gender,@created_at)`).run(user);

  res.json({ token: makeToken(user), user: { ...publicUser(user), email: user.email, phone: user.phone } });
});

app.post('/api/login', async (req, res) => {
  // Accept email, username, or phone in the "email" field (kept name for compatibility) or "identifier"
  const idRaw = (req.body && (req.body.identifier || req.body.email)) || '';
  const password = req.body && req.body.password;
  const identifier = String(idRaw).trim();
  if (!identifier || !password) return res.status(400).json({ error: 'Enter your email, username, or phone and password.' });
  const lower = identifier.toLowerCase();
  const digits = identifier.replace(/[^0-9+]/g, '');
  // Try email, then username, then phone
  let row = await db.prepare('SELECT * FROM users WHERE email = ?').get(lower);
  if (!row) row = await db.prepare('SELECT * FROM users WHERE username = ?').get(lower.replace(/^@/, ''));
  if (!row && digits.length >= 6) row = await db.prepare('SELECT * FROM users WHERE phone = ?').get(digits);
  if (!row || !bcrypt.compareSync(String(password), row.pass_hash)) {
    return res.status(401).json({ error: 'Wrong login or password.' });
  }
  if (row.suspended) {
    return res.status(403).json({ error: 'This account has been suspended. Contact support if you think this is a mistake.' });
  }
  res.json({ token: makeToken(row), user: { ...publicUser(row), email: row.email || '', phone: row.phone || '', incognito: !!row.incognito, readReceipts: row.read_receipts !== 0 } });
});

// Return the current user (used on app load to restore session)
app.get('/api/me', requireAuth, async (req, res) => {
  // Read the full, current record from the DB — the token snapshot can be stale
  // (e.g. relationship/bio set after login), which would blank fields on refresh.
  const full = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id) || req.user;
  res.json({ user: { ...publicUser(full), email: full.email || '', phone: full.phone || '', incognito: !!full.incognito, readReceipts: full.read_receipts !== 0,
    dob: full.dob || '', age: ageFromDob(full.dob), gender: full.gender || '', showAge: !!full.show_age } });
});

// Presence of my friends (respects their incognito setting)
app.get('/api/friends/presence', requireAuth, async (req, res) => {
  const friendIds = (await db.prepare('SELECT friend_id AS fid FROM friendships WHERE user_id = ?').all(req.user.id)).map(r => r.fid);
  const presence = {};
  for (const fid of friendIds) {
    const u = await db.prepare('SELECT incognito FROM users WHERE id = ?').get(fid);
    // If the friend is incognito, always report offline
    presence[fid] = (u && u.incognito) ? false : isUserOnline(fid);
  }
  res.json({ presence });
});

// Toggle my incognito (appear offline to friends)
app.post('/api/me/incognito', requireAuth, async (req, res) => {
  const on = req.body && req.body.incognito ? 1 : 0;
  await db.prepare('UPDATE users SET incognito = ? WHERE id = ?').run(on, req.user.id);
  res.json({ incognito: !!on });
});

// Toggle my read receipts
app.post('/api/me/read-receipts', requireAuth, async (req, res) => {
  const on = req.body && req.body.readReceipts ? 1 : 0;
  await db.prepare('UPDATE users SET read_receipts = ? WHERE id = ?').run(on, req.user.id);
  res.json({ readReceipts: !!on });
});

// ---- Link preview: fetch a URL and extract Open Graph title/description/image ----
app.get('/api/link-preview', requireAuth, async (req, res) => {
  const raw = String((req.query && req.query.url) || '').trim();
  if (!/^https?:\/\//i.test(raw)) return res.status(400).json({ error: 'Invalid URL.' });
  if (urlIsBlocked(raw)) return res.status(400).json({ error: 'blocked' });
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 6000);
    const r = await fetch(raw, { signal: ctrl.signal, headers: { 'User-Agent': 'ShowUppBot/1.0 (+link-preview)' } });
    clearTimeout(timer);
    const html = (await r.text()).slice(0, 200000);
    const pick = (prop) => {
      const re = new RegExp('<meta[^>]+(?:property|name)=["\']' + prop + '["\'][^>]*content=["\']([^"\']+)["\']', 'i');
      const m = html.match(re);
      return m ? m[1] : '';
    };
    let title = pick('og:title') || pick('twitter:title');
    if (!title) { const tm = html.match(/<title[^>]*>([^<]+)<\/title>/i); title = tm ? tm[1].trim() : ''; }
    const desc = pick('og:description') || pick('twitter:description') || pick('description');
    let image = pick('og:image') || pick('twitter:image');
    let host = ''; try { host = new URL(raw).hostname.replace(/^www\./, ''); } catch (e) {}
    // Resolve protocol-relative or root-relative image URLs
    if (image && image.startsWith('//')) image = 'https:' + image;
    else if (image && image.startsWith('/')) { try { image = new URL(raw).origin + image; } catch (e) {} }
    res.json({ url: raw, title: (title || '').slice(0, 160), description: (desc || '').slice(0, 240), image: (image || '').slice(0, 500), site: host });
  } catch (e) {
    res.json({ url: raw, title: '', description: '', image: '', site: '', error: 'unreachable' });
  }
});

// Server-side geocoding (address -> lat/lng). Runs here so we can send a proper
// User-Agent, which OpenStreetMap's Nominatim requires — browser calls are often blocked.
app.get('/api/geocode', requireAuth, async (req, res) => {
  const q = String((req.query && req.query.q) || '').trim();
  if (!q || q.length < 3) return res.status(400).json({ error: 'Enter an address.' });
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 6000);
    const url = 'https://nominatim.openstreetmap.org/search?format=json&addressdetails=1&namedetails=1&limit=1&q=' + encodeURIComponent(q);
    const r = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': 'ShowUppApp/1.0 (friendship app; contact admin@showupp.app)', 'Accept': 'application/json' }
    });
    clearTimeout(timer);
    if (!r.ok) return res.json({ found: false });
    const arr = await r.json();
    if (Array.isArray(arr) && arr.length) {
      const it = arr[0];
      let name = '';
      if (it.namedetails && it.namedetails.name) name = it.namedetails.name;
      else if (it.type && ['office', 'shop', 'restaurant', 'cafe', 'bar', 'amenity'].some(k => (it.class === k || it.type === k))) name = (it.display_name || '').split(',')[0];
      return res.json({ found: true, lat: parseFloat(it.lat), lng: parseFloat(it.lon), name: name || '', display: it.display_name || '' });
    }
    res.json({ found: false });
  } catch (e) {
    res.json({ found: false, error: 'geocode-failed' });
  }
});
app.post('/api/me/secure-change', requireAuth, async (req, res) => {
  const { field, currentPassword, newValue } = req.body || {};
  if (!['email', 'phone', 'password'].includes(field)) return res.status(400).json({ error: 'Invalid field.' });
  if (!currentPassword) return res.status(400).json({ error: 'Enter your current password.' });
  const row = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!row || !bcrypt.compareSync(String(currentPassword), row.pass_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }
  const val = String(newValue || '').trim();
  if (field === 'email') {
    const email = val.toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    const taken = await db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(email, req.user.id);
    if (taken) return res.status(409).json({ error: 'That email is already in use.' });
    await db.prepare('UPDATE users SET email = ? WHERE id = ?').run(email, req.user.id);
  } else if (field === 'phone') {
    const phone = val.replace(/[^0-9+]/g, '').slice(0, 20);
    await db.prepare('UPDATE users SET phone = ? WHERE id = ?').run(phone, req.user.id);
  } else if (field === 'password') {
    if (val.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters.' });
    const hash = bcrypt.hashSync(val, 10);
    await db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(hash, req.user.id);
  }
  const updated = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: { ...publicUser(updated), email: updated.email || '', phone: updated.phone || '' } });
});

// ---- Forgot email: look up a (masked) email by username or phone ----
app.post('/api/forgot-email', async (req, res) => {
  const idRaw = (req.body && req.body.identifier) || '';
  const identifier = String(idRaw).trim();
  if (!identifier) return res.status(400).json({ error: 'Enter your username or phone number.' });
  const lower = identifier.toLowerCase().replace(/^@/, '');
  const digits = identifier.replace(/[^0-9+]/g, '');
  let row = await db.prepare('SELECT email FROM users WHERE username = ?').get(lower);
  if (!row && digits.length >= 6) row = await db.prepare('SELECT email FROM users WHERE phone = ?').get(digits);
  if (!row) return res.status(404).json({ error: 'No account found with that username or phone.' });
  // mask the email: keep first char + domain
  const em = row.email || '';
  const at = em.indexOf('@');
  let masked = em;
  if (at > 0) {
    const namePart = em.slice(0, at);
    const domain = em.slice(at);
    masked = namePart[0] + '•'.repeat(Math.max(2, namePart.length - 1)) + domain;
  }
  res.json({ maskedEmail: masked });
});

// ---- Password recovery via email ----
// Sends real email if RESEND_API_KEY is set; otherwise returns the link so it still works in testing.
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'ShowUpp <onboarding@resend.dev>';
const APP_URL = process.env.APP_URL || '';

async function sendEmail(to, subject, html) {
  if (!RESEND_API_KEY) {
    console.log('[email] No RESEND_API_KEY set — skipping real send to', to);
    return { sent: false };
  }
  try {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: EMAIL_FROM, to: [to], subject, html })
    });
    if (!resp.ok) { console.log('[email] send failed', resp.status); return { sent: false }; }
    return { sent: true };
  } catch (e) {
    console.log('[email] error', e.message);
    return { sent: false };
  }
}

// Step 1: request a reset. Always responds success (don't reveal whether an email exists).
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Enter your email.' });
  const row = await db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase());
  let resetUrl = null;
  if (row) {
    const token = crypto.randomBytes(24).toString('hex');
    await db.prepare('INSERT INTO reset_tokens (token,user_id,expires_at,used,created_at) VALUES (?,?,?,0,?)')
      .run(token, row.id, now() + 60 * 60 * 1000, now()); // valid 1 hour
    const base = APP_URL || (req.headers.origin || '');
    resetUrl = base + '/?reset=' + token;
    const html = `<div style="font-family:sans-serif;max-width:480px;margin:auto">
      <h2>Reset your ShowUpp password</h2>
      <p>Hi ${row.name || ''}, we got a request to reset your password.</p>
      <p><a href="${resetUrl}" style="display:inline-block;background:#FF6B5B;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none">Reset my password</a></p>
      <p style="color:#666;font-size:13px">This link expires in 1 hour. If you didn't ask for this, you can ignore this email — your password won't change.</p>
      <p style="color:#999;font-size:12px">Your username is <b>${row.username || '(not set)'}</b>.</p>
    </div>`;
    const result = await sendEmail(row.email, 'Reset your ShowUpp password', html);
    // If email isn't configured, return the link so testing still works.
    return res.json({ ok: true, emailed: result.sent, devLink: result.sent ? null : resetUrl });
  }
  // No such user — still say ok (privacy), no link.
  res.json({ ok: true, emailed: false, devLink: null });
});

// Step 2: complete the reset with the token + new password.
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Missing token or password.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const row = await db.prepare('SELECT * FROM reset_tokens WHERE token = ?').get(String(token));
  if (!row || row.used || row.expires_at < now()) {
    return res.status(400).json({ error: 'This reset link is invalid or has expired. Request a new one.' });
  }
  const hash = bcrypt.hashSync(String(password), 10);
  await db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(hash, row.user_id);
  await db.prepare('UPDATE reset_tokens SET used = 1 WHERE token = ?').run(String(token));
  const user = await db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
  res.json({ ok: true, token: makeToken(user), user: publicUser(user) });
});

// Update the current user's profile (name, username, city, interests, lang)
app.post('/api/me/update', requireAuth, async (req, res) => {
  const { name, username, city, interests, lang, bio, gallery, isPrivate, relationship, email, phone, gender, showAge, dob } = req.body || {};
  // Date of birth: if provided, validate it and enforce the 18+ rule (same as signup).
  let cleanDob = null;
  if (dob !== undefined && dob !== null && String(dob).trim() !== '') {
    const a = ageFromDob(dob);
    if (a === null) return res.status(400).json({ error: 'Please enter a valid date of birth.' });
    if (a < 18) return res.status(403).json({ error: 'You must be 18 or older to use ShowUpp.' });
    if (a > 120) return res.status(400).json({ error: 'Please enter a valid date of birth.' });
    cleanDob = String(dob).slice(0, 10);
  }
  // Gender: restricted to a small, standard, inclusive set.
  const GENDERS = ['Woman', 'Man', 'Non-binary', 'Prefer to self-describe', 'Prefer not to say'];
  let cleanGender = null;
  if (gender !== undefined && gender !== null) {
    const g = String(gender).slice(0, 40);
    // Accept a listed value, an empty string (clear), or a custom self-description
    cleanGender = (g === '' || GENDERS.includes(g)) ? g : g; // free text allowed for self-describe
  }
  let cleanShowAge = null;
  if (typeof showAge === 'boolean') cleanShowAge = showAge ? 1 : 0;
  // If a username is provided, enforce simple rules + uniqueness
  let cleanUser = null;
  if (username && String(username).trim()) {
    cleanUser = String(username).trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
    if (cleanUser.length < 3) return res.status(400).json({ error: 'Username needs at least 3 letters/numbers.' });
    const taken = await db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(cleanUser, req.user.id);
    if (taken) return res.status(409).json({ error: 'That username is taken. Try another.' });
  }
  // Email: validate + enforce uniqueness if changing
  let cleanEmail = null;
  if (email !== undefined && email !== null && String(email).trim()) {
    cleanEmail = String(email).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) return res.status(400).json({ error: 'Enter a valid email address.' });
    const emailTaken = await db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(cleanEmail, req.user.id);
    if (emailTaken) return res.status(409).json({ error: 'That email is already in use.' });
  }
  // Phone: optional, store digits/plus only
  let cleanPhone = null;
  if (phone !== undefined && phone !== null) {
    cleanPhone = String(phone).replace(/[^0-9+]/g, '').slice(0, 20);
  }
  const cleanLang = (lang && ['en', 'es'].includes(lang)) ? lang : null;
  // gallery: array of pictures, max 15. Each item is {url, caption} (older data may be a plain URL string).
  let cleanGallery = null;
  if (Array.isArray(gallery)) {
    const cleaned = gallery.map(g => {
      // Normalize both shapes to {url, caption}
      const url = (g && typeof g === 'object') ? g.url : g;
      const caption = (g && typeof g === 'object' && typeof g.caption === 'string') ? g.caption : '';
      if (typeof url !== 'string' || !url.startsWith('data:image')) return null;
      return { url: url.slice(0, 2000000), caption: caption.slice(0, 80) };
    }).filter(Boolean).slice(0, 15);
    cleanGallery = JSON.stringify(cleaned);
  }
  await db.prepare(`UPDATE users SET
      name = COALESCE(?, name),
      username = COALESCE(?, username),
      city = COALESCE(?, city),
      interests = COALESCE(?, interests),
      lang = COALESCE(?, lang),
      bio = COALESCE(?, bio),
      gallery = COALESCE(?, gallery),
      is_private = COALESCE(?, is_private),
      relationship = COALESCE(?, relationship),
      gender = COALESCE(?, gender),
      show_age = COALESCE(?, show_age),
      dob = COALESCE(?, dob),
      email = COALESCE(?, email),
      phone = COALESCE(?, phone)
    WHERE id = ?`).run(
    name ? String(name).trim() : null,
    cleanUser,
    (city !== undefined && city !== null) ? String(city) : null,
    Array.isArray(interests) ? JSON.stringify(interests) : null,
    cleanLang,
    (bio !== undefined && bio !== null) ? String(bio).slice(0, 500) : null,
    cleanGallery,
    (typeof isPrivate === 'boolean') ? (isPrivate ? 1 : 0) : null,
    (relationship !== undefined && relationship !== null) ? String(relationship).slice(0, 40) : null,
    cleanGender,
    cleanShowAge,
    cleanDob,
    cleanEmail,
    cleanPhone,
    req.user.id
  );
  const updated = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: { ...publicUser(updated), email: updated.email || '', phone: updated.phone || '',
    dob: updated.dob || '', age: ageFromDob(updated.dob), gender: updated.gender || '', showAge: !!updated.show_age } });
});

// Upload / change profile picture (stored as a data URL; kept small)
app.post('/api/me/avatar', requireAuth, async (req, res) => {
  const { avatar } = req.body || {};
  if (typeof avatar !== 'string' || !avatar.startsWith('data:image/')) {
    return res.status(400).json({ error: 'Please choose a valid image.' });
  }
  // ~700KB cap on the encoded string to protect the free-tier database
  if (avatar.length > 700000) {
    return res.status(413).json({ error: 'That image is too large. Please pick a smaller one.' });
  }
  await db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatar, req.user.id);
  const updated = await db.prepare('SELECT id, email, name, username, avatar, city, origin, interests FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: publicUser(updated) });
});

// Remove profile picture (revert to initial)
app.post('/api/me/avatar/remove', requireAuth, async (req, res) => {
  await db.prepare('UPDATE users SET avatar = NULL WHERE id = ?').run(req.user.id);
  const updated = await db.prepare('SELECT id, email, name, username, avatar, city, origin, interests FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: publicUser(updated) });
});

// Permanently delete the current user's account and all their data
app.post('/api/me/delete', requireAuth, async (req, res) => {
  const uid = req.user.id;
  await db.prepare('DELETE FROM messages WHERE user_id = ?').run(uid);
  await db.prepare('DELETE FROM memberships WHERE user_id = ?').run(uid);
  await db.prepare('DELETE FROM friendships WHERE user_id = ? OR friend_id = ?').run(uid, uid);
  // Rounds they host: remove the round and its data
  const hosted = await db.prepare('SELECT id FROM rounds WHERE host_id = ?').all(uid);
  for (const r of hosted) {
    await db.prepare('DELETE FROM messages WHERE round_id = ?').run(r.id);
    await db.prepare('DELETE FROM memberships WHERE round_id = ?').run(r.id);
    await db.prepare('DELETE FROM rounds WHERE id = ?').run(r.id);
  }
  await db.prepare('DELETE FROM users WHERE id = ?').run(uid);
  res.json({ ok: true });
});

// ---- Friends, requests, blocks, reports ----
// Helper: are two users friends (either direction stored both ways on accept)
async function areFriends(a, b) {
  return !!(await db.prepare('SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?').get(a, b));
}
async function isBlocked(a, b) { // has a blocked b OR b blocked a
  return !!(await db.prepare('SELECT 1 FROM blocks WHERE (user_id = ? AND blocked_id = ?) OR (user_id = ? AND blocked_id = ?)').get(a, b, b, a));
}

// Search users by username or name, excluding yourself and anyone blocked
// View a user's profile — respects privacy. Friends always see full profile.
// Non-friends see full profile only if the user is public. Private users show limited info.
app.get('/api/users/:id/profile', requireAuth, async (req, res) => {
  const u = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'User not found.' });
  if (await isBlocked(req.user.id, u.id)) return res.status(403).json({ error: 'Unavailable.' });
  const friends = await areFriends(req.user.id, u.id);
  const isSelf = req.user.id === u.id;
  const canSeeFull = isSelf || friends || !u.is_private;
  // Interest-picture gallery is visible ONLY to the person themselves and their friends.
  // Non-friends (even on public profiles) see just the main avatar.
  const canSeeGallery = isSelf || friends;
  // relationship status for the button
  const sent = await db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(req.user.id, u.id);
  const incoming = await db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(u.id, req.user.id);
  const status = friends ? 'friend' : (sent ? 'pending' : (incoming ? 'incoming' : 'none'));
  if (canSeeFull) {
    res.json({
      profile: {
        id: u.id, name: u.name, username: u.username || '', avatar: u.avatar || '',
        city: u.city, origin: u.origin, interests: u.interests ? JSON.parse(u.interests) : [],
        bio: u.bio || '', gallery: canSeeGallery && u.gallery ? JSON.parse(u.gallery) : [],
        isPrivate: !!u.is_private, full: true, status, isFriend: friends, relationship: u.relationship || '',
        gender: u.gender || '',
        // Age only shows if the person turned on "Show my age" (or you're viewing yourself)
        age: (isSelf || u.show_age) ? ageFromDob(u.dob) : null
      }
    });
  } else {
    // limited view for a private, non-friend user — main avatar only
    res.json({
      profile: {
        id: u.id, name: u.name, username: u.username || '', avatar: u.avatar || '',
        city: u.city, interests: [], bio: '', gallery: [],
        isPrivate: true, full: false, status, isFriend: false,
        gender: '', age: null
      }
    });
  }
});

// Reactions (like/love) on a person's interest pictures — friends only.
app.get('/api/users/:id/gallery-reactions', requireAuth, async (req, res) => {
  const ownerId = req.params.id;
  const isSelf = ownerId === req.user.id;
  const friends = await areFriends(req.user.id, ownerId);
  if (!isSelf && !friends) return res.status(403).json({ error: 'Friends only.' });
  const rows = await db.prepare('SELECT pic_index, reactor_id, reaction FROM gallery_reactions WHERE owner_id = ?').all(ownerId);
  // Summarize per picture: counts by type, plus what the current viewer reacted.
  const byPic = {};
  for (const r of rows) {
    const k = r.pic_index;
    if (!byPic[k]) byPic[k] = { like: 0, love: 0, mine: null };
    if (r.reaction === 'like') byPic[k].like++;
    else if (r.reaction === 'love') byPic[k].love++;
    if (r.reactor_id === req.user.id) byPic[k].mine = r.reaction;
  }
  res.json({ reactions: byPic });
});

app.post('/api/users/:id/gallery-reactions', requireAuth, async (req, res) => {
  const ownerId = req.params.id;
  if (ownerId === req.user.id) return res.status(400).json({ error: "You can't react to your own pictures." });
  const friends = await areFriends(req.user.id, ownerId);
  if (!friends) return res.status(403).json({ error: 'You can only react to friends\' pictures.' });
  const picIndex = parseInt(req.body && req.body.picIndex, 10);
  const reaction = String(req.body && req.body.reaction || '');
  if (isNaN(picIndex) || picIndex < 0) return res.status(400).json({ error: 'Invalid picture.' });
  if (!['like', 'love', 'none'].includes(reaction)) return res.status(400).json({ error: 'Invalid reaction.' });
  // Verify the picture actually exists on the owner's gallery
  const owner = await db.prepare('SELECT gallery FROM users WHERE id = ?').get(ownerId);
  let gallery = [];
  try { gallery = owner && owner.gallery ? JSON.parse(owner.gallery) : []; } catch (e) { gallery = []; }
  if (picIndex >= gallery.length) return res.status(400).json({ error: 'That picture no longer exists.' });
  if (reaction === 'none') {
    await db.prepare('DELETE FROM gallery_reactions WHERE owner_id = ? AND pic_index = ? AND reactor_id = ?')
      .run(ownerId, picIndex, req.user.id);
  } else {
    // upsert
    const existing = await db.prepare('SELECT 1 FROM gallery_reactions WHERE owner_id = ? AND pic_index = ? AND reactor_id = ?')
      .get(ownerId, picIndex, req.user.id);
    if (existing) {
      await db.prepare('UPDATE gallery_reactions SET reaction = ?, created_at = ? WHERE owner_id = ? AND pic_index = ? AND reactor_id = ?')
        .run(reaction, now(), ownerId, picIndex, req.user.id);
    } else {
      await db.prepare('INSERT INTO gallery_reactions (owner_id,pic_index,reactor_id,reaction,created_at) VALUES (?,?,?,?,?)')
        .run(ownerId, picIndex, req.user.id, reaction, now());
      // Notify the owner that a friend reacted (best-effort)
      try {
        const me2 = await db.prepare('SELECT name FROM users WHERE id = ?').get(req.user.id);
        await pushNotif(ownerId, 'gallery', (me2 ? me2.name : 'A friend') + (reaction === 'love' ? ' loved' : ' liked') + ' one of your pictures 💛');
      } catch (e) {}
    }
  }
  res.json({ ok: true });
});

// ---- Save the user's approximate location (for "find similar people" & distance) ----
app.post('/api/me/location', requireAuth, async (req, res) => {
  const { lat, lng } = req.body || {};
  if (typeof lat !== 'number' || typeof lng !== 'number') return res.status(400).json({ error: 'Invalid location.' });
  await db.prepare('UPDATE users SET lat = ?, lng = ? WHERE id = ?').run(lat, lng, req.user.id);
  res.json({ ok: true });
});

// ---- Find people with similar interests (5+ shared) within a distance range ----
app.get('/api/discover-people', requireAuth, async (req, res) => {
  const me = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const myInterests = me.interests ? JSON.parse(me.interests) : [];
  const radiusMi = Math.min(parseFloat(req.query.radius) || 25, 500);
  const lat = parseFloat(req.query.lat), lng = parseFloat(req.query.lng);
  const hasLoc = !isNaN(lat) && !isNaN(lng);
  const mode = req.query.mode || 'distance'; // 'distance' | 'country'
  const country = (req.query.country || '').trim().toLowerCase();
  const MIN_SHARED = 5;
  const others = await db.prepare('SELECT * FROM users WHERE id != ?').all(req.user.id);
  const matches = [];
  for (const u of others) {
    if (await isBlocked(req.user.id, u.id)) continue;
    const theirInterests = u.interests ? JSON.parse(u.interests) : [];
    const shared = theirInterests.filter(x => myInterests.includes(x));
    if (shared.length < MIN_SHARED) continue;
    let dist = null;
    if (mode === 'country') {
      // match by the country embedded in their city string ("City, Country")
      const theirCity = (u.city || '').toLowerCase();
      if (!country || !theirCity.includes(country)) continue;
    } else {
      if (hasLoc && typeof u.lat === 'number' && typeof u.lng === 'number') {
        dist = distanceMiles(lat, lng, u.lat, u.lng);
        if (dist > radiusMi) continue;
      } else if (hasLoc) {
        continue;
      }
    }
    matches.push({
      id: u.id, name: u.name, username: u.username || '', avatar: u.avatar || '',
      city: u.city, interests: theirInterests, sharedCount: shared.length,
      sharedInterests: shared, distance: dist, isPrivate: !!u.is_private,
      lat: (typeof u.lat === 'number') ? u.lat : null, lng: (typeof u.lng === 'number') ? u.lng : null,
      isFriend: await areFriends(req.user.id, u.id)
    });
  }
  matches.sort((a, b) => b.sharedCount - a.sharedCount || (a.distance ?? 1e9) - (b.distance ?? 1e9));
  res.json({ people: matches });
});

// ---- Moments: temporary 24h profile posts ----
const MOMENT_TTL = 24 * 3600 * 1000; // 24 hours
const MOMENT_DAILY_MAX = 10;
async function pruneMoments() {
  await db.prepare('DELETE FROM moments WHERE expires_at < ?').run(now());
}
// Create a moment
app.post('/api/moments', requireAuth, async (req, res) => {
  await pruneMoments();
  const { text, photo, media } = req.body || {};
  const cleanText = String(text || '').slice(0, 500);
  // media: array of {type:'image'|'video', data:dataURL, caption?}. Cap total size.
  let cleanMedia = [];
  if (Array.isArray(media)) {
    let budget = 20 * 1024 * 1024;
    for (const item of media.slice(0, 20)) {
      if (!item || typeof item.data !== 'string') continue;
      const isImg = item.data.startsWith('data:image');
      const isVid = item.data.startsWith('data:video');
      if (!isImg && !isVid) continue;
      if (item.data.length > budget) continue;
      budget -= item.data.length;
      const caption = (typeof item.caption === 'string') ? item.caption.slice(0, 80) : '';
      cleanMedia.push({ type: isVid ? 'video' : 'image', data: item.data, caption });
    }
  }
  // legacy single-photo support
  const cleanPhoto = (photo && String(photo).startsWith('data:image')) ? String(photo).slice(0, 3000000) : null;
  if (cleanPhoto && !cleanMedia.length) cleanMedia.push({ type: 'image', data: cleanPhoto });
  if (!cleanText.trim() && !cleanMedia.length) return res.status(400).json({ error: 'Write something or add a photo/video.' });
  const since = now() - MOMENT_TTL;
  const count = Number((await db.prepare('SELECT COUNT(*) c FROM moments WHERE user_id = ? AND created_at > ?').get(req.user.id, since)).c) || 0;
  if (count >= MOMENT_DAILY_MAX) return res.status(429).json({ error: "You've reached the limit of 10 posts in 24 hours. Try again later." });
  const firstPhoto = cleanMedia.find(x => x.type === 'image');
  const m = {
    id: id(), user_id: req.user.id, text: cleanText,
    photo: firstPhoto ? firstPhoto.data : null,
    media: JSON.stringify(cleanMedia),
    created_at: now(), expires_at: now() + MOMENT_TTL
  };
  await db.prepare('INSERT INTO moments (id,user_id,text,photo,media,created_at,expires_at) VALUES (@id,@user_id,@text,@photo,@media,@created_at,@expires_at)').run(m);
  const remaining = MOMENT_DAILY_MAX - (count + 1);
  res.json({ moment: m, remaining });
});
// Get my own active moments
app.get('/api/moments/mine', requireAuth, async (req, res) => {
  await pruneMoments();
  const rows = await db.prepare('SELECT * FROM moments WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC').all(req.user.id, now());
  const since = now() - MOMENT_TTL;
  const used = Number((await db.prepare('SELECT COUNT(*) c FROM moments WHERE user_id = ? AND created_at > ?').get(req.user.id, since)).c) || 0;
  res.json({ moments: rows, remaining: Math.max(0, MOMENT_DAILY_MAX - used) });
});
// Get a user's active moments — only if self or friends
// All friends who currently have active daily updates, each with their posts.
// Powers the "Daily Updates" tab under Circles > Friends.
app.get('/api/friends/moments', requireAuth, async (req, res) => {
  await pruneMoments();
  const friendRows = await db.prepare('SELECT friend_id FROM friendships WHERE user_id = ?').all(req.user.id);
  const out = [];
  for (const fr of friendRows) {
    const u = await db.prepare('SELECT id,name,username,avatar FROM users WHERE id = ?').get(fr.friend_id);
    if (!u) continue;
    const moments = await db.prepare('SELECT * FROM moments WHERE user_id = ? AND expires_at > ? ORDER BY created_at ASC').all(fr.friend_id, now());
    if (moments.length) {
      out.push({ user: u, moments, latest: moments[moments.length - 1].created_at });
    }
  }
  // Most recently updated friends first
  out.sort((a, b) => b.latest - a.latest);
  res.json({ feed: out });
});

app.get('/api/users/:id/moments', requireAuth, async (req, res) => {
  await pruneMoments();
  const targetId = req.params.id;
  if (targetId !== req.user.id && !await areFriends(req.user.id, targetId)) {
    return res.status(403).json({ error: 'Only friends can see these posts.' });
  }
  const rows = await db.prepare('SELECT * FROM moments WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC').all(targetId, now());
  res.json({ moments: rows });
});
// Delete a moment (own only)
app.post('/api/moments/:id/delete', requireAuth, async (req, res) => {
  const m = await db.prepare('SELECT user_id FROM moments WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Post not found.' });
  if (m.user_id !== req.user.id) return res.status(403).json({ error: 'Not allowed.' });
  await db.prepare('DELETE FROM moments WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/users/search', requireAuth, async (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase().replace(/^@/, '');
  if (q.length < 2) return res.json({ users: [] });
  const rows = await db.prepare(`
    SELECT id, name, username, avatar, city FROM users
    WHERE id != ? AND (LOWER(username) LIKE ? OR LOWER(name) LIKE ?)
    LIMIT 20
  `).all(req.user.id, '%' + q + '%', '%' + q + '%');
  const friendRows = await db.prepare('SELECT friend_id FROM friendships WHERE user_id = ?').all(req.user.id);
  const friendIds = new Set(friendRows.map(r => r.friend_id));
  const sentRows = await db.prepare('SELECT to_id FROM friend_requests WHERE from_id = ?').all(req.user.id);
  const sentIds = new Set(sentRows.map(r => r.to_id));
  // Fetch everyone this user has blocked or been blocked by, once, so filtering stays synchronous
  const blockRows = await db.prepare('SELECT user_id, blocked_id FROM blocks WHERE user_id = ? OR blocked_id = ?').all(req.user.id, req.user.id);
  const blockedSet = new Set();
  for (const b of blockRows) { blockedSet.add(b.user_id === req.user.id ? b.blocked_id : b.user_id); }
  const out = rows
    .filter(u => u.username && !blockedSet.has(u.id))
    .map(u => ({
      id: u.id, name: u.name, username: u.username, avatar: u.avatar || '', city: u.city,
      status: friendIds.has(u.id) ? 'friend' : (sentIds.has(u.id) ? 'pending' : 'none')
    }));
  res.json({ users: out });
});

// Send a friend request
app.post('/api/friends/request', requireAuth, async (req, res) => {
  const { toId } = req.body || {};
  if (!toId || toId === req.user.id) return res.status(400).json({ error: 'Invalid user.' });
  if (await isBlocked(req.user.id, toId)) return res.status(403).json({ error: 'Unavailable.' });
  const exists = await db.prepare('SELECT id FROM users WHERE id = ?').get(toId);
  if (!exists) return res.status(404).json({ error: 'User not found.' });
  if (await areFriends(req.user.id, toId)) return res.json({ ok: true, status: 'friend' });
  // If they already sent YOU a request, accept it instead
  const incoming = await db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(toId, req.user.id);
  if (incoming) {
    await db.prepare('INSERT INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(req.user.id, toId, now());
    await db.prepare('INSERT INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(toId, req.user.id, now());
    await db.prepare('DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?').run(toId, req.user.id);
    return res.json({ ok: true, status: 'friend' });
  }
  await db.prepare('INSERT INTO friend_requests (from_id,to_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(req.user.id, toId, now());
  await pushNotif(toId, 'friend_request', 'New friend request', (req.user.name || 'Someone') + ' wants to be friends', 'friends:requests');
  res.json({ ok: true, status: 'pending' });
});

// Incoming friend requests (people who want to add me)
app.get('/api/friends/requests', requireAuth, async (req, res) => {
  const rows = await db.prepare(`
    SELECT u.id, u.name, u.username, u.avatar, u.city
    FROM friend_requests fr JOIN users u ON u.id = fr.from_id
    WHERE fr.to_id = ? ORDER BY fr.created_at DESC
  `).all(req.user.id);
  res.json({ requests: rows });
});

// Outgoing friend requests (people I've asked to be friends, still awaiting a reply)
app.get('/api/friends/sent', requireAuth, async (req, res) => {
  const rows = await db.prepare(`
    SELECT u.id, u.name, u.username, u.avatar, u.city
    FROM friend_requests fr JOIN users u ON u.id = fr.to_id
    WHERE fr.from_id = ? ORDER BY fr.created_at DESC
  `).all(req.user.id);
  res.json({ requests: rows });
});

// Rescind (cancel) a friend request I sent — lets someone change their mind before it's answered
app.post('/api/friends/rescind', requireAuth, async (req, res) => {
  const { toId } = req.body || {};
  if (!toId) return res.status(400).json({ error: 'Invalid user.' });
  const existing = await db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(req.user.id, toId);
  if (!existing) return res.status(404).json({ error: "That request no longer exists." });
  await db.prepare('DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?').run(req.user.id, toId);
  res.json({ ok: true });
});

// Accept a request
app.post('/api/friends/accept', requireAuth, async (req, res) => {
  const { fromId } = req.body || {};
  const pending = await db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(fromId, req.user.id);
  if (!pending) return res.status(404).json({ error: 'No such request.' });
  await db.prepare('INSERT INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(req.user.id, fromId, now());
  await db.prepare('INSERT INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(fromId, req.user.id, now());
  await db.prepare('DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?').run(fromId, req.user.id);
  await pushNotif(fromId, 'friend_accept', 'Friend request accepted', (req.user.name || 'Someone') + ' accepted your friend request 🎉', 'friends:friends');
  res.json({ ok: true });
});

// Decline a request
app.post('/api/friends/decline', requireAuth, async (req, res) => {
  const { fromId } = req.body || {};
  await db.prepare('DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?').run(fromId, req.user.id);
  res.json({ ok: true });
});

// Remove a friend (both directions)
app.post('/api/friends/remove', requireAuth, async (req, res) => {
  const { friendId } = req.body || {};
  await db.prepare('DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)')
    .run(req.user.id, friendId, friendId, req.user.id);
  res.json({ ok: true });
});

// List my friends
app.get('/api/friends', requireAuth, async (req, res) => {
  const rows = await db.prepare(`
    SELECT u.id, u.name, u.username, u.avatar, u.city
    FROM friendships f JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ? ORDER BY f.created_at DESC
  `).all(req.user.id);
  res.json({ friends: rows });
});

// Block a user (also removes friendship + pending requests both ways)
app.post('/api/block', requireAuth, async (req, res) => {
  const { userId } = req.body || {};
  if (!userId || userId === req.user.id) return res.status(400).json({ error: 'Invalid user.' });
  await db.prepare('INSERT INTO blocks (user_id,blocked_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(req.user.id, userId, now());
  await db.prepare('DELETE FROM friendships WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)').run(req.user.id, userId, userId, req.user.id);
  await db.prepare('DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)').run(req.user.id, userId, userId, req.user.id);
  res.json({ ok: true });
});

// Unblock
app.post('/api/unblock', requireAuth, async (req, res) => {
  const { userId } = req.body || {};
  await db.prepare('DELETE FROM blocks WHERE user_id = ? AND blocked_id = ?').run(req.user.id, userId);
  res.json({ ok: true });
});

// List people I've blocked
app.get('/api/blocks', requireAuth, async (req, res) => {
  const rows = await db.prepare(`
    SELECT u.id, u.name, u.username, u.avatar
    FROM blocks b JOIN users u ON u.id = b.blocked_id
    WHERE b.user_id = ? ORDER BY b.created_at DESC
  `).all(req.user.id);
  res.json({ blocked: rows });
});

// Report a user / content
app.post('/api/report', requireAuth, async (req, res) => {
  const { reportedId, context, reason } = req.body || {};
  await db.prepare('INSERT INTO reports (id,reporter_id,reported_id,context,reason,created_at) VALUES (?,?,?,?,?,?)')
    .run(id(), req.user.id, reportedId || null, String(context || '').slice(0, 200), String(reason || '').slice(0, 500), now());
  res.json({ ok: true });
});

// ---- Notifications ----
function isUserOnline(userId) {
  let online = false;
  wss.clients.forEach(c => { if (c.readyState === 1 && c.user && c.user.id === userId) online = true; });
  return online;
}
async function pushNotif(userId, type, title, body, link) {
  try {
    await db.prepare('INSERT INTO notifications (id,user_id,type,title,body,link,read,created_at) VALUES (?,?,?,?,?,?,0,?)')
      .run(id(), userId, type, title || '', body || '', link || '', now());
    // live ping over WS if they're connected
    const payload = JSON.stringify({ type: 'notify' });
    wss.clients.forEach(c => { if (c.readyState === 1 && c.user && c.user.id === userId) c.send(payload); });
  } catch (e) { /* ignore */ }
}

// Notify people when a friend has a birthday today. Runs on startup and once a day.
// Each person is told about each friend's birthday at most once per year.
async function checkBirthdays() {
  try {
    const today = new Date();
    const mm = String(today.getMonth() + 1).padStart(2, '0');
    const dd = String(today.getDate()).padStart(2, '0');
    const year = today.getFullYear();
    // Everyone with a birthday matching today's month + day (dob stored as YYYY-MM-DD)
    const birthdayPeople = await db.prepare("SELECT id, name, dob FROM users WHERE dob IS NOT NULL AND SUBSTR(dob,6,5) = ?").all(mm + '-' + dd);
    for (const bp of birthdayPeople) {
      // Find their friends (people who should be told)
      const friendRows = await db.prepare('SELECT user_id FROM friendships WHERE friend_id = ?').all(bp.id);
      for (const fr of friendRows) {
        const already = await db.prepare('SELECT 1 FROM birthday_notifs WHERE user_id = ? AND friend_id = ? AND year = ?').get(fr.user_id, bp.id, year);
        if (already) continue;
        const firstName = (bp.name || 'Your friend').split(' ')[0];
        await pushNotif(
          fr.user_id, 'birthday',
          '🎂 ' + firstName + "'s birthday is today!",
          'Make their day — reach out and celebrate ' + firstName + '.',
          'birthday:' + bp.id
        );
        await db.prepare('INSERT INTO birthday_notifs (user_id, friend_id, year) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(fr.user_id, bp.id, year);
      }
    }
  } catch (e) { /* ignore */ }
}

app.get('/api/notifications', requireAuth, async (req, res) => {
  const rows = await db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(req.user.id);
  res.json({ notifications: rows });
});

// Unread counts for the badge (notifications + unread messages), broken down by category
app.get('/api/notifications/counts', requireAuth, async (req, res) => {
  // Bell = non-message notifications only (friend requests, accepts, group events).
  const notif = Number((await db.prepare("SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND read = 0 AND type != 'dm'").get(req.user.id)).c) || 0;

  // Friends (DMs): total unread messages across all conversations
  const convs = await db.prepare('SELECT conv_id, last_read FROM conversation_members WHERE user_id = ?').all(req.user.id);
  let dmMessages = 0;
  for (const cm of convs) {
    dmMessages += Number((await db.prepare('SELECT COUNT(*) AS c FROM dm_messages WHERE conv_id = ? AND created_at > ? AND user_id != ?')
      .get(cm.conv_id, cm.last_read || 0, req.user.id)).c) || 0;
  }

  // Round chats: total unread messages across all Rounds the user belongs to
  const mems = await db.prepare('SELECT round_id, last_read FROM memberships WHERE user_id = ?').all(req.user.id);
  let roundMessages = 0;
  for (const mm of mems) {
    roundMessages += Number((await db.prepare('SELECT COUNT(*) AS c FROM messages WHERE round_id = ? AND created_at > ? AND user_id != ?')
      .get(mm.round_id, mm.last_read || 0, req.user.id)).c) || 0;
  }

  const chatsTotal = dmMessages + roundMessages;
  res.json({
    notifications: notif,
    rounds: roundMessages,
    dms: dmMessages,
    chatsTotal,
    total: notif + chatsTotal
  });
});

app.post('/api/notifications/read', requireAuth, async (req, res) => {
  await db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

// Delete a single notification (used by swipe-to-delete)
app.post('/api/notifications/:id/delete', requireAuth, async (req, res) => {
  await db.prepare('DELETE FROM notifications WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ---- Direct messages / friend group chats ----
// List my conversations with last message + unread flag
// Searches message text across every Round chat and DM/group conversation the person
// belongs to. Used by the search boxes on the Chats page ("look for a conversation,
// a text, anything").
app.get('/api/search/messages', requireAuth, async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (!q || q.length < 2) return res.json({ rounds: [], conversations: [] });
  const like = '%' + q.toLowerCase() + '%';

  const roundHits = await db.prepare(`
    SELECT m.id AS message_id, m.round_id, m.body, m.created_at, u.name AS sender, r.title AS round_title, r.emoji AS round_emoji
    FROM messages m
    JOIN memberships mm ON mm.round_id = m.round_id AND mm.user_id = ?
    JOIN rounds r ON r.id = m.round_id
    JOIN users u ON u.id = m.user_id
    WHERE m.deleted = 0 AND LOWER(m.body) LIKE ?
    ORDER BY m.created_at DESC LIMIT 30
  `).all(req.user.id, like);

  const dmHits = await db.prepare(`
    SELECT m.id AS message_id, m.conv_id, m.body, m.created_at, u.name AS sender, c.title AS conv_title, c.is_group
    FROM dm_messages m
    JOIN conversation_members cm ON cm.conv_id = m.conv_id AND cm.user_id = ?
    JOIN conversations c ON c.id = m.conv_id
    JOIN users u ON u.id = m.user_id
    WHERE m.deleted = 0 AND LOWER(m.body) LIKE ?
    ORDER BY m.created_at DESC LIMIT 30
  `).all(req.user.id, like);
  // 1:1 conversations don't store a title — fill in the other person's name
  for (const hit of dmHits) {
    if (!hit.is_group && !hit.conv_title) {
      const other = await db.prepare(`
        SELECT u.name FROM conversation_members cm JOIN users u ON u.id = cm.user_id
        WHERE cm.conv_id = ? AND cm.user_id != ? LIMIT 1
      `).get(hit.conv_id, req.user.id);
      hit.conv_title = other ? other.name : 'Conversation';
    }
  }

  res.json({ rounds: roundHits, conversations: dmHits });
});

app.get('/api/conversations', requireAuth, async (req, res) => {
  const convs = await db.prepare(`
    SELECT c.*, cm.last_read FROM conversations c
    JOIN conversation_members cm ON cm.conv_id = c.id
    WHERE cm.user_id = ? ORDER BY c.created_at DESC
  `).all(req.user.id);
  const out = [];
  for (const c of convs) {
    const members = await db.prepare(`SELECT u.id,u.name,u.username,u.avatar FROM conversation_members m JOIN users u ON u.id=m.user_id WHERE m.conv_id=?`).all(c.id);
    const others = members.filter(m => m.id !== req.user.id);
    const last = await db.prepare('SELECT body,kind,created_at,user_id FROM dm_messages WHERE conv_id=? ORDER BY created_at DESC LIMIT 1').get(c.id);
    const unread = Number((await db.prepare('SELECT COUNT(*) AS c FROM dm_messages WHERE conv_id=? AND created_at > ? AND user_id != ?').get(c.id, c.last_read || 0, req.user.id)).c) || 0;
    let title = c.title;
    if (!c.is_group) title = others[0] ? others[0].name : 'Conversation';
    out.push({
      id: c.id, is_group: !!c.is_group, title,
      members: others,
      avatar: c.is_group ? (c.avatar || '') : (others[0] ? (others[0].avatar || '') : ''),
      last: last ? { body: last.kind === 'gif' ? '📷 GIF' : last.body, created_at: last.created_at, mine: last.user_id === req.user.id } : null,
      unread
    });
  }
  res.json({ conversations: out });
});

// Open (or create) a 1-on-1 conversation with a friend
app.post('/api/conversations/open', requireAuth, async (req, res) => {
  const { friendId } = req.body || {};
  if (!friendId || friendId === req.user.id) return res.status(400).json({ error: 'Invalid user.' });
  // must be friends
  const friend = await db.prepare('SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?').get(req.user.id, friendId);
  if (!friend) return res.status(403).json({ error: 'You can only message friends.' });
  if (await isBlocked(req.user.id, friendId)) return res.status(403).json({ error: 'Unavailable.' });
  // find an existing 1-on-1 between exactly these two
  const existing = await db.prepare(`
    SELECT c.id FROM conversations c
    WHERE c.is_group = 0
      AND EXISTS(SELECT 1 FROM conversation_members m WHERE m.conv_id=c.id AND m.user_id=?)
      AND EXISTS(SELECT 1 FROM conversation_members m WHERE m.conv_id=c.id AND m.user_id=?)
      AND (SELECT COUNT(*) FROM conversation_members m WHERE m.conv_id=c.id)=2
  `).get(req.user.id, friendId);
  let convId = existing ? existing.id : null;
  if (!convId) {
    convId = id();
    await db.prepare('INSERT INTO conversations (id,is_group,title,created_by,created_at) VALUES (?,0,?,?,?)').run(convId, '', req.user.id, now());
    await db.prepare('INSERT INTO conversation_members (conv_id,user_id,last_read) VALUES (?,?,0)').run(convId, req.user.id);
    await db.prepare('INSERT INTO conversation_members (conv_id,user_id,last_read) VALUES (?,?,0)').run(convId, friendId);
  }
  res.json({ conversationId: convId });
});

// Create a friend group chat
app.post('/api/conversations/group', requireAuth, async (req, res) => {
  const { title, memberIds } = req.body || {};
  const ids = Array.isArray(memberIds) ? memberIds.filter(x => x && x !== req.user.id) : [];
  if (!ids.length) return res.status(400).json({ error: 'Pick at least one friend.' });
  // all must be friends
  for (const fid of ids) {
    const ok = await db.prepare('SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?').get(req.user.id, fid);
    if (!ok) return res.status(403).json({ error: 'You can only add friends to a group.' });
  }
  const convId = id();
  await db.prepare('INSERT INTO conversations (id,is_group,title,created_by,created_at) VALUES (?,1,?,?,?)')
    .run(convId, String(title || 'Group chat').slice(0, 60), req.user.id, now());
  await db.prepare('INSERT INTO conversation_members (conv_id,user_id,last_read) VALUES (?,?,0)').run(convId, req.user.id);
  for (const fid of ids) {
    await db.prepare('INSERT INTO conversation_members (conv_id,user_id,last_read) VALUES (?,?,0) ON CONFLICT DO NOTHING').run(convId, fid);
    await pushNotif(fid, 'group', 'New group chat', (req.user.name || 'A friend') + ' added you to "' + (title || 'Group chat') + '"', 'dm:' + convId);
  }
  res.json({ conversationId: convId });
});

// Get messages in a conversation (and mark read)
app.get('/api/conversations/:id/messages', requireAuth, async (req, res) => {
  const member = await db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Not in this conversation.' });
  const rows = await db.prepare(`
    SELECT m.id,m.body,m.kind,m.media_url,m.created_at,m.user_id,u.name AS sender,u.avatar,m.reactions,m.reply_to,m.reply_preview,m.deleted,m.edited
    FROM dm_messages m JOIN users u ON u.id=m.user_id
    WHERE m.conv_id=? ORDER BY m.created_at ASC LIMIT 300
  `).all(req.params.id);
  const msgs = rows.map(m => ({
    id: m.id, body: m.body, kind: m.kind || 'text', media_url: m.media_url || null,
    created_at: m.created_at, user_id: m.user_id, sender: m.sender, avatar: m.avatar,
    reactions: m.reactions ? JSON.parse(m.reactions) : {},
    reply_to: m.reply_to || null, reply_preview: m.reply_preview || null, deleted: !!m.deleted, edited: !!m.edited
  }));
  await db.prepare('UPDATE conversation_members SET last_read=? WHERE conv_id=? AND user_id=?').run(now(), req.params.id, req.user.id);
  const conv = await db.prepare('SELECT * FROM conversations WHERE id=?').get(req.params.id);
  const members = await db.prepare(`SELECT u.id,u.name,u.username,u.avatar FROM conversation_members m JOIN users u ON u.id=m.user_id WHERE m.conv_id=?`).all(req.params.id);
  const others = members.filter(m => m.id !== req.user.id);
  const title = conv.is_group ? conv.title : (others[0] ? others[0].name : 'Conversation');
  // Read-receipt info for 1-on-1 chats: the other member's last_read time and whether they + I have receipts on
  let otherLastRead = 0, receiptsOn = false;
  if (!conv.is_group && others[0]) {
    const om = await db.prepare('SELECT last_read FROM conversation_members WHERE conv_id=? AND user_id=?').get(req.params.id, others[0].id);
    otherLastRead = (om && om.last_read) || 0;
    const meRow = await db.prepare('SELECT read_receipts FROM users WHERE id=?').get(req.user.id);
    const otherRow = await db.prepare('SELECT read_receipts FROM users WHERE id=?').get(others[0].id);
    receiptsOn = (meRow && meRow.read_receipts !== 0) && (otherRow && otherRow.read_receipts !== 0);
  }
  res.json({ messages: msgs, conversation: {
    id: conv.id, is_group: !!conv.is_group, title, members: others,
    all_members: members, owner_id: conv.created_by || null, is_owner: conv.created_by === req.user.id,
    avatar: conv.avatar || '', description: conv.description || '',
    other_last_read: otherLastRead, receipts_on: receiptsOn
  } });
});

// ---- Group chat management ----
// Helper: is this user a member of the conversation?
async function isConvMember(convId, userId) {
  return !!await db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(convId, userId);
}

// Update group picture and/or description — ANY member may do this.
app.post('/api/conversations/:id/info', requireAuth, async (req, res) => {
  const convId = req.params.id;
  const conv = await db.prepare('SELECT * FROM conversations WHERE id=?').get(convId);
  if (!conv || !conv.is_group) return res.status(404).json({ error: 'Group not found.' });
  if (!await isConvMember(convId, req.user.id)) return res.status(403).json({ error: 'Not in this group.' });
  const { avatar, description } = req.body || {};
  if (typeof avatar === 'string') {
    // avatar is a data URL image (or empty string to clear)
    const clean = avatar && avatar.startsWith('data:image') ? avatar.slice(0, 2000000) : (avatar === '' ? '' : null);
    if (clean !== null) await db.prepare('UPDATE conversations SET avatar=? WHERE id=?').run(clean, convId);
  }
  if (typeof description === 'string') {
    await db.prepare('UPDATE conversations SET description=? WHERE id=?').run(description.slice(0, 300), convId);
  }
  res.json({ ok: true });
});

// Rename the group — OWNER only.
app.post('/api/conversations/:id/rename', requireAuth, async (req, res) => {
  const convId = req.params.id;
  const conv = await db.prepare('SELECT * FROM conversations WHERE id=?').get(convId);
  if (!conv || !conv.is_group) return res.status(404).json({ error: 'Group not found.' });
  if (conv.created_by !== req.user.id) return res.status(403).json({ error: 'Only the group creator can rename it.' });
  const title = String((req.body && req.body.title) || '').trim();
  if (!title) return res.status(400).json({ error: 'Enter a group name.' });
  await db.prepare('UPDATE conversations SET title=? WHERE id=?').run(title.slice(0, 60), convId);
  res.json({ ok: true, title: title.slice(0, 60) });
});

// Add members — OWNER only, and only their friends.
app.post('/api/conversations/:id/add-members', requireAuth, async (req, res) => {
  const convId = req.params.id;
  const conv = await db.prepare('SELECT * FROM conversations WHERE id=?').get(convId);
  if (!conv || !conv.is_group) return res.status(404).json({ error: 'Group not found.' });
  if (conv.created_by !== req.user.id) return res.status(403).json({ error: 'Only the group creator can add people.' });
  const ids = Array.isArray(req.body && req.body.memberIds) ? req.body.memberIds.filter(x => x && x !== req.user.id) : [];
  if (!ids.length) return res.status(400).json({ error: 'Pick at least one friend.' });
  let added = 0;
  for (const fid of ids) {
    const friend = await db.prepare('SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?').get(req.user.id, fid);
    if (!friend) continue;
    await db.prepare('INSERT INTO conversation_members (conv_id,user_id,last_read) VALUES (?,?,0) ON CONFLICT DO NOTHING').run(convId, fid);
    await pushNotif(fid, 'group', 'Added to a group', (req.user.name || 'A friend') + ' added you to "' + (conv.title || 'a group') + '"', 'dm:' + convId);
    added++;
  }
  res.json({ ok: true, added });
});

// Remove a member — OWNER only (owner can't remove themselves this way; they'd use leave/transfer).
app.post('/api/conversations/:id/remove-member', requireAuth, async (req, res) => {
  const convId = req.params.id;
  const conv = await db.prepare('SELECT * FROM conversations WHERE id=?').get(convId);
  if (!conv || !conv.is_group) return res.status(404).json({ error: 'Group not found.' });
  if (conv.created_by !== req.user.id) return res.status(403).json({ error: 'Only the group creator can remove people.' });
  const uid = String((req.body && req.body.userId) || '');
  if (!uid || uid === req.user.id) return res.status(400).json({ error: 'Invalid member.' });
  await db.prepare('DELETE FROM conversation_members WHERE conv_id=? AND user_id=?').run(convId, uid);
  res.json({ ok: true });
});

// Leave a group — ANY member. If the owner leaves, hand ownership to the oldest remaining member.
app.post('/api/conversations/:id/leave', requireAuth, async (req, res) => {
  const convId = req.params.id;
  const conv = await db.prepare('SELECT * FROM conversations WHERE id=?').get(convId);
  if (!conv || !conv.is_group) return res.status(404).json({ error: 'Group not found.' });
  if (!await isConvMember(convId, req.user.id)) return res.status(403).json({ error: 'Not in this group.' });
  await db.prepare('DELETE FROM conversation_members WHERE conv_id=? AND user_id=?').run(convId, req.user.id);
  if (conv.created_by === req.user.id) {
    const next = await db.prepare('SELECT user_id FROM conversation_members WHERE conv_id=? ORDER BY last_read ASC LIMIT 1').get(convId);
    if (next) await db.prepare('UPDATE conversations SET created_by=? WHERE id=?').run(next.user_id, convId);
  }
  res.json({ ok: true });
});

// Remove a conversation from MY chat list (swipe-to-delete).
// For a group this is the same as leaving; for a 1-on-1 it just hides it for me
// (the other person keeps their copy). If everyone has left, the conversation is cleaned up.
app.post('/api/conversations/:id/delete', requireAuth, async (req, res) => {
  const convId = req.params.id;
  const conv = await db.prepare('SELECT * FROM conversations WHERE id=?').get(convId);
  if (!conv) return res.json({ ok: true }); // already gone
  if (!await isConvMember(convId, req.user.id)) return res.status(403).json({ error: 'Not in this conversation.' });
  await db.prepare('DELETE FROM conversation_members WHERE conv_id=? AND user_id=?').run(convId, req.user.id);
  // If the owner of a group leaves, hand ownership to someone else
  if (conv.is_group && conv.created_by === req.user.id) {
    const next = await db.prepare('SELECT user_id FROM conversation_members WHERE conv_id=? ORDER BY last_read ASC LIMIT 1').get(convId);
    if (next) await db.prepare('UPDATE conversations SET created_by=? WHERE id=?').run(next.user_id, convId);
  }
  // If nobody is left in the conversation, delete it and its messages entirely
  const remaining = Number((await db.prepare('SELECT COUNT(*) AS c FROM conversation_members WHERE conv_id=?').get(convId)).c) || 0;
  if (remaining === 0) {
    await db.prepare('DELETE FROM dm_messages WHERE conv_id=?').run(convId);
    await db.prepare('DELETE FROM conversations WHERE id=?').run(convId);
  }
  res.json({ ok: true });
});

// React to a DM message
app.post('/api/dm/:id/react', requireAuth, async (req, res) => {
  const { emoji } = req.body || {};
  if (!emoji) return res.status(400).json({ error: 'No emoji.' });
  const m = await db.prepare('SELECT id, conv_id, reactions FROM dm_messages WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Message gone.' });
  const member = await db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(m.conv_id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Not in this conversation.' });
  const reactions = m.reactions ? JSON.parse(m.reactions) : {};
  const users = reactions[emoji] || [];
  const idx = users.indexOf(req.user.id);
  if (idx >= 0) users.splice(idx, 1); else users.push(req.user.id);
  if (users.length) reactions[emoji] = users; else delete reactions[emoji];
  await db.prepare('UPDATE dm_messages SET reactions = ? WHERE id = ?').run(JSON.stringify(reactions), req.params.id);
  const payload = JSON.stringify({ type: 'dmReaction', convId: m.conv_id, messageId: req.params.id, reactions });
  wss.clients.forEach(c => { if (c.readyState === 1 && c.dmRooms && c.dmRooms.has(m.conv_id)) c.send(payload); });
  res.json({ ok: true, reactions });
});

// Unsend a DM / group-chat message for everyone — sender only.
app.post('/api/dm/:id/delete', requireAuth, async (req, res) => {
  const m = await db.prepare('SELECT id, conv_id, user_id FROM dm_messages WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Message already gone.' });
  if (m.user_id !== req.user.id) return res.status(403).json({ error: 'You can only unsend your own messages.' });
  await db.prepare("UPDATE dm_messages SET deleted = 1, body = '', media_url = NULL, reactions = NULL WHERE id = ?").run(req.params.id);
  const payload = JSON.stringify({ type: 'dmMessageDeleted', convId: m.conv_id, messageId: req.params.id });
  wss.clients.forEach(c => { if (c.readyState === 1 && c.dmRooms && c.dmRooms.has(m.conv_id)) c.send(payload); });
  res.json({ ok: true });
});

// Edit a DM / group-chat message — sender only, text messages only.
app.post('/api/dm/:id/edit', requireAuth, async (req, res) => {
  const { body } = req.body || {};
  const text = String(body || '').trim();
  if (!text) return res.status(400).json({ error: 'Message cannot be empty.' });
  const m = await db.prepare('SELECT id, conv_id, user_id, deleted, kind FROM dm_messages WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Message not found.' });
  if (m.deleted) return res.status(400).json({ error: "Can't edit an unsent message." });
  if (m.user_id !== req.user.id) return res.status(403).json({ error: 'You can only edit your own messages.' });
  if (m.kind && m.kind !== 'text') return res.status(400).json({ error: 'Only text messages can be edited.' });
  await db.prepare('UPDATE dm_messages SET body = ?, edited = 1 WHERE id = ?').run(text, req.params.id);
  const payload = JSON.stringify({ type: 'dmMessageEdited', convId: m.conv_id, messageId: req.params.id, body: text });
  wss.clients.forEach(c => { if (c.readyState === 1 && c.dmRooms && c.dmRooms.has(m.conv_id)) c.send(payload); });
  res.json({ ok: true });
});

// ---- Admin (owner-only) ----
// Requires: logged-in user with is_admin = 1
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_admin) return res.status(403).json({ error: 'Not authorized.' });
  next();
}

// Confirm whether current user is an admin (used by the app to show/hide the panel)
app.get('/api/admin/check', requireAuth, async (req, res) => {
  res.json({ isAdmin: !!req.user.is_admin });
});

// List all users (admin only)
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  let rows;
  if (q) {
    rows = await db.prepare(`SELECT id,name,username,email,city,suspended,is_admin,created_at
      FROM users WHERE LOWER(name) LIKE ? OR LOWER(username) LIKE ? OR LOWER(email) LIKE ?
      ORDER BY created_at DESC LIMIT 200`).all('%'+q+'%','%'+q+'%','%'+q+'%');
  } else {
    rows = await db.prepare('SELECT id,name,username,email,city,suspended,is_admin,created_at FROM users ORDER BY created_at DESC LIMIT 200').all();
  }
  res.json({ users: rows });
});

// Suspend / unsuspend a user (admin only)
app.post('/api/admin/suspend', requireAuth, requireAdmin, async (req, res) => {
  const { userId, suspend } = req.body || {};
  const target = await db.prepare('SELECT id,is_admin FROM users WHERE id = ?').get(userId);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  if (target.is_admin) return res.status(400).json({ error: 'You cannot suspend an admin account.' });
  await db.prepare('UPDATE users SET suspended = ? WHERE id = ?').run(suspend ? 1 : 0, userId);
  res.json({ ok: true });
});

// Permanently delete a user and their data (admin only)
app.post('/api/admin/delete', requireAuth, requireAdmin, async (req, res) => {
  const { userId } = req.body || {};
  const target = await db.prepare('SELECT id,is_admin FROM users WHERE id = ?').get(userId);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  if (target.is_admin) return res.status(400).json({ error: 'You cannot delete an admin account.' });
  await db.prepare('DELETE FROM messages WHERE user_id = ?').run(userId);
  await db.prepare('DELETE FROM memberships WHERE user_id = ?').run(userId);
  await db.prepare('DELETE FROM friendships WHERE user_id = ? OR friend_id = ?').run(userId, userId);
  await db.prepare('DELETE FROM friend_requests WHERE from_id = ? OR to_id = ?').run(userId, userId);
  await db.prepare('DELETE FROM blocks WHERE user_id = ? OR blocked_id = ?').run(userId, userId);
  {
    const hosted = await db.prepare('SELECT id FROM rounds WHERE host_id = ?').all(userId);
    for (const r of hosted) {
      await db.prepare('DELETE FROM messages WHERE round_id = ?').run(r.id);
      await db.prepare('DELETE FROM memberships WHERE round_id = ?').run(r.id);
      await db.prepare('DELETE FROM rounds WHERE id = ?').run(r.id);
    }
  }
  await db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  res.json({ ok: true });
});

// View reports (admin only)
app.get('/api/admin/reports', requireAuth, requireAdmin, async (req, res) => {
  const rows = await db.prepare(`
    SELECT r.id, r.context, r.reason, r.created_at,
      reporter.name AS reporter_name, reporter.username AS reporter_username,
      reported.id AS reported_id, reported.name AS reported_name, reported.username AS reported_username
    FROM reports r
    LEFT JOIN users reporter ON reporter.id = r.reporter_id
    LEFT JOIN users reported ON reported.id = r.reported_id
    ORDER BY r.created_at DESC LIMIT 100
  `).all();
  res.json({ reports: rows });
});

// List / search all Rounds (admin only) — for moderation, e.g. finding a Round that was reported
app.get('/api/admin/rounds', requireAuth, requireAdmin, async (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  let rows;
  if (q) {
    rows = await db.prepare(`
      SELECT r.id, r.title, r.emoji, r.created_at, host.name AS host_name, host.username AS host_username,
        (SELECT COUNT(*) FROM memberships m WHERE m.round_id = r.id) AS member_count
      FROM rounds r LEFT JOIN users host ON host.id = r.host_id
      WHERE LOWER(r.title) LIKE ? OR LOWER(host.name) LIKE ? OR LOWER(host.username) LIKE ?
      ORDER BY r.created_at DESC LIMIT 200
    `).all('%' + q + '%', '%' + q + '%', '%' + q + '%');
  } else {
    rows = await db.prepare(`
      SELECT r.id, r.title, r.emoji, r.created_at, host.name AS host_name, host.username AS host_username,
        (SELECT COUNT(*) FROM memberships m WHERE m.round_id = r.id) AS member_count
      FROM rounds r LEFT JOIN users host ON host.id = r.host_id
      ORDER BY r.created_at DESC LIMIT 200
    `).all();
  }
  res.json({ rounds: rows });
});

// Permanently delete any Round (admin only) — for rule violations, spam, etc.
// Unlike the host's own delete, this notifies the host with an optional reason.
app.post('/api/admin/rounds/:id/delete', requireAuth, requireAdmin, async (req, res) => {
  const { reason } = req.body || {};
  const round = await db.prepare('SELECT id, title, host_id FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'That Round no longer exists.' });
  await db.prepare('DELETE FROM messages WHERE round_id = ?').run(req.params.id);
  await db.prepare('DELETE FROM memberships WHERE round_id = ?').run(req.params.id);
  await db.prepare('DELETE FROM rounds WHERE id = ?').run(req.params.id);
  if (round.host_id) {
    await pushNotif(
      round.host_id,
      'round_removed',
      'A Round you hosted was removed',
      '"' + round.title + '" was removed by our team for violating community guidelines.' + (reason ? ' Reason: ' + reason : ''),
      null
    );
  }
  res.json({ ok: true });
});


// ---- Rounds ----
app.get('/api/rounds', requireAuth, async (req, res) => {
  const rounds = await db.prepare(`
    SELECT r.*,
      (SELECT COUNT(*) FROM memberships m WHERE m.round_id = r.id) AS member_count,
      EXISTS(SELECT 1 FROM memberships m WHERE m.round_id = r.id AND m.user_id = ?) AS joined,
      (r.host_id = ?) AS is_host,
      (SELECT COUNT(*) FROM round_reactions rr WHERE rr.round_id = r.id AND rr.type='like') AS like_count,
      (SELECT COUNT(*) FROM round_reactions rr WHERE rr.round_id = r.id AND rr.type='love') AS love_count,
      EXISTS(SELECT 1 FROM round_reactions rr WHERE rr.round_id = r.id AND rr.user_id = ? AND rr.type='like') AS i_liked,
      EXISTS(SELECT 1 FROM round_reactions rr WHERE rr.round_id = r.id AND rr.user_id = ? AND rr.type='love') AS i_loved,
      EXISTS(SELECT 1 FROM saved_rounds sr WHERE sr.round_id = r.id AND sr.user_id = ?) AS i_saved
    FROM rounds r ORDER BY r.created_at DESC
  `).all(req.user.id, req.user.id, req.user.id, req.user.id, req.user.id);
  // attach up to 4 member avatars for the card preview
  const avStmt = db.prepare(`SELECT u.avatar FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.round_id=? ORDER BY m.joined_at ASC LIMIT 4`);
  for (const r of rounds) {
    const avRows = await avStmt.all(r.id);
    r.member_avatars = avRows.map(x => x.avatar || '').filter(Boolean);
  }
  res.json({ rounds });
});

// Toggle save/bookmark on a Round
app.post('/api/rounds/:id/save', requireAuth, async (req, res) => {
  const round = await db.prepare('SELECT id FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'Round not found.' });
  const existing = await db.prepare('SELECT 1 FROM saved_rounds WHERE round_id=? AND user_id=?').get(req.params.id, req.user.id);
  if (existing) await db.prepare('DELETE FROM saved_rounds WHERE round_id=? AND user_id=?').run(req.params.id, req.user.id);
  else await db.prepare('INSERT INTO saved_rounds (round_id,user_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(req.params.id, req.user.id, now());
  res.json({ ok: true, saved: !existing });
});

// List Rounds the user has saved
app.get('/api/saved-rounds', requireAuth, async (req, res) => {
  const rounds = await db.prepare(`
    SELECT r.*,
      (SELECT COUNT(*) FROM memberships m WHERE m.round_id = r.id) AS member_count,
      EXISTS(SELECT 1 FROM memberships m WHERE m.round_id = r.id AND m.user_id = ?) AS joined,
      1 AS i_saved
    FROM rounds r JOIN saved_rounds sr ON sr.round_id = r.id
    WHERE sr.user_id = ? ORDER BY sr.created_at DESC
  `).all(req.user.id, req.user.id);
  res.json({ rounds });
});

// Toggle a like/love reaction on a Round
app.post('/api/rounds/:id/react', requireAuth, async (req, res) => {
  const { type } = req.body || {};
  if (!['like', 'love'].includes(type)) return res.status(400).json({ error: 'Invalid reaction.' });
  const round = await db.prepare('SELECT id FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'Round not found.' });
  const existing = await db.prepare('SELECT 1 FROM round_reactions WHERE round_id=? AND user_id=? AND type=?').get(req.params.id, req.user.id, type);
  if (existing) {
    await db.prepare('DELETE FROM round_reactions WHERE round_id=? AND user_id=? AND type=?').run(req.params.id, req.user.id, type);
  } else {
    await db.prepare('INSERT INTO round_reactions (round_id,user_id,type,created_at) VALUES (?,?,?,?) ON CONFLICT DO NOTHING').run(req.params.id, req.user.id, type, now());
  }
  const like_count = Number((await db.prepare("SELECT COUNT(*) c FROM round_reactions WHERE round_id=? AND type='like'").get(req.params.id)).c) || 0;
  const love_count = Number((await db.prepare("SELECT COUNT(*) c FROM round_reactions WHERE round_id=? AND type='love'").get(req.params.id)).c) || 0;
  res.json({ ok: true, like_count, love_count, active: !existing });
});


// Basic safe-URL check: only http/https, reasonable length
// Domains/keywords we refuse to attach to Rounds. Not exhaustive — a first line of defense.
const BLOCKED_URL_PATTERNS = [
  'porn', 'xxx', 'xvideos', 'xnxx', 'pornhub', 'redtube', 'youporn', 'xhamster',
  'onlyfans', 'brazzers', 'nsfw', 'escort', 'camgirl', 'sex-', 'adult-', 'hentai',
  'darkweb', 'silkroad', 'drugs-', 'buyweed', 'cocaine', 'counterfeit', 'stolen',
  'warez', 'crackz', 'torrent', 'piratebay', '1337x', 'gambling', 'casino-', 'betting-'
];
function urlIsBlocked(s) {
  const low = s.toLowerCase();
  let host = '';
  try { host = new URL(low).hostname; } catch (e) { host = low; }
  return BLOCKED_URL_PATTERNS.some(p => host.includes(p) || low.includes(p));
}
function safeUrl(u) {
  if (!u) return null;
  const s = String(u).trim();
  if (!/^https?:\/\/[^\s]+\.[^\s]+/i.test(s)) return null;
  if (urlIsBlocked(s)) return null; // silently drop unsafe links
  return s.slice(0, 500);
}

app.post('/api/rounds', requireAuth, async (req, res) => {
  const { title, emoji, category, blurb, lat, lng, place, photo, link, event_at } = req.body || {};
  if (!title) return res.status(400).json({ error: 'Give your Round a name.' });
  // Validate/flag any attached link
  if (link && String(link).trim()) {
    const raw = String(link).trim();
    if (!/^https?:\/\//i.test(raw)) return res.status(400).json({ error: 'Links must start with http:// or https://' });
    if (urlIsBlocked(raw)) return res.status(400).json({ error: '🚫 That link was blocked. Links to adult or unsafe sites are not allowed on ShowUpp.' });
  }
  const round = {
    id: id(), title: String(title).trim(), emoji: emoji || '✨',
    category: category || 'General', blurb: blurb || '',
    host_id: req.user.id, created_at: now(),
    lat: (typeof lat === 'number') ? lat : null,
    lng: (typeof lng === 'number') ? lng : null,
    place: place || null,
    photo: (photo && String(photo).startsWith('data:image')) ? String(photo).slice(0, 3000000) : null,
    link: safeUrl(link),
    event_at: (typeof event_at === 'number' && event_at > 0) ? event_at : null
  };
  await db.prepare(`INSERT INTO rounds (id,title,emoji,category,blurb,host_id,created_at,lat,lng,place,photo,link,event_at)
              VALUES (@id,@title,@emoji,@category,@blurb,@host_id,@created_at,@lat,@lng,@place,@photo,@link,@event_at)`).run(round);
  await db.prepare('INSERT INTO memberships (round_id,user_id,joined_at) VALUES (?,?,?) ON CONFLICT DO NOTHING')
    .run(round.id, req.user.id, now());
  res.json({ round });
});

// Edit a Round — only the host
app.post('/api/rounds/:id/edit', requireAuth, async (req, res) => {
  const round = await db.prepare('SELECT * FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'That Round no longer exists.' });
  if (round.host_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can edit this Round.' });
  const { title, emoji, category, blurb, place, photo, link, event_at, removePhoto } = req.body || {};
  const newPhoto = removePhoto ? null : ((photo && String(photo).startsWith('data:image')) ? String(photo).slice(0, 3000000) : round.photo);
  await db.prepare(`UPDATE rounds SET
      title = COALESCE(?, title),
      emoji = COALESCE(?, emoji),
      category = COALESCE(?, category),
      blurb = COALESCE(?, blurb),
      place = COALESCE(?, place),
      photo = ?,
      link = ?,
      event_at = ?
    WHERE id = ?`).run(
    title ? String(title).trim() : null,
    emoji || null, category || null,
    (blurb !== undefined && blurb !== null) ? String(blurb) : null,
    (place !== undefined && place !== null) ? String(place) : null,
    newPhoto,
    (link !== undefined) ? safeUrl(link) : round.link,
    (typeof event_at === 'number') ? (event_at > 0 ? event_at : null) : round.event_at,
    req.params.id
  );
  res.json({ round: await db.prepare('SELECT * FROM rounds WHERE id = ?').get(req.params.id) });
});

// Remove / block a member from a Round — only the host
app.post('/api/rounds/:id/remove-member', requireAuth, async (req, res) => {
  const round = await db.prepare('SELECT host_id FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'That Round no longer exists.' });
  if (round.host_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can remove members.' });
  const { userId } = req.body || {};
  if (!userId || userId === req.user.id) return res.status(400).json({ error: 'Invalid member.' });
  await db.prepare('DELETE FROM memberships WHERE round_id = ? AND user_id = ?').run(req.params.id, userId);
  res.json({ ok: true });
});

// List members of a Round (host sees a manage list)
app.get('/api/rounds/:id/members', requireAuth, async (req, res) => {
  // Anyone signed in can see who's in a Round — this helps people decide whether to join.
  // Only public fields are returned (never email/phone).
  const round = await db.prepare('SELECT host_id FROM rounds WHERE id=?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'That Round no longer exists.' });
  const rows = await db.prepare(`SELECT u.id,u.name,u.username,u.avatar,u.city,m.rsvp FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.round_id=? ORDER BY m.joined_at ASC`).all(req.params.id);
  res.json({ members: rows, host_id: round ? round.host_id : null, isHost: round && round.host_id === req.user.id });
});

// RSVP to a Round event
app.post('/api/rounds/:id/rsvp', requireAuth, async (req, res) => {
  const { rsvp } = req.body || {};
  if (!['going', 'maybe', 'no'].includes(rsvp)) return res.status(400).json({ error: 'Invalid RSVP.' });
  const member = await db.prepare('SELECT 1 FROM memberships WHERE round_id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Join the Round first.' });
  await db.prepare('UPDATE memberships SET rsvp = ? WHERE round_id = ? AND user_id = ?').run(rsvp, req.params.id, req.user.id);
  const counts = await db.prepare(`SELECT rsvp, COUNT(*) AS c FROM memberships WHERE round_id=? AND rsvp IS NOT NULL GROUP BY rsvp`).all(req.params.id);
  res.json({ ok: true, counts });
});

// ---- Custom categories (user-suggested, moderated) ----
const BANNED_WORDS = ['fuck','shit','bitch','cunt','nigger','faggot','rape','porn','sex','nazi','kill','slut','whore','pedo','molest'];
function cleanCategoryName(raw) {
  const s = String(raw || '').trim().replace(/\s+/g, ' ').slice(0, 30);
  if (s.length < 2) return null;
  const low = s.toLowerCase();
  for (const w of BANNED_WORDS) { if (low.includes(w)) return false; }
  return s;
}
app.get('/api/categories', requireAuth, async (req, res) => {
  const rows = await db.prepare('SELECT name, emoji FROM categories WHERE approved = 1 ORDER BY name ASC').all();
  res.json({ categories: rows });
});
app.post('/api/categories', requireAuth, async (req, res) => {
  const { name, emoji } = req.body || {};
  const clean = cleanCategoryName(name);
  if (clean === null) return res.status(400).json({ error: 'Category name too short.' });
  if (clean === false) return res.status(400).json({ error: "That category name isn't allowed. Try another." });
  const existing = await db.prepare('SELECT name, approved FROM categories WHERE LOWER(name) = LOWER(?)').get(clean);
  if (existing) return res.json({ ok: true, name: existing.name, approved: !!existing.approved });
  await db.prepare('INSERT INTO categories (name,emoji,created_by,approved,created_at) VALUES (?,?,?,0,?)')
    .run(clean, emoji || '✨', req.user.id, now());
  res.json({ ok: true, name: clean, approved: false, pending: true });
});
app.get('/api/admin/categories', requireAdmin, async (req, res) => {
  const rows = await db.prepare('SELECT * FROM categories ORDER BY approved ASC, created_at DESC').all();
  res.json({ categories: rows });
});
app.post('/api/admin/categories/approve', requireAdmin, async (req, res) => {
  const { name, approve } = req.body || {};
  if (approve) await db.prepare('UPDATE categories SET approved = 1 WHERE name = ?').run(name);
  else await db.prepare('DELETE FROM categories WHERE name = ?').run(name);
  res.json({ ok: true });
});

// ---- Public events ("Happening Nearby") ----
// Source-agnostic: community-posted events live in the DB; paid providers can be
// ingested into the same table with source != 'community'. The list endpoint merges
// everything and filters by distance, so adding a provider needs NO change here.
function distanceMiles(lat1, lng1, lat2, lng2) {
  const toRad = d => d * Math.PI / 180;
  const R = 3958.8; // Earth radius in miles
  const dLat = toRad(lat2 - lat1), dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// PROVIDER REGISTRY — one entry per event-account type the Manager panel can offer.
// Each function takes (apiKey, lat, lng, radiusMi, label) and returns normalized events.
// To support a new paid source later (Eventbrite, SeatGeek, etc.), add a key here and
// list it in the Manager panel's provider dropdown — nothing else needs to change.
const EVENT_PROVIDERS = {
  ticketmaster: async (apiKey, lat, lng, radiusMi, label) => {
    if (!apiKey || typeof lat !== 'number' || typeof lng !== 'number') return [];
    const km = Math.round(radiusMi * 1.60934);
    const url = `https://app.ticketmaster.com/discovery/v2/events.json?apikey=${encodeURIComponent(apiKey)}&latlong=${lat},${lng}&radius=${km}&unit=km&size=50&sort=date,asc`;
    const r = await fetch(url);
    if (!r.ok) return [];
    const data = await r.json();
    const evs = (data._embedded && data._embedded.events) || [];
    return evs.map(e => {
      const v = (e._embedded && e._embedded.venues && e._embedded.venues[0]) || {};
      const loc = v.location || {};
      return {
        id: 'tm_' + e.id, source: 'ticketmaster', source_id: e.id,
        title: e.name, description: (e.info || e.pleaseNote || ''),
        category: (e.classifications && e.classifications[0] && e.classifications[0].segment && e.classifications[0].segment.name) || 'Event',
        emoji: '🎟️',
        photo: (e.images && e.images[0] && e.images[0].url) || null,
        link: e.url || null,
        place: v.name || (v.city && v.city.name) || '',
        lat: loc.latitude ? parseFloat(loc.latitude) : null,
        lng: loc.longitude ? parseFloat(loc.longitude) : null,
        starts_at: (e.dates && e.dates.start && e.dates.start.dateTime) ? new Date(e.dates.start.dateTime).getTime() : null,
        ends_at: null, source_label: label || 'Ticketmaster'
      };
    });
  }
  // Add more providers here later the same way, e.g.:
  //   eventbrite: async (apiKey, lat, lng, radiusMi, label) => { ...map their API... }
};

// Pulls events from every enabled account the Manager panel has configured, plus a
// Ticketmaster key set via env var as a fallback for people who deploy that way instead.
async function fetchExternalEvents(lat, lng, radiusMi) {
  const external = [];
  if (typeof lat !== 'number' || typeof lng !== 'number') return external;
  const sources = await db.prepare('SELECT * FROM event_sources WHERE enabled = 1').all();
  for (const s of sources) {
    const fn = EVENT_PROVIDERS[s.provider];
    if (!fn) continue;
    try { external.push(...(await fn(s.api_key, lat, lng, radiusMi, s.label))); }
    catch (err) { console.log('[events]', s.provider, 'error', err.message); }
  }
  if (process.env.TICKETMASTER_API_KEY && !sources.some(s => s.provider === 'ticketmaster')) {
    try { external.push(...(await EVENT_PROVIDERS.ticketmaster(process.env.TICKETMASTER_API_KEY, lat, lng, radiusMi, 'Ticketmaster'))); }
    catch (err) {}
  }
  return external;
}

// List events near a location, within radius (default 25 miles), optional category filter.
app.get('/api/events', requireAuth, async (req, res) => {
  const lat = parseFloat(req.query.lat), lng = parseFloat(req.query.lng);
  const radius = Math.min(parseFloat(req.query.radius) || 25, 100);
  const category = req.query.category || null;
  const hasLoc = !isNaN(lat) && !isNaN(lng);

  // 1) community events from our DB (only upcoming, approved)
  let community = await db.prepare(`SELECT * FROM events WHERE approved = 1 AND source = 'community'
    AND (starts_at IS NULL OR starts_at > ?) ORDER BY starts_at ASC LIMIT 200`).all(now() - 6 * 3600 * 1000);
  community = community.map(e => ({ ...e, source_label: 'Community' }));

  // 2) external providers (Ticketmaster etc.) — only if configured & we have a location
  let external = [];
  if (hasLoc) {
    try { external = await fetchExternalEvents(lat, lng, radius); } catch (e) {}
  }

  // merge, attach distance, filter by radius + category
  let all = community.concat(external);
  all = all.map(e => {
    let dist = null;
    if (hasLoc && typeof e.lat === 'number' && typeof e.lng === 'number') dist = distanceMiles(lat, lng, e.lat, e.lng);
    return { ...e, distance: dist };
  });
  if (hasLoc) all = all.filter(e => e.distance == null || e.distance <= radius);
  if (category && category !== 'all') all = all.filter(e => (e.category || '').toLowerCase() === category.toLowerCase());
  // sort: soonest first, then nearest
  all.sort((a, b) => (a.starts_at || Infinity) - (b.starts_at || Infinity) || (a.distance || 0) - (b.distance || 0));

  res.json({ events: all, providers: { ticketmaster: !!process.env.TICKETMASTER_API_KEY } });
});

// Post a community event
app.post('/api/events', requireAuth, async (req, res) => {
  const { title, description, category, emoji, photo, link, place, lat, lng, starts_at, ends_at } = req.body || {};
  if (!title || !String(title).trim()) return res.status(400).json({ error: 'Give the event a name.' });
  const ev = {
    id: id(), source: 'community', source_id: null,
    title: String(title).trim().slice(0, 120),
    description: String(description || '').slice(0, 1000),
    category: category || 'Event', emoji: emoji || '📣',
    photo: (photo && String(photo).startsWith('data:image')) ? String(photo).slice(0, 3000000) : null,
    link: safeUrl(link), place: String(place || '').slice(0, 200),
    lat: (typeof lat === 'number') ? lat : null,
    lng: (typeof lng === 'number') ? lng : null,
    starts_at: (typeof starts_at === 'number' && starts_at > 0) ? starts_at : null,
    ends_at: (typeof ends_at === 'number' && ends_at > 0) ? ends_at : null,
    posted_by: req.user.id, approved: 1, created_at: now()
  };
  await db.prepare(`INSERT INTO events (id,source,source_id,title,description,category,emoji,photo,link,place,lat,lng,starts_at,ends_at,posted_by,approved,created_at)
    VALUES (@id,@source,@source_id,@title,@description,@category,@emoji,@photo,@link,@place,@lat,@lng,@starts_at,@ends_at,@posted_by,@approved,@created_at)`).run(ev);
  res.json({ event: ev });
});

// Delete a community event (poster or admin)
app.post('/api/events/:id/delete', requireAuth, async (req, res) => {
  const ev = await db.prepare('SELECT posted_by FROM events WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Event not found.' });
  if (ev.posted_by !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'Not allowed.' });
  await db.prepare('DELETE FROM events WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---- Manager panel: event-account sources (admin only) ----
// Lists configured accounts. API keys are masked (only the last 4 chars shown) so the
// key isn't echoed back in full once it's saved.
app.get('/api/admin/event-sources', requireAuth, requireAdmin, async (req, res) => {
  const rows = await db.prepare('SELECT id, provider, label, api_key, enabled, created_at FROM event_sources ORDER BY created_at DESC').all();
  const masked = rows.map(r => ({
    ...r,
    api_key: r.api_key ? '••••••••' + String(r.api_key).slice(-4) : ''
  }));
  res.json({ sources: masked, availableProviders: Object.keys(EVENT_PROVIDERS) });
});

// Add a new event-account (e.g. a Ticketmaster API key) — the events filter will start
// pulling from it automatically the next time someone searches Nearby.
app.post('/api/admin/event-sources', requireAuth, requireAdmin, async (req, res) => {
  const { provider, label, apiKey } = req.body || {};
  if (!provider || !EVENT_PROVIDERS[provider]) return res.status(400).json({ error: 'Unknown provider.' });
  if (!apiKey || !String(apiKey).trim()) return res.status(400).json({ error: 'An API key is required.' });
  const row = {
    id: id(), provider: String(provider), label: String(label || '').slice(0, 80) || provider,
    api_key: String(apiKey).trim(), enabled: 1, created_by: req.user.id, created_at: now()
  };
  await db.prepare(`INSERT INTO event_sources (id,provider,label,api_key,enabled,created_by,created_at)
    VALUES (@id,@provider,@label,@api_key,@enabled,@created_by,@created_at)`).run(row);
  res.json({ ok: true, id: row.id });
});

// Toggle an account on/off without deleting its saved key
app.post('/api/admin/event-sources/:id/toggle', requireAuth, requireAdmin, async (req, res) => {
  const src = await db.prepare('SELECT id, enabled FROM event_sources WHERE id = ?').get(req.params.id);
  if (!src) return res.status(404).json({ error: 'Not found.' });
  await db.prepare('UPDATE event_sources SET enabled = ? WHERE id = ?').run(src.enabled ? 0 : 1, req.params.id);
  res.json({ ok: true, enabled: !src.enabled });
});

// Remove an account entirely
app.post('/api/admin/event-sources/:id/delete', requireAuth, requireAdmin, async (req, res) => {
  const src = await db.prepare('SELECT id FROM event_sources WHERE id = ?').get(req.params.id);
  if (!src) return res.status(404).json({ error: 'Not found.' });
  await db.prepare('DELETE FROM event_sources WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});




// Delete a Round — only the host (creator) can do this
app.post('/api/rounds/:id/delete', requireAuth, async (req, res) => {
  const round = await db.prepare('SELECT host_id FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'That Round no longer exists.' });
  if (round.host_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can delete this Round.' });
  await db.prepare('DELETE FROM messages WHERE round_id = ?').run(req.params.id);
  await db.prepare('DELETE FROM memberships WHERE round_id = ?').run(req.params.id);
  await db.prepare('DELETE FROM rounds WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/rounds/:id/join', requireAuth, async (req, res) => {
  const round = await db.prepare('SELECT id FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'That Round no longer exists.' });
  await db.prepare('INSERT INTO memberships (round_id,user_id,joined_at) VALUES (?,?,?) ON CONFLICT DO NOTHING')
    .run(req.params.id, req.user.id, now());
  res.json({ ok: true });
});

// Leave a Round the user has joined. This removes them from both the Round and its
// group chat at once, since Round membership *is* chat membership — there's no
// separate leave-the-chat-but-stay-in-the-Round state. Hosts can't leave their own
// Round this way (they'd orphan it); they need to delete it or hand off hosting.
app.post('/api/rounds/:id/leave', requireAuth, async (req, res) => {
  const round = await db.prepare('SELECT host_id FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'That Round no longer exists.' });
  if (round.host_id === req.user.id) {
    return res.status(400).json({ error: "You're hosting this Round — delete it or transfer hosting instead of leaving." });
  }
  const member = await db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!member) return res.status(400).json({ error: "You're not a member of this Round." });
  await db.prepare('DELETE FROM memberships WHERE round_id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// Rounds the current user belongs to (their "Circles")
app.get('/api/my-rounds', requireAuth, async (req, res) => {
  const rounds = await db.prepare(`
    SELECT r.*,
      (SELECT COUNT(*) FROM memberships m WHERE m.round_id = r.id) AS member_count,
      (r.host_id = ?) AS is_host,
      1 AS joined,
      EXISTS(SELECT 1 FROM saved_rounds sr WHERE sr.round_id = r.id AND sr.user_id = ?) AS i_saved,
      COALESCE(mm.last_read, 0) AS my_last_read
    FROM rounds r
    JOIN memberships mm ON mm.round_id = r.id
    WHERE mm.user_id = ?
    ORDER BY r.created_at DESC
  `).all(req.user.id, req.user.id, req.user.id);
  // Attach how many messages in each Round the user hasn't seen yet
  for (const r of rounds) {
    r.unread = Number((await db.prepare(
      'SELECT COUNT(*) AS c FROM messages WHERE round_id = ? AND created_at > ? AND user_id != ?'
    ).get(r.id, r.my_last_read || 0, req.user.id)).c) || 0;
  }
  res.json({ rounds });
});

// Mark a Round's chat as read up to now
app.post('/api/rounds/:id/read', requireAuth, async (req, res) => {
  await db.prepare('UPDATE memberships SET last_read = ? WHERE round_id = ? AND user_id = ?')
    .run(now(), req.params.id, req.user.id);
  res.json({ ok: true });
});

// ---- Messages (history) ----
app.get('/api/rounds/:id/messages', requireAuth, async (req, res) => {
  const member = await db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Join this Round to see its chat.' });
  const rows = await db.prepare(`
    SELECT m.id, m.body, m.created_at, m.user_id, u.name AS sender,
           m.reactions, m.reply_to, m.reply_preview, m.kind, m.media_url, m.ephemeral, m.seen_by, m.deleted, m.edited
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.round_id = ? ORDER BY m.created_at ASC LIMIT 200
  `).all(req.params.id);
  // For ephemeral messages the current user has already seen (and isn't the sender), delete + hide
  const out = [];
  for (const m of rows) {
    if (m.ephemeral && m.user_id !== req.user.id) {
      const seen = m.seen_by ? JSON.parse(m.seen_by) : [];
      if (seen.includes(req.user.id)) {
        await db.prepare('DELETE FROM messages WHERE id = ?').run(m.id); // it's been read once by this viewer
        continue;
      } else {
        seen.push(req.user.id);
        await db.prepare('UPDATE messages SET seen_by = ? WHERE id = ?').run(JSON.stringify(seen), m.id);
      }
    }
    out.push({
      id: m.id, body: m.body, created_at: m.created_at, user_id: m.user_id, sender: m.sender,
      reactions: m.reactions ? JSON.parse(m.reactions) : {},
      reply_to: m.reply_to || null, reply_preview: m.reply_preview || null,
      kind: m.kind || 'text', media_url: m.media_url || null, ephemeral: !!m.ephemeral, deleted: !!m.deleted, edited: !!m.edited
    });
  }
  res.json({ messages: out });
});

// React to a message (toggle emoji)
app.post('/api/messages/:id/react', requireAuth, async (req, res) => {
  const { emoji } = req.body || {};
  if (!emoji) return res.status(400).json({ error: 'No emoji.' });
  const m = await db.prepare('SELECT id, round_id, reactions FROM messages WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Message gone.' });
  const member = await db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?').get(m.round_id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Not a member.' });
  const reactions = m.reactions ? JSON.parse(m.reactions) : {};
  const users = reactions[emoji] || [];
  const idx = users.indexOf(req.user.id);
  if (idx >= 0) users.splice(idx, 1); else users.push(req.user.id);
  if (users.length) reactions[emoji] = users; else delete reactions[emoji];
  await db.prepare('UPDATE messages SET reactions = ? WHERE id = ?').run(JSON.stringify(reactions), req.params.id);
  // broadcast the reaction update
  const payload = JSON.stringify({ type: 'reaction', roundId: m.round_id, messageId: req.params.id, reactions });
  wss.clients.forEach(c => { if (c.readyState === 1 && c.rooms && c.rooms.has(m.round_id)) c.send(payload); });
  res.json({ ok: true, reactions });
});

// Unsend a Round chat message — sender or the Round's host can remove it for everyone.
// We soft-delete (keep the row, blank the body) so reply-previews pointing at it don't break.
app.post('/api/messages/:id/delete', requireAuth, async (req, res) => {
  const m = await db.prepare('SELECT id, round_id, user_id FROM messages WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Message already gone.' });
  const round = await db.prepare('SELECT host_id FROM rounds WHERE id = ?').get(m.round_id);
  const isHost = round && round.host_id === req.user.id;
  if (m.user_id !== req.user.id && !isHost) return res.status(403).json({ error: 'You can only unsend your own messages.' });
  await db.prepare("UPDATE messages SET deleted = 1, body = '', media_url = NULL, reactions = NULL WHERE id = ?").run(req.params.id);
  const payload = JSON.stringify({ type: 'messageDeleted', roundId: m.round_id, messageId: req.params.id });
  wss.clients.forEach(c => { if (c.readyState === 1 && c.rooms && c.rooms.has(m.round_id)) c.send(payload); });
  res.json({ ok: true });
});

// Edit a Round chat message — sender only, and only plain text messages (not GIFs/media).
app.post('/api/messages/:id/edit', requireAuth, async (req, res) => {
  const { body } = req.body || {};
  const text = String(body || '').trim();
  if (!text) return res.status(400).json({ error: 'Message cannot be empty.' });
  const m = await db.prepare('SELECT id, round_id, user_id, deleted, kind FROM messages WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Message not found.' });
  if (m.deleted) return res.status(400).json({ error: "Can't edit an unsent message." });
  if (m.user_id !== req.user.id) return res.status(403).json({ error: 'You can only edit your own messages.' });
  if (m.kind && m.kind !== 'text') return res.status(400).json({ error: 'Only text messages can be edited.' });
  await db.prepare('UPDATE messages SET body = ?, edited = 1 WHERE id = ?').run(text, req.params.id);
  const payload = JSON.stringify({ type: 'messageEdited', roundId: m.round_id, messageId: req.params.id, body: text });
  wss.clients.forEach(c => { if (c.readyState === 1 && c.rooms && c.rooms.has(m.round_id)) c.send(payload); });
  res.json({ ok: true });
});

// --- HTTP + WebSocket server share one port ---
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 10 * 1024 * 1024 });

/*
 * WebSocket protocol (simple JSON messages):
 *   client -> server: { type:'auth', token }
 *   client -> server: { type:'join', roundId }
 *   client -> server: { type:'message', roundId, body }
 *   server -> client: { type:'message', roundId, message:{...} }
 *   server -> client: { type:'error', error }
 */
wss.on('connection', (ws) => {
  ws.user = null;
  ws.rooms = new Set();

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'auth') {
      const user = await authFromToken(msg.token);
      if (!user) { ws.send(JSON.stringify({ type: 'error', error: 'auth failed' })); return; }
      ws.user = user;
      ws.send(JSON.stringify({ type: 'ready' }));
      return;
    }

    if (!ws.user) { ws.send(JSON.stringify({ type: 'error', error: 'not authed' })); return; }

    if (msg.type === 'join') {
      const member = await db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?')
        .get(msg.roundId, ws.user.id);
      if (member) ws.rooms.add(msg.roundId);
      return;
    }

    if (msg.type === 'message') {
      const MEDIA_KINDS = ['gif', 'image', 'video'];
      const kind = MEDIA_KINDS.includes(msg.kind) ? msg.kind : 'text';
      const body = String(msg.body || '').trim();
      // data URLs for images/videos can be large; allow up to ~8MB of characters
      const mediaUrl = (kind !== 'text') ? String(msg.mediaUrl || '').slice(0, 8500000) : null;
      if (kind === 'text' && !body) return;
      if (kind !== 'text' && !mediaUrl) return;
      const member = await db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?')
        .get(msg.roundId, ws.user.id);
      if (!member) { ws.send(JSON.stringify({ type: 'error', error: 'not a member' })); return; }

      const replyTo = msg.replyTo ? String(msg.replyTo) : null;
      const replyPreview = msg.replyPreview ? String(msg.replyPreview).slice(0, 120) : null;
      const ephemeral = msg.ephemeral ? 1 : 0;

      const record = {
        id: id(), round_id: msg.roundId, user_id: ws.user.id, body, created_at: now(),
        reply_to: replyTo, reply_preview: replyPreview, kind, media_url: mediaUrl,
        ephemeral, seen_by: JSON.stringify([])
      };
      await db.prepare(`INSERT INTO messages (id,round_id,user_id,body,created_at,reply_to,reply_preview,kind,media_url,ephemeral,seen_by)
        VALUES (@id,@round_id,@user_id,@body,@created_at,@reply_to,@reply_preview,@kind,@media_url,@ephemeral,@seen_by)`).run(record);

      const outbound = JSON.stringify({
        type: 'message',
        roundId: msg.roundId,
        message: {
          id: record.id, body, created_at: record.created_at, user_id: ws.user.id, sender: ws.user.name,
          reply_to: replyTo, reply_preview: replyPreview, kind, media_url: mediaUrl, ephemeral: !!ephemeral, reactions: {}
        }
      });
      wss.clients.forEach((client) => {
        if (client.readyState === 1 && client.rooms && client.rooms.has(msg.roundId)) {
          client.send(outbound);
        }
      });
    }

    // Direct / group conversation messages
    if (msg.type === 'dm') {
      const MEDIA_KINDS = ['gif', 'image', 'video'];
      const kind = MEDIA_KINDS.includes(msg.kind) ? msg.kind : 'text';
      const body = String(msg.body || '').trim();
      const mediaUrl = (kind !== 'text') ? String(msg.mediaUrl || '').slice(0, 8500000) : null;
      if (kind === 'text' && !body) return;
      if (kind !== 'text' && !mediaUrl) return;
      const member = await db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(msg.convId, ws.user.id);
      if (!member) { ws.send(JSON.stringify({ type: 'error', error: 'not in conversation' })); return; }

      const record = { id: id(), conv_id: msg.convId, user_id: ws.user.id, body, kind, media_url: mediaUrl, created_at: now(),
        reply_to: msg.replyTo ? String(msg.replyTo) : null,
        reply_preview: msg.replyPreview ? String(msg.replyPreview).slice(0, 120) : null };
      await db.prepare('INSERT INTO dm_messages (id,conv_id,user_id,body,kind,media_url,created_at,reply_to,reply_preview) VALUES (@id,@conv_id,@user_id,@body,@kind,@media_url,@created_at,@reply_to,@reply_preview)').run(record);

      const outbound = JSON.stringify({
        type: 'dm',
        convId: msg.convId,
        message: { id: record.id, body, kind, media_url: mediaUrl, created_at: record.created_at, user_id: ws.user.id, sender: ws.user.name, avatar: ws.user.avatar || '', reply_to: record.reply_to, reply_preview: record.reply_preview, reactions: {} }
      });
      // deliver to connected members in that conversation room; notify the rest
      const members = (await db.prepare('SELECT user_id FROM conversation_members WHERE conv_id=?').all(msg.convId)).map(r => r.user_id);
      const connectedUserIds = new Set();
      wss.clients.forEach((client) => {
        if (client.readyState === 1 && client.dmRooms && client.dmRooms.has(msg.convId)) {
          client.send(outbound);
          if (client.user) connectedUserIds.add(client.user.id);
        }
      });
      // notification for members not currently viewing the conversation
      for (const uid of members) {
        if (uid === ws.user.id) continue;
        if (!connectedUserIds.has(uid)) {
          await pushNotif(uid, 'dm', ws.user.name || 'New message', kind === 'gif' ? 'Sent a GIF' : body.slice(0, 80), 'dm:' + msg.convId);
        }
      }
    }

    if (msg.type === 'joinDm') {
      const member = await db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(msg.convId, ws.user.id);
      if (member) { ws.dmRooms = ws.dmRooms || new Set(); ws.dmRooms.add(msg.convId); }
      // Mark this conversation read for the joiner and notify the room (live read receipts)
      if (member) {
        const ts = now();
        await db.prepare('UPDATE conversation_members SET last_read=? WHERE conv_id=? AND user_id=?').run(ts, msg.convId, ws.user.id);
        const meRow = await db.prepare('SELECT read_receipts FROM users WHERE id=?').get(ws.user.id);
        const payload = JSON.stringify({ type: 'dmRead', convId: msg.convId, readerId: ws.user.id, readAt: ts, receiptsOn: (meRow && meRow.read_receipts !== 0) });
        wss.clients.forEach(c => { if (c.readyState === 1 && c.dmRooms && c.dmRooms.has(msg.convId)) c.send(payload); });
      }
      return;
    }
    if (msg.type === 'dmRead') {
      const member = await db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(msg.convId, ws.user.id);
      if (member) {
        const ts = now();
        await db.prepare('UPDATE conversation_members SET last_read=? WHERE conv_id=? AND user_id=?').run(ts, msg.convId, ws.user.id);
        const meRow = await db.prepare('SELECT read_receipts FROM users WHERE id=?').get(ws.user.id);
        const payload = JSON.stringify({ type: 'dmRead', convId: msg.convId, readerId: ws.user.id, readAt: ts, receiptsOn: (meRow && meRow.read_receipts !== 0) });
        wss.clients.forEach(c => { if (c.readyState === 1 && c.dmRooms && c.dmRooms.has(msg.convId)) c.send(payload); });
      }
      return;
    }
    if (msg.type === 'leaveDm') {
      if (ws.dmRooms) ws.dmRooms.delete(msg.convId);
      return;
    }

    // ---- Voice / video call signaling (friend-only) ----
    // Calls are ONLY allowed between people who share a conversation that is either
    // a 1-on-1 friend DM or a friend group chat. Never for Rounds.
    // ---- Group calls (mesh) for Rounds and friend group chats ----
    // roomType: 'round' | 'conv'; roomId: the round or conversation id.
    if (msg.type === 'group-call-invite' || msg.type === 'group-call-join' ||
        msg.type === 'group-call-leave' || msg.type === 'group-call-offer' ||
        msg.type === 'group-call-answer' || msg.type === 'group-call-ice') {
      if (!ws.user) return;

      // Resolve who is allowed in this call (members of the round or conversation).
      async function roomMemberIds(roomType, roomId) {
        if (roomType === 'round') {
          const rows = await db.prepare('SELECT user_id FROM memberships WHERE round_id = ?').all(roomId);
          return rows.map(r => r.user_id);
        } else {
          const rows = await db.prepare('SELECT user_id FROM conversation_members WHERE conv_id = ?').all(roomId);
          return rows.map(r => r.user_id);
        }
      }

      // The caller must be a member of the room they're signaling in.
      if (msg.type === 'group-call-invite' || msg.type === 'group-call-join') {
        const members = await roomMemberIds(msg.roomType, msg.roomId);
        if (!members.includes(ws.user.id)) {
          ws.send(JSON.stringify({ type: 'call-error', error: 'You are not in this chat.' }));
          return;
        }
      }

      // Broadcast invite/join/leave to all OTHER members; relay targeted offer/answer/ice to one peer.
      if (msg.type === 'group-call-invite' || msg.type === 'group-call-join' || msg.type === 'group-call-leave') {
        const members = await roomMemberIds(msg.roomType, msg.roomId);
        const payload = JSON.stringify({
          type: msg.type, from: ws.user.id, fromName: ws.user.name, fromAvatar: ws.user.avatar || '',
          roomType: msg.roomType, roomId: msg.roomId, media: msg.media || 'video'
        });
        wss.clients.forEach(client => {
          if (client.readyState === 1 && client.user && client.user.id !== ws.user.id && members.includes(client.user.id)) {
            client.send(payload);
          }
        });
      } else {
        // targeted signaling (offer/answer/ice) to a specific peer in the room
        const targetId = msg.to;
        if (!targetId) return;
        const payload = JSON.stringify({
          type: msg.type, from: ws.user.id, fromName: ws.user.name, fromAvatar: ws.user.avatar || '',
          roomType: msg.roomType, roomId: msg.roomId, media: msg.media || 'video',
          sdp: msg.sdp || null, candidate: msg.candidate || null
        });
        wss.clients.forEach(client => {
          if (client.readyState === 1 && client.user && client.user.id === targetId) client.send(payload);
        });
      }
      return;
    }

    if (msg.type === 'call-offer' || msg.type === 'call-answer' || msg.type === 'call-ice' ||
        msg.type === 'call-end' || msg.type === 'call-decline') {
      const targetId = msg.to;
      if (!targetId) return;

      // For a new offer, verify caller and callee are friends (or in a friend group together).
      if (msg.type === 'call-offer') {
        const areFriends = await db.prepare('SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?').get(ws.user.id, targetId);
        let shareFriendGroup = false;
        if (!areFriends) {
          // check they share a non-Round conversation (friend group chat)
          shareFriendGroup = !!await db.prepare(`
            SELECT 1 FROM conversation_members a
            JOIN conversation_members b ON a.conv_id = b.conv_id
            WHERE a.user_id = ? AND b.user_id = ?
          `).get(ws.user.id, targetId);
        }
        if (!areFriends && !shareFriendGroup) {
          ws.send(JSON.stringify({ type: 'call-error', error: 'You can only call friends.' }));
          return;
        }
        if (await isBlocked(ws.user.id, targetId)) {
          ws.send(JSON.stringify({ type: 'call-error', error: 'Unavailable.' }));
          return;
        }
      }

      // Relay the signaling message to the target if they're connected.
      const payload = JSON.stringify({
        type: msg.type,
        from: ws.user.id,
        fromName: ws.user.name,
        fromAvatar: ws.user.avatar || '',
        media: msg.media || 'audio',        // 'audio' or 'video'
        sdp: msg.sdp || null,               // offer/answer
        candidate: msg.candidate || null    // ICE candidate
      });
      let delivered = false;
      wss.clients.forEach((client) => {
        if (client.readyState === 1 && client.user && client.user.id === targetId) {
          client.send(payload);
          delivered = true;
        }
      });
      // If calling someone who's offline, tell the caller.
      if (msg.type === 'call-offer' && !delivered) {
        ws.send(JSON.stringify({ type: 'call-unavailable', to: targetId }));
      }
      return;
    }
  });
});

initDb()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`ShowUpp backend running on port ${PORT}`);
      console.log(`Open http://localhost:${PORT} to use the app.`);
    });
    // Birthday notifications: check shortly after boot, then once every 24 hours.
    setTimeout(() => { checkBirthdays(); }, 15000);
    setInterval(() => { checkBirthdays(); }, 24 * 60 * 60 * 1000);
  })
  .catch((err) => {
    console.error('Failed to initialize the database. Is DATABASE_URL correct?');
    console.error(err.message);
    process.exit(1);
  });
