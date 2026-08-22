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
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// --- Config ---
const PORT = process.env.PORT || 3000;
// In production, set these as environment variables on your host.
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';
// Admin / owner account — seeded on boot so it survives free-tier DB resets.
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@showupp.app';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme123';
const ADMIN_NAME = process.env.ADMIN_NAME || 'ShowUpp Admin';

// --- Database setup ---
// IMPORTANT for data persistence:
// On hosts with an ephemeral filesystem (like Render's free tier), a database file
// stored inside the app folder is WIPED on every deploy/restart — which deletes all
// accounts. To keep data, set DATA_DIR to a mounted persistent disk (e.g. /data on Render)
// and the DB will live there and survive restarts.
const DATA_DIR = process.env.DATA_DIR || __dirname;
let dbPath = path.join(DATA_DIR, 'showupp.db');
try {
  // make sure the directory exists and is writable; otherwise fall back to app dir
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.accessSync(DATA_DIR, fs.constants.W_OK);
} catch (e) {
  console.log('DATA_DIR not writable (' + DATA_DIR + '), falling back to app folder. Set a persistent disk to keep data across restarts.');
  dbPath = path.join(__dirname, 'showupp.db');
}
console.log('Using database at:', dbPath);
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    email      TEXT UNIQUE NOT NULL,
    pass_hash  TEXT NOT NULL,
    name       TEXT NOT NULL,
    city       TEXT,
    origin     TEXT,
    interests  TEXT,           -- JSON array
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS rounds (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    emoji      TEXT,
    category   TEXT,
    blurb      TEXT,
    host_id    TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS memberships (
    round_id  TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (round_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id        TEXT PRIMARY KEY,
    round_id  TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    body      TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS friendships (
    user_id    TEXT NOT NULL,
    friend_id  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, friend_id)
  );

  CREATE TABLE IF NOT EXISTS friend_requests (
    from_id    TEXT NOT NULL,
    to_id      TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (from_id, to_id)
  );

  CREATE TABLE IF NOT EXISTS blocks (
    user_id    TEXT NOT NULL,
    blocked_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, blocked_id)
  );

  CREATE TABLE IF NOT EXISTS reports (
    id          TEXT PRIMARY KEY,
    reporter_id TEXT NOT NULL,
    reported_id TEXT,
    context     TEXT,
    reason      TEXT,
    created_at  INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT PRIMARY KEY,
    is_group   INTEGER DEFAULT 0,
    title      TEXT,
    created_by TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conversation_members (
    conv_id   TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    last_read INTEGER DEFAULT 0,
    PRIMARY KEY (conv_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS dm_messages (
    id         TEXT PRIMARY KEY,
    conv_id    TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    body       TEXT NOT NULL,
    kind       TEXT DEFAULT 'text',
    media_url  TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    type       TEXT,
    title      TEXT,
    body       TEXT,
    link       TEXT,
    read       INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS reset_tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used       INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
  );
`);

// --- Safe migration: add username column if it doesn't exist yet ---
try {
  const cols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
  if (!cols.includes('username')) {
    db.exec("ALTER TABLE users ADD COLUMN username TEXT");
    console.log('Added username column.');
  }
  if (!cols.includes('avatar')) {
    db.exec("ALTER TABLE users ADD COLUMN avatar TEXT");
    console.log('Added avatar column.');
  }
  if (!cols.includes('lang')) {
    db.exec("ALTER TABLE users ADD COLUMN lang TEXT DEFAULT 'en'");
    console.log('Added lang column.');
  }
  if (!cols.includes('is_admin')) {
    db.exec("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0");
    console.log('Added is_admin column.');
  }
  if (!cols.includes('suspended')) {
    db.exec("ALTER TABLE users ADD COLUMN suspended INTEGER DEFAULT 0");
    console.log('Added suspended column.');
  }
} catch (e) { console.log('Migration note:', e.message); }

// --- Safe migration: add messaging feature columns ---
try {
  const mcols = db.prepare("PRAGMA table_info(messages)").all().map(c => c.name);
  if (!mcols.includes('reactions')) { db.exec("ALTER TABLE messages ADD COLUMN reactions TEXT"); console.log('Added messages.reactions'); }
  if (!mcols.includes('reply_to')) { db.exec("ALTER TABLE messages ADD COLUMN reply_to TEXT"); console.log('Added messages.reply_to'); }
  if (!mcols.includes('reply_preview')) { db.exec("ALTER TABLE messages ADD COLUMN reply_preview TEXT"); console.log('Added messages.reply_preview'); }
  if (!mcols.includes('kind')) { db.exec("ALTER TABLE messages ADD COLUMN kind TEXT DEFAULT 'text'"); console.log('Added messages.kind'); }
  if (!mcols.includes('media_url')) { db.exec("ALTER TABLE messages ADD COLUMN media_url TEXT"); console.log('Added messages.media_url'); }
  if (!mcols.includes('ephemeral')) { db.exec("ALTER TABLE messages ADD COLUMN ephemeral INTEGER DEFAULT 0"); console.log('Added messages.ephemeral'); }
  if (!mcols.includes('seen_by')) { db.exec("ALTER TABLE messages ADD COLUMN seen_by TEXT"); console.log('Added messages.seen_by'); }
} catch (e) { console.log('Migration note:', e.message); }

// --- Safe migration: add DM messaging feature columns ---
try {
  const dcols = db.prepare("PRAGMA table_info(dm_messages)").all().map(c => c.name);
  if (!dcols.includes('reactions')) { db.exec("ALTER TABLE dm_messages ADD COLUMN reactions TEXT"); console.log('Added dm_messages.reactions'); }
  if (!dcols.includes('reply_to')) { db.exec("ALTER TABLE dm_messages ADD COLUMN reply_to TEXT"); console.log('Added dm_messages.reply_to'); }
  if (!dcols.includes('reply_preview')) { db.exec("ALTER TABLE dm_messages ADD COLUMN reply_preview TEXT"); console.log('Added dm_messages.reply_preview'); }
} catch (e) { console.log('Migration note:', e.message); }
function seedAdmin() {
  try {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(ADMIN_EMAIL.toLowerCase());
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    if (existing) {
      // keep password in sync with env and ensure admin flag
      db.prepare('UPDATE users SET pass_hash = ?, is_admin = 1 WHERE id = ?').run(hash, existing.id);
    } else {
      db.prepare(`INSERT INTO users (id,email,pass_hash,name,username,city,origin,interests,created_at,is_admin)
                  VALUES (?,?,?,?,?,?,?,?,?,1)`).run(
        crypto.randomUUID(), ADMIN_EMAIL.toLowerCase(), hash, ADMIN_NAME, 'admin',
        '', '', JSON.stringify([]), Date.now());
      console.log('Seeded admin account:', ADMIN_EMAIL);
    }
  } catch (e) { console.log('Admin seed note:', e.message); }
}
seedAdmin();

// --- Safe migration: add location columns to rounds ---
try {
  const rcols = db.prepare("PRAGMA table_info(rounds)").all().map(c => c.name);
  if (!rcols.includes('lat')) { db.exec("ALTER TABLE rounds ADD COLUMN lat REAL"); console.log('Added rounds.lat'); }
  if (!rcols.includes('lng')) { db.exec("ALTER TABLE rounds ADD COLUMN lng REAL"); console.log('Added rounds.lng'); }
  if (!rcols.includes('place')) { db.exec("ALTER TABLE rounds ADD COLUMN place TEXT"); console.log('Added rounds.place'); }
} catch (e) { console.log('Migration note:', e.message); }

// --- Seed a few starter Rounds so the app isn't empty on first run ---
function seedRounds() {
  const count = db.prepare('SELECT COUNT(*) AS c FROM rounds').get().c;
  if (count > 0) return;
  const systemHost = 'system';
  const seed = [
    ['Sunday Sancocho & Domino Nights', '🍳', 'Food', 'Cook, play dominoes, swap stories. Newcomers welcome — just come hungry.'],
    ['Global Book Club', '📚', 'Book Club', 'One book a month, honest conversation, new friends.'],
    ['Weekend Wanderers', '✈️', 'Travel', 'Plan trips together and explore as a group.'],
    ['Newborns & Coffee', '👶', 'New Parents', 'New parents meeting up for walks and cafecito.'],
    ['Foreign Film Fridays', '🎬', 'Movies', 'Watch a film, then talk it over.'],
    ['Saturday Morning Fútbol', '⚽', 'Sports', 'Friendly pickup games every weekend.']
  ];
  const insert = db.prepare(
    'INSERT INTO rounds (id, title, emoji, category, blurb, host_id, created_at) VALUES (?,?,?,?,?,?,?)'
  );
  const now = Date.now();
  for (const [title, emoji, category, blurb] of seed) {
    insert.run(crypto.randomUUID(), title, emoji, category, blurb, systemHost, now);
  }
  console.log('Seeded starter Rounds.');
}
seedRounds();

// --- Helpers ---
const id = () => crypto.randomUUID();
const now = () => Date.now();

function makeToken(user) {
  return jwt.sign({ uid: user.id, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
}

function authFromToken(token) {
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return db.prepare('SELECT id, email, name, username, avatar, city, origin, interests, is_admin, lang FROM users WHERE id = ?').get(payload.uid);
  } catch {
    return null;
  }
}

// Express middleware that requires a valid Bearer token
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const user = token && authFromToken(token);
  if (!user) return res.status(401).json({ error: 'Please log in again.' });
  req.user = user;
  next();
}

function publicUser(u) {
  return {
    id: u.id,
    name: u.name,
    username: u.username || '',
    avatar: u.avatar || '',
    city: u.city,
    origin: u.origin,
    interests: u.interests ? JSON.parse(u.interests) : [],
    isAdmin: !!u.is_admin,
    lang: u.lang || 'en'
  };
}

// --- App ---
const app = express();
app.use(express.json({ limit: '2mb' }));
// Serve the front-end (index.html) from /public
app.use(express.static(path.join(__dirname, 'public')));

// Health check (useful for hosts)
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ---- Auth ----
// Quick check whether an email is already registered (used during signup)
app.post('/api/check-email', (req, res) => {
  const { email } = req.body || {};
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(String(email).toLowerCase());
  res.json({ available: !existing });
});

app.post('/api/signup', (req, res) => {
  const { email, password, name, city, origin, interests, lang } = req.body || {};
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }
  if (String(password).length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'That email is already registered. Try logging in.' });

  const user = {
    id: id(),
    email: email.toLowerCase(),
    pass_hash: bcrypt.hashSync(String(password), 10),
    name: String(name).trim(),
    city: city || '',
    origin: origin || '',
    interests: JSON.stringify(Array.isArray(interests) ? interests : []),
    lang: (lang && ['en', 'es'].includes(lang)) ? lang : 'en',
    created_at: now()
  };
  db.prepare(`INSERT INTO users (id,email,pass_hash,name,city,origin,interests,lang,created_at)
              VALUES (@id,@email,@pass_hash,@name,@city,@origin,@interests,@lang,@created_at)`).run(user);

  res.json({ token: makeToken(user), user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase());
  if (!row || !bcrypt.compareSync(String(password), row.pass_hash)) {
    return res.status(401).json({ error: 'Wrong email or password.' });
  }
  if (row.suspended) {
    return res.status(403).json({ error: 'This account has been suspended. Contact support if you think this is a mistake.' });
  }
  res.json({ token: makeToken(row), user: publicUser(row) });
});

// Return the current user (used on app load to restore session)
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
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
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase());
  let resetUrl = null;
  if (row) {
    const token = crypto.randomBytes(24).toString('hex');
    db.prepare('INSERT INTO reset_tokens (token,user_id,expires_at,used,created_at) VALUES (?,?,?,0,?)')
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
app.post('/api/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Missing token or password.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const row = db.prepare('SELECT * FROM reset_tokens WHERE token = ?').get(String(token));
  if (!row || row.used || row.expires_at < now()) {
    return res.status(400).json({ error: 'This reset link is invalid or has expired. Request a new one.' });
  }
  const hash = bcrypt.hashSync(String(password), 10);
  db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(hash, row.user_id);
  db.prepare('UPDATE reset_tokens SET used = 1 WHERE token = ?').run(String(token));
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
  res.json({ ok: true, token: makeToken(user), user: publicUser(user) });
});

// Update the current user's profile (name, username, city, interests, lang)
app.post('/api/me/update', requireAuth, (req, res) => {
  const { name, username, city, interests, lang } = req.body || {};
  // If a username is provided, enforce simple rules + uniqueness
  let cleanUser = null;
  if (username && String(username).trim()) {
    cleanUser = String(username).trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
    if (cleanUser.length < 3) return res.status(400).json({ error: 'Username needs at least 3 letters/numbers.' });
    const taken = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(cleanUser, req.user.id);
    if (taken) return res.status(409).json({ error: 'That username is taken. Try another.' });
  }
  const cleanLang = (lang && ['en', 'es'].includes(lang)) ? lang : null;
  db.prepare(`UPDATE users SET
      name = COALESCE(?, name),
      username = COALESCE(?, username),
      city = COALESCE(?, city),
      interests = COALESCE(?, interests),
      lang = COALESCE(?, lang)
    WHERE id = ?`).run(
    name ? String(name).trim() : null,
    cleanUser,
    (city !== undefined && city !== null) ? String(city) : null,
    Array.isArray(interests) ? JSON.stringify(interests) : null,
    cleanLang,
    req.user.id
  );
  const updated = db.prepare('SELECT id, email, name, username, avatar, city, origin, interests, lang FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: publicUser(updated) });
});

// Upload / change profile picture (stored as a data URL; kept small)
app.post('/api/me/avatar', requireAuth, (req, res) => {
  const { avatar } = req.body || {};
  if (typeof avatar !== 'string' || !avatar.startsWith('data:image/')) {
    return res.status(400).json({ error: 'Please choose a valid image.' });
  }
  // ~700KB cap on the encoded string to protect the free-tier database
  if (avatar.length > 700000) {
    return res.status(413).json({ error: 'That image is too large. Please pick a smaller one.' });
  }
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatar, req.user.id);
  const updated = db.prepare('SELECT id, email, name, username, avatar, city, origin, interests FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: publicUser(updated) });
});

// Remove profile picture (revert to initial)
app.post('/api/me/avatar/remove', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET avatar = NULL WHERE id = ?').run(req.user.id);
  const updated = db.prepare('SELECT id, email, name, username, avatar, city, origin, interests FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: publicUser(updated) });
});

// Permanently delete the current user's account and all their data
app.post('/api/me/delete', requireAuth, (req, res) => {
  const uid = req.user.id;
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM messages WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM memberships WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM friendships WHERE user_id = ? OR friend_id = ?').run(uid, uid);
    // Rounds they host: remove the round and its data
    const hosted = db.prepare('SELECT id FROM rounds WHERE host_id = ?').all(uid);
    for (const r of hosted) {
      db.prepare('DELETE FROM messages WHERE round_id = ?').run(r.id);
      db.prepare('DELETE FROM memberships WHERE round_id = ?').run(r.id);
      db.prepare('DELETE FROM rounds WHERE id = ?').run(r.id);
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(uid);
  });
  tx();
  res.json({ ok: true });
});

// ---- Friends, requests, blocks, reports ----
// Helper: are two users friends (either direction stored both ways on accept)
function areFriends(a, b) {
  return !!db.prepare('SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?').get(a, b);
}
function isBlocked(a, b) { // has a blocked b OR b blocked a
  return !!db.prepare('SELECT 1 FROM blocks WHERE (user_id = ? AND blocked_id = ?) OR (user_id = ? AND blocked_id = ?)').get(a, b, b, a);
}

// Search users by username or name, excluding yourself and anyone blocked
app.get('/api/users/search', requireAuth, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase().replace(/^@/, '');
  if (q.length < 2) return res.json({ users: [] });
  const rows = db.prepare(`
    SELECT id, name, username, avatar, city FROM users
    WHERE id != ? AND (LOWER(username) LIKE ? OR LOWER(name) LIKE ?)
    LIMIT 20
  `).all(req.user.id, '%' + q + '%', '%' + q + '%');
  const friendIds = new Set(db.prepare('SELECT friend_id FROM friendships WHERE user_id = ?').all(req.user.id).map(r => r.friend_id));
  const sentIds = new Set(db.prepare('SELECT to_id FROM friend_requests WHERE from_id = ?').all(req.user.id).map(r => r.to_id));
  const out = rows
    .filter(u => u.username && !isBlocked(req.user.id, u.id))
    .map(u => ({
      id: u.id, name: u.name, username: u.username, avatar: u.avatar || '', city: u.city,
      status: friendIds.has(u.id) ? 'friend' : (sentIds.has(u.id) ? 'pending' : 'none')
    }));
  res.json({ users: out });
});

// Send a friend request
app.post('/api/friends/request', requireAuth, (req, res) => {
  const { toId } = req.body || {};
  if (!toId || toId === req.user.id) return res.status(400).json({ error: 'Invalid user.' });
  if (isBlocked(req.user.id, toId)) return res.status(403).json({ error: 'Unavailable.' });
  const exists = db.prepare('SELECT id FROM users WHERE id = ?').get(toId);
  if (!exists) return res.status(404).json({ error: 'User not found.' });
  if (areFriends(req.user.id, toId)) return res.json({ ok: true, status: 'friend' });
  // If they already sent YOU a request, accept it instead
  const incoming = db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(toId, req.user.id);
  if (incoming) {
    const t = db.transaction(() => {
      db.prepare('INSERT OR IGNORE INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?)').run(req.user.id, toId, now());
      db.prepare('INSERT OR IGNORE INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?)').run(toId, req.user.id, now());
      db.prepare('DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?').run(toId, req.user.id);
    });
    t();
    return res.json({ ok: true, status: 'friend' });
  }
  db.prepare('INSERT OR IGNORE INTO friend_requests (from_id,to_id,created_at) VALUES (?,?,?)').run(req.user.id, toId, now());
  pushNotif(toId, 'friend_request', 'New friend request', (req.user.name || 'Someone') + ' wants to be friends', 'friends:requests');
  res.json({ ok: true, status: 'pending' });
});

// Incoming friend requests (people who want to add me)
app.get('/api/friends/requests', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.username, u.avatar, u.city
    FROM friend_requests fr JOIN users u ON u.id = fr.from_id
    WHERE fr.to_id = ? ORDER BY fr.created_at DESC
  `).all(req.user.id);
  res.json({ requests: rows });
});

// Accept a request
app.post('/api/friends/accept', requireAuth, (req, res) => {
  const { fromId } = req.body || {};
  const pending = db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(fromId, req.user.id);
  if (!pending) return res.status(404).json({ error: 'No such request.' });
  const t = db.transaction(() => {
    db.prepare('INSERT OR IGNORE INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?)').run(req.user.id, fromId, now());
    db.prepare('INSERT OR IGNORE INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?)').run(fromId, req.user.id, now());
    db.prepare('DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?').run(fromId, req.user.id);
  });
  t();
  pushNotif(fromId, 'friend_accept', 'Friend request accepted', (req.user.name || 'Someone') + ' accepted your friend request 🎉', 'friends:friends');
  res.json({ ok: true });
});

// Decline a request
app.post('/api/friends/decline', requireAuth, (req, res) => {
  const { fromId } = req.body || {};
  db.prepare('DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?').run(fromId, req.user.id);
  res.json({ ok: true });
});

// Remove a friend (both directions)
app.post('/api/friends/remove', requireAuth, (req, res) => {
  const { friendId } = req.body || {};
  db.prepare('DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)')
    .run(req.user.id, friendId, friendId, req.user.id);
  res.json({ ok: true });
});

// List my friends
app.get('/api/friends', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.username, u.avatar, u.city
    FROM friendships f JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ? ORDER BY f.created_at DESC
  `).all(req.user.id);
  res.json({ friends: rows });
});

// Block a user (also removes friendship + pending requests both ways)
app.post('/api/block', requireAuth, (req, res) => {
  const { userId } = req.body || {};
  if (!userId || userId === req.user.id) return res.status(400).json({ error: 'Invalid user.' });
  const t = db.transaction(() => {
    db.prepare('INSERT OR IGNORE INTO blocks (user_id,blocked_id,created_at) VALUES (?,?,?)').run(req.user.id, userId, now());
    db.prepare('DELETE FROM friendships WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)').run(req.user.id, userId, userId, req.user.id);
    db.prepare('DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)').run(req.user.id, userId, userId, req.user.id);
  });
  t();
  res.json({ ok: true });
});

// Unblock
app.post('/api/unblock', requireAuth, (req, res) => {
  const { userId } = req.body || {};
  db.prepare('DELETE FROM blocks WHERE user_id = ? AND blocked_id = ?').run(req.user.id, userId);
  res.json({ ok: true });
});

// List people I've blocked
app.get('/api/blocks', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.username, u.avatar
    FROM blocks b JOIN users u ON u.id = b.blocked_id
    WHERE b.user_id = ? ORDER BY b.created_at DESC
  `).all(req.user.id);
  res.json({ blocked: rows });
});

// Report a user / content
app.post('/api/report', requireAuth, (req, res) => {
  const { reportedId, context, reason } = req.body || {};
  db.prepare('INSERT INTO reports (id,reporter_id,reported_id,context,reason,created_at) VALUES (?,?,?,?,?,?)')
    .run(id(), req.user.id, reportedId || null, String(context || '').slice(0, 200), String(reason || '').slice(0, 500), now());
  res.json({ ok: true });
});

// ---- Notifications ----
function pushNotif(userId, type, title, body, link) {
  try {
    db.prepare('INSERT INTO notifications (id,user_id,type,title,body,link,read,created_at) VALUES (?,?,?,?,?,?,0,?)')
      .run(id(), userId, type, title || '', body || '', link || '', now());
    // live ping over WS if they're connected
    const payload = JSON.stringify({ type: 'notify' });
    wss.clients.forEach(c => { if (c.readyState === 1 && c.user && c.user.id === userId) c.send(payload); });
  } catch (e) { /* ignore */ }
}

app.get('/api/notifications', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(req.user.id);
  res.json({ notifications: rows });
});

// Unread counts for the badge (notifications + unread DMs)
app.get('/api/notifications/counts', requireAuth, (req, res) => {
  const notif = db.prepare('SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND read = 0').get(req.user.id).c;
  const convs = db.prepare('SELECT conv_id, last_read FROM conversation_members WHERE user_id = ?').all(req.user.id);
  let unreadDms = 0;
  for (const cm of convs) {
    const c = db.prepare('SELECT COUNT(*) AS c FROM dm_messages WHERE conv_id = ? AND created_at > ? AND user_id != ?')
      .get(cm.conv_id, cm.last_read || 0, req.user.id).c;
    if (c > 0) unreadDms++;
  }
  res.json({ notifications: notif, dms: unreadDms, total: notif + unreadDms });
});

app.post('/api/notifications/read', requireAuth, (req, res) => {
  db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

// ---- Direct messages / friend group chats ----
// List my conversations with last message + unread flag
app.get('/api/conversations', requireAuth, (req, res) => {
  const convs = db.prepare(`
    SELECT c.*, cm.last_read FROM conversations c
    JOIN conversation_members cm ON cm.conv_id = c.id
    WHERE cm.user_id = ? ORDER BY c.created_at DESC
  `).all(req.user.id);
  const out = convs.map(c => {
    const members = db.prepare(`SELECT u.id,u.name,u.username,u.avatar FROM conversation_members m JOIN users u ON u.id=m.user_id WHERE m.conv_id=?`).all(c.id);
    const others = members.filter(m => m.id !== req.user.id);
    const last = db.prepare('SELECT body,kind,created_at,user_id FROM dm_messages WHERE conv_id=? ORDER BY created_at DESC LIMIT 1').get(c.id);
    const unread = db.prepare('SELECT COUNT(*) AS c FROM dm_messages WHERE conv_id=? AND created_at > ? AND user_id != ?').get(c.id, c.last_read || 0, req.user.id).c;
    let title = c.title;
    if (!c.is_group) title = others[0] ? others[0].name : 'Conversation';
    return {
      id: c.id, is_group: !!c.is_group, title,
      members: others,
      avatar: (!c.is_group && others[0]) ? (others[0].avatar || '') : '',
      last: last ? { body: last.kind === 'gif' ? '📷 GIF' : last.body, created_at: last.created_at, mine: last.user_id === req.user.id } : null,
      unread
    };
  });
  res.json({ conversations: out });
});

// Open (or create) a 1-on-1 conversation with a friend
app.post('/api/conversations/open', requireAuth, (req, res) => {
  const { friendId } = req.body || {};
  if (!friendId || friendId === req.user.id) return res.status(400).json({ error: 'Invalid user.' });
  // must be friends
  const friend = db.prepare('SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?').get(req.user.id, friendId);
  if (!friend) return res.status(403).json({ error: 'You can only message friends.' });
  if (isBlocked(req.user.id, friendId)) return res.status(403).json({ error: 'Unavailable.' });
  // find an existing 1-on-1 between exactly these two
  const existing = db.prepare(`
    SELECT c.id FROM conversations c
    WHERE c.is_group = 0
      AND EXISTS(SELECT 1 FROM conversation_members m WHERE m.conv_id=c.id AND m.user_id=?)
      AND EXISTS(SELECT 1 FROM conversation_members m WHERE m.conv_id=c.id AND m.user_id=?)
      AND (SELECT COUNT(*) FROM conversation_members m WHERE m.conv_id=c.id)=2
  `).get(req.user.id, friendId);
  let convId = existing ? existing.id : null;
  if (!convId) {
    convId = id();
    db.prepare('INSERT INTO conversations (id,is_group,title,created_by,created_at) VALUES (?,0,?,?,?)').run(convId, '', req.user.id, now());
    db.prepare('INSERT INTO conversation_members (conv_id,user_id,last_read) VALUES (?,?,0)').run(convId, req.user.id);
    db.prepare('INSERT INTO conversation_members (conv_id,user_id,last_read) VALUES (?,?,0)').run(convId, friendId);
  }
  res.json({ conversationId: convId });
});

// Create a friend group chat
app.post('/api/conversations/group', requireAuth, (req, res) => {
  const { title, memberIds } = req.body || {};
  const ids = Array.isArray(memberIds) ? memberIds.filter(x => x && x !== req.user.id) : [];
  if (!ids.length) return res.status(400).json({ error: 'Pick at least one friend.' });
  // all must be friends
  for (const fid of ids) {
    const ok = db.prepare('SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?').get(req.user.id, fid);
    if (!ok) return res.status(403).json({ error: 'You can only add friends to a group.' });
  }
  const convId = id();
  db.prepare('INSERT INTO conversations (id,is_group,title,created_by,created_at) VALUES (?,1,?,?,?)')
    .run(convId, String(title || 'Group chat').slice(0, 60), req.user.id, now());
  db.prepare('INSERT INTO conversation_members (conv_id,user_id,last_read) VALUES (?,?,0)').run(convId, req.user.id);
  for (const fid of ids) {
    db.prepare('INSERT OR IGNORE INTO conversation_members (conv_id,user_id,last_read) VALUES (?,?,0)').run(convId, fid);
    pushNotif(fid, 'group', 'New group chat', (req.user.name || 'A friend') + ' added you to "' + (title || 'Group chat') + '"', 'dm:' + convId);
  }
  res.json({ conversationId: convId });
});

// Get messages in a conversation (and mark read)
app.get('/api/conversations/:id/messages', requireAuth, (req, res) => {
  const member = db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Not in this conversation.' });
  const rows = db.prepare(`
    SELECT m.id,m.body,m.kind,m.media_url,m.created_at,m.user_id,u.name AS sender,u.avatar,m.reactions,m.reply_to,m.reply_preview
    FROM dm_messages m JOIN users u ON u.id=m.user_id
    WHERE m.conv_id=? ORDER BY m.created_at ASC LIMIT 300
  `).all(req.params.id);
  const msgs = rows.map(m => ({
    id: m.id, body: m.body, kind: m.kind || 'text', media_url: m.media_url || null,
    created_at: m.created_at, user_id: m.user_id, sender: m.sender, avatar: m.avatar,
    reactions: m.reactions ? JSON.parse(m.reactions) : {},
    reply_to: m.reply_to || null, reply_preview: m.reply_preview || null
  }));
  db.prepare('UPDATE conversation_members SET last_read=? WHERE conv_id=? AND user_id=?').run(now(), req.params.id, req.user.id);
  const conv = db.prepare('SELECT * FROM conversations WHERE id=?').get(req.params.id);
  const members = db.prepare(`SELECT u.id,u.name,u.username,u.avatar FROM conversation_members m JOIN users u ON u.id=m.user_id WHERE m.conv_id=?`).all(req.params.id);
  const others = members.filter(m => m.id !== req.user.id);
  const title = conv.is_group ? conv.title : (others[0] ? others[0].name : 'Conversation');
  res.json({ messages: msgs, conversation: { id: conv.id, is_group: !!conv.is_group, title, members: others } });
});

// React to a DM message
app.post('/api/dm/:id/react', requireAuth, (req, res) => {
  const { emoji } = req.body || {};
  if (!emoji) return res.status(400).json({ error: 'No emoji.' });
  const m = db.prepare('SELECT id, conv_id, reactions FROM dm_messages WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Message gone.' });
  const member = db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(m.conv_id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Not in this conversation.' });
  const reactions = m.reactions ? JSON.parse(m.reactions) : {};
  const users = reactions[emoji] || [];
  const idx = users.indexOf(req.user.id);
  if (idx >= 0) users.splice(idx, 1); else users.push(req.user.id);
  if (users.length) reactions[emoji] = users; else delete reactions[emoji];
  db.prepare('UPDATE dm_messages SET reactions = ? WHERE id = ?').run(JSON.stringify(reactions), req.params.id);
  const payload = JSON.stringify({ type: 'dmReaction', convId: m.conv_id, messageId: req.params.id, reactions });
  wss.clients.forEach(c => { if (c.readyState === 1 && c.dmRooms && c.dmRooms.has(m.conv_id)) c.send(payload); });
  res.json({ ok: true, reactions });
});

// ---- Admin (owner-only) ----
// Requires: logged-in user with is_admin = 1
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_admin) return res.status(403).json({ error: 'Not authorized.' });
  next();
}

// Confirm whether current user is an admin (used by the app to show/hide the panel)
app.get('/api/admin/check', requireAuth, (req, res) => {
  res.json({ isAdmin: !!req.user.is_admin });
});

// List all users (admin only)
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  let rows;
  if (q) {
    rows = db.prepare(`SELECT id,name,username,email,city,suspended,is_admin,created_at
      FROM users WHERE LOWER(name) LIKE ? OR LOWER(username) LIKE ? OR LOWER(email) LIKE ?
      ORDER BY created_at DESC LIMIT 200`).all('%'+q+'%','%'+q+'%','%'+q+'%');
  } else {
    rows = db.prepare('SELECT id,name,username,email,city,suspended,is_admin,created_at FROM users ORDER BY created_at DESC LIMIT 200').all();
  }
  res.json({ users: rows });
});

// Suspend / unsuspend a user (admin only)
app.post('/api/admin/suspend', requireAuth, requireAdmin, (req, res) => {
  const { userId, suspend } = req.body || {};
  const target = db.prepare('SELECT id,is_admin FROM users WHERE id = ?').get(userId);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  if (target.is_admin) return res.status(400).json({ error: 'You cannot suspend an admin account.' });
  db.prepare('UPDATE users SET suspended = ? WHERE id = ?').run(suspend ? 1 : 0, userId);
  res.json({ ok: true });
});

// Permanently delete a user and their data (admin only)
app.post('/api/admin/delete', requireAuth, requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  const target = db.prepare('SELECT id,is_admin FROM users WHERE id = ?').get(userId);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  if (target.is_admin) return res.status(400).json({ error: 'You cannot delete an admin account.' });
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM messages WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM memberships WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM friendships WHERE user_id = ? OR friend_id = ?').run(userId, userId);
    db.prepare('DELETE FROM friend_requests WHERE from_id = ? OR to_id = ?').run(userId, userId);
    db.prepare('DELETE FROM blocks WHERE user_id = ? OR blocked_id = ?').run(userId, userId);
    const hosted = db.prepare('SELECT id FROM rounds WHERE host_id = ?').all(userId);
    for (const r of hosted) {
      db.prepare('DELETE FROM messages WHERE round_id = ?').run(r.id);
      db.prepare('DELETE FROM memberships WHERE round_id = ?').run(r.id);
      db.prepare('DELETE FROM rounds WHERE id = ?').run(r.id);
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  });
  tx();
  res.json({ ok: true });
});

// View reports (admin only)
app.get('/api/admin/reports', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`
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


// ---- Rounds ----
app.get('/api/rounds', requireAuth, (req, res) => {
  const rounds = db.prepare(`
    SELECT r.*,
      (SELECT COUNT(*) FROM memberships m WHERE m.round_id = r.id) AS member_count,
      EXISTS(SELECT 1 FROM memberships m WHERE m.round_id = r.id AND m.user_id = ?) AS joined,
      (r.host_id = ?) AS is_host
    FROM rounds r ORDER BY r.created_at DESC
  `).all(req.user.id, req.user.id);
  res.json({ rounds });
});

app.post('/api/rounds', requireAuth, (req, res) => {
  const { title, emoji, category, blurb, lat, lng, place } = req.body || {};
  if (!title) return res.status(400).json({ error: 'Give your Round a name.' });
  const round = {
    id: id(), title: String(title).trim(), emoji: emoji || '✨',
    category: category || 'General', blurb: blurb || '',
    host_id: req.user.id, created_at: now(),
    lat: (typeof lat === 'number') ? lat : null,
    lng: (typeof lng === 'number') ? lng : null,
    place: place || null
  };
  db.prepare(`INSERT INTO rounds (id,title,emoji,category,blurb,host_id,created_at,lat,lng,place)
              VALUES (@id,@title,@emoji,@category,@blurb,@host_id,@created_at,@lat,@lng,@place)`).run(round);
  db.prepare('INSERT OR IGNORE INTO memberships (round_id,user_id,joined_at) VALUES (?,?,?)')
    .run(round.id, req.user.id, now());
  res.json({ round });
});

// Delete a Round — only the host (creator) can do this
app.post('/api/rounds/:id/delete', requireAuth, (req, res) => {
  const round = db.prepare('SELECT host_id FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'That Round no longer exists.' });
  if (round.host_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can delete this Round.' });
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM messages WHERE round_id = ?').run(req.params.id);
    db.prepare('DELETE FROM memberships WHERE round_id = ?').run(req.params.id);
    db.prepare('DELETE FROM rounds WHERE id = ?').run(req.params.id);
  });
  tx();
  res.json({ ok: true });
});

app.post('/api/rounds/:id/join', requireAuth, (req, res) => {
  const round = db.prepare('SELECT id FROM rounds WHERE id = ?').get(req.params.id);
  if (!round) return res.status(404).json({ error: 'That Round no longer exists.' });
  db.prepare('INSERT OR IGNORE INTO memberships (round_id,user_id,joined_at) VALUES (?,?,?)')
    .run(req.params.id, req.user.id, now());
  res.json({ ok: true });
});

// Rounds the current user belongs to (their "Circles")
app.get('/api/my-rounds', requireAuth, (req, res) => {
  const rounds = db.prepare(`
    SELECT r.*,
      (SELECT COUNT(*) FROM memberships m WHERE m.round_id = r.id) AS member_count,
      (r.host_id = ?) AS is_host
    FROM rounds r
    JOIN memberships mm ON mm.round_id = r.id
    WHERE mm.user_id = ?
    ORDER BY r.created_at DESC
  `).all(req.user.id, req.user.id);
  res.json({ rounds });
});

// ---- Messages (history) ----
app.get('/api/rounds/:id/messages', requireAuth, (req, res) => {
  const member = db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Join this Round to see its chat.' });
  const rows = db.prepare(`
    SELECT m.id, m.body, m.created_at, m.user_id, u.name AS sender,
           m.reactions, m.reply_to, m.reply_preview, m.kind, m.media_url, m.ephemeral, m.seen_by
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.round_id = ? ORDER BY m.created_at ASC LIMIT 200
  `).all(req.params.id);
  // For ephemeral messages the current user has already seen (and isn't the sender), delete + hide
  const out = [];
  for (const m of rows) {
    if (m.ephemeral && m.user_id !== req.user.id) {
      const seen = m.seen_by ? JSON.parse(m.seen_by) : [];
      if (seen.includes(req.user.id)) {
        db.prepare('DELETE FROM messages WHERE id = ?').run(m.id); // it's been read once by this viewer
        continue;
      } else {
        seen.push(req.user.id);
        db.prepare('UPDATE messages SET seen_by = ? WHERE id = ?').run(JSON.stringify(seen), m.id);
      }
    }
    out.push({
      id: m.id, body: m.body, created_at: m.created_at, user_id: m.user_id, sender: m.sender,
      reactions: m.reactions ? JSON.parse(m.reactions) : {},
      reply_to: m.reply_to || null, reply_preview: m.reply_preview || null,
      kind: m.kind || 'text', media_url: m.media_url || null, ephemeral: !!m.ephemeral
    });
  }
  res.json({ messages: out });
});

// React to a message (toggle emoji)
app.post('/api/messages/:id/react', requireAuth, (req, res) => {
  const { emoji } = req.body || {};
  if (!emoji) return res.status(400).json({ error: 'No emoji.' });
  const m = db.prepare('SELECT id, round_id, reactions FROM messages WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Message gone.' });
  const member = db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?').get(m.round_id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Not a member.' });
  const reactions = m.reactions ? JSON.parse(m.reactions) : {};
  const users = reactions[emoji] || [];
  const idx = users.indexOf(req.user.id);
  if (idx >= 0) users.splice(idx, 1); else users.push(req.user.id);
  if (users.length) reactions[emoji] = users; else delete reactions[emoji];
  db.prepare('UPDATE messages SET reactions = ? WHERE id = ?').run(JSON.stringify(reactions), req.params.id);
  // broadcast the reaction update
  const payload = JSON.stringify({ type: 'reaction', roundId: m.round_id, messageId: req.params.id, reactions });
  wss.clients.forEach(c => { if (c.readyState === 1 && c.rooms && c.rooms.has(m.round_id)) c.send(payload); });
  res.json({ ok: true, reactions });
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

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'auth') {
      const user = authFromToken(msg.token);
      if (!user) { ws.send(JSON.stringify({ type: 'error', error: 'auth failed' })); return; }
      ws.user = user;
      ws.send(JSON.stringify({ type: 'ready' }));
      return;
    }

    if (!ws.user) { ws.send(JSON.stringify({ type: 'error', error: 'not authed' })); return; }

    if (msg.type === 'join') {
      const member = db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?')
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
      const member = db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?')
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
      db.prepare(`INSERT INTO messages (id,round_id,user_id,body,created_at,reply_to,reply_preview,kind,media_url,ephemeral,seen_by)
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
      const member = db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(msg.convId, ws.user.id);
      if (!member) { ws.send(JSON.stringify({ type: 'error', error: 'not in conversation' })); return; }

      const record = { id: id(), conv_id: msg.convId, user_id: ws.user.id, body, kind, media_url: mediaUrl, created_at: now(),
        reply_to: msg.replyTo ? String(msg.replyTo) : null,
        reply_preview: msg.replyPreview ? String(msg.replyPreview).slice(0, 120) : null };
      db.prepare('INSERT INTO dm_messages (id,conv_id,user_id,body,kind,media_url,created_at,reply_to,reply_preview) VALUES (@id,@conv_id,@user_id,@body,@kind,@media_url,@created_at,@reply_to,@reply_preview)').run(record);

      const outbound = JSON.stringify({
        type: 'dm',
        convId: msg.convId,
        message: { id: record.id, body, kind, media_url: mediaUrl, created_at: record.created_at, user_id: ws.user.id, sender: ws.user.name, avatar: ws.user.avatar || '', reply_to: record.reply_to, reply_preview: record.reply_preview, reactions: {} }
      });
      // deliver to connected members in that conversation room; notify the rest
      const members = db.prepare('SELECT user_id FROM conversation_members WHERE conv_id=?').all(msg.convId).map(r => r.user_id);
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
          pushNotif(uid, 'dm', ws.user.name || 'New message', kind === 'gif' ? 'Sent a GIF' : body.slice(0, 80), 'dm:' + msg.convId);
        }
      }
    }

    if (msg.type === 'joinDm') {
      const member = db.prepare('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?').get(msg.convId, ws.user.id);
      if (member) { ws.dmRooms = ws.dmRooms || new Set(); ws.dmRooms.add(msg.convId); }
      return;
    }
    if (msg.type === 'leaveDm') {
      if (ws.dmRooms) ws.dmRooms.delete(msg.convId);
      return;
    }

    // ---- Voice / video call signaling (friend-only) ----
    // Calls are ONLY allowed between people who share a conversation that is either
    // a 1-on-1 friend DM or a friend group chat. Never for Rounds.
    if (msg.type === 'call-offer' || msg.type === 'call-answer' || msg.type === 'call-ice' ||
        msg.type === 'call-end' || msg.type === 'call-decline') {
      const targetId = msg.to;
      if (!targetId) return;

      // For a new offer, verify caller and callee are friends (or in a friend group together).
      if (msg.type === 'call-offer') {
        const areFriends = db.prepare('SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?').get(ws.user.id, targetId);
        let shareFriendGroup = false;
        if (!areFriends) {
          // check they share a non-Round conversation (friend group chat)
          shareFriendGroup = !!db.prepare(`
            SELECT 1 FROM conversation_members a
            JOIN conversation_members b ON a.conv_id = b.conv_id
            WHERE a.user_id = ? AND b.user_id = ?
          `).get(ws.user.id, targetId);
        }
        if (!areFriends && !shareFriendGroup) {
          ws.send(JSON.stringify({ type: 'call-error', error: 'You can only call friends.' }));
          return;
        }
        if (isBlocked(ws.user.id, targetId)) {
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

server.listen(PORT, () => {
  console.log(`ShowUpp backend running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT} to use the app.`);
});
