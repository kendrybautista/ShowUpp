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
// Secondary "supervisor" password required to permanently delete a report.
// Placeholder gate until deletion is scoped to real supervisor accounts.
const SUPERVISOR_PASSWORD = process.env.SUPERVISOR_PASSWORD || 'supervisor123';

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
  -- Fun avatar (item 2): a small JSON blob describing chosen features (face, eyes, hair,
  -- accessory, colors). Kept separate from the avatar photo column so it's purely
  -- additive. avatar_on_map (item 3) opts the avatar in as the user's map location pin.
  ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_config TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_on_map INTEGER DEFAULT 0;
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
  -- Friendship Engine ("Vibe Check"): stores the user's questionnaire answers as JSON.
  -- Shape: {"answers":{"0":[1,3],"1":[0],...},"archetype":"...","updated_at":1234567890}
  ALTER TABLE users ADD COLUMN IF NOT EXISTS vibe_answers TEXT;
  -- Optional note attached to a friend request (Vibe Check matches include a message
  -- so the recipient sees WHY this person is reaching out).
  ALTER TABLE friend_requests ADD COLUMN IF NOT EXISTS message TEXT;
  -- People a user has chosen to ignore as potential Vibe matches.
  CREATE TABLE IF NOT EXISTS vibe_ignores (
    user_id    TEXT NOT NULL,
    ignored_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, ignored_id)
  );

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
  CREATE TABLE IF NOT EXISTS saved_events (
    event_id TEXT NOT NULL, user_id TEXT NOT NULL, created_at BIGINT,
    PRIMARY KEY (event_id, user_id)
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
  -- Caches each event-account's results per (source, rough location, radius bucket) so
  -- repeated searches from the same area don't re-hit Ticketmaster's (etc.) API and burn
  -- through its daily request allowance. See EVENT_CACHE_TTL_MS below.
  CREATE TABLE IF NOT EXISTS event_cache (
    cache_key   TEXT PRIMARY KEY,
    payload     TEXT NOT NULL,
    fetched_at  BIGINT NOT NULL
  );
  -- Display label for an event's source, set at ingest/creation time so /api/events
  -- never has to join back to event_sources (whose label can change independently).
  ALTER TABLE events ADD COLUMN IF NOT EXISTS source_label TEXT;
  -- event_sources.api_key is optional now: a manually-labeled source (see the
  -- Manager panel's "Other / manual" provider option) has nothing to authenticate
  -- with — its events are added by hand, not fetched.
  ALTER TABLE event_sources ALTER COLUMN api_key DROP NOT NULL;
  -- Track real ingest health per source (last attempt time, last error if the fetch
  -- failed, and how many events it returned) so the Manager panel can show whether a
  -- source is actually working instead of just whether its toggle is switched on.
  ALTER TABLE event_sources ADD COLUMN IF NOT EXISTS last_ingest_at BIGINT;
  ALTER TABLE event_sources ADD COLUMN IF NOT EXISTS last_error TEXT;
  ALTER TABLE event_sources ADD COLUMN IF NOT EXISTS last_fetched_count INTEGER;
  -- For the "website" provider: the events-page URL to auto-read (no API).
  ALTER TABLE event_sources ADD COLUMN IF NOT EXISTS url TEXT;
  -- Country the event takes place in (ISO 3166-1 alpha-2, e.g. 'US', 'DO'). Lets the
  -- feed serve users their own country's events instead of a US-only catalog (item 6).
  ALTER TABLE events ADD COLUMN IF NOT EXISTS country TEXT;
  CREATE INDEX IF NOT EXISTS idx_events_country ON events (country);
  CREATE INDEX IF NOT EXISTS idx_events_category ON events (category);

  -- Moderation workflow for reports: status walks open -> investigating -> resolved.
  -- verdict records the manager's finding once analyzed (discarded = unfounded,
  -- validated = confirmed a violation) and feeds the repeat-offender/malicious-reporter
  -- counts below. description lets the reporter add context up front.
  ALTER TABLE reports ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'open';
  ALTER TABLE reports ADD COLUMN IF NOT EXISTS verdict TEXT;
  ALTER TABLE reports ADD COLUMN IF NOT EXISTS description TEXT;
  ALTER TABLE reports ADD COLUMN IF NOT EXISTS analyzed_at BIGINT;
  ALTER TABLE reports ADD COLUMN IF NOT EXISTS resolved_at BIGINT;
  -- Indexes for the daily-ingested nationwide event feed: requests filter by date
  -- range and a lat/lng bounding box, so both need to be fast on a large table.
  CREATE INDEX IF NOT EXISTS idx_events_starts_at ON events(starts_at);
  CREATE INDEX IF NOT EXISTS idx_events_lat_lng ON events(lat, lng);
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
    lang: u.lang || 'en',
    // When on, the user's profile photo is used as their map location pin (Public profile tab).
    avatarOnMap: !!u.avatar_on_map
  };
}

// --- App ---
const app = express();
app.use(express.json({ limit: '16mb' }));
// Serve the front-end (index.html) from /public
app.use(express.static(path.join(__dirname, 'public')));

// Health check (useful for hosts)
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Public front-end config. Currently just the Google client ID, so the browser can
// initialize "Sign in with Google" only when the server is actually configured for it.
app.get('/api/config', (_req, res) => {
  res.json({ googleClientId: process.env.GOOGLE_CLIENT_ID || '' });
});

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

// ---- Sign in with Google (item 3) ----
// The web client runs Google Identity Services, which hands us a signed ID token (JWT).
// We verify it against Google (tokeninfo) rather than trusting it blind, confirm it was
// minted for our own client ID, then either log the matching user in or create a fresh
// account from the Google profile — sorting out name, email, avatar, and a default
// language automatically so the person lands straight in the app with nothing else to fill in.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
async function verifyGoogleIdToken(idToken) {
  // tokeninfo does full signature + expiry validation for us and returns the claims.
  const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken));
  if (!r.ok) return null;
  const p = await r.json().catch(() => null);
  if (!p || !p.email) return null;
  // Must be issued by Google, for OUR app, and to a verified email.
  const goodIss = p.iss === 'accounts.google.com' || p.iss === 'https://accounts.google.com';
  const goodAud = !GOOGLE_CLIENT_ID || p.aud === GOOGLE_CLIENT_ID;
  const verifiedEmail = p.email_verified === true || p.email_verified === 'true';
  if (!goodIss || !goodAud || !verifiedEmail) return null;
  return p;
}
// Build a unique @username from a display name / email local-part for brand-new Google users.
async function uniqueUsernameFrom(seed) {
  let base = String(seed || 'user').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20) || 'user';
  let candidate = base;
  for (let i = 0; i < 50; i++) {
    const taken = await db.prepare('SELECT 1 FROM users WHERE username = ?').get(candidate);
    if (!taken) return candidate;
    candidate = (base + Math.floor(1000 + Math.random() * 9000)).slice(0, 24);
  }
  return base + '_' + id().slice(0, 6);
}
app.post('/api/auth/google', async (req, res) => {
  const idToken = req.body && (req.body.credential || req.body.idToken || req.body.token);
  if (!idToken) return res.status(400).json({ error: 'Missing Google credential.' });
  const claims = await verifyGoogleIdToken(idToken);
  if (!claims) return res.status(401).json({ error: "Couldn't verify that Google account. Please try again." });

  const email = String(claims.email).toLowerCase();
  let row = await db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (row) {
    // Existing account — log them in. Refresh a couple of profile fields from Google
    // if they were never set locally (e.g. an avatar), but never overwrite their choices.
    if (row.suspended) return res.status(403).json({ error: 'This account has been suspended. Contact support if you think this is a mistake.' });
    if ((!row.avatar || !row.avatar.trim()) && claims.picture) {
      await db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(String(claims.picture).slice(0, 3000000), row.id);
      row.avatar = claims.picture;
    }
    return res.json({
      token: makeToken(row),
      user: { ...publicUser(row), email: row.email || '', phone: row.phone || '', incognito: !!row.incognito, readReceipts: row.read_receipts !== 0 },
      isNew: false
    });
  }

  // New account — provision it from the Google profile. Google accounts have no local
  // password, so we store a random hash they can never log in with directly (they use
  // "Sign in with Google" from here on, and can set a password later via secure-change).
  const name = String(claims.name || (claims.given_name || '') || email.split('@')[0]).trim().slice(0, 60) || 'ShowUpp user';
  const username = await uniqueUsernameFrom(claims.given_name || claims.name || email.split('@')[0]);
  const langHint = (typeof claims.locale === 'string') ? claims.locale.slice(0, 2).toLowerCase() : 'en';
  const user = {
    id: id(),
    email,
    pass_hash: bcrypt.hashSync('google-oauth:' + crypto.randomUUID(), 10),
    name,
    username,
    avatar: claims.picture ? String(claims.picture).slice(0, 3000000) : '',
    phone: '',
    city: '',
    origin: '',
    interests: JSON.stringify([]),
    lang: ['en', 'es'].includes(langHint) ? langHint : 'en',
    dob: '',
    gender: '',
    created_at: now()
  };
  await db.prepare(`INSERT INTO users (id,email,pass_hash,name,username,avatar,phone,city,origin,interests,lang,dob,gender,created_at)
              VALUES (@id,@email,@pass_hash,@name,@username,@avatar,@phone,@city,@origin,@interests,@lang,@dob,@gender,@created_at)`).run(user);

  res.json({
    token: makeToken(user),
    user: { ...publicUser(user), email: user.email, phone: '', incognito: false, readReceipts: true },
    isNew: true
  });
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
// ---- Address handling (item 1) ----
// Two problems this solves: (a) people pasting a Google/Apple Maps *link* instead of
// an address (which geocoders can't resolve, so the Round never got coordinates and
// never showed a distance), and (b) free-text that isn't really an address at all.
// A shared helper classifies the raw input and, where possible, salvages coordinates
// straight out of a pasted maps URL so the Round still lands on the map.

// Pull "@lat,lng" or "?q=lat,lng" / "!3dLAT!4dLNG" out of common Google/Apple Maps URLs.
function coordsFromMapUrl(s) {
  try {
    // google: /maps/@18.47,-69.9,15z  or  ...!3d18.47!4d-69.9
    let m = s.match(/@(-?\d{1,3}\.\d+),(-?\d{1,3}\.\d+)/);
    if (m) return { lat: parseFloat(m[1]), lng: parseFloat(m[2]) };
    m = s.match(/!3d(-?\d{1,3}\.\d+)!4d(-?\d{1,3}\.\d+)/);
    if (m) return { lat: parseFloat(m[1]), lng: parseFloat(m[2]) };
    // ?q=lat,lng  or  &ll=lat,lng  or  &center=lat,lng  (apple/google/bing)
    m = s.match(/[?&](?:q|ll|sll|center|daddr|destination)=(-?\d{1,3}\.\d+),\s*(-?\d{1,3}\.\d+)/);
    if (m) return { lat: parseFloat(m[1]), lng: parseFloat(m[2]) };
    return null;
  } catch (e) { return null; }
}
function looksLikeUrl(s) { return /^(https?:\/\/|www\.)|maps\.app\.goo\.gl|goo\.gl\/maps|maps\.google|google\.[a-z.]+\/maps|bing\.com\/maps|apple\.co\/|maps\.apple\.com/i.test(s); }
// Is a bare "lat,lng" pair (people sometimes paste just the coordinates).
function coordsFromPair(s) {
  const m = s.match(/^\s*(-?\d{1,2}(?:\.\d+)?),\s*(-?\d{1,3}(?:\.\d+)?)\s*$/);
  if (!m) return null;
  const lat = parseFloat(m[1]), lng = parseFloat(m[2]);
  if (Math.abs(lat) <= 90 && Math.abs(lng) <= 180) return { lat, lng };
  return null;
}

// Core validator/geocoder. Returns a structured verdict the client uses to guide the
// user, and (when it can) the resolved coordinates. `country` biases the geocoder so
// e.g. "Calle El Conde" resolves in the Dominican Republic, not a same-named street
// elsewhere — honoring local address formats per the request.
async function resolveAddress(rawInput, country) {
  const q = String(rawInput || '').trim();
  if (!q) return { ok: false, reason: 'empty', message: 'Enter an address.' };

  // A pasted maps LINK: try to salvage coordinates from it; if we can, accept — otherwise
  // tell the user plainly that a link isn't an address.
  if (looksLikeUrl(q)) {
    const fromUrl = coordsFromMapUrl(q);
    if (fromUrl) return { ok: true, lat: fromUrl.lat, lng: fromUrl.lng, name: '', display: '', source: 'map-url', normalized: '' };
    return { ok: false, reason: 'is-url', message: "That looks like a map link, not an address. Paste the place's street address or name instead (e.g. \"Av. Winston Churchill 1099, Santo Domingo\")." };
  }

  // Bare coordinates pasted directly.
  const pair = coordsFromPair(q);
  if (pair) return { ok: true, lat: pair.lat, lng: pair.lng, name: '', display: '', source: 'coords', normalized: '' };

  // Too short / clearly not an address.
  if (q.length < 4) return { ok: false, reason: 'too-short', message: 'That address looks too short. Add a street and city.' };
  if (!/[a-zA-Z\u00C0-\u024F\u0400-\u04FF\u0600-\u06FF\u4e00-\u9fff]/.test(q)) {
    return { ok: false, reason: 'no-letters', message: 'Enter a street address or place name.' };
  }

  // Geocode via Nominatim, biased to the user's country when we know it.
  const cc = countryToCode(country);
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 6000);
    let url = 'https://nominatim.openstreetmap.org/search?format=json&addressdetails=1&namedetails=1&limit=1&q=' + encodeURIComponent(q);
    if (cc) url += '&countrycodes=' + encodeURIComponent(cc);
    const r = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': 'ShowUppApp/1.0 (friendship app; contact admin@showupp.app)', 'Accept': 'application/json' }
    });
    clearTimeout(timer);
    if (!r.ok) return { ok: false, reason: 'geocode-failed', message: "Couldn't check that address right now. You can still continue." };
    let arr = await r.json();
    // If a country-biased search finds nothing, retry once without the bias — the place
    // may legitimately be just across a border, or the country on file may be stale.
    if ((!Array.isArray(arr) || !arr.length) && cc) {
      const url2 = 'https://nominatim.openstreetmap.org/search?format=json&addressdetails=1&namedetails=1&limit=1&q=' + encodeURIComponent(q);
      const r2 = await fetch(url2, { headers: { 'User-Agent': 'ShowUppApp/1.0 (friendship app; contact admin@showupp.app)', 'Accept': 'application/json' } });
      if (r2.ok) arr = await r2.json();
    }
    if (Array.isArray(arr) && arr.length) {
      const it = arr[0];
      let name = '';
      if (it.namedetails && it.namedetails.name) name = it.namedetails.name;
      else if (it.type && ['office', 'shop', 'restaurant', 'cafe', 'bar', 'amenity'].some(k => (it.class === k || it.type === k))) name = (it.display_name || '').split(',')[0];
      return { ok: true, lat: parseFloat(it.lat), lng: parseFloat(it.lon), name: name || '', display: it.display_name || '', normalized: it.display_name || '', source: 'geocode' };
    }
    return { ok: false, reason: 'not-found', message: "We couldn't find that address. Check the spelling, or add the city so it can be pinned on the map." };
  } catch (e) {
    return { ok: false, reason: 'geocode-failed', message: "Couldn't check that address right now. You can still continue." };
  }
}

// Minimal country-name → ISO 3166-1 alpha-2 map for the countries the app ships with.
// Falls back to null (no bias) for anything unrecognized. Kept here so both the geocode
// and validate endpoints share it.
const COUNTRY_CODES = {
  'dominican republic': 'do', 'united states': 'us', 'usa': 'us', 'united states of america': 'us',
  'mexico': 'mx', 'canada': 'ca', 'spain': 'es', 'france': 'fr', 'germany': 'de', 'italy': 'it',
  'portugal': 'pt', 'brazil': 'br', 'argentina': 'ar', 'colombia': 'co', 'chile': 'cl', 'peru': 'pe',
  'united kingdom': 'gb', 'uk': 'gb', 'ireland': 'ie', 'india': 'in', 'china': 'cn', 'japan': 'jp',
  'puerto rico': 'pr', 'haiti': 'ht', 'venezuela': 've', 'ecuador': 'ec', 'guatemala': 'gt',
  'honduras': 'hn', 'el salvador': 'sv', 'nicaragua': 'ni', 'costa rica': 'cr', 'panama': 'pa',
  'cuba': 'cu', 'jamaica': 'jm', 'netherlands': 'nl', 'belgium': 'be', 'switzerland': 'ch',
  'australia': 'au', 'new zealand': 'nz', 'south africa': 'za', 'nigeria': 'ng', 'egypt': 'eg'
};
function countryToCode(country) {
  if (!country) return '';
  const s = String(country).trim();
  // Already an ISO 3166-1 alpha-2 code (e.g. origin stored as "do")?
  if (/^[a-zA-Z]{2}$/.test(s)) return s.toLowerCase();
  // The app stores city as "City, Country" — take the last comma-separated chunk if present.
  const parts = s.split(',');
  const tail = parts[parts.length - 1].trim().toLowerCase();
  return COUNTRY_CODES[tail] || COUNTRY_CODES[s.toLowerCase()] || '';
}

// Back-compat geocode endpoint (used by the older event-location flow). Now country-aware
// and Maps-URL-tolerant via resolveAddress.
app.get('/api/geocode', requireAuth, async (req, res) => {
  const q = String((req.query && req.query.q) || '').trim();
  if (!q || q.length < 3) return res.status(400).json({ error: 'Enter an address.' });
  // Prefer an explicit country param; otherwise fall back to the user's stored city/country.
  const country = (req.query && req.query.country) || (req.user && req.user.city) || '';
  const v = await resolveAddress(q, country);
  if (v.ok) return res.json({ found: true, lat: v.lat, lng: v.lng, name: v.name || '', display: v.display || '' });
  res.json({ found: false, reason: v.reason, message: v.message });
});

// Structured address validation for the create/edit forms (item 1). Returns ok + a
// human message and, when resolvable, coordinates and a normalized display string.
app.post('/api/validate-address', requireAuth, async (req, res) => {
  const raw = (req.body && (req.body.address || req.body.q)) || '';
  const country = (req.body && req.body.country) || (req.user && req.user.city) || '';
  const v = await resolveAddress(raw, country);
  res.json(v);
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
  const { name, username, city, interests, lang, bio, gallery, isPrivate, relationship, email, phone, gender, showAge, dob, avatarOnMap } = req.body || {};
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
      phone = COALESCE(?, phone),
      avatar_on_map = COALESCE(?, avatar_on_map)
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
    (typeof avatarOnMap === 'boolean') ? (avatarOnMap ? 1 : 0) : null,
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
// Relationship of `me` toward `other`: 'friend' | 'pending' (I sent) | 'incoming' (they sent) | 'none'
async function friendStatus(me, other) {
  if (await areFriends(me, other)) return 'friend';
  if (await db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(me, other)) return 'pending';
  if (await db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(other, me)) return 'incoming';
  return 'none';
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
  const radiusMi = Math.min(parseFloat(req.query.radius) || 25, 500); // true max is 500 mi (~805 km), matching the client-side slider
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

// ============================================================================
//  FRIENDSHIP ENGINE — "Vibe Check"
//  A 25-question multi-select questionnaire that learns how people *socialize*,
//  not just what they like. Matching is done server-side so scores are
//  authoritative. The engine returns up to 5 people scoring >= 80% within 25 mi.
// ============================================================================

// There are 25 questions. Some questions predict social compatibility more
// strongly than others (energy level, social battery, planner-vs-spontaneous,
// ideal Saturday), so they carry more base weight. Indices here MUST line up
// with the VIBE_QUESTIONS array on the client.
const VIBE_QUESTION_COUNT = 25;
const VIBE_BASE_WEIGHTS = [
  3.0, // 0  ideal Saturday
  3.0, // 1  social battery
  2.5, // 2  energy at gatherings
  2.5, // 3  planner vs spontaneous
  2.0, // 4  group size preference
  2.0, // 5  how you recharge
  2.0, // 6  ideal hangout vibe
  1.5, // 7  conversation style
  1.5, // 8  humor style
  1.5, // 9  friday night
  1.5, // 10 travel style
  1.5, // 11 how you show you care
  1.5, // 12 conflict style
  1.5, // 13 food/eating out vibe
  1.0, // 14 music setting
  1.0, // 15 morning vs night
  1.0, // 16 texting style
  1.0, // 17 what you bond over
  1.0, // 18 activity pace
  1.0, // 19 new experiences appetite
  1.0, // 20 how you make plans
  1.0, // 21 what a good friend is
  1.0, // 22 weekend getaway
  1.0, // 23 how you unwind after a hard day
  1.0  // 24 what you're looking for here
];
const VIBE_MATCH_THRESHOLD = 80;   // percent
const VIBE_MAX_RESULTS = 5;
const VIBE_RADIUS_MI = 25;

function parseVibe(raw) {
  if (!raw) return null;
  try {
    const v = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (v && v.answers && typeof v.answers === 'object') return v;
  } catch (e) {}
  return null;
}
function answeredCount(vibe) {
  if (!vibe || !vibe.answers) return 0;
  let n = 0;
  for (let i = 0; i < VIBE_QUESTION_COUNT; i++) {
    const a = vibe.answers[i] || vibe.answers[String(i)];
    if (Array.isArray(a) && a.length) n++;
  }
  return n;
}
// Per-question overlap using Jaccard (|A∩B| / |A∪B|) on the chosen option sets.
function questionOverlap(a, b) {
  const A = new Set(a || []), B = new Set(b || []);
  if (!A.size && !B.size) return null;      // neither answered → skip
  if (!A.size || !B.size) return 0;          // one answered, one didn't → no overlap
  let inter = 0;
  A.forEach(x => { if (B.has(x)) inter++; });
  const uni = A.size + B.size - inter;
  return uni ? inter / uni : 0;
}
// The "learning" part: questions where the whole nearby population answers
// almost identically carry little signal, so we down-weight them; questions
// that split the population carry more. We compute a normalized entropy per
// question across the candidate pool and blend it with the base weights.
function adaptiveWeights(pool) {
  const w = VIBE_BASE_WEIGHTS.slice();
  if (pool.length < 4) return w; // not enough data to learn yet — use base weights
  for (let q = 0; q < VIBE_QUESTION_COUNT; q++) {
    const counts = {};
    let total = 0;
    for (const p of pool) {
      const a = p.answers[q] || p.answers[String(q)];
      if (!Array.isArray(a) || !a.length) continue;
      for (const opt of a) { counts[opt] = (counts[opt] || 0) + 1; total++; }
    }
    if (!total) continue;
    // Shannon entropy of the option distribution, normalized to 0..1.
    const opts = Object.values(counts);
    let H = 0;
    for (const c of opts) { const pr = c / total; H -= pr * Math.log2(pr); }
    const maxH = opts.length > 1 ? Math.log2(opts.length) : 1;
    const norm = maxH ? H / maxH : 0;        // 0 = everyone agrees, 1 = evenly split
    // Blend: keep 60% of base weight, scale the rest by how discriminating it is.
    w[q] = w[q] * (0.6 + 0.4 * norm);
  }
  return w;
}
function vibeScore(mine, theirs, weights) {
  let num = 0, den = 0, sharedQ = 0;
  for (let q = 0; q < VIBE_QUESTION_COUNT; q++) {
    const a = mine[q] || mine[String(q)];
    const b = theirs[q] || theirs[String(q)];
    const ov = questionOverlap(a, b);
    if (ov === null) continue;
    num += weights[q] * ov;
    den += weights[q];
    if (ov > 0) sharedQ++;
  }
  if (!den) return { score: 0, sharedQ: 0 };
  return { score: Math.round((num / den) * 100), sharedQ };
}

// Save / update my questionnaire answers.
app.post('/api/vibe/save', requireAuth, async (req, res) => {
  const { answers, archetype } = req.body || {};
  if (!answers || typeof answers !== 'object') return res.status(400).json({ error: 'No answers provided.' });
  const clean = {};
  for (let i = 0; i < VIBE_QUESTION_COUNT; i++) {
    const a = answers[i] ?? answers[String(i)];
    if (Array.isArray(a)) {
      const opts = a.filter(x => Number.isInteger(x) && x >= 0 && x < 20).slice(0, 12);
      if (opts.length) clean[i] = opts;
    }
  }
  const payload = { answers: clean, archetype: (typeof archetype === 'string' ? archetype.slice(0, 60) : ''), updated_at: now() };
  await db.prepare('UPDATE users SET vibe_answers = ? WHERE id = ?').run(JSON.stringify(payload), req.user.id);
  res.json({ ok: true, answeredCount: answeredCount(payload) });
});

// Fetch my own saved answers (to resume / re-take).
app.get('/api/vibe/me', requireAuth, async (req, res) => {
  const me = await db.prepare('SELECT vibe_answers FROM users WHERE id = ?').get(req.user.id);
  const vibe = parseVibe(me && me.vibe_answers);
  res.json({ vibe: vibe || null, answeredCount: answeredCount(vibe), total: VIBE_QUESTION_COUNT });
});

// The matcher: up to 5 people >= 80% within 25 miles.
// Shared matcher used by /matches (top 5 >=80%) and /suggested (broader feed).
// Returns { ready, matches:[...], poolSize, weights } sorted by score desc.
async function computeVibeMatches(userId, opts) {
  opts = opts || {};
  const me = await db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const myVibe = parseVibe(me.vibe_answers);
  if (!myVibe || answeredCount(myVibe) < 10) return { ready: false, me, myVibe, matches: [], poolSize: 0 };
  const myLat = (typeof opts.lat === 'number') ? opts.lat : me.lat;
  const myLng = (typeof opts.lng === 'number') ? opts.lng : me.lng;
  const haveLoc = typeof myLat === 'number' && typeof myLng === 'number';
  const radius = opts.radius || VIBE_RADIUS_MI;
  const threshold = (opts.threshold != null) ? opts.threshold : VIBE_MATCH_THRESHOLD;

  const ignoredRows = await db.prepare('SELECT ignored_id FROM vibe_ignores WHERE user_id = ?').all(userId);
  const ignored = new Set(ignoredRows.map(r => r.ignored_id));

  const others = await db.prepare('SELECT * FROM users WHERE id != ? AND vibe_answers IS NOT NULL AND suspended = 0').all(userId);
  const pool = [];
  for (const u of others) {
    if (ignored.has(u.id)) continue;
    const v = parseVibe(u.vibe_answers);
    if (!v || answeredCount(v) < 10) continue;
    if (await isBlocked(userId, u.id)) continue;
    let dist = null;
    if (haveLoc && typeof u.lat === 'number' && typeof u.lng === 'number') {
      dist = distanceMiles(myLat, myLng, u.lat, u.lng);
      if (dist > radius) continue;
    } else {
      const a = (me.city || '').toLowerCase().trim();
      const b = (u.city || '').toLowerCase().trim();
      if (!a || !b || a !== b) continue;
    }
    pool.push({ u, answers: v.answers, dist, archetype: v.archetype || '', joined: u.created_at || 0 });
  }
  const weights = adaptiveWeights(pool.concat([{ answers: myVibe.answers }]));
  const scored = [];
  for (const c of pool) {
    const { score, sharedQ } = vibeScore(myVibe.answers, c.answers, weights);
    if (score < threshold) continue;
    const rel = await friendStatus(userId, c.u.id);
    if (opts.excludeFriends && rel === 'friend') continue;
    scored.push({
      id: c.u.id, name: c.u.name, username: c.u.username || '', avatar: c.u.avatar || '',
      city: c.u.city || '', bio: c.u.bio || '', archetype: c.archetype,
      distance: c.dist, score, sharedQuestions: sharedQ, status: rel,
      joined: c.joined, answers: c.answers
    });
  }
  scored.sort((a, b) => b.score - a.score || (a.distance ?? 1e9) - (b.distance ?? 1e9));
  return { ready: true, me, myVibe, matches: scored, poolSize: pool.length };
}

app.get('/api/vibe/matches', requireAuth, async (req, res) => {
  try {
    const lat = parseFloat(req.query.lat), lng = parseFloat(req.query.lng);
    const opts = {};
    if (!isNaN(lat) && !isNaN(lng)) { opts.lat = lat; opts.lng = lng; }
    const r = await computeVibeMatches(req.user.id, opts);
    if (!r.ready) return res.json({ ready: false, reason: 'incomplete', answeredCount: answeredCount(r.myVibe), total: VIBE_QUESTION_COUNT });
    res.json({
      ready: true, threshold: VIBE_MATCH_THRESHOLD, radius: VIBE_RADIUS_MI,
      myAnswers: r.myVibe.answers, myArchetype: r.myVibe.archetype || '',
      poolSize: r.poolSize, matches: r.matches.slice(0, VIBE_MAX_RESULTS)
    });
  } catch (e) {
    console.error('vibe/matches error:', e);
    res.status(500).json({ error: 'Could not load matches right now.' });
  }
});

// Suggested potential friends feed (Circles → Friends → Suggested). Broader than
// the top-5 reveal: everyone >=80% nearby who isn't already a friend, freshest first,
// so the list keeps refilling as new people join or take the Vibe Check.
app.get('/api/vibe/suggested', requireAuth, async (req, res) => {
  try {
    const lat = parseFloat(req.query.lat), lng = parseFloat(req.query.lng);
    const opts = { excludeFriends: true };
    if (!isNaN(lat) && !isNaN(lng)) { opts.lat = lat; opts.lng = lng; }
    const r = await computeVibeMatches(req.user.id, opts);
    if (!r.ready) return res.json({ ready: false, answeredCount: answeredCount(r.myVibe), total: VIBE_QUESTION_COUNT });
    const list = r.matches.slice().sort((a, b) => (b.joined || 0) - (a.joined || 0) || b.score - a.score).slice(0, 30);
    res.json({ ready: true, myAnswers: r.myVibe.answers, myArchetype: r.myVibe.archetype || '', people: list });
  } catch (e) {
    console.error('vibe/suggested error:', e);
    res.status(500).json({ error: 'Could not load suggestions right now.' });
  }
});

// Ignore a potential match — stops them surfacing in matches & suggested.
app.post('/api/vibe/ignore', requireAuth, async (req, res) => {
  const { userId } = req.body || {};
  if (!userId || userId === req.user.id) return res.status(400).json({ error: 'Invalid user.' });
  await db.prepare('INSERT INTO vibe_ignores (user_id,ignored_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(req.user.id, userId, now());
  res.json({ ok: true });
});
// Un-ignore (in case they change their mind).
app.post('/api/vibe/unignore', requireAuth, async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'Invalid user.' });
  await db.prepare('DELETE FROM vibe_ignores WHERE user_id = ? AND ignored_id = ?').run(req.user.id, userId);
  res.json({ ok: true });
});

// ============================================================================
//  BUILD A CREW
//  Idea -> the app assembles the crew. Finds people who fit by (a) matching the
//  chosen activity to their interests, (b) distance, and (c) Vibe Check overlap
//  when available; then suggests places to actually do the thing.
// ============================================================================

// Map each crew activity to: the interest tags that signal a fit, and the kind
// of place to suggest (label + a maps search term).
const CREW_ACTIVITIES = {
  bowling:  { emoji:'🎳', label:'Bowling',  interests:['Games & Trivia','Sports','Gaming'], place:{term:'bowling alley', label:'Bowling alleys'} },
  food:     { emoji:'🍔', label:'Food',     interests:['Food','Cooking','Coffee'], place:{term:'popular restaurants', label:'Restaurants'} },
  hiking:   { emoji:'🏕️', label:'Hiking',   interests:['Outdoors','Fitness','Camping','Travel'], place:{term:'hiking trails', label:'Trailheads & parks'} },
  gaming:   { emoji:'🎮', label:'Gaming',   interests:['Gaming','Games & Trivia','Tech'], place:{term:'game bar arcade', label:'Arcades & game bars'} },
  movies:   { emoji:'🎬', label:'Movies',   interests:['Movies','Theater'], place:{term:'movie theater', label:'Cinemas'} },
  coffee:   { emoji:'☕', label:'Coffee',   interests:['Coffee','Book Reviews','Book Club'], place:{term:'coffee shops', label:'Coffee shops'} },
  cars:     { emoji:'🚗', label:'Cars',     interests:['Cars','Motorcycles'], place:{term:'cars and coffee meetup', label:'Meetup spots'} },
  fitness:  { emoji:'🏋️', label:'Fitness',  interests:['Fitness','Sports','Outdoors','Wellness'], place:{term:'gym fitness studio', label:'Gyms & studios'} },
  art:      { emoji:'🎨', label:'Art',      interests:['Art','Crafts & DIY','Photography'], place:{term:'art gallery studio', label:'Galleries & studios'} },
  music:    { emoji:'🎵', label:'Music',    interests:['Music','Instruments','Dance'], place:{term:'live music venue', label:'Live music venues'} },
  drinks:   { emoji:'🍸', label:'Drinks',   interests:['Food','Music','Dance'], place:{term:'cocktail bar', label:'Bars & lounges'} },
  sports:   { emoji:'⚽', label:'Watch sports', interests:['Sports','Basketball','Football','Baseball','Soccer'], place:{term:'sports bar', label:'Sports bars'} },
  outdoors: { emoji:'🌳', label:'Outdoors', interests:['Outdoors','Camping','Fitness','Pets'], place:{term:'park', label:'Parks & green spaces'} },
  books:    { emoji:'📚', label:'Books',    interests:['Book Club','Book Reviews','Writing'], place:{term:'bookstore cafe', label:'Bookstores & cafés'} }
};

function crewMapsLink(term, lat, lng, city) {
  const q = encodeURIComponent(term + (city ? (' in ' + city) : ''));
  if (typeof lat === 'number' && typeof lng === 'number') {
    return 'https://www.google.com/maps/search/' + q + '/@' + lat + ',' + lng + ',13z';
  }
  return 'https://www.google.com/maps/search/' + q;
}

// Find people who fit an activity + distance, ranked by vibe + interest overlap.
app.get('/api/crew/build', requireAuth, async (req, res) => {
 try {
  const me = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const act = CREW_ACTIVITIES[(req.query.activity || '').toLowerCase()];
  if (!act) return res.status(400).json({ error: 'Pick an activity.' });
  const size = String(req.query.size || '3-4');
  const wanted = size === '7-10' ? 10 : (size === '5-6' ? 6 : 4);
  const radiusMi = Math.min(parseFloat(req.query.radius) || VIBE_RADIUS_MI, 100);
  const lat = parseFloat(req.query.lat), lng = parseFloat(req.query.lng);
  const hasLoc = !isNaN(lat) && !isNaN(lng);
  const myLat = hasLoc ? lat : me.lat, myLng = hasLoc ? lng : me.lng;
  const haveLoc = typeof myLat === 'number' && typeof myLng === 'number';

  const myVibe = parseVibe(me.vibe_answers);
  const ignoredRows = await db.prepare('SELECT ignored_id FROM vibe_ignores WHERE user_id = ?').all(req.user.id);
  const ignored = new Set(ignoredRows.map(r => r.ignored_id));
  const wantSet = new Set(act.interests);

  const others = await db.prepare('SELECT * FROM users WHERE id != ? AND suspended = 0').all(req.user.id);
  const pool = [];
  for (const u of others) {
    if (ignored.has(u.id)) continue;
    if (await isBlocked(req.user.id, u.id)) continue;
    let dist = null;
    if (haveLoc && typeof u.lat === 'number' && typeof u.lng === 'number') {
      dist = distanceMiles(myLat, myLng, u.lat, u.lng);
      if (dist > radiusMi) continue;
    } else if (haveLoc) {
      continue; // I have a location but they don't — can't confirm they're nearby
    } else {
      const a = (me.city || '').toLowerCase().trim(), b = (u.city || '').toLowerCase().trim();
      if (!a || !b || a !== b) continue;
    }
    let theirInterests = [];
    try { theirInterests = u.interests ? JSON.parse(u.interests) : []; } catch (e) { theirInterests = []; }
    if (!Array.isArray(theirInterests)) theirInterests = [];
    const interestHits = theirInterests.filter(x => wantSet.has(x)).length;
    // vibe overlap (0..100) if both have taken it
    let vibe = null;
    const uv = parseVibe(u.vibe_answers);
    if (myVibe && uv && answeredCount(myVibe) >= 10 && answeredCount(uv) >= 10) {
      vibe = vibeScore(myVibe.answers, uv.answers, VIBE_BASE_WEIGHTS).score;
    }
    // fit score: category match dominates, vibe boosts, closer is better
    const fit = interestHits * 22 + (vibe != null ? vibe * 0.5 : 0) + (dist != null ? Math.max(0, 20 - dist) : 0);
    if (interestHits === 0 && vibe == null) continue; // no signal at all → skip
    const rel = await friendStatus(req.user.id, u.id);
    pool.push({
      id: u.id, name: u.name, username: u.username || '', avatar: u.avatar || '',
      city: u.city || '', distance: dist, interestHits, vibe, fit, status: rel,
      isFriend: rel === 'friend'
    });
  }
  // Friends first (easiest to convince!), then best fit
  pool.sort((a, b) => (b.isFriend - a.isFriend) || b.fit - a.fit || (a.distance ?? 1e9) - (b.distance ?? 1e9));
  const suggested = pool.slice(0, Math.max(wanted + 4, 8)); // a few extra so the user can swap people out

  res.json({
    activity: { key:(req.query.activity||'').toLowerCase(), ...act },
    size, wanted,
    place: { label: act.place.label, mapsUrl: crewMapsLink(act.place.term, myLat, myLng, me.city) },
    people: suggested
  });
 } catch (e) {
  console.error('crew/build error:', e);
  res.status(500).json({ error: 'Could not build the crew right now.' });
 }
});

// Create the crew: makes a Round and invites the chosen people with a note.
app.post('/api/crew/create', requireAuth, async (req, res) => {
  const me = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const { activity, title, memberIds, place, lat, lng, event_at } = req.body || {};
  const act = CREW_ACTIVITIES[(activity || '').toLowerCase()];
  if (!act) return res.status(400).json({ error: 'Pick an activity.' });
  const ids = Array.isArray(memberIds) ? memberIds.filter(x => typeof x === 'string').slice(0, 20) : [];
  const round = {
    id: id(), title: String(title || (act.label + ' crew')).trim().slice(0, 80),
    emoji: act.emoji, category: act.label, blurb: 'A crew put together with Build a Crew ✨',
    host_id: req.user.id, created_at: now(),
    lat: (typeof lat === 'number') ? lat : (typeof me.lat === 'number' ? me.lat : null),
    lng: (typeof lng === 'number') ? lng : (typeof me.lng === 'number' ? me.lng : null),
    place: (place && typeof place === 'string') ? place.slice(0, 200) : null,
    photo: null, link: null,
    event_at: (typeof event_at === 'number' && event_at > 0) ? event_at : null
  };
  await db.prepare(`INSERT INTO rounds (id,title,emoji,category,blurb,host_id,created_at,lat,lng,place,photo,link,event_at)
              VALUES (@id,@title,@emoji,@category,@blurb,@host_id,@created_at,@lat,@lng,@place,@photo,@link,@event_at)`).run(round);
  await db.prepare('INSERT INTO memberships (round_id,user_id,joined_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(round.id, req.user.id, now());
  // invite each person via a notification linking to the Round
  let invited = 0;
  for (const uid of ids) {
    if (uid === req.user.id) continue;
    if (await isBlocked(req.user.id, uid)) continue;
    await pushNotif(uid, 'crew_invite', (me.name || 'Someone') + ' started a ' + act.label + ' crew ' + act.emoji,
      'You\'re a great fit for “' + round.title + '”. Tap to join!', 'round:' + round.id);
    invited++;
  }
  res.json({ ok: true, round, invited });
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
  const { toId, message } = req.body || {};
  if (!toId || toId === req.user.id) return res.status(400).json({ error: 'Invalid user.' });
  if (await isBlocked(req.user.id, toId)) return res.status(403).json({ error: 'Unavailable.' });
  const exists = await db.prepare('SELECT id FROM users WHERE id = ?').get(toId);
  if (!exists) return res.status(404).json({ error: 'User not found.' });
  if (await areFriends(req.user.id, toId)) return res.json({ ok: true, status: 'friend' });
  const msg = (typeof message === 'string') ? message.slice(0, 280) : null;
  // If they already sent YOU a request, accept it instead
  const incoming = await db.prepare('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?').get(toId, req.user.id);
  if (incoming) {
    await db.prepare('INSERT INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(req.user.id, toId, now());
    await db.prepare('INSERT INTO friendships (user_id,friend_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(toId, req.user.id, now());
    await db.prepare('DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?').run(toId, req.user.id);
    return res.json({ ok: true, status: 'friend' });
  }
  await db.prepare('INSERT INTO friend_requests (from_id,to_id,created_at,message) VALUES (?,?,?,?) ON CONFLICT (from_id,to_id) DO UPDATE SET message = excluded.message').run(req.user.id, toId, now(), msg);
  const preview = msg ? ('“' + msg.slice(0, 60) + (msg.length > 60 ? '…' : '') + '”') : ((req.user.name || 'Someone') + ' wants to be friends');
  await pushNotif(toId, 'friend_request', 'New friend request', preview, 'friends:requests');
  res.json({ ok: true, status: 'pending' });
});

// Incoming friend requests (people who want to add me)
app.get('/api/friends/requests', requireAuth, async (req, res) => {
  const rows = await db.prepare(`
    SELECT u.id, u.name, u.username, u.avatar, u.city, fr.message
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
  const { reportedId, context, reason, description } = req.body || {};
  const reportId = id();
  await db.prepare('INSERT INTO reports (id,reporter_id,reported_id,context,reason,description,status,created_at) VALUES (?,?,?,?,?,?,?,?)')
    .run(reportId, req.user.id, reportedId || null, String(context || '').slice(0, 200), String(reason || '').slice(0, 500), String(description || '').slice(0, 1000), 'open', now());

  // Let the reporter know it went through, with a running count so they can keep
  // track of how many reports they've filed (also doubles as an early, visible signal
  // if their own account is filing an unusual number of them).
  const reporterCountRow = await db.prepare('SELECT COUNT(*) AS n FROM reports WHERE reporter_id = ?').get(req.user.id);
  const reporterTotal = reporterCountRow ? Number(reporterCountRow.n) || 0 : 0;
  await pushNotif(
    req.user.id,
    'report_submitted',
    'Report received ✅',
    'You reported "' + (reason || 'an issue') + '"' + (description ? ' — "' + String(description).slice(0, 120) + '"' : '') + '. Our team will review it. This is report #' + reporterTotal + ' you\'ve submitted.',
    ''
  );

  // Notify every manager so reports don't sit unseen until someone happens to open the panel.
  const admins = await db.prepare('SELECT id FROM users WHERE is_admin = 1').all();
  for (const a of admins) {
    await pushNotif(
      a.id,
      'report_new',
      '🚩 New report submitted',
      'Reason: ' + (reason || 'Unspecified') + (description ? ' — "' + String(description).slice(0, 120) + '"' : ''),
      'admin:reports'
    );
  }

  res.json({ ok: true, id: reportId, total: reporterTotal });
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
    SELECT m.id AS message_id, m.round_id, m.body, m.created_at, u.name AS sender, r.title AS round_title, r.emoji AS round_emoji, r.photo AS round_photo
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

// View reports (admin only) — includes moderation status/verdict, an "incomplete for
// N days" age, and status counts for the metrics pills at the top of the panel.
app.get('/api/admin/reports', requireAuth, requireAdmin, async (req, res) => {
  const rows = await db.prepare(`
    SELECT r.id, r.context, r.reason, r.description, r.status, r.verdict, r.created_at, r.analyzed_at, r.resolved_at,
      r.reporter_id, reporter.name AS reporter_name, reporter.username AS reporter_username,
      r.reported_id, reported.name AS reported_name, reported.username AS reported_username, reported.suspended AS reported_suspended
    FROM reports r
    LEFT JOIN users reporter ON reporter.id = r.reporter_id
    LEFT JOIN users reported ON reported.id = r.reported_id
    ORDER BY r.created_at DESC LIMIT 200
  `).all();
  const t = now();
  const reports = rows.map(r => ({
    ...r,
    // Only counts up while the report is unresolved — freezes once resolved, per spec.
    days_incomplete: r.status === 'resolved' ? null : Math.floor((t - r.created_at) / 86400000)
  }));
  const countRows = await db.prepare('SELECT status, COUNT(*) AS n FROM reports GROUP BY status').all();
  const counts = { open: 0, investigating: 0, resolved: 0 };
  for (const c of countRows) { if (Object.prototype.hasOwnProperty.call(counts, c.status)) counts[c.status] = Number(c.n) || 0; }
  counts.all = counts.open + counts.investigating + counts.resolved;
  res.json({ reports, counts });
});

// Looks up the actual content behind a report's `context` field (e.g. "message:<id>",
// "user:<id>", "chat:<roundId>") so the Analyze panel can show the reported message,
// round, or profile inline instead of sending the manager off to go find it themselves.
async function getReportedItemPreview(r) {
  const context = String(r.context || '');
  const [kind, refId] = context.includes(':') ? [context.split(':')[0], context.split(':').slice(1).join(':')] : [context, null];

  if (kind === 'message' && refId) {
    // Could be a Round group-chat message or a DM — try both, Round first.
    const rm = await db.prepare(`
      SELECT m.id, m.body, m.kind, m.media_url, m.created_at, m.deleted, u.name AS sender_name, u.avatar AS sender_avatar,
        r.id AS round_id, r.title AS round_title
      FROM messages m LEFT JOIN users u ON u.id = m.user_id LEFT JOIN rounds r ON r.id = m.round_id
      WHERE m.id = ?
    `).get(refId);
    if (rm) {
      return {
        type: 'round_message', id: rm.id, body: rm.body, kind: rm.kind || 'text', media_url: rm.media_url,
        created_at: rm.created_at, deleted: !!rm.deleted, sender_name: rm.sender_name, sender_avatar: rm.sender_avatar,
        round_id: rm.round_id, round_title: rm.round_title
      };
    }
    const dm = await db.prepare(`
      SELECT m.id, m.body, m.kind, m.media_url, m.created_at, m.deleted, u.name AS sender_name, u.avatar AS sender_avatar,
        c.id AS conv_id, c.title AS conv_title, c.is_group
      FROM dm_messages m LEFT JOIN users u ON u.id = m.user_id LEFT JOIN conversations c ON c.id = m.conv_id
      WHERE m.id = ?
    `).get(refId);
    if (dm) {
      return {
        type: 'dm_message', id: dm.id, body: dm.body, kind: dm.kind || 'text', media_url: dm.media_url,
        created_at: dm.created_at, deleted: !!dm.deleted, sender_name: dm.sender_name, sender_avatar: dm.sender_avatar,
        conv_id: dm.conv_id, conv_title: dm.is_group ? dm.conv_title : null
      };
    }
    return null;
  }

  if (kind === 'chat') {
    // refId is the Round id when the whole chat was reported from the group-chat options menu.
    const roundId = refId || null;
    if (!roundId) return null;
    const round = await db.prepare('SELECT id, title, emoji, photo, category, blurb, host_id FROM rounds WHERE id = ?').get(roundId);
    if (!round) return null;
    const memberRow = await db.prepare('SELECT COUNT(*) AS n FROM memberships WHERE round_id = ?').get(round.id);
    return { type: 'round', ...round, member_count: memberRow ? Number(memberRow.n) || 0 : 0 };
  }

  if (kind === 'user' || r.reported_id) {
    const uid = refId || r.reported_id;
    if (!uid) return null;
    const u = await db.prepare('SELECT id, name, username, avatar, bio FROM users WHERE id = ?').get(uid);
    if (!u) return null;
    return { type: 'user', ...u };
  }

  return null;
}

// Analyze: opens the report for review. Auto-advances "open" -> "investigating" so the
// status reflects that a manager is actively on it, and hands back everything the
// Analyze panel needs, including the reported message/round/profile itself so the
// manager can review it inline without leaving the panel.
app.post('/api/admin/reports/:id/analyze', requireAuth, requireAdmin, async (req, res) => {
  const r = await db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Report not found.' });
  if (r.status === 'open') {
    await db.prepare('UPDATE reports SET status = ?, analyzed_at = ? WHERE id = ?').run('investigating', now(), r.id);
  }
  const updated = await db.prepare(`
    SELECT r.*, reported.username AS reported_username, reported.name AS reported_name
    FROM reports r LEFT JOIN users reported ON reported.id = r.reported_id WHERE r.id = ?
  `).get(r.id);
  let item = null;
  try { item = await getReportedItemPreview(updated); } catch (e) { item = null; }
  res.json({ ok: true, report: { ...updated, item } });
});

// Discard: the report didn't hold up — mark it unfounded, optionally tell the reporter
// why, and check whether this reporter is racking up a pattern of unfounded reports
// (especially repeatedly against the same account, which reads as targeted/malicious).
app.post('/api/admin/reports/:id/discard', requireAuth, requireAdmin, async (req, res) => {
  const r = await db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Report not found.' });
  await db.prepare('UPDATE reports SET verdict = ? WHERE id = ?').run('discarded', r.id);
  const { message } = req.body || {};
  // Always tell the reporter the actual conclusion — not a vague "update" — so they
  // know we reviewed it and why it didn't lead to action. Any manager note is appended.
  const discardBody = 'We reviewed your report' + (r.reason ? ' about "' + r.reason + '"' : '')
    + " and didn't find that it violated our Community Pact, so no action was taken."
    + (message && String(message).trim() ? ' Note from our team: "' + String(message).trim().slice(0, 400) + '"' : '');
  await pushNotif(r.reporter_id, 'report_discarded', 'Report reviewed — no violation found', discardBody.slice(0, 600), '');
  let warning = null;
  const unfoundedRow = await db.prepare(`SELECT COUNT(*) AS n FROM reports WHERE reporter_id = ? AND verdict = 'discarded'`).get(r.reporter_id);
  const unfoundedTotal = unfoundedRow ? Number(unfoundedRow.n) || 0 : 0;
  if (unfoundedTotal >= 5) {
    let sameTargetNote = '';
    if (r.reported_id) {
      const sameTargetRow = await db.prepare(`SELECT COUNT(*) AS n FROM reports WHERE reporter_id = ? AND reported_id = ? AND verdict = 'discarded'`).get(r.reporter_id, r.reported_id);
      const sameTargetCount = sameTargetRow ? Number(sameTargetRow.n) || 0 : 0;
      if (sameTargetCount >= 3) sameTargetNote = ' ' + sameTargetCount + ' of those were against the very same account — this looks targeted.';
    }
    warning = { type: 'reporter_unfounded', count: unfoundedTotal, message: 'This account has filed ' + unfoundedTotal + ' reports that turned out to be unfounded.' + sameTargetNote + ' Consider reviewing their reporting activity for possible misuse.' };
  }
  res.json({ ok: true, warning });
});

// Validate: the report held up — mark it confirmed, optionally notify the reported
// account, and check the account's validated-report count against the escalation
// thresholds (3+ = suggest a temporary suspension, 5+ = recommend termination).
app.post('/api/admin/reports/:id/validate', requireAuth, requireAdmin, async (req, res) => {
  const r = await db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Report not found.' });
  await db.prepare('UPDATE reports SET verdict = ? WHERE id = ?').run('validated', r.id);
  const { message } = req.body || {};
  // Tell the reporter their report was confirmed — separate from the (optional) notice
  // sent to the reported account below, which is about their account, not the report.
  const validateBody = 'We reviewed your report' + (r.reason ? ' about "' + r.reason + '"' : '')
    + ' and confirmed it violated our Community Pact. Thanks for helping keep ShowUpp safe — we took action.';
  await pushNotif(r.reporter_id, 'report_conclusion', 'Report reviewed — violation confirmed', validateBody.slice(0, 600), '');
  if (message && String(message).trim() && r.reported_id) {
    await pushNotif(r.reported_id, 'report_validated', 'Account notice', String(message).slice(0, 500), '');
  }
  let warning = null;
  if (r.reported_id) {
    const row = await db.prepare(`SELECT COUNT(*) AS n FROM reports WHERE reported_id = ? AND verdict = 'validated'`).get(r.reported_id);
    const validatedTotal = row ? Number(row.n) || 0 : 0;
    if (validatedTotal >= 5) {
      warning = { type: 'terminate', count: validatedTotal, message: 'This account now has ' + validatedTotal + ' validated reports against it. We recommend terminating this account.' };
    } else if (validatedTotal >= 3) {
      warning = { type: 'suspend', count: validatedTotal, message: 'This account now has ' + validatedTotal + ' validated reports against it. Consider temporarily suspending it.' };
    }
  }
  res.json({ ok: true, warning });
});

// Close: analysis is done — move the report to Resolved and freeze its "days incomplete" count.
app.post('/api/admin/reports/:id/close', requireAuth, requireAdmin, async (req, res) => {
  const r = await db.prepare('SELECT id FROM reports WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Report not found.' });
  await db.prepare('UPDATE reports SET status = ?, resolved_at = ? WHERE id = ?').run('resolved', now(), r.id);
  res.json({ ok: true });
});

// Permanently delete a report (admin only) — gated by a secondary supervisor password.
app.post('/api/admin/reports/:id/delete', requireAuth, requireAdmin, async (req, res) => {
  const { supervisorPassword } = req.body || {};
  if (!supervisorPassword || String(supervisorPassword) !== SUPERVISOR_PASSWORD) {
    return res.status(403).json({ error: 'Incorrect supervisor password.' });
  }
  const r = await db.prepare('SELECT id FROM reports WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Report not found.' });
  await db.prepare('DELETE FROM reports WHERE id = ?').run(r.id);
  res.json({ ok: true });
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

// Toggle save/bookmark on an event (mirrors the Round save behavior).
app.post('/api/events/:id/save', requireAuth, async (req, res) => {
  const ev = await db.prepare('SELECT id FROM events WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Event not found.' });
  const existing = await db.prepare('SELECT 1 FROM saved_events WHERE event_id=? AND user_id=?').get(req.params.id, req.user.id);
  if (existing) await db.prepare('DELETE FROM saved_events WHERE event_id=? AND user_id=?').run(req.params.id, req.user.id);
  else await db.prepare('INSERT INTO saved_events (event_id,user_id,created_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(req.params.id, req.user.id, now());
  res.json({ ok: true, saved: !existing });
});

// List events the user has saved.
app.get('/api/saved-events', requireAuth, async (req, res) => {
  const lat = parseFloat(req.query.lat), lng = parseFloat(req.query.lng);
  const hasLoc = !isNaN(lat) && !isNaN(lng);
  const rows = await db.prepare(`
    SELECT e.* FROM events e JOIN saved_events se ON se.event_id = e.id
    WHERE se.user_id = ? ORDER BY se.created_at DESC
  `).all(req.user.id);
  const events = rows.map(e => {
    let dist = (hasLoc && typeof e.lat === 'number' && typeof e.lng === 'number') ? distanceMiles(lat, lng, e.lat, e.lng) : null;
    return { ...e, source_label: e.source === 'community' ? 'Community' : (e.source_label || e.source), distance: dist, i_saved: true };
  });
  res.json({ events });
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
  // Item 1 defense-in-depth: if someone pasted a maps LINK into the place field,
  // never store the raw URL as the "address". Salvage coordinates from it when the
  // client didn't already supply them, then blank the place text so the UI doesn't
  // show a URL where a street address belongs.
  let finalLat = (typeof lat === 'number') ? lat : null;
  let finalLng = (typeof lng === 'number') ? lng : null;
  let finalPlace = place || null;
  if (finalPlace && looksLikeUrl(String(finalPlace))) {
    const salvaged = coordsFromMapUrl(String(finalPlace));
    if (salvaged && finalLat == null) { finalLat = salvaged.lat; finalLng = salvaged.lng; }
    finalPlace = null; // don't keep a link masquerading as an address
  }
  const round = {
    id: id(), title: String(title).trim(), emoji: emoji || '✨',
    category: category || 'General', blurb: blurb || '',
    host_id: req.user.id, created_at: now(),
    lat: finalLat,
    lng: finalLng,
    place: finalPlace,
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

// PROVIDER REGISTRY — one entry per event-account type the Manager panel offers with
// automatic fetching. Each function takes (apiKey, label) and returns normalized US-wide
// events for the next EVENT_INGEST_WINDOW_DAYS days. A source whose provider ISN'T listed
// here (e.g. a manually-labeled account — see "Other / manual" in the Manager panel) is
// simply never auto-fetched; its events are added by hand via the admin panel instead.
// To support a new paid source later (Eventbrite, SeatGeek, etc.), add a key here and
// list it in the Manager panel's provider dropdown — nothing else needs to change.
// Pull events up to a full year ahead so people can plan well in advance (item 4).
const EVENT_INGEST_WINDOW_DAYS = 365;
// ---- Event classifier (items 1 & 4) ----
// Ticketmaster tags each event with a broad "segment" (Sports, Music, Arts & Theatre,
// Film, Miscellaneous...). Using that raw segment as our category is what let a sporting
// event land under the wrong bucket — e.g. anything Ticketmaster couldn't segment cleanly
// defaulted oddly. This classifier maps the RICH classification (segment + genre +
// subGenre) plus a light keyword pass over the title into ShowUpp's own category names,
// with a matching emoji. It runs once per event at ingest time (not per request), so it
// adds zero cost to the hot path and can't slow the app down or crash it. Pure function,
// no I/O, wrapped by callers in try/catch.
const EVENT_CATEGORY_EMOJI = {
  'Sports': '⚽', 'Basketball': '🏀', 'Baseball': '⚾', 'Football': '🏈', 'Tennis': '🎾',
  'Music': '🎵', 'Comedy': '🎤', 'Theater': '🎭', 'Movies': '🎬', 'Art': '🎨',
  'Family': '🎪', 'Food': '🍽️', 'Culture': '🌍', 'Event': '🎟️'
};
// Keyword → category, checked against genre/subGenre/title when the segment alone is
// ambiguous (Miscellaneous/Undefined) or to refine a specific sport. Ordered most- to
// least-specific; first match wins.
const CLASSIFY_KEYWORDS = [
  [/\bnba\b|basketball|hoops/i, 'Basketball'],
  [/\bmlb\b|baseball|béisbol|beisbol/i, 'Baseball'],
  [/\bnfl\b|american football|gridiron/i, 'Football'],
  [/\btennis\b|atp|wta/i, 'Tennis'],
  [/soccer|f[uú]tbol|fifa|la liga|premier league|mls\b/i, 'Sports'],
  [/hockey|nhl\b/i, 'Sports'],
  [/golf|pga\b/i, 'Sports'],
  [/boxing|\bmma\b|\bufc\b|wrestling|wwe\b/i, 'Sports'],
  [/marathon|running|cycling|swim|athletic|olympic|rugby|cricket|volleyball|motorsport|nascar|racing/i, 'Sports'],
  [/comedy|comedian|stand-?up|improv/i, 'Comedy'],
  [/theat(er|re)|broadway|musical|opera|ballet|dance|drama|playhouse/i, 'Theater'],
  [/film|movie|cinema|screening/i, 'Movies'],
  [/\bart\b|gallery|exhibit|museum|painting|sculpture/i, 'Art'],
  [/food|wine|beer|tasting|culinary|restaurant|brunch|dining/i, 'Food'],
  [/festival|concert|dj\b|live music|symphony|orchestra|band|tour\b/i, 'Music'],
  [/family|kids|children|circus|disney on ice/i, 'Family']
];
// Ticketmaster segment.name → our category (the reliable, coarse mapping).
const SEGMENT_MAP = {
  'sports': 'Sports', 'music': 'Music', 'arts & theatre': 'Theater',
  'arts & theater': 'Theater', 'film': 'Movies', 'comedy': 'Comedy',
  'family': 'Family', 'miscellaneous': null, 'undefined': null
};
// Ticketmaster genre.name → our category, used to refine within a segment (e.g. a Sports
// event whose genre is "Basketball" becomes Basketball, not generic Sports).
const GENRE_MAP = {
  'basketball': 'Basketball', 'baseball': 'Baseball', 'football': 'Football',
  'tennis': 'Tennis', 'comedy': 'Comedy', 'theatre': 'Theater', 'theater': 'Theater',
  'dance': 'Theater', 'classical': 'Music', 'rock': 'Music', 'pop': 'Music',
  'hip-hop/rap': 'Music', 'jazz': 'Music', 'country': 'Music', 'latin': 'Music',
  'film': 'Movies', 'fine art': 'Art', 'arts': 'Art'
};
// Classify one raw Ticketmaster event object. Returns { category, emoji }.
function classifyTicketmasterEvent(e) {
  try {
    const cls = (e.classifications && e.classifications[0]) || {};
    const segment = (cls.segment && cls.segment.name || '').trim();
    const genre = (cls.genre && cls.genre.name || '').trim();
    const subGenre = (cls.subGenre && cls.subGenre.name || '').trim();
    const title = (e.name || '').trim();

    let category = null;

    // 1) Genre is the most specific reliable signal — try it first.
    if (genre && GENRE_MAP[genre.toLowerCase()]) category = GENRE_MAP[genre.toLowerCase()];

    // 2) Fall back to the coarse segment mapping.
    if (!category && segment) {
      const seg = segment.toLowerCase();
      if (Object.prototype.hasOwnProperty.call(SEGMENT_MAP, seg)) category = SEGMENT_MAP[seg];
      else category = null; // unknown segment → let keywords decide
    }

    // 3) If still unresolved (or the segment was Miscellaneous/Undefined), run the keyword
    //    pass over genre + subGenre + title so a mis-segmented sporting event, say, still
    //    lands in Sports instead of a random bucket.
    if (!category) {
      const hay = [genre, subGenre, title].filter(Boolean).join(' ');
      for (const [re, cat] of CLASSIFY_KEYWORDS) { if (re.test(hay)) { category = cat; break; } }
    }

    // 4) Even when we DID get a category from the segment (e.g. generic "Sports"), let a
    //    specific keyword refine it to the exact sport when the title makes it obvious.
    if (category === 'Sports') {
      const hay = [genre, subGenre, title].filter(Boolean).join(' ');
      for (const [re, cat] of CLASSIFY_KEYWORDS) {
        if (['Basketball', 'Baseball', 'Football', 'Tennis'].includes(cat) && re.test(hay)) { category = cat; break; }
      }
    }

    if (!category) category = 'Event';
    return { category, emoji: EVENT_CATEGORY_EMOJI[category] || '🎟️' };
  } catch (err) {
    return { category: 'Event', emoji: '🎟️' };
  }
}

function normalizeTicketmasterEvent(e, label, country) {
  const v = (e._embedded && e._embedded.venues && e._embedded.venues[0]) || {};
  const loc = v.location || {};
  const { category, emoji } = classifyTicketmasterEvent(e); // items 1 & 4
  // Country: prefer the venue's own country code, fall back to the ingest country param.
  const venueCC = (v.country && (v.country.countryCode || v.country.code)) || '';
  return {
    id: 'tm_' + e.id, source: 'ticketmaster', source_id: e.id,
    title: e.name, description: (e.info || e.pleaseNote || ''),
    category: category,
    emoji: emoji,
    photo: (e.images && e.images[0] && e.images[0].url) || null,
    link: e.url || null,
    place: v.name || (v.city && v.city.name) || '',
    lat: loc.latitude ? parseFloat(loc.latitude) : null,
    lng: loc.longitude ? parseFloat(loc.longitude) : null,
    starts_at: (e.dates && e.dates.start && e.dates.start.dateTime) ? new Date(e.dates.start.dateTime).getTime() : null,
    ends_at: null, source_label: label || 'Ticketmaster',
    country: (venueCC || country || '').toUpperCase() || null
  };
}
// Countries we ingest from Ticketmaster. US is the largest catalog, but ShowUpp is used
// abroad (e.g. the Dominican Republic), and hardcoding countryCode=US meant non-US users
// saw nothing local (item 6). This list covers the app's primary markets; Ticketmaster's
// Discovery API supports each of these country codes. Override with the TICKETMASTER_COUNTRIES
// env var (comma-separated ISO codes) without a code change.
const TM_DEFAULT_COUNTRIES = ['US', 'DO', 'CA', 'MX', 'GB', 'IE', 'AU', 'NZ', 'ES', 'DE', 'FR', 'NL', 'PR'];
function ticketmasterCountries() {
  const raw = (process.env.TICKETMASTER_COUNTRIES || '').trim();
  if (raw) return raw.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
  return TM_DEFAULT_COUNTRIES;
}

// Pages through Ticketmaster's catalog for EACH configured country, in weekly slices
// (rather than one huge date range) so a single slow/failed page never loses the whole
// window, and caps pages per slice so one ingest run can't run away against the API's
// rate limit. Returns { events, error }.
async function fetchTicketmaster(apiKey, label, countries) {
  if (!apiKey) return { events: [], error: 'No API key configured for this source.' };
  const events = [];
  let lastError = null;
  const ccs = (countries && countries.length) ? countries : ticketmasterCountries();
  // Keep the per-country page budget modest so covering many countries doesn't multiply
  // into a runaway number of requests. US gets a little more depth than the rest.
  const sliceDays = 7, pageSize = 200;
  for (const cc of ccs) {
    const maxPagesPerSlice = (cc === 'US') ? 5 : 2; // 5*200 US, 2*200 others per slice
    for (let offset = 0; offset < EVENT_INGEST_WINDOW_DAYS; offset += sliceDays) {
      const sliceStart = new Date(Date.now() + offset * 86400000);
      const sliceEnd = new Date(Date.now() + Math.min(offset + sliceDays, EVENT_INGEST_WINDOW_DAYS) * 86400000);
      const startDateTime = sliceStart.toISOString().split('.')[0] + 'Z';
      const endDateTime = sliceEnd.toISOString().split('.')[0] + 'Z';
      for (let page = 0; page < maxPagesPerSlice; page++) {
        const url = `https://app.ticketmaster.com/discovery/v2/events.json?apikey=${encodeURIComponent(apiKey)}&countryCode=${encodeURIComponent(cc)}&size=${pageSize}&page=${page}&sort=date,asc&startDateTime=${startDateTime}&endDateTime=${endDateTime}`;
        let r;
        try { r = await fetch(url); } catch (err) { lastError = `Network error: ${err.message}`; break; }
        if (!r.ok) {
          let detail = r.statusText;
          try { const body = await r.json(); detail = (body.fault && body.fault.faultstring) || (body.errors && body.errors[0] && body.errors[0].detail) || detail; } catch (e) {}
          lastError = `Ticketmaster returned HTTP ${r.status}${detail ? ' — ' + detail : ''} (country ${cc})`;
          break; // stop this country's slice rather than throwing the whole ingest away
        }
        const data = await r.json();
        const evs = (data._embedded && data._embedded.events) || [];
        for (const e of evs) events.push(normalizeTicketmasterEvent(e, label, cc));
        const totalPages = (data.page && data.page.totalPages) || 1;
        if (page + 1 >= totalPages || evs.length === 0) break;
        await new Promise(res => setTimeout(res, 250)); // be gentle on the rate limit
      }
    }
  }
  return { events, error: events.length === 0 ? lastError : null };
}
// Back-compat alias — older callers referenced fetchTicketmasterUS.
async function fetchTicketmasterUS(apiKey, label) { return fetchTicketmaster(apiKey, label); }
const EVENT_PROVIDERS = {
  ticketmaster: async (s) => fetchTicketmaster(s.api_key, s.label)
  // Add more API providers here later the same way, e.g.:
  //   eventbrite: async (s) => { ...page through their API, return normalized events... }
};
// Providers that read a plain website (no API). Kept separate because they take a URL
// instead of an API key and share one scraping implementation.
const WEBSITE_PROVIDER = 'website';

// ---- Website auto-reader (no API) ----------------------------------------
// Fetches an organizer/promoter's public events page and extracts events WITHOUT
// any API. Strategy, most-reliable first:
//   1) schema.org "Event" JSON-LD (<script type="application/ld+json">) — the
//      structured data most event sites already embed for Google. This is by far
//      the most accurate, so we use it whenever present.
//   2) A light fallback that scans for time tags / date-ish text near headings.
// Anything we can't confidently parse is skipped rather than guessed.
function stripTags(html) { return String(html || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim(); }
function decodeEntities(s) {
  return String(s || '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
}
function absolutizeUrl(href, base) {
  if (!href) return null;
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function collectJsonLdEvents(node, out) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) { node.forEach(n => collectJsonLdEvents(n, out)); return; }
  const t = node['@type'];
  const types = Array.isArray(t) ? t : [t];
  if (types.some(x => typeof x === 'string' && /Event$/i.test(x))) out.push(node);
  // Common containers: @graph, itemListElement, subEvent
  if (node['@graph']) collectJsonLdEvents(node['@graph'], out);
  if (node.itemListElement) collectJsonLdEvents(node.itemListElement, out);
  if (node.subEvent) collectJsonLdEvents(node.subEvent, out);
  if (node.item) collectJsonLdEvents(node.item, out);
}
function normalizeWebsiteEvent(ev, s, pageUrl) {
  const name = decodeEntities(ev.name || ev.headline || '');
  if (!name) return null;
  let starts = null;
  const sd = ev.startDate || (ev.subEvent && ev.subEvent.startDate) || null;
  if (sd) { const ms = Date.parse(sd); if (!isNaN(ms)) starts = ms; }
  const loc = ev.location || {};
  let place = '';
  if (typeof loc === 'string') place = loc;
  else if (loc.name) place = loc.name;
  else if (loc.address) place = (typeof loc.address === 'string') ? loc.address : (loc.address.streetAddress || loc.address.addressLocality || '');
  const geo = (loc && loc.geo) || {};
  const lat = geo.latitude != null ? parseFloat(geo.latitude) : null;
  const lng = geo.longitude != null ? parseFloat(geo.longitude) : null;
  let photo = null;
  if (ev.image) photo = Array.isArray(ev.image) ? (ev.image[0] && (ev.image[0].url || ev.image[0])) : (ev.image.url || ev.image);
  let link = ev.url || ev.mainEntityOfPage || null;
  link = absolutizeUrl(typeof link === 'object' ? (link['@id'] || link.url) : link, pageUrl) || pageUrl;
  // Stable id from source + link/name so re-reads upsert instead of duplicating.
  const key = (link || '') + '|' + name + '|' + (sd || '');
  const hash = require('crypto').createHash('md5').update(key).digest('hex').slice(0, 16);
  const { category, emoji } = classifyByText(name + ' ' + decodeEntities(ev.description || ''));
  return {
    id: 'web_' + s.id + '_' + hash,
    source: WEBSITE_PROVIDER + ':' + s.id,
    source_id: hash,
    title: name.slice(0, 200),
    description: decodeEntities(stripTags(ev.description || '')).slice(0, 1000),
    category, emoji,
    photo: (typeof photo === 'string' ? absolutizeUrl(photo, pageUrl) : null),
    link,
    place: String(place || '').slice(0, 200),
    lat: (typeof lat === 'number' && !isNaN(lat)) ? lat : null,
    lng: (typeof lng === 'number' && !isNaN(lng)) ? lng : null,
    starts_at: starts, ends_at: (ev.endDate ? (Date.parse(ev.endDate) || null) : null),
    source_label: s.label || 'Website',
    country: null
  };
}
// Very light keyword classifier for website events (Ticketmaster has its own richer one).
function classifyByText(text) {
  const t = (text || '').toLowerCase();
  const map = [
    [/\b(concert|music|band|dj|live music|festival|tour)\b/, 'Music', '🎵'],
    [/\b(comedy|stand-?up)\b/, 'Comedy', '🎤'],
    [/\b(theat|play|musical|opera|ballet)\b/, 'Theater', '🎭'],
    [/\b(art|gallery|exhibit|museum)\b/, 'Art', '🎨'],
    [/\b(food|taste|dining|dinner|brunch|wine|beer|culinary)\b/, 'Food', '🍽️'],
    [/\b(run|marathon|yoga|fitness|workout|game|match|tournament|sports?)\b/, 'Sports', '🏃'],
    [/\b(dance|salsa|bachata|dancing)\b/, 'Dance', '💃'],
    [/\b(book|author|reading|poetry)\b/, 'Book Club', '📚'],
    [/\b(tech|startup|hackathon|coding|developer)\b/, 'Tech', '💻'],
    [/\b(market|fair|festival|fest)\b/, 'Culture', '🎪']
  ];
  for (const [re, category, emoji] of map) if (re.test(t)) return { category, emoji };
  return { category: 'Event', emoji: '🎟️' };
}
async function fetchWebsiteEvents(s) {
  const pageUrl = (s.url || '').trim();
  if (!pageUrl) return { events: [], error: 'No website URL configured for this source.' };
  let html;
  try {
    const r = await fetch(pageUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ShowUppBot/1.0; +https://showupp.app)', 'Accept': 'text/html' } });
    if (!r.ok) return { events: [], error: `Website returned HTTP ${r.status} ${r.statusText}` };
    html = await r.text();
  } catch (err) { return { events: [], error: 'Could not reach the website: ' + err.message }; }

  const out = [];
  // 1) JSON-LD structured data
  const ldRe = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = ldRe.exec(html)) !== null) {
    let json;
    try { json = JSON.parse(m[1].trim()); } catch (e) { continue; }
    const events = [];
    collectJsonLdEvents(json, events);
    for (const ev of events) { const n = normalizeWebsiteEvent(ev, s, pageUrl); if (n) out.push(n); }
  }
  // Deduplicate by id (some sites repeat the same JSON-LD block).
  const seen = new Set();
  const deduped = out.filter(e => { if (seen.has(e.id)) return false; seen.add(e.id); return true; });

  if (!deduped.length) {
    return { events: [], error: "Couldn't find machine-readable events on that page. Sites that publish schema.org Event data (most do, for Google) work automatically; otherwise add this source's events by hand." };
  }
  return { events: deduped, error: null };
}


// ---- Daily ingest job ----
// Runs once at boot and then every 24h (see bottom of file). Pulls each enabled
// provider account's events straight into the `events` table (upserted by id, so
// re-running just refreshes rows instead of duplicating them), then trims anything
// that's now outside the 1-year display window. Request time (`/api/events` below)
// never talks to a provider — it only ever reads from our own indexed table, so a
// slow or rate-limited provider can't slow down anyone's app.
async function upsertExternalEvent(e) {
  const row = {
    id: e.id, source: e.source, source_id: e.source_id || null,
    title: String(e.title || '').slice(0, 200), description: String(e.description || '').slice(0, 1000),
    category: e.category || 'Event', emoji: e.emoji || '🎟️',
    photo: e.photo || null, link: e.link || null, place: String(e.place || '').slice(0, 200),
    lat: (typeof e.lat === 'number') ? e.lat : null, lng: (typeof e.lng === 'number') ? e.lng : null,
    starts_at: e.starts_at || null, ends_at: e.ends_at || null,
    posted_by: null, approved: 1, created_at: now(), source_label: e.source_label || e.source,
    country: e.country || null
  };
  await db.prepare(`
    INSERT INTO events (id,source,source_id,title,description,category,emoji,photo,link,place,lat,lng,starts_at,ends_at,posted_by,approved,created_at,source_label,country)
    VALUES (@id,@source,@source_id,@title,@description,@category,@emoji,@photo,@link,@place,@lat,@lng,@starts_at,@ends_at,@posted_by,@approved,@created_at,@source_label,@country)
    ON CONFLICT (id) DO UPDATE SET
      title=excluded.title, description=excluded.description, category=excluded.category, emoji=excluded.emoji,
      photo=excluded.photo, link=excluded.link, place=excluded.place, lat=excluded.lat, lng=excluded.lng,
      starts_at=excluded.starts_at, ends_at=excluded.ends_at, source_label=excluded.source_label, country=excluded.country
  `).run(row);
}
// Pulls one source's events and records ingest health on its row. Shared by the
// scheduled all-sources job and the Manager panel's per-account "Refresh now" button,
// so a manual refresh behaves identically to the nightly one instead of being a
// second, subtly-different code path.
async function ingestOneSource(s) {
  const isWebsite = (s.provider === WEBSITE_PROVIDER);
  const fn = isWebsite ? fetchWebsiteEvents : EVENT_PROVIDERS[s.provider];
  if (!fn) return { ok: false, error: 'This source has no automatic provider — add its events manually instead.' };
  const cutoff = now() + EVENT_INGEST_WINDOW_DAYS * 24 * 3600 * 1000;
  try {
    // Website provider reads s.url; registered API providers read s.api_key. Both now
    // receive the whole source row so each can pull what it needs.
    const result = await fn(s);
    const evs = result.events || [];
    let kept = 0;
    for (const e of evs) {
      if (e.starts_at && e.starts_at > cutoff) continue; // outside the display window — skip storing it
      await upsertExternalEvent(e);
      kept++;
    }
    console.log(`[events] ingested ${kept}/${evs.length} from ${s.provider} (${s.label})${result.error ? ' — error: ' + result.error : ''}`);
    await db.prepare('UPDATE event_sources SET last_ingest_at=?, last_error=?, last_fetched_count=? WHERE id=?')
      .run(now(), result.error || null, kept, s.id);
    // Trim this source's own past/out-of-window events. Website events are namespaced
    // per source ('website:<id>'); API providers use the provider key as the source.
    const srcKey = isWebsite ? (WEBSITE_PROVIDER + ':' + s.id) : s.provider;
    await db.prepare(`DELETE FROM events WHERE source = ? AND starts_at IS NOT NULL AND (starts_at < ? OR starts_at > ?)`)
      .run(srcKey, now() - 6 * 3600 * 1000, cutoff);
    return { ok: true, kept, total: evs.length, error: result.error || null };
  } catch (err) {
    console.log('[events] ingest failed for', s.provider, err.message);
    await db.prepare('UPDATE event_sources SET last_ingest_at=?, last_error=?, last_fetched_count=? WHERE id=?')
      .run(now(), err.message, 0, s.id).catch(() => {});
    return { ok: false, error: err.message };
  }
}
let eventIngestRunning = false;
async function ingestExternalEvents() {
  if (eventIngestRunning) return; // don't overlap a manual "refresh now" with the scheduled run
  eventIngestRunning = true;
  const cutoff = now() + EVENT_INGEST_WINDOW_DAYS * 24 * 3600 * 1000;
  try {
    const sources = await db.prepare('SELECT * FROM event_sources WHERE enabled = 1').all();
    for (const s of sources) {
      const auto = EVENT_PROVIDERS[s.provider] || s.provider === WEBSITE_PROVIDER;
      if (!auto) continue; // manual/unregistered provider — nothing to auto-fetch
      await ingestOneSource(s);
    }
    // env-var fallback key, for deployments that set it instead of using the Manager panel
    if (process.env.TICKETMASTER_API_KEY && !sources.some(s => s.provider === 'ticketmaster')) {
      try {
        const result = await fetchTicketmaster(process.env.TICKETMASTER_API_KEY, 'Ticketmaster');
        for (const e of (result.events || [])) { if (!e.starts_at || e.starts_at <= cutoff) await upsertExternalEvent(e); }
      } catch (err) {}
    }
    // Trim: drop non-community events that are now in the past or have fallen outside
    // the display window (e.g. a provider stopped returning them). Community posts are
    // left for their poster/admin to manage via the existing delete endpoint.
    await db.prepare(`DELETE FROM events WHERE source != 'community' AND (starts_at IS NULL OR starts_at < ? OR starts_at > ?)`)
      .run(now() - 6 * 3600 * 1000, cutoff);
  } finally { eventIngestRunning = false; }
}

// List events, paginated. Reads only from our own DB — see ingest job above.
// The same filters the UI exposes for Rounds now apply to API-sourced events too
// (item 1): category, a date-range ("when": today | week | month | any), and — when
// a location and a maxDistance are given — a distance cap. Distance is computed in
// SQL so the cap and the nearest-first ordering apply across the *entire* feed, not
// just whatever page happens to be loaded.
app.get('/api/events', requireAuth, async (req, res) => {
  const lat = parseFloat(req.query.lat), lng = parseFloat(req.query.lng);
  const category = req.query.category || null;
  const hasLoc = !isNaN(lat) && !isNaN(lng);
  const page = Math.max(0, parseInt(req.query.page) || 0);
  const pageSize = Math.min(50, Math.max(1, parseInt(req.query.pageSize) || 25));
  const cutoff = now() + EVENT_INGEST_WINDOW_DAYS * 24 * 3600 * 1000;

  // ---- Date-range ("when") filter — mirrors the app's Today / This week / This month chips.
  // Computed as an upper bound on starts_at (in ms). "today" also needs a same-calendar-day
  // check, which we do in JS after the query since day boundaries are timezone-sensitive.
  const when = (req.query.when || 'any').toLowerCase();
  const startFloor = now() - 6 * 3600 * 1000; // include things that started in the last few hours
  let whenCeil = cutoff;
  let dateFloorOverride = null; // set when a specific-date range is requested
  if (when === 'today') whenCeil = Math.min(cutoff, now() + 24 * 3600 * 1000);
  else if (when === 'week') whenCeil = Math.min(cutoff, now() + 7 * 24 * 3600 * 1000);
  else if (when === 'month') whenCeil = Math.min(cutoff, now() + 31 * 24 * 3600 * 1000);

  // Specific-date range (item 2): overrides the presets. dateFrom/dateTo are YYYY-MM-DD;
  // we bound starts_at to [00:00 of dateFrom, 23:59:59 of dateTo]. This can look further
  // ahead than the normal display window, so it also lifts the ceiling up to the range end.
  const dfRaw = String(req.query.dateFrom || '').trim();
  const dtRaw = String(req.query.dateTo || dfRaw).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(dfRaw)) {
    const from = new Date(dfRaw + 'T00:00:00').getTime();
    const to = new Date((/^\d{4}-\d{2}-\d{2}$/.test(dtRaw) ? dtRaw : dfRaw) + 'T23:59:59.999').getTime();
    if (!isNaN(from) && !isNaN(to)) { dateFloorOverride = from; whenCeil = to; }
  }
  const effectiveFloor = (dateFloorOverride != null) ? dateFloorOverride : startFloor;

  const catClause = (category && category !== 'all') ? ' AND LOWER(category) = LOWER(?)' : '';
  const catParams = (category && category !== 'all') ? [category] : [];

  // ---- Country filter (item 6). ShowUpp is used outside the US, so by default a user
  // sees events in THEIR country rather than a US-only list. The country is taken from an
  // explicit ?country= (ISO-2) if the client sends one, else derived from the user's saved
  // city/origin. `international=1` opts out (show everything). If the user's country turns
  // out to have no events, we transparently fall back to the full list so they're never
  // staring at an empty feed.
  const wantsInternational = req.query.international === '1' || req.query.international === 'true';
  let userCC = String(req.query.country || '').trim().toUpperCase();
  if (!userCC && !wantsInternational) {
    userCC = (countryToCode(req.user && (req.user.origin || req.user.city)) || '').toUpperCase();
  }
  let countryClause = '', countryParams = [];
  if (userCC && !wantsInternational) {
    // Include NULL-country community posts too (they're local user submissions).
    countryClause = ' AND (country = ? OR country IS NULL OR source = \'community\')';
    countryParams = [userCC];
  }

  // ---- Preferred-category ordering (item 4). Events whose category is one of the user's
  // interests are surfaced FIRST, then the rest, preserving the distance/date ordering
  // within each group. Implemented as a leading ORDER BY term (0 for preferred, 1 for the
  // rest) so it costs nothing extra and works across pagination. Skipped when the user is
  // already filtering to a single category (nothing to prioritize) or has no interests.
  let interests = [];
  try { interests = (req.user && req.user.interests) ? JSON.parse(req.user.interests) : []; } catch (e) { interests = []; }
  const prioritize = (!category || category === 'all') && Array.isArray(interests) && interests.length > 0;
  let prefSelect = '', prefOrder = '', prefParams = [];
  if (prioritize) {
    const placeholders = interests.map(() => '?').join(',');
    prefSelect = `, (CASE WHEN LOWER(category) IN (${placeholders}) THEN 0 ELSE 1 END) AS pref_rank`;
    prefParams = interests.map(s => String(s).toLowerCase());
    prefOrder = 'pref_rank ASC, ';
  }

  // ---- Distance filter. Only meaningful with a location. When maxDistance (miles) is
  // provided, events are both capped to that radius and sorted nearest-first at the DB
  // level. Events with no coordinates are excluded once a radius is in force (they can't
  // be shown to satisfy a "within X miles" request). Without a cap we keep everything and
  // just sort by distance when we can.
  const maxDistanceMiles = parseFloat(req.query.maxDistance);
  const hasDistCap = hasLoc && !isNaN(maxDistanceMiles) && maxDistanceMiles > 0;

  let distSelect = '', orderClause = 'ORDER BY ' + prefOrder + '(starts_at IS NULL), starts_at ASC', orderParams = [], distClause = '', distParams = [];
  if (hasLoc) {
    const distExpr = `(3958.8 * 2 * ASIN(SQRT(
        POWER(SIN(RADIANS(lat - ?) / 2), 2) +
        COS(RADIANS(?)) * COS(RADIANS(lat)) * POWER(SIN(RADIANS(lng - ?) / 2), 2)
      )))`;
    distSelect = `, ${distExpr} AS calc_distance`;
    orderParams = [lat, lat, lng];
    orderClause = 'ORDER BY ' + prefOrder + '(lat IS NULL OR lng IS NULL), calc_distance ASC, (starts_at IS NULL), starts_at ASC';
    if (hasDistCap) {
      // Require coordinates AND within-radius. Repeats the distance expression in WHERE
      // (Postgres can't reference a SELECT alias there); params are ordered to match.
      distClause = ` AND lat IS NOT NULL AND lng IS NOT NULL AND ${distExpr} <= ?`;
      distParams = [lat, lat, lng, maxDistanceMiles];
    }
  }

  // Param order must match the SQL: SELECT distance params, SELECT pref params, then WHERE
  // (floor, ceil, category, country, distance), then LIMIT/OFFSET.
  const runQuery = (withCountry) => db.prepare(`
    SELECT * ${distSelect} ${prefSelect} FROM events
    WHERE approved = 1 AND (starts_at IS NULL OR (starts_at > ? AND starts_at <= ?))
    ${catClause}
    ${withCountry ? countryClause : ''}
    ${distClause}
    ${orderClause}
    LIMIT ? OFFSET ?
  `).all(...orderParams, ...prefParams, effectiveFloor, whenCeil, ...catParams, ...(withCountry ? countryParams : []), ...distParams, pageSize, page * pageSize);

  let rows = await runQuery(!!countryClause);
  // Empty-country fallback: if country filtering returned nothing on the first page,
  // retry once without it so international users with a thin local catalog still see events.
  if (countryClause && rows.length === 0 && page === 0) {
    rows = await runQuery(false);
  }

  let all = rows.map(e => {
    const { calc_distance, pref_rank, ...rest } = e;
    let dist = (typeof calc_distance === 'number') ? calc_distance : null;
    if (dist == null && hasLoc && typeof e.lat === 'number' && typeof e.lng === 'number') dist = distanceMiles(lat, lng, e.lat, e.lng);
    return { ...rest, source_label: e.source === 'community' ? 'Community' : (e.source_label || e.source), distance: dist };
  });

  // "today" is the one range that needs a calendar-day check (not just "next 24h"),
  // so apply it here where we have real Date objects to compare against.
  if (when === 'today') {
    const todayStr = new Date().toDateString();
    all = all.filter(e => !e.starts_at || new Date(e.starts_at).toDateString() === todayStr);
  }

  // Mark which of these events the user has saved (bookmarked), so the card can show it.
  let savedSet = new Set();
  try {
    const ids = all.map(e => e.id);
    if (ids.length) {
      const ph = ids.map(() => '?').join(',');
      const savedRows = await db.prepare(`SELECT event_id FROM saved_events WHERE user_id = ? AND event_id IN (${ph})`).all(req.user.id, ...ids);
      savedSet = new Set(savedRows.map(r => r.event_id));
    }
  } catch (e) {}
  all = all.map(e => ({ ...e, i_saved: savedSet.has(e.id) }));

  res.json({ events: all, page, pageSize, hasMore: rows.length === pageSize, country: userCC || null, providers: { ticketmaster: !!process.env.TICKETMASTER_API_KEY } });
});

// Distinct categories currently available (nationwide, no distance limit) — used to
// populate the category filter chips. Kept separate from the (paginated) main list so
// the chips reflect everything available, not just whatever page happens to be loaded.
app.get('/api/events/categories', requireAuth, async (req, res) => {
  const cutoff = now() + EVENT_INGEST_WINDOW_DAYS * 24 * 3600 * 1000;
  const rows = await db.prepare(`
    SELECT DISTINCT category FROM events
    WHERE approved = 1 AND category IS NOT NULL AND (starts_at IS NULL OR (starts_at > ? AND starts_at <= ?))
    LIMIT 100
  `).all(now() - 6 * 3600 * 1000, cutoff);
  res.json({ categories: rows.map(r => r.category).filter(Boolean) });
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
// key isn't echoed back in full once it's saved. A source whose provider isn't in
// EVENT_PROVIDERS (see "Other / manual" in the form) is flagged isManual: true — it's
// never auto-fetched, and the panel offers an "add event" form for it instead.
app.get('/api/admin/event-sources', requireAuth, requireAdmin, async (req, res) => {
  const rows = await db.prepare('SELECT id, provider, label, api_key, url, enabled, created_at, last_ingest_at, last_error, last_fetched_count FROM event_sources ORDER BY created_at DESC').all();
  const masked = [];
  const cutoff = now() + EVENT_INGEST_WINDOW_DAYS * 24 * 3600 * 1000;
  for (const r of rows) {
    const isWebsite = (r.provider === WEBSITE_PROVIDER);
    const isManual = !EVENT_PROVIDERS[r.provider] && !isWebsite;
    // Website events are namespaced per source ('website:<id>'); API providers use the
    // provider key as the event source. Count against the right key.
    const srcKey = isWebsite ? (WEBSITE_PROVIDER + ':' + r.id) : r.provider;
    const evRow = await db.prepare(`
      SELECT COUNT(*) AS n, MAX(created_at) AS latest FROM events
      WHERE source = ? AND approved = 1 AND (starts_at IS NULL OR (starts_at > ? AND starts_at <= ?))
    `).get(srcKey, now() - 6 * 3600 * 1000, cutoff);
    masked.push({
      ...r,
      api_key: r.api_key ? '••••••••' + String(r.api_key).slice(-4) : '',
      isManual, isWebsite,
      live_events: evRow ? Number(evRow.n) || 0 : 0,
      last_event_added: evRow && evRow.latest ? Number(evRow.latest) : null
    });
  }
  res.json({ sources: masked, availableProviders: Object.keys(EVENT_PROVIDERS), ingestWindowDays: EVENT_INGEST_WINDOW_DAYS });
});

// Add a new event-account. `provider` can be a registered auto-fetch provider (e.g.
// "ticketmaster", needs an API key) OR any free-typed label for a manual source —
// one whose events the admin will add by hand from the panel instead of an API pull.
app.post('/api/admin/event-sources', requireAuth, requireAdmin, async (req, res) => {
  const { provider, label, apiKey, url } = req.body || {};
  if (!provider || !String(provider).trim()) return res.status(400).json({ error: 'Give the source a provider name.' });
  const providerKey = String(provider).trim().slice(0, 60);
  const isWebsite = (providerKey === WEBSITE_PROVIDER);
  const isRegistered = !!EVENT_PROVIDERS[providerKey];
  if (isRegistered && (!apiKey || !String(apiKey).trim())) {
    return res.status(400).json({ error: 'An API key is required for this provider.' });
  }
  let cleanUrl = null;
  if (isWebsite) {
    cleanUrl = String(url || '').trim();
    if (!/^https?:\/\/.+/i.test(cleanUrl)) return res.status(400).json({ error: 'Enter the full events-page URL (starting with https://).' });
    cleanUrl = cleanUrl.slice(0, 500);
  }
  const row = {
    id: id(), provider: providerKey, label: String(label || '').slice(0, 80) || providerKey,
    api_key: (apiKey && String(apiKey).trim()) ? String(apiKey).trim() : null,
    url: cleanUrl,
    enabled: 1, created_by: req.user.id, created_at: now()
  };
  await db.prepare(`INSERT INTO event_sources (id,provider,label,api_key,url,enabled,created_by,created_at)
    VALUES (@id,@provider,@label,@api_key,@url,@enabled,@created_by,@created_at)`).run(row);
  // Kick off an immediate ingest for a freshly-added auto source (API or website) so the
  // owner doesn't have to wait up to 24h to see it start working.
  if (isRegistered || isWebsite) ingestExternalEvents().catch(() => {});
  res.json({ ok: true, id: row.id, isManual: !isRegistered && !isWebsite });
});

// Edit an existing account's label and/or API key. The label can be cleared to fall
// back to the provider name; the API key is only touched if a new one is actually
// supplied (an empty field means "leave it as-is", not "erase it"), so the manager
// can rename an account without being forced to re-paste a working key.
app.post('/api/admin/event-sources/:id/update', requireAuth, requireAdmin, async (req, res) => {
  const src = await db.prepare('SELECT id, provider, label FROM event_sources WHERE id = ?').get(req.params.id);
  if (!src) return res.status(404).json({ error: 'Not found.' });
  const { label, apiKey, url } = req.body || {};
  const newLabel = (label !== undefined) ? (String(label).slice(0, 80) || src.provider) : src.label;
  if (apiKey && String(apiKey).trim()) {
    await db.prepare('UPDATE event_sources SET label = ?, api_key = ? WHERE id = ?').run(newLabel, String(apiKey).trim(), req.params.id);
  } else {
    await db.prepare('UPDATE event_sources SET label = ? WHERE id = ?').run(newLabel, req.params.id);
  }
  // Website sources can update their events-page URL.
  if (src.provider === WEBSITE_PROVIDER && url !== undefined) {
    const cleanUrl = String(url || '').trim();
    if (cleanUrl && !/^https?:\/\/.+/i.test(cleanUrl)) return res.status(400).json({ error: 'Enter a full URL starting with https://.' });
    await db.prepare('UPDATE event_sources SET url = ? WHERE id = ?').run(cleanUrl.slice(0, 500) || null, req.params.id);
  }
  res.json({ ok: true });
});

// Pull a fresh batch for just this one account, on demand — separate from the
// all-sources "refresh" below, so a manager doesn't have to re-fetch every other
// connected account just to check on one that looks stalled or was just edited.
app.post('/api/admin/event-sources/:id/refresh', requireAuth, requireAdmin, async (req, res) => {
  const src = await db.prepare('SELECT * FROM event_sources WHERE id = ?').get(req.params.id);
  if (!src) return res.status(404).json({ error: 'Not found.' });
  const result = await ingestOneSource(src);
  if (!result.ok) return res.status(400).json({ error: result.error || 'Refresh failed.' });
  res.json({ ok: true, kept: result.kept, total: result.total });
});

// Toggle an account on/off without deleting its saved key
app.post('/api/admin/event-sources/:id/toggle', requireAuth, requireAdmin, async (req, res) => {
  const src = await db.prepare('SELECT id, enabled FROM event_sources WHERE id = ?').get(req.params.id);
  if (!src) return res.status(404).json({ error: 'Not found.' });
  await db.prepare('UPDATE event_sources SET enabled = ? WHERE id = ?').run(src.enabled ? 0 : 1, req.params.id);
  res.json({ ok: true, enabled: !src.enabled });
});

// Remove an account entirely. Any events it already contributed just age out on their
// own via the daily trim (or the admin can remove them directly) rather than being
// deleted here, since a manual source's hand-entered events shouldn't vanish by accident.
app.post('/api/admin/event-sources/:id/delete', requireAuth, requireAdmin, async (req, res) => {
  const src = await db.prepare('SELECT id, provider FROM event_sources WHERE id = ?').get(req.params.id);
  if (!src) return res.status(404).json({ error: 'Not found.' });
  await db.prepare('DELETE FROM event_sources WHERE id = ?').run(req.params.id);
  // A website source's events are auto-read (not hand-entered), so remove them when the
  // source is deleted rather than leaving orphaned rows in Discover.
  if (src.provider === WEBSITE_PROVIDER) {
    await db.prepare('DELETE FROM events WHERE source = ?').run(WEBSITE_PROVIDER + ':' + src.id).catch(() => {});
  }
  res.json({ ok: true });
});

// Trigger the daily ingest job immediately (e.g. right after adding/editing an account).
app.post('/api/admin/event-sources/refresh', requireAuth, requireAdmin, async (req, res) => {
  ingestExternalEvents().catch(err => console.log('[events] manual refresh failed', err.message));
  res.json({ ok: true, started: true });
});

// Add a manually-entered event under a source (registered or manual). Lets an owner
// hand-add listings for a site that has no API — these flow into /api/events exactly
// like any other event, so they show up in the Discover tab's list and map too.
app.post('/api/admin/event-sources/:id/events', requireAuth, requireAdmin, async (req, res) => {
  const src = await db.prepare('SELECT id, provider, label FROM event_sources WHERE id = ?').get(req.params.id);
  if (!src) return res.status(404).json({ error: 'Source not found.' });
  const { title, category, emoji, place, link, lat, lng, startsAt } = req.body || {};
  if (!title || !String(title).trim()) return res.status(400).json({ error: 'Give the event a name.' });
  const ev = {
    id: id(), source: src.provider, source_id: null,
    title: String(title).trim().slice(0, 200), description: '',
    category: category ? String(category).slice(0, 40) : 'Event', emoji: emoji || '📣',
    photo: null, link: safeUrl(link), place: place ? String(place).slice(0, 200) : '',
    lat: (typeof lat === 'number') ? lat : null, lng: (typeof lng === 'number') ? lng : null,
    starts_at: (typeof startsAt === 'number' && startsAt > 0) ? startsAt : null, ends_at: null,
    posted_by: req.user.id, approved: 1, created_at: now(), source_label: src.label
  };
  await db.prepare(`INSERT INTO events (id,source,source_id,title,description,category,emoji,photo,link,place,lat,lng,starts_at,ends_at,posted_by,approved,created_at,source_label)
    VALUES (@id,@source,@source_id,@title,@description,@category,@emoji,@photo,@link,@place,@lat,@lng,@starts_at,@ends_at,@posted_by,@approved,@created_at,@source_label)`).run(ev);
  res.json({ ok: true, event: ev });
});

// List the events currently attributed to a source (for the Manager panel to show/manage
// what's been manually added, or what an auto provider currently has live).
app.get('/api/admin/event-sources/:id/events', requireAuth, requireAdmin, async (req, res) => {
  const src = await db.prepare('SELECT id, provider FROM event_sources WHERE id = ?').get(req.params.id);
  if (!src) return res.status(404).json({ error: 'Source not found.' });
  const rows = await db.prepare('SELECT * FROM events WHERE source = ? ORDER BY starts_at ASC NULLS LAST LIMIT 100').all(src.provider);
  res.json({ events: rows });
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
    // Housekeeping: clear out event-provider cache rows once they're well past their TTL,
    // so the table doesn't grow forever as people search from new locations. (The live
    // event feed itself no longer uses this cache — see the daily ingest job below —
    // but old rows may still be lying around from before that change.)
    setInterval(() => {
      db.prepare('DELETE FROM event_cache WHERE fetched_at < ?').run(Date.now() - 7 * 24 * 60 * 60 * 1000).catch(() => {});
    }, 6 * 60 * 60 * 1000);
    // Event feed: one ingest pass per provider per day, pulling events (across all
    // configured countries — item 6) up to 1 year out straight into the `events` table.
    // Re-upserting also re-runs classification, so the category fix (item 1) heals
    // existing rows on the next run. Delay the first run slightly; then once every 24h.
    setTimeout(() => { ingestExternalEvents().catch(err => console.log('[events] initial ingest failed:', err.message)); }, 20000);
    setInterval(() => { ingestExternalEvents().catch(err => console.log('[events] scheduled ingest failed:', err.message)); }, 24 * 60 * 60 * 1000);
  })
  .catch((err) => {
    console.error('Failed to initialize the database. Is DATABASE_URL correct?');
    console.error(err.message);
    process.exit(1);
  });
