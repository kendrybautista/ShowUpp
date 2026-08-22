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
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// --- Config ---
const PORT = process.env.PORT || 3000;
// In production, set JWT_SECRET as an environment variable on your host.
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';

// --- Database setup ---
const db = new Database(path.join(__dirname, 'showupp.db'));
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
} catch (e) { console.log('Migration note:', e.message); }

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
    return db.prepare('SELECT id, email, name, username, avatar, city, origin, interests FROM users WHERE id = ?').get(payload.uid);
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
    interests: u.interests ? JSON.parse(u.interests) : []
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
app.post('/api/signup', (req, res) => {
  const { email, password, name, city, origin, interests } = req.body || {};
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
    created_at: now()
  };
  db.prepare(`INSERT INTO users (id,email,pass_hash,name,city,origin,interests,created_at)
              VALUES (@id,@email,@pass_hash,@name,@city,@origin,@interests,@created_at)`).run(user);

  res.json({ token: makeToken(user), user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase());
  if (!row || !bcrypt.compareSync(String(password), row.pass_hash)) {
    return res.status(401).json({ error: 'Wrong email or password.' });
  }
  res.json({ token: makeToken(row), user: publicUser(row) });
});

// Return the current user (used on app load to restore session)
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// Update the current user's profile (name, username, city, interests)
app.post('/api/me/update', requireAuth, (req, res) => {
  const { name, username, city, interests } = req.body || {};
  // If a username is provided, enforce simple rules + uniqueness
  let cleanUser = null;
  if (username && String(username).trim()) {
    cleanUser = String(username).trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
    if (cleanUser.length < 3) return res.status(400).json({ error: 'Username needs at least 3 letters/numbers.' });
    const taken = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(cleanUser, req.user.id);
    if (taken) return res.status(409).json({ error: 'That username is taken. Try another.' });
  }
  db.prepare(`UPDATE users SET
      name = COALESCE(?, name),
      username = COALESCE(?, username),
      city = COALESCE(?, city),
      interests = COALESCE(?, interests)
    WHERE id = ?`).run(
    name ? String(name).trim() : null,
    cleanUser,
    (city !== undefined && city !== null) ? String(city) : null,
    Array.isArray(interests) ? JSON.stringify(interests) : null,
    req.user.id
  );
  const updated = db.prepare('SELECT id, email, name, username, avatar, city, origin, interests FROM users WHERE id = ?').get(req.user.id);
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

// ---- Friends ----
// Search users by username (or name), excluding yourself
app.get('/api/users/search', requireAuth, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase().replace(/^@/, '');
  if (q.length < 2) return res.json({ users: [] });
  const rows = db.prepare(`
    SELECT id, name, username, city FROM users
    WHERE id != ? AND (LOWER(username) LIKE ? OR LOWER(name) LIKE ?)
    LIMIT 20
  `).all(req.user.id, '%' + q + '%', '%' + q + '%');
  const friendIds = new Set(db.prepare('SELECT friend_id FROM friendships WHERE user_id = ?').all(req.user.id).map(r => r.friend_id));
  res.json({ users: rows.filter(u => u.username).map(u => ({
    id: u.id, name: u.name, username: u.username, city: u.city,
    isFriend: friendIds.has(u.id)
  })) });
});

// Add a friend (one-directional save, like following)
app.post('/api/friends/add', requireAuth, (req, res) => {
  const { friendId } = req.body || {};
  if (!friendId || friendId === req.user.id) return res.status(400).json({ error: 'Invalid user.' });
  const exists = db.prepare('SELECT id FROM users WHERE id = ?').get(friendId);
  if (!exists) return res.status(404).json({ error: 'User not found.' });
  db.prepare('INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at) VALUES (?,?,?)')
    .run(req.user.id, friendId, now());
  res.json({ ok: true });
});

// Remove a friend
app.post('/api/friends/remove', requireAuth, (req, res) => {
  const { friendId } = req.body || {};
  db.prepare('DELETE FROM friendships WHERE user_id = ? AND friend_id = ?').run(req.user.id, friendId);
  res.json({ ok: true });
});

// List my saved friends
app.get('/api/friends', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.username, u.city
    FROM friendships f JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ? ORDER BY f.created_at DESC
  `).all(req.user.id);
  res.json({ friends: rows });
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
  const msgs = db.prepare(`
    SELECT m.id, m.body, m.created_at, m.user_id, u.name AS sender
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.round_id = ? ORDER BY m.created_at ASC LIMIT 200
  `).all(req.params.id);
  res.json({ messages: msgs });
});

// --- HTTP + WebSocket server share one port ---
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

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
      const body = String(msg.body || '').trim();
      if (!body) return;
      const member = db.prepare('SELECT 1 FROM memberships WHERE round_id = ? AND user_id = ?')
        .get(msg.roundId, ws.user.id);
      if (!member) { ws.send(JSON.stringify({ type: 'error', error: 'not a member' })); return; }

      const record = { id: id(), round_id: msg.roundId, user_id: ws.user.id, body, created_at: now() };
      db.prepare('INSERT INTO messages (id,round_id,user_id,body,created_at) VALUES (@id,@round_id,@user_id,@body,@created_at)').run(record);

      const outbound = JSON.stringify({
        type: 'message',
        roundId: msg.roundId,
        message: { id: record.id, body, created_at: record.created_at, user_id: ws.user.id, sender: ws.user.name }
      });
      // Broadcast to everyone currently connected who is in that room
      wss.clients.forEach((client) => {
        if (client.readyState === 1 && client.rooms && client.rooms.has(msg.roundId)) {
          client.send(outbound);
        }
      });
    }
  });
});

server.listen(PORT, () => {
  console.log(`ShowUpp backend running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT} to use the app.`);
});
