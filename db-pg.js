/*
 * db-pg.js — Postgres data layer for ShowUpp
 * -------------------------------------------------------------
 * Provides a small wrapper that mimics the better-sqlite3 API the
 * rest of the app already uses (db.prepare(sql).get/.all/.run),
 * but backed by Neon Postgres. The important difference: every
 * query is ASYNC, so call sites use `await`.
 *
 * SQL dialect translation handled here:
 *   - `?` positional placeholders  ->  `$1, $2, ...`
 *   - `@name` named placeholders    ->  `$1...` mapped from an object arg
 *   - INTEGER-as-boolean stays numeric (0/1) — we keep the same shape
 *
 * Schema DDL is written in Postgres-compatible SQL in server.js.
 */

const { Pool, types } = require('pg');

// Postgres returns int8 (bigint) — including COUNT(*) — as a string by default,
// which breaks arithmetic like member_count - 4. Parse int8 as a JS number.
// (Our bigints are JS millisecond timestamps and small counts, all well within
// Number.MAX_SAFE_INTEGER, so this is safe here.)
types.setTypeParser(20, (val) => (val === null ? null : parseInt(val, 10)));

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('FATAL: DATABASE_URL is not set. Point it at your Neon Postgres connection string.');
  process.exit(1);
}

const pool = new Pool({
  connectionString,
  // Neon requires SSL. The connection string already includes sslmode=require,
  // but we set this too so it works even if the flag is missing.
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('Unexpected Postgres pool error:', err.message);
});

// Convert a SQLite-style statement + args into a Postgres query.
// Supports:
//   - positional `?`  with spread args:  stmt.get(a, b)
//   - named `@foo`    with a single object arg: stmt.run({ foo: 1 })
function toPg(sql, args) {
  // Named params?  e.g.  VALUES (@id, @name)
  const named = sql.match(/@[a-zA-Z_][a-zA-Z0-9_]*/g);
  if (named && named.length) {
    const obj = (args.length === 1 && typeof args[0] === 'object' && args[0] !== null) ? args[0] : {};
    const values = [];
    const seen = {};
    let i = 0;
    const text = sql.replace(/@([a-zA-Z_][a-zA-Z0-9_]*)/g, (m, key) => {
      if (seen[key]) return seen[key];
      i += 1;
      const ph = '$' + i;
      seen[key] = ph;
      values.push(obj[key] === undefined ? null : obj[key]);
      return ph;
    });
    return { text, values };
  }
  // Positional `?`
  let i = 0;
  const text = sql.replace(/\?/g, () => '$' + (++i));
  const values = args.map(v => (v === undefined ? null : v));
  return { text, values };
}

function prepare(sql) {
  return {
    async get(...args) {
      const { text, values } = toPg(sql, args);
      const res = await pool.query(text, values);
      return res.rows[0] || undefined;
    },
    async all(...args) {
      const { text, values } = toPg(sql, args);
      const res = await pool.query(text, values);
      return res.rows;
    },
    async run(...args) {
      const { text, values } = toPg(sql, args);
      const res = await pool.query(text, values);
      return { changes: res.rowCount, rowCount: res.rowCount };
    },
  };
}

// Run raw DDL / multi-statement SQL (schema creation, migrations).
async function exec(sql) {
  await pool.query(sql);
}

// Does a column exist?  (replaces SQLite PRAGMA table_info)
async function columnExists(table, column) {
  const res = await pool.query(
    `SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`,
    [table, column]
  );
  return res.rowCount > 0;
}

// Does a table exist?
async function tableExists(table) {
  const res = await pool.query(
    `SELECT 1 FROM information_schema.tables WHERE table_name = $1`,
    [table]
  );
  return res.rowCount > 0;
}

module.exports = { pool, prepare, exec, columnExists, tableExists };
