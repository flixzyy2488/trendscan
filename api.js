// TrendPulse AI — Netlify Serverless Function
// Secure backend proxy between the browser and Netlify Postgres (Neon).
// The DB connection string lives only here (server-side), never exposed to the browser.
// Deploy: drop the whole project folder on Netlify. Set env var DB_URL in Netlify dashboard.

const { Client } = require('pg');

const DB_URL = process.env.DB_URL ||
  'postgresql://netlifydb_owner:npg_HAm3zwiIdF2K@ep-blue-cloud-ajqgz1gh.c-3.us-east-2.db.netlify.com/netlifydb?sslmode=require';

// ── CORS headers (allow your Netlify site + local dev) ──────────────────────
function corsHeaders(event) {
  const origin = (event.headers && (event.headers.origin || event.headers.Origin)) || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}

function ok(data, event) {
  return { statusCode: 200, headers: corsHeaders(event), body: JSON.stringify(data) };
}
function err(msg, code, event) {
  return { statusCode: code || 400, headers: corsHeaders(event), body: JSON.stringify({ error: msg }) };
}

// ── DB helper ────────────────────────────────────────────────────────────────
async function query(sql, params = []) {
  const client = new Client({ connectionString: DB_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    const res = await client.query(sql, params);
    return res.rows;
  } finally {
    await client.end();
  }
}

// ── Ensure tables exist ──────────────────────────────────────────────────────
async function ensureTables() {
  await query(`
    CREATE TABLE IF NOT EXISTS trendpulse_users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      first_name TEXT DEFAULT '',
      last_name TEXT DEFAULT '',
      role TEXT DEFAULT 'Solo Creator',
      plan TEXT DEFAULT 'Starter',
      is_admin BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login TIMESTAMPTZ
    )`);
  await query(`
    CREATE TABLE IF NOT EXISTS trendpulse_sessions (
      token TEXT PRIMARY KEY,
      user_id BIGINT REFERENCES trendpulse_users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days')
    )`);
}

// ── Route handlers ───────────────────────────────────────────────────────────

// POST /api  { action: 'init' }
// Creates tables if they don't exist. Safe to call on every page load.
async function handleInit(event) {
  await ensureTables();
  return ok({ ok: true }, event);
}

// POST /api  { action: 'signup', email, passwordHash, firstName, lastName, role, plan }
async function handleSignup(body, event) {
  const { email, passwordHash, firstName, lastName, role, plan } = body;
  if (!email || !passwordHash) return err('Missing email or password hash', 400, event);

  const ADMIN_EMAILS = ['ezforno@gmail.com', 'artemi.demish@gmail.com'];
  const isAdmin = ADMIN_EMAILS.includes(email.toLowerCase());

  // Check duplicate
  const existing = await query('SELECT id FROM trendpulse_users WHERE email = $1', [email.toLowerCase()]);
  if (existing.length) return err('An account with this email already exists', 409, event);

  const rows = await query(
    `INSERT INTO trendpulse_users (email, password_hash, first_name, last_name, role, plan, is_admin)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, email, first_name, last_name, role, plan, is_admin`,
    [email.toLowerCase(), passwordHash, firstName || '', lastName || '', role || 'Solo Creator', plan || 'Starter', isAdmin]
  );
  return ok({ user: rows[0] }, event);
}

// POST /api  { action: 'get_user', email }
async function handleGetUser(body, event) {
  const { email } = body;
  if (!email) return err('Missing email', 400, event);
  const rows = await query(
    'SELECT id, email, password_hash, first_name, last_name, role, plan, is_admin FROM trendpulse_users WHERE email = $1 LIMIT 1',
    [email.toLowerCase()]
  );
  if (!rows.length) return err('User not found', 404, event);
  return ok({ user: rows[0] }, event);
}

// POST /api  { action: 'create_session', userId, token }
async function handleCreateSession(body, event) {
  const { userId, token } = body;
  if (!userId || !token) return err('Missing userId or token', 400, event);
  await query('INSERT INTO trendpulse_sessions (token, user_id) VALUES ($1, $2)', [token, userId]);
  await query('UPDATE trendpulse_users SET last_login = NOW() WHERE id = $1', [userId]);
  return ok({ ok: true }, event);
}

// POST /api  { action: 'restore_session', token }
async function handleRestoreSession(body, event) {
  const { token } = body;
  if (!token) return err('Missing token', 400, event);
  const rows = await query(
    `SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.plan, u.is_admin
     FROM trendpulse_sessions s
     JOIN trendpulse_users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > NOW() LIMIT 1`,
    [token]
  );
  if (!rows.length) return err('Session not found or expired', 404, event);
  return ok({ user: rows[0] }, event);
}

// POST /api  { action: 'delete_session', token }
async function handleDeleteSession(body, event) {
  const { token } = body;
  if (!token) return err('Missing token', 400, event);
  await query('DELETE FROM trendpulse_sessions WHERE token = $1', [token]);
  return ok({ ok: true }, event);
}

// POST /api  { action: 'admin_list_users' }  (admin only — validated by session)
async function handleAdminListUsers(body, event) {
  const { token } = body;
  // Verify session is admin
  const sess = await query(
    `SELECT u.is_admin, u.email FROM trendpulse_sessions s
     JOIN trendpulse_users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > NOW() LIMIT 1`,
    [token]
  );
  const ADMIN_EMAILS = ['ezforno@gmail.com', 'artemi.demish@gmail.com'];
  if (!sess.length || (!sess[0].is_admin && !ADMIN_EMAILS.includes(sess[0].email))) {
    return err('Unauthorized', 403, event);
  }
  const users = await query(
    'SELECT id, email, first_name, last_name, role, plan, is_admin, created_at, last_login FROM trendpulse_users ORDER BY created_at DESC'
  );
  return ok({ users }, event);
}

// POST /api  { action: 'admin_update_user', token, userId, plan, role, isAdmin }
async function handleAdminUpdateUser(body, event) {
  const { token, userId, plan, role, isAdmin } = body;
  const sess = await query(
    `SELECT u.is_admin, u.email FROM trendpulse_sessions s
     JOIN trendpulse_users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > NOW() LIMIT 1`,
    [token]
  );
  const ADMIN_EMAILS = ['ezforno@gmail.com', 'artemi.demish@gmail.com'];
  if (!sess.length || (!sess[0].is_admin && !ADMIN_EMAILS.includes(sess[0].email))) {
    return err('Unauthorized', 403, event);
  }
  await query('UPDATE trendpulse_users SET plan=$1, role=$2, is_admin=$3 WHERE id=$4', [plan, role, isAdmin, userId]);
  return ok({ ok: true }, event);
}

// POST /api  { action: 'admin_delete_user', token, userId }
async function handleAdminDeleteUser(body, event) {
  const { token, userId } = body;
  const sess = await query(
    `SELECT u.is_admin, u.email FROM trendpulse_sessions s
     JOIN trendpulse_users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > NOW() LIMIT 1`,
    [token]
  );
  const ADMIN_EMAILS = ['ezforno@gmail.com', 'artemi.demish@gmail.com'];
  if (!sess.length || (!sess[0].is_admin && !ADMIN_EMAILS.includes(sess[0].email))) {
    return err('Unauthorized', 403, event);
  }
  await query('DELETE FROM trendpulse_sessions WHERE user_id=$1', [userId]);
  await query('DELETE FROM trendpulse_users WHERE id=$1', [userId]);
  return ok({ ok: true }, event);
}

// ── Main handler ─────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: corsHeaders(event), body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return err('Method not allowed', 405, event);
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return err('Invalid JSON', 400, event);
  }

  const { action } = body;

  try {
    switch (action) {
      case 'init':               return await handleInit(event);
      case 'signup':             return await handleSignup(body, event);
      case 'get_user':           return await handleGetUser(body, event);
      case 'create_session':     return await handleCreateSession(body, event);
      case 'restore_session':    return await handleRestoreSession(body, event);
      case 'delete_session':     return await handleDeleteSession(body, event);
      case 'admin_list_users':   return await handleAdminListUsers(body, event);
      case 'admin_update_user':  return await handleAdminUpdateUser(body, event);
      case 'admin_delete_user':  return await handleAdminDeleteUser(body, event);
      default:                   return err(`Unknown action: ${action}`, 400, event);
    }
  } catch (e) {
    console.error('API error:', e);
    return err('Internal server error: ' + e.message, 500, event);
  }
};
