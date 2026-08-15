/**
 * db.js — Hybrid Database Layer
 * Supports PostgreSQL when active, with instant local JSON fallback (users.json)
 * so auth NEVER hangs or fails when PostgreSQL is not installed.
 */

require('dotenv').config();
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const usersFile = path.join(__dirname, 'users.json');

// Fast PostgreSQL Pool with 2s connection timeout
const pool = new Pool({
  connectionString: process.env.DATABASE_URL ||
    `postgresql://${process.env.DB_USER || 'postgres'}:${process.env.DB_PASS || 'postgres'}@${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 5432}/${process.env.DB_NAME || 'mailforge'}`,
  connectionTimeoutMillis: 2000, // 2 second max timeout
  idleTimeoutMillis: 10000
});

let isPgConnected = false;

// Local JSON DB Helper
function getLocalUsers() {
  try {
    if (!fs.existsSync(usersFile)) return [];
    return JSON.parse(fs.readFileSync(usersFile, 'utf8'));
  } catch (e) {
    return [];
  }
}

function saveLocalUsers(users) {
  try {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), 'utf8');
  } catch (e) {
    console.error('Error saving users.json:', e);
  }
}

async function initDB() {
  let client;
  try {
    client = await pool.connect();
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        name          VARCHAR(255)  NOT NULL,
        email         VARCHAR(255)  UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        google_id     VARCHAR(255),
        picture       TEXT,
        created_at    TIMESTAMPTZ   DEFAULT NOW(),
        last_login    TIMESTAMPTZ   DEFAULT NOW()
      );
    `);
    isPgConnected = true;
    console.log('✅ PostgreSQL database connected and users table ready');
  } catch (err) {
    isPgConnected = false;
    console.log('ℹ️ PostgreSQL not connected. Using local JSON database (users.json)');
  } finally {
    if (client) client.release();
  }
}

// Universal User Query Abstraction
async function findUserByEmail(email) {
  const clean = email.toLowerCase().trim();
  if (isPgConnected) {
    try {
      const res = await pool.query('SELECT * FROM users WHERE email = $1', [clean]);
      return res.rows[0] || null;
    } catch (e) { isPgConnected = false; }
  }
  const users = getLocalUsers();
  return users.find(u => u.email.toLowerCase() === clean) || null;
}

async function createUser({ name, email, password_hash, google_id = null, picture = null }) {
  const cleanEmail = email.toLowerCase().trim();
  if (isPgConnected) {
    try {
      const res = await pool.query(
        'INSERT INTO users (name, email, password_hash, google_id, picture) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, picture, created_at',
        [name, cleanEmail, password_hash, google_id, picture]
      );
      return res.rows[0];
    } catch (e) { isPgConnected = false; }
  }

  const users = getLocalUsers();
  const newUser = {
    id: users.length + 1,
    name,
    email: cleanEmail,
    password_hash,
    google_id,
    picture: picture || `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=6366f1&color=fff`,
    created_at: new Date().toISOString(),
    last_login: new Date().toISOString()
  };
  users.push(newUser);
  saveLocalUsers(users);
  return { id: newUser.id, name: newUser.name, email: newUser.email, picture: newUser.picture };
}

async function getAllUsers() {
  if (isPgConnected) {
    try {
      const res = await pool.query('SELECT id, name, email, google_id, picture, created_at, last_login FROM users ORDER BY created_at DESC');
      return res.rows;
    } catch (e) { isPgConnected = false; }
  }
  return getLocalUsers().map(u => ({
    id: u.id, name: u.name, email: u.email, google_id: u.google_id, picture: u.picture, created_at: u.created_at, last_login: u.last_login
  }));
}

module.exports = { pool, initDB, findUserByEmail, createUser, getAllUsers };
