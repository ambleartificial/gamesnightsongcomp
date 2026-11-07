const express = require('express'), { neon } = require('@neondatabase/serverless'), bcrypt = require('bcryptjs'),
  crypto = require('crypto'), { handleUpload } = require('@vercel/blob/client'), { del } = require('@vercel/blob');

const sql = neon(process.env.DATABASE_URL);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const q = async (t, p = []) => {
  for (let i = 0; i < 3; i++) {
    try { return await sql.query(t, p); }
    catch (e) {
      if (i === 2 || !/fetch failed|other side closed/i.test(e.message + (e.cause?.message || ''))) throw e;
      await sleep(500 * (i + 1));
    }
  }
};
const one = async (t, p) => (await q(t, p))[0] || null;
const SECRET = process.env.SECRET || process.env.DATABASE_URL || 'dev';

const ready = (async () => {
  for (const s of ) await q(s);
  if (process.env.ADMIN_USER && process.env.ADMIN_PASS) {
    const u = process.env.ADMIN_USER.trim(), hash = bcrypt.hashSync(process.env.ADMIN_PASS.trim(), 10);
    if (await one('SELECT 1 x FROM users WHERE LOWER(username)=LOWER($1)', )) await q('UPDATE users SET hash=$1, is_admin=1 WHERE LOWER(username)=LOWER($2)', );
    else await q('INSERT INTO users(username,name,hash,is_admin) VALUES($1,$2,$3,1)', );
  }
})();
ready.catch(console.error);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '50kb' }));
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' }); next(); });

const h = fn => (req, res, next) => fn(req, res, next).catch(e => { console.error(e); if (!res.headersSent) res.status(500).json({ error: 'Server error' }); });
const err = (res, msg, code = 400) => res.status(code).json({ error: msg });
const cookies = (s = '') => Object.fromEntries(s.split(';').map(c => c.trim().split('=')).filter(x => x[0]).map(( ) => ));
const gen = () => crypto.randomBytes(6).toString
