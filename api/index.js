const express = require('express'), { neon } = require('@neondatabase/serverless'), bcrypt = require('bcryptjs'),
  crypto = require('crypto'), { handleUpload } = require('@vercel/blob/client'), { del } = require('@vercel/blob');

const sql = neon(process.env.DATABASE_URL);
const q = (t, p = []) => sql.query(t, p);
const one = async (t, p) => (await q(t, p))[0] || null;
const SECRET = process.env.SECRET || process.env.DATABASE_URL || 'dev';

const ready = (async () => {
  for (const s of [
    `CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username TEXT NOT NULL, name TEXT NOT NULL, hash TEXT NOT NULL, is_admin INTEGER DEFAULT 0)`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS image TEXT`,
    `CREATE UNIQUE INDEX IF NOT EXISTS users_username ON users(LOWER(username))`,
    `CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, exp BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS rounds(id SERIAL PRIMARY KEY, phase TEXT NOT NULL DEFAULT 'setup')`,
    `CREATE TABLE IF NOT EXISTS round_players(round_id INTEGER, user_id INTEGER, PRIMARY KEY(round_id, user_id))`,
    `CREATE TABLE IF NOT EXISTS duos(round_id INTEGER, a INTEGER, b INTEGER)`,
    `ALTER TABLE duos ADD COLUMN IF NOT EXISTS ord INTEGER DEFAULT 0`,
    `CREATE TABLE IF NOT EXISTS songs(id SERIAL PRIMARY KEY, round_id INTEGER, user_id INTEGER, title TEXT, url TEXT, UNIQUE(round_id, user_id))`,
    `CREATE TABLE IF NOT EXISTS votes(song_id INTEGER, voter_id INTEGER, s TEXT NOT NULL, PRIMARY KEY(song_id, voter_id))`,
    `CREATE TABLE IF NOT EXISTS login_fails(k TEXT PRIMARY KEY, n INTEGER, t BIGINT)`,
  ]) await q(s);
  if (process.env.ADMIN_USER && process.env.ADMIN_PASS) {
    const u = process.env.ADMIN_USER.trim(), hash = bcrypt.hashSync(process.env.ADMIN_PASS.trim(), 10);
    if (await one('SELECT 1 x FROM users WHERE LOWER(username)=LOWER($1)', [u])) await q('UPDATE users SET hash=$1, is_admin=1 WHERE LOWER(username)=LOWER($2)', [hash, u]);
    else await q('INSERT INTO users(username,name,hash,is_admin) VALUES($1,$2,$3,1)', [u, process.env.ADMIN_NAME || 'Admin', hash]);
  }
})();
ready.catch(console.error);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '50kb' }));
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' }); next(); });

const h = fn => (req, res, next) => fn(req, res, next).catch(e => { console.error(e); if (!res.headersSent) res.status(500).json({ error: 'Server error' }); });
const err = (res, msg, code = 400) => res.status(code).json({ error: msg });
const cookies = (s = '') => Object.fromEntries(s.split(';').map(c => c.trim().split('=')).filter(x => x[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
const gen = () => crypto.randomBytes(6).toString('base64url');
const hh = id => crypto.createHash('sha256').update(SECRET + id).digest('hex');

const cur = () => one('SELECT * FROM rounds ORDER BY id DESC LIMIT 1');
const isActive = async (rid, uid) => !!(await one('SELECT 1 x FROM round_players WHERE round_id=$1 AND user_id=$2', [rid, uid]));
const partnerOf = async (rid, uid) => { const d = await one('SELECT a,b FROM duos WHERE round_id=$1 AND (a=$2 OR b=$2)', [rid, uid]); return d ? (d.a === uid ? d.b : d.a) : null; };
const nameOf = async id => id ? (await one('SELECT name FROM users WHERE id=$1', [id]))?.name || null : null;
const ordered = async rid => (await q('SELECT * FROM songs WHERE round_id=$1', [rid])).sort((a, b) => hh(a.id) < hh(b.id) ? -1 : 1);
const scorableFor = async (rid, uid) => { const p = await partnerOf(rid, uid); return (await ordered(rid)).filter(s => s.user_id !== uid && s.user_id !== p); };

app.use(h(async (req, res, next) => {
  await ready;
  const t = cookies(req.headers.cookie).sid;
  req.user = t ? await one('SELECT u.id,u.username,u.name,u.is_admin FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=$1 AND s.exp>$2', [t, Date.now()]) : null;
  next();
}));
const auth = (q, s, n) => q.user ? n() : err(s, 'Not logged in', 401);
const adminOnly = (q, s, n) => q.user.is_admin ? n() : err(s, 'Admin only', 403);

app.post('/api/login', h(async (req, res) => {
  const { username = '', password = '' } = req.body || {};
  const k = req.ip + '|' + String(username).toLowerCase(), f = await one('SELECT * FROM login_fails WHERE k=$1', [k]);
  const fresh = f && Date.now() - Number(f.t) < 9e5;
  if (fresh && f.n >= 5) return err(res, 'Too many attempts. Try again in 15 minutes.', 429);
  const u = await one('SELECT * FROM users WHERE LOWER(username)=LOWER($1)', [String(username)]);
  if (!u || !bcrypt.compareSync(String(password), u.hash)) {
    await q('INSERT INTO login_fails VALUES($1,$2,$3) ON CONFLICT(k) DO UPDATE SET n=EXCLUDED.n,t=EXCLUDED.t', [k, (fresh ? f.n : 0) + 1, Date.now()]);
    return err(res, 'Wrong username or password', 401);
  }
  await q('DELETE FROM login_fails WHERE k=$1', [k]);
  const token = crypto.randomBytes(32).toString('hex');
  await q('INSERT INTO sessions VALUES($1,$2,$3)', [token, u.id, Date.now() + 30 * 864e5]);
  res.set('Set-Cookie', `sid=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${30 * 86400}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  res.json({ ok: true });
}));
app.post('/api/logout', auth, h(async (req, res) => {
  await q('DELETE FROM sessions WHERE token=$1', [cookies(req.headers.cookie).sid]);
  res.set('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0'); res.json({ ok: true });
}));
app.post('/api/password', auth, h(async (req, res) => {
  const { current = '', next = '' } = req.body || {};
  const u = await one('SELECT * FROM users WHERE id=$1', [req.user.id]);
  if (!bcrypt.compareSync(String(current), u.hash)) return err(res, 'Current password is wrong');
  if (String(next).length < 8) return err(res, 'New password needs at least 8 characters');
  await q('UPDATE users SET hash=$1 WHERE id=$2', [bcrypt.hashSync(String(next), 10), u.id]);
  res.json({ ok: true });
}));

app.get('/api/state', auth, h(async (req, res) => {
  const me = req.user, r = await cur(), out = { me: { uid: me.id, name: me.name, admin: !!me.is_admin }, round: null };
  if (r) {
    const [active, pid, mine, cnt, pl, d, duosRaw, songs, allUsers] = await Promise.all([
      isActive(r.id, me.id), partnerOf(r.id, me.id),
      one('SELECT id,title FROM songs WHERE round_id=$1 AND user_id=$2', [r.id, me.id]),
      one('SELECT COUNT(*)::int c FROM songs WHERE round_id=$1', [r.id]),
      one('SELECT COUNT(*)::int c FROM round_players WHERE round_id=$1', [r.id]),
      one('SELECT 1 x FROM duos WHERE round_id=$1', [r.id]),
      q('SELECT a,b,ord FROM duos WHERE round_id=$1 ORDER BY ord, a', [r.id]),
      q('SELECT user_id FROM songs WHERE round_id=$1', [r.id]),
      q('SELECT id,name,image FROM users')
    ]);
    const songUsers = new Set(songs.map(s => s.user_id));
    const userMap = Object.fromEntries(allUsers.map(u => [u.id, u]));
    out.round = { 
      n: r.id, phase: r.phase, active, partner: await nameOf(pid), hasDuos: !!d, 
      mine: mine ? { title: mine.title } : null, mySongId: mine?.id || null, 
      submitted: cnt.c, players: pl.c,
      duos: duosRaw.map(d => ({
        a: userMap[d.a]?.name || '?',
        aImg: userMap[d.a]?.image || null,
        aId: d.a,
        b: d.b ? (userMap[d.b]?.name || '?') : null,
        bImg: d.b ? (userMap[d.b]?.image || null) : null,
        bId: d.b,
        submitted: songUsers.has(d.a) || (d.b && songUsers.has(d.b))
      }))
    };
  }
  res.json(out);
}));

app.post('/api/upload', h(async (req, res) => {
  try {
    const json = await handleUpload({
      body: req.body, request: req,
      onBeforeGenerateToken: async pathname => {
        if (!req.user) throw new Error('Not logged in');
        if (pathname.startsWith('avatars/')) {
          if (!req.user.is_admin) throw new Error('Admin only');
          return { allowedContentTypes: ['image/jpeg','image/png','image/webp'], maximumSizeInBytes: 5 * 1024 * 1024, addRandomSuffix: true };
        }
        const r = await cur();
        if (!r || r.phase !== 'submit' || !(await isActive(r.id, req.user.id))) throw new Error('Submissions are not open for you');
        if (pathname !== `songs/r${r.id}-u${req.user.id}.mp3`) throw new Error('Bad file name');
        return { allowedContentTypes: ['audio/mpeg'], maximumSizeInBytes: 25 * 1024 * 1024, addRandomSuffix: true };
      },
      onUploadCompleted: async () => {},
    });
    res.json(json);
  } catch (e) { err(res, e.message); }
}));
app.post('/api/song', auth, h(async (req, res) => {
  const r = await cur(), title = String(req.body?.title || '').trim().slice(0, 100);
  let url = req.body?.url;
  if (!r || r.phase !== 'submit' || !(await isActive(r.id, req.user.id))) return err(res, 'Submissions are not open for you');
  const old = await one('SELECT * FROM songs WHERE round_id=$1 AND user_id=$2', [r.id, req.user.id]);
  if (!title || (!url && !old)) return err(res, 'Add a title and an mp3 file');
  if (url) {
    let u; try { u = new URL(url); } catch { return err(res, 'Bad file link'); }
    if (!u.hostname.endsWith('.public.blob.vercel-storage.com') || !u.pathname.startsWith(`/songs/r${r.id}-u${req.user.id}-`)) return err(res, 'Bad file link');
  } else url = old.url;
  await q('INSERT INTO songs(round_id,user_id,title,url) VALUES($1,$2,$3,$4) ON CONFLICT(round_id,user_id) DO UPDATE SET title=EXCLUDED.title,url=EXCLUDED.url', [r.id, req.user.id, title, url]);
  if (old && old.url !== url) del(old.url).catch(() => {});
  res.json({ ok: true });
}));

app.post('/api/song/delete', auth, h(async (req, res) => {
  const r = await cur();
  if (!r || r.phase !== 'submit') return err(res, 'Can only delete during submissions');
  const song = await one('SELECT * FROM songs WHERE round_id=$1 AND user_id=$2', [r.id, req.body.userId || req.user.id]);
  if (!song) return err(res, 'No song found');
  const isOwner = song.user_id === req.user.id;
  const isPartner = (await partnerOf(r.id, song.user_id)) === req.user.id;
  if (!req.user.is_admin && !isOwner && !isPartner) return err(res, 'Not allowed', 403);
  await q('DELETE FROM songs WHERE id=$1', [song.id]);
  if (song.url) del(song.url).catch(() => {});
  res.json({ ok: true });
}));

app.post('/api/image', auth, adminOnly, h(async (req, res) => {
  const { userId, url } = req.body || {};
  if (!userId || !url) return err(res, 'Missing data');
  await q('UPDATE users SET image=$1 WHERE id=$2', [url, +userId]);
  res.json({ ok: true });
}));

app.get('/audio/:id', auth, h(async (req, res) => {
  const s = await one('SELECT * FROM songs WHERE id=$1', [+req.params.id]);
  if (!s) return err(res, 'Not found', 404);
  const r = await one('SELECT * FROM rounds WHERE id=$1', [s.round_id]), me = req.user.id;
  const ok = req.user.is_admin || s.user_id === me || r.phase === 'results' || (r.phase === 'voting' && (await isActive(r.id, me)) && (await partnerOf(r.id, me)) !== s.user_id);
  if (!ok) return err(res, 'Not available', 403);
  res.set('Cache-Control', 'private, no-store'); res.redirect(302, s.url);
}));

app.get('/api/score', auth, h(async (req, res) => {
  const r = await cur();
  if (!r || r.phase !== 'voting' || !(await isActive(r.id, req.user.id))) return err(res, 'Voting is not open', 403);
  const all = await ordered(r.id), list = await scorableFor(r.id, req.user.id);
  const mine = await q('SELECT song_id,s FROM votes WHERE voter_id=$1', [req.user.id]);
  res.json(list.map(s => ({ id: s.id, label: String.fromCharCode(65 + all.findIndex(x => x.id === s.id)), title: s.title, score: JSON.parse(mine.find(v => v.song_id === s.id)?.s || 'null') })));
}));
app.post('/api/vote', auth, h(async (req, res) => {
  const r = await cur(), { songId, s } = req.body || {};
  if (!r || r.phase !== 'voting' || !(await isActive(r.id, req.user.id))) return err(res, 'Voting is not open', 403);
  if (!(await scorableFor(r.id, req.user.id)).some(x => x.id === songId)) return err(res, 'You can’t score that song', 403);
  if (!Array.isArray(s) || s.length !== 5 || !s.every(n => Number.isInteger(n) && n >= 0 && n <= 10)) return err(res, 'Scores must be whole numbers from 0 to 10');
  await q('INSERT INTO votes VALUES($1,$2,$3) ON CONFLICT(song_id,voter_id) DO UPDATE SET s=EXCLUDED.s', [songId, req.user.id, JSON.stringify(s)]);
  res.json({ ok: true });
}));

async function roundResults(rid, names) {
  const [songs, duos] = await Promise.all([q('SELECT * FROM songs WHERE round_id=$1', [rid]), q('SELECT a,b FROM duos WHERE round_id=$1', [rid])]);
  const votes = songs.length ? await q('SELECT song_id,s FROM votes WHERE song_id = ANY($1)', [songs.map(s => s.id)]) : [];
  return songs.map(s => {
    const vs = votes.filter(v => v.song_id === s.id).map(v => JSON.parse(v.s));
    if (!vs.length) return null;
    const a = [0, 1, 2, 3, 4].map(i => vs.reduce((x, v) => x + v[i], 0) / vs.length);
    const d = duos.find(d => d.a === s.user_id || d.b === s.user_id), p = d ? (d.a === s.user_id ? d.b : d.a) : null;
    return { uid: s.user_id, title: s.title, name: names[s.user_id], partner: p ? names[p] : null, a, tot: a.reduce((x, y) => x + y, 0), votes: vs.length };
  }).filter(Boolean).sort((x, y) => y.tot - x.tot);
}
app.get('/api/results', auth, h(async (req, res) => {
  const names = Object.fromEntries((await q('SELECT id,name FROM users')).map(u => [u.id, u.name]));
  const ids = (await q("SELECT id FROM rounds WHERE phase='results' ORDER BY id")).map(r => r.id);
  const rounds = []; for (const n of ids) rounds.push({ n, rows: await roundResults(n, names) });
  const t = {};
  rounds.forEach(r => r.rows.forEach(x => { t[x.uid] = t[x.uid] || { name: x.name, tot: 0, n: 0 }; t[x.uid].tot += x.tot; t[x.uid].n++; }));
  res.json({ rounds: rounds.map(r => ({ n: r.n, rows: r.rows.map(({ uid, ...x }) => x) })), overall: Object.values(t).sort((a, b) => b.tot - a.tot) });
}));

app.get('/api/admin', auth, adminOnly, h(async (req, res) => {
  const r = await cur(), users = await q('SELECT id,username,name,is_admin FROM users ORDER BY name');
  let round = null;
  if (r) {
    const [pl, songs, duos, votes] = await Promise.all([
      q('SELECT user_id FROM round_players WHERE round_id=$1', [r.id]), ordered(r.id), q('SELECT a,b,ord FROM duos WHERE round_id=$1 ORDER BY ord, a', [r.id]),
      q('SELECT v.song_id,v.voter_id FROM votes v JOIN songs s ON s.id=v.song_id WHERE s.round_id=$1', [r.id])]);
    const act = new Set(pl.map(x => x.user_id)), nm = Object.fromEntries(users.map(u => [u.id, u.name]));
    const pof = u => { const d = duos.find(d => d.a === u || d.b === u); return d ? (d.a === u ? d.b : d.a) : null; };
    round = {
      n: r.id, phase: r.phase,
      players: users.map(u => {
        const list = r.phase === 'voting' ? songs.filter(s => s.user_id !== u.id && s.user_id !== pof(u.id)) : [];
        return { id: u.id, active: act.has(u.id), song: songs.some(s => s.user_id === u.id), songId: (songs.find(s => s.user_id === u.id) || {}).id || null, need: list.length, done: list.filter(s => votes.some(v => v.song_id === s.id && v.voter_id === u.id)).length };
      }),
      duos: duos.map(d => ({ a: nm[d.a], b: d.b ? nm[d.b] : null, ai: d.a, bi: d.b, ord: d.ord })),
    };
  }
  res.json({ users, round });
}));
app.post('/api/admin/user', auth, adminOnly, h(async (req, res) => {
  let { username, name, password, admin } = req.body || {};
  username = String(username || '').trim(); name = String(name || '').trim(); password = String(password || '').trim() || gen();
  if (!/^[a-z0-9_.-]{3,30}$/i.test(username) || !name || name.length > 40) return err(res, 'Username needs 3 to 30 letters or numbers, and a name is required');
  if (password.length < 8) return err(res, 'Password needs at least 8 characters');
  if (await one('SELECT 1 x FROM users WHERE LOWER(username)=LOWER($1)', [username])) return err(res, 'That username is taken');
  await q('INSERT INTO users(username,name,hash,is_admin) VALUES($1,$2,$3,$4)', [username, name, bcrypt.hashSync(password, 10), admin ? 1 : 0]);
  res.json({ username, password });
}));
app.post('/api/admin/user/:id/password', auth, adminOnly, h(async (req, res) => {
  const password = String(req.body?.password || '').trim() || gen();
  if (password.length < 8) return err(res, 'Password needs at least 8 characters');
  await q('UPDATE users SET hash=$1 WHERE id=$2', [bcrypt.hashSync(password, 10), +req.params.id]);
  await q('DELETE FROM sessions WHERE user_id=$1', [+req.params.id]);
  res.json({ password });
}));
app.post('/api/admin/player', auth, adminOnly, h(async (req, res) => {
  const r = await cur(), { userId, active } = req.body || {};
  if (!r || r.phase !== 'setup') return err(res, 'You can only change players during setup');
  if (active) await q('INSERT INTO round_players VALUES($1,$2) ON CONFLICT DO NOTHING', [r.id, userId]);
  else await q('DELETE FROM round_players WHERE round_id=$1 AND user_id=$2', [r.id, userId]);
  await q('DELETE FROM duos WHERE round_id=$1', [r.id]);
  res.json({ ok: true });
}));
app.post('/api/admin/shuffle', auth, adminOnly, h(async (req, res) => {
  const r = await cur();
  if (!r || !['setup', 'submit'].includes(r.phase)) return err(res, 'Duos can only change before voting');
  const ids = (await q('SELECT user_id FROM round_players WHERE round_id=$1', [r.id])).map(x => x.user_id);
  if (ids.length < 2) return err(res, 'Need at least two players');
  const past = new Set(); (await q('SELECT a,b FROM duos WHERE b IS NOT NULL')).forEach(d => { past.add(d.a + '-' + d.b); past.add(d.b + '-' + d.a); });
  let best = null, bs = 1e9;
  for (let t = 0; t < 300 && bs > 0; t++) {
    const a = [...ids].sort(() => Math.random() - .5), duos = []; let sc = 0;
    for (let i = 0; i < a.length; i += 2) { const d = { a: a[i], b: a[i + 1] ?? null }; if (d.b && past.has(d.a + '-' + d.b)) sc++; duos.push(d); }
    if (sc < bs) { bs = sc; best = duos; }
  }
  await q('DELETE FROM duos WHERE round_id=$1', [r.id]);
  const vals = [], ph = best.map((d, i) => { vals.push(r.id, d.a, d.b, i); return `($${i * 4 + 1},$${i * 4 + 2},$${i * 4 + 3},$${i * 4 + 4})`; });
  await q('INSERT INTO duos(round_id,a,b,ord) VALUES ' + ph.join(','), vals);
  res.json({ ok: true });
}));
app.post('/api/admin/duo', auth, adminOnly, h(async (req, res) => {
  const r = await cur(), a = +req.body?.a, b = req.body?.b ? +req.body.b : null;
  if (!r || !['setup', 'submit'].includes(r.phase)) return err(res, 'Duos can only change before voting');
  if (!a || a === b) return err(res, 'Pick two different players');
  const act = new Set((await q('SELECT user_id FROM round_players WHERE round_id=$1', [r.id])).map(x => x.user_id));
  if (!act.has(a) || (b && !act.has(b))) return err(res, 'Both players must be ticked as playing');
  if (await one('SELECT 1 x FROM duos WHERE round_id=$1 AND (a=$2 OR b=$2 OR a=$3 OR b=$3)', [r.id, a, b || 0])) return err(res, 'One of them is already in a duo');
  const maxOrd = await one('SELECT COALESCE(MAX(ord),-1)+1 o FROM duos WHERE round_id=$1', [r.id]);
  await q('INSERT INTO duos(round_id,a,b,ord) VALUES($1,$2,$3,$4)', [r.id, a, b, maxOrd.o]);
  res.json({ ok: true });
}));
app.post('/api/admin/duos/clear', auth, adminOnly, h(async (req, res) => {
  const r = await cur();
  if (!r || !['setup', 'submit'].includes(r.phase)) return err(res, 'Duos can only change before voting');
  await q('DELETE FROM duos WHERE round_id=$1', [r.id]); res.json({ ok: true });
}));
app.post('/api/admin/duo/move', auth, adminOnly, h(async (req, res) => {
  const r = await cur(), { ai, dir } = req.body || {};
  if (!r) return err(res, 'No round');
  const all = await q('SELECT a,ord FROM duos WHERE round_id=$1 ORDER BY ord, a', [r.id]);
  const idx = all.findIndex(d => d.a === +ai);
  if (idx < 0) return err(res, 'Duo not found');
  const swap = dir === 'up' ? idx - 1 : idx + 1;
  if (swap < 0 || swap >= all.length) return res.json({ ok: true });
  const a = all[idx], b = all[swap];
  await q('UPDATE duos SET ord=$1 WHERE round_id=$2 AND a=$3', [b.ord, r.id, a.a]);
  await q('UPDATE duos SET ord=$1 WHERE round_id=$2 AND a=$3', [a.ord, r.id, b.a]);
  res.json({ ok: true });
}));
app.post('/api/admin/advance', auth, adminOnly, h(async (req, res) => {
  const r = await cur();
  const newRound = async from => {
    const id = (await q('INSERT INTO rounds DEFAULT VALUES RETURNING id'))[0].id;
    if (from) await q('INSERT INTO round_players SELECT $1::int,user_id FROM round_players WHERE round_id=$2', [id, from]);
    else await q('INSERT INTO round_players SELECT $1::int,id FROM users', [id]);
  };
  if (!r) { await newRound(null); return res.json({ ok: true }); }
  if (r.phase === 'setup') {
    const unpaired = await one('SELECT 1 x FROM round_players p WHERE p.round_id=$1 AND NOT EXISTS (SELECT 1 FROM duos d WHERE d.round_id=$1 AND (d.a=p.user_id OR d.b=p.user_id))', [r.id]);
    if (unpaired || !(await one('SELECT 1 x FROM duos WHERE round_id=$1', [r.id]))) return err(res, 'Every player needs a duo first. Pair them up or shuffle.');
  }
  if (r.phase === 'submit' && !(await one('SELECT 1 x FROM songs WHERE round_id=$1', [r.id]))) return err(res, 'No songs have been submitted yet');
  const next = { setup: 'submit', submit: 'voting', voting: 'results' }[r.phase];
  if (next) await q('UPDATE rounds SET phase=$1 WHERE id=$2', [next, r.id]); else await newRound(r.id);
  res.json({ ok: true });
}));
app.post('/api/admin/back', auth, adminOnly, h(async (req, res) => {
  const r = await cur(), prev = r && { submit: 'setup', voting: 'submit', results: 'voting' }[r.phase];
  if (!prev) return err(res, 'Nothing to go back to');
  await q('UPDATE rounds SET phase=$1 WHERE id=$2', [prev, r.id]); res.json({ ok: true });
}));

module.exports = app;
