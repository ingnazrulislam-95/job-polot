import express from 'express';
import helmet from 'helmet';
import cookieSession from 'cookie-session';
import rateLimit from 'express-rate-limit';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import Anthropic from '@anthropic-ai/sdk';
import Stripe from 'stripe';
import bcrypt from 'bcryptjs';

const {
  PORT = 3000, SESSION_SECRET, LINKEDIN_CLIENT_ID, LINKEDIN_CLIENT_SECRET,
  ANTHROPIC_API_KEY, AI_MODEL = 'claude-sonnet-4-6', ADMIN_EMAILS = '', ADMIN_PASSWORD, NODE_ENV,
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID,
} = process.env;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const prod = NODE_ENV === 'production';
if (!SESSION_SECRET) throw new Error('Set SESSION_SECRET in .env');
const admins = ADMIN_EMAILS.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const ai = ANTHROPIC_API_KEY ? new Anthropic({ apiKey: ANTHROPIC_API_KEY }) : null;

// ---------- database ----------
const db = new Database('jobpilot.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, sub TEXT UNIQUE, email TEXT, name TEXT, role TEXT DEFAULT 'user', created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS state(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, json TEXT NOT NULL, updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS usage(user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, day TEXT, n INTEGER DEFAULT 0, PRIMARY KEY(user_id, day));
CREATE TABLE IF NOT EXISTS sources(id INTEGER PRIMARY KEY, name TEXT, url TEXT, enabled INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE, ext_id TEXT, t TEXT, c TEXT, loc TEXT, rem TEXT, lvl TEXT, sal INTEGER, sk TEXT, d TEXT, UNIQUE(source_id, ext_id));
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS errors(id INTEGER PRIMARY KEY, at TEXT DEFAULT CURRENT_TIMESTAMP, where_ TEXT, msg TEXT);
INSERT OR IGNORE INTO settings VALUES('free_ai_limit','2'),('pro_ai_limit','30');
`);
for (const c of ['password_hash TEXT', "plan TEXT DEFAULT 'free'", 'stripe_customer TEXT', 'sub_status TEXT'])
  try { db.exec(`ALTER TABLE users ADD COLUMN ${c}`); } catch {}
// Bootstrap admin: first ADMIN_EMAILS entry + ADMIN_PASSWORD (customers can never self-register an admin email)
if (admins[0] && ADMIN_PASSWORD) db.prepare(`INSERT INTO users(sub,email,name,role,password_hash) VALUES(?,?,'Admin','admin',?)
  ON CONFLICT(sub) DO UPDATE SET password_hash=excluded.password_hash, role='admin'`).run('email:' + admins[0], admins[0], bcrypt.hashSync(ADMIN_PASSWORD, 12));
const setting = k => db.prepare('SELECT v FROM settings WHERE k=?').get(k)?.v;
const logErr = (where_, e) => db.prepare('INSERT INTO errors(where_,msg) VALUES(?,?)').run(where_, String(e?.message || e).slice(0, 500));

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], scriptSrcAttr: ["'unsafe-inline'"],
  styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  fontSrc: ['https://fonts.gstatic.com'], connectSrc: ["'self'"], imgSrc: ["'self'", 'data:'],
} } }));
// ---------- Stripe webhook (raw body, must come before express.json) ----------
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
const setPlan = (cust, status) => db.prepare('UPDATE users SET sub_status=?, plan=? WHERE stripe_customer=?')
  .run(status, ['active', 'trialing'].includes(status) ? 'pro' : 'free', cust);
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.sendStatus(503);
  let ev;
  try { ev = stripe.webhooks.constructEvent(req.body, req.get('stripe-signature'), STRIPE_WEBHOOK_SECRET); }
  catch { return res.status(400).send('bad signature'); }
  try {
    const o = ev.data.object;
    if (ev.type === 'checkout.session.completed' && o.mode === 'subscription' && o.payment_status !== 'unpaid') {
      db.prepare('UPDATE users SET stripe_customer=? WHERE id=?').run(o.customer, +o.client_reference_id);
      setPlan(o.customer, 'active');
    } else if (ev.type.startsWith('customer.subscription.')) setPlan(o.customer, o.status);
  } catch (e) { logErr('stripe', e); return res.sendStatus(500); }
  res.json({ received: true });
});

app.use(express.json({ limit: '1mb' }));
app.use(cookieSession({ name: 'jp', keys: [SESSION_SECRET], httpOnly: true, sameSite: 'lax', secure: prod, maxAge: 7 * 864e5 }));
app.use('/api', rateLimit({ windowMs: 60_000, limit: 120 }));
// CSRF guard: state-changing API calls must carry a custom header (browsers block it cross-site)
app.use('/api', (req, res, next) =>
  req.method === 'GET' || req.get('X-Requested-With') === 'jobpilot' ? next() : res.status(403).json({ error: 'csrf' }));

const auth = (req, res, next) => req.session.uid ? next() : res.status(401).json({ error: 'sign in required' });
const adminOnly = (req, res, next) => {
  const u = db.prepare('SELECT role FROM users WHERE id=?').get(req.session.uid);
  u?.role === 'admin' ? next() : res.status(403).json({ error: 'admin only' });
};

function signIn(req, sub, email, name, verified = false) {
  const role = verified && admins.includes((email || '').toLowerCase()) ? 'admin' : 'user';
  db.prepare(`INSERT INTO users(sub,email,name,role) VALUES(?,?,?,?)
    ON CONFLICT(sub) DO UPDATE SET email=excluded.email, name=excluded.name, role=CASE WHEN excluded.role='admin' THEN 'admin' ELSE role END`).run(sub, email, name, role);
  req.session.uid = db.prepare('SELECT id FROM users WHERE sub=?').get(sub).id;
}

// ---------- LinkedIn OAuth 2.0 / OpenID Connect (sign-in only; no passwords, no automation) ----------
app.get('/auth/linkedin', (req, res) => {
  if (!LINKEDIN_CLIENT_ID) return prod ? res.status(503).send('LinkedIn not configured') : res.redirect('/auth/dev');
  req.session.state = crypto.randomBytes(16).toString('hex');
  res.redirect('https://www.linkedin.com/oauth/v2/authorization?' + new URLSearchParams({
    response_type: 'code', client_id: LINKEDIN_CLIENT_ID, redirect_uri: BASE_URL + '/auth/linkedin/callback',
    state: req.session.state, scope: 'openid profile email',
  }));
});
app.get('/auth/linkedin/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || state !== req.session.state) return res.status(400).send('Invalid state');
    req.session.state = null;
    const tok = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: BASE_URL + '/auth/linkedin/callback', client_id: LINKEDIN_CLIENT_ID, client_secret: LINKEDIN_CLIENT_SECRET }),
    }).then(r => r.json());
    if (!tok.access_token) throw new Error('token exchange failed');
    const p = await fetch('https://api.linkedin.com/v2/userinfo', { headers: { Authorization: 'Bearer ' + tok.access_token } }).then(r => r.json());
    signIn(req, 'li:' + p.sub, p.email, p.name, p.email_verified === true); // access token is not stored
    res.redirect('/');
  } catch (e) { logErr('linkedin', e); res.status(500).send('Sign-in failed. Try again.'); }
});
app.get('/auth/dev', (req, res) => { // local preview only
  if (prod) return res.sendStatus(404);
  signIn(req, 'dev:demo', 'dev@local', 'Demo user');
  res.redirect('/');
});
// ---------- email + password accounts ----------
const authLimit = rateLimit({ windowMs: 15 * 60_000, limit: 20 });
app.post('/api/register', authLimit, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), name = String(req.body.name || '').trim().slice(0, 80), pw = String(req.body.password || '');
  if (!name || !/^\S+@\S+\.\S+$/.test(email) || pw.length < 10 || pw.length > 200)
    return res.status(400).json({ error: 'Enter your name, a valid email and a password of at least 10 characters.' });
  if (admins.includes(email)) return res.status(400).json({ error: 'This email address is reserved.' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return res.status(409).json({ error: 'An account with this email already exists. Sign in instead.' });
  const r = db.prepare("INSERT INTO users(sub,email,name,password_hash) VALUES(?,?,?,?)").run('email:' + email, email, name, bcrypt.hashSync(pw, 12));
  req.session.uid = r.lastInsertRowid;
  res.json({ ok: true, role: 'user' });
});
app.post('/api/login', authLimit, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = db.prepare('SELECT id,role,password_hash FROM users WHERE sub=?').get('email:' + email);
  if (!u?.password_hash || !bcrypt.compareSync(String(req.body.password || ''), u.password_hash))
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  req.session.uid = u.id;
  res.json({ ok: true, role: u.role });
});
app.post('/api/logout', (req, res) => { req.session = null; res.json({ ok: true }); });

// ---------- user API ----------
app.get('/api/me', (req, res) => {
  const u = req.session.uid && db.prepare('SELECT name,email,role,plan,sub_status FROM users WHERE id=?').get(req.session.uid);
  res.json(u ? { user: u, aiEnabled: !!ai, billing: !!(stripe && STRIPE_PRICE_ID) } : {});
});
app.get('/api/state', auth, (req, res) => {
  const r = db.prepare('SELECT json FROM state WHERE user_id=?').get(req.session.uid);
  res.json(r ? JSON.parse(r.json) : {});
});
app.put('/api/state', auth, (req, res) => {
  if (typeof req.body !== 'object' || Array.isArray(req.body)) return res.status(400).json({ error: 'bad body' });
  db.prepare(`INSERT INTO state(user_id,json) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated=CURRENT_TIMESTAMP`)
    .run(req.session.uid, JSON.stringify(req.body));
  res.json({ ok: true });
});
app.get('/api/jobs', auth, (req, res) => {
  const rows = db.prepare('SELECT id,t,c,loc,rem,lvl,sal,sk,d FROM jobs WHERE source_id IN (SELECT id FROM sources WHERE enabled=1) LIMIT 500').all();
  res.json(rows.map(r => ({ ...r, sk: JSON.parse(r.sk || '[]') })));
});

// ---------- AI cover letter (server-side key, per-user daily limit) ----------
app.post('/api/prepare', auth, async (req, res) => {
  if (!ai) return res.status(503).json({ error: 'AI is not configured on the server.' });
  const day = new Date().toISOString().slice(0, 10), uid = req.session.uid; let limit;
  const me = db.prepare('SELECT plan,role FROM users WHERE id=?').get(uid), pro = me.plan === 'pro' || me.role === 'admin';
  limit = +setting(pro ? 'pro_ai_limit' : 'free_ai_limit');
  const used = db.prepare('SELECT n FROM usage WHERE user_id=? AND day=?').get(uid, day)?.n || 0;
  if (used >= limit) return res.status(429).json({ error: `Daily AI limit reached (${limit}).` + (pro ? '' : ' Upgrade to Pro for more.') });
  const job = db.prepare('SELECT t,c,d,sk FROM jobs WHERE id=?').get(+req.body.jobId);
  const st = JSON.parse(db.prepare('SELECT json FROM state WHERE user_id=?').get(uid)?.json || '{}');
  if (!job) return res.status(404).json({ error: 'Job not found. Sample jobs are not stored on the server; add a job source first.' });
  if (!st.cv) return res.status(400).json({ error: 'Add your CV first.' });
  try {
    const r = await ai.messages.create({
      model: AI_MODEL, max_tokens: 700,
      system: 'You write concise, honest cover letters. Use only facts present in the CV. Never invent employers, degrees or numbers. Plain text, under 220 words.',
      messages: [{ role: 'user', content: `CV:\n${String(st.cv).slice(0, 8000)}\n\nJob: ${job.t} at ${job.c}\n${job.d}\nKey skills: ${job.sk}\n\nWrite the cover letter.` }],
    });
    db.prepare('INSERT INTO usage(user_id,day,n) VALUES(?,?,1) ON CONFLICT(user_id,day) DO UPDATE SET n=n+1').run(uid, day);
    res.json({ letter: r.content.filter(b => b.type === 'text').map(b => b.text).join(''), remaining: limit - used - 1 });
  } catch (e) { logErr('ai', e); res.status(502).json({ error: 'AI request failed.' }); }
});

// ---------- admin (never returns CVs or user state) ----------
const A = express.Router();
app.use('/api/admin', auth, adminOnly, A);
const day = () => new Date().toISOString().slice(0, 10);
A.get('/users', (req, res) => res.json(db.prepare(
  `SELECT u.id,u.name,u.email,u.role,u.plan,u.sub_status,u.created,COALESCE((SELECT n FROM usage WHERE user_id=u.id AND day=?),0) ai_today FROM users u`).all(day())));
A.delete('/users/:id', (req, res) => { db.prepare('DELETE FROM users WHERE id=?').run(+req.params.id); res.json({ ok: true }); });
A.get('/settings', (req, res) => res.json(Object.fromEntries(db.prepare('SELECT k,v FROM settings').all().map(r => [r.k, r.v]))));
A.put('/settings', (req, res) => {
  for (const k of ['free_ai_limit', 'pro_ai_limit']) {
    const n = parseInt(req.body[k], 10);
    if (!(n >= 0 && n <= 1000)) return res.status(400).json({ error: k + ' must be 0-1000' });
    db.prepare('UPDATE settings SET v=? WHERE k=?').run(String(n), k);
  }
  res.json({ ok: true });
});
A.put('/users/:id/plan', (req, res) => { // manual grant, e.g. complimentary Pro
  if (!['free', 'pro'].includes(req.body.plan)) return res.status(400).json({ error: 'plan must be free or pro' });
  db.prepare('UPDATE users SET plan=? WHERE id=?').run(req.body.plan, +req.params.id);
  res.json({ ok: true });
});
A.get('/sources', (req, res) => res.json(db.prepare('SELECT * FROM sources').all()));
A.post('/sources', (req, res) => {
  const { name, url } = req.body;
  if (!name || !/^https:\/\//.test(url || '')) return res.status(400).json({ error: 'name and https url required' });
  res.json({ id: db.prepare('INSERT INTO sources(name,url) VALUES(?,?)').run(name, url).lastInsertRowid });
});
A.patch('/sources/:id', (req, res) => { db.prepare('UPDATE sources SET enabled=? WHERE id=?').run(req.body.enabled ? 1 : 0, +req.params.id); res.json({ ok: true }); });
A.delete('/sources/:id', (req, res) => { db.prepare('DELETE FROM sources WHERE id=?').run(+req.params.id); res.json({ ok: true }); });
// Source feeds must be authorised JSON arrays: [{id,title,company,location,remote,level,salary,skills[],description}]
A.post('/sync', async (req, res) => {
  const out = [];
  for (const s of db.prepare('SELECT * FROM sources WHERE enabled=1').all()) {
    try {
      const feed = await fetch(s.url, { signal: AbortSignal.timeout(15000) }).then(r => r.json());
      if (!Array.isArray(feed)) throw new Error('feed is not an array');
      const ins = db.prepare(`INSERT INTO jobs(source_id,ext_id,t,c,loc,rem,lvl,sal,sk,d) VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(source_id,ext_id) DO UPDATE SET t=excluded.t,c=excluded.c,loc=excluded.loc,rem=excluded.rem,lvl=excluded.lvl,sal=excluded.sal,sk=excluded.sk,d=excluded.d`);
      db.transaction(() => feed.slice(0, 500).forEach(j => ins.run(s.id, String(j.id), j.title, j.company, j.location, j.remote || 'onsite', j.level || 'mid', +j.salary || 0,
        JSON.stringify((j.skills || []).map(x => String(x).toLowerCase())), String(j.description || '').slice(0, 2000))))();
      out.push({ source: s.name, ok: true, count: Math.min(feed.length, 500) });
    } catch (e) { logErr('sync:' + s.name, e); out.push({ source: s.name, ok: false, error: e.message }); }
  }
  res.json(out);
});
A.get('/errors', (req, res) => res.json(db.prepare('SELECT * FROM errors ORDER BY id DESC LIMIT 100').all()));

// ---------- billing (Stripe Checkout + Customer Portal; card data never touches this server) ----------
app.post('/api/billing/checkout', auth, async (req, res) => {
  if (!stripe || !STRIPE_PRICE_ID) return res.status(503).json({ error: 'Billing is not configured.' });
  try {
    const u = db.prepare('SELECT id,email,plan,stripe_customer FROM users WHERE id=?').get(req.session.uid);
    if (u.plan === 'pro') return res.status(400).json({ error: 'You already have Pro.' });
    const who = u.stripe_customer ? { customer: u.stripe_customer } : (u.email && u.email !== 'dev@local' ? { customer_email: u.email } : {});
    const s = await stripe.checkout.sessions.create({ mode: 'subscription', line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      client_reference_id: String(u.id), ...who, success_url: BASE_URL + '/?billing=success', cancel_url: BASE_URL + '/?billing=cancelled' });
    res.json({ url: s.url });
  } catch (e) { logErr('checkout', e); res.status(502).json({ error: 'Could not start checkout.' }); }
});
app.post('/api/billing/portal', auth, async (req, res) => {
  const u = db.prepare('SELECT stripe_customer FROM users WHERE id=?').get(req.session.uid);
  if (!stripe || !u?.stripe_customer) return res.status(400).json({ error: 'No billing account yet.' });
  try { res.json({ url: (await stripe.billingPortal.sessions.create({ customer: u.stripe_customer, return_url: BASE_URL + '/' })).url }); }
  catch (e) { logErr('portal', e); res.status(502).json({ error: 'Could not open billing portal.' }); }
});

// ---------- frontend + errors ----------
app.get('/admin', (req, res) => { // admin screen is only served to admins
  const u = req.session.uid && db.prepare('SELECT role FROM users WHERE id=?').get(req.session.uid);
  u?.role === 'admin' ? res.sendFile('admin.html', { root: 'views' }) : res.redirect('/login.html');
});
app.use(express.static('public'));
app.use((e, req, res, next) => { logErr('server', e); res.status(500).json({ error: 'server error' }); });
app.listen(PORT, () => console.log(`JobPilot running at ${BASE_URL}`));
