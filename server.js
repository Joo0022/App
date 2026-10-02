const express = require('express'), http = require('http'), crypto = require('crypto'), fs = require('fs');
const { WebSocketServer } = require('ws');
const app = express(), srv = http.createServer(app);
const ADMIN = process.env.ADMIN_KEY || '';
const DB = (process.env.DATA_DIR || '.') + '/users.json';
let users = {}; try { users = JSON.parse(fs.readFileSync(DB)); } catch {}
const save = () => fs.writeFileSync(DB, JSON.stringify(users));
const hash = (p, s) => crypto.scryptSync(p, s, 64);
const eq = (a, b) => { a = Buffer.from(a); b = Buffer.from(b); return a.length === b.length && crypto.timingSafeEqual(a, b); };

app.set('trust proxy', 1);
app.use((q, r, n) => {
  r.set({
    'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; connect-src 'self' wss: ws:; frame-ancestors 'none'",
    'Strict-Transport-Security': 'max-age=31536000',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'
  }); n();
});
app.use(express.json({ limit: '2kb' }));
app.use(express.static('public'));

// brute-force protection: 5 failures per IP per 10 minutes
const fails = new Map(), sessions = new Map();
const blocked = ip => { const f = fails.get(ip); if (f && Date.now() - f.t > 6e5) fails.delete(ip); return (fails.get(ip)?.n || 0) >= 5; };
const fail = ip => { const f = fails.get(ip) || { n: 0, t: Date.now() }; f.n++; fails.set(ip, f); };

app.post('/api/login', (q, r) => {
  if (blocked(q.ip)) return r.status(429).json({ e: 'Too many attempts. Try again in 10 minutes.' });
  const { u, p } = q.body || {}, x = users[u];
  const salt = x ? x.s : '00', h = typeof p === 'string' ? hash(p, salt) : null;
  if (!x || !h || !eq(h, Buffer.from(x.h, 'hex'))) { fail(q.ip); return r.status(401).json({ e: 'Wrong username or password.' }); }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { u, exp: Date.now() + 12 * 36e5 });
  r.json({ token, u });
});

app.post('/api/admin', (q, r) => {
  if (blocked(q.ip)) return r.status(429).json({ e: 'Too many attempts.' });
  const { k, u, p, del } = q.body || {};
  if (!ADMIN || typeof k !== 'string' || !eq(k, ADMIN)) { fail(q.ip); return r.status(403).json({ e: 'Wrong owner key.' }); }
  if (typeof u !== 'string' || !/^\w{2,20}$/.test(u)) return r.status(400).json({ e: 'Username: 2-20 letters, numbers or _' });
  if (del) delete users[u];
  else {
    if (typeof p !== 'string' || p.length < 10) return r.status(400).json({ e: 'Password needs 10+ characters.' });
    const s = crypto.randomBytes(16).toString('hex'); users[u] = { s, h: hash(p, s).toString('hex') };
  }
  save(); r.json({ ok: 1, users: Object.keys(users) });
});

// the server only ever relays encrypted text
const hist = [];
const wss = new WebSocketServer({ server: srv, maxPayload: 4096 });
wss.on('connection', ws => {
  ws.on('message', d => {
    let m; try { m = JSON.parse(d); } catch { return; }
    if (!ws.me) {
      const s = sessions.get(m.token);
      if (m.t === 'auth' && s && s.exp > Date.now()) { ws.me = s.u; ws.send(JSON.stringify({ t: 'hist', h: hist })); } else ws.close();
      return;
    }
    if (m.t === 'msg' && typeof m.c === 'string' && typeof m.iv === 'string') {
      const o = { u: ws.me, c: m.c, iv: m.iv, ts: Date.now() };
      hist.push(o); if (hist.length > 50) hist.shift();
      const out = JSON.stringify({ t: 'msg', ...o });
      wss.clients.forEach(c => c.me && c.readyState === 1 && c.send(out));
    }
  });
});
srv.listen(process.env.PORT || 3000);
