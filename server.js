const express = require('express'), http = require('http'), crypto = require('crypto'), fs = require('fs');
const { WebSocketServer } = require('ws');
const app = express(), srv = http.createServer(app);
const ADMIN = process.env.ADMIN_KEY || '';
const DB = (process.env.DATA_DIR || '.') + '/users.json';
const MSGDB = (process.env.DATA_DIR || '.') + '/messages.json';
let users = {}; try { users = JSON.parse(fs.readFileSync(DB)); } catch {}
let rooms = {}; try { rooms = JSON.parse(fs.readFileSync(MSGDB)); } catch {}
const saveUsers = () => fs.writeFileSync(DB, JSON.stringify(users));
const saveRooms = () => fs.writeFileSync(MSGDB, JSON.stringify(rooms));
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
  r.json({ token, u, users: Object.keys(users) });
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
  saveUsers(); r.json({ ok: 1, users: Object.keys(users) });
});

// the server only ever relays encrypted text, never plaintext
const wss = new WebSocketServer({ server: srv, maxPayload: 4096 });
const online = new Map(); // username -> Set of sockets

function broadcastPresence() {
  const list = [...online.keys()];
  const out = JSON.stringify({ t: 'presence', online: list });
  wss.clients.forEach(c => c.me && c.readyState === 1 && c.send(out));
}

wss.on('connection', ws => {
  ws.on('message', d => {
    let m; try { m = JSON.parse(d); } catch { return; }
    if (!ws.me) {
      const s = sessions.get(m.token);
      if (m.t === 'auth' && s && s.exp > Date.now()) {
        ws.me = s.u;
        if (!online.has(ws.me)) online.set(ws.me, new Set());
        online.get(ws.me).add(ws);
        const mine = {};
        for (const id in rooms) if (id === 'general' || id.split('::').includes(ws.me)) mine[id] = rooms[id];
        ws.send(JSON.stringify({ t: 'rooms', rooms: mine, users: Object.keys(users) }));
        broadcastPresence();
      } else ws.close();
      return;
    }
    if (m.t === 'msg' && typeof m.c === 'string' && typeof m.iv === 'string' && typeof m.room === 'string') {
      // room must be "general" or a private room this user belongs to
      if (m.room !== 'general' && !m.room.split('::').includes(ws.me)) return;
      if (m.room !== 'general' && !(m.room.split('::').length === 2 && m.room.split('::').every(u => users[u]))) return;
      const o = { id: crypto.randomUUID(), u: ws.me, c: m.c, iv: m.iv, ts: Date.now(), room: m.room };
      if (!rooms[m.room]) rooms[m.room] = [];
      rooms[m.room].push(o); if (rooms[m.room].length > 200) rooms[m.room].shift();
      saveRooms();
      const out = JSON.stringify({ t: 'msg', ...o });
      wss.clients.forEach(c => {
        if (!c.me || c.readyState !== 1) return;
        if (m.room === 'general' || m.room.split('::').includes(c.me)) c.send(out);
      });
    }
    if (m.t === 'typing' && typeof m.room === 'string') {
      const out = JSON.stringify({ t: 'typing', u: ws.me, room: m.room });
      wss.clients.forEach(c => {
        if (c === ws || !c.me || c.readyState !== 1) return;
        if (m.room === 'general' || m.room.split('::').includes(c.me)) c.send(out);
      });
    }
  });
  ws.on('close', () => {
    if (ws.me && online.has(ws.me)) {
      online.get(ws.me).delete(ws);
      if (online.get(ws.me).size === 0) online.delete(ws.me);
      broadcastPresence();
    }
  });
});
srv.listen(process.env.PORT || 3000);
