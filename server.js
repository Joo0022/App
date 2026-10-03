const express = require('express'), http = require('http'), crypto = require('crypto'), fs = require('fs'), https = require('https');
const { WebSocketServer } = require('ws');
const multer = require('multer');
const app = express(), srv = http.createServer(app);
const ADMIN = process.env.ADMIN_KEY || '';
const DB = (process.env.DATA_DIR || '.') + '/users.json';
const MSGDB = (process.env.DATA_DIR || '.') + '/messages.json';
const CLOUD_NAME = (process.env.CLOUDINARY_CLOUD_NAME || '').trim();
const CLOUD_KEY = (process.env.CLOUDINARY_API_KEY || '').trim();
const CLOUD_SECRET = (process.env.CLOUDINARY_API_SECRET || '').trim();
let users = {}; try { users = JSON.parse(fs.readFileSync(DB)); } catch {}
let rooms = {}; try { rooms = JSON.parse(fs.readFileSync(MSGDB)); } catch {}
const saveUsers = () => fs.writeFileSync(DB, JSON.stringify(users));
const saveRooms = () => fs.writeFileSync(MSGDB, JSON.stringify(rooms));
const hash = (p, s) => crypto.scryptSync(p, s, 64);
const eq = (a, b) => { a = Buffer.from(a); b = Buffer.from(b); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const roomId = (a, b) => [a, b].sort().join('::');
const userRooms = u => ['general', ...Object.keys(users).filter(x => x !== u).map(x => roomId(x, u))];
const filteredRooms = u => { const r = {}; for (const id of userRooms(u)) if (rooms[id]) r[id] = rooms[id]; return r; };

app.set('trust proxy', 1);
app.use((q, r, n) => {
  r.set({
    'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; img-src 'self' https://res.cloudinary.com data:; media-src 'self' https://res.cloudinary.com; connect-src 'self' wss: ws:; frame-ancestors 'none'",
    'Strict-Transport-Security': 'max-age=31536000',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'
  }); n();
});
app.use(express.json({ limit: '2kb' }));
app.use(express.static('public'));

const fails = new Map(), sessions = new Map();
const blocked = ip => { const f = fails.get(ip); if (f && Date.now() - f.t > 6e5) fails.delete(ip); return (fails.get(ip)?.n || 0) >= 5; };
const fail = ip => { const f = fails.get(ip) || { n: 0, t: Date.now() }; f.n++; fails.set(ip, f); };
const authed = q => { const h = q.headers.authorization || ''; const t = h.startsWith('Bearer ') ? h.slice(7) : ''; const s = sessions.get(t); return s && s.exp > Date.now() ? s.u : null; };

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

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });
app.post('/api/upload', upload.single('file'), (q, r) => {
  const me = authed(q);
  if (!me) return r.status(401).json({ e: 'Session expired, please log in again.' });
  if (!CLOUD_NAME || !CLOUD_KEY || !CLOUD_SECRET) return r.status(500).json({ e: 'File storage is not configured yet.' });
  if (!q.file) return r.status(400).json({ e: 'No file received.' });

  const timestamp = Math.floor(Date.now() / 1000);
  const toSign = `timestamp=${timestamp}`;
  const signature = crypto.createHash('sha1').update(toSign + CLOUD_SECRET).digest('hex');

  const boundary = '----vaultline' + crypto.randomBytes(8).toString('hex');
  const parts = [];
  const field = (name, value) => parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
  field('timestamp', timestamp);
  field('api_key', CLOUD_KEY);
  field('signature', signature);
  parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${q.file.originalname.replace(/"/g, '')}"\r\nContent-Type: ${q.file.mimetype}\r\n\r\n`));
  parts.push(q.file.buffer);
  parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
  const body = Buffer.concat(parts);

  const req = https.request({
    hostname: 'api.cloudinary.com', path: `/v1_1/${CLOUD_NAME}/auto/upload`, method: 'POST',
    headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': body.length }
  }, res => {
    let data = ''; res.on('data', c => data += c);
    res.on('end', () => {
      try {
        const j = JSON.parse(data);
        if (!j.secure_url) {
          const why = (j.error && j.error.message) ? j.error.message : ('HTTP ' + res.statusCode);
          console.log('Cloudinary rejected upload:', why);
          return r.status(502).json({ e: 'Cloudinary says: ' + why });
        }
        r.json({ url: j.secure_url, name: q.file.originalname, size: q.file.size, mime: q.file.mimetype });
      } catch (err) {
        console.log('Bad reply from Cloudinary, HTTP', res.statusCode);
        r.status(502).json({ e: 'Unreadable reply from Cloudinary (HTTP ' + res.statusCode + ').' });
      }
    });
  });
  req.on('error', err => {
    console.log('Could not reach Cloudinary:', err.message);
    r.status(502).json({ e: 'Could not reach Cloudinary: ' + err.message });
  });
  req.write(body); req.end();
});

const wss = new WebSocketServer({ server: srv, maxPayload: 4096 });
const online = new Map();

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
        ws.send(JSON.stringify({ t: 'rooms', rooms: filteredRooms(ws.me), users: Object.keys(users) }));
        broadcastPresence();
      } else ws.close();
      return;
    }
    if (m.t === 'msg' && typeof m.c === 'string' && typeof m.iv === 'string' && typeof m.room === 'string') {
      if (m.room !== 'general' && !m.room.split('::').includes(ws.me)) return;
      if (m.room !== 'general' && !(m.room.split('::').length === 2 && m.room.split('::').every(u => users[u]))) return;
      const o = { id: crypto.randomUUID(), u: ws.me, c: m.c, iv: m.iv, ts: Date.now(), room: m.room };
      if (m.file && typeof m.file === 'object' && typeof m.file.url === 'string') {
        o.file = { url: m.file.url, name: String(m.file.name || 'file').slice(0, 200), size: Number(m.file.size) || 0, mime: String(m.file.mime || '').slice(0, 100) };
      }
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
