const $ = s => document.querySelector(s), enc8 = new TextEncoder();
let me, tok, key, ws, allUsers = [], rooms = {}, activeRoom = null, lastTyping = 0;

const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const post = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(r => r.json());

async function derive(pass) {
  const base = await crypto.subtle.importKey('raw', enc8.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: enc8.encode('vaultline-v1'), iterations: 310000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function enc(text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { iv: b64(iv), c: b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc8.encode(text))) };
}
async function dec(m) {
  try { return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(m.iv) }, key, unb64(m.c))); }
  catch { return null; }
}
function hue(name) { let h = 0; for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) % 360; return h; }
function avatarStyle(name) { const h = hue(name); return 'background:linear-gradient(135deg,hsl(' + h + ' 80% 60%),hsl(' + ((h + 50) % 360) + ' 80% 50%))'; }
function otherUser(room) { if (room === 'general') return null; return room.split('::').find(u => u !== me); }
function roomLabel(room) { return room === 'general' ? 'General' : otherUser(room); }

async function lastPreview(room) {
  const list = rooms[room] || [];
  if (!list.length) return 'No messages yet';
  const t = await dec(list[list.length - 1]);
  return t === null ? '🔒 Encrypted message' : t;
}

async function renderList() {
  const el = $('#chatlist'); el.innerHTML = '';
  const roomIds = ['general', ...allUsers.filter(u => u !== me).map(u => [u, me].sort().join('::'))];
  for (const room of roomIds) {
    const label = roomLabel(room), isGroup = room === 'general';
    const div = document.createElement('div');
    div.className = 'chatitem' + (room === activeRoom ? ' active' : '');
    const av = document.createElement('div'); av.className = 'av';
    av.textContent = isGroup ? '#' : label.charAt(0);
    av.style = isGroup ? 'background:linear-gradient(135deg,#7a5cff,#3dffc0)' : avatarStyle(label);
    if (!isGroup && window.__online && window.__online.includes(label)) {
      const d = document.createElement('span'); d.className = 'dot'; av.append(d);
    }
    const txt = document.createElement('div'); txt.className = 'ci-text';
    const nm = document.createElement('div'); nm.className = 'ci-name'; nm.textContent = label;
    const pv = document.createElement('div'); pv.className = 'ci-prev'; pv.textContent = await lastPreview(room);
    txt.append(nm, pv); div.append(av, txt);
    div.onclick = () => openRoom(room);
    el.append(div);
  }
}

function tickSvg() {
  return '<svg class="tick" viewBox="0 0 24 24" fill="none" stroke="#3dffc0" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12l5 5L20 6"/></svg>';
}

async function paintLog() {
  const log = $('#log'); log.innerHTML = '';
  const list = rooms[activeRoom] || [];
  for (const m of list) await appendMsg(m, false);
  log.scrollTop = log.scrollHeight;
}

async function appendMsg(m, scroll) {
  if (m.room !== activeRoom) return;
  const text = await dec(m), row = document.createElement('div');
  row.className = 'row' + (m.u === me ? ' me' : '');
  const av = document.createElement('div'); av.className = 'av sm'; av.textContent = m.u.charAt(0); av.style = avatarStyle(m.u);
  const box = document.createElement('div'); box.className = 'm' + (text === null ? ' bad' : '');
  const n = document.createElement('b'), t = document.createElement('span'), meta = document.createElement('div');
  meta.className = 'meta';
  n.textContent = m.u; t.textContent = text ?? 'Cannot decrypt (wrong team passphrase?)';
  meta.textContent = new Date(m.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (m.u === me) meta.insertAdjacentHTML('beforeend', tickSvg());
  box.append(n, t, meta); row.append(av, box);
  const log = $('#log'); log.append(row);
  if (scroll !== false) log.scrollTop = log.scrollHeight;
}

function openRoom(room) {
  activeRoom = room;
  const main = $('#main'); main.classList.remove('empty');
  main.innerHTML = '';
  const label = roomLabel(room), isGroup = room === 'general';
  const header = document.createElement('div'); header.id = 'chatheader';
  const back = document.createElement('button'); back.className = 'iconbtn'; back.id = 'backbtn'; back.setAttribute('aria-label', 'Back');
  back.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="#f3f1ff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>';
  back.onclick = () => $('#sidebar').classList.remove('collapsed');
  const av = document.createElement('div'); av.className = 'av sm';
  av.textContent = isGroup ? '#' : label.charAt(0);
  av.style = isGroup ? 'background:linear-gradient(135deg,#7a5cff,#3dffc0)' : avatarStyle(label);
  const who = document.createElement('div'); who.className = 'who';
  const nm = document.createElement('div'); nm.className = 'ci-name'; nm.textContent = label;
  const st = document.createElement('div'); st.className = 'ci-prev'; st.id = 'statusline'; st.textContent = isGroup ? 'Everyone on the team' : 'Offline';
  who.append(nm, st); header.append(back, av, who);
  const log = document.createElement('div'); log.id = 'log';
  const typing = document.createElement('div'); typing.id = 'typing';
  const form = document.createElement('form'); form.id = 'send';
  form.innerHTML = '<input id="t" placeholder="Write a message..." autocomplete="off" maxlength="1000"><button aria-label="Send"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></button>';
  main.append(header, log, typing, form);
  updateStatus();
  paintLog();
  form.onsubmit = async e => {
    e.preventDefault(); const v = $('#t').value.trim(); if (!v || ws.readyState !== 1) return;
    const o = await enc(v); ws.send(JSON.stringify({ t: 'msg', room: activeRoom, ...o })); $('#t').value = '';
  };
  $('#t').oninput = () => { const now = Date.now(); if (now - lastTyping > 2000) { lastTyping = now; ws.send(JSON.stringify({ t: 'typing', room: activeRoom })); } };
  if (window.innerWidth <= 760) { $('#sidebar').classList.add('collapsed'); back.style.display = 'grid'; }
  renderList();
}

function updateStatus() {
  if (!activeRoom || activeRoom === 'general') return;
  const label = otherUser(activeRoom), line = document.getElementById('statusline');
  if (line) line.textContent = (window.__online || []).includes(label) ? 'Online' : 'Offline';
}

function connect() {
  ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host);
  ws.onopen = () => ws.send(JSON.stringify({ t: 'auth', token: tok }));
  ws.onmessage = async e => {
    const m = JSON.parse(e.data);
    if (m.t === 'rooms') {
      rooms = m.rooms; allUsers = m.users;
      await renderList();
      if (!activeRoom) openRoom('general');
    } else if (m.t === 'msg') {
      if (!rooms[m.room]) rooms[m.room] = [];
      rooms[m.room].push(m);
      await appendMsg(m, true);
      renderList();
    } else if (m.t === 'presence') {
      window.__online = m.online; updateStatus(); renderList();
    } else if (m.t === 'typing') {
      if (m.room === activeRoom) {
        const el = document.getElementById('typing');
        if (el) { el.textContent = m.u + ' is typing...'; clearTimeout(window.__tt); window.__tt = setTimeout(() => el.textContent = '', 2500); }
      }
    }
  };
  ws.onclose = () => { if (tok) setTimeout(connect, 2000); };
}

$('#go').onclick = async () => {
  $('#err').textContent = '';
  if (!$('#k').value) return $('#err').textContent = 'Enter the team passphrase.';
  const r = await post('/api/login', { u: $('#u').value.trim(), p: $('#p').value });
  if (r.e) return $('#err').textContent = r.e;
  me = r.u; tok = r.token; allUsers = r.users; key = await derive($('#k').value);
  $('#p').value = $('#k').value = '';
  $('#login').classList.add('hide'); $('#app').classList.remove('hide'); connect();
};
$('#out').onclick = () => { tok = null; if (ws) ws.close(); location.reload(); };
const admin = del => async () => {
  const r = await post('/api/admin', { k: $('#ak').value, u: $('#au').value.trim(), p: $('#ap').value, del });
  $('#aerr').style.color = r.e ? '' : '#3dffc0';
  $('#aerr').textContent = r.e || 'Done. Teammates: ' + r.users.join(', ');
};
$('#add').onclick = admin(false); $('#del').onclick = admin(true);
