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
function roomLabel(room) { return room === 'general' ? 'Team · General' : otherUser(room); }
function fmtSize(n) { if (n > 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB'; if (n > 1024) return Math.round(n / 1024) + ' KB'; return n + ' B'; }

async function lastPreview(room) {
  const list = rooms[room] || [];
  if (!list.length) return 'No messages yet';
  const last = list[list.length - 1];
  if (last.file) return '📎 ' + last.file.name;
  const t = await dec(last);
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
    const nm = document.createElement('div'); nm.className = 'ci-name'; nm.textContent = isGroup ? 'General' : label;
    const pv = document.createElement('div'); pv.className = 'ci-prev'; pv.textContent = await lastPreview(room);
    txt.append(nm, pv); div.append(av, txt);
    div.onclick = () => openRoom(room);
    el.append(div);
  }
}

function tickSvg(seen) {
  return '<svg class="tick" viewBox="0 0 24 24" fill="none" stroke="' + (seen ? '#3dffc0' : 'currentColor') + '" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12l5 5L20 6"/></svg>';
}

function fileCard(file) {
  const isImg = /^image\//.test(file.mime || '');
  if (isImg) {
    return '<a href="' + file.url + '" target="_blank" rel="noopener" style="display:block"><img src="' + file.url + '" alt="' + file.name.replace(/"/g, '') + '" style="max-width:220px;max-height:220px;border-radius:14px;display:block;margin-bottom:4px"></a>';
  }
  return '<a href="' + file.url + '" target="_blank" rel="noopener" class="filecard" style="display:flex;align-items:center;gap:10px;background:rgba(0,0,0,.18);border-radius:14px;padding:10px 12px;text-decoration:none;color:inherit;margin-bottom:4px">' +
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>' +
    '<span style="min-width:0"><span style="display:block;font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px">' + file.name + '</span>' +
    '<span style="display:block;font-size:11px;opacity:.7">' + fmtSize(file.size) + '</span></span></a>';
}

async function paintLog() {
  const log = $('#log'); log.innerHTML = '';
  const list = rooms[activeRoom] || [];
  for (const m of list) await appendMsg(m, false);
  log.scrollTop = log.scrollHeight;
}

async function appendMsg(m, scroll) {
  if (m.room !== activeRoom) return;
  const text = m.file ? '' : await dec(m), row = document.createElement('div');
  row.className = 'row' + (m.u === me ? ' me' : '');
  const av = document.createElement('div'); av.className = 'av sm'; av.textContent = m.u.charAt(0); av.style = avatarStyle(m.u);
  const box = document.createElement('div'); box.className = 'm' + (!m.file && text === null ? ' bad' : '');
  const n = document.createElement('b'), meta = document.createElement('div');
  meta.className = 'meta';
  n.textContent = m.u;
  box.append(n);
  if (m.file) {
    const wrap = document.createElement('div'); wrap.innerHTML = fileCard(m.file); box.append(wrap);
  } else {
    const t = document.createElement('span'); t.textContent = text ?? 'Cannot decrypt (wrong team passphrase?)'; box.append(t);
  }
  meta.innerHTML = new Date(m.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + (m.u === me ? tickSvg(true) : '');
  box.append(meta); row.append(av, box);
  const log = $('#log'); log.append(row);
  if (scroll !== false) log.scrollTop = log.scrollHeight;
}

function openRoom(room) {
  activeRoom = room;
  const main = $('#main'); main.classList.remove('empty');
  main.innerHTML = '';
  const label = roomLabel(room), isGroup = room === 'general';
  const header = document.createElement('div'); header.id = 'chatheader';
  header.innerHTML = `
    <button class="iconbtn" id="backbtn2" aria-label="Back" style="display:none"><svg viewBox="0 0 24 24" fill="none" stroke="#f3f1ff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg></button>
    <div class="av sm" style="${isGroup ? 'background:linear-gradient(135deg,#7a5cff,#3dffc0)' : avatarStyle(label)}">${isGroup ? '#' : label.charAt(0)}</div>
    <div class="who"><div class="ci-name">${isGroup ? 'General' : label}</div><div class="ci-prev" id="statusline">${isGroup ? 'Everyone on the team' : 'Offline'}</div></div>`;
  const log = document.createElement('div'); log.id = 'log';
  const typing = document.createElement('div'); typing.id = 'typing';
  const form = document.createElement('form'); form.id = 'send';
  form.innerHTML = `<button type="button" id="clip" aria-label="Attach file" style="width:40px;height:40px;flex:none;padding:0;border-radius:50%;display:grid;place-items:center;background:transparent;border:1px solid var(--line)"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#f3f1ff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a5 5 0 0 1-7.07-7.07l9.19-9.19a3.33 3.33 0 0 1 4.71 4.71l-9.2 9.19a1.67 1.67 0 0 1-2.36-2.36l8.49-8.48"/></svg></button>
    <input type="file" id="filepick" style="display:none">
    <input id="t" placeholder="Write a message..." autocomplete="off" maxlength="1000"><button aria-label="Send"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></button>`;
  main.append(header, log, typing, form);
  document.getElementById('backbtn2').onclick = () => $('#sidebar').classList.remove('collapsed');
  updateStatus();
  paintLog();
  form.onsubmit = async e => {
    e.preventDefault(); const v = $('#t').value.trim(); if (!v || ws.readyState !== 1) return;
    const o = await enc(v); ws.send(JSON.stringify({ t: 'msg', room: activeRoom, ...o })); $('#t').value = '';
  };
  $('#t').oninput = () => { const now = Date.now(); if (now - lastTyping > 2000) { lastTyping = now; ws.send(JSON.stringify({ t: 'typing', room: activeRoom })); } };
  $('#clip').onclick = () => $('#filepick').click();
  $('#filepick').onchange = async () => {
    const f = $('#filepick').files[0]; if (!f) return;
    if (f.size > 15 * 1024 * 1024) { alert('That file is too large. Please keep files under 15 MB.'); $('#filepick').value = ''; return; }
    $('#clip').disabled = true;
    try {
      const fd = new FormData(); fd.append('file', f);
      const res = await fetch('/api/upload', { method: 'POST', headers: { Authorization: 'Bearer ' + tok }, body: fd });
      const j = await res.json();
      if (j.e) { alert(j.e); return; }
      const o = await enc('[file] ' + j.name);
      ws.send(JSON.stringify({ t: 'msg', room: activeRoom, ...o, file: { url: j.url, name: j.name, size: j.size, mime: j.mime } }));
    } catch { alert('Upload failed. Check your connection and try again.'); }
    finally { $('#clip').disabled = false; $('#filepick').value = ''; }
  };
  if (window.innerWidth <= 760) { $('#sidebar').classList.add('collapsed'); document.getElementById('backbtn2').style.display = 'inline-grid'; }
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
$('#backbtn').onclick = () => $('#sidebar').classList.remove('collapsed');
