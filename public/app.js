const $ = s => document.querySelector(s), enc8 = new TextEncoder();
let me, tok, key, ws;
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
async function show(m) {
  const text = await dec(m), d = document.createElement('div');
  d.className = 'm' + (m.u === me ? ' me' : '') + (text === null ? ' bad' : '');
  const n = document.createElement('b'), t = document.createElement('span'), i = document.createElement('i');
  n.textContent = m.u; t.textContent = text ?? '🔒 Cannot decrypt (wrong team passphrase?)';
  i.textContent = new Date(m.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  d.append(n, t, i); const log = $('#log'); log.append(d); log.scrollTop = log.scrollHeight;
}
function connect() {
  ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host);
  ws.onopen = () => ws.send(JSON.stringify({ t: 'auth', token: tok }));
  ws.onmessage = async e => {
    const m = JSON.parse(e.data);
    if (m.t === 'hist') for (const x of m.h) await show(x); else if (m.t === 'msg') show(m);
  };
  ws.onclose = () => { if (tok) setTimeout(connect, 2000); };
}
$('#go').onclick = async () => {
  $('#err').textContent = '';
  if (!$('#k').value) return $('#err').textContent = 'Enter the team passphrase.';
  const r = await post('/api/login', { u: $('#u').value.trim(), p: $('#p').value });
  if (r.e) return $('#err').textContent = r.e;
  me = r.u; tok = r.token; key = await derive($('#k').value);
  $('#p').value = $('#k').value = '';
  $('#login').classList.add('hide'); $('#chat').classList.remove('hide'); connect();
};
$('#send').onsubmit = async e => {
  e.preventDefault(); const v = $('#t').value.trim(); if (!v || ws.readyState !== 1) return;
  const o = await enc(v); ws.send(JSON.stringify({ t: 'msg', ...o })); $('#t').value = '';
};
$('#out').onclick = () => { tok = null; ws.close(); location.reload(); };
const admin = del => async () => {
  const r = await post('/api/admin', { k: $('#ak').value, u: $('#au').value.trim(), p: $('#ap').value, del });
  $('#aerr').style.color = r.e ? '' : 'var(--aqua)';
  $('#aerr').textContent = r.e || 'Done. Teammates: ' + r.users.join(', ');
};
$('#add').onclick = admin(false); $('#del').onclick = admin(true);
