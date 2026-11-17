// chatmesh (lehno-mesh) Phase 1.9 - anonymer Ende-zu-Ende-Messenger.
// Verschlüsselter Verlauf, Regeln je Chat (Löschfrist, Einmal-Ansicht, Löschen
// bei beiden), Sprachnachrichten und Dateien, Tarnverkehr.
//
// Grundsätze dieser Datei:
// - Der komplette Chat-Verlauf (eingehend UND ausgehend) liegt in einer
//   verschlüsselten Ablage auf dem Server. Der Schlüssel entsteht nur hier im
//   Browser. Auf dem Gerät selbst bleibt nach dem Abmelden nichts lesbar zurück.
// - Ein Paket wird erst dann vom Server gelöscht (bestätigt), wenn die Nachricht
//   sicher im verschlüsselten Verlauf gespeichert ist. So geht nichts verloren.
// - Jede Nachricht hat eine eigene Kennung, doppelte Zustellung wird erkannt.
// - Es gibt KEINE Uhrzeiten und kein Datum: weder in der Nachricht noch im
//   Verlauf noch in der Anzeige. Nachrichten haben nur eine Reihenfolge-Nummer.
// - Senden, Schlüsselabruf und Anhänge laufen OHNE Konto-Token: der Server
//   erfährt nicht, welches Konto an wen sendet.

const MESH_VERSION = "20261117-phase1.9";
const APP_NAME = "chatmesh";
const DECOY_ADDRESS = "mesh:" + "1".repeat(33);
const ADDR_RE = /^mesh:[1-9A-HJ-NP-Za-km-z]{30,50}$/;
const TOKEN_RE = /^[0-9a-f]{32}$/;
const MIN_PASSWORD = 10;
const SHOW_STEP = 200;                 // so viele Nachrichten je Chat auf einmal anzeigen
const GONE_MAX = 5000;                 // gemerkte Kennungen gelöschter Nachrichten je Chat
// Schutz vor Zumüllen durch Fremde: solange eine Adresse kein Kontakt ist,
// nimmt der Verlauf von ihr nur wenig auf. So kann niemand mit vielen großen
// Anfragen echte Nachrichten aus dem Verlauf drängen.
const REQ_MAX_MSGS = 20;               // Nachrichten je Anfrage-Chat
const REQ_MAX_TEXT = 2000;             // Zeichen je Anfrage-Nachricht
const REQ_MAX_CHATS = 100;             // offene Anfragen insgesamt
const MEDIA_MIMES = {
  image: ["image/jpeg", "image/png", "image/gif", "image/webp"],
  video: ["video/mp4", "video/webm"],
  voice: ["audio/webm", "audio/ogg", "audio/mp4", "audio/mpeg", "audio/wav", "audio/x-wav"],
};
// Arten von Nachrichten. "file" = beliebige Datei (z. B. PDF), wird nie im
// Browser dargestellt, sondern nur nach Klick entschlüsselt und gespeichert.
const KINDS = ["text", "image", "video", "voice", "file"];
const TTL_MAX_MIN = 60 * 24 * 30;      // längste Löschfrist: 30 Tage
const CTL_MAX = 200;                   // wartende Lösch-Aufträge an Gegenüber
const LS_LAST = "lehno-mesh:last-address";
const LS_SEEN = "lehno-mesh:seen";

const STATE = {
  me: null,                       // { address, jwt, identityPriv, signingPriv, kek, identity_pub_b64, signing_pub_b64 }
  sid: 0,                         // Sitzungszähler: ändert sich bei jedem An- und Abmelden
  pubKeyCache: {},                // address -> identity_pub_b64 (geprüft)
  contacts: [],                   // [{ address }] - aus verschlüsselter Userdata-Ablage
  nicknames: {},                  // address -> Spitzname
  declined: [],                   // [address]
  userdataVersion: 0,
  userdataCount: 0,               // Zähler IN der verschlüsselten Ablage (Schutz vor altem Stand)
  userdataDirty: false,
  history: { v: 1, chats: {}, ctl: [] },   // chats[address] = { msgs: [...], gone: [...], read, rules }
  historyVersion: 0,
  historyCount: 0,
  historyLoaded: false,           // nur wenn true darf gespeichert werden (sonst würden wir Daten überschreiben)
  historyDirty: false,
  activeChat: null,
  showCount: SHOW_STEP,
  mediaAllowed: new Set(),        // Chats von Nicht-Kontakten, in denen Medien per Klick freigegeben wurden
  drafts: {},                     // address -> angefangener Text (nur im Arbeitsspeicher)
  cover: true,                    // Tarnverkehr an (Einstellung liegt in der verschlüsselten Kontaktablage)
  outQueue: [],                   // fertig verschlüsselte Pakete, die auf den nächsten Takt warten
  ws: null,
  wsRetry: 0,
  timers: [],
  lastOrder: 0,
};

const MEDIA_URLS = new Map();     // token -> Promise<objectURL> (nur im Arbeitsspeicher)

const $ = (sel, root=document) => root.querySelector(sel);
const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

function show(viewName) {
  $$(".view").forEach(v => v.classList.remove("active"));
  $("#view-" + viewName).classList.add("active");
}

let _toastTimer = null;
function toast(text, kind="") {
  let t = $(".toast");
  if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.appendChild(t); }
  t.textContent = text;
  t.className = "toast show " + kind;
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove("show"), kind === "err" ? 6000 : 2400);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function normalizeAddressInput(raw) {
  let addr = String(raw || "").trim();
  if (!addr) return null;
  if (!addr.startsWith("mesh:")) addr = "mesh:" + addr;
  return ADDR_RE.test(addr) ? addr : null;
}

// Avatar-Initialen: aus Spitzname (1-2 Buchstaben) oder Adress-Präfix (2 Zeichen).
function avatarLabel(addr) {
  if (!addr) return "??";
  const nick = STATE.nicknames[addr];
  if (nick && nick.trim()) {
    const parts = nick.trim().split(/\s+/);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return parts[0].slice(0, 2).toUpperCase();
  }
  return addr.replace(/^mesh:/, "").slice(0, 2).toUpperCase();
}

// =========================================================================
// REIHENFOLGE (statt Zeit)
// =========================================================================
// Jede Nachricht bekommt beim Eintragen die nächste laufende Nummer. Das ist
// ein reiner Zähler ohne Bezug zu Uhr oder Datum.
function nextOrder() {
  STATE.lastOrder = STATE.lastOrder + 1;
  return STATE.lastOrder;
}

// =========================================================================
// API
// =========================================================================
class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

// anon: true = ohne Konto-Token (Senden, Schlüsselabruf, Anhänge).
async function apiFetch(method, path, { json, body, raw, anon } = {}) {
  const headers = {};
  const sid = STATE.sid;
  if (!anon && STATE.me?.jwt) headers["authorization"] = "Bearer " + STATE.me.jwt;
  let payload = body;
  if (json !== undefined) { headers["content-type"] = "application/json"; payload = JSON.stringify(json); }
  let r;
  try {
    r = await fetch(path, { method, headers, body: payload, cache: "no-store" });
  } catch (e) {
    throw new ApiError("Keine Verbindung zum Server", 0);
  }
  if (!r.ok) {
    let detail = r.statusText;
    try { const err = await r.json(); if (err && err.detail) detail = typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail); } catch (e) {}
    // Token ungültig (Konto gelöscht oder auf anderem Gerät wiederhergestellt): abmelden.
    if (r.status === 401 && !anon && STATE.me && sid === STATE.sid && !path.startsWith("/api/login")) {
      logout("Sitzung abgelaufen. Bitte neu anmelden.");
    }
    throw new ApiError(detail, r.status);
  }
  if (raw) return new Uint8Array(await r.arrayBuffer());
  return r.json();
}

const API = {
  post: (path, json) => apiFetch("POST", path, { json }),
  put:  (path, json) => apiFetch("PUT", path, { json }),
  get:  (path) => apiFetch("GET", path),
  del:  (path) => apiFetch("DELETE", path),
  keys: (address) => apiFetch("GET", "/api/keys/" + encodeURIComponent(address), { anon: true }),
  // Alle Anfragen sind gleich lang (Füllfeld gleicht verschieden lange Adressen
  // aus). Der Server antwortet immer mit Status 200 und gleicher Länge; ob es
  // geklappt hat, steht im Feld ok.
  async sendPacket(packet) {
    const pad = "x".repeat(Math.max(0, 55 - String(packet.recipient_address).length));
    const r = await apiFetch("POST", "/api/packets", { json: { ...packet, pad }, anon: true });
    if (!r || r.ok !== true) throw new ApiError((r && r.detail) || "send failed", (r && r.code) || 500);
    return r;
  },
  proofPacket: (pid) => apiFetch("GET", "/api/proof/packet/" + pid, { anon: true }),
  uploadAttachment(blob) {
    const fd = new FormData();
    fd.append("file", new File([blob], "encrypted.bin", { type: "application/octet-stream" }));
    return apiFetch("POST", "/api/attachments", { body: fd, anon: true });   // { token, size_bytes }
  },
  fetchAttachment: (token) => apiFetch("GET", "/api/attachments/" + encodeURIComponent(token), { raw: true, anon: true }),
  deleteAttachment: (token) => apiFetch("DELETE", "/api/attachments/" + encodeURIComponent(token), { anon: true }),
};

function humanError(err) {
  const m = String(err && err.message || err);
  if (err && err.status === 429) return "Zu viele Versuche. Bitte kurz warten.";
  if (err && err.status === 503) return "Der Server ist gerade ausgelastet. Bitte gleich noch einmal versuchen.";
  if (err && err.status === 403) return "Unter dieser Adresse ist chatmesh nicht erreichbar.";
  if (/invalid credentials/.test(m)) return "Adresse oder Passwort falsch.";
  if (/recipient not found|address not found/.test(m)) return "Diese Adresse gibt es nicht.";
  if (/payload too large/.test(m)) return "Die Nachricht ist zu lang (höchstens etwa 60.000 Zeichen).";
  if (/attachment too large/.test(m)) return "Die Datei ist zu groß (höchstens 16 MB).";
  if (/recipient inbox full/.test(m)) return "Das Postfach des Empfängers ist voll.";
  if (err && err.status === 507) return "Der Speicher ist gerade voll. Bitte später erneut versuchen.";
  if (err && err.status === 422) return "Der Server hat die Anfrage abgelehnt. Bitte die Seite neu laden.";
  return m;
}

// =========================================================================
// MERKEN AUF DIESEM GERÄT (nur wenn der Nutzer es ausdrücklich anhakt)
// Gespeichert werden ausschließlich die eigene Adresse und zwei Zähler, mit
// denen ein veralteter Stand vom Server erkannt wird. Kein Schlüssel, kein Inhalt.
// =========================================================================
function rememberEnabled() {
  try { return !!localStorage.getItem(LS_LAST); } catch (e) { return false; }
}
function getRememberedAddress() {
  try { return localStorage.getItem(LS_LAST) || ""; } catch (e) { return ""; }
}
function setRemember(addr) {
  try {
    if (addr) localStorage.setItem(LS_LAST, addr);
    else { localStorage.removeItem(LS_LAST); localStorage.removeItem(LS_SEEN); }
  } catch (e) {}
}
function seenCounters() {
  try {
    const o = JSON.parse(localStorage.getItem(LS_SEEN) || "null");
    if (o && o.a === STATE.me?.address) return o;
  } catch (e) {}
  return { a: STATE.me?.address, h: 0, u: 0 };
}
function noteSeen(kind, n) {
  if (!STATE.me || !rememberEnabled() || getRememberedAddress() !== STATE.me.address) return;
  const o = seenCounters();
  if (n > (o[kind] || 0)) {
    o[kind] = n;
    try { localStorage.setItem(LS_SEEN, JSON.stringify(o)); } catch (e) {}
  }
}
// true, wenn der Server einen älteren Stand liefert als dieses Gerät schon gesehen hat.
function isRollback(kind, n) {
  if (!rememberEnabled() || getRememberedAddress() !== STATE.me?.address) return false;
  return n < (seenCounters()[kind] || 0);
}

// =========================================================================
// VERSCHLÜSSELTE USERDATA-ABLAGE (Kontakte, Spitznamen, Abgelehnte)
// Klartext-Format: { contacts: [{address}], nicknames: {address: name}, declined: [address], _n: Zähler }
// =========================================================================
let _userdataLoaded = false;

function applyUserdata(data) {
  const contacts = Array.isArray(data?.contacts) ? data.contacts : [];
  STATE.contacts = contacts
    .filter(c => c && typeof c.address === "string" && ADDR_RE.test(c.address))
    .map(c => ({ address: c.address }));
  const nicks = (data?.nicknames && typeof data.nicknames === "object") ? data.nicknames : {};
  STATE.nicknames = {};
  for (const [k, v] of Object.entries(nicks)) {
    if (ADDR_RE.test(k) && typeof v === "string") STATE.nicknames[k] = v.slice(0, 60);
  }
  STATE.declined = (Array.isArray(data?.declined) ? data.declined : []).filter(a => typeof a === "string" && ADDR_RE.test(a));
  STATE.userdataCount = Number.isFinite(data?._n) ? data._n : 0;
  STATE.cover = data?.cover === false ? false : true;
}

async function loadUserdata() {
  const sid = STATE.sid;
  const resp = await API.get("/api/userdata");
  if (sid !== STATE.sid) return;
  STATE.userdataVersion = resp.version || 0;
  if (!resp.ciphertext_b64) {
    applyUserdata({});
  } else {
    // Schlägt das Entschlüsseln fehl, brechen wir ab statt mit leeren Daten
    // weiterzumachen (sonst würde die Ablage beim nächsten Speichern überschrieben).
    const data = await LehnoCrypto.decryptUserdata(STATE.me.kek, resp);
    if (sid !== STATE.sid) return;
    applyUserdata(data);
    if (isRollback("u", STATE.userdataCount)) {
      toast("Achtung: Der Server liefert einen älteren Stand deiner Kontaktliste als dieses Gerät zuletzt gesehen hat.", "err");
    }
    noteSeen("u", STATE.userdataCount);
  }
  _userdataLoaded = true;
}

let _saveTimer = null;
function scheduleUserdataSave() {
  STATE.userdataDirty = true;
  if (_saveTimer) clearTimeout(_saveTimer);
  _saveTimer = setTimeout(() => { _saveTimer = null; saveUserdata(); }, 400);
}

let _udChain = Promise.resolve(true);
function saveUserdata() {
  _udChain = _udChain.then(doSaveUserdata, doSaveUserdata);
  return _udChain;
}

async function doSaveUserdata() {
  const sid = STATE.sid;
  if (!STATE.me?.kek || !_userdataLoaded) return false;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const data = { contacts: STATE.contacts, nicknames: STATE.nicknames, declined: STATE.declined, cover: STATE.cover, _n: STATE.userdataCount + 1 };
      const enc = await LehnoCrypto.encryptUserdata(STATE.me.kek, data);
      const resp = await API.put("/api/userdata", { ...enc, expected_version: STATE.userdataVersion });
      if (sid !== STATE.sid) return false;
      STATE.userdataVersion = resp.version;
      STATE.userdataCount = data._n;
      STATE.userdataDirty = false;
      noteSeen("u", data._n);
      return true;
    } catch (e) {
      if (sid !== STATE.sid) return false;
      if (e.status !== 409) break;
      // Anderes Gerät war schneller: neu laden und unsere Änderungen dazumischen.
      try { await reloadUserdataMerging(); } catch (e2) { break; }
      if (sid !== STATE.sid) return false;
    }
  }
  STATE.userdataDirty = true;      // der regelmäßige Takt versucht es erneut
  return false;
}

// Lädt die Kontaktablage neu und behält dabei alles, was lokal schon geändert wurde.
async function reloadUserdataMerging() {
  const sid = STATE.sid;
  const before = { contacts: [...STATE.contacts], nicknames: { ...STATE.nicknames }, declined: [...STATE.declined], cover: STATE.cover };
  await loadUserdata();
  if (sid !== STATE.sid) return;
  STATE.cover = before.cover;
  for (const a of before.declined) {
    if (!STATE.declined.includes(a)) STATE.declined.push(a);
  }
  for (const c of before.contacts) {
    if (!STATE.contacts.find(x => x.address === c.address) && !STATE.declined.includes(c.address)) STATE.contacts.unshift(c);
  }
  Object.assign(STATE.nicknames, before.nicknames);
}

function ensureContact(addr) {
  if (STATE.contacts.find(c => c.address === addr)) return false;
  STATE.contacts.unshift({ address: addr });
  STATE.declined = STATE.declined.filter(a => a !== addr);
  scheduleUserdataSave();
  return true;
}
// Kontakt ist, wen ich angenommen habe ODER wem ich selbst schon geschrieben habe
// (so verschwindet ein Chat auch dann nicht, wenn das Speichern der Kontaktliste
// einmal scheitert).
function isContact(addr) {
  if (STATE.contacts.find(c => c.address === addr)) return true;
  const c = STATE.history.chats[addr];
  return !!(c && c.msgs.some(m => m.me));
}
function chatAddresses() {
  const out = STATE.contacts.map(c => c.address);
  for (const [addr, c] of Object.entries(STATE.history.chats)) {
    if (!out.includes(addr) && c.msgs.some(m => m.me)) out.push(addr);
  }
  return out;
}

// =========================================================================
// VERSCHLÜSSELTER CHAT-VERLAUF
// Nachricht: { id, me: 0|1, k: "text"|"image"|"video", x: Text,
//              a: { t: Token, k: Dateischlüssel, i: IV, m: MIME, c: Bildtext },
//              o: Reihenfolge-Nummer (reiner Zähler, keine Zeit),
//              u: 1 = Alt-Format, Absender nicht kryptografisch geprüft,
//              q: 1 = Einmal-Ansicht, e: Löschzeitpunkt (nur bei Löschfrist) }
// Regeln:    { ttl: Minuten bis zum Löschen (0 = aus), once: Einmal-Ansicht, v }
//            gelten für MEINE Nachrichten in diesem Chat.
// Chat:      { msgs, gone: [Kennungen gelöschter Nachrichten], read }
// =========================================================================
function emptyHistory() { return { v: 1, chats: {}, ctl: [] }; }
function emptyRules() { return { ttl: 0, once: 0, v: 0 }; }
function emptyChat() { return { msgs: [], gone: [], read: 0, rules: emptyRules() }; }

function sanitizeRules(r) {
  if (!r || typeof r !== "object") return emptyRules();
  let ttl = Number(r.ttl);
  if (!Number.isFinite(ttl) || ttl <= 0) ttl = 0;
  return { ttl: Math.min(ttl, TTL_MAX_MIN), once: r.once ? 1 : 0, v: Number.isFinite(r.v) ? Math.max(0, Math.floor(r.v)) : 0 };
}

// Lösch-Aufträge an das Gegenüber, die noch nicht rausgegangen sind.
function sanitizeCtl(list) {
  const out = [];
  const seen = new Set();
  const ids = (x) => (Array.isArray(x) ? x : []).filter(v => typeof v === "string" && v && v.length <= 60).slice(0, 500);
  for (const c of (Array.isArray(list) ? list : [])) {
    if (!c || typeof c !== "object" || typeof c.id !== "string" || seen.has(c.id) || !ADDR_RE.test(c.p)) continue;
    const b = c.b && typeof c.b === "object" ? c.b : {};
    seen.add(c.id);
    out.push({ id: c.id.slice(0, 40), p: c.p, b: { mine: ids(b.mine), yours: ids(b.yours) } });
  }
  return out.slice(-CTL_MAX);
}

function sanitizeMsg(m) {
  if (!m || typeof m !== "object" || typeof m.id !== "string" || !m.id || m.id.length > 80) return null;
  const k = KINDS.includes(m.k) ? m.k : "text";
  const out = {
    id: m.id,
    me: m.me ? 1 : 0,
    k,
    x: typeof m.x === "string" ? m.x : "",
    o: Number.isFinite(m.o) ? m.o : 0,
  };
  if (m.u) out.u = 1;
  if (m.q) out.q = 1;
  if (Number.isFinite(m.e) && m.e > 0) out.e = Math.floor(m.e);
  if (typeof m.p === "string" && /^[0-9a-f]{24}$/.test(m.p)) out.p = m.p;
  if (k !== "text") {
    const a = m.a && typeof m.a === "object" ? m.a : {};
    out.a = {
      t: typeof a.t === "string" && TOKEN_RE.test(a.t) ? a.t : "",
      k: typeof a.k === "string" ? a.k.slice(0, 64) : "",
      i: typeof a.i === "string" ? a.i.slice(0, 32) : "",
      m: typeof a.m === "string" ? a.m.slice(0, 40) : "",
      c: typeof a.c === "string" ? a.c.slice(0, 2000) : "",
    };
    if (k === "file") {
      out.a.n = safeFileName(a.n);
      out.a.s = Number.isFinite(a.s) && a.s > 0 ? Math.floor(a.s) : 0;
    }
  }
  return out;
}

function safeFileName(name) {
  let n = typeof name === "string" ? name : "";
  // Steuer- und Richtungszeichen raus (sonst ließe sich z. B. "exe" als "pdf" tarnen).
  n = n.replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "");
  n = n.replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, "_").replace(/^\.+/, "").trim().slice(0, 120);
  return n || "datei";
}

function sanitizeGone(list) {
  const out = [];
  const seen = new Set();
  for (const id of (Array.isArray(list) ? list : [])) {
    if (typeof id === "string" && id && id.length <= 80 && !seen.has(id)) { seen.add(id); out.push(id); }
  }
  return out.slice(-GONE_MAX);
}

function sanitizeHistory(h) {
  const out = emptyHistory();
  const chats = (h && typeof h === "object" && h.chats && typeof h.chats === "object") ? h.chats : {};
  for (const [addr, c] of Object.entries(chats)) {
    if (!ADDR_RE.test(addr) || !c || typeof c !== "object") continue;
    const gone = sanitizeGone(c.gone);
    const goneSet = new Set(gone);
    const seen = new Set();
    const msgs = [];
    for (const raw of (Array.isArray(c.msgs) ? c.msgs : [])) {
      const m = sanitizeMsg(raw);
      if (!m || seen.has(m.id) || goneSet.has(m.id)) continue;
      seen.add(m.id);
      msgs.push(m);
    }
    msgs.sort(msgCompare);
    out.chats[addr] = { msgs, gone, read: Number.isFinite(c.read) ? c.read : 0, rules: sanitizeRules(c.rules) };
  }
  out.ctl = sanitizeCtl(h && h.ctl);
  return out;
}

function msgCompare(a, b) {
  if (a.o !== b.o) return a.o - b.o;
  return a.id < b.id ? -1 : (a.id > b.id ? 1 : 0);
}

// Vereinigt zwei Verläufe (z. B. zwei Geräte). Nachrichten werden nie
// überschrieben, nur ergänzt. Gelöscht bleibt gelöscht: maßgeblich sind die
// gemerkten Kennungen, nicht Uhrzeiten (Uhren verschiedener Geräte weichen ab).
function mergeHistory(a, b) {
  const out = emptyHistory();
  const addrs = new Set([...Object.keys(a.chats), ...Object.keys(b.chats)]);
  for (const addr of addrs) {
    const ca = a.chats[addr] || emptyChat();
    const cb = b.chats[addr] || emptyChat();
    const gone = sanitizeGone([...(ca.gone || []), ...(cb.gone || [])]);
    const goneSet = new Set(gone);
    const byId = new Map();
    for (const m of [...ca.msgs, ...cb.msgs]) {
      if (goneSet.has(m.id)) continue;
      if (!byId.has(m.id)) byId.set(m.id, m);
    }
    const ra = sanitizeRules(ca.rules), rb = sanitizeRules(cb.rules);
    out.chats[addr] = {
      msgs: Array.from(byId.values()).sort(msgCompare),
      gone,
      read: Math.max(ca.read || 0, cb.read || 0),
      rules: rb.v > ra.v ? rb : ra,      // die zuletzt geänderten Regeln gelten
    };
  }
  out.ctl = sanitizeCtl([...(a.ctl || []), ...(b.ctl || [])]);
  return out;
}

// Übernimmt einen vom Server geladenen Stand in den Arbeitsspeicher (mit
// allem, was lokal schon da ist). Nachrichten, die es bisher nur hier gibt
// (noch nicht gesichert), reihen sich HINTER den Stand vom Server ein: so
// rutscht nichts nachträglich mitten in einen Verlauf, den ein anderes Gerät
// inzwischen weitergeschrieben hat.
function adoptRemoteHistory(remote) {
  let remoteMax = 0;
  const remoteIds = {};
  for (const [addr, c] of Object.entries(remote.data.chats)) {
    remoteIds[addr] = new Set(c.msgs.map(m => m.id));
    remoteMax = Math.max(remoteMax, c.read || 0);
    for (const m of c.msgs) remoteMax = Math.max(remoteMax, m.o);
  }
  const localOnly = [];
  for (const [addr, c] of Object.entries(STATE.history.chats)) {
    const ids = remoteIds[addr];
    for (const m of c.msgs) {
      if ((!ids || !ids.has(m.id)) && m.o <= remoteMax) localOnly.push([addr, m, m.o <= (c.read || 0)]);
    }
  }
  localOnly.sort((x, y) => msgCompare(x[1], y[1]));
  let next = Math.max(remoteMax, STATE.lastOrder);
  for (const [addr, m, wasRead] of localOnly) {
    m.o = ++next;
    if (wasRead) STATE.history.chats[addr].read = m.o;
  }
  STATE.history = mergeHistory(remote.data, STATE.history);
  STATE.historyVersion = remote.version;
  STATE.historyCount = Math.max(STATE.historyCount, remote.count);
  STATE.lastOrder = Math.max(STATE.lastOrder, next);
  for (const c of Object.values(STATE.history.chats)) {
    STATE.lastOrder = Math.max(STATE.lastOrder, c.read || 0);
    for (const m of c.msgs) STATE.lastOrder = Math.max(STATE.lastOrder, m.o);
  }
}

function chatOf(addr, create=false) {
  let c = STATE.history.chats[addr];
  if (!c && create) { c = emptyChat(); STATE.history.chats[addr] = c; }
  return c || null;
}

function addMessage(addr, msg) {
  const c = chatOf(addr, true);
  if (c.msgs.some(m => m.id === msg.id) || c.gone.includes(msg.id)) return false;
  c.msgs.push(msg);
  c.msgs.sort(msgCompare);
  STATE.lastOrder = Math.max(STATE.lastOrder, msg.o);
  return true;
}

// Entfernt Nachrichten spurlos aus einem Chat: kein Platzhalter, kein Hinweis.
// Die Kennungen bleiben intern gemerkt, damit nichts wieder eingespielt wird.
// dropAtt: zugehörige Anhänge auch auf dem Server löschen.
function removeMessages(addr, ids, dropAtt) {
  const c = chatOf(addr);
  if (!c || !ids.length) return 0;
  const set = new Set(ids);
  const removed = c.msgs.filter(m => set.has(m.id));
  if (!removed.length) return 0;
  c.msgs = c.msgs.filter(m => !set.has(m.id));
  c.gone = sanitizeGone([...c.gone, ...removed.map(m => m.id)]);
  // Ein offenes Menü könnte sich auf eine eben entfernte Nachricht beziehen.
  if (STATE.activeChat === addr) { try { closeSheet(); } catch (e) {} }
  for (const m of removed) {
    const tok = m.a && m.a.t;
    if (!tok) continue;
    const pending = MEDIA_URLS.get(tok);
    if (pending) { Promise.resolve(pending).then(u => { try { URL.revokeObjectURL(u); } catch (e) {} }).catch(() => {}); MEDIA_URLS.delete(tok); }
    if (dropAtt) API.deleteAttachment(tok).catch(() => {});
  }
  STATE.historyDirty = true;
  return removed.length;
}

// Löschfrist: Nachrichten, deren Frist abgelaufen ist, verschwinden auf diesem
// Gerät. Das Gegenüber macht dasselbe mit seiner Kopie. Läuft alle paar Sekunden.
function purgeExpired() {
  if (!STATE.me || !STATE.historyLoaded) return false;
  const now = Math.floor(Date.now() / 1000);
  let n = 0, active = false;
  for (const [addr, c] of Object.entries(STATE.history.chats)) {
    const ids = c.msgs.filter(m => m.e && m.e <= now).map(m => m.id);
    if (!ids.length) continue;
    n += removeMessages(addr, ids, true);
    if (addr === STATE.activeChat) active = true;
  }
  if (n) { renderSidebar(); if (active) renderChat(); scheduleHistorySave(); }
  return n > 0;
}

// Einmal-Ansicht: beim Verlassen eines Chats verschwinden dort meine eigenen
// Einmal-Nachrichten und alle Einmal-Nachrichten des Gegenübers, die ich schon
// gesehen habe.
function purgeOnce(addr) {
  const c = chatOf(addr);
  if (!c) return 0;
  const mine = c.msgs.filter(m => m.q && m.me).map(m => m.id);
  const seen = c.msgs.filter(m => m.q && !m.me && m.o <= (c.read || 0)).map(m => m.id);
  const n = removeMessages(addr, mine, false) + removeMessages(addr, seen, true);
  if (n) scheduleHistorySave();
  return n;
}

// Wird immer aufgerufen, wenn der gerade offene Chat verlassen wird.
function leaveChat() {
  const addr = STATE.activeChat;
  if (!addr) return;
  stopRecording(true);          // eine laufende Sprachaufnahme gehört zu diesem Chat
  stashDraft();
  purgeOnce(addr);
}

// Regeln, die beim Senden für meine Nachricht in diesem Chat gelten.
function outgoingRules(peer) {
  const c = chatOf(peer);
  const r = c ? sanitizeRules(c.rules) : emptyRules();
  const out = {};
  if (r.ttl > 0) {
    out.ttl = Math.max(1, Math.round(r.ttl * 60));
    out.exp = Math.floor(Date.now() / 1000) + out.ttl;
  }
  if (r.once) out.once = 1;
  return out;
}
function ruleFields(rule) {
  const f = {};
  if (rule.exp) f.e = rule.exp;
  if (rule.once) f.q = 1;
  return f;
}

// Lösch-Auftrag vom Gegenüber: jeder darf in einem Chat jede Nachricht (eigene
// und fremde) bei beiden entfernen. Gilt nur für den Chat mit genau diesem Absender.
function applyDeleteControl(sender, body) {
  const c = chatOf(sender);
  if (!c) return false;
  const clean = (x) => (Array.isArray(x) ? x : []).filter(v => typeof v === "string" && v && v.length <= 60).slice(0, 500);
  const theirs = clean(body.mine).map(x => "r-" + x);          // Nachrichten des Absenders (bei mir mit Präfix)
  const mineRaw = new Set(clean(body.yours));                   // meine Nachrichten (bei mir ohne Präfix)
  const ids = theirs.concat(c.msgs.filter(m => m.me && mineRaw.has(m.id)).map(m => m.id));
  // Kennungen, die noch gar nicht angekommen sind, merken wir nur bei Kontakten
  // (sonst könnte ein Fremder den Verlauf mit erfundenen Kennungen aufblähen).
  if (isContact(sender)) c.gone = sanitizeGone([...c.gone, ...theirs]);
  removeMessages(sender, ids, true);
  STATE.historyDirty = true;
  return true;
}

// Entfernt Nachrichten bei mir und gibt dem Gegenüber den Auftrag, sie ebenfalls
// zu entfernen. Der Auftrag nennt immer die einzelnen Kennungen (nie "alles"):
// so trifft er nur, was beim Abschicken da war, auch wenn er verspätet ankommt.
async function deleteForBoth(peer, msgs, all=false) {
  const c = chatOf(peer, true);
  const list = all ? [...c.msgs] : msgs;
  const mine = list.filter(m => m.me).map(m => m.id);
  const yours = list.filter(m => !m.me && m.id.startsWith("r-")).map(m => m.id.slice(2));
  const entries = [];
  for (let i = 0; i < Math.max(mine.length, yours.length, 1); i += 500) {
    const part = { mine: mine.slice(i, i + 500), yours: yours.slice(i, i + 500) };
    if (part.mine.length || part.yours.length) entries.push({ id: LehnoCrypto.b64(LehnoCrypto.randomBytes(9)), p: peer, b: part });
  }
  removeMessages(peer, list.map(m => m.id), true);
  if (all) c.read = Math.max(c.read || 0, STATE.lastOrder);
  STATE.history.ctl = sanitizeCtl([...(STATE.history.ctl || []), ...entries]);
  STATE.historyDirty = true;
  renderSidebar();
  renderChat();
  const saved = await saveHistory();
  flushControls();
  return saved;
}

let _ctlRunning = false;
async function flushControls() {
  if (_ctlRunning || !STATE.me) return;
  _ctlRunning = true;
  const sid = STATE.sid, me = STATE.me;
  try {
    for (const entry of [...(STATE.history.ctl || [])]) {
      if (sid !== STATE.sid) return;
      try {
        await sendBody(me, sid, entry.p, { msg_type: "delete", ...entry.b });
      } catch (e) {
        if (e && (e.status === 404 || e.status === 400 || e.status === 422)) { /* Gegenüber gibt es nicht mehr: Auftrag verwerfen */ }
        else break;      // später erneut versuchen
      }
      if (sid !== STATE.sid) return;
      STATE.history.ctl = (STATE.history.ctl || []).filter(x => x.id !== entry.id);
      scheduleHistorySave();
    }
  } finally {
    _ctlRunning = false;
  }
}

function unreadCount(addr) {
  const c = chatOf(addr);
  if (!c) return 0;
  let n = 0;
  for (const m of c.msgs) if (!m.me && m.o > (c.read || 0)) n++;
  return n;
}

function lastMsg(addr) {
  const c = chatOf(addr);
  return c && c.msgs.length ? c.msgs[c.msgs.length - 1] : null;
}

// Adressen, die uns geschrieben haben, aber (noch) kein Kontakt sind.
function requestAddresses() {
  const out = [];
  for (const [addr, c] of Object.entries(STATE.history.chats)) {
    if (isContact(addr) || STATE.declined.includes(addr)) continue;
    if (c.msgs.some(m => !m.me)) out.push(addr);
  }
  return out;
}

async function fetchRemoteHistory() {
  const resp = await API.get("/api/history");
  const version = resp.version || 0;
  if (!resp.ciphertext_b64) return { version, data: emptyHistory(), count: 0 };
  const plain = await LehnoCrypto.decryptHistory(STATE.me.kek, resp);
  return { version, data: sanitizeHistory(plain), count: Number.isFinite(plain?._n) ? plain._n : 0 };
}

async function loadHistory() {
  const sid = STATE.sid;
  const remote = await fetchRemoteHistory();   // wirft bei Fehler -> historyLoaded bleibt false
  if (sid !== STATE.sid) return;
  if (isRollback("h", remote.count)) {
    toast("Achtung: Der Server liefert einen älteren Stand deines Verlaufs als dieses Gerät zuletzt gesehen hat.", "err");
  }
  adoptRemoteHistory(remote);
  STATE.historyLoaded = true;
  noteSeen("h", remote.count);
}

// Passt der Verlauf nicht mehr in die größte Ablage (4 MB), wird gekürzt:
// zuerst bei Adressen, die kein Kontakt sind, erst danach fallen die ältesten
// Nachrichten der echten Chats weg. Die Kennungen bleiben gemerkt, damit
// Gelöschtes nicht erneut eingespielt werden kann.
function trimHistoryToFit() {
  const fits = () => LehnoCrypto.historyFits({ ...STATE.history, _n: STATE.historyCount + 1 });
  if (fits()) return;
  // 1) Leere Hüllen fremder Adressen entfernen.
  for (const [addr, c] of Object.entries(STATE.history.chats)) {
    if (!c.msgs.length && !c.gone.length && !STATE.contacts.find(x => x.address === addr)) delete STATE.history.chats[addr];
  }
  let guard = 0;
  while (!fits() && guard++ < 400) {
    const strangers = [], known = [];
    for (const [addr, c] of Object.entries(STATE.history.chats)) {
      const list = isContact(addr) ? known : strangers;
      for (const m of c.msgs) list.push([m.o, addr, m.id]);
    }
    if (!strangers.length) {
      // Bevor echte Chats gekürzt werden: leere Reste fremder Adressen (nur
      // gemerkte Kennungen, keine Nachrichten) vollständig entfernen.
      let dropped = false;
      for (const [addr, c] of Object.entries(STATE.history.chats)) {
        if (!c.msgs.length && !isContact(addr)) { delete STATE.history.chats[addr]; dropped = true; }
      }
      if (dropped) continue;
    }
    const pool = strangers.length ? strangers : known;
    if (!pool.length) {
      // Keine Nachrichten mehr: dann sind es die gemerkten Kennungen.
      let cut = false;
      for (const c of Object.values(STATE.history.chats)) {
        if (c.gone.length) { c.gone = c.gone.slice(-Math.floor(c.gone.length / 2)); cut = true; }
      }
      if (!cut) break;
      continue;
    }
    pool.sort((x, y) => x[0] - y[0]);
    const drop = pool.slice(0, Math.max(20, Math.floor(pool.length / 20)));
    for (const [, addr, id] of drop) {
      const c = STATE.history.chats[addr];
      c.msgs = c.msgs.filter(m => m.id !== id);
      c.gone = sanitizeGone([...c.gone, id]);
    }
  }
}

// Alle Speichervorgänge laufen nacheinander (nie zwei gleichzeitig).
let _histChain = Promise.resolve(true);
function saveHistory() {
  _histChain = _histChain.then(doSaveHistory, doSaveHistory);
  return _histChain;
}

async function doSaveHistory() {
  const sid = STATE.sid;
  if (!STATE.me?.kek) return false;
  if (!STATE.historyLoaded) {
    // Verlauf konnte beim Anmelden nicht geladen werden: erst nachladen, damit
    // wir nichts überschreiben.
    try { await loadHistory(); } catch (e) { if (sid === STATE.sid) STATE.historyDirty = true; return false; }
    if (sid !== STATE.sid || !STATE.historyLoaded) return false;
  }
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      trimHistoryToFit();
      const n = STATE.historyCount + 1;
      const enc = await LehnoCrypto.encryptHistory(STATE.me.kek, { ...STATE.history, _n: n });
      const resp = await API.put("/api/history", { ...enc, expected_version: STATE.historyVersion });
      if (sid !== STATE.sid) return false;
      STATE.historyVersion = resp.version;
      STATE.historyCount = n;
      STATE.historyDirty = false;
      noteSeen("h", n);
      return true;
    } catch (e) {
      if (sid !== STATE.sid) return false;
      if (e.status === 409) {
        try {
          const remote = await fetchRemoteHistory();
          if (sid !== STATE.sid) return false;
          adoptRemoteHistory(remote);
          renderSidebar();
          renderChat();
          continue;
        } catch (e2) { break; }
      }
      break;
    }
  }
  if (sid === STATE.sid) STATE.historyDirty = true;
  return false;
}

let _histTimer = null;
function scheduleHistorySave() {
  STATE.historyDirty = true;
  if (_histTimer) clearTimeout(_histTimer);
  _histTimer = setTimeout(() => { _histTimer = null; saveHistory(); }, 600);
}

// Frühere Versionen haben gesendete Nachrichten unverschlüsselt im Browser
// abgelegt. Diese werden einmalig in den verschlüsselten Verlauf übernommen.
// Gelöscht werden sie auf dem Gerät erst, wenn das Sichern geklappt hat.
function migrateLegacyLocal() {
  const keys = [];
  const found = [];
  try {
    const prefix = "lehno-mesh:" + STATE.me.address + ":out:";
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(prefix)) keys.push(k);
    }
    for (const k of keys) {
      const peer = k.slice(prefix.length);
      let list = [];
      try { list = JSON.parse(localStorage.getItem(k) || "[]"); } catch (e) {}
      if (!ADDR_RE.test(peer) || !Array.isArray(list)) continue;
      for (const old of list) {
        const ts = Date.parse(old && old.ts) || 0;
        if (!old || !ts) continue;
        const msg = { id: "alt-" + String(old.id || ts), me: 1, k: "text", x: "", o: 0 };
        if (old.msg_type === "image" || old.msg_type === "video") {
          let meta = {};
          try { meta = JSON.parse(old.plain || "{}"); } catch (e) {}
          msg.k = old.msg_type;
          msg.a = { t: old.attachment_token || "", k: meta.file_key_b64 || "", i: meta.file_iv_b64 || "", m: meta.mime || "", c: meta.caption || "" };
        } else {
          msg.x = String(old.plain || "");
        }
        found.push([ts, peer, msg]);
      }
    }
  } catch (e) { console.warn("legacy migration", e); }
  // Die alte Zeitangabe dient nur noch zum Sortieren und wird nicht übernommen.
  // Alt-Nachrichten kommen in ihrer alten Reihenfolge VOR alles Vorhandene
  // (Nummern unter null).
  found.sort((x, y) => x[0] - y[0]);
  let imported = 0;
  let minOrder = 0;
  for (const c of Object.values(STATE.history.chats)) for (const m of c.msgs) minOrder = Math.min(minOrder, m.o);
  let n = minOrder - found.length - 1;
  for (const [, peer, msg] of found) {
    msg.o = ++n;
    const clean = sanitizeMsg(msg);
    if (clean && addMessage(peer, clean)) imported++;
  }
  return { imported, keys };
}

// =========================================================================
// REGISTER / LOGIN
// =========================================================================
async function doRegister(password) {
  const setup = await LehnoCrypto.setupAccount(password);
  const resp = await API.post("/api/register", {
    auth_key_b64: setup.auth_key_b64,
    salt_b64: setup.salt_b64,
    identity_pub_b64: setup.identity_pub_b64,
    signing_pub_b64: setup.signing_pub_b64,
    keys_blob_b64: setup.keys_blob_b64,
    keys_nonce_b64: setup.keys_nonce_b64,
    kek_blob_b64: setup.kek_blob_b64,
    kek_nonce_b64: setup.kek_nonce_b64,
    kdf: setup.kdf,
  });
  if (resp.address !== setup.address) throw new Error("Server meldet eine falsche Adresse");
  await loginWithPassword(setup.address, password);
  const mnemonic = await LehnoBip39.bytesToMnemonic(setup.kek_for_backup);
  showMnemonic(mnemonic, setup.address);
}

async function loginWithPassword(address, password) {
  const init = await API.post("/api/login/init", { address });
  const kdf = init.kdf === 2 ? 2 : 1;
  const salt = LehnoCrypto.unb64(String(init.salt_b64 || ""));
  if (salt.byteLength !== 16) throw new Error("Der Server liefert ungültige Anmeldedaten.");
  const { auth_key } = await LehnoCrypto.deriveFromPassword(password, salt, kdf);
  // Ist die Anmeldung für diese Adresse gerade gebremst (viele Fehlversuche),
  // versuchen wir es ein paar Mal von selbst erneut.
  let resp = null;
  for (let attempt = 0; ; attempt++) {
    try {
      resp = await API.post("/api/login", { address, auth_key_b64: LehnoCrypto.b64(auth_key) });
      break;
    } catch (e) {
      if (e.status !== 429 || attempt >= 6) throw e;
      await new Promise(r => setTimeout(r, 1500 + Math.floor(Math.random() * 3000)));
    }
  }
  // unlockAccount berechnet unsere öffentlichen Schlüssel selbst und prüft,
  // dass sie zur Adresse gehören. Verfahren und Salz nehmen wir aus dem ersten
  // Schritt, nicht aus der Antwort.
  const live = await LehnoCrypto.unlockAccount(password, { ...resp, address, kdf, salt_b64: init.salt_b64 });
  STATE.sid++;
  STATE.history = emptyHistory();
  STATE.historyLoaded = false;
  STATE.me = {
    address: live.address,
    jwt: live.jwt,
    identityPriv: live.identityPriv,
    signingPriv: live.signingPriv,
    kek: live.kek,
    identity_pub_b64: live.identity_pub_b64,
    signing_pub_b64: live.signing_pub_b64,
  };
}

async function doLogin(address, password) {
  await loginWithPassword(address, password);
  await afterLogin();
}

async function doRecover(address, mnemonic, newPassword) {
  const init = await API.post("/api/recover/init", { address });
  const finalizePayload = await LehnoCrypto.recoverWithMnemonic(address, mnemonic, newPassword, init);
  await API.post("/api/recover/finalize", finalizePayload);
  await doLogin(address, newPassword);
}

function showMnemonic(mnemonic, address) {
  show("mnemonic");
  $("#my-address-display").textContent = address;
  setLastBackupData(address, mnemonic);
  const grid = $("#mnemonic-grid");
  grid.textContent = "";
  mnemonic.split(" ").forEach((w, i) => {
    const el = document.createElement("div");
    el.className = "w";
    const num = document.createElement("span"); num.className = "w-num"; num.textContent = (i + 1) + ".";
    const txt = document.createElement("span"); txt.className = "w-text"; txt.textContent = w;
    el.appendChild(num); el.appendChild(txt);
    grid.appendChild(el);
  });
  $("#mnemonic-confirm").checked = false;
  $("#mnemonic-continue").disabled = true;
}

function clearSensitiveInputs() {
  $$("input[type=password], textarea[name=mnemonic]").forEach(el => { el.value = ""; });
  $("#mnemonic-grid").textContent = "";
  setLastBackupData(null, null);
}

function logout(message) {
  STATE.sid++;
  for (const t of STATE.timers) clearInterval(t);
  STATE.timers = [];
  if (_saveTimer) { clearTimeout(_saveTimer); _saveTimer = null; }
  if (_histTimer) { clearTimeout(_histTimer); _histTimer = null; }
  if (_tickTimer) { clearTimeout(_tickTimer); _tickTimer = null; }
  const ws = STATE.ws;
  STATE.ws = null;
  if (ws) { try { ws.onclose = null; ws.close(); } catch (e) {} }
  for (const p of MEDIA_URLS.values()) { Promise.resolve(p).then(u => { try { URL.revokeObjectURL(u); } catch (e) {} }).catch(() => {}); }
  MEDIA_URLS.clear();
  STATE.me = null;
  STATE.pubKeyCache = {};
  STATE.contacts = [];
  STATE.nicknames = {};
  STATE.declined = [];
  STATE.history = emptyHistory();
  STATE.historyVersion = 0;
  STATE.historyCount = 0;
  STATE.historyLoaded = false;
  STATE.historyDirty = false;
  STATE.userdataVersion = 0;
  STATE.userdataCount = 0;
  STATE.userdataDirty = false;
  STATE.activeChat = null;
  STATE.mediaAllowed = new Set();
  STATE.drafts = {};
  for (const q of STATE.outQueue) { try { q.reject(new SessionChanged()); } catch (e) {} }
  STATE.outQueue = [];
  STATE.cover = true;
  stopRecording(true);
  STATE.lastOrder = 0;
  _userdataLoaded = false;
  _histChain = Promise.resolve(true);
  _udChain = Promise.resolve(true);
  _lastFailed = null;
  _sendChain = Promise.resolve();
  for (const id of ["#chat-stream", "#chat-header", "#contact-list", "#request-list",
                    "#me-address-full", "#popup-my-address", "#my-address-display"]) {
    $(id).textContent = "";
  }
  $("#msg-input").value = "";
  $("#new-chat-address").value = "";
  $("#addr-popup").style.display = "none";
  $("#view-chat").classList.remove("peek-chat");
  clearSensitiveInputs();
  const remembered = getRememberedAddress();
  $$("#form-login input[name=address], #form-recover input[name=address]").forEach(el => { el.value = remembered; });
  document.title = APP_NAME;
  // Nach dem Abmelden immer das Anmelde-Formular zeigen (nicht das Registrieren).
  $$("#view-auth .tab").forEach(x => x.classList.toggle("active", x.dataset.tab === "login"));
  $$("#view-auth .auth-form").forEach(f => f.classList.toggle("active", f.id === "form-login"));
  closeSheet();
  show("auth");
  $("#auth-msg").textContent = typeof message === "string" ? message : "";
}

async function afterLogin() {
  const sid = STATE.sid;
  $("#me-address-full").textContent = STATE.me.address;
  clearSensitiveInputs();
  let loadProblem = false;
  try { await loadUserdata(); } catch (e) { console.warn("loadUserdata failed", e); loadProblem = true; }
  if (sid !== STATE.sid) return;
  try { await loadHistory(); } catch (e) { console.warn("loadHistory failed", e); loadProblem = true; }
  if (sid !== STATE.sid) return;
  if (STATE.historyLoaded) {
    const legacy = migrateLegacyLocal();
    if (legacy.keys.length) {
      const saved = legacy.imported > 0 ? await saveHistory() : true;
      if (sid !== STATE.sid) return;
      if (saved) { for (const k of legacy.keys) { try { localStorage.removeItem(k); } catch (e) {} } }
    }
  }
  if (STATE.historyLoaded) {
    // Beim Anmelden ist kein Chat offen: alles, was als Einmal-Ansicht schon
    // gesehen oder selbst gesendet wurde, und alles Abgelaufene ist weg.
    for (const addr of Object.keys(STATE.history.chats)) purgeOnce(addr);
    purgeExpired();
  }
  show("chat");
  renderSidebar();
  renderChat();
  if (loadProblem) toast("Verlauf oder Kontakte konnten nicht geladen werden. Es wird weiter versucht.", "err");
  if (!STATE.cover) startWebSocket();
  startTimers();
  startTick();
  await pollInbox();
  flushControls();
}

// =========================================================================
// INBOX
// =========================================================================
let _pollRunning = false;
let _pollAgain = false;

async function pollInbox() {
  if (!STATE.me) return;
  if (_pollRunning) { _pollAgain = true; return; }
  _pollRunning = true;
  try {
    do {
      _pollAgain = false;
      await pollInboxOnce();
    } while (_pollAgain && STATE.me);
  } catch (e) {
    console.warn("inbox poll", e && e.message);
  } finally {
    _pollRunning = false;
  }
}

async function packetFallbackId(p) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", LehnoCrypto.utf8(p.ephemeral_pub_b64 + "|" + p.nonce_b64)));
  return "p-" + LehnoCrypto.b64(h.slice(0, 12));
}

async function pollInboxOnce() {
  const sid = STATE.sid;
  for (let round = 0; round < 40 && STATE.me && sid === STATE.sid; round++) {
    const r = await API.get("/api/packets/inbox?limit=50");
    if (sid !== STATE.sid) return;

    // Hat ein anderes Gerät den Verlauf geändert? Dann zuerst nachladen.
    if (STATE.historyLoaded && r.history_version !== STATE.historyVersion && !STATE.historyDirty) {
      try {
        const remote = await fetchRemoteHistory();
        if (sid !== STATE.sid) return;
        if (remote.version !== STATE.historyVersion) {
          adoptRemoteHistory(remote);
          renderSidebar();
          renderChat();
        }
      } catch (e) { console.warn("history refresh", e && e.message); }
    }

    const ackIds = [];
    let changed = false;
    const incomingFor = new Set();

    for (const p of r.packets) {
      let body, unverified = false;
      try {
        body = await LehnoCrypto.decryptMessage(STATE.me, p);
      } catch (e) {
        body = null;
        // Alt-Paket von vor dem Update? Lesbar machen, aber kennzeichnen.
        if (p.signature_b64) {
          try { body = await LehnoCrypto.decryptLegacyMessage(STATE.me, p); unverified = true; } catch (e2) { body = null; }
        }
        if (!body) {
          // Nicht entschlüsselbar oder Absender-Nachweis ungültig: verwerfen.
          console.warn("packet rejected", e && e.message);
          ackIds.push(p.id);
          continue;
        }
      }
      if (sid !== STATE.sid) return;
      const sender = body.sender_address;
      if (!ADDR_RE.test(sender) || STATE.declined.includes(sender)) { ackIds.push(p.id); continue; }

      // Kennung des Absenders. Eingehende Kennungen bekommen ein eigenes Präfix:
      // so kann das Gegenüber mit einer geschickt gewählten Kennung keine meiner
      // eigenen Nachrichten verdrängen.
      const rawId = (typeof body.msg_id === "string" && body.msg_id.length >= 8 && body.msg_id.length <= 40)
        ? body.msg_id : await packetFallbackId(p);
      const id = "r-" + rawId;
      const chat = chatOf(sender) || emptyChat();
      // Schon vorhanden (doppelte Zustellung) oder von mir gelöscht: nicht erneut anzeigen.
      if (chat.msgs.some(m => m.id === id) || chat.gone.includes(id)) { ackIds.push(p.id); continue; }
      // Nachricht an mich selbst: die gesendete Fassung steht schon im Verlauf.
      if (sender === STATE.me.address && chat.msgs.some(m => m.me && m.id === rawId)) { ackIds.push(p.id); continue; }

      // Lösch-Auftrag des Gegenübers (jeder darf jede Nachricht im gemeinsamen
      // Chat bei beiden entfernen). Erscheint nie als Nachricht.
      if (body.msg_type === "delete") {
        const c2 = chatOf(sender);
        if (c2 && !unverified) {
          applyDeleteControl(sender, body);
          c2.gone = sanitizeGone([...c2.gone, id]);
          changed = true;
          incomingFor.add(sender);
        }
        ackIds.push(p.id);
        continue;
      }

      const known = isContact(sender);
      if (!known) {
        // Fremde Adresse: nur begrenzt aufnehmen (siehe REQ_MAX_*).
        const incoming = chat.msgs.filter(m => !m.me).length;
        if (incoming >= REQ_MAX_MSGS || (incoming === 0 && requestAddresses().length >= REQ_MAX_CHATS)) {
          ackIds.push(p.id);
          continue;
        }
      }

      const kind = KINDS.includes(body.msg_type) ? body.msg_type : "text";
      // Löschfrist des Absenders: zählt ab dem Absenden, egal ob gelesen. Ist
      // sie schon vorbei, erscheint die Nachricht gar nicht erst.
      const nowSec = Math.floor(Date.now() / 1000);
      let expiry = 0;
      const ttl = Number(body.ttl), exp = Number(body.exp);
      if (Number.isFinite(ttl) && ttl > 0) {
        expiry = nowSec + Math.min(ttl, TTL_MAX_MIN * 60);
        if (Number.isFinite(exp) && exp > 0) expiry = Math.min(expiry, Math.floor(exp));
        if (expiry <= nowSec) {
          // Schon abgelaufen: gar nicht erst aufnehmen und nichts dazu merken.
          if (body.attachment_token && TOKEN_RE.test(String(body.attachment_token))) API.deleteAttachment(body.attachment_token).catch(() => {});
          ackIds.push(p.id);
          continue;
        }
      }
      let text = kind === "text" ? String(body.text || "") : "";
      let caption = typeof body.caption === "string" ? body.caption : "";
      if (!known) {
        if (text.length > REQ_MAX_TEXT) text = text.slice(0, REQ_MAX_TEXT) + " … [gekürzt, weil diese Adresse noch kein Kontakt ist]";
        caption = caption.slice(0, 200);
      }
      const msg = sanitizeMsg({
        id, me: 0, k: kind, u: unverified ? 1 : 0,
        x: text,
        a: kind === "text" ? undefined : {
          t: body.attachment_token, k: body.file_key_b64, i: body.file_iv_b64, m: body.mime, c: caption,
          n: body.file_name, s: Number(body.file_size),
        },
        q: body.once ? 1 : 0,
        e: expiry,
        o: nextOrder(),
      });
      if (msg && addMessage(sender, msg)) { changed = true; incomingFor.add(sender); }
      ackIds.push(p.id);
    }

    if (changed) {
      if (STATE.activeChat && incomingFor.has(STATE.activeChat) && !document.hidden) markRead(STATE.activeChat, false);
      renderSidebar();
      if (STATE.activeChat && incomingFor.has(STATE.activeChat)) renderChat();
    }
    // Erst sichern, dann beim Server löschen. Das gilt auch, wenn ein früherer
    // Sicherungsversuch gescheitert ist: solange etwas ungesichert im
    // Arbeitsspeicher liegt, wird nichts bestätigt. Klappt das Sichern nicht,
    // bleiben die Pakete liegen und werden beim nächsten Abruf erneut geholt.
    if (ackIds.length) {
      if (changed || STATE.historyDirty || !STATE.historyLoaded) {
        const saved = await saveHistory();
        if (sid !== STATE.sid) return;
        if (!saved) { toast("Verlauf konnte nicht gesichert werden. Neuer Versuch folgt.", "err"); return; }
      }
      try { await API.post("/api/packets/ack", { packet_ids: ackIds }); } catch (e) { return; }
    }
    if (!r.more) break;
  }
}

// =========================================================================
// ANFRAGE AKZEPTIEREN / ABLEHNEN, VERLAUF LÖSCHEN
// =========================================================================
function acceptRequest(addr) {
  ensureContact(addr);
  renderSidebar();
  if (STATE.activeChat === addr) renderChat();
  toast("Kontakt akzeptiert", "ok");
}

async function clearChat(addr) {
  const c = chatOf(addr, true);
  c.gone = sanitizeGone([...c.gone, ...c.msgs.map(m => m.id)]);
  c.msgs = [];
  c.read = Math.max(c.read || 0, STATE.lastOrder);
  return await saveHistory();
}

async function declineRequest(addr) {
  if (!STATE.declined.includes(addr)) STATE.declined.push(addr);
  STATE.contacts = STATE.contacts.filter(c => c.address !== addr);
  scheduleUserdataSave();
  if (STATE.activeChat === addr) {
    $("#msg-input").value = "";
    STATE.activeChat = null;
    $("#view-chat").classList.remove("peek-chat");
  }
  delete STATE.drafts[addr];
  await clearChat(addr);
  renderSidebar();
  renderChat();
  toast("Anfrage abgelehnt");
}

function markRead(addr, save=true) {
  const c = chatOf(addr);
  const last = lastMsg(addr);
  if (!c || !last || (c.read || 0) >= last.o) return;
  c.read = last.o;
  if (save) scheduleHistorySave();
}

// =========================================================================
// SPITZNAMEN
// =========================================================================
function setNickname(addr, nick) {
  const trimmed = (nick || "").trim().slice(0, 60);
  if (trimmed) STATE.nicknames[addr] = trimmed;
  else delete STATE.nicknames[addr];
  scheduleUserdataSave();
  renderSidebar();
  if (STATE.activeChat === addr) renderChat();
}

function promptNickname(addr) {
  const current = STATE.nicknames[addr] || "";
  const next = prompt("Spitzname für diesen Kontakt\n\n(verschlüsselt, nur du siehst ihn)", current);
  if (next === null) return;
  setNickname(addr, next);
  toast(next.trim() ? "Spitzname gespeichert" : "Spitzname entfernt", "ok");
}

// =========================================================================
// SEITENLEISTE
// =========================================================================
let currentList = "chats";

function previewText(m) {
  if (!m) return "";
  const who = m.me ? "Du: " : "";
  if (m.q) return who + "Einmal-Nachricht";
  if (m.k === "image") return who + "Bild" + (m.a && m.a.c ? ": " + m.a.c : "");
  if (m.k === "video") return who + "Video" + (m.a && m.a.c ? ": " + m.a.c : "");
  if (m.k === "voice") return who + "Sprachnachricht";
  if (m.k === "file") return who + "Datei: " + ((m.a && m.a.n) || "");
  return who + m.x.replace(/\s+/g, " ").slice(0, 80);
}

function renderSidebar() {
  if (!STATE.me) return;
  const reqs = requestAddresses();
  $("#req-count").textContent = reqs.length > 0 ? String(reqs.length) : "";

  let totalUnread = 0;
  for (const addr of chatAddresses()) totalUnread += unreadCount(addr);
  document.title = (totalUnread + reqs.length > 0 ? "(" + (totalUnread + reqs.length) + ") " : "") + APP_NAME;

  if (currentList === "chats") {
    $("#contact-list").style.display = "";
    $("#request-list").style.display = "none";
    renderContacts();
  } else {
    $("#contact-list").style.display = "none";
    $("#request-list").style.display = "";
    renderRequests(reqs);
  }
}

function contactRow(addr, { isRequest }) {
  const div = document.createElement("div");
  div.className = "contact" + (addr === STATE.activeChat ? " active" : "");
  const last = lastMsg(addr);
  const unread = unreadCount(addr);
  const nick = STATE.nicknames[addr];
  const hasNick = !!(nick && nick.trim());
  const nameClass = hasNick ? "name is-nick" : "name is-address";
  const nameContent = hasNick
    ? `${escapeHtml(nick)}<div class="sub-addr">${escapeHtml(addr)}</div>`
    : escapeHtml(addr);
  const preview = isRequest ? "Anfrage: " + previewText(last) : previewText(last);
  div.innerHTML = `
    <div class="avatar${isRequest ? " req" : ""}" data-av="1">${escapeHtml(avatarLabel(addr))}</div>
    <div class="meta">
      <div class="${nameClass}" title="${escapeHtml(addr)}">${nameContent}</div>
      <div class="last-row">
        <div class="last${isRequest ? " warn" : ""}">${escapeHtml(preview || "Noch keine Nachrichten")}</div>
        ${unread > 0 ? `<span class="unread">${unread > 99 ? "99+" : unread}</span>` : ""}
      </div>
    </div>`;
  if (!isRequest) div.querySelector("[data-av]").style.background = avatarColor(addr);
  div.addEventListener("click", () => openChat(addr));
  return div;
}

function renderContacts() {
  const list = $("#contact-list");
  list.textContent = "";
  const addrs = chatAddresses();
  if (!addrs.length) {
    list.innerHTML = '<div class="contact-empty">Noch keine Chats.<br>Füge oben eine Adresse hinzu.</div>';
    return;
  }
  addrs.sort((a, b) => {
    const la = lastMsg(a), lb = lastMsg(b);
    return (lb ? lb.o : 0) - (la ? la.o : 0);
  });
  for (const addr of addrs) list.appendChild(contactRow(addr, { isRequest: false }));
}

function renderRequests(reqs) {
  const list = $("#request-list");
  list.textContent = "";
  if (!reqs.length) {
    list.innerHTML = '<div class="contact-empty">Keine offenen Anfragen.</div>';
    return;
  }
  for (const addr of reqs) list.appendChild(contactRow(addr, { isRequest: true }));
}

// =========================================================================
// CHAT-ANSICHT
// =========================================================================
// Angefangener Text gehört zu dem Chat, in dem er getippt wurde. Beim Wechsel
// wird er dort abgelegt und nie in einen anderen Chat mitgenommen.
function stashDraft() {
  const input = $("#msg-input");
  if (STATE.activeChat) {
    if (input.value) STATE.drafts[STATE.activeChat] = input.value;
    else delete STATE.drafts[STATE.activeChat];
  }
  input.value = "";
}

async function openChat(address) {
  if (STATE.activeChat !== address) {
    leaveChat();
    $("#msg-input").value = STATE.drafts[address] || "";
    delete STATE.drafts[address];
  }
  STATE.activeChat = address;
  STATE.showCount = SHOW_STEP;
  $("#view-chat").classList.add("peek-chat");
  markRead(address);
  renderSidebar();
  renderChat(true);
  fetchPubKey(address).catch(() => {});
}

// Holt den öffentlichen Schlüssel einer Adresse und PRÜFT, dass er wirklich zu
// dieser Adresse gehört (Adresse = Hash des Schlüssels). Der Server kann uns so
// keinen fremden Schlüssel unterschieben.
async function fetchPubKey(address) {
  if (address === STATE.me.address) return STATE.me.identity_pub_b64;
  if (STATE.pubKeyCache[address]) return STATE.pubKeyCache[address];
  const r = await API.keys(address);
  const derived = await LehnoCrypto.addressFromIdentityPubB64(String(r.identity_pub_b64 || ""));
  if (derived !== address) throw new Error("Der Schlüssel vom Server passt nicht zur Adresse. Es wird NICHT gesendet.");
  STATE.pubKeyCache[address] = r.identity_pub_b64;
  return r.identity_pub_b64;
}

// =========================================================================
// SYMBOLE (eingebettete SVG, keine fremden Dateien)
// =========================================================================
const ICON = {
  back: '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>',
  more: '<svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>',
  lock: '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
  key: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M14 9l2 2"/></svg>',
  timer: '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 2M9 2h6"/></svg>',
  eye: '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  file: '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>',
};

function svgEl(markup) {
  const span = document.createElement("span");
  span.className = "ico";
  span.innerHTML = markup;      // nur feste Symbole aus ICON, nie fremde Daten
  return span;
}

// =========================================================================
// AUSKLAPP-MENÜ (Blatt von unten bzw. Fenster in der Mitte)
// =========================================================================
function closeSheet() {
  const bg = $("#sheet-bg");
  bg.style.display = "none";
  $("#sheet").textContent = "";
}

// items: [{ label, sub?, danger?, onClick }] oder { node }
function openSheet(title, items) {
  const sheet = $("#sheet");
  sheet.textContent = "";
  if (title) {
    const h = document.createElement("div");
    h.className = "sheet-title";
    h.textContent = title;
    sheet.appendChild(h);
  }
  for (const it of items) {
    if (it.node) { sheet.appendChild(it.node); continue; }
    const b = document.createElement("button");
    b.type = "button";
    b.className = "sheet-item" + (it.danger ? " danger" : "");
    const l = document.createElement("span");
    l.className = "sheet-label";
    l.textContent = it.label;
    b.appendChild(l);
    if (it.sub) {
      const sub = document.createElement("span");
      sub.className = "sheet-sub";
      sub.textContent = it.sub;
      b.appendChild(sub);
    }
    b.addEventListener("click", () => { closeSheet(); it.onClick(); });
    sheet.appendChild(b);
  }
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "sheet-item cancel";
  cancel.textContent = "Schließen";
  cancel.addEventListener("click", closeSheet);
  sheet.appendChild(cancel);
  $("#sheet-bg").style.display = "flex";
}

// =========================================================================
// REGELN JE CHAT
// =========================================================================
const TTL_CHOICES = [
  [0, "Aus"], [1, "1 Minute"], [5, "5 Minuten"], [30, "30 Minuten"],
  [60, "1 Stunde"], [1440, "1 Tag"], [10080, "7 Tage"],
];

function ttlLabel(min) {
  if (!min) return "aus";
  const hit = TTL_CHOICES.find(c => c[0] === min);
  if (hit) return hit[1];
  if (min < 60) return min + " Minuten";
  if (min % 1440 === 0) return (min / 1440) + " Tage";
  if (min % 60 === 0) return (min / 60) + " Stunden";
  return min + " Minuten";
}

function setRules(peer, change) {
  const c = chatOf(peer, true);
  const r = sanitizeRules(c.rules);
  c.rules = sanitizeRules({ ...r, ...change, v: r.v + 1 });
  STATE.historyDirty = true;
  scheduleHistorySave();
  if (STATE.activeChat === peer) renderChat();
}

function openRulesSheet(peer) {
  const c = chatOf(peer);
  const r = c ? sanitizeRules(c.rules) : emptyRules();
  const items = [];
  const info = document.createElement("p");
  info.className = "sheet-info";
  info.textContent = "Diese Regeln gelten für DEINE Nachrichten in diesem Chat, und zwar bei dir und beim Gegenüber. Gelöschtes verschwindet spurlos, ohne Hinweis.";
  items.push({ node: info });
  const h1 = document.createElement("div");
  h1.className = "sheet-section";
  h1.textContent = "Meine Nachrichten bei beiden löschen nach";
  items.push({ node: h1 });
  for (const [min, label] of TTL_CHOICES) {
    items.push({ label: (r.ttl === min ? "● " : "○ ") + label, onClick: () => { setRules(peer, { ttl: min }); toast("Löschfrist: " + ttlLabel(min), "ok"); } });
  }
  items.push({ label: "○ Eigene Minutenzahl …", onClick: () => {
    const v = prompt("Nach wie vielen Minuten sollen deine Nachrichten bei beiden gelöscht werden?", r.ttl ? String(r.ttl) : "10");
    if (v === null) return;
    const n = Math.floor(Number(String(v).replace(",", ".")));
    if (!Number.isFinite(n) || n < 1 || n > TTL_MAX_MIN) { toast("Bitte eine Zahl zwischen 1 und " + TTL_MAX_MIN + " eingeben.", "err"); return; }
    setRules(peer, { ttl: n });
    toast("Löschfrist: " + ttlLabel(n), "ok");
  } });
  const h2 = document.createElement("div");
  h2.className = "sheet-section";
  h2.textContent = "Einmal-Ansicht";
  items.push({ node: h2 });
  items.push({
    label: (r.once ? "● An" : "○ An"),
    sub: "Deine Nachrichten sind nur einmal zu sehen. Sobald der Chat verlassen wird, sind sie weg, bei dir sofort nach dem Wechsel.",
    onClick: () => { setRules(peer, { once: 1 }); toast("Einmal-Ansicht an", "ok"); },
  });
  items.push({ label: (r.once ? "○ Aus" : "● Aus"), onClick: () => { setRules(peer, { once: 0 }); toast("Einmal-Ansicht aus", "ok"); } });
  openSheet("Regeln für diesen Chat", items);
}

function openChatMenu(peer) {
  const nick = STATE.nicknames[peer] || "";
  openSheet(null, [
    { label: "Regeln (Löschfrist, Einmal-Ansicht)", onClick: () => openRulesSheet(peer) },
    { label: nick ? "Spitzname ändern" : "Spitzname vergeben", onClick: () => promptNickname(peer) },
    { label: "Adresse kopieren", onClick: () => { navigator.clipboard.writeText(peer).then(() => toast("Adresse kopiert", "ok")).catch(() => {}); } },
    { label: "Chat bei beiden leeren", danger: true, sub: "Entfernt alle Nachrichten bei dir und beim Gegenüber.", onClick: async () => {
      if (!confirm("Alle Nachrichten dieses Chats bei dir UND beim Gegenüber löschen?\n\nDas lässt sich nicht rückgängig machen.")) return;
      const saved = await deleteForBoth(peer, [], true);
      toast(saved ? "Chat bei beiden geleert" : "Geleert, wird gesichert sobald der Server erreichbar ist", saved ? "ok" : "err");
    } },
    { label: "Verlauf nur bei mir löschen", danger: true, onClick: async () => {
      if (!confirm("Den gesamten Verlauf dieses Chats nur bei dir löschen?\n\nBeim Gegenüber bleibt er bestehen.")) return;
      const saved = await clearChat(peer);
      renderSidebar();
      renderChat();
      toast(saved ? "Verlauf gelöscht" : "Gelöscht, wird gesichert sobald der Server erreichbar ist", saved ? "ok" : "err");
    } },
  ]);
}

function openMessageMenu(peer, m) {
  const items = [];
  if (m.k === "text" && m.x) {
    items.push({ label: "Text kopieren", onClick: () => { navigator.clipboard.writeText(m.x).then(() => toast("Kopiert", "ok")).catch(() => {}); } });
  }
  items.push({ label: "Bei beiden löschen", danger: true, sub: "Verschwindet bei dir und beim Gegenüber, ohne Hinweis.", onClick: async () => {
    const saved = await deleteForBoth(peer, [m], false);
    if (!saved) toast("Gelöscht, wird gesichert sobald der Server erreichbar ist", "err");
  } });
  items.push({ label: "Nur bei mir löschen", onClick: async () => {
    removeMessages(peer, [m.id], false);
    renderSidebar();
    renderChat();
    await saveHistory();
  } });
  if (m.me && m.p) {
    items.push({ label: "Beweis ansehen", sub: "Zeigt öffentlich, was der Server zu dieser Nachricht gespeichert hat. Kennung: " + m.p, onClick: () => {
      window.open("/beweis#" + m.p, "_blank", "noopener");
    } });
  }
  openSheet(null, items);
}

function openMainMenu() {
  const wrap = document.createElement("div");
  wrap.className = "sheet-info";
  const row = document.createElement("label");
  row.className = "switch-row";
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.checked = STATE.cover;
  cb.id = "cover-toggle";
  const txt = document.createElement("span");
  txt.textContent = "Tarnverkehr: gleichmäßiger Strom gleich großer Pakete. Macht es im Netz dazwischen sehr schwer zu erkennen, ob und wann du schreibst. Braucht mehr Datenvolumen (grob 20 bis 30 MB pro Stunde bei geöffneter App), Nachrichten gehen im nächsten Takt raus (wenige Sekunden).";
  row.appendChild(cb);
  row.appendChild(txt);
  wrap.appendChild(row);
  cb.addEventListener("change", () => {
    STATE.cover = cb.checked;
    scheduleUserdataSave();
    if (STATE.cover) {
      const ws = STATE.ws; STATE.ws = null;
      if (ws) { try { ws.onclose = null; ws.close(); } catch (e) {} }
    } else {
      startWebSocket();
    }
    toast(STATE.cover ? "Tarnverkehr an" : "Tarnverkehr aus", "ok");
  });
  openSheet(APP_NAME, [
    { label: "Meine Adresse anzeigen", onClick: () => { $("#popup-my-address").textContent = STATE.me.address; $("#addr-popup").style.display = "flex"; } },
    { node: wrap },
    { label: "Beweis: was der Server speichert", sub: "Öffentliche Seite mit Live-Verzeichnis, Speicherformat und Quelltext.", onClick: () => window.open("/beweis", "_blank", "noopener") },
    { label: "Abmelden", onClick: () => $("#btn-logout").click() },
  ]);
}

// =========================================================================
// CHAT-ANSICHT
// =========================================================================
function renderChat(forceBottom=false) {
  const stream = $("#chat-stream");
  const header = $("#chat-header");
  const banner = $("#request-banner");
  const composer = $("#form-send");
  const rulesBar = $("#rules-bar");
  const peer = STATE.activeChat;
  if (!peer || !STATE.me) {
    stream.textContent = "";
    header.textContent = "";
    banner.style.display = "none";
    composer.style.display = "none";
    rulesBar.hidden = true;
    const hint = document.createElement("div");
    hint.className = "empty";
    hint.textContent = STATE.me ? "Wähle links einen Chat oder füge oben eine Adresse hinzu." : "";
    stream.appendChild(hint);
    return;
  }
  composer.style.display = "";
  const contact = isContact(peer);
  const chat = chatOf(peer);
  const msgs = chat ? chat.msgs : [];
  const isRequest = !contact && msgs.some(m => !m.me);
  const nick = STATE.nicknames[peer] || "";

  header.textContent = "";
  const back = document.createElement("button");
  back.className = "icon-btn back";
  back.id = "btn-back";
  back.setAttribute("aria-label", "Zurück");
  back.appendChild(svgEl(ICON.back));
  const av = document.createElement("div");
  av.className = "avatar";
  av.style.background = avatarColor(peer);
  av.textContent = avatarLabel(peer);
  const idBox = document.createElement("div");
  idBox.className = "head-id";
  if (nick) { const n = document.createElement("div"); n.className = "head-name"; n.textContent = nick; idBox.appendChild(n); }
  const addrEl = document.createElement("div");
  addrEl.className = "head-addr";
  addrEl.title = "Adresse kopieren";
  addrEl.textContent = peer;
  idBox.appendChild(addrEl);
  const sec = document.createElement("div");
  sec.className = "head-sec";
  sec.appendChild(svgEl(ICON.lock));
  sec.appendChild(document.createTextNode(" Ende-zu-Ende verschlüsselt"));
  idBox.appendChild(sec);
  const menu = document.createElement("button");
  menu.className = "icon-btn";
  menu.id = "btn-chat-menu";
  menu.setAttribute("aria-label", "Menü");
  menu.appendChild(svgEl(ICON.more));
  header.appendChild(back);
  header.appendChild(av);
  header.appendChild(idBox);
  header.appendChild(menu);

  back.addEventListener("click", () => {
    $("#view-chat").classList.remove("peek-chat");
    leaveChat();
    STATE.activeChat = null;
    renderSidebar();
    renderChat();
  });
  menu.addEventListener("click", () => openChatMenu(peer));
  addrEl.addEventListener("click", () => {
    navigator.clipboard.writeText(peer).then(() => toast("Adresse kopiert", "ok")).catch(() => {});
  });

  // Hinweiszeile zu aktiven Regeln
  const r = chat ? sanitizeRules(chat.rules) : emptyRules();
  rulesBar.textContent = "";
  if (r.ttl || r.once) {
    if (r.ttl) { const c1 = document.createElement("span"); c1.className = "chip"; c1.appendChild(svgEl(ICON.timer)); c1.appendChild(document.createTextNode(" Meine Nachrichten: bei beiden weg nach " + ttlLabel(r.ttl))); rulesBar.appendChild(c1); }
    if (r.once) { const c2 = document.createElement("span"); c2.className = "chip"; c2.appendChild(svgEl(ICON.eye)); c2.appendChild(document.createTextNode(" Einmal-Ansicht")); rulesBar.appendChild(c2); }
    rulesBar.hidden = false;
    rulesBar.onclick = () => openRulesSheet(peer);
  } else {
    rulesBar.hidden = true;
  }

  banner.style.display = isRequest ? "flex" : "none";

  const nearBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 120;
  const oldTop = stream.scrollTop;
  stream.textContent = "";

  if (!msgs.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "Noch keine Nachrichten.";
    stream.appendChild(empty);
    return;
  }

  const start = Math.max(0, msgs.length - STATE.showCount);
  if (start > 0) {
    const more = document.createElement("button");
    more.className = "ghost small older-btn";
    more.textContent = `Ältere Nachrichten anzeigen (${start})`;
    more.addEventListener("click", () => { STATE.showCount += SHOW_STEP; renderChat(); stream.scrollTop = 0; });
    stream.appendChild(more);
  }

  // Medien von Adressen, die noch kein Kontakt sind, erst nach Klick laden.
  const autoMedia = contact || STATE.mediaAllowed.has(peer);
  // Reine Reihenfolge, bewusst ohne Datum und Uhrzeit.
  let prevMe = null;
  for (let i = start; i < msgs.length; i++) {
    const m = msgs[i];
    const row = messageRow(m, autoMedia || !!m.me, peer);
    if (prevMe !== null && prevMe !== !!m.me) row.classList.add("gap");
    prevMe = !!m.me;
    stream.appendChild(row);
  }
  if (forceBottom || nearBottom) stream.scrollTop = stream.scrollHeight;
  else stream.scrollTop = oldTop;
}

function avatarColor(addr) {
  // Farbe aus der Adresse (rein optisch, damit Chats leichter zu unterscheiden sind).
  let h = 0;
  for (let i = 0; i < addr.length; i++) h = (h * 31 + addr.charCodeAt(i)) % 360;
  return `linear-gradient(135deg, hsl(${h} 70% 52%), hsl(${(h + 40) % 360} 75% 42%))`;
}

function messageRow(m, autoMedia, peer) {
  const row = document.createElement("div");
  row.className = "msg-row" + (m.me ? " me" : "");
  row.dataset.id = m.id;
  const bubble = document.createElement("div");
  bubble.className = "bubble";

  if (m.k === "text") {
    const body = document.createElement("span");
    body.className = "body";
    body.textContent = m.x;
    bubble.appendChild(body);
  } else {
    bubble.appendChild(mediaElement(m, autoMedia, peer));
    if (m.a && m.a.c) {
      const cap = document.createElement("div");
      cap.className = "body";
      cap.textContent = m.a.c;
      bubble.appendChild(cap);
    }
  }
  if (m.u) {
    const note = document.createElement("span");
    note.className = "unverified";
    note.textContent = "Ältere Version: Absender nicht geprüft";
    bubble.appendChild(note);
  }
  const meta = document.createElement("span");
  meta.className = "ts";
  if (m.e) { const t = svgEl(ICON.timer); t.title = "Verschwindet nach Ablauf der Löschfrist"; meta.appendChild(t); }
  if (m.q) { const e = svgEl(ICON.eye); e.title = "Einmal-Ansicht"; meta.appendChild(e); }
  if (m.me) { const tick = document.createElement("span"); tick.className = "tick"; tick.title = "Gesendet"; tick.textContent = "✓"; meta.appendChild(tick); }
  if (meta.childNodes.length) bubble.appendChild(meta);
  // Antippen (bzw. Rechtsklick) öffnet die Aktionen zur Nachricht.
  bubble.addEventListener("click", (e) => {
    if (e.target.closest("button, a, audio, video, .media-action")) return;
    openMessageMenu(peer, m);
  });
  row.appendChild(bubble);
  return row;
}

function fmtSize(n) {
  if (!n) return "";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(0) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

function mediaElement(m, autoMedia, peer) {
  const a = m.a || {};
  const labels = { image: "Bild", video: "Video", voice: "Sprachnachricht", file: "Datei" };
  const label = labels[m.k] || "Datei";
  const allowed = MEDIA_MIMES[m.k] || [];
  const mime = m.k === "file" ? "application/octet-stream" : (allowed.includes(a.m) ? a.m : null);
  if (!mime || !TOKEN_RE.test(a.t || "") || !a.k || !a.i) {
    const note = document.createElement("div");
    note.className = "pending";
    note.textContent = `[${label} kann nicht angezeigt werden]`;
    return note;
  }
  const wrap = document.createElement("div");
  wrap.className = "media";

  // Dateien (z. B. PDF) werden nie im Browser dargestellt, nur auf Klick
  // entschlüsselt und gespeichert.
  if (m.k === "file") {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "file-card media-action";
    btn.appendChild(svgEl(ICON.file));
    const txt = document.createElement("span");
    txt.className = "file-meta";
    const nm = document.createElement("span"); nm.className = "file-name"; nm.textContent = a.n || "datei";
    const sz = document.createElement("span"); sz.className = "file-size"; sz.textContent = (fmtSize(a.s) + " · verschlüsselt").replace(/^ · /, "");
    txt.appendChild(nm); txt.appendChild(sz);
    btn.appendChild(txt);
    btn.addEventListener("click", async () => {
      if (!m.me && !confirm("Diese Datei entschlüsseln und auf deinem Gerät speichern?\n\nÖffne Dateien nur von Leuten, denen du vertraust. Auf dem Gerät liegt sie danach unverschlüsselt.")) return;
      sz.textContent = "wird entschlüsselt …";
      try {
        const url = await loadMediaUrl(a, "application/octet-stream");
        const link = document.createElement("a");
        link.href = url;
        link.download = safeFileName(a.n);
        document.body.appendChild(link);
        link.click();
        setTimeout(() => { try { document.body.removeChild(link); } catch (e) {} }, 200);
        sz.textContent = (fmtSize(a.s) + " · gespeichert").replace(/^ · /, "");
      } catch (e) {
        sz.textContent = "nicht mehr verfügbar";
      }
    });
    wrap.appendChild(btn);
    return wrap;
  }

  if (!autoMedia) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ghost small media-action";
    btn.textContent = `${label} laden`;
    btn.title = "Diese Adresse ist noch kein Kontakt. Medien werden erst nach deinem Klick geladen.";
    btn.addEventListener("click", () => { STATE.mediaAllowed.add(peer); renderChat(); });
    wrap.appendChild(btn);
    return wrap;
  }
  const note = document.createElement("div");
  note.className = "pending";
  note.textContent = `${label} wird entschlüsselt …`;
  wrap.appendChild(note);
  loadMediaUrl(a, mime).then(url => {
    const tag = m.k === "video" ? "video" : (m.k === "voice" ? "audio" : "img");
    const el = document.createElement(tag);
    if (tag === "img") el.alt = "Bild"; else { el.controls = true; el.preload = "metadata"; }
    el.src = url;
    attachDownloadWarning(el);
    wrap.textContent = "";
    wrap.appendChild(el);
  }).catch(() => {
    note.textContent = `[${label} nicht mehr verfügbar]`;
  });
  return wrap;
}

function loadMediaUrl(a, mime) {
  if (MEDIA_URLS.has(a.t)) return MEDIA_URLS.get(a.t);
  const p = (async () => {
    const enc = await API.fetchAttachment(a.t);
    const fileKey = new Uint8Array(LehnoCrypto.unb64(a.k));
    const iv = LehnoCrypto.unb64(a.i);
    const plain = await LehnoCrypto.decryptFile(fileKey, iv, enc);
    return URL.createObjectURL(new Blob([plain], { type: mime }));
  })();
  MEDIA_URLS.set(a.t, p);
  p.catch(() => MEDIA_URLS.delete(a.t));
  return p;
}

// =========================================================================
// SENDEN
// Der Empfänger (peer) wird immer vom Aufrufer festgehalten, nie mitten im
// Vorgang neu aus dem gerade offenen Chat gelesen.
// =========================================================================
let _lastFailed = null;   // { peer, text, id } eines gescheiterten Sendeversuchs
let _sendChain = Promise.resolve();

class SessionChanged extends Error {}

// me und sid werden vom Aufrufer am Anfang festgehalten. Wechselt die Sitzung
// zwischendurch (Abmelden, anderes Konto), wird abgebrochen: nie darf eine
// Nachricht mit dem Schlüssel eines anderen Kontos rausgehen.
async function sendBody(me, sid, peer, body, opts) {
  const recipientPub = await fetchPubKey(peer);
  if (sid !== STATE.sid) throw new SessionChanged();
  const enc = await LehnoCrypto.encryptMessage(me, recipientPub, {
    ...body,
    is_contact_request: !isContact(peer),
  }, opts);
  if (sid !== STATE.sid) throw new SessionChanged();
  const packet = {
    v: 2,
    recipient_address: peer,
    ephemeral_pub_b64: enc.ephemeral_pub_b64,
    nonce_b64: enc.nonce_b64,
    ciphertext_b64: enc.ciphertext_b64,
  };
  enc.proof = await proofIdOf(packet);
  await transmit(packet);
  if (sid !== STATE.sid) throw new SessionChanged();
  return enc;
}

// Öffentliche Beweis-Kennung: Hash über genau die Felder, die der Server
// speichert. Auf der Beweis-Seite kann jeder nachsehen, was dazu gespeichert ist.
async function proofIdOf(packet) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256",
    LehnoCrypto.utf8(packet.ephemeral_pub_b64 + "|" + packet.nonce_b64 + "|" + packet.ciphertext_b64)));
  let hex = "";
  for (let i = 0; i < 12; i++) hex += h[i].toString(16).padStart(2, "0");
  return hex;
}

// Mit Tarnverkehr geht ein Paket nicht sofort raus, sondern im nächsten Takt
// (dort wo sonst ein Tarnpaket gegangen wäre). Ohne Tarnverkehr sofort.
function transmit(packet) {
  if (!STATE.cover) return API.sendPacket(packet);
  return new Promise((resolve, reject) => { STATE.outQueue.push({ packet, resolve, reject }); });
}

async function afterSent(sid, peer, msg) {
  if (sid !== STATE.sid) return;          // inzwischen abgemeldet: nichts in fremden Zustand schreiben
  addMessage(peer, msg);
  ensureContact(peer);
  if (STATE.activeChat === peer) {
    markRead(peer, false);
  } else if (msg.q) {
    // Der Chat wurde schon verlassen: eine eigene Einmal-Nachricht taucht dann
    // gar nicht mehr auf (und Ungesehenes des Gegenübers gilt nicht als gesehen).
    removeMessages(peer, [msg.id], false);
  }
  STATE.historyDirty = true;
  renderSidebar();
  if (STATE.activeChat === peer) renderChat(true);
  const saved = await saveHistory();
  if (!saved && sid === STATE.sid) toast("Gesendet, aber der Verlauf konnte noch nicht gesichert werden. Neuer Versuch folgt.", "err");
}

function ruleBody(rule) {
  const b = {};
  if (rule.ttl) { b.ttl = rule.ttl; b.exp = rule.exp; }
  if (rule.once) b.once = 1;
  return b;
}

async function sendText(peer, text) {
  const sid = STATE.sid;
  const me = STATE.me;
  // Wiederholung derselben Nachricht nach einem Fehler: gleiche Kennung, damit
  // der Empfänger sie nicht doppelt bekommt, falls der erste Versuch doch ankam.
  const reuse = (_lastFailed && _lastFailed.peer === peer && _lastFailed.text === text) ? _lastFailed : null;
  const opts = { msgId: reuse ? reuse.id : LehnoCrypto.b64(LehnoCrypto.randomBytes(16)) };
  const rule = outgoingRules(peer);
  let enc;
  try {
    enc = await sendBody(me, sid, peer, { msg_type: "text", text, ...ruleBody(rule) }, opts);
  } catch (e) {
    if (sid === STATE.sid && !(e instanceof SessionChanged)) _lastFailed = { peer, text, id: opts.msgId };
    throw e;
  }
  if (sid === STATE.sid) _lastFailed = null;
  // Anzeige sofort, das Sichern läuft im Hintergrund weiter (die nächste
  // Nachricht muss darauf nicht warten).
  afterSent(sid, peer, { id: enc.msg_id, me: 1, k: "text", x: text, p: enc.proof, ...ruleFields(rule), o: nextOrder() }).catch(() => {});
}

// Bild, Video, Sprachnachricht oder beliebige Datei: wird im Browser mit einem
// eigenen Zufallsschlüssel verschlüsselt, auf Einheitsgröße aufgefüllt und
// hochgeladen. Schlüssel, Dateiname und Art stehen nur in der verschlüsselten Nachricht.
async function sendMedia(peer, blob, mime, msgType, extra={}) {
  const sid = STATE.sid;
  const me = STATE.me;
  if (msgType !== "file" && !(MEDIA_MIMES[msgType] || []).includes(mime)) throw new Error("Dieses Format wird hier nicht unterstützt.");
  if (blob.size > 16 * 1024 * 1024 - 64) throw new Error("Die Datei ist zu groß (höchstens 16 MB).");
  toast("Verschlüsseln und senden …");
  const fileBytes = new Uint8Array(await blob.arrayBuffer());
  const encFile = await LehnoCrypto.encryptFile(fileBytes);
  if (sid !== STATE.sid) throw new SessionChanged();
  const up = await API.uploadAttachment(new Blob([encFile.ciphertext], { type: "application/octet-stream" }));
  const a = { t: up.token, k: LehnoCrypto.b64(encFile.fileKey), i: LehnoCrypto.b64(encFile.iv), m: mime, c: extra.caption || "" };
  if (msgType === "file") { a.n = safeFileName(extra.name); a.s = fileBytes.byteLength; }
  const rule = outgoingRules(peer);
  let enc;
  try {
    if (sid !== STATE.sid) throw new SessionChanged();
    enc = await sendBody(me, sid, peer, {
      msg_type: msgType, attachment_token: a.t, file_key_b64: a.k, file_iv_b64: a.i, mime, caption: a.c,
      ...(msgType === "file" ? { file_name: a.n, file_size: a.s } : {}),
      ...ruleBody(rule),
    });
  } catch (e) {
    // Nachricht ging nicht raus: die hochgeladene Datei wieder entfernen.
    API.deleteAttachment(up.token).catch(() => {});
    throw e;
  }
  afterSent(sid, peer, { id: enc.msg_id, me: 1, k: msgType, x: "", a, p: enc.proof, ...ruleFields(rule), o: nextOrder() }).catch(() => {});
  if (sid === STATE.sid) toast("Gesendet", "ok");
}

// =========================================================================
// SPRACHNACHRICHT
// =========================================================================
let _rec = null;      // { recorder, stream, chunks, peer, sid, cancelled }
let _recStarting = false;

async function startRecording() {
  const peer = STATE.activeChat;
  const sid = STATE.sid;
  if (!peer || _rec || _recStarting) return;
  if (!navigator.mediaDevices || typeof MediaRecorder === "undefined") { toast("Dieser Browser kann keine Sprachnachrichten aufnehmen.", "err"); return; }
  _recStarting = true;
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); }
  catch (e) { _recStarting = false; toast("Kein Zugriff auf das Mikrofon.", "err"); return; }
  _recStarting = false;
  // Während der Mikrofon-Abfrage abgemeldet oder den Chat gewechselt: abbrechen.
  if (sid !== STATE.sid || STATE.activeChat !== peer) {
    try { stream.getTracks().forEach(t => t.stop()); } catch (e) {}
    return;
  }
  const mime = ["audio/webm", "audio/ogg", "audio/mp4"].find(t => MediaRecorder.isTypeSupported(t)) || "";
  const recorder = mime ? new MediaRecorder(stream, { mimeType: mime }) : new MediaRecorder(stream);
  const rec = { recorder, stream, chunks: [], peer, sid, cancelled: false };
  _rec = rec;
  recorder.ondataavailable = (e) => { if (e.data && e.data.size) rec.chunks.push(e.data); };
  recorder.onstop = async () => {
    if (_rec === rec) _rec = null;
    try { rec.stream.getTracks().forEach(t => t.stop()); } catch (e) {}
    updateRecordUI();
    if (rec.cancelled || rec.sid !== STATE.sid || !rec.chunks.length) return;
    const type = (recorder.mimeType || mime || "audio/webm").split(";")[0];
    try { await sendMedia(rec.peer, new Blob(rec.chunks, { type }), type, "voice"); }
    catch (err) { if (rec.sid === STATE.sid && !(err instanceof SessionChanged)) toast("Nicht gesendet: " + humanError(err), "err"); }
  };
  recorder.start();
  updateRecordUI();
}

function stopRecording(cancel) {
  const rec = _rec;
  if (!rec) return;
  rec.cancelled = !!cancel;
  try { rec.recorder.stop(); }
  catch (e) {
    try { rec.stream.getTracks().forEach(t => t.stop()); } catch (e2) {}
    _rec = null;
    updateRecordUI();
  }
}

function updateRecordUI() {
  const btn = $("#btn-record"), bar = $("#record-bar");
  if (!btn || !bar) return;
  btn.classList.toggle("recording", !!_rec);
  bar.hidden = !_rec;
}

// =========================================================================
// TARNVERKEHR: gleichmäßiger Takt
// In jedem Takt geht genau ein Paket in Einheitsgröße raus (echte Nachricht
// oder Tarnpaket) und das Postfach wird abgefragt (Antwort in fester Größe).
// Zusätzlich gibt es in zufälligen Takten denselben Ablauf wie nach einer
// echten Nachricht (Verlauf sichern, bestätigen), auch wenn nichts passiert ist.
// Von außen sieht man einen gleichförmigen Strom, in dem einzelne Nachrichten
// nicht erkennbar sind.
// =========================================================================
let _tickTimer = null;

function randInt(n) {
  const r = new Uint32Array(1);
  crypto.getRandomValues(r);
  return r[0] % n;
}

function startTick() {
  if (_tickTimer) { clearTimeout(_tickTimer); _tickTimer = null; }
  const sid = STATE.sid;
  const run = async () => {
    _tickTimer = null;
    if (!STATE.me || sid !== STATE.sid) return;
    if (STATE.cover) {
      try { await tickOnce(sid); } catch (e) {}
    } else {
      // Tarnverkehr abgeschaltet: Wartendes sofort senden.
      while (STATE.outQueue.length) {
        const item = STATE.outQueue.shift();
        API.sendPacket(item.packet).then(item.resolve, item.reject);
      }
    }
    if (STATE.me && sid === STATE.sid) _tickTimer = setTimeout(run, 2500 + randInt(2000));
  };
  _tickTimer = setTimeout(run, 400);
}

function decoyPacket() {
  const C = LehnoCrypto;
  // Zufallsdaten in genau der Form eines echten kleinen Pakets.
  const eph = C.randomBytes(65);
  eph[0] = 4;
  return {
    v: 2,
    recipient_address: DECOY_ADDRESS,
    ephemeral_pub_b64: C.b64(eph),
    nonce_b64: C.b64(C.randomBytes(12)),
    ciphertext_b64: C.b64(C.randomBytes(C.PAYLOAD_BUCKETS[0] + 16)),
  };
}

async function tickOnce(sid) {
  const item = STATE.outQueue.shift();
  if (item) {
    try { item.resolve(await API.sendPacket(item.packet)); } catch (e) { item.reject(e); }
  } else {
    try { await API.sendPacket(decoyPacket()); } catch (e) {}
  }
  if (sid !== STATE.sid) return;
  await pollInbox();
  if (sid !== STATE.sid) return;
  // Schein-Ablauf in zufälligen Takten (im Schnitt etwa jeder zwölfte).
  if (randInt(12) === 0 && STATE.historyLoaded && !STATE.historyDirty) {
    await saveHistory();
    if (sid !== STATE.sid) return;
    const fake = Array.from(LehnoCrypto.randomBytes(16)).map(b => b.toString(16).padStart(2, "0")).join("");
    try { await API.post("/api/packets/ack", { packet_ids: [fake] }); } catch (e) {}
  }
  flushControls();
}

// =========================================================================
// LIVE-VERBINDUNG + REGELMÄSSIGER ABRUF
// =========================================================================
function startWebSocket() {
  if (!STATE.me || STATE.ws) return;
  let ws;
  try {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}/ws`);
  } catch (e) { console.warn("ws err", e); return; }
  STATE.ws = ws;
  ws.onopen = () => {
    // Token als erste Nachricht, nicht in der Adresse.
    try { ws.send(JSON.stringify({ type: "auth", token: STATE.me.jwt })); } catch (e) {}
  };
  ws.onmessage = (evt) => {
    if (evt.data === "pong") return;
    let payload = null;
    try { payload = JSON.parse(evt.data); } catch (e) { return; }
    if (payload.type === "ready") { STATE.wsRetry = 0; ws._ready = true; pollInbox(); }
    else if (payload.type === "new_packet") pollInbox();
    // Ein anderes Gerät dieses Kontos hat den Verlauf geändert.
    else if (payload.type === "history" && payload.version !== STATE.historyVersion) pollInbox();
  };
  ws.onclose = (evt) => {
    if (STATE.ws === ws) STATE.ws = null;
    if (!STATE.me) return;
    // 4001 = Token nicht mehr gültig (Konto gelöscht oder woanders wiederhergestellt).
    // Ein Abruf klärt das sofort und meldet uns gegebenenfalls ab.
    if (evt && evt.code === 4001) pollInbox();
    STATE.wsRetry = Math.min(STATE.wsRetry + 1, 6);
    const sid = STATE.sid;
    setTimeout(() => { if (sid === STATE.sid && !STATE.cover) startWebSocket(); }, 2000 * STATE.wsRetry);
  };
  ws.onerror = () => {};
}

function startTimers() {
  for (const t of STATE.timers) clearInterval(t);
  STATE.timers = [];
  // Löschfristen: alle 5 Sekunden prüfen.
  STATE.timers.push(setInterval(() => { purgeExpired(); }, 5000));
  let tick = 0;
  STATE.timers.push(setInterval(() => {
    if (!STATE.me) return;
    tick++;
    const live = STATE.ws && STATE.ws._ready && STATE.ws.readyState === 1;
    if (live) { try { STATE.ws.send("ping"); } catch (e) {} }
    // Mit Tarnverkehr fragt der Takt selbst ab. Sonst: ohne Live-Verbindung alle
    // 15 Sekunden, mit Live-Verbindung zur Sicherheit einmal pro Minute.
    if (!STATE.cover && (!live || tick % 4 === 0)) pollInbox();
    if (!STATE.cover) flushControls();
    // Ungesichertes erneut versuchen.
    if ((STATE.historyDirty || !STATE.historyLoaded) && !_histTimer) saveHistory().then(ok => { if (ok) { renderSidebar(); renderChat(); } });
    if (!_userdataLoaded) {
      const hadChanges = STATE.contacts.length > 0 || STATE.declined.length > 0 || Object.keys(STATE.nicknames).length > 0;
      reloadUserdataMerging().then(() => { if (hadChanges) STATE.userdataDirty = true; renderSidebar(); }).catch(() => {});
    } else if (STATE.userdataDirty && !_saveTimer) {
      saveUserdata();
    }
  }, 15000));
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden || !STATE.me) return;
  purgeExpired();
  pollInbox();
  if (STATE.activeChat) { markRead(STATE.activeChat); renderSidebar(); }
});

// Beim Schließen des Tabs warnen, solange etwas noch nicht gesichert ist.
window.addEventListener("beforeunload", (e) => {
  if (STATE.me && (STATE.historyDirty || STATE.userdataDirty)) { e.preventDefault(); e.returnValue = ""; }
});

// =========================================================================
// MEDIA-DOWNLOAD-WARNUNG
// =========================================================================
function attachDownloadWarning(el) {
  el.addEventListener("contextmenu", (e) => {
    if (!confirm(
      "ACHTUNG: Wenn du diese Datei jetzt speicherst, liegt sie ENTSCHLÜSSELT auf deinem Gerät.\n\n" +
      "In chatmesh bleibt sie verschlüsselt und ist nur für euch beide lesbar.\n\n" +
      "Trotzdem das Menü zum Speichern öffnen?"
    )) e.preventDefault();
  });
  el.addEventListener("dragstart", e => e.preventDefault());
}

// =========================================================================
// KONTO LÖSCHEN
// =========================================================================
async function deleteAccount() {
  if (!STATE.me) return;
  if (!confirm("Dein Konto wirklich endgültig löschen?\n\nAdresse, Kontakte, Verlauf und wartende Nachrichten werden auf dem Server gelöscht. Das lässt sich nicht rückgängig machen.")) return;
  const typed = prompt("Zur Bestätigung bitte LÖSCHEN eintippen:");
  if ((typed || "").trim().toUpperCase() !== "LÖSCHEN") { toast("Abgebrochen"); return; }
  try {
    await API.del("/api/account");
    setRemember(null);
    logout("Konto gelöscht.");
  } catch (e) {
    toast("Löschen fehlgeschlagen: " + humanError(e), "err");
  }
}

// =========================================================================
// UI BINDINGS
// =========================================================================
function bindUI() {
  $$("#view-auth .tab").forEach(t => t.addEventListener("click", () => {
    $$("#view-auth .tab").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    $$("#view-auth .auth-form").forEach(f => f.classList.remove("active"));
    $("#form-" + t.dataset.tab).classList.add("active");
    $("#auth-msg").textContent = "";
  }));

  $$(".sidebar-tabs .tab").forEach(t => t.addEventListener("click", () => {
    $$(".sidebar-tabs .tab").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    currentList = t.dataset.list;
    renderSidebar();
  }));

  $("#form-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    const addr = normalizeAddressInput(e.target.address.value);
    const p = e.target.password.value;
    const remember = $("#remember-address").checked;
    if (!addr) { $("#auth-msg").textContent = "Das ist keine gültige Adresse (sie beginnt mit mesh:)."; return; }
    $("#auth-msg").textContent = "Einloggen …";
    $("#auth-msg").className = "msg";
    try {
      await loginWithPassword(addr, p);
      setRemember(remember ? addr : null);
      await afterLogin();
      $("#auth-msg").textContent = "";
    } catch (err) {
      if (STATE.me) logout();
      $("#auth-msg").textContent = "Login fehlgeschlagen: " + humanError(err);
    }
  });

  $("#form-register").addEventListener("submit", async (e) => {
    e.preventDefault();
    const p = e.target.password.value;
    const p2 = e.target.password2.value;
    if (p !== p2) { $("#auth-msg").textContent = "Passwörter stimmen nicht überein"; return; }
    if (p.length < MIN_PASSWORD) { $("#auth-msg").textContent = `Das Passwort braucht mindestens ${MIN_PASSWORD} Zeichen.`; return; }
    $("#auth-msg").textContent = "Schlüssel werden erzeugt …";
    try {
      await doRegister(p);
      $("#auth-msg").textContent = "";
    } catch (err) {
      if (STATE.me) logout();
      $("#auth-msg").textContent = "Registrierung fehlgeschlagen: " + humanError(err);
    }
  });

  $("#form-recover").addEventListener("submit", async (e) => {
    e.preventDefault();
    const addr = normalizeAddressInput(e.target.address.value);
    const mnemonic = e.target.mnemonic.value.trim().toLowerCase().replace(/\s+/g, " ");
    const newPw = e.target.password.value;
    const newPw2 = e.target.password2.value;
    if (!addr) { $("#recover-msg").textContent = "Das ist keine gültige Adresse (sie beginnt mit mesh:)."; return; }
    if (newPw !== newPw2) { $("#recover-msg").textContent = "Passwörter stimmen nicht überein"; return; }
    if (newPw.length < MIN_PASSWORD) { $("#recover-msg").textContent = `Das Passwort braucht mindestens ${MIN_PASSWORD} Zeichen.`; return; }
    const wordCount = mnemonic ? mnemonic.split(" ").filter(Boolean).length : 0;
    if (wordCount !== 24) {
      $("#recover-msg").textContent = `Genau 24 Wörter nötig (du hast ${wordCount}).`;
      return;
    }
    $("#recover-msg").textContent = "Wiederherstellen …";
    $("#recover-msg").className = "msg";
    try {
      await doRecover(addr, mnemonic, newPw);
      $("#recover-msg").textContent = "";
      toast("Account wiederhergestellt", "ok");
    } catch (err) {
      if (STATE.me) logout();
      show("recover");
      $("#recover-msg").textContent = "Wiederherstellung fehlgeschlagen: " + humanError(err);
    }
  });

  $("#mnemonic-confirm").addEventListener("change", e => {
    $("#mnemonic-continue").disabled = !e.target.checked;
  });
  $("#mnemonic-continue").addEventListener("click", () => afterLogin());

  $("#btn-copy-addr").addEventListener("click", () => {
    navigator.clipboard.writeText($("#my-address-display").textContent).then(() => toast("Adresse kopiert", "ok")).catch(() => {});
  });

  $("#btn-download-backup").addEventListener("click", downloadAccountBackup);

  $("#btn-logout").addEventListener("click", async () => {
    // Laufende und offene Speichervorgänge abwarten (höchstens 8 Sekunden), dann abmelden.
    const btn = $("#btn-logout");
    btn.disabled = true;
    stopRecording(true);
    leaveChat();
    try {
      const pending = (async () => {
        if (STATE.userdataDirty) await saveUserdata();
        await saveHistory();
      })();
      await Promise.race([pending, new Promise(r => setTimeout(r, 8000))]);
    } catch (e) {}
    btn.disabled = false;
    if (STATE.me && (STATE.historyDirty || STATE.userdataDirty)) {
      if (!confirm("Ein Teil deines Verlaufs konnte noch nicht gesichert werden (Server gerade nicht erreichbar).\n\nTrotzdem abmelden? Ungesichertes geht dabei verloren.")) return;
    }
    logout();
  });

  $("#me-pill").addEventListener("click", () => {
    $("#popup-my-address").textContent = STATE.me.address;
    $("#addr-popup").style.display = "flex";
  });
  $("#btn-popup-close").addEventListener("click", () => $("#addr-popup").style.display = "none");
  $("#btn-popup-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(STATE.me.address).then(() => toast("Adresse kopiert", "ok")).catch(() => {});
  });
  $("#btn-delete-account").addEventListener("click", deleteAccount);

  $("#btn-new-chat").addEventListener("click", async () => {
    const addr = normalizeAddressInput($("#new-chat-address").value);
    if (!addr) { toast("Das ist keine gültige Adresse (sie beginnt mit mesh:)", "err"); return; }
    try {
      await fetchPubKey(addr);
      $("#new-chat-address").value = "";
      await openChat(addr);
    } catch (e) {
      toast(e.status === 404 ? "Adresse nicht gefunden" : humanError(e), "err");
    }
  });
  $("#new-chat-address").addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); $("#btn-new-chat").click(); }
  });

  $("#btn-accept").addEventListener("click", () => { if (STATE.activeChat) acceptRequest(STATE.activeChat); });
  $("#btn-decline").addEventListener("click", () => { if (STATE.activeChat) declineRequest(STATE.activeChat); });

  // Sende-Warteschlange: wer schnell hintereinander schreibt, verliert nichts,
  // und die Nachrichten gehen in genau der getippten Reihenfolge raus.
  $("#form-send").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("#msg-input");
    const text = input.value.trim();
    const peer = STATE.activeChat;       // Empfänger jetzt festhalten
    const sid = STATE.sid;
    if (!text || !peer) return;
    input.value = "";
    _sendChain = _sendChain.then(async () => {
      if (sid !== STATE.sid) return;
      try {
        await sendText(peer, text);
      } catch (err) {
        // Nicht gesendet: Text zurück ins Feld, damit nichts verloren geht.
        if (sid !== STATE.sid) return;
        if (STATE.activeChat === peer) {
          input.value = input.value ? text + " " + input.value : text;
          toast("Nicht gesendet: " + humanError(err), "err");
        } else {
          // Inzwischen in einem anderen Chat: Text als Entwurf im richtigen Chat ablegen.
          STATE.drafts[peer] = STATE.drafts[peer] ? text + " " + STATE.drafts[peer] : text;
          toast("Eine Nachricht wurde nicht gesendet. Der Text liegt im betreffenden Chat bereit. (" + humanError(err) + ")", "err");
        }
      }
    });
  });

  $("#btn-attach").addEventListener("click", () => $("#file-input").click());
  $("#file-input").addEventListener("change", async (e) => {
    const peer = STATE.activeChat;       // alle gewählten Dateien gehen an DIESEN Chat
    const sid = STATE.sid;
    const files = Array.from(e.target.files);
    e.target.value = "";
    if (!peer) return;
    for (const f of files) {
      if (sid !== STATE.sid) return;
      // Bilder, Videos und Tonaufnahmen in bekannten Formaten werden im Chat
      // angezeigt bzw. abgespielt. Alles andere (PDF usw.) geht als Datei.
      const type = (f.type || "").split(";")[0];
      let kind = "file";
      if (MEDIA_MIMES.image.includes(type)) kind = "image";
      else if (MEDIA_MIMES.video.includes(type)) kind = "video";
      else if (MEDIA_MIMES.voice.includes(type)) kind = "voice";
      try { await sendMedia(peer, f, kind === "file" ? "application/octet-stream" : type, kind, { name: f.name }); }
      catch (err) { if (sid === STATE.sid && !(err instanceof SessionChanged)) toast("Nicht gesendet: " + humanError(err), "err"); }
    }
  });

  // Sprachnachricht: Mikrofon antippen startet, noch einmal antippen sendet.
  $("#btn-record").addEventListener("click", () => { if (_rec) stopRecording(false); else startRecording(); });
  $("#btn-record-cancel").addEventListener("click", () => stopRecording(true));
  $("#btn-record-send").addEventListener("click", () => stopRecording(false));

  // Menüs
  $("#btn-main-menu").addEventListener("click", openMainMenu);
  $("#sheet-bg").addEventListener("click", (e) => { if (e.target.id === "sheet-bg") closeSheet(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSheet(); });

  $("#link-recover").addEventListener("click", e => { e.preventDefault(); show("recover"); });
  $("#btn-back-to-auth").addEventListener("click", () => show("auth"));

  // Erst jetzt lassen sich die Formulare absenden (ohne JavaScript bleiben die
  // Knöpfe gesperrt, damit nie ein Passwort als normale Formularanfrage rausgeht).
  $$("button[data-needs-js]").forEach(b => { b.disabled = false; });
}

// =========================================================================
// BACKUP-DATEI DOWNLOAD
// =========================================================================
let _lastMnemonic = null;
let _lastAddress = null;

function setLastBackupData(addr, mnemonic) {
  _lastAddress = addr;
  _lastMnemonic = mnemonic;
}

function downloadAccountBackup() {
  if (!_lastAddress || !_lastMnemonic) {
    toast("Backup-Daten nicht verfügbar", "err");
    return;
  }
  const content = [
    "chatmesh - Account-Backup",
    "=".repeat(60),
    "",
    "DEINE ADRESSE (öffentlich, kannst du teilen):",
    _lastAddress,
    "",
    "DEIN 24-WORT-BACKUP-CODE (GEHEIM, niemals teilen!):",
    "",
    _lastMnemonic.split(" ").map((w, i) => `${String(i + 1).padStart(2, " ")}.  ${w}`).join("\n"),
    "",
    "=".repeat(60),
    "WICHTIG:",
    "",
    "- Wer den 24-Wort-Code hat, hat vollen Zugriff auf deinen Account und deinen Verlauf.",
    "- Speichere diese Datei OFFLINE (USB-Stick, Papier-Ausdruck, sicherer Tresor).",
    "- NIEMALS in der Cloud (iCloud, Google Drive, Dropbox, E-Mail).",
    "- NIEMALS als Foto/Screenshot.",
    "- Vergisst du Passwort UND Backup-Code = Account für immer weg.",
    "",
    "Wiederherstellung: chatmesh öffnen, unter dem Login auf \"Passwort vergessen?\" gehen,",
    "Adresse + 24 Wörter + neues Passwort eingeben.",
    "",
    "Open-Source-Code: github.com/aliecommerce123-web/lehno-mesh",
  ].join("\n");

  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `chatmesh-backup-${_lastAddress.replace(/^mesh:/, "").slice(0, 10)}.txt`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
  toast("Backup heruntergeladen", "ok");
}

// =========================================================================
// INIT
// =========================================================================
window.LehnoApp = { show, STATE };

document.addEventListener("DOMContentLoaded", () => {
  bindUI();
  show("auth");
  renderChat();

  const last = getRememberedAddress();
  if (last) {
    $$("#form-login input[name=address], #form-recover input[name=address]").forEach(el => { el.value = last; });
    $("#remember-address").checked = true;
  }
  // Im normalen Browser: kurzer Hinweis auf den zusätzlichen Schutz durch Tor.
  if (!location.host.endsWith(".onion")) $("#tor-hint").hidden = false;

  // Früher gab es einen Service Worker als Offline-Zwischenspeicher. Er wird
  // nicht mehr gebraucht und könnte veralteten Code festhalten: entfernen und
  // seine Zwischenspeicher löschen.
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.getRegistrations().then(regs => {
      regs.forEach(r => r.unregister());
    }).catch(()=>{});
  }
  if (typeof caches !== "undefined") {
    caches.keys().then(keys => Promise.all(keys.map(k => caches.delete(k)))).catch(()=>{});
  }
});
