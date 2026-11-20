// chatmesh Phase 2 - anonymer Messenger ohne Adressen.
//
// Grundsätze dieser Datei:
// - Ein Konto besteht nur aus 12 Anmeldewörtern. Dazu gibt es 12 Löschwörter.
// - Kanäle entstehen über einen Einmal-Schlüssel (24 Zeichen oder QR-Code). Ein
//   eigenes Passwort je Kanal ist freiwillig. Mit Passwort genügen die 12
//   Anmeldewörter allein nicht, um Nachrichten zu lesen, zu senden oder zu
//   löschen. Ohne Passwort genügen sie.
// - Jede Nachricht liegt als namenloser Block unter einer neuen Zufallsmarke
//   auf dem Server. Dieses Gerät lädt nur ein Verzeichnis (je Block die ersten
//   5 Bytes der Marke), erkennt daran selbst, was für es da ist, und holt genau
//   diese Blöcke mit der vollen Marke ab. Fremde Blöcke kann niemand laden. Der
//   Server bekommt keine Angabe, für wen ein Block ist.
// - Standard: Nachrichten werden beim Öffnen vom Server gelöscht, sind nur im
//   Arbeitsspeicher sichtbar und verschwinden nach der eingestellten Zeit oder
//   sofort beim Verlassen des Chats. Verlauf behalten nur, wenn beide zustimmen.
// - Es gibt nirgends Uhrzeiten. Auf dem Gerät liegt nur die mit dem eigenen Code
//   verschlossene Anmeldung, und nur bis das Browser-Fenster geschlossen wird.
// - Schein-Verkehr: Abrufe und Schein-Blöcke in unregelmäßigen Abständen.
(function () {
"use strict";
const C = window.CM;
const APP_NAME = "chatmesh";
const WINDOW_BACK = 32, WINDOW_AHEAD = 256, RESERVE = 8;
const LIM = { keep: 300000 };            // so viele Verzeichnis-Einträge bleiben höchstens im Arbeitsspeicher
const INDEX_MAX = 60000;                 // so viele Einträge schickt der Server höchstens je Antwort
const PFX = 10;                          // ein Verzeichnis-Eintrag: die ersten 5 Bytes einer Marke (10 Hex-Zeichen)
const FETCH_MAX = 4;                     // so viele Marken werden am Stück verarbeitet (jede in einem eigenen Abruf)
const VIEW_MIN = 5, VIEW_MAX = 30 * 86400, VIEW_DEFAULT = 600;
const INVITE_SECONDS = 24 * 3600;
const HIST_BYTES = 200000;              // Verlauf je Chat-Kanal (verschlüsselt im Konto)
const PW_MIN = 6;
const UNREAD_MIN = 60;                 // kürzeste Frist für ungeöffnete Nachrichten (Sekunden)
const CLOCK_SLACK = 90;                // so viel dürfen die Uhren zweier Geräte auseinander liegen
const MIMES = {
  image: ["image/jpeg", "image/png", "image/gif", "image/webp"],
  video: ["video/mp4", "video/webm", "video/quicktime"],
  voice: ["audio/webm", "audio/ogg", "audio/mp4", "audio/mpeg", "audio/wav", "audio/x-wav"],
};
const SHOW_MIMES = {
  image: ["image/jpeg", "image/png", "image/webp"],
  video: ["video/mp4", "video/webm"],
  voice: ["audio/webm", "audio/ogg", "audio/mp4", "audio/mpeg", "audio/wav", "audio/x-wav"],
};

const S = {
  me: null,            // { id, token, encKey }
  sid: 0,              // Sitzungszähler: ändert sich bei jedem An- und Abmelden
  acct: null,          // entschlüsselter Konto-Inhalt
  version: 0,
  dirty: false,
  urgent: false,
  blobLen: 0,
  blobClass: 0,
  work: { salt: "", pile: [12, 16], delete: 8, account: [17, 19, 21, 23, 25], account_wipe_extra: 2, upload: [16, 18, 20, 22] },
  wipeBig: false,
  index: new Map(),    // Verzeichnis: Anfang (5 Bytes) der Marke -> Platz in der Reihenfolge der Einlieferung
  indexN: 0,
  cursor: 0,
  synced: false,
  expect: new Map(),   // Marke -> { id, kind, lane, n }
  run: {},             // Chat-Kanal-ID -> Laufzeitdaten (nur Arbeitsspeicher)
  active: null,        // gerade offener Chat-Kanal
  timers: new Set(),
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
function randInt(n) { const r = new Uint32Array(1); crypto.getRandomValues(r); return r[0] % n; }
function randBetween(a, b) { return a + randInt(Math.max(1, b - a)); }
function randExp(mean, lo, hi) {
  const r = new Uint32Array(1); crypto.getRandomValues(r);
  const u = (r[0] + 1) / 4294967297;
  return Math.max(lo, Math.min(hi, -Math.log(u) * mean));
}
const nowSec = () => Math.floor(Date.now() / 1000);

function show(view) {
  $$(".view").forEach(v => v.classList.remove("active"));
  $("#view-" + view).classList.add("active");
}
let _toastTimer = null;
function toast(text, kind = "") {
  let t = $(".toast");
  if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.appendChild(t); }
  t.textContent = text;
  t.className = "toast show " + kind;
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove("show"), kind === "err" ? 6000 : 2600);
}
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// =========================================================================
// SERVER-AUFRUFE
// =========================================================================
class ApiError extends Error { constructor(m, status) { super(m); this.status = status; } }

async function api(method, path, opt = {}) {
  const headers = Object.assign({}, opt.headers || {});
  const sid = S.sid;
  if (opt.auth) headers["authorization"] = "Bearer " + S.me.id + "." + S.me.token;
  let body = opt.body;
  if (opt.json !== undefined) { headers["content-type"] = "application/json"; body = JSON.stringify(opt.json); }
  let r;
  const init = { method, headers, body, cache: "no-store" };
  if (opt.keepalive && typeof body === "string" && body.length < 60000) init.keepalive = true;
  // Mit Zeitgrenze: Ein hängender Abruf darf die folgenden nicht aufhalten.
  let stop = null;
  if (opt.timeout && typeof AbortController !== "undefined") {
    const ac = new AbortController();
    init.signal = ac.signal;
    stop = setTimeout(() => { try { ac.abort(); } catch (e) {} }, opt.timeout);
  }
  try { r = await fetch(path, init); }
  catch (e) { if (stop) clearTimeout(stop); throw new ApiError("Keine Verbindung zum Server", 0); }
  if (stop && !opt.raw) clearTimeout(stop);
  if (stop && opt.raw) r.__stop = stop;
  if (!r.ok) {
    let detail = r.statusText;
    try { const j = await r.json(); if (j && j.detail) detail = String(j.detail); } catch (e) {}
    if (r.status === 401 && opt.auth && S.me && sid === S.sid && !opt.noLogout) logout("Sitzung beendet. Bitte neu anmelden.");
    throw new ApiError(detail, r.status);
  }
  return opt.raw ? r : r.json();
}

// Der Server verlangt zu jeder Einlieferung eine kleine Rechenaufgabe. Wie
// schwer sie gerade ist, steht in den öffentlichen Einstellungen.
async function loadConfig() {
  try {
    const c = await api("GET", "/api/v2/config");
    if (c && Number.isInteger(c.min_client) && c.min_client > CLIENT_VER) needReload();
    if (c && c.work && Array.isArray(c.work.pile) && Array.isArray(c.work.account) && Array.isArray(c.work.upload) && /^[0-9a-f]{16}$/.test(String(c.work.salt || ""))) S.work = c.work;
  } catch (e) {}
}
// Gegenstand der Rechenaufgabe: aktuelles Salz des Servers + Kennung + Art.
const subject = (hexId, letter, extra) => C.concat(C.unhex(S.work.salt || ""), C.unhex(hexId), C.utf8(letter), extra === undefined ? new Uint8Array(0) : new Uint8Array([extra]));

// Einliefern und Löschen sehen von außen gleich aus: gleiche Länge der Anfrage,
// gleiche Länge und Dauer der Antwort.
const POST_LEN = JSON.stringify({ tag: "0".repeat(32), data: "x".repeat(5500), del_hash: "0".repeat(64), work: "0".repeat(16) }).length;
async function pilePost(tag, bytes, delToken, maxBits = 26) {
  if (!S.work.salt) await loadConfig();
  const delHash = await C.delHash(delToken);
  const idx = bytes.byteLength > 5000 ? 1 : 0;
  for (let i = 0; i < 3; i++) {
    const bits = S.work.pile[idx] || 0;
    if (bits > maxBits) return 428;      // Server unter Last: nicht endlos rechnen
    const work = await C.work(subject(tag, "p"), bits);
    const r = await api("POST", "/api/v2/pile", { json: { tag, data: C.b64(bytes), del_hash: delHash, work } });
    if (r && r.ok === true) return 200;
    const code = (r && r.code) || 500;
    if (code !== 428) return code;
    await loadConfig();                 // Aufgabe ist schwerer geworden: neu holen, noch einmal
  }
  return 428;
}

async function pileDelete(tag, token) {
  try {
    if (!S.work.salt) await loadConfig();
    const bits = S.work.delete || 0;
    if (bits > 24) return false;
    const work = await C.work(subject(tag, "d"), bits);
    const base = JSON.stringify({ tag, token, work, pad: "" }).length;
    const r = await api("POST", "/api/v2/pile/delete", { json: { tag, token, work, pad: "x".repeat(Math.max(0, POST_LEN - base)) } });
    if (r && r.code === 428) { await loadConfig(); return false; }
    return !!(r && (r.ok || r.code === 404));
  } catch (e) { return false; }
}

// Wie pileDelete, sagt aber, ob der Block noch da war: "ok", "gone" oder "fail".
async function pileDeleteState(tag, token) {
  try {
    if (!S.work.salt) await loadConfig();
    const bits = S.work.delete || 0;
    if (bits > 24) return "fail";
    const work = await C.work(subject(tag, "d"), bits);
    const base = JSON.stringify({ tag, token, work, pad: "" }).length;
    const r = await api("POST", "/api/v2/pile/delete", { json: { tag, token, work, pad: "x".repeat(Math.max(0, POST_LEN - base)) } });
    if (r && r.ok) return "ok";
    if (r && r.code === 404) return "gone";
    if (r && r.code === 428) await loadConfig();
    return "fail";
  } catch (e) { return "fail"; }
}
// Löschen mit Wiederholung: geht ein Versuch verloren, folgen weitere.
function queueDelete(tag, token, delay = 0) {
  const sid = S.sid;
  const waits = [2000, 6000, 20000, 60000, 180000];
  let attempt = 0;
  const run = async () => {
    if (await pileDelete(tag, token)) return;
    if (sid !== S.sid || attempt >= waits.length) return;
    setTimeout(run, waits[attempt++] + randInt(1500));
  };
  if (delay > 0) setTimeout(run, delay); else run();
}

// =========================================================================
// KONTO
// =========================================================================
function emptyAccount(wipeOuterKey, wipePub, wipePrivSealed) {
  return { v: 2, set: { view: VIEW_DEFAULT, unread: 0, lockOn: 1, rv: 0 }, wk: C.b64(wipeOuterKey), wp: C.b64(wipePub), wq: C.b64(wipePrivSealed), ch: [], gone: [], notes: [], n: 1 };
}
const strList = (v, max) => (Array.isArray(v) ? v : []).filter(x => typeof x === "string").slice(-max);
const numList = (v) => (Array.isArray(v) ? v : []).filter(x => Number.isInteger(x) && x >= 0).slice(-WINDOW_BACK * 2);
const modeList = (v) => (Array.isArray(v) ? v : []).filter(x => x === "keep" || x === "shots").filter((x, i, a) => a.indexOf(x) === i);
function sanitizeChannel(c) {
  if (!c || typeof c.id !== "string" || !/^[0-9a-f]{16}$/.test(c.id)) return null;
  c.name = String(c.name || "Chat").slice(0, 40);
  c.dir = c.dir === "b" ? "b" : "a";
  c.rv = Number.isInteger(c.rv) ? c.rv : 0;
  if (c.pend) {
    const p = c.pend;
    if (![p.ta, p.da, p.tb].every(x => typeof x === "string" && /^[0-9a-f]{32}$/.test(x)) || typeof p.s !== "string" || typeof p.c !== "string") return null;
    p.exp = Number.isFinite(p.exp) ? p.exp : 0;
    if (p.n !== undefined && (typeof p.n !== "string" || p.n.length < 40 || p.n.length > 48)) return null;
    return c;
  }
  if (typeof c.kt !== "string" || !c.wrap || typeof c.wrap.s !== "string" || typeof c.wrap.c !== "string") return null;
  if (!c.pd || typeof c.pd.t !== "string" || typeof c.pd.k !== "string" || typeof c.pd.d !== "string") return null;
  if (c.wrap.n !== undefined && (typeof c.wrap.n !== "string" || c.wrap.n.length < 40 || c.wrap.n.length > 48)) return null;
  c.wrap.v = Number.isInteger(c.wrap.v) && c.wrap.v > 0 ? c.wrap.v : 0;
  for (const k of ["sn", "cn", "sr", "cr", "rn", "rc"]) c[k] = Number.isInteger(c[k]) && c[k] >= 0 ? c[k] : 0;
  c.rp = numList(c.rp); c.rpc = numList(c.rpc);
  c.keep = c.keep ? 1 : 0; c.shots = c.shots ? 1 : 0;
  c.rq = modeList(c.rq); c.ro = modeList(c.ro);
  c.pu = (Array.isArray(c.pu) ? c.pu : []).filter(e => e && typeof e.t === "string" && typeof e.d === "string" && Number.isFinite(e.x)).slice(-300);
  c.hist = typeof c.hist === "string" ? c.hist : "";
  c.sym = typeof c.sym === "string" ? c.sym.slice(0, 80) : "";
  delete c.open;
  return c;
}
function sanitizeAccount(a) {
  const out = { v: 2, set: {}, wk: typeof a.wk === "string" ? a.wk : "", wp: typeof a.wp === "string" ? a.wp : "", wq: typeof a.wq === "string" ? a.wq : "", wl: typeof a.wl === "string" ? a.wl : "", ch: [], gone: strList(a.gone, 300), notes: [], n: Number.isFinite(a.n) ? a.n : 1 };
  const s = a.set && typeof a.set === "object" ? a.set : {};
  out.set.view = Math.max(VIEW_MIN, Math.min(VIEW_MAX, Math.floor(Number(s.view) || VIEW_DEFAULT)));
  out.set.unread = Math.max(0, Math.min(VIEW_MAX, Math.floor(Number(s.unread) || 0)));
  out.set.lockOn = s.lockOn === 0 ? 0 : 1;
  out.set.rv = Number.isInteger(s.rv) ? s.rv : 0;
  const ids = new Set();
  for (const raw of (Array.isArray(a.ch) ? a.ch : [])) {
    const c = sanitizeChannel(raw);
    if (c && !ids.has(c.id) && !out.gone.includes(c.id)) { ids.add(c.id); out.ch.push(c); }
  }
  out.notes = strList(a.notes, 20).map(n => n.slice(0, 300));
  return out;
}

// Kleiner zweiter Block für die Löschwörter. Er enthält, was zum Auflösen der
// Kanäle beim Gegenüber nötig ist, je Kanal verschlossen an einen Schlüssel,
// den nur die 12 Löschwörter öffnen. Das Konto selbst kann die Einträge nicht lesen.
async function wipeBlobFor(acct) {
  // Je Kanal: der verschlossene Eintrag plus die Zähler, damit beim Löschen auch
  // liegengebliebene Blöcke dieses Kanals vom Server entfernt werden können.
  const entries = acct.ch.filter(c => !c.pend && c.wb).map(c => ({ b: c.wb, d: c.dir, s: c.sn || 0, c: c.cn || 0, r: c.rn || 0, q: c.rc || 0 }));
  for (;;) {
    try { return C.b64(await C.sealJson(C.unb64(acct.wk), { p: acct.wp, q: acct.wq, l: acct.wl || "", e: entries }, C.WIPE)); }
    catch (e) { if (!entries.length) throw e; entries.pop(); }
  }
}
async function accountBlobs() {
  await flushChains();
  S.acct.n = (S.acct.n || 0) + 1;
  const plainLen = C.utf8(JSON.stringify(S.acct)).byteLength + 4;
  S.blobClass = Math.max(0, C.ACCOUNT.findIndex(x => plainLen <= x));
  const blob = C.b64(await C.sealJson(S.me.encKey, S.acct, C.ACCOUNT));
  S.blobLen = blob.length;
  const wipe_blob = await wipeBlobFor(S.acct);
  S.wipeBig = wipe_blob.length > 10000;
  return { blob, wipe_blob };
}

// Zwei Geräte mit demselben Konto: Stände je Kanal zusammenführen statt
// überschreiben. Zähler nehmen den höheren Wert, Gelöschtes bleibt gelöscht,
// bei Einstellungen gewinnt die neuere Änderung.
function mergeChannel(l, r) {
  if (l.pend && !r.pend) { for (const k of Object.keys(l)) delete l[k]; Object.assign(l, r); return; }
  if (l.pend || r.pend) return;
  // Nummern: hinter allem weitermachen, was irgendein Gerät benutzt oder reserviert hat.
  l.sn = Math.max(l.sn || 0, r.sn || 0, r.sr || 0);
  l.cn = Math.max(l.cn || 0, r.cn || 0, r.cr || 0);
  l.sr = Math.max(l.sr || 0, r.sr || 0);
  l.cr = Math.max(l.cr || 0, r.cr || 0);
  l.rn = Math.max(l.rn || 0, r.rn || 0);
  l.rc = Math.max(l.rc || 0, r.rc || 0);
  l.cf = Math.max(l.cf || 0, r.cf || 0);
  for (const [k, base] of [["rp", "rn"], ["rpc", "rc"], ["ca", "rc"]]) {
    l[k] = Array.from(new Set([...(l[k] || []), ...(r[k] || [])])).filter(n => n >= l[base] - WINDOW_BACK).sort((a, b) => a - b);
  }
  if (!r.ib) delete l.ib;
  if (r.wrap && l.wrap && r.wrap.c !== l.wrap.c) {
    const lr = S.run[l.id];
    const lv = wrapVer(l), rv = wrapVer(r);
    const sameKey = r.wrap.s === l.wrap.s;
    // Bei gleichem Stand, aber verschiedenem Salz haben zwei Geräte gleichzeitig geändert:
    // Dann gilt überall das Päckchen mit dem größeren Salz.
    if (rv > lv || (rv === lv && !sameKey && r.wrap.s > l.wrap.s)) {
      // Auf einem anderen Gerät wurde das Passwort geändert, festgelegt oder entfernt:
      // Dessen Päckchen gilt. Der hier noch bekannte alte Schlüssel wird sofort vergessen,
      // damit nichts mehr mit ihm verpackt wird.
      l.wrap = r.wrap; l.wp = r.wp || 0;
      if (lr && (lr.pwKey || lr.kMsg)) {
        lr.kMsg = null; lr.kDel = null; lr.own = null; lr.ch = null; lr.pwKey = null; lr.ws = null; lr.chDirty = false;
        if (S.active === l.id) { try { closeChannel(false); } catch (e) {} toast("Das Passwort dieses Chat-Kanals wurde auf einem anderen Gerät geändert. Bitte neu öffnen."); }
      }
    } else if (rv === lv && sameKey) {
      if (lr && lr.ch && lr.pwKey) _wrapMerges.push([l.id, r.wrap]);          // hier geöffnet: je Kette den weiteren Stand nehmen
      else if ((r.wp || 0) > (l.wp || 0)) { l.wrap = r.wrap; l.wp = r.wp || 0; }   // hier gesperrt: das weitere Päckchen gilt
    }
  }
  { const seen = new Set(); l.pu = [...(l.pu || []), ...(r.pu || [])].filter(e => e && !seen.has(e.t) && seen.add(e.t)).slice(-300); }
  const run = S.run[l.id];
  const open = S.active === l.id && run && run.loaded;
  const newer = (r.rv || 0) > (l.rv || 0);
  if (newer) for (const k of ["name", "keep", "shots", "rq", "ro", "rv", "vf"]) l[k] = r[k];
  const lhv = l.hv || 0, rhv = r.hv || 0;
  if (rhv > lhv) {
    // Das andere Gerät hat den Kanal inzwischen geleert: Das gilt auch hier.
    l.hv = rhv;
    l.hist = l.keep ? (r.hist || "") : "";
    if (run) {
      if (S.active === l.id) { for (const m of run.msgs) dropMedia(l, m, false); run.msgs = []; _mergeRender = true; if (l.hist) _histMerges.push([l.id, l.hist]); }
      else run.loaded = false;
    }
    return;
  }
  if (!l.keep) { l.hist = ""; return; }
  if (rhv < lhv) return;                       // das andere Gerät kennt die Löschung noch nicht
  if (r.hist && r.hist !== l.hist) {
    // Verlauf: Ist der Chat hier gerade offen, werden beide Stände vereint.
    // Sonst gilt der Stand des anderen Geräts (dieses hat ihn nicht verändert).
    if (open) _histMerges.push([l.id, r.hist]);
    else { l.hist = r.hist; if (run) run.loaded = false; }
  }
}
let _mergeRender = false;
const _wrapMerges = [];
async function applyWrapMerges() {
  while (_wrapMerges.length) {
    const [id, wrap] = _wrapMerges.shift();
    const c = chan(id), r = c && S.run[id];
    if (!c || !r || !r.ch || !r.pwKey) continue;
    try {
      const plain = JSON.parse(C.fromUtf8(await C.open(r.pwKey, C.unb64(wrap.c))));
      if (plain && plain.ch && chainMerge(r.ch, plain.ch)) r.chDirty = true;
      else r.chDirty = true;      // eigener Stand ist der weitere: wieder zurückschreiben
    } catch (e) {}
  }
}

function mergeAccount(local, remote) {
  const gone = new Set([...remote.gone, ...local.gone]);
  const mine = new Map(local.ch.map(c => [c.id, c]));
  const out = [], seen = new Set();
  for (const c of local.ch) if (!gone.has(c.id)) { out.push(c); seen.add(c.id); }
  for (const rc of remote.ch) {
    if (gone.has(rc.id)) continue;
    if (seen.has(rc.id)) mergeChannel(mine.get(rc.id), rc);
    else out.push(rc);
  }
  for (const c of local.ch) if (gone.has(c.id)) dropRuntime(c.id);
  local.ch = out;
  local.gone = Array.from(gone).slice(-300);
  if ((remote.set.rv || 0) > (local.set.rv || 0)) local.set = remote.set;
  local.notes = Array.from(new Set([...remote.notes, ...local.notes])).slice(-20);
}
function dropRuntime(id) {
  if (S.active === id) { try { closeChannel(true); } catch (e) {} }
  const r = S.run[id];
  if (r) { freeUrls(r); for (const t of r.tags) S.expect.delete(t); }
  delete S.run[id];
}

// Alle Speichervorgänge laufen nacheinander.
let _saveChain = Promise.resolve(true);
let _saveWarned = false;
function saveAccount() { _saveChain = _saveChain.then(doSave, doSave); return _saveChain; }
async function doSave() {
  const sid = S.sid;
  if (!S.me || !S.acct) return false;
  let work = "";
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const blobs = await accountBlobs();
      const body = { ...blobs, expected_version: S.version, cv: CLIENT_VER };
      if (work) body.work = work;
      const r = await api("PUT", "/api/v2/account", { auth: true, keepalive: true, json: body });
      if (sid !== S.sid) return false;
      S.version = r.version;
      if (!_saveTimer) S.urgent = false;
      S.dirty = false;
      if (_saveWarned) { _saveWarned = false; setSync(""); }
      return true;
    } catch (e) {
      if (sid !== S.sid) return false;
      if (e.status === 426) { needReload(); break; }
      if (e.status === 428) {
        // Das Konto wächst in eine größere Stufe: einmalige Rechenaufgabe.
        await loadConfig();
        const bits = (S.work.account[S.blobClass] || 0) + (S.wipeBig ? (S.work.account_wipe_extra || 2) : 0);
        if (bits > 28) { setSync("Speichern gerade nicht möglich"); break; }
        work = await C.work(subject(S.me.id, "g", S.blobClass * 2 + (S.wipeBig ? 1 : 0)), bits);
        continue;
      }
      if (e.status !== 409) {
        if (String(e.message) === "too large") { setSync("Konto ist voll"); if (!_saveWarned) toast("Der Speicher für behaltene Verläufe ist voll. Bitte in einem Chat-Kanal „Verlauf nicht mehr behalten“ wählen.", "err"); _saveWarned = true; }
        break;
      }
      // Ein anderes Gerät hat gespeichert: Stand holen und zusammenführen.
      try {
        const r = await api("GET", "/api/v2/account", { auth: true });
        if (sid !== S.sid) return false;
        const remote = sanitizeAccount(await C.openJson(S.me.encKey, C.unb64(r.blob), C.ACCOUNT));
        mergeAccount(S.acct, remote);
        S.version = r.version;
        for (const c of S.acct.ch) runOf(c);
        await applyHistMerges();
        await applyWrapMerges();
        if (_mergeRender) { _mergeRender = false; renderChat(); }
        await rebuildExpect();
        renderList();
      } catch (e2) { break; }
    }
  }
  if (sid === S.sid) S.dirty = true;
  return false;
}
// Dringend: Dinge, die nicht verloren gehen dürfen (Einstellungen, Zustimmungen, Verlauf).
let _saveTimer = null;
function saveSoon() {
  S.dirty = true;
  S.urgent = true;
  if (_saveTimer) return;
  _saveTimer = setTimeout(() => { _saveTimer = null; saveAccount(); }, 700);
}
// Ruhig: Zähler und Kleinigkeiten. Sie gehen mit dem nächsten Hintergrund-Speichern
// mit, das ohnehin in unregelmäßigen Abständen läuft. So verrät der Zeitpunkt
// des Speicherns nicht, wann eine Nachricht kam oder ging.
function saveLazy() { S.dirty = true; }

// Legt ein leeres Konto an. L = die 16 geheimen Bytes hinter den 12 Wörtern,
// W = die 16 Bytes hinter den Löschwörtern dieses Kontos.
async function createAccount(L, W) {
  const ak = await C.accountKeys(L), wk = await C.wipeKeys(W);
  const box = await C.newExchangeKey();
  const acct = emptyAccount(wk.encKey, box.pub, await C.seal(wk.innerKey, C.utf8(JSON.stringify(box.privJwk))));
  // Für die Löschwörter hinterlegt: damit sich das Konto nach dem Löschen leer
  // wieder anlegen lässt. Öffnen kann das nur, wer die Löschwörter hat.
  acct.wl = C.b64(await C.seal(wk.innerKey, L));
  const blob = C.b64(await C.sealJson(ak.encKey, acct, C.ACCOUNT));
  const wipe_blob = await wipeBlobFor(acct);
  let r = null;
  for (let i = 0; i < 3 && !r; i++) {
    const work = await C.work(subject(ak.id, "a"), S.work.account[0] || 0);
    try { r = await api("POST", "/api/v2/account", { json: { id: ak.id, auth_hash: ak.authHash, wipe_hash: wk.wipeHash, blob, wipe_blob, work } }); }
    catch (e) { if (e.status !== 428 || i === 2) throw e; await loadConfig(); }
  }
  return { ak, acct, version: r.version };
}

async function doRegister() {
  await loadConfig();
  const L = C.rand(16), W = C.rand(16);
  const made = await createAccount(L, W);
  S.sid++;
  S.me = { id: made.ak.id, token: made.ak.token, encKey: made.ak.encKey };
  S.acct = made.acct;
  S.version = made.version;
  _pendingLogin = L;
  showWords(await C.bytesToWords(L), await C.bytesToWords(W));
}

async function doLogin(wordsText) {
  let L;
  try { L = await C.wordsToBytes(wordsText, 16); }
  catch (e) { throw new Error(wordError(e, 12)); }
  await loginWithBytes(L, true);
  // Angemeldet. Jetzt legt man seinen eigenen Code fest.
  _pendingLogin = L;
  showCode("set");
}

// Meldet mit den geheimen Bytes hinter den 12 Wörtern an. fromWords: nur dann
// werden die Wörter bei unbekanntem Konto auch als Löschwörter geprüft.
async function loginWithBytes(L, fromWords) {
  const ak = await C.accountKeys(L);
  S.sid++;
  S.me = { id: ak.id, token: ak.token, encKey: ak.encKey };
  let r = null;
  for (let round = 0; round < 2 && !r; round++) {
    try { r = await api("GET", "/api/v2/account", { auth: true, noLogout: true }); }
    catch (e) {
      if (e.status !== 401) { S.me = null; throw new Error(e.message || "Anmeldung nicht möglich"); }
      // Kein Konto zu diesen Wörtern. Sind es die Löschwörter eines Kontos, wird
      // jetzt alles unwiderruflich gelöscht, und es öffnet sich ein leeres Konto.
      let wiped = false;
      if (fromWords && round === 0) {
        // Kommt die Lösch-Anfrage nicht durch, darf das nicht wie "kein Konto"
        // aussehen: sonst glaubt man, es sei gelöscht, obwohl nichts passiert ist.
        try { wiped = await wipeWith(L); }
        catch (e2) { S.me = null; throw new Error("Keine Verbindung zum Server. Bitte noch einmal versuchen."); }
      }
      if (!wiped) {
        S.me = null;
        const err = new Error("Zu diesen Wörtern gibt es kein Konto.");
        err.gone = true;
        throw err;
      }
    }
  }
  S.acct = sanitizeAccount(await C.openJson(ak.encKey, C.unb64(r.blob), C.ACCOUNT));
  S.version = r.version;
  // Wurde die letzte Sitzung nicht sauber beendet, könnten reservierte Nummern
  // schon benutzt sein. Dann geht es hinter der Reservierung weiter.
  for (const c of S.acct.ch) { if (c.pend) continue; c.sn = Math.max(c.sn, c.sr); c.cn = Math.max(c.cn, c.cr); }
}

// =========================================================================
// EIGENER CODE
// Nach dem Anmelden legt man einen eigenen Code fest. Lädt man die Seite neu,
// bleibt man angemeldet und gibt nur diesen Code ein. Dafür liegt die Anmeldung
// verschlossen mit dem Code im Speicher dieses einen Browser-Fensters. Sie ist
// weg, sobald das Fenster geschlossen wird, man sich abmeldet oder der Code
// fünfmal falsch war. Sonst speichert chatmesh nichts auf dem Gerät.
// =========================================================================
const SESSION_KEY = "cm";
const CODE_MIN = 8, CODE_TRIES = 5;
let _pendingLogin = null, _codeMode = null;
function readSession() {
  try {
    const j = JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
    return j && typeof j.s === "string" && typeof j.c === "string" ? j : null;
  } catch (e) { return null; }
}
function clearSession() { try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {} }
async function storeSession(loginBytes, code) {
  const salt = C.rand(16);
  const key = await C.passwordKey(code, salt);
  sessionStorage.setItem(SESSION_KEY, JSON.stringify({ s: C.b64(salt), c: C.b64(await C.seal(key, loginBytes)), n: 0 }));
}
function showCode(mode) {
  _codeMode = mode;
  const set = mode === "set";
  $("#code-title").textContent = set ? "Lege deinen Code fest" : "Gib deinen Code ein";
  $("#code-info").textContent = set
    ? "Diesen Code wählst du selbst: mindestens 8 Zeichen, auch nur Zahlen sind möglich. Lädst du die Seite neu, bleibst du angemeldet und gibst nur diesen Code ein. Schließt du das Fenster oder meldest dich ab, brauchst du wieder deine 12 Wörter."
    : "Du bist noch angemeldet. Gib deinen Code ein, um weiterzumachen. Code vergessen? Dann auf „Abmelden“ tippen und mit deinen 12 Wörtern neu anmelden.";
  $("#code-repeat").hidden = !set;
  $("#code-submit").textContent = set ? "Weiter" : "Entsperren";
  $("#code-msg").textContent = "";
  const f = $("#form-code");
  f.code.value = ""; f.code2.value = "";
  show("code");
  setTimeout(() => { try { f.code.focus(); } catch (e) {} }, 50);
}
async function submitCode() {
  const f = $("#form-code"), msg = $("#code-msg"), btn = $("#code-submit");
  const code = f.code.value;
  if (btn.disabled) return;
  if (_codeMode === "set") {
    if (!_pendingLogin || !S.me) { logout(); return; }
    if (code.length < CODE_MIN) { msg.textContent = "Der Code braucht mindestens " + CODE_MIN + " Zeichen."; return; }
    if (code !== f.code2.value) { msg.textContent = "Die beiden Eingaben stimmen nicht überein."; return; }
    btn.disabled = true; msg.textContent = "Einen Moment …";
    const sid = S.sid, bytes = _pendingLogin;
    try { await storeSession(bytes, code); } catch (e) {}
    // Wurde inzwischen abgemeldet, darf nichts zurückbleiben.
    if (sid !== S.sid || !S.me) { clearSession(); btn.disabled = false; msg.textContent = ""; return; }
    _pendingLogin = null;
    f.code.value = ""; f.code2.value = "";
    btn.disabled = false; msg.textContent = "";
    await startSession();
    return;
  }
  const sess = readSession();
  if (!sess) { logout(); return; }
  btn.disabled = true; msg.textContent = "Wird geprüft …";
  let L = null;
  try { L = await C.open(await C.passwordKey(code, C.unb64(sess.s)), C.unb64(sess.c)); } catch (e) { L = null; }
  f.code.value = "";
  if (!L) {
    btn.disabled = false;
    sess.n = (Number(sess.n) || 0) + 1;
    if (sess.n >= CODE_TRIES) { logout("Der Code war zu oft falsch. Bitte melde dich mit deinen 12 Wörtern an."); return; }
    try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(sess)); } catch (e) {}
    const left = CODE_TRIES - sess.n;
    msg.textContent = "Falscher Code. Noch " + left + (left === 1 ? " Versuch." : " Versuche.");
    return;
  }
  if (sess.n) { sess.n = 0; try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(sess)); } catch (e) {} }
  try { await loginWithBytes(L, false); }
  catch (e) {
    btn.disabled = false;
    if (e.gone) { logout("Zu dieser Anmeldung gibt es kein Konto mehr."); return; }
    msg.textContent = e.message || "Keine Verbindung. Bitte noch einmal versuchen.";
    return;
  }
  btn.disabled = false; msg.textContent = "";
  await startSession();
}

function wordError(e, count) {
  const m = String(e && e.message || "");
  if (m === "count") return `Es müssen genau ${count} Wörter sein.`;
  if (m.startsWith("word:")) return `Das Wort „${m.slice(5)}“ gibt es in der Wortliste nicht. Bitte Schreibweise prüfen.`;
  if (m === "checksum") return "Die Wörter passen nicht zusammen. Bitte auf Tippfehler oder falsche Reihenfolge prüfen.";
  return "Die Wörter konnten nicht gelesen werden.";
}

// Unwiderrufliches Löschen mit den 12 Löschwörtern. Es gibt dafür keinen eigenen
// Knopf: Wer bei "Anmelden" die Löschwörter eingibt, löscht alles. Danach
// - gibt es das alte Konto weiter, aber leer (die alten 12 Wörter öffnen es),
// - öffnen auch die Löschwörter ein eigenes, leeres Konto,
// - verschwinden die Kanäle bei den Gegenübern wie bei einem gewöhnlichen Löschen,
// - werden liegengebliebene Blöcke der alten Kanäle vom Server entfernt.
// Auf dem Bildschirm sieht es aus wie eine normale Anmeldung in ein leeres Konto.
// Die Anfrage geht bei jeder fehlgeschlagenen Anmeldung raus, egal welche Wörter
// es waren. Gibt true zurück, wenn gelöscht wurde und ein leeres Konto bereitsteht.
async function wipeWith(W) {
  const wk = await C.wipeKeys(W);
  const r = await api("POST", "/api/v2/wipe", { json: { token: wk.token } });
  await loadConfig();
  if (!r.ok) {
    // Kein Treffer. Damit es von außen ähnlich aussieht wie ein echtes Löschen,
    // gehen auch hier ein, zwei Blöcke raus (Schein-Blöcke, die wieder verschwinden).
    try {
      const k = 1 + randInt(2);
      for (let i = 0; i < k; i++) {
        const tag = C.hex(C.rand(16)), token = C.hex(C.rand(16));
        if ((await pilePost(tag, C.rand(4124), token, 20)) === 200) queueDelete(tag, token, randBetween(20000, 120000));
      }
    } catch (e) {}
    return false;
  }
  let ready = false;
  try {
    const data = await C.openJson(wk.encKey, C.unb64(String(r.wipe_blob).replace(/\.+$/, "")), C.WIPE);
    // 1. Beide Konten leer neu anlegen: das alte (zu den alten 12 Wörtern) und
    //    eines zu den Löschwörtern. Keines hat danach noch nutzbare Löschwörter.
    if (data.l) {
      try {
        const oldL = await C.open(wk.innerKey, C.unb64(data.l));
        try { await createAccount(oldL, C.rand(16)); } catch (e) {}
      } catch (e) {}
    }
    try { await createAccount(W, C.rand(16)); ready = true; } catch (e) { ready = false; }
    // 2. Die Gegenüber benachrichtigen und Reste vom Server entfernen (im Hintergrund).
    (async () => {
      try {
        const priv = JSON.parse(C.fromUtf8(await C.open(wk.innerKey, C.unb64(data.q))));
        const pub = C.unb64(data.p);
        for (const entry of (data.e || [])) {
          try {
            const e = typeof entry === "string" ? { b: entry } : entry;
            const own = JSON.parse(C.fromUtf8(await C.boxOpen(priv, pub, C.unb64(e.b))));
            for (let i = 0; i < 5; i++) {
              let code = 0;
              // Für das Gegenüber sieht es aus wie ein gewöhnlich gelöschter Kanal.
              try { code = await postDissolve(own, "deleted"); } catch (e2) {}
              if (code === 200 || code === 409) break;
              await sleep(1500 * (i + 1));
            }
            if (own.kt && own.kd && (e.d === "a" || e.d === "b")) await removeLeftovers(own, e);
          } catch (e3) {}
        }
      } catch (e4) {}
    })();
  } catch (e) {}
  return ready;
}

// Entfernt liegengebliebene Blöcke eines gelöschten Kanals vom Server: eigene,
// die das Gegenüber noch nicht geöffnet hat, und fremde, die hier noch warteten.
async function removeLeftovers(own, e) {
  const kt = C.unb64(own.kt), kd = C.unb64(own.kd);
  const me = e.d, peer = me === "a" ? "b" : "a";
  const jobs = [];
  const add = async (dir, from, to) => {
    from = Math.max(0, Math.floor(from)); to = Math.max(from, Math.floor(to));
    const tags = await C.msgTags(kt, dir, from, to);
    for (let n = from; n < to; n++) jobs.push([tags[n - from], await C.msgDelToken(kd, dir, n)]);
  };
  await add(me, (e.s || 0) - 64, e.s || 0);
  await add(me + "c", (e.c || 0) - 64, e.c || 0);
  await add(peer, e.r || 0, (e.r || 0) + 64);
  await add(peer + "c", e.q || 0, (e.q || 0) + 64);
  let i = 0;
  const worker = async () => { while (i < jobs.length) { const [tag, token] = jobs[i++]; try { await pileDelete(tag, token); } catch (e2) {} } };
  await Promise.all([worker(), worker(), worker(), worker(), worker(), worker()]);
}

function showWords(login, wipe) {
  show("words");
  for (const [id, words] of [["#words-login", login], ["#words-wipe", wipe]]) {
    const grid = $(id);
    grid.textContent = "";
    words.split(" ").forEach((w, i) => {
      const d = el("div", "w");
      d.appendChild(el("span", "w-num", (i + 1) + "."));
      d.appendChild(el("span", "w-text", w));
      grid.appendChild(d);
    });
  }
  _backup = { login, wipe };
  $("#words-confirm").checked = false;
  $("#words-continue").disabled = true;
}
let _backup = null;
function downloadWords() {
  if (!_backup) return;
  const content = [
    "chatmesh - Konto-Sicherung", "=".repeat(60), "",
    "DEINE 12 WÖRTER (damit meldest du dich an):", "",
    _backup.login.split(" ").map((w, i) => `${String(i + 1).padStart(2, " ")}.  ${w}`).join("\n"), "",
    "FÜR DEN NOTFALL: LÖSCHWÖRTER (bei \"Anmelden\" eingeben = alles wird sofort unwiderruflich gelöscht, es öffnet sich ein leeres Konto):", "",
    _backup.wipe.split(" ").map((w, i) => `${String(i + 1).padStart(2, " ")}.  ${w}`).join("\n"), "",
    "=".repeat(60),
    "- Wer deine 12 Wörter hat, hat Zugriff auf dein Konto.",
    "- Wer die Löschwörter bei \"Anmelden\" eingibt, löscht alles: sofort, ohne Rückfrage.",
    "- Danach sind beide Konten leer. Es sieht aus wie eine normale Anmeldung.",
    "- Offline aufbewahren (Papier, USB-Stick). Niemals Cloud, niemals Foto.",
    "- Es gibt keine Wiederherstellung.",
  ].join("\n");
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url; a.download = "chatmesh-sicherung.txt";
  document.body.appendChild(a); a.click();
  setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 200);
}

function logout(message) {
  clearSession();
  _pendingLogin = null;
  try { closeChannel(true); } catch (e) {}
  S.sid++;
  for (const t of S.timers) clearTimeout(t);
  S.timers = new Set();
  if (_saveTimer) { clearTimeout(_saveTimer); _saveTimer = null; }
  for (const k of Object.keys(_histTimers)) { clearTimeout(_histTimers[k]); delete _histTimers[k]; }
  stopRecording(true);
  stopScan();
  for (const r of Object.values(S.run)) freeUrls(r);
  S.me = null; S.acct = null; S.version = 0; S.dirty = false; S.urgent = false; S.blobLen = 0;
  S.index = new Map(); S.indexN = 0; S.cursor = 0; S.synced = false; S.expect = new Map(); S.run = {}; S.active = null;
  _saveChain = Promise.resolve(true);
  _backup = null;
  for (const id of ["#chat-stream", "#chat-header", "#channel-list", "#notes", "#words-login", "#words-wipe"]) $(id).textContent = "";
  $("#msg-input").value = "";
  $$("textarea[name=words]").forEach(t => { t.value = ""; });
  { const f = $("#form-code"); if (f) { f.code.value = ""; f.code2.value = ""; } }
  $("#view-chat").classList.remove("peek-chat", "sidebar-collapsed");
  closeSheet();
  $$("#view-auth .tab").forEach(x => x.classList.toggle("active", x.dataset.tab === "login"));
  $$("#view-auth .auth-form").forEach(f => f.classList.toggle("active", f.id === "form-login"));
  document.title = APP_NAME;
  show("auth");
  $("#auth-msg").textContent = typeof message === "string" ? message : "";
}

async function startSession() {
  const sid = S.sid;
  for (const c of S.acct.ch) runOf(c);
  show("chat");
  renderList();
  renderChat();
  setSync("Synchronisiere …");
  await loadConfig();
  // Erst ausrechnen, welche Marken uns gehören, dann das Verzeichnis laden.
  await rebuildExpect();
  if (sid !== S.sid) return;
  try { await pileSync(true); } catch (e) {}
  if (sid !== S.sid) return;
  S.synced = true;
  setSync("");
  renderList();
  startLoops();
}
// Fassung dieser App. Der Server nimmt Speicherungen älterer Fassungen nicht mehr an,
// damit ein altes, noch offenes Fenster keine neueren Angaben überschreibt.
const CLIENT_VER = 2;
let _reloadTold = false;
// Der Server verlangt eine neuere Fassung: Ab hier würde nichts mehr gespeichert.
// Deshalb wird die Bedienung angehalten, bis die Seite neu geladen ist. Die
// Anmeldung bleibt dabei erhalten, es wird nur der eigene Code verlangt.
function needReload() {
  if (_reloadTold) return;
  _reloadTold = true;
  try { setSync("Bitte Seite neu laden"); } catch (e) {}
  const bg = el("div", "reload-note");
  bg.setAttribute("role", "alertdialog");
  const box = el("div", "reload-box");
  box.appendChild(el("div", "reload-title", "Neue Fassung von chatmesh"));
  box.appendChild(el("p", "", "Bitte lade die Seite neu, damit weiter alles richtig gespeichert wird. Du bleibst angemeldet und gibst nur deinen Code ein."));
  const b = el("button", "primary", "Seite neu laden");
  b.type = "button";
  b.addEventListener("click", () => location.reload());
  box.appendChild(b);
  bg.appendChild(box);
  document.body.appendChild(bg);
  setTimeout(() => { try { b.focus(); } catch (e) {} }, 50);
}
function setSync(text) { const e = $("#sync-state"); if (e) e.textContent = text; }

// =========================================================================
// KANÄLE: Laufzeitdaten und Erwartungen
// =========================================================================
function chan(id) { return S.acct ? S.acct.ch.find(c => c.id === id) : null; }
function runOf(c) {
  // kMsg/kDel/own: nur nach Eingabe des Kanal-Passworts vorhanden.
  // wait: wartende Nachrichten, cwait: wartende stille Steuerzeichen.
  // ps: Geheimnisse einer offenen Einladung (nur in dieser Sitzung).
  // ok: bis zu welcher Nummer diese Sitzung bestätigt reserviert hat (je Spur).
  // ch: die Schlüssel-Ketten (je Richtung und Spur), pwKey: zum Zurückschreiben der Ketten.
  if (!S.run[c.id]) S.run[c.id] = { kMsg: null, kDel: null, own: null, ch: null, pwKey: null, chDirty: false, rewrapP: null, ps: null, ok: {}, msgs: [], wait: new Map(), cwait: new Map(), top: {}, seen: new Set(), urls: [], tags: [], loaded: false, flush: null };
  return S.run[c.id];
}
const peerDir = (c) => c.dir === "a" ? "b" : "a";
const unlocked = (c) => !!(S.run[c.id] && S.run[c.id].kMsg);

// Rechnet für einen Kanal aus, unter welchen Marken als Nächstes etwas für uns
// liegen kann, und merkt sie vor. Schon verarbeitete Nummern werden nie wieder
// angenommen: ein alter Block lässt sich nicht noch einmal unterschieben.
async function refreshExpect(c) {
  const r = runOf(c);
  // Erst alles ausrechnen, dann in einem Zug tauschen: So gibt es keinen Augenblick,
  // in dem ein gerade abgeholter Block zu keiner Erwartung passt.
  const next = [];
  if (c.pend) {
    if (!c.pend.ans) next.push([c.pend.tb, { id: c.id, kind: "ans" }]);
  } else {
    const kt = C.unb64(c.kt), p = peerDir(c);
    const tops = {};
    for (const [lane, base, map, done] of [["", c.rn || 0, r.wait, c.rp], ["c", c.rc || 0, r.cwait, c.rpc]]) {
      let top = base;
      for (const k of map.keys()) if (k + 1 > top) top = k + 1;
      const from = Math.max(0, base - WINDOW_BACK), to = top + WINDOW_AHEAD;
      tops[lane] = to;
      const tags = await C.msgTags(kt, p + lane, from, to);
      next.push({ lane, from, to, tags });
    }
    if (chan(c.id) !== c || c.pend) return;        // inzwischen gelöscht oder ersetzt
    const out = [];
    for (const g of next) {
      const map = g.lane ? r.cwait : r.wait;
      const used = new Set(g.lane ? c.rpc : c.rp);
      r.top[g.lane] = tops[g.lane];
      for (let n = g.from; n < g.to; n++) {
        if (map.has(n) || used.has(n)) continue;
        out.push([g.tags[n - g.from], { id: c.id, kind: "msg", lane: g.lane, n }]);
      }
    }
    out.push([c.pd.t, { id: c.id, kind: "dis" }]);
    next.length = 0;
    for (const e of out) next.push(e);
  }
  if (chan(c.id) !== c) return;
  for (const t of r.tags) S.expect.delete(t);
  r.tags = [];
  for (const [tag, info] of next) { S.expect.set(tag, info); r.tags.push(tag); }
}
async function rebuildExpect() {
  if (!S.acct) return;
  const sid = S.sid;
  for (const c of [...S.acct.ch]) { await refreshExpect(c); if (sid !== S.sid || !S.acct) return; }
  // Erwartungen von Chat-Kanälen, die es nicht mehr gibt, entfernen.
  const ids = new Set(S.acct.ch.map(c => c.id));
  for (const [tag, info] of S.expect) if (!ids.has(info.id)) S.expect.delete(tag);
  await matchPile();
}
// Vergleicht die vorgemerkten Marken mit dem Verzeichnis. Steht der Anfang einer
// eigenen Marke darin, wird genau dieser Block geholt: jeder in einem eigenen Abruf
// und streng in der Reihenfolge, in der die Blöcke eingeliefert wurden. So kommen
// Nachrichten und Lösch-Aufträge in derselben Folge an, in der sie gesendet wurden.
let _matching = null, _matchAgain = false, _matchRetry = false;
async function matchPile() {
  const sid = S.sid;
  if (_matching === sid) { _matchAgain = true; return; }
  _matching = sid;
  try {
    for (let pass = 0; pass < 200; pass++) {
      _matchAgain = false;
      _matchRetry = false;
      const hits = [];
      for (const tag of S.expect.keys()) { const at = S.index.get(tag.slice(0, PFX)); if (at !== undefined) hits.push([at, tag]); }
      hits.sort((x, y) => x[0] - y[0]);
      let progress = false;
      // Wenige Abrufe laufen gleichzeitig, verarbeitet wird trotzdem streng der Reihe nach.
      for (let i = 0; i < hits.length; i += FETCH_MAX) {
        if (sid !== S.sid || !S.me) return;
        const part = hits.slice(i, i + FETCH_MAX).map(h => h[1]).filter(tag => S.expect.has(tag));
        const res = await Promise.all(part.map(tag => fetchBlocks([tag]).then(m => ({ block: m.get(tag) }), () => ({ failed: true }))));
        if (sid !== S.sid || !S.me) return;
        for (let k = 0; k < part.length; k++) {
          const tag = part[k];
          // Scheitert ein Abruf, wird hier angehalten und beim nächsten Mal an derselben Stelle
          // weitergemacht: Spätere Blöcke dürfen frühere nicht überholen.
          if (res[k].failed) { _matchRetry = true; _matchAgain = false; return; }
          const block = res[k].block;
          // Nichts da: Der Block wurde inzwischen gelöscht, oder ein fremder Eintrag fing zufällig gleich an.
          if (!block) { S.index.delete(tag.slice(0, PFX)); continue; }
          const info = S.expect.get(tag);
          if (!info) continue;                               // wird nicht mehr erwartet
          await onMatch(tag, info, block);
          progress = true;
          if (sid !== S.sid || !S.me) return;
        }
      }
      // Nach Treffern rückt das Fenster der erwarteten Marken weiter: noch einmal vergleichen.
      if (!progress && !_matchAgain) break;
    }
  } finally {
    if (_matching === sid) _matching = null;
    if (_matchAgain) _matchRetry = true;
  }
}

// =========================================================================
// VERZEICHNIS UND ABRUF
// Alle Apps laden dasselbe Verzeichnis: je Block nur die ersten 5 Bytes seiner
// Marke. Daran erkennt jede App für sich, ob etwas für sie da ist, ohne dass der
// Server erfährt, worauf sie wartet. Den Block selbst gibt der Server nur gegen
// die volle Marke heraus. Fremde Blöcke kann deshalb niemand herunterladen.
// =========================================================================
function parseBlocks(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const out = new Map();
  let o = 0;
  while (o + 20 <= buf.length) {
    const len = dv.getUint32(o + 16);
    if (o + 20 + len > buf.length) break;
    out.set(C.hex(buf.subarray(o, o + 16)), buf.slice(o + 20, o + 20 + len));
    o += 20 + len;
  }
  return out;
}
// Holt Blöcke zu genau diesen Marken. Liefert Marke -> Block; was es nicht gibt, fehlt.
// Jede Marke geht in einem eigenen Abruf: So sehen alle Abrufe gleich aus, auch die der
// Schein-Blöcke, und der Server erfährt nicht, welche Blöcke zusammengehören.
async function fetchBlocks(tags) {
  const out = new Map();
  for (const tag of tags) {
    const resp = await api("POST", "/api/v2/pile/fetch", { raw: true, timeout: 30000, json: { tags: [tag] } });
    let buf;
    try { buf = new Uint8Array(await resp.arrayBuffer()); } finally { if (resp.__stop) clearTimeout(resp.__stop); }
    for (const [t, block] of parseBlocks(buf)) if (t === tag) out.set(t, block);
  }
  return out;
}
function pileDrop(tag) { S.index.delete(tag.slice(0, PFX)); }
let _syncing = null, _indexFloor = 0;
async function pileSync(initial) {
  const sid = S.sid;
  if (_syncing === sid || !S.me) return;
  _syncing = sid;
  let fresh = false;
  const fromZero = S.cursor === 0;
  try {
    for (let round = 0; round < 400; round++) {
      const resp = await api("GET", "/api/v2/pile/index?since=" + S.cursor, { raw: true, timeout: 30000 });
      const state = String(resp.headers.get("X-Pile") || "ende:" + S.cursor).split(":");
      let buf;
      try { buf = new Uint8Array(await resp.arrayBuffer()); } finally { if (resp.__stop) clearTimeout(resp.__stop); }
      if (sid !== S.sid) return;
      const step = PFX / 2;
      if (buf.length % step || buf.length > INDEX_MAX * step) throw new Error("Verzeichnis ungültig");
      for (let o = 0; o + step <= buf.length; o += step) {
        const p = C.hex(buf.subarray(o, o + step));
        if (!S.index.has(p)) S.index.set(p, S.indexN++);
        fresh = true;
      }
      const last = Number(state[1]);
      if (Number.isFinite(last) && last > S.cursor) S.cursor = last;
      if (state[0] !== "weiter") break;
    }
    if (fromZero) _indexFloor = S.index.size;
  } finally { if (_syncing === sid) _syncing = null; }
  if (initial) { matchPile().catch(() => {}); }
  else if (fresh || _matchRetry) await matchPile();
  // Arbeitsspeicher begrenzen: Im Lauf einer langen Sitzung sammeln sich Einträge längst
  // gelöschter Blöcke. Dann wird das Verzeichnis einmal frisch geholt.
  if (sid === S.sid && S.me && S.index.size > Math.max(LIM.keep, _indexFloor * 2)) { S.index = new Map(); S.indexN = 0; S.cursor = 0; }
}
// Fragt gezielt nach bestimmten Marken (für das Einlösen eines Einmal-Schlüssels).
// Verändert nichts am eigenen Stand.
async function scanFor(tags) {
  const found = {};
  for (const [tag, block] of await fetchBlocks(tags)) found[tag] = block;
  return found;
}

async function onMatch(tag, info, block) {
  const c = chan(info.id);
  S.expect.delete(tag);
  pileDrop(tag);
  if (!c) return;
  const r = runOf(c);
  if (info.kind === "ans") {
    if (!c.pend) return;
    if (c.pend.exp <= nowSec()) { expireInvites(); return; }
    let ps = r.ps;
    if (!ps && noPw(c)) { try { ps = await unsealPending(c, ""); } catch (e) { ps = null; } }
    if (!c.pend) return;
    if (ps) await completeInvite(c, block, ps);
    else { c.pend.ans = C.b64(block); saveSoon(); renderList(); toast("Jemand ist „" + c.name + "“ beigetreten. " + (noPw(c) ? "Chat-Kanal antippen zum Verbinden." : "Chat-Kanal antippen und Passwort eingeben."), "ok"); }
    return;
  }
  if (info.kind === "dis") {
    try {
      const body = await C.openJson(C.unb64(c.pd.k), block, C.BLOCK);
      queueDelete(tag, c.pd.d);
      dissolveLocal(c, String(body.r || "deleted"), false);
    } catch (e) { await refreshExpect(c); }
    return;
  }
  // Nachricht oder Steuerzeichen: bleibt verschlossen liegen, bis der Chat geöffnet wird.
  (info.lane ? r.cwait : r.wait).set(info.n, block);
  if (!info.lane) { r.arr = r.arr || new Map(); r.arr.set(info.n, Date.now()); }
  if (info.n + 32 >= (r.top[info.lane] || 0)) await refreshExpect(c);
  if (S.active === c.id && r.kMsg) await processWaiting(c);
  else renderList();
}

// Öffnet alle wartenden Blöcke eines Kanals (nur wenn der Chat offen ist),
// löscht sie sofort vom Server und zeigt sie an.
let _processing = false;
async function processWaiting(c) {
  const r = runOf(c);
  if (_processing || !r.kMsg || S.active !== c.id) return;
  _processing = true;
  const sid = S.sid, kMsg = r.kMsg, kDel = r.kDel, ch = r.ch;
  const alive = () => sid === S.sid && S.active === c.id && r.kMsg === kMsg;
  try {
    const p = peerDir(c), kt = C.unb64(c.kt);
    const seenIds = [];
    const jobs = [];
    let advanced = false;
    // Wartende Lösch-Aufträge zuerst: Der Kanal wird geleert, bevor neue Nachrichten
    // geöffnet werden. So bleibt, was NACH dem Löschen gesendet wurde.
    await applyPendingClear(c, kMsg);
    if (!alive()) return;
    // Erst die Nachrichten, dann die stillen Steuerzeichen.
    for (const [lane, map, key, doneKey] of [["", r.wait, "rn", "rp"], ["c", r.cwait, "rc", "rpc"]]) {
      while (map.size && alive()) {
        const n = Math.min(...map.keys());
        const block = map.get(n);
        let body = null;
        try { const mk = await chainPeek(ch[p + lane], n); body = mk ? await C.openJson(mk, block, C.BLOCK) : null; } catch (e) { body = null; }
        if (!alive()) break;                 // Chat inzwischen verlassen: Block bleibt verschlossen liegen
        map.delete(n);
        if (!body || typeof body !== "object") {
          // Nicht zu öffnen (untergeschoben oder beschädigt): Nur diese eine Nummer
          // wird gesperrt. Zähler und Schlüssel-Kette rücken dadurch NICHT vor.
          c[doneKey] = (c[doneKey] || []).filter(x => x !== n);
          c[doneKey].push(n);
          if (c[doneKey].length > WINDOW_BACK * 2) c[doneKey] = c[doneKey].slice(-WINDOW_BACK * 2);
          advanced = true;
          saveLazy();
          continue;
        }
        // Schlüssel dieser Nachricht verbrauchen: Die Kette rückt weiter, der alte Stand ist weg.
        try { await chainUse(ch[p + lane], n, true); r.chDirty = true; } catch (e) {}
        // Nummer als verarbeitet merken: sie wird nie wieder angenommen.
        if (n + 1 > (c[key] || 0)) c[key] = n + 1;
        c[doneKey] = (c[doneKey] || []).filter(x => x !== n && x >= c[key] - WINDOW_BACK);
        c[doneKey].push(n);
        advanced = true;
        // Einzel-Schlüssel, die nicht mehr gebraucht werden können, sofort wegwerfen.
        if (chainPrune(ch[p + lane], Math.max(c[key] - WINDOW_BACK, lane ? 0 : (c.cf || 0)), c[doneKey])) r.chDirty = true;
        jobs.push([p + lane, n]);
        if (!lane && n < (c.cf || 0)) {            // vom Gegenüber gelöscht (auch wenn sie verspätet ankommt)
          if (body.t === "m" && body.a) { const a = cleanAtt(body.a); if (a) dropAttachment(a.t); }
          continue;
        }
        if (!lane && r.arr) { body.__arr = r.arr.get(n); r.arr.delete(n); }
        const shown = await handleIncoming(c, body);
        if (shown) seenIds.push(shown);
        // Wurde der Chat genau in diesem Augenblick verlassen, bleibt nichts sichtbar zurück.
        if (!alive() && !c.keep) { r.msgs = []; break; }
      }
    }
    if (jobs.length) {
      // Erst im Konto merken, dass diese Nummern verarbeitet sind, dann sofort vom
      // Server löschen. So lässt sich ein gelesener Block nie wieder unterschieben.
      saveAccount().catch(() => false).then(async () => {
        for (const [d, n] of jobs) { try { queueDelete(await C.msgTag(kt, d, n), await C.msgDelToken(kDel, d, n)); } catch (e) {} }
      });
    }
    if (advanced && c.ib) dropAnswerBlock(c);
    if (advanced) { await refreshExpect(c); await matchPile(); }
    if (seenIds.length && alive()) sendObj(c, { t: "seen", ids: seenIds.slice(0, 200) }, "c").catch(() => {});
    renderList();
    renderChat();
  } finally { _processing = false; }
  if ((r.wait.size || r.cwait.size) && S.active === c.id && r.kMsg) processWaiting(c);
}

// =========================================================================
// EINGEHENDES
// =========================================================================
function clampView(v) { v = Math.floor(Number(v)); return Number.isFinite(v) ? Math.max(VIEW_MIN, Math.min(VIEW_MAX, v)) : VIEW_DEFAULT; }
function safeName(n) {
  let s = typeof n === "string" ? n : "";
  s = s.replace(/[​-‏‪-‮⁦-⁩﻿]/g, "");
  s = s.replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, "_").replace(/^\.+/, "").trim().slice(0, 120);
  return s || "datei";
}
function cleanAtt(a) {
  if (!a || typeof a !== "object") return null;
  if (typeof a.t !== "string" || !/^[0-9a-f]{32}$/.test(a.t) || typeof a.k !== "string") return null;
  return { t: a.t, k: a.k.slice(0, 64), m: typeof a.m === "string" ? a.m.slice(0, 40) : "", n: safeName(a.n), s: Number.isFinite(a.s) ? Math.floor(a.s) : 0 };
}
const bump = (c) => { c.rv = (c.rv || 0) + 1; };

async function handleIncoming(c, body) {
  const r = runOf(c);
  const t = body.t;
  if (t === "m") {
    const id = typeof body.i === "string" && body.i.length >= 6 && body.i.length <= 32 ? "r" + body.i : null;
    if (!id || r.seen.has(id) || r.msgs.some(m => m.i === id)) return null;
    if (r.seen.size > 5000) r.seen.clear();
    r.seen.add(id);
    const kind = ["image", "video", "voice", "file"].includes(body.k) ? body.k : "text";
    // Vom Absender nur bis zu einem Zeitpunkt gültig, solange ungeöffnet: danach wird sie nie gezeigt.
    // Geprüft wird zweifach: nach der Uhr (mit etwas Spielraum für falsch gehende Uhren)
    // und nach der Zeit, die der Block schon hier auf dem Gerät gewartet hat.
    const waited = Number.isFinite(body.__arr) ? (Date.now() - body.__arr) / 1000 : 0;
    const lateByClock = Number.isFinite(body.xu) && body.xu > 0 && nowSec() > body.xu + CLOCK_SLACK;
    const lateByWait = Number.isFinite(body.xd) && body.xd > 0 && waited > body.xd;
    // Lag der Block schon fast die ganze Frist hier und ist sie nach der Uhr vorbei, gilt er ebenfalls als abgelaufen.
    const lateNear = Number.isFinite(body.xd) && body.xd > 0 && waited > body.xd - 5 && Number.isFinite(body.xu) && body.xu > 0 && nowSec() > body.xu;
    if (lateByClock || lateByWait || lateNear) {
      if (kind !== "text") { const gone = cleanAtt(body.a); if (gone) dropAttachment(gone.t); }
      return null;
    }
    const m = { i: id, me: 0, k: kind, x: kind === "text" ? String(body.x || "").slice(0, 60000) : "", vs: clampView(body.vs) };
    if (kind !== "text") { m.a = cleanAtt(body.a); if (!m.a) return null; }
    if (!c.keep) m.exp = Date.now() + m.vs * 1000;       // Zeit läuft ab dem Öffnen
    r.msgs.push(m);
    if (kind !== "text") fetchMedia(c, m);
    if (c.keep) saveHistorySoon(c);
    return body.i;
  }
  if (t === "seen") {
    const ids = new Set((Array.isArray(body.ids) ? body.ids : []).filter(x => typeof x === "string"));
    for (const m of r.msgs) if (m.me && ids.has(m.i)) m.st = "seen";
    if (c.pu && c.pu.length) { c.pu = c.pu.filter(e => !ids.has(e.i)); saveLazy(); }     // geöffnet: Frist erledigt
    if (c.keep) saveHistorySoon(c);
    return null;
  }
  if (t === "del") {
    const ids = new Set((Array.isArray(body.ids) ? body.ids : []).filter(x => typeof x === "string").slice(0, 500));
    // Kennungen des Gegenübers stehen bei uns mit "r" davor, unsere eigenen ohne.
    const before = r.msgs.length;
    r.msgs = r.msgs.filter(m => {
      const hit = m.me ? ids.has(m.i) : ids.has(m.i.slice(1));
      if (hit) dropMedia(c, m, true);
      return !hit;
    });
    if (r.msgs.length !== before && c.keep) saveHistorySoon(c);
    return null;
  }
  if (t === "clr") {
    // Geleert wurde schon vor dem Öffnen der Nachrichten (applyPendingClear).
    toast("Dein Gegenüber hat alle Nachrichten in diesem Chat-Kanal gelöscht.");
    return null;
  }
  if (t === "req" && (body.k === "keep" || body.k === "shots")) {
    if (c[body.k]) return null;                           // schon eingeschaltet
    if (!c.rq.includes(body.k)) c.rq.push(body.k);
    bump(c);
    saveSoon();
    if (S.active === c.id) askRequest(c);
    return null;
  }
  if (t === "ans" && (body.k === "keep" || body.k === "shots")) {
    // Gilt nur, wenn wir selbst danach gefragt haben.
    if (!c.ro.includes(body.k)) return null;
    c.ro = c.ro.filter(x => x !== body.k);
    if (body.y) {
      c[body.k] = 1;
      if (body.k === "keep") { for (const m of r.msgs) delete m.exp; if (S.active === c.id) r.loaded = true; saveHistorySoon(c); }
      toast(body.k === "keep" ? "Dein Gegenüber stimmt zu: Verlauf wird behalten." : "Dein Gegenüber stimmt zu: Screenshots sind erlaubt.", "ok");
    } else toast(body.k === "keep" ? "Dein Gegenüber möchte den Verlauf nicht behalten." : "Dein Gegenüber möchte Screenshots nicht erlauben.");
    bump(c);
    saveSoon();
    return null;
  }
  if (t === "set" && (body.k === "keep" || body.k === "shots") && !body.v) {
    setMode(c, body.k, 0);
    return null;
  }
  return null;
}

function setMode(c, kind, value) {
  const r = runOf(c);
  c[kind] = value ? 1 : 0;
  if (kind === "keep" && !value) {
    c.hist = "";
    const view = S.acct.set.view;
    for (const m of r.msgs) if (!m.exp) m.exp = Date.now() + (m.vs || view) * 1000;
  }
  if (kind === "keep" && value) { for (const m of r.msgs) delete m.exp; if (S.active === c.id) r.loaded = true; }
  bump(c);
  saveSoon();
  if (S.active === c.id) renderChat();
}

// =========================================================================
// SENDEN
// =========================================================================
// Nummern werden vor der Benutzung im Konto reserviert, je Spur und in kleinen
// Schritten. Benutzt wird eine Nummer erst, wenn die Reservierung wirklich
// gespeichert ist. So wird nach einem Absturz oder mit zwei Geräten nie eine
// Nummer zweimal vergeben.
const _reserving = {};
function reserveNumbers(c, key) {
  const rkey = key === "sn" ? "sr" : "cr", slot = c.id + key;
  if (!_reserving[slot]) {
    _reserving[slot] = (async () => {
      try {
        c[rkey] = Math.max(c[rkey] || 0, c[key] || 0) + RESERVE;
        if (!(await saveAccount())) throw new ApiError("Keine Verbindung zum Server", 0);
        // Nach dem Speichern gilt, was im Konto steht (ein anderes Gerät kann
        // inzwischen weiter sein: dann ist c[key] schon dahinter gesetzt).
        if (chan(c.id) === c) runOf(c).ok[key] = c[rkey];
      } finally { delete _reserving[slot]; }
    })();
  }
  return _reserving[slot];
}

// Verschließt einen Inhalt und legt ihn als Block auf dem Server ab.
// lane "" = Nachricht, lane "c" = stilles Steuerzeichen (gelesen, gelöscht, Antwort).
// Gibt die Nummer zurück, unter der er liegt.
async function sendObj(c, obj, lane = "") {
  const r = runOf(c);
  const kMsg = r.kMsg, kDel = r.kDel, ch = r.ch;
  if (!kMsg || !ch) throw new Error("Chat-Kanal ist gesperrt");
  const sid = S.sid;
  const key = lane ? "cn" : "sn";
  const kt = C.unb64(c.kt), dir = c.dir + lane;
  for (let attempt = 0; attempt < 8; attempt++) {
    while ((c[key] || 0) >= (r.ok[key] || 0)) { await reserveNumbers(c, key); if (sid !== S.sid) throw new Error("abgemeldet"); }
    const n = c[key] || 0;
    c[key] = n + 1;
    saveLazy();
    const mk = await chainUse(ch[dir], n, false);
    if (!mk) throw new Error("Senden nicht möglich. Bitte den Chat-Kanal schließen und neu öffnen.");
    r.chDirty = true;
    const block = await C.sealJson(mk, obj, C.BLOCK);
    const code = await pilePost(await C.msgTag(kt, dir, n), block, await C.msgDelToken(kDel, dir, n));
    if (sid !== S.sid) throw new Error("abgemeldet");
    if (code === 200) return n;
    if (code !== 409) throw new ApiError(code === 507 ? "Der Server ist gerade voll." : (code === 429 || code === 428 ? "Der Server ist gerade überlastet, bitte kurz warten." : "Senden nicht möglich"), code);
  }
  throw new Error("Senden nicht möglich");
}

function newId() { return C.b64(C.rand(9)); }

function sendText(c, text) {
  const r = runOf(c);
  const vs = S.acct.set.view;
  const m = { i: newId(), me: 1, k: "text", x: text, vs, st: "sending" };
  const obj = { t: "m", i: m.i, x: text, vs };
  if (S.acct.set.unread > 0) obj.xu = 1;      // ungeöffnet nur bis zu einer Frist gültig (wird beim Senden gesetzt)
  if (!C.fitsJson(obj, C.BLOCK)) { toast("Die Nachricht ist zu lang.", "err"); return false; }
  if (!c.keep) m.exp = Date.now() + vs * 1000;
  r.msgs.push(m);                       // sofort anzeigen, das Senden läuft im Hintergrund
  renderChat(true);
  deliver(c, m, obj, true);
  return true;
}

async function deliver(c, m, obj, canRetry) {
  const r = runOf(c);
  const kDel = r.kDel, kt = C.unb64(c.kt);       // jetzt festhalten: der Chat-Kanal kann gleich gesperrt werden
  // Frist für "ungeöffnet": beginnt mit dem Senden (auch beim Wiederholen neu).
  if (obj.xu) {
    obj.xd = S.acct.set.unread > 0 ? S.acct.set.unread : UNREAD_MIN;
    obj.xu = nowSec() + obj.xd;
  }
  try {
    m.n = await sendObj(c, obj);
    m.st = "sent";
    delete m.retry;
    const tag = kDel ? await C.msgTag(kt, c.dir, m.n) : null;
    const del = kDel ? await C.msgDelToken(kDel, c.dir, m.n) : null;
    if (m.cancel) {
      // Während des Sendens wurde "bei beiden löschen" gewählt: sofort zurückholen.
      if (tag) queueDelete(tag, del);
      if (obj.a && obj.a.t) dropAttachment(obj.a.t);
      sendObj(c, { t: "del", ids: [m.i] }, "c").catch(() => {});
      return;
    }
    // Frist vormerken: Marke und Lösch-Geheimnis dieses einen Blocks, damit er nach
    // Ablauf vom Server entfernt wird, auch wenn der Kanal dann gesperrt ist.
    if (obj.xu && tag) {
      const e = { t: tag, d: del, x: obj.xu, i: m.i };
      if (obj.a && obj.a.t) e.a = obj.a.t;
      c.pu = [...(c.pu || []), e].slice(-300);
      saveLazy();
    }
    if (c.keep) saveHistorySoon(c);
  } catch (e) {
    if (m.cancel) return;
    m.st = "failed";
    if (canRetry) m.retry = obj;
    if (S.me) toast("Nicht gesendet: " + (e.message || "Fehler") + (canRetry ? " Antippen zum Wiederholen." : ""), "err");
  }
  if (S.active === c.id && r.msgs.includes(m)) renderChat();
}

async function uploadAttachment(sealed) {
  const index = C.FILE_SIZES.indexOf(sealed.byteLength);
  if (index < 0) throw new Error("Die Datei konnte nicht verarbeitet werden.");
  const token = C.hex(C.rand(16));
  for (let i = 0; i < 3; i++) {
    const work = await C.work(subject(token, "u", index), S.work.upload[index] || 0);
    const fd = new FormData();
    fd.append("file", new File([sealed], "block.bin", { type: "application/octet-stream" }));
    try { await api("POST", "/api/attachments", { body: fd, headers: { "x-work": token + "." + index + "." + work } }); return token; }
    catch (e) { if (e.status !== 428 || i === 2) throw e; await loadConfig(); }
  }
  throw new Error("Hochladen nicht möglich");
}
const dropAttachment = (token) => api("DELETE", "/api/attachments/" + token).catch(() => {});

let _uploads = 0;
async function sendMedia(c, file, kind, name) {
  _uploads++;
  try { return await sendMediaInner(c, file, kind, name); }
  finally { _uploads--; }
}
async function sendMediaInner(c, file, kind, name) {
  const r = runOf(c);
  const sid = S.sid, kMsg = r.kMsg;
  const here = () => sid === S.sid && S.active === c.id && r.kMsg && r.kMsg === kMsg;
  if (file.size > 16 * 1024 * 1024 - 64) throw new Error("Die Datei ist zu groß (höchstens 16 MB).");
  toast("Verschlüsseln und senden …");
  // Zusatzangaben (Ort, Gerät, Aufnahmezeit) entfernen, bevor etwas das Gerät verlässt.
  let clean;
  try { clean = kind === "file" ? { bytes: new Uint8Array(await file.arrayBuffer()), mime: "application/octet-stream" } : await window.CMMedia.cleanFile(file, kind); }
  catch (e) { throw new Error("Die Datei konnte nicht verarbeitet werden."); }
  if (clean.bytes.byteLength > 16 * 1024 * 1024 - 64) throw new Error("Die Datei ist zu groß (höchstens 16 MB).");
  const enc = await C.encryptFile(clean.bytes);
  if (!here()) return;
  const token = await uploadAttachment(enc.data);
  // Wurde der Chat währenddessen verlassen, wird nichts gesendet und nichts angezeigt.
  if (!here()) { dropAttachment(token); return; }
  const vs = S.acct.set.view;
  const a = { t: token, k: C.b64(enc.key), m: clean.mime, n: kind === "file" ? safeName(name) : "", s: clean.bytes.byteLength };
  const m = { i: newId(), me: 1, k: kind, x: "", a, vs, st: "sending" };
  if (!c.keep) m.exp = Date.now() + vs * 1000;
  m.url = URL.createObjectURL(new Blob([clean.bytes], { type: kind === "file" ? "application/octet-stream" : clean.mime }));
  r.urls.push(m.url);
  r.msgs.push(m);
  renderChat(true);
  const mobj = { t: "m", i: m.i, k: kind, a, vs };
  if (S.acct.set.unread > 0) mobj.xu = 1;
  await deliver(c, m, mobj, false);
  if (m.st === "failed") dropAttachment(token);
}

// =========================================================================
// MEDIEN ANZEIGEN
// =========================================================================
function freeUrls(r) { for (const u of r.urls) { try { URL.revokeObjectURL(u); } catch (e) {} } r.urls = []; }

// Lädt einen Anhang, entschlüsselt ihn in den Arbeitsspeicher und löscht ihn
// (außer bei „Verlauf behalten“) sofort vom Server.
async function fetchMedia(c, m) {
  const r = runOf(c);
  if (m.url || m.loading) return;
  m.loading = true;
  try {
    const resp = await api("GET", "/api/attachments/" + m.a.t, { raw: true });
    const plain = await C.decryptFile(C.unb64(m.a.k), new Uint8Array(await resp.arrayBuffer()));
    if (S.active !== c.id || !r.msgs.includes(m)) { m.loading = false; return; }
    const show = (SHOW_MIMES[m.k] || []).includes(m.a.m);
    m.url = URL.createObjectURL(new Blob([plain], { type: show ? m.a.m : "application/octet-stream" }));
    r.urls.push(m.url);
    if (!c.keep) dropAttachment(m.a.t);
  } catch (e) { m.gone = true; }
  m.loading = false;
  if (S.active === c.id) renderChat();
}
function dropMedia(c, m, alsoServer) {
  if (m.url) { try { URL.revokeObjectURL(m.url); } catch (e) {} m.url = null; }
  if (alsoServer && m.a && m.a.t) dropAttachment(m.a.t);
}

// =========================================================================
// VERLAUF BEHALTEN (nur wenn beide zugestimmt haben)
// Liegt verschlüsselt im Konto, zusätzlich geschützt durch das Kanal-Passwort.
// =========================================================================
async function histKey(k) { return k; }      // der Verlauf hat einen eigenen, festen Schlüssel
const _histTimers = {};
function saveHistorySoon(c) {
  if (_histTimers[c.id]) return;
  _histTimers[c.id] = setTimeout(() => { delete _histTimers[c.id]; saveHistory(c); }, 600);
}
// Schreibt den Verlauf verschlüsselt ins Konto. Nur wenn der Verlauf gerade
// geladen ist (Chat offen), sonst würde ein leerer Stand den echten überschreiben.
async function saveHistory(c, msgs, kMsg) {
  const r = runOf(c);
  if (!msgs) { if (!r.loaded) return; msgs = r.msgs; kMsg = r.kMsg; }
  if (!c.keep || !kMsg || !S.me) return;
  // Begrenzt nach Größe: die neuesten Einträge bleiben, die ältesten fallen weg.
  const list = [];
  let bytes = 2;
  for (let i = msgs.length - 1; i >= 0; i--) {
    const m = msgs[i];
    if (m.st === "failed") continue;
    const e = { i: m.i, me: m.me, k: m.k, x: m.x, a: m.a, st: m.st === "seen" ? "seen" : "sent", n: m.n };
    bytes += C.utf8(JSON.stringify(e)).byteLength + 1;
    if (bytes > HIST_BYTES) break;
    list.unshift(e);
  }
  const sealed = C.b64(await C.seal(await histKey(kMsg), C.utf8(JSON.stringify(list))));
  if (!c.keep || !chan(c.id)) return;
  c.hist = sealed;
  bump(c);
  saveSoon();
}
// Liest einen gespeicherten Verlauf und gibt die Einträge zurück, die noch fehlen.
async function readHistory(c, sealed, kMsg, have) {
  const list = JSON.parse(C.fromUtf8(await C.open(await histKey(kMsg), C.unb64(sealed))));
  const out = [];
  for (const m of (Array.isArray(list) ? list : [])) {
    if (!m || typeof m.i !== "string" || have.has(m.i)) continue;
    const kind = ["image", "video", "voice", "file"].includes(m.k) ? m.k : "text";
    const o = { i: m.i, me: m.me ? 1 : 0, k: kind, x: typeof m.x === "string" ? m.x : "", st: m.st === "seen" ? "seen" : "sent", n: m.n };
    if (kind !== "text") { o.a = cleanAtt(m.a); if (!o.a) continue; }
    out.push(o);
  }
  return out;
}
async function loadHistory(c) {
  const r = runOf(c);
  if (!c.keep || !r.kMsg) return;
  if (!c.hist) { r.loaded = true; return; }
  try {
    let old = await readHistory(c, c.hist, r.kMsg, new Set(r.msgs.map(m => m.i)));
    if (c.xp && c.xp.length) {
      const gone = new Set(c.xp);
      old = old.filter(m => !gone.has(m.i));
      c.xp = [];
      saveHistorySoon(c);
    }
    for (const o of old) if (!o.me) r.seen.add(o.i);
    r.msgs = old.concat(r.msgs);
    for (const m of old) if (m.k !== "text") fetchMedia(c, m);
  } catch (e) {}
  r.loaded = true;
}
// Ein anderes Gerät hat denselben Verlauf weitergeschrieben, während der Chat
// hier offen ist: fehlende Einträge übernehmen, dann den vereinten Stand sichern.
const _histMerges = [];
async function applyHistMerges() {
  while (_histMerges.length) {
    const [id, sealed] = _histMerges.shift();
    const c = chan(id), r = c && S.run[id];
    if (!c || !r || !r.kMsg || S.active !== id || !c.keep || !r.loaded) continue;
    try {
      const add = await readHistory(c, sealed, r.kMsg, new Set(r.msgs.map(m => m.i)));
      if (add.length) {
        for (const o of add) if (!o.me) r.seen.add(o.i);
        r.msgs = add.concat(r.msgs);
        for (const m of add) if (m.k !== "text") fetchMedia(c, m);
        renderChat();
      }
      await saveHistory(c);
    } catch (e) {}
  }
}

// =========================================================================
// KANAL ÖFFNEN / SCHLIESSEN / SPERREN
// =========================================================================
// ---------- Schlüssel-Kette ----------
// Für jede Richtung und jede Spur gibt es eine Kette. Aus dem aktuellen
// Ketten-Schlüssel entsteht der Schlüssel für genau eine Nachricht und der
// nächste Ketten-Schlüssel. Der alte wird überschrieben. Rückwärts rechnen geht
// nicht: Wer den heutigen Stand bekommt, kann frühere Nachrichten nicht öffnen.
const CHAIN_SKIP_MAX = 320;
const CHAIN_LANES = ["a", "ac", "b", "bc"];
async function chainInit(kMsg) {
  const ch = {};
  for (const d of CHAIN_LANES) ch[d] = { n: 0, k: C.b64(await C.hkdf(kMsg, "chatmesh2|chain|" + d)) };
  return ch;
}
const chainMk = (ck) => C.hkdf(ck, "chatmesh2|mk");
const chainNext = (ck) => C.hkdf(ck, "chatmesh2|ck");
// Schlüssel für Nummer n ansehen, ohne die Kette zu verändern.
async function chainPeek(st, n) {
  if (!st) return null;
  if (n < st.n) return st.skip && st.skip[n] ? C.unb64(st.skip[n]) : null;
  if (n - st.n > 4096) return null;
  let ck = C.unb64(st.k);
  for (let i = st.n; i < n; i++) ck = await chainNext(ck);
  return await chainMk(ck);
}
// Schlüssel für Nummer n benutzen: Die Kette rückt hinter n. Übersprungene
// Nummern behält der Empfänger einzeln (für verspätet ankommende Blöcke).
const _chainLocks = new WeakMap();
function chainUse(st, n, keepSkipped) {
  const prev = _chainLocks.get(st) || Promise.resolve();
  const job = prev.then(async () => {
    if (n < st.n) {
      const v = st.skip && st.skip[n];
      if (!v) return null;
      delete st.skip[n];
      return C.unb64(v);
    }
    if (n - st.n > 4096) return null;
    let ck = C.unb64(st.k);
    const skipped = {};
    for (let i = st.n; i < n; i++) { if (keepSkipped) skipped[i] = C.b64(await chainMk(ck)); ck = await chainNext(ck); }
    const mk = await chainMk(ck);
    const next = C.b64(await chainNext(ck));
    if (keepSkipped) {
      st.skip = Object.assign(st.skip || {}, skipped);
      const keys = Object.keys(st.skip).map(Number).sort((a, b) => a - b);
      for (const k of keys.slice(0, Math.max(0, keys.length - CHAIN_SKIP_MAX))) delete st.skip[k];
    }
    st.n = n + 1; st.k = next;
    return mk;
  });
  _chainLocks.set(st, job.catch(() => null));
  return job;
}
// Rückt eine Kette bis vor die Nummer target, ohne Zwischen-Schlüssel zu behalten.
async function chainAdvance(st, target) {
  if (!(target > st.n)) return;
  let ck = C.unb64(st.k);
  for (let i = st.n; i < target; i++) ck = await chainNext(ck);
  st.n = target; st.k = C.b64(ck);
}
// Einzel-Schlüssel übersprungener Nummern wegwerfen, sobald sie nicht mehr
// gebraucht werden können (zu alt, gelöscht oder schon verarbeitet).
function chainPrune(st, below, done) {
  if (!st || !st.skip) return false;
  let changed = false;
  const used = new Set(done || []);
  for (const k of Object.keys(st.skip)) {
    const n = Number(k);
    if (n < below || used.has(n)) { delete st.skip[k]; changed = true; }
  }
  return changed;
}
const chainProgress = (ch) => CHAIN_LANES.reduce((sum, d) => sum + ((ch && ch[d] && ch[d].n) || 0), 0);
// Vereint zwei Stände derselben Ketten (zwei Geräte): je Kette gilt der weitere.
function chainMerge(mine, other) {
  let changed = false;
  for (const d of CHAIN_LANES) {
    const a = mine[d], b = other && other[d];
    if (!a || !b || typeof b.k !== "string" || !Number.isInteger(b.n)) continue;
    if (b.n > a.n) {
      const keep = {};
      for (const [k, v] of Object.entries(a.skip || {})) keep[k] = v;
      for (const [k, v] of Object.entries(b.skip || {})) keep[k] = v;
      mine[d] = { n: b.n, k: b.k };
      if (Object.keys(keep).length) mine[d].skip = keep;
      changed = true;
    }
  }
  return changed;
}
// Schreibt den aktuellen Stand der Ketten zurück in das mit dem Kanal-Passwort
// verpackte Päckchen im Konto. Je Kanal läuft immer nur ein Zurückschreiben.
// Chat-Kanal ohne eigenes Passwort: Statt eines Passworts verschließt ein Zufalls-Schlüssel
// das Päckchen. Er liegt im Konto, das nur mit den 12 Wörtern lesbar ist.
function noPw(c) { return !!(c && (c.pend ? c.pend.n : (c.wrap && c.wrap.n))); }
function wrapVer(c) { return (c && c.wrap && c.wrap.v) || 0; }
async function wrapKeyFor(password, salt, nk) { return nk ? C.unb64(nk) : await C.passwordKey(password, salt); }

function rewrap(c, k) {
  const r = S.run[c.id];
  const prev = (r && r.rewrapP) || Promise.resolve();
  const job = prev.then(async () => {
    // Passt der Schlüssel nicht (mehr) zum Päckchen im Konto, etwa weil das Passwort
    // inzwischen geändert wurde, wird nichts geschrieben. Erkannt wird das am Salz.
    if (chan(c.id) !== c || !c.wrap || !k.ws || k.ws !== c.wrap.s) return;
    const payload = { h: C.b64(k.kMsg), d: C.b64(k.kDel), o: k.own, ch: k.ch };
    const wrap = await C.wrapWithKey(k.pwKey, C.unb64(k.ws), C.utf8(JSON.stringify(payload)));
    if (chan(c.id) === c && c.wrap && k.ws === c.wrap.s) {
      wrap.v = wrapVer(c);
      if (c.wrap.n) wrap.n = c.wrap.n;
      c.wrap = wrap; c.wp = chainProgress(k.ch);
    }
  });
  if (r) r.rewrapP = job.catch(() => {});
  return job;
}
async function flushChains() {
  if (!S.acct) return;
  const waits = Object.values(S.run).map(r => r.rewrapP).filter(Boolean);
  if (waits.length) await Promise.all(waits);
  for (const c of S.acct.ch) {
    const r = S.run[c.id];
    if (!r || !r.chDirty || !r.pwKey || !r.ch || !r.kMsg || c.pend) continue;
    r.chDirty = false;
    try { await rewrap(c, { kMsg: r.kMsg, kDel: r.kDel, own: r.own, pwKey: r.pwKey, ws: r.ws, ch: JSON.parse(JSON.stringify(r.ch)) }); } catch (e) { r.chDirty = true; }
  }
}

// Öffnet die verpackten Kanal-Schlüssel mit dem Kanal-Passwort.
async function unwrapKeys(c, password) {
  let plain, pwKey;
  const w = c.wrap;                 // genau dieses Päckchen; das Konto kann sich währenddessen ändern
  try {
    pwKey = await wrapKeyFor(password, C.unb64(w.s), w.n);
    plain = JSON.parse(C.fromUtf8(await C.open(pwKey, C.unb64(w.c))));
  } catch (e) { throw new Error(w.n ? "Dieser Chat-Kanal lässt sich gerade nicht öffnen." : "Falsches Passwort."); }
  const out = { kDel: C.unb64(plain.d), own: plain.o, pwKey, ws: w.s, migrated: false };
  if (plain.ch && plain.h) {
    out.kMsg = C.unb64(plain.h);          // Schlüssel nur für einen behaltenen Verlauf
    out.ch = plain.ch;
  } else {
    // Kanal aus der Zeit vor der Schlüssel-Kette: einmalig umstellen.
    const old = C.unb64(plain.m);
    out.kMsg = await C.hkdf(old, "chatmesh2|history");
    out.ch = await chainInit(old);
    const p = c.dir === "a" ? "b" : "a";
    await chainAdvance(out.ch[c.dir], c.sn || 0);
    await chainAdvance(out.ch[c.dir + "c"], c.cn || 0);
    await chainAdvance(out.ch[p], Math.max(0, (c.rn || 0) - WINDOW_BACK));
    await chainAdvance(out.ch[p + "c"], Math.max(0, (c.rc || 0) - WINDOW_BACK));
    out.migrated = true;
  }
  return out;
}

async function unlock(c, password) {
  const r = runOf(c);
  if (r.rewrapP) { try { await r.rewrapP; } catch (e) {} }
  // Hat ein anderes Gerät das Päckchen währenddessen ersetzt, wird mit dem neuen noch einmal geöffnet.
  let k = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const w = c.wrap;
    const got = await unwrapKeys(c, password);
    if (chan(c.id) !== c || c.pend) throw new Error("Diesen Chat-Kanal gibt es nicht mehr.");
    if (c.wrap === w || (c.wrap && c.wrap.s === got.ws && c.wrap.c === w.c)) { k = got; break; }
  }
  if (!k) throw new Error("Dieser Chat-Kanal wurde gerade auf einem anderen Gerät geändert. Bitte noch einmal öffnen.");
  r.kMsg = k.kMsg; r.kDel = k.kDel; r.own = k.own; r.ch = k.ch; r.pwKey = k.pwKey; r.ws = k.ws;
  r.chDirty = !!k.migrated;
  if (k.migrated) saveSoon();
}

async function setChannelPassword(c, newPw) {
  const r = S.run[c.id];
  if (!r || !r.ch || !r.kMsg || !r.pwKey || c.pend) throw new Error("Bitte den Chat-Kanal erst öffnen.");
  const salt = C.rand(16);
  const nk = newPw ? null : C.b64(C.rand(32));
  const key = await wrapKeyFor(newPw, salt, nk);
  const prev = r.rewrapP || Promise.resolve();
  const job = prev.then(async () => {
    if (chan(c.id) !== c || S.run[c.id] !== r || !r.ch || !r.kMsg) throw new Error("Bitte den Chat-Kanal erst öffnen.");
    const ver = wrapVer(c);
    const progress = chainProgress(r.ch);
    const payload = { h: C.b64(r.kMsg), d: C.b64(r.kDel), o: r.own, ch: r.ch };
    const wrap = await C.wrapWithKey(key, salt, C.utf8(JSON.stringify(payload)));
    if (chan(c.id) !== c || wrapVer(c) !== ver) throw new Error("Das Passwort wurde gerade auf einem anderen Gerät geändert. Bitte noch einmal versuchen.");
    wrap.v = ver + 1;
    if (nk) wrap.n = nk;
    c.wrap = wrap; c.wp = progress;
    // Ist der Chat-Kanal noch offen, gilt ab jetzt der neue Schlüssel; der Stand der Ketten wird gleich noch einmal gesichert.
    if (r.ch && r.kMsg) { r.pwKey = key; r.ws = wrap.s; r.chDirty = true; }
  });
  r.rewrapP = job.catch(() => {});
  await job;
  // Die Änderung gilt hier bereits. Klappt das Sichern gerade nicht, wird es nachgeholt.
  const saved = await saveAccount();
  // Hat gleichzeitig ein anderes Gerät geändert und dessen Stand gilt, ist diese Änderung verworfen.
  if (chan(c.id) !== c || !c.wrap || c.wrap.s !== C.b64(salt)) return "lost";
  if (!saved) { saveSoon(); return "later"; }
  return "ok";
}

function lockKeys(c) {
  const r = S.run[c.id];
  if (!r) return;
  // Vor dem Vergessen den Stand der Ketten sichern.
  if (r.chDirty && r.pwKey && r.ch && r.kMsg && !c.pend) {
    const snap = { kMsg: r.kMsg, kDel: r.kDel, own: r.own, pwKey: r.pwKey, ws: r.ws, ch: JSON.parse(JSON.stringify(r.ch)) };
    rewrap(c, snap).then(() => { saveSoon(); }).catch(() => {});
  }
  r.kMsg = null; r.kDel = null; r.own = null; r.ch = null; r.pwKey = null; r.ws = null; r.chDirty = false;
}

function openChannel(id) {
  const c = chan(id);
  if (!c) return;
  if (c.pend) { openPending(c); return; }
  if (S.active === id) { $("#view-chat").classList.add("peek-chat"); return; }
  const r = runOf(c);
  const go = async () => {
    closeChannel(false);
    S.active = id;
    $("#view-chat").classList.add("peek-chat");
    renderList();
    renderChat(true);
    if (r.flush) { try { await r.flush; } catch (e) {} }
    if (S.active !== id) return;
    // Hat das Gegenüber inzwischen alles gelöscht, wird der alte Verlauf gar nicht erst gezeigt.
    await applyPendingClear(c, r.kMsg);
    if (S.active !== id) return;
    await loadHistory(c);
    if (S.active !== id) return;
    renderList();
    renderChat(true);
    await processWaiting(c);
    if (S.active === id && c.rq.length) askRequest(c);
  };
  // Ist die Kanal-Sperre abgeschaltet, bleibt der Kanal nach der ersten
  // Passwort-Eingabe für die Dauer der Anmeldung offen (nur im Arbeitsspeicher).
  if (r.kMsg) { go(); return; }
  if (noPw(c)) {
    // Ohne eigenes Passwort öffnet sich der Chat-Kanal direkt.
    if (r.opening) return;
    r.opening = true;
    unlock(c, "").then(() => { r.opening = false; if (chan(id) === c) go(); }, (e) => { r.opening = false; toast(e.message || "Öffnen nicht möglich", "err"); });
    return;
  }
  askPassword("Chat-Kanal „" + c.name + "“ öffnen", "Dein Passwort für diesen Chat-Kanal", async (pw) => { await unlock(c, pw); go(); });
}

// Verlässt den offenen Kanal. Ohne „Verlauf behalten“ ist danach alles weg,
// auch die eigenen Nachrichten. Mit Kanal-Sperre werden die Schlüssel vergessen.
function closeChannel(silent) {
  const id = S.active;
  if (!id) return;
  const c = chan(id);
  S.active = null;
  stopRecording(true);
  $("#msg-input").value = "";
  if (c) {
    const r = runOf(c);
    freeUrls(r);
    for (const m of r.msgs) { m.url = null; m.loading = false; }
    if (!c.keep) {
      for (const m of r.msgs) if (!m.me && m.a) dropMedia(c, m, true);
    } else if (r.loaded && r.kMsg) {
      // Verlauf ein letztes Mal sichern; beim nächsten Öffnen wird er daraus geladen.
      if (_histTimers[c.id]) { clearTimeout(_histTimers[c.id]); delete _histTimers[c.id]; }
      r.flush = saveHistory(c, r.msgs.slice(), r.kMsg).catch(() => {});
    }
    r.msgs = [];
    r.loaded = false;
    if (S.acct && S.acct.set.lockOn) lockKeys(c);
  }
  closeSheet();
  if (!silent) { $("#view-chat").classList.remove("peek-chat"); renderList(); renderChat(); }
}

// =========================================================================
// KANAL AUFLÖSEN (löschen, Screenshot-Versuch, Löschwörter)
// =========================================================================
// own = { t: Marke, k: Schlüssel, d: Lösch-Geheimnis } der eigenen Richtung.
async function postDissolve(own, reason) {
  const block = await C.sealJson(C.unb64(own.k), { r: reason }, C.BLOCK);
  return await pilePost(own.t, block, own.d);
}
function reasonText(name, reason, mine) {
  if (reason === "shot") return mine
    ? `Screenshot-Versuch erkannt. Der Chat-Kanal „${name}“ wurde bei euch beiden aufgelöst.`
    : `Im Chat-Kanal „${name}“ wurde versucht, einen Screenshot zu machen. Der Chat-Kanal wurde aufgelöst.`;
  if (reason === "wipe") return `Dein Gegenüber im Chat-Kanal „${name}“ hat sein Konto gelöscht. Der Chat-Kanal wurde aufgelöst.`;
  return mine ? `Chat-Kanal „${name}“ gelöscht.` : `Der Chat-Kanal „${name}“ wurde vom Gegenüber gelöscht.`;
}
function dissolveLocal(c, reason, mine) {
  dropRuntime(c.id);
  S.acct.ch = S.acct.ch.filter(x => x.id !== c.id);
  S.acct.gone = [...S.acct.gone.filter(x => x !== c.id), c.id].slice(-300);
  if (!(mine && reason === "deleted")) S.acct.notes.push(reasonText(c.name, reason, mine));
  S.acct.notes = S.acct.notes.slice(-20);
  saveAccount();
  $("#view-chat").classList.remove("peek-chat");
  renderList();
  renderChat();
}
// Schickt die Mitteilung "Kanal aufgelöst" ans Gegenüber, mit Wiederholung.
function notifyDissolve(own, reason) {
  if (!own) return;
  const waits = [1500, 5000, 15000, 45000, 120000, 300000, 900000];
  let i = 0;
  const run = async () => {
    let ok = false;
    try { const code = await postDissolve(own, reason); ok = code === 200 || code === 409; } catch (e) {}
    if (!ok && i < waits.length) setTimeout(run, waits[i++]);
  };
  run();
}
// Löst den Kanal bei beiden auf. Normal: erst wenn die Mitteilung auf dem Server
// liegt, verschwindet er hier. Mit force (Screenshot-Versuch): sofort hier weg,
// die Mitteilung geht parallel raus und wird bei Bedarf wiederholt.
async function dissolveChannel(c, reason, own, force) {
  if (c.pend) {
    queueDelete(c.pend.ta, c.pend.da);
    dissolveLocal(c, reason, true);
    return true;
  }
  own = own || runOf(c).own;
  if (force) {
    dissolveLocal(c, reason, true);
    notifyDissolve(own, reason);
    return true;
  }
  let code = 0;
  if (own) { try { code = await postDissolve(own, reason); } catch (e) { code = 0; } }
  if (code !== 200 && code !== 409) return false;
  dissolveLocal(c, reason, true);
  return true;
}

// =========================================================================
// KANAL ANLEGEN UND BEITRETEN (Einmal-Code)
// =========================================================================
async function dissolvePart(kDis, dir) {
  const dk = await C.dissolveKeys(kDis, dir);
  return { t: dk.tag, k: C.b64(dk.key), d: dk.del };
}
// Legt die Schlüssel eines neuen Kanals ab: Marken-Schlüssel offen (damit
// Ungelesenes auch bei gesperrtem Kanal gezählt werden kann), alles andere
// verpackt mit dem Kanal-Passwort.
async function installKeys(c, keys, pwKey, salt, nk) {
  const own = await dissolvePart(keys.kDis, c.dir);
  c.kt = C.b64(keys.kTag);
  c.pd = await dissolvePart(keys.kDis, peerDir(c));
  // Im Päckchen liegen nur: Verlauf-Schlüssel, Lösch-Schlüssel, eigener Auflöse-Teil
  // und der aktuelle Stand der Schlüssel-Ketten. Der Ausgangs-Schlüssel wird nicht aufbewahrt.
  const hist = await C.hkdf(keys.kMsg, "chatmesh2|history");
  const ch = await chainInit(keys.kMsg);
  c.wrap = await C.wrapWithKey(pwKey, salt, C.utf8(JSON.stringify({ h: C.b64(hist), d: C.b64(keys.kDel), o: own, ch })));
  c.wrap.v = 0;                // Stand des Päckchens: steigt, wenn das Passwort wechselt (für zwei Geräte)
  if (nk) c.wrap.n = nk;       // ohne eigenes Passwort
  c.wb = C.b64(await C.boxSeal(C.unb64(S.acct.wp), C.utf8(JSON.stringify({ t: own.t, k: own.k, d: own.d, kt: C.b64(keys.kTag), kd: C.b64(keys.kDel) }))));
  c.sym = keys.symbols;
  c.sn = 0; c.cn = 0; c.sr = 0; c.cr = 0; c.rn = 0; c.rc = 0; c.rp = []; c.rpc = [];
  c.keep = 0; c.shots = 0; c.rq = []; c.ro = []; c.hist = ""; c.rv = 0;
  c.vf = 0;      // Prüf-Zahl noch nicht verglichen
  c.cf = 0;      // Lösch-Grenze: ältere Nachrichten des Gegenübers werden verworfen
  c.hv = 0;      // zählt, wie oft der Chat-Kanal geleert wurde (für zwei Geräte)
  c.ca = [];     // schon umgesetzte Lösch-Aufträge des Gegenübers
  c.pu = [];     // eigene Nachrichten, die nach einer Frist ungeöffnet gelöscht werden
  c.wp = 0;      // wie weit die Schlüssel-Ketten im gespeicherten Päckchen sind (für zwei Geräte)
  return { own, kMsg: hist, kDel: keys.kDel, ch, pwKey, ws: c.wrap.s };
}

async function createChannel(name, password, keepReq) {
  const I = C.rand(12);
  const ik = await C.inviteKeys(I);
  const ex = await C.newExchangeKey();
  const salt = C.rand(16);
  const nk = password ? null : C.b64(C.rand(32));
  const pwKey = await wrapKeyFor(password, salt, nk);
  const kr = keepReq ? 1 : 0;
  const offer = await C.sealJson(ik.key, { t: "offer", p: C.b64(ex.pub), kr }, C.BLOCK);
  // Das Lösch-Geheimnis für das Angebot kennt nur dieses Gerät. Wer den
  // Einmal-Schlüssel abfängt, kann das Angebot deshalb nicht austauschen.
  const delA = C.hex(C.rand(16));
  const code = await pilePost(ik.tagA, offer, delA);
  if (code !== 200) throw new Error("Der Chat-Kanal konnte gerade nicht angelegt werden. Bitte noch einmal versuchen.");
  // Die Geheimnisse der Einladung liegen im Konto nur verpackt mit dem Kanal-Passwort.
  const sealed = await C.seal(pwKey, C.utf8(JSON.stringify({ inv: C.b64(I), priv: ex.privJwk, pub: C.b64(ex.pub), kr })));
  const c = {
    id: C.hex(C.rand(8)), name, dir: "a", rv: 0,
    pend: { ta: ik.tagA, da: delA, tb: ik.tagB, exp: nowSec() + INVITE_SECONDS, s: C.b64(salt), c: C.b64(sealed) },
  };
  if (nk) c.pend.n = nk;
  S.acct.ch.unshift(c);
  runOf(c).ps = { I, priv: ex.privJwk, pub: ex.pub, kr, pwKey, salt, nk };
  await refreshExpect(c);
  await saveAccount();
  renderList();
  return c;
}

// Öffnet die verpackten Geheimnisse einer offenen Einladung mit dem Kanal-Passwort.
async function unsealPending(c, password) {
  const salt = C.unb64(c.pend.s);
  const nk = c.pend.n || null;
  const pwKey = await wrapKeyFor(password, salt, nk);
  let plain;
  try { plain = JSON.parse(C.fromUtf8(await C.open(pwKey, C.unb64(c.pend.c)))); }
  catch (e) { throw new Error(nk ? "Der Einmal-Schlüssel lässt sich gerade nicht öffnen." : "Falsches Passwort."); }
  const ps = { I: C.unb64(plain.inv), priv: plain.priv, pub: C.unb64(plain.pub), kr: plain.kr ? 1 : 0, pwKey, salt, nk };
  runOf(c).ps = ps;
  return ps;
}

async function completeInvite(c, block, ps) {
  if (!c.pend) return false;
  const r = runOf(c);
  try {
    const ik = await C.inviteKeys(ps.I);
    const offerTag = c.pend.ta, offerDel = c.pend.da;
    const ans = await C.openJson(ik.key, block, C.BLOCK);
    const pubB = C.unb64(String(ans.p || ""));
    const keys = await C.channelKeys(await C.channelRoot(ps.priv, pubB, ps.I, ps.pub, pubB));
    const inst = await installKeys(c, keys, ps.pwKey, ps.salt, ps.nk);
    c.ro = ps.kr ? ["keep"] : [];          // die Anfrage steckte schon im Einmal-Code
    delete c.pend;
    r.ps = null;
    if (!S.acct.set.lockOn) { r.kMsg = inst.kMsg; r.kDel = inst.kDel; r.own = inst.own; r.ch = inst.ch; r.pwKey = inst.pwKey; r.ws = inst.ws; r.chDirty = false; }
    await refreshExpect(c);
    await saveAccount();
    // Die beiden Blöcke des Einmal-Codes später unauffällig entfernen.
    const wait = randBetween(15000, 90000);
    queueDelete(offerTag, offerDel, wait);      // die Antwort entfernt das Gegenüber selbst
    toast("Chat-Kanal „" + c.name + "“ ist verbunden.", "ok");
    if ($("#sheet .qr-canvas")) closeSheet();
    renderList();
    await matchPile();
    return true;
  } catch (e) {
    // Ungültige Antwort: verwerfen und weiter warten.
    if (c.pend) { delete c.pend.ans; await refreshExpect(c); }
    return false;
  }
}

async function joinChannel(codeText, name, password) {
  let I;
  try { I = await C.codeToBytes(codeText); }
  catch (e) {
    const m = String(e && e.message || "");
    throw new Error(m === "count" ? "Der Einmal-Schlüssel ist unvollständig (er hat 24 Zeichen)." : "Der Einmal-Schlüssel stimmt nicht. Bitte noch einmal kopieren oder auf Tippfehler prüfen.");
  }
  const ik = await C.inviteKeys(I);
  const invalid = "Dieser Einmal-Schlüssel ist nicht gültig (schon benutzt, abgelaufen oder zurückgezogen).";
  const found = await scanFor([ik.tagA, ik.tagB]);
  const block = found[ik.tagA];
  if (!block || found[ik.tagB]) throw new Error(invalid);
  let offer;
  try { offer = await C.openJson(ik.key, block, C.BLOCK); } catch (e) { throw new Error(invalid); }
  const pubA = C.unb64(String(offer.p || ""));
  const ex = await C.newExchangeKey();
  let keys;
  try { keys = await C.channelKeys(await C.channelRoot(ex.privJwk, pubA, I, pubA, ex.pub)); } catch (e) { throw new Error(invalid); }
  const salt = C.rand(16);
  const nk = password ? null : C.b64(C.rand(32));
  const pwKey = await wrapKeyFor(password, salt, nk);
  const c = { id: C.hex(C.rand(8)), name, dir: "b" };
  const inst = await installKeys(c, keys, pwKey, salt, nk);
  if (offer.kr) c.rq = ["keep"];
  const answer = await C.sealJson(ik.key, { t: "answer", p: C.b64(ex.pub) }, C.BLOCK);
  const delB = C.hex(C.rand(16));
  const code = await pilePost(ik.tagB, answer, delB);
  if (code !== 200) throw new Error(invalid);
  // Die eigene Antwort wird entfernt, sobald das Gegenüber sich meldet (oder nach einem Tag).
  c.ib = { t: ik.tagB, d: delB, exp: nowSec() + INVITE_SECONDS + 3600 };
  pileDrop(ik.tagA);
  S.acct.ch.unshift(c);
  const r = runOf(c);
  r.kMsg = inst.kMsg; r.kDel = inst.kDel; r.own = inst.own; r.ch = inst.ch; r.pwKey = inst.pwKey; r.ws = inst.ws; r.chDirty = false;
  await refreshExpect(c);
  await saveAccount();
  renderList();
  await matchPile();
  return c;
}

// Abgelaufene Einmal-Codes entfernen (24 Stunden).
function dropAnswerBlock(c) {
  if (!c.ib) return;
  queueDelete(c.ib.t, c.ib.d, randBetween(2000, 30000));
  delete c.ib;
  saveLazy();
}
function expireInvites() {
  if (!S.acct) return;
  for (const c of [...S.acct.ch]) {
    if (c.ib && c.ib.exp <= nowSec()) dropAnswerBlock(c);
    // Ist das Gegenüber schon beigetreten, läuft nichts mehr ab: es fehlt nur das Passwort.
    if (c.pend && !c.pend.ans && c.pend.exp <= nowSec()) {
      queueDelete(c.pend.ta, c.pend.da);
      dropRuntime(c.id);
      S.acct.ch = S.acct.ch.filter(x => x.id !== c.id);
      S.acct.gone = [...S.acct.gone, c.id].slice(-300);
      S.acct.notes.push(`Der Einmal-Schlüssel für „${c.name}“ ist abgelaufen.`);
      saveSoon();
      renderList();
    }
  }
}

// =========================================================================
// SCHLEIFEN: Abruf, Schein-Verkehr, Ablauf, Sperre
// Alles in unregelmäßigen Abständen, damit kein Takt erkennbar ist.
// =========================================================================
function loop(fn, nextDelay) {
  const sid = S.sid;
  let timer = null;
  const plan = () => { timer = setTimeout(run, nextDelay()); S.timers.add(timer); };
  const run = async () => {
    S.timers.delete(timer);
    if (!S.me || sid !== S.sid) return;
    try { await fn(); } catch (e) {}
    if (S.me && sid === S.sid) plan();
  };
  plan();
}

function startLoops() {
  // Verzeichnis abrufen
  loop(() => pileSync(false), () => randBetween(600, 1700));
  // Schein-Blöcke: sehen aus wie echte, werden nach kurzer Zeit wieder gelöscht
  loop(async () => {
    const big = randInt(40) === 0;
    const tag = C.hex(C.rand(16)), token = C.hex(C.rand(16));
    const code = await pilePost(tag, C.rand(big ? 65564 : 4124), token, 24);
    if (code === 200) {
      // Meist wird er vorher abgeholt, so wie eine echte Nachricht vom Gegenüber abgeholt wird.
      if (randInt(5) !== 0) {
        const sid = S.sid, t = setTimeout(() => { S.timers.delete(t); if (S.me && sid === S.sid) fetchBlocks([tag]).catch(() => {}); }, randBetween(700, 3500));
        S.timers.add(t);
      }
      queueDelete(tag, token, randBetween(4000, 90000));
    }
  }, () => Math.round(randExp(10000, 1200, 45000)));
  // Ablauf der Anzeige-Zeit und der Einmal-Schlüssel
  loop(async () => { tickExpiry(); expireInvites(); expireUnread(); }, () => 1000);
  // Konto in unregelmäßigen Abständen speichern, mit und ohne Anlass: von außen
  // sieht beides gleich aus. Größere Konten (mit behaltenem Verlauf) seltener.
  loop(async () => { await saveAccount(); }, () => {
    const mean = (S.blobLen || 0) < 100000 ? 14000 : ((S.blobLen || 0) < 400000 ? 45000 : 120000);
    return Math.round(randExp(mean, mean / 4, mean * 4));
  });
  // Schwere der Rechenaufgabe ab und zu neu holen
  loop(loadConfig, () => randBetween(120000, 360000));
}

// Eigene Nachrichten, die bis zur eingestellten Frist niemand geöffnet hat,
// werden vom Server entfernt. Das geht auch bei gesperrtem Kanal.
let _unreadBusy = false;
async function expireUnread() {
  if (!S.acct || _unreadBusy) return;
  const sid = S.sid, now = nowSec();
  _unreadBusy = true;
  try {
    for (const c of S.acct.ch) {
      if (!c.pu || !c.pu.length) continue;
      for (const e of c.pu.filter(x => x.x <= now)) {
        const state = await pileDeleteState(e.t, e.d);
        if (sid !== S.sid) return;
        if (state === "fail") { e.x = nowSec() + 30; continue; }      // später noch einmal
        c.pu = (c.pu || []).filter(x => x !== e);
        if (state === "ok") {
          // Der Block lag noch ungeöffnet da: Er ist jetzt weg, der Anhang auch, und
          // die Nachricht verschwindet bei mir aus Anzeige und behaltenem Verlauf.
          if (e.a) dropAttachment(e.a);
          const r = S.run[c.id];
          if (r && r.msgs.some(m => m.i === e.i)) {
            r.msgs = r.msgs.filter(m => m.i !== e.i);
            if (S.active === c.id) renderChat();
            if (c.keep) saveHistorySoon(c);
          } else if (c.keep && e.i) {
            c.xp = [...(c.xp || []), e.i].slice(-100);
          }
        }
        saveLazy();
      }
    }
  } finally { _unreadBusy = false; }
}

function tickExpiry() {
  const c = S.active ? chan(S.active) : null;
  if (!c) return;
  const r = runOf(c);
  const now = Date.now();
  const before = r.msgs.length;
  r.msgs = r.msgs.filter(m => {
    if (m.exp && m.exp <= now) { dropMedia(c, m, !m.me); return false; }
    return true;
  });
  if (r.msgs.length !== before) renderChat();
  else updateCountdowns();
}

// =========================================================================
// SCREENSHOT-SCHUTZ
// Eine Webseite kann Screenshots nicht sicher verhindern. Was möglich ist:
// Inhalt ausblenden, sobald das Fenster den Fokus verliert oder eine typische
// Tastenkombination gedrückt wird, und den Kanal bei einem erkannten Versuch
// auflösen. Auf Handys lässt sich ein Screenshot technisch nicht erkennen.
// =========================================================================
let _shieldHold = 0;
function shield(on) {
  if (!on && Date.now() < _shieldHold) return;
  document.body.classList.toggle("shielded", !!on);
}
function holdShield(ms) {
  _shieldHold = Date.now() + ms;
  shield(true);
  setTimeout(() => { if (document.hasFocus() && !document.hidden) shield(false); }, ms + 60);
}
function shotsAllowed() { const c = S.active ? chan(S.active) : null; return !c || !!c.shots; }
let _shotBusy = false;
async function onShotAttempt() {
  if (_shotBusy || shotsAllowed()) return;
  const c = chan(S.active);
  if (!c) return;
  _shotBusy = true;
  _shieldHold = Date.now() + 1500;
  shield(true);
  // Sofort auflösen, auch ohne Verbindung. Die Mitteilung ans Gegenüber wird dann nachgeholt.
  try { await dissolveChannel(c, "shot", null, true); }
  finally { _shotBusy = false; setTimeout(() => { if (document.hasFocus() && !document.hidden) shield(false); }, 1600); }
}

function bindShield() {
  window.addEventListener("blur", () => { if (!shotsAllowed()) shield(true); });
  window.addEventListener("focus", () => shield(false));
  document.addEventListener("visibilitychange", () => { if (document.hidden) { if (!shotsAllowed()) shield(true); } else shield(false); });
  const check = (e) => {
    const k = String(e.key || "");
    const low = k.toLowerCase();
    if (shotsAllowed()) return;
    // Vorbereitung einer Aufnahme: sofort ausblenden.
    if (e.metaKey && e.shiftKey) holdShield(8000);
    else if (k === "Meta" || k === "OS") shield(true);
    const code = String(e.code || "");
    const attempt = k === "PrintScreen" || code === "PrintScreen"
      || (e.metaKey && e.shiftKey && (["Digit3", "Digit4", "Digit5", "Digit6", "KeyS"].includes(code) || low === "s"))
      || (e.ctrlKey && e.shiftKey && !e.altKey && (code === "KeyS" || low === "s"))
      || ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && (code === "KeyP" || low === "p"));
    if (attempt) { e.preventDefault(); onShotAttempt(); }
  };
  document.addEventListener("keydown", check, true);
  document.addEventListener("keyup", (e) => {
    if (String(e.key) === "PrintScreen" || e.code === "PrintScreen") { if (!shotsAllowed()) onShotAttempt(); }
    if (!e.metaKey && !document.hidden && document.hasFocus()) shield(false);
  }, true);
  window.addEventListener("beforeprint", () => { if (!shotsAllowed()) onShotAttempt(); });
  document.addEventListener("contextmenu", (e) => { if (e.target.closest && e.target.closest("#chat-stream") && !shotsAllowed()) e.preventDefault(); });
  document.addEventListener("copy", (e) => { if (e.target.closest && e.target.closest("#chat-stream") && !shotsAllowed()) e.preventDefault(); });
  document.addEventListener("dragstart", (e) => { if (e.target.closest && e.target.closest("#chat-stream")) e.preventDefault(); });
}

// =========================================================================
// FENSTER (Menüs, Eingaben)
// =========================================================================
function closeSheet() {
  stopScan();
  $("#sheet-bg").style.display = "none";
  $("#sheet").textContent = "";
}
function openSheetNodes(title, nodes, noClose) {
  const sheet = $("#sheet");
  stopScan();
  sheet.textContent = "";
  if (title) sheet.appendChild(el("div", "sheet-title", title));
  for (const n of nodes) sheet.appendChild(n);
  if (!noClose) {
    const cancel = el("button", "sheet-item cancel", "Schließen");
    cancel.type = "button";
    cancel.addEventListener("click", closeSheet);
    sheet.appendChild(cancel);
  }
  $("#sheet-bg").style.display = "flex";
}
function menuItem(label, sub, danger, onClick) {
  const b = el("button", "sheet-item" + (danger ? " danger" : ""));
  b.type = "button";
  b.appendChild(el("span", "sheet-label", label));
  if (sub) b.appendChild(el("span", "sheet-sub", sub));
  b.addEventListener("click", () => { closeSheet(); onClick(); });
  return b;
}
function infoNode(text) { return el("p", "sheet-info", text); }

// Formular in einem Fenster. onSubmit darf einen Fehler werfen, dessen Text
// dann im Fenster erscheint.
function formSheet(title, opts) {
  const form = el("form", "sheet-form");
  const inputs = {};
  let grid = null;
  if (opts.info) form.appendChild(infoNode(opts.info));
  for (const f of opts.fields) {
    if (f.node) { form.appendChild(f.node); grid = null; continue; }
    const lab = el("label", f.type === "checkbox" ? "check-row" : "sheet-field");
    const inp = document.createElement(f.type === "textarea" ? "textarea" : "input");
    // Kanal-Passwörter sind bewusst keine "Passwort-Felder" des Browsers: so bietet
    // er nicht an, sie zu speichern oder vorzuschlagen. Verdeckt werden sie per Stil.
    if (f.type === "password") { inp.type = "text"; inp.classList.add("pw"); inp.setAttribute("inputmode", "text"); }
    else if (f.type !== "textarea") inp.type = f.type || "text";
    if (f.type === "textarea") inp.rows = 3;
    inp.name = f.name;
    if (f.placeholder) inp.placeholder = f.placeholder;
    if (f.value !== undefined) { if (f.type === "checkbox") inp.checked = !!f.value; else inp.value = f.value; }
    inp.autocomplete = "off";
    inp.spellcheck = false;
    if (f.type !== "checkbox") { inp.setAttribute("autocapitalize", "none"); inp.setAttribute("autocorrect", "off"); }
    if (f.type === "number") { inp.setAttribute("inputmode", "numeric"); inp.min = "0"; }
    if (f.max) inp.maxLength = f.max;
    inputs[f.name] = inp;
    if (f.type === "checkbox") { lab.appendChild(inp); lab.appendChild(el("span", "", f.label)); }
    else { lab.appendChild(el("span", "sheet-field-label", f.label)); lab.appendChild(inp); if (f.hint) lab.appendChild(el("small", "", f.hint)); }
    if (f.grid) { if (!grid) { grid = el("div", "sheet-grid"); form.appendChild(grid); } grid.appendChild(lab); }
    else { grid = null; form.appendChild(lab); }
  }
  const err = el("div", "sheet-error");
  form.appendChild(err);
  const row = el("div", "sheet-row");
  const cancel = el("button", "ghost small", "Abbrechen");
  cancel.type = "button";
  cancel.addEventListener("click", () => { closeSheet(); if (opts.onCancel) opts.onCancel(); });
  const ok = el("button", "primary small" + (opts.danger ? " danger-fill" : ""), opts.submit || "OK");
  ok.type = "submit";
  row.appendChild(cancel); row.appendChild(ok);
  form.appendChild(row);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (ok.disabled) return;
    const values = {};
    for (const [k, inp] of Object.entries(inputs)) values[k] = inp.type === "checkbox" ? inp.checked : inp.value;
    for (const inp of Object.values(inputs)) if (inp.classList.contains("pw")) inp.value = "";
    ok.disabled = true;
    err.textContent = opts.busy || "Einen Moment …";
    err.className = "sheet-error busy";
    try {
      await opts.onSubmit(values, inputs);
    } catch (ex) {
      if (opts.keepPw) for (const [k, inp] of Object.entries(inputs)) if (inp.classList.contains("pw") && inp.isConnected) inp.value = values[k];
      err.textContent = String(ex && ex.message || ex);
      err.className = "sheet-error";
      ok.disabled = false;
      return;
    }
    if (err.isConnected && err.className === "sheet-error busy") { err.textContent = ""; ok.disabled = false; }
  });
  openSheetNodes(title, [form], true);
  const first = Object.values(inputs)[0];
  if (first && !opts.noFocus) setTimeout(() => { try { first.focus(); } catch (e) {} }, 50);
  return inputs;
}

function askPassword(title, label, onPassword, submit) {
  formSheet(title, {
    fields: [{ name: "pw", type: "password", label }],
    submit: submit || "Öffnen",
    busy: "Wird geprüft …",
    onSubmit: async (v) => { await onPassword(v.pw); if ($("#sheet .sheet-form input.pw")) closeSheet(); },
  });
}

// =========================================================================
// FENSTER: Neuer Kanal, Beitreten, Code anzeigen, QR
// =========================================================================
function checkPw(v) {
  if (!v.pw && !v.pw2) return;          // freiwillig: ohne eigenes Passwort
  if (!v.pw || v.pw.length < PW_MIN) throw new Error("Das Passwort für den Chat-Kanal braucht mindestens " + PW_MIN + " Zeichen.");
  if (v.pw !== v.pw2) throw new Error("Die beiden Passwörter stimmen nicht überein.");
}

function newChannelSheet() {
  formSheet("Neuer Chat-Kanal", {
    info: "Du bekommst einen Einmal-Schlüssel. Den gibst du deinem Gegenüber: als QR-Code zum Scannen oder als Schlüssel zum Kopieren. Er gilt 24 Stunden und nur ein einziges Mal.",
    fields: [
      { name: "name", label: "Name für diesen Chat-Kanal (frei wählbar, siehst nur du)", max: 40 },
      { name: "pw", type: "password", label: "Dein eigenes Passwort, um auf diesen Chat-Kanal zuzugreifen (freiwillig)", hint: "Mit Passwort: Nur du kennst es, und du brauchst es, wenn du diesen Chat-Kanal öffnest oder löschst. Mit deinen 12 Anmeldewörtern hat es nichts zu tun. Leer lassen: Der Chat-Kanal öffnet sich ohne Passwort, dann genügen deine 12 Anmeldewörter, um ihn zu öffnen." },
      { name: "pw2", type: "password", label: "Passwort wiederholen (nur wenn du eins vergibst)" },
      { name: "keep", type: "checkbox", label: "Verlauf behalten anfragen (dein Gegenüber muss zustimmen, sonst wird wie üblich gelöscht)" },
    ],
    submit: "Chat-Kanal anlegen",
    busy: "Chat-Kanal wird angelegt …",
    keepPw: true,
    onSubmit: async (v) => {
      const name = (v.name || "").trim() || "Chat";
      checkPw(v);
      const c = await createChannel(name.slice(0, 40), v.pw, v.keep);
      showInvite(c);
    },
  });
}

function drawQr(canvas, text) {
  const qr = window.qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount(), scale = Math.max(3, Math.floor(260 / (n + 8)));
  const size = (n + 8) * scale;
  canvas.width = size; canvas.height = size;
  const g = canvas.getContext("2d");
  g.fillStyle = "#ffffff"; g.fillRect(0, 0, size, size);
  g.fillStyle = "#000000";
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (qr.isDark(y, x)) g.fillRect((x + 4) * scale, (y + 4) * scale, scale, scale);
}

async function showInvite(c) {
  if (!c.pend) return;
  let ps = runOf(c).ps;
  if (!ps && noPw(c)) {
    try { ps = await unsealPending(c, ""); } catch (e) { toast(e.message, "err"); return; }
    if (!c.pend) return;
  }
  if (!ps) {
    // In einer neuen Sitzung ist der Einmal-Code nur mit dem Kanal-Passwort lesbar.
    askPassword("Einmal-Schlüssel für „" + c.name + "“", "Dein Passwort für diesen Chat-Kanal", async (pw) => { await unsealPending(c, pw); setTimeout(() => showInvite(c), 0); }, "Anzeigen");
    return;
  }
  // Ein einziger Schlüssel am Stück: lässt sich als Ganzes kopieren und einfügen.
  const key = (await C.bytesToCode(ps.I)).replace(/-/g, "");
  const canvas = el("canvas", "qr-canvas");
  drawQr(canvas, key);
  const code = el("div", "code-key", key);
  const copy = el("button", "primary small", "Schlüssel kopieren");
  copy.type = "button";
  copy.addEventListener("click", () => { navigator.clipboard.writeText(key).then(() => toast("Schlüssel kopiert", "ok")).catch(() => toast("Kopieren nicht möglich", "err")); });
  const wait = el("p", "sheet-info center", "Warte auf den Beitritt … Der Chat-Kanal erscheint von selbst, sobald dein Gegenüber den Schlüssel eingegeben hat.");
  const drop = menuItem("Einmal-Schlüssel zurückziehen", "Er wird sofort ungültig.", true, () => dissolveChannel(c, "deleted"));
  openSheetNodes("Einmal-Schlüssel für „" + c.name + "“", [
    infoNode("Lass dein Gegenüber diesen QR-Code scannen, oder kopiere den Schlüssel und gib ihn weiter. Gültig 24 Stunden, nur ein einziges Mal."),
    canvas, code, copy, wait, drop,
  ]);
}

// Kanal, dessen Einmal-Code noch offen ist: Code zeigen oder, wenn das Gegenüber
// schon beigetreten ist, mit dem Kanal-Passwort fertig verbinden.
function openPending(c) {
  if (!c.pend) return;
  if (!c.pend.ans) { showInvite(c); return; }
  const finish = async (ps) => {
    const ok = await completeInvite(c, C.unb64(c.pend.ans), ps);
    if (!ok) { saveSoon(); renderList(); throw new Error("Der Beitritt war ungültig. Der Einmal-Schlüssel gilt weiter."); }
  };
  const ps = runOf(c).ps;
  if (ps) { finish(ps).catch(e => toast(e.message, "err")); return; }
  if (noPw(c)) { unsealPending(c, "").then(finish).catch(e => toast(e.message, "err")); return; }
  askPassword("Chat-Kanal „" + c.name + "“ verbinden", "Dein Passwort für diesen Chat-Kanal", async (pw) => { await finish(await unsealPending(c, pw)); }, "Verbinden");
}

let _scan = null;
function stopScan() {
  if (!_scan) return;
  try { _scan.stream.getTracks().forEach(t => t.stop()); } catch (e) {}
  if (_scan.timer) clearInterval(_scan.timer);
  _scan = null;
}
async function startScan(video, onText) {
  stopScan();
  if (!navigator.mediaDevices || !window.jsQR) throw new Error("Die Kamera steht hier nicht zur Verfügung. Bitte den Schlüssel einfügen.");
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false }); }
  catch (e) { throw new Error("Kein Zugriff auf die Kamera. Bitte den Schlüssel einfügen."); }
  video.srcObject = stream;
  video.setAttribute("playsinline", "");
  await video.play().catch(() => {});
  const canvas = document.createElement("canvas");
  const g = canvas.getContext("2d", { willReadFrequently: true });
  _scan = { stream, timer: null };
  _scan.timer = setInterval(() => {
    if (!video.videoWidth) return;
    const w = Math.min(640, video.videoWidth), h = Math.round(video.videoHeight * w / video.videoWidth);
    canvas.width = w; canvas.height = h;
    g.drawImage(video, 0, 0, w, h);
    let res = null;
    try { res = window.jsQR(g.getImageData(0, 0, w, h).data, w, h); } catch (e) {}
    if (res && res.data) { const text = res.data; stopScan(); onText(text); }
  }, 250);
}

function joinChannelSheet() {
  const video = el("video", "scan-video");
  video.hidden = true;
  video.muted = true;
  const scanBtn = el("button", "ghost small", "QR-Code scannen");
  scanBtn.type = "button";
  const scanWrap = el("div", "scan-wrap");
  scanWrap.appendChild(scanBtn);
  scanWrap.appendChild(video);
  const inputs = formSheet("Chat-Kanal beitreten", {
    info: "Gib den Einmal-Schlüssel ein, den du von deinem Gegenüber bekommen hast: QR-Code scannen oder Schlüssel einfügen.",
    noFocus: true,
    fields: [
      { node: scanWrap },
      { name: "code", label: "Einmal-Schlüssel", placeholder: "Schlüssel hier einfügen", max: 60 },
      { name: "name", label: "Name für diesen Chat-Kanal (frei wählbar, siehst nur du)", max: 40 },
      { name: "pw", type: "password", label: "Dein eigenes Passwort, um auf diesen Chat-Kanal zuzugreifen (freiwillig)", hint: "Mit Passwort: Nur du kennst es, und du brauchst es, wenn du diesen Chat-Kanal öffnest oder löschst. Dein Gegenüber entscheidet das für sich selbst. Leer lassen: Der Chat-Kanal öffnet sich ohne Passwort, dann genügen deine 12 Anmeldewörter, um ihn zu öffnen." },
      { name: "pw2", type: "password", label: "Passwort wiederholen (nur wenn du eins vergibst)" },
    ],
    submit: "Beitreten",
    busy: "Chat-Kanal wird verbunden …",
    keepPw: true,
    onCancel: stopScan,
    onSubmit: async (v) => {
      const name = (v.name || "").trim() || "Chat";
      checkPw(v);
      stopScan();
      const c = await joinChannel(v.code, name.slice(0, 40), v.pw);
      closeSheet();
      toast("Chat-Kanal „" + c.name + "“ ist verbunden.", "ok");
      openChannel(c.id);
    },
  });
  inputs.code.classList.add("key-input");
  scanBtn.addEventListener("click", async () => {
    try {
      video.hidden = false;
      await startScan(video, (text) => { inputs.code.value = text; video.hidden = true; toast("Schlüssel erkannt", "ok"); });
    } catch (e) { video.hidden = true; toast(e.message, "err"); }
  });
}

// =========================================================================
// FENSTER: Einstellungen, Anfragen, Kanal-Menü, Nachricht-Menü
// =========================================================================
function fmtDuration(sec) {
  sec = Math.max(0, Math.floor(sec));
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  const parts = [];
  if (d) parts.push(d + (d === 1 ? " Tag" : " Tage"));
  if (h) parts.push(h + (h === 1 ? " Stunde" : " Stunden"));
  if (m) parts.push(m + (m === 1 ? " Minute" : " Minuten"));
  if (s || !parts.length) parts.push(s + (s === 1 ? " Sekunde" : " Sekunden"));
  return parts.join(", ");
}
function fmtClock(sec) {
  sec = Math.max(0, Math.ceil(sec));
  if (sec >= 86400) return Math.floor(sec / 86400) + " T " + Math.floor(sec % 86400 / 3600) + " Std";
  if (sec >= 3600) return Math.floor(sec / 3600) + ":" + String(Math.floor(sec % 3600 / 60)).padStart(2, "0") + " Std";
  return Math.floor(sec / 60) + ":" + String(sec % 60).padStart(2, "0");
}

// Eigenen Code ändern: zur Sicherheit mit den 12 Wörtern bestätigen.
function codeChangeButton() {
  const b = el("button", "ghost small code-change", "Code ändern");
  b.type = "button";
  b.addEventListener("click", changeCodeSheet);
  const wrap = el("div", "sheet-btn-row");
  wrap.appendChild(b);
  return wrap;
}
function changeCodeSheet() {
  formSheet("Code ändern", {
    info: "Bestätige mit deinen 12 Wörtern und lege einen neuen Code fest. Der Code gilt für diese Anmeldung: Nach dem Neu-Laden der Seite gibst du ihn ein.",
    fields: [
      { name: "words", type: "textarea", label: "Deine 12 Wörter" },
      { name: "code", type: "password", label: "Neuer Code (mindestens 8 Zeichen)" },
      { name: "code2", type: "password", label: "Neuen Code wiederholen" },
    ],
    submit: "Code ändern",
    busy: "Einen Moment …",
    onSubmit: async (v) => {
      let L;
      try { L = await C.wordsToBytes(v.words, 16); }
      catch (e) { throw new Error(wordError(e, 12)); }
      // Nur prüfen, ob die Wörter zu diesem Konto gehören. Hier wird nie etwas gelöscht.
      if ((await C.accountKeys(L)).id !== S.me.id) throw new Error("Diese Wörter gehören nicht zu diesem Konto.");
      if (!v.code || v.code.length < CODE_MIN) throw new Error("Der Code braucht mindestens " + CODE_MIN + " Zeichen.");
      if (v.code !== v.code2) throw new Error("Die beiden Eingaben stimmen nicht überein.");
      await storeSession(L, v.code);
      closeSheet();
      toast("Neuer Code gespeichert.", "ok");
    },
  });
}

function settingsSheet() {
  const set = S.acct.set;
  const v = set.view, u = set.unread || 0;
  formSheet("Einstellungen", {
    info: "Geöffnete Nachrichten: So lange bleibt eine Nachricht von dir nach dem Öffnen sichtbar. Danach verschwindet sie bei dir und beim Gegenüber. Verlässt jemand den Chat, ist sie bei ihm sofort weg.",
    noFocus: true,
    fields: [
      { name: "d", type: "number", grid: true, label: "Tage", value: Math.floor(v / 86400) },
      { name: "h", type: "number", grid: true, label: "Stunden", value: Math.floor(v % 86400 / 3600) },
      { name: "m", type: "number", grid: true, label: "Minuten", value: Math.floor(v % 3600 / 60) },
      { name: "s", type: "number", grid: true, label: "Sekunden", value: v % 60 },
      { node: el("div", "sheet-section", "Ungeöffnete Nachrichten löschen nach") },
      { node: infoNode("Hat dein Gegenüber eine Nachricht von dir bis dahin nicht geöffnet, wird sie gelöscht und nie mehr angezeigt. Alles auf 0 heißt: nicht automatisch (ungeöffnete Nachrichten bleiben höchstens ein bis zwei Wochen liegen).") },
      { name: "ud", type: "number", grid: true, label: "Tage", value: Math.floor(u / 86400) },
      { name: "uh", type: "number", grid: true, label: "Stunden", value: Math.floor(u % 86400 / 3600) },
      { name: "um", type: "number", grid: true, label: "Minuten", value: Math.floor(u % 3600 / 60) },
      { name: "us", type: "number", grid: true, label: "Sekunden", value: u % 60 },
      { node: el("div", "sheet-section", "Chat-Kanal-Sperre") },
      { name: "lockOn", type: "checkbox", label: "Passwort des Chat-Kanals jedes Mal verlangen: beim Öffnen und immer, wenn du einen Chat-Kanal verlassen hast. Ausgeschaltet fragt jeder Chat-Kanal nur einmal je Anmeldung. Betrifft nur Chat-Kanäle, für die du ein Passwort vergeben hast.", value: set.lockOn },
      { node: infoNode("Lädst du die Seite neu, bleibst du angemeldet und gibst nur deinen Code ein. Schließt du das Fenster, bist du abgemeldet. chatmesh beobachtet nicht, ob du die Maus bewegst oder tippst.") },
      { node: codeChangeButton() },
    ],
    submit: "Speichern",
    onSubmit: async (val) => {
      const num = (x) => Math.max(0, Math.floor(Number(x) || 0));
      const total = num(val.d) * 86400 + num(val.h) * 3600 + num(val.m) * 60 + num(val.s);
      if (total < VIEW_MIN) throw new Error("Mindestens " + VIEW_MIN + " Sekunden.");
      if (total > VIEW_MAX) throw new Error("Höchstens 30 Tage.");
      const unread = num(val.ud) * 86400 + num(val.uh) * 3600 + num(val.um) * 60 + num(val.us);
      if (unread > VIEW_MAX) throw new Error("Höchstens 30 Tage.");
      if (unread > 0 && unread < UNREAD_MIN) throw new Error("Ungeöffnet: mindestens 1 Minute (oder alles auf 0).");
      set.view = total;
      set.unread = unread;
      const wasOn = set.lockOn;
      set.lockOn = val.lockOn ? 1 : 0;
      set.rv = (set.rv || 0) + 1;
      if (set.lockOn && !wasOn) {
        // Sperre wieder an: alle nicht geöffneten Kanäle sofort sperren.
        for (const c of S.acct.ch) if (S.active !== c.id) lockKeys(c);
      }
      if (!(await saveAccount())) throw new Error("Speichern nicht möglich. Bitte Verbindung prüfen.");
      closeSheet();
      renderList();
      renderChat();
      toast("Gespeichert", "ok");
    },
  });
}

function askRequest(c) {
  const kind = c.rq[0];
  if (!kind || $("#sheet .sheet-choice")) return;
  const answer = async (yes, btn) => {
    for (const b of $$("#sheet .sheet-choice")) b.disabled = true;
    // Erst wenn die Antwort wirklich unterwegs ist, gilt sie auch hier.
    try { await sendObj(c, { t: "ans", k: kind, y: yes ? 1 : 0 }, "c"); }
    catch (e) {
      for (const b of $$("#sheet .sheet-choice")) b.disabled = false;
      toast("Antwort nicht gesendet: " + (e.message || "Fehler") + " Bitte noch einmal.", "err");
      return;
    }
    closeSheet();
    c.rq = c.rq.filter(x => x !== kind);
    if (yes) setMode(c, kind, 1); else { bump(c); saveSoon(); }
    if (yes && kind === "keep") saveHistorySoon(c);
    renderChat();
    if (c.rq.length && S.active === c.id) askRequest(c);
  };
  const yes = el("button", "sheet-choice danger-fill", kind === "keep" ? "Ja, Chats behalten" : "Ja, Screenshots erlauben");
  yes.type = "button";
  yes.addEventListener("click", () => answer(true));
  const no = el("button", "sheet-choice", kind === "keep" ? "Nein, Chats löschen (Standard)" : "Nein, Screenshots verbieten (Standard)");
  no.type = "button";
  no.addEventListener("click", () => answer(false));
  openSheetNodes(kind === "keep" ? "Verlauf behalten?" : "Screenshots erlauben?", [
    infoNode(kind === "keep"
      ? "Dein Gegenüber möchte, dass der Verlauf dieses Chat-Kanals behalten wird. Dann bleiben Nachrichten bei euch beiden gespeichert (verschlüsselt, nur für euch lesbar), statt zu verschwinden. Bilder, Videos und Dateien bleiben dabei etwa 5 Wochen abrufbar. Jeder von euch kann den Verlauf jederzeit bei beiden wieder löschen, ohne den anderen zu fragen."
      : "Dein Gegenüber möchte in diesem Chat-Kanal Screenshots erlauben. Dann wird der Chat-Kanal bei einem Screenshot nicht mehr aufgelöst."),
    no, yes,
  ], true);
}

async function requestMode(c, kind) {
  try {
    await sendObj(c, { t: "req", k: kind });
    if (!c.ro.includes(kind)) c.ro.push(kind);
    bump(c);
    saveSoon();
    renderChat();
    toast("Anfrage gesendet. Dein Gegenüber muss zustimmen.", "ok");
  } catch (e) { toast("Anfrage nicht gesendet: " + (e.message || ""), "err"); }
}

async function endMode(c, kind) {
  try { await sendObj(c, { t: "set", k: kind, v: 0 }, "c"); }
  catch (e) { toast("Nicht geändert: " + (e.message || "keine Verbindung"), "err"); return; }
  setMode(c, kind, 0);
  toast(kind === "keep" ? "Verlauf wird nicht mehr behalten." : "Screenshots sind wieder verboten.", "ok");
}

function channelMenu(c) {
  const items = [];
  items.push(menuItem("Alle Nachrichten bei beiden löschen", "Sofort und ohne Zustimmung deines Gegenübers. Gilt für alles: Geöffnetes, noch nicht Geöffnetes und einen behaltenen Verlauf. Der Chat-Kanal bleibt bestehen.", true, () => confirmClear(c)));
  if (c.keep) items.push(menuItem("Verlauf nicht mehr behalten", "Sofort und ohne Zustimmung deines Gegenübers. Der gespeicherte Verlauf wird bei euch beiden gelöscht, ab dann verschwinden Nachrichten wieder.", false, () => endMode(c, "keep")));
  else items.push(menuItem("Verlauf behalten anfragen", "Standard ist: alles verschwindet. Dein Gegenüber muss zustimmen. Abschalten kann es später jeder von euch allein.", false, () => requestMode(c, "keep")));
  if (c.shots) items.push(menuItem("Screenshots wieder verbieten", "Sofort und ohne Zustimmung deines Gegenübers.", false, () => endMode(c, "shots")));
  else items.push(menuItem("Screenshots erlauben anfragen", "Standard ist: Ein erkannter Screenshot-Versuch löst den Chat-Kanal bei euch beiden auf. Am Handy kann eine Webseite Screenshots nicht erkennen.", false, () => requestMode(c, "shots")));
  const sym = el("div", "sheet-item static");
  sym.appendChild(el("span", "sheet-label", c.vf ? "Prüf-Zahl (geprüft)" : "Prüf-Zahl (noch nicht geprüft)"));
  sym.appendChild(el("span", "sym-row", c.sym || ""));
  sym.appendChild(el("span", "sheet-sub", "Vergleicht diese Zahl einmal, am besten persönlich oder am Telefon. Steht bei deinem Gegenüber dieselbe Zahl, hat sich niemand dazwischengedrängt."));
  if (!c.vf) {
    const okBtn = el("button", "ghost small", "Die Zahl stimmt überein");
    okBtn.type = "button";
    okBtn.addEventListener("click", () => { c.vf = 1; bump(c); saveSoon(); closeSheet(); renderChat(); toast("Chat-Kanal als geprüft markiert.", "ok"); });
    sym.appendChild(okBtn);
  }
  items.push(sym);
  items.push(menuItem("Chat-Kanal umbenennen", "", false, () => {
    formSheet("Chat-Kanal umbenennen", {
      fields: [{ name: "name", label: "Neuer Name (siehst nur du)", value: c.name, max: 40 }],
      submit: "Speichern",
      onSubmit: async (v) => { c.name = ((v.name || "").trim() || c.name).slice(0, 40); bump(c); await saveAccount(); closeSheet(); renderList(); renderChat(); },
    });
  }));
  if (noPw(c)) items.push(menuItem("Passwort festlegen", "Dieser Chat-Kanal hat bei dir kein eigenes Passwort. Mit Passwort wird es beim Öffnen und beim Löschen verlangt.", false, () => passwordSheet(c)));
  else items.push(menuItem("Passwort ändern oder entfernen", "Braucht dein bisheriges Passwort für diesen Chat-Kanal.", false, () => passwordSheet(c)));
  items.push(menuItem("Chat-Kanal löschen", "Geht jederzeit, auch wenn der Chat-Kanal leer ist. Löscht den Chat-Kanal mit allem darin bei dir und bei deinem Gegenüber." + (noPw(c) ? "" : " Braucht dein Passwort für diesen Chat-Kanal."), true, () => deleteChannelSheet(c)));
  openSheetNodes(c.name, items);
}

// Passwort eines Chat-Kanals festlegen, ändern oder entfernen. Nur dieses Gerät und
// dieses Konto sind betroffen; das Gegenüber hat sein eigenes (oder keins).
function passwordSheet(c) {
  const has = !noPw(c);
  const fields = [];
  if (has) fields.push({ name: "pw0", type: "password", label: "Bisheriges Passwort" });
  fields.push({ name: "pw", type: "password", label: has ? "Neues Passwort (leer lassen: Passwort entfernen)" : "Neues Passwort", hint: (has ? "Wenn du eins vergibst: mindestens " : "Mindestens ") + PW_MIN + " Zeichen. Nur du kennst es." });
  fields.push({ name: "pw2", type: "password", label: has ? "Neues Passwort wiederholen (nur wenn du eins vergibst)" : "Neues Passwort wiederholen" });
  formSheet(has ? "Passwort ändern oder entfernen" : "Passwort festlegen", {
    info: has
      ? "Gilt für den Chat-Kanal „" + c.name + "“. Ohne Passwort öffnet er sich direkt, sobald du angemeldet bist: Dann genügen deine 12 Anmeldewörter."
      : "Gilt für den Chat-Kanal „" + c.name + "“. Ab jetzt brauchst du das Passwort, wenn du ihn öffnest oder löschst. Es schützt ab jetzt, nicht rückwirkend.",
    fields,
    submit: "Speichern",
    busy: "Wird gespeichert …",
    keepPw: true,
    onSubmit: async (v) => {
      if (chan(c.id) !== c || c.pend) throw new Error("Diesen Chat-Kanal gibt es nicht mehr.");
      if (has !== !noPw(c)) throw new Error("Das Passwort wurde inzwischen geändert. Bitte dieses Fenster schließen und neu öffnen.");
      if (!has && !v.pw && !v.pw2) throw new Error("Bitte ein Passwort eingeben.");
      checkPw(v);
      if (has) await unwrapKeys(c, v.pw0 || "");
      const res = await setChannelPassword(c, v.pw || "");
      closeSheet();
      if (res === "ok") toast(v.pw ? "Passwort gespeichert." : "Passwort entfernt.", "ok");
      else if (res === "later") toast((v.pw ? "Passwort geändert." : "Passwort entfernt.") + " Gerade keine Verbindung: Die Sicherung wird nachgeholt.");
      else toast("Auf einem anderen Gerät wurde gleichzeitig das Passwort geändert. Dessen Änderung gilt.", "err");
      renderList();
    },
  });
}

function deleteChannelSheet(c) {
  const has = !noPw(c);
  formSheet("Chat-Kanal „" + c.name + "“ löschen", {
    info: "Der Chat-Kanal wird mit allem darin bei dir und bei deinem Gegenüber gelöscht: Nachrichten, Anhänge und ein behaltener Verlauf. Das geht jederzeit, auch wenn der Chat-Kanal leer ist, und lässt sich nicht rückgängig machen.",
    fields: has ? [{ name: "pw", type: "password", label: "Dein Passwort für diesen Chat-Kanal" }] : [],
    submit: "Endgültig löschen",
    danger: true,
    busy: "Wird geprüft …",
    onSubmit: async (v) => {
      // Nur mit dem Passwort lässt sich die Mitteilung ans Gegenüber überhaupt erzeugen.
      const k = await unwrapKeys(c, v.pw || "");
      if (!(await dissolveChannel(c, "deleted", k.own))) throw new Error("Keine Verbindung. Der Chat-Kanal wurde nicht gelöscht, bitte noch einmal versuchen.");
      closeSheet();
      toast("Chat-Kanal gelöscht", "ok");
    },
  });
}

async function deleteForBoth(c, m) {
  const r = runOf(c);
  if (m.st === "sending") m.cancel = true;          // wird direkt nach dem Senden zurückgeholt
  if (m.st !== "failed" && m.st !== "sending") {
    try { await sendObj(c, { t: "del", ids: [m.me ? m.i : m.i.slice(1)] }, "c"); }
    catch (e) { toast("Nicht gelöscht: " + (e.message || "keine Verbindung"), "err"); return; }
    if (m.me && Number.isFinite(m.n) && r.kDel) {
      // Liegt der Block noch auf dem Server, wird er dort direkt entfernt.
      const kt = C.unb64(c.kt);
      queueDelete(await C.msgTag(kt, c.dir, m.n), await C.msgDelToken(r.kDel, c.dir, m.n));
    }
  }
  r.msgs = r.msgs.filter(x => x !== m);
  if (c.pu && c.pu.length) c.pu = c.pu.filter(e => e.i !== m.i);
  dropMedia(c, m, true);
  renderChat();
  if (c.keep) saveHistorySoon(c);
}

// Leert den Kanal auf diesem Gerät: angezeigte Nachrichten, Anhänge und ein
// gespeicherter Verlauf. Der Kanal selbst und seine Einstellungen bleiben.
// Kurze Rückfrage, damit niemand aus Versehen alles löscht.
function confirmClear(c) {
  const yes = el("button", "sheet-choice danger-fill", "Ja, alles bei beiden löschen");
  yes.type = "button";
  yes.addEventListener("click", () => { closeSheet(); clearForBoth(c); });
  const no = el("button", "sheet-choice", "Abbrechen");
  no.type = "button";
  no.addEventListener("click", closeSheet);
  openSheetNodes("Alle Nachrichten löschen?", [
    infoNode("Alle Nachrichten in diesem Chat-Kanal verschwinden sofort bei dir und bei deinem Gegenüber: Geöffnetes, noch nicht Geöffnetes und ein behaltener Verlauf. Das lässt sich nicht rückgängig machen."),
    no, yes,
  ], true);
}
function clearLocal(c) {
  const r = runOf(c);
  for (const m of r.msgs) dropMedia(c, m, true);
  r.msgs = [];
  c.hist = "";
  c.pu = [];
  c.hv = (c.hv || 0) + 1;
  bump(c);
  if (_histTimers[c.id]) { clearTimeout(_histTimers[c.id]); delete _histTimers[c.id]; }
  saveSoon();
  if (S.active === c.id) renderChat();
}

// Sieht in den wartenden stillen Steuerzeichen nach, ob das Gegenüber alles
// gelöscht oder „Verlauf behalten“ abgeschaltet hat, und setzt das um, BEVOR
// Verlauf geladen oder Nachrichten geöffnet werden. Jeder Auftrag wird genau
// einmal umgesetzt. Die Steuerzeichen selbst bleiben liegen und werden danach
// ganz normal verarbeitet (und vom Server gelöscht).
async function applyPendingClear(c, kMsg) {
  const r = runOf(c), p = peerDir(c);
  const done = new Set(c.ca || []);
  const fresh = [];
  let cutoff = -1, keepOff = false;
  for (const [n, block] of r.cwait) {
    if (done.has(n)) continue;
    let b = null;
    try { const mk = await chainPeek(r.ch && r.ch[p + "c"], n); if (!mk) continue; b = await C.openJson(mk, block, C.BLOCK); } catch (e) { continue; }
    if (!b || typeof b !== "object") continue;
    if (b.t === "clr" && Number.isInteger(b.upto) && b.upto >= 0) { cutoff = Math.max(cutoff, b.upto); fresh.push(n); }
    else if (b.t === "set" && b.k === "keep" && !b.v) { keepOff = true; fresh.push(n); }
  }
  if (!fresh.length) return;
  c.ca = [...(c.ca || []), ...fresh].filter(n => n >= (c.rc || 0) - WINDOW_BACK).slice(-64);
  if (keepOff && c.keep) c.keep = 0;
  if (cutoff >= 0) {
    c.cf = Math.max(c.cf || 0, cutoff);
    // Schlüssel für gelöschte, nie geöffnete Nachrichten wegwerfen.
    if (r.ch && chainPrune(r.ch[p], c.cf, null)) r.chDirty = true;
    clearLocal(c);
  } else if (keepOff) {
    c.hist = "";
    c.hv = (c.hv || 0) + 1;
    bump(c);
    saveSoon();
  }
}

async function clearForBoth(c) {
  const r = runOf(c);
  if (!r.kMsg || !r.kDel) return;
  const upto = c.sn || 0;
  try { await sendObj(c, { t: "clr", upto }, "c"); }
  catch (e) { toast("Nicht gelöscht: " + (e.message || "keine Verbindung"), "err"); return; }
  // Eigene Blöcke, die noch ungelesen auf dem Server liegen, direkt dort entfernen.
  const kt = C.unb64(c.kt), kDel = r.kDel;
  const from = Math.max(0, upto - WINDOW_AHEAD);
  (async () => {
    const tags = await C.msgTags(kt, c.dir, from, upto);
    for (let n = from; n < upto; n++) { try { queueDelete(tags[n - from], await C.msgDelToken(kDel, c.dir, n)); } catch (e) {} }
  })().catch(() => {});
  clearLocal(c);
  toast("Alle Nachrichten bei euch beiden gelöscht.", "ok");
}

function messageMenu(c, m) {
  if (m.st === "failed" && m.retry) {
    m.st = "sending";
    renderChat();
    deliver(c, m, m.retry);
    return;
  }
  const items = [];
  if (c.shots && m.k === "text" && m.x) items.push(menuItem("Text kopieren", "", false, () => { navigator.clipboard.writeText(m.x).then(() => toast("Kopiert", "ok")).catch(() => {}); }));
  items.push(menuItem("Bei beiden löschen", "Verschwindet sofort bei dir und beim Gegenüber. Geht jederzeit: ob schon geöffnet oder nicht, auch bei behaltenem Verlauf.", true, () => deleteForBoth(c, m)));
  openSheetNodes(null, items);
}

// =========================================================================
// ANZEIGE: Kanal-Liste
// =========================================================================
function initials(name) {
  const p = String(name || "?").trim().split(/\s+/);
  return (p.length >= 2 ? p[0][0] + p[1][0] : p[0].slice(0, 2)).toUpperCase();
}

function renderList() {
  if (!S.acct) return;
  const notes = $("#notes");
  notes.textContent = "";
  S.acct.notes.forEach((text, idx) => {
    const n = el("div", "note");
    n.appendChild(el("span", "", text));
    const x = el("button", "note-x", "×");
    x.type = "button";
    x.setAttribute("aria-label", "Hinweis schließen");
    x.addEventListener("click", () => { S.acct.notes.splice(idx, 1); saveLazy(); renderList(); });
    n.appendChild(x);
    notes.appendChild(n);
  });
  const list = $("#channel-list");
  list.textContent = "";
  let unread = 0;
  if (!S.acct.ch.length) {
    const e = el("div", "contact-empty");
    e.appendChild(document.createTextNode("Noch keine Chat-Kanäle."));
    e.appendChild(document.createElement("br"));
    e.appendChild(document.createTextNode("Lege einen neuen Chat-Kanal an oder tritt mit einem Einmal-Schlüssel bei."));
    list.appendChild(e);
  }
  for (const c of S.acct.ch) {
    const r = runOf(c);
    const row = el("div", "contact" + (c.id === S.active ? " active" : ""));
    const av = el("div", "avatar", initials(c.name));
    const meta = el("div", "meta");
    meta.appendChild(el("div", "name is-nick", c.name));
    const line = el("div", "last-row");
    let sub = "Ende-zu-Ende verschlüsselt";
    if (c.pend) sub = c.pend.ans ? (noPw(c) ? "Beitritt da: antippen zum Verbinden" : "Beitritt da: antippen und Passwort eingeben") : "Wartet auf Beitritt (Einmal-Schlüssel anzeigen)";
    else if (c.id === S.active) sub = "geöffnet";
    else if (!unlocked(c) && !noPw(c)) sub = "mit Passwort gesperrt";
    line.appendChild(el("div", "last" + (c.pend ? " warn" : ""), sub));
    const waiting = r.wait.size;
    if (waiting > 0 && c.id !== S.active) { unread += waiting; line.appendChild(el("span", "unread", waiting > 99 ? "99+" : String(waiting))); }
    meta.appendChild(line);
    row.appendChild(av); row.appendChild(meta);
    row.addEventListener("click", () => openChannel(c.id));
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    row.addEventListener("keydown", (e) => { if (e.key === "Enter") openChannel(c.id); });
    list.appendChild(row);
  }
  document.title = (unread > 0 ? "(" + unread + ") " : "") + APP_NAME;
}

// =========================================================================
// ANZEIGE: Chat
// =========================================================================
const ICON = {
  back: '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>',
  more: '<svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>',
  lock: '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
  timer: '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 2M9 2h6"/></svg>',
  file: '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>',
};
function svgEl(markup) { const s = el("span", "ico"); s.innerHTML = markup; return s; }   // nur feste Symbole

function renderChat(forceBottom) {
  const stream = $("#chat-stream"), header = $("#chat-header"), bar = $("#info-bar"), composer = $("#form-send");
  const c = S.active ? chan(S.active) : null;
  if (!c || !S.me) {
    stream.textContent = ""; header.textContent = ""; bar.hidden = true; composer.style.display = "none";
    document.body.classList.remove("no-select");
    if (S.me) stream.appendChild(el("div", "empty", "Wähle links einen Chat-Kanal oder lege einen neuen an."));
    return;
  }
  const r = runOf(c);
  composer.style.display = "";
  document.body.classList.toggle("no-select", !c.shots);

  header.textContent = "";
  const back = el("button", "icon-btn back");
  back.setAttribute("aria-label", "Zurück");
  back.appendChild(svgEl(ICON.back));
  back.addEventListener("click", () => closeChannel(false));
  const av = el("div", "avatar", initials(c.name));
  const idBox = el("div", "head-id");
  idBox.appendChild(el("div", "head-name", c.name));
  const sec = el("div", "head-sec");
  sec.appendChild(svgEl(ICON.lock));
  sec.appendChild(document.createTextNode(" Ende-zu-Ende verschlüsselt"));
  idBox.appendChild(sec);
  const menu = el("button", "icon-btn");
  menu.id = "btn-chat-menu";
  menu.setAttribute("aria-label", "Menü");
  menu.appendChild(svgEl(ICON.more));
  menu.addEventListener("click", () => channelMenu(c));
  header.appendChild(back); header.appendChild(av); header.appendChild(idBox); header.appendChild(menu);

  bar.textContent = "";
  bar.hidden = false;
  const chip = (text, icon) => { const s = el("span", "chip"); if (icon) s.appendChild(svgEl(icon)); s.appendChild(document.createTextNode(" " + text)); bar.appendChild(s); };
  if (c.keep) chip("Verlauf wird behalten (verschlüsselt, nur für euch beide). Jeder von euch kann ihn jederzeit bei beiden löschen.");
  else chip("Deine Nachrichten bleiben " + fmtDuration(S.acct.set.view) + " nach dem Öffnen sichtbar, danach werden sie gelöscht. Beim Verlassen des Chats sofort.", ICON.timer);
  if (S.acct.set.unread > 0) chip("Öffnet dein Gegenüber eine Nachricht von dir nicht innerhalb von " + fmtDuration(S.acct.set.unread) + ", wird sie gelöscht.");
  chip(c.shots ? "Screenshots erlaubt" : "Screenshots verboten");
  if (!c.vf) chip("Noch nicht geprüft: Vergleicht einmal eure Prüf-Zahl (Menü oben rechts).");
  if (c.ro.length) chip("Anfrage gesendet: wartet auf Zustimmung");

  const nearBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 140;
  const oldTop = stream.scrollTop;
  stream.textContent = "";
  if (!r.msgs.length) {
    stream.appendChild(el("div", "empty", c.keep ? "Noch keine Nachrichten." : "Keine Nachrichten. Was hier geschrieben wird, verschwindet von selbst."));
    return;
  }
  let prevMe = null;
  for (const m of r.msgs) {
    const row = messageRow(c, m);
    if (prevMe !== null && prevMe !== !!m.me) row.classList.add("gap");
    prevMe = !!m.me;
    stream.appendChild(row);
  }
  if (forceBottom || nearBottom) stream.scrollTop = stream.scrollHeight; else stream.scrollTop = oldTop;
}

function fmtSize(n) {
  if (!n) return "";
  if (n < 1024) return n + " B";
  if (n < 1048576) return Math.round(n / 1024) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

function messageRow(c, m) {
  const row = el("div", "msg-row" + (m.me ? " me" : ""));
  const bubble = el("div", "bubble" + (m.st === "failed" ? " failed" : ""));
  if (m.k === "text") bubble.appendChild(el("span", "body", m.x));
  else bubble.appendChild(mediaNode(c, m));
  const meta = el("span", "ts");
  if (m.exp) { const cd = el("span", "countdown", fmtClock((m.exp - Date.now()) / 1000)); cd.dataset.exp = String(m.exp); cd.title = "So lange bleibt die Nachricht noch sichtbar"; meta.appendChild(cd); }
  if (m.me) {
    const st = m.st === "seen" ? "✓✓" : (m.st === "sent" ? "✓" : (m.st === "failed" ? "nicht gesendet" : "…"));
    const tick = el("span", "tick", st);
    tick.title = m.st === "seen" ? "Gelesen" : (m.st === "sent" ? "Gesendet" : (m.st === "failed" ? "Antippen zum Wiederholen" : "Wird gesendet"));
    meta.appendChild(tick);
  }
  if (meta.childNodes.length) bubble.appendChild(meta);
  bubble.addEventListener("click", (e) => {
    if (e.target.closest("button, a, audio, video")) return;
    messageMenu(c, m);
  });
  bubble.tabIndex = 0;
  bubble.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target === bubble) messageMenu(c, m); });
  row.appendChild(bubble);
  return row;
}

function mediaNode(c, m) {
  const labels = { image: "Bild", video: "Video", voice: "Sprachnachricht", file: "Datei" };
  const label = labels[m.k] || "Datei";
  const wrap = el("div", "media");
  if (m.gone) { wrap.appendChild(el("div", "pending", `[${label} nicht mehr verfügbar]`)); return wrap; }
  if (!m.url) { wrap.appendChild(el("div", "pending", `${label} wird entschlüsselt …`)); return wrap; }
  const show = (SHOW_MIMES[m.k] || []).includes(m.a.m);
  if (m.k === "file" || !show) {
    const btn = el("button", "file-card");
    btn.type = "button";
    btn.appendChild(svgEl(ICON.file));
    const txt = el("span", "file-meta");
    txt.appendChild(el("span", "file-name", m.k === "file" ? (m.a.n || "datei") : label));
    txt.appendChild(el("span", "file-size", (fmtSize(m.a.s) + " · verschlüsselt übertragen").replace(/^ · /, "")));
    btn.appendChild(txt);
    btn.addEventListener("click", () => {
      if (!c.shots && !m.me) { toast("Speichern ist in diesem Chat-Kanal nicht erlaubt (wie Screenshots).", "err"); return; }
      const a = document.createElement("a");
      a.href = m.url; a.download = m.k === "file" ? safeName(m.a.n) : "datei";
      document.body.appendChild(a); a.click();
      setTimeout(() => a.remove(), 200);
    });
    wrap.appendChild(btn);
    return wrap;
  }
  const tag = m.k === "video" ? "video" : (m.k === "voice" ? "audio" : "img");
  const node = document.createElement(tag);
  if (tag === "img") { node.alt = "Bild"; node.draggable = false; }
  else { node.controls = true; node.preload = "metadata"; node.setAttribute("controlsList", "nodownload noplaybackrate"); node.disablePictureInPicture = true; }
  node.src = m.url;
  wrap.appendChild(node);
  return wrap;
}

function updateCountdowns() {
  const now = Date.now();
  for (const e of $$("#chat-stream .countdown")) e.textContent = fmtClock((Number(e.dataset.exp) - now) / 1000);
}

// =========================================================================
// SPRACHNACHRICHT
// =========================================================================
let _rec = null, _recStarting = false;
async function startRecording() {
  const c = S.active ? chan(S.active) : null;
  const sid = S.sid;
  if (!c || _rec || _recStarting) return;
  if (!navigator.mediaDevices || typeof MediaRecorder === "undefined") { toast("Dieser Browser kann keine Sprachnachrichten aufnehmen.", "err"); return; }
  _recStarting = true;
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); }
  catch (e) { _recStarting = false; toast("Kein Zugriff auf das Mikrofon.", "err"); return; }
  _recStarting = false;
  if (sid !== S.sid || S.active !== c.id) { try { stream.getTracks().forEach(t => t.stop()); } catch (e) {} return; }
  const mime = ["audio/webm", "audio/ogg", "audio/mp4"].find(t => MediaRecorder.isTypeSupported(t)) || "";
  const recorder = mime ? new MediaRecorder(stream, { mimeType: mime }) : new MediaRecorder(stream);
  const rec = { recorder, stream, chunks: [], id: c.id, sid, cancelled: false };
  _rec = rec;
  recorder.ondataavailable = (e) => { if (e.data && e.data.size) rec.chunks.push(e.data); };
  recorder.onstop = async () => {
    if (_rec === rec) _rec = null;
    try { rec.stream.getTracks().forEach(t => t.stop()); } catch (e) {}
    updateRecordUI();
    const ch = chan(rec.id);
    if (rec.cancelled || rec.sid !== S.sid || !rec.chunks.length || !ch || S.active !== rec.id) return;
    const type = (recorder.mimeType || mime || "audio/webm").split(";")[0];
    try { await sendMedia(ch, new File(rec.chunks, "aufnahme", { type }), "voice", ""); }
    catch (err) { toast("Nicht gesendet: " + (err.message || ""), "err"); }
  };
  recorder.start();
  updateRecordUI();
}
function stopRecording(cancel) {
  const rec = _rec;
  if (!rec) return;
  rec.cancelled = !!cancel;
  try { rec.recorder.stop(); }
  catch (e) { try { rec.stream.getTracks().forEach(t => t.stop()); } catch (e2) {} _rec = null; updateRecordUI(); }
}
function updateRecordUI() {
  const btn = $("#btn-record"), bar = $("#record-bar");
  if (!btn || !bar) return;
  btn.classList.toggle("recording", !!_rec);
  bar.hidden = !_rec;
}

// =========================================================================
// BEDIENUNG
// =========================================================================
function toggleSidebar() {
  const view = $("#view-chat");
  if (window.matchMedia("(max-width: 720px)").matches) {
    if (S.active) view.classList.add("peek-chat"); else toast("Wähle erst einen Chat-Kanal aus.");
    return;
  }
  view.classList.toggle("sidebar-collapsed");
}

function bindUI() {
  $$("#view-auth .tab").forEach(t => t.addEventListener("click", () => {
    $$("#view-auth .tab").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    $$("#view-auth .auth-form").forEach(f => f.classList.remove("active"));
    $("#form-" + t.dataset.tab).classList.add("active");
    $("#auth-msg").textContent = "";
  }));

  $("#form-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = $("#auth-msg");
    msg.textContent = "Anmelden …";
    try { await doLogin(e.target.words.value); msg.textContent = ""; e.target.words.value = ""; }
    catch (err) { if (S.me) logout(); if (err.gone) e.target.words.value = ""; msg.textContent = err.message || "Anmeldung nicht möglich"; }
  });
  $("#form-register").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = $("#auth-msg");
    msg.textContent = "Konto wird angelegt …";
    try { await doRegister(); msg.textContent = ""; }
    catch (err) { S.me = null; msg.textContent = "Konto konnte nicht angelegt werden: " + (err.message || ""); }
  });
  $("#words-confirm").addEventListener("change", e => { $("#words-continue").disabled = !e.target.checked; });
  $("#words-continue").addEventListener("click", () => { _backup = null; $("#words-login").textContent = ""; $("#words-wipe").textContent = ""; showCode("set"); });
  $("#form-code").addEventListener("submit", (e) => { e.preventDefault(); submitCode(); });
  $("#code-logout").addEventListener("click", () => logout());
  $("#btn-download-words").addEventListener("click", downloadWords);

  $("#btn-logout").addEventListener("click", async () => {
    const btn = $("#btn-logout");
    btn.disabled = true;
    closeChannel(true);
    for (const r of Object.values(S.run)) { if (r.flush) { try { await r.flush; } catch (e) {} } }
    try { await Promise.race([saveAccount(), sleep(6000)]); } catch (e) {}
    btn.disabled = false;
    logout();
  });
  $("#btn-main-menu").addEventListener("click", toggleSidebar);
  $("#btn-sidebar-open").addEventListener("click", toggleSidebar);
  $("#btn-settings").addEventListener("click", settingsSheet);
  $("#btn-new-channel").addEventListener("click", newChannelSheet);
  $("#btn-join-channel").addEventListener("click", joinChannelSheet);

  $("#form-send").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("#msg-input");
    const text = input.value.trim();
    const c = S.active ? chan(S.active) : null;
    if (!text || !c || !runOf(c).kMsg) return;
    if (sendText(c, text)) input.value = "";
  });
  $("#btn-attach").addEventListener("click", () => $("#file-input").click());
  $("#file-input").addEventListener("change", async (e) => {
    const c = S.active ? chan(S.active) : null;       // alle gewählten Dateien gehen an DIESEN Chat-Kanal
    const sid = S.sid;
    const files = Array.from(e.target.files);
    e.target.value = "";
    if (!c) return;
    for (const f of files) {
      if (sid !== S.sid || S.active !== c.id) return;
      const type = (f.type || "").split(";")[0];
      let kind = "file";
      if (MIMES.image.includes(type)) kind = "image";
      else if (MIMES.video.includes(type)) kind = "video";
      else if (MIMES.voice.includes(type)) kind = "voice";
      try { await sendMedia(c, f, kind, f.name); }
      catch (err) { if (sid === S.sid) toast("Nicht gesendet: " + (err.message || ""), "err"); }
    }
  });
  $("#btn-record").addEventListener("click", () => { if (_rec) stopRecording(false); else startRecording(); });
  $("#btn-record-cancel").addEventListener("click", () => stopRecording(true));
  $("#btn-record-send").addEventListener("click", () => stopRecording(false));

  $("#sheet-bg").addEventListener("click", (e) => { if (e.target.id === "sheet-bg" && !$("#sheet .sheet-form") && !$("#sheet .sheet-choice")) closeSheet(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#sheet .sheet-choice")) closeSheet(); });

  window.addEventListener("beforeunload", (e) => { if (S.me && S.urgent) { e.preventDefault(); e.returnValue = ""; } });
  window.addEventListener("pagehide", () => { if (S.me && S.dirty) saveAccount(); });

  // Erst jetzt lassen sich die Formulare absenden (ohne JavaScript bleiben die
  // Knöpfe gesperrt, damit nie Wörter als normale Formularanfrage rausgehen).
  $$("button[data-needs-js]").forEach(b => { b.disabled = false; });
}

// Nur in der lokalen Testumgebung: Zugriff für automatische Prüfungen.
if (location.hostname === "127.0.0.1" || location.hostname === "localhost") window.__cmTest = { S, closeChannel, LIM, clearForBoth, saveAccount, noPw };

// Start. Dieses Skript steht am Ende der Seite: alle Bausteine sind schon da.
// Es wird sofort entschieden, welche Ansicht erscheint. Liegt in diesem Fenster
// eine Anmeldung, kommt direkt die Code-Eingabe und nie die Anmelde-Seite.
function init() {
  bindUI();
  bindShield();
  if (readSession()) showCode("unlock"); else show("auth");
  renderChat();
  if (!location.host.endsWith(".onion")) $("#tor-hint").hidden = false;
  // Reste früherer Fassungen entfernen: Service Worker, Zwischenspeicher, Browser-Speicher.
  if ("serviceWorker" in navigator) navigator.serviceWorker.getRegistrations().then(rs => rs.forEach(r => r.unregister())).catch(() => {});
  if (typeof caches !== "undefined") caches.keys().then(ks => Promise.all(ks.map(k => caches.delete(k)))).catch(() => {});
  try { localStorage.clear(); for (const k of Object.keys(sessionStorage)) if (k !== SESSION_KEY) sessionStorage.removeItem(k); } catch (e) {}
}
init();
})();
