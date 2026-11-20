// chatmesh Phase 2 - anonymer Messenger ohne Adressen.
//
// Grundsätze dieser Datei:
// - Ein Konto besteht nur aus 12 Anmeldewörtern. Dazu gibt es 12 Löschwörter.
// - Kanäle entstehen über einen Einmal-Schlüssel (24 Zeichen oder QR-Code). Jeder
//   Kanal hat ein eigenes Passwort. Ohne dieses Passwort lassen sich auch mit
//   den 12 Anmeldewörtern keine Nachrichten lesen, senden oder löschen.
// - Jede Nachricht liegt als namenloser Block unter einer neuen Zufallsmarke
//   auf dem gemeinsamen Haufen. Dieses Gerät lädt den ganzen Haufen und findet
//   seine Blöcke selbst. Der Server bekommt keine Angabe, für wen ein Block ist.
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
const LIM = { keep: 6000, bytes: 24 * 1024 * 1024 };         // nicht zugeordnete Blöcke im Arbeitsspeicher
const VIEW_MIN = 5, VIEW_MAX = 30 * 86400, VIEW_DEFAULT = 600;
const INVITE_SECONDS = 24 * 3600;
const HIST_BYTES = 200000;              // Verlauf je Kanal (verschlüsselt im Konto)
const PW_MIN = 6;
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
  pile: new Map(),     // Marke -> Block (noch nicht zugeordnet)
  pileBytes: 0,
  cursor: 0,
  synced: false,
  expect: new Map(),   // Marke -> { id, kind, lane, n }
  run: {},             // Kanal-ID -> Laufzeitdaten (nur Arbeitsspeicher)
  active: null,        // gerade offener Kanal
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
  try { r = await fetch(path, init); }
  catch (e) { throw new ApiError("Keine Verbindung zum Server", 0); }
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
  return { v: 2, set: { view: VIEW_DEFAULT, lockOn: 1, rv: 0 }, wk: C.b64(wipeOuterKey), wp: C.b64(wipePub), wq: C.b64(wipePrivSealed), ch: [], gone: [], notes: [], n: 1 };
}
const strList = (v, max) => (Array.isArray(v) ? v : []).filter(x => typeof x === "string").slice(-max);
const numList = (v) => (Array.isArray(v) ? v : []).filter(x => Number.isInteger(x) && x >= 0).slice(-WINDOW_BACK * 2);
const modeList = (v) => (Array.isArray(v) ? v : []).filter(x => x === "keep" || x === "shots").filter((x, i, a) => a.indexOf(x) === i);
function sanitizeChannel(c) {
  if (!c || typeof c.id !== "string" || !/^[0-9a-f]{16}$/.test(c.id)) return null;
  c.name = String(c.name || "Kanal").slice(0, 40);
  c.dir = c.dir === "b" ? "b" : "a";
  c.rv = Number.isInteger(c.rv) ? c.rv : 0;
  if (c.pend) {
    const p = c.pend;
    if (![p.ta, p.da, p.tb].every(x => typeof x === "string" && /^[0-9a-f]{32}$/.test(x)) || typeof p.s !== "string" || typeof p.c !== "string") return null;
    p.exp = Number.isFinite(p.exp) ? p.exp : 0;
    return c;
  }
  if (typeof c.kt !== "string" || !c.wrap || typeof c.wrap.s !== "string" || typeof c.wrap.c !== "string") return null;
  if (!c.pd || typeof c.pd.t !== "string" || typeof c.pd.k !== "string" || typeof c.pd.d !== "string") return null;
  for (const k of ["sn", "cn", "sr", "cr", "rn", "rc"]) c[k] = Number.isInteger(c[k]) && c[k] >= 0 ? c[k] : 0;
  c.rp = numList(c.rp); c.rpc = numList(c.rpc);
  c.keep = c.keep ? 1 : 0; c.shots = c.shots ? 1 : 0;
  c.rq = modeList(c.rq); c.ro = modeList(c.ro);
  c.hist = typeof c.hist === "string" ? c.hist : "";
  c.sym = typeof c.sym === "string" ? c.sym.slice(0, 80) : "";
  delete c.open;
  return c;
}
function sanitizeAccount(a) {
  const out = { v: 2, set: {}, wk: typeof a.wk === "string" ? a.wk : "", wp: typeof a.wp === "string" ? a.wp : "", wq: typeof a.wq === "string" ? a.wq : "", ch: [], gone: strList(a.gone, 300), notes: [], n: Number.isFinite(a.n) ? a.n : 1 };
  const s = a.set && typeof a.set === "object" ? a.set : {};
  out.set.view = Math.max(VIEW_MIN, Math.min(VIEW_MAX, Math.floor(Number(s.view) || VIEW_DEFAULT)));
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
  const entries = acct.ch.filter(c => !c.pend && c.wb).map(c => c.wb);
  for (;;) {
    try { return C.b64(await C.sealJson(C.unb64(acct.wk), { p: acct.wp, q: acct.wq, e: entries }, C.WIPE)); }
    catch (e) { if (!entries.length) throw e; entries.pop(); }
  }
}
async function accountBlobs() {
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
      const body = { ...blobs, expected_version: S.version };
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
      if (e.status === 428) {
        // Das Konto wächst in eine größere Stufe: einmalige Rechenaufgabe.
        await loadConfig();
        const bits = (S.work.account[S.blobClass] || 0) + (S.wipeBig ? (S.work.account_wipe_extra || 2) : 0);
        if (bits > 28) { setSync("Speichern gerade nicht möglich"); break; }
        work = await C.work(subject(S.me.id, "g", S.blobClass * 2 + (S.wipeBig ? 1 : 0)), bits);
        continue;
      }
      if (e.status !== 409) {
        if (String(e.message) === "too large") { setSync("Konto ist voll"); if (!_saveWarned) toast("Der Speicher für behaltene Verläufe ist voll. Bitte in einem Kanal „Verlauf nicht mehr behalten“ wählen.", "err"); _saveWarned = true; }
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

async function doRegister() {
  await loadConfig();
  const L = C.rand(16), W = C.rand(16);
  const ak = await C.accountKeys(L), wk = await C.wipeKeys(W);
  const box = await C.newExchangeKey();
  const acct = emptyAccount(wk.encKey, box.pub, await C.seal(wk.innerKey, C.utf8(JSON.stringify(box.privJwk))));
  const blob = C.b64(await C.sealJson(ak.encKey, acct, C.ACCOUNT));
  const wipe_blob = await wipeBlobFor(acct);
  let r = null;
  for (let i = 0; i < 3 && !r; i++) {
    const work = await C.work(subject(ak.id, "a"), S.work.account[0] || 0);
    try { r = await api("POST", "/api/v2/account", { json: { id: ak.id, auth_hash: ak.authHash, wipe_hash: wk.wipeHash, blob, wipe_blob, work } }); }
    catch (e) { if (e.status !== 428 || i === 2) throw e; await loadConfig(); }
  }
  S.sid++;
  S.me = { id: ak.id, token: ak.token, encKey: ak.encKey };
  S.acct = acct;
  S.version = r.version;
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
  let r;
  try { r = await api("GET", "/api/v2/account", { auth: true, noLogout: true }); }
  catch (e) {
    S.me = null;
    if (e.status !== 401) throw new Error(e.message || "Anmeldung nicht möglich");
    // Kein Konto zu diesen Wörtern. Sind es die Löschwörter eines Kontos, wird
    // jetzt alles unwiderruflich gelöscht. Von außen und auf dem Bildschirm sieht
    // beides gleich aus: Es gibt kein Konto zu diesen Wörtern.
    if (fromWords) {
      // Kommt die Lösch-Anfrage nicht durch, darf das nicht wie "kein Konto"
      // aussehen: sonst glaubt man, es sei gelöscht, obwohl nichts passiert ist.
      try { await wipeWith(L); }
      catch (e2) { throw new Error("Keine Verbindung zum Server. Bitte noch einmal versuchen."); }
    }
    const err = new Error("Zu diesen Wörtern gibt es kein Konto.");
    err.gone = true;
    throw err;
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
    : "Du bist noch angemeldet. Gib deinen Code ein, um weiterzumachen.";
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
// Knopf: Wer bei "Anmelden" die Löschwörter eingibt, löscht alles. Die Anfrage
// geht bei jeder fehlgeschlagenen Anmeldung raus, egal welche Wörter es waren.
// Gibt die Zahl der benachrichtigten Kanäle zurück, -1 wenn es kein Konto gab.
async function wipeWith(W) {
  const wk = await C.wipeKeys(W);
  const r = await api("POST", "/api/v2/wipe", { json: { token: wk.token } });
  await loadConfig();
  if (!r.ok) {
    // Kein Treffer. Damit es von außen gleich aussieht wie ein echtes Löschen,
    // gehen auch hier ein, zwei Blöcke raus (Schein-Blöcke, die wieder verschwinden).
    try {
      const k = 1 + randInt(2);
      for (let i = 0; i < k; i++) {
        const tag = C.hex(C.rand(16)), token = C.hex(C.rand(16));
        if ((await pilePost(tag, C.rand(4124), token, 20)) === 200) queueDelete(tag, token, randBetween(20000, 120000));
      }
    } catch (e) {}
    return -1;
  }
  // Die Gegenüber benachrichtigen: jeder gemeinsame Kanal wird bei ihnen aufgelöst.
  let n = 0;
  try {
    const data = await C.openJson(wk.encKey, C.unb64(String(r.wipe_blob).replace(/\.+$/, "")), C.WIPE);
    const priv = JSON.parse(C.fromUtf8(await C.open(wk.innerKey, C.unb64(data.q))));
    const pub = C.unb64(data.p);
    for (const entry of (data.e || [])) {
      try {
        const own = JSON.parse(C.fromUtf8(await C.boxOpen(priv, pub, C.unb64(entry))));
        for (let i = 0; i < 4; i++) {
          let code = 0;
          try { code = await postDissolve(own, "wipe"); } catch (e) {}
          if (code === 200 || code === 409) { n++; break; }
          await sleep(1500 * (i + 1));
        }
      } catch (e) {}
    }
  } catch (e) {}
  return n;
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
    "FÜR DEN NOTFALL: LÖSCHWÖRTER (bei \"Anmelden\" eingeben = alles wird sofort unwiderruflich gelöscht):", "",
    _backup.wipe.split(" ").map((w, i) => `${String(i + 1).padStart(2, " ")}.  ${w}`).join("\n"), "",
    "=".repeat(60),
    "- Wer deine 12 Wörter hat, hat Zugriff auf dein Konto.",
    "- Wer die Löschwörter bei \"Anmelden\" eingibt, löscht alles: sofort, ohne Rückfrage.",
    "- Danach sieht es so aus, als hätte es das Konto nie gegeben.",
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
  S.pile = new Map(); S.pileBytes = 0; S.cursor = 0; S.synced = false; S.expect = new Map(); S.run = {}; S.active = null;
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
  // Erst ausrechnen, welche Marken uns gehören, dann den Haufen laden. So geht
  // auch bei einem sehr großen Haufen nichts Eigenes verloren.
  await rebuildExpect();
  if (sid !== S.sid) return;
  try { await pileSync(true); } catch (e) {}
  if (sid !== S.sid) return;
  S.synced = true;
  setSync("");
  renderList();
  startLoops();
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
  if (!S.run[c.id]) S.run[c.id] = { kMsg: null, kDel: null, own: null, ps: null, ok: {}, msgs: [], wait: new Map(), cwait: new Map(), top: {}, seen: new Set(), urls: [], tags: [], loaded: false, flush: null };
  return S.run[c.id];
}
const peerDir = (c) => c.dir === "a" ? "b" : "a";
const unlocked = (c) => !!(S.run[c.id] && S.run[c.id].kMsg);

// Rechnet für einen Kanal aus, unter welchen Marken als Nächstes etwas für uns
// liegen kann, und merkt sie vor. Schon verarbeitete Nummern werden nie wieder
// angenommen: ein alter Block lässt sich nicht noch einmal unterschieben.
async function refreshExpect(c) {
  const r = runOf(c);
  for (const t of r.tags) S.expect.delete(t);
  r.tags = [];
  const add = (tag, info) => { S.expect.set(tag, info); r.tags.push(tag); };
  if (c.pend) {
    if (!c.pend.ans) add(c.pend.tb, { id: c.id, kind: "ans" });
    return;
  }
  const kt = C.unb64(c.kt), p = peerDir(c);
  for (const [lane, base, map, done] of [["", c.rn || 0, r.wait, c.rp], ["c", c.rc || 0, r.cwait, c.rpc]]) {
    let top = base;
    for (const k of map.keys()) if (k + 1 > top) top = k + 1;
    const from = Math.max(0, base - WINDOW_BACK), to = top + WINDOW_AHEAD;
    r.top[lane] = to;
    const used = new Set(done);
    const tags = await C.msgTags(kt, p + lane, from, to);
    for (let n = from; n < to; n++) {
      if (map.has(n) || used.has(n)) continue;
      add(tags[n - from], { id: c.id, kind: "msg", lane, n });
    }
  }
  add(c.pd.t, { id: c.id, kind: "dis" });
}
async function rebuildExpect() {
  S.expect = new Map();
  if (!S.acct) return;
  for (const c of S.acct.ch) { runOf(c).tags = []; await refreshExpect(c); }
  await matchPile();
}
// Sucht im schon geladenen Haufen nach vorgemerkten Marken.
async function matchPile() {
  const hits = [];
  for (const [tag, info] of S.expect) { if (S.pile.has(tag)) hits.push([tag, info]); }
  for (const [tag, info] of hits) await onMatch(tag, info, S.pile.get(tag));
}

// =========================================================================
// DER HAUFEN: abrufen und zuordnen
// =========================================================================
function parsePile(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const out = [];
  let o = 0;
  while (o + 28 <= buf.length) {
    const seq = dv.getUint32(o) * 4294967296 + dv.getUint32(o + 4);
    const len = dv.getUint32(o + 24);
    if (o + 28 + len > buf.length) break;
    out.push([seq, C.hex(buf.subarray(o + 8, o + 24)), buf.slice(o + 28, o + 28 + len)]);
    o += 28 + len;
  }
  return out;
}
function pileStore(tag, block) {
  const old = S.pile.get(tag);
  if (old) S.pileBytes -= old.byteLength;
  S.pile.set(tag, block);
  S.pileBytes += block.byteLength;
}
function pileDrop(tag) {
  const old = S.pile.get(tag);
  if (old) { S.pileBytes -= old.byteLength; S.pile.delete(tag); }
}
let _syncing = false;
async function pileSync(initial) {
  if (_syncing || !S.me) return;
  _syncing = true;
  const sid = S.sid;
  try {
    for (let round = 0; round < 400; round++) {
      const resp = await api("GET", "/api/v2/pile?since=" + S.cursor, { raw: true });
      const state = String(resp.headers.get("X-Pile") || "ende:" + S.cursor + ":0").split(":");
      const buf = new Uint8Array(await resp.arrayBuffer());
      if (sid !== S.sid) return;
      for (const [seq, tag, block] of parsePile(buf)) {
        if (seq > S.cursor) S.cursor = seq;
        const info = S.expect.get(tag);
        if (info) await onMatch(tag, info, block);
        else pileStore(tag, block);
        if (sid !== S.sid) return;
      }
      // Arbeitsspeicher begrenzen: die ältesten nicht zugeordneten Blöcke fallen weg.
      if (S.pile.size > LIM.keep || S.pileBytes > LIM.bytes) {
        for (const k of S.pile.keys()) {
          if (S.pile.size <= LIM.keep * 0.9 && S.pileBytes <= LIM.bytes * 0.9) break;
          pileDrop(k);
        }
      }
      if (initial) setSync("Synchronisiere … " + S.pile.size + " Blöcke");
      if (state[0] !== "weiter") break;
    }
  } finally { _syncing = false; }
}
// Sucht gezielt nach bestimmten Marken im ganzen Haufen (für das Einlösen
// eines Einmal-Codes). Verändert nichts am eigenen Stand.
async function scanFor(tags) {
  const found = {};
  let cursor = 0;
  for (let round = 0; round < 400; round++) {
    const resp = await api("GET", "/api/v2/pile?since=" + cursor, { raw: true });
    const state = String(resp.headers.get("X-Pile") || "ende:0:0").split(":");
    for (const [seq, tag, block] of parsePile(new Uint8Array(await resp.arrayBuffer()))) {
      if (seq > cursor) cursor = seq;
      if (tags.includes(tag)) found[tag] = block;
    }
    if (state[0] !== "weiter") break;
  }
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
    if (r.ps) await completeInvite(c, block, r.ps);
    else { c.pend.ans = C.b64(block); saveSoon(); renderList(); toast("Jemand ist „" + c.name + "“ beigetreten. Kanal antippen und Passwort eingeben.", "ok"); }
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
  const sid = S.sid, kMsg = r.kMsg, kDel = r.kDel;
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
        try { body = await C.openJson(await C.msgKey(kMsg, p + lane, n), block, C.BLOCK); } catch (e) { body = null; }
        if (!alive()) break;                 // Chat inzwischen verlassen: Block bleibt verschlossen liegen
        map.delete(n);
        // Nummer als verarbeitet merken: sie wird nie wieder angenommen.
        if (n + 1 > (c[key] || 0)) c[key] = n + 1;
        c[doneKey] = (c[doneKey] || []).filter(x => x !== n && x >= c[key] - WINDOW_BACK);
        c[doneKey].push(n);
        advanced = true;
        jobs.push([p + lane, n]);
        if (!body || typeof body !== "object") continue;
        if (!lane && n < (c.cf || 0)) {            // vom Gegenüber gelöscht (auch wenn sie verspätet ankommt)
          if (body.t === "m" && body.a) { const a = cleanAtt(body.a); if (a) dropAttachment(a.t); }
          continue;
        }
        const shown = await handleIncoming(c, body);
        if (shown) seenIds.push(shown);
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
    toast("Dein Gegenüber hat alle Nachrichten in diesem Kanal gelöscht.");
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

// Verschließt einen Inhalt und legt ihn als Block auf den Haufen.
// lane "" = Nachricht, lane "c" = stilles Steuerzeichen (gelesen, gelöscht, Antwort).
// Gibt die Nummer zurück, unter der er liegt.
async function sendObj(c, obj, lane = "") {
  const r = runOf(c);
  const kMsg = r.kMsg, kDel = r.kDel;
  if (!kMsg) throw new Error("Kanal ist gesperrt");
  const sid = S.sid;
  const key = lane ? "cn" : "sn";
  const kt = C.unb64(c.kt), dir = c.dir + lane;
  for (let attempt = 0; attempt < 8; attempt++) {
    while ((c[key] || 0) >= (r.ok[key] || 0)) { await reserveNumbers(c, key); if (sid !== S.sid) throw new Error("abgemeldet"); }
    const n = c[key] || 0;
    c[key] = n + 1;
    saveLazy();
    const block = await C.sealJson(await C.msgKey(kMsg, dir, n), obj, C.BLOCK);
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
  if (!C.fitsJson(obj, C.BLOCK)) { toast("Die Nachricht ist zu lang.", "err"); return false; }
  if (!c.keep) m.exp = Date.now() + vs * 1000;
  r.msgs.push(m);                       // sofort anzeigen, das Senden läuft im Hintergrund
  renderChat(true);
  deliver(c, m, obj, true);
  return true;
}

async function deliver(c, m, obj, canRetry) {
  const r = runOf(c);
  try {
    m.n = await sendObj(c, obj);
    m.st = "sent";
    delete m.retry;
    if (c.keep) saveHistorySoon(c);
  } catch (e) {
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
  await deliver(c, m, { t: "m", i: m.i, k: kind, a, vs }, false);
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
async function histKey(kMsg) { return await C.hkdf(kMsg, "chatmesh2|history"); }
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
    const old = await readHistory(c, c.hist, r.kMsg, new Set(r.msgs.map(m => m.i)));
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
// Öffnet die verpackten Kanal-Schlüssel mit dem Kanal-Passwort.
async function unwrapKeys(c, password) {
  let plain;
  try { plain = JSON.parse(C.fromUtf8(await C.unwrapWithPassword(password, c.wrap))); }
  catch (e) { throw new Error("Falsches Passwort."); }
  return { kMsg: C.unb64(plain.m), kDel: C.unb64(plain.d), own: plain.o };
}
async function unlock(c, password) {
  const r = runOf(c);
  const k = await unwrapKeys(c, password);
  r.kMsg = k.kMsg; r.kDel = k.kDel; r.own = k.own;
}
function lockKeys(c) {
  const r = S.run[c.id];
  if (r) { r.kMsg = null; r.kDel = null; r.own = null; }
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
  askPassword("Kanal „" + c.name + "“ öffnen", "Dein Passwort für diesen Kanal", async (pw) => { await unlock(c, pw); go(); });
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
    ? `Screenshot-Versuch erkannt. Der Kanal „${name}“ wurde bei euch beiden aufgelöst.`
    : `Im Kanal „${name}“ wurde versucht, einen Screenshot zu machen. Der Kanal wurde aufgelöst.`;
  if (reason === "wipe") return `Dein Gegenüber im Kanal „${name}“ hat sein Konto gelöscht. Der Kanal wurde aufgelöst.`;
  return mine ? `Kanal „${name}“ gelöscht.` : `Der Kanal „${name}“ wurde vom Gegenüber gelöscht.`;
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
async function installKeys(c, keys, pwKey, salt) {
  const own = await dissolvePart(keys.kDis, c.dir);
  c.kt = C.b64(keys.kTag);
  c.pd = await dissolvePart(keys.kDis, peerDir(c));
  c.wrap = await C.wrapWithKey(pwKey, salt, C.utf8(JSON.stringify({ m: C.b64(keys.kMsg), d: C.b64(keys.kDel), o: own })));
  c.wb = C.b64(await C.boxSeal(C.unb64(S.acct.wp), C.utf8(JSON.stringify(own))));
  c.sym = keys.symbols;
  c.sn = 0; c.cn = 0; c.sr = 0; c.cr = 0; c.rn = 0; c.rc = 0; c.rp = []; c.rpc = [];
  c.keep = 0; c.shots = 0; c.rq = []; c.ro = []; c.hist = ""; c.rv = 0;
  c.vf = 0;      // Prüf-Zahl noch nicht verglichen
  c.cf = 0;      // Lösch-Grenze: ältere Nachrichten des Gegenübers werden verworfen
  c.hv = 0;      // zählt, wie oft der Kanal geleert wurde (für zwei Geräte)
  c.ca = [];     // schon umgesetzte Lösch-Aufträge des Gegenübers
  return own;
}

async function createChannel(name, password, keepReq) {
  const I = C.rand(12);
  const ik = await C.inviteKeys(I);
  const ex = await C.newExchangeKey();
  const salt = C.rand(16);
  const pwKey = await C.passwordKey(password, salt);
  const kr = keepReq ? 1 : 0;
  const offer = await C.sealJson(ik.key, { t: "offer", p: C.b64(ex.pub), kr }, C.BLOCK);
  // Das Lösch-Geheimnis für das Angebot kennt nur dieses Gerät. Wer den
  // Einmal-Schlüssel abfängt, kann das Angebot deshalb nicht austauschen.
  const delA = C.hex(C.rand(16));
  const code = await pilePost(ik.tagA, offer, delA);
  if (code !== 200) throw new Error("Der Kanal konnte gerade nicht angelegt werden. Bitte noch einmal versuchen.");
  // Die Geheimnisse der Einladung liegen im Konto nur verpackt mit dem Kanal-Passwort.
  const sealed = await C.seal(pwKey, C.utf8(JSON.stringify({ inv: C.b64(I), priv: ex.privJwk, pub: C.b64(ex.pub), kr })));
  const c = {
    id: C.hex(C.rand(8)), name, dir: "a", rv: 0,
    pend: { ta: ik.tagA, da: delA, tb: ik.tagB, exp: nowSec() + INVITE_SECONDS, s: C.b64(salt), c: C.b64(sealed) },
  };
  S.acct.ch.unshift(c);
  runOf(c).ps = { I, priv: ex.privJwk, pub: ex.pub, kr, pwKey, salt };
  await refreshExpect(c);
  await saveAccount();
  renderList();
  return c;
}

// Öffnet die verpackten Geheimnisse einer offenen Einladung mit dem Kanal-Passwort.
async function unsealPending(c, password) {
  const salt = C.unb64(c.pend.s);
  const pwKey = await C.passwordKey(password, salt);
  let plain;
  try { plain = JSON.parse(C.fromUtf8(await C.open(pwKey, C.unb64(c.pend.c)))); }
  catch (e) { throw new Error("Falsches Passwort."); }
  const ps = { I: C.unb64(plain.inv), priv: plain.priv, pub: C.unb64(plain.pub), kr: plain.kr ? 1 : 0, pwKey, salt };
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
    const own = await installKeys(c, keys, ps.pwKey, ps.salt);
    c.ro = ps.kr ? ["keep"] : [];          // die Anfrage steckte schon im Einmal-Code
    delete c.pend;
    r.ps = null;
    if (!S.acct.set.lockOn) { r.kMsg = keys.kMsg; r.kDel = keys.kDel; r.own = own; }
    await refreshExpect(c);
    await saveAccount();
    // Die beiden Blöcke des Einmal-Codes später unauffällig entfernen.
    const wait = randBetween(15000, 90000);
    queueDelete(offerTag, offerDel, wait);      // die Antwort entfernt das Gegenüber selbst
    toast("Kanal „" + c.name + "“ ist verbunden.", "ok");
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
  const pwKey = await C.passwordKey(password, salt);
  const c = { id: C.hex(C.rand(8)), name, dir: "b" };
  const own = await installKeys(c, keys, pwKey, salt);
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
  r.kMsg = keys.kMsg; r.kDel = keys.kDel; r.own = own;
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
  // Haufen abrufen
  loop(() => pileSync(false), () => randBetween(600, 1700));
  // Schein-Blöcke: sehen aus wie echte, werden nach kurzer Zeit wieder gelöscht
  loop(async () => {
    const big = randInt(40) === 0;
    const tag = C.hex(C.rand(16)), token = C.hex(C.rand(16));
    const code = await pilePost(tag, C.rand(big ? 65564 : 4124), token, 24);
    if (code === 200) queueDelete(tag, token, randBetween(4000, 90000));
  }, () => Math.round(randExp(10000, 1200, 45000)));
  // Ablauf der Anzeige-Zeit und der Einmal-Schlüssel
  loop(async () => { tickExpiry(); expireInvites(); }, () => 1000);
  // Konto in unregelmäßigen Abständen speichern, mit und ohne Anlass: von außen
  // sieht beides gleich aus. Größere Konten (mit behaltenem Verlauf) seltener.
  loop(async () => { await saveAccount(); }, () => {
    const mean = (S.blobLen || 0) < 100000 ? 14000 : ((S.blobLen || 0) < 400000 ? 45000 : 120000);
    return Math.round(randExp(mean, mean / 4, mean * 4));
  });
  // Schwere der Rechenaufgabe ab und zu neu holen
  loop(loadConfig, () => randBetween(120000, 360000));
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
  if (!v.pw || v.pw.length < PW_MIN) throw new Error("Das Kanal-Passwort braucht mindestens " + PW_MIN + " Zeichen.");
  if (v.pw !== v.pw2) throw new Error("Die beiden Passwörter stimmen nicht überein.");
}

function newChannelSheet() {
  formSheet("Neuer Kanal", {
    info: "Du bekommst einen Einmal-Schlüssel. Den gibst du deinem Gegenüber: als QR-Code zum Scannen oder als Schlüssel zum Kopieren. Er gilt 24 Stunden und nur ein einziges Mal.",
    fields: [
      { name: "name", label: "Name für diesen Kanal (frei wählbar, siehst nur du)", max: 40 },
      { name: "pw", type: "password", label: "Dein eigenes Passwort, um auf diesen Kanal zuzugreifen", hint: "Nur du kennst es. Du brauchst es jedes Mal, wenn du diesen Kanal öffnest oder löschst. Mit deinen 12 Anmeldewörtern hat es nichts zu tun." },
      { name: "pw2", type: "password", label: "Passwort wiederholen" },
      { name: "keep", type: "checkbox", label: "Verlauf behalten anfragen (dein Gegenüber muss zustimmen, sonst wird wie üblich gelöscht)" },
    ],
    submit: "Kanal anlegen",
    busy: "Kanal wird angelegt …",
    onSubmit: async (v) => {
      const name = (v.name || "").trim() || "Kanal";
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
  const ps = runOf(c).ps;
  if (!ps) {
    // In einer neuen Sitzung ist der Einmal-Code nur mit dem Kanal-Passwort lesbar.
    askPassword("Einmal-Schlüssel für „" + c.name + "“", "Dein Passwort für diesen Kanal", async (pw) => { await unsealPending(c, pw); setTimeout(() => showInvite(c), 0); }, "Anzeigen");
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
  const wait = el("p", "sheet-info center", "Warte auf den Beitritt … Der Kanal erscheint von selbst, sobald dein Gegenüber den Schlüssel eingegeben hat.");
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
  askPassword("Kanal „" + c.name + "“ verbinden", "Dein Passwort für diesen Kanal", async (pw) => { await finish(await unsealPending(c, pw)); }, "Verbinden");
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
  const inputs = formSheet("Kanal beitreten", {
    info: "Gib den Einmal-Schlüssel ein, den du von deinem Gegenüber bekommen hast: QR-Code scannen oder Schlüssel einfügen.",
    noFocus: true,
    fields: [
      { node: scanWrap },
      { name: "code", label: "Einmal-Schlüssel", placeholder: "Schlüssel hier einfügen", max: 60 },
      { name: "name", label: "Name für diesen Kanal (frei wählbar, siehst nur du)", max: 40 },
      { name: "pw", type: "password", label: "Dein eigenes Passwort, um auf diesen Kanal zuzugreifen", hint: "Nur du kennst es. Dein Gegenüber hat sein eigenes. Du brauchst es jedes Mal, wenn du diesen Kanal öffnest oder löschst." },
      { name: "pw2", type: "password", label: "Passwort wiederholen" },
    ],
    submit: "Beitreten",
    busy: "Kanal wird verbunden …",
    onCancel: stopScan,
    onSubmit: async (v) => {
      const name = (v.name || "").trim() || "Kanal";
      checkPw(v);
      stopScan();
      const c = await joinChannel(v.code, name.slice(0, 40), v.pw);
      closeSheet();
      toast("Kanal „" + c.name + "“ ist verbunden.", "ok");
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

function settingsSheet() {
  const set = S.acct.set;
  const v = set.view;
  formSheet("Einstellungen", {
    info: "So lange bleibt eine Nachricht von dir nach dem Öffnen sichtbar. Danach verschwindet sie bei dir und beim Gegenüber. Verlässt jemand den Chat, ist sie bei ihm sofort weg.",
    noFocus: true,
    fields: [
      { name: "d", type: "number", grid: true, label: "Tage", value: Math.floor(v / 86400) },
      { name: "h", type: "number", grid: true, label: "Stunden", value: Math.floor(v % 86400 / 3600) },
      { name: "m", type: "number", grid: true, label: "Minuten", value: Math.floor(v % 3600 / 60) },
      { name: "s", type: "number", grid: true, label: "Sekunden", value: v % 60 },
      { node: el("div", "sheet-section", "Kanal-Sperre") },
      { name: "lockOn", type: "checkbox", label: "Kanal-Passwort jedes Mal verlangen: beim Öffnen und immer, wenn du einen Kanal verlassen hast. Ausgeschaltet fragt jeder Kanal nur einmal je Anmeldung.", value: set.lockOn },
      { node: infoNode("Lädst du die Seite neu, bleibst du angemeldet und gibst nur deinen Code ein. Schließt du das Fenster, bist du abgemeldet. chatmesh beobachtet nicht, ob du die Maus bewegst oder tippst.") },
    ],
    submit: "Speichern",
    onSubmit: async (val) => {
      const num = (x) => Math.max(0, Math.floor(Number(x) || 0));
      const total = num(val.d) * 86400 + num(val.h) * 3600 + num(val.m) * 60 + num(val.s);
      if (total < VIEW_MIN) throw new Error("Mindestens " + VIEW_MIN + " Sekunden.");
      if (total > VIEW_MAX) throw new Error("Höchstens 30 Tage.");
      set.view = total;
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
      ? "Dein Gegenüber möchte, dass der Verlauf dieses Kanals behalten wird. Dann bleiben Nachrichten bei euch beiden gespeichert (verschlüsselt, nur für euch lesbar), statt zu verschwinden. Bilder, Videos und Dateien bleiben dabei etwa 5 Wochen abrufbar. Jeder von euch kann den Verlauf jederzeit bei beiden wieder löschen, ohne den anderen zu fragen."
      : "Dein Gegenüber möchte in diesem Kanal Screenshots erlauben. Dann wird der Kanal bei einem Screenshot nicht mehr aufgelöst."),
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
  items.push(menuItem("Alle Nachrichten bei beiden löschen", "Sofort und ohne Zustimmung deines Gegenübers. Gilt auch für einen behaltenen Verlauf. Der Kanal bleibt bestehen.", true, () => confirmClear(c)));
  if (c.keep) items.push(menuItem("Verlauf nicht mehr behalten", "Sofort und ohne Zustimmung deines Gegenübers. Der gespeicherte Verlauf wird bei euch beiden gelöscht, ab dann verschwinden Nachrichten wieder.", false, () => endMode(c, "keep")));
  else items.push(menuItem("Verlauf behalten anfragen", "Standard ist: alles verschwindet. Dein Gegenüber muss zustimmen. Abschalten kann es später jeder von euch allein.", false, () => requestMode(c, "keep")));
  if (c.shots) items.push(menuItem("Screenshots wieder verbieten", "Sofort und ohne Zustimmung deines Gegenübers.", false, () => endMode(c, "shots")));
  else items.push(menuItem("Screenshots erlauben anfragen", "Standard ist: Ein erkannter Screenshot-Versuch löst den Kanal bei euch beiden auf. Am Handy kann eine Webseite Screenshots nicht erkennen.", false, () => requestMode(c, "shots")));
  const sym = el("div", "sheet-item static");
  sym.appendChild(el("span", "sheet-label", c.vf ? "Prüf-Zahl (geprüft)" : "Prüf-Zahl (noch nicht geprüft)"));
  sym.appendChild(el("span", "sym-row", c.sym || ""));
  sym.appendChild(el("span", "sheet-sub", "Vergleicht diese Zahl einmal, am besten persönlich oder am Telefon. Steht bei deinem Gegenüber dieselbe Zahl, hat sich niemand dazwischengedrängt."));
  if (!c.vf) {
    const okBtn = el("button", "ghost small", "Die Zahl stimmt überein");
    okBtn.type = "button";
    okBtn.addEventListener("click", () => { c.vf = 1; bump(c); saveSoon(); closeSheet(); renderChat(); toast("Kanal als geprüft markiert.", "ok"); });
    sym.appendChild(okBtn);
  }
  items.push(sym);
  items.push(menuItem("Kanal umbenennen", "", false, () => {
    formSheet("Kanal umbenennen", {
      fields: [{ name: "name", label: "Neuer Name (siehst nur du)", value: c.name, max: 40 }],
      submit: "Speichern",
      onSubmit: async (v) => { c.name = ((v.name || "").trim() || c.name).slice(0, 40); bump(c); await saveAccount(); closeSheet(); renderList(); renderChat(); },
    });
  }));
  items.push(menuItem("Kanal löschen", "Geht jederzeit, auch wenn der Kanal leer ist. Löscht den Kanal mit allem darin bei dir und bei deinem Gegenüber. Braucht dein Kanal-Passwort.", true, () => deleteChannelSheet(c)));
  openSheetNodes(c.name, items);
}

function deleteChannelSheet(c) {
  formSheet("Kanal „" + c.name + "“ löschen", {
    info: "Der Kanal wird mit allem darin bei dir und bei deinem Gegenüber gelöscht: Nachrichten, Anhänge und ein behaltener Verlauf. Das geht jederzeit, auch wenn der Kanal leer ist, und lässt sich nicht rückgängig machen.",
    fields: [{ name: "pw", type: "password", label: "Dein Passwort für diesen Kanal" }],
    submit: "Endgültig löschen",
    danger: true,
    busy: "Wird geprüft …",
    onSubmit: async (v) => {
      // Nur mit dem Passwort lässt sich die Mitteilung ans Gegenüber überhaupt erzeugen.
      const k = await unwrapKeys(c, v.pw);
      if (!(await dissolveChannel(c, "deleted", k.own))) throw new Error("Keine Verbindung. Der Kanal wurde nicht gelöscht, bitte noch einmal versuchen.");
      closeSheet();
      toast("Kanal gelöscht", "ok");
    },
  });
}

async function deleteForBoth(c, m) {
  const r = runOf(c);
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
    infoNode("Alle Nachrichten in diesem Kanal verschwinden sofort bei dir und bei deinem Gegenüber, auch ein behaltener Verlauf. Das lässt sich nicht rückgängig machen."),
    no, yes,
  ], true);
}
function clearLocal(c) {
  const r = runOf(c);
  for (const m of r.msgs) dropMedia(c, m, true);
  r.msgs = [];
  c.hist = "";
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
    try { b = await C.openJson(await C.msgKey(kMsg, p + "c", n), block, C.BLOCK); } catch (e) { continue; }
    if (!b || typeof b !== "object") continue;
    if (b.t === "clr" && Number.isInteger(b.upto) && b.upto >= 0) { cutoff = Math.max(cutoff, b.upto); fresh.push(n); }
    else if (b.t === "set" && b.k === "keep" && !b.v) { keepOff = true; fresh.push(n); }
  }
  if (!fresh.length) return;
  c.ca = [...(c.ca || []), ...fresh].filter(n => n >= (c.rc || 0) - WINDOW_BACK).slice(-64);
  if (keepOff && c.keep) c.keep = 0;
  if (cutoff >= 0) {
    c.cf = Math.max(c.cf || 0, cutoff);
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
  items.push(menuItem("Bei beiden löschen", "Verschwindet sofort bei dir und beim Gegenüber. Geht jederzeit, auch bei behaltenem Verlauf.", true, () => deleteForBoth(c, m)));
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
    e.appendChild(document.createTextNode("Noch keine Kanäle."));
    e.appendChild(document.createElement("br"));
    e.appendChild(document.createTextNode("Lege einen neuen Kanal an oder tritt mit einem Einmal-Schlüssel bei."));
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
    if (c.pend) sub = c.pend.ans ? "Beitritt da: antippen und Passwort eingeben" : "Wartet auf Beitritt (Einmal-Schlüssel anzeigen)";
    else if (c.id === S.active) sub = "geöffnet";
    else if (!unlocked(c)) sub = "gesperrt";
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
    if (S.me) stream.appendChild(el("div", "empty", "Wähle links einen Kanal oder lege einen neuen an."));
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
      if (!c.shots && !m.me) { toast("Speichern ist in diesem Kanal nicht erlaubt (wie Screenshots).", "err"); return; }
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
    if (S.active) view.classList.add("peek-chat"); else toast("Wähle erst einen Kanal aus.");
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
    const c = S.active ? chan(S.active) : null;       // alle gewählten Dateien gehen an DIESEN Kanal
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
if (location.hostname === "127.0.0.1" || location.hostname === "localhost") window.__cmTest = { S, closeChannel, LIM, clearForBoth };

document.addEventListener("DOMContentLoaded", () => {
  bindUI();
  bindShield();
  if (readSession()) showCode("unlock"); else show("auth");
  renderChat();
  if (!location.host.endsWith(".onion")) $("#tor-hint").hidden = false;
  // Reste früherer Fassungen entfernen: Service Worker, Zwischenspeicher, Browser-Speicher.
  if ("serviceWorker" in navigator) navigator.serviceWorker.getRegistrations().then(rs => rs.forEach(r => r.unregister())).catch(() => {});
  if (typeof caches !== "undefined") caches.keys().then(ks => Promise.all(ks.map(k => caches.delete(k)))).catch(() => {});
  try { localStorage.clear(); for (const k of Object.keys(sessionStorage)) if (k !== SESSION_KEY) sessionStorage.removeItem(k); } catch (e) {}
});
})();
