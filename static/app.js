// lehno-mesh Phase 1.6 - Zero-Metadata Sealed-Sender + Mnemonic-Recovery +
// Encrypted-Spitznamen-Sync + volle Adress-Anzeige.

const STATE = {
  me: null,                       // { address, jwt, identityPriv, signingPriv, kek, identity_pub_b64, signing_pub_b64 }
  pubKeyCache: {},                // address -> { identity_pub_b64, signing_pub_b64 }
  contacts: [],                   // [{ address, last_at }] - aus encrypted userdata blob
  nicknames: {},                  // address -> spitzname (lokaler Klartext, sync via blob)
  declined: [],                   // [address] - aus encrypted userdata blob
  userdataVersion: 0,             // optimistic concurrency
  userdataDirty: false,
  requests: [],                   // [{ address, packet_id, content_preview }]
  activeChat: null,
  messagesByContact: {},          // address -> [{ id, isMe, body, msg_type, attachment_token, ts }]
  ws: null,
  lastInboxId: 0,
};

const $ = (sel, root=document) => root.querySelector(sel);
const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

function show(viewName) {
  $$(".view").forEach(v => v.classList.remove("active"));
  $("#view-" + viewName).classList.add("active");
}

function toast(text, kind="") {
  let t = $(".toast");
  if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.appendChild(t); }
  t.textContent = text;
  t.className = "toast show " + kind;
  setTimeout(() => t.classList.remove("show"), 2400);
}

// Anzeige-Name: Spitzname wenn gesetzt, sonst volle Adresse.
function displayName(addr) {
  if (!addr) return "";
  const nick = STATE.nicknames[addr];
  return nick && nick.trim() ? nick : addr;
}

// Avatar-Initialen: aus Spitzname (1-2 Buchstaben) oder Adress-Praefix (2 Zeichen).
function avatarLabel(addr) {
  if (!addr) return "??";
  const nick = STATE.nicknames[addr];
  if (nick && nick.trim()) {
    const parts = nick.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    // Einzelnes Wort: 2 Buchstaben statt 1 fuer Konsistenz
    return parts[0].slice(0, 2).toUpperCase();
  }
  return addr.replace(/^mesh:/, "").slice(0, 2).toUpperCase();
}

// =========================================================================
// LOCAL STORAGE (nur ausgehender Nachrichten-Cache + last-address)
// Kontakte/Spitznamen/declined liegen in encrypted userdata-Blob auf dem Server.
// =========================================================================
function storageKey(suffix) {
  return `lehno-mesh:${STATE.me?.address || "anon"}:${suffix}`;
}
function loadOutgoing(peer) {
  try { return JSON.parse(localStorage.getItem(storageKey("out:" + peer)) || "[]"); }
  catch { return []; }
}
function appendOutgoing(peer, msg) {
  const list = loadOutgoing(peer);
  list.push(msg);
  if (list.length > 1000) list.splice(0, list.length - 1000);
  localStorage.setItem(storageKey("out:" + peer), JSON.stringify(list));
}

// =========================================================================
// API
// =========================================================================
const API = {
  async post(path, body) {
    const headers = { "content-type": "application/json" };
    if (STATE.me?.jwt) headers["authorization"] = "Bearer " + STATE.me.jwt;
    const r = await fetch(path, { method: "POST", headers, body: JSON.stringify(body) });
    if (!r.ok) {
      const err = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(err.detail || r.statusText);
    }
    return r.json();
  },
  async put(path, body) {
    const headers = { "content-type": "application/json" };
    if (STATE.me?.jwt) headers["authorization"] = "Bearer " + STATE.me.jwt;
    const r = await fetch(path, { method: "PUT", headers, body: JSON.stringify(body) });
    if (!r.ok) {
      const err = await r.json().catch(() => ({ detail: r.statusText }));
      const ex = new Error(err.detail || r.statusText);
      ex.status = r.status;
      throw ex;
    }
    return r.json();
  },
  async get(path) {
    const headers = {};
    if (STATE.me?.jwt) headers["authorization"] = "Bearer " + STATE.me.jwt;
    const r = await fetch(path, { headers });
    if (!r.ok) {
      const err = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(err.detail || r.statusText);
    }
    return r.json();
  },
  async del(path) {
    const r = await fetch(path, { method: "DELETE", headers: { "authorization": "Bearer " + STATE.me.jwt } });
    if (!r.ok) throw new Error(r.statusText);
    return r.json();
  },
  async uploadAttachment(blob) {
    const fd = new FormData();
    fd.append("file", new File([blob], "encrypted.bin", { type: "application/octet-stream" }));
    const r = await fetch("/api/attachments", {
      method: "POST",
      headers: { "authorization": "Bearer " + STATE.me.jwt },
      body: fd,
    });
    if (!r.ok) throw new Error("upload failed");
    return r.json();   // { token, size_bytes }
  },
  async fetchAttachment(token) {
    const r = await fetch("/api/attachments/" + encodeURIComponent(token), {
      headers: { "authorization": "Bearer " + STATE.me.jwt },
    });
    if (!r.ok) throw new Error("download failed");
    return new Uint8Array(await r.arrayBuffer());
  },
};

// =========================================================================
// ENCRYPTED USERDATA SYNC
// Format des klartext-Userdata-Objekts:
//   { contacts: [{address, last_at}], nicknames: {address: name}, declined: [address] }
// =========================================================================
async function loadUserdata() {
  try {
    const resp = await API.get("/api/userdata");
    STATE.userdataVersion = resp.version || 0;
    if (!resp.ciphertext_b64) {
      STATE.contacts = [];
      STATE.nicknames = {};
      STATE.declined = [];
      return;
    }
    const data = await LehnoCrypto.decryptUserdata(STATE.me.kek, resp);
    STATE.contacts = Array.isArray(data?.contacts) ? data.contacts : [];
    STATE.nicknames = (data?.nicknames && typeof data.nicknames === "object") ? data.nicknames : {};
    STATE.declined = Array.isArray(data?.declined) ? data.declined : [];
  } catch (e) {
    console.warn("loadUserdata failed", e);
    STATE.contacts = [];
    STATE.nicknames = {};
    STATE.declined = [];
  }
}

let _saveTimer = null;
function scheduleUserdataSave() {
  STATE.userdataDirty = true;
  if (_saveTimer) clearTimeout(_saveTimer);
  _saveTimer = setTimeout(saveUserdata, 400);
}

async function saveUserdata() {
  if (!STATE.me?.kek) return;
  _saveTimer = null;
  STATE.userdataDirty = false;
  const data = {
    contacts: STATE.contacts,
    nicknames: STATE.nicknames,
    declined: STATE.declined,
  };
  try {
    const enc = await LehnoCrypto.encryptUserdata(STATE.me.kek, data);
    const resp = await API.put("/api/userdata", {
      ...enc,
      expected_version: STATE.userdataVersion,
    });
    STATE.userdataVersion = resp.version;
  } catch (e) {
    if (e.status === 409) {
      // anderes Geraet hat schneller geschrieben -> reload + merge unsere Aenderungen
      const before = { contacts: [...STATE.contacts], nicknames: {...STATE.nicknames}, declined: [...STATE.declined] };
      await loadUserdata();
      // Merge: lokale Spitznamen/Kontakte/declined haben Vorrang
      for (const c of before.contacts) {
        if (!STATE.contacts.find(x => x.address === c.address)) STATE.contacts.unshift(c);
      }
      Object.assign(STATE.nicknames, before.nicknames);
      for (const a of before.declined) {
        if (!STATE.declined.includes(a)) STATE.declined.push(a);
      }
      // Retry mit neuer Version
      try {
        const enc = await LehnoCrypto.encryptUserdata(STATE.me.kek, {
          contacts: STATE.contacts, nicknames: STATE.nicknames, declined: STATE.declined,
        });
        const resp = await API.put("/api/userdata", { ...enc, expected_version: STATE.userdataVersion });
        STATE.userdataVersion = resp.version;
      } catch (e2) {
        console.warn("userdata save retry failed", e2);
      }
    } else {
      console.warn("userdata save failed", e);
    }
  }
}

// =========================================================================
// REGISTER / LOGIN
// =========================================================================
async function doRegister(password) {
  const setup = await LehnoCrypto.setupAccount(password);
  const payload = {
    auth_key_b64: setup.auth_key_b64,
    salt_b64: setup.salt_b64,
    identity_pub_b64: setup.identity_pub_b64,
    signing_pub_b64: setup.signing_pub_b64,
    keys_blob_b64: setup.keys_blob_b64,
    keys_nonce_b64: setup.keys_nonce_b64,
    kek_blob_b64: setup.kek_blob_b64,
    kek_nonce_b64: setup.kek_nonce_b64,
  };
  const resp = await API.post("/api/register", payload);

  STATE.me = {
    address: resp.address,
    jwt: resp.jwt,
    identityPriv: null,
    signingPriv: null,
    kek: setup.kek_for_backup,
    identity_pub_b64: setup.identity_pub_b64,
    signing_pub_b64: setup.signing_pub_b64,
  };
  await unlockAfterRegister(password);

  const mnemonic = await LehnoBip39.bytesToMnemonic(setup.kek_for_backup);
  showMnemonic(mnemonic, resp.address);
}

async function unlockAfterRegister(password) {
  const init = await API.post("/api/login/init", { address: STATE.me.address });
  const salt = LehnoCrypto.unb64(init.salt_b64);
  const { auth_key } = await LehnoCrypto.deriveFromPassword(password, salt);
  const resp = await API.post("/api/login", { address: STATE.me.address, auth_key_b64: LehnoCrypto.b64(auth_key) });
  const live = await LehnoCrypto.unlockAccount(password, resp);
  STATE.me = {
    ...STATE.me,
    identityPriv: live.identityPriv,
    signingPriv: live.signingPriv,
    kek: live.kek,
    jwt: live.jwt,
  };
}

async function doLogin(address, password) {
  const init = await API.post("/api/login/init", { address });
  const salt = LehnoCrypto.unb64(init.salt_b64);
  const { auth_key } = await LehnoCrypto.deriveFromPassword(password, salt);
  const resp = await API.post("/api/login", { address, auth_key_b64: LehnoCrypto.b64(auth_key) });
  const live = await LehnoCrypto.unlockAccount(password, resp);
  STATE.me = {
    address: resp.address,
    jwt: resp.jwt,
    identityPriv: live.identityPriv,
    signingPriv: live.signingPriv,
    kek: live.kek,
  };
  const my = await API.get("/api/keys/" + encodeURIComponent(resp.address));
  STATE.me.identity_pub_b64 = my.identity_pub_b64;
  STATE.me.signing_pub_b64 = my.signing_pub_b64;
  await afterLogin();
}

async function doRecover(address, mnemonic, newPassword) {
  if (!address.startsWith("mesh:")) address = "mesh:" + address;
  const init = await API.post("/api/recover/init", { address });
  const finalizePayload = await LehnoCrypto.recoverWithMnemonic(address, mnemonic, newPassword, init);
  await API.post("/api/recover/finalize", finalizePayload);
  // Direkt einloggen mit dem neuen Passwort
  await doLogin(address, newPassword);
}

function showMnemonic(mnemonic, address) {
  show("mnemonic");
  $("#my-address-display").textContent = address;
  setLastBackupData(address, mnemonic);
  const grid = $("#mnemonic-grid");
  grid.innerHTML = "";
  mnemonic.split(" ").forEach((w, i) => {
    const el = document.createElement("div");
    el.className = "w";
    el.innerHTML = `<span class="w-num">${i + 1}.</span><span class="w-text">${w}</span>`;
    grid.appendChild(el);
  });
  $("#mnemonic-confirm").checked = false;
  $("#mnemonic-continue").disabled = true;
}

function logout() {
  if (STATE.ws) { try { STATE.ws.close(); } catch(e) {} }
  STATE.me = null;
  STATE.contacts = [];
  STATE.nicknames = {};
  STATE.declined = [];
  STATE.requests = [];
  STATE.messagesByContact = {};
  STATE.activeChat = null;
  STATE.lastInboxId = 0;
  STATE.userdataVersion = 0;
  show("auth");
}

async function afterLogin() {
  rememberAddress(STATE.me.address);
  $("#me-address-full").textContent = STATE.me.address;
  await loadUserdata();
  show("chat");
  renderSidebar();
  startWebSocket();
  await pollInbox();
}

// =========================================================================
// INBOX
// =========================================================================
async function pollInbox() {
  try {
    const r = await API.get("/api/packets/inbox?since_id=" + STATE.lastInboxId);
    const ackIds = [];
    const declinedSet = new Set(STATE.declined);

    for (const p of r.packets) {
      STATE.lastInboxId = Math.max(STATE.lastInboxId, p.id);
      try {
        const body = await LehnoCrypto.decryptMessage(STATE.me, p);
        const senderAddr = body.sender_address;
        if (!senderAddr) continue;

        if (declinedSet.has(senderAddr)) {
          ackIds.push(p.id);
          continue;
        }

        const isKnown = STATE.contacts.find(c => c.address === senderAddr);
        const msg_type = body.msg_type || "text";
        const isContactReq = !!body.is_contact_request;

        // Plain-Content fuer Anzeige aufbereiten
        let displayPlain = body.text || "";
        let mediaMeta = null;
        if (msg_type !== "text") {
          mediaMeta = {
            caption: body.caption || "",
            mime: body.mime || "",
            file_key_b64: body.file_key_b64,
            file_iv_b64: body.file_iv_b64,
          };
          displayPlain = JSON.stringify(mediaMeta);
        }

        const msgObj = {
          id: p.id, server_id: p.id, isMe: false,
          plain: displayPlain, msg_type,
          attachment_token: body.attachment_token || null,
          ts: new Date(p.created_day * 1000).toISOString(),
        };

        if (isContactReq && !isKnown) {
          if (!STATE.requests.find(rr => rr.address === senderAddr)) {
            STATE.requests.push({
              address: senderAddr,
              packet_id: p.id,
              preview: msg_type === "text" ? (body.text || "") : "[" + msg_type + "]",
              ts: p.created_day,
            });
          }
          (STATE.messagesByContact[senderAddr] ||= []).push(msgObj);
        } else if (isKnown) {
          (STATE.messagesByContact[senderAddr] ||= []).push(msgObj);
          isKnown.last_at = new Date().toISOString();
          scheduleUserdataSave();
          ackIds.push(p.id);
        } else {
          if (!STATE.requests.find(rr => rr.address === senderAddr)) {
            STATE.requests.push({
              address: senderAddr,
              packet_id: p.id,
              preview: msg_type === "text" ? (body.text || "") : "[" + msg_type + "]",
              ts: p.created_day,
            });
          }
          (STATE.messagesByContact[senderAddr] ||= []).push(msgObj);
        }
      } catch (e) {
        console.warn("decrypt failed for packet", p.id, e);
      }
    }

    if (ackIds.length) {
      try { await API.post("/api/packets/ack", ackIds); } catch(e) {}
    }

    renderSidebar();
    if (STATE.activeChat) renderChat();
  } catch(e) {
    console.warn("inbox poll", e);
  }
}

// =========================================================================
// CONTACT REQUEST AKZEPTIEREN / ABLEHNEN
// =========================================================================
async function acceptRequest(addr) {
  if (!STATE.contacts.find(c => c.address === addr)) {
    STATE.contacts.unshift({ address: addr, last_at: new Date().toISOString() });
    scheduleUserdataSave();
  }
  const reqs = STATE.requests.filter(r => r.address === addr);
  STATE.requests = STATE.requests.filter(r => r.address !== addr);
  if (reqs.length) {
    try { await API.post("/api/packets/ack", reqs.map(r => r.packet_id)); } catch(e) {}
  }
  const followups = (STATE.messagesByContact[addr] || []).map(m => m.server_id).filter(Boolean);
  if (followups.length) {
    try { await API.post("/api/packets/ack", followups); } catch(e) {}
  }
  renderSidebar();
  if (STATE.activeChat === addr) renderChat();
  toast("Kontakt akzeptiert", "ok");
}

async function declineRequest(addr) {
  if (!STATE.declined.includes(addr)) STATE.declined.push(addr);
  scheduleUserdataSave();
  const reqs = STATE.requests.filter(r => r.address === addr);
  STATE.requests = STATE.requests.filter(r => r.address !== addr);
  if (reqs.length) {
    try { await API.post("/api/packets/ack", reqs.map(r => r.packet_id)); } catch(e) {}
  }
  delete STATE.messagesByContact[addr];
  if (STATE.activeChat === addr) {
    STATE.activeChat = null;
    $("#view-chat").classList.remove("peek-chat");
  }
  renderSidebar();
  toast("Anfrage abgelehnt");
}

// =========================================================================
// SPITZNAMEN
// =========================================================================
function setNickname(addr, nick) {
  const trimmed = (nick || "").trim();
  if (trimmed) STATE.nicknames[addr] = trimmed;
  else delete STATE.nicknames[addr];
  scheduleUserdataSave();
  renderSidebar();
  if (STATE.activeChat === addr) renderChat();
}

function promptNickname(addr) {
  const current = STATE.nicknames[addr] || "";
  const next = prompt(`Spitzname fuer ${addr}\n\n(verschluesselt, nur du siehst ihn)`, current);
  if (next === null) return;  // Cancel
  setNickname(addr, next);
  toast(next.trim() ? "Spitzname gespeichert" : "Spitzname entfernt", "ok");
}

// =========================================================================
// SIDEBAR RENDERING
// =========================================================================
let currentList = "chats";
function renderSidebar() {
  const cnt = STATE.requests.length;
  const badge = $("#req-count");
  badge.textContent = cnt > 0 ? String(cnt) : "";

  if (currentList === "chats") {
    $("#contact-list").style.display = "";
    $("#request-list").style.display = "none";
    renderContacts();
  } else {
    $("#contact-list").style.display = "none";
    $("#request-list").style.display = "";
    renderRequests();
  }
}

function renderContacts() {
  const list = $("#contact-list");
  list.innerHTML = "";
  if (!STATE.contacts.length) {
    list.innerHTML = '<div class="contact-empty">Noch keine Chats.<br>Fuege oben eine Adresse hinzu.</div>';
    return;
  }
  STATE.contacts.forEach(c => {
    const div = document.createElement("div");
    div.className = "contact" + (c.address === STATE.activeChat ? " active" : "");
    const nick = STATE.nicknames[c.address];
    const hasNick = !!(nick && nick.trim());
    const nameClass = hasNick ? "name is-nick" : "name is-address";
    const nameContent = hasNick
      ? `${escapeHtml(nick)}<div class="sub-addr">${escapeHtml(c.address)}</div>`
      : escapeHtml(c.address);
    div.innerHTML = `
      <div class="avatar">${escapeHtml(avatarLabel(c.address))}</div>
      <div class="meta">
        <div class="${nameClass}" title="${escapeHtml(c.address)}">${nameContent}</div>
        <div class="last">${formatRelative(c.last_at)}</div>
      </div>`;
    div.addEventListener("click", () => openChat(c.address));
    list.appendChild(div);
  });
}

function renderRequests() {
  const list = $("#request-list");
  list.innerHTML = "";
  if (!STATE.requests.length) {
    list.innerHTML = '<div class="contact-empty">Keine offenen Anfragen.</div>';
    return;
  }
  STATE.requests.forEach(r => {
    const div = document.createElement("div");
    div.className = "contact" + (r.address === STATE.activeChat ? " active" : "");
    div.innerHTML = `
      <div class="avatar req">${escapeHtml(avatarLabel(r.address))}</div>
      <div class="meta">
        <div class="name is-address" title="${escapeHtml(r.address)}">${escapeHtml(r.address)}</div>
        <div class="last warn">Anfrage: ${escapeHtml((r.preview || "").slice(0, 32))}</div>
      </div>`;
    div.addEventListener("click", () => openChat(r.address));
    list.appendChild(div);
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function formatRelative(iso) {
  if (!iso) return "";
  const dt = new Date(iso);
  const diff = (Date.now() - dt.getTime()) / 1000;
  if (diff < 60) return "gerade eben";
  if (diff < 3600) return Math.floor(diff / 60) + " Min";
  if (diff < 86400) return Math.floor(diff / 3600) + " Std";
  return Math.floor(diff / 86400) + " Tage";
}

// =========================================================================
// CHAT VIEW
// =========================================================================
async function openChat(address) {
  STATE.activeChat = address;
  $("#view-chat").classList.add("peek-chat");
  renderSidebar();
  await fetchPubKey(address).catch(() => {});
  renderChat();
}

async function fetchPubKey(address) {
  if (STATE.pubKeyCache[address]) return STATE.pubKeyCache[address];
  const r = await API.get("/api/keys/" + encodeURIComponent(address));
  STATE.pubKeyCache[address] = r;
  return r;
}

function renderChat() {
  const stream = $("#chat-stream");
  const header = $("#chat-header");
  const banner = $("#request-banner");
  const peer = STATE.activeChat;
  if (!peer) {
    stream.innerHTML = "";
    header.innerHTML = "";
    banner.style.display = "none";
    return;
  }
  const isRequest = STATE.requests.find(r => r.address === peer);
  const isContact = STATE.contacts.find(c => c.address === peer);
  const nick = STATE.nicknames[peer] || "";

  const nickRow = nick
    ? `<div class="head-name">${escapeHtml(nick)}</div>`
    : "";
  header.innerHTML = `
    <button class="ghost small back" id="btn-back" aria-label="Zurueck">&larr;</button>
    <div class="avatar">${escapeHtml(avatarLabel(peer))}</div>
    <div class="head-id">
      ${nickRow}
      <div class="head-addr" title="Adresse kopieren">${escapeHtml(peer)}</div>
    </div>
    <button class="ghost small head-action" id="btn-set-nickname" title="Spitzname setzen">
      ${nick ? "Umbenennen" : "Spitzname"}
    </button>
    <div class="lock" title="Ende-zu-Ende verschluesselt">&#x1F512;</div>`;

  $("#btn-back").addEventListener("click", () => {
    $("#view-chat").classList.remove("peek-chat");
    STATE.activeChat = null;
    renderSidebar();
  });
  $("#btn-set-nickname").addEventListener("click", () => promptNickname(peer));
  $(".head-addr", header).addEventListener("click", () => {
    navigator.clipboard.writeText(peer);
    toast("Adresse kopiert", "ok");
  });

  banner.style.display = (isRequest && !isContact) ? "flex" : "none";

  const incoming = STATE.messagesByContact[peer] || [];
  const outgoing = loadOutgoing(peer);
  const all = [...incoming, ...outgoing].sort((a, b) => new Date(a.ts) - new Date(b.ts));

  if (!all.length) {
    stream.innerHTML = '<div class="empty">Noch keine Nachrichten.</div>';
    return;
  }

  stream.innerHTML = "";
  for (const m of all) {
    const row = document.createElement("div");
    row.className = "msg-row" + (m.isMe ? " me" : "");
    const bubble = document.createElement("div");
    bubble.className = "bubble";

    if (m.msg_type === "text") {
      bubble.textContent = m.plain;
    } else {
      try {
        const meta = JSON.parse(m.plain);
        const captionEl = meta.caption ? document.createElement("div") : null;
        if (captionEl) captionEl.textContent = meta.caption;
        const mediaEl = document.createElement(
          m.msg_type === "voice" ? "audio" : (m.msg_type === "video" ? "video" : "img")
        );
        mediaEl.dataset.token = m.attachment_token || "";
        mediaEl.dataset.fileKey = meta.file_key_b64;
        mediaEl.dataset.fileIv = meta.file_iv_b64;
        mediaEl.dataset.mime = meta.mime || (m.msg_type === "voice" ? "audio/webm" : "image/jpeg");
        if (m.msg_type !== "image") mediaEl.controls = true;
        bubble.appendChild(mediaEl);
        if (captionEl) bubble.appendChild(captionEl);
        loadMediaInto(mediaEl).catch(()=>{});
      } catch(e) {
        bubble.textContent = "[Mediennachricht]";
      }
    }
    const ts = document.createElement("span");
    ts.className = "ts";
    ts.textContent = formatTime(m.ts);
    bubble.appendChild(ts);
    row.appendChild(bubble);
    stream.appendChild(row);
  }
  stream.scrollTop = stream.scrollHeight;
}

async function loadMediaInto(el) {
  try {
    const token = el.dataset.token;
    if (!token) throw new Error("no attachment token");
    const enc = await API.fetchAttachment(token);
    const fileKey = LehnoCrypto.unb64(el.dataset.fileKey);
    const iv = LehnoCrypto.unb64(el.dataset.fileIv);
    const plain = await LehnoCrypto.decryptFile(new Uint8Array(fileKey), iv, enc);
    const blob = new Blob([plain], { type: el.dataset.mime });
    el.src = URL.createObjectURL(blob);
    attachDownloadWarning(el);
  } catch (e) {
    el.alt = "[Fehler beim Entschluesseln]";
  }
}

function formatTime(iso) {
  if (!iso) return "";
  const dt = new Date(iso);
  return dt.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
}

// =========================================================================
// SEND
// =========================================================================
async function sendText(text) {
  if (!STATE.activeChat) return;
  const recipientKeys = await fetchPubKey(STATE.activeChat);
  const isContact = STATE.contacts.find(c => c.address === STATE.activeChat);
  const body = {
    msg_type: "text",
    is_contact_request: !isContact,
    text,
  };
  const enc = await LehnoCrypto.encryptMessage(STATE.me, recipientKeys.identity_pub_b64, body);
  const resp = await API.post("/api/packets", {
    recipient_address: STATE.activeChat,
    ephemeral_pub_b64: enc.ephemeral_pub_b64,
    nonce_b64: enc.nonce_b64,
    ciphertext_b64: enc.ciphertext_b64,
    signature_b64: enc.signature_b64,
  });
  const msg = {
    id: "out-" + resp.packet_id,
    isMe: true,
    plain: text,
    msg_type: "text",
    ts: new Date().toISOString(),
  };
  appendOutgoing(STATE.activeChat, msg);
  if (!isContact) {
    STATE.contacts.unshift({ address: STATE.activeChat, last_at: new Date().toISOString() });
    scheduleUserdataSave();
    renderSidebar();
  } else {
    isContact.last_at = new Date().toISOString();
    scheduleUserdataSave();
  }
  renderChat();
}

async function sendMedia(blob, mime, msgType, caption="") {
  if (!STATE.activeChat) return;
  toast("Verschluesseln + senden...");
  const fileBytes = new Uint8Array(await blob.arrayBuffer());
  const enc = await LehnoCrypto.encryptFile(fileBytes);
  const up = await API.uploadAttachment(new Blob([enc.ciphertext], { type: "application/octet-stream" }));
  const isContact = STATE.contacts.find(c => c.address === STATE.activeChat);
  const body = {
    msg_type: msgType,
    is_contact_request: !isContact,
    attachment_token: up.token,
    file_key_b64: LehnoCrypto.b64(enc.fileKey),
    file_iv_b64: LehnoCrypto.b64(enc.iv),
    mime,
    caption,
  };
  const recipientKeys = await fetchPubKey(STATE.activeChat);
  const encMsg = await LehnoCrypto.encryptMessage(STATE.me, recipientKeys.identity_pub_b64, body);
  const resp = await API.post("/api/packets", {
    recipient_address: STATE.activeChat,
    ephemeral_pub_b64: encMsg.ephemeral_pub_b64,
    nonce_b64: encMsg.nonce_b64,
    ciphertext_b64: encMsg.ciphertext_b64,
    signature_b64: encMsg.signature_b64,
  });
  const meta = { caption, mime, file_key_b64: body.file_key_b64, file_iv_b64: body.file_iv_b64 };
  appendOutgoing(STATE.activeChat, {
    id: "out-" + resp.packet_id,
    isMe: true,
    plain: JSON.stringify(meta),
    msg_type: msgType,
    attachment_token: up.token,
    ts: new Date().toISOString(),
  });
  if (!isContact) {
    STATE.contacts.unshift({ address: STATE.activeChat, last_at: new Date().toISOString() });
    scheduleUserdataSave();
    renderSidebar();
  } else {
    isContact.last_at = new Date().toISOString();
    scheduleUserdataSave();
  }
  renderChat();
  toast("Gesendet", "ok");
}

// =========================================================================
// WebSocket
// =========================================================================
function startWebSocket() {
  try {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${location.host}/ws?token=${encodeURIComponent(STATE.me.jwt)}`;
    STATE.ws = new WebSocket(url);
    STATE.ws.onmessage = async (evt) => {
      let payload = null;
      try { payload = JSON.parse(evt.data); } catch(e) { return; }
      if (payload.type === "new_packet") {
        await pollInbox();
      }
    };
    STATE.ws.onclose = () => {
      STATE.ws = null;
      if (STATE.me) setTimeout(startWebSocket, 3000);
    };
  } catch (e) { console.warn("ws err", e); }
}

// =========================================================================
// MEDIA-DOWNLOAD-WARNUNG
// =========================================================================
function attachDownloadWarning(el) {
  const warn = (e) => {
    e.preventDefault();
    if (confirm(
      "ACHTUNG: Wenn du diese Datei jetzt speicherst, liegt sie ENTSCHLUESSELT auf deinem Geraet.\n\n" +
      "Im mesh-Browser bleibt sie verschluesselt im Speicher und ist nur dir sichtbar.\n\n" +
      "Trotzdem speichern? (Nur tun wenn du dem Speicherort vertraust)"
    )) { /* Browser-Default-Action */ }
  };
  el.addEventListener("contextmenu", warn);
  el.addEventListener("dragstart", e => e.preventDefault());
}

// =========================================================================
// UI BINDINGS
// =========================================================================
function bindUI() {
  $$("#view-auth .tab").forEach(t => t.addEventListener("click", () => {
    $$("#view-auth .tab").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    $$(".auth-form").forEach(f => f.classList.remove("active"));
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
    let addr = e.target.address.value.trim();
    if (!addr.startsWith("mesh:")) addr = "mesh:" + addr;
    const p = e.target.password.value;
    $("#auth-msg").textContent = "Einloggen...";
    $("#auth-msg").className = "msg";
    try {
      await doLogin(addr, p);
      $("#auth-msg").textContent = "";
    } catch(err) {
      $("#auth-msg").textContent = "Login fehlgeschlagen: " + err.message;
    }
  });

  $("#form-register").addEventListener("submit", async (e) => {
    e.preventDefault();
    const p = e.target.password.value;
    const p2 = e.target.password2.value;
    if (p !== p2) {
      $("#auth-msg").textContent = "Passwoerter stimmen nicht ueberein";
      return;
    }
    $("#auth-msg").textContent = "Schluessel werden generiert...";
    try {
      await doRegister(p);
    } catch(err) {
      $("#auth-msg").textContent = "Registrierung fehlgeschlagen: " + err.message;
    }
  });

  $("#form-recover").addEventListener("submit", async (e) => {
    e.preventDefault();
    let addr = e.target.address.value.trim();
    if (!addr.startsWith("mesh:")) addr = "mesh:" + addr;
    const mnemonic = e.target.mnemonic.value.trim().toLowerCase().replace(/\s+/g, " ");
    const newPw = e.target.password.value;
    const newPw2 = e.target.password2.value;
    if (newPw !== newPw2) {
      $("#recover-msg").textContent = "Passwoerter stimmen nicht ueberein";
      return;
    }
    const wordCount = mnemonic ? mnemonic.split(" ").filter(Boolean).length : 0;
    if (wordCount !== 24) {
      $("#recover-msg").textContent = `Genau 24 Woerter noetig (du hast ${wordCount}).`;
      return;
    }
    $("#recover-msg").textContent = "Wiederherstellen...";
    $("#recover-msg").className = "msg";
    try {
      await doRecover(addr, mnemonic, newPw);
      $("#recover-msg").textContent = "";
      toast("Account wiederhergestellt", "ok");
    } catch(err) {
      $("#recover-msg").textContent = "Wiederherstellung fehlgeschlagen: " + err.message;
    }
  });

  $("#mnemonic-confirm").addEventListener("change", e => {
    $("#mnemonic-continue").disabled = !e.target.checked;
  });
  $("#mnemonic-continue").addEventListener("click", () => afterLogin());

  $("#btn-copy-addr").addEventListener("click", () => {
    navigator.clipboard.writeText($("#my-address-display").textContent);
    toast("Adresse kopiert", "ok");
  });

  $("#btn-download-backup").addEventListener("click", downloadAccountBackup);

  $("#btn-logout").addEventListener("click", logout);

  $("#me-pill").addEventListener("click", () => {
    $("#popup-my-address").textContent = STATE.me.address;
    $("#addr-popup").style.display = "flex";
  });
  $("#btn-popup-close").addEventListener("click", () => $("#addr-popup").style.display = "none");
  $("#btn-popup-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(STATE.me.address);
    toast("Adresse kopiert", "ok");
  });

  $("#btn-new-chat").addEventListener("click", async () => {
    let addr = $("#new-chat-address").value.trim();
    if (!addr) return;
    if (!addr.startsWith("mesh:")) addr = "mesh:" + addr;
    try {
      await fetchPubKey(addr);
      $("#new-chat-address").value = "";
      await openChat(addr);
    } catch(e) {
      toast("Adresse nicht gefunden", "err");
    }
  });
  $("#new-chat-address").addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); $("#btn-new-chat").click(); }
  });

  $("#btn-accept").addEventListener("click", () => { if (STATE.activeChat) acceptRequest(STATE.activeChat); });
  $("#btn-decline").addEventListener("click", () => { if (STATE.activeChat) declineRequest(STATE.activeChat); });

  $("#form-send").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = $("#msg-input").value.trim();
    if (!text) return;
    $("#msg-input").value = "";
    try { await sendText(text); } catch (err) { toast("Senden fehlgeschlagen: " + err.message, "err"); }
  });

  $("#btn-attach").addEventListener("click", () => $("#file-input").click());
  $("#file-input").addEventListener("change", async (e) => {
    for (const f of e.target.files) {
      const isVideo = f.type.startsWith("video/");
      const isImage = f.type.startsWith("image/");
      if (!isVideo && !isImage) { toast("Nur Bilder/Videos", "err"); continue; }
      try { await sendMedia(f, f.type, isVideo ? "video" : "image"); }
      catch (err) { toast("Fehler: " + err.message, "err"); }
    }
    e.target.value = "";
  });

  $("#link-recover").addEventListener("click", e => { e.preventDefault(); show("recover"); });
  $("#btn-back-to-auth").addEventListener("click", () => show("auth"));
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
    toast("Backup-Daten nicht verfuegbar", "err");
    return;
  }
  const date = new Date().toISOString().slice(0, 10);
  const content = [
    "mesh - Account-Backup",
    "=".repeat(60),
    "",
    "Erstellt: " + date,
    "",
    "DEINE ADRESSE (oeffentlich, kannst du teilen):",
    _lastAddress,
    "",
    "DEIN 24-WORT-BACKUP-CODE (GEHEIM, niemals teilen!):",
    "",
    _lastMnemonic.split(" ").map((w, i) => `${String(i + 1).padStart(2, " ")}.  ${w}`).join("\n"),
    "",
    "=".repeat(60),
    "WICHTIG:",
    "",
    "- Wer den 24-Wort-Code hat, hat vollen Zugriff auf deinen Account.",
    "- Speichere diese Datei OFFLINE (USB-Stick, Papier-Ausdruck, sicherer Tresor).",
    "- NIEMALS in der Cloud (iCloud, Google Drive, Dropbox, Email).",
    "- NIEMALS als Foto/Screenshot.",
    "- Vergisst du Passwort UND Backup-Code = Account fuer immer weg.",
    "",
    "Wiederherstellung: mesh - Login - 'Backup-Code' - Eingabe + neues Passwort.",
    "",
    "Open-Source-Code: github.com/aliecommerce123-web/lehno-mesh",
  ].join("\n");

  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `mesh-backup-${_lastAddress.replace(/^mesh:/, "").slice(0, 10)}-${date}.txt`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
  toast("Backup heruntergeladen", "ok");
}

// =========================================================================
// LAST-ADDRESS-MEMORY (Login-Komfort)
// =========================================================================
function rememberAddress(addr) {
  try { localStorage.setItem("lehno-mesh:last-address", addr); } catch(e) {}
}
function getRememberedAddress() {
  try { return localStorage.getItem("lehno-mesh:last-address") || ""; } catch(e) { return ""; }
}

// =========================================================================
// INIT
// =========================================================================
window.LehnoApp = { show, STATE };

document.addEventListener("DOMContentLoaded", () => {
  bindUI();
  show("auth");

  const last = getRememberedAddress();
  if (last) {
    const el = $("#form-login input[name=address]");
    if (el) el.value = last;
    const elR = $("#form-recover input[name=address]");
    if (elR) elR.value = last;
  }

  if ("serviceWorker" in navigator) {
    if (location.host.endsWith(".onion")) {
      navigator.serviceWorker.register("/sw.js?v=" + (window.__MESH_VERSION || "0"))
        .catch(()=>{});
    } else {
      navigator.serviceWorker.getRegistrations().then(regs => {
        regs.forEach(r => r.unregister());
      }).catch(()=>{});
    }
  }
});
