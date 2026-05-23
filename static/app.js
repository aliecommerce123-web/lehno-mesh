// lehno-mesh Phase 1.5 - Anonyme Adressen + Sealed-Sender + Contact-Requests.

const STATE = {
  me: null,                       // { address, jwt, identityPriv, signingPriv, identity_pub_b64, signing_pub_b64 }
  pubKeyCache: {},                // address -> { identity_pub_b64, signing_pub_b64 }
  contacts: [],                   // [{ address, last_at }] - lokal im localStorage gespeichert (akzeptierte)
  requests: [],                   // [{ address, packet_id, content_preview }] - pending Contact-Requests
  activeChat: null,               // address des aktuell geoeffneten Chats
  messagesByContact: {},          // address -> [{ id, isMe, plain, msg_type, ts, attachment_id }]
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

function shortAddress(addr) {
  if (!addr) return "";
  const a = addr.replace(/^mesh:/, "");
  return "mesh:" + a.slice(0, 8) + "…" + a.slice(-4);
}

// =========================================================================
// LOCAL STORAGE (akzeptierte Kontakte + ausgehender Nachrichten-Cache)
// =========================================================================
function storageKey(suffix) {
  return `lehno-mesh:${STATE.me?.address || "anon"}:${suffix}`;
}
function loadAcceptedContacts() {
  try { return JSON.parse(localStorage.getItem(storageKey("contacts")) || "[]"); }
  catch { return []; }
}
function saveAcceptedContacts() {
  localStorage.setItem(storageKey("contacts"), JSON.stringify(STATE.contacts));
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
function loadDeclined() {
  try { return JSON.parse(localStorage.getItem(storageKey("declined")) || "[]"); }
  catch { return []; }
}
function saveDeclined(list) {
  localStorage.setItem(storageKey("declined"), JSON.stringify(list));
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
    return r.json();
  },
  async fetchAttachment(id) {
    const r = await fetch("/api/attachments/" + id, {
      headers: { "authorization": "Bearer " + STATE.me.jwt },
    });
    if (!r.ok) throw new Error("download failed");
    return new Uint8Array(await r.arrayBuffer());
  },
};

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
    identity_pub_b64: setup.identity_pub_b64,
    signing_pub_b64: setup.signing_pub_b64,
  };
  await unlockAfterRegister(password, setup);

  const mnemonic = await LehnoBip39.bytesToMnemonic(setup.kek_for_backup);
  showMnemonic(mnemonic, resp.address);
}

async function unlockAfterRegister(password, setup) {
  // Wir haben die priv keys schon im Speicher (setup.identityPriv exportiert als jwk),
  // aber zur Konsistenz: re-fetch + re-unlock damit wir CryptoKey-Objekte haben.
  const init = await API.post("/api/login/init", { address: STATE.me.address });
  const salt = LehnoCrypto.unb64(init.salt_b64);
  const { auth_key } = await LehnoCrypto.deriveFromPassword(password, salt);
  const resp = await API.post("/api/login", { address: STATE.me.address, auth_key_b64: LehnoCrypto.b64(auth_key) });
  const live = await LehnoCrypto.unlockAccount(password, resp);
  STATE.me = {
    ...STATE.me,
    identityPriv: live.identityPriv,
    signingPriv: live.signingPriv,
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
  };
  // pubkeys von uns selbst nachfragen damit sender_signing_pub_b64 verfügbar ist
  const my = await API.get("/api/keys/" + encodeURIComponent(resp.address));
  STATE.me.identity_pub_b64 = my.identity_pub_b64;
  STATE.me.signing_pub_b64 = my.signing_pub_b64;
  await afterLogin();
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
  STATE.requests = [];
  STATE.messagesByContact = {};
  STATE.activeChat = null;
  STATE.lastInboxId = 0;
  show("auth");
}

async function afterLogin() {
  rememberAddress(STATE.me.address);
  $("#me-address-short").textContent = shortAddress(STATE.me.address);
  STATE.contacts = loadAcceptedContacts();
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
    const declined = new Set(loadDeclined());

    for (const p of r.packets) {
      STATE.lastInboxId = Math.max(STATE.lastInboxId, p.id);
      try {
        const body = await LehnoCrypto.decryptMessage(STATE.me, p);
        const senderAddr = body.sender_address;
        if (!senderAddr) continue;

        // Sender-Adress-Konsistenz prüfen: muss matchen mit address_from(sender_identity_pub)
        // (wir verifizieren das nicht hier weil wir den identity_pub des Senders nicht haben,
        //  aber signature_pub haben wir aus body, und Signatur über ephemeral wurde schon
        //  verifiziert in decryptMessage)

        if (declined.has(senderAddr)) {
          ackIds.push(p.id);
          continue;
        }

        const isKnown = STATE.contacts.find(c => c.address === senderAddr);
        const msg_type = p.msg_type;
        let plainContent = body.content;

        if (p.is_contact_request && !isKnown) {
          // In requests aufnehmen (nicht in contacts)
          const existing = STATE.requests.find(r => r.address === senderAddr);
          if (!existing) {
            STATE.requests.push({
              address: senderAddr,
              packet_id: p.id,
              preview: msg_type === "text" ? plainContent : "[" + msg_type + "]",
              ts: p.created_day,
            });
          }
          // Speichere die Nachricht im Conversation-Cache, damit sie sichtbar ist nach Accept
          (STATE.messagesByContact[senderAddr] ||= []).push({
            id: p.id, server_id: p.id, isMe: false,
            plain: plainContent, msg_type, attachment_id: p.attachment_id,
            ts: new Date(p.created_day * 1000).toISOString(),
          });
        } else if (isKnown) {
          (STATE.messagesByContact[senderAddr] ||= []).push({
            id: p.id, server_id: p.id, isMe: false,
            plain: plainContent, msg_type, attachment_id: p.attachment_id,
            ts: new Date(p.created_day * 1000).toISOString(),
          });
          // Update last_at
          isKnown.last_at = new Date().toISOString();
          ackIds.push(p.id);  // bekannt -> sofort acked + Server-Delete
        } else {
          // Unbekannter Sender, kein contact_request flag -> ignoriere (oder behandle als request)
          // Für Phase 1.5: behandle es als request
          if (!STATE.requests.find(r => r.address === senderAddr)) {
            STATE.requests.push({
              address: senderAddr,
              packet_id: p.id,
              preview: msg_type === "text" ? plainContent : "[" + msg_type + "]",
              ts: p.created_day,
            });
          }
          (STATE.messagesByContact[senderAddr] ||= []).push({
            id: p.id, server_id: p.id, isMe: false,
            plain: plainContent, msg_type, attachment_id: p.attachment_id,
            ts: new Date(p.created_day * 1000).toISOString(),
          });
        }
      } catch (e) {
        console.warn("decrypt failed for packet", p.id, e);
      }
    }

    // Bekannte Nachrichten von Server löschen (Auto-Delete)
    if (ackIds.length) {
      try { await API.post("/api/packets/ack", ackIds); } catch(e) {}
    }

    saveAcceptedContacts();
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
    saveAcceptedContacts();
  }
  // Alle pending requests für diese Adresse acken (auf Server löschen) - die
  // Nachrichten sind ja schon lokal gespeichert
  const reqs = STATE.requests.filter(r => r.address === addr);
  STATE.requests = STATE.requests.filter(r => r.address !== addr);
  if (reqs.length) {
    try { await API.post("/api/packets/ack", reqs.map(r => r.packet_id)); } catch(e) {}
  }
  // Auch alle Folge-Nachrichten der gleichen Adresse aus inbox cleanen
  const followups = (STATE.messagesByContact[addr] || []).map(m => m.server_id).filter(Boolean);
  if (followups.length) {
    try { await API.post("/api/packets/ack", followups); } catch(e) {}
  }
  renderSidebar();
  if (STATE.activeChat === addr) renderChat();
  toast("Kontakt akzeptiert", "ok");
}

async function declineRequest(addr) {
  const declined = new Set(loadDeclined());
  declined.add(addr);
  saveDeclined(Array.from(declined));
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
// SIDEBAR RENDERING (mit Tabs)
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
    list.innerHTML = '<div style="padding:24px 14px; color:var(--text-dimmer); font-size:12.5px; text-align:center">Noch keine Chats.<br>Fuege oben eine Adresse hinzu.</div>';
    return;
  }
  STATE.contacts.forEach(c => {
    const div = document.createElement("div");
    div.className = "contact" + (c.address === STATE.activeChat ? " active" : "");
    const short = c.address.replace(/^mesh:/, "").slice(0, 2).toUpperCase();
    div.innerHTML = `
      <div class="avatar">${short}</div>
      <div class="meta">
        <div class="name">${shortAddress(c.address)}</div>
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
    list.innerHTML = '<div style="padding:24px 14px; color:var(--text-dimmer); font-size:12.5px; text-align:center">Keine offenen Anfragen.</div>';
    return;
  }
  STATE.requests.forEach(r => {
    const div = document.createElement("div");
    div.className = "contact" + (r.address === STATE.activeChat ? " active" : "");
    const short = r.address.replace(/^mesh:/, "").slice(0, 2).toUpperCase();
    div.innerHTML = `
      <div class="avatar" style="background:linear-gradient(135deg,#a8741a,#ffb347)">${short}</div>
      <div class="meta">
        <div class="name">${shortAddress(r.address)}</div>
        <div class="last" style="color:var(--warn)">Anfrage: ${escapeHtml((r.preview || "").slice(0, 32))}</div>
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

  const short = peer.replace(/^mesh:/, "").slice(0, 2).toUpperCase();
  header.innerHTML = `
    <button class="ghost small back" id="btn-back">&larr;</button>
    <div class="avatar">${short}</div>
    <div class="name" title="${escapeHtml(peer)}">${shortAddress(peer)}</div>
    <div class="lock"><span>&#x1F512;</span> Ende-zu-Ende</div>`;
  $("#btn-back").addEventListener("click", () => {
    $("#view-chat").classList.remove("peek-chat");
    STATE.activeChat = null;
    renderSidebar();
  });

  banner.style.display = (isRequest && !isContact) ? "flex" : "none";

  // Merge incoming (im messagesByContact gespeichert) + outgoing (localStorage)
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
      // Mediennachricht: m.plain ist JSON-Meta
      try {
        const meta = JSON.parse(m.plain);
        const captionEl = meta.caption ? document.createElement("div") : null;
        if (captionEl) captionEl.textContent = meta.caption;
        const mediaEl = document.createElement(
          m.msg_type === "voice" ? "audio" : (m.msg_type === "video" ? "video" : "img")
        );
        mediaEl.dataset.attId = m.attachment_id;
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
    const enc = await API.fetchAttachment(el.dataset.attId);
    const fileKey = LehnoCrypto.unb64(el.dataset.fileKey);
    const iv = LehnoCrypto.unb64(el.dataset.fileIv);
    const plain = await LehnoCrypto.decryptFile(new Uint8Array(fileKey), iv, enc);
    const blob = new Blob([plain], { type: el.dataset.mime });
    el.src = URL.createObjectURL(blob);
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
  const enc = await LehnoCrypto.encryptMessage(STATE.me, recipientKeys.identity_pub_b64, text);
  const isContact = STATE.contacts.find(c => c.address === STATE.activeChat);
  const resp = await API.post("/api/packets", {
    recipient_address: STATE.activeChat,
    ephemeral_pub_b64: enc.ephemeral_pub_b64,
    nonce_b64: enc.nonce_b64,
    ciphertext_b64: enc.ciphertext_b64,
    signature_b64: enc.signature_b64,
    msg_type: "text",
    is_contact_request: !isContact,
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
    // Wir senden an Adresse die wir noch nicht in Kontakten haben -> wir akzeptieren sie implicit
    STATE.contacts.unshift({ address: STATE.activeChat, last_at: new Date().toISOString() });
    saveAcceptedContacts();
    renderSidebar();
  } else {
    isContact.last_at = new Date().toISOString();
    saveAcceptedContacts();
  }
  renderChat();
}

async function sendMedia(blob, mime, msgType, caption="") {
  if (!STATE.activeChat) return;
  toast("Verschlüsseln + senden...");
  const fileBytes = new Uint8Array(await blob.arrayBuffer());
  const enc = await LehnoCrypto.encryptFile(fileBytes);
  const up = await API.uploadAttachment(new Blob([enc.ciphertext], { type: "application/octet-stream" }));
  const meta = {
    caption, mime,
    file_key_b64: LehnoCrypto.b64(enc.fileKey),
    file_iv_b64: LehnoCrypto.b64(enc.iv),
  };
  const recipientKeys = await fetchPubKey(STATE.activeChat);
  const encMsg = await LehnoCrypto.encryptMessage(STATE.me, recipientKeys.identity_pub_b64, JSON.stringify(meta));
  const isContact = STATE.contacts.find(c => c.address === STATE.activeChat);
  const resp = await API.post("/api/packets", {
    recipient_address: STATE.activeChat,
    ephemeral_pub_b64: encMsg.ephemeral_pub_b64,
    nonce_b64: encMsg.nonce_b64,
    ciphertext_b64: encMsg.ciphertext_b64,
    signature_b64: encMsg.signature_b64,
    msg_type: msgType,
    is_contact_request: !isContact,
    attachment_id: up.attachment_id,
  });
  appendOutgoing(STATE.activeChat, {
    id: "out-" + resp.packet_id,
    isMe: true,
    plain: JSON.stringify(meta),
    msg_type: msgType,
    attachment_id: up.attachment_id,
    ts: new Date().toISOString(),
  });
  if (!isContact) {
    STATE.contacts.unshift({ address: STATE.activeChat, last_at: new Date().toISOString() });
    saveAcceptedContacts();
    renderSidebar();
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
// MEDIA RECORDING
// =========================================================================
let mediaRecorder = null;
let recordedChunks = [];
async function startRecording() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream, { mimeType: "audio/webm;codecs=opus" });
    recordedChunks = [];
    mediaRecorder.ondataavailable = e => { if (e.data.size > 0) recordedChunks.push(e.data); };
    mediaRecorder.onstop = async () => {
      stream.getTracks().forEach(t => t.stop());
      const blob = new Blob(recordedChunks, { type: "audio/webm" });
      if (blob.size > 100) await sendMedia(blob, "audio/webm", "voice");
    };
    mediaRecorder.start();
    $("#btn-record").classList.add("recording");
  } catch (e) {
    toast("Mikrofon-Zugriff verweigert", "err");
  }
}
function stopRecording() {
  if (mediaRecorder && mediaRecorder.state === "recording") mediaRecorder.stop();
  $("#btn-record").classList.remove("recording");
}

// =========================================================================
// UI BINDINGS
// =========================================================================
function bindUI() {
  // Auth-Tabs
  $$("#view-auth .tab").forEach(t => t.addEventListener("click", () => {
    $$("#view-auth .tab").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    $$(".auth-form").forEach(f => f.classList.remove("active"));
    $("#form-" + t.dataset.tab).classList.add("active");
    $("#auth-msg").textContent = "";
  }));

  // Sidebar-Tabs (Chats / Anfragen)
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
      $("#auth-msg").textContent = "Passwörter stimmen nicht überein";
      return;
    }
    $("#auth-msg").textContent = "Schlüssel werden generiert...";
    try {
      await doRegister(p);
    } catch(err) {
      $("#auth-msg").textContent = "Registrierung fehlgeschlagen: " + err.message;
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

  $("#btn-download-backup").addEventListener("click", () => {
    downloadAccountBackup();
  });

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

  let recording = false;
  $("#btn-record").addEventListener("click", async () => {
    if (recording) { stopRecording(); recording = false; }
    else { await startRecording(); recording = true; }
  });

  $("#link-recover").addEventListener("click", e => { e.preventDefault(); show("recover"); });
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
  const date = new Date().toISOString().slice(0, 10);
  const content = [
    "mesh - Account-Backup",
    "=" .repeat(60),
    "",
    "Erstellt: " + date,
    "",
    "DEINE ADRESSE (öffentlich, kannst du teilen):",
    _lastAddress,
    "",
    "DEIN 24-WORT-BACKUP-CODE (GEHEIM, niemals teilen!):",
    "",
    _lastMnemonic.split(" ").map((w, i) => `${String(i + 1).padStart(2, " ")}.  ${w}`).join("\n"),
    "",
    "=" .repeat(60),
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
// Wir speichern nach erfolgreichem Login die Adresse lokal damit der User
// beim naechsten Login nur das Passwort eintippen muss. Das Passwort wird
// NIEMALS gespeichert.
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

  // Adresse vom letzten Login vorausfuellen
  const last = getRememberedAddress();
  if (last) {
    const el = $("#form-login input[name=address]");
    if (el) el.value = last;
  }

  // Service Worker NUR auf .onion registrieren. Auf Clearnet wuerde ein SW
  // nur Probleme machen (alte Cache-Versionen, Update-Lag).
  if ("serviceWorker" in navigator) {
    if (location.host.endsWith(".onion")) {
      navigator.serviceWorker.register("/sw.js?v=" + (window.__MESH_VERSION || "0"))
        .catch(()=>{});
    } else {
      // Defensiv: falls alter SW noch registriert ist (z.B. aus frueheren Versionen) -> killen
      navigator.serviceWorker.getRegistrations().then(regs => {
        regs.forEach(r => r.unregister());
      }).catch(()=>{});
    }
  }
});
