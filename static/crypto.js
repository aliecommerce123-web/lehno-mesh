// chatmesh Phase 2 - alle Krypto-Operationen laufen hier im Browser (WebCrypto).
// Verfahren: ECDH P-256, AES-256-GCM, HKDF-SHA256, HMAC-SHA256, PBKDF2-SHA256.
//
// Überblick:
// - Konto: 12 Anmeldewörter (128 Bit Zufall) -> Kontokennung, Zugang, Schlüssel.
//   12 Löschwörter (eigene 128 Bit) -> Zugang zum unwiderruflichen Löschen.
// - Kanal: entsteht aus einem Einmal-Code (9 Wörter) plus einem Schlüsseltausch
//   zwischen den beiden Geräten. Der Code allein reicht später nicht mehr.
// - Jede Nachricht liegt unter einer neuen Zufallsmarke, die nur die beiden
//   Geräte ausrechnen können, und ist mit einem eigenen Schlüssel verschlossen.
// - Das Kanal-Passwort verschließt den Inhalts-Schlüssel des Kanals zusätzlich.
(function () {
  "use strict";
  const te = new TextEncoder(), td = new TextDecoder();
  const utf8 = (s) => te.encode(s);
  const fromUtf8 = (b) => td.decode(b);
  // Der Browser liefert höchstens 65536 Zufallsbytes auf einmal.
  function rand(n) {
    const out = new Uint8Array(n);
    for (let o = 0; o < n; o += 65536) crypto.getRandomValues(out.subarray(o, Math.min(n, o + 65536)));
    return out;
  }

  function b64(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function unb64(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function hex(buf) {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
    return s;
  }
  function unhex(s) {
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }
  function concat(...arrs) {
    let n = 0;
    for (const a of arrs) n += a.byteLength;
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arrs) { out.set(a instanceof Uint8Array ? a : new Uint8Array(a), o); o += a.byteLength; }
    return out;
  }

  async function sha256(buf) { return new Uint8Array(await crypto.subtle.digest("SHA-256", buf)); }

  async function hkdf(secret, info, len) {
    const key = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: typeof info === "string" ? utf8(info) : info },
      key, (len || 32) * 8);
    return new Uint8Array(bits);
  }
  async function hmac(keyBytes, data) {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, typeof data === "string" ? utf8(data) : data));
  }
  // Verschlüsseln: Ergebnis ist Zufallswert (12) | Geheimtext | Prüfwert (16).
  async function seal(keyBytes, plain) {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
    const iv = rand(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
    return concat(iv, ct);
  }
  async function open(keyBytes, sealed) {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const b = sealed instanceof Uint8Array ? sealed : new Uint8Array(sealed);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.subarray(0, 12) }, key, b.subarray(12)));
  }

  // ---------- Auffüllen auf feste Größen ----------
  // Format: 4 Bytes Länge | Inhalt | Nullen.
  function padTo(bytes, sizes) {
    let size = null;
    for (const s of sizes) { if (bytes.byteLength + 4 <= s) { size = s; break; } }
    if (size === null) throw new Error("too large");
    const out = new Uint8Array(size);
    new DataView(out.buffer).setUint32(0, bytes.byteLength, false);
    out.set(bytes, 4);
    return out;
  }
  function unpad(bytes, sizes) {
    if (!sizes.includes(bytes.byteLength)) throw new Error("bad size");
    const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
    if (len > bytes.byteLength - 4) throw new Error("bad length");
    return bytes.slice(4, 4 + len);
  }
  async function sealJson(keyBytes, obj, sizes) { return await seal(keyBytes, padTo(utf8(JSON.stringify(obj)), sizes)); }
  async function openJson(keyBytes, sealed, sizes) { return JSON.parse(fromUtf8(unpad(await open(keyBytes, sealed), sizes))); }
  function fitsJson(obj, sizes) { return utf8(JSON.stringify(obj)).byteLength + 4 <= sizes[sizes.length - 1]; }

  const BLOCK = [4096, 65536];
  const ACCOUNT = [8192, 65536, 262144, 1048576, 4194304];
  const WIPE = [4096, 65536];

  // ---------- Wörter (BIP39-Verfahren, englische Liste) ----------
  // 16 Bytes -> 12 Wörter, 12 Bytes -> 9 Wörter. Die letzten Bits sind eine
  // Prüfsumme, damit Tippfehler auffallen.
  async function bytesToWords(entropy) {
    const list = window.LehnoBip39.BIP39_WORDS;
    const bytes = new Uint8Array(entropy);
    const csBits = bytes.length * 8 / 32;
    const hash = await sha256(bytes);
    const bits = [];
    for (const b of bytes) for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
    for (let i = 0; i < csBits; i++) bits.push((hash[0] >> (7 - i)) & 1);
    const words = [];
    for (let i = 0; i < bits.length / 11; i++) {
      let idx = 0;
      for (let j = 0; j < 11; j++) idx = (idx << 1) | bits[i * 11 + j];
      words.push(list[idx]);
    }
    return words.join(" ");
  }
  async function wordsToBytes(text, nBytes) {
    const list = window.LehnoBip39.BIP39_WORDS;
    const words = String(text || "").trim().toLowerCase().split(/[\s,;.\-]+/).filter(Boolean);
    const csBits = nBytes * 8 / 32;
    if (words.length !== (nBytes * 8 + csBits) / 11) throw new Error("count");
    const bits = [];
    for (const w of words) {
      const idx = list.indexOf(w);
      if (idx < 0) throw new Error("word:" + w);
      for (let j = 10; j >= 0; j--) bits.push((idx >> j) & 1);
    }
    const out = new Uint8Array(nBytes);
    for (let i = 0; i < nBytes; i++) {
      let v = 0;
      for (let j = 0; j < 8; j++) v = (v << 1) | bits[i * 8 + j];
      out[i] = v;
    }
    const hash = await sha256(out);
    for (let i = 0; i < csBits; i++) {
      if (bits[nBytes * 8 + i] !== ((hash[0] >> (7 - i)) & 1)) throw new Error("checksum");
    }
    return out;
  }

  // ---------- Konto ----------
  // Aus den 12 Anmeldewörtern: Kennung (unter der der Block liegt), Zugang
  // (wird dem Server gezeigt, er kennt nur dessen Prüfwert) und Schlüssel
  // (verlässt das Gerät nie).
  async function accountKeys(loginBytes) {
    const token = await hkdf(loginBytes, "chatmesh2|account|auth");
    return {
      id: hex(await hkdf(loginBytes, "chatmesh2|account|id")),
      token: hex(token),
      authHash: hex(await sha256(token)),
      encKey: await hkdf(loginBytes, "chatmesh2|account|enc"),
    };
  }
  async function wipeKeys(wipeBytes) {
    const token = await hkdf(wipeBytes, "chatmesh2|wipe|auth");
    return {
      token: hex(token),
      wipeHash: hex(await sha256(token)),
      encKey: await hkdf(wipeBytes, "chatmesh2|wipe|enc"),
      innerKey: await hkdf(wipeBytes, "chatmesh2|wipe|inner"),
    };
  }

  // ---------- Kanal öffnen: Einmal-Code + Schlüsseltausch ----------
  async function inviteKeys(inviteBytes) {
    return {
      tagA: hex((await hkdf(inviteBytes, "chatmesh2|invite|tag-a")).subarray(0, 16)),
      tagB: hex((await hkdf(inviteBytes, "chatmesh2|invite|tag-b")).subarray(0, 16)),
      delA: hex((await hkdf(inviteBytes, "chatmesh2|invite|del-a")).subarray(0, 16)),
      delB: hex((await hkdf(inviteBytes, "chatmesh2|invite|del-b")).subarray(0, 16)),
      key: await hkdf(inviteBytes, "chatmesh2|invite|key"),
    };
  }
  async function newExchangeKey() {
    const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    return {
      pub: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)),
      privJwk: await crypto.subtle.exportKey("jwk", kp.privateKey),
    };
  }
  // Gemeinsames Geheimnis aus eigenem privaten und fremdem öffentlichen Schlüssel,
  // gebunden an den Einmal-Code und an beide öffentlichen Schlüssel.
  async function channelRoot(privJwk, theirPub, inviteBytes, pubA, pubB) {
    if (theirPub.byteLength !== 65 || theirPub[0] !== 4) throw new Error("bad key");
    const priv = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = await crypto.subtle.importKey("raw", theirPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
    return await hkdf(concat(shared, inviteBytes), concat(utf8("chatmesh2|root|"), pubA, pubB));
  }
  // Aus dem gemeinsamen Geheimnis: Schlüssel für Marken, Inhalt, Löschen, Auflösen.
  async function channelKeys(root) {
    const sym = await hkdf(root, "chatmesh2|verify", 8);
    const EMOJI = ["🔑","🌙","🐬","⚡","🍀","🔥","🎈","🌵","🐝","🍉","🚲","🎧","🧩","🪁","🦊","🐢","🌻","🍋","⛵","🎲","🪐","🐙","🍄","🧭","🎯","🦉","🌈","🥝","🛼","🪴","🐳","🍒"];
    return {
      kTag: await hkdf(root, "chatmesh2|ch|tag"),
      kMsg: await hkdf(root, "chatmesh2|ch|msg"),
      kDel: await hkdf(root, "chatmesh2|ch|del"),
      kDis: await hkdf(root, "chatmesh2|ch|dissolve"),
      // 8 Symbole (40 Bit): ein Dazwischendrängen lässt sich nicht passend zurechtprobieren.
      symbols: Array.from(sym).map(v => EMOJI[v % EMOJI.length]).join(" "),
    };
  }
  function dn(dir, n) { return dir + "|" + String(n); }
  async function msgTag(kTag, dir, n) { return hex((await hmac(kTag, "t|" + dn(dir, n))).subarray(0, 16)); }
  // Viele Marken auf einmal (der Schlüssel wird nur einmal eingelesen).
  async function msgTags(kTag, dir, from, to) {
    const key = await crypto.subtle.importKey("raw", kTag, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const out = [];
    for (let n = from; n < to; n++) out.push(hex(new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8("t|" + dn(dir, n)))).subarray(0, 16)));
    return out;
  }
  async function msgDelToken(kDel, dir, n) { return hex((await hmac(kDel, "d|" + dn(dir, n))).subarray(0, 16)); }
  async function msgKey(kMsg, dir, n) { return await hkdf(kMsg, "chatmesh2|m|" + dn(dir, n)); }
  async function delHash(tokenHex) { return hex(await sha256(unhex(tokenHex))); }
  async function dissolveKeys(kDis, dir) {
    return {
      tag: hex((await hmac(kDis, "tag|" + dir)).subarray(0, 16)),
      del: hex((await hmac(kDis, "del|" + dir)).subarray(0, 16)),
      key: await hkdf(kDis, "chatmesh2|dissolve|key|" + dir),
    };
  }

  // ---------- Kanal-Passwort ----------
  // Verschließt den Inhalts-Schlüssel des Kanals. Ohne Passwort kann auch mit
  // den 12 Anmeldewörtern niemand die Nachrichten dieses Kanals lesen.
  const PW_ITER = 600000;
  async function passwordKey(password, salt) {
    const base = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PW_ITER }, base, 256));
  }
  async function wrapWithKey(pwKey, salt, secret) { return { s: b64(salt), c: b64(await seal(pwKey, secret)) }; }
  async function wrapWithPassword(password, secret) {
    const salt = rand(16);
    return await wrapWithKey(await passwordKey(password, salt), salt, secret);
  }
  async function unwrapWithPassword(password, wrapped) {
    return await open(await passwordKey(password, unb64(wrapped.s)), unb64(wrapped.c));
  }

  // ---------- Dateien (Bilder, Videos, Sprachnachrichten, beliebige Dateien) ----------
  // Eigener Zufallsschlüssel je Datei, aufgefüllt auf eine von vier Größen.
  const FILE_SIZES = [262144, 1048576, 4194304, 16777216];
  async function encryptFile(fileBytes) {
    let size = null;
    for (const s of FILE_SIZES) { if (fileBytes.byteLength + 4 + 28 <= s) { size = s; break; } }
    if (size === null) throw new Error("file too large");
    const padded = new Uint8Array(size - 28);
    new DataView(padded.buffer).setUint32(0, fileBytes.byteLength, false);
    padded.set(fileBytes, 4);
    const key = rand(32);
    return { data: await seal(key, padded), key };
  }
  async function decryptFile(keyBytes, sealed) {
    const plain = await open(keyBytes, sealed);
    const len = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0, false);
    if (len > plain.byteLength - 4) throw new Error("bad length");
    return plain.slice(4, 4 + len);
  }

  // ---------- Verschließen an einen öffentlichen Schlüssel ----------
  // Damit kann das Konto etwas für die Löschwörter hinterlegen, ohne es selbst
  // wieder öffnen zu können: Öffnen geht nur mit dem privaten Schlüssel, der
  // seinerseits nur mit den 12 Löschwörtern zugänglich ist.
  async function boxSeal(pubRaw, plain) {
    const eph = await newExchangeKey();
    const priv = await crypto.subtle.importKey("jwk", eph.privJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = await crypto.subtle.importKey("raw", pubRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
    const key = await hkdf(shared, concat(utf8("chatmesh2|box|"), eph.pub, pubRaw));
    return concat(eph.pub, await seal(key, plain));
  }
  async function boxOpen(privJwk, pubRaw, sealed) {
    const b = sealed instanceof Uint8Array ? sealed : new Uint8Array(sealed);
    const ephPub = b.subarray(0, 65);
    const priv = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = await crypto.subtle.importKey("raw", ephPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
    const key = await hkdf(shared, concat(utf8("chatmesh2|box|"), ephPub, pubRaw));
    return await open(key, b.subarray(65));
  }

  // ---------- Rechenaufgabe ----------
  // Der Server verlangt zu jeder Einlieferung eine Zahl, mit der die Prüfsumme
  // über (Gegenstand + Zahl) mit einer bestimmten Anzahl Null-Bits beginnt.
  // Im Alltag sind das Millisekunden. Eigene, schnelle SHA-256-Rechnung für
  // genau einen Block (Gegenstand höchstens 47 Bytes + 8 Bytes Zahl).
  const K256 = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  // Kurze Pause ohne Zeitgeber (Zeitgeber werden in Hintergrund-Fenstern gebremst).
  function pause() {
    if (typeof MessageChannel === "undefined") return new Promise(r => setTimeout(r, 0));
    return new Promise(r => { const ch = new MessageChannel(); ch.port1.onmessage = () => { ch.port1.close(); r(); }; ch.port2.postMessage(0); });
  }
  async function work(subject, bits) {
    if (!bits || bits <= 0) return "0000000000000000";
    const len = subject.byteLength + 8;
    if (len > 55) throw new Error("subject too long");
    const block = new Uint8Array(64);
    block.set(subject, 0);
    block[len] = 0x80;
    const dv = new DataView(block.buffer);
    dv.setUint32(60, len * 8, false);
    const noncePos = subject.byteLength;
    const start = rand(4);
    block.set(start, noncePos);                      // obere Hälfte der Zahl: Zufall
    const w = new Uint32Array(64);
    let counter = 0;
    for (;;) {
      const until = counter + 60000;
      for (; counter < until; counter++) {
        dv.setUint32(noncePos + 4, counter, false);
        for (let i = 0; i < 16; i++) w[i] = dv.getUint32(i * 4, false);
        for (let i = 16; i < 64; i++) {
          const a = w[i - 15], b = w[i - 2];
          const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
          const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
          w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        }
        let a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a, e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;
        for (let i = 0; i < 64; i++) {
          const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
          const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K256[i] + w[i]) | 0;
          const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
          const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
          h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
        }
        const h0 = (a + 0x6a09e667) >>> 0;
        let good;
        if (bits <= 32) good = bits === 32 ? h0 === 0 : (h0 >>> (32 - bits)) === 0;
        else { const h1 = (b + 0xbb67ae85) >>> 0; good = h0 === 0 && (h1 >>> (64 - bits)) === 0; }
        if (good) return hex(block.subarray(noncePos, noncePos + 8));
      }
      if (counter >= 0xfffffff0) { block.set(rand(4), noncePos); counter = 0; }
      await pause();                                  // Oberfläche bleibt bedienbar
    }
  }

  window.CM = {
    utf8, fromUtf8, rand, b64, unb64, hex, unhex, concat, sha256, hkdf, hmac, seal, open,
    sealJson, openJson, fitsJson, BLOCK, ACCOUNT, WIPE,
    bytesToWords, wordsToBytes, accountKeys, wipeKeys,
    inviteKeys, newExchangeKey, channelRoot, channelKeys,
    msgTag, msgTags, msgDelToken, msgKey, delHash, dissolveKeys,
    passwordKey, wrapWithKey, wrapWithPassword, unwrapWithPassword,
    encryptFile, decryptFile, FILE_SIZES,
    boxSeal, boxOpen, work,
  };
})();
