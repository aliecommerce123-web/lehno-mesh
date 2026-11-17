// lehno-mesh Phase 1.6 - alle Krypto-Operationen via WebCrypto API.
// Curves: ECDH P-256 + ECDSA P-256.
// Symmetrisch: AES-256-GCM. KDF: PBKDF2-SHA256 (600k Iter) + HKDF-SHA256.
// NEU in 1.6: Padding-Buckets, msg_type/is_contact_request/attachment_token im
// verschluesselten Body, encrypted userdata blob fuer Spitznamen-Sync.
// NEU in 1.8: Absender-Nachweis über den Identitätsschlüssel (ein Dritter kann
// sich nicht mehr als fremde Adresse ausgeben), keine Unterschrift mehr außen am
// Paket (sie hätte dem Server den Absender verraten), Nachrichtenschlüssel an
// Einmal- und Empfängerschlüssel gebunden, eigene öffentliche Schlüssel werden
// aus dem privaten Bündel berechnet statt vom Server geholt, verschlüsselter
// Chat-Verlauf als verschlüsselte Ablage, alle Ablagen auf Einheitsgrößen aufgefüllt.

const PBKDF2_ITER = 600000;
const SALT_PREFIX = "lehno-mesh-v1:";

// Padding-Buckets (PFLICHT - Server validiert die Ciphertext-Laenge gegen genau diese).
// Plaintext wird auf eine dieser Groessen gepadded BEVOR encrypt.
// Format vor encrypt: 4 bytes big-endian length || payload bytes || zero padding.
const PAYLOAD_BUCKETS = [4096, 65536];
const PAYLOAD_LEN_PREFIX = 4;

// ---------- Base64 helpers ----------
function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  const CH = 0x8000;   // in Blöcken, damit auch mehrere MB schnell gehen
  for (let i = 0; i < bytes.length; i += CH) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  }
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function utf8(s) { return new TextEncoder().encode(s); }
function fromUtf8(buf) { return new TextDecoder().decode(buf); }
function concatBytes(...arrs) {
  let total = 0; for (const a of arrs) total += a.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(new Uint8Array(a), off); off += a.byteLength; }
  return out;
}

// ---------- Random ----------
function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }

// ---------- Hash ----------
async function sha256(buf) { return await crypto.subtle.digest("SHA-256", buf); }

// ---------- Passwort -> auth_key (für den Server) + pdk (bleibt im Browser) ----------
// kdf 1 (Konten vor Phase 1.8): ein PBKDF2-Lauf mit 64 Bytes Ausgabe, erste
//   Hälfte auth_key, zweite Hälfte pdk. Nachteil: wer das Passwort offline
//   raten will, braucht nur eine der beiden Hälften und damit halb so viel
//   Rechenzeit wie der Nutzer.
// kdf 2 (neue Konten und jede Wiederherstellung): ein PBKDF2-Lauf mit doppelt
//   so vielen Runden und 32 Bytes Ausgabe, daraus per HKDF zwei unabhängige
//   Schlüssel. Raten kostet jetzt genauso viel wie die echte Anmeldung.
const PBKDF2_ITER_V2 = 1200000;
const KDF_CURRENT = 2;

async function deriveFromPassword(password, salt, kdf) {
  const baseKey = await crypto.subtle.importKey(
    "raw", utf8(password), "PBKDF2", false, ["deriveBits"]
  );
  if (kdf === 2) {
    const master = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITER_V2 },
      baseKey, 32 * 8
    ));
    return {
      auth_key: await hkdf(master, "lehno-mesh-auth-v2"),
      pdk:      await hkdf(master, "lehno-mesh-pdk-v2"),
    };
  }
  if (kdf !== 1 && kdf !== undefined) throw new Error("unbekanntes Schlüsselverfahren");
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITER },
    baseKey, 64 * 8
  );
  const all = new Uint8Array(bits);
  return {
    auth_key: all.slice(0, 32),
    pdk:      all.slice(32, 64),
  };
}

async function importAesKey(rawKey) {
  return await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function aesGcmEncrypt(rawKey, plaintext) {
  const key = await importAesKey(rawKey);
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { ct, iv };
}

async function aesGcmDecrypt(rawKey, iv, ct) {
  const key = await importAesKey(rawKey);
  return await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
}

// ---------- ECDH P-256 ----------
async function generateEcdhKeypair() {
  return await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
}

async function exportPubKey(pubKey) {
  const raw = await crypto.subtle.exportKey("raw", pubKey);
  return new Uint8Array(raw);
}

async function importEcdhPub(rawBytes) {
  return await crypto.subtle.importKey(
    "raw", rawBytes, { name: "ECDH", namedCurve: "P-256" }, true, []
  );
}

async function exportEcdhPriv(privKey) {
  return await crypto.subtle.exportKey("jwk", privKey);
}

async function importEcdhPriv(jwk) {
  return await crypto.subtle.importKey(
    "jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
}

async function ecdhDerive(myPriv, theirPub) {
  return await crypto.subtle.deriveBits(
    { name: "ECDH", public: theirPub }, myPriv, 256
  );
}

// ---------- ECDSA P-256 ----------
async function generateEcdsaKeypair() {
  return await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
  );
}

async function exportEcdsaPub(pubKey) {
  const raw = await crypto.subtle.exportKey("raw", pubKey);
  return new Uint8Array(raw);
}

async function importEcdsaPub(rawBytes) {
  return await crypto.subtle.importKey(
    "raw", rawBytes, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]
  );
}

async function exportEcdsaPriv(privKey) {
  return await crypto.subtle.exportKey("jwk", privKey);
}

async function importEcdsaPriv(jwk) {
  return await crypto.subtle.importKey(
    "jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]
  );
}

async function ecdsaSign(priv, data) {
  return await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, data);
}

async function ecdsaVerify(pub, signature, data) {
  return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, signature, data);
}

// ---------- HKDF ----------
async function hkdf(rawSecret, info) {
  const baseKey = await crypto.subtle.importKey(
    "raw", rawSecret, "HKDF", false, ["deriveBits"]
  );
  const infoBytes = (typeof info === "string") ? utf8(info) : info;
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256",
      salt: new Uint8Array(0),
      info: infoBytes },
    baseKey, 256
  );
  return new Uint8Array(bits);
}

// ---------- Öffentlichen Schlüssel aus privatem JWK berechnen ----------
// Ein P-256-JWK enthält x und y (je 32 Bytes, base64url). Der rohe öffentliche
// Schlüssel ist 0x04 || x || y. Damit müssen wir dem Server nicht vertrauen,
// wenn es um unsere EIGENEN öffentlichen Schlüssel geht.
function b64urlToBytes(s) {
  let t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return new Uint8Array(unb64(t));
}
function rawPubFromJwk(jwk) {
  const x = b64urlToBytes(jwk.x), y = b64urlToBytes(jwk.y);
  if (x.byteLength !== 32 || y.byteLength !== 32) throw new Error("invalid key coordinates");
  const out = new Uint8Array(65);
  out[0] = 4; out.set(x, 1); out.set(y, 33);
  return out;
}
function bytesEqual(a, b) {
  const x = new Uint8Array(a), y = new Uint8Array(b);
  if (x.byteLength !== y.byteLength) return false;
  let d = 0;
  for (let i = 0; i < x.byteLength; i++) d |= x[i] ^ y[i];
  return d === 0;
}
function normAddr(a) { return String(a || "").replace(/^mesh:/, ""); }

// ---------- Nachrichtenschlüssel (an Einmal- und Empfängerschlüssel gebunden) ----------
async function deriveMsgKey(sharedBits, ephemeralPubBytes, recipientPubBytes) {
  const info = concatBytes(utf8("lehno-mesh-msg-v2|"), ephemeralPubBytes, recipientPubBytes);
  return await hkdf(sharedBits, info);
}

// ---------- Absender-Nachweis ----------
// Nur wer den privaten Identitätsschlüssel des Absenders (oder des Empfängers)
// besitzt, kann diesen Nachweis berechnen: gemeinsames Geheimnis aus den beiden
// festen Identitätsschlüsseln, daraus ein HMAC über den Einmalschlüssel dieser
// Nachricht + Identitätsschlüssel von Absender und Empfänger.
// Die Adresse ist der Hash des Identitätsschlüssels, damit ist die Kette
// Adresse -> Identitätsschlüssel -> genau diese Nachricht geschlossen.
// Bewusst KEINE Unterschrift außen am Paket: der Server kennt alle öffentlichen
// Signaturschlüssel und könnte sonst durch Ausprobieren den Absender finden.
async function senderAuthKey(myIdentityPriv, theirIdentityPubBytes) {
  const theirPub = await importEcdhPub(theirIdentityPubBytes);
  const shared = await ecdhDerive(myIdentityPriv, theirPub);
  const raw = await hkdf(shared, "lehno-mesh-sender-auth-v2");
  return await crypto.subtle.importKey(
    "raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
}
function senderAuthData(ephemeralPubBytes, senderIdentityPubBytes, recipientIdentityPubBytes) {
  for (const k of [ephemeralPubBytes, senderIdentityPubBytes, recipientIdentityPubBytes]) {
    if (k.byteLength !== 65) throw new Error("invalid public key length");
  }
  return concatBytes(utf8("lehno-mesh-sender-auth-v2|"),
    ephemeralPubBytes, senderIdentityPubBytes, recipientIdentityPubBytes);
}

// ---------- Base58 (Adressen) ----------
const B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    const r = Number(n % 58n);
    n = n / 58n;
    out = B58_ALPH[r] + out;
  }
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

async function addressFromIdentityPubB64(identityPubB64) {
  const raw = unb64(identityPubB64);
  const hash = new Uint8Array(await sha256(raw)).slice(0, 24);
  return "mesh:" + b58encode(hash);
}

function randomSalt() { return randomBytes(16); }

// ---------- Account Setup ----------
async function setupAccount(password) {
  const identity = await generateEcdhKeypair();
  const signing  = await generateEcdsaKeypair();

  const identityPub = await exportPubKey(identity.publicKey);
  const identityPriv = await exportEcdhPriv(identity.privateKey);
  const signingPub = await exportEcdsaPub(signing.publicKey);
  const signingPriv = await exportEcdsaPriv(signing.privateKey);

  const identityPubB64 = b64(identityPub);
  const address = await addressFromIdentityPubB64(identityPubB64);

  const salt = randomSalt();
  const { auth_key, pdk } = await deriveFromPassword(password, salt, KDF_CURRENT);

  const privateBundle = utf8(JSON.stringify({ identityPriv, signingPriv }));

  const kek = randomBytes(32);
  const { ct: keysBlob, iv: keysIv } = await aesGcmEncrypt(kek, privateBundle);
  const { ct: kekBlob,  iv: kekIv  } = await aesGcmEncrypt(pdk, kek);

  return {
    address,
    salt_b64: b64(salt),
    auth_key_b64: b64(auth_key),
    identity_pub_b64: identityPubB64,
    signing_pub_b64: b64(signingPub),
    keys_blob_b64: b64(keysBlob),
    keys_nonce_b64: b64(keysIv),
    kek_blob_b64: b64(kekBlob),
    kek_nonce_b64: b64(kekIv),
    kdf: KDF_CURRENT,
    kek_for_backup: kek,
  };
}

// ---------- Login mit Passwort ----------
async function unlockAccount(password, loginResponse) {
  const salt = unb64(loginResponse.salt_b64);
  const { pdk } = await deriveFromPassword(password, salt, loginResponse.kdf === 2 ? 2 : 1);

  const kekBuf = await aesGcmDecrypt(
    pdk,
    unb64(loginResponse.kek_nonce_b64),
    unb64(loginResponse.kek_blob_b64),
  );
  const kek = new Uint8Array(kekBuf);
  const privateBundleBytes = await aesGcmDecrypt(
    kek,
    unb64(loginResponse.keys_nonce_b64),
    unb64(loginResponse.keys_blob_b64),
  );
  const bundle = JSON.parse(fromUtf8(privateBundleBytes));

  const identityPriv = await importEcdhPriv(bundle.identityPriv);
  const signingPriv  = await importEcdsaPriv(bundle.signingPriv);

  // Eigene öffentliche Schlüssel aus dem entschlüsselten Bündel berechnen und
  // prüfen, dass sie zur Adresse gehören. Ein manipulierter Server kann uns so
  // kein fremdes Schlüsselbündel unterschieben.
  const identity_pub_b64 = b64(rawPubFromJwk(bundle.identityPriv));
  const signing_pub_b64  = b64(rawPubFromJwk(bundle.signingPriv));
  const derived = await addressFromIdentityPubB64(identity_pub_b64);
  if (normAddr(derived) !== normAddr(loginResponse.address)) {
    throw new Error("Schlüssel passen nicht zur Adresse");
  }

  return {
    address: derived,
    jwt: loginResponse.jwt,
    identityPriv,
    signingPriv,
    kek,
    identity_pub_b64,
    signing_pub_b64,
  };
}

// ---------- Padding ----------
function padToBucket(payloadBytes) {
  const need = payloadBytes.byteLength + PAYLOAD_LEN_PREFIX;
  let bucket = null;
  for (const b of PAYLOAD_BUCKETS) {
    if (need <= b) { bucket = b; break; }
  }
  if (bucket === null) throw new Error("payload too large for any bucket");
  const out = new Uint8Array(bucket);
  // Big-endian uint32 length prefix
  new DataView(out.buffer).setUint32(0, payloadBytes.byteLength, false);
  out.set(payloadBytes, PAYLOAD_LEN_PREFIX);
  return out;
}

function unpadFromBucket(plainBytes) {
  const arr = plainBytes instanceof Uint8Array ? plainBytes : new Uint8Array(plainBytes);
  if (arr.byteLength < PAYLOAD_LEN_PREFIX) throw new Error("padded payload too short");
  if (!PAYLOAD_BUCKETS.includes(arr.byteLength)) {
    throw new Error("padded payload not in allowed bucket sizes");
  }
  const view = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  const actualLen = view.getUint32(0, false);
  if (actualLen > arr.byteLength - PAYLOAD_LEN_PREFIX) throw new Error("invalid padded length");
  return arr.slice(PAYLOAD_LEN_PREFIX, PAYLOAD_LEN_PREFIX + actualLen);
}

// ---------- Nachricht verschlüsseln (Sealed Sender + Padding) ----------
// bodyObject ist ein freies JSON-Objekt mit ALLEM was rein soll:
//   { msg_type, is_contact_request, text?, attachment_token?, file_key_b64?,
//     file_iv_b64?, mime?, caption? }
// Absenderadresse, Absender-Nachweis und Nachrichten-Kennung werden automatisch
// ergänzt und liegen ausschließlich im verschlüsselten Teil. Eine Nachricht
// enthält KEINE Zeitangabe, auch nicht verschlüsselt.
// opts.msgId: bei einem erneuten Sendeversuch derselben Nachricht
// wiederverwenden, damit der Empfänger sie nicht doppelt sieht.
async function encryptMessage(myState, recipientIdentityPubB64, bodyObject, opts) {
  const recipientPubBytes = new Uint8Array(unb64(recipientIdentityPubB64));
  const recipientPub = await importEcdhPub(recipientPubBytes);
  const ephemeral = await generateEcdhKeypair();
  const ephemeralPub = await exportPubKey(ephemeral.publicKey);

  const shared = await ecdhDerive(ephemeral.privateKey, recipientPub);
  const msgKey = await deriveMsgKey(shared, ephemeralPub, recipientPubBytes);

  const senderIdentityPubBytes = new Uint8Array(unb64(myState.identity_pub_b64));
  const authKey = await senderAuthKey(myState.identityPriv, recipientPubBytes);
  const authTag = await crypto.subtle.sign(
    "HMAC", authKey,
    senderAuthData(ephemeralPub, senderIdentityPubBytes, recipientPubBytes)
  );

  const fullBody = {
    ...bodyObject,
    v: 2,
    msg_id: (opts && opts.msgId) || b64(randomBytes(16)),
    sender_address: myState.address,
    sender_identity_pub_b64: myState.identity_pub_b64,
    sender_auth_b64: b64(authTag),
  };
  const padded = padToBucket(utf8(JSON.stringify(fullBody)));
  const { ct, iv } = await aesGcmEncrypt(msgKey, padded);

  return {
    ephemeral_pub_b64: b64(ephemeralPub),
    nonce_b64: b64(iv),
    ciphertext_b64: b64(ct),
    msg_id: fullBody.msg_id,
  };
}

// ---------- Nachricht entschlüsseln + Padding entfernen ----------
async function decryptMessage(myState, encryptedMsg) {
  const ephemeralPubBytes = new Uint8Array(unb64(encryptedMsg.ephemeral_pub_b64));
  const iv = unb64(encryptedMsg.nonce_b64);
  const ct = unb64(encryptedMsg.ciphertext_b64);
  const myIdentityPubBytes = new Uint8Array(unb64(myState.identity_pub_b64));

  const ephemeralPub = await importEcdhPub(ephemeralPubBytes);
  const shared = await ecdhDerive(myState.identityPriv, ephemeralPub);
  const msgKey = await deriveMsgKey(shared, ephemeralPubBytes, myIdentityPubBytes);

  const paddedBuf = await aesGcmDecrypt(msgKey, iv, ct);
  const payloadBytes = unpadFromBucket(new Uint8Array(paddedBuf));
  const body = JSON.parse(fromUtf8(payloadBytes));
  if (!body || typeof body !== "object") throw new Error("malformed payload");
  for (const f of ["sender_address", "sender_identity_pub_b64", "sender_auth_b64"]) {
    if (typeof body[f] !== "string" || !body[f]) throw new Error("malformed payload");
  }

  // 1) Adresse muss der Hash des Identitätsschlüssels sein.
  const derived = await addressFromIdentityPubB64(body.sender_identity_pub_b64);
  if (derived !== body.sender_address) {
    throw new Error("sender address does not match identity key");
  }

  // 2) Absender-Nachweis: beweist den Besitz des privaten Identitätsschlüssels
  //    zu genau dieser Adresse und bindet ihn an genau diese Nachricht.
  //    Ohne diesen Schritt könnte jeder einen fremden (öffentlichen)
  //    Identitätsschlüssel angeben.
  const senderIdentityPubBytes = new Uint8Array(unb64(body.sender_identity_pub_b64));
  const authKey = await senderAuthKey(myState.identityPriv, senderIdentityPubBytes);
  const authOk = await crypto.subtle.verify(
    "HMAC", authKey, unb64(body.sender_auth_b64),
    senderAuthData(ephemeralPubBytes, senderIdentityPubBytes, myIdentityPubBytes)
  );
  if (!authOk) throw new Error("sender proof invalid");

  return body;
}

// ---------- Alt-Format (vor Phase 1.8) nur noch LESEN ----------
// Für Nachrichten, die beim Update noch auf dem Server warteten. Das alte Format
// beweist den Absender nicht (jeder konnte eine fremde Adresse angeben), deshalb
// kennzeichnet der Aufrufer solche Nachrichten als "Absender nicht geprüft".
// Neue Nachrichten in diesem Format nimmt der Server nicht mehr an.
async function decryptLegacyMessage(myState, encryptedMsg) {
  if (!encryptedMsg.signature_b64) throw new Error("no legacy signature");
  const ephemeralPubBytes = new Uint8Array(unb64(encryptedMsg.ephemeral_pub_b64));
  const iv = unb64(encryptedMsg.nonce_b64);
  const ct = unb64(encryptedMsg.ciphertext_b64);
  const sig = unb64(encryptedMsg.signature_b64);

  const ephemeralPub = await importEcdhPub(ephemeralPubBytes);
  const shared = await ecdhDerive(myState.identityPriv, ephemeralPub);
  const msgKey = await hkdf(shared, "lehno-mesh-msg-v1");
  const paddedBuf = await aesGcmDecrypt(msgKey, iv, ct);
  const body = JSON.parse(fromUtf8(unpadFromBucket(new Uint8Array(paddedBuf))));
  if (!body || typeof body !== "object" || body.v === 2) throw new Error("malformed payload");
  for (const f of ["sender_address", "sender_identity_pub_b64", "sender_signing_pub_b64"]) {
    if (typeof body[f] !== "string" || !body[f]) throw new Error("malformed payload");
  }
  const senderSign = await importEcdsaPub(unb64(body.sender_signing_pub_b64));
  const sigOk = await ecdsaVerify(senderSign, sig, concatBytes(ephemeralPubBytes, iv, ct));
  if (!sigOk) throw new Error("signature invalid");
  const derived = await addressFromIdentityPubB64(body.sender_identity_pub_b64);
  if (derived !== body.sender_address) throw new Error("sender address does not match identity key");
  return body;
}

// ---------- Datei verschluesseln (mit Padding auf Buckets) ----------
// Attachments werden auf eine der 4 Bucket-Groessen gepadded, damit der Server
// nicht aus der File-Groesse auf Inhaltstyp (Foto/Audio/Video) schliessen kann.
// AES-GCM haengt 16-byte Tag an, daher plaintext-size = bucket - 16 -> ct-size = bucket.
// Format vor encrypt: 4 bytes BE length || file bytes || zero padding bis (bucket-16).
// Server-validierte Bucket-Groessen MUESSEN mit ATTACHMENT_BUCKETS in app.py
// uebereinstimmen (256 KB / 1 MB / 4 MB / 16 MB).
const ATTACHMENT_BUCKETS = [262144, 1048576, 4194304, 16777216];
const ATTACHMENT_LEN_PREFIX = 4;
const ATTACHMENT_GCM_TAG = 16;

function pickAttachmentBucket(fileLen) {
  const need = fileLen + ATTACHMENT_LEN_PREFIX + ATTACHMENT_GCM_TAG;
  for (const b of ATTACHMENT_BUCKETS) {
    if (need <= b) return b;
  }
  throw new Error("attachment too large (>16 MB)");
}

function padAttachment(fileBytes, bucket) {
  const plainSize = bucket - ATTACHMENT_GCM_TAG;
  const out = new Uint8Array(plainSize);
  new DataView(out.buffer).setUint32(0, fileBytes.byteLength, false);
  out.set(fileBytes, ATTACHMENT_LEN_PREFIX);
  return out;
}

function unpadAttachment(paddedBytes) {
  const arr = paddedBytes instanceof Uint8Array ? paddedBytes : new Uint8Array(paddedBytes);
  // padded plaintext-size = bucket - 16
  const validSizes = ATTACHMENT_BUCKETS.map(b => b - ATTACHMENT_GCM_TAG);
  if (!validSizes.includes(arr.byteLength)) {
    throw new Error("attachment plaintext not in allowed bucket size");
  }
  const view = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  const actualLen = view.getUint32(0, false);
  if (actualLen > arr.byteLength - ATTACHMENT_LEN_PREFIX) throw new Error("invalid attachment length");
  return arr.slice(ATTACHMENT_LEN_PREFIX, ATTACHMENT_LEN_PREFIX + actualLen);
}

async function encryptFile(fileBytes) {
  const bucket = pickAttachmentBucket(fileBytes.byteLength);
  const padded = padAttachment(fileBytes, bucket);
  const fileKey = randomBytes(32);
  const iv = randomBytes(12);
  const key = await importAesKey(fileKey);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, padded);
  // ct.byteLength === bucket (padded.length + 16 GCM tag), Server-Bucket-Check passt.
  return { ciphertext: new Uint8Array(ct), fileKey, iv };
}

async function decryptFile(fileKey, iv, ciphertext) {
  const key = await importAesKey(fileKey);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  // Padding entfernen: 4-byte length-prefix lesen, dann file-bytes ausschneiden
  return unpadAttachment(new Uint8Array(plain));
}

// ---------- Verschlüsselte Ablagen auf dem Server (nur der Nutzer kann sie lesen) ----------
// Zwei Ablagen je Konto, beide mit einem eigenen Schlüssel aus dem KEK:
//   userdata = Kontakte, Spitznamen, abgelehnte Adressen
//   history  = der komplette Chat-Verlauf (damit er auf jedem Gerät und nach
//              dem Schließen des Tor-Browsers wieder da ist)
// Der Klartext wird auf Einheitsgrößen aufgefüllt, damit der Server aus der
// Größe nicht auf die Anzahl der Kontakte oder Nachrichten schließen kann.
// Format: 4 Bytes Länge (big-endian) || JSON || Null-Auffüllung.
// Alt-Format (vor 1.8, nur userdata): rohes JSON, beginnt mit "{".
// Die Größen MÜSSEN zu USERDATA_BUCKETS / HISTORY_BUCKETS in app.py passen.
const USERDATA_BUCKETS = [2048, 8192, 32768, 131072];
const HISTORY_BUCKETS  = [65536, 262144, 1048576, 4194304];

async function encryptPadded(kek, purpose, dataObject, buckets) {
  const key = await hkdf(kek, purpose);
  const jsonBytes = utf8(JSON.stringify(dataObject));
  let bucket = null;
  for (const b of buckets) { if (jsonBytes.byteLength + 4 <= b) { bucket = b; break; } }
  if (bucket === null) throw new Error("blob too large");
  const padded = new Uint8Array(bucket);
  new DataView(padded.buffer).setUint32(0, jsonBytes.byteLength, false);
  padded.set(jsonBytes, 4);
  const { ct, iv } = await aesGcmEncrypt(key, padded);
  return { nonce_b64: b64(iv), ciphertext_b64: b64(ct) };
}

async function decryptPadded(kek, purpose, payload) {
  if (!payload || !payload.nonce_b64 || !payload.ciphertext_b64) return null;
  const key = await hkdf(kek, purpose);
  const plain = new Uint8Array(
    await aesGcmDecrypt(key, unb64(payload.nonce_b64), unb64(payload.ciphertext_b64))
  );
  if (plain.byteLength > 0 && plain[0] === 0x7b) {
    return JSON.parse(fromUtf8(plain));               // Alt-Format
  }
  if (plain.byteLength < 4) throw new Error("blob malformed");
  const len = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0, false);
  if (len > plain.byteLength - 4) throw new Error("blob malformed");
  return JSON.parse(fromUtf8(plain.slice(4, 4 + len)));
}

function historyFits(dataObject) {
  return utf8(JSON.stringify(dataObject)).byteLength + 4 <= HISTORY_BUCKETS[HISTORY_BUCKETS.length - 1];
}

async function encryptUserdata(kek, dataObject) {
  return await encryptPadded(kek, "lehno-mesh-userdata-v1", dataObject, USERDATA_BUCKETS);
}
async function decryptUserdata(kek, payload) {
  return await decryptPadded(kek, "lehno-mesh-userdata-v1", payload);
}
async function encryptHistory(kek, dataObject) {
  return await encryptPadded(kek, "lehno-mesh-history-v1", dataObject, HISTORY_BUCKETS);
}
async function decryptHistory(kek, payload) {
  return await decryptPadded(kek, "lehno-mesh-history-v1", payload);
}

// ---------- Mnemonic-Recovery ----------
// 1) GET /api/recover/init {address} -> {keys_blob_b64, keys_nonce_b64, identity_pub_b64, challenge_hex}
// 2) recoverWithMnemonic(...) entschluesselt keys_blob mit KEK aus Mnemonic,
//    signiert die Challenge mit dem privaten Signing-Key, baut neuen
//    encrypted_kek (mit pdk aus neuem Passwort) und gibt das fertige
//    Finalize-Payload zurueck.
// 3) POST /api/recover/finalize <- diesen Payload.
async function recoverWithMnemonic(address, mnemonic, newPassword, recoverInitResp) {
  const kekBytes = await LehnoBip39.mnemonicToBytes(mnemonic);
  const kek = new Uint8Array(kekBytes);

  // keys_blob mit KEK entschluesseln - failt mit AES-GCM-Auth-Error wenn Mnemonic falsch
  let bundle;
  try {
    const privBytes = await aesGcmDecrypt(
      kek,
      unb64(recoverInitResp.keys_nonce_b64),
      unb64(recoverInitResp.keys_blob_b64),
    );
    bundle = JSON.parse(fromUtf8(privBytes));
  } catch (e) {
    throw new Error("Backup-Code falsch oder Adresse unbekannt");
  }
  if (!bundle.signingPriv) throw new Error("Backup ungueltig (kein signing key)");

  // Plausibilität: Der Identitätsschlüssel aus dem entschlüsselten Bündel muss
  // zur eingegebenen Adresse passen (nicht dem Server glauben).
  if (!bundle.identityPriv) throw new Error("Backup ungültig (kein Identitätsschlüssel)");
  const derivedAddr = await addressFromIdentityPubB64(b64(rawPubFromJwk(bundle.identityPriv)));
  if (normAddr(derivedAddr) !== normAddr(address)) {
    throw new Error("Backup-Code gehört nicht zu dieser Adresse");
  }

  const signingPriv = await importEcdsaPriv(bundle.signingPriv);
  const dataToSign = utf8("lehno-mesh-recovery-v1:" + recoverInitResp.challenge_hex);
  const sig = await ecdsaSign(signingPriv, dataToSign);

  const newSalt = randomSalt();
  const { auth_key: newAuthKey, pdk: newPdk } = await deriveFromPassword(newPassword, newSalt, KDF_CURRENT);
  const { ct: newKekBlob, iv: newKekIv } = await aesGcmEncrypt(newPdk, kek);

  return {
    address,
    challenge_hex: recoverInitResp.challenge_hex,
    signature_b64: b64(sig),
    new_auth_key_b64: b64(newAuthKey),
    new_salt_b64: b64(newSalt),
    new_kek_blob_b64: b64(newKekBlob),
    new_kek_nonce_b64: b64(newKekIv),
    new_kdf: KDF_CURRENT,
  };
}

window.LehnoCrypto = {
  b64, unb64, utf8, fromUtf8, randomBytes,
  setupAccount, unlockAccount,
  encryptMessage, decryptMessage, decryptLegacyMessage,
  encryptFile, decryptFile,
  encryptUserdata, decryptUserdata,
  encryptHistory, decryptHistory, historyFits,
  recoverWithMnemonic,
  addressFromIdentityPubB64,
  deriveFromPassword,
  PAYLOAD_BUCKETS,
};
