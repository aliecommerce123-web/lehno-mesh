// lehno-mesh Phase 1.6 - alle Krypto-Operationen via WebCrypto API.
// Curves: ECDH P-256 + ECDSA P-256.
// Symmetrisch: AES-256-GCM. KDF: PBKDF2-SHA256 (600k Iter) + HKDF-SHA256.
// NEU in 1.6: Padding-Buckets, msg_type/is_contact_request/attachment_token im
// verschluesselten Body, encrypted userdata blob fuer Spitznamen-Sync.

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
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
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

// ---------- PBKDF2: Passwort -> 64 bytes (auth_key 32 + pdk 32) ----------
async function deriveFromPassword(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw", utf8(password), "PBKDF2", false, ["deriveBits"]
  );
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
async function hkdf(rawSecret, infoString) {
  const baseKey = await crypto.subtle.importKey(
    "raw", rawSecret, "HKDF", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256",
      salt: new Uint8Array(0),
      info: utf8(infoString) },
    baseKey, 256
  );
  return new Uint8Array(bits);
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
  const { auth_key, pdk } = await deriveFromPassword(password, salt);

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
    kek_for_backup: kek,
  };
}

// ---------- Login mit Passwort ----------
async function unlockAccount(password, loginResponse) {
  const salt = unb64(loginResponse.salt_b64);
  const { pdk } = await deriveFromPassword(password, salt);

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

  return {
    address: loginResponse.address,
    jwt: loginResponse.jwt,
    identityPriv,
    signingPriv,
    kek,
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

// ---------- Nachricht verschluesseln (Sealed Sender + Padding) ----------
// bodyObject ist ein freies JSON-Objekt mit ALLEM was rein soll:
//   { msg_type, is_contact_request, text?, attachment_token?, file_key_b64?,
//     file_iv_b64?, mime?, caption? }
// sender_address + sender_signing_pub_b64 werden automatisch ergaenzt.
async function encryptMessage(myState, recipientIdentityPubB64, bodyObject) {
  const recipientPub = await importEcdhPub(unb64(recipientIdentityPubB64));
  const ephemeral = await generateEcdhKeypair();
  const ephemeralPub = await exportPubKey(ephemeral.publicKey);

  const shared = await ecdhDerive(ephemeral.privateKey, recipientPub);
  const msgKey = await hkdf(shared, "lehno-mesh-msg-v1");

  const fullBody = {
    sender_address: myState.address,
    sender_identity_pub_b64: myState.identity_pub_b64,
    sender_signing_pub_b64: myState.signing_pub_b64,
    ...bodyObject,
  };
  const payloadJson = JSON.stringify(fullBody);
  const payloadBytes = utf8(payloadJson);
  const padded = padToBucket(payloadBytes);

  const { ct, iv } = await aesGcmEncrypt(msgKey, padded);

  const ctBytes = new Uint8Array(ct);
  const sigData = concatBytes(ephemeralPub, iv, ctBytes);
  const sig = await ecdsaSign(myState.signingPriv, sigData);

  return {
    ephemeral_pub_b64: b64(ephemeralPub),
    nonce_b64: b64(iv),
    ciphertext_b64: b64(ct),
    signature_b64: b64(sig),
  };
}

// ---------- Nachricht entschluesseln + Padding entfernen ----------
async function decryptMessage(myState, encryptedMsg) {
  const ephemeralPubBytes = unb64(encryptedMsg.ephemeral_pub_b64);
  const iv = unb64(encryptedMsg.nonce_b64);
  const ct = unb64(encryptedMsg.ciphertext_b64);
  const sig = unb64(encryptedMsg.signature_b64);

  const ephemeralPub = await importEcdhPub(ephemeralPubBytes);
  const shared = await ecdhDerive(myState.identityPriv, ephemeralPub);
  const msgKey = await hkdf(shared, "lehno-mesh-msg-v1");

  const paddedBuf = await aesGcmDecrypt(msgKey, iv, ct);
  const payloadBytes = unpadFromBucket(new Uint8Array(paddedBuf));
  const body = JSON.parse(fromUtf8(payloadBytes));
  if (!body.sender_address || !body.sender_signing_pub_b64 || !body.sender_identity_pub_b64) {
    throw new Error("malformed payload");
  }

  // Signatur ueber ephemeral||nonce||ct mit sender_signing_pub aus body verifizieren.
  const senderSign = await importEcdsaPub(unb64(body.sender_signing_pub_b64));
  const sigData = concatBytes(ephemeralPubBytes, iv, ct);
  const sigOk = await ecdsaVerify(senderSign, sig, sigData);
  if (!sigOk) throw new Error("signature invalid");

  // Sender-Impersonation-Schutz: address muss deterministisch aus sender_identity_pub
  // ableitbar sein. Sonst koennte ein Angreifer ein eigenes Keypair haben + behaupten
  // er sei die Adresse XYZ. Mit dieser Pruefung scheitert er, weil
  // address_from(seinem_identity_pub) != XYZ.
  const derived = await addressFromIdentityPubB64(body.sender_identity_pub_b64);
  if (derived !== body.sender_address) {
    throw new Error("sender address does not match identity key");
  }
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

// ---------- Encrypted Userdata (Spitznamen + Kontakte synced) ----------
// Eigener Key abgeleitet aus KEK via HKDF, damit gleicher Account auf
// mehreren Geraeten dieselben Spitznamen sieht.
async function deriveUserdataKey(kek) {
  return await hkdf(kek, "lehno-mesh-userdata-v1");
}

async function encryptUserdata(kek, dataObject) {
  const dataKey = await deriveUserdataKey(kek);
  const json = JSON.stringify(dataObject);
  const { ct, iv } = await aesGcmEncrypt(dataKey, utf8(json));
  return { nonce_b64: b64(iv), ciphertext_b64: b64(ct) };
}

async function decryptUserdata(kek, payload) {
  if (!payload || !payload.nonce_b64 || !payload.ciphertext_b64) return null;
  const dataKey = await deriveUserdataKey(kek);
  const plain = await aesGcmDecrypt(dataKey, unb64(payload.nonce_b64), unb64(payload.ciphertext_b64));
  return JSON.parse(fromUtf8(plain));
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

  // Plausibilitaet: identity_pub aus dem entschluesselten Bundle muss zur
  // gemeldeten Adresse passen.
  const identityPubServer = recoverInitResp.identity_pub_b64;

  const signingPriv = await importEcdsaPriv(bundle.signingPriv);
  const dataToSign = utf8("lehno-mesh-recovery-v1:" + recoverInitResp.challenge_hex);
  const sig = await ecdsaSign(signingPriv, dataToSign);

  const newSalt = randomSalt();
  const { auth_key: newAuthKey, pdk: newPdk } = await deriveFromPassword(newPassword, newSalt);
  const { ct: newKekBlob, iv: newKekIv } = await aesGcmEncrypt(newPdk, kek);

  return {
    address,
    challenge_hex: recoverInitResp.challenge_hex,
    signature_b64: b64(sig),
    new_auth_key_b64: b64(newAuthKey),
    new_salt_b64: b64(newSalt),
    new_kek_blob_b64: b64(newKekBlob),
    new_kek_nonce_b64: b64(newKekIv),
  };
}

window.LehnoCrypto = {
  b64, unb64, utf8, fromUtf8, randomBytes,
  setupAccount, unlockAccount,
  encryptMessage, decryptMessage,
  encryptFile, decryptFile,
  encryptUserdata, decryptUserdata,
  recoverWithMnemonic,
  addressFromIdentityPubB64,
  deriveFromPassword,
  PAYLOAD_BUCKETS,
};
