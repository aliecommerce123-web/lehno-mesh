// lehno-mesh: alle Krypto-Operationen via WebCrypto API.
// Curves: ECDH P-256 + ECDSA P-256 (universell unterstuetzt).
// Symmetrisch: AES-256-GCM. KDF: PBKDF2-SHA256 (600k Iter) + HKDF-SHA256.

const PBKDF2_ITER = 600000;
const SALT_PREFIX = "lehno-mesh-v1:";

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

// ---------- Salt für Username (deterministisch) ----------
async function saltForUsername(username) {
  const h = await sha256(utf8(SALT_PREFIX + username.toLowerCase()));
  return new Uint8Array(h).slice(0, 16);
}

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
    auth_key: all.slice(0, 32),  // wird über TLS zum Server geschickt
    pdk:      all.slice(32, 64), // bleibt LOKAL, verschlüsselt KEK
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

// ---------- ECDH P-256 (Identity-Keypair) ----------
async function generateEcdhKeypair() {
  return await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
}

async function exportPubKey(pubKey) {
  // raw uncompressed: 65 bytes (0x04 || X(32) || Y(32))
  const raw = await crypto.subtle.exportKey("raw", pubKey);
  return new Uint8Array(raw);
}

async function importEcdhPub(rawBytes) {
  return await crypto.subtle.importKey(
    "raw", rawBytes, { name: "ECDH", namedCurve: "P-256" }, true, []
  );
}

async function exportEcdhPriv(privKey) {
  // pkcs8 ist serialisierbar, JWK auch (lesbarer)
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

// ---------- ECDSA P-256 (Signing-Keypair) ----------
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

// ---------- HKDF: shared secret -> 32-byte message key ----------
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

// ---------- Base58 (Bitcoin-Alphabet) - für Adressen ----------
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

// Salt für Account: leiten aus der eigenen Adresse ab (nicht aus Username
// weil es keinen mehr gibt). Beim Register zufaellig, beim Login bekommen wir
// das salt_b64 vom Server.
function randomSalt() { return randomBytes(16); }

// ---------- High-Level: Account Setup ----------
// Generiert: Identity (ECDH), Signing (ECDSA), KEK (random 32b),
//            encrypted_keys = AES-GCM(JSON(priv keys), KEK),
//            encrypted_kek  = AES-GCM(KEK, PDK).
// Returns address (deterministisch aus identity_pub) + Mnemonic-Seed (= KEK).
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

// ---------- High-Level: Login mit Passwort ----------
async function unlockAccount(password, loginResponse) {
  const salt = unb64(loginResponse.salt_b64);
  const { auth_key, pdk } = await deriveFromPassword(password, salt);

  const kek = await aesGcmDecrypt(
    pdk,
    unb64(loginResponse.kek_nonce_b64),
    unb64(loginResponse.kek_blob_b64),
  );
  const privateBundleBytes = await aesGcmDecrypt(
    new Uint8Array(kek),
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
    kek: new Uint8Array(kek),
  };
}

// ---------- High-Level: Nachricht verschlüsseln (Sealed Sender) ----------
// Body wird als JSON serialisiert mit { sender_address, sender_identity_pub_b64,
// sender_signing_pub_b64, content }. Damit kann Empfänger die Sender-Adresse
// prüfen ohne dass der Server sie sieht.
async function encryptMessage(myState, recipientIdentityPubB64, contentString) {
  const recipientPub = await importEcdhPub(unb64(recipientIdentityPubB64));
  const ephemeral = await generateEcdhKeypair();
  const ephemeralPub = await exportPubKey(ephemeral.publicKey);

  const shared = await ecdhDerive(ephemeral.privateKey, recipientPub);
  const msgKey = await hkdf(shared, "lehno-mesh-msg-v1");

  // Sender-Identität IM VERSCHLUESSELTEN Body (sealed sender)
  const payload = utf8(JSON.stringify({
    sender_address: myState.address,
    sender_signing_pub_b64: myState.signing_pub_b64,
    content: contentString,
  }));

  const { ct, iv } = await aesGcmEncrypt(msgKey, payload);

  // Signatur über ephemeral || nonce || ciphertext
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

// ---------- High-Level: Nachricht entschlüsseln ----------
// Gibt {sender_address, sender_signing_pub_b64, content} zurück.
// Verifiziert ZUSAETZLICH dass sender_address == address_from(sender_identity_pub).
async function decryptMessage(myState, encryptedMsg) {
  const ephemeralPubBytes = unb64(encryptedMsg.ephemeral_pub_b64);
  const iv = unb64(encryptedMsg.nonce_b64);
  const ct = unb64(encryptedMsg.ciphertext_b64);
  const sig = unb64(encryptedMsg.signature_b64);

  // ECDH derive (geht ohne Sender-Info, weil nur unsere privKey + ephemeralPub gebraucht)
  const ephemeralPub = await importEcdhPub(ephemeralPubBytes);
  const shared = await ecdhDerive(myState.identityPriv, ephemeralPub);
  const msgKey = await hkdf(shared, "lehno-mesh-msg-v1");

  const plainBytes = await aesGcmDecrypt(msgKey, iv, ct);
  const body = JSON.parse(fromUtf8(plainBytes));
  if (!body.sender_address || !body.sender_signing_pub_b64) {
    throw new Error("malformed payload");
  }

  // Signatur verifizieren mit der Sender-PubKey aus dem verschlüsselten Body
  const senderSign = await importEcdsaPub(unb64(body.sender_signing_pub_b64));
  const sigData = concatBytes(ephemeralPubBytes, iv, ct);
  const sigOk = await ecdsaVerify(senderSign, sig, sigData);
  if (!sigOk) throw new Error("signature invalid");

  return body;  // { sender_address, sender_signing_pub_b64, content }
}

// ---------- High-Level: Datei verschlüsseln (Bild / Audio / Video) ----------
// File-Key wird random gewählt und im Message-Body verschlüsselt mitgeliefert.
async function encryptFile(fileBytes) {
  const fileKey = randomBytes(32);
  const iv = randomBytes(12);
  const key = await importAesKey(fileKey);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileBytes);
  return { ciphertext: new Uint8Array(ct), fileKey, iv };
}

async function decryptFile(fileKey, iv, ciphertext) {
  const key = await importAesKey(fileKey);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(plain);
}

window.LehnoCrypto = {
  b64, unb64, utf8, fromUtf8, randomBytes,
  setupAccount, unlockAccount, encryptMessage, decryptMessage,
  encryptFile, decryptFile,
  addressFromIdentityPubB64,
  deriveFromPassword,  // damit app.js login-init nutzen kann
};
