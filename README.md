# mesh

Anonymes, Ende-zu-Ende verschluesseltes Messaging.

Live unter:
- `https://mesh.lehno.de` (Cloudflare-Proxy, Caddy, Hetzner)
- `http://35m6ezqw2ugdqnsqhpxe4ccpnzvesfj24ile3xswvt4s5n6fyy5xfqqd.onion` (Tor Hidden Service)

## Was es ist

Ein selbstgehostetes E2EE-Messaging das so wenig wie moeglich ueber seine User weiss.

- **Keine Usernames.** Jeder Account hat eine kryptografische Adresse die deterministisch aus dem Public-Key abgeleitet wird (`mesh:Base58...`). User koennen ihre Adresse teilen wie eine Krypto-Wallet.
- **Sealed-Sender.** Der Server sieht beim Speichern eines Pakets nur die Empfaenger-Adresse. Wer Sender ist, steckt nur im verschluesselten Body.
- **Keine User-Liste.** Keine Suche, kein Verzeichnis, kein Count-Endpoint. Wer dich kontaktieren will, muss deine Adresse direkt von dir bekommen.
- **Contact-Requests.** Erste Nachricht von neuem Sender erscheint als Anfrage. Empfaenger akzeptiert oder lehnt ab.
- **Auto-Delete.** Nachrichten werden nach Abholung sofort vom Server geloescht. Nicht abgeholte Nachrichten verfallen nach 30 Tagen.
- **Keine Admin-Macht.** Kein Sperr-Endpoint, kein User-Listing. Wer Server-Root hat kann natuerlich technisch alles, aber die API exponiert nichts davon.
- **Keine Server-Logs.** Caddy + uvicorn Access-Logs sind deaktiviert.
- **Tor Hidden Service.** Wer ueber Tor Browser kommt, ist auch vor Cloudflare und Hetzner unsichtbar.

## Krypto

Alle Krypto-Operationen passieren im Browser via WebCrypto API. Der Server kennt
keinen einzigen Private-Key.

| Zweck | Algorithmus |
|---|---|
| Identity-Keypair (Schluessel-Tausch) | ECDH P-256 |
| Signing-Keypair | ECDSA P-256 (SHA-256) |
| Symmetrische Verschluesselung | AES-256-GCM mit 96-bit-IV |
| Schluessel aus Passwort | PBKDF2-SHA256, 600.000 Iterationen |
| Shared-Secret -> Message-Key | HKDF-SHA256 |
| Server-side Auth-Verifikation | Argon2id (t=3, m=64MB, p=2) |
| Address-Ableitung | base58(sha256(identity_pub)[:24]) |
| Backup-Code | BIP39 Englisch, 24 Woerter (256 bits + 8 bit checksum) |

### Sealed-Sender-Schema

Pro Nachricht:
1. Sender generiert ephemeren ECDH-Keypair.
2. `shared = ECDH(ephemeral_priv, recipient_identity_pub)`.
3. `msg_key = HKDF(shared, "lehno-mesh-msg-v1")`.
4. Payload-JSON `{sender_address, sender_signing_pub_b64, content}` wird mit `msg_key` via AES-GCM verschluesselt.
5. Signatur via Ed25519/ECDSA ueber `ephemeral_pub || nonce || ciphertext` mit `sender_signing_priv`.
6. Server speichert: `recipient_address, ephemeral_pub, nonce, ciphertext, signature, msg_type, is_contact_request, attachment_id, created_day`. Kein Sender-Feld.

Empfaenger leitet `shared = ECDH(identity_priv, ephemeral_pub)`, entschluesselt, prueft Signatur mit dem Sender-Signing-Pub aus dem entschluesselten Body.

### Account-Setup

```
salt              = random(16 bytes)
PDK               = PBKDF2(password, salt, 600k, 32 bytes)
auth_key          = PBKDF2(password, salt, 600k, weitere 32 bytes)
identity_keypair  = ECDH P-256 generate
signing_keypair   = ECDSA P-256 generate
KEK               = random(32 bytes)
encrypted_keys    = AES-GCM(JSON(identity_priv, signing_priv), key=KEK)
encrypted_kek     = AES-GCM(KEK, key=PDK)
address           = "mesh:" + base58(sha256(identity_pub_raw)[:24])
mnemonic          = BIP39(KEK)   // 24 Woerter Backup
```

Beim Login fragt der Server `argon2id(auth_key)` ab und gibt bei Match `salt`, `encrypted_keys`, `encrypted_kek` zurueck. Der Browser leitet PDK und KEK lokal ab, entschluesselt die Private-Keys, haelt sie im RAM.

### Recovery via Mnemonic

(Phase 2, noch nicht implementiert.) Mit den 24 Backup-Woertern kann der KEK rekonstruiert werden, damit der User ein neues Passwort setzen kann. Ohne Mnemonic + ohne Passwort: Account weg.

## Was der Server NICHT sehen kann

- Klartext-Nachrichten (alles E2EE)
- Passwoerter (kommen nie zum Server)
- 24-Wort-Backup-Codes (sind clientseitig)
- Sender einer Nachricht (sealed sender)
- Wer mit wem chattet (kein from-Feld, recipient_address steht da aber sagt nichts darueber WER schickt)
- User-Namen (es gibt keine)
- IP-Adressen (Cloudflare-Proxy + Tor verstecken die)

## Was der Server SEHEN kann (Trade-offs)

- Anzahl Pakete pro Empfaenger-Adresse (zu welcher Adresse gerade was rein kam)
- Paket-Groesse (mitigierbar via Padding, noch nicht aktiv)
- Tag (nicht Uhrzeit - `created_day` ist Tag-Bucket)
- Wer mit dem Server verbunden ist via WebSocket (nicht-Tor-User: IP. Tor-User: nur Tor-Exit)

## Bekannte Trust-Issues

- **Frontend-Vertrauen:** Wer den Server kontrolliert kann theoretisch ein boeses Frontend pushen das Passwoerter mitschickt. Schutz dagegen: Open-Source-Repo + reproducible builds + clientseitige Verifikation. Phase 3.
- **Server-Hoster:** Hetzner sehen Tor-Traffic, Cloudflare-Traffic. Sehen aber den Inhalt nicht. Wirklich unsichtbar nur ueber Tor-Browser-Connection.
- **TOFU bei erstem Kontakt:** Erste Anfrage von einer Adresse hat noch keine Out-of-Band-Verifikation. Phase 2: Fingerprint-Vergleich + QR-Scan.

## Stack

- Backend: Python 3.12 + FastAPI + uvicorn + SQLite (aiosqlite)
- Frontend: Vanilla JS, WebCrypto, BIP39, PWA-Manifest, Service Worker
- Reverse-Proxy: Caddy mit Cloudflare-Origin-Cert
- Hidden Service: Tor v3 (`HiddenServiceVersion 3`)
- Hosting: Hetzner Cloud (CX21 oder aehnlich)

## Lizenz

MIT.

## Status

Phase 1.5 (Mai 2026). Voll funktional fuer 1:1-Chat, Bilder, Sprachnachrichten, Tor.

Phase 2 (geplant):
- 24-Wort-Mnemonic Recovery
- X3DH + Double-Ratchet (volle Forward-Secrecy)
- Gruppen-Chats
- 1:1 + Gruppen Audio/Video-Calls (WebRTC + coturn + LiveKit)
- Native iOS + Android Apps (React Native)
- Push-Notifications
- Multi-Device-Sync
- Fingerprint-Verifikation per QR

Phase 3 (laenger):
- Reproducible Builds
- Cover-Traffic (alle x Sekunden Dummy-Pakete um Timing-Analyse zu erschweren)
- Mix-Network-Anbindung (SimpleX-Style oder eigene Cascade)
- Native App ohne Browser-Vertrauensproblem
