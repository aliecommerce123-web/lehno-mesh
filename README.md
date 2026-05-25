# mesh

Anonymes, Ende-zu-Ende verschlüsseltes Messaging.

Live unter:
- `https://mesh.lehno.de` (Clearnet-Zugang, leitet Nicht-Tor-User auf eine Anleitung)
- `http://35m6ezqw2ugdqnsqhpxe4ccpnzvesfj24ile3xswvt4s5n6fyy5xfqqd.onion` (Tor Hidden Service - empfohlen)

## Was es ist

Ein selbstgehostetes E2EE-Messaging das so wenig wie möglich über seine User weiß.

- **Keine Usernames.** Jeder Account hat eine kryptografische Adresse die deterministisch aus dem Public-Key abgeleitet wird (`mesh:Base58...`). User können ihre Adresse teilen wie eine Krypto-Wallet.
- **Sealed-Sender.** Der Server sieht beim Speichern eines Pakets nur die Empfänger-Adresse. Wer Sender ist, steckt nur im verschlüsselten Body.
- **Keine User-Liste.** Keine Suche, kein Verzeichnis, kein Count-Endpoint. Wer dich kontaktieren will, muss deine Adresse direkt von dir bekommen.
- **Contact-Requests.** Erste Nachricht von neuem Sender erscheint als Anfrage. Empfänger akzeptiert oder lehnt ab.
- **Auto-Delete.** Nachrichten werden nach Abholung sofort vom Server gelöscht. Nicht abgeholte Nachrichten verfallen nach 30 Tagen.
- **Keine Admin-Macht.** Kein Sperr-Endpoint, kein User-Listing. Wer Server-Root hat kann natürlich technisch alles, aber die API exponiert nichts davon.
- **Keine Server-Logs.** Caddy + uvicorn Access-Logs sind deaktiviert.
- **Tor Hidden Service.** Wer über Tor Browser kommt, ist auch vor allen Zwischenstellen im Netz unsichtbar.

## Krypto

Alle Krypto-Operationen passieren im Browser via WebCrypto API. Der Server kennt
keinen einzigen Private-Key.

| Zweck | Algorithmus |
|---|---|
| Identity-Keypair (Schlüssel-Tausch) | ECDH P-256 |
| Signing-Keypair | ECDSA P-256 (SHA-256) |
| Symmetrische Verschlüsselung | AES-256-GCM mit 96-bit-IV |
| Schlüssel aus Passwort | PBKDF2-SHA256, 600.000 Iterationen |
| Shared-Secret -> Message-Key | HKDF-SHA256 |
| Server-side Auth-Verifikation | Argon2id (t=3, m=64MB, p=2) |
| Address-Ableitung | base58(sha256(identity_pub)[:24]) |
| Backup-Code | BIP39 Englisch, 24 Wörter (256 bits + 8 bit checksum) |

### Sealed-Sender-Schema (Phase 1.6)

Pro Nachricht:
1. Sender generiert ephemeren ECDH-Keypair.
2. `shared = ECDH(ephemeral_priv, recipient_identity_pub)`.
3. `msg_key = HKDF(shared, "lehno-mesh-msg-v1")`.
4. Payload-JSON `{sender_address, sender_identity_pub_b64, sender_signing_pub_b64, msg_type, is_contact_request, ...content_fields}` wird auf einen Padding-Bucket (4 KB oder 64 KB) gepadded und mit `msg_key` via AES-GCM verschlüsselt.
5. Signatur via ECDSA P-256 über `ephemeral_pub || nonce || ciphertext` mit `sender_signing_priv`.
6. Server speichert NUR: `recipient_address, ephemeral_pub, nonce, ciphertext, signature, created_day`. KEINE msg_type/is_contact_request/attachment-Spalten mehr.

Empfänger leitet `shared = ECDH(identity_priv, ephemeral_pub)`, entschlüsselt, entfernt Padding, prüft Signatur mit dem `sender_signing_pub_b64` aus dem Body, **plus Sender-Impersonation-Schutz: `address_from(sender_identity_pub_b64)` muss `sender_address` ergeben** — sonst Reject.

### Padding-Buckets (PFLICHT, Server-validiert)

- **Messages:** Plaintext wird auf 4 KB oder 64 KB gepadded. Server prüft die b64-Länge des Ciphertexts und lehnt nicht-konforme Pakete ab.
- **Attachments:** Plaintext-Datei wird auf 256 KB / 1 MB / 4 MB / 16 MB gepadded (vor AES-GCM). Server prüft die hochgeladene Blob-Größe.

Damit kann der Server nicht mehr aus Paket- oder Datei-Größen auf Inhaltstyp (Text/Bild/Audio/Video) schließen.

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
mnemonic          = BIP39(KEK)   // 24 Wörter Backup
```

Beim Login fragt der Server `argon2id(auth_key)` ab und gibt bei Match `salt`, `encrypted_keys`, `encrypted_kek` zurück. Der Browser leitet PDK und KEK lokal ab, entschlüsselt die Private-Keys, hält sie im RAM.

### Recovery via Mnemonic (Phase 1.6)

Mit den 24 Backup-Wörtern kann der KEK rekonstruiert werden. Ablauf:

1. Client ruft `POST /api/recover/init {address}` → bekommt `keys_blob`, `keys_nonce`, `identity_pub`, `challenge_hex` (5 Min TTL).
2. Client leitet KEK aus Mnemonic ab (BIP39), entschlüsselt damit das `keys_blob` → bekommt `signingPriv`.
3. Client signiert `"lehno-mesh-recovery-v1:" + challenge_hex` mit `signingPriv`.
4. Client leitet aus neuem Passwort frische `auth_key` und `pdk` ab, baut `encrypted_kek` mit dem neuen `pdk` neu.
5. Client ruft `POST /api/recover/finalize {address, challenge_hex, signature_b64, new_auth_key, new_salt, new_kek_blob, new_kek_nonce}`.
6. Server verifiziert die Signatur mit `signing_pub_b64` aus der `users`-Tabelle, updated `auth_hash`, `salt`, `kek_blob`, `kek_nonce` und setzt `jwt_min_iat = now()` — damit sind alle vorher ausgegebenen JWTs sofort ungültig (Schutz gegen geklautes Gerät).

Ohne Mnemonic + ohne Passwort: Account weg.

### Spitznamen-Sync via Encrypted-Userdata (Phase 1.6)

Pro Account speichert der Server EINEN verschlüsselten Blob mit `{contacts, nicknames, declined}`. Schlüssel: `HKDF(KEK, "lehno-mesh-userdata-v1")`. Endpoints:

- `GET /api/userdata` → `{version, nonce_b64, ciphertext_b64}`
- `PUT /api/userdata {nonce_b64, ciphertext_b64, expected_version}` → optimistic concurrency, 409 bei Konflikt.

Damit syncen Spitznamen + Kontakte zwischen Geräten — der Server sieht weder die Adressen noch die Namen.

## Was der Server NICHT sehen kann

- Klartext-Nachrichten (alles E2EE)
- Passwörter (kommen nie zum Server)
- 24-Wort-Backup-Codes (sind clientseitig)
- Sender einer Nachricht (sealed sender)
- Wer mit wem chattet (kein from-Feld, recipient_address steht da aber sagt nichts darüber WER schickt)
- User-Namen (es gibt keine)
- IP-Adressen (werden vor dem Backend gestrippt + Tor versteckt sie netzseitig)

## Was der Server SEHEN kann (Trade-offs)

- Anzahl Pakete pro Empfänger-Adresse (zu welcher Adresse gerade was rein kam)
- Paket-Bucket: 4 KB oder 64 KB Plaintext (1 von 2 Stufen, nicht die exakte Inhalts-Größe)
- Attachment-Bucket: 256 KB / 1 MB / 4 MB / 16 MB (1 von 4 Stufen)
- Tag (nicht Uhrzeit - `created_day` ist Tag-Bucket; bei Online-Empfängern via WebSocket-Push aber Echtzeit)
- Wer mit dem Server verbunden ist via WebSocket (nicht-Tor-User: IP. Tor-User: nur Tor-Exit)
- Wer wessen Public-Keys via `/api/keys` abfragt → Sozialgraph (TOFU-Limit)

## Bekannte Trust-Issues

- **Frontend-Vertrauen:** Wer den Server kontrolliert kann theoretisch ein boeses Frontend pushen das Passwörter mitschickt. Schutz dagegen: Open-Source-Repo + reproducible builds + clientseitige Verifikation. Phase 3.
- **Server-Hoster:** Auf der Clearnet-Strecke sehen Zwischenstellen Verbindungsmetadaten (IP-zu-Server, Zeit, Paketgrößen). Inhalt sehen sie nicht. Wirklich unsichtbar nur über Tor-Browser-Connection zur .onion-Adresse.
- **TOFU bei erstem Kontakt:** Erste Anfrage von einer Adresse hat noch keine Out-of-Band-Verifikation. Phase 2: Fingerprint-Vergleich + QR-Scan.

## Stack

- Backend: Python 3.12 + FastAPI + uvicorn + SQLite (aiosqlite)
- Frontend: Vanilla JS, WebCrypto, BIP39, PWA-Manifest, Service Worker
- Reverse-Proxy: Caddy mit Origin-Cert
- Hidden Service: Tor v3 (`HiddenServiceVersion 3`)
- Hosting: Standard-VPS in der EU

## Lizenz

MIT.

## Status

Phase 1.6 (Mai 2026). Voll funktional für 1:1-Chat, Bilder, Sprachnachrichten, Tor.

Neu in Phase 1.6:
- Zero-Metadata-Sealed-Sender: msg_type / is_contact_request / attachment_token sind komplett aus dem DB-Schema raus und liegen nur noch im verschlüsselten Body
- Padding-Buckets für Messages (4 KB / 64 KB) und Attachments (256 KB / 1 MB / 4 MB / 16 MB) — Server kann nicht mehr aus Größen auf Inhaltstyp schließen
- Mnemonic-Recovery (24-Wort-Code) via signierter Challenge — alte JWTs werden bei Recovery sofort invalidiert
- Sender-Impersonation-Schutz: Empfänger verifiziert dass `address_from(identity_pub) == sender_address` im entschlüsselten Body
- Encrypted Userdata-Blob für Spitznamen + Kontaktliste mit optimistic-concurrency Server-Sync
- Volle Adress-Anzeige (keine Truncation mehr)

HINWEIS für Phase-1.5-Nutzer: das Schema von packets + attachments wurde gewipt. Eure Adresse + Passwort funktionieren weiter, aber alte unzugestellte Nachrichten sind weg. Backup unter `mesh.db.phase15.bak.*`.

Phase 2 (geplant):
- X3DH + Double-Ratchet (volle Forward-Secrecy auch bei Identity-Key-Kompromittierung)
- Gruppen-Chats
- 1:1 + Gruppen Audio/Video-Calls (WebRTC + coturn + LiveKit)
- Native iOS + Android Apps (React Native)
- Push-Notifications (ohne Inhalt-Leak)
- Fingerprint-Verifikation per QR (TOFU-Lösung)
- Conflict-resistente Userdata-Sync (CRDT statt last-writer-wins)

Phase 3 (laenger):
- Reproducible Builds
- Cover-Traffic (alle x Sekunden Dummy-Pakete um Timing-Analyse zu erschweren)
- Mix-Network-Anbindung (SimpleX-Style oder eigene Cascade)
- Native App ohne Browser-Vertrauensproblem
