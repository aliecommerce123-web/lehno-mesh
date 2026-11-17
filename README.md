# chatmesh

Anonymer, Ende-zu-Ende verschlüsselter Messenger. Offener Quelltext von A bis Z: Server, App und Verschlüsselung liegen vollständig in diesem Verzeichnis.

Erreichbar unter:
- `https://mesh.lehno.de` (normaler Browser)
- `http://35m6ezqw2ugdqnsqhpxe4ccpnzvesfj24ile3xswvt4s5n6fyy5xfqqd.onion` (Tor Hidden Service, verbirgt zusätzlich die IP-Adresse gegenüber dem Netz)

Unter beiden Adressen läuft dieselbe App. Der Server liest und speichert in keinem Fall eine IP-Adresse, eine Browser- oder Gerätekennung oder eine Uhrzeit.

**Öffentlicher Beweis:** `/beweis` zeigt, was der laufende Server speichert: Bestand als Summen (Momentaufnahme alle 10 Minuten, damit niemand ablesen kann, wann ein Konto online ist), das Speicherformat und den laufenden Quelltext mit Prüfsummen. Jede Nachricht hat eine Beweis-Kennung, mit der ihr Absender nachsehen kann, was der Server zu ihr gespeichert hat und dass sie nach der Zustellung gelöscht ist. Eine Liste der Kennungen gibt es nicht.

## Was es ist

Ein selbstgehostetes Messaging, das so wenig wie möglich über seine Nutzer weiß.

- **Keine Benutzernamen.** Jedes Konto hat eine kryptografische Adresse, die aus dem öffentlichen Schlüssel berechnet wird (`mesh:Base58...`). Man teilt sie wie eine Wallet-Adresse.
- **Der Server kennt den Absender nicht.** Ein Paket enthält außen nur die Empfängeradresse und Geheimtext in Einheitsgröße. Eingeliefert wird ohne Konto-Token. Wer geschrieben hat, steht nur im verschlüsselten Teil.
- **Absender nicht fälschbar.** Der Empfänger prüft kryptografisch, dass die Nachricht wirklich vom Inhaber der Absenderadresse stammt.
- **Keine Nutzerliste.** Keine Suche, kein Verzeichnis. Wer dich erreichen will, braucht deine Adresse direkt von dir.
- **Anfragen.** Die erste Nachricht einer unbekannten Adresse erscheint als Anfrage, die man annimmt oder ablehnt. Solange eine Adresse kein Kontakt ist, nimmt der Verlauf von ihr höchstens 20 gekürzte Nachrichten auf und lädt Medien erst nach Klick. So kann niemand mit Massenanfragen echte Nachrichten verdrängen.
- **Vollständiger Verlauf, nur für dich lesbar.** Der Chat-Verlauf (gesendet und empfangen, in fester Reihenfolge) liegt als ein verschlüsselter Block je Konto auf dem Server. Der Schlüssel entsteht nur im Browser. So ist der Verlauf auf jedem Gerät und nach dem Schließen des Tor-Browsers wieder da.
- **Zustellung ohne Verlust.** Ein Paket wird erst vom Server gelöscht, wenn die Nachricht sicher im verschlüsselten Verlauf des Empfängers liegt. Nicht abgeholte Pakete verfallen nach 5 bis 6 Wochen.
- **Regeln je Chat.** Jeder legt für SEINE Nachrichten in einem Chat fest: Löschfrist (nach X Minuten bei beiden weg, egal ob gelesen) und Einmal-Ansicht (nach dem Verlassen des Chats weg). Jeder kann außerdem jede Nachricht eines Chats bei beiden löschen. Gelöschtes verschwindet spurlos, ohne Hinweis.
- **Alles verschlüsselt.** Text, Bilder, Videos, Sprachnachrichten und beliebige Dateien (PDF usw.), dazu Dateiname, Art und Größe.
- **Tarnverkehr.** Die App sendet in gleichmäßigem Takt gleich große Pakete, egal ob jemand schreibt. Anfragen und Antworten haben feste Größen und feste Mindestdauer. Das macht es im Netz dazwischen sehr schwer zu erkennen, ob oder wann jemand etwas sendet. Anhänge, sehr lange Texte und das Sichern des Verlaufs sind als größere Übertragungen sichtbar (deshalb sichert die App auch in zufälligen Takten ohne Anlass).
- **Keine Zeitangaben.** Nachrichten tragen weder Uhrzeit noch Datum, und die Anzeige zeigt nur die Reihenfolge. Einzige Ausnahme: Wer eine Löschfrist setzt, dessen Nachricht trägt den Löschzeitpunkt, verschlüsselt. Der Server merkt sich allein für das Aufräumen die Kalenderwoche wartender Pakete und Anhänge, dazu für 5 Minuten den Ablauf einer laufenden Konto-Wiederherstellung. Konten, Verläufe und Kontaktlisten tragen keine Zeitangabe.
- **Nichts auf dem Gerät.** Nach dem Abmelden bleibt im Browser nichts gespeichert. Nur wer „Adresse merken“ anhakt, speichert seine Adresse.
- **Keine Admin-Macht in der Schnittstelle.** Kein Sperren, kein Auflisten, kein Mitlesen.
- **Keine Protokolle.** Zugriffs- und Verbindungsprotokolle sind abgeschaltet.

## Krypto

Alle Krypto-Operationen laufen im Browser über die WebCrypto-API. Der Server kennt keinen privaten Schlüssel.

| Zweck | Verfahren |
|---|---|
| Identitätsschlüssel (Schlüsseltausch, Absender-Nachweis) | ECDH P-256 |
| Signaturschlüssel (nur für die Wiederherstellung) | ECDSA P-256 (SHA-256) |
| Symmetrische Verschlüsselung | AES-256-GCM, 96-Bit-IV |
| Schlüssel aus Passwort | PBKDF2-SHA256, 1.200.000 Runden, danach HKDF in zwei unabhängige Schlüssel |
| Gemeinsames Geheimnis zu Nachrichtenschlüssel | HKDF-SHA256, gebunden an Einmal- und Empfängerschlüssel |
| Absender-Nachweis | HMAC-SHA256 mit Schlüssel aus ECDH der beiden Identitätsschlüssel |
| Prüfung der Anmeldung am Server | Argon2id (t=3, m=64 MB, p=2) |
| Adresse | base58(sha256(identity_pub)[:24]) |
| Backup-Code | BIP39 Englisch, 24 Wörter |

### Nachricht (Phase 1.8)

1. Absender erzeugt ein Einmal-Schlüsselpaar `E`.
2. `shared = ECDH(E_priv, empfänger_identity_pub)`
3. `msg_key = HKDF(shared, "lehno-mesh-msg-v2|" || E_pub || empfänger_identity_pub)`
4. `auth = HMAC(HKDF(ECDH(absender_identity_priv, empfänger_identity_pub), "lehno-mesh-sender-auth-v2"), E_pub || absender_identity_pub || empfänger_identity_pub)`
5. Inhalt als JSON `{v, msg_id, sender_address, sender_identity_pub_b64, sender_auth_b64, msg_type, ...}` (ohne Zeitangabe) wird auf 4 KB oder 64 KB aufgefüllt und mit `msg_key` verschlüsselt.
6. Der Server speichert nur: Empfängeradresse, `E_pub`, Nonce, Geheimtext, Kalenderwoche der Annahme, zufälliges Bestätigungs-Token.

Der Empfänger entschlüsselt, prüft `address_from(sender_identity_pub) == sender_address` und rechnet den Absender-Nachweis mit seinem eigenen privaten Identitätsschlüssel nach. Ein Dritter kann den Nachweis nicht berechnen. Bewusst gibt es keine Unterschrift außen am Paket: Der Server kennt alle öffentlichen Signaturschlüssel und könnte sonst durch Ausprobieren den Absender finden.

Vor dem Verschlüsseln prüft der Absender, dass der vom Server gelieferte Schlüssel des Empfängers wirklich zu dessen Adresse gehört. Ein Server kann keinen fremden Schlüssel unterschieben.

### Einheitsgrößen (vom Server erzwungen)

- **Nachrichten:** 4 KB oder 64 KB.
- **Anhänge:** 256 KB, 1 MB, 4 MB oder 16 MB.
- **Kontaktablage:** 2 KB, 8 KB, 32 KB oder 128 KB.
- **Verlaufsablage:** 64 KB, 256 KB, 1 MB oder 4 MB.

Aus Größen lässt sich weder die Art des Inhalts noch die Zahl der Kontakte oder Nachrichten ablesen.

### Konto

```
salt             = random(16 Bytes)
master           = PBKDF2(passwort, salt, 1.200.000, 32 Bytes)
auth_key         = HKDF(master, "lehno-mesh-auth-v2")     -> geht an den Server, dort Argon2id
PDK              = HKDF(master, "lehno-mesh-pdk-v2")      -> bleibt im Browser
identity_keypair = ECDH P-256
signing_keypair  = ECDSA P-256
KEK              = random(32 Bytes)
encrypted_keys   = AES-GCM(JSON(identity_priv, signing_priv), KEK)
encrypted_kek    = AES-GCM(KEK, PDK)
address          = "mesh:" + base58(sha256(identity_pub_raw)[:24])
mnemonic         = BIP39(KEK)   // 24 Wörter
```

Konten aus der Zeit vor Phase 1.8 nutzen das alte Verfahren (ein PBKDF2-Lauf mit 600.000 Runden und 64 Bytes Ausgabe) weiter, bis sie einmal über die 24 Wörter wiederhergestellt werden. Der Browser berechnet die eigenen öffentlichen Schlüssel aus dem entschlüsselten Bündel selbst und prüft, dass sie zur Adresse passen.

### Wiederherstellung mit den 24 Wörtern

1. `POST /api/recover/init {address}` liefert `keys_blob`, `keys_nonce`, `challenge_hex` (5 Minuten gültig). Für unbekannte Adressen kommt eine gleich aussehende Attrappe.
2. Der Browser leitet den KEK aus den 24 Wörtern ab, entschlüsselt das Bündel, prüft die Adresse und signiert `"lehno-mesh-recovery-v1:" + challenge_hex`.
3. `POST /api/recover/finalize` setzt neues Passwort-Material. Alle bisher ausgegebenen Sitzungs-Token werden sofort ungültig, offene Verbindungen getrennt.

Ohne Passwort und ohne die 24 Wörter ist das Konto verloren.

### Verschlüsselte Ablagen

Je Konto zwei Blöcke, Schlüssel jeweils per HKDF aus dem KEK:
- `userdata`: Kontakte, Spitznamen, abgelehnte Adressen (`/api/userdata`)
- `history`: kompletter Chat-Verlauf samt gemerkter Kennungen gelöschter Nachrichten (`/api/history`)

Geschrieben wird nur, wenn der Client den aktuellen Stand kennt (sonst Konflikt, dann zusammenführen). Die Versionsmarke ist eine Zufallszahl, kein Zähler.

## Was auf dem Server liegt

- je Konto: Adresse, öffentliche Schlüssel, Salz, Argon2id-Hash des `auth_key`, die mit KEK bzw. Passwort verschlüsselten Schlüsselblöcke (keine Zeitangabe)
- wartende Pakete: Empfängeradresse, Einmalschlüssel, Nonce, Geheimtext, Kalenderwoche
- Anhänge: Geheimtext-Blöcke unter zufälligem Token, ohne Besitzer, in einer Datenbank (keine einzelnen Dateien, also keine Datei-Zeitstempel), 5 bis 6 Wochen
- die zwei verschlüsselten Ablagen je Konto

## Was der Server nicht kann

- Nachrichten, Bilder, Kontakte, Spitznamen oder Verlauf lesen
- Passwörter oder Backup-Wörter sehen
- aus gespeicherten Daten ablesen, wer wem geschrieben hat
- einen falschen Empfängerschlüssel unterschieben oder Nachrichten fälschen

## Was der Server sehen kann (ehrliche Grenzen)

- wie viele Pakete für eine Adresse warten und in welcher Kalenderwoche sie ankamen (kein Tag, keine Uhrzeit)
- die Größenstufe von Paketen, Anhängen und Ablagen
- wann ein Konto angemeldet ist und Pakete abholt (im laufenden Betrieb, nichts davon wird gespeichert)
- ein absichtlich veränderter Server könnte Verbindungen zeitlich zuordnen (wer liefert gerade ein, wer wird gerade benachrichtigt). Dagegen hilft nur Deckverkehr, siehe Ausblick.
- im normalen Browser sehen der Internetanbieter und vorgeschaltete Netzdienste, dass ein Gerät mit chatmesh verbunden ist (IP-Adresse der Verbindung). Was, an wen und dank Tarnverkehr auch ob und wann geschrieben wird, sehen sie nicht. Der chatmesh-Server selbst bekommt die IP-Adresse nicht zu sehen. Wer auch die Verbindung selbst verbergen will, nutzt die Onion-Adresse.
- größere Anhänge fallen im Netz als größere Übertragung auf (Inhalt bleibt unlesbar).

## Bekannte Grenzen

- **Vertrauen in den ausgelieferten Code:** Die App kommt als Webseite vom Server. Wer den Server kontrolliert, könnte künftig veränderten Code ausliefern, der Passwörter abgreift. Gespeicherte Daten lassen sich damit nicht nachträglich öffnen, aber neue Anmeldungen wären betroffen. Schutz: offener Quelltext, Hash-Prüfung beim Start, langfristig eine eigenständige App.
- **Passwortstärke:** Der Server hält den mit dem Passwort verschlüsselten KEK. Ein schwaches Passwort kann von jemandem mit Zugriff auf die Datenbank durch Ausprobieren gefunden werden. Mindestlänge ist 10 Zeichen, mehrere Wörter sind besser.
- **Keine nachträgliche Sicherheit bei Schlüsselverlust:** Wird der private Identitätsschlüssel eines Kontos bekannt, lassen sich mitgeschnittene alte Pakete an dieses Konto öffnen (kein Double Ratchet).
- **Löschen bei beiden braucht das Gegenüber:** Lösch-Aufträge und Fristen setzt die App des Gegenübers um. Eine unveränderte App tut das immer. Wer die App absichtlich umbaut oder vorher abfotografiert, kann Inhalte behalten, das kann kein Messenger verhindern.
- **Medien einige Wochen:** Bilder und Videos werden nach 5 bis 6 Wochen vom Server gelöscht (bei vollem Speicher früher) und sind danach im Verlauf nicht mehr abrufbar.
- **Verfügbarkeit:** Mengen- und Platzgrenzen schützen die Maschine, ein entschlossener Angreifer kann den Dienst aber zeitweise ausbremsen. Wer eine Adresse kennt und ununterbrochen falsche Anmeldungen schickt, kann die Anmeldung für diese Adresse in der Zeit behindern.

## Schutz des Servers

- App und Schnittstelle nur unter genau den zwei eigenen Namen (Onion-Adresse und mesh.lehno.de)
- feste Längen für alle Felder, unbekannte Felder werden abgelehnt
- Mengenbegrenzung, Begrenzung gleichzeitiger großer Anfragen, Platzgrenzen für Datenbank und Anhänge, Mindestfreiraum der Platte
- Bremse nach Fehlanmeldungen (ein Versuch alle 3 Sekunden je Adresse, keine Dauersperre)
- Anhänge werden in Stücken ausgeliefert, nicht abgeholte Downloads binden keinen Arbeitsspeicher
- eigene Speichertöpfe für wartende Pakete, Verläufe und Anhänge; ist der Anhang-Topf voll, weichen die ältesten Anhänge von vor heute
- strenge Content-Security-Policy, keine Inline-Skripte, Formulare können nirgendwohin senden
- SQLite mit sicherem Löschen

## Technik

- Server: Python mit FastAPI und SQLite
- App: reines JavaScript mit der WebCrypto-Schnittstelle des Browsers, BIP39
- Zugang über Tor (Hidden Service) und über eine vorgeschaltete Schleuse im normalen Netz (ohne Protokoll, IP- und Geräte-Angaben werden vor der App entfernt)

## Selbst betreiben und prüfen

Nach jeder Änderung an `app.py` oder `static/` muss `scripts/update_hashes.py` laufen. Der Server startet nur, wenn die Prüfsummen in `EXPECTED_HASHES.json` zu den Dateien passen. Für einen lokalen Test die Umgebungsvariable `LEHNO_MESH_ALLOW_LOCAL=1` setzen.

## Lizenz

MIT.

## Stand

Phase 1.9 (November 2026): 1:1-Chat mit Text, Bildern, Videos, Sprachnachrichten und Dateien, im normalen Browser und über Tor.

Neu in Phase 1.9:
- Regeln je Chat (Löschfrist, Einmal-Ansicht), Löschen bei beiden, spurlos
- Sprachnachrichten und beliebige Dateien
- Tarnverkehr und aufgefüllte Postfach-Antworten
- öffentlicher Beweis-Bereich (`/beweis`, `/api/proof/*`) mit Beweis-Kennung je Nachricht
- neues Aussehen, neuer Name chatmesh

Neu in Phase 1.8:
- vollständiger, verschlüsselter Chat-Verlauf in richtiger Reihenfolge, auf jedem Gerät, ohne jede Zeitangabe
- Live-Zustellung repariert, zusätzlich regelmäßiger Abruf
- Absender-Nachweis (vorher konnte sich ein Dritter als fremde Adresse ausgeben)
- keine Unterschrift mehr außen am Paket, Einliefern und Anhänge ohne Konto-Token
- Prüfung des Empfängerschlüssels gegen die Adresse
- Sicherheits-Header, Mengen- und Platzgrenzen
- zufällige Paket-Kennungen und Versionsmarken, Anhänge ohne Datei-Zeitstempel
- nichts Lesbares mehr im Browser-Speicher, Konto löschen in der Oberfläche

Hinweis für bestehende Konten: Adresse und Passwort funktionieren weiter. Nachrichten, die beim Update noch auf dem Server warteten, bleiben lesbar und sind als „Absender nicht geprüft“ markiert. Offene Tabs der alten Fassung müssen neu geladen werden.

Ausblick:
- X3DH und Double Ratchet
- Gruppen-Chats
- Vergleich von Sicherheitsnummern per QR
- Deckverkehr gegen Zeit-Zuordnung
- eigenständige App ohne Vertrauen in ausgelieferten Web-Code
