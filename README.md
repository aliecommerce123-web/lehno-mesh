# chatmesh

Anonymer Messenger als Webseite. Kein Name, keine Nummer, keine E-Mail, keine
Adresse. Nachrichten verschwinden von selbst, wie ein Gespräch im echten Leben.

Der komplette Quelltext liegt in diesem Verzeichnis: Server (`app.py`), App
(`static/`), Verschlüsselung (`static/crypto.js`), Entfernen von Zusatzangaben
aus Medien (`static/media.js`) und der Dienst für Schein-Verkehr (`bots.py`).
Der laufende Server zeigt unter `/beweis` die Prüfsummen genau der Dateien, die
er gerade ausliefert. Mit `verify.py` lässt sich das von außen nachprüfen.

## Die Idee in einfachen Worten

1. **Konto = 12 Wörter.** Es gibt keinen Namen und kein Passwort. Aus den
   12 Anmeldewörtern entstehen im Browser eine Zufallskennung und ein Schlüssel.
   Dazu gibt es 12 Löschwörter: Wer sie bei „Anmelden“ eingibt, löscht alles
   unwiderruflich. Einen eigenen Knopf gibt es dafür nicht. Es öffnet sich ein
   leeres Konto wie bei einer normalen Anmeldung, das alte Konto ist danach
   ebenfalls leer, und die Kanäle verschwinden bei den Gegenübern wie bei
   einem gewöhnlichen Löschen.
2. **Kanal = Einmal-Code.** Wer mit jemandem schreiben will, legt einen Kanal
   an und bekommt einen Einmal-Schlüssel (24 Zeichen oder QR-Code). Das Gegenüber gibt
   ihn ein. Danach ist der Code für alle ungültig. Jeder Kanal hat bei jedem
   der beiden ein eigenes Passwort.
3. **Der Haufen.** Jede Nachricht ist ein namenloser Block fester Größe unter
   einer neuen Zufallsmarke. Alle Blöcke aller Nutzer liegen auf einem
   gemeinsamen Haufen. Jede App lädt den ganzen Haufen und findet ihre Blöcke
   selbst. Der Server bekommt keine Angabe, für wen ein Block ist, und
   speichert nicht, wer ihn löscht.
4. **Verschwinden.** Öffnet das Gegenüber den Chat, wird der Block sofort vom
   Server gelöscht. Die Nachricht ist dann nur noch im Arbeitsspeicher des
   Browsers und verschwindet nach der eingestellten Zeit (Standard 10 Minuten)
   oder sofort, wenn man den Chat verlässt. Das gilt auch für den Absender.
5. **Verlauf behalten** gibt es nur, wenn beide zustimmen. Dann liegt der
   Verlauf verschlüsselt im Konto-Block.
6. **Schein-Verkehr.** Jede offene App und ein eigener Dienst auf dem Server
   legen ständig Blöcke ab und löschen sie wieder, in unregelmäßigen Abständen.
   Ein Schein-Block ist von einem echten nicht zu unterscheiden. Der Dienst
   legt außerdem laufend neue Schein-Konten an und benutzt sie wie ein Mensch.
   Er merkt sich nichts dauerhaft: Es gibt keine Liste, aus der sich ablesen
   ließe, welches Konto ein Schein-Konto ist, auch nicht für den Betreiber.

## Was auf dem Server liegt

Zwei Tabellen in der Hauptdatenbank, eine für Anhänge. Der echte Bauplan steht
unter `/api/proof/schema`.

| Tabelle | Inhalt |
| --- | --- |
| `accounts` | Zufallskennung, Prüfwert des Zugangs, Prüfwert der Löschwörter, zwei verschlüsselte Blöcke in fester Größe, eine zufällige Versionsmarke, Abschnitt von vier Wochen der letzten Speicherung |
| `pile` | Reihenfolge-Nummer, Zufallsmarke, Block in fester Größe (4124 oder 65564 Bytes), Prüfwert des Lösch-Geheimnisses, Kalenderwoche |
| `blobs` | Zufallskennung, verschlüsselter Anhang in fester Größe (256 KB, 1 MB, 4 MB, 16 MB), Kalenderwoche |

Es gibt keine Spalte für Absender, Empfänger, IP-Adresse, Gerät oder Uhrzeit.
Die einzigen Zeitangaben sind grobe Abschnitte, damit Liegengebliebenes
verschwindet: die Kalenderwoche bei Blöcken (weg nach ein bis zwei Wochen) und
Anhängen (weg nach fünf bis sechs), ein Abschnitt von vier Wochen bei Konten
(ein Jahr lang unbenutzte Konten werden entfernt).

## Verschlüsselung

Alles läuft im Browser mit der eingebauten WebCrypto-Schnittstelle. Der Server
bekommt nur Geheimtext.

- **Konto:** 16 Zufallsbytes, dargestellt als 12 Wörter (BIP39-Liste mit
  Prüfsumme). Daraus per HKDF-SHA256: Kennung, Zugang (der Server speichert nur
  dessen SHA-256) und Schlüssel für den Konto-Block (AES-256-GCM).
- **Löschwörter:** weitere 16 Zufallsbytes. Der Server speichert nur den
  Prüfwert. Ein kleiner zweiter Block enthält, verschlüsselt mit einem
  Schlüssel aus den Löschwörtern, was zum Benachrichtigen der Gegenüber nötig
  ist.
- **Einmal-Schlüssel:** 12 Zufallsbytes, gezeigt als 24 Zeichen mit Prüfteil. Daraus entstehen zwei Marken
  und ein Schlüssel. Unter der ersten Marke liegt das verschlüsselte Angebot
  mit einem frischen ECDH-Schlüssel (P-256), unter der zweiten die Antwort.
  Aus ECDH-Geheimnis, Code und beiden öffentlichen Schlüsseln entsteht per
  HKDF die Wurzel des Kanals. Eine Prüf-Zahl (12 Ziffern) zeigt beiden Seiten, dass
  sich niemand dazwischengedrängt hat.
- **Kanal:** Aus der Wurzel entstehen vier Schlüssel: für Marken, Inhalt,
  Löschen und Auflösen. Für jede Nachricht werden daraus per HMAC/HKDF eine
  neue Marke, ein neuer Inhaltsschlüssel und ein neues Lösch-Geheimnis
  gebildet. Zwei Nachrichten desselben Kanals haben für Außenstehende nichts
  gemeinsam.
- **Kanal-Passwort:** Die Schlüssel zum Lesen, Senden, Löschen und Auflösen
  eines Kanals liegen im Konto nur verpackt mit dem Kanal-Passwort
  (PBKDF2-SHA256, 600.000 Runden, AES-GCM). Mit den 12 Anmeldewörtern allein
  lässt sich kein Kanal lesen. Offen liegt nur, was zum Zählen ungelesener
  Blöcke nötig ist.
- **Rechenaufgabe:** Jede Einlieferung bringt eine kleine Rechenaufgabe mit
  (SHA-256 mit führenden Null-Bits). Sie wird schwerer, je voller der Speicher
  ist und je mehr gerade eingeliefert wird. Der Server kennt keine
  IP-Adressen, so schützt er sich trotzdem vor dem Vollmüllen.
- **Nachricht:** JSON, aufgefüllt auf 4096 oder 65536 Bytes, AES-256-GCM.
  Lesebestätigungen, Löschaufträge, Anfragen und Antworten sind Blöcke wie
  alle anderen.
- **Anhänge:** eigener Zufallsschlüssel je Datei, aufgefüllt auf eine von vier
  Größen. Der Schlüssel steht nur in der verschlüsselten Nachricht.
- **Zusatzangaben in Medien:** Bilder werden vor dem Verschlüsseln neu
  gezeichnet (Ort, Gerät, Aufnahmezeit gehen verloren). In MP4/MOV und WebM
  werden die Bereiche mit Zusatzangaben genullt und Zeitangaben entfernt.
  Gewöhnliche Dateien (zum Beispiel PDF) werden unverändert übertragen.

## Gleichförmigkeit

- Einliefern und Löschen eines Blocks sehen gleich aus: gleiche Länge der
  Anfrage, immer Status 200, gleiche Länge und Mindestdauer der Antwort.
- Abrufe des Haufens, Schein-Blöcke und das Speichern des Kontos laufen in
  zufälligen Abständen, mit und ohne Anlass.
- Der Server setzt keine Cookies, schreibt kein Zugriffsprotokoll und liest
  keine IP-Adresse oder Gerätekennung.
- Im Browser liegt nur die Anmeldung, verschlossen mit dem eigenen Code des
  Nutzers, und nur im Speicher dieses einen Fensters: Nach dem Neu-Laden der
  Seite genügt der Code. Fenster zu oder abgemeldet, und sie ist weg.
- Die App beobachtet weder Maus noch Tastatur, um Untätigkeit zu erkennen.

## Was der Server nicht kann

- Nachrichten, Anhänge, Kanal-Namen oder Verläufe lesen.
- Aus dem, was er speichert, ablesen, wer mit wem schreibt.
- Echte Blöcke von Schein-Blöcken unterscheiden.
- Ein Konto wiederherstellen. Wer die Wörter verliert, verliert das Konto.

## Ehrliche Grenzen

- Die App kommt als Webseite vom Server. Wer dem Server nicht traut, vergleicht
  die Prüfsummen unter `/beweis` mit diesem Verzeichnis.
- Im normalen Internet sehen Netzanbieter und vorgeschaltete Netzdienste die
  IP-Adresse (nicht den Inhalt). Über den Tor-Browser und die Onion-Adresse
  entfällt das.
- Das Verschwinden von Nachrichten setzt die App des Gegenübers um. Eine
  veränderte App könnte Inhalte behalten.
- Screenshots: Am Rechner blendet die App den Inhalt aus, sobald das Fenster
  nicht vorne ist, und löst den Kanal auf, wenn sie einen Versuch erkennt
  (bestimmte Tasten, Drucken). Sicher verhindern kann eine Webseite
  Bildschirmfotos nicht, am Handy lässt sich ein Screenshot nicht erkennen, und
  niemand kann das Abfotografieren eines Bildschirms verhindern.
- Wer den Datenverkehr über lange Zeit beobachtet, sieht, wann ein Gerät mit
  chatmesh verbunden ist. Große Anhänge fallen als größere Übertragung auf.
- Jede App lädt den ganzen Haufen. Das kostet Datenvolumen.

## Schutz des Servers

Feste Größen für alles, Obergrenzen für den gesamten Speicher, Begrenzung
gleichzeitiger großer Anfragen, Mengenbegrenzung im Arbeitsspeicher (ohne IP),
strenge Inhalts-Sicherheitsrichtlinie ohne fremde Quellen, Selbstprüfung der
eigenen Dateien beim Start (`EXPECTED_HASHES.json`).

## Technik

Python (FastAPI, SQLite), im Browser reines JavaScript ohne Rahmenwerk.
Mitgelieferte Bausteine: `static/vendor/qrcode.js` (QR-Code erzeugen,
MIT-Lizenz) und `static/vendor/jsqr.js` (QR-Code lesen, Apache-Lizenz 2.0).

## Von außen prüfen

Jeder kann kontrollieren, ob ein Server genau diesen Quelltext ausliefert:

```
python3 verify.py https://mesh.lehno.de
```

Das Programm lädt alle Dateien, die der Server benutzt und an Browser
ausliefert, und vergleicht sie mit dem öffentlichen Stand. Es braucht nur
Python.

Der Server zeigt und zählt bewusst keine Mengen: nicht, wie viele Konten es
gibt, nicht, wie viele Blöcke oder Anhänge. Die Seite `/beweis` zeigt nur
Speicherformat, Quelltext und Prüfsummen.

## Selbst betreiben und prüfen

```
pip install fastapi uvicorn aiosqlite python-multipart httpx
python3 scripts/update_hashes.py
LEHNO_MESH_ALLOW_LOCAL=1 uvicorn app:app --port 8000 --no-access-log --no-server-header --no-date-header
python3 bots.py
```

## Lizenz

Siehe `LICENSE`.
