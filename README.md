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
   ebenfalls leer, und die Chat-Kanäle verschwinden bei den Gegenübern wie bei
   einem gewöhnlichen Löschen.
2. **Chat-Kanal = Einmal-Code.** Wer mit jemandem schreiben will, legt einen Chat-Kanal
   an und bekommt einen Einmal-Schlüssel (24 Zeichen oder QR-Code). Das Gegenüber gibt
   ihn ein. Danach ist der Code für alle ungültig. Jeder der beiden kann dem
   Chat-Kanal für sich ein eigenes Passwort geben. Das ist freiwillig und lässt
   sich später festlegen, ändern oder entfernen.
3. **Das Verzeichnis.** Jede Nachricht ist ein namenloser Block fester Größe
   unter einer neuen Zufallsmarke (16 Bytes), die nur die beiden Geräte des
   Chat-Kanals ausrechnen können. Der Server führt ein Verzeichnis, das zu
   jedem Block nur die ersten 5 Bytes seiner Marke nennt. Jede App lädt
   dasselbe Verzeichnis und erkennt selbst, ob etwas für sie da ist. So
   erfährt der Server nicht, worauf eine App wartet. Den Block selbst gibt er
   nur gegen die volle Marke heraus: Fremde Blöcke kann niemand herunterladen.
   Der Server bekommt keine Angabe, für wen ein Block ist, und speichert
   nicht, wer ihn abholt oder löscht.
4. **Verschwinden.** Hat das Gegenüber eine Nachricht geöffnet, wird der Block
   wenige Sekunden später vom Server gelöscht. Die Nachricht ist dann nur noch
   im Arbeitsspeicher des Browsers und verschwindet nach der eingestellten
   Zeit (Standard 10 Minuten) oder sofort, wenn man den Chat verlässt. Das
   gilt auch für den Absender.
5. **Verlauf behalten** gibt es nur, wenn beide zustimmen. Dann liegt der
   Verlauf verschlüsselt im Konto-Block.
6. **Fester Takt.** Solange man angemeldet ist, schickt die App in
   gleichmäßigen Zufallsabständen (0,75 bis 2,15 Sekunden) einen Umschlag
   immer gleicher Größe, einen "Schlag". Ein Schlag trägt höchstens einen
   Vorgang: einen kleinen Block ablegen, abholen oder löschen. Gibt es nichts
   zu tun, geht er leer hinaus. Auch das Verzeichnis, ein kleiner Zusatz-Block
   und das Speichern des Kontos laufen in eigenen festen Zufallsabständen, mit
   und ohne Anlass. Wer nur die Leitung sieht, erkennt deshalb nicht, ob
   gerade geschrieben wird oder mit wem. Weil nie zwei Vorgänge im selben
   Schlag stecken, sieht auch der Server nicht, welche Vorgänge vom selben
   Gerät kommen. Der Preis: Echte Vorgänge warten auf den nächsten Schlag.
   Eine Nachricht braucht meist 2 bis 5 Sekunden, viele Nachrichten in
   schneller Folge gehen mit etwa einer je anderthalb Sekunden hinaus, und
   die offene App verbraucht laufend Daten (rund 30 MB je Stunde).
   Ein eigener Dienst auf dem Server legt außerdem laufend Schein-Blöcke und
   Schein-Konten an und benutzt sie im selben Takt wie eine App. Er merkt sich
   nichts dauerhaft: Es gibt keine Liste, aus der sich ablesen ließe, welches
   Konto ein Schein-Konto ist, auch nicht für den Betreiber.
7. **Versiegelter Umschlag.** Die App schickt jede Anfrage verschlossen an
   einen einzigen Eingang. Öffnen kann sie nur der Server. Wer zwischen App
   und Server sitzt (Netzanbieter, vorgeschaltete Netzdienste), sieht, von
   welchem Anschluss ein Umschlag kommt, aber nicht, was darin steht: nicht,
   ob etwas abgelegt, abgeholt oder gelöscht wird, keine Marke, keine
   Konto-Kennung. Wer unterwegs die IP-Adresse sieht, kann den Umschlag nicht
   öffnen. Der Server öffnet ihn, liest aber keine IP-Adresse.

## Was auf dem Server liegt

Zwei Tabellen in der Hauptdatenbank, eine für Anhänge. Der echte Bauplan steht
unter `/api/proof/schema`.

| Tabelle | Inhalt |
| --- | --- |
| `accounts` | Zufallskennung, Prüfwert des Zugangs, Prüfwert der Löschwörter, zwei verschlüsselte Blöcke in fester Größe, eine zufällige Versionsmarke, ein kleiner verschlüsselter Zusatz-Block fester Größe mit eigener Versionsmarke, Abschnitt von vier Wochen der letzten Speicherung |
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
  HKDF die Wurzel des Chat-Kanals. Eine Prüf-Zahl (18 Ziffern) zeigt beiden Seiten, dass
  sich niemand dazwischengedrängt hat.
- **Chat-Kanal:** Aus der Wurzel entstehen vier Schlüssel: für Marken, Inhalt,
  Löschen und Auflösen. Für jede Nachricht werden daraus per HMAC/HKDF eine
  neue Marke, ein neuer Inhaltsschlüssel und ein neues Lösch-Geheimnis
  gebildet. Zwei Nachrichten desselben Chat-Kanals haben für Außenstehende nichts
  gemeinsam.
- **Chat-Kanal-Passwort (freiwillig):** Die Schlüssel zum Lesen, Senden, Löschen
  und Auflösen eines Chat-Kanals liegen im Konto nur in einem verschlossenen
  Päckchen. Offen liegt nur, was zum Zählen ungelesener Blöcke nötig ist.
  Mit Passwort: Das Päckchen ist mit dem Chat-Kanal-Passwort verschlossen
  (PBKDF2-SHA256, 600.000 Runden, AES-GCM). Die 12 Anmeldewörter allein
  genügen dann nicht, um den Chat-Kanal zu lesen.
  Ohne Passwort: Ein Zufalls-Schlüssel verschließt das Päckchen. Er liegt im
  verschlüsselten Konto, die 12 Anmeldewörter genügen dann zum Öffnen.
  Ein später festgelegtes Passwort schützt ab diesem Zeitpunkt, nicht
  rückwirkend.
- **Versiegelter Umschlag:** Für jede Anfrage erzeugt die App einen neuen
  kurzlebigen ECDH-Schlüssel (P-256). Aus dem gemeinsamen Geheimnis mit dem
  öffentlichen Schlüssel des Eingangs entstehen per HKDF-SHA256 zwei
  Schlüssel (AES-256-GCM): einer für die Anfrage, einer für die Antwort. Der
  öffentliche Schlüssel steht in den öffentlichen Einstellungen. Der geheime
  liegt nur im Arbeitsspeicher des Servers, in keiner Datei, und wird alle
  zehn Minuten ersetzt: Wer später den Server bekommt, kann früher
  mitgeschnittene Umschläge nicht mehr öffnen. Ein mitgeschnittener Umschlag
  lässt sich auch nicht ein zweites Mal einspielen. Anfragen und
  Antworten werden auf feste Größen aufgefüllt. Ablegen, Abholen und Löschen
  eines kleinen Blocks sind in beiden Richtungen gleich groß.
- **Rechenaufgabe:** Jede Einlieferung bringt eine kleine Rechenaufgabe mit
  (SHA-256 mit führenden Null-Bits). Sie wird schwerer, je voller der Speicher
  ist und je mehr gerade eingeliefert wird. Der Server kennt keine
  IP-Adressen, so schützt er sich trotzdem vor dem Vollmüllen.
- **Schlüssel-Kette:** Für jede Richtung gibt es eine Kette. Aus dem aktuellen
  Ketten-Schlüssel entstehen der Schlüssel für genau eine Nachricht und der
  nächste Ketten-Schlüssel (HKDF), der alte wird überschrieben. Der
  Ausgangs-Schlüssel wird nicht aufbewahrt. Wer später den Stand eines Geräts
  bekommt, kann frühere Nachrichten nicht mehr öffnen. Der Stand liegt im
  Konto nur im Päckchen, das das Chat-Kanal-Passwort oder, ohne Passwort, der
  Zufalls-Schlüssel verschließt.
- **Zwei Löschzeiten:** Nach dem Öffnen bleibt eine Nachricht eine einstellbare
  Zeit sichtbar. Zusätzlich lässt sich einstellen, nach welcher Zeit eine
  ungeöffnete Nachricht gelöscht wird: Die Frist steht verschlüsselt in der
  Nachricht, und der Absender entfernt den Block nach Ablauf vom Server.
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

- Einliefern, Abholen und Löschen eines kleinen Blocks reisen alle als
  Schlag: gleiche Größe der Anfrage und der Antwort, immer derselbe Eingang,
  immer Status 200, gleiche Mindestdauer, gleicher Takt mit und ohne Inhalt.
- Der Taktgeber läuft in einem eigenen Arbeiter des Browsers, damit der Takt
  derselbe bleibt, wenn das Fenster im Hintergrund liegt.
- Abrufe des Verzeichnisses und das Speichern des Kontos laufen in eigenen
  festen Zufallsabständen, mit und ohne Anlass. Wie oft das Konto gespeichert
  wird, hängt nur von seiner Größe ab.
- Vor dem Senden muss eine Nummer reserviert sein. Dafür gibt es je Konto einen
  kleinen verschlüsselten Zusatz-Block fester Größe, der alle zwei bis fünf
  Sekunden geschrieben wird, mit und ohne Anlass. So muss nie eigens das Konto
  gespeichert werden, und zwei Geräte bekommen nie dieselben Nummern.
- Lesebestätigungen werden kurz gesammelt und gebündelt gesendet. Gelesene
  Blöcke werden einzeln und zufällig versetzt entfernt.
- Ein eben eingetroffener Anhang wird erst nach einer kurzen Zufallszeit
  geladen.
- Der Server setzt keine Cookies, schreibt kein Zugriffsprotokoll und liest
  keine IP-Adresse oder Gerätekennung.
- Im Browser liegt nur die Anmeldung, verschlossen mit dem eigenen Code des
  Nutzers, und nur im Speicher dieses einen Fensters: Nach dem Neu-Laden der
  Seite genügt der Code. Fenster zu oder abgemeldet, und sie ist weg. Wer es
  in den Einstellungen einschaltet, bleibt auf diesem Gerät angemeldet: Dann
  liegt dieselbe verschlossene Anmeldung zusätzlich im dauerhaften Speicher
  des Browsers, bis man sich abmeldet. Wer das Gerät in die Hände bekommt,
  könnte dann den Code durchprobieren; deshalb ist das aus, solange man es
  nicht selbst einschaltet.
- Die App beobachtet weder Maus noch Tastatur, um Untätigkeit zu erkennen.

## Was der Server nicht kann

- Nachrichten, Anhänge, Chat-Kanal-Namen oder Verläufe lesen.
- Aus dem, was er speichert, ablesen, wer mit wem schreibt.
- Echte Blöcke von Schein-Blöcken unterscheiden.
- Ein Konto wiederherstellen. Wer die Wörter verliert, verliert das Konto.

## Ehrliche Grenzen

- Die App kommt als Webseite vom Server. Wer dem Server nicht traut, vergleicht
  die Prüfsummen unter `/beweis` mit diesem Verzeichnis.
- Im normalen Internet sehen Netzanbieter und vorgeschaltete Netzdienste die
  IP-Adresse, dazu Zeitpunkt und Größe jedes Umschlags, aber nicht den
  Inhalt. Große Blöcke, Anhänge und das Speichern großer Konten haben andere
  Größen und fallen auf. Mit dem Tor-Browser und der Onion-Adresse sieht der
  Netzanbieter nur, dass Tor genutzt wird, und niemand sieht die IP-Adresse.
- Der versiegelte Umschlag schützt vor dem Mitlesen. Wer zwischen App und
  Server aktiv eingreift, könnte den Schlüssel des Eingangs austauschen oder
  die App verändern und dann mitlesen. Das Prüf-Programm erkennt nur eine
  veränderte App. Sicher schützt die Onion-Adresse.
- Außerhalb des Takts bleiben sichtbar: wann ein Anschluss verbunden ist,
  das Anmelden, seltene Schritte wie Einstellungen speichern, Anhänge und
  sehr lange Nachrichten (eigene Größen) und ein zweites Gerät am selben
  Konto (zusätzliche Abrufe).
- Friert ein Handy die Seite im Hintergrund ganz ein, sieht es von außen aus,
  als wäre der Anschluss nicht verbunden. Nachrichten kommen dann erst an,
  wenn die Seite wieder geöffnet wird.
- Für ältere, noch offene Fenster nimmt der Server Anfragen übergangsweise
  auch ohne Umschlag an. Die aktuelle App lädt nur die Seite selbst und den
  öffentlichen Schlüssel des Eingangs ohne Umschlag, alles andere mit.
- Das Verschwinden von Nachrichten setzt die App des Gegenübers um. Eine
  veränderte App könnte Inhalte behalten.
- Die Frist für ungeöffnete Nachrichten löscht der Absender selbst vom
  Server, sobald er angemeldet ist. Ist er es bei Ablauf nicht, zeigt die App
  des Gegenübers die Nachricht trotzdem nicht mehr an.
- Screenshots: Am Rechner blendet die App den Inhalt aus, sobald das Fenster
  nicht vorne ist, und löst den Chat-Kanal auf, wenn sie einen Versuch erkennt
  (bestimmte Tasten, Drucken). Sicher verhindern kann eine Webseite
  Bildschirmfotos nicht, am Handy lässt sich ein Screenshot nicht erkennen, und
  niemand kann das Abfotografieren eines Bildschirms verhindern.
- Wer den Datenverkehr über lange Zeit beobachtet, sieht, wann ein Gerät mit
  chatmesh verbunden ist. Große Anhänge fallen als größere Übertragung auf.
- Holt eine App einen Block ab, sieht der Server, dass genau dieser Block
  abgeholt wurde, aber nicht von wem: Er liest keine IP-Adresse und es gibt
  dabei keine Anmeldung. Wer davor am Netz die IP-Adressen sieht, kann wegen
  des versiegelten Umschlags nicht erkennen, welcher Block es war oder ob
  überhaupt etwas abgeholt wurde.
- Der Server selbst sieht die echten Vorgänge (Block abgelegt, abgeholt,
  gelöscht), aber nicht von wem. Eine Kennung für den Chat-Kanal gibt es
  nirgends, jede Nachricht hat eine neue Marke. Aus dem zeitlichen Ablauf
  könnte ein Server, der mitschreibt, bei wenig Betrieb trotzdem vermuten,
  welche Blöcke zu einem Gespräch gehören. Deshalb laufen ständig
  Schein-Gespräche mit, und das Speichern der Konten hängt zeitlich nicht mehr
  an einzelnen Nachrichten.
- Ohne behaltenen Verlauf wird ein gelesener Block entfernt, bevor der neue
  Stand im Konto gespeichert ist (das Speichern folgt im festen Abstand). Lädt
  die Seite genau dazwischen neu, könnte ein böswilliger Server denselben
  Block noch einmal zustellen. Er bekäme dadurch nichts zu lesen; der
  Empfänger sähe eine Nachricht doppelt. Mit behaltenem Verlauf wird erst
  nach dem Speichern entfernt.

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
gibt, nicht, wie viele Blöcke oder Anhänge. Am Verzeichnis lässt sich
abzählen, wie viele Blöcke gerade liegen. Darunter sind Schein-Blöcke, und
welche echt sind, steht nirgends. Die Seite `/beweis` zeigt nur
Speicherformat, Quelltext und Prüfsummen.

## Selbst betreiben und prüfen

```
pip install fastapi uvicorn aiosqlite python-multipart httpx cryptography
python3 scripts/update_hashes.py
LEHNO_MESH_ALLOW_LOCAL=1 uvicorn app:app --port 8000 --no-access-log --no-server-header --no-date-header
python3 bots.py
```

## Lizenz

Siehe `LICENSE`.
