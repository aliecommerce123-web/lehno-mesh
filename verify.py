#!/usr/bin/env python3
"""chatmesh prüfen: Läuft auf dem Server wirklich der öffentliche Quelltext?

Dieses Programm kann jeder von außen laufen lassen. Es braucht nur Python,
keine weiteren Bausteine, und es meldet sich nirgends an.

Was es tut:
  1. Es fragt den Server, welche Dateien er gerade benutzt, und lädt jede davon.
  2. Es vergleicht jede Datei mit dem Stand im öffentlichen Quelltext-Verzeichnis
     (oder mit einem Ordner auf deinem Rechner, wenn du --ordner angibst).
  3. Es lädt die Dateien, die der Server an Browser ausliefert (die App selbst),
     und prüft, dass es genau dieselben sind.

Aufruf:
  python3 verify.py https://mesh.lehno.de
  python3 verify.py https://mesh.lehno.de --ordner .      (Vergleich mit lokalem Ordner)

Ergebnis: "Alles stimmt überein" oder eine Liste der Abweichungen.
Ende-Wert 0 heißt: alles stimmt. Ende-Wert 1 heißt: Abweichung gefunden.
"""
import hashlib
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

TIMEOUT = 60

# So werden die Dateien an den Browser ausgeliefert (Adresse -> Datei im Quelltext).
SERVED = {
    "/": "static/index.html",
    "/app": "static/index.html",
    "/beweis": "static/proof.html",
    "/proof": "static/proof.html",
    "/tor": "static/landing.html",
    "/manifest.json": "static/manifest.json",
    "/s/app.js": "static/app.js",
    "/s/crypto.js": "static/crypto.js",
    "/s/media.js": "static/media.js",
    "/s/bip39.js": "static/bip39.js",
    "/s/style.css": "static/style.css",
    "/s/proof.js": "static/proof.js",
    "/s/landing.js": "static/landing.js",
    "/s/vendor/jsqr.js": "static/vendor/jsqr.js",
    "/s/vendor/qrcode.js": "static/vendor/qrcode.js",
}


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "chatmesh-verify"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def raw_url(repository: str, commit: str, name: str) -> str:
    """Adresse einer Datei im öffentlichen Verzeichnis zu einem bestimmten Stand."""
    parts = urllib.parse.urlparse(repository)
    path = parts.path.strip("/")
    return "https://raw.githubusercontent.com/" + path + "/" + commit + "/" + urllib.parse.quote(name)


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    base = args[0].rstrip("/")
    folder = None
    if "--ordner" in sys.argv:
        i = sys.argv.index("--ordner")
        folder = Path(sys.argv[i + 1]) if i + 1 < len(sys.argv) else Path(".")
        args = [a for a in args if a != str(folder)]

    problems = []
    print("Prüfe", base)

    info = json.loads(fetch(base + "/api/proof/source"))
    repository, commit = info.get("repository", ""), info.get("commit", "")
    files = info.get("files", [])
    print("  Server nennt", len(files), "Dateien, Stand:", commit[:12] or "(keiner genannt)")

    # 1. Dateien vom Server laden
    live = {}
    for f in files:
        name = f["name"]
        data = fetch(base + "/api/proof/file?name=" + urllib.parse.quote(name))
        live[name] = data
        if sha(data) != f["sha256"]:
            problems.append(f"{name}: Server nennt eine andere Prüfsumme, als die Datei hat")

    # 2. Vergleich mit dem öffentlichen Stand (oder dem lokalen Ordner)
    where = "lokalem Ordner " + str(folder) if folder else "öffentlichem Verzeichnis"
    print("  Vergleiche mit", where, "…")
    if not folder and not (repository and commit):
        problems.append("Der Server nennt keinen Stand im öffentlichen Verzeichnis. Bitte mit --ordner prüfen.")
    else:
        for name, data in live.items():
            try:
                ref = (folder / name).read_bytes() if folder else fetch(raw_url(repository, commit, name))
            except Exception:
                problems.append(f"{name}: im Vergleichsstand nicht gefunden")
                continue
            if sha(ref) != sha(data):
                problems.append(f"{name}: weicht vom Vergleichsstand ab")

    # 3. Was wirklich an den Browser geht
    print("  Prüfe, was an Browser ausgeliefert wird …")
    for url, name in SERVED.items():
        if name not in live:
            problems.append(f"{url}: Datei {name} fehlt in der Liste des Servers")
            continue
        try:
            data = fetch(base + url)
        except Exception as e:
            problems.append(f"{url}: nicht abrufbar ({e})")
            continue
        if sha(data) != sha(live[name]):
            problems.append(f"{url}: ausgeliefert wird etwas anderes als {name}")

    # 4. Die App darf nur eigene Dateien laden
    page = live.get("static/index.html", b"").decode("utf-8", "replace")
    for marker in ("http://", "https://"):
        for piece in page.split(marker)[1:]:
            host = piece.split("/")[0].split('"')[0].split("'")[0]
            if host and "w3.org" not in host:
                problems.append(f"Startseite verweist auf fremde Adresse: {marker}{host}")

    print()
    if problems:
        print("ABWEICHUNGEN GEFUNDEN:")
        for line in problems:
            print("  -", line)
        return 1
    print("Alles stimmt überein:", len(live), "Dateien geprüft,", len(SERVED), "Auslieferungen geprüft.")
    print("Der Server läuft mit genau dem öffentlichen Quelltext (Stand " + (commit[:12] or "lokaler Ordner") + ").")
    return 0


if __name__ == "__main__":
    sys.exit(main())
