#!/usr/bin/env python3
"""Berechnet SHA-256 fuer alle kritischen Files und schreibt EXPECTED_HASHES.json.

Nach jeder legitimen Code-Aenderung musst du dieses Skript laufen lassen und das
neue EXPECTED_HASHES.json mit-committen, sonst startet der Service nicht mehr.

Das ist Absicht: jede Aenderung muss im public Repo sichtbar werden.
"""
import hashlib
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Files die immer mit-versioniert sind und sich nie unangekuendigt aendern duerfen
PROTECTED = [
    "app.py",
    "static/index.html",
    "static/landing.html",
    "static/style.css",
    "static/app.js",
    "static/crypto.js",
    "static/bip39.js",
    "static/manifest.json",
    "static/sw.js",
]

result = {}
for rel in PROTECTED:
    full = BASE_DIR / rel
    if not full.exists():
        print(f"WARN: file missing, skipping: {rel}")
        continue
    h = hashlib.sha256(full.read_bytes()).hexdigest()
    result[rel] = h
    print(f"{h}  {rel}")

(BASE_DIR / "EXPECTED_HASHES.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(f"\nwrote {len(result)} hashes to EXPECTED_HASHES.json")
