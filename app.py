"""lehno-mesh Phase 1.6 - Zero-Metadata Sealed-Sender + Mnemonic-Recovery + Encrypted-Userdata.

Aenderungen ggue Phase 1.5:
- packets-Tabelle hat KEIN msg_type, is_contact_request, attachment_token mehr.
  Alles im verschluesselten Body. Server sieht nur: Empfaenger, Ciphertext-Bucket-Groesse.
- Ciphertext-Padding zwingend in 2 Buckets: SHORT (4 KB plaintext) und LONG (64 KB).
  Server lehnt Pakete ab die nicht exakt eine der erlaubten Groessen haben.
- Attachments unter zufaelligem Token (UUID), NICHT mehr sequential ID.
  Server kennt kein Owner-Mapping. Token steckt im verschluesselten Body.
- Mnemonic-Recovery: /api/recover/init liefert keys_blob ohne Auth, /api/recover/finalize
  verifiziert eine signierte Challenge mit dem Public-Signing-Key des Accounts.
- Encrypted-Userdata: /api/userdata GET/PUT speichert pro Account einen einzigen
  encrypted blob (Spitznamen, Kontaktliste, etc.) - syncs zwischen Geraeten ohne
  dass der Server etwas davon lesen kann.

Phase 1.8 (Sicherheits- und Verlaufs-Update):
- Chat-Verlauf als verschlüsselte Ablage je Konto (/api/history). Der Schlüssel
  entsteht nur im Browser aus dem KEK, der Server sieht nur aufgefüllte Blöcke.
- Live-Zustellung repariert (WebSocket-Adresse wurde nie gefunden), Anmeldung am
  WebSocket per erster Nachricht statt Token in der Adresse.
- App und API nur unter genau zwei Namen: Onion-Adresse und mesh.lehno.de.
- Keine Uhrzeiten: Nachrichten tragen nur eine Reihenfolge, der Server merkt
  sich höchstens die Kalenderwoche wartender Pakete (zum Aufräumen).
- Tarnverkehr (Tarnpakete, aufgefüllte Postfach-Antworten) und ein öffentlicher
  Beweis-Bereich (/beweis, /api/proof/*): Schema, Live-Verzeichnis, Quelltext.
- Strenge Längenprüfung aller Felder, Mengen- und Platzgrenzen, Begrenzung von
  Anmeldeversuchen, Sicherheits-Header (CSP), sicheres Löschen in SQLite.
- Keine Unterschrift mehr außen am Paket (hätte den Absender verraten), Senden,
  Schlüsselabruf und Anhänge ohne Konto-Token (der Server erfährt nicht, wer an
  wen sendet), zufällige statt fortlaufende Paket-Kennungen und Versionsmarken,
  Anhänge als Blöcke in einer Datenbank (keine Datei-Zeitstempel), keine
  Verbindungszeilen im Systemprotokoll.
"""
import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import sys
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import aiosqlite
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from fastapi import (FastAPI, HTTPException, Depends, UploadFile, File,
                     WebSocket, WebSocketDisconnect, Request)
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, constr

BASE_DIR = Path(__file__).resolve().parent
DB_PATH  = BASE_DIR / "mesh.db"
ATT_DB_PATH = BASE_DIR / "attachments.db"
STATIC   = BASE_DIR / "static"

# Die App ist nur unter GENAU diesen beiden Namen erreichbar: der Onion-Adresse
# (Tor) und der Adresse im normalen Netz. Lokale Aufrufe (localhost) sind nur im
# Testbetrieb erlaubt. Die App liest nirgends eine IP-Adresse, Browser-Kennung
# oder sonstige Geräte-Merkmale aus, und nichts davon wird protokolliert.
ONION_HOST = os.environ.get(
    "LEHNO_MESH_ONION", "35m6ezqw2ugdqnsqhpxe4ccpnzvesfj24ile3xswvt4s5n6fyy5xfqqd.onion"
).strip().lower()
CLEARNET_HOST = os.environ.get("LEHNO_MESH_CLEARNET", "mesh.lehno.de").strip().lower()
ALLOW_LOCAL = os.environ.get("LEHNO_MESH_ALLOW_LOCAL") == "1"
# Pfad und Schreibweise der vorgeschalteten Schleuse kommen aus der Umgebung
# (nicht aus dem Quelltext), damit hier nichts über den Aufbau steht.
PROXY_CONFIG_PATH = os.environ.get("LEHNO_MESH_PROXY_CONFIG", "")
PROXY_REMOVE_PREFIX = os.environ.get("LEHNO_MESH_PROXY_REMOVE_PREFIX", "")
PROXY_LOG_OFF = os.environ.get("LEHNO_MESH_PROXY_LOG_OFF", "")

JWT_SECRET = os.environ.get("LEHNO_MESH_JWT_SECRET") or secrets.token_hex(32)
JWT_ALGO   = "HS256"
JWT_TTL    = 60 * 60 * 24 * 30

ADMIN_API_DISABLED = True


# ---------------------------------------------------------------------------
# Tamper-Evident Self-Hash-Check
# ---------------------------------------------------------------------------
def check_integrity():
    expected_path = BASE_DIR / "EXPECTED_HASHES.json"
    if not expected_path.exists():
        print("WARNING: EXPECTED_HASHES.json missing - integrity check skipped", file=sys.stderr)
        return
    try:
        expected = json.loads(expected_path.read_text())
    except Exception as e:
        print(f"FATAL: cannot read EXPECTED_HASHES.json: {e}", file=sys.stderr)
        sys.exit(1)
    for rel_path, expected_hash in expected.items():
        actual_path = BASE_DIR / rel_path
        if not actual_path.exists():
            print(f"FATAL: file missing: {rel_path}", file=sys.stderr)
            sys.exit(1)
        h = hashlib.sha256(actual_path.read_bytes()).hexdigest()
        if h != expected_hash:
            print(f"FATAL: tamper detected in {rel_path}", file=sys.stderr)
            print(f"  expected: {expected_hash}", file=sys.stderr)
            print(f"  actual:   {h}", file=sys.stderr)
            sys.exit(1)
    print(f"integrity OK ({len(expected)} files verified)", file=sys.stderr)


check_integrity()

ADDR_RE = r"^(mesh:)?[1-9A-HJ-NP-Za-km-z]{30,50}$"


def normalize_address(addr: str) -> str:
    return addr[5:] if addr.startswith("mesh:") else addr


def pretty_address(addr: str) -> str:
    return addr if addr.startswith("mesh:") else f"mesh:{addr}"

ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)
# Für unbekannte Adressen wird trotzdem ein Hash geprüft, damit die Antwortzeit
# nicht verrät, ob es ein Konto gibt.
_DUMMY_HASH = ph.hash(secrets.token_hex(16))
# Argon2 braucht 64 MB und spürbar Rechenzeit: nie mehr als 2 gleichzeitig und
# nie im Hauptablauf, damit der Dienst bei vielen Anfragen erreichbar bleibt.
_ARGON_SEM = asyncio.Semaphore(2)


async def argon_hash(value: str) -> str:
    async with _ARGON_SEM:
        return await asyncio.to_thread(ph.hash, value)


async def argon_verify(hashed: str, value: str) -> bool:
    async with _ARGON_SEM:
        def _v():
            try:
                return ph.verify(hashed, value)
            except Exception:
                return False
        return await asyncio.to_thread(_v)


# ---------------------------------------------------------------------------
# Mengenbegrenzung (nur im Arbeitsspeicher, nichts davon wird gespeichert)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self):
        self.hits: dict[str, deque] = defaultdict(deque)

    MAX_KEYS = 100_000

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        if len(self.hits) > self.MAX_KEYS:
            # Notbremse gegen Speicherwachstum durch massenhaft verschiedene Schlüssel.
            self.sweep()
            if len(self.hits) > self.MAX_KEYS:
                self.hits.clear()
        q = self.hits[key]
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def count(self, key: str, window: int) -> int:
        now = time.monotonic()
        q = self.hits.get(key)
        if not q:
            return 0
        while q and q[0] <= now - window:
            q.popleft()
        return len(q)

    def sweep(self):
        now = time.monotonic()
        for k in list(self.hits.keys()):
            q = self.hits[k]
            while q and q[0] <= now - 3600:
                q.popleft()
            if not q:
                del self.hits[k]


limiter = RateLimiter()


def limit_or_429(key: str, limit: int, window: int):
    if not limiter.allow(key, limit, window):
        raise HTTPException(429, "too many requests, try again later")


# ---------------------------------------------------------------------------
# Platzgrenzen: der Dienst darf nie die Platte füllen.
# ---------------------------------------------------------------------------
MIN_FREE_BYTES    = int(1.5 * 1024**3)   # darunter nimmt mesh nichts Neues an
MAX_DB_BYTES      = 1 * 1024**3          # belegte Seiten der Datenbank insgesamt
MAX_UPLOADS_BYTES = int(1.5 * 1024**3)   # alle Anhänge zusammen
MAX_INBOX_WEIGHT  = 600                  # wartende Pakete je Empfänger (große zählen 16-fach)
MAX_HISTORY_BYTES = 600 * 1024**2        # alle Verlaufsablagen zusammen (eigener Topf, damit
                                         # Verläufe nie den Platz für neue Nachrichten aufbrauchen)


# ---------------------------------------------------------------------------
# Strenge Feldprüfung: jedes Feld hat eine feste Länge. Damit kann niemand
# zusätzliche Daten oder Kennzeichen in die Datenbank schmuggeln.
# ---------------------------------------------------------------------------
def b64_exact(value: str, nbytes: int, name: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, f"invalid base64 in {name}")
    if len(raw) != nbytes:
        raise HTTPException(400, f"invalid length of {name}")
    return raw


def b64_valid(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, f"invalid base64 in {name}")


def p256_point(value: str, name: str) -> bytes:
    raw = b64_exact(value, 65, name)
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        raise HTTPException(400, f"invalid public key in {name}")
    return raw


# ---------------------------------------------------------------------------
# Base58
# ---------------------------------------------------------------------------
_B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58_ALPH[r] + out
    for b in data:
        if b == 0:
            out = "1" + out
        else:
            break
    return out


def address_from_identity_pub(identity_pub_b64: str) -> str:
    raw = base64.b64decode(identity_pub_b64)
    h = hashlib.sha256(raw).digest()[:24]
    return b58_encode(h)


# Zeit auf dem Server: Es gibt KEINE Uhrzeiten und keine Tagesangaben. Nur für
# das Aufräumen nie abgeholter Pakete und alter Anhänge wird die laufende
# Kalenderwoche gemerkt (grober Marker, 7 Tage). Konten und Ablagen tragen gar
# keine Zeitangabe.
WEEK = 7 * 86400
KEEP_WEEKS = 5          # Aufbewahrung nie abgeholter Pakete und Anhänge: 5 bis 6 Wochen


def week_bucket(ts: int) -> int:
    return (ts // WEEK) * WEEK


# ---------------------------------------------------------------------------
# Padding-Buckets (PFLICHT, Server-validiert)
# Plaintext-Groessen in Bytes. Client paddet das Plaintext-JSON auf eine
# dieser Groessen BEVOR encrypt. Server prueft die resultierende b64-Laenge
# des Ciphertexts (= deterministisch ableitbar aus plaintext-size + 16 GCM tag).
# ---------------------------------------------------------------------------
PAYLOAD_BUCKETS_PLAIN = [4096, 65536]   # 4 KB, 64 KB


def b64_len_for_plain(plain_bytes: int) -> int:
    # AES-GCM-Ciphertext = plain + 16 byte tag. b64-Laenge = ceil(n/3)*4
    ct = plain_bytes + 16
    return ((ct + 2) // 3) * 4


PAYLOAD_BUCKETS_B64 = [b64_len_for_plain(p) for p in PAYLOAD_BUCKETS_PLAIN]

# Verschlüsselte Ablagen je Konto (Kontakte bzw. Chat-Verlauf): ebenfalls nur
# feste Größen. MUSS zu USERDATA_BUCKETS / HISTORY_BUCKETS in crypto.js passen.
USERDATA_BUCKETS_PLAIN = [2048, 8192, 32768, 131072]
HISTORY_BUCKETS_PLAIN  = [65536, 262144, 1048576, 4194304]
USERDATA_BUCKETS_B64 = [b64_len_for_plain(p) for p in USERDATA_BUCKETS_PLAIN]
HISTORY_BUCKETS_B64  = [b64_len_for_plain(p) for p in HISTORY_BUCKETS_PLAIN]


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    address TEXT PRIMARY KEY,
    auth_hash TEXT NOT NULL,
    salt_b64 TEXT NOT NULL,
    identity_pub_b64 TEXT NOT NULL,
    signing_pub_b64 TEXT NOT NULL,
    keys_blob_b64 TEXT NOT NULL,
    keys_nonce_b64 TEXT NOT NULL,
    kek_blob_b64 TEXT NOT NULL,
    kek_nonce_b64 TEXT NOT NULL,
    created_day INTEGER NOT NULL,
    jwt_min_iat INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_address TEXT NOT NULL,
    ephemeral_pub_b64 TEXT NOT NULL,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    created_day INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_packets_recipient ON packets(recipient_address, id);

CREATE TABLE IF NOT EXISTS attachments (
    token TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_day INTEGER NOT NULL,
    expires_day INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attachments_expires ON attachments(expires_day);

CREATE TABLE IF NOT EXISTS userdata (
    user_address TEXT PRIMARY KEY,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    updated_day INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_challenges (
    challenge_hex TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    expires_ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    user_address TEXT PRIMARY KEY,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    updated_day INTEGER NOT NULL
);
"""

ATT_SCHEMA = """
CREATE TABLE IF NOT EXISTS blobs (
    token TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_day INTEGER NOT NULL,
    expires_day INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blobs_expires ON blobs(expires_day);
"""


def init_db():
    con = sqlite3.connect(DB_PATH)
    # Freie Seiten sollen wieder an das Dateisystem zurückgehen, sonst wächst die
    # Datei nur. Die Umstellung braucht einmalig ein VACUUM.
    if con.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
        con.execute("PRAGMA auto_vacuum=INCREMENTAL")
        con.execute("VACUUM")
    con.executescript(SCHEMA)
    # Additive Migrationen (nie destruktiv).
    for stmt in (
        "ALTER TABLE users ADD COLUMN jwt_min_iat INTEGER NOT NULL DEFAULT 0",
        # Schlüsselverfahren des Kontos: 1 = alt (vor Phase 1.8), 2 = neu.
        "ALTER TABLE users ADD COLUMN kdf INTEGER NOT NULL DEFAULT 1",
        # Zufälliges Bestätigungs-Token je Paket: der Empfänger sieht keine
        # fortlaufende Nummer mehr (die den Gesamtverkehr verraten würde).
        "ALTER TABLE packets ADD COLUMN ack_token TEXT",
        # Größe der Verlaufsablage (für das Gesamtbudget, ohne die Blöcke lesen zu müssen).
        "ALTER TABLE history ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0",
    ):
        try:
            con.execute(stmt)
        except sqlite3.OperationalError:
            pass  # Spalte existiert bereits
    con.execute("CREATE INDEX IF NOT EXISTS idx_packets_ack ON packets(recipient_address, ack_token)")
    con.execute("UPDATE packets SET ack_token = lower(hex(randomblob(16))) WHERE ack_token IS NULL")
    # Vorhandene Zeitangaben entfernen bzw. auf den Wochen-Marker vergröbern.
    con.execute("UPDATE users SET created_day = 0 WHERE created_day != 0")
    con.execute("UPDATE userdata SET updated_day = 0 WHERE updated_day != 0")
    con.execute("UPDATE history SET updated_day = 0 WHERE updated_day != 0")
    con.execute(f"UPDATE packets SET created_day = created_day - (created_day % {WEEK}) WHERE created_day % {WEEK} != 0")
    con.commit()
    con.close()

    # Anhänge liegen als Blöcke in einer eigenen Datenbank statt als einzelne
    # Dateien: so gibt es je Anhang keine Datei-Zeitstempel (Anlage, Zugriff).
    acon = sqlite3.connect(ATT_DB_PATH)
    if acon.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
        acon.execute("PRAGMA auto_vacuum=INCREMENTAL")
        acon.execute("VACUUM")
    acon.executescript(ATT_SCHEMA)
    acon.execute(f"UPDATE blobs SET created_day = 0, expires_day = expires_day - (expires_day % {WEEK}) + {WEEK} "
                 f"WHERE created_day != 0 OR expires_day % {WEEK} != 0")
    acon.commit()
    acon.close()
    for path in (DB_PATH, ATT_DB_PATH):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Keine Verbindungs-Zeilen im Systemprotokoll (uvicorn schreibt sonst jede
    # WebSocket-Verbindung mit Uhrzeit mit, auch bei --no-access-log).
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).setLevel(logging.WARNING)
    init_db()
    cleanup_task = asyncio.create_task(cleanup_loop())
    proof_task = asyncio.create_task(proof_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()
        proof_task.cancel()


app = FastAPI(title="lehno-mesh", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


async def open_db() -> aiosqlite.Connection:
    con = await aiosqlite.connect(DB_PATH, timeout=15)
    con.row_factory = aiosqlite.Row
    # Gelöschte Zeilen werden mit Nullen überschrieben statt nur freigegeben.
    await con.execute("PRAGMA secure_delete=ON")
    return con


async def open_att_db() -> aiosqlite.Connection:
    con = await aiosqlite.connect(ATT_DB_PATH, timeout=15)
    con.row_factory = aiosqlite.Row
    await con.execute("PRAGMA secure_delete=ON")
    return con


async def db():
    con = await open_db()
    try:
        yield con
    finally:
        await con.close()


async def ensure_disk_space(con: aiosqlite.Connection):
    """Lehnt neue Daten ab, wenn die Platte knapp oder die Datenbank zu groß wird."""
    try:
        free = shutil.disk_usage(BASE_DIR).free
    except OSError:
        free = MIN_FREE_BYTES
    cur = await con.execute("PRAGMA page_count")
    pages = (await cur.fetchone())[0]
    cur = await con.execute("PRAGMA freelist_count")
    free_pages = (await cur.fetchone())[0]
    cur = await con.execute("PRAGMA page_size")
    page_size = (await cur.fetchone())[0]
    if free < MIN_FREE_BYTES or (pages - free_pages) * page_size > MAX_DB_BYTES:
        raise HTTPException(507, "storage full, try again later")


# ---------------------------------------------------------------------------
# Nur über Tor + Sicherheits-Header
# ---------------------------------------------------------------------------
_SAFE_HOST_RE = re.compile(r"^[a-z0-9.\-]+(:[0-9]{1,5})?$")

SECURITY_HEADERS = {
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(self), geolocation=(), payment=(), usb=()",
    # no-transform: Zwischenstellen sollen Antworten nicht umformen (z. B.
    # zusammendrücken), sonst wären gleich große Antworten nicht mehr gleich groß.
    "Cache-Control": "no-store, no-transform, max-age=0",
}
# Diese Kopfzeilen würden verraten, wann Dateien zuletzt geändert wurden.
DROP_HEADERS = ("etag", "last-modified", "server", "date")


def host_kind(host_header: str):
    """'onion', 'clear' oder 'local' für erlaubte Namen, sonst None."""
    host = (host_header or "").strip().lower()
    if host in (ONION_HOST, ONION_HOST + ":80"):
        return "onion"
    if host in (CLEARNET_HOST, CLEARNET_HOST + ":443"):
        return "clear"
    if ALLOW_LOCAL and _SAFE_HOST_RE.match(host) and host.split(":")[0] in ("localhost", "127.0.0.1"):
        return "local"
    return None


def host_is_allowed(host_header: str) -> bool:
    return host_kind(host_header) is not None


def csp_for(host_header: str) -> str:
    host = (host_header or "").strip().lower()
    kind = host_kind(host)
    # WebSocket nur zum eigenen Host, nicht zu beliebigen Servern.
    connect = "'self'"
    if kind == "clear":
        connect += f" wss://{CLEARNET_HOST}"
    elif kind in ("onion", "local") and _SAFE_HOST_RE.match(host):
        connect += f" ws://{host}"
    return (
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' blob: data:; media-src blob:; connect-src {connect}; "
        "manifest-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'; object-src 'none'"
    )


MAX_BODY_DEFAULT    = 200 * 1024
MAX_BODY_HISTORY    = 6 * 1024 * 1024
MAX_BODY_ATTACHMENT = 17 * 1024 * 1024

# Große Anfragen: nur wenige gleichzeitig und mit Zeitlimit, damit hängende
# Verbindungen weder Arbeitsspeicher noch /tmp belegen können.
_INFLIGHT: dict[str, int] = defaultdict(int)
BIG_ROUTES = {
    # (Methode, Pfad) -> (Zähler, gleichzeitig, Zeitlimit s, Body-Grenze)
    ("PUT", "/api/history"):      ("history", 6, 240, MAX_BODY_HISTORY),
    ("POST", "/api/attachments"): ("upload", 3, 900, MAX_BODY_ATTACHMENT),
}
DEFAULT_TIMEOUT = 60


def _json(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


@app.middleware("http")
async def guard(request: Request, call_next):
    # Pfad direkt aus der Anfrage nehmen (request.url würde bei einem kaputten
    # Host-Header mit einer Ausnahme abbrechen).
    path = request.scope.get("path", "")
    method = request.method
    host = request.headers.get("host", "")
    resp = None
    counter = None
    timeout = DEFAULT_TIMEOUT
    try:
        if not host_is_allowed(host) and path != "/healthz":
            resp = _json(403, "unknown host")
        elif method in ("POST", "PUT", "PATCH", "DELETE"):
            big = BIG_ROUTES.get((method, path))
            cap = big[3] if big else MAX_BODY_DEFAULT
            cl = request.headers.get("content-length")
            if method != "DELETE" and (cl is None or not cl.isdigit()):
                resp = _json(411, "content-length required")
            elif cl is not None and cl.isdigit() and int(cl) > cap:
                resp = _json(413, "request too large")
            elif big:
                name, max_parallel, timeout, _ = big
                if name == "history":
                    # Token prüfen, BEVOR der große Body gelesen wird.
                    auth = request.headers.get("authorization", "")
                    parts = auth.split(None, 1)
                    if len(parts) != 2 or parts[0].lower() != "bearer":
                        resp = _json(401, "missing bearer token")
                    else:
                        try:
                            await address_from_token(parts[1].strip())
                        except HTTPException as e:
                            resp = _json(e.status_code, str(e.detail))
                if resp is None:
                    if _INFLIGHT[name] >= max_parallel:
                        resp = _json(503, "busy, try again in a moment")
                    else:
                        counter = name
                        _INFLIGHT[name] += 1
        elif method == "GET" and path.startswith("/api/attachments/"):
            # Zeitlimit und Platzvergabe regelt die Antwort selbst (stückweise).
            timeout = None
        if resp is None:
            try:
                if timeout is None:
                    resp = await call_next(request)
                else:
                    resp = await asyncio.wait_for(call_next(request), timeout=timeout)
            except asyncio.TimeoutError:
                resp = _json(408, "request timeout")
            except Exception:
                # Keine Einzelheiten nach außen, aber immer mit Sicherheits-Headern.
                resp = _json(500, "internal error")
    finally:
        if counter:
            _INFLIGHT[counter] -= 1
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    resp.headers["Content-Security-Policy"] = csp_for(host)
    for k in DROP_HEADERS:
        if k in resp.headers:
            del resp.headers[k]
    return resp


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def new_generation() -> int:
    return secrets.randbits(53) + 1


def make_jwt(address: str, generation: int) -> str:
    """generation = aktueller Wert von users.jwt_min_iat. Ändert sich dieser Wert
    (Wiederherstellung, Neuanlage), sind alle älteren Token sofort ungültig."""
    # Bewusst ohne Ausstellungszeit (iat): die Generation reicht zum Entwerten.
    payload = {"sub": address, "exp": int(time.time()) + JWT_TTL, "gen": int(generation)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def parse_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid token")


async def address_from_token(token: str) -> str:
    """Prüft Token, Konto-Existenz und Generation. Gibt die Adresse ohne Präfix zurück."""
    data = parse_jwt(token)
    addr = normalize_address(str(data.get("sub", "")))
    con = await open_db()
    try:
        cur = await con.execute("SELECT jwt_min_iat FROM users WHERE address=?", (addr,))
        row = await cur.fetchone()
    finally:
        await con.close()
    if not row:
        # Konto gelöscht oder nie vorhanden: Token ist wertlos.
        raise HTTPException(401, "invalid token")
    if data.get("gen") != row["jwt_min_iat"]:
        raise HTTPException(401, "token revoked")
    return addr


async def current_address(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    parts = auth.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(401, "missing bearer token")
    return await address_from_token(parts[1].strip())


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
AddressStr = constr(pattern=ADDR_RE)
BIG_INT = 2**62


class StrictModel(BaseModel):
    # Unbekannte Felder werden abgelehnt (niemand kann Zusatzdaten mitschicken,
    # alte Clients mit anderem Format bekommen eine klare Absage).
    model_config = {"extra": "forbid"}


class RegisterReq(StrictModel):
    auth_key_b64: str = Field(..., min_length=44, max_length=44)
    salt_b64: str = Field(..., min_length=24, max_length=24)
    keys_blob_b64: str = Field(..., min_length=100, max_length=2000)
    keys_nonce_b64: str = Field(..., min_length=16, max_length=16)
    kek_blob_b64: str = Field(..., min_length=64, max_length=64)
    kek_nonce_b64: str = Field(..., min_length=16, max_length=16)
    identity_pub_b64: str = Field(..., min_length=88, max_length=88)
    signing_pub_b64: str = Field(..., min_length=88, max_length=88)
    kdf: int = Field(..., ge=2, le=2)


class LoginInitReq(StrictModel):
    address: AddressStr


class LoginReq(StrictModel):
    address: AddressStr
    auth_key_b64: str = Field(..., min_length=44, max_length=44)


class SendPacketReq(StrictModel):
    v: int = Field(..., ge=2, le=2)
    pad: str = Field("", max_length=64, pattern=r"^x*$")     # nur Füllzeichen
    recipient_address: AddressStr
    ephemeral_pub_b64: str = Field(..., min_length=88, max_length=88)
    nonce_b64: str = Field(..., min_length=16, max_length=16)
    ciphertext_b64: str = Field(..., min_length=1, max_length=90_000)


class RecoverInitReq(StrictModel):
    address: AddressStr


class RecoverFinalizeReq(StrictModel):
    address: AddressStr
    challenge_hex: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    signature_b64: str = Field(..., min_length=88, max_length=88)
    new_auth_key_b64: str = Field(..., min_length=44, max_length=44)
    new_salt_b64: str = Field(..., min_length=24, max_length=24)
    new_kek_blob_b64: str = Field(..., min_length=64, max_length=64)
    new_kek_nonce_b64: str = Field(..., min_length=16, max_length=16)
    new_kdf: int = Field(..., ge=2, le=2)


class BlobPutReq(StrictModel):
    nonce_b64: str = Field(..., min_length=16, max_length=16)
    ciphertext_b64: str = Field(..., min_length=1, max_length=5_700_000)
    expected_version: int = Field(..., ge=0, le=BIG_INT)


class AckReq(StrictModel):
    packet_ids: list[constr(pattern=r"^[0-9a-f]{32}$")] = Field(..., max_length=1000)


# ---------------------------------------------------------------------------
# Auth-Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/register")
async def register(req: RegisterReq, con: aiosqlite.Connection = Depends(db)):
    b64_exact(req.auth_key_b64, 32, "auth_key")
    b64_exact(req.salt_b64, 16, "salt")
    b64_exact(req.keys_nonce_b64, 12, "keys_nonce")
    b64_exact(req.kek_blob_b64, 48, "kek_blob")
    b64_exact(req.kek_nonce_b64, 12, "kek_nonce")
    b64_valid(req.keys_blob_b64, "keys_blob")
    p256_point(req.identity_pub_b64, "identity_pub")
    p256_point(req.signing_pub_b64, "signing_pub")
    # Erst nach der Feldprüfung zählen (ungültige Anfragen verbrauchen nichts).
    limit_or_429("register:global", 90, 3600)
    await ensure_disk_space(con)
    address = address_from_identity_pub(req.identity_pub_b64)

    cur = await con.execute("SELECT 1 FROM users WHERE address=?", (address,))
    if await cur.fetchone():
        raise HTTPException(409, "address collision")

    auth_hash = await argon_hash(req.auth_key_b64)
    generation = new_generation()
    try:
        await con.execute(
            "INSERT INTO users (address, auth_hash, salt_b64, identity_pub_b64, signing_pub_b64, "
            " keys_blob_b64, keys_nonce_b64, kek_blob_b64, kek_nonce_b64, created_day, jwt_min_iat, kdf) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (address, auth_hash, req.salt_b64,
             req.identity_pub_b64, req.signing_pub_b64,
             req.keys_blob_b64, req.keys_nonce_b64,
             req.kek_blob_b64, req.kek_nonce_b64,
             0, generation, req.kdf),
        )
        await con.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "address collision")

    pretty = pretty_address(address)
    return {"address": pretty, "jwt": make_jwt(pretty, generation)}


@app.post("/api/login/init")
async def login_init(req: LoginInitReq, con: aiosqlite.Connection = Depends(db)):
    addr = normalize_address(req.address)
    cur = await con.execute("SELECT salt_b64, kdf FROM users WHERE address=?", (addr,))
    row = await cur.fetchone()
    if row:
        return {"salt_b64": row["salt_b64"], "kdf": row["kdf"]}
    fake = hashlib.sha256(f"lehno-mesh-fake-salt-v1.6:{addr}".encode()).digest()[:16]
    return {"salt_b64": base64.b64encode(fake).decode(), "kdf": 2}


@app.post("/api/login")
async def login(req: LoginReq, con: aiosqlite.Connection = Depends(db)):
    addr = normalize_address(req.address)
    b64_exact(req.auth_key_b64, 32, "auth_key")
    # Schutz der Rechenzeit (Argon2 ist teuer), bewusst großzügig.
    limit_or_429("login:global", 20000, 3600)
    # Nach 10 Fehlversuchen in 15 Minuten wird je Adresse nur noch ein Versuch
    # alle 3 Sekunden geprüft (Schutz gegen Durchprobieren von Passwörtern).
    # Keine dauerhafte Sperre: sobald die Fehlversuche aufhören, geht es sofort
    # normal weiter. Der Client wiederholt die Anmeldung bei 429 von selbst.
    # Grenze: wer die Adresse kennt und ununterbrochen falsche Versuche schickt,
    # kann die Anmeldung für diese Adresse in der Zeit behindern.
    if limiter.count(f"loginfail:{addr}", 900) >= 10:
        limit_or_429(f"loginslow:{addr}", 1, 3)
    cur = await con.execute(
        "SELECT address, auth_hash, salt_b64, kdf, jwt_min_iat, "
        "       keys_blob_b64, keys_nonce_b64, kek_blob_b64, kek_nonce_b64 "
        "FROM users WHERE address=?", (addr,)
    )
    user = await cur.fetchone()
    ok = await argon_verify(user["auth_hash"] if user else _DUMMY_HASH, req.auth_key_b64)
    if not user or not ok:
        limiter.allow(f"loginfail:{addr}", 10**9, 900)
        raise HTTPException(401, "invalid credentials")

    pretty = pretty_address(user["address"])
    return {
        "address": pretty,
        "jwt": make_jwt(pretty, user["jwt_min_iat"]),
        "salt_b64": user["salt_b64"],
        "kdf": user["kdf"],
        "keys_blob_b64": user["keys_blob_b64"],
        "keys_nonce_b64": user["keys_nonce_b64"],
        "kek_blob_b64": user["kek_blob_b64"],
        "kek_nonce_b64": user["kek_nonce_b64"],
    }


# ---------------------------------------------------------------------------
# Mnemonic-Recovery
# ---------------------------------------------------------------------------
RECOVERY_TTL = 300  # 5 Min


@app.post("/api/recover/init")
async def recover_init(req: RecoverInitReq, con: aiosqlite.Connection = Depends(db)):
    """Liefert keys_blob + frische Challenge. KEIN Auth.

    Jeder kann für jede Adresse einen Versuch starten. Das ist in Ordnung, weil
    der nächste Schritt (finalize) eine gültige Signatur mit dem privaten
    Signing-Key des Kontos braucht, und der ist ohne die 24 Wörter nicht zugänglich.
    Der öffentliche Identitätsschlüssel wird hier bewusst NICHT mitgeliefert:
    daran ließe sich prüfen, ob es das Konto gibt.
    """
    addr = normalize_address(req.address)
    limit_or_429("recover:global", 6000, 3600)
    cur = await con.execute(
        "SELECT keys_blob_b64, keys_nonce_b64 FROM users WHERE address=?",
        (addr,),
    )
    row = await cur.fetchone()
    if not row:
        # Unbekannte Adresse: Attrappe in Form und Länge eines echten Kontos.
        seed = hashlib.sha256(f"lehno-mesh-fake-keys:{addr}".encode()).digest()
        fake_keys_raw = b"".join(
            hashlib.sha256(seed + i.to_bytes(2, "big")).digest() for i in range(15)
        )[:480]
        fake_nonce_raw = hashlib.sha256(seed + b":nonce").digest()[:12]
        return {
            "keys_blob_b64": base64.b64encode(fake_keys_raw).decode(),
            "keys_nonce_b64": base64.b64encode(fake_nonce_raw).decode(),
            "challenge_hex": secrets.token_hex(32),
        }

    challenge_hex = secrets.token_hex(32)
    expires = int(time.time()) + RECOVERY_TTL
    # Pro Adresse höchstens 3 aktive Challenges (ältere fallen weg). Begrenzt den
    # Speicher, ohne dass ein Fremder eine laufende Wiederherstellung durch einen
    # einzigen Aufruf abbrechen kann.
    await con.execute("DELETE FROM recovery_challenges WHERE expires_ts < ?", (int(time.time()),))
    await con.execute(
        "DELETE FROM recovery_challenges WHERE address=? AND challenge_hex NOT IN ("
        " SELECT challenge_hex FROM recovery_challenges WHERE address=? "
        " ORDER BY expires_ts DESC LIMIT 2)",
        (addr, addr),
    )
    await con.execute(
        "INSERT INTO recovery_challenges (challenge_hex, address, expires_ts) VALUES (?,?,?)",
        (challenge_hex, addr, expires),
    )
    await con.commit()

    return {
        "keys_blob_b64": row["keys_blob_b64"],
        "keys_nonce_b64": row["keys_nonce_b64"],
        "challenge_hex": challenge_hex,
    }


def _verify_ecdsa_p256(signing_pub_raw: bytes, signature_raw: bytes, data: bytes) -> bool:
    """Verifiziert eine WebCrypto-ECDSA-P-256-Signatur (P1363, 64 bytes = R||S)."""
    if len(signature_raw) != 64:
        return False
    r = int.from_bytes(signature_raw[:32], "big")
    s = int.from_bytes(signature_raw[32:], "big")
    if r == 0 or s == 0:
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), signing_pub_raw)
        pub.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


@app.post("/api/recover/finalize")
async def recover_finalize(req: RecoverFinalizeReq, con: aiosqlite.Connection = Depends(db)):
    """Schließt die Wiederherstellung ab: neuer auth_hash, salt, verschlüsselter KEK.

    Das Schlüsselbündel bleibt unverändert, nur die Verschlüsselung des KEK und
    das Passwort ändern sich. Keine Sperre je Adresse: eine Signatur lässt sich
    nicht erraten, und Fremde sollen den Inhaber nicht aussperren können.
    """
    addr = normalize_address(req.address)
    limit_or_429("recoverfin:global", 6000, 3600)
    b64_exact(req.new_auth_key_b64, 32, "new_auth_key")
    b64_exact(req.new_salt_b64, 16, "new_salt")
    b64_exact(req.new_kek_blob_b64, 48, "new_kek_blob")
    b64_exact(req.new_kek_nonce_b64, 12, "new_kek_nonce")
    signature_raw = b64_exact(req.signature_b64, 64, "signature")

    cur = await con.execute(
        "SELECT address FROM recovery_challenges WHERE challenge_hex=? AND address=? AND expires_ts > ?",
        (req.challenge_hex, addr, int(time.time())),
    )
    if not await cur.fetchone():
        raise HTTPException(400, "invalid or expired challenge")

    cur = await con.execute("SELECT signing_pub_b64 FROM users WHERE address=?", (addr,))
    user = await cur.fetchone()
    if not user:
        raise HTTPException(400, "invalid or expired challenge")
    try:
        signing_pub_raw = base64.b64decode(user["signing_pub_b64"])
    except Exception:
        raise HTTPException(400, "signature invalid")

    # Signiert wird "lehno-mesh-recovery-v1:" + challenge_hex
    data_to_verify = b"lehno-mesh-recovery-v1:" + req.challenge_hex.encode()
    if not _verify_ecdsa_p256(signing_pub_raw, signature_raw, data_to_verify):
        raise HTTPException(400, "signature invalid")

    new_auth_hash = await argon_hash(req.new_auth_key_b64)
    # Neue Generation: alle bisher ausgegebenen Token sind sofort ungültig
    # (gestohlenes Gerät, mitgelesener Token).
    generation = new_generation()
    await con.execute(
        "UPDATE users SET auth_hash=?, salt_b64=?, kek_blob_b64=?, kek_nonce_b64=?, jwt_min_iat=?, kdf=? "
        "WHERE address=?",
        (new_auth_hash, req.new_salt_b64, req.new_kek_blob_b64, req.new_kek_nonce_b64,
         generation, req.new_kdf, addr),
    )
    await con.execute("DELETE FROM recovery_challenges WHERE address=?", (addr,))
    await con.commit()
    # Offene Live-Verbindungen mit alten Token trennen.
    await ws_hub.drop(addr)

    pretty = pretty_address(addr)
    return {"address": pretty, "jwt": make_jwt(pretty, generation)}


# ---------------------------------------------------------------------------
# Öffentliche Schlüssel einer Adresse
# OHNE Anmeldung: sonst sähe der Server, welches Konto sich für welche Adresse
# interessiert. Adressen sind 192 Bit lang und nicht erratbar. Der Client prüft
# selbst, dass der Schlüssel zur Adresse gehört.
# ---------------------------------------------------------------------------
@app.get("/api/keys/{address}")
async def fetch_keys(address: constr(pattern=ADDR_RE), con: aiosqlite.Connection = Depends(db)):
    limit_or_429("keys:global", 6000, 60)
    addr = normalize_address(address)
    cur = await con.execute("SELECT identity_pub_b64 FROM users WHERE address=?", (addr,))
    row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "address not found")
    return {"address": pretty_address(addr), "identity_pub_b64": row["identity_pub_b64"]}


# ---------------------------------------------------------------------------
# Pakete (sealed sender: nur Empfänger + Geheimtext in Einheitsgröße)
# Einliefern OHNE Anmeldung: der Server erfährt nicht, welches Konto sendet.
# Wer der Absender ist, steht nur im verschlüsselten Teil und wird vom
# Empfänger kryptografisch geprüft; Unsinn wird dort verworfen.
# ---------------------------------------------------------------------------
INBOX_WEIGHT_LARGE = 16
# Tarnverkehr: Clients schicken in gleichmäßigem Takt Pakete. Ist gerade keine
# echte Nachricht zu senden, geht ein Tarnpaket an diese Sammeladresse. Es sieht
# von außen (Größe, Ablauf, Antwort) genauso aus wie ein echtes und wird hier
# sofort verworfen. So ist im Netz dazwischen nicht erkennbar, ob und wann
# jemand wirklich etwas sendet.
DECOY_ADDRESS = "1" * 33
INBOX_PAD_STEP = 8192


PACKET_REPLY_CHARS = 96
PACKET_MIN_SECONDS = 0.06


def _packet_reply(ok: bool, code: int = 200, detail: str = "") -> JSONResponse:
    """Immer Status 200 und immer gleich lang: von außen sieht jede Antwort gleich
    aus, egal ob echte Nachricht, Tarnpaket oder Fehler."""
    body = {"ok": ok, "code": code, "detail": detail[:40], "pad": ""}
    size = len(json.dumps(body, separators=(",", ":")))
    body["pad"] = "x" * max(0, PACKET_REPLY_CHARS - size)
    return JSONResponse(body)


@app.post("/api/packets")
async def send_packet(req: SendPacketReq, con: aiosqlite.Connection = Depends(db)):
    started = time.monotonic()
    recipient = normalize_address(req.recipient_address)
    b64_exact(req.ephemeral_pub_b64, 65, "ephemeral_pub")
    b64_exact(req.nonce_b64, 12, "nonce")
    # Einheitsgröße: aus der Länge lässt sich weder Inhalt noch Art ablesen.
    if len(req.ciphertext_b64) not in PAYLOAD_BUCKETS_B64:
        raise HTTPException(400, "invalid payload bucket size")
    b64_valid(req.ciphertext_b64, "ciphertext")
    result = await _store_packet(req, recipient, con)
    # Mindestdauer: Tarnpaket (nichts zu speichern) und echte Nachricht
    # (Datenbankzugriff) antworten gleich schnell.
    rest = PACKET_MIN_SECONDS - (time.monotonic() - started)
    if rest > 0:
        await asyncio.sleep(rest)
    return result


async def _store_packet(req, recipient: str, con) -> JSONResponse:
    if recipient == DECOY_ADDRESS:
        return _packet_reply(True)          # Tarnpaket: nichts speichern, nichts zählen
    if not limiter.allow("send:global", 60000, 60):
        return _packet_reply(False, 429, "too many requests")
    try:
        await ensure_disk_space(con)
    except HTTPException:
        return _packet_reply(False, 507, "storage full")

    cur = await con.execute("SELECT 1 FROM users WHERE address=?", (recipient,))
    if not await cur.fetchone():
        return _packet_reply(False, 404, "recipient not found")
    # Zähler je Empfänger erst anlegen, wenn es den Empfänger gibt.
    if not limiter.allow(f"send:{recipient}", 300, 60):
        return _packet_reply(False, 429, "too many requests")

    # Postfach-Grenze: große Pakete zählen 16-fach.
    cur = await con.execute(
        "SELECT COALESCE(SUM(CASE WHEN LENGTH(ciphertext_b64) > ? THEN ? ELSE 1 END), 0) AS w "
        "FROM packets WHERE recipient_address=?",
        (PAYLOAD_BUCKETS_B64[0], INBOX_WEIGHT_LARGE, recipient),
    )
    weight = (await cur.fetchone())["w"]
    add = INBOX_WEIGHT_LARGE if len(req.ciphertext_b64) > PAYLOAD_BUCKETS_B64[0] else 1
    if weight + add > MAX_INBOX_WEIGHT:
        return _packet_reply(False, 507, "recipient inbox full")

    await con.execute(
        "INSERT INTO packets (recipient_address, ephemeral_pub_b64, nonce_b64, "
        " ciphertext_b64, signature_b64, created_day, ack_token) VALUES (?,?,?,?,?,?,?)",
        (recipient, req.ephemeral_pub_b64, req.nonce_b64, req.ciphertext_b64, "",
         week_bucket(int(time.time())), secrets.token_hex(16)),
    )
    await con.commit()

    await ws_hub.notify(recipient, {"type": "new_packet"})
    return _packet_reply(True)


@app.get("/api/packets/inbox")
async def inbox(limit: int = 50,
                con: aiosqlite.Connection = Depends(db),
                me: str = Depends(current_address)):
    """Wartende Pakete, älteste zuerst. Pakete bleiben liegen, bis der Client sie
    bestätigt (erst nachdem er sie sicher in seinem verschlüsselten Verlauf hat)."""
    limit = max(1, min(int(limit), 50)) if -10**6 < limit < 10**6 else 50
    cur = await con.execute(
        "SELECT ack_token, ephemeral_pub_b64, nonce_b64, ciphertext_b64, signature_b64 "
        "FROM packets WHERE recipient_address=? ORDER BY id ASC LIMIT ?",
        (me, limit + 1),
    )
    rows = await cur.fetchall()
    more = len(rows) > limit
    rows = rows[:limit]
    cur = await con.execute("SELECT version FROM history WHERE user_address=?", (me,))
    hrow = await cur.fetchone()
    packets = []
    for r in rows:
        p = {
            "id": r["ack_token"],
            "ephemeral_pub_b64": r["ephemeral_pub_b64"],
            "nonce_b64": r["nonce_b64"],
            "ciphertext_b64": r["ciphertext_b64"],
        }
        # Nur Alt-Pakete (vor Phase 1.8) tragen noch eine Signatur.
        if r["signature_b64"]:
            p["signature_b64"] = r["signature_b64"]
        packets.append(p)
    out = {"packets": packets, "more": more, "history_version": hrow["version"] if hrow else 0, "pad": ""}
    # Antwort auf feste Größenstufen auffüllen: ein leeres Postfach und eines mit
    # einer Nachricht sind von außen gleich groß.
    size = len(json.dumps(out, separators=(",", ":")))
    fill = (-size) % INBOX_PAD_STEP
    out["pad"] = base64.b64encode(secrets.token_bytes((fill * 3) // 4 + 3)).decode()[:fill]
    return out


@app.post("/api/packets/ack")
async def ack_packets(req: AckReq, con: aiosqlite.Connection = Depends(db),
                     me: str = Depends(current_address)):
    if not req.packet_ids:
        return {"deleted": 0}
    placeholders = ",".join("?" * len(req.packet_ids))
    cur = await con.execute(
        f"DELETE FROM packets WHERE recipient_address=? AND ack_token IN ({placeholders})",
        (me, *req.packet_ids),
    )
    await con.commit()
    return {"deleted": cur.rowcount}


@app.delete("/api/account")
async def delete_account(con: aiosqlite.Connection = Depends(db),
                        me: str = Depends(current_address)):
    await con.execute("DELETE FROM users WHERE address=?", (me,))
    await con.execute("DELETE FROM packets WHERE recipient_address=?", (me,))
    await con.execute("DELETE FROM userdata WHERE user_address=?", (me,))
    await con.execute("DELETE FROM history WHERE user_address=?", (me,))
    await con.execute("DELETE FROM recovery_challenges WHERE address=?", (me,))
    await con.commit()
    await ws_hub.drop(me)
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Anhänge (verschlüsselte Blöcke in Einheitsgröße, Zugriff nur über das Token)
# OHNE Anmeldung: das zufällige Token (128 Bit) steht nur im verschlüsselten
# Teil der Nachricht. So kann der Server Absender und Empfänger nicht über den
# Anhang miteinander verknüpfen. Es gibt keinen Besitzer-Eintrag.
# ---------------------------------------------------------------------------
ATTACHMENT_BUCKETS = [262144, 1048576, 4194304, 16777216]   # 256 KB / 1 MB / 4 MB / 16 MB
ATTACHMENT_MAX_BYTES = ATTACHMENT_BUCKETS[-1]
_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


def _check_token(token: str):
    if not _TOKEN_RE.match(token):
        raise HTTPException(400, "invalid token format")


@app.post("/api/attachments")
async def upload_attachment(file: UploadFile = File(...)):
    limit_or_429("upload:global", 900, 3600)
    chunks = []
    size = 0
    while chunk := await file.read(1024 * 1024):
        size += len(chunk)
        if size > ATTACHMENT_MAX_BYTES:
            raise HTTPException(413, "attachment too large (max 16 MB)")
        chunks.append(chunk)
    if size not in ATTACHMENT_BUCKETS:
        raise HTTPException(400, "attachment size not in bucket")
    data = b"".join(chunks)
    del chunks
    token = uuid.uuid4().hex
    today = week_bucket(int(time.time()))
    con = await open_att_db()
    try:
        try:
            free = shutil.disk_usage(BASE_DIR).free
        except OSError:
            free = MIN_FREE_BYTES + size
        if free - size < MIN_FREE_BYTES:
            raise HTTPException(507, "attachment storage full, try again later")
        cur = await con.execute("SELECT COALESCE(SUM(size_bytes),0) AS total FROM blobs")
        total = (await cur.fetchone())["total"]
        if total + size > MAX_UPLOADS_BYTES:
            # Topf voll: die ältesten Anhänge weichen (Reihenfolge der Ablage,
            # keine Zeitangabe nötig). Sie sind in aller Regel längst abgeholt.
            # So kann niemand den Topf auf Wochen blockieren.
            cur = await con.execute("SELECT token, size_bytes FROM blobs ORDER BY rowid ASC")
            for r in await cur.fetchall():
                if total + size <= MAX_UPLOADS_BYTES:
                    break
                await con.execute("DELETE FROM blobs WHERE token=?", (r["token"],))
                total -= r["size_bytes"]
            if total + size > MAX_UPLOADS_BYTES:
                await con.rollback()
                raise HTTPException(507, "attachment storage full, try again later")
        await con.execute(
            "INSERT INTO blobs (token, data, size_bytes, created_day, expires_day) VALUES (?,?,?,?,?)",
            (token, data, size, 0, today + (KEEP_WEEKS + 1) * WEEK),
        )
        await con.commit()
    finally:
        await con.close()
    return {"token": token, "size_bytes": size}


DOWNLOAD_CHUNK = 512 * 1024
DOWNLOAD_MAX_PARALLEL = 16
DOWNLOAD_SEND_TIMEOUT = 60      # so lange darf ein einzelnes Stück beim Client hängen


def _blob_info(token: str):
    con = sqlite3.connect(ATT_DB_PATH, timeout=15)
    try:
        return con.execute("SELECT rowid, size_bytes FROM blobs WHERE token=?", (token,)).fetchone()
    finally:
        con.close()


def _blob_read(rowid: int, offset: int, length: int) -> bytes:
    con = sqlite3.connect(ATT_DB_PATH, timeout=15)
    try:
        with con.blobopen("blobs", "data", rowid, readonly=True) as blob:
            blob.seek(offset)
            return blob.read(length)
    finally:
        con.close()


class BlobResponse(Response):
    """Liefert einen Anhang in Stücken aus. Im Arbeitsspeicher liegt immer nur
    ein Stück, auch wenn der Client nicht liest; hängt er zu lange, wird
    abgebrochen. Der Platz wird erst nach dem letzten Stück wieder frei."""

    def __init__(self, rowid: int, size: int):
        self.rowid = rowid
        self.size = size
        self.status_code = 200
        self.background = None
        self.body = b""
        self.init_headers({
            "content-type": "application/octet-stream",
            "content-length": str(size),
        })

    async def __call__(self, scope, receive, send):
        _INFLIGHT["download"] += 1
        try:
            await send({"type": "http.response.start", "status": 200, "headers": self.raw_headers})
            offset = 0
            while offset < self.size:
                try:
                    chunk = await asyncio.to_thread(_blob_read, self.rowid, offset, DOWNLOAD_CHUNK)
                except Exception:
                    chunk = b""
                if not chunk:
                    break       # inzwischen gelöscht: Verbindung endet vorzeitig
                offset += len(chunk)
                await asyncio.wait_for(
                    send({"type": "http.response.body", "body": chunk, "more_body": True}),
                    timeout=DOWNLOAD_SEND_TIMEOUT,
                )
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        finally:
            _INFLIGHT["download"] -= 1


@app.get("/api/attachments/{token}")
async def get_attachment(token: str):
    _check_token(token)
    if _INFLIGHT["download"] >= DOWNLOAD_MAX_PARALLEL:
        raise HTTPException(503, "busy, try again in a moment")
    info = await asyncio.to_thread(_blob_info, token)
    if not info:
        raise HTTPException(404, "attachment not found")
    return BlobResponse(info[0], info[1])


@app.delete("/api/attachments/{token}")
async def delete_attachment(token: str):
    """Wer das Token kennt (Absender oder Empfänger), darf den Anhang entfernen."""
    _check_token(token)
    con = await open_att_db()
    try:
        cur = await con.execute("DELETE FROM blobs WHERE token=?", (token,))
        await con.commit()
        return {"deleted": cur.rowcount}
    finally:
        await con.close()


# ---------------------------------------------------------------------------
# Verschlüsselte Ablagen je Konto: Kontakte (userdata) und Chat-Verlauf (history)
# Der Server kann weder Inhalt noch Anzahl der Chats oder Nachrichten erkennen,
# nur eine von vier Blockgrößen. Die "version" ist eine ZUFALLSZAHL, kein Zähler:
# sie dient nur dem Schutz vor gegenseitigem Überschreiben und verrät nicht, wie
# oft gespeichert wurde.
# ---------------------------------------------------------------------------
async def _blob_get(con, table: str, me: str):
    cur = await con.execute(
        f"SELECT nonce_b64, ciphertext_b64, version FROM {table} WHERE user_address=?", (me,)
    )
    row = await cur.fetchone()
    if not row:
        return {"version": 0, "nonce_b64": None, "ciphertext_b64": None}
    return {
        "version": row["version"],
        "nonce_b64": row["nonce_b64"],
        "ciphertext_b64": row["ciphertext_b64"],
    }


async def _history_budget_check(con, me: str, new_size: int):
    """Verlaufsablagen haben einen eigenen Gesamt-Topf. Wachsen darf eine Ablage
    nur, solange der Topf nicht voll ist; gleich groß oder kleiner geht immer."""
    cur = await con.execute("SELECT size_bytes FROM history WHERE user_address=?", (me,))
    row = await cur.fetchone()
    old = row["size_bytes"] if row else 0
    if new_size <= old:
        return
    cur = await con.execute("SELECT COALESCE(SUM(size_bytes),0) AS total FROM history")
    total = (await cur.fetchone())["total"]
    if total - old + new_size > MAX_HISTORY_BYTES:
        raise HTTPException(507, "history storage full, try again later")


async def _blob_put(con, table: str, me: str, req: BlobPutReq, allowed_b64_lens: list[int]):
    """Atomarer Schreibvorgang: nur wenn der Client den aktuellen Stand kennt.

    Ein einziges UPDATE mit WHERE version=expected. rowcount=1 heißt OK. Bei
    expected_version=0 folgt ein INSERT; ein doppelter Insert scheitert am
    Primärschlüssel und zählt als Konflikt.
    """
    if len(req.ciphertext_b64) not in allowed_b64_lens:
        raise HTTPException(400, "invalid blob bucket size")
    b64_exact(req.nonce_b64, 12, "nonce")
    b64_valid(req.ciphertext_b64, "ciphertext")
    await ensure_disk_space(con)
    today = 0           # Ablagen tragen keine Zeitangabe
    new_version = secrets.randbits(53) + 1

    cur = await con.execute(
        f"UPDATE {table} SET nonce_b64=?, ciphertext_b64=?, version=?, updated_day=? "
        "WHERE user_address=? AND version=?",
        (req.nonce_b64, req.ciphertext_b64, new_version, today, me, req.expected_version),
    )
    if cur.rowcount == 1:
        await con.commit()
        return {"version": new_version}

    if req.expected_version == 0:
        try:
            await con.execute(
                f"INSERT INTO {table} (user_address, nonce_b64, ciphertext_b64, version, updated_day) "
                "VALUES (?,?,?,?,?)",
                (me, req.nonce_b64, req.ciphertext_b64, new_version, today),
            )
            await con.commit()
            return {"version": new_version}
        except sqlite3.IntegrityError:
            pass

    raise HTTPException(409, "version conflict")


@app.get("/api/userdata")
async def get_userdata(con: aiosqlite.Connection = Depends(db),
                      me: str = Depends(current_address)):
    return await _blob_get(con, "userdata", me)


@app.put("/api/userdata")
async def put_userdata(req: BlobPutReq, con: aiosqlite.Connection = Depends(db),
                      me: str = Depends(current_address)):
    limit_or_429(f"userdata:{me}", 240, 60)
    return await _blob_put(con, "userdata", me, req, USERDATA_BUCKETS_B64)


@app.get("/api/history")
async def get_history(con: aiosqlite.Connection = Depends(db),
                     me: str = Depends(current_address)):
    return await _blob_get(con, "history", me)


@app.put("/api/history")
async def put_history(req: BlobPutReq, con: aiosqlite.Connection = Depends(db),
                     me: str = Depends(current_address)):
    limit_or_429(f"history:{me}", 240, 60)
    if len(req.ciphertext_b64) in HISTORY_BUCKETS_B64:
        await _history_budget_check(con, me, len(req.ciphertext_b64))
    result = await _blob_put(con, "history", me, req, HISTORY_BUCKETS_B64)
    await con.execute("UPDATE history SET size_bytes=? WHERE user_address=?", (len(req.ciphertext_b64), me))
    await con.commit()
    # Andere angemeldete Geräte desselben Kontos sollen den Verlauf nachladen.
    await ws_hub.notify(me, {"type": "history", "version": result["version"]})
    return result


# ---------------------------------------------------------------------------
# Background: Auto-Cleanup
# ---------------------------------------------------------------------------
async def cleanup_loop():
    await asyncio.sleep(60)
    while True:
        con = None
        acon = None
        try:
            today = week_bucket(int(time.time()))
            con = await open_db()
            await con.execute("DELETE FROM packets WHERE created_day < ?", (today - KEEP_WEEKS * WEEK,))
            await con.execute("DELETE FROM recovery_challenges WHERE expires_ts < ?", (int(time.time()),))
            # Alt-Anhänge aus der Zeit vor Phase 1.8 (einzelne Dateien)
            cur = await con.execute("SELECT token, file_path FROM attachments WHERE expires_day < ?", (today,))
            for r in await cur.fetchall():
                try: os.unlink(r["file_path"])
                except OSError: pass
            await con.execute("DELETE FROM attachments WHERE expires_day < ?", (today,))
            await con.commit()
            await (await con.execute("PRAGMA incremental_vacuum")).fetchall()
            await con.commit()
            acon = await open_att_db()
            await acon.execute("DELETE FROM blobs WHERE expires_day < ?", (today,))
            await acon.commit()
            await (await acon.execute("PRAGMA incremental_vacuum")).fetchall()
            await acon.commit()
            limiter.sweep()
        except Exception:
            pass
        finally:
            for c in (con, acon):
                if c is not None:
                    try: await c.close()
                    except Exception: pass
        await asyncio.sleep(3600)


# ---------------------------------------------------------------------------
# WebSocket Hub
# ---------------------------------------------------------------------------
WS_MAX_PER_ADDRESS = 6
WS_MAX_TOTAL = 2000
WS_MAX_PENDING = 100          # verbunden, aber noch nicht angemeldet
WS_AUTH_TIMEOUT = 15
WS_MAX_MSG = 4096


class WSHub:
    """Live-Benachrichtigung. Schlüssel ist immer die Adresse OHNE Präfix."""

    def __init__(self):
        self.conns: dict[str, set[WebSocket]] = {}
        self.lock = asyncio.Lock()
        self.total = 0
        self.pending = 0

    async def connect(self, address: str, ws: WebSocket) -> bool:
        async with self.lock:
            conns = self.conns.setdefault(address, set())
            if len(conns) >= WS_MAX_PER_ADDRESS or self.total >= WS_MAX_TOTAL:
                if not conns:
                    del self.conns[address]
                return False
            conns.add(ws)
            self.total += 1
            return True

    async def disconnect(self, address: str, ws: WebSocket):
        async with self.lock:
            conns = self.conns.get(address)
            if conns and ws in conns:
                conns.discard(ws)
                self.total -= 1
                if not conns:
                    del self.conns[address]

    async def notify(self, address: str, payload: dict):
        for ws in list(self.conns.get(address, ())):
            try:
                await asyncio.wait_for(ws.send_json(payload), timeout=5)
            except Exception:
                pass

    async def drop(self, address: str):
        """Trennt alle Verbindungen einer Adresse (Konto gelöscht / wiederhergestellt)."""
        for ws in list(self.conns.get(address, ())):
            try:
                await asyncio.wait_for(ws.close(code=4001), timeout=5)
            except Exception:
                pass


ws_hub = WSHub()


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """Der Token kommt als erste Nachricht, nicht in der Adresse (dort könnte er
    in Verläufen oder Protokollen landen)."""
    if not host_is_allowed(ws.headers.get("host", "")) or ws_hub.pending >= WS_MAX_PENDING:
        await ws.close(code=4003)
        return
    await ws.accept()
    address = None
    ws_hub.pending += 1
    try:
        first = await asyncio.wait_for(ws.receive_text(), timeout=WS_AUTH_TIMEOUT)
        if len(first) > WS_MAX_MSG:
            raise ValueError("too long")
        msg = json.loads(first)
        if not isinstance(msg, dict) or msg.get("type") != "auth":
            raise ValueError("auth expected")
        address = await address_from_token(str(msg.get("token", "")))
    except Exception:
        address = None
    finally:
        ws_hub.pending -= 1
    if address is None:
        try:
            await ws.close(code=4001)
        except Exception:
            pass
        return
    if not await ws_hub.connect(address, ws):
        try:
            await ws.close(code=4008)
        except Exception:
            pass
        return
    try:
        await ws.send_json({"type": "ready"})
        while True:
            msg = await ws.receive_text()
            if len(msg) > WS_MAX_MSG:
                break
            if msg == "ping":
                await ws.send_text("pong")
    except Exception:
        # Verbindung getrennt, Binärdaten oder sonstiger Fehler: einfach beenden.
        pass
    finally:
        await ws_hub.disconnect(address, ws)
        try:
            await ws.close()
        except Exception:
            pass



# ---------------------------------------------------------------------------
# Static + Index
# ---------------------------------------------------------------------------
@app.get("/")
async def index(request: Request):
    return FileResponse(STATIC / "index.html")


@app.get("/app")
async def app_force(request: Request):
    return FileResponse(STATIC / "index.html")


@app.get("/tor")
async def tor_info(request: Request):
    """Anleitung für den Zugang über den Tor-Browser."""
    return FileResponse(STATIC / "landing.html")


@app.get("/manifest.json")
async def manifest():
    return FileResponse(STATIC / "manifest.json", media_type="application/manifest+json")


@app.get("/sw.js")
async def service_worker():
    return FileResponse(STATIC / "sw.js", media_type="application/javascript")


# ---------------------------------------------------------------------------
# Öffentlicher Beweis (ohne Anmeldung, für jeden einsehbar)
# Zeigt, WIE der Server speichert, WIE VIEL gerade gespeichert ist und WELCHER
# Quelltext gerade läuft. Alles wird aus der echten Datenbank und den echten
# Dateien gelesen, nichts ist von Hand geschrieben.
#
# Wichtig für die Anonymität: Der Bestand wird nur als Momentaufnahme alle
# 10 Minuten gezeigt, als Summen, ohne Zeilen einzelner Konten. Sonst könnte
# jeder durch ständiges Abfragen ablesen, wann ein Konto online ist oder wer
# mit wem schreibt. Wer eine eigene Nachricht prüfen will, braucht deren
# Beweis-Kennung; eine Liste aller Kennungen gibt es nicht.
# ---------------------------------------------------------------------------
PROOF_FILES = [
    "app.py", "README.md", "scripts/update_hashes.py", "EXPECTED_HASHES.json",
    "static/index.html", "static/app.js", "static/crypto.js", "static/bip39.js",
    "static/style.css", "static/landing.html", "static/landing.js",
    "static/proof.html", "static/proof.js", "static/sw.js", "static/manifest.json",
]
REPO_URL = os.environ.get("LEHNO_MESH_REPO_URL", "https://github.com/aliecommerce123-web/lehno-mesh")
PROOF_REFRESH_SECONDS = max(1, int(os.environ.get("LEHNO_MESH_PROOF_REFRESH", "600")))
_proof_snapshot = {"live": None, "packets": {}, "schema": None, "source": None, "config": None}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def proof_id(ephemeral_pub_b64: str, nonce_b64: str, ciphertext_b64: str) -> str:
    """Öffentliche Beweis-Kennung eines Pakets: Hash über genau die gespeicherten
    Felder. Der Absender kann sie selbst nachrechnen, erraten lässt sie sich nicht."""
    return _sha(ephemeral_pub_b64 + "|" + nonce_b64 + "|" + ciphertext_b64)[:24]


def _size_classes(sizes, classes):
    out = {str(c): 0 for c in classes}
    other = 0
    for n in sizes:
        if str(n) in out:
            out[str(n)] += 1
        else:
            other += 1
    if other:
        out["andere"] = other
    return out


def _label_for_removed(name: str) -> str:
    n = name.lower()
    if "ip" in n.split("-") or "forwarded-for" in n or n == "forwarded" or "client-ip" in n or "connecting" in n:
        return "IP-Adresse"
    if "country" in n:
        return "Land"
    if "user-agent" in n or n.startswith("sec-ch"):
        return "Browser- und Gerätekennung"
    if "language" in n:
        return "eingestellte Sprache"
    if "cookie" in n:
        return "Cookies"
    if "referer" in n:
        return "vorher besuchte Seite"
    return "weitere Verbindungsangabe"


async def refresh_proof_snapshot():
    """Liest den Bestand neu ein. Läuft beim Start und danach alle 10 Minuten."""
    con = await open_db()
    try:
        cur = await con.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        main = [{"table": r["name"], "sql": r["sql"]} for r in await cur.fetchall()]

        cur = await con.execute("SELECT substr(address, -4) AS tail FROM users ORDER BY tail LIMIT 5000")
        tails = sorted({"…" + r["tail"] for r in await cur.fetchall()})
        cur = await con.execute("SELECT COUNT(*) AS n, COUNT(DISTINCT created_day) AS d, MAX(created_day) AS m FROM users")
        urow = await cur.fetchone()

        packets = {}
        sizes = []
        cur = await con.execute(
            "SELECT ephemeral_pub_b64, nonce_b64, ciphertext_b64, signature_b64, created_day FROM packets ORDER BY id DESC LIMIT 5000")
        async for r in cur:
            sizes.append(len(r["ciphertext_b64"]))
            packets[proof_id(r["ephemeral_pub_b64"], r["nonce_b64"], r["ciphertext_b64"])] = {
                "stored": True,
                "columns": ["recipient_address", "ephemeral_pub_b64", "nonce_b64", "ciphertext_b64", "signature_b64", "created_day", "ack_token"],
                "ephemeral_pub_sha256": _sha(r["ephemeral_pub_b64"]),
                "nonce_sha256": _sha(r["nonce_b64"]),
                "ciphertext_sha256": _sha(r["ciphertext_b64"]),
                "ciphertext_chars": len(r["ciphertext_b64"]),
                "ciphertext_start": r["ciphertext_b64"][:48] + "…",
                "signature_chars": len(r["signature_b64"] or ""),
                "week_marker": r["created_day"],
                "sender_stored": False,
            }
        cur = await con.execute("SELECT COUNT(*) AS n FROM packets")
        packets_total = (await cur.fetchone())["n"]

        cur = await con.execute("SELECT size_bytes FROM history")
        hist = [r["size_bytes"] for r in await cur.fetchall()]
        cur = await con.execute("SELECT length(ciphertext_b64) AS n FROM userdata")
        udat = [r["n"] for r in await cur.fetchall()]
        cur = await con.execute("SELECT COUNT(*) AS n FROM recovery_challenges WHERE expires_ts > ?", (int(time.time()),))
        recov = (await cur.fetchone())["n"]
    finally:
        await con.close()

    acon = await open_att_db()
    try:
        cur = await acon.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        att_schema = [{"table": r["name"], "sql": r["sql"]} for r in await cur.fetchall()]
        cur = await acon.execute("SELECT size_bytes FROM blobs")
        att = [r["size_bytes"] for r in await cur.fetchall()]
    finally:
        await acon.close()

    files = []
    for name in PROOF_FILES:
        path = BASE_DIR / name
        if path.exists():
            data = path.read_bytes()
            files.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    try:
        expected = json.loads((BASE_DIR / "EXPECTED_HASHES.json").read_text())
    except Exception:
        expected = {}

    removed, log_off = [], False
    try:
        if PROXY_CONFIG_PATH:
            text = Path(PROXY_CONFIG_PATH).read_text()
            start = text.index(CLEARNET_HOST + " {")
            end = text.index("\n}\n", start)
            for line in text[start:end].splitlines():
                line = line.strip()
                if PROXY_REMOVE_PREFIX and line.startswith(PROXY_REMOVE_PREFIX):
                    removed.append(_label_for_removed(line[len(PROXY_REMOVE_PREFIX):].strip()))
                if PROXY_LOG_OFF and line.startswith(PROXY_LOG_OFF):
                    log_off = True
    except Exception:
        pass
    counts = {}
    for lab in removed:
        counts[lab] = counts.get(lab, 0) + 1

    _proof_snapshot["schema"] = {"mesh_db": main, "attachments_db": att_schema}
    _proof_snapshot["packets"] = packets
    _proof_snapshot["source"] = {"repository": REPO_URL, "files": files, "expected_hashes": expected}
    _proof_snapshot["config"] = {
        "removed_before_app": [{"what": k, "entries": v} for k, v in sorted(counts.items())],
        "proxy_log_disabled": log_off,
        "app_access_log_disabled": "--no-access-log" in sys.argv,
    }
    _proof_snapshot["live"] = {
        "refresh_minutes": PROOF_REFRESH_SECONDS // 60,
        "accounts_total": urow["n"],
        "accounts_time_markers": {"different_values": urow["d"], "highest_value": urow["m"] or 0},
        "account_address_ends": tails,
        "waiting_packets_total": packets_total,
        "waiting_packets_by_size": _size_classes(sizes, PAYLOAD_BUCKETS_B64),
        "history_blobs_by_size": _size_classes(hist, HISTORY_BUCKETS_B64),
        "contact_blobs_by_size": _size_classes(udat, USERDATA_BUCKETS_B64),
        "attachments_by_size": _size_classes(att, ATTACHMENT_BUCKETS),
        "running_recoveries_with_expiry": recov,
    }


async def proof_loop():
    while True:
        try:
            await refresh_proof_snapshot()
        except Exception:
            pass
        await asyncio.sleep(PROOF_REFRESH_SECONDS)


def _snap(key: str):
    data = _proof_snapshot.get(key)
    if data is None:
        raise HTTPException(503, "snapshot not ready")
    return data


@app.get("/api/proof/schema")
async def proof_schema():
    return _snap("schema")


@app.get("/api/proof/live")
async def proof_live():
    """Bestand als Summen, Stand der letzten Momentaufnahme (alle 10 Minuten)."""
    return _snap("live")


@app.get("/api/proof/packet/{pid}")
async def proof_packet(pid: constr(pattern=r"^[0-9a-f]{24}$")):
    """Was war bei der letzten Momentaufnahme zu dieser Beweis-Kennung gespeichert?
    Liegt nichts vor, war das Paket schon zugestellt und gelöscht, erst nach der
    Momentaufnahme entstanden, oder die Kennung gab es nie."""
    _snap("live")
    return _proof_snapshot["packets"].get(pid) or {"stored": False}


@app.get("/api/proof/source")
async def proof_source():
    """Der Quelltext, der gerade läuft, mit Prüfsummen."""
    return _snap("source")


@app.get("/api/proof/file")
async def proof_file(name: str):
    limit_or_429("proof:file", 1200, 60)
    if name not in PROOF_FILES:
        raise HTTPException(404, "unknown file")
    path = BASE_DIR / name
    if not path.exists():
        raise HTTPException(404, "unknown file")
    return Response(content=path.read_bytes(), media_type="text/plain; charset=utf-8")


@app.get("/api/proof/config")
async def proof_config():
    """Was laut der echten Einstellung der vorgeschalteten Schleuse entfernt wird,
    bevor eine Anfrage die App erreicht. Nur Bezeichnungen, kein Aufbau."""
    return _snap("config")


@app.get("/beweis")
async def proof_page():
    return FileResponse(STATIC / "proof.html")


app.mount("/s", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/healthz")
async def healthz():
    return {"ok": True}
