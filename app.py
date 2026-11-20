"""chatmesh Phase 2 - anonymer Messenger ohne Adressen.

Grundidee:
- Es gibt keine Adressen, keine Benutzernamen, keine Passwörter auf dem Server.
- Ein Konto ist ein verschlüsselter Block, der unter einer Zufallskennung liegt.
  Kennung und Schlüssel entstehen im Browser aus 12 Wörtern.
- Alle Nachrichten aller Nutzer liegen als gleich aussehende Blöcke auf EINEM
  gemeinsamen Haufen. Ein Block trägt nur eine Zufallsmarke. Kein Absender,
  kein Empfänger, kein Konto. Welche Blöcke zusammengehören, können nur die
  zwei Geräte ausrechnen, die den Kanal miteinander geöffnet haben.
- Jeder holt den ganzen Haufen (bzw. ganze Reihen davon) ab. Der Server sieht
  nie, für wen ein Block bestimmt ist.
- Löschen darf, wer das Lösch-Geheimnis des Blocks kennt (Absender und
  Empfänger). Auch das läuft ohne Anmeldung.
- Im Hintergrund erzeugen Schein-Nutzer (bots.py) ständig gleich aussehenden
  Verkehr, damit echte Aktivität nicht auffällt.
- Zeit: Der Server speichert keine Uhrzeiten. Blöcke und Anhänge tragen nur die
  Kalenderwoche, damit nie Abgeholtes irgendwann verschwindet.
"""
import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import struct
import sys
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, constr

BASE_DIR = Path(__file__).resolve().parent
DB_PATH  = BASE_DIR / "chatmesh.db"
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
PROXY_BLOCK_END = os.environ.get("LEHNO_MESH_PROXY_BLOCK_END", "")


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


def limit_ok(key: str, limit: int, window: int) -> bool:
    return limiter.allow(key, limit, window)


# ---------------------------------------------------------------------------
# Grenzen: der Dienst darf nie die Platte füllen.
# ---------------------------------------------------------------------------
MIN_FREE_BYTES     = 3 * 1024**3          # darunter wird nichts Neues angenommen
MAX_PILE_BYTES     = 200 * 1024**2        # alle Blöcke auf dem Haufen zusammen
MAX_ACCOUNT_BYTES  = 300 * 1024**2        # alle Konto-Blöcke zusammen
MAX_UPLOADS_BYTES  = 500 * 1024**2        # alle Anhänge zusammen

# Zeit auf dem Server: KEINE Uhrzeiten, keine Tagesangaben. Nur die laufende
# Kalenderwoche wird gemerkt, damit nie Abgeholtes irgendwann verschwindet.
WEEK = 7 * 86400
PILE_KEEP_WEEKS = 1     # Blöcke: 1 bis 2 Wochen
KEEP_WEEKS = 5          # Anhänge: 5 bis 6 Wochen
# Konten tragen nur einen groben Abschnitt von 4 Wochen (wann zuletzt benutzt).
# Ein Jahr lang nicht benutzte Konten verschwinden, damit der Speicher nie
# dauerhaft mit toten Konten gefüllt werden kann.
ACCOUNT_BUCKET = 4 * WEEK
ACCOUNT_KEEP_BUCKETS = 13


def account_bucket(ts: int) -> int:
    return (ts // ACCOUNT_BUCKET) * ACCOUNT_BUCKET


def week_bucket(ts: int) -> int:
    return (ts // WEEK) * WEEK


# Feste Größen. Ein Block besteht aus Zufallswert (12) + Geheimtext + Prüfwert (16).
BLOCK_PLAIN = [4096, 65536]
BLOCK_BYTES = [p + 28 for p in BLOCK_PLAIN]              # 4124, 65564
ACCOUNT_PLAIN = [8192, 65536, 262144, 1048576, 4194304]
WIPE_PLAIN = [4096, 65536]


def b64_len(nbytes: int) -> int:
    return ((nbytes + 2) // 3) * 4


BLOCK_B64 = [b64_len(n) for n in BLOCK_BYTES]
ACCOUNT_B64 = [b64_len(p + 28) for p in ACCOUNT_PLAIN]
WIPE_B64 = [b64_len(p + 28) for p in WIPE_PLAIN]

# Der Haufen kann später in Reihen geteilt werden (Anfang der Zufallsmarke).
# 0 heißt: eine Reihe, jeder holt alles ab.
BUCKET_HEX = max(0, min(4, int(os.environ.get("LEHNO_MESH_BUCKET_HEX", "0"))))

HEX32 = r"^[0-9a-f]{32}$"
HEX64 = r"^[0-9a-f]{64}$"


def b64_bytes(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, f"invalid base64 in {name}")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Rechenaufgabe
# Der Server kennt keine IP-Adressen und kann deshalb niemanden einzeln bremsen.
# Stattdessen muss jede Einlieferung eine kleine Rechenaufgabe mitbringen: eine
# Zahl, mit der die Prüfsumme über (Gegenstand + Zahl) mit genügend Null-Bits
# beginnt. Im Alltag dauert das Millisekunden. Je voller der Speicher wird,
# desto schwerer wird die Aufgabe: Vollmüllen wird teuer, normales Schreiben nicht.
# ---------------------------------------------------------------------------
WORK_RE = re.compile(r"^[0-9a-f]{16}$")


def work_ok(subject: bytes, work: str, bits: int) -> bool:
    if bits <= 0:
        return True
    if not isinstance(work, str) or not WORK_RE.match(work):
        return False
    digest = hashlib.sha256(subject + bytes.fromhex(work)).digest()
    return int.from_bytes(digest[:8], "big") >> (64 - bits) == 0


def _step(value: float, steps) -> int:
    bits = steps[0][1]
    for limit, b in steps:
        if value >= limit:
            bits = b
    return bits


def _rush(key: str, window: int, steps) -> int:
    """Zuschlag bei Andrang: Je mehr Einlieferungen gerade kommen, desto schwerer
    wird die Aufgabe. So kann niemand alle anderen billig aussperren."""
    return _step(limiter.count(key, window), steps)


def work_bits_pile(size: int) -> int:
    mb = _totals["pile"] / 1048576
    bits = _step(mb, [(0, 12), (16, 16), (32, 19), (64, 22), (110, 24), (150, 26)])
    bits += _rush("pile:post", 60, [(0, 0), (1200, 3), (2400, 6), (4000, 9), (6000, 12)])
    return bits + (4 if size == BLOCK_BYTES[1] else 0)


def work_bits_delete() -> int:
    return 8 + _rush("pile:delete", 60, [(0, 0), (1500, 4), (3000, 8), (5000, 12)])


def work_bits_account(class_index: int = 0, wipe_big: bool = False) -> int:
    fill = _totals["accounts"] / MAX_ACCOUNT_BYTES
    bits = _step(fill, [(0, 17), (0.1, 20), (0.3, 23), (0.5, 26), (0.7, 29)])
    bits += _rush("account:create", 3600, [(0, 0), (150, 3), (400, 6), (900, 9)])
    return bits + 2 * class_index + (2 if wipe_big else 0)


def work_bits_upload(size_index: int) -> int:
    fill = _totals["uploads"] / MAX_UPLOADS_BYTES
    bits = _step(fill, [(0, 16), (0.1, 18), (0.3, 21), (0.5, 24), (0.7, 27)])
    bits += _rush("upload:global", 3600, [(0, 0), (600, 3), (1500, 6), (3000, 9)])
    return bits + 2 * size_index


# ---------------------------------------------------------------------------
# Datenbank
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    auth_hash TEXT NOT NULL,
    wipe_hash TEXT NOT NULL UNIQUE,
    blob TEXT NOT NULL,
    wipe_blob TEXT NOT NULL,
    version INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    wk INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pile (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,
    data BLOB NOT NULL,
    del_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    wk INTEGER NOT NULL
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

_totals = {"pile": 0, "accounts": 0, "uploads": 0}


def init_db():
    for path, schema in ((DB_PATH, SCHEMA), (ATT_DB_PATH, ATT_SCHEMA)):
        con = sqlite3.connect(path)
        # Freie Seiten sollen wieder an das Dateisystem zurückgehen.
        if con.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
            con.execute("PRAGMA auto_vacuum=INCREMENTAL")
            con.execute("VACUUM")
        con.executescript(schema)
        con.commit()
        con.close()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    con = sqlite3.connect(DB_PATH)
    _totals["pile"] = con.execute("SELECT COALESCE(SUM(size_bytes),0) FROM pile").fetchone()[0]
    _totals["accounts"] = con.execute("SELECT COALESCE(SUM(size_bytes),0) FROM accounts").fetchone()[0]
    con.close()
    con = sqlite3.connect(ATT_DB_PATH)
    _totals["uploads"] = con.execute("SELECT COALESCE(SUM(size_bytes),0) FROM blobs").fetchone()[0]
    con.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Keine Verbindungs-Zeilen im Systemprotokoll.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).setLevel(logging.WARNING)
    init_db()
    tasks = [asyncio.create_task(cleanup_loop()), asyncio.create_task(proof_loop())]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()


app = FastAPI(title="chatmesh", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


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


def disk_ok(extra: int = 0) -> bool:
    try:
        return shutil.disk_usage(BASE_DIR).free - extra >= MIN_FREE_BYTES
    except OSError:
        return True


# ---------------------------------------------------------------------------
# Erlaubte Namen + Sicherheits-Header
# ---------------------------------------------------------------------------
_SAFE_HOST_RE = re.compile(r"^[a-z0-9.\-]+(:[0-9]{1,5})?$")

SECURITY_HEADERS = {
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    # Kamera nur für das Scannen eines Kanal-Codes, Mikrofon nur für Sprachnachrichten.
    "Permissions-Policy": "camera=(self), microphone=(self), geolocation=(), payment=(), usb=(), display-capture=()",
    # no-transform: Zwischenstellen sollen Antworten nicht umformen.
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


CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; "
    "manifest-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'; object-src 'none'"
)

MAX_BODY_DEFAULT    = 200 * 1024
MAX_BODY_ACCOUNT    = 6 * 1024 * 1024
MAX_BODY_ATTACHMENT = 17 * 1024 * 1024

# Große Anfragen: nur wenige gleichzeitig und mit Zeitlimit.
_INFLIGHT: dict[str, int] = defaultdict(int)
BIG_ROUTES = {
    # (Methode, Pfad) -> (Zähler, gleichzeitig, Zeitlimit s, Body-Grenze, vorher anmelden?)
    ("PUT", "/api/v2/account"):   ("account", 8, 240, MAX_BODY_ACCOUNT, True),
    ("POST", "/api/attachments"): ("upload", 8, 600, MAX_BODY_ATTACHMENT, False),
}
# Kopfzeilen, mit denen sich das Änderungsdatum von Dateien erfragen ließe.
STRIP_REQUEST_HEADERS = (b"if-modified-since", b"if-none-match", b"if-range", b"range", b"if-unmodified-since")
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
    request.scope["headers"] = [(k, v) for k, v in request.scope["headers"] if k not in STRIP_REQUEST_HEADERS]
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
                name, max_parallel, timeout, _, pre_auth = big
                if pre_auth:
                    # Anmeldung prüfen, BEVOR der große Body gelesen wird.
                    try:
                        await account_from_header(request.headers.get("authorization", ""))
                    except HTTPException as e:
                        resp = _json(e.status_code, str(e.detail))
                elif name == "upload":
                    # Rechenaufgabe prüfen, BEVOR der große Body gelesen wird.
                    try:
                        upload_ticket(request.headers.get("x-work", ""), int(cl))
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
    resp.headers["Content-Security-Policy"] = CSP
    for k in DROP_HEADERS:
        if k in resp.headers:
            del resp.headers[k]
    return resp


class StrictModel(BaseModel):
    # Unbekannte Felder werden abgelehnt (niemand kann Zusatzdaten mitschicken).
    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Konten
# Ein Konto ist für den Server nur: Zufallskennung, Prüfwert des Zugangs,
# Prüfwert der Löschwörter und zwei verschlüsselte Blöcke in fester Größe.
# Kennung und Zugang entstehen im Browser aus den 12 Anmeldewörtern. Der Server
# kann weder die Wörter noch den Inhalt zurückrechnen.
# ---------------------------------------------------------------------------
class AccountCreateReq(StrictModel):
    id: constr(pattern=HEX64)
    auth_hash: constr(pattern=HEX64)
    wipe_hash: constr(pattern=HEX64)
    blob: str = Field(..., min_length=1, max_length=5_700_000)
    wipe_blob: str = Field(..., min_length=1, max_length=90_000)
    work: str = Field("", max_length=16)


class AccountPutReq(StrictModel):
    blob: str = Field(..., min_length=1, max_length=5_700_000)
    wipe_blob: str = Field(..., min_length=1, max_length=90_000)
    expected_version: int = Field(..., ge=1, le=2**62)
    work: str = Field("", max_length=16)


class WipeReq(StrictModel):
    token: constr(pattern=HEX64)


def _check_blobs(blob: str, wipe_blob: str):
    if len(blob) not in ACCOUNT_B64:
        raise HTTPException(400, "invalid account block size")
    if len(wipe_blob) not in WIPE_B64:
        raise HTTPException(400, "invalid wipe block size")
    b64_bytes(blob, "blob")
    b64_bytes(wipe_blob, "wipe_blob")


async def account_from_header(header: str) -> str:
    """Erwartet 'Bearer <kennung>.<zugang>'. Gibt die Kennung zurück."""
    parts = (header or "").split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or "." not in parts[1]:
        raise HTTPException(401, "not signed in")
    acc_id, _, token = parts[1].strip().partition(".")
    if not re.match(HEX64, acc_id) or not re.match(HEX64, token):
        raise HTTPException(401, "not signed in")
    if not limit_ok("account:auth", 60000, 60):
        raise HTTPException(429, "too many requests")
    con = await open_db()
    try:
        cur = await con.execute("SELECT auth_hash FROM accounts WHERE id=?", (acc_id,))
        row = await cur.fetchone()
    finally:
        await con.close()
    expected = row["auth_hash"] if row else "0" * 64
    given = sha256_hex(bytes.fromhex(token))
    # Vergleich in gleichbleibender Zeit, auch wenn es das Konto nicht gibt.
    if not hmac.compare_digest(expected, given) or not row:
        raise HTTPException(401, "not signed in")
    return acc_id


async def current_account(request: Request) -> str:
    return await account_from_header(request.headers.get("authorization", ""))


def new_version() -> int:
    return secrets.randbits(53) + 1


@app.post("/api/v2/account")
async def account_create(req: AccountCreateReq, con: aiosqlite.Connection = Depends(db)):
    _check_blobs(req.blob, req.wipe_blob)
    # Neue Konten beginnen immer in der kleinsten Stufe.
    if len(req.blob) != ACCOUNT_B64[0] or len(req.wipe_blob) != WIPE_B64[0]:
        raise HTTPException(400, "invalid account block size")
    if not work_ok(bytes.fromhex(req.id) + b"a", req.work, work_bits_account()):
        raise HTTPException(428, "more work required")
    if not limit_ok("account:create", 5000, 3600):
        raise HTTPException(429, "too many requests")
    size = len(req.blob) + len(req.wipe_blob)
    if not disk_ok(size) or _totals["accounts"] + size > MAX_ACCOUNT_BYTES:
        raise HTTPException(507, "storage full, try again later")
    version = new_version()
    try:
        await con.execute(
            "INSERT INTO accounts (id, auth_hash, wipe_hash, blob, wipe_blob, version, size_bytes, wk) VALUES (?,?,?,?,?,?,?,?)",
            (req.id, req.auth_hash, req.wipe_hash, req.blob, req.wipe_blob, version, size, account_bucket(int(time.time()))),
        )
        await con.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "exists")
    _totals["accounts"] += size
    return {"version": version}


@app.get("/api/v2/account")
async def account_get(con: aiosqlite.Connection = Depends(db), me: str = Depends(current_account)):
    cur = await con.execute("SELECT blob, version FROM accounts WHERE id=?", (me,))
    row = await cur.fetchone()
    if not row:
        raise HTTPException(401, "not signed in")
    return {"blob": row["blob"], "version": row["version"]}


@app.put("/api/v2/account")
async def account_put(req: AccountPutReq, con: aiosqlite.Connection = Depends(db), me: str = Depends(current_account)):
    """Schreibt den Konto-Block nur, wenn der Client den aktuellen Stand kennt.
    Die Versionsmarke ist eine Zufallszahl, kein Zähler."""
    _check_blobs(req.blob, req.wipe_blob)
    if not limit_ok(f"account:put:{me}", 240, 60):
        raise HTTPException(429, "too many requests")
    size = len(req.blob) + len(req.wipe_blob)
    cur = await con.execute("SELECT size_bytes, length(blob) AS blen, length(wipe_blob) AS wlen FROM accounts WHERE id=?", (me,))
    row = await cur.fetchone()
    old = row["size_bytes"] if row else 0
    if size > old and (not disk_ok(size) or _totals["accounts"] - old + size > MAX_ACCOUNT_BYTES):
        raise HTTPException(507, "storage full, try again later")
    # Wächst das Konto in eine größere Stufe, kostet das einmal eine Rechenaufgabe.
    new_class = ACCOUNT_B64.index(len(req.blob))
    wipe_big = len(req.wipe_blob) == WIPE_B64[1]
    if row and (len(req.blob) > row["blen"] or len(req.wipe_blob) > row["wlen"]):
        mark = new_class * 2 + (1 if wipe_big else 0)
        if not work_ok(bytes.fromhex(me) + b"g" + bytes([mark]), req.work, work_bits_account(new_class, wipe_big)):
            raise HTTPException(428, "more work required")
    version = new_version()
    cur = await con.execute(
        "UPDATE accounts SET blob=?, wipe_blob=?, version=?, size_bytes=?, wk=? WHERE id=? AND version=?",
        (req.blob, req.wipe_blob, version, size, account_bucket(int(time.time())), me, req.expected_version),
    )
    if cur.rowcount != 1:
        raise HTTPException(409, "version conflict")
    await con.commit()
    _totals["accounts"] += size - old
    return {"version": version}


@app.delete("/api/v2/account")
async def account_delete(con: aiosqlite.Connection = Depends(db), me: str = Depends(current_account)):
    cur = await con.execute("DELETE FROM accounts WHERE id=? RETURNING size_bytes", (me,))
    row = await cur.fetchone()
    await con.commit()
    if row:
        _totals["accounts"] -= row["size_bytes"]
    return {"deleted": True}


@app.post("/api/v2/wipe")
async def account_wipe(req: WipeReq, con: aiosqlite.Connection = Depends(db)):
    """Unwiderrufliches Löschen mit den 12 Löschwörtern. Gibt den kleinen
    Lösch-Block zurück (damit das Gerät die Gegenüber benachrichtigen kann) und
    entfernt das Konto sofort. Die Antwort ist immer gleich lang und gleich
    schnell, egal ob es ein passendes Konto gab."""
    started = time.monotonic()
    # Kein enges Limit: das Lösch-Geheimnis hat 256 Bit, Raten ist aussichtslos,
    # und das Löschen im Notfall darf niemand von außen blockieren können.
    if not limit_ok("account:wipe", 20000, 60):
        raise HTTPException(429, "too many requests")
    wipe_hash = sha256_hex(bytes.fromhex(req.token))
    cur = await con.execute("DELETE FROM accounts WHERE wipe_hash=? RETURNING wipe_blob, size_bytes", (wipe_hash,))
    row = await cur.fetchone()
    await con.commit()
    if row:
        _totals["accounts"] -= row["size_bytes"]
        blob = row["wipe_blob"]
        if len(blob) < WIPE_B64[-1]:
            blob = blob + "." * (WIPE_B64[-1] - len(blob))      # Antwort immer gleich lang
        out = {"ok": 1, "wipe_blob": blob}
    else:
        out = {"ok": 0, "wipe_blob": "." * WIPE_B64[-1]}
    rest = 0.08 - (time.monotonic() - started)
    if rest > 0:
        await asyncio.sleep(rest)
    return out


# ---------------------------------------------------------------------------
# Der Haufen
# Jede Nachricht (und jede Schein-Nachricht) ist ein Block in fester Größe mit
# einer Zufallsmarke. Ohne Anmeldung, ohne Absender, ohne Empfänger.
# ---------------------------------------------------------------------------
REPLY_CHARS = 96
REPLY_MIN_SECONDS = 0.05


def _reply(ok: bool, code: int = 200) -> JSONResponse:
    """Immer Status 200 und immer gleich lang: von außen sieht jede Antwort gleich aus."""
    body = {"ok": ok, "code": code, "pad": ""}
    size = len(json.dumps(body, separators=(",", ":")))
    body["pad"] = "x" * max(0, REPLY_CHARS - size)
    return JSONResponse(body)


async def _even(started: float, result):
    rest = REPLY_MIN_SECONDS - (time.monotonic() - started)
    if rest > 0:
        await asyncio.sleep(rest)
    return result


class PilePostReq(StrictModel):
    tag: constr(pattern=HEX32)
    data: str = Field(..., min_length=1, max_length=90_000)
    del_hash: constr(pattern=HEX64)
    work: str = Field("", max_length=16)


class PileDeleteReq(StrictModel):
    tag: constr(pattern=HEX32)
    token: constr(pattern=HEX32)
    work: str = Field("", max_length=16)
    pad: str = Field("", max_length=5600, pattern=r"^x*$")      # nur Füllzeichen


@app.post("/api/v2/pile")
async def pile_post(req: PilePostReq, con: aiosqlite.Connection = Depends(db)):
    started = time.monotonic()
    if len(req.data) not in BLOCK_B64:
        raise HTTPException(400, "invalid block size")
    raw = b64_bytes(req.data, "data")
    if len(raw) not in BLOCK_BYTES:
        raise HTTPException(400, "invalid block size")
    if not work_ok(bytes.fromhex(req.tag) + b"p", req.work, work_bits_pile(len(raw))):
        return await _even(started, _reply(False, 428))
    if not limit_ok("pile:post", 20000, 60):
        return await _even(started, _reply(False, 429))
    if not disk_ok(len(raw)) or _totals["pile"] + len(raw) > MAX_PILE_BYTES:
        return await _even(started, _reply(False, 507))
    try:
        await con.execute(
            "INSERT INTO pile (tag, data, del_hash, size_bytes, wk) VALUES (?,?,?,?,?)",
            (req.tag, raw, req.del_hash, len(raw), week_bucket(int(time.time()))),
        )
        await con.commit()
    except sqlite3.IntegrityError:
        return await _even(started, _reply(False, 409))      # Marke schon vergeben
    _totals["pile"] += len(raw)
    return await _even(started, _reply(True))


@app.post("/api/v2/pile/delete")
async def pile_delete(req: PileDeleteReq, con: aiosqlite.Connection = Depends(db)):
    """Löscht einen Block. Das darf, wer das Lösch-Geheimnis kennt."""
    started = time.monotonic()
    if not work_ok(bytes.fromhex(req.tag) + b"d", req.work, work_bits_delete()):
        return await _even(started, _reply(False, 428))
    if not limit_ok("pile:delete", 20000, 60):
        return await _even(started, _reply(False, 429))
    del_hash = sha256_hex(bytes.fromhex(req.token))
    # Ein einziger Schritt: so kann derselbe Block nie zweimal abgezogen werden.
    cur = await con.execute("DELETE FROM pile WHERE tag=? AND del_hash=? RETURNING size_bytes", (req.tag, del_hash))
    row = await cur.fetchone()
    await con.commit()
    if not row:
        return await _even(started, _reply(False, 404))
    _totals["pile"] -= row["size_bytes"]
    return await _even(started, _reply(True))


PILE_CHUNK_BYTES = 2 * 1024 * 1024


@app.get("/api/v2/pile")
async def pile_get(since: int = 0, b: str = "", con: aiosqlite.Connection = Depends(db)):
    """Liefert alle Blöcke nach einer laufenden Nummer, als Binärstrom:
    je Block: Nummer (8 Bytes) | Marke (16 Bytes) | Länge (4 Bytes) | Block.
    Die laufende Nummer ist nur eine Reihenfolge, keine Uhrzeit.
    Kopfzeile X-Pile: 'weiter' (es gibt noch mehr) oder 'ende', dazu die höchste Nummer."""
    if not limit_ok("pile:get", 40000, 60):
        raise HTTPException(429, "too many requests")
    if since < 0 or since > 2**62:
        raise HTTPException(400, "invalid cursor")
    prefix = b.lower()
    if len(prefix) != BUCKET_HEX or not re.match(r"^[0-9a-f]*$", prefix):
        raise HTTPException(400, "invalid row")
    if prefix:
        cur = await con.execute(
            "SELECT seq, tag, data FROM pile WHERE seq > ? AND tag >= ? AND tag < ? ORDER BY seq ASC LIMIT 2000",
            (since, prefix, prefix + "g"),
        )
    else:
        cur = await con.execute("SELECT seq, tag, data FROM pile WHERE seq > ? ORDER BY seq ASC LIMIT 2000", (since,))
    out = bytearray()
    more = False
    last = since
    async for r in cur:
        data = bytes(r["data"])
        if len(out) + len(data) + 28 > PILE_CHUNK_BYTES and out:
            more = True
            break
        out += struct.pack(">Q", r["seq"]) + bytes.fromhex(r["tag"]) + struct.pack(">I", len(data)) + data
        last = r["seq"]
    cur2 = await con.execute("SELECT COALESCE(MAX(seq),0) AS m FROM pile")
    top = (await cur2.fetchone())["m"]
    resp = Response(content=bytes(out), media_type="application/octet-stream")
    resp.headers["X-Pile"] = ("weiter" if more else "ende") + ":" + str(last) + ":" + str(top)
    return resp


@app.get("/api/v2/config")
async def config():
    """Öffentliche Einstellungen, dazu die gerade geforderte Schwere der Rechenaufgabe."""
    return {
        "row_hex": BUCKET_HEX, "block_bytes": BLOCK_BYTES, "keep_weeks": PILE_KEEP_WEEKS,
        "work": {
            "pile": [work_bits_pile(n) for n in BLOCK_BYTES],
            "delete": work_bits_delete(),
            "account": [work_bits_account(i) for i in range(len(ACCOUNT_B64))],
            "account_wipe_extra": 2,
            "upload": [work_bits_upload(i) for i in range(len(ATTACHMENT_BUCKETS))],
        },
    }


# ---------------------------------------------------------------------------
# Anhänge (verschlüsselte Blöcke in Einheitsgröße, Zugriff nur über das Token)
# OHNE Anmeldung: das zufällige Token (128 Bit) steht nur im verschlüsselten
# Teil der Nachricht. Es gibt keinen Besitzer-Eintrag.
# ---------------------------------------------------------------------------
ATTACHMENT_BUCKETS = [262144, 1048576, 4194304, 16777216]   # 256 KB / 1 MB / 4 MB / 16 MB
ATTACHMENT_MAX_BYTES = ATTACHMENT_BUCKETS[-1]
_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


def _check_token(token: str):
    if not _TOKEN_RE.match(token):
        raise HTTPException(400, "invalid token format")


def upload_ticket(header: str, content_length: int = 0):
    """Kopfzeile X-Work: <Kennung>.<Stufe>.<Zahl>. Die Kennung (128 Bit Zufall)
    wählt das Gerät selbst, sie wird die Kennung des Anhangs. Gibt (Kennung, Stufe) zurück."""
    parts = (header or "").split(".")
    if len(parts) != 3 or not _TOKEN_RE.match(parts[0]) or parts[1] not in ("0", "1", "2", "3"):
        raise HTTPException(428, "more work required")
    index = int(parts[1])
    if content_length and content_length > ATTACHMENT_BUCKETS[index] + 8192:
        raise HTTPException(413, "request too large")
    if not work_ok(bytes.fromhex(parts[0]) + b"u" + bytes([index]), parts[2], work_bits_upload(index)):
        raise HTTPException(428, "more work required")
    return parts[0], index


@app.post("/api/attachments")
async def upload_attachment(request: Request, file: UploadFile = File(...)):
    token, index = upload_ticket(request.headers.get("x-work", ""))
    chunks = []
    size = 0
    while chunk := await file.read(1024 * 1024):
        size += len(chunk)
        if size > ATTACHMENT_BUCKETS[index]:
            raise HTTPException(413, "attachment too large")
        chunks.append(chunk)
    if size != ATTACHMENT_BUCKETS[index]:
        raise HTTPException(400, "attachment size not in bucket")
    limit_or_429("upload:global", 12000, 3600)
    data = b"".join(chunks)
    del chunks
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
        _totals["uploads"] = total
        # Topf voll: nichts Fremdes verdrängen. Liegengebliebenes läuft von selbst ab.
        if total + size > MAX_UPLOADS_BYTES:
            raise HTTPException(507, "attachment storage full, try again later")
        try:
            await con.execute(
                "INSERT INTO blobs (token, data, size_bytes, created_day, expires_day) VALUES (?,?,?,?,?)",
                (token, data, size, 0, today + KEEP_WEEKS * WEEK),
            )
            await con.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "exists")
        _totals["uploads"] = total + size
    finally:
        await con.close()
    return {"token": token, "size_bytes": size}


DOWNLOAD_CHUNK = 512 * 1024
DOWNLOAD_MAX_PARALLEL = 32
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
        cur = await con.execute("DELETE FROM blobs WHERE token=? RETURNING size_bytes", (token,))
        row = await cur.fetchone()
        await con.commit()
        if row:
            _totals["uploads"] = max(0, _totals["uploads"] - row["size_bytes"])
        return {"deleted": 1 if row else 0}
    finally:
        await con.close()


# ---------------------------------------------------------------------------
# Aufräumen im Hintergrund
# ---------------------------------------------------------------------------
async def cleanup_loop():
    await asyncio.sleep(30)
    while True:
        con = None
        acon = None
        try:
            now_wk = week_bucket(int(time.time()))
            con = await open_db()
            await con.execute("DELETE FROM pile WHERE wk < ?", (now_wk - PILE_KEEP_WEEKS * WEEK,))
            await con.execute("DELETE FROM accounts WHERE wk < ?", (account_bucket(int(time.time())) - ACCOUNT_KEEP_BUCKETS * ACCOUNT_BUCKET,))
            await con.commit()
            await (await con.execute("PRAGMA incremental_vacuum")).fetchall()
            await con.commit()
            cur = await con.execute("SELECT COALESCE(SUM(size_bytes),0) AS n FROM pile")
            _totals["pile"] = (await cur.fetchone())["n"]
            cur = await con.execute("SELECT COALESCE(SUM(size_bytes),0) AS n FROM accounts")
            _totals["accounts"] = (await cur.fetchone())["n"]
            acon = await open_att_db()
            await acon.execute("DELETE FROM blobs WHERE expires_day < ?", (now_wk,))
            await acon.commit()
            cur = await acon.execute("SELECT COALESCE(SUM(size_bytes),0) AS n FROM blobs")
            _totals["uploads"] = (await cur.fetchone())["n"]
            await (await acon.execute("PRAGMA incremental_vacuum")).fetchall()
            await acon.commit()
            limiter.sweep()
        except Exception:
            pass
        finally:
            for c in (con, acon):
                if c is not None:
                    try:
                        await c.close()
                    except Exception:
                        pass
        await asyncio.sleep(1800)


# ---------------------------------------------------------------------------
# Öffentlicher Beweis (ohne Anmeldung, für jeden einsehbar)
# Zeigt, WIE der Server speichert, WIE VIEL ungefähr gespeichert ist und WELCHER
# Quelltext gerade läuft. Alles wird aus der echten Datenbank und den echten
# Dateien gelesen. Bewusst nur grobe Summen als Momentaufnahme alle 10 Minuten:
# nichts, woran sich einzelne Nutzer, Kanäle oder Nachrichten erkennen ließen.
# ---------------------------------------------------------------------------
PROOF_FILES = [
    "app.py", "bots.py", "README.md", "scripts/update_hashes.py", "EXPECTED_HASHES.json",
    "static/index.html", "static/app.js", "static/crypto.js", "static/media.js", "static/bip39.js",
    "static/style.css", "static/landing.html", "static/landing.js",
    "static/proof.html", "static/proof.js", "static/manifest.json",
    "static/vendor/jsqr.js", "static/vendor/qrcode.js",
]
REPO_URL = os.environ.get("LEHNO_MESH_REPO_URL", "https://github.com/aliecommerce123-web/lehno-mesh")
PROOF_REFRESH_SECONDS = max(1, int(os.environ.get("LEHNO_MESH_PROOF_REFRESH", "600")))
_proof_snapshot = {"live": None, "schema": None, "source": None, "config": None}


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


def _round_coarse(n: int) -> int:
    """Grobe Zahl (auf Zehner bzw. Hunderter gerundet), damit sich aus kleinen
    Änderungen nichts über einzelne Vorgänge ablesen lässt."""
    if n == 0:
        return 0
    step = 10 if n < 1000 else 100
    # Etwas Zufall dazu: so verrät auch ein Sprung der Zahl keinen einzelnen Vorgang.
    n = max(1, n + secrets.randbelow(2 * step + 1) - step)
    return max(step, int(round(n / step) * step))


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
    con = await open_db()
    try:
        cur = await con.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        main = [{"table": r["name"], "sql": r["sql"]} for r in await cur.fetchall()]
        cur = await con.execute("SELECT size_bytes, COUNT(*) AS n FROM pile GROUP BY size_bytes")
        pile = {str(r["size_bytes"]): _round_coarse(r["n"]) for r in await cur.fetchall()}
        cur = await con.execute("SELECT COUNT(*) AS n FROM accounts")
        accounts = _round_coarse((await cur.fetchone())["n"])
        cur = await con.execute("SELECT COUNT(DISTINCT wk) AS n FROM pile")
        weeks = (await cur.fetchone())["n"]
    finally:
        await con.close()
    acon = await open_att_db()
    try:
        cur = await acon.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        att_schema = [{"table": r["name"], "sql": r["sql"]} for r in await cur.fetchall()]
        cur = await acon.execute("SELECT size_bytes, COUNT(*) AS n FROM blobs GROUP BY size_bytes")
        att = {str(r["size_bytes"]): _round_coarse(r["n"]) for r in await cur.fetchall()}
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
            inside = False
            block = []
            for raw_line in text.splitlines():
                if not inside and raw_line.startswith(CLEARNET_HOST):
                    inside = True
                elif inside and PROXY_BLOCK_END and raw_line == PROXY_BLOCK_END:
                    break
                elif inside:
                    block.append(raw_line)
            for line in block:
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

    _proof_snapshot["schema"] = {"main_db": main, "attachments_db": att_schema}
    _proof_snapshot["source"] = {"repository": REPO_URL, "files": files, "expected_hashes": expected}
    _proof_snapshot["config"] = {
        "removed_before_app": [{"what": k, "entries": v} for k, v in sorted(counts.items())],
        "proxy_log_disabled": log_off,
        "app_access_log_disabled": "--no-access-log" in sys.argv,
        "no_date_header": "--no-date-header" in sys.argv,
    }
    _proof_snapshot["live"] = {
        "refresh_minutes": max(1, PROOF_REFRESH_SECONDS // 60),
        "rounded": True,
        "account_blocks": accounts,
        "pile_blocks_by_size": pile,
        "pile_distinct_week_markers": weeks,
        "attachments_by_size": att,
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
    """Bestand als grobe Summen, Stand der letzten Momentaufnahme."""
    return _snap("live")


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


# ---------------------------------------------------------------------------
# Seiten
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


@app.get("/beweis")
async def proof_page():
    return FileResponse(STATIC / "proof.html")


@app.get("/manifest.json")
async def manifest():
    return FileResponse(STATIC / "manifest.json", media_type="application/manifest+json")


app.mount("/s", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/healthz")
async def healthz():
    return {"ok": True}
