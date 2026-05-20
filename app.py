"""lehno-mesh Phase 1.5 - Anonymes E2E-verschluesseltes Messaging (Port 8985).

Aenderungen ggue Phase 1:
- KEINE Usernames mehr. Stattdessen: kryptografische Adresse = base58(sha256(identity_pub)),
  also deterministisch aus dem Public-Key abgeleitet. User waehlt nichts aus, alles random.
- SEALED-SENDER komplett. messages-Tabelle hat KEIN from_address-Feld mehr. Server
  sieht nur "Paket fuer Inbox X", weiss nicht wer Sender ist (Sender steckt im
  verschluesselten Body).
- KEIN /api/contacts (User-Listing entfernt), KEIN User-Count, KEINE Admin-Endpoints.
- Contact-Request-Flag: erste Nachricht von neuem Sender hat `is_contact_request=1`,
  Empfaenger akzeptiert/lehnt clientseitig ab. Server traegt nur das Flag.
- Auto-Delete nach Abholung (per packets DELETE-Endpoint).
- Login per Adresse, nicht per Username.
- Tor-Onion-Service zusaetzlich erreichbar (mesh.onion-Adresse via Caddy oder direkt).
"""
import asyncio
import base64
import hashlib
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import aiosqlite
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import (FastAPI, HTTPException, Depends, UploadFile, File,
                     WebSocket, WebSocketDisconnect, Request)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, constr

BASE_DIR = Path(__file__).resolve().parent
DB_PATH  = BASE_DIR / "mesh.db"
UPLOADS  = BASE_DIR / "uploads"
STATIC   = BASE_DIR / "static"
UPLOADS.mkdir(exist_ok=True)

JWT_SECRET = os.environ.get("LEHNO_MESH_JWT_SECRET") or secrets.token_hex(32)
JWT_ALGO   = "HS256"
JWT_TTL    = 60 * 60 * 24 * 30

# Address-Format: base58 von sha256(identity_pub_raw)[:24] = 24 bytes = ca 33 Zeichen
ADDR_RE = r"^[1-9A-HJ-NP-Za-km-z]{30,50}$"

ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)


# ---------------------------------------------------------------------------
# Base58 (Bitcoin-Alphabet) - keine I/O/l/0 -> verwechslungs-sicher
# ---------------------------------------------------------------------------
_B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58_ALPH[r] + out
    # leading zeros
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


def day_bucket(ts: int) -> int:
    """Reduziert Timestamp auf Tags-Genauigkeit, damit Server keinen Timing-Track hat."""
    return (ts // 86400) * 86400


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
    created_day INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_address TEXT NOT NULL,
    ephemeral_pub_b64 TEXT NOT NULL,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    msg_type TEXT NOT NULL DEFAULT 'text',
    is_contact_request INTEGER NOT NULL DEFAULT 0,
    attachment_id INTEGER,
    created_day INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_packets_recipient ON packets(recipient_address, id);

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_day INTEGER NOT NULL,
    expires_day INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attachments_expires ON attachments(expires_day);
"""


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.commit()
    con.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    cleanup_task = asyncio.create_task(cleanup_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()


app = FastAPI(title="lehno-mesh", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


async def db():
    con = await aiosqlite.connect(DB_PATH)
    con.row_factory = aiosqlite.Row
    try:
        yield con
    finally:
        await con.close()


# ---------------------------------------------------------------------------
# Auth helpers - JWT enthaelt nur die Adresse, keinen Klartext-Username
# ---------------------------------------------------------------------------
def make_jwt(address: str) -> str:
    payload = {
        "sub": address,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_TTL,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def parse_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "invalid token")


async def current_address(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = auth.split(None, 1)[1].strip()
    data = parse_jwt(token)
    return data["sub"]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
AddressStr = constr(pattern=ADDR_RE)


class RegisterReq(BaseModel):
    auth_key_b64: str = Field(..., min_length=8, max_length=200)
    salt_b64: str = Field(..., min_length=8, max_length=80)
    keys_blob_b64: str
    keys_nonce_b64: str
    kek_blob_b64: str
    kek_nonce_b64: str
    identity_pub_b64: str
    signing_pub_b64: str


class LoginInitReq(BaseModel):
    address: AddressStr


class LoginReq(BaseModel):
    address: AddressStr
    auth_key_b64: str


class SendPacketReq(BaseModel):
    recipient_address: AddressStr
    ephemeral_pub_b64: str
    nonce_b64: str
    ciphertext_b64: str
    signature_b64: str
    msg_type: str = "text"
    is_contact_request: bool = False
    attachment_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Endpoints: Auth (Adressen statt Usernames)
# ---------------------------------------------------------------------------
@app.post("/api/register")
async def register(req: RegisterReq, con: aiosqlite.Connection = Depends(db)):
    # Adresse wird deterministisch aus identity_pub abgeleitet, nicht vom User gewaehlt
    address = address_from_identity_pub(req.identity_pub_b64)

    cur = await con.execute("SELECT 1 FROM users WHERE address=?", (address,))
    if await cur.fetchone():
        # Address collision (praktisch unmoeglich) - 409
        raise HTTPException(409, "address collision")

    auth_hash = ph.hash(req.auth_key_b64)
    await con.execute(
        "INSERT INTO users (address, auth_hash, salt_b64, identity_pub_b64, signing_pub_b64, "
        " keys_blob_b64, keys_nonce_b64, kek_blob_b64, kek_nonce_b64, created_day) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (address, auth_hash, req.salt_b64,
         req.identity_pub_b64, req.signing_pub_b64,
         req.keys_blob_b64, req.keys_nonce_b64,
         req.kek_blob_b64, req.kek_nonce_b64,
         day_bucket(int(time.time()))),
    )
    await con.commit()

    return {"address": address, "jwt": make_jwt(address)}


@app.post("/api/login/init")
async def login_init(req: LoginInitReq, con: aiosqlite.Connection = Depends(db)):
    """Salt-Lookup. Bei nicht existenten Adressen: deterministischer Fake-Salt
    damit Enumerieren keinen Info-Leak gibt."""
    cur = await con.execute("SELECT salt_b64 FROM users WHERE address=?", (req.address,))
    row = await cur.fetchone()
    if row:
        return {"salt_b64": row["salt_b64"]}
    fake = hashlib.sha256(f"lehno-mesh-fake-salt-v1.5:{req.address}".encode()).digest()[:16]
    return {"salt_b64": base64.b64encode(fake).decode()}


@app.post("/api/login")
async def login(req: LoginReq, con: aiosqlite.Connection = Depends(db)):
    cur = await con.execute(
        "SELECT address, auth_hash, salt_b64, "
        "       keys_blob_b64, keys_nonce_b64, kek_blob_b64, kek_nonce_b64 "
        "FROM users WHERE address=?", (req.address,)
    )
    user = await cur.fetchone()
    if not user:
        raise HTTPException(401, "invalid credentials")
    try:
        ph.verify(user["auth_hash"], req.auth_key_b64)
    except VerifyMismatchError:
        raise HTTPException(401, "invalid credentials")

    return {
        "address": user["address"],
        "jwt": make_jwt(user["address"]),
        "salt_b64": user["salt_b64"],
        "keys_blob_b64": user["keys_blob_b64"],
        "keys_nonce_b64": user["keys_nonce_b64"],
        "kek_blob_b64": user["kek_blob_b64"],
        "kek_nonce_b64": user["kek_nonce_b64"],
    }


# ---------------------------------------------------------------------------
# Public-Key-Lookup per Adresse (oeffentlich, weil Krypto)
# ---------------------------------------------------------------------------
@app.get("/api/keys/{address}")
async def fetch_keys(address: str, con: aiosqlite.Connection = Depends(db),
                    me: str = Depends(current_address)):
    cur = await con.execute(
        "SELECT identity_pub_b64, signing_pub_b64 FROM users WHERE address=?",
        (address,),
    )
    row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "address not found")
    return {
        "address": address,
        "identity_pub_b64": row["identity_pub_b64"],
        "signing_pub_b64": row["signing_pub_b64"],
    }


# ---------------------------------------------------------------------------
# Packets (sealed sender, kein from-Feld in der DB)
# ---------------------------------------------------------------------------
@app.post("/api/packets")
async def send_packet(req: SendPacketReq, con: aiosqlite.Connection = Depends(db),
                     me: str = Depends(current_address)):
    # Auth-Token bestaetigt nur "ich existiere", nicht "ich bin der Sender dieses Pakets".
    # Sender-Identitaet steckt im verschluesselten Body.
    cur = await con.execute("SELECT 1 FROM users WHERE address=?", (req.recipient_address,))
    if not await cur.fetchone():
        raise HTTPException(404, "recipient not found")

    cur = await con.execute(
        "INSERT INTO packets (recipient_address, ephemeral_pub_b64, nonce_b64, "
        " ciphertext_b64, signature_b64, msg_type, is_contact_request, attachment_id, created_day) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (req.recipient_address, req.ephemeral_pub_b64, req.nonce_b64,
         req.ciphertext_b64, req.signature_b64, req.msg_type,
         1 if req.is_contact_request else 0, req.attachment_id,
         day_bucket(int(time.time()))),
    )
    packet_id = cur.lastrowid
    await con.commit()

    await ws_hub.notify(req.recipient_address, {"type": "new_packet", "packet_id": packet_id})
    return {"packet_id": packet_id}


@app.get("/api/packets/inbox")
async def inbox(since_id: int = 0,
                con: aiosqlite.Connection = Depends(db),
                me: str = Depends(current_address)):
    """Eigene Inbox abrufen. Server prueft JWT-Adresse = recipient_address."""
    cur = await con.execute(
        "SELECT id, ephemeral_pub_b64, nonce_b64, ciphertext_b64, signature_b64, "
        "       msg_type, is_contact_request, attachment_id, created_day "
        "FROM packets WHERE recipient_address=? AND id > ? ORDER BY id ASC",
        (me, since_id),
    )
    rows = await cur.fetchall()
    return {
        "packets": [
            {
                "id": r["id"],
                "ephemeral_pub_b64": r["ephemeral_pub_b64"],
                "nonce_b64": r["nonce_b64"],
                "ciphertext_b64": r["ciphertext_b64"],
                "signature_b64": r["signature_b64"],
                "msg_type": r["msg_type"],
                "is_contact_request": bool(r["is_contact_request"]),
                "attachment_id": r["attachment_id"],
                "created_day": r["created_day"],
            }
            for r in rows
        ]
    }


@app.delete("/api/packets/{packet_id}")
async def delete_packet(packet_id: int, con: aiosqlite.Connection = Depends(db),
                       me: str = Depends(current_address)):
    """User loescht selbst Pakete aus seiner Inbox (nach Abholung+Entschluesselung)."""
    cur = await con.execute(
        "DELETE FROM packets WHERE id=? AND recipient_address=?",
        (packet_id, me),
    )
    await con.commit()
    return {"deleted": cur.rowcount}


@app.post("/api/packets/ack")
async def ack_packets(packet_ids: list[int], con: aiosqlite.Connection = Depends(db),
                     me: str = Depends(current_address)):
    """Batch-Delete fuer abgeholte Pakete."""
    if not packet_ids:
        return {"deleted": 0}
    placeholders = ",".join("?" * len(packet_ids))
    cur = await con.execute(
        f"DELETE FROM packets WHERE recipient_address=? AND id IN ({placeholders})",
        (me, *packet_ids),
    )
    await con.commit()
    return {"deleted": cur.rowcount}


@app.delete("/api/account")
async def delete_account(con: aiosqlite.Connection = Depends(db),
                        me: str = Depends(current_address)):
    """Komplettes Self-Delete. Account, eigene Pakete, encrypted_keys - weg."""
    await con.execute("DELETE FROM users WHERE address=?", (me,))
    await con.execute("DELETE FROM packets WHERE recipient_address=?", (me,))
    await con.commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Attachments (encrypted blobs, Server entschluesselt nicht)
# ---------------------------------------------------------------------------
ATTACHMENT_TTL_DAYS = 30


@app.post("/api/attachments")
async def upload_attachment(file: UploadFile = File(...),
                           me: str = Depends(current_address),
                           con: aiosqlite.Connection = Depends(db)):
    file_id = uuid.uuid4().hex
    fpath = UPLOADS / file_id
    size = 0
    with open(fpath, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            f.write(chunk)
            size += len(chunk)
    today = day_bucket(int(time.time()))
    cur = await con.execute(
        "INSERT INTO attachments (file_path, size_bytes, created_day, expires_day) VALUES (?,?,?,?)",
        (str(fpath), size, today, today + ATTACHMENT_TTL_DAYS * 86400),
    )
    await con.commit()
    return {"attachment_id": cur.lastrowid, "size_bytes": size}


@app.get("/api/attachments/{att_id}")
async def get_attachment(att_id: int, con: aiosqlite.Connection = Depends(db),
                        me: str = Depends(current_address)):
    cur = await con.execute("SELECT file_path FROM attachments WHERE id=?", (att_id,))
    row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "attachment not found")
    return FileResponse(row["file_path"], media_type="application/octet-stream")


# ---------------------------------------------------------------------------
# Background: Auto-Cleanup
# ---------------------------------------------------------------------------
async def cleanup_loop():
    """Loescht abgelaufene Attachments + Pakete aelter als 30 Tage falls nie abgeholt."""
    await asyncio.sleep(60)
    while True:
        try:
            con = await aiosqlite.connect(DB_PATH)
            con.row_factory = aiosqlite.Row
            today = day_bucket(int(time.time()))
            # Pakete: nach 30 Tagen weg, egal ob abgeholt oder nicht
            await con.execute(
                "DELETE FROM packets WHERE created_day < ?",
                (today - 30 * 86400,),
            )
            # Attachments: nach expires_day
            cur = await con.execute("SELECT id, file_path FROM attachments WHERE expires_day < ?", (today,))
            expired = await cur.fetchall()
            for r in expired:
                try: os.unlink(r["file_path"])
                except FileNotFoundError: pass
            await con.execute("DELETE FROM attachments WHERE expires_day < ?", (today,))
            await con.commit()
            await con.close()
        except Exception as e:
            pass
        await asyncio.sleep(3600)


# ---------------------------------------------------------------------------
# WebSocket Hub (sealed sender, keine User-Info im Push)
# ---------------------------------------------------------------------------
class WSHub:
    def __init__(self):
        self.conns: dict[str, set[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, address: str, ws: WebSocket):
        async with self.lock:
            self.conns.setdefault(address, set()).add(ws)

    async def disconnect(self, address: str, ws: WebSocket):
        async with self.lock:
            if address in self.conns:
                self.conns[address].discard(ws)
                if not self.conns[address]:
                    del self.conns[address]

    async def notify(self, address: str, payload: dict):
        for ws in list(self.conns.get(address, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                pass


ws_hub = WSHub()


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str = ""):
    if not token:
        await ws.close(code=4001)
        return
    try:
        data = parse_jwt(token)
        address = data["sub"]
    except Exception:
        await ws.close(code=4001)
        return
    await ws.accept()
    await ws_hub.connect(address, ws)
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        await ws_hub.disconnect(address, ws)


# ---------------------------------------------------------------------------
# Static + Index
# ---------------------------------------------------------------------------
@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/manifest.json")
async def manifest():
    return FileResponse(STATIC / "manifest.json", media_type="application/manifest+json")


@app.get("/sw.js")
async def service_worker():
    return FileResponse(STATIC / "sw.js", media_type="application/javascript")


app.mount("/s", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/healthz")
async def healthz():
    return {"ok": True}
