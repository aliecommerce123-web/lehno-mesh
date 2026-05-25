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
"""
import asyncio
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
import uuid
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


def day_bucket(ts: int) -> int:
    return (ts // 86400) * 86400


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
"""


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    # Migration: jwt_min_iat-Spalte zu existierenden Phase-1.6-DBs hinzufuegen.
    try:
        con.execute("ALTER TABLE users ADD COLUMN jwt_min_iat INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # Spalte existiert bereits
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
# Auth helpers
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
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid token")


async def current_address(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = auth.split(None, 1)[1].strip()
    data = parse_jwt(token)
    addr = data["sub"]
    iat = int(data.get("iat", 0))
    # JWT-Revocation: nach Recovery wird jwt_min_iat hochgesetzt, alte Token
    # mit iat < jwt_min_iat sind ungueltig. Einmaliger DB-Lookup pro Request.
    con = await aiosqlite.connect(DB_PATH)
    con.row_factory = aiosqlite.Row
    try:
        cur = await con.execute(
            "SELECT jwt_min_iat FROM users WHERE address=?",
            (normalize_address(addr),),
        )
        row = await cur.fetchone()
    finally:
        await con.close()
    if row and iat < row["jwt_min_iat"]:
        raise HTTPException(401, "token revoked")
    return addr


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


class RecoverInitReq(BaseModel):
    address: AddressStr


class RecoverFinalizeReq(BaseModel):
    address: AddressStr
    challenge_hex: str = Field(..., min_length=32, max_length=128)
    signature_b64: str
    new_auth_key_b64: str = Field(..., min_length=8, max_length=200)
    new_salt_b64: str = Field(..., min_length=8, max_length=80)
    new_kek_blob_b64: str
    new_kek_nonce_b64: str


class UserdataPutReq(BaseModel):
    nonce_b64: str = Field(..., min_length=8, max_length=40)
    ciphertext_b64: str = Field(..., min_length=1, max_length=200_000)
    expected_version: int = Field(..., ge=0)


# ---------------------------------------------------------------------------
# Auth-Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/register")
async def register(req: RegisterReq, con: aiosqlite.Connection = Depends(db)):
    address = address_from_identity_pub(req.identity_pub_b64)

    cur = await con.execute("SELECT 1 FROM users WHERE address=?", (address,))
    if await cur.fetchone():
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

    pretty = pretty_address(address)
    return {"address": pretty, "jwt": make_jwt(pretty)}


@app.post("/api/login/init")
async def login_init(req: LoginInitReq, con: aiosqlite.Connection = Depends(db)):
    addr = normalize_address(req.address)
    cur = await con.execute("SELECT salt_b64 FROM users WHERE address=?", (addr,))
    row = await cur.fetchone()
    if row:
        return {"salt_b64": row["salt_b64"]}
    fake = hashlib.sha256(f"lehno-mesh-fake-salt-v1.6:{addr}".encode()).digest()[:16]
    return {"salt_b64": base64.b64encode(fake).decode()}


@app.post("/api/login")
async def login(req: LoginReq, con: aiosqlite.Connection = Depends(db)):
    addr = normalize_address(req.address)
    cur = await con.execute(
        "SELECT address, auth_hash, salt_b64, "
        "       keys_blob_b64, keys_nonce_b64, kek_blob_b64, kek_nonce_b64 "
        "FROM users WHERE address=?", (addr,)
    )
    user = await cur.fetchone()
    if not user:
        raise HTTPException(401, "invalid credentials")
    try:
        ph.verify(user["auth_hash"], req.auth_key_b64)
    except VerifyMismatchError:
        raise HTTPException(401, "invalid credentials")

    pretty = pretty_address(user["address"])
    return {
        "address": pretty,
        "jwt": make_jwt(pretty),
        "salt_b64": user["salt_b64"],
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

    Damit kann jeder fuer jede Adresse einen Recovery-Versuch starten - das
    ist OK, weil der naechste Schritt (finalize) eine gueltige Signatur mit
    dem privaten Signing-Key des Accounts braucht. Ohne den Mnemonic ist
    der Signing-Key nicht zugaenglich.
    """
    addr = normalize_address(req.address)
    cur = await con.execute(
        "SELECT keys_blob_b64, keys_nonce_b64, identity_pub_b64 FROM users WHERE address=?",
        (addr,),
    )
    row = await cur.fetchone()
    if not row:
        # Anti-Enumeration: Fake-Response in EXAKT der Form/Laenge eines echten
        # Accounts. identity_pub_b64 ist immer 88 chars (65 raw bytes), keys_nonce
        # 16 chars (12 raw), keys_blob variabel je nach Bundle (real: 268 oder
        # 640 b64-chars; wir nehmen 640 als Worst-Case, weil reine Existenz-
        # Pruefung sonst weiter Side-Channel waere).
        seed = hashlib.sha256(f"lehno-mesh-fake-keys:{addr}".encode()).digest()
        # Deterministisch 480 random-aussehende Bytes -> 640 b64-chars
        fake_keys_raw = b"".join(
            hashlib.sha256(seed + i.to_bytes(2, "big")).digest() for i in range(15)
        )[:480]
        fake_identity_pub_raw = (b"\x04" + hashlib.sha512(seed + b":ipub").digest())  # 65 bytes
        fake_nonce_raw = hashlib.sha256(seed + b":nonce").digest()[:12]
        return {
            "keys_blob_b64": base64.b64encode(fake_keys_raw).decode(),
            "keys_nonce_b64": base64.b64encode(fake_nonce_raw).decode(),
            "identity_pub_b64": base64.b64encode(fake_identity_pub_raw).decode(),
            "challenge_hex": secrets.token_hex(32),
        }

    challenge_hex = secrets.token_hex(32)
    expires = int(time.time()) + RECOVERY_TTL
    # Pro Adresse nur EINE aktive Challenge: alte loeschen, dann neue einfuegen.
    # Verhindert Storage-DoS durch Recovery-Init-Flood.
    await con.execute("DELETE FROM recovery_challenges WHERE address=?", (addr,))
    await con.execute(
        "INSERT INTO recovery_challenges (challenge_hex, address, expires_ts) VALUES (?,?,?)",
        (challenge_hex, addr, expires),
    )
    await con.execute("DELETE FROM recovery_challenges WHERE expires_ts < ?", (int(time.time()),))
    await con.commit()

    return {
        "keys_blob_b64": row["keys_blob_b64"],
        "keys_nonce_b64": row["keys_nonce_b64"],
        "identity_pub_b64": row["identity_pub_b64"],
        "challenge_hex": challenge_hex,
    }


def _verify_ecdsa_p256(signing_pub_raw: bytes, signature_raw: bytes, data: bytes) -> bool:
    """Verifiziert eine WebCrypto-ECDSA-P-256-Signatur (P1363, 64 bytes = R||S).

    Cryptography-Lib erwartet DSS-DER, also umpacken.
    """
    if len(signature_raw) != 64:
        return False
    r = int.from_bytes(signature_raw[:32], "big")
    s = int.from_bytes(signature_raw[32:], "big")
    if r == 0 or s == 0:
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), signing_pub_raw)
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        dss_sig = encode_dss_signature(r, s)
        pub.verify(dss_sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


@app.post("/api/recover/finalize")
async def recover_finalize(req: RecoverFinalizeReq, con: aiosqlite.Connection = Depends(db)):
    """Schliesst Recovery ab. Setzt neuen auth_hash, salt, encrypted_kek.

    Der keys_blob bleibt unveraendert (die Identity- und Signing-Privatkeys
    aendern sich nicht, nur die Verschluesselung des KEK).
    """
    addr = normalize_address(req.address)

    cur = await con.execute(
        "SELECT address FROM recovery_challenges WHERE challenge_hex=? AND address=? AND expires_ts > ?",
        (req.challenge_hex, addr, int(time.time())),
    )
    chal = await cur.fetchone()
    if not chal:
        raise HTTPException(400, "invalid or expired challenge")

    cur = await con.execute(
        "SELECT signing_pub_b64 FROM users WHERE address=?",
        (addr,),
    )
    user = await cur.fetchone()
    if not user:
        raise HTTPException(404, "account not found")

    try:
        signing_pub_raw = base64.b64decode(user["signing_pub_b64"])
        signature_raw = base64.b64decode(req.signature_b64)
    except Exception:
        raise HTTPException(400, "invalid base64")

    # Signiert wird "lehno-mesh-recovery-v1:" + challenge_hex
    data_to_verify = b"lehno-mesh-recovery-v1:" + req.challenge_hex.encode()
    if not _verify_ecdsa_p256(signing_pub_raw, signature_raw, data_to_verify):
        raise HTTPException(400, "signature invalid")

    new_auth_hash = ph.hash(req.new_auth_key_b64)
    now_ts = int(time.time())
    # jwt_min_iat hochsetzen invalidiert alle JWTs die VOR jetzt ausgegeben wurden.
    # Schuetzt den Recovery-Use-Case (gestohlenes Geraet): ein vom Angreifer
    # bereits geklauter Token ist nach erfolgreicher Recovery sofort ungueltig.
    await con.execute(
        "UPDATE users SET auth_hash=?, salt_b64=?, kek_blob_b64=?, kek_nonce_b64=?, jwt_min_iat=? "
        "WHERE address=?",
        (new_auth_hash, req.new_salt_b64, req.new_kek_blob_b64, req.new_kek_nonce_b64, now_ts, addr),
    )
    await con.execute("DELETE FROM recovery_challenges WHERE challenge_hex=?", (req.challenge_hex,))
    await con.commit()

    pretty = pretty_address(addr)
    return {"address": pretty, "jwt": make_jwt(pretty)}


# ---------------------------------------------------------------------------
# Public-Key-Lookup per Adresse
# ---------------------------------------------------------------------------
@app.get("/api/keys/{address:path}")
async def fetch_keys(address: str, con: aiosqlite.Connection = Depends(db),
                    me: str = Depends(current_address)):
    addr = normalize_address(address)
    cur = await con.execute(
        "SELECT identity_pub_b64, signing_pub_b64 FROM users WHERE address=?",
        (addr,),
    )
    row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "address not found")
    return {
        "address": pretty_address(addr),
        "identity_pub_b64": row["identity_pub_b64"],
        "signing_pub_b64": row["signing_pub_b64"],
    }


# ---------------------------------------------------------------------------
# Packets (sealed sender, zero metadata - nur Empfaenger + Ciphertext)
# ---------------------------------------------------------------------------
@app.post("/api/packets")
async def send_packet(req: SendPacketReq, con: aiosqlite.Connection = Depends(db),
                     me: str = Depends(current_address)):
    recipient = normalize_address(req.recipient_address)
    cur = await con.execute("SELECT 1 FROM users WHERE address=?", (recipient,))
    if not await cur.fetchone():
        raise HTTPException(404, "recipient not found")

    # Padding-Bucket-Validation: Ciphertext-Laenge muss EXAKT einer erlaubten
    # Bucket-Groesse entsprechen. Damit kann der Server nicht aus Nachrichten-
    # Groessen auf Inhalt/Typ schliessen.
    ct_len = len(req.ciphertext_b64)
    if ct_len not in PAYLOAD_BUCKETS_B64:
        raise HTTPException(
            400,
            f"invalid payload bucket size (got {ct_len}, expected one of {PAYLOAD_BUCKETS_B64})",
        )

    cur = await con.execute(
        "INSERT INTO packets (recipient_address, ephemeral_pub_b64, nonce_b64, "
        " ciphertext_b64, signature_b64, created_day) VALUES (?,?,?,?,?,?)",
        (recipient, req.ephemeral_pub_b64, req.nonce_b64,
         req.ciphertext_b64, req.signature_b64,
         day_bucket(int(time.time()))),
    )
    packet_id = cur.lastrowid
    await con.commit()

    await ws_hub.notify(recipient, {"type": "new_packet", "packet_id": packet_id})
    return {"packet_id": packet_id}


@app.get("/api/packets/inbox")
async def inbox(since_id: int = 0,
                con: aiosqlite.Connection = Depends(db),
                me: str = Depends(current_address)):
    me_norm = normalize_address(me)
    cur = await con.execute(
        "SELECT id, ephemeral_pub_b64, nonce_b64, ciphertext_b64, signature_b64, created_day "
        "FROM packets WHERE recipient_address=? AND id > ? ORDER BY id ASC",
        (me_norm, since_id),
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
                "created_day": r["created_day"],
            }
            for r in rows
        ]
    }


@app.delete("/api/packets/{packet_id}")
async def delete_packet(packet_id: int, con: aiosqlite.Connection = Depends(db),
                       me: str = Depends(current_address)):
    cur = await con.execute(
        "DELETE FROM packets WHERE id=? AND recipient_address=?",
        (packet_id, normalize_address(me)),
    )
    await con.commit()
    return {"deleted": cur.rowcount}


@app.post("/api/packets/ack")
async def ack_packets(packet_ids: list[int], con: aiosqlite.Connection = Depends(db),
                     me: str = Depends(current_address)):
    if not packet_ids:
        return {"deleted": 0}
    placeholders = ",".join("?" * len(packet_ids))
    me_norm = normalize_address(me)
    cur = await con.execute(
        f"DELETE FROM packets WHERE recipient_address=? AND id IN ({placeholders})",
        (me_norm, *packet_ids),
    )
    await con.commit()
    return {"deleted": cur.rowcount}


@app.delete("/api/account")
async def delete_account(con: aiosqlite.Connection = Depends(db),
                        me: str = Depends(current_address)):
    me_norm = normalize_address(me)
    await con.execute("DELETE FROM users WHERE address=?", (me_norm,))
    await con.execute("DELETE FROM packets WHERE recipient_address=?", (me_norm,))
    await con.execute("DELETE FROM userdata WHERE user_address=?", (me_norm,))
    await con.commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Attachments (Token-basiert, Server kennt keinen Owner)
# ---------------------------------------------------------------------------
ATTACHMENT_TTL_DAYS = 30
# Padding-Buckets fuer Attachments: nur diese 4 Groessen sind erlaubt.
# Damit kann der Server nicht mehr aus File-Groessen auf Inhaltstyp
# (Foto/Audio/Video) schliessen.  256 KB / 1 MB / 4 MB / 16 MB.
ATTACHMENT_BUCKETS = [262144, 1048576, 4194304, 16777216]
ATTACHMENT_MAX_BYTES = ATTACHMENT_BUCKETS[-1]


@app.post("/api/attachments")
async def upload_attachment(file: UploadFile = File(...),
                           me: str = Depends(current_address),
                           con: aiosqlite.Connection = Depends(db)):
    token = uuid.uuid4().hex
    fpath = UPLOADS / token
    size = 0
    with open(fpath, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > ATTACHMENT_MAX_BYTES:
                f.close()
                try: os.unlink(fpath)
                except FileNotFoundError: pass
                raise HTTPException(413, "attachment too large (max 16 MB)")
            f.write(chunk)
    # Padding-Bucket-Validation: nur exakte Bucket-Groessen erlaubt.
    if size not in ATTACHMENT_BUCKETS:
        try: os.unlink(fpath)
        except FileNotFoundError: pass
        raise HTTPException(
            400,
            f"attachment size not in bucket (got {size}, expected one of {ATTACHMENT_BUCKETS})",
        )
    today = day_bucket(int(time.time()))
    await con.execute(
        "INSERT INTO attachments (token, file_path, size_bytes, created_day, expires_day) "
        "VALUES (?,?,?,?,?)",
        (token, str(fpath), size, today, today + ATTACHMENT_TTL_DAYS * 86400),
    )
    await con.commit()
    return {"token": token, "size_bytes": size}


@app.get("/api/attachments/{token}")
async def get_attachment(token: str, con: aiosqlite.Connection = Depends(db),
                        me: str = Depends(current_address)):
    if not all(c in "0123456789abcdef" for c in token) or len(token) != 32:
        raise HTTPException(400, "invalid token format")
    cur = await con.execute("SELECT file_path FROM attachments WHERE token=?", (token,))
    row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "attachment not found")
    return FileResponse(row["file_path"], media_type="application/octet-stream")


# ---------------------------------------------------------------------------
# Encrypted Userdata (Spitznamen + Kontaktliste, encrypted blob)
# ---------------------------------------------------------------------------
@app.get("/api/userdata")
async def get_userdata(con: aiosqlite.Connection = Depends(db),
                      me: str = Depends(current_address)):
    cur = await con.execute(
        "SELECT nonce_b64, ciphertext_b64, version FROM userdata WHERE user_address=?",
        (normalize_address(me),),
    )
    row = await cur.fetchone()
    if not row:
        return {"version": 0, "nonce_b64": None, "ciphertext_b64": None}
    return {
        "version": row["version"],
        "nonce_b64": row["nonce_b64"],
        "ciphertext_b64": row["ciphertext_b64"],
    }


@app.put("/api/userdata")
async def put_userdata(req: UserdataPutReq, con: aiosqlite.Connection = Depends(db),
                      me: str = Depends(current_address)):
    """Atomarer optimistic-concurrency PUT.

    Statt SELECT-then-UPDATE (race-condition) machen wir ein einziges UPDATE
    mit WHERE version=expected. rowcount=1 heisst OK, rowcount=0 heisst entweder
    Konflikt oder Insert-Fall. Bei expected_version=0 versuchen wir INSERT mit
    PK-Constraint; doppelter Insert wirft IntegrityError = Konflikt.
    """
    me_norm = normalize_address(me)
    today = day_bucket(int(time.time()))

    # 1) UPDATE-Pfad (Account hat bereits userdata)
    cur = await con.execute(
        "UPDATE userdata SET nonce_b64=?, ciphertext_b64=?, version=version+1, updated_day=? "
        "WHERE user_address=? AND version=?",
        (req.nonce_b64, req.ciphertext_b64, today, me_norm, req.expected_version),
    )
    if cur.rowcount == 1:
        await con.commit()
        return {"version": req.expected_version + 1}

    # 2) Wenn kein UPDATE: entweder INSERT-Fall (expected_version=0, kein Eintrag) oder Konflikt
    if req.expected_version == 0:
        try:
            await con.execute(
                "INSERT INTO userdata (user_address, nonce_b64, ciphertext_b64, version, updated_day) "
                "VALUES (?,?,?,1,?)",
                (me_norm, req.nonce_b64, req.ciphertext_b64, today),
            )
            await con.commit()
            return {"version": 1}
        except sqlite3.IntegrityError:
            pass  # Fallthrough zu 409

    # 3) Konflikt
    cur = await con.execute("SELECT version FROM userdata WHERE user_address=?", (me_norm,))
    row = await cur.fetchone()
    current = row["version"] if row else 0
    raise HTTPException(409, f"version conflict (current={current}, expected={req.expected_version})")


# ---------------------------------------------------------------------------
# Background: Auto-Cleanup
# ---------------------------------------------------------------------------
async def cleanup_loop():
    await asyncio.sleep(60)
    while True:
        try:
            con = await aiosqlite.connect(DB_PATH)
            con.row_factory = aiosqlite.Row
            today = day_bucket(int(time.time()))
            await con.execute(
                "DELETE FROM packets WHERE created_day < ?",
                (today - 30 * 86400,),
            )
            cur = await con.execute("SELECT token, file_path FROM attachments WHERE expires_day < ?", (today,))
            expired = await cur.fetchall()
            for r in expired:
                try: os.unlink(r["file_path"])
                except FileNotFoundError: pass
            await con.execute("DELETE FROM attachments WHERE expires_day < ?", (today,))
            await con.execute("DELETE FROM recovery_challenges WHERE expires_ts < ?", (int(time.time()),))
            await con.commit()
            await con.close()
        except Exception:
            pass
        await asyncio.sleep(3600)


# ---------------------------------------------------------------------------
# WebSocket Hub
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
def _is_onion(request: Request) -> bool:
    host = request.headers.get("host", "").lower()
    return host.endswith(".onion")


@app.get("/")
async def index(request: Request):
    if _is_onion(request):
        return FileResponse(STATIC / "index.html")
    return FileResponse(STATIC / "landing.html")


@app.get("/app")
async def app_force(request: Request):
    if not _is_onion(request):
        return FileResponse(STATIC / "landing.html")
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
