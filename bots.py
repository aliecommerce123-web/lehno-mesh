#!/usr/bin/env python3
"""chatmesh Bots: Schein-Verkehr rund um die Uhr.

Dieses Programm läuft als eigener Dienst neben dem Server. Es benimmt sich wie
eine wechselnde Zahl von Menschen, die chatmesh benutzen: Sie kommen und gehen,
rufen den Haufen ab, legen Blöcke ab, "lesen" sie (= löschen sie wieder),
schicken ab und zu etwas Größeres und speichern ihr Konto. Alles in
unregelmäßigen Abständen, nie im festen Takt.

Wozu: Auch wenn nur wenige echte Menschen online sind, ist auf dem Server
ständig etwas los. Ein Schein-Block ist von einem echten nicht zu unterscheiden:
gleiche Größen, gleiche Wege, gleiche Antworten, gleiche Rechenaufgabe. Dieses
Programm benutzt nur die öffentlichen Schnittstellen, die auch die App benutzt.
Es hat keinen Zugang zur Datenbank und kennt keinen einzigen Schlüssel eines
echten Kontos.

Der Inhalt der Schein-Blöcke ist reiner Zufall. Verschlüsselter Text sieht
genauso aus. Die Bots räumen hinter sich auf und haben feste Obergrenzen: Sie
können den Speicher nicht füllen.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import sys
from pathlib import Path

import httpx

BASE_DIR = Path(__file__).resolve().parent
TARGET = os.environ.get("LEHNO_MESH_BOT_TARGET", "http://127.0.0.1:8000")
HOST = os.environ.get("LEHNO_MESH_BOT_HOST", "localhost").strip().lower()
SEED_PATH = Path(os.environ.get("LEHNO_MESH_BOT_SEED_FILE", str(BASE_DIR / "bots.seed")))
INTENSITY = float(os.environ.get("LEHNO_MESH_BOT_INTENSITY", "1.0"))   # 1.0 = Standard

SMALL, BIG = 4124, 65564                 # Blockgrößen wie in der App
ACCOUNT_PLAIN = [8192, 65536, 262144, 1048576]
WIPE_BYTES = 4096 + 28
ATTACHMENT_SIZES = [262144, 1048576, 4194304, 16777216]
MAX_PENDING = 1500                       # so viele eigene Löschungen stehen höchstens aus
MAX_LINGER = 400                         # so viele Blöcke dürfen ohne Löschung liegen bleiben
MAX_ATTACHMENTS = 2                      # so viele Schein-Anhänge gleichzeitig
MAX_WORK_BITS = 23                       # wird die Rechenaufgabe schwerer, pausieren die Bots
POST_LEN = len(json.dumps({"tag": "0" * 32, "data": "x" * 5500, "del_hash": "0" * 64, "work": "0" * 16}, separators=(",", ":")))

rng = secrets.SystemRandom()
_pending = 0                             # Blöcke, deren Löschung noch aussteht
_linger = 0                              # Blöcke, die bewusst liegen bleiben (laufen beim Server ab)
_attachments = 0


def expo(mean: float, lo: float, hi: float) -> float:
    """Zufällige Wartezeit: meist kurz, manchmal lang (wie bei Menschen)."""
    return max(lo, min(hi, -math.log(1.0 - rng.random()) * mean))


def lognorm(median: float, spread: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, median * math.exp(rng.gauss(0.0, spread))))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def solve(subject: bytes, bits: int) -> str:
    """Rechenaufgabe wie in der App: Zahl suchen, mit der die Prüfsumme mit
    genügend Null-Bits beginnt."""
    if bits <= 0:
        return "0" * 16
    prefix = secrets.token_bytes(4)
    n = 0
    while True:
        nonce = prefix + n.to_bytes(4, "big")
        if int.from_bytes(hashlib.sha256(subject + nonce).digest()[:8], "big") >> (64 - bits) == 0:
            return nonce.hex()
        n += 1
        if n >= 0xFFFFFFF0:
            prefix, n = secrets.token_bytes(4), 0


class Mood:
    """Wie viel gerade los ist. Wandert langsam und zufällig, unabhängig von der Uhr."""

    def __init__(self):
        self.level = 1.0

    async def drift(self):
        while True:
            await asyncio.sleep(expo(240, 30, 1500))
            self.level = max(0.35, min(2.6, self.level * math.exp(rng.gauss(0.0, 0.35))))

    def scale(self, seconds: float) -> float:
        return seconds / (self.level * max(0.1, INTENSITY))


mood = Mood()


class Api:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=TARGET, headers={"host": HOST}, timeout=60.0)
        self.work = {"pile": [12, 16], "delete": 8, "account": [17, 19, 21, 23, 25], "upload": [16, 18, 20, 22]}

    async def load_config(self):
        try:
            r = await self.client.get("/api/v2/config")
            if r.status_code == 200 and isinstance(r.json().get("work"), dict):
                self.work = r.json()["work"]
        except Exception:
            pass

    async def config_loop(self):
        while True:
            await self.load_config()
            await asyncio.sleep(120 + rng.random() * 240)

    async def post_block(self, size: int):
        """Legt einen Block ab. Gibt (Marke, Lösch-Geheimnis) zurück oder None."""
        if _pending >= MAX_PENDING:
            return None
        tag, token = secrets.token_hex(16), secrets.token_hex(16)
        for _ in range(2):
            bits = self.work["pile"][1 if size == BIG else 0]
            if bits > MAX_WORK_BITS:
                return None                # Server ist unter Last: Bots halten sich zurück
            work = await asyncio.to_thread(solve, bytes.fromhex(tag) + b"p", bits)
            body = {"tag": tag, "data": b64(secrets.token_bytes(size)), "del_hash": hashlib.sha256(bytes.fromhex(token)).hexdigest(), "work": work}
            r = await self.client.post("/api/v2/pile", json=body)
            if r.status_code != 200:
                return None
            answer = r.json()
            if answer.get("ok") is True:
                return tag, token
            if answer.get("code") != 428:
                return None
            await self.load_config()
        return None

    async def delete_block(self, tag: str, token: str):
        """Löscht einen eigenen Block. Wiederholt, bis der Server bestätigt, dass er weg ist."""
        for wait in (0, 5, 30, 120, 600):
            if wait:
                await asyncio.sleep(wait)
            try:
                bits = int(self.work.get("delete", 8))
                if bits > MAX_WORK_BITS:
                    continue
                work = await asyncio.to_thread(solve, bytes.fromhex(tag) + b"d", bits)
                base = len(json.dumps({"tag": tag, "token": token, "work": work, "pad": ""}, separators=(",", ":")))
                body = {"tag": tag, "token": token, "work": work, "pad": "x" * max(0, POST_LEN - base)}
                r = await self.client.post("/api/v2/pile/delete", json=body)
                if r.status_code == 200:
                    answer = r.json()
                    if answer.get("ok") is True or answer.get("code") == 404:
                        return
                    if answer.get("code") == 428:
                        await self.load_config()
            except Exception:
                pass

    async def fetch_pile(self, cursor: int) -> int:
        """Ruft den Haufen ab wie die App. Gibt die neue Lesemarke zurück."""
        for _ in range(400):
            r = await self.client.get("/api/v2/pile", params={"since": cursor})
            if r.status_code != 200:
                return cursor
            state = (r.headers.get("x-pile") or "ende:%d:0" % cursor).split(":")
            try:
                cursor = max(cursor, int(state[1]))
            except (IndexError, ValueError):
                return cursor
            if state[0] != "weiter":
                break
        return cursor

    async def upload(self, index: int):
        bits = self.work["upload"][index]
        if bits > MAX_WORK_BITS + 3:
            return None
        token = secrets.token_hex(16)
        work = await asyncio.to_thread(solve, bytes.fromhex(token) + b"u" + bytes([index]), bits)
        r = await self.client.post(
            "/api/attachments",
            headers={"x-work": f"{token}.{index}.{work}"},
            files={"file": ("block.bin", secrets.token_bytes(ATTACHMENT_SIZES[index]), "application/octet-stream")},
        )
        return token if r.status_code == 200 else None

    async def download(self, token: str):
        async with self.client.stream("GET", f"/api/attachments/{token}") as r:
            async for _ in r.aiter_bytes():
                pass

    async def delete_upload(self, token: str):
        for wait in (0, 5, 30, 120):
            if wait:
                await asyncio.sleep(wait)
            try:
                r = await self.client.delete(f"/api/attachments/{token}")
                if r.status_code == 200:
                    return
            except Exception:
                pass


class Account:
    """Ein Schein-Konto. Seine Kennung entsteht aus einer geheimen Zufallsdatei
    neben dem Programm, damit nach einem Neustart dieselben Konten weiterbenutzt
    werden und keine verwaisten Konten zurückbleiben. Wie echte Konten sind die
    meisten klein, manche größer (so, als würden sie Verläufe behalten)."""

    def __init__(self, api: Api, seed: bytes, index: int):
        self.api = api
        d = lambda label: hmac.new(seed, f"{label}|{index}".encode(), hashlib.sha256).digest()
        self.id = d("id").hex()
        self.token = d("auth").hex()
        self.wipe = d("wipe").hex()
        pick = d("size")[0]
        self.wanted = 0 if pick < 150 else (1 if pick < 215 else (2 if pick < 245 else 3))
        self.cls = 0
        self.version = None

    @property
    def auth(self):
        return {"authorization": f"Bearer {self.id}.{self.token}"}

    def blobs(self, cls: int):
        return {"blob": b64(secrets.token_bytes(ACCOUNT_PLAIN[cls] + 28)), "wipe_blob": b64(secrets.token_bytes(WIPE_BYTES))}

    async def ensure(self):
        r = await self.api.client.get("/api/v2/account", headers=self.auth)
        if r.status_code == 200:
            self.version = r.json()["version"]
            raw = len(r.json()["blob"]) * 3 // 4
            self.cls = max([i for i, p in enumerate(ACCOUNT_PLAIN) if p + 28 <= raw + 2] or [0])
            return True
        if r.status_code != 401:
            return False
        bits = self.api.work["account"][0]
        if bits > MAX_WORK_BITS + 3:
            return False
        work = await asyncio.to_thread(solve, bytes.fromhex(self.id) + b"a", bits)
        body = {
            "id": self.id,
            "auth_hash": hashlib.sha256(bytes.fromhex(self.token)).hexdigest(),
            "wipe_hash": hashlib.sha256(bytes.fromhex(self.wipe)).hexdigest(),
            "work": work,
            **self.blobs(0),
        }
        r = await self.api.client.post("/api/v2/account", json=body)
        if r.status_code == 200:
            self.version = r.json()["version"]
            self.cls = 0
            return True
        return False

    async def save(self):
        if self.version is None and not await self.ensure():
            return
        # Manche Konten wachsen mit der Zeit in eine größere Stufe.
        cls = self.cls
        if cls < self.wanted and rng.random() < 0.02:
            cls += 1
        body = {**self.blobs(cls), "expected_version": self.version}
        r = await self.api.client.put("/api/v2/account", headers=self.auth, json=body)
        if r.status_code == 428 and cls > self.cls:
            bits = self.api.work["account"][cls]
            if bits > MAX_WORK_BITS + 3:
                return
            body["work"] = await asyncio.to_thread(solve, bytes.fromhex(self.id) + b"g" + bytes([cls * 2]), bits)
            r = await self.api.client.put("/api/v2/account", headers=self.auth, json=body)
        if r.status_code == 200:
            self.version = r.json()["version"]
            self.cls = cls
        elif r.status_code in (401, 409):
            self.version = None


async def later(delay: float, coro_fn, *args):
    """Führt etwas später aus. Zählt mit, wie viele Löschungen noch ausstehen."""
    global _pending
    _pending += 1
    try:
        await asyncio.sleep(delay)
        await coro_fn(*args)
    except Exception:
        pass
    finally:
        _pending -= 1


async def linger_slot():
    """Ein Block bleibt bewusst liegen. Der Server räumt ihn nach ein bis zwei
    Wochen weg; so lange zählt er hier mit, damit es nie zu viele werden."""
    global _linger
    _linger += 1
    try:
        await asyncio.sleep(14 * 86400)
    finally:
        _linger -= 1


def lifetime() -> float:
    """Wie lange ein Schein-Block liegen bleibt, bis er "gelesen" (gelöscht) wird.
    Meist Sekunden bis Minuten, manchmal Stunden, selten gar nicht (dann räumt
    der Server ihn nach ein bis zwei Wochen selbst weg), wie bei echten Menschen."""
    x = rng.random()
    if x < 0.62:
        return lognorm(9, 0.9, 1.2, 180)
    if x < 0.90:
        return lognorm(150, 1.0, 20, 3600)
    if x < 0.997 or _linger >= MAX_LINGER:
        return lognorm(4 * 3600, 1.0, 1800, 2 * 86400)
    return -1.0


async def person(api: Api, account: Account, tasks: set):
    """Ein Schein-Mensch: kommt, ist eine Weile da, geht wieder."""

    def spawn(coro):
        t = asyncio.ensure_future(coro)
        tasks.add(t)
        t.add_done_callback(tasks.discard)

    def schedule_read(got):
        life = lifetime()
        if life >= 0:
            spawn(later(life, read_block, api, got, spawn))
        else:
            spawn(linger_slot())

    await asyncio.sleep(expo(mood.scale(40), 0, 600))
    while True:
        # --- kommt online: Konto holen, ganzen Haufen laden
        try:
            await account.ensure()
            cursor = await api.fetch_pile(0)
        except Exception:
            await asyncio.sleep(expo(20, 5, 120))
            continue
        loop = asyncio.get_running_loop()
        end = loop.time() + lognorm(420 * mood.level, 1.0, 25, 4 * 3600)
        next_post = expo(mood.scale(25), 1, 600)
        next_save = expo(14, 3.5, 56)
        next_decoy = expo(10, 1.2, 45)
        chatting = 0
        while loop.time() < end:
            step = 0.6 + rng.random() * 1.1           # Abruf wie die App
            await asyncio.sleep(step)
            try:
                cursor = await api.fetch_pile(cursor)
                next_decoy -= step
                if next_decoy <= 0:
                    # Schein-Block der App: kurz da, dann wieder weg
                    next_decoy = expo(10, 1.2, 45)
                    got = await api.post_block(BIG if rng.random() < 0.025 else SMALL)
                    if got:
                        spawn(later(4 + rng.random() * 86, api.delete_block, *got))
                next_post -= step
                if next_post <= 0:
                    # "schreibt" eine Nachricht; in einem Gespräch folgen weitere dicht hintereinander
                    if chatting <= 0:
                        if rng.random() < 0.6:
                            chatting = rng.randint(2, 14)
                        await account.save()          # wie die App vor der ersten Nachricht
                    chatting -= 1
                    next_post = lognorm(7, 0.8, 1.2, 90) if chatting > 0 else expo(mood.scale(70), 3, 1800)
                    got = await api.post_block(BIG if rng.random() < 0.03 else SMALL)
                    if got:
                        schedule_read(got)
                    if rng.random() < 0.012:
                        spawn(send_attachment(api))
                next_save -= step
                if next_save <= 0:
                    next_save = expo(14, 3.5, 56)
                    await account.save()
            except Exception:
                await asyncio.sleep(expo(10, 2, 60))
        # --- geht offline
        try:
            await account.save()
        except Exception:
            pass
        await asyncio.sleep(lognorm(mood.scale(900), 1.2, 20, 10 * 3600))


async def read_block(api: Api, got, spawn):
    """Das "Gegenüber" liest: Block löschen, oft folgt kurz darauf eine Lesebestätigung."""
    await api.delete_block(*got)
    if rng.random() < 0.8:
        await asyncio.sleep(0.05 + rng.random() * 0.6)
        receipt = await api.post_block(SMALL)
        if receipt:
            # Die Bestätigung wird immer wieder entfernt.
            spawn(later(lognorm(60, 1.2, 2, 6 * 3600), api.delete_block, *receipt))


async def send_attachment(api: Api):
    global _attachments
    if _attachments >= MAX_ATTACHMENTS:
        return
    _attachments += 1
    token = None
    try:
        x = rng.random()
        index = 0 if x < 0.70 else (1 if x < 0.90 else (2 if x < 0.975 else 3))
        token = await api.upload(index)
        if not token:
            return
        note = await api.post_block(SMALL)
        await asyncio.sleep(lognorm(40, 1.1, 2, 1800))
        if note:
            await api.delete_block(*note)
        await api.download(token)
        await asyncio.sleep(0.1 + rng.random())
    except Exception:
        pass
    finally:
        # Der Schein-Anhang wird in jedem Fall wieder entfernt.
        try:
            if token:
                await api.delete_upload(token)
        except Exception:
            pass
        _attachments -= 1


def load_seed() -> bytes:
    try:
        raw = SEED_PATH.read_bytes()
        if len(raw) >= 32:
            return raw[:32]
    except OSError:
        pass
    raw = secrets.token_bytes(32)
    SEED_PATH.write_bytes(raw)
    try:
        os.chmod(SEED_PATH, 0o600)
    except OSError:
        pass
    return raw


async def main():
    seed = load_seed()
    # Anzahl der Schein-Menschen: fest je Installation, aus der Zufallsdatei abgeleitet.
    count = 9 + seed[0] % 8
    api = Api()
    # Warten, bis der Server da ist.
    for _ in range(120):
        try:
            r = await api.client.get("/healthz")
            if r.status_code == 200:
                break
        except Exception:
            pass
        await asyncio.sleep(2)
    await api.load_config()
    tasks: set = set()
    people = [person(api, Account(api, seed, i), tasks) for i in range(count)]
    print(f"bots running ({count})", file=sys.stderr)
    await asyncio.gather(mood.drift(), api.config_loop(), *people)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
