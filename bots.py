#!/usr/bin/env python3
"""chatmesh Bots: Schein-Verkehr rund um die Uhr.

Dieses Programm läuft als eigener Dienst neben dem Server. Es benimmt sich wie
eine wechselnde Zahl von Menschen, die chatmesh benutzen: Neue kommen dazu und
legen sich ein Konto an, sie kommen und gehen, rufen den Haufen ab, legen Blöcke
ab, "lesen" sie (= löschen sie wieder), schicken ab und zu etwas Größeres und
speichern ihr Konto. Manche bleiben lange, manche hören nach kurzer Zeit auf,
einige löschen ihr Konto wieder. Alles in unregelmäßigen Abständen.

Wozu: Auch wenn nur wenige echte Menschen da sind, ist auf dem Server ständig
etwas los, und es kommen laufend neue Konten dazu. Ein Schein-Konto und ein
Schein-Block sind von echten nicht zu unterscheiden: gleiche Größen, gleiche
Wege, gleiche Antworten, gleiche Rechenaufgabe.

Wichtig: Dieses Programm merkt sich NICHTS dauerhaft. Die Zugänge der
Schein-Konten liegen nur im Arbeitsspeicher. Es gibt keine Liste und keine
Datei, aus der sich später ablesen ließe, welches Konto ein Schein-Konto ist,
auch nicht für den Betreiber. Nach einem Neustart fängt das Programm mit neuen
Konten an; die alten sehen dann aus wie Konten von Menschen, die nicht
wiedergekommen sind, und verschwinden wie diese nach einem Jahr.

Das Programm benutzt nur die öffentlichen Schnittstellen, die auch die App
benutzt. Es hat keinen Zugang zur Datenbank und kennt keinen Schlüssel eines
echten Kontos. Es räumt hinter sich auf und hat feste Obergrenzen.
"""
import asyncio
import base64
import hashlib
import json
import math
import os
import secrets
import sys
from collections import deque

import httpx

TARGET = os.environ.get("LEHNO_MESH_BOT_TARGET", "http://127.0.0.1:8000")
HOST = os.environ.get("LEHNO_MESH_BOT_HOST", "localhost").strip().lower()
INTENSITY = float(os.environ.get("LEHNO_MESH_BOT_INTENSITY", "1.0"))   # 1.0 = Standard

SMALL, BIG = 4124, 65564                 # Blockgrößen wie in der App
ACCOUNT_PLAIN = [8192, 65536, 262144, 1048576]
WIPE_PLAIN = [4096, 65536]
ATTACHMENT_SIZES = [262144, 1048576, 4194304, 16777216]
MAX_PENDING = 1500                       # so viele eigene Löschungen stehen höchstens aus
MAX_LINGER = 400                         # so viele Blöcke dürfen ohne Löschung liegen bleiben
MAX_ATTACHMENTS = 2                      # so viele Schein-Anhänge gleichzeitig unterwegs
MAX_LINGER_ATTACHMENTS = 30              # so viele kleine Schein-Anhänge dürfen liegen bleiben
MAX_WORK_BITS = 24                       # wird die Rechenaufgabe schwerer, pausieren die Bots (wie die Schein-Blöcke der App)
CLIENT_VER = 1            # dieselbe Fassungs-Angabe wie die App

PEOPLE_MIN, PEOPLE_MAX = 5, 24           # so viele Schein-Menschen gibt es gleichzeitig
NEW_PER_DAY_MAX = 6                      # mehr neue Schein-Konten entstehen nie an einem Tag
POST_LEN = len(json.dumps({"tag": "0" * 32, "data": "x" * 5500, "del_hash": "0" * 64, "work": "0" * 16}, separators=(",", ":")))

rng = secrets.SystemRandom()
_pending = 0                             # Blöcke, deren Löschung noch aussteht
_linger = 0                              # Blöcke, die bewusst liegen bleiben (laufen beim Server ab)
_attachments = 0
_linger_attachments = 0
_people = 0                              # Schein-Menschen, die es gerade gibt
_created = deque()                       # Zeitpunkte der letzten Konto-Anlagen (nur im Arbeitsspeicher)


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
        self.work = {"salt": "", "pile": [12, 16], "delete": 8, "account": [17, 19, 21, 23, 25], "upload": [16, 18, 20, 22]}

    def subject(self, raw: bytes) -> bytes:
        """Gegenstand der Rechenaufgabe: aktuelles Salz des Servers + Kennung + Art."""
        return bytes.fromhex(self.work.get("salt") or "") + raw

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
            work = await asyncio.to_thread(solve, self.subject(bytes.fromhex(tag) + b"p"), bits)
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
                work = await asyncio.to_thread(solve, self.subject(bytes.fromhex(tag) + b"d"), bits)
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
        work = await asyncio.to_thread(solve, self.subject(bytes.fromhex(token) + b"u" + bytes([index])), bits)
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
    """Ein Schein-Konto. Kennung und Zugänge sind reiner Zufall und liegen nur im
    Arbeitsspeicher dieses Programms. Wie echte Konten sind die meisten klein,
    manche wachsen (so, als würden sie Verläufe behalten)."""

    def __init__(self, api: Api):
        self.api = api
        self.id = secrets.token_hex(32)
        self.token = secrets.token_hex(32)
        self.wipe = secrets.token_hex(32)
        pick = rng.random()
        self.wanted = 0 if pick < 0.90 else (1 if pick < 0.975 else (2 if pick < 0.995 else 3))
        self.wipe_wanted = 1 if rng.random() < 0.02 else 0
        self.cls = 0
        self.wcls = 0
        self.version = None
        self.gone = False

    @property
    def auth(self):
        return {"authorization": f"Bearer {self.id}.{self.token}"}

    def blobs(self, cls: int, wcls: int = 0):
        return {"blob": b64(secrets.token_bytes(ACCOUNT_PLAIN[cls] + 28)), "wipe_blob": b64(secrets.token_bytes(WIPE_PLAIN[wcls] + 28))}

    def save_pause(self) -> float:
        """Abstand bis zum nächsten Speichern, wie in der App: große Konten seltener."""
        mean = 14 if self.cls == 0 else (45 if self.cls == 1 else 120)
        return expo(mean, mean / 4, mean * 4)

    async def create(self) -> bool:
        """Legt das Konto an, genau wie die App beim Anlegen."""
        await self.api.load_config()
        for _ in range(3):
            bits = self.api.work["account"][0]
            if bits > MAX_WORK_BITS + 3:
                return False
            work = await asyncio.to_thread(solve, self.api.subject(bytes.fromhex(self.id) + b"a"), bits)
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
                return True
            if r.status_code != 428:
                return False
            await self.api.load_config()
        return False

    async def login(self) -> bool:
        """Meldet sich an wie die App: Konto-Block holen. Nur eine klare Absage
        (401) heißt, dass es das Konto nicht mehr gibt."""
        r = await self.api.client.get("/api/v2/account", headers=self.auth)
        if r.status_code == 200:
            self.version = r.json()["version"]
            return True
        if r.status_code == 401:
            self.gone = True
        return False

    async def save(self):
        if self.version is None and not await self.login():
            return
        # Manche Konten wachsen mit der Zeit in eine größere Stufe.
        cls, wcls = self.cls, self.wcls
        if cls < self.wanted and rng.random() < 0.004:
            cls += 1
        if wcls < self.wipe_wanted and rng.random() < 0.004:
            wcls = 1
        body = {**self.blobs(cls, wcls), "expected_version": self.version, "cv": CLIENT_VER}
        r = await self.api.client.put("/api/v2/account", headers=self.auth, json=body)
        if r.status_code == 428 and (cls > self.cls or wcls > self.wcls):
            await self.api.load_config()
            bits = self.api.work["account"][cls] + (2 if wcls else 0)
            if bits > MAX_WORK_BITS + 3:
                return
            mark = cls * 2 + (1 if wcls else 0)
            body["work"] = await asyncio.to_thread(solve, self.api.subject(bytes.fromhex(self.id) + b"g" + bytes([mark])), bits)
            r = await self.api.client.put("/api/v2/account", headers=self.auth, json=body)
        if r.status_code == 200:
            self.version = r.json()["version"]
            self.cls, self.wcls = cls, wcls
        elif r.status_code in (401, 409):
            self.version = None

    async def erase(self):
        """Löscht das Konto so, wie es ein Mensch mit seinen Löschwörtern tut."""
        await self.api.client.post("/api/v2/wipe", json={"token": self.wipe})


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


async def session(api: Api, account: Account, spawn):
    """Eine Sitzung: anmelden, eine Weile da sein, wieder gehen."""

    def schedule_read(got):
        life = lifetime()
        if life >= 0:
            spawn(later(life, read_block, api, got, spawn))
        else:
            spawn(linger_slot())

    cursor = await api.fetch_pile(0)
    loop = asyncio.get_running_loop()
    end = loop.time() + lognorm(420 * mood.level, 1.0, 25, 4 * 3600)
    next_post = expo(mood.scale(25), 1, 600)
    next_save = account.save_pause()
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
                next_save = account.save_pause()
                await account.save()
        except Exception:
            await asyncio.sleep(expo(10, 2, 60))
    try:
        await account.save()
    except Exception:
        pass


async def person(api: Api, tasks: set):
    """Ein Schein-Mensch: legt sich ein Konto an, benutzt es eine Zeit lang und
    hört irgendwann auf. Manche nach einem Besuch, manche erst nach Wochen."""
    global _people

    def spawn(coro):
        t = asyncio.ensure_future(coro)
        tasks.add(t)
        t.add_done_callback(tasks.discard)

    _people += 1
    try:
        account = Account(api)
        if not await account.create():
            return
        # Wie oft kommt dieser Mensch wieder, und wie lange bleibt er zwischendurch weg?
        x = rng.random()
        visits = 1 if x < 0.15 else (rng.randint(2, 8) if x < 0.40 else (rng.randint(9, 80) if x < 0.75 else rng.randint(80, 800)))
        habit = lognorm(1200, 1.2, 240, 12 * 3600)      # übliche Pause zwischen zwei Besuchen
        first = True
        while visits > 0:
            visits -= 1
            try:
                if first or await account.login():
                    first = False
                    await session(api, account, spawn)
                elif account.gone:
                    return                         # Konto gibt es nicht mehr
                else:
                    visits += 1                    # Server gerade nicht erreichbar: später noch einmal
                    await asyncio.sleep(expo(60, 10, 600))
            except Exception:
                await asyncio.sleep(expo(20, 5, 120))
            if visits > 0:
                await asyncio.sleep(lognorm(mood.scale(habit), 1.0, 30, 3 * 86400))
        # Schluss: Die meisten kommen einfach nicht wieder, einige löschen ihr Konto.
        if rng.random() < 0.15:
            try:
                await account.erase()
            except Exception:
                pass
    finally:
        _people -= 1


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
    global _attachments, _linger_attachments
    if _attachments >= MAX_ATTACHMENTS:
        return
    _attachments += 1
    token = None
    keep = False
    try:
        x = rng.random()
        index = 0 if x < 0.70 else (1 if x < 0.90 else (2 if x < 0.975 else 3))
        # Manche kleinen Anhänge bleiben liegen, wie bei Menschen, die nicht lesen
        # oder ihren Verlauf behalten. Der Server räumt sie nach einigen Wochen weg.
        keep = index <= 1 and rng.random() < 0.12 and _linger_attachments < MAX_LINGER_ATTACHMENTS
        token = await api.upload(index)
        if not token:
            return
        note = await api.post_block(SMALL)
        await asyncio.sleep(lognorm(40, 1.1, 2, 1800))
        if note:
            await api.delete_block(*note)
        if not keep or rng.random() < 0.5:
            await api.download(token)
        await asyncio.sleep(0.1 + rng.random())
    except Exception:
        pass
    finally:
        _attachments -= 1
        if token and keep:
            _linger_attachments += 1
            try:
                await asyncio.sleep(42 * 86400)
            finally:
                _linger_attachments -= 1
        elif token:
            try:
                await api.delete_upload(token)
            except Exception:
                pass


async def newcomers(api: Api, tasks: set):
    """Lässt in unregelmäßigen Abständen neue Schein-Menschen dazukommen, so wie
    sich bei einem echten Dienst immer wieder jemand neu anmeldet. Sind es
    gerade wenige, kommen sie schneller, sind es viele, kommt niemand dazu.
    Eine feste Tages-Obergrenze verhindert, dass der Speicher sich füllt."""
    loop = asyncio.get_running_loop()
    first = True
    while True:
        if first:
            wait = expo(150, 20, 600) / max(1.0, INTENSITY)
        elif _people < PEOPLE_MIN:
            wait = expo(420, 45, 2400) / max(1.0, INTENSITY)
        else:
            wait = expo(mood.scale(8 * 3600), 900 / max(1.0, INTENSITY), 36 * 3600)
        first = False
        await asyncio.sleep(wait)
        now = loop.time()
        while _created and _created[0] < now - 86400:
            _created.popleft()
        if _people >= PEOPLE_MAX or len(_created) >= NEW_PER_DAY_MAX:
            continue
        _created.append(now)
        t = asyncio.ensure_future(person(api, tasks))
        tasks.add(t)
        t.add_done_callback(tasks.discard)


async def main():
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
    print("bots running", file=sys.stderr)
    await asyncio.gather(mood.drift(), api.config_loop(), newcomers(api, tasks))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
