// chatmesh Phase 2 - Zusatzangaben aus Mediendateien entfernen, BEVOR sie
// verschlüsselt und hochgeladen werden. Alles läuft im Browser.
//
// - Bilder: werden neu gezeichnet. Dabei gehen Aufnahmeort, Gerät, Uhrzeit und
//   alle anderen eingebetteten Angaben verloren.
// - Videos (MP4/MOV, WebM): die Bereiche mit Zusatzangaben werden mit Nullen
//   überschrieben, Erstell- und Änderungszeiten auf null gesetzt. Bild und Ton
//   bleiben unverändert.
// - Sprachnachrichten (WebM): dasselbe wie bei WebM-Videos.
(function () {
  "use strict";

  // ---------- Bilder ----------
  async function cleanImage(file) {
    const type = (file.type || "").split(";")[0];
    const outType = type === "image/png" || type === "image/gif" ? "image/png" : (type === "image/webp" ? "image/webp" : "image/jpeg");
    let bmp;
    try { bmp = await createImageBitmap(file, { imageOrientation: "from-image" }); }
    catch (e) { bmp = await createImageBitmap(file); }
    // Sehr große Bilder verkleinern (lange Kante höchstens 4096 Punkte).
    const scale = Math.min(1, 4096 / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale)), h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = w; canvas.height = h;
    canvas.getContext("2d").drawImage(bmp, 0, 0, w, h);
    if (bmp.close) bmp.close();
    const blob = await new Promise((res, rej) => canvas.toBlob(b => b ? res(b) : rej(new Error("encode")), outType, 0.92));
    return { bytes: new Uint8Array(await blob.arrayBuffer()), mime: blob.type || outType };
  }

  // ---------- MP4 / MOV ----------
  const u32 = (b, o) => (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
  const typ = (b, o) => String.fromCharCode(b[o], b[o + 1], b[o + 2], b[o + 3]);
  const CONTAINERS = new Set(["moov", "trak", "mdia", "minf", "dinf", "stbl", "edts", "mvex", "moof", "traf"]);
  const WIPE_BOXES = new Set(["udta", "meta", "uuid", "XMP_", "ilst", "auth", "titl", "dscp", "cprt", "loci", "©xyz"]);
  const TIME_BOXES = new Set(["mvhd", "tkhd", "mdhd"]);

  function scrubBoxes(b, start, end, depth, stats) {
    let o = start;
    while (o + 8 <= end) {
      let size = u32(b, o), head = 8;
      const t = typ(b, o + 4);
      if (size === 1) {            // 64-Bit-Größe
        if (o + 16 > end) break;
        const hi = u32(b, o + 8), lo = u32(b, o + 12);
        if (hi !== 0) break;       // größer als 4 GB kommt hier nicht vor
        size = lo; head = 16;
      } else if (size === 0) {
        size = end - o;
      }
      if (size < head || o + size > end) break;
      if (WIPE_BOXES.has(t)) {
        // Zu einem leeren Platzhalter machen: Typ "free", Inhalt Nullen.
        b[o + 4] = 0x66; b[o + 5] = 0x72; b[o + 6] = 0x65; b[o + 7] = 0x65;
        b.fill(0, o + head, o + size);
        stats.wiped++;
      } else if (TIME_BOXES.has(t)) {
        // Erstell- und Änderungszeit auf null (Version 0: 2x4 Bytes, Version 1: 2x8 Bytes).
        const ver = b[o + head];
        const n = ver === 1 ? 16 : 8;
        if (o + head + 4 + n <= o + size) { b.fill(0, o + head + 4, o + head + 4 + n); stats.times++; }
      } else if (CONTAINERS.has(t) && depth < 8) {
        scrubBoxes(b, o + head, o + size, depth + 1, stats);
      }
      o += size;
    }
  }
  function cleanMp4(bytes) {
    const b = new Uint8Array(bytes);
    const stats = { wiped: 0, times: 0 };
    scrubBoxes(b, 0, b.length, 0, stats);
    return { bytes: b, stats };
  }

  // ---------- WebM / Matroska ----------
  function readVint(b, o, isId) {
    if (o >= b.length) return null;
    const first = b[o];
    let len = 1, mask = 0x80;
    while (len <= 8 && !(first & mask)) { len++; mask >>= 1; }
    if (len > 8 || o + len > b.length) return null;
    let val = isId ? first : (first & (mask - 1));
    let unknown = !isId && val === (mask - 1);
    for (let i = 1; i < len; i++) {
      val = val * 256 + b[o + i];
      if (!isId && b[o + i] !== 0xff) unknown = false;
    }
    return { val, len, unknown };
  }
  const ID_SEGMENT = 0x18538067, ID_INFO = 0x1549A966, ID_TAGS = 0x1254C367, ID_CLUSTER = 0x1F43B675;
  const ID_ATTACH = 0x1941A469, ID_CHAPTERS = 0x1043A770;
  const INFO_ZERO = new Set([0x4461 /* DateUTC */, 0x73A4 /* SegmentUID */]);
  const INFO_BLANK = new Set([0x4D80 /* MuxingApp */, 0x5741 /* WritingApp */, 0x7BA9 /* Title */, 0x7384 /* SegmentFilename */]);

  function voidElement(b, o, total) {
    // Ganzes Element durch einen leeren Platzhalter gleicher Länge ersetzen.
    if (total < 2) return;
    if (total < 10) {
      b[o] = 0xEC; b[o + 1] = 0x80 | (total - 2);
      b.fill(0, o + 2, o + total);
      return;
    }
    b[o] = 0xEC; b[o + 1] = 0x01;
    let v = total - 9;
    for (let i = 8; i >= 2; i--) { b[o + i] = v % 256; v = Math.floor(v / 256); }
    b.fill(0, o + 9, o + total);
  }
  function cleanWebm(bytes) {
    const b = new Uint8Array(bytes);
    const stats = { wiped: 0, blanked: 0 };
    let o = 0;
    const head = readVint(b, o, true);
    if (!head || head.val !== 0x1A45DFA3) return { bytes: b, stats };
    const hs = readVint(b, o + head.len, false);
    if (!hs) return { bytes: b, stats };
    o += head.len + hs.len + hs.val;
    const seg = readVint(b, o, true);
    if (!seg || seg.val !== ID_SEGMENT) return { bytes: b, stats };
    const ss = readVint(b, o + seg.len, false);
    if (!ss) return { bytes: b, stats };
    o += seg.len + ss.len;
    const segEnd = ss.unknown ? b.length : Math.min(b.length, o + ss.val);
    let guard = 0;
    while (o < segEnd && guard++ < 100000) {
      const id = readVint(b, o, true);
      if (!id) break;
      const sz = readVint(b, o + id.len, false);
      if (!sz) break;
      const bodyStart = o + id.len + sz.len;
      if (id.val === ID_CLUSTER) break;                 // ab hier nur noch Bild und Ton
      if (sz.unknown) break;
      const total = id.len + sz.len + sz.val;
      if (o + total > segEnd) break;
      if (id.val === ID_TAGS || id.val === ID_ATTACH || id.val === ID_CHAPTERS) {
        voidElement(b, o, total);
        stats.wiped++;
      } else if (id.val === ID_INFO) {
        let p = bodyStart;
        const end = bodyStart + sz.val;
        while (p < end) {
          const cid = readVint(b, p, true);
          if (!cid) break;
          const csz = readVint(b, p + cid.len, false);
          if (!csz || csz.unknown) break;
          const cs = p + cid.len + csz.len;
          if (cs + csz.val > end) break;
          if (INFO_ZERO.has(cid.val)) { b.fill(0, cs, cs + csz.val); stats.blanked++; }
          else if (INFO_BLANK.has(cid.val)) { b.fill(0x20, cs, cs + csz.val); stats.blanked++; }
          p = cs + csz.val;
        }
      }
      o += total;
    }
    return { bytes: b, stats };
  }

  // Wählt das passende Verfahren. Gibt die bereinigten Bytes zurück.
  async function cleanFile(file, kind) {
    const type = (file.type || "").split(";")[0];
    if (kind === "image") return await cleanImage(file);
    const raw = new Uint8Array(await file.arrayBuffer());
    if (type === "video/mp4" || type === "video/quicktime" || type === "audio/mp4") return { bytes: cleanMp4(raw).bytes, mime: type };
    if (type === "video/webm" || type === "audio/webm") return { bytes: cleanWebm(raw).bytes, mime: type };
    return { bytes: raw, mime: type };
  }

  const api = { cleanImage, cleanMp4, cleanWebm, cleanFile };
  if (typeof window !== "undefined") window.CMMedia = api;
  if (typeof module !== "undefined") module.exports = api;
})();
