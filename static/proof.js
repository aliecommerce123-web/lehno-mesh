// chatmesh Beweis-Seite: liest alles von den öffentlichen Schnittstellen
// /api/proof/* und zeigt es unverändert an. Keine fremden Dateien, keine Cookies.
(function () {
  const $ = (id) => document.getElementById(id);

  async function getJson(path) {
    const r = await fetch(path, { cache: "no-store" });
    if (!r.ok) throw new Error("Status " + r.status);
    return r.json();
  }

  function cell(text, cls) {
    const td = document.createElement("td");
    if (cls) td.className = cls;
    td.textContent = text === null || text === undefined ? "" : String(text);
    return td;
  }

  function stat(label, value) {
    const d = document.createElement("div");
    d.className = "stat";
    const b = document.createElement("b"); b.textContent = String(value);
    const s = document.createElement("span"); s.textContent = label;
    d.appendChild(b); d.appendChild(s);
    return d;
  }

  const sum = (obj) => Object.values(obj || {}).reduce((a, b) => a + b, 0);

  function sizeLabel(kind, key) {
    if (key === "andere") return "andere Größe";
    const n = Number(key);
    if (kind === "Anhang") return (n >= 1048576 ? (n / 1048576) + " MB" : (n / 1024) + " KB") + " (" + n + " Bytes)";
    return n + " Zeichen Geheimtext";
  }

  async function loadLive() {
    try {
      const d = await getJson("/api/proof/live");
      const stats = $("stats");
      stats.textContent = "";
      stats.appendChild(stat("Konten", d.accounts_total));
      stats.appendChild(stat("wartende Nachrichten", d.waiting_packets_total));
      stats.appendChild(stat("verschlüsselte Verläufe", sum(d.history_blobs_by_size)));
      stats.appendChild(stat("verschlüsselte Kontaktlisten", sum(d.contact_blobs_by_size)));
      stats.appendChild(stat("verschlüsselte Anhänge", sum(d.attachments_by_size)));
      $("live-pill").textContent = "Momentaufnahme, alle " + d.refresh_minutes + " Minuten neu";

      const tails = $("tails");
      tails.textContent = "";
      for (const t of d.account_address_ends) { const s = document.createElement("span"); s.textContent = t; tails.appendChild(s); }
      const m = d.accounts_time_markers;
      $("markers").textContent = "Zeitmarken der Konten: " + m.different_values + " verschiedener Wert, höchster Wert " + m.highest_value +
        " (0 heißt: es ist kein Zeitpunkt gespeichert).";

      const el = $("t-sizes");
      el.textContent = "";
      const head = document.createElement("tr");
      for (const h of ["Art", "Größe (feste Stufe)", "Anzahl"]) { const th = document.createElement("th"); th.textContent = h; head.appendChild(th); }
      el.appendChild(head);
      const groups = [["wartende Nachricht", d.waiting_packets_by_size], ["Verlauf", d.history_blobs_by_size],
                      ["Kontaktliste", d.contact_blobs_by_size], ["Anhang", d.attachments_by_size]];
      for (const [kind, obj] of groups) {
        for (const [key, n] of Object.entries(obj || {})) {
          const tr = document.createElement("tr");
          tr.appendChild(cell(kind)); tr.appendChild(cell(sizeLabel(kind, key))); tr.appendChild(cell(n));
          el.appendChild(tr);
        }
      }
    } catch (e) {
      $("live-pill").textContent = "gerade nicht erreichbar";
    }
  }

  async function loadSchema() {
    try {
      const d = await getJson("/api/proof/schema");
      const lines = [];
      lines.push("-- Hauptdatenbank (Konten, wartende Nachrichten, verschlüsselte Ablagen)");
      for (const t of d.mesh_db) lines.push(t.sql + ";\n");
      lines.push("-- Datenbank für Anhänge");
      for (const t of d.attachments_db) lines.push(t.sql + ";\n");
      const text = lines.join("\n");
      $("schema").textContent = text;
      // Aus dem Bauplan selbst gezählt (nicht fest eingetragen):
      const low = text.toLowerCase();
      const count = (words) => words.reduce((n, w) => n + (low.split(w).length - 1), 0);
      $("schema-facts").textContent =
        "Aus diesem Bauplan gezählt: Spalten für Absender: " + count(["sender", "from_address"]) +
        ", für IP-Adressen: " + count(["ip_addr", "remote_addr", " ip "]) +
        ", für Geräte oder Browser: " + count(["user_agent", "device", "browser"]) + ".";
    } catch (e) { $("schema").textContent = "konnte nicht geladen werden"; }
  }

  async function loadSource() {
    try {
      const d = await getJson("/api/proof/source");
      $("repo").href = d.repository;
      const el = $("t-files");
      el.textContent = "";
      const head = document.createElement("tr");
      for (const h of ["Datei (anklicken zum Lesen)", "Größe", "Prüfsumme SHA-256", "passt zur hinterlegten?"]) { const th = document.createElement("th"); th.textContent = h; head.appendChild(th); }
      el.appendChild(head);
      for (const f of d.files) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        const a = document.createElement("a");
        a.href = "/api/proof/file?name=" + encodeURIComponent(f.name);
        a.target = "_blank"; a.rel = "noopener";
        a.textContent = f.name;
        td.appendChild(a);
        tr.appendChild(td);
        tr.appendChild(cell(f.bytes + " Bytes"));
        tr.appendChild(cell(f.sha256, "mono"));
        const exp = d.expected_hashes[f.name];
        const ok = cell(exp === undefined ? "nicht hinterlegt" : (exp === f.sha256 ? "ja" : "NEIN"));
        ok.className = exp === f.sha256 ? "ok" : (exp === undefined ? "" : "warn");
        tr.appendChild(ok);
        el.appendChild(tr);
      }
    } catch (e) { /* bleibt leer */ }
  }

  async function loadProxy() {
    try {
      const d = await getJson("/api/proof/config");
      const lines = [];
      for (const r of d.removed_before_app) lines.push("  entfernt: " + r.what + (r.entries > 1 ? "   (" + r.entries + " Angaben)" : ""));
      if (!lines.length) lines.push("  (keine Angaben lesbar)");
      lines.push("");
      lines.push("Protokoll der Schleuse abgeschaltet:    " + (d.proxy_log_disabled ? "ja" : "nein"));
      lines.push("Zugriffsprotokoll der App abgeschaltet: " + (d.app_access_log_disabled ? "ja" : "nein"));
      $("proxy").textContent = lines.join("\n");
    } catch (e) { $("proxy").textContent = "konnte nicht geladen werden"; }
  }

  async function check() {
    const out = $("check-out");
    const pid = $("pid").value.trim().toLowerCase();
    out.textContent = "";
    const p = document.createElement("p");
    if (!/^[0-9a-f]{24}$/.test(pid)) { p.className = "warn"; p.textContent = "Eine Beweis-Kennung besteht aus genau 24 Zeichen (0-9, a-f)."; out.appendChild(p); return; }
    try {
      const d = await getJson("/api/proof/packet/" + pid);
      if (!d.stored) {
        p.className = "ok";
        p.textContent = "Zu dieser Kennung war bei der letzten Momentaufnahme nichts gespeichert. Entweder wurde die Nachricht schon abgeholt und gelöscht, oder sie ist jünger als die letzte Momentaufnahme (dann in ein paar Minuten noch einmal prüfen), oder die Kennung gab es nie.";
        out.appendChild(p);
        return;
      }
      p.textContent = "Diese Nachricht wartete bei der letzten Momentaufnahme auf Abholung. Genau das hat der Server dazu gespeichert:";
      out.appendChild(p);
      const pre = document.createElement("pre");
      pre.textContent = [
        "Spalten der Zeile:         " + d.columns.join(", "),
        "Absender gespeichert:      nein (dieses Feld gibt es nicht)",
        "Geheimtext, Größe:         " + d.ciphertext_chars + " Zeichen (feste Stufe)",
        "Geheimtext, Anfang:        " + d.ciphertext_start,
        "Prüfsumme Geheimtext:      " + d.ciphertext_sha256,
        "Prüfsumme Einmalschlüssel: " + d.ephemeral_pub_sha256,
        "Prüfsumme Zufallswert:     " + d.nonce_sha256,
        "Unterschrift:              " + (d.signature_chars ? d.signature_chars + " Zeichen (altes Format)" : "keine (würde den Absender verraten)"),
        "Wochen-Marker:             " + d.week_marker + " (nur zum Aufräumen, keine Uhrzeit)",
      ].join("\n");
      out.appendChild(pre);
    } catch (e) {
      p.className = "warn"; p.textContent = "Abfrage gerade nicht möglich. Bitte gleich noch einmal versuchen."; out.appendChild(p);
    }
  }

  $("btn-check").addEventListener("click", check);
  $("pid").addEventListener("keydown", (e) => { if (e.key === "Enter") check(); });
  if (location.hash.length > 1) { $("pid").value = location.hash.slice(1); check(); }

  loadLive(); loadSchema(); loadSource(); loadProxy();
  setInterval(loadLive, 60000);
})();
