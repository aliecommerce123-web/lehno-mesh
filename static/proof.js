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
  const about = (n) => (n === 0 ? "0" : "ca. " + n);

  function sizeLabel(key) {
    if (key === "andere") return "andere Größe";
    const n = Number(key);
    if (n >= 1048576) return (n / 1048576) + " MB";
    if (n >= 1024) return Math.round(n / 1024) + " KB";
    return n + " Bytes";
  }

  async function loadLive() {
    try {
      const d = await getJson("/api/proof/live");
      const stats = $("stats");
      stats.textContent = "";
      stats.appendChild(stat("verschlüsselte Konto-Blöcke", about(d.account_blocks)));
      stats.appendChild(stat("Blöcke auf dem Haufen (echte und Schein-Blöcke, nicht unterscheidbar)", about(sum(d.pile_blocks_by_size))));
      stats.appendChild(stat("verschlüsselte Anhänge", about(sum(d.attachments_by_size))));
      stats.appendChild(stat("verschiedene Wochen-Marken auf dem Haufen", d.pile_distinct_week_markers));
      $("live-pill").textContent = "Momentaufnahme, alle " + d.refresh_minutes + " Minuten neu, gerundet";

      const el = $("t-sizes");
      el.textContent = "";
      const head = document.createElement("tr");
      for (const h of ["Art", "Größe (feste Stufe)", "Anzahl (gerundet)"]) { const th = document.createElement("th"); th.textContent = h; head.appendChild(th); }
      el.appendChild(head);
      const groups = [["Block auf dem Haufen", d.pile_blocks_by_size], ["Anhang", d.attachments_by_size]];
      for (const [kind, obj] of groups) {
        for (const [key, n] of Object.entries(obj || {})) {
          const tr = document.createElement("tr");
          tr.appendChild(cell(kind)); tr.appendChild(cell(sizeLabel(key))); tr.appendChild(cell(about(n)));
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
      lines.push("-- Hauptdatenbank (Konto-Blöcke und der gemeinsame Haufen)");
      for (const t of d.main_db) lines.push(t.sql + ";\n");
      lines.push("-- Datenbank für Anhänge");
      for (const t of d.attachments_db) lines.push(t.sql + ";\n");
      const text = lines.join("\n");
      $("schema").textContent = text;
      // Aus dem Bauplan selbst gezählt (nicht fest eingetragen):
      const low = text.toLowerCase();
      const count = (words) => words.reduce((n, w) => n + (low.split(w).length - 1), 0);
      $("schema-facts").textContent =
        "Aus diesem Bauplan gezählt: Spalten für Absender: " + count(["sender", "from_"]) +
        ", für Empfänger: " + count(["recipient", "receiver", "to_address"]) +
        ", für IP-Adressen: " + count(["ip_addr", "remote_addr", " ip "]) +
        ", für Geräte oder Browser: " + count(["user_agent", "device", "browser"]) +
        ", für Uhrzeiten: " + count(["created_at", "updated_at", "timestamp", "datetime"]) + ".";
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
        const self = f.name === "EXPECTED_HASHES.json";
        const ok = cell(self ? "ist die Liste selbst" : (exp === undefined ? "nicht hinterlegt" : (exp === f.sha256 ? "ja" : "NEIN")));
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

  loadLive(); loadSchema(); loadSource(); loadProxy();
  setInterval(loadLive, 60000);
})();
