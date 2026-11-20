// chatmesh Beweis-Seite: liest Speicherformat, Quelltext-Liste und Einstellungen
// von den öffentlichen Schnittstellen /api/proof/* und zeigt sie unverändert an.
// Bewusst ohne jede Zahl über Nutzer oder Nachrichten. Keine fremden Dateien, keine Cookies.
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
      if (d.commit) {
        const line = $("commit-line");
        line.textContent = "Stand im öffentlichen Quelltext-Verzeichnis: ";
        const a = document.createElement("a");
        a.href = d.repository + "/commit/" + d.commit;
        a.target = "_blank"; a.rel = "noopener";
        a.textContent = d.commit.slice(0, 12);
        line.appendChild(a);
        const hist = document.createElement("a");
        hist.href = d.repository + "/commits";
        hist.target = "_blank"; hist.rel = "noopener";
        hist.textContent = "alle Änderungen ansehen";
        line.appendChild(document.createTextNode(" · "));
        line.appendChild(hist);
      }
      $("verify-cmd").textContent = "python3 verify.py " + location.origin;
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

  loadSchema(); loadSource(); loadProxy();
})();
