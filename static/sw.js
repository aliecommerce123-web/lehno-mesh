// lehno-mesh Service Worker
// Strategie: NETWORK-FIRST fuer alles. Cache ist nur Offline-Fallback.
// Jede HTML/JS/CSS-Aenderung muss bei der naechsten Anfrage sofort live sein.
// Kein User soll je Cookies/Cache manuell loeschen muessen.

const CACHE = "lehno-mesh-v3";

self.addEventListener("install", e => {
  // Sofort zur neuen Version wechseln, nicht erst beim naechsten Tab-Reload
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil((async () => {
    // Alle alten Caches loeschen
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)));
    // Sofort alle offenen Tabs uebernehmen
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);

  // API + WebSocket: niemals cachen, immer direkt
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/ws")) return;

  // Network-First: erst aus Netz, nur als Fallback aus Cache (Offline-Mode)
  e.respondWith((async () => {
    try {
      const networkResp = await fetch(e.request, { cache: "no-store" });
      // Wenn erfolgreich: in Cache fuer Offline-Fallback
      if (networkResp && networkResp.ok && e.request.method === "GET") {
        const cache = await caches.open(CACHE);
        cache.put(e.request, networkResp.clone()).catch(()=>{});
      }
      return networkResp;
    } catch (err) {
      // Nur wenn Netz wirklich tot: Cache-Fallback
      const cached = await caches.match(e.request);
      if (cached) return cached;
      throw err;
    }
  })());
});

// Periodischer Self-Update-Check (jede Stunde)
setInterval(() => {
  self.registration.update().catch(()=>{});
}, 3600 * 1000);
