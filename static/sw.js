// lehno-mesh Service Worker - ABGESCHALTET (Phase 1.8)
// Früher hielt er einen Offline-Zwischenspeicher. Das wird nicht mehr gebraucht
// und könnte veralteten Code festhalten. Diese Fassung löscht alle
// Zwischenspeicher und meldet sich selbst ab, sobald ein Browser sie lädt.
self.addEventListener("install", () => { self.skipWaiting(); });
self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    try {
      const keys = await caches.keys();
      await Promise.all(keys.map(k => caches.delete(k)));
    } catch (err) {}
    try { await self.registration.unregister(); } catch (err) {}
  })());
});
