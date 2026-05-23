// lehno-mesh Service Worker
// Minimal: nur als Marker für PWA-Installation. Kein offline caching von API-Daten
// (das wäre bei E2EE eh sinnlos, da Schlüssel im Speicher sind).
const CACHE = "lehno-mesh-v1";
const SHELL = ["/", "/s/style.css", "/s/app.js", "/s/crypto.js", "/s/bip39.js", "/manifest.json"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", e => {
  e.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/ws")) return; // never cache API
  e.respondWith(
    caches.match(e.request).then(r => r || fetch(e.request))
  );
});
