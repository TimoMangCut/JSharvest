// Proxies every request, as a NetworkOnly/NetworkFirst route does, and
// writes on its own when told to.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => e.respondWith(fetch(e.request)));
self.addEventListener('message', () => { fetch('/api/write-sw-own', { method: 'POST', body: 'w' }); });
