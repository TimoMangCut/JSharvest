// A service worker of the public origin that reaches for the internal network.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim().then(go)));
function go() { return fetch('http://127.0.0.1:8771/lan/sw', { mode: 'no-cors' }).catch(() => {}); }
self.addEventListener('message', () => { go(); });
