console.debug('JSHMARK:guard:page');
const json = { 'Content-Type': 'application/json' };
// Reads that must pass.
fetch('/api/read?x=1');
fetch('/graphql?op=query', { method: 'POST', headers: json, body: JSON.stringify({ query: 'query Me { me { id } }' }) });
// Writes and destructive calls that must not.
fetch('/api/write-fetch', { method: 'POST', headers: json, body: '{"a":1}' });
fetch('/api/write-put', { method: 'PUT', body: 'x' });
const x = new XMLHttpRequest(); x.open('POST', '/api/write-xhr'); x.send('b=2');
navigator.sendBeacon('/api/write-beacon', 'c=3');
fetch('/api/write-keepalive', { method: 'POST', body: 'k', keepalive: true });
fetch('/graphql?op=mutation', { method: 'POST', headers: json, body: JSON.stringify({ query: 'mutation Up { up }' }) });
fetch('/api/logout');
new Worker('/guard-worker.js');
// A response that would wipe cookies and storage.
document.cookie = 'keep=1; path=/';
// Report the cookie after the response, so the server log shows whether it was wiped.
const csd = fetch('/csd').then(() => new Promise((done) => setTimeout(() => { fetch('/api/read?after-csd=' + encodeURIComponent(document.cookie || 'EMPTY')); done(); }, 200)));
// Cases from the guard review.
new Image().src = '/img/logout.gif';
fetch('/users/sign_out');
fetch('/api/%64elete');
fetch('/api/notes', { method: 'POST', headers: json, body: JSON.stringify({ query: 'shoes', text: 'new note' }) });
fetch('/graphql?op=bom', { method: 'POST', headers: json, body: JSON.stringify({ query: '\ufeffmutation{x}' }) });
try { new WebSocket('ws://' + location.host + '/ws'); } catch (e) {}
// Writes through the service worker: a page POST it proxies, and a POST of
// its own. Interception of the tab does not reach a service worker; the
// guard must hold it on the worker's own session.
// Registered once Clear-Site-Data has done its work: its "storage" removes
// the origin's service workers.
const viaSW = new Promise((done) => {
  setTimeout(done, 6000);
  csd.then(() => navigator.serviceWorker.register('/guard-sw.js')).then(() => {
    // Wait for the worker to control the page (it claims its clients).
    const wait = setInterval(() => {
      const sw = navigator.serviceWorker.controller;
      if (!sw) return;
      clearInterval(wait);
      sw.postMessage('write');
      fetch('/api/write-via-sw', { method: 'POST', body: 's' }).finally(() => setTimeout(done, 300));
    }, 200);
  });
});
// A shared worker's write.
try { new SharedWorker('/guard-shared.js').port.start(); } catch (e) {}
// Form POSTs last, once the service worker case is done: without a guard
// they navigate away. One goes to a new window, one in place.
viaSW.then(() => {
  document.getElementById('popup').requestSubmit();
  setTimeout(() => document.getElementById('f').requestSubmit(), 300);
});
