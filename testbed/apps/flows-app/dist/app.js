// JSHMARK:flows:app
// Every request goes through apiClient(), as in most real apps, so the
// frame on top of every request's stack is the same function.
async function apiClient(method, path, opts = {}) {
  const res = await fetch(path, { method, headers: opts.headers, body: opts.body });
  const type = res.headers.get('content-type') || '';
  return type.includes('json') ? res.json() : res.text();
}

// Load: two requests while the page starts.
apiClient('GET', '/api/me');
apiClient('GET', '/api/config');

// Noise: polling and analytics on timers, at any time.
setInterval(() => apiClient('GET', '/api/notifications'), 2000);
setInterval(() => navigator.sendBeacon('/api/analytics', JSON.stringify({ t: Date.now() })), 5000);
// A poll on a recursive setTimeout: no setInterval in its chain.
(function heartbeat() { apiClient('GET', '/api/heartbeat').finally(() => setTimeout(heartbeat, 1500)); })();
// A request of the page's start that comes after the user has begun.
setTimeout(() => apiClient('GET', '/api/late-config'), 4000);
// Promises in the background at the rate of a busy framework (zone.js,
// RxJS): V8 then drops old async stacks, and with them some tags.
setInterval(() => { for (let i = 0; i < 300; i++) Promise.resolve(i).then((x) => x + 1); }, 100);

const $ = (s) => document.querySelector(s);

// 1. Search.
$('#search').addEventListener('click', () => {
  apiClient('GET', '/api/search?q=' + encodeURIComponent($('#q').value) + '&page=1');
  // A parameter only the code names: never sent (the export's hidden one).
  if (location.hash === '#debug-deleted') apiClient('GET', '/api/search?q=' + encodeURIComponent($('#q').value) + '&include_deleted=1');
});

// 2. Open an item: one delegated handler for every row; the reviews come
// after the item, on a promise chain.
$('#items').addEventListener('click', (e) => {
  const id = e.target.dataset && e.target.dataset.id;
  if (!id) return;
  apiClient('GET', '/api/items/' + id).then((item) => apiClient('GET', '/api/items/' + item.id + '/reviews'));
});

// 3. Save the profile: a CSRF token from one response goes into the next
// request's header.
$('#profile').addEventListener('submit', async (e) => {
  e.preventDefault();
  const { csrf } = await apiClient('GET', '/api/csrf');
  await apiClient('POST', '/api/profile', {
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: JSON.stringify({ display_name: new FormData(e.target).get('display_name') }),
  });
});

// 4. Delete with a confirmation: the first click only opens the modal.
$('#delete').addEventListener('click', () => { $('#modal').hidden = false; });
$('#confirm').addEventListener('click', () => {
  $('#modal').hidden = true;
  apiClient('DELETE', '/api/items/42');
});

// 5. A two-step wizard; the second step waits, then chains.
$('#next1').addEventListener('click', () => {
  apiClient('POST', '/api/wizard/step1', { body: 'a=1' }).then(() => { $('#next2').disabled = false; });
});
$('#next2').addEventListener('click', () => {
  setTimeout(() => {
    apiClient('POST', '/api/wizard/step2', { body: 'b=2' }).then(() => apiClient('GET', '/api/wizard/summary'));
  }, 300);
});

// 6. Export through a worker: the request comes from another thread.
const exporter = new Worker('/export-worker.js');
$('#export').addEventListener('click', () => exporter.postMessage({ format: 'csv' }));

// 7. An HTML attribute handler (onclick="legacyLoad()").
function legacyLoad() {
  apiClient('GET', '/api/legacy');
}

// 8. Enter in a search form: keydown, a click on the submit button, then
// submit, all one gesture.
$('#find').addEventListener('submit', (e) => {
  e.preventDefault();
  apiClient('GET', '/api/find?q=' + encodeURIComponent($('#q2').value));
});

// 9. A click on a label: the checkbox's change does the work.
$('#agree').addEventListener('change', (e) => apiClient('POST', '/api/consent', { body: 'agree=' + e.target.checked }));

// 10. Create, then use the new id.
$('#new-note').addEventListener('click', async () => {
  const note = await apiClient('POST', '/api/notes', { headers: { 'Content-Type': 'application/json' }, body: '{"text":"hi"}' });
  apiClient('GET', '/api/notes/' + note.id);
});

// 11. A click that starts a poll: the first request is the click's, the
// ticks are background work it started.
$('#live').addEventListener('click', () => {
  apiClient('POST', '/api/live/start');
  setInterval(() => apiClient('GET', '/api/live/tick'), 700);
});

// 12. A slow report: the request comes long after the click.
$('#report').addEventListener('click', () => {
  setTimeout(() => apiClient('GET', '/api/report/ready'), 2500);
});

// 13. A timer set after an await in the handler (refreshing a list).
$('#refresh').addEventListener('click', async () => {
  await apiClient('POST', '/api/items', { body: 'name=x' });
  setTimeout(() => apiClient('GET', '/api/items?refresh=1'), 100);
});

// 14. A form whose controls are named "id" and "action", which shadow the
// form's own properties.
$('#edit').addEventListener('submit', (e) => {
  e.preventDefault();
  apiClient('POST', '/api/edit', { body: new URLSearchParams(new FormData(e.target)).toString() });
});

// 15. An upload in chunks: each request waits for the last, at a steady pace.
$('#upload').addEventListener('click', async () => {
  for (let n = 0; n < 4; n++) await apiClient('PUT', '/api/upload/' + n, { body: 'chunk' });
});

// 16. A one-off delay made with setInterval, as RxJS's delay and
// debounceTime do.
$('#find-later').addEventListener('click', () => {
  const id = setInterval(() => { clearInterval(id); apiClient('GET', '/api/find-later'); }, 200);
});

// 17. A slow export through the worker: the user starts typing before it
// sends its request.
$('#export-slow').addEventListener('click', () => exporter.postMessage({ format: 'pdf', delay: 400 }));
