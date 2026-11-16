// Requests that come from timers, five ways. Each page load names its runs
// with a key, so the server's counters (retry, export) start fresh.
const KEY = 'r' + Date.now().toString(36);
const $ = (s) => document.querySelector(s);

// One client for every request, as in flows-app's app.js.
async function api(method, path) {
  const res = await fetch(path, { method });
  let body = null;
  try { body = await res.json(); } catch (e) { /* no body */ }
  return { status: res.status, body };
}

// 1. A poll that sets its next tick from the response of the last: the
// first request is the click's, the rest are background.
$('#poll-start').addEventListener('click', () => {
  let n = 0;
  function tick() {
    api('GET', '/api/poll?n=' + n++).then(() => setTimeout(tick, 1000));
  }
  tick();
});

// 2. A bounded retry: three tries 300 ms apart, all the click's.
$('#retry-save').addEventListener('click', () => {
  function attempt(i) {
    api('POST', '/api/retry-save?k=' + KEY).then((r) => {
      if (r.status === 503 && i < 3) setTimeout(() => attempt(i + 1), 300);
    });
  }
  attempt(1);
});

// 3. A long export: start, poll its status every 500 ms until it is done
// (about 4 s), then download. It recurses on a timer like the poll, but it
// stops, and all of it follows from the click.
$('#export').addEventListener('click', () => {
  api('POST', '/api/export/start?k=' + KEY).then(function poll() {
    setTimeout(() => {
      api('GET', '/api/export/status?k=' + KEY).then((r) => {
        if (r.body && r.body.done) api('GET', '/api/export/download?k=' + KEY);
        else poll();
      });
    }, 500);
  });
});

// 4. A scheduler as RxJS's asyncScheduler is: a queue of actions and one
// shared timer that runs whatever is due. Whoever schedules first arms the
// timer; every later action, whoever scheduled it, runs from that timer.
class AsyncScheduler {
  constructor() { this.queue = []; this.id = null; }
  schedule(work, delay) {
    const action = { work, due: Date.now() + delay, cancelled: false };
    this.queue.push(action);
    if (this.id === null) this.id = setInterval(() => this.flush(), 50);
    return { unsubscribe: () => { action.cancelled = true; } };
  }
  flush() {
    const now = Date.now();
    const due = this.queue.filter((a) => a.due <= now);
    this.queue = this.queue.filter((a) => a.due > now);
    for (const a of due) if (!a.cancelled) a.work();
    if (this.queue.length === 0) { clearInterval(this.id); this.id = null; }
  }
}
const asyncScheduler = new AsyncScheduler();
// interval(): reschedules itself on the same scheduler, for ever.
function interval(period, fn) {
  (function run() { asyncScheduler.schedule(() => { fn(); run(); }, period); })();
}
// A heartbeat from the page's load, before any click.
interval(1500, () => api('GET', '/api/heartbeat'));
// debounce 300 ms, then the search.
let pending = null;
$('#rx-search').addEventListener('click', () => {
  if (pending) pending.unsubscribe();
  pending = asyncScheduler.schedule(() => api('GET', '/api/search?q=rx'), 300);
});

// 5. A real setInterval: the first tick is the click's, the rest background.
$('#ticker-start').addEventListener('click', () => {
  setInterval(() => api('GET', '/api/tick'), 1000);
});
