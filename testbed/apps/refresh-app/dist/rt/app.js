// refresh-app client (28B(b)). Naive on purpose: each tab refreshes by itself
// from the tokens it holds, as many apps do. Every refresh tries, and every
// failure, or a 200 without a token (the guard's fake 200 {}), is reported by
// GET /rt/_clientlog?e=... (a GET, which a guard that holds back writes lets by).
(function () {
  var d = document.documentElement.dataset;
  var kind = d.kind, mode = d.mode;
  function report(e) { return fetch('/rt/_clientlog?e=' + encodeURIComponent(e)).catch(function () {}); }
  function tokens() { try { return JSON.parse(localStorage.getItem('rt_auth') || '{}'); } catch (e) { return {}; } }

  // ?lock=1 (or lock=1 in the page's query): a careful app, which refreshes
  // under a lock all its tabs share (Web Locks) and takes the token another
  // tab got meanwhile instead of spending its own (a reuse would revoke the
  // family). Without it the app is naive, as 28B measured.
  var lock = /[?&]lock=1(&|$)/.test(location.search) && navigator.locks;
  var inflight = null; // one refresh at a time in a tab
  function refresh() {
    if (inflight) return inflight;
    var seen = tokens().rt;
    var run = lock ? navigator.locks.request('rt-refresh', function () {
      if (kind !== 'bff' && tokens().rt && tokens().rt !== seen) return report('refresh_shared').then(function () { return true; });
      return doRefresh();
    }) : doRefresh();
    inflight = run.then(function (ok) { inflight = null; return ok; });
    return inflight;
  }
  async function doRefresh() {
    await report('refresh_try');
    var r;
    try {
      if (kind === 'bff') {
        r = await fetch('/rt/api/auth/refresh', { method: 'POST', credentials: 'same-origin' });
      } else {
        var t = tokens(), url = '/rt/oauth/token', init = { method: 'POST' };
        if (mode === 'json') {
          init.headers = { 'Content-Type': 'application/json' };
          init.body = JSON.stringify({ grant_type: 'refresh_token', refresh_token: t.rt });
        } else if (mode === 'query') {
          url += '?grant_type=refresh_token&refresh_token=' + encodeURIComponent(t.rt || '');
        } else {
          init.body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: t.rt || '' });
        }
        r = await fetch(url, init);
      }
    } catch (e) { await report('refresh_neterr'); return false; }
    if (!r.ok) { await report('refresh_status_' + r.status); return false; }
    var j = {};
    try { j = await r.json(); } catch (e) {}
    if (kind === 'bff' ? j.ok !== true : !j.access_token) { await report('refresh_fake'); return false; } // 200 {}
    if (kind !== 'bff') localStorage.setItem('rt_auth', JSON.stringify({ at: j.access_token, rt: j.refresh_token }));
    await report('refresh_ok');
    return true;
  }
  function call(page) {
    var h = {};
    if (kind !== 'bff') h.Authorization = 'Bearer ' + (tokens().at || '');
    return fetch('/rt/api/data?hold=1500&page=' + page, { headers: h, credentials: 'same-origin' });
  }
  async function data(page) {
    var r = await call(page);
    if (r.status === 401) {
      await report('data_401');
      if (await refresh()) { r = await call(page); if (r.status === 401) await report('data_401_after_refresh'); }
    }
    return r.ok;
  }
  // six calls a page, one after another, each held 1.5 s by the server: a
  // page keeps a request in flight for about ten seconds.
  window.rtDone = (async function () {
    for (var i = 1; i <= 6; i++) { await data(i); await new Promise(function (r) { setTimeout(r, 200); }); }
    document.getElementById('state').textContent = 'done';
  })();
})();
