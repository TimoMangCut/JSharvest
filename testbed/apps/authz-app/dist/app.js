// JSHMARK:authz:app
const $ = (s) => document.querySelector(s);
const json = (r) => r.json();

// The admin's writes carry a CSRF token of the session, from /api/az/csrf.
async function write(path, body) {
  const { csrf } = await fetch('/api/az/csrf').then(json);
  return fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(body) });
}

(async () => {
  fetch('/api/az/pub/news');
  const r = await fetch('/api/az/me');
  if (!r.ok) return;
  const me = await r.json();
  $('#who').textContent = 'Signed in as ' + me.name;
  if (me.role !== 'admin') return;
  // The admin's tools: in every role's code, shown to the admin only.
  $('#admin-tools').hidden = false;
  $('#stats').addEventListener('click', () => fetch('/api/az/admin/stats'));
  $('#summary').addEventListener('click', () => fetch('/api/az/admin/summary'));
  $('#public-export').addEventListener('click', () => fetch('/api/az/admin/export'));
  $('#report').addEventListener('click', () => fetch('/api/az/admin/report'));
  $('#flags').addEventListener('click', () => fetch('/api/az/admin/flags'));
  $('#orders').addEventListener('click', () => fetch('/api/az/admin/orders'));
  $('#account').addEventListener('click', () => fetch('/api/az/admin/accounts/1'));
  $('#invite').addEventListener('click', () => write('/api/az/admin/invite', { email: 'new@authz.test' }));
  $('#note').addEventListener('click', () => write('/api/az/admin/notes', { text: 'hello' }));
  $('#wipe').addEventListener('click', () => fetch('/api/az/admin/cache?action=wipe'));
})();
