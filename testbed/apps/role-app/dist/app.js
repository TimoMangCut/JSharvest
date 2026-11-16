// JSHMARK:roles:app
const $ = (s) => document.querySelector(s);

const gql = (operationName, query) => fetch('/api/ra/graphql', { method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ operationName, query }) });

(async () => {
  fetch('/api/ra/pub/news');      // every role: the same
  fetch('/api/ra/admin/stats');   // every role asks; only an admin is answered
  fetch('/api/ra/me/profile');    // every role asks; anon is refused
  fetch('/api/ra/me/inbox');      // anon is sent to the login page
  fetch('/api/ra/pub/legacy');    // a user is refused, anon and admin are not
  fetch('/api/ra/rpc?action=list'); // one RPC endpoint, many actions
  gql('News', 'query News { news { id title } }');
  const r = await fetch('/api/me');
  const me = r.ok ? await r.json() : null;
  if (!me) return;
  $('#user-tools').hidden = false; // a logged-in user's button, named after the role
  $('#orders').textContent = 'My orders, ' + me.role;
  fetch('/api/ra/admin/summary'); // an admin's endpoint the server lets a user call
  if (me.role !== 'admin') return;
  // An admin's: a link, a lazy chunk (named here, so anyone can fetch it),
  // a script the server gives admins only, and one more search option.
  $('#nav').insertAdjacentHTML('beforeend', ' <a href="/ra/admin">Admin</a>');
  const m = await import('/ra/js/admin-chunk.js');
  m.mount($('#admin-tools'));
  const s = document.createElement('script');
  s.src = '/private/ra-audit.js';
  document.head.appendChild(s);
  $('#incl').hidden = false;
})();

$('#orders').addEventListener('click', () => fetch('/api/ra/me/orders'));

$('#search-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const body = { q: e.target.elements.q.value };
  if ($('#include-deleted').checked) body.include_deleted = true;
  fetch('/api/ra/search', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
});
