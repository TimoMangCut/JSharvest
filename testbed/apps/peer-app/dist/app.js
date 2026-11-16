// JSHMARK:peer:app
const $ = (s) => document.querySelector(s);
const json = (r) => r.json();
const get = (u, h) => fetch(u, h ? { headers: h } : undefined);
// A fresh nonce for each request: the server serves it once.
const nonce = () => crypto.randomUUID().replace(/-/g, '');

(async () => {
  // Open to anon: the feed, and each announcement by the id it names.
  const feed = await get('/api/peer/feed').then(json);
  for (const a of feed.announcements) {
    $('#feed').insertAdjacentHTML('beforeend', '<li>' + a.title + '</li>');
    await get('/api/peer/announcements/' + a.id);
  }
  const r = await get('/api/peer/me');
  if (!r.ok) return;
  const me = await r.json();
  $('#who').textContent = 'Signed in as ' + me.name;
  // What the caller owns, as the API lists it. Each request below carries an
  // id of the caller's own; nothing is asked of another person's.
  const home = await get('/api/peer/home').then(json);
  await get('/api/peer/preferences?userId=' + encodeURIComponent(me.id));
  for (const id of home.docs) await get('/api/peer/org-docs/' + id);
  for (const id of home.notes) await get('/api/peer/private-notes/' + id);
  for (const id of home.items) await get('/api/peer/lookup?itemId=' + encodeURIComponent(id));
  for (const id of home.orders) await get('/api/peer/orders/' + id);
  for (const id of home.featured) await get('/api/peer/featured/' + id);
  for (const p of home.projects) await get('/api/peer/orgs/' + p.org + '/projects/' + p.id);
  for (const id of home.wallets) {
    await get('/api/peer/wallets/' + id);
    await get('/api/peer/wallets-leaky/' + id);
  }
  for (const id of home.quotas) await get('/api/peer/quota/' + id);
  for (const id of home.transfers) await get('/api/peer/signed-preview/' + id, { 'X-Req-Nonce': nonce() });
  // The signed URLs come from the API; the page follows them as they are.
  const links = await get('/api/peer/file-links').then(json);
  for (const f of links.files) await get(f.url);
  // A GraphQL batch: the viewer, and the vault item by its Relay id.
  const batch = [{ operationName: 'GetViewer', query: 'query GetViewer { viewer { id name org } }', variables: {} }];
  if (home.vault.length) {
    batch.push({
      operationName: 'GetVaultItem',
      query: 'query GetVaultItem($id: ID!) { vaultItem(id: $id) { id label secret private } }',
      variables: { id: home.vault[0] },
    });
  }
  await fetch('/api/peer/graphql', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(batch) });
  // Case 11: a key's regeneration is a GET with a verb. Only a click sends it
  // (the explore of crawl clicks; the gate checks the request was recorded).
  if (home.keys.length) {
    $('#keys').hidden = false;
    $('#regen').addEventListener('click', () => get('/api/peer/keys/' + home.keys[0] + '?action=regenerate'));
  }
})();
