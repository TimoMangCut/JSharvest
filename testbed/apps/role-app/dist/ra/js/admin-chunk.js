// JSHMARK:roles:admin-chunk
// Loaded for an admin only; its calls are in every role's code all the same.
export function mount(el) {
  el.innerHTML = '<button id="list-users">List users</button> <button id="invite">Invite user</button> ' +
    '<button id="remove-user" data-id="7">Remove user 7</button>';
  el.querySelector('#list-users').addEventListener('click', () => fetch('/api/ra/admin/users'));
  el.querySelector('#invite').addEventListener('click', () => fetch('/api/ra/admin/invite', { method: 'POST', body: 'email=x@y.z' }));
  el.querySelector('#remove-user').addEventListener('click', (e) => fetch('/api/ra/admin/users/' + e.target.dataset.id, { method: 'DELETE' }));
  el.insertAdjacentHTML('beforeend', ' <button id="purge-users">Purge users</button> <button id="purge-cache">Purge cache</button>');
  // One GraphQL endpoint and one RPC endpoint for every role; these
  // operations are the admin's.
  el.querySelector('#purge-users').addEventListener('click', () => fetch('/api/ra/graphql', { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ operationName: 'PurgeUsers', query: 'mutation PurgeUsers { purgeUsers }' }) }));
  el.querySelector('#purge-cache').addEventListener('click', () => fetch('/api/ra/rpc?action=purge'));
}
