import { http, request } from './http.js';

// Only an admin's page runs this: its endpoints are never seen in an
// anonymous visitor's traffic.
export default function admin(root) {
  console.debug('JSHMARK:route:admin');
  const list = (role, page) => http.get('/admin/users?role=' + role + '&page=' + page);
  const remove = (id) => fetch(`/api/admin/users/${id}`, { method: 'DELETE' });
  const impersonate = (id, reason) =>
    fetch('/api/admin/impersonate', { method: 'POST', body: JSON.stringify({ userId: id, reason }) });
  const settings = (on, text) => request('PUT', '/api/admin/settings', { maintenance: on, banner: text });
  const audit = new EventSource('/api/admin/audit/stream');
  root.dataset.admin = '1';
  return { list, remove, impersonate, settings, audit };
}
