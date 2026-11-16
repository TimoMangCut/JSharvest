import { http, request } from './http.js';
import { $ } from './jq.js';

const API = '/api';
// Client-side routes: pages, not API calls.
export const routes = [
  { path: '/settings', title: 'Settings' },
  { path: '/editor/:slug', title: 'Editor' },
  { path: '/profile/:username', title: 'Profile' },
];
// Strings that look like paths and are not endpoints.
export const noise = {
  icon: 'M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z',
  types: ['application/json', 'text/plain', 'image/svg+xml', 'multipart/form-data'],
  dateFormat: 'yyyy/mm/dd',
  released: '2026/11/03',
  svg: 'http://www.w3.org/2000/svg',
  module: './utils/format.js',
  ratio: '16/9',
  copy: 'Read and/or write',
};
// Endpoints named in a table, used further down.
const ENDPOINTS = { upload: '/api/uploads', exportCsv: '/api/export/csv' };

export function listArticles(tag, page) {
  return fetch(`${API}/articles?` + new URLSearchParams({ tag, limit: 10, offset: page * 10 }));
}

export function feed(page) {
  return http.get('/articles/feed', { params: { limit: 10, offset: page * 10 } });
}

export function createArticle(a) {
  return fetch(API + '/articles', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
    body: JSON.stringify({ article: { title: a.title, description: a.description, body: a.body, tagList: a.tags } }),
  });
}

export const updateArticle = (slug, article) => request('PUT', API + '/articles/' + slug, { article });
export const deleteArticle = (slug) => request('DELETE', `${API}/articles/${slug}`);

export const profile = (username) => http.get(`/profiles/${username}`);
export const follow = (username) => http.post(`/profiles/${username}/follow`);
export const unfollow = (username) => http.delete(`/profiles/${username}/follow`);
export const updateUser = (u) => http.put('/user', { user: { email: u.email, username: u.username, bio: u.bio, image: u.image } });

export function addComment(slug, body) {
  const x = new XMLHttpRequest();
  x.open('POST', '/api/articles/' + slug + '/comments');
  x.setRequestHeader('Content-Type', 'application/json');
  x.send(JSON.stringify({ comment: { body } }));
}

export const tags = () => $.ajax({ url: '/api/tags', type: 'GET', dataType: 'json' });
export const login = (email, password) => $.post('/api/users/login', { email, password });

export function favorite(slug) {
  return fetch('/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: 'mutation FavoriteArticle($slug: String!) { favorite(slug: $slug) { slug } }', variables: { slug } }),
  });
}

export function live(channel) {
  const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/notifications');
  const es = new EventSource('/api/events?channel=' + encodeURIComponent(channel));
  return [ws, es];
}

export const status = () => fetch('http://127.0.0.1:8770/api/v2/status');
export const upload = (form) => fetch(ENDPOINTS.upload, { method: 'POST', body: form });
export const exportPdf = (id) => window.open('/api/export/pdf?id=' + id);

// The UI: every call takes its values from the page, as in an app, so
// that the bundler can neither drop nor fold them.
const api = {
  listArticles, feed, createArticle, updateArticle, deleteArticle, profile, follow, unfollow, updateUser,
  addComment, tags, login, favorite, live, status, upload, exportPdf,
  exportCsv: () => fetch(ENDPOINTS.exportCsv),
  publish: () => createArticle({ title: document.title, description: 'd', body: 'b', tags: [] }),
};
document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const args = (el.dataset.args || '').split(',').filter(Boolean);
  api[el.dataset.action](...args);
});
function render() {
  const nav = routes.map((r) => `<a href="${r.path}">${r.title}</a>`).join(' ');
  const svg = document.createElementNS(noise.svg, 'svg');
  const icon = document.createElementNS(noise.svg, 'path');
  icon.setAttribute('d', noise.icon);
  svg.appendChild(icon);
  document.getElementById('app').innerHTML = nav + `<p>${noise.copy}, ${noise.ratio}, ${noise.released} (${noise.dateFormat})</p>` +
    `<p>${noise.types.join(' ')} ${noise.module}</p>`;
  document.getElementById('app').appendChild(svg);
}
render();
const params = new URLSearchParams(location.search);
api.listArticles(params.get('tag') || 'go', Number(params.get('page') || 0));
api.tags();
navigator.sendBeacon('/api/telemetry', JSON.stringify({ event: 'view', page: location.pathname }));

// The admin part is only loaded for an admin: an anonymous visitor never
// runs it, but its chunk is named in the webpack runtime.
fetch('/api/me')
  .then((r) => r.json())
  .then((me) => {
    if (me && me.role === 'admin') import('./admin.js').then((m) => m.default(document.getElementById('app')));
  })
  .catch(() => {});
console.debug('JSHMARK:entry:main');
