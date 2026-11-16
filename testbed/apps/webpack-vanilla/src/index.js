// Each module logs one JSHMARK:<category>:<name> marker. The scorer collects
// the markers from the sources and looks for them in jsharvest's output.
console.debug('JSHMARK:entry:main');

// Code that only ever exists as an eval string, never as a file. It is
// base64 so that the marker is not also visible inside this bundle.
eval(atob('d2luZG93Ll9fanNoRXZhbCA9ICJKU0hNQVJLOmV2YWw6bWFpbiI='));

const routes = {
  '/': () => import('./routes/home.js'),
  '/about': () => import('./routes/about.js'), // linked from the nav
  '/login': () => import('./routes/login.js'), // linked from the nav
  '/hidden': () => import('./routes/hidden.js'), // in this table only; no link anywhere
  '/account': () => import('./routes/account.js'), // reachable only once logged in (client-side check)
  '/admin': () => import('./routes/admin.js'), // loads server-gated JS
};

export function loggedIn() {
  return document.cookie.split('; ').some((c) => c.startsWith('session='));
}

async function render(path) {
  const load = routes[path] || routes['/'];
  const mod = await load();
  const app = document.getElementById('app');
  app.innerHTML = '';
  mod.default(app, navigate);
}

export function navigate(path) {
  history.pushState({}, '', path);
  render(path);
}

document.addEventListener('click', (e) => {
  const a = e.target.closest('a');
  if (a && a.origin === location.origin) {
    e.preventDefault();
    navigate(a.pathname);
  }
});
window.addEventListener('popstate', () => render(location.pathname));

if (loggedIn()) {
  const nav = document.querySelector('nav');
  nav.insertAdjacentHTML('beforeend', ' · <a href="/account">Account</a> · <a href="/admin">Admin</a>');
}

// Loads on a timer, with no user action.
setTimeout(() => import('./features/telemetry.js'), 800);

// Scripts that run outside the page: a service worker (with importScripts), a
// shared worker, and a frame from another site, which Chrome puts in its own
// process. The testbed server serves these from extra/ as they are.
navigator.serviceWorker?.register('/extra/sw.js');
if (window.SharedWorker) new SharedWorker('/extra/shared.js').port.start();
const frame = document.createElement('iframe');
frame.src = `${location.protocol}//${location.hostname === 'localhost' ? '127.0.0.1' : 'localhost'}:${location.port}/extra/frame.html`;
frame.style.display = 'none';
document.body.appendChild(frame);

render(location.pathname);
