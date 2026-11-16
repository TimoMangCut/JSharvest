console.debug('JSHMARK:entry:main');

const routes = {
  '/': () => import('./routes/home.js'),
  '/about': () => import('./routes/about.js'), // linked from the nav
  '/hidden': () => import('./routes/hidden.js'), // in this table only; no link anywhere
};

async function render(path) {
  const load = routes[path] || routes['/'];
  const mod = await load();
  const app = document.getElementById('app');
  app.innerHTML = '';
  mod.default(app);
}

document.addEventListener('click', (e) => {
  const a = e.target.closest('a');
  if (a && a.origin === location.origin) {
    e.preventDefault();
    history.pushState({}, '', a.pathname);
    render(a.pathname);
  }
});
window.addEventListener('popstate', () => render(location.pathname));

setTimeout(() => import('./features/telemetry.js'), 800);

render(location.pathname);
