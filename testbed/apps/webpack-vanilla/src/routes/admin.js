console.debug('JSHMARK:route:admin');

export default function (app) {
  app.innerHTML = '<h1>Admin</h1>';
  // The server only serves this file to an admin session.
  const s = document.createElement('script');
  s.src = '/private/admin-panel.js';
  document.body.appendChild(s);
}
