console.debug('JSHMARK:route:login');

export default function (app, navigate) {
  app.innerHTML = `<h1>Login</h1>
    <form id="f">
      <input name="email" type="email" required placeholder="email">
      <input name="password" type="password" required minlength="6" placeholder="password">
      <button>Sign in</button>
    </form>`;
  // Loads only after a valid form is submitted and the login request succeeds.
  app.querySelector('#f').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = new URLSearchParams(new FormData(e.target));
    const res = await fetch('/api/login', { method: 'POST', body });
    if (res.ok) {
      await import('../features/welcome.js');
      navigate('/account');
    }
  });
}
