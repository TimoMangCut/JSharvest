console.debug('JSHMARK:route:home');

export default function (app) {
  app.innerHTML = '<h1>Home</h1><button id="report">Generate report</button><pre id="out"></pre>';
  // Loads only when the button is clicked.
  app.querySelector('#report').addEventListener('click', async () => {
    const { run } = await import('../features/report.js');
    app.querySelector('#out').textContent = run();
  });
  // A dedicated worker, which in turn lazy-loads a chunk of its own.
  const w = new Worker(new URL('../workers/hash.worker.js', import.meta.url));
  w.postMessage('hi');
}
