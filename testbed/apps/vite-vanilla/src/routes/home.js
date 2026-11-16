console.debug('JSHMARK:route:home');

export default function (app) {
  app.innerHTML = '<h1>Home</h1><button id="report">Generate report</button><pre id="out"></pre>';
  app.querySelector('#report').addEventListener('click', async () => {
    const { run } = await import('../features/report.js');
    app.querySelector('#out').textContent = run();
  });
  const w = new Worker(new URL('../workers/calc.worker.js', import.meta.url), { type: 'module' });
  w.postMessage('hi');
}
