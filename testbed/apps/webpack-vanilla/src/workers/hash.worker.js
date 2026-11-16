console.debug('JSHMARK:worker:main');

self.onmessage = async () => {
  await import('./worker-dep.js');
};
