console.debug('JSHMARK:worker:main');

self.onmessage = async () => {
  await import('./calc-dep.js');
};
