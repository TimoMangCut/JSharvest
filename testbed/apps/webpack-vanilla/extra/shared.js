console.debug('JSHMARK:shared-worker:main');
onconnect = (e) => e.ports[0].postMessage('hi');
