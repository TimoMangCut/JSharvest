console.debug('JSHMARK:guard:worker');
fetch('/api/write-worker', { method: 'POST', body: 'w' });
