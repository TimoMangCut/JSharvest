// A shared worker that writes as soon as it starts, and once more later.
const post = () => fetch('/api/write-shared', { method: 'POST', body: 'x' });
post();
setTimeout(post, 1500);
onconnect = () => {};
