// JSHMARK:flows:worker
onmessage = (e) => {
  const send = () => fetch('/api/export?format=' + e.data.format);
  if (e.data.delay) setTimeout(send, e.data.delay); else send();
};
