// JSHMARK:archive:app
// Today's build: API v2.
const api = (p, o) => fetch('/api/v2' + p, o);
api('/orders');
document.getElementById('open').addEventListener('click', () => api('/items/' + 42));
const search = (q) => api('/search?q=' + encodeURIComponent(q));
// GET /api/v2/hidden-report is built where no extractor follows:
const parts = ['/api/v2', 'hidden' + '-report'];
window.report = () => fetch(parts.join('/'));
// Round 16: API 2.0 of the scooters (1.0 in the 2022 build), and a path
// written where no extractor follows, relative to a client's base: today's
// code all the same.
window.scooter = (id) => fetch('/v2.0/scooters/' + id);
window.links = { invoice: (id) => `billing/v1.0/invoices/${id}` };
