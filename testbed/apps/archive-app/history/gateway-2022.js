// A 2022 module on a client with a base: its paths are relative to it
// (ARC-07: the base stays in historical.jsonl; ARC-09: today's code still
// writes billing/v1.0/invoices/, so that one is today's).
const http = axios.create({ baseURL: '/api-gateway' });
http.post('legacy/v1.0/export', { from: 1, to: 2 });
window.invoice = (id) => http.get('billing/v1.0/invoices/' + id);
