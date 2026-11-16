// The 2022 build: API v1.
fetch('/api/v1/orders');
fetch('/api/v1/legacy-export?format=csv');
fetch('/api/v2/items/' + 7);
const debugPanel = '/internal/debug-panel';
fetch('/api/v2/hidden-report');
window.oldScooter = (id) => fetch('/v1.0/scooters/' + id);
