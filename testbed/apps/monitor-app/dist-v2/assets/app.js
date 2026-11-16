// JSHMARK:monitor:app
// Build v2: /api/old-feed is gone; /api/news is new; search takes a page,
// and, for the staff, deleted items; an admin's export.
fetch('/api/items/42');
fetch('/api/search?q=' + encodeURIComponent('shoes') + '&page=1');
fetch('/api/report');
fetch('/api/report?again=1');
fetch('/api/news');
import('/assets/extra.js');
if (window.STAFF) fetch('/api/search?q=x&include_deleted=1');
if (window.ADMIN) fetch('/api/admin/export', { method: 'POST' });
