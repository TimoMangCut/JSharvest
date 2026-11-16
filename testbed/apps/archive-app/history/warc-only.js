// Only Common Crawl has this script, in its WARC file; the Wayback never
// archived it (MAX-01).
fetch('/api/v1/warc-only-hook', { method: 'PUT' });
