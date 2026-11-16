// CF-04a: only the archived front page names this script.
fetch('/api/v1/html-only-hook');
const load = () => import('./html-chunk.js');
