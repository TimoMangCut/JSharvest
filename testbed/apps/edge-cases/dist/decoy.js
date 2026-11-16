// Never called: only the resolver reads these references. The first is in
// scope and must be fetched; the second is on another host (localhost is
// not 127.0.0.1) and must never be requested.
function inScope() { return import("./decoy-in-scope.js"); }
function outOfScope() { return import("http://localhost:8770/decoy-out-of-scope.js"); }
function viaRedirect() { return import("./redirect-bait.js"); }
// In scope only when the testbed runs under *.jsh.test names.
function crossOrigin() { return import("http://cdn.jsh.test:8770/cdn-chunk.js"); }
