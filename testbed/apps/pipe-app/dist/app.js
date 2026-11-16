// pipe-app (testbed/pipeline-check.sh): an app on app.jsh.test whose API
// is on api.jsh.test, a NestJS server that keeps its description at
// /api-json; the app's own origin is an OpenID Provider too.
var MARK = "JSHMARK:pipe:app"; // testbed/bench.sh
var API = "http://api.jsh.test:8770";
function items() {
  return fetch(API + "/v1/items");
}
function status() {
  return fetch("/api/boot-status").then(function (r) { return r.json(); });
}
status();
