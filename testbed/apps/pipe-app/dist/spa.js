// spa.jsh.test: an SPA whose only API call is the one it sends as it
// boots; no page links to it (crawl -spa-boot).
fetch("/api/spa-boot-data", { headers: { Accept: "application/json" } })
  .then(function (r) { return r.json(); })
  .then(function (d) { document.getElementById("root").textContent = "items " + d.n; });
