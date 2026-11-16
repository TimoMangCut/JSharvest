pipe-app: testbed/pipeline-check.sh (gate 17, round 22B). Served by
testbed/cmd/testbed (pipeApp) under three names, with
--host-resolver-rules "MAP *.jsh.test 127.0.0.1":
  app.jsh.test  the app (dist/index.html, app.js), /api/boot-status (JSON,
                linked), /.well-known/openid-configuration
  api.jsh.test  a NestJS API: /api-json (its OpenAPI), every other path a
                NestJS 404; every answer x-powered-by Express and CORS
                * with credentials
  spa.jsh.test  an SPA (dist/spa.html, spa.js) that calls
                /api/spa-boot-data as it boots, which no page links to
