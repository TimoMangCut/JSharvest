verify-app: testbed/verify-check.sh (gate 18, round 23). catalog.jsonl is
the catalog jsharvest verify is given; testbed/cmd/testbed/verifyapp.go
answers as real gateways do:
  /opaque/*    401 to every path and method, a new request_id each time
               (auth_wall_opaque)
  /walled/*    401 likewise, but OPTIONS /walled/admin answers 204 Allow:
               the route is there (verified_alive)
  /spa/*       the SPA's shell for any path (dead_or_fp)
  /api/v1/*    404 {"code":"NO_ROUTE","trace_id":…,"path":…} (dead_or_fp),
               but tenants/<id> 404 TENANT_NOT_FOUND (resource_404), orders
               405 Allow: POST to a GET and 422 {"missing":["warehouse_id"]}
               to a POST without it, items 200, boom 500
  /docs-only/ping 200 (a document's line), other /docs-only/* a page 404
