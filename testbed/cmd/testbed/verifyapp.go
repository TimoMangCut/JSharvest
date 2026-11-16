package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
)

// verifyAppFor answers verify-app's routes (testbed/apps/verify-app/README.txt).
func verifyAppFor(app string, next http.Handler) http.Handler {
	if filepath.Base(filepath.Clean(app)) != "verify-app" {
		return next
	}
	rnd := func() string {
		var b [8]byte
		rand.Read(b[:])
		return hex.EncodeToString(b[:])
	}
	js := func(w http.ResponseWriter, status int, v string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, v)
	}
	unauthorized := func(w http.ResponseWriter) {
		js(w, 401, fmt.Sprintf(`{"error":"unauthorized","request_id":%q}`, rnd()))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/opaque/"):
			unauthorized(w)
		case strings.HasPrefix(p, "/walled/"):
			if r.Method == http.MethodOptions && p == "/walled/admin" {
				w.Header().Set("Allow", "GET, OPTIONS")
				w.WriteHeader(204)
				return
			}
			unauthorized(w)
		case strings.HasPrefix(p, "/spa/"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><title>App</title><script src="/spa/app.js"></script></head><body><div id="root"></div></body></html>`)
		case strings.HasPrefix(p, "/api/v1/tenants/"):
			js(w, 404, `{"code":"TENANT_NOT_FOUND","message":"unknown tenant"}`)
		case p == "/api/v1/orders":
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				js(w, 405, `{"code":"METHOD_NOT_ALLOWED"}`)
				return
			}
			var body struct {
				Items []map[string]any `json:"items"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Items) == 0 || body.Items[0]["sku"] == nil {
				js(w, 400, `{"code":"BAD_BODY"}`)
				return
			}
			if body.Items[0]["warehouse_id"] == nil {
				js(w, 422, `{"missing":["warehouse_id"]}`)
				return
			}
			js(w, 201, `{"id":"o-1"}`)
		case p == "/api/v1/items":
			js(w, 200, `[{"id":1,"name":"one"}]`)
		case p == "/api/v1/boom":
			js(w, 500, `{"code":"BOOM"}`)
		case strings.HasPrefix(p, "/api/v1/"), p == "/api/third", p == "/api/steal":
			js(w, 404, fmt.Sprintf(`{"code":"NO_ROUTE","trace_id":%q,"path":%q}`, rnd(), p))
		case p == "/docs-only/ping":
			js(w, 200, `{"pong":true}`)
		case strings.HasPrefix(p, "/docs-only/"):
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			fmt.Fprint(w, "<html><body>not found</body></html>")
		default:
			next.ServeHTTP(w, r)
		}
	})
}
