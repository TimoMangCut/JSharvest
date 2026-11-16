package main

import (
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"strings"
)

// pipeAppFor serves pipe-app by host name (testbed/apps/pipe-app/README.txt):
// app.jsh.test, api.jsh.test (a NestJS API), spa.jsh.test.
func pipeAppFor(app string, next http.Handler) http.Handler {
	if filepath.Base(filepath.Clean(app)) != "pipe-app" {
		return next
	}
	dist := filepath.Join(app, "dist")
	nest404 := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"statusCode":404,"message":"Cannot %s %s","error":"Not Found"}`, r.Method, r.URL.Path)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if i := strings.LastIndexByte(host, ':'); i > 0 {
			host = host[:i]
		}
		switch {
		case strings.HasPrefix(host, "api."):
			w.Header().Set("X-Powered-By", "Express")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			if r.Method == http.MethodGet && r.URL.Path == "/api-json" {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"Pipe API","version":"1.0"},"paths":{`+
					`"/v1/items":{"get":{"operationId":"list","parameters":[{"name":"page","in":"query","schema":{"type":"integer"}}]}},`+
					`"/v1/items/{id}":{"get":{"operationId":"get","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]},`+
					`"delete":{"operationId":"remove","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]}}}}`)
				return
			}
			nest404(w, r)
		case strings.HasPrefix(host, "spa."):
			switch {
			case r.URL.Path == "/api/spa-boot-data":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"n":3}`)
			case r.URL.Path == "/spa.js":
				serveFile(w, r, filepath.Join(dist, "spa.js"))
			case path.Ext(r.URL.Path) == "":
				serveFile(w, r, filepath.Join(dist, "spa.html")) // the SPA's fallback
			default:
				http.NotFound(w, r)
			}
		default:
			switch r.URL.Path {
			case "/api/boot-status":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"ok":true,"version":"22b"}`)
			case "/.well-known/openid-configuration":
				w.Header().Set("Content-Type", "application/json")
				iss := "http://app.jsh.test:8770"
				fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":"%s/oauth/authorize","token_endpoint":"%s/oauth/token",`+
					`"userinfo_endpoint":"%s/oauth/userinfo","jwks_uri":"%s/.well-known/jwks.json","end_session_endpoint":"%s/oauth/logout"}`,
					iss, iss, iss, iss, iss, iss)
			case "/spa.html", "/spa.js":
				http.NotFound(w, r)
			default:
				next.ServeHTTP(w, r)
			}
		}
	})
}
