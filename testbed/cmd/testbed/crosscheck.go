package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// crossserve serves the five local multi-host fixtures of Gate 19
// (testbed/crosscheck-check.sh, round 24):
//
//  1. sub.jsh.test + jsh.test + api.jsh.test + ext.other.test (ENH-01, ENH-03, ENH-04a)
//  2. nest.jsh.test (ENH-02, ENH-09, ENH-13)
//  3. n8n.jsh.test (ENH-10, ENH-12)
//  4. Vite multi-chunk ESM + bundled Axios Basic auth on sub.jsh.test (ENH-05, ENH-08)
//  5. dicom.jsh.test / and /covered (ENH-06, ENH-07, ENH-11)
func crossserve(args []string) error {
	fs := flag.NewFlagSet("crossserve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8770", "listen address")
	fs.Parse(args)

	var logMu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		host := strings.ToLower(r.Host)
		if idx := strings.IndexByte(host, ':'); idx >= 0 {
			host = host[:idx]
		}
		switch host {
		case "sub.jsh.test":
			serveSubHost(rec, r)
		case "jsh.test":
			serveParentHost(rec, r)
		case "api.jsh.test":
			serveAPIHost(rec, r)
		case "ext.other.test":
			serveThirdPartyHost(rec, r)
		case "nest.jsh.test":
			serveNestHost(rec, r)
		case "n8n.jsh.test":
			serveN8nHost(rec, r)
		case "dicom.jsh.test":
			serveDicomHost(rec, r)
		case "redir.jsh.test":
			http.Redirect(rec, r, "http://www.jsh.test:8770/app", http.StatusFound)
		case "www.jsh.test":
			serveWwwHost(rec, r)
		case "wedge.jsh.test":
			serveWedgeHost(rec, r)
		case "dead.jsh.test":
			serveDeadHost(rec, r)
		case "tsmap.jsh.test":
			serveTSMapHost(rec, r)
		default:
			rec.WriteHeader(404)
			fmt.Fprint(rec, "unknown host")
		}
		u := r.URL.Path
		if r.URL.RawQuery != "" {
			u += "?" + r.URL.RawQuery
		}
		logMu.Lock()
		fmt.Printf("%s %s %d %s %s\n", time.Now().UTC().Format(time.RFC3339Nano), r.Host, rec.status, r.Method, u)
		os.Stdout.Sync()
		logMu.Unlock()
	})
	return http.ListenAndServe(*addr, handler)
}

func serveSubHost(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<html><head><title>Sub Portal</title>
<script>
window.axios = {
  create: function(cfg) {
    return {
      get: function(p, o) {
        var q = o && o.params ? "?" + new URLSearchParams(o.params).toString() : "";
        return fetch(cfg.baseURL + p + q);
      },
      post: function(p, b) {
        return fetch(cfg.baseURL + p, { method: "POST", body: JSON.stringify(b || {}) });
      }
    };
  }
};
</script>
</head><body>
<a href="/manuals">Manuals</a>
<a href="http://jsh.test:8770/parent-page">Parent Site</a>
<script type="module" src="/assets/view-def.js"></script>
<script src="http://ext.other.test:8770/third.js"></script>
</body></html>`)
	case "/manuals":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>Manuals</title><p>Subdomain manuals page</p>`)
	case "/assets/index-abc.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `
function axiosBasicSerializer(cfg, hdrs) {
  if (cfg.auth) {
    const u = cfg.auth.username || "";
    const p = cfg.auth.password ? unescape(encodeURIComponent(cfg.auth.password)) : "";
    hdrs.set("Authorization", "Basic " + btoa(u + ":" + p));
  }
}
const sr = axios.create({ baseURL: window.ENV_API || "http://api.jsh.test:8770/fe/v1" });
const legacy = axios.create({ baseURL: "/fe/v1" });
const gm = p => sr.get("/itemType", { params: p });
const gmLegacy = p => legacy.get("/itemType", { params: p });
const ly = e => sr.get("/manualAvailability", { params: e });
export { gm as c, gmLegacy as cl, ly as e };
`)
	case "/assets/view-def.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `
import { c as getModels, e as Z } from "./index-abc.js";
getModels({ country: "vn", lang: "en" });
export function checkAvailability(itemType, version, lang, country) {
  return Z({ itemType, version, lang, country });
}
`)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>Sub Portal</title><div id="app"></div>`)
	}
}

func serveParentHost(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/parent-page":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>Parent Corp</title><script src="/parent.js"></script>`)
	case "/parent.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `function parentLead() { return fetch("/api/parent-lead", { method: "POST" }); }`)
	default:
		w.WriteHeader(404)
	}
}

func serveAPIHost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/fe/v1/itemType":
		q := r.URL.Query()
		if q.Get("country") != "vn" || q.Get("lang") != "en" {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":"expected observed country=vn&lang=en, got %s"}`, r.URL.RawQuery)
			return
		}
		fmt.Fprint(w, `{"data":["ModelA","ModelB"]}`)
	case "/fe/v1/manualAvailability":
		q := r.URL.Query()
		for _, req := range []string{"itemType", "country", "lang", "version"} {
			if q.Get(req) == "" {
				w.WriteHeader(400)
				fmt.Fprintf(w, `{"error":"missing %s"}`, req)
				return
			}
		}
		if q.Get("country") == "1" || q.Get("lang") == "sample" {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":"bad sample query %s"}`, r.URL.RawQuery)
			return
		}
		fmt.Fprint(w, `{"available":true}`)
	default:
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":"not found"}`)
	}
}

func serveThirdPartyHost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.URL.Path == "/third.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `function sendAnalytics() { return fetch("http://ext.other.test:8770/v1/third-party-track", { method: "POST" }); }`)
		return
	}
	w.WriteHeader(404)
}

func serveNestHost(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}
	switch {
	case r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>Nest Service</title><script src="/app.js"></script>`)
	case r.URL.Path == "/app.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		var sb strings.Builder
		sb.WriteString("function calls(id) {\n")
		// 7 /p01../p07 + /express + /uniform404 + /v1/room + /v1 + /zchat = 12
		// ready prefixes, so parameterized 2-segment /zchat/tools falls back to /zchat.
		for i := 1; i <= 7; i++ {
			fmt.Fprintf(&sb, "  fetch('/p%02d/ping');\n", i)
		}
		sb.WriteString("  fetch('/express/submit', { method: 'POST' });\n")
		sb.WriteString("  fetch('/uniform404/dead', { method: 'POST' });\n")
		sb.WriteString("  fetch('/zchat/status');\n")
		sb.WriteString("  fetch('/zchat/tools/' + id, { method: 'DELETE' });\n")
		sb.WriteString("}\n")
		fmt.Fprint(w, sb.String())
	case r.URL.Path == "/api-json":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
  "openapi": "3.0.0",
  "info": {"title": "Nest API", "version": "1.0"},
  "security": [{"bearer": []}],
  "components": {
    "securitySchemes": {
      "bearer": {"type": "http", "bearerFormat": "JWT"}
    }
  },
  "paths": {
    "/v1/test": {
      "get": {"security": [], "responses": {"200": {"description": "public"}}}
    },
    "/v1/room/create": {
      "post": {"responses": {"201": {"description": "created"}}}
    },
    "/v1/room/{id}": {
      "put": {
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "updated"}}
      }
    }
  }
}`)
	case r.URL.Path == "/v1/test" && r.Method == "GET":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	case strings.HasPrefix(r.URL.Path, "/express/"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(404)
		fmt.Fprintf(w, "<!DOCTYPE html>\n<html lang=\"en\"><head><title>Error</title></head><body><pre>Cannot %s %s</pre></body></html>\n", r.Method, r.URL.Path)
	case strings.HasPrefix(r.URL.Path, "/uniform404/"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":"not_found","message":"No such endpoint"}`)
	case strings.HasPrefix(r.URL.Path, "/v1/"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprintf(w, `{"statusCode":404,"message":"Cannot %s %s","error":"Not Found"}`, r.Method, r.URL.Path)
	case strings.HasPrefix(r.URL.Path, "/zchat"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(500)
		fmt.Fprint(w, `<html><title>500 Internal Server Error</title><body>Chat gateway down</body></html>`)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>Nest Service</title><div id="root"></div>`)
	}
}

func serveN8nHost(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>n8n</title><div id="app"></div><script src="/app.js"></script>`)
	case r.URL.Path == "/app.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `
function Da(opts) {
  return fetch((opts.baseURL || "") + opts.endpoint, { method: opts.method || "GET" });
}
function Y(ctx, method, endpoint, data) {
  return Da({ method: method, baseURL: ctx.baseUrl, endpoint: endpoint, data: data });
}
const bootCtx = JSON.parse('{"baseUrl":"/rest"}');
Y(bootCtx, "GET", "/settings");
window.n8nApi = function(ctx) {
  sendEvent("click", "POST", "/api/track");
  Y(ctx, "GET", "/api-keys");
  return Y(ctx, "GET", "/active-workflows");
};
const spaRoute = "/services/change-plan";
window.spaRoute = spaRoute;
`)
	case r.URL.Path == "/rest/settings":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"version":"1.0.0"}}`)
	case r.URL.Path == "/rest/active-workflows":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":["wf-alpha"]}`)
	case strings.HasPrefix(r.URL.Path, "/rest/"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprint(w, `{"code":404,"message":"Not Found"}`)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>n8n</title><div id="app"></div><script src="/app.js"></script>`)
	}
}

func serveDicomHost(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<html><head><title>DICOM Viewer</title>
<style>
  body { margin: 0; font-family: sans-serif; }
  #toolbar { padding: 20px; }
  #btn-open-folder { width: 160px; height: 44px; }
  #viewport { width: 320px; height: 220px; margin: 20px; background: #111; color: #eee; }
  #overlay { position: fixed; inset: 0; pointer-events: none; z-index: 50; }
</style></head><body>
<div id="toolbar"><button id="btn-open-folder" type="button">Open DICOM Folder</button></div>
<div id="viewport">Viewport</div>
<div id="overlay">HUD Overlay</div>
<script>
document.getElementById("btn-open-folder").addEventListener("click", function() {
  const inp = document.createElement("input");
  inp.type = "file";
  inp.webkitdirectory = true;
  inp.multiple = true;
  inp.addEventListener("change", async function() {
    const skip = /\.(txt|png|jpg|jpeg|json|xml)$/i;
    for (const f of Array.from(inp.files || [])) {
      if (skip.test(f.name)) continue;
      const buf = new Uint8Array(await f.slice(128, 132).arrayBuffer());
      const magic = String.fromCharCode(...buf);
      if (magic === "DICM") {
        fetch("/api/dicom-loaded?file=" + encodeURIComponent(f.name) + "&magic=" + magic);
      }
    }
  });
  inp.click();
});
document.getElementById("viewport").addEventListener("contextmenu", function(ev) {
  ev.preventDefault();
  fetch("/api/viewport-menu");
});
</script>
</body></html>`)
	case "/covered":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<html><head><title>Covered Modal</title>
<style>
  body { margin: 0; }
  #covered-box { position: fixed; top: 40px; left: 40px; width: 140px; height: 80px; background: #ccc; }
  #covered-upload-btn { position: fixed; top: 160px; left: 40px; width: 160px; height: 44px; }
  #blocker { position: fixed; top: 0; left: 0; width: 400px; height: 400px; background: rgba(0,0,0,0.5); pointer-events: auto; z-index: 99; }
</style></head><body>
<div id="covered-box">Right-click target</div>
<button id="covered-upload-btn" type="button">Upload File</button>
<div id="blocker">Modal backdrop</div>
<script>
document.getElementById("covered-box").addEventListener("contextmenu", function(ev) {
  ev.preventDefault();
  fetch("/api/covered-menu");
});
document.getElementById("covered-upload-btn").addEventListener("click", function() {
  const inp = document.createElement("input");
  inp.type = "file";
  inp.addEventListener("change", function() {
    if (inp.files && inp.files.length > 0) {
      fetch("/api/covered-file?file=" + encodeURIComponent(inp.files[0].name));
    }
  });
  inp.click();
});
</script>
</body></html>`)
	default:
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		w.WriteHeader(404)
	}
}

func serveWwwHost(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/app":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><head><title>Redirected App</title></head><body>
<a href="http://jsh.test:8770/parent-page">Parent Corp</a>
<script src="/portal.js"></script>
</body></html>`)
	case "/portal.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `
const svc = { username: "svc", password: "hunter2" };
function loadPortal(q) {
  return fetch("/api/v1/profile?otp=" + encodeURIComponent(q), {
    headers: { Authorization: "Basic " + btoa(svc.username + ":" + svc.password) }
  });
}
`)
	default:
		w.WriteHeader(404)
	}
}

func serveWedgeHost(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><head><title>Wedge Root</title></head><body>
<a href="/page1-wedge">Page 1 (wedges V8)</a>
<a href="/page2-ok">Page 2 (healthy)</a>
<script type="module" src="/boot.js"></script>
</body></html>`)
	case "/boot.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `
export function lazyDead() {
  return [
    import("http://dead.jsh.test:8770/c1.js"),
    import("http://dead.jsh.test:8770/c2.js"),
    import("http://dead.jsh.test:8770/c3.js"),
    import("http://dead.jsh.test:8770/c4.js"),
    import("http://dead.jsh.test:8770/c5.js")
  ];
}
export function lazySlow() {
  return import("/slow-chunk.js");
}
`)
	case "/slow-chunk.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.WriteHeader(200)
		fmt.Fprint(w, "// header arrived quickly\n")
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(8500 * time.Millisecond):
		}
		fmt.Fprint(w, `export function slowCall() { return fetch("/api/from-slow-chunk"); }`+"\n")
	case "/page1-wedge":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><head><title>Wedge Page</title>
<script src="/wedge-marker.js"></script>
<script>for(;;){}</script>
</head><body>Wedged</body></html>`)
	case "/wedge-marker.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `function page1Marker() { return fetch("/api/from-page1"); }`)
	case "/page2-ok":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><head><title>Healthy Page 2</title>
<script src="/page2.js"></script>
</head><body>Healthy</body></html>`)
	case "/page2.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `function page2Marker() { return fetch("/api/from-page2"); }`)
	default:
		w.WriteHeader(404)
	}
}

func serveDeadHost(w http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(12 * time.Second):
		w.WriteHeader(504)
	}
}

func serveTSMapHost(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><head><title>TS Map App</title></head><body>
<div id="app"></div>
<script type="module" src="/assets/bundle.js"></script>
</body></html>`)
	case r.URL.Path == "/assets/bundle.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		fmt.Fprint(w, `function rawReq(cfg) {
  var q = cfg.params ? "?" + new URLSearchParams(cfg.params).toString() : "";
  var init = { method: cfg.method || "GET" };
  if (cfg.data) init.body = JSON.stringify(cfg.data);
  return fetch((cfg.baseURL || "") + cfg.endpoint + q, init);
}
function get(baseUrl, endpoint, params) {
  return rawReq({ method: "GET", baseURL: baseUrl, endpoint: endpoint, params: params });
}
function post(baseUrl, endpoint, data) {
  return rawReq({ method: "POST", baseURL: baseUrl, endpoint: endpoint, data: data });
}
function streamRequest(ctx, endpoint, payload) {
  return fetch(ctx.baseUrl + endpoint, { method: "POST", body: JSON.stringify(payload) });
}
const boot = JSON.parse('{"baseUrl":"/rest"}');
get(boot.baseUrl, "/v1/workflows", { active: "true" });
window.tsmapApi = function(ctx, p) {
  post(ctx.baseUrl, "/v1/workflows", { name: p.name, nodes: p.nodes });
  streamRequest(ctx, "/ai/stream", { prompt: p.q, sessionId: p.sid });
  post(ctx.baseUrl, "/admin/audit-logs", { days: 7 });
  return fetch("/rest/v1/vue-summary?filter=" + encodeURIComponent(p.f));
};
//# sourceMappingURL=/assets/bundle.js.map
`)
	case r.URL.Path == "/assets/bundle.js.map":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		httpTS := `export interface ReqOpts {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  baseURL: string;
  endpoint: string;
  data?: Record<string, unknown>;
  params?: Record<string, unknown>;
}
export enum ApiPrefix {
  Admin = "/admin",
}
function Injectable(): ClassDecorator {
  return (target) => target;
}
@Injectable()
export class HttpTransport {}
export async function rawRequest<T>(config: ReqOpts): Promise<T> {
  const { method, baseURL, endpoint, data, params } = config;
  const init: RequestInit = { method };
  if (data !== undefined) init.body = JSON.stringify(data);
  void params;
  const res = await fetch(` + "`${baseURL}${endpoint}`" + `, init);
  return (await res.json()) as T;
}
`
		helpersTS := `import { rawRequest } from "./http";
export async function get<T>(baseUrl: string, endpoint: string, params?: Record<string, unknown>): Promise<T> {
  return await rawRequest<T>({ method: "GET", baseURL: baseUrl, endpoint, params });
}
export async function post<T>(baseUrl: string, endpoint: string, data?: Record<string, unknown>): Promise<T> {
  return await rawRequest<T>({ method: "POST", baseURL: baseUrl, endpoint, data });
}
export async function streamRequest(ctx: { baseUrl: string }, endpoint: string, payload: Record<string, unknown>) {
  return await fetch(` + "`${ctx.baseUrl}${endpoint}`" + `, { method: "POST", body: JSON.stringify(payload) });
}
`
		indexTS := `export * from "./helpers";
import { post } from "./helpers";
import { ApiPrefix } from "./http";
export async function postAdmin<T>(ctx: { baseUrl: string }, path: string, body: Record<string, unknown>): Promise<T> {
  return await post<T>(ctx.baseUrl, ` + "`${ApiPrefix.Admin}${path}`" + `, body);
}
`
		workflowsTS := `import { get, post, streamRequest, postAdmin } from "@app/client";
export async function listWorkflows(ctx: { baseUrl: string }) {
  return await get(ctx.baseUrl, "/v1/workflows", { active: true, limit: 25 });
}
export async function createWorkflow(ctx: { baseUrl: string }, name: string, nodes: unknown[]) {
  return await post(ctx.baseUrl, "/v1/workflows", { name, nodes });
}
export async function askStream(ctx: { baseUrl: string }, prompt: string, sessionId: string) {
  return await streamRequest(ctx, "/ai/stream", { prompt, sessionId });
}
export async function queryAuditLogs(ctx: { baseUrl: string }, days: number) {
  return await postAdmin(ctx, "/audit-logs", { days });
}
export async function unusedLegacyEndpoint(ctx: { baseUrl: string }) {
  return await get(ctx.baseUrl, "/v1/legacy-treeshaken", { dryRun: true });
}
`
		vueSFC := "<template>\n" +
			"  <div class=\"wf\">\n" +
			"    <h1>Workflows</h1>\n" +
			"    <button>Run</button>\n" +
			"  </div>\n" +
			"</template>\n" +
			"<script lang=\"ts\">\n" +
			"interface ViewState { filter: string }\n" +
			"export function fetchVueSummary(state: ViewState) {\n" +
			"  return fetch(\"/rest/v1/vue-summary?filter=\" + encodeURIComponent(state.filter));\n" +
			"}\n" +
			"</script>\n" +
			"<style scoped>\n" +
			".wf { padding: 8px; }\n" +
			"</style>\n"
		smap := map[string]any{
			"version": 3,
			"file":    "bundle.js",
			"sources": []string{
				"packages/@app/client/src/http.ts",
				"packages/@app/client/src/helpers.ts",
				"packages/@app/client/src/index.ts",
				"src/api/workflows.api.ts",
				"src/views/WorkflowView.vue",
			},
			"sourcesContent": []string{httpTS, helpersTS, indexTS, workflowsTS, vueSFC},
		}
		b, _ := json.Marshal(smap)
		w.Write(b)
	case r.URL.Path == "/rest/v1/workflows" && r.Method == "GET":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"wf-1"}]}`)
	case r.URL.Path == "/rest/v1/vue-summary" && r.Method == "GET":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"summary":"ready"}`)
	case r.URL.Path == "/rest/v1/legacy-treeshaken" && r.Method == "GET":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"legacy":true}`)
	case (r.URL.Path == "/rest/ai/stream" || r.URL.Path == "/rest/admin/audit-logs") && r.Method == "GET":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprintf(w, `{"statusCode":404,"message":"Cannot GET %s","error":"Not Found"}`, r.URL.Path)
	case strings.HasPrefix(r.URL.Path, "/rest/"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprint(w, `{"code":404,"message":"Not Found"}`)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>TS Map App</title><div id="app"></div>`)
	}
}

// crosscheck scores all five scenarios of Gate 19.
func crosscheck(args []string) error {
	fs := flag.NewFlagSet("crosscheck", flag.ExitOnError)
	subDir := fs.String("sub", "", "sub.jsh.test_8770/anon directory")
	subLog := fs.String("sub-log", "", "server log for sub crawl+verify")
	nestDir := fs.String("nest", "", "nest.jsh.test_8770/anon directory")
	n8nDir := fs.String("n8n", "", "n8n.jsh.test_8770/anon directory")
	n8nStrings := fs.String("n8n-strings", "", "verify.json path from n8n verify -include-strings")
	dicomDir := fs.String("dicom", "", "dicom.jsh.test_8770/anon directory (viewer)")
	covDir := fs.String("covered", "", "dicom.jsh.test_8770/anon directory (/covered)")
	redirDir := fs.String("redir", "", "redir.jsh.test_8770/anon directory")
	redirRedDir := fs.String("redir-redacted", "", "redir-red/redir.jsh.test_8770/anon directory")
	redirLog := fs.String("redir-log", "", "server log for redir httpcrawl")
	wedgeDir := fs.String("wedge", "", "wedge.jsh.test_8770/anon directory")
	wedgeLog := fs.String("wedge-log", "", "server log for wedge cdp crawl")
	tsmapDir := fs.String("tsmap", "", "tsmap.jsh.test_8770/anon directory")
	tsmapSrcVerify := fs.String("tsmap-source-only", "", "verify.json path from tsmap verify -include-source-only")
	fs.Parse(args)

	failed := 0
	check := func(name string, ok bool, detail string) {
		if ok {
			fmt.Printf("  pass  %s\n", name)
			return
		}
		failed++
		fmt.Printf("  FAIL  %s: %s\n", name, detail)
	}

	type ep struct {
		Method     string   `json:"method"`
		Host       string   `json:"host"`
		Path       string   `json:"path"`
		Base       string   `json:"base"`
		Bases      []string `json:"bases"`
		Origin     string   `json:"origin"`
		Query      []string `json:"query"`
		Body       []string `json:"body"`
		Headers    []string `json:"headers"`
		Auth       []string `json:"auth"`
		Confidence string   `json:"confidence"`
		ThirdParty bool     `json:"third_party"`
		SourceOnly bool     `json:"source_only"`
		Static     []struct {
			Script string `json:"script"`
			Line   int    `json:"line"`
		} `json:"static"`
		Params []struct {
			Name   string   `json:"name"`
			In     string   `json:"in"`
			Values []string `json:"values"`
		} `json:"params"`
	}
	readEps := func(dir string) []ep {
		b, _ := os.ReadFile(filepath.Join(dir, "endpoints.jsonl"))
		var out []ep
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var e ep
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				out = append(out, e)
			}
		}
		return out
	}
	type vres struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
		URL     string `json:"url"`
		Prefix  string `json:"prefix"`
	}
	readVerify := func(path string) map[string]vres {
		var rep struct {
			Results []vres `json:"results"`
		}
		b, _ := os.ReadFile(path)
		json.Unmarshal(b, &rep)
		m := map[string]vres{}
		for _, r := range rep.Results {
			m[r.Path] = r
		}
		return m
	}

	// --- Scenario 1 & 4: sub.jsh.test + api.jsh.test + Vite ESM + Axios Basic ---
	subEps := readEps(*subDir)
	subLogBytes, _ := os.ReadFile(*subLog)
	check("1. -page-scope auto did not visit parent jsh.test/parent-page",
		!bytes.Contains(subLogBytes, []byte("jsh.test:8770 200 GET /parent-page")), string(subLogBytes))

	var itemType, manual *ep
	for i := range subEps {
		switch subEps[i].Path {
		case "/fe/v1/itemType", "/itemType":
			itemType = &subEps[i]
		case "/fe/v1/manualAvailability", "/manualAvailability":
			manual = &subEps[i]
		}
	}
	check("1. cross-origin itemType keeps api.jsh.test:8770 host and /fe/v1 path/base",
		itemType != nil && itemType.Host == "api.jsh.test:8770" && (itemType.Base == "/fe/v1" || itemType.Path == "/fe/v1/itemType"),
		fmt.Sprintf("%+v", itemType))
	hasVN := itemType != nil && slices.ContainsFunc(itemType.Params, func(p struct {
		Name   string   `json:"name"`
		In     string   `json:"in"`
		Values []string `json:"values"`
	}) bool {
		return p.Name == "country" && slices.Contains(p.Values, "vn")
	})
	check("1. observed query param country=vn recorded in Params.Values", hasVN, fmt.Sprintf("%+v", itemType))

	subV := readVerify(filepath.Join(*subDir, "verify", "verify.json"))
	cmV, okCM := subV["/fe/v1/itemType"]
	if !okCM {
		cmV = subV["/itemType"]
	}
	check("1. verify probes api.jsh.test with country=vn&lang=en -> verified_alive",
		cmV.Verdict == "verified_alive" && strings.Contains(cmV.URL, "api.jsh.test:8770/fe/v1/itemType?country=vn&lang=en"),
		fmt.Sprintf("%+v", cmV))

	var expIdx struct {
		Drafts []struct {
			ThirdParty bool   `json:"third_party"`
			File       string `json:"file"`
		} `json:"drafts"`
	}
	if b, err := os.ReadFile(filepath.Join(*subDir, "export", "drafts", "index.json")); err == nil {
		json.Unmarshal(b, &expIdx)
	}
	tpFiles := 0
	for _, d := range expIdx.Drafts {
		if d.ThirdParty && d.File != "" {
			tpFiles++
		}
	}
	check("1. third_party endpoints emit 0 .http draft files", tpFiles == 0, fmt.Sprintf("%d files", tpFiles))

	check("4. Vite multi-chunk ESM links [itemType, country, lang, version] on /manualAvailability",
		manual != nil && slices.Equal(manual.Query, []string{"country", "itemType", "lang", "version"}),
		fmt.Sprintf("%+v", manual))
	maV, okMA := subV["/fe/v1/manualAvailability"]
	if !okMA {
		maV = subV["/manualAvailability"]
	}
	check("4. /manualAvailability draft verified_alive with linked query params",
		maV.Verdict == "verified_alive", fmt.Sprintf("%+v", maV))

	intelBytes, _ := os.ReadFile(filepath.Join(*subDir, "intel.json"))
	check("4. bundled Axios Basic {} suppressed from intel.json",
		!bytes.Contains(intelBytes, []byte("Basic {}")), string(intelBytes))

	// --- Scenario 2: nest.jsh.test (ENH-02, ENH-09, ENH-13) ---
	nestEps := readEps(*nestDir)
	var v1Test, roomCreate *ep
	for i := range nestEps {
		if nestEps[i].Method == "GET" && nestEps[i].Path == "/v1/test" {
			v1Test = &nestEps[i]
		}
		if nestEps[i].Method == "POST" && nestEps[i].Path == "/v1/room/create" {
			roomCreate = &nestEps[i]
		}
	}
	check("2. OpenAPI security attaches auth:[bearer] to POST /v1/room/create",
		roomCreate != nil && slices.Equal(roomCreate.Auth, []string{"bearer"}) && slices.Contains(roomCreate.Headers, "Authorization"),
		fmt.Sprintf("%+v", roomCreate))
	check("2. OpenAPI security:[] keeps GET /v1/test public (empty auth)",
		v1Test != nil && len(v1Test.Auth) == 0 && !slices.Contains(v1Test.Headers, "Authorization"),
		fmt.Sprintf("%+v", v1Test))

	nestV := readVerify(filepath.Join(*nestDir, "verify", "verify.json"))
	check("2. NestJS 404 Cannot GET on POST /v1/room/create -> write_unverified",
		nestV["/v1/room/create"].Verdict == "write_unverified", fmt.Sprintf("%+v", nestV["/v1/room/create"]))
	check("2. Express HTML 404 Cannot GET on POST /express/submit -> write_unverified",
		nestV["/express/submit"].Verdict == "write_unverified", fmt.Sprintf("%+v", nestV["/express/submit"]))
	check("2. Uniform JSON 404 on POST /uniform404/dead -> dead_or_fp",
		nestV["/uniform404/dead"].Verdict == "dead_or_fp", fmt.Sprintf("%+v", nestV["/uniform404/dead"]))
	check("2. GET /v1/test -> verified_alive",
		nestV["/v1/test"].Verdict == "verified_alive", fmt.Sprintf("%+v", nestV["/v1/test"]))
	check("2. /zchat/tools/{} beyond maxPrefixes uses /zchat parent 500 canary -> dead_or_fp",
		nestV["/zchat/tools/{}"].Verdict == "dead_or_fp" && strings.HasSuffix(nestV["/zchat/tools/{}"].Prefix, "/zchat"),
		fmt.Sprintf("%+v", nestV["/zchat/tools/{}"]))

	// --- Scenario 3: n8n.jsh.test (ENH-10, P0-1, ENH-12) ---
	n8nEps := readEps(*n8nDir)
	var activeWF, sendEv *ep
	for i := range n8nEps {
		if strings.HasSuffix(n8nEps[i].Path, "/active-workflows") {
			activeWF = &n8nEps[i]
		}
		if strings.HasSuffix(n8nEps[i].Path, "/api/track") {
			sendEv = &n8nEps[i]
		}
	}
	n8nIntelBytes, _ := os.ReadFile(filepath.Join(*n8nDir, "intel.json"))
	check("3. Y(ctx, GET, /active-workflows) inherits observed /rest base",
		activeWF != nil && slices.Contains(activeWF.Bases, "http://n8n.jsh.test:8770/rest") && activeWF.Origin == "",
		fmt.Sprintf("%+v", activeWF))
	check("3. Y(ctx, GET, /api-keys) does NOT pollute intel.json bases with /api-keys and sendEvent stays non-client",
		!bytes.Contains(n8nIntelBytes, []byte(`"/api-keys"`)) && (sendEv == nil || !strings.HasPrefix(sendEv.Path, "{}")),
		fmt.Sprintf("intel=%s sendEv=%+v", string(n8nIntelBytes), sendEv))

	n8nV := readVerify(filepath.Join(*n8nDir, "verify", "verify.json"))
	awV, okAW := n8nV["{}/active-workflows"]
	if !okAW {
		awV = n8nV["/active-workflows"]
	}
	check("3. /active-workflows probes /rest/active-workflows -> verified_alive",
		awV.Verdict == "verified_alive" && strings.HasSuffix(awV.URL, "/rest/active-workflows"),
		fmt.Sprintf("%+v", awV))
	check("3. bare string /services/change-plan skipped by default",
		n8nV["/services/change-plan"].Verdict == "skipped", fmt.Sprintf("%+v", n8nV["/services/change-plan"]))

	n8nStrV := readVerify(*n8nStrings)
	check("3. bare string /services/change-plan with -include-strings -> client_route",
		n8nStrV["/services/change-plan"].Verdict == "client_route", fmt.Sprintf("%+v", n8nStrV["/services/change-plan"]))

	// --- Scenario 5: dicom.jsh.test / and /covered (ENH-06, ENH-07, ENH-11) ---
	readExplore := func(dir string) (untrusted, errs, covSkip int, urls []string) {
		var run struct {
			Explore struct {
				Untrusted int            `json:"untrusted"`
				Errors    int            `json:"errors"`
				Skipped   map[string]int `json:"skipped"`
			} `json:"explore"`
		}
		b, _ := os.ReadFile(filepath.Join(dir, "run.json"))
		json.Unmarshal(b, &run)
		rb, _ := os.ReadFile(filepath.Join(dir, "requests.jsonl"))
		sc := bufio.NewScanner(bytes.NewReader(rb))
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var q struct {
				URL string `json:"url"`
			}
			if json.Unmarshal(sc.Bytes(), &q) == nil && q.URL != "" {
				urls = append(urls, q.URL)
			}
		}
		return run.Explore.Untrusted, run.Explore.Errors, run.Explore.Skipped["covered-for-good"], urls
	}
	hasURL := func(urls []string, sub string) bool {
		return slices.ContainsFunc(urls, func(u string) bool { return strings.Contains(u, sub) })
	}
	dUntrusted, dErrs, _, dURLs := readExplore(*dicomDir)
	check("5. pointer-events:none overlay pierced with trusted clicks (untrusted=0, errors=0)",
		dUntrusted == 0 && dErrs == 0, fmt.Sprintf("untrusted=%d errors=%d", dUntrusted, dErrs))
	check("5. webkitdirectory IM000001 DICOM sample parsed (magic=DICM) and viewport contextmenu fired",
		hasURL(dURLs, "/api/dicom-loaded?file=IM000001&magic=DICM") && hasURL(dURLs, "/api/viewport-menu"),
		strings.Join(dURLs, ", "))

	cUntrusted, cErrs, cSkip, cURLs := readExplore(*covDir)
	check("5. covered contextmenu counted in skipped[covered-for-good] with errors=0",
		cSkip >= 1 && cErrs == 0, fmt.Sprintf("covered-for-good=%d errors=%d", cSkip, cErrs))
	check("5. covered upload button fallback click (UserGesture:true) opens FileChooser",
		cUntrusted >= 1 && hasURL(cURLs, "/api/covered-file?file=document.txt"),
		fmt.Sprintf("untrusted=%d urls=%v", cUntrusted, cURLs))

	// --- Scenario 6: redir.jsh.test -> www.jsh.test httpcrawl + hardcoded Basic + export -redact -drafts ---
	redirEps := readEps(*redirDir)
	redirLogBytes, _ := os.ReadFile(*redirLog)
	hasProfile := slices.ContainsFunc(redirEps, func(e ep) bool { return e.Path == "/api/v1/profile" })
	check("6. httpcrawl follows seed 302 redirect redir.jsh.test -> www.jsh.test/app under -page-scope auto without visiting parent jsh.test",
		hasProfile && !bytes.Contains(redirLogBytes, []byte("jsh.test:8770 200 GET /parent-page")),
		fmt.Sprintf("hasProfile=%v log=%s", hasProfile, string(redirLogBytes)))
	redirIntel, _ := os.ReadFile(filepath.Join(*redirDir, "intel.json"))
	check("6. hardcoded btoa Basic auth preserved in unredacted intel.json (Basic c3ZjOmh1bnRlcjI=)",
		bytes.Contains(redirIntel, []byte("Basic c3ZjOmh1bnRlcjI=")), string(redirIntel))
	var redIdx struct {
		Drafts []struct {
			File string `json:"file"`
		} `json:"drafts"`
	}
	redIdxPath := filepath.Join(*redirRedDir, "export", "drafts", "index.json")
	if b, err := os.ReadFile(redIdxPath); err == nil {
		json.Unmarshal(b, &redIdx)
	}
	redDraftOK := len(redIdx.Drafts) > 0
	for _, d := range redIdx.Drafts {
		raw, err := os.ReadFile(filepath.Join(*redirRedDir, "export", "drafts", d.File))
		if err != nil {
			redDraftOK = false
			break
		}
		if _, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw))); err != nil {
			redDraftOK = false
			break
		}
		if bytes.Contains(raw, []byte("c3ZjOmh1bnRlcjI=")) || !bytes.Contains(raw, []byte("REDACTED_")) {
			redDraftOK = false
			break
		}
	}
	check("6. export -redact -drafts masks Basic credentials with valid HTTP syntax",
		redDraftOK, fmt.Sprintf("drafts=%d", len(redIdx.Drafts)))

	// --- Scenario 7: wedge.jsh.test + dead.jsh.test (recycleTab + resolver circuit breaker + slow body > 8s) ---
	wedgeEps := readEps(*wedgeDir)
	wedgeLogBytes, _ := os.ReadFile(*wedgeLog)
	deadHits := 0
	for _, line := range bytes.Split(wedgeLogBytes, []byte("\n")) {
		if bytes.Contains(line, []byte("dead.jsh.test:8770")) {
			deadHits++
		}
	}
	hasSlow := slices.ContainsFunc(wedgeEps, func(e ep) bool { return e.Path == "/api/from-slow-chunk" })
	hasP1 := slices.ContainsFunc(wedgeEps, func(e ep) bool { return e.Path == "/api/from-page1" })
	hasP2 := slices.ContainsFunc(wedgeEps, func(e ep) bool { return e.Path == "/api/from-page2" })
	check("7. resolver 3-strike TTFB circuit breaker stops dead.jsh.test at <= 3 hits",
		deadHits >= 1 && deadHits <= 3, fmt.Sprintf("deadHits=%d", deadHits))
	check("7. resolver two-stage timeout reads 8.5s chunk body (/api/from-slow-chunk)",
		hasSlow, fmt.Sprintf("eps=%+v", wedgeEps))
	check("7. recycleTab replaces V8-wedged /page1-wedge and harvests /page2-ok (/api/from-page2)",
		hasP1 && hasP2, fmt.Sprintf("hasP1=%v hasP2=%v eps=%+v", hasP1, hasP2, wedgeEps))

	// --- Scenario 8: tsmap.jsh.test (Round 25: 3-module Via + barrel export * + 2-arg get/post + streamRequest + TS/Vue sourcemap + -include-source-only) ---
	if *tsmapDir != "" {
		tsEps := readEps(*tsmapDir)
		byMP := map[string]*ep{}
		for i := range tsEps {
			byMP[tsEps[i].Method+" "+tsEps[i].Path] = &tsEps[i]
		}
		findEP := func(method, suffix string) *ep {
			if e := byMP[method+" "+suffix]; e != nil {
				return e
			}
			if e := byMP[method+" {}"+suffix]; e != nil {
				return e
			}
			if e := byMP[method+" /rest"+suffix]; e != nil {
				return e
			}
			return nil
		}

		wfGet := findEP("GET", "/v1/workflows")
		wfPost := findEP("POST", "/v1/workflows")
		aiStream := findEP("POST", "/ai/stream")
		auditPost := findEP("POST", "/admin/audit-logs")
		legacyGet := findEP("GET", "/v1/legacy-treeshaken")
		vueGet := byMP["GET /rest/v1/vue-summary"]

		check("8. 3-module Via + barrel export * + TS enum resolves POST /admin/audit-logs with body [days]",
			auditPost != nil && !auditPost.SourceOnly && slices.Contains(auditPost.Body, "days"),
			fmt.Sprintf("%+v", auditPost))
		check("8. 2-arg get/post and streamRequest resolve query/body keys across TS sourcemap",
			wfGet != nil && slices.Contains(wfGet.Query, "limit") &&
				wfPost != nil && slices.Equal(wfPost.Body, []string{"name", "nodes"}) &&
				aiStream != nil && slices.Equal(aiStream.Body, []string{"prompt", "sessionId"}),
			fmt.Sprintf("wfGet=%+v wfPost=%+v aiStream=%+v", wfGet, wfPost, aiStream))
		check("8. tree-shaken TS route /v1/legacy-treeshaken tagged source_only:true while active routes stay source_only:false",
			legacyGet != nil && legacyGet.SourceOnly && wfGet != nil && !wfGet.SourceOnly && wfPost != nil && !wfPost.SourceOnly && aiStream != nil && !aiStream.SourceOnly,
			fmt.Sprintf("legacy=%+v wfGet=%+v", legacyGet, wfGet))
		vueLine10 := vueGet != nil && slices.ContainsFunc(vueGet.Static, func(st struct {
			Script string `json:"script"`
			Line   int    `json:"line"`
		}) bool {
			return strings.HasSuffix(st.Script, "WorkflowView.vue") && st.Line == 10
		})
		check("8. Vue SFC WorkflowView.vue preserves exact Line 10 on /rest/v1/vue-summary",
			vueLine10, fmt.Sprintf("%+v", vueGet))

		tsV := readVerify(filepath.Join(*tsmapDir, "verify", "verify.json"))
		legDef, okLeg := tsV["{}/v1/legacy-treeshaken"]
		if !okLeg {
			legDef = tsV["/v1/legacy-treeshaken"]
		}
		check("8. default verify skips source_only endpoint /v1/legacy-treeshaken",
			legDef.Verdict == "skipped" && strings.Contains(legDef.Reason, "source_only"),
			fmt.Sprintf("%+v", legDef))

		tsSrcV := readVerify(*tsmapSrcVerify)
		legInc, okInc := tsSrcV["{}/v1/legacy-treeshaken"]
		if !okInc {
			legInc = tsSrcV["/v1/legacy-treeshaken"]
		}
		check("8. verify -include-source-only probes /rest/v1/legacy-treeshaken -> verified_alive",
			legInc.Verdict == "verified_alive" && strings.Contains(legInc.URL, "/rest/v1/legacy-treeshaken"),
			fmt.Sprintf("%+v", legInc))
	}

	if failed > 0 {
		return errors.New("crosscheck failed")
	}
	return nil
}
