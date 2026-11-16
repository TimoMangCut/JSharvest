package jsapi

import (
	"slices"
	"testing"
)

// Round 26F: a fetch with options that show no method is a GET; the
// options may be built with Object.assign. Diagnosed on Medusa (dev since
// 26F): this.client.fetch(path, {headers, query}) for every list and
// retrieve, the client's fetch handing its options on through
// Object.assign(Object.assign({}, init), {headers}).
func TestFetchOptionsWithoutMethodAreGET(t *testing.T) {
	src := `
const normalize = (init, headers) => Object.assign(Object.assign({}, init), { headers, credentials: "include" });
const forcePost = (init) => Object.assign({ method: "GET" }, init, { method: "POST" });
class Client {
  constructor(config) { this.config = config; this.fetch_ = this.initClient(); }
  fetch(input, init) { return this.fetch_(input, init); }
  initClient() {
    return async (input, init) => fetch(new URL(input, this.config.baseUrl), normalize(init, {}));
  }
}
class Campaigns {
  constructor(client) { this.client = client; }
  retrieve(id, query, headers) { return this.client.fetch("/admin/campaigns/" + id, { headers, query }); }
  list(query, headers) { return this.client.fetch("/admin/campaigns", { headers, query }); }
  create(body, headers) { return this.client.fetch("/admin/campaigns", { method: "POST", headers, body }); }
  // A method the code computes: no default is guessed.
  act(id, verb, headers) { return this.client.fetch("/admin/campaigns/" + id + "/act", { method: verb, headers }); }
}
class Admin { constructor(client) { this.campaigns = new Campaigns(client); } }
export const sdk = { admin: new Admin(new Client({ baseUrl: "/" })) };
export const ping = () => fetch("/api/ping", forcePost({}));
// Not a fetch: a router's navigation keeps being a route.
export const go = (navigate) => navigate("/settings/profile", { replace: true });
`
	r := Extract([]byte(src))
	got := map[string]bool{}
	for _, e := range r.Endpoints {
		got[e.Method+" "+e.URL] = true
	}
	for _, want := range []string{"GET /admin/campaigns", "GET /admin/campaigns/{}", "POST /admin/campaigns", "POST /api/ping"} {
		if !got[want] {
			t.Errorf("no %s in %v", want, eps(src))
		}
	}
	for _, bad := range []string{"GET /admin/campaigns/{}/act", "GET /settings/profile", "GET /api/ping"} {
		if got[bad] {
			t.Errorf("%s guessed: %v", bad, eps(src))
		}
	}
	if !slices.Contains(r.Routes, "/settings/profile") {
		t.Errorf("/settings/profile is no route: %v", r.Routes)
	}
}

// Round 26F review: no GET is guessed from options the code does not show
// wholly, and a method written after an unknown one is the method.
func TestFetchMethodFromOptionsInOrder(t *testing.T) {
	src := `
export function send(runtimeInit, verb, opts, body, token) {
  fetch("/api/assign-opaque", Object.assign({}, runtimeInit, { headers: {} }));
  fetch("/api/spread-opaque", { ...runtimeInit, headers: {} });
  fetch("/api/assign-override", Object.assign({ method: verb }, { method: "POST" }));
  fetch("/api/spread-override", { ...runtimeInit, method: "PUT" });
  fetch("/api/assign-dynamic-last", Object.assign({ method: "POST" }, { method: verb }));
  fetch("/api/cond-body", Object.assign({}, { headers: {} }, body ? { body } : {}));
  fetch("/api/and-headers", { ...(token && { headers: { authorization: token } }) });
  fetch("/api/cond-method", { ...(body ? { method: "POST", body } : { method: "GET" }) });
}
class Api {
  constructor(client) { this.client = client; }
  items(opts) { return this.client.fetch("/admin/items", opts); }
  tags(query) { return this.client.fetch("/admin/tags", { query }); }
}
export const api = new Api(window.client);
`
	got := map[string]string{}
	for _, e := range Extract([]byte(src)).Endpoints {
		got[e.URL] = e.Method
	}
	for url, want := range map[string]string{
		"/api/assign-opaque": "", "/api/spread-opaque": "",
		"/api/assign-override": "POST", "/api/spread-override": "PUT",
		"/api/assign-dynamic-last": "",
		"/api/cond-body":           "GET", "/api/and-headers": "GET",
		"/api/cond-method": "",
		"/admin/items":     "", "/admin/tags": "GET",
	} {
		m, ok := got[url]
		if !ok && want == "" {
			continue // a request whose method is unknown may also not be listed
		}
		if m != want {
			t.Errorf("%s: method %q, want %q (all: %v)", url, m, want, got)
		}
	}
}

// A method written out stays when extra options the code does not show
// are spread after it (bT("POST", body, extra) → {method, body, ...extra}).
func TestWrittenMethodSurvivesTrailingSpread(t *testing.T) {
	src := `
function opts(m, body, extra) { return { method: m, body: JSON.stringify(body), ...extra }; }
export function save(id, data, extra) { return fetch("/api/things/" + id, opts("POST", data, extra)); }
export function raw(extra) { return fetch("/api/raw", { method: "DELETE", ...extra }); }
`
	got := map[string]string{}
	for _, e := range Extract([]byte(src)).Endpoints {
		got[e.URL] = e.Method
	}
	if got["/api/things/{}"] != "POST" || got["/api/raw"] != "DELETE" {
		t.Errorf("methods %v, want POST /api/things/{} and DELETE /api/raw", got)
	}
}

// Round 26H: a development server's endpoints a bundle carries (Vue's
// devtools: fetch(`${host}__open-in-editor?file=…`)) are no app's.
func TestDevToolEndpointsDropped(t *testing.T) {
	src := "export function open(t){const n=window.VUE_DEVTOOLS_CONFIG?.openInEditorHost??`/`;fetch(`${n}__open-in-editor?file=${encodeURI(t)}`)}" +
		"export const ping=()=>fetch(`/__vite_ping`);export const items=()=>fetch(`/api/items`)"
	for _, e := range Extract([]byte(src)).Endpoints {
		if devToolPath(e.URL) || e.URL != "/api/items" {
			t.Errorf("kept %s %s", e.Method, e.URL)
		}
	}
	for u, want := range map[string]bool{"/__open-in-editor": true, "{}/__vite_ping": true, "https://h.test/__webpack_hmr": true,
		"/__/auth/handler": false, "/api/__meta": false} {
		if devToolPath(u) != want {
			t.Errorf("devToolPath(%s) != %v", u, want)
		}
	}
}
