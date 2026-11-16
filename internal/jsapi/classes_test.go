package jsapi

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/evanw/esbuild/pkg/api"
)

// Round 26A: requests made through classes. Dev fixtures of two common
// shapes of an SDK client, written for this round (the held-out set is
// not looked at while developing):
//   - A: resource classes extending a base that keeps its transport in a
//     #private field; the resource's methods are class fields made by an
//     inherited factory (list = this.makeRequest({…})); the path is given
//     to super(…); the transport builds the URL with new URL(base) and
//     url.pathname = …, from an RFC 6570 template it expands.
//   - B: services with public fields: the prefix given to super(…), the
//     methods inherited (this.get(path) → this.http.send(…)), the client
//     an instance the service is given.
//
// Each is read as written, minified (as a bundle ships it), and through
// the arrow lowering a parse error sends a bundle to (transformJSLower).

const classFixtureA = `
function parseTemplate(template) {
  return {
    expand(vars) {
      return template.replace(/\{([^}]+)\}/g, (_, name) => encodeURIComponent(vars[name] ?? ""));
    },
  };
}
const joinPath = (a, b) => (a.endsWith("/") ? a.slice(0, -1) : a) + (b.startsWith("/") ? b : "/" + b);
async function fetchJSON(url, init) {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error("request failed: " + res.status);
  return res.status === 204 ? undefined : res.json();
}
class Transport {
  #client;
  #path;
  constructor({ client, path = "/" }) {
    this.#client = client;
    this.#path = path;
  }
  request({ method, path = "" }) {
    return async (params = {}, payload) => this.#send(method, path, params, payload);
  }
  async #send(method, path, params, payload) {
    const url = new URL(this.#client.baseUrl);
    url.pathname = joinPath(url.pathname, parseTemplate(joinPath(this.#path, path)).expand(params));
    return fetchJSON(url, { method, body: payload ? JSON.stringify(payload) : undefined });
  }
}
class Resource {
  #transport;
  constructor(client, settings = {}) {
    this.#transport = new Transport({ client, ...settings });
  }
  makeRequest = (args) => this.#transport.request(args);
}
class Projects extends Resource {
  list = this.makeRequest({ method: "GET" });
  get = this.makeRequest({ method: "GET", path: "/{id}" });
  create = this.makeRequest({ method: "POST" });
  archive = this.makeRequest({ method: "POST", path: "/{id}/archive" });
  constructor(client) {
    super(client, { path: "/api/workspaces/{workspace}/projects" });
  }
}
class Members extends Resource {
  // A #private name of its own: Resource's this.#transport is still
  // Resource's (private names are the declaring class's).
  #transport = new Map();
  remove = this.makeRequest({ method: "DELETE", path: "/{userId}" });
  constructor(client) {
    super(client, { path: "/api/workspaces/{workspace}/members" });
  }
}
export class WorkspaceClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.projects = new Projects(this);
    this.members = new Members(this);
  }
}
`

const classFixtureB = `
class ApiClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
  }
  async send(method, path, body) {
    const res = await fetch(this.baseURL + path, { method, body: body && JSON.stringify(body) });
    return res.json();
  }
}
class BaseService {
  constructor(http, prefix) {
    this.http = http;
    this.prefix = prefix;
  }
  get(path) {
    return this.http.send("GET", this.prefix + path);
  }
  post(path, body) {
    return this.http.send("POST", this.prefix + path, body);
  }
}
class InvoiceService extends BaseService {
  constructor(http) {
    super(http, "/billing/invoices");
  }
  list() {
    return this.get("");
  }
  pay(id, card) {
    return this.post("/" + id + "/pay", { card });
  }
}
export const invoices = new InvoiceService(new ApiClient("/api"));
`

// classFixtureC covers the gaps the round 26A review found: a named
// class expression (const Http = (class HttpClient {…}); a base class made
// only through its subclasses, each made once with its own prefix; a
// method and a function field calling fetch themselves with this's fields
// (no helper in between); a call on an instance from outside a class.
const classFixtureC = `
const Http = (class HttpClient {
  constructor(base) {
    this.base = base;
  }
  async send(method, path) {
    const res = await fetch(this.base + path, { method });
    return res.json();
  }
});
class Repo {
  #prefix;
  constructor(http, prefix) {
    this.http = http;
    this.#prefix = prefix;
  }
  all = () => fetch(this.http.base + this.#prefix, { method: "GET" });
  remove(id) {
    return fetch(this.http.base + this.#prefix + "/" + id, { method: "DELETE" });
  }
}
class Users extends Repo {
  constructor(http) {
    super(http, "/v2/users");
  }
}
class Teams extends Repo {
  constructor(http) {
    super(http, "/v2/teams");
  }
}
const http = new Http("https://api.example.test");
export const sdk = { users: new Users(http), teams: new Teams(http), raw: http };
export const health = () => sdk.raw.send("GET", "/v2/health");
`

// classFixtureD: a variadic path join (urlJoin(...parts), each part's
// slashes trimmed by the map), an array literal's join, and a map that
// does something else (upper-casing), which is no path join.
const classFixtureD = `
const SEP = "/";
function urlJoin(...parts) {
  return parts.map((p, i) => {
    if (i > 0 && p.startsWith(SEP)) p = p.slice(1);
    if (i < parts.length - 1 && p.endsWith(SEP)) p = p.slice(0, -1);
    return p;
  }).join(SEP);
}
function joinAll(...parts) {
  return parts.filter(Boolean).map((p) => p.replace(/^\/+|\/+$/g, "") || SEP).join(SEP);
}
function shout(...parts) {
  return parts.map((p) => p.toUpperCase()).join("/");
}
class Catalog {
  constructor(base) {
    this.base = base;
  }
  async items(id) {
    const url = new URL(this.base);
    url.pathname = urlJoin(url.pathname, "/catalog/", "items/", String(id));
    return fetch(url, { method: "GET" });
  }
  tags() {
    return fetch(["/api", "catalog", "tags"].join("/"), { method: "GET" });
  }
  sections() {
    return fetch(joinAll("/api/", "", "/catalog/", "sections"), { method: "GET" });
  }
  loud() {
    return fetch(shout("/api", "loud"), { method: "POST" });
  }
}
export const catalog = new Catalog("https://shop.example.test/v1/");
`

// lowerTrigger is a valid arrow the parser fails on (round 25E), which
// sends the script through transformJSLower.
const lowerTrigger = "\nexport const lowerTrigger = ({ a: b = 1 } = { a: 1 }) => b;\n"

// classFixtureATS is fixture A as TypeScript emits it without
// useDefineForClassFields: the fields set in the constructor, after
// super(…).
var classFixtureATS = strings.NewReplacer(
	`  list = this.makeRequest({ method: "GET" });
  get = this.makeRequest({ method: "GET", path: "/{id}" });
  create = this.makeRequest({ method: "POST" });
  archive = this.makeRequest({ method: "POST", path: "/{id}/archive" });
  constructor(client) {
    super(client, { path: "/api/workspaces/{workspace}/projects" });
  }`,
	`  constructor(client) {
    super(client, { path: "/api/workspaces/{workspace}/projects" });
    this.list = this.makeRequest({ method: "GET" });
    this.get = this.makeRequest({ method: "GET", path: "/{id}" });
    this.create = this.makeRequest({ method: "POST" });
    this.archive = this.makeRequest({ method: "POST", path: "/{id}/archive" });
  }`,
	`  remove = this.makeRequest({ method: "DELETE", path: "/{userId}" });
  constructor(client) {
    super(client, { path: "/api/workspaces/{workspace}/members" });
  }`,
	`  constructor(client) {
    super(client, { path: "/api/workspaces/{workspace}/members" });
    this.remove = this.makeRequest({ method: "DELETE", path: "/{userId}" });
  }`,
	`  makeRequest = (args) => this.#transport.request(args);`,
	`  makeRequest(args) {
    return this.#transport.request(args);
  }`,
).Replace(classFixtureA)

func classVariants(t *testing.T, src string) map[string]string {
	t.Helper()
	min := api.Transform(src, api.TransformOptions{Loader: api.LoaderJS, Target: api.ES2022, Format: api.FormatESModule,
		MinifyIdentifiers: true, MinifySyntax: true, MinifyWhitespace: true})
	if len(min.Errors) > 0 {
		t.Fatalf("minify: %v", min.Errors)
	}
	return map[string]string{"source": src, "minified": string(min.Code), "lowered": src + lowerTrigger}
}

// classEndpoints are the endpoints with a method (the string pass also
// lists the paths it reads, methodless).
func classEndpoints(r Result) []string {
	var out []string
	for _, e := range r.Endpoints {
		if e.Method == "" {
			continue
		}
		out = append(out, strings.TrimSpace(e.Method+" "+e.URL))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestClassFixtures(t *testing.T) {
	want := map[string][]string{
		// joinPath(prefix, "") is prefix + "/": the URL the code makes.
		"A": {
			"DELETE {}/api/workspaces/{}/members/{}",
			"GET {}/api/workspaces/{}/projects/",
			"GET {}/api/workspaces/{}/projects/{}",
			"POST {}/api/workspaces/{}/projects/",
			"POST {}/api/workspaces/{}/projects/{}/archive",
		},
		"ATS": {
			"DELETE {}/api/workspaces/{}/members/{}",
			"GET {}/api/workspaces/{}/projects/",
			"GET {}/api/workspaces/{}/projects/{}",
			"POST {}/api/workspaces/{}/projects/",
			"POST {}/api/workspaces/{}/projects/{}/archive",
		},
		"C": {
			"DELETE https://api.example.test/v2/teams/{}",
			"DELETE https://api.example.test/v2/users/{}",
			"GET https://api.example.test/v2/health",
			"GET https://api.example.test/v2/teams",
			"GET https://api.example.test/v2/users",
		},
		"D": {
			"GET /api/catalog/sections",
			"GET /api/catalog/tags",
			"GET https://shop.example.test/v1/catalog/items/{}",
		},
		"B": {
			"GET /api/billing/invoices",
			"POST /api/billing/invoices/{}/pay",
		},
	}
	if classFixtureATS == classFixtureA {
		t.Fatal("the TypeScript variant of fixture A is fixture A")
	}
	for name, src := range map[string]string{"A": classFixtureA, "ATS": classFixtureATS, "B": classFixtureB, "C": classFixtureC, "D": classFixtureD} {
		for v, code := range classVariants(t, src) {
			r := Extract([]byte(code))
			if r.Error != "" {
				t.Errorf("%s/%s: %s", name, v, r.Error)
				continue
			}
			if v == "lowered" && !r.ASTLowered {
				t.Errorf("%s/%s: not lowered", name, v)
			}
			if got := classEndpoints(r); !slices.Equal(got, want[name]) {
				t.Errorf("%s/%s:\n got %v\nwant %v", name, v, got, want[name])
			}
			if name == "B" {
				if ep := byURL(r)["POST /api/billing/invoices/{}/pay"]; !slices.Equal(ep.Body, []string{"card"}) {
					t.Errorf("%s/%s: pay body %v, want [card]", name, v, ep.Body)
				}
			}
		}
	}
}

// Round 26B review: which instances a base class's calls are read in must
// not depend on Go's map order. Nine subclasses, each made once: the
// first eight (maxInstanceSites) in source order, every run.
func TestInstanceSitesDeterministic(t *testing.T) {
	src := "class Repo { constructor(prefix) { this.prefix = prefix; } all() { return fetch(\"https://api.example.test\" + this.prefix, { method: \"GET\" }); } }\n"
	var want []string
	for i := 1; i <= 9; i++ {
		src += fmt.Sprintf("class R%d extends Repo { constructor() { super(\"/r%d\"); } }\nexport const r%d = new R%d();\n", i, i, i, i)
		if i <= maxInstanceSites {
			want = append(want, fmt.Sprintf("GET https://api.example.test/r%d", i))
		}
	}
	slices.Sort(want)
	for run := 0; run < 30; run++ {
		if got := classEndpoints(Extract([]byte(src))); !slices.Equal(got, want) {
			t.Fatalf("run %d:\n got %v\nwant %v", run, got, want)
		}
	}
}

// Round 26B review: an options or body parameter handed on is no path
// (forwardsPath reads the URL argument only): these calls are read in the
// instance, its base and prefix known.
func TestForwardsPathReadsTheURLOnly(t *testing.T) {
	src := `
class Store {
  constructor(base) {
    this.base = base;
    this.prefix = "/v3/store";
  }
  create(payload) {
    return fetch(this.base + "/items", payload);
  }
  update(id, body) {
    return fetch(this.base + this.prefix + "/items/" + id, body);
  }
  send(path) {
    return fetch(this.base + path, { method: "POST" });
  }
}
export const store = new Store("https://store.example.test");
`
	r := Extract([]byte(src))
	var urls []string
	for _, e := range r.Endpoints {
		urls = append(urls, e.URL)
	}
	for _, u := range []string{"https://store.example.test/items", "https://store.example.test/v3/store/items/{}"} {
		if !slices.Contains(urls, u) {
			t.Errorf("no %s in %v", u, urls)
		}
	}
	// send(path) hands its parameter on as the path: a frame, not an
	// endpoint of the instance's.
	for _, u := range urls {
		if u == "https://store.example.test{}" {
			t.Errorf("frame read in the instance: %v", urls)
		}
	}
}

// Round 26C review: a helper with a summary decides which of its
// arguments are a path. postItem's path is its own ("/items"), putItem's
// takes id as a segment: neither call hands a path on, both are read in
// the instance. send(base, path) splits its base off: path is a whole
// path, so relay(p) hands its parameter on (a frame).
func TestForwardsPathThroughHelpers(t *testing.T) {
	src := `
function send(base, path, body) {
  return fetch(base + path, { method: "POST", body });
}
class Store {
  constructor(base) {
    this.base = base;
  }
  postItem(payload) {
    return fetch(this.base + "/items", { method: "POST", body: payload });
  }
  putItem(id, payload) {
    return fetch(this.base + "/items/" + id, { method: "PUT", body: payload });
  }
  create(payload) {
    return this.postItem(payload);
  }
  update(id, body) {
    return this.putItem(id, body);
  }
  relay(p, body) {
    return send(this.base, p, body);
  }
}
export const store = new Store("https://store.example.test");
`
	r := Extract([]byte(src))
	got := classEndpoints(r)
	for _, want := range []string{"POST https://store.example.test/items", "PUT https://store.example.test/items/{}"} {
		if !slices.Contains(got, want) {
			t.Errorf("no %s in %v", want, got)
		}
	}
	for _, e := range got {
		if strings.HasSuffix(e, "store.example.test{}") || strings.HasPrefix(e, "POST {}") || strings.HasPrefix(e, "PUT {}") {
			t.Errorf("a frame or a base lost: %s in %v", e, got)
		}
	}
}
