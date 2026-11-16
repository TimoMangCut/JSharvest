package endpoints

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

var t0 = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

func inApp(h string) bool { return h == "app.test" }

func req(id int, method, u string) Request {
	return Request{Run: "R1", ID: id, Time: t0.Add(time.Duration(id) * time.Second), Method: method, URL: u, ResourceType: "Fetch", Outcome: "ok"}
}

func byPath(eps []Endpoint) map[string]Endpoint {
	out := map[string]Endpoint{}
	for _, e := range eps {
		out[strings.TrimSpace(e.Method+" "+e.Host+e.Path)] = e
	}
	return out
}

// The lifecycle: what the code calls is static until a request to it is
// seen; then both. What only the traffic has is observed.
func TestLifecycle(t *testing.T) {
	main := Script{SHA256: "aa", URLs: []string{"http://app.test/main.js"}, Result: jsapi.Extract([]byte(
		`const c=mk({baseURL:"/api"});fetch("/api/articles/"+s,{method:"DELETE"});fetch("/api/articles/"+s+"/comments",{method:"POST"});` +
			`c.post("/profiles/"+u+"/follow");fetch("/api/me");const x="/api/me";`))}
	admin := Script{SHA256: "bb", URLs: []string{"http://app.test/447.chunk.js"}, Result: jsapi.Extract([]byte(
		`fetch("/api/admin/users/"+i,{method:"DELETE"})`))}
	reqs := []Request{
		req(1, "GET", "http://app.test/api/me"),
		req(2, "POST", "http://app.test/api/articles/hello/comments"),
		req(3, "POST", "http://app.test/api/profiles/jake/follow"),
		req(4, "GET", "http://app.test/api/items/42"),
		req(5, "GET", "http://app.test/api/items/108"),
		req(6, "GET", "http://cdn.other.test/v1/pixel"),
		{Run: "R1", ID: 7, Method: "GET", URL: "http://app.test/static/x.js", ResourceType: "Script"},
	}
	reqs[1].Outcome = "held_back:write"
	got := byPath(Build([]Script{main, admin}, reqs, inApp))

	if e := got["GET /api/me"]; e.Status != Both || e.Observed.Requests != 1 || len(e.Static) != 2 || e.Static[0].Col == e.Static[1].Col-1 {
		t.Fatalf("GET /api/me (a fetch and a string): %+v", e)
	}
	if e := got["POST /api/articles/{}/comments"]; e.Status != Both || e.Observed.Outcomes[0] != "held_back:write" {
		t.Fatalf("comments: %+v", e)
	}
	if e := got["DELETE /api/articles/{}"]; e.Status != Static || e.Observed != nil {
		t.Fatalf("the comments request went to the less specific endpoint: %+v", e)
	}
	if e := got["POST /profiles/{}/follow"]; e.Status != Both || e.Base != "/api" || e.Bases != nil {
		t.Fatalf("the client's base, confirmed by the traffic: %+v", e)
	}
	if e := got["DELETE /api/admin/users/{}"]; e.Status != Static || e.Static[0].Script != "http://app.test/447.chunk.js" {
		t.Fatalf("admin chunk: %+v", e)
	}
	if e := got["GET app.test/api/items/{id}"]; e.Status != ObservedOnly || e.Observed.Requests != 2 {
		t.Fatalf("observed only: %+v", got)
	}
	if e := got["GET cdn.other.test/v1/pixel"]; !e.ThirdParty {
		t.Fatalf("third party: %+v", e)
	}
	for k := range got {
		if strings.Contains(k, "x.js") {
			t.Fatalf("a script request is in the catalog: %s", k)
		}
	}
}

// The cache: made once per script and extractor version, read back by a
// reader that analyses nothing.
func TestAnalyzeCache(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "js"), 0o755)
	os.WriteFile(filepath.Join(dir, "js", "aa.js"), []byte(`fetch("/api/x",{method:"PUT"})`), 0o644)
	os.WriteFile(filepath.Join(dir, "js", "bb.js"), []byte(`fetch("/api/y"`), 0o644)
	os.WriteFile(filepath.Join(dir, "index.jsonl"), []byte(`{"sha256":"aa","urls":["http://app.test/a.js"]}
{"sha256":"bb","urls":["http://cdn.test/b.js"],"tags":["third-party"]}
{"sha256":"cc","urls":["http://app.test/c.js"]}
`), 0o644)
	if got, _ := Load(dir); len(got) != 0 {
		t.Fatalf("loaded before any analysis: %d", len(got))
	}
	ss, err := Analyze(dir, 2)
	if err != nil || len(ss) != 3 {
		t.Fatal(len(ss), err)
	}
	if ss[0].Endpoints[0].Method != "PUT" ||
		!ss[1].LooseFallback || !strings.HasPrefix(ss[1].ParseError, "parse") || len(ss[1].Endpoints) != 1 || ss[1].Endpoints[0].URL != "/api/y" || !ss[1].ThirdParty ||
		!strings.HasPrefix(ss[2].Error, "read:") {
		t.Fatalf("%+v", ss)
	}
	got, _ := Load(dir)
	if len(got) != 2 { // the missing script is not cached: it may come later
		t.Fatalf("cached %d", len(got))
	}
	// A cache of another version is made again.
	os.WriteFile(filepath.Join(dir, CacheDir, "aa.json"), []byte(`{"version":0,"endpoints":[]}`), 0o644)
	ss, _ = Analyze(dir, 1)
	if len(ss[0].Endpoints) != 1 {
		t.Fatalf("stale cache kept: %+v", ss[0])
	}
	if err := Write(dir, Build(ss, nil, inApp)); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, File)); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

func TestPattern(t *testing.T) {
	ep := &Endpoint{Path: "{}/ws/notes", client: true}
	if re := pattern(ep); !re.MatchString("/ws/notes") || !re.MatchString("/v2/ws/notes") || re.MatchString("/ws/notes/x") {
		t.Fatal(re)
	}
	ep = &Endpoint{Path: "/api/{}/items"}
	if re := pattern(ep); !re.MatchString("/api/a/b/items") || re.MatchString("/api/items") {
		t.Fatal(re)
	}
	if h, p := split("https://api.app.test/v2/s"); h != "api.app.test" || p != "/v2/s" {
		t.Fatal(h, p)
	}
	if h, p := split("api/users"); h != "" || p != "/api/users" {
		t.Fatal(h, p)
	}
	if !slices.Equal(uniq([]string{"b", "a", "b", ""}), []string{"a", "b"}) {
		t.Fatal()
	}
}

// A large run: matching stays fast because most endpoints are skipped by
// their fixed text before their regexp.
func BenchmarkBuild(b *testing.B) {
	var src strings.Builder
	for i := range 2000 {
		src.WriteString(`fetch("/api/r` + strconv.Itoa(i) + `/items/"+x,{method:"POST"});`)
	}
	scripts := []Script{{SHA256: "aa", Result: jsapi.Extract([]byte(src.String()))}}
	var reqs []Request
	for i := range 20000 {
		reqs = append(reqs, req(i, "POST", "http://app.test/api/r"+strconv.Itoa(i%2500)+"/items/"+strconv.Itoa(i)))
	}
	b.ResetTimer()
	for range b.N {
		Build(scripts, reqs, inApp)
	}
}

// An outcome of ok is any answer; the statuses tell a 403 from a 200, and a
// held-back request has none.
func TestStatuses(t *testing.T) {
	s := Script{SHA256: "aa", URLs: []string{"http://app.test/main.js"}, Result: jsapi.Extract([]byte(`fetch("/api/admin/stats");fetch("/api/save",{method:"POST"})`))}
	a, b, c := req(1, "GET", "http://app.test/api/admin/stats"), req(2, "GET", "http://app.test/api/admin/stats"), req(3, "POST", "http://app.test/api/save")
	a.Status, b.Status, c.Status, c.Outcome = 403, 200, 200, "held_back:write"
	eps := byPath(Build([]Script{s}, []Request{a, b, c}, inApp))
	if got := eps["GET /api/admin/stats"].Observed.Statuses; !slices.Equal(got, []int64{200, 403}) {
		t.Fatalf("statuses %v", got)
	}
	if got := eps["POST /api/save"].Observed.Statuses; len(got) != 0 {
		t.Fatalf("a held-back request has no status: %v", got)
	}
}

// P0-2 & P0-5: sensitive/PII/REDACTED sample values are rejected while benign
// values (country, country_code, lang) are kept; non-API observed paths
// (/locales/en/translation.json) never propagate /locales to {} client routes.
func TestSampleFilteringAndPropagatedBaseGuards(t *testing.T) {
	s := Script{
		SHA256: "s1",
		URLs:   []string{"http://app.test/assets/index.js"},
		Result: jsapi.Extract([]byte(`
			async function f(ctx) {
				await Y(ctx, "GET", "/active-workflows");
				fetch("/api/lookup?country=x&country_code=x&lang=x&otp=x&pwd=x&pass=x&user_pin=x&cvv=x&email=x&token=x");
			}
		`)),
	}
	r1 := req(1, "GET", "http://app.test/api/lookup?country=vn&country_code=VN&lang=en&otp=123456&pwd=hunter2&pass=secret&user_pin=9999&cvv=321&email=u@app.test&token=REDACTED_12ab34cd")
	r1.Body = `{"otp":"654321","email":"body@app.test","country":"vn","note":"REDACTED_deadbeef","jwt_like":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}`
	rLocales := req(2, "GET", "http://app.test/locales/en/translation.json")

	got := byPath(Build([]Script{s}, []Request{r1}, inApp))
	lookup := got["GET /api/lookup"]
	vals := map[string][]string{}
	for _, p := range lookup.Params {
		vals[p.In+"."+p.Name] = p.Values
	}
	for _, want := range []string{"query.country", "query.country_code", "query.lang", "body.country"} {
		if len(vals[want]) == 0 {
			t.Errorf("expected benign param %s to keep observed value, got %v", want, vals)
		}
	}
	for _, bad := range []string{"query.otp", "query.pwd", "query.pass", "query.user_pin", "query.cvv", "query.email", "query.token", "body.otp", "body.email", "body.note", "body.jwt_like"} {
		if len(vals[bad]) != 0 {
			t.Errorf("sensitive/redacted param %s leaked into catalog Params: %v", bad, vals[bad])
		}
	}
	gotLocales := byPath(Build([]Script{s}, []Request{rLocales}, inApp))
	if wf := gotLocales["GET {}/active-workflows"]; len(wf.Bases) != 0 {
		t.Errorf("/locales traffic polluted {}/active-workflows Bases: %v", wf.Bases)
	}

	// Conversely, an actual API root (/rest/settings) DOES propagate http://app.test/rest.
	rRest := req(3, "GET", "http://app.test/rest/settings")
	got2 := byPath(Build([]Script{s}, []Request{rLocales, rRest}, inApp))
	if wf := got2["GET {}/active-workflows"]; !slices.Equal(wf.Bases, []string{"http://app.test/rest"}) {
		t.Errorf("expected /rest propagation on {}/active-workflows, got %v", wf.Bases)
	}
}
