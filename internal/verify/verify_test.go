package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/replay"
)

func TestDrafts(t *testing.T) {
	in := Inputs{
		InScope: func(h string) bool { return strings.HasSuffix(h, "x.test") },
		Intel:   endpoints.Intel{Bases: []string{"https://api.x.test/svc", "https://api.x.test", "https://other.com/v1"}},
		Catalog: []endpoints.Endpoint{
			{Method: "POST", Path: "{}/v1/tenants/{}/files", Bases: []string{"https://api.x.test/svc"}, Confidence: "code",
				Body: []string{"files", "files.checksum", "files.name", "meta.locale", "tenant_id"},
				Params: []jsapi.ParamSpec{{Name: "tenantId", In: "path", Position: 0}, {Name: "files", In: "body", Type: "array"},
					{Name: "meta.locale", In: "body", Type: "string", Values: []string{"vi"}}}},
			{Method: "GET", Path: "/svc/v1/apps/by-slug/{}", Bases: []string{"https://api.x.test/svc"}, Confidence: "code"},
			{Method: "GET", Path: "/health", Host: "api.x.test", Confidence: "code"},
			{Method: "GET", Path: "/cms/v1/entries", Kind: "doc", Confidence: "doc"},
			{Path: "/v1/thing", Origin: "https://x.test", Confidence: "string"},
		},
	}
	ds := Drafts(in)
	if len(ds) != 5 {
		t.Fatalf("%d drafts", len(ds))
	}
	files := ds[0]
	if files.URL != "https://api.x.test/svc/v1/tenants/"+sampleUUID+"/files" || files.Tier != Parameterized {
		t.Errorf("files: %s %s", files.URL, files.Tier)
	}
	var body map[string]any
	json.Unmarshal(files.Body, &body)
	list, ok := body["files"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("files is a list of objects: %s", files.Body)
	}
	if item := list[0].(map[string]any); item["checksum"] != "sample" || item["name"] != "sample" {
		t.Errorf("item: %v", item)
	}
	if m := body["meta"].(map[string]any); m["locale"] != "vi" {
		t.Errorf("meta: %v", m)
	}
	if body["tenant_id"] != sampleUUID {
		t.Errorf("tenant_id: %v", body["tenant_id"])
	}
	if ds[1].URL != "https://api.x.test/svc/v1/apps/by-slug/sample-item" {
		t.Errorf("by-slug: %s", ds[1].URL)
	}
	if ds[2].URL != "https://api.x.test/health" || ds[2].Tier != Ready {
		t.Errorf("health: %s %s", ds[2].URL, ds[2].Tier)
	}
	// A document's line with no base: the target's bases, shortest first,
	// in scope only; several candidates: no one URL.
	if d := ds[3]; d.URL != "" || !slices.Equal(d.Candidates, []string{"https://api.x.test/cms/v1/entries", "https://api.x.test/svc/cms/v1/entries"}) ||
		d.Tier != Incomplete || len(d.CandidateBases) != 2 {
		t.Errorf("doc: %+v", d)
	}
	if d := ds[4]; d.URL != "https://x.test/v1/thing" || d.Tier != Incomplete || d.Why != "no method" {
		t.Errorf("no method: %+v", d)
	}
	for _, d := range ds {
		target := d.URL
		if target == "" {
			target = d.Candidates[0]
		}
		if _, err := d.Raw(target); err != nil {
			t.Errorf("%s: %v", d.ID, err)
		}
	}
}

func TestSig(t *testing.T) {
	a := SigOf(401, map[string]string{"content-type": "application/json"}, []byte(`{"error":"unauthorized","request_id":"a1"}`))
	b := SigOf(401, map[string]string{"content-type": "application/json; charset=utf-8"}, []byte(`{"error":"unauthorized","request_id":"zz9"}`))
	if !Same(a, b) || a.Code != "unauthorized" {
		t.Errorf("a request id makes no difference: %+v %+v", a, b)
	}
	r1 := SigOf(404, map[string]string{"content-type": "application/json"}, []byte(`{"code":"NO_ROUTE","trace_id":"1","path":"/a"}`))
	r2 := SigOf(404, map[string]string{"content-type": "application/json"}, []byte(`{"code":"TENANT_NOT_FOUND","message":"unknown tenant"}`))
	if Same(r1, r2) {
		t.Error("two 404s of two kinds")
	}
	s1 := SigOf(200, map[string]string{"content-type": "text/html"}, []byte(`<html><title>App</title><script src="/a.js"></script> x y</html>`))
	s2 := SigOf(200, map[string]string{"content-type": "text/html"}, []byte(`<html><title>App</title><script src="/a.js"></script> a b c d e f</html>`))
	if !Same(s1, s2) {
		t.Error("the SPA's shell twice")
	}
}

func TestMissingParams(t *testing.T) {
	for body, want := range map[string][]string{
		`{"missing":["warehouse_id"]}`: {"warehouse_id"},
		`{"statusCode":400,"message":["warehouse_id should not be empty","qty must be a number"],"error":"Bad Request"}`: {"qty", "warehouse_id"},
		`{"detail":[{"loc":["body","sku"],"msg":"field required"}]}`:                                                     {"sku"},
		`{"errors":[{"field":"email","message":"invalid"}]}`:                                                             {"email"},
		`{"error":"missing field ` + "`token`" + `"}`:                                                                    {"token"},
		`{"ok":false}`: nil,
	} {
		if got := MissingParams([]byte(body)); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", body, got, want)
		}
	}
}

func TestGatewayPrefix(t *testing.T) {
	for u, want := range map[string]string{
		"https://api.x/hub/auth/v1/token":               "/hub/auth",
		"https://api.x/health":                          "/",
		"https://api.x/opaque/profile":                  "/opaque",
		"https://api.x/tenants/" + sampleUUID + "/apps": "/tenants",
		"https://api.x/api/v1/tenants/" + sampleUUID:    "/api/v1",
	} {
		if _, p := GatewayPrefix(u); p != want {
			t.Errorf("%s: %s, want %s", u, p, want)
		}
	}
}

// POL-23-1, -2, -3: a candidate base the policy will not send to (/auth)
// does not end the line: the next is tried, and found; an anon probe and
// its canary carry no sample credential and one Accept; the drafts file
// is the URL the route answered at.
func TestCandidatesAndSampleHeaders(t *testing.T) {
	var mu sync.Mutex
	var auths, accepts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		accepts = append(accepts, strings.Join(r.Header.Values("Accept"), "|"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/open/api/items" {
			w.Write([]byte(`[{"id":1}]`))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte(`{"code":"NO_ROUTE"}`))
	}))
	defer srv.Close()
	in := Inputs{
		InScope: func(string) bool { return true },
		Intel: endpoints.Intel{Bases: []string{srv.URL, srv.URL + "/svc", srv.URL + "/auth", srv.URL + "/open"},
			Headers: []endpoints.IntelHeader{{Name: "Authorization", Value: "Bearer {}"}, {Name: "Accept", Value: "application/json"},
				{Name: "Access-Control-Allow-Origin", Value: "{origin}"}, {Name: "app_version", Value: "1.14"}}},
		Catalog: []endpoints.Endpoint{{Method: "GET", Path: "/api/items", Confidence: "code", Kind: "fetch"}},
	}
	ds := Drafts(in)
	if len(ds) != 1 || len(ds[0].Candidates) != 4 || !slices.Equal(ds[0].SampleHeaders, []string{"Authorization"}) {
		t.Fatalf("drafts: %+v", ds)
	}
	raw, _ := ds[0].Raw(ds[0].Candidates[0])
	if strings.Count(string(raw), "Accept:") != 1 || strings.Contains(string(raw), "Access-Control") || !strings.Contains(string(raw), "Bearer sample") {
		t.Errorf("the file:\n%s", raw)
	}
	s, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rep, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: ds, Sender: s, InScope: in.InScope, IncludeDocs: true})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if r.Verdict != Alive || r.URL != srv.URL+"/open/api/items" || r.VerifiedBase != srv.URL+"/open" {
		t.Errorf("result: %+v", r)
	}
	mu.Lock()
	for i, a := range auths {
		if a != "" || accepts[i] != "application/json" {
			t.Errorf("request %d: Authorization %q, Accept %q", i, a, accepts[i])
		}
	}
	mu.Unlock()
	dir := t.TempDir() + "/drafts"
	idx, err := WriteDraftsFull(dir, ds, false, false, false, map[string]string{"GET /api/items": r.URL})
	if err != nil || idx.Files != 1 {
		t.Fatalf("%v %+v", err, idx)
	}
	b, _ := os.ReadFile(dir + "/" + idx.Drafts[0].File)
	if !strings.HasPrefix(string(b), "GET /open/api/items HTTP/1.1") {
		t.Errorf("the file is not the verified URL's:\n%s", b)
	}
	if md := Markdown(&Report{Results: []Result{{Verdict: Alive, Method: "POST", Sent: "GET", URL: "x"}}}); !strings.Contains(md, "(probed via GET)") {
		t.Error("verify.md does not say a write was probed with a GET")
	}
}

// cfServer answers as an app behind Cloudflare: the 1020 page for paths
// under rule, the 1006 page to all once banned, else 200 or the router's 404.
func cfServer(t *testing.T, rule string, banned *atomic.Bool) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "99aabbccddeeff00-SIN")
		page := func(code string) {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`<!DOCTYPE html><html><head><title>Access denied | target.test used Cloudflare to restrict access</title></head><body><div id="cf-error-details"><p>Error ` + code + `</p></div></body></html>`))
		}
		switch {
		case banned != nil && banned.Load():
			page("1006")
		case rule != "" && strings.HasPrefix(r.URL.Path, rule):
			page("1020")
		case r.URL.Path == "/api/v1/users" || r.URL.Path == "/api/v1/orders":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		default: // a canary, or any other path
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			w.Write([]byte(`{"code":"NO_ROUTE"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func cfInputs(base string) Inputs {
	return Inputs{
		InScope: func(string) bool { return true },
		Intel:   endpoints.Intel{Bases: []string{base}},
		Catalog: []endpoints.Endpoint{
			{Method: "GET", Path: "/api/v1/users", Bases: []string{base}, Confidence: "code", Kind: "fetch"},
			{Method: "GET", Path: "/api/v1/admin/keys", Bases: []string{base}, Confidence: "code", Kind: "fetch"},
			{Method: "GET", Path: "/api/v1/orders", Bases: []string{base}, Confidence: "code", Kind: "fetch"},
		},
	}
}

// Round 25H: the host banned (1006 everywhere): the first answer is
// blocked, its control too, and the host is given up; the run stops (its
// only host) after two requests, and no block page reads as a route.
func TestVerifyHostBannedGivesUpHost(t *testing.T) {
	var banned atomic.Bool
	banned.Store(true)
	srv, hits := cfServer(t, "", &banned)
	s, _ := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 100})
	defer s.Close()
	rep, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: Drafts(cfInputs(srv.URL)), Sender: s, InScope: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	if rep.Sent != 2 || len(*hits) != 2 || !strings.Contains(rep.HostsBlocked[host], "1006") || !strings.Contains(rep.Stopped, "every host is blocked") {
		t.Fatalf("sent %d, hits %v, given up %v, stopped %q", rep.Sent, *hits, rep.HostsBlocked, rep.Stopped)
	}
	if rep.Verdicts[Alive] != 0 || rep.Verdicts[HostBlocked] == 0 {
		t.Fatalf("verdicts %v", rep.Verdicts)
	}
}

// Round 25H: a rule on one path (1020): that draft is waf_blocked, the
// host still answers its control, the others are judged as usual.
func TestVerifyRuleOnOnePathGoesOn(t *testing.T) {
	srv, _ := cfServer(t, "/api/v1/admin", nil)
	s, _ := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 100})
	defer s.Close()
	rep, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: Drafts(cfInputs(srv.URL)), Sender: s, InScope: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Result{}
	for _, r := range rep.Results {
		by[r.Path] = r
	}
	if r := by["/api/v1/admin/keys"]; r.Verdict != WAFBlocked || !strings.Contains(r.Reason, "1020") {
		t.Fatalf("the blocked path: %+v", r)
	}
	if by["/api/v1/users"].Verdict != Alive || by["/api/v1/orders"].Verdict != Alive {
		t.Fatalf("the others: %+v", rep.Results)
	}
	if rep.Stopped != "" || len(rep.HostsBlocked) != 0 {
		t.Fatalf("stopped %q, given up %v", rep.Stopped, rep.HostsBlocked)
	}
}

// Round 25I (N4): a gateway answering every path alike, as its canaries
// do (a device or app check before every route), is given up after
// GateAfter probes: the host's other drafts are host_gated, not sent.
func TestVerifyGatedHostStopsEarly(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write([]byte(`{"status":{"code":"021229","message":"device not allowed","description":"unauthorized_client"},"data":null}`))
	}))
	defer srv.Close()
	var cat []endpoints.Endpoint
	for _, svc := range []string{"scooter", "customer", "report"} {
		for i := range 10 {
			cat = append(cat, endpoints.Endpoint{Method: "GET", Path: fmt.Sprintf("/%s/v1.0/items%d", svc, i), Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch"})
		}
	}
	in := Inputs{InScope: func(string) bool { return true }, Intel: endpoints.Intel{Bases: []string{srv.URL}}, Catalog: cat}
	s, _ := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 500})
	defer s.Close()
	rep, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: Drafts(in), Sender: s, InScope: in.InScope, GateAfter: 5})
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	// The gate needs 5 probes over 3 gateway prefixes: taken in turn
	// (round 25J), the third prefix comes at the third probe.
	if rep.HostsGated[host] == "" || rep.Verdicts[HostGated] != 25 || rep.Verdicts[DeadOrFP] != 5 {
		t.Fatalf("gated %v, verdicts %v", rep.HostsGated, rep.Verdicts)
	}
	if rep.Sent > 5+3 || hits != rep.Sent {
		t.Fatalf("sent %d (server saw %d), want at most 5 probes and their canaries", rep.Sent, hits)
	}
	// verify.json lists the drafts in their own order, not the order sent.
	for i, r := range rep.Results {
		if r.Path != cat[i].Path {
			t.Fatalf("result %d is %s, want %s (the drafts' order)", i, r.Path, cat[i].Path)
		}
	}
}

// Round 25J: a host whose drafts that are sent have two gateway prefixes
// is found gated on those two; a prefix whose drafts are never sent (a
// logout) does not count.
func TestVerifyGateCountsSentPrefixesOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()
	var cat []endpoints.Endpoint
	for _, svc := range []string{"orders", "users"} {
		for i := range 10 {
			cat = append(cat, endpoints.Endpoint{Method: "GET", Path: fmt.Sprintf("/%s/v1/items%d", svc, i), Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch"})
		}
	}
	for i := range 3 {
		cat = append(cat, endpoints.Endpoint{Method: "POST", Path: fmt.Sprintf("/auth/v1/logout%d", i), Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch"})
	}
	in := Inputs{InScope: func(string) bool { return true }, Intel: endpoints.Intel{Bases: []string{srv.URL}}, Catalog: cat}
	s, _ := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 500})
	defer s.Close()
	rep, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: Drafts(in), Sender: s, InScope: in.InScope, GateAfter: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.HostsGated) != 1 || rep.Verdicts[HostGated] != 15 {
		t.Fatalf("gated %v, verdicts %v", rep.HostsGated, rep.Verdicts)
	}
}

// Round 25I review: a router's uniform "no such route" (404 JSON, an SPA's
// 200 shell) is routing, not a gate: the host is never given up for it,
// however many drafts in a row miss.
func TestVerifyUniform404IsNotAGate(t *testing.T) {
	for _, tc := range []struct {
		name, ctype, body string
		status            int
	}{
		{"json 404", "application/json", `{"error":"Not Found"}`, 404},
		{"spa shell", "text/html", `<!doctype html><html><body><div id="app"></div></body></html>`, 200},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/zz/v1/live" {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"ok":true}`))
				return
			}
			w.Header().Set("Content-Type", tc.ctype)
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		}))
		var cat []endpoints.Endpoint
		for _, svc := range []string{"aa", "bb", "cc", "dd"} {
			for i := range 8 {
				cat = append(cat, endpoints.Endpoint{Method: "GET", Path: fmt.Sprintf("/%s/v1/gone%d", svc, i), Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch"})
			}
		}
		cat = append(cat, endpoints.Endpoint{Method: "GET", Path: "/zz/v1/live", Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch"})
		in := Inputs{InScope: func(string) bool { return true }, Intel: endpoints.Intel{Bases: []string{srv.URL}}, Catalog: cat}
		s, _ := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 500})
		rep, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: Drafts(in), Sender: s, InScope: in.InScope, GateAfter: 5})
		s.Close()
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.HostsGated) != 0 || rep.Verdicts[HostGated] != 0 || rep.Verdicts[Alive] != 1 {
			t.Errorf("%s: gated %v, verdicts %v", tc.name, rep.HostsGated, rep.Verdicts)
		}
	}
}

// Round 25I review: past maxPrefixes, a gateway's next service is judged
// against its 1-segment parent's canary, not the origin root's: an SPA's
// 200 shell at / made every gateway 400 read as a route (observed 14
// false verified_alive).
func TestVerifyParentCanaryPastMaxPrefixes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api-gateway/") {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!doctype html><html><body><div id="root"></div></body></html>`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write([]byte(`{"status":{"code":"021229","message":"device not allowed"},"data":null}`))
	}))
	defer srv.Close()
	var cat []endpoints.Endpoint
	for i := range maxPrefixes + 3 {
		cat = append(cat, endpoints.Endpoint{Method: "GET", Path: fmt.Sprintf("/api-gateway/svc%02d/v1.0/items", i), Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch"})
	}
	in := Inputs{InScope: func(string) bool { return true }, Intel: endpoints.Intel{Bases: []string{srv.URL}}, Catalog: cat}
	s, _ := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 500})
	defer s.Close()
	rep, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: Drafts(in), Sender: s, InScope: in.InScope})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdicts[Alive] != 0 || rep.Verdicts[DeadOrFP] != len(cat) {
		t.Fatalf("verdicts %v, want every draft dead_or_fp (the gateway refuses alike)", rep.Verdicts)
	}
}

// Round 25K: verify -concurrency runs hosts at once, never two requests
// at once on one host, and comes to the verdicts a run of one does.
func TestVerifyConcurrentHosts(t *testing.T) {
	var global, peak atomic.Int32
	var srvs []*httptest.Server
	inflight := make([]*atomic.Int32, 3)
	perPeak := make([]*atomic.Int32, 3)
	for i := range 3 {
		inflight[i], perPeak[i] = &atomic.Int32{}, &atomic.Int32{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := inflight[i].Add(1)
			defer inflight[i].Add(-1)
			if n > perPeak[i].Load() {
				perPeak[i].Store(n)
			}
			g := global.Add(1)
			defer global.Add(-1)
			if g > peak.Load() {
				peak.Store(g)
			}
			time.Sleep(30 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			if strings.HasSuffix(r.URL.Path, "/live") {
				w.Write([]byte(`{"ok":true}`))
				return
			}
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"no route"}`))
		}))
		defer srv.Close()
		srvs = append(srvs, srv)
	}
	var cat []endpoints.Endpoint
	for _, srv := range srvs {
		for _, p := range []string{"/a/v1/live", "/a/v1/gone", "/b/v1/live", "/b/v1/gone", "/c/v1/gone"} {
			cat = append(cat, endpoints.Endpoint{Method: "GET", Path: p, Host: strings.TrimPrefix(srv.URL, "http://"), Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch"})
		}
	}
	in := Inputs{InScope: func(string) bool { return true }, Catalog: cat}
	run := func(conc int) *Report {
		s, _ := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 500, Concurrency: conc})
		defer s.Close()
		rep, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: Drafts(in), Sender: s, InScope: in.InScope, Concurrency: conc})
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	one := run(1)
	for i := range perPeak {
		perPeak[i].Store(0)
	}
	peak.Store(0)
	three := run(3)
	for i, p := range perPeak {
		if p.Load() > 1 {
			t.Errorf("host %d had %d requests at once", i, p.Load())
		}
	}
	if peak.Load() < 2 {
		t.Errorf("the hosts never ran at once (peak %d)", peak.Load())
	}
	verdicts := func(r *Report) string {
		var out []string
		for _, x := range r.Results {
			out = append(out, x.URL+" "+x.Verdict)
		}
		return strings.Join(out, "\n")
	}
	if verdicts(one) != verdicts(three) || one.Sent != three.Sent {
		t.Errorf("-concurrency 3 differs from 1 (sent %d vs %d):\n%s\n---\n%s", three.Sent, one.Sent, verdicts(three), verdicts(one))
	}
}
