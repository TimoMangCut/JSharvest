package verify

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// ENH-01: Drafts resolves relative Base against Host when Host is present, and
// recovers the cross-origin API host from Intel.Bases for legacy catalogs on disk.
func TestCrossOriginDraftResolution(t *testing.T) {
	inScope := func(h string) bool { return strings.HasSuffix(h, "example.com") }
	in := Inputs{
		InScope: inScope,
		Intel:   endpoints.Intel{Bases: []string{"https://api.example.com/fe/v1"}},
		Catalog: []endpoints.Endpoint{
			{
				Method: "GET", Host: "api.example.com", Path: "/itemType", Base: "/fe/v1",
				Status: endpoints.Both, Confidence: "confirmed",
				Static: []endpoints.Source{{Script: "https://sub.example.com/assets/index.js"}},
			},
			{
				// Legacy catalog line on disk (Host was empty, Base was "/fe/v1").
				Method: "GET", Path: "/storeList", Base: "/fe/v1",
				Status: endpoints.Both, Confidence: "confirmed",
				Static: []endpoints.Source{{Script: "https://sub.example.com/assets/index.js"}},
			},
		},
	}
	ds := Drafts(in)
	if len(ds) != 2 {
		t.Fatalf("got %d drafts", len(ds))
	}
	if ds[0].URL != "https://api.example.com/fe/v1/itemType" {
		t.Errorf("explicit Host draft URL = %s", ds[0].URL)
	}
	if ds[1].URL != "https://api.example.com/fe/v1/storeList" {
		t.Errorf("legacy Intel fallback draft URL = %s", ds[1].URL)
	}
}

// ENH-02 & ENH-13:
//   - Express/NestJS method-scoped routes returning 404 "Cannot GET ..." to a
//     read-only GET probe get write_unverified (or verified_alive when OPTIONS
//     differs), while SPA 200 HTML shells remain dead_or_fp.
//   - A 2-segment prefix (/chat/tools) beyond maxPrefixes falls back to its
//     calibrated 1-segment parent (/chat) instead of root /.
func TestWriteUnverifiedAndParentCanary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			if r.URL.Path == "/v1/room/with-allow" {
				w.Header().Set("Allow", "POST, OPTIONS")
				w.WriteHeader(204)
				return
			}
			w.WriteHeader(204)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			fmt.Fprintf(w, `{"statusCode":404,"message":"Cannot %s %s","error":"Not Found"}`, r.Method, r.URL.Path)
		case strings.HasPrefix(r.URL.Path, "/chat"):
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(500)
			w.Write([]byte(`<html><title>Chat Down</title><body>500 Internal Error</body></html>`))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			w.Write([]byte(`<html><title>SPA</title><script src="/app.js"></script></html>`))
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	cat := []endpoints.Endpoint{
		{Method: "POST", Host: host, Path: "/v1/room/create", Confidence: "spec"},
		{Method: "POST", Host: host, Path: "/v1/room/with-allow", Confidence: "spec"},
		{Method: "POST", Host: host, Path: "/spa-only/submit", Confidence: "code"},
		{Method: "GET", Host: host, Path: "/chat/settings", Confidence: "code"},
	}
	// Fill maxPrefixes (12) on the same origin before /chat/tools/{} arrives.
	for i := range 12 {
		cat = append(cat, endpoints.Endpoint{
			Method: "GET", Host: host, Path: fmt.Sprintf("/p%02d/item", i), Confidence: "code",
		})
	}
	cat = append(cat, endpoints.Endpoint{Method: "DELETE", Host: host, Path: "/chat/tools/{}", Confidence: "code"})

	ds := Drafts(Inputs{InScope: func(string) bool { return true }, Catalog: cat})
	s, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 200})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rep, err := Run(context.Background(), Options{Target: host, Role: "anon", Drafts: ds, Sender: s, InScope: func(string) bool { return true }, MaxPrefixes: 12})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Result{}
	for _, r := range rep.Results {
		byPath[r.Path] = r
	}
	if r := byPath["/v1/room/create"]; r.Verdict != WriteUnverified {
		t.Errorf("POST /v1/room/create verdict = %s (%s), want %s", r.Verdict, r.Reason, WriteUnverified)
	}
	if r := byPath["/v1/room/with-allow"]; r.Verdict != Alive || r.VerifiedMethod != "POST" {
		t.Errorf("POST /v1/room/with-allow = %+v, want Alive POST", r)
	}
	if r := byPath["/spa-only/submit"]; r.Verdict != DeadOrFP {
		t.Errorf("POST /spa-only/submit on SPA shell = %s, want %s", r.Verdict, DeadOrFP)
	}
	// /chat/tools/{} fell back to /chat's 500 canary (not root's 200 HTML canary),
	// so it must NOT be misclassified as server_error!
	if r := byPath["/chat/tools/{}"]; r.Verdict == ServerError || !strings.HasSuffix(r.Prefix, "/chat") {
		t.Errorf("DELETE /chat/tools/{} = %+v, want /chat parent canary and not server_error", r)
	}
}

// ENH-03 & ENH-04a:
//   - Observed param values override synthetic samples; word-boundary numeric
//     matching gives country="us", lang="en", account="sample", retryCount="1";
//   - ThirdParty catalog lines do not inherit target bases and stay ThirdParty.
func TestObservedValuesWordBoundariesAndThirdPartyExclusion(t *testing.T) {
	inScope := func(h string) bool { return h == "sub.example.com" || h == "api.example.com" }
	in := Inputs{
		InScope: inScope,
		Intel:   endpoints.Intel{Bases: []string{"https://api.example.com/fe/v1"}},
		Catalog: []endpoints.Endpoint{
			{
				Method: "GET", Host: "api.example.com", Path: "/fe/v1/itemType",
				Confidence: "confirmed",
				Query:      []string{"account", "country", "lang", "page_size", "retryCount"},
				Params: []jsapi.ParamSpec{
					{Name: "country", In: "query", Values: []string{"vn"}},
				},
			},
			{
				Method: "GET", Host: "api.example.com", Path: "/fe/v1/defaults",
				Confidence: "code",
				Query:      []string{"account", "country", "lang"},
			},
			{
				Method: "POST", Path: "/api/parent-form", ThirdParty: true,
				Confidence: "code",
				Static:     []endpoints.Source{{Script: "https://example.com/parent.js"}},
			},
		},
	}
	ds := Drafts(in)
	if len(ds) != 3 {
		t.Fatalf("got %d drafts", len(ds))
	}
	if ds[0].URL != "https://api.example.com/fe/v1/itemType?account=sample&country=vn&lang=en&page_size=1&retryCount=1" {
		t.Errorf("draft[0] URL = %s", ds[0].URL)
	}
	if ds[1].URL != "https://api.example.com/fe/v1/defaults?account=sample&country=us&lang=en" {
		t.Errorf("draft[1] URL = %s", ds[1].URL)
	}
	if !ds[2].ThirdParty || strings.Contains(ds[2].URL, "api.example.com") {
		t.Errorf("third-party draft leaked into target bases: %+v", ds[2])
	}
}

// ENH-12: bare method-less path strings (confidence == "string" && Method == "")
// are skipped by default in Run and omitted in WriteDraftsWith, get client_route
// when -include-strings probes a 200 HTML SPA shell matching the canary, and
// preserve dead_or_fp for explicit-method strings (Method == "GET").
func TestBareStringsDefaultSkipAndClientRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/hidden-ping" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"pong":true}`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(`<!doctype html><title>App</title><div id="app"></div><script src="/main.js"></script>`))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	cat := []endpoints.Endpoint{
		{Path: "/account/change-plan", Origin: srv.URL, Kind: "string", Confidence: "string"},
		{Path: "/rest/hidden-ping", Origin: srv.URL, Kind: "string", Confidence: "string"},
		{Method: "GET", Host: host, Path: "/spa/settings", Kind: "string", Confidence: "string"},
	}
	ds := Drafts(Inputs{InScope: func(string) bool { return true }, Catalog: cat})

	idxDefault, err := WriteDraftsFull(t.TempDir()+"/drafts", ds, false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if idxDefault.Files != 1 {
		t.Errorf("default WriteDraftsFull wrote %d files, want 1 (/spa/settings only)", idxDefault.Files)
	}
	idxIncl, err := WriteDraftsFull(t.TempDir()+"/drafts", ds, false, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if idxIncl.Files != 3 {
		t.Errorf("-include-strings WriteDraftsFull wrote %d files, want 3", idxIncl.Files)
	}

	s1, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 50})
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	repDef, err := Run(context.Background(), Options{Target: host, Role: "anon", Drafts: ds, Sender: s1, InScope: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Result{}
	for _, r := range repDef.Results {
		byPath[r.Path] = r
	}
	if r := byPath["/account/change-plan"]; r.Verdict != Skipped || !strings.Contains(r.Reason, "bare string") {
		t.Errorf("default /account/change-plan = %+v, want skipped (bare string)", r)
	}
	if r := byPath["/spa/settings"]; r.Verdict != DeadOrFP {
		t.Errorf("explicit GET /spa/settings = %s, want %s", r.Verdict, DeadOrFP)
	}

	s2, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 50})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	repIncl, err := Run(context.Background(), Options{Target: host, Role: "anon", Drafts: ds, Sender: s2, InScope: func(string) bool { return true }, IncludeStrings: true})
	if err != nil {
		t.Fatal(err)
	}
	byPath2 := map[string]Result{}
	for _, r := range repIncl.Results {
		byPath2[r.Path] = r
	}
	if r := byPath2["/account/change-plan"]; r.Verdict != ClientRoute {
		t.Errorf("-include-strings /account/change-plan = %s (%s), want %s", r.Verdict, r.Reason, ClientRoute)
	}
	if r := byPath2["/rest/hidden-ping"]; r.Verdict != Alive {
		t.Errorf("-include-strings /rest/hidden-ping = %s, want %s", r.Verdict, Alive)
	}
	if r := byPath2["/spa/settings"]; r.Verdict != DeadOrFP {
		t.Errorf("-include-strings explicit GET /spa/settings = %s, want %s", r.Verdict, DeadOrFP)
	}
}

// P0-2 & P0-4:
//   - Static-only lines and shared relative bases (/api) are never hijacked to
//     another subdomain's Intel.Bases entry (https://admin.example.com/api);
//   - Sensitive/REDACTED values in Observed.Samples or Params are dropped while
//     OpenAPI enum values stay intact;
//   - RedactDrafts masks headers, query, URLs and JSON bodies cleanly.
func TestIntelBaseGuardAndRedactDrafts(t *testing.T) {
	inScope := func(h string) bool { return h == "app.example.com" || h == "admin.example.com" }
	in := Inputs{
		InScope: inScope,
		Intel: endpoints.Intel{
			Bases:   []string{"/api", "https://admin.example.com/api"},
			Headers: []endpoints.IntelHeader{{Name: "Authorization", Value: "Basic dXNlcjpodW50ZXIy"}, {Name: "X-Api-Key", Value: "sk_live_secret999"}},
		},
		Catalog: []endpoints.Endpoint{
			{
				// Static-only line with Base="/api" even when Intel only names admin.example.com/api:
				Method: "GET", Path: "/users", Base: "/api", Status: endpoints.Static, Confidence: "code",
				Static: []endpoints.Source{{Script: "https://app.example.com/main.js"}},
			},
			{
				// Observed line where "/api" is also a relative base in Intel.Bases:
				Method: "POST", Path: "/login", Base: "/api", Status: endpoints.Both, Confidence: "confirmed",
				Static: []endpoints.Source{{Script: "https://app.example.com/main.js"}},
				Query:  []string{"country", "otp", "status"},
				Body:   []string{"email", "password", "role"},
				Params: []jsapi.ParamSpec{
					{Name: "otp", In: "query", Values: []string{"REDACTED_12ab34cd"}},
					{Name: "status", In: "query", Values: []string{"active", "pending"}},
					{Name: "password", In: "body", Values: []string{"REDACTED_deadbeef"}},
					{Name: "role", In: "body", Values: []string{"member"}},
				},
				Observed: &endpoints.Observed{
					Requests: 1,
					Samples:  []string{"https://app.example.com/api/login?country=vn&otp=654321"},
				},
			},
		},
	}
	// First check static-only line even when Intel.Bases has ONLY admin.example.com/api:
	inAdminOnly := in
	inAdminOnly.Intel.Bases = []string{"https://admin.example.com/api"}
	dsStatic := Drafts(inAdminOnly)
	if !strings.HasPrefix(dsStatic[0].URL, "https://app.example.com/api/users") {
		t.Errorf("static-only line hijacked to admin host: %s", dsStatic[0].URL)
	}

	ds := Drafts(in)
	if !strings.HasPrefix(ds[1].URL, "https://app.example.com/api/login?") {
		t.Errorf("observed line with relative /api in Intel.Bases hijacked: %s", ds[1].URL)
	}
	if ds[1].Query["country"] != "vn" || ds[1].Query["status"] != "active" {
		t.Errorf("expected country=vn and OpenAPI enum status=active, got %v", ds[1].Query)
	}
	if ds[1].Query["otp"] == "654321" || strings.Contains(ds[1].Query["otp"], "REDACTED_") {
		t.Errorf("otp leaked real or REDACTED value in unredacted draft: %v", ds[1].Query)
	}
	if strings.Contains(string(ds[1].Body), "REDACTED_") {
		t.Errorf("REDACTED_ value leaked into draft body: %s", string(ds[1].Body))
	}

	red := RedactDrafts(ds, traffic.NewRedactor())
	dir := filepath.Join(t.TempDir(), "drafts")
	idx, err := WriteDraftsFull(dir, red, false, false, false, nil)
	if err != nil || idx.Files != 2 {
		t.Fatalf("WriteDraftsFull redacted: files=%d err=%v", idx.Files, err)
	}
	for _, ent := range idx.Drafts {
		raw, err := os.ReadFile(filepath.Join(dir, ent.File))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw))); err != nil {
			t.Errorf("%s invalid HTTP after RedactDrafts: %v\n%s", ent.File, err, string(raw))
		}
		text := string(raw)
		for _, secret := range []string{"dXNlcjpodW50ZXIy", "sk_live_secret999", "jsharvest@example.com"} {
			if strings.Contains(text, secret) {
				t.Errorf("%s still contains unredacted %q:\n%s", ent.File, secret, text)
			}
		}
		if !strings.Contains(text, "REDACTED_") {
			t.Errorf("%s expected REDACTED_ markers:\n%s", ent.File, text)
		}
	}
}

// P1-1: Express default HTML 404 (<title>Error</title><pre>Cannot GET /...</pre>)
// is recognized as MethodScoped -> write_unverified, while a uniform JSON 404
// ({"error":"not_found"}) without method-routing markers gets dead_or_fp so dead
// write routes do not outrank real candidates.
func TestExpressHTML404AndUniformJSON404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/express/"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(404)
			fmt.Fprintf(w, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot %s %s</pre>\n</body>\n</html>\n", r.Method, r.URL.Path)
		case strings.HasPrefix(r.URL.Path, "/uniform/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"not_found","message":"The requested resource does not exist"}`))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			w.Write([]byte(`<html><title>SPA</title><script src="/bundle.js"></script></html>`))
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	cat := []endpoints.Endpoint{
		{Method: "POST", Host: host, Path: "/express/orders", Confidence: "code"},
		{Method: "POST", Host: host, Path: "/uniform/dead-write", Confidence: "code"},
		{Method: "POST", Host: host, Path: "{}/orders", Bases: []string{"/uniform", "/express"}, Confidence: "code"},
	}
	ds := Drafts(Inputs{InScope: func(string) bool { return true }, Catalog: cat})
	s, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rep, err := Run(context.Background(), Options{Target: host, Role: "anon", Drafts: ds, Sender: s, InScope: func(string) bool { return true }, MaxPrefixes: 12})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Result{}
	for _, r := range rep.Results {
		byPath[r.Path] = r
	}
	if r := byPath["/express/orders"]; r.Verdict != WriteUnverified {
		t.Errorf("Express HTML 404 POST /express/orders = %s (%s), want %s", r.Verdict, r.Reason, WriteUnverified)
	}
	if r := byPath["/uniform/dead-write"]; r.Verdict != DeadOrFP {
		t.Errorf("uniform JSON 404 POST /uniform/dead-write = %s (%s), want %s", r.Verdict, r.Reason, DeadOrFP)
	}
	if r := byPath["{}/orders"]; r.Verdict != WriteUnverified || !strings.HasSuffix(r.URL, "/express/orders") {
		t.Errorf("multi-candidate POST {}/orders = %+v, want WriteUnverified on /express/orders", r)
	}
}
