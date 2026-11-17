package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/archive"
	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/replay"
)

func TestCanaryOptionsHeaderParityPreventsAuthWallFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Frameworks like Laravel/Symfony redirect non-AJAX requests (302 /login)
		// and return 401 JSON whenever X-Requested-With: XMLHttpRequest is present.
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message":"Unauthenticated."}`))
			return
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	in := Inputs{
		InScope: func(string) bool { return true },
		Intel: endpoints.Intel{
			Headers: []endpoints.IntelHeader{
				{
					Name:    "X-Requested-With",
					Value:   "XMLHttpRequest",
					Sources: []endpoints.Source{{SHA256: "sha-ajax", Script: srv.URL + "/js/app.js"}},
				},
			},
		},
		Catalog: []endpoints.Endpoint{
			{
				Method:     "POST",
				Host:       host,
				Path:       "/admin/users/export",
				Confidence: "confirmed",
				Static:     []endpoints.Source{{SHA256: "sha-ajax", Script: srv.URL + "/js/app.js"}},
			},
		},
	}

	ds := Drafts(in)
	if len(ds) != 1 {
		t.Fatalf("expected 1 draft, got %d", len(ds))
	}
	ds[0].URL = strings.Replace(ds[0].URL, "https://", "http://", 1)

	s, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 200})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rep, err := Run(context.Background(), Options{
		Target:  host,
		Role:    "anon",
		Drafts:  ds,
		Sender:  s,
		InScope: func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rep.Results))
	}
	if rep.Results[0].Verdict == Alive {
		t.Fatalf("false positive: AJAX 401 auth wall classified as verified_alive: %+v", rep.Results[0])
	}
	if rep.Results[0].Verdict != AuthWall {
		t.Errorf("expected auth_wall_opaque, got %q (%s)", rep.Results[0].Verdict, rep.Results[0].Reason)
	}
}

func TestHistoricalOriginRecoveryScopedHeadersAndLangInference(t *testing.T) {
	inScope := func(h string) bool { return strings.HasSuffix(h, ".example.tr") }
	in := Inputs{
		InScope: inScope,
		Intel: endpoints.Intel{
			Headers: []endpoints.IntelHeader{
				{
					Name:    "X-Sub1-Token",
					Value:   "tok-123456",
					Sources: []endpoints.Source{{SHA256: "sha-sub1", Script: "https://sub1.example.tr/app.js"}},
				},
			},
		},
		Catalog: []endpoints.Endpoint{
			{
				Method: "GET",
				Host:   "portal.example.tr",
				Path:   "/{}/api/announcements",
				Query:  []string{"page"},
				Params: []jsapi.ParamSpec{
					{Name: "currentLanguage", In: "path", Type: "string", Required: true},
				},
				Confidence: "confirmed",
				Static:     []endpoints.Source{{SHA256: "sha-portal", Script: "https://portal.example.tr/sites/default/files/js/bundle.js"}},
			},
			{
				Method:     "GET",
				Host:       "sub1.example.tr",
				Path:       "/api/profile",
				Confidence: "confirmed",
				Static:     []endpoints.Source{{SHA256: "sha-sub1", Script: "https://sub1.example.tr/app.js"}},
			},
		},
		Historical: []archive.HistLine{
			{
				// Legacy historical.jsonl entry with empty Host and Origin, only Scripts[].URL populated.
				Class:  "historical",
				Method: "POST",
				Path:   "/pb/api/upload/image.htm",
				Kind:   "xhr",
				Scripts: []archive.HistScript{
					{SHA256: "sha-hist-1", URL: "https://legacy.example.tr/pb/js/editor.js"},
				},
			},
		},
	}

	ds := Drafts(in)
	byPath := map[string]Draft{}
	for _, d := range ds {
		byPath[d.Path] = d
	}

	ann, ok := byPath["/{}/api/announcements"]
	if !ok {
		t.Fatalf("missing announcements draft in %+v", ds)
	}
	if !strings.HasPrefix(ann.URL, "https://portal.example.tr/tr/api/announcements") {
		t.Errorf("expected language slot inferred as 'tr', got URL=%q", ann.URL)
	}
	for _, h := range ann.Headers {
		if h[0] == "X-Sub1-Token" {
			t.Errorf("X-Sub1-Token from sub1 leaked onto portal.example.tr draft: %+v", ann.Headers)
		}
	}

	sub1, ok := byPath["/api/profile"]
	if !ok {
		t.Fatalf("missing /api/profile draft")
	}
	hasSub1Header := slices.ContainsFunc(sub1.Headers, func(kv [2]string) bool {
		return kv[0] == "X-Sub1-Token" && kv[1] == "tok-123456"
	})
	if !hasSub1Header {
		t.Errorf("expected X-Sub1-Token on sub1.example.tr draft, got %+v", sub1.Headers)
	}

	hist, ok := byPath["/pb/api/upload/image.htm"]
	if !ok {
		t.Fatalf("missing historical draft")
	}
	if hist.Tier == Incomplete || hist.URL != "https://legacy.example.tr/pb/api/upload/image.htm" {
		t.Errorf("expected historical draft resolved to https://legacy.example.tr/pb/api/upload/image.htm, got tier=%q url=%q why=%q", hist.Tier, hist.URL, hist.Why)
	}
}
