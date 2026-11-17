package httpcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
)

func TestSkeletonControllerPrunesSaturatedSSRButKeepsFeatureTabs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString(`<html><head><title>Portal</title><script src="/app.js"></script></head><body>`)
		// 4 static feature tabs under /account/* (< fanout 8): ALL must be visited.
		for _, tab := range []string{"profile", "billing", "security", "api-keys"} {
			fmt.Fprintf(&b, `<a href="/account/%s">%s</a>`, tab, tab)
		}
		// 30 SSR news detail pages /news/100..129 with changing <title> (defeating shellPrint)
		// but zero new scripts, forms, or endpoints.
		for id := 100; id < 130; id++ {
			fmt.Fprintf(&b, `<a href="/news/%d">News %d</a>`, id, id)
		}
		b.WriteString(`</body></html>`)
		_, _ = w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/v1/boot");`))
	})
	mux.HandleFunc("/account/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		tab := strings.TrimPrefix(r.URL.Path, "/account/")
		// Note: api-keys has a unique form!
		extra := ""
		if tab == "api-keys" {
			extra = `<form method="POST" action="/api/v1/keys/rotate"><input name="key_id"/></form>`
		}
		fmt.Fprintf(w, `<html><head><title>Account %s</title><script src="/app.js"></script></head><body>%s</body></html>`, tab, extra)
	})
	newsHits := 0
	mux.HandleFunc("/news/", func(w http.ResponseWriter, r *http.Request) {
		newsHits++
		w.Header().Set("Content-Type", "text/html")
		// Distinct <title> per article so SPA shellPrint does not match, plus
		// repetitive inline config with no new API endpoints.
		fmt.Fprintf(w, `<html><head><title>Article %s</title><script src="/app.js"></script></head><body><script>window.__NODE=%q;</script><a href="/">Home</a></body></html>`,
			r.URL.Path, r.URL.Path)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")

	visitedTabs := map[string]bool{}
	res, err := Crawl(context.Background(), Options{
		Target:       u,
		Depth:        2,
		Rate:         500,
		AllowPrivate: true,
		Probe:        false,
		InScope:      func(h string) bool { return h == u.Hostname() },
		Page: func(p Page) {
			if p.Visited && strings.HasPrefix(p.URL, srv.URL+"/account/") {
				visitedTabs[strings.TrimPrefix(p.URL, srv.URL+"/account/")] = true
			}
		},
	})
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}
	for _, tab := range []string{"profile", "billing", "security", "api-keys"} {
		if !visitedTabs[tab] {
			t.Errorf("feature tab /account/%s was not visited", tab)
		}
	}
	if newsHits >= 15 {
		t.Fatalf("expected SSR /news/{id} template to saturate early, but hit %d/30 articles", newsHits)
	}
	if res.Listed[frontier.TemplateSaturated] < 15 {
		t.Fatalf("expected >= 15 template-saturated listings, got %d (listed=%v)", res.Listed[frontier.TemplateSaturated], res.Listed)
	}
}
