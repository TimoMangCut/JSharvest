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

func TestCrawlRootHomepageManyStaticLinksStillVisitsAdminAndBilling(t *testing.T) {
	mux := http.NewServeMux()
	staticPages := []string{
		"about", "pricing", "contact", "faq", "terms", "privacy", "press",
		"jobs", "legal", "team", "partners", "investors", "security", "status", "support",
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString(`<html><head><title>Home</title><script src="/main.js"></script></head><body>`)
		for _, p := range staticPages {
			fmt.Fprintf(&b, `<a href="/%s">%s</a>`, p, p)
		}
		for i := 1; i <= 30; i++ {
			fmt.Fprintf(&b, `<a href="/blog/how-to-guide-%d">Post %d</a>`, i, i)
		}
		// Placed AFTER 15 static pages and 30 blog posts: must never be pruned!
		b.WriteString(`<a href="/admin">Admin</a><a href="/billing">Billing</a></body></html>`)
		_, _ = w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/main.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/v1/health");`))
	})
	for _, p := range staticPages {
		pageName := p
		mux.HandleFunc("/"+pageName, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>%s</title><script src="/main.js"></script></head><body><p>Static marketing copy for %s</p></body></html>`, pageName, pageName)
		})
	}
	mux.HandleFunc("/blog/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><title>Blog %s</title><script src="/main.js"></script></head><body><p>Article %s</p></body></html>`, r.URL.Path, r.URL.Path)
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>Admin</title><script src="/admin-secret.js"></script></head><body>Admin Console</body></html>`))
	})
	mux.HandleFunc("/admin-secret.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/v1/admin/users/suspend", {method: "POST"});`))
	})
	mux.HandleFunc("/billing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>Billing</title></head><body><form method="POST" action="/api/v1/billing/portal"><input name="plan"/></form></body></html>`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")

	visited := map[string]bool{}
	gotAdminJS := false
	res, err := Crawl(context.Background(), Options{
		Target:       u,
		Depth:        2,
		Rate:         500,
		AllowPrivate: true,
		Probe:        false,
		InScope:      func(h string) bool { return h == u.Hostname() },
		Page: func(p Page) {
			if p.Visited {
				visited[p.URL] = true
			}
		},
		Script: func(s Script) {
			if strings.HasSuffix(s.URL, "/admin-secret.js") {
				gotAdminJS = true
			}
		},
	})
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}
	if !visited[srv.URL+"/admin"] || !visited[srv.URL+"/billing"] {
		t.Fatalf("critical root routes dropped! admin=%v billing=%v", visited[srv.URL+"/admin"], visited[srv.URL+"/billing"])
	}
	if !gotAdminJS {
		t.Fatalf("expected /admin-secret.js from /admin to be harvested")
	}
	if res.Listed[frontier.TemplateSaturated] < 15 {
		t.Fatalf("expected >= 15 saturated blog posts, got %d", res.Listed[frontier.TemplateSaturated])
	}
}
