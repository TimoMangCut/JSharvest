package frontier

import (
	"fmt"
	"testing"
)

func TestRootControllerProtectionNeverCollapsesStaticRoutes(t *testing.T) {
	sk := NewSkeleton()
	inScope := func(h string) bool { return h == "app.example.test" }

	rootStatic := []string{
		"about", "pricing", "contact", "faq", "terms", "privacy", "press", "jobs",
		"legal", "team", "partners", "investors", "security", "status", "support",
		"docs", "blog", "admin", "billing", "api-keys",
	}
	var links []Found
	for _, seg := range rootStatic {
		links = append(links, Found{URL: "https://app.example.test/" + seg, How: Link, Visit: true})
	}
	for i := 1; i <= 30; i++ {
		links = append(links, Found{
			URL:   fmt.Sprintf("https://app.example.test/blog/post-slug-one-%d", i),
			How:   Link,
			Visit: true,
		})
	}
	for i := 1; i <= 15; i++ {
		links = append(links, Found{
			URL:   fmt.Sprintf("https://app.example.test/settings/tab-%s", string(rune('a'+i-1))),
			How:   Link,
			Visit: true,
		})
	}
	sk.Observe(Observation{
		PageURL:    "https://app.example.test/",
		Status:     200,
		NewScripts: []string{"https://app.example.test/app.js"},
		Links:      links,
		InScope:    inScope,
	})

	// Visit all non-functional root static pages first with 0 new info;
	// /admin, /billing, and /api-keys MUST remain static and unskipped.
	for _, seg := range rootStatic[:17] {
		u := "https://app.example.test/" + seg
		if sk.ShouldSkip(u) {
			t.Fatalf("root controller page %s was falsely skipped", u)
		}
		sk.Observe(Observation{PageURL: u, Status: 200, InScope: inScope})
	}
	for _, critical := range []string{"admin", "billing", "api-keys"} {
		u := "https://app.example.test/" + critical
		k, dyn := sk.Key(u, true)
		if dyn || k != u {
			t.Fatalf("critical root route %s collapsed: key=%q dynamic=%v", u, k, dyn)
		}
		if sk.ShouldSkip(u) {
			t.Fatalf("critical root route %s was falsely marked saturated!", u)
		}
	}

	// 15 plain feature tabs under /settings/* must also remain static.
	for i := 1; i <= 15; i++ {
		u := fmt.Sprintf("https://app.example.test/settings/tab-%s", string(rune('a'+i-1)))
		if _, dyn := sk.Key(u, true); dyn {
			t.Fatalf("feature tab %s should not collapse at depth 1 (<32 plain tabs)", u)
		}
	}

	// Meanwhile 30 multi-hyphen/numbered blog slugs under /blog/* MUST saturate at #13!
	visitedBlog := 0
	prunedBlog := 0
	for i := 1; i <= 30; i++ {
		u := fmt.Sprintf("https://app.example.test/blog/post-slug-one-%d", i)
		if sk.ShouldSkip(u) {
			prunedBlog++
			continue
		}
		visitedBlog++
		sk.Observe(Observation{PageURL: u, Status: 200, InScope: inScope})
	}
	if visitedBlog != 13 || prunedBlog != 17 {
		t.Fatalf("blog slug pruning mismatch: visited=%d pruned=%d (want 13 and 17)", visitedBlog, prunedBlog)
	}

	// Combinatorial query-key cap (<= 8 keys + remainder counter).
	qk, qdyn := sk.Key("https://app.example.test/catalog?k9=1&k2=1&k1=1&k4=1&k3=1&k6=1&k5=1&k8=1&k7=1&k10=1&k11=1", false)
	wantQK := "https://app.example.test/catalog?k1&k10&k11&k2&k3&k4&k5&k6&+3"
	if !qdyn || qk != wantQK {
		t.Fatalf("query key cap mismatch: got (%q, %v), want (%q, true)", qk, qdyn, wantQK)
	}
}

func TestQueueListedSliceBoundedWithExtraListed(t *testing.T) {
	q := NewQueue(Options{
		InScope:  func(h string) bool { return h == "app.example.test" },
		MaxDepth: 2,
	})
	total := maxListedEntries + 250
	for i := 0; i < total; i++ {
		q.ListAs(Found{
			URL:   fmt.Sprintf("https://app.example.test/products/%d", i),
			How:   Link,
			Visit: true,
		}, "https://app.example.test/", TemplateSaturated)
	}
	if len(q.Listed) != maxListedEntries {
		t.Fatalf("len(q.Listed) = %d, want capped at %d", len(q.Listed), maxListedEntries)
	}
	if q.ExtraListed[TemplateSaturated] != 250 {
		t.Fatalf("ExtraListed = %d, want 250", q.ExtraListed[TemplateSaturated])
	}
}
