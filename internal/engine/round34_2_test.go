package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

func runSimulatedCDPCrawl(t *testing.T, shuffleLevel bool) (visited []string, listed []string, maxWindow int) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Flush()

	seedURL := "https://shop.example.test/"
	inScope := func(h string) bool { return h == "shop.example.test" }
	q := frontier.NewQueue(frontier.Options{InScope: inScope, MaxDepth: 2})
	q.Add(frontier.Found{URL: seedURL, How: frontier.Seed, Visit: true}, 0, "")

	var pagesBuf bytes.Buffer
	c := &crawl{
		runID:          "sim",
		seedOrigin:     "https://shop.example.test",
		inScope:        inScope,
		pageScope:      inScope,
		q:              q,
		st:             st,
		enc:            json.NewEncoder(&pagesBuf),
		stats:          &FrontierStats{Listed: map[string]int{}},
		visited:        map[string]string{},
		blamed:         map[string]bool{},
		scripts:        map[string]bool{},
		thirdPartyDone: map[string]bool{},
		skel:           frontier.NewSkeleton(),
		seenScriptSHA:  map[string]bool{},
		queuedBySkel:   map[string]int{},
		deferredBySkel: map[string][]deferredFound{},
		deferredSeen:   map[string]bool{},
		dedupe:         shuffleLevel,
	}
	c.cond = sync.NewCond(&c.mu)

	appSHA, _, err := st.Put(store.Record{
		Body:   []byte(`fetch("/api/v1/cart");`),
		URL:    "https://shop.example.test/app.js",
		Kind:   "file",
		Via:    "network",
		Source: "live",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for {
		var batch []struct {
			it    frontier.Item
			order int
		}
		// Pop the first item (which also commits the completed previous level when busy == 0).
		if c.busy == 0 {
			itFirst, ordFirst, okFirst := c.next(ctx)
			if !okFirst {
				break
			}
			batch = append(batch, struct {
				it    frontier.Item
				order int
			}{it: itFirst, order: ordFirst})
		}
		// Pop all remaining items of the current level before finishing any of them
		// (simulating concurrent tabs draining the level together).
		for {
			c.mu.Lock()
			canTake := false
			if it, ok := c.q.Peek(); ok && it.Depth <= c.level {
				canTake = true
			}
			c.mu.Unlock()
			if !canTake {
				break
			}
			itPop, ord, okPop := c.next(ctx)
			if !okPop {
				break
			}
			batch = append(batch, struct {
				it    frontier.Item
				order int
			}{it: itPop, order: ord})
		}
		if len(batch) == 0 {
			break
		}
		prodInBatch := 0
		for _, b := range batch {
			if strings.Contains(b.it.URL, "/products/") {
				prodInBatch++
			}
		}
		if prodInBatch > maxWindow {
			maxWindow = prodInBatch
		}
		if shuffleLevel && len(batch) > 1 {
			// Reverse completion order to simulate multi-tab out-of-order finishes.
			for i, j := 0, len(batch)-1; i < j; i, j = i+1, j-1 {
				batch[i], batch[j] = batch[j], batch[i]
			}
		}
		for _, b := range batch {
			u := b.it.URL
			var found []frontier.Found
			scripts := []string{appSHA}
			if u == seedURL {
				for i := 1000; i < 1060; i++ {
					found = append(found, frontier.Found{
						URL:   fmt.Sprintf("https://shop.example.test/products/%d", i),
						How:   frontier.Link,
						Visit: true,
					})
				}
				found = append(found,
					frontier.Found{URL: "https://shop.example.test/admin", How: frontier.Link, Visit: true},
					frontier.Found{URL: "https://shop.example.test/pages/a.html", How: frontier.Link, Visit: true},
					frontier.Found{URL: "https://shop.example.test/pages/b.html", How: frontier.Link, Visit: true},
				)
			} else if strings.Contains(u, "/products/") {
				// Unique __NEXT_DATA__ inline script per SSR product page (must NOT prevent saturation!).
				inlineSHA, _, _ := st.Put(store.Record{
					Body:   []byte(fmt.Sprintf(`window.__NEXT_DATA__ = {"productUrl": %q};`, u)),
					URL:    u,
					Page:   u,
					Kind:   "inline",
					Via:    "debugger",
					Source: "live",
				})
				scripts = append(scripts, inlineSHA)
			}
			c.finish(donePage{
				order:       b.order,
				it:          b.it,
				p:           Page{Run: "sim", URL: u, FinalURL: u, Visited: true, Status: 200, Depth: b.it.Depth, From: b.it.From, How: b.it.How},
				marks:       []string{u},
				found:       found,
				readScripts: true,
				scripts:     scripts,
			}, "", false)
		}
	}
	c.mu.Lock()
	c.commit()
	_ = c.finalizeDeferredLocked()
	c.mu.Unlock()

	q.SortListed()
	for _, l := range q.Listed {
		_ = c.enc.Encode(Page{Run: "sim", URL: l.URL, How: l.How, Method: l.Method, From: l.From, Reason: l.Reason})
	}

	for _, line := range strings.Split(strings.TrimSpace(pagesBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var p Page
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			t.Fatal(err)
		}
		if p.Visited {
			visited = append(visited, fmt.Sprintf("%s %d %s", p.URL, p.Depth, p.From))
		} else {
			listed = append(listed, fmt.Sprintf("%s %s %s", p.URL, p.Reason, p.From))
		}
	}
	sort.Strings(visited)
	sort.Strings(listed)
	return visited, listed, maxWindow
}

func TestCDPWindowedDynamicSkeletonDeterminismAndPruning(t *testing.T) {
	v1, l1, win1 := runSimulatedCDPCrawl(t, false)
	v3, l3, win3 := runSimulatedCDPCrawl(t, true)

	if !reflect.DeepEqual(v1, v3) {
		t.Fatalf("visited pages differ between 1-tab and 3-tab order:\nv1=%v\nv3=%v", v1, v3)
	}
	if !reflect.DeepEqual(l1, l3) {
		t.Fatalf("listed pages differ between 1-tab and 3-tab order:\nl1=%v\nl3=%v", l1, l3)
	}
	if win1 > cdpDynamicWindow || win3 > cdpDynamicWindow {
		t.Fatalf("expected max active dynamic window <= %d, got win1=%d win3=%d", cdpDynamicWindow, win1, win3)
	}
	// 1 seed + 12 products + 1 admin + 2 /pages/*.html = 16 visited pages; 48 products saturated!
	if len(v1) != 16 {
		t.Fatalf("expected 16 visited pages (12 products + 4 static), got %d: %v", len(v1), v1)
	}
	satCount := 0
	for _, entry := range l1 {
		if strings.Contains(entry, " "+frontier.TemplateSaturated+" ") {
			satCount++
		}
	}
	if satCount != 48 {
		t.Fatalf("expected 48 template-saturated product pages, got %d (listed=%v)", satCount, l1)
	}
}
