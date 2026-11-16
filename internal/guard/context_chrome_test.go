//go:build chrome

package guard_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/browser"
	"github.com/TimoMangCut/JSharvest/internal/guard"
)

// TestNewBrowserContext checks that a browser context made after the guard
// started is guarded too (crawl -urls -tabs N gives each URL one): its
// writes are held back, and speculative prefetch does not go around the
// interception. go test -tags chrome ./internal/guard/
func TestNewBrowserContext(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><a href="/prefetched">p</a>
<script type="speculationrules">{"prefetch":[{"source":"list","urls":["/prefetched"]}],"prerender":[{"source":"list","urls":["/prerendered"]}]}</script>
<script>fetch("/api/save",{method:"POST",body:"x=1"}).then(r=>r.text()).then(t=>document.title="done:"+t)</script>`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sess, err := browser.New(ctx, browser.Options{NoPrediction: true, NoSandbox: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	g, err := guard.Start(sess.Tab, guard.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	tab, closeTab := chromedp.NewContext(sess.Tab, chromedp.WithNewBrowserContext())
	defer closeTab()
	if err := chromedp.Do(tab, chromedp.Navigate(srv.URL+"/")); err != nil {
		t.Fatal(err)
	}
	if _, err := chromedp.Run(tab, chromedp.Poll[bool](`document.title.startsWith("done")`)); err != nil {
		t.Fatal(err)
	}
	title, _ := chromedp.Run(tab, chromedp.Evaluate[string](`document.title + " " + document.visibilityState`))
	time.Sleep(2 * time.Second) // time for a prefetch to go out
	mu.Lock()
	defer mu.Unlock()
	t.Logf("title %q; the server saw %v", title, seen)
	for _, s := range seen {
		switch s {
		case "POST /api/save":
			t.Error("a write from the new browser context reached the server")
		case "GET /prefetched", "GET /prerendered":
			t.Errorf("speculative loading in the new browser context: %s", s)
		}
	}
	if len(g.Take(nil)) == 0 {
		t.Error("the guard holds no record of the write")
	}
}

// TestPrefetchControl shows the page above does prefetch when nothing turns
// it off, so that TestNewBrowserContext's check means something.
func TestPrefetchControl(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<!doctype html><a href="/prefetched">p</a>
<script type="speculationrules">{"prefetch":[{"source":"list","urls":["/prefetched"]}]}</script>`)
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sess, err := browser.New(ctx, browser.Options{NoSandbox: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	tab, closeTab := chromedp.NewContext(sess.Tab, chromedp.WithNewBrowserContext())
	defer closeTab()
	if err := chromedp.Do(tab, chromedp.Navigate(srv.URL+"/")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(seen, "GET /prefetched") {
		t.Fatalf("no prefetch without the guard: the check above proves nothing (the server saw %v)", seen)
	}
}
