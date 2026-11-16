//go:build chrome

package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/browser"
)

// TestTabsAtOnce checks what crawl -tabs N needs of several tabs of one
// browser context at work at once: each is visible, and its timers are not
// throttled as a background tab's are (to one a second, or worse), and,
// with focus emulation, each has the focus (only the last opened has it
// otherwise).
// go test -tags chrome ./internal/browser/
func TestTabsAtOnce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><script>window.ticks=0;setInterval(()=>window.ticks++,50)</script>`)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sess, err := browser.New(ctx, browser.Options{NoSandbox: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	tabs := []context.Context{sess.Tab}
	for range 2 {
		tab, closeTab := chromedp.NewContext(sess.Tab)
		defer closeTab()
		tabs = append(tabs, tab)
	}
	for _, tab := range tabs {
		if err := chromedp.Do(tab, chromedp.Navigate(srv.URL)); err != nil {
			t.Fatal(err)
		}
		// Only the last tab opened has the focus: explore types into
		// fields, and a page without it may not take the keys.
		if _, err := chromedp.Call(tab, emulation.SetFocusEmulationEnabled, emulation.SetFocusEmulationEnabledParams{Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(2 * time.Second)
	for i, tab := range tabs {
		got, err := chromedp.Run(tab, chromedp.Evaluate[string](`document.visibilityState + " " + document.hasFocus() + " " + window.ticks`))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("tab %d: %s", i, got)
		var state, focus string
		var ticks int
		fmt.Sscan(got, &state, &focus, &ticks)
		if state != "visible" || focus != "true" || ticks < 25 {
			t.Errorf("tab %d: %s: want visible, focused, and about 40 ticks in 2 s", i, got)
		}
	}
}
