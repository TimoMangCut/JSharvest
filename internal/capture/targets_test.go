package capture

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/chromedp/cdproto/target"
)

// newTestTargets returns a manager whose attaches are only recorded.
func newTestTargets(inScope func(string) bool) (*targetManager, func() []string) {
	c := &Capture{opts: Options{InScope: inScope}}
	ctx, cancel := context.WithCancel(context.Background())
	tm := newTargetManager(c, "tab", ctx, cancel)
	tm.tabCtxID = "ctx1"
	var mu sync.Mutex
	var got []string
	done := make(chan struct{}, 64)
	tm.attachFn = func(info target.Info) {
		mu.Lock()
		got = append(got, string(info.TargetID))
		mu.Unlock()
		tm.attachDone()
		done <- struct{}{}
	}
	attached := func() []string {
		// Wait for the attaches that consider started.
		for tm.pending() > 0 {
			<-done
		}
		mu.Lock()
		defer mu.Unlock()
		out := slices.Clone(got)
		slices.Sort(out)
		return out
	}
	return tm, attached
}

func info(id, typ, url, parent string) target.Info {
	return target.Info{TargetID: target.ID(id), Type: typ, URL: url, ParentID: target.ID(parent), BrowserContextID: "ctx1"}
}

func TestTargetsChildBeforeParent(t *testing.T) {
	tm, attached := newTestTargets(nil)
	// A worker inside a cross-site frame is reported before the frame.
	tm.consider(info("w", "worker", "http://other/w.js", "f"))
	if got := attached(); len(got) != 0 {
		t.Fatalf("worker attached before its parent was known: %v", got)
	}
	tm.consider(info("f", "iframe", "http://other/frame.html", "tab"))
	if got := strings.Join(attached(), ","); got != "f,w" {
		t.Fatalf("attached %q, want f,w once the parent arrives", got)
	}
}

func TestTargetsURLArrivesLater(t *testing.T) {
	tm, attached := newTestTargets(nil)
	tm.consider(info("w", "worker", "", "tab"))
	tm.consider(info("w", "worker", "http://h/w.js", "tab"))
	tm.consider(info("w", "worker", "http://h/w.js", "tab")) // repeated event
	if got := strings.Join(attached(), ","); got != "w" {
		t.Fatalf("attached %q, want w exactly once", got)
	}
}

func TestTargetsFilter(t *testing.T) {
	tm, attached := newTestTargets(func(h string) bool { return h == "h" })
	for _, i := range []target.Info{
		info("sw-in", "service_worker", "http://h/sw.js", ""),
		info("sw-out", "service_worker", "http://elsewhere/sw.js", ""),
		info("ext", "service_worker", "chrome-extension://abc/sw.js", ""),
		info("other-tab-frame", "iframe", "http://h/f.html", "some-other-tab"),
		info("page", "page", "http://h/", ""),
		info("frame", "iframe", "http://ads.example/f.html", "tab"),
	} {
		tm.consider(i)
	}
	otherCtx := info("sw-other-ctx", "service_worker", "http://h/sw.js", "")
	otherCtx.BrowserContextID = "ctx2"
	tm.consider(otherCtx)
	if got := strings.Join(attached(), ","); got != "frame,sw-in" {
		t.Fatalf("attached %q, want frame,sw-in", got)
	}
}

func TestTargetsGoneAndStopped(t *testing.T) {
	tm, attached := newTestTargets(nil)
	tm.targetGone("w1")
	tm.consider(info("w1", "worker", "http://h/w.js", "tab"))
	tm.stop()
	tm.consider(info("w2", "worker", "http://h/w2.js", "tab"))
	if got := attached(); len(got) != 0 {
		t.Fatalf("attached %v after gone/stop", got)
	}
}
