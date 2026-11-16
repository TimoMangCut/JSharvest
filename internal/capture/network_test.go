package capture

import (
	"fmt"
	"testing"

	"github.com/chromedp/cdproto/network"
)

// The events of one request arrive on separate subscriptions, in any order.
// Every order must give the same outcome.
func TestNetTrackerEventOrder(t *testing.T) {
	type event struct {
		name string
		f    func(*request)
	}
	sent := func(rtype network.ResourceType) event {
		return event{"sent", func(q *request) { q.url = "http://h/a.js"; q.rtype = rtype }}
	}
	// As in production, the response carries the final URL and the type.
	resp := func(rtype network.ResourceType, status int64, mime string) event {
		return event{"resp", func(q *request) {
			q.url, q.rtype, q.status, q.mime, q.responded = "http://h/a.js", rtype, status, mime, true
		}}
	}
	fin := event{"fin", func(q *request) { q.done, q.finished = true, true }}
	fail := event{"fail", func(q *request) { q.done = true }}

	cases := []struct {
		name   string
		events []event
		want   int // bodies fetched
	}{
		{"script", []event{sent(network.ResourceTypeScript), resp(network.ResourceTypeScript, 200, "text/javascript"), fin}, 1},
		{"js by mime from a service worker", []event{sent(network.ResourceTypeFetch), resp(network.ResourceTypeFetch, 200, "application/javascript"), fin}, 1},
		{"js by extension, wrong mime", []event{sent(network.ResourceTypeFetch), resp(network.ResourceTypeFetch, 200, "text/plain"), fin}, 1},
		{"spa fallback under a .js name", []event{sent(network.ResourceTypeFetch), resp(network.ResourceTypeFetch, 200, "text/html"), fin}, 0},
		{"404 script", []event{sent(network.ResourceTypeScript), resp(network.ResourceTypeScript, 404, "text/javascript"), fin}, 0},
		{"failed", []event{sent(network.ResourceTypeScript), resp(network.ResourceTypeScript, 200, "text/javascript"), fail}, 0},
	}
	for _, c := range cases {
		for _, order := range permutations(len(c.events)) {
			got := 0
			n := &netTracker{s: &session{c: &Capture{}, kind: "page"}, reqs: map[network.RequestID]*request{}}
			n.ready = func(network.RequestID, *request) { got++ }
			var names []string
			for _, i := range order {
				n.update("1", c.events[i].f)
				names = append(names, c.events[i].name)
			}
			if got != c.want {
				t.Errorf("%s, order %v: fetched %d, want %d", c.name, names, got, c.want)
			}
			if open := n.open(); len(open) != 0 {
				t.Errorf("%s, order %v: still open: %v", c.name, names, open)
			}
		}
	}
}

func TestNetTrackerOpen(t *testing.T) {
	n := &netTracker{s: &session{c: &Capture{}, kind: "page"}, reqs: map[network.RequestID]*request{}}
	n.ready = func(network.RequestID, *request) {}
	n.update("1", func(q *request) { q.url = "http://h/slow" })
	if got := fmt.Sprint(n.open()); got != "[page http://h/slow]" {
		t.Fatalf("open = %s", got)
	}
	// A request that another target finishes goes stale on this session.
	n.reqs["1"].lastEvent = n.reqs["1"].lastEvent.Add(-staleAfter)
	if open := n.open(); len(open) != 0 {
		t.Fatalf("stale request still open: %v", open)
	}
}

func permutations(n int) [][]int {
	if n == 1 {
		return [][]int{{0}}
	}
	var out [][]int
	for _, p := range permutations(n - 1) {
		for i := 0; i <= len(p); i++ {
			q := append(append(append([]int{}, p[:i]...), n-1), p[i:]...)
			out = append(out, q)
		}
	}
	return out
}
