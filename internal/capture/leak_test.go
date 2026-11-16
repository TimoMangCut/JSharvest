package capture

import (
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
)

func leakTracker() (*netTracker, *Capture) {
	c := &Capture{initiators: map[string]*Initiator{}, requests: map[string]bool{}, frames: map[string]bool{}}
	n := &netTracker{s: &session{c: c, kind: "page"}, reqs: map[network.RequestID]*request{}}
	n.ready = func(network.RequestID, *request) {}
	return n, c
}

func sent(n *netTracker, c *Capture, id string) {
	c.noteRequest(id, "F", &Initiator{Type: "script", URL: "http://h/app.js"})
	n.update(network.RequestID(id), func(q *request) { q.url = "http://h/a.js"; q.rtype = network.ResourceTypeScript })
}

func respond(n *netTracker, id string) {
	n.update(network.RequestID(id), func(q *request) {
		q.url, q.status, q.mime, q.responded = "http://h/a.js", 200, "text/javascript", true
	})
}

func finish(n *netTracker, id string) {
	n.update(network.RequestID(id), func(q *request) { q.done, q.finished = true, true })
}

func TestLeakCompletedRequestIsForgotten(t *testing.T) {
	n, c := leakTracker()
	sent(n, c, "1")
	respond(n, "1")
	finish(n, "1")
	if len(c.requests) != 0 || len(c.initiators) != 0 {
		t.Errorf("kept: requests=%d initiators=%d", len(c.requests), len(c.initiators))
	}
	// The tracker's key is a tombstone, swept once stale.
	n.reqs["1"].lastEvent = time.Now().Add(-2 * staleAfter)
	n.lastSweep = time.Time{}
	sent(n, c, "2")
	if _, ok := n.reqs["1"]; ok {
		t.Error("the tombstone stayed")
	}
}

func TestLeakLateWillBeSentIsNotNoted(t *testing.T) {
	n, _ := leakTracker()
	respond(n, "1")
	finish(n, "1")
	if !n.over("1") {
		t.Fatal("not over")
	}
}

func TestLeakFinishedBeforeResponseIsNotForgottenEarly(t *testing.T) {
	n, c := leakTracker()
	sent(n, c, "1")
	finish(n, "1")
	if !c.Owns("1", "", "") || c.InitiatorOf("1") == nil {
		t.Fatal("forgot a request whose response is not known yet")
	}
	respond(n, "1")
	if c.Owns("1", "", "") {
		t.Error("kept after the response came")
	}
}

func TestLeakRedirectIsNotForgottenInTheMiddle(t *testing.T) {
	n, c := leakTracker()
	sent(n, c, "1")
	sent(n, c, "1") // the redirect hop: the same id, a new requestWillBeSent
	if !c.Owns("1", "", "") || len(n.reqs) != 1 {
		t.Fatal("forgot a request in the middle of a redirect")
	}
	respond(n, "1")
	finish(n, "1")
	if c.Owns("1", "", "") {
		t.Error("kept after the last hop finished")
	}
}

func TestLeakStaleDoneKeyIsSwept(t *testing.T) {
	n, c := leakTracker()
	sent(n, c, "1")
	finish(n, "1") // never responded
	n.reqs["1"].lastEvent = time.Now().Add(-2 * staleAfter)
	n.lastSweep = time.Time{}
	sent(n, c, "2")
	if _, ok := n.reqs["1"]; ok {
		t.Error("a stale done key stayed")
	}
	if _, ok := n.reqs["2"]; !ok {
		t.Error("an open key was swept")
	}
}

func TestLeakEmptyIDAddsNoKey(t *testing.T) {
	n, c := leakTracker()
	sent(n, c, "")
	finish(n, "")
	if len(n.reqs) != 0 || len(c.requests) != 0 || len(c.initiators) != 0 {
		t.Errorf("empty id kept: reqs=%d requests=%d initiators=%d", len(n.reqs), len(c.requests), len(c.initiators))
	}
}

func TestLeakGuardHeldResponseIsKept(t *testing.T) {
	n, c := leakTracker()
	sent(n, c, "1")
	n.update("1", func(q *request) {
		q.url, q.status, q.mime, q.responded, q.held = "http://h/api", 200, "application/json", true, true
	})
	finish(n, "1")
	if !c.Owns("1", "", "") || c.InitiatorOf("1") == nil {
		t.Error("forgot a request the guard held back")
	}
	// Held before the finished event, too.
	n2, c2 := leakTracker()
	sent(n2, c2, "2")
	finish(n2, "2")
	n2.update("2", func(q *request) { q.responded, q.held = true, true })
	if !c2.Owns("2", "", "") || c2.InitiatorOf("2") == nil {
		t.Error("forgot a held request when finished came first")
	}
}

func TestLeakGuardFailedRequestIsKeptOtherFailuresAreNot(t *testing.T) {
	if !failedByGuard(&network.EventLoadingFailed{ErrorText: "net::ERR_BLOCKED_BY_CLIENT"}) {
		t.Error("the guard's fail mode is not recognised")
	}
	if failedByGuard(&network.EventLoadingFailed{ErrorText: "net::ERR_CONNECTION_REFUSED"}) {
		t.Error("an ordinary failure is taken for the guard's")
	}
	n, c := leakTracker()
	sent(n, c, "1")
	n.update("1", func(q *request) { q.done, q.keep = true, true })
	if !c.Owns("1", "", "") || c.InitiatorOf("1") == nil {
		t.Error("forgot a request the guard failed")
	}
	sent(n, c, "2")
	n.update("2", func(q *request) { q.done = true })
	if c.Owns("2", "", "") || c.InitiatorOf("2") != nil {
		t.Error("kept an ordinary failed request")
	}
}

// The guard's mark on a response event keeps the request (P3.1 review: the
// held test above sets the flag by hand).
func TestLeakGuardMarkOnResponseEventKeeps(t *testing.T) {
	n, c := leakTracker()
	sent(n, c, "7")
	ev := &network.EventResponseReceived{RequestID: "7", Type: network.ResourceTypeFetch,
		Response: &network.Response{URL: "http://h/api/x", Status: 200, MimeType: "application/json",
			Headers: network.Headers{"X-Jsharvest-Guard": "write"}}}
	n.update("7", func(q *request) { q.response(ev) })
	finish(n, "7")
	if !c.Owns("7", "", "") || c.InitiatorOf("7") == nil {
		t.Error("forgot a request whose response carries the guard's mark")
	}
	ev.RequestID, ev.Response.Headers = "8", network.Headers{"Content-Type": "application/json"}
	sent(n, c, "8")
	n.update("8", func(q *request) { q.response(ev) })
	finish(n, "8")
	if c.InitiatorOf("8") != nil {
		t.Error("kept a request with a plain response")
	}
}

func TestLeakAbandonedRequestIsSwept(t *testing.T) {
	n, c := leakTracker()
	sent(n, c, "1") // an SSE, a fetch nobody reads: no loadingFinished, ever
	sent(n, c, "keep")
	n.update("keep", func(q *request) { q.keep = true })
	n.reqs["1"].lastEvent = time.Now().Add(-2 * abandonedAfter)
	n.reqs["keep"].lastEvent = time.Now().Add(-2 * abandonedAfter)
	n.lastSweep = time.Time{}
	sent(n, c, "2")
	if _, ok := n.reqs["1"]; ok {
		t.Error("an abandoned request stayed in the tracker")
	}
	if c.Owns("1", "", "") || c.InitiatorOf("1") != nil {
		t.Error("an abandoned request stayed in the capture")
	}
	if _, ok := n.reqs["keep"]; !ok {
		t.Error("a request the guard may claim was swept")
	}
	if _, ok := n.reqs["2"]; !ok {
		t.Error("a live request was swept")
	}
}
