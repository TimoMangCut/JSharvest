package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/detect"
)

// request tracks one network request of a session. The events of a request
// arrive on separate subscriptions, so their order is not guaranteed; every
// flag is set on its own and the body is fetched once they all line up.
type request struct {
	url       string
	mime      string
	status    int64
	rtype     network.ResourceType
	headers   map[string]string
	initiator *Initiator
	responded bool
	finished  bool
	held      bool // the response is the guard's made-up one: the guard may still claim the request
	keep      bool // the guard failed it (ERR_BLOCKED_BY_CLIENT): same
	done      bool // finished or failed
	queued    bool
	lastEvent time.Time
}

// script reports whether the response is JavaScript worth keeping. The
// extension rule catches JS served with a wrong type, but not an HTML error
// page or SPA fallback served under a .js name.
func (q *request) script() bool {
	if q.status < 200 || q.status >= 400 {
		return false
	}
	if strings.HasPrefix(q.url, "data:") || strings.HasPrefix(q.url, "blob:") {
		return false
	}
	if q.rtype == network.ResourceTypeScript || isJSMime(q.mime) {
		return true
	}
	return hasJSExt(q.url) && !strings.Contains(strings.ToLower(q.mime), "html")
}

type netTracker struct {
	s *session
	// ready receives each script response once its body can be fetched. It
	// is fetch in production and a recorder in tests.
	ready func(network.RequestID, *request)

	mu        sync.Mutex
	reqs      map[network.RequestID]*request
	lastSweep time.Time
}

func newNetTracker(s *session) *netTracker {
	n := &netTracker{s: s, reqs: map[network.RequestID]*request{}}
	n.ready = n.fetch
	return n
}

// start subscribes to the session's network events. Subscriptions start when
// Events returns, before any goroutine ranges over them.
func (n *netTracker) start() {
	ctx := n.s.ctx
	willBeSent := chromedp.Events(ctx, network.RequestWillBeSent)
	responses := chromedp.Events(ctx, network.ResponseReceived)
	finished := chromedp.Events(ctx, network.LoadingFinished)
	failed := chromedp.Events(ctx, network.LoadingFailed)

	go func() {
		for ev, err := range willBeSent {
			if err != nil {
				return
			}
			// A redirect's hop has no responseReceived: its response rides
			// here, and is judged as one.
			if ev.RedirectResponse != nil {
				n.s.checkPrivateResp(ev.FrameID, ev.Type, ev.RedirectResponse)
			}
			init := initiator(ev.Initiator)
			// A willBeSent that comes after the request's end is not noted.
			if !n.over(ev.RequestID) {
				n.s.c.noteRequest(string(ev.RequestID), string(ev.FrameID), init)
			}
			n.update(ev.RequestID, func(q *request) {
				q.url = ev.Request.URL
				if ev.Type != "" {
					q.rtype = ev.Type
				}
				if q.initiator == nil {
					q.initiator = init
				}
			})
		}
	}()
	go func() {
		for ev, err := range responses {
			if err != nil {
				return
			}
			n.update(ev.RequestID, func(q *request) { q.response(&ev) })
			n.s.checkPrivate(&ev)
			// The tab's main frame has the id of the tab target. A navigation
			// the guard answered never left the page: the document is still
			// the one before.
			if n.s.kind == "page" && ev.Type == network.ResourceTypeDocument && string(ev.FrameID) == string(n.s.id) && heldBack(ev.Response) == "" {
				n.s.c.setMainDoc(detect.Doc{URL: ev.Response.URL, Status: ev.Response.Status, Headers: flatHeaders(ev.Response.Headers)})
			}
		}
	}()
	go func() {
		for ev, err := range finished {
			if err != nil {
				return
			}
			n.update(ev.RequestID, func(q *request) { q.done, q.finished = true, true })
		}
	}()
	go func() {
		for ev, err := range failed {
			if err != nil {
				return
			}
			if denied, insecure := lnaRefused(&ev); denied || insecure {
				n.s.c.noteLNADenied(n.urlOf(ev.RequestID), insecure)
			}
			keep := failedByGuard(&ev)
			n.update(ev.RequestID, func(q *request) { q.done, q.keep = true, keep })
		}
	}()
}

// response notes a request's response: what it is, and whether it is the
// guard's made-up one (held: the guard may still claim the request).
func (q *request) response(ev *network.EventResponseReceived) {
	q.url = ev.Response.URL
	q.mime = ev.Response.MimeType
	q.status = ev.Response.Status
	q.headers = flatHeaders(ev.Response.Headers)
	if ev.Type != "" {
		q.rtype = ev.Type
	}
	q.responded = true
	q.held = heldBack(ev.Response) != ""
}

// failedByGuard reports whether the guard failed the request (its fail
// mode, or a held request it could not fulfill): such a request has no
// response to carry the guard's mark, so the capture keeps it for the
// guard to claim at the end of the run.
func failedByGuard(ev *network.EventLoadingFailed) bool {
	return strings.Contains(ev.ErrorText, "ERR_BLOCKED_BY_CLIENT")
}

// lnaRefused reports a request Chrome's Local Network Access refused:
// for the permission jsharvest denies, or because the page is not a
// secure context (Chrome refuses those without asking).
func lnaRefused(ev *network.EventLoadingFailed) (denied, insecure bool) {
	if ev.CorsErrorStatus == nil {
		return false, false
	}
	switch ev.CorsErrorStatus.CorsError {
	case network.CorsErrorLocalNetworkAccessPermissionDenied:
		return true, false
	case network.CorsErrorInsecureLocalNetwork:
		return false, true
	}
	return false, false
}

// urlOf is the URL the tracker noted for a request ("" if none).
func (n *netTracker) urlOf(id network.RequestID) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if q := n.reqs[id]; q != nil {
		return q.url
	}
	return ""
}

// over reports whether the request is complete and not the guard's: its
// ids are no longer kept by the capture.
func (n *netTracker) over(id network.RequestID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	q := n.reqs[id]
	return q != nil && ((q.responded && q.finished && !q.held) || (q.done && !q.finished && !q.keep))
}

// raiseBuffers re-sends Network.enable with larger buffers. Chrome keeps
// 20 MB per resource and 200 MB in total by default, and evicts bodies past
// that before anyone can read them.
func (n *netTracker) raiseBuffers() error {
	ctx, cancel := context.WithTimeout(n.s.ctx, n.s.c.opts.CallTimeout)
	defer cancel()
	total, per := n.s.c.opts.MaxTotalBuffer, n.s.c.opts.MaxResourceBuffer
	_, err := chromedp.Call(ctx, network.Enable, network.EnableParams{
		MaxTotalBufferSize:    &total,
		MaxResourceBufferSize: &per,
	})
	return err
}

func (n *netTracker) update(id network.RequestID, f func(*request)) {
	if id == "" { // a worker's request has no network id: nothing to match it by
		n.s.c.touch()
		return
	}
	n.mu.Lock()
	q := n.reqs[id]
	if q == nil {
		q = &request{}
		n.reqs[id] = q
	}
	f(q)
	q.lastEvent = time.Now()
	var job *request
	if q.responded && q.finished && !q.queued && q.script() {
		q.queued = true
		cp := *q
		job = &cp
	}
	// Drop the details once nothing can change the outcome: the body is
	// queued, the response is known not to be a script, or the request
	// failed. Until the response has arrived the type is unknown, and a
	// finished event can come before it.
	if q.queued || (q.finished && q.responded && !q.script()) || (q.done && !q.finished) {
		*q = request{done: q.done, finished: q.finished, responded: q.responded, queued: q.queued, held: q.held, keep: q.keep, lastEvent: q.lastEvent}
	}
	// Forget the request once it is over and the guard cannot claim it. A
	// response comes once, for the last hop of a redirect (the hops before
	// it ride on requestWillBeSent), so responded and finished mean the
	// last hop is done. A finished event before the response keeps it.
	forget := (q.responded && q.finished && !q.held) || (q.done && !q.finished && !q.keep)
	// The tracker's own key stays as a small tombstone, so that a late
	// event of the request does not open it again; the sweep below takes
	// it after staleAfter.
	forgetCapture := forget && !q.held && !q.keep
	now := time.Now()
	var stale []string
	if now.Sub(n.lastSweep) >= staleAfter {
		n.lastSweep = now
		for k, r := range n.reqs {
			// A request that never ends (a fetch whose body nobody reads,
			// an event stream, one another target finishes) has no done
			// to wait for: after abandonedAfter without an event it goes
			// too, unless the guard may still claim it.
			gone := (r.done && now.Sub(r.lastEvent) >= staleAfter) ||
				(!r.done && !r.held && !r.keep && now.Sub(r.lastEvent) >= abandonedAfter)
			if gone {
				delete(n.reqs, k)
				if !r.held && !r.keep {
					stale = append(stale, string(k))
				}
			}
		}
	}
	n.mu.Unlock()
	if forgetCapture {
		n.s.c.forgetRequest(string(id))
	}
	for _, k := range stale {
		n.s.c.forgetRequest(k)
	}

	n.s.c.touch()
	if job != nil {
		n.ready(id, job)
	}
}

func (n *netTracker) fetch(id network.RequestID, q *request) {
	c := n.s.c
	if ini := q.initiator; detect.ChallengeURL(q.url) || (ini != nil && detect.ChallengeURL(ini.URL)) {
		iu := ""
		if ini != nil {
			iu = ini.URL
		}
		c.skipChallenge("", q.url, iu)
		return
	}
	page := c.currentPage()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if !c.acquire(n.s.ctx) {
			c.lost("canceled")
			return
		}
		defer c.release()
		ctx, cancel := context.WithTimeout(n.s.ctx, c.opts.CallTimeout)
		defer cancel()
		res, err := chromedp.Call(ctx, network.GetResponseBody, network.GetResponseBodyParams{RequestID: id})
		if err != nil {
			reason := bodyErrReason(err)
			c.lost(reason)
			slog.Debug("get body", "target", n.s.kind, "url", q.url, "reason", reason, "err", err)
			return
		}
		if len(res.Body) == 0 {
			return
		}
		c.emit(Script{
			Body: res.Body, Kind: "file", Via: "network", URL: q.url,
			Target: n.s.kind, TargetURL: n.s.targetURL, Page: page,
			Status: q.status, MIME: q.mime, Headers: q.headers, Initiator: q.initiator,
			Tags: detect.ScriptTags(q.url),
		})
	}()
}

// staleAfter is how long a request may go without any event before it no
// longer counts as open. A request the tab starts but another target
// finishes (a worker's main script, a cross-site frame's document, a shared
// worker) never gets its loadingFinished on the tab's session.
const staleAfter = 5 * time.Second

// abandonedAfter is how long a request that has not ended may go without
// an event before the tracker and the capture forget it (the sweep). Much
// longer than staleAfter: a slow response is not an abandoned one, and one
// that comes after all is simply noted again.
const abandonedAfter = 10 * staleAfter

// open lists the requests that have not finished or failed and are not
// stale.
func (n *netTracker) open() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, q := range n.reqs {
		if !q.done && time.Since(q.lastEvent) < staleAfter {
			out = append(out, n.s.kind+" "+q.url)
		}
	}
	return out
}

func bodyErrReason(err error) string {
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case strings.Contains(msg, "evicted"):
		return "evicted"
	case strings.Contains(msg, "No resource with given identifier"):
		return "no_resource"
	case strings.Contains(msg, "No data found"):
		return "no_data"
	}
	return "other"
}

func initiator(in *network.Initiator) *Initiator {
	if in == nil {
		return nil
	}
	out := &Initiator{Type: string(in.Type), URL: in.URL, Line: int64(in.LineNumber), Col: int64(in.ColumnNumber)}
	if out.URL == "" && in.Stack != nil && len(in.Stack.CallFrames) > 0 {
		f := in.Stack.CallFrames[0]
		out.URL, out.Line, out.Col = f.URL, f.LineNumber, f.ColumnNumber
	}
	return out
}

func flatHeaders(h network.Headers) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = fmt.Sprint(v)
	}
	return out
}

func isJSMime(m string) bool {
	m = strings.ToLower(m)
	return strings.Contains(m, "javascript") || strings.Contains(m, "ecmascript")
}

func hasJSExt(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch path.Ext(u.Path) {
	case ".js", ".mjs", ".cjs":
		return true
	}
	return false
}
