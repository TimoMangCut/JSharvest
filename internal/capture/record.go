package capture

import (
	"context"
	"iter"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// RecordOptions turns on the request log. Sink receives each request once
// it is complete, from any goroutine.
type RecordOptions struct {
	Mode    traffic.Mode
	MaxBody int // bytes kept of each request and response body; 0 keeps none
	Sink    func(traffic.Entry)
}

const (
	// settle is how long a finished request waits before it is written, for
	// the events that run behind on other subscriptions.
	settle = 500 * time.Millisecond
	// extraWait is the longest a finished request waits for the raw headers
	// Chrome said it would send.
	extraWait = 2 * time.Second
	// orphanAfter drops what never got its requestWillBeSent here: events
	// for a request another session owns, or late events for one written.
	// A request that did start here is kept until it ends or the capture
	// stops.
	orphanAfter = 10 * time.Second
)

// recorder keeps the request log of one session. Like netTracker, it gets
// each kind of event on its own subscription, so a request is put together
// from events in any order, and written once it is complete.
type recorder struct {
	s    *session
	opts RecordOptions

	mu  sync.Mutex
	xs  map[network.RequestID]*exchange
	now func() time.Time
}

// exchange is one request id: a request and the hops of its redirects.
type exchange struct {
	hops  []*hop
	rtype string
	frame string
	page  string
	init  *traffic.Initiator

	final         *network.Response // the response of the last hop
	finalType     string
	finalHasExtra bool
	reqExtra      []network.Headers // raw request headers, one per hop that has them, in order
	respExtra     []*network.EventResponseReceivedExtraInfo

	memoryCache bool // answered from the memory cache: never reached the server

	ended     bool
	endedAt   time.Time
	endTS     float64
	failed    string
	encoded   float64
	body      *traffic.Body
	omitted   string
	fetching  bool
	pending   int // body reads in flight
	lastEvent time.Time
}

// resourceType is the type the request was sent as, or else the type its
// response was received as.
func (x *exchange) resourceType() string {
	if x.rtype != "" {
		return x.rtype
	}
	return x.finalType
}

type hop struct {
	method, url string
	headers     map[string]string
	body        traffic.Body
	wall        time.Time
	ts          float64
	redirect    *network.Response // set when this hop was redirected
	extra       bool              // raw headers come for this hop
}

func newRecorder(s *session, o RecordOptions) *recorder {
	return &recorder{s: s, opts: o, xs: map[network.RequestID]*exchange{}, now: time.Now}
}

func (r *recorder) start() {
	ctx := r.s.ctx
	sent := chromedp.Events(ctx, network.RequestWillBeSent)
	sentExtra := chromedp.Events(ctx, network.RequestWillBeSentExtraInfo)
	resp := chromedp.Events(ctx, network.ResponseReceived)
	respExtra := chromedp.Events(ctx, network.ResponseReceivedExtraInfo)
	finished := chromedp.Events(ctx, network.LoadingFinished)
	failed := chromedp.Events(ctx, network.LoadingFailed)
	cached := chromedp.Events(ctx, network.RequestServedFromCache)
	go each(cached, r.onServedFromCache)
	go each(sent, r.onSent)
	go each(sentExtra, r.onSentExtra)
	go each(resp, r.onResponse)
	go each(respExtra, r.onResponseExtra)
	go each(finished, r.onFinished)
	go each(failed, r.onFailed)
}

func each[T any](events iter.Seq2[T, error], f func(*T)) {
	for ev, err := range events {
		if err != nil {
			return
		}
		f(&ev)
	}
}

func (r *recorder) onServedFromCache(ev *network.EventRequestServedFromCache) {
	r.with(ev.RequestID, func(x *exchange) { x.memoryCache = true })
}

func (r *recorder) onSentExtra(ev *network.EventRequestWillBeSentExtraInfo) {
	r.with(ev.RequestID, func(x *exchange) { x.reqExtra = append(x.reqExtra, ev.Headers) })
}

func (r *recorder) onResponse(ev *network.EventResponseReceived) {
	r.with(ev.RequestID, func(x *exchange) {
		x.final, x.finalHasExtra = ev.Response, ev.HasExtraInfo
		x.finalType = string(ev.Type)
		// The guard's made-up response ends the request: a fetch() whose
		// body the page never reads gets no loadingFinished.
		if heldBack(ev.Response) != "" && !x.ended {
			x.ended, x.endedAt, x.endTS = true, r.now(), float64(ev.Timestamp)
		}
	})
	r.maybeFetch(ev.RequestID)
}

func (r *recorder) onResponseExtra(ev *network.EventResponseReceivedExtraInfo) {
	r.with(ev.RequestID, func(x *exchange) { x.respExtra = append(x.respExtra, ev) })
}

func (r *recorder) onFinished(ev *network.EventLoadingFinished) {
	r.with(ev.RequestID, func(x *exchange) {
		x.ended, x.endedAt, x.endTS, x.encoded = true, r.now(), float64(ev.Timestamp), ev.EncodedDataLength
	})
	r.maybeFetch(ev.RequestID)
}

func (r *recorder) onFailed(ev *network.EventLoadingFailed) {
	r.with(ev.RequestID, func(x *exchange) {
		x.ended, x.endedAt, x.endTS = true, r.now(), float64(ev.Timestamp)
		x.failed = failReason(ev)
	})
}

func failReason(ev *network.EventLoadingFailed) string {
	switch {
	case ev.BlockedReason != "":
		return "blocked:" + string(ev.BlockedReason)
	case ev.CorsErrorStatus != nil:
		return "cors:" + string(ev.CorsErrorStatus.CorsError)
	case ev.Canceled:
		return "canceled"
	}
	return ev.ErrorText
}

// with runs f on the exchange of id, creating it if needed.
func (r *recorder) with(id network.RequestID, f func(*exchange)) {
	r.mu.Lock()
	x := r.xs[id]
	if x == nil {
		x = &exchange{}
		r.xs[id] = x
	}
	f(x)
	x.lastEvent = r.now()
	r.mu.Unlock()
}

func (r *recorder) onSent(ev *network.EventRequestWillBeSent) {
	req := ev.Request
	h := &hop{
		method: req.Method, url: req.URL, headers: flatHeaders(req.Headers),
		wall: wallTime(ev.WallTime), ts: float64(ev.Timestamp),
	}
	needPost := false
	if req.HasPostData {
		var b []byte
		for _, e := range req.PostDataEntries {
			b = append(b, e.Bytes...)
		}
		if len(b) > 0 {
			h.body = traffic.MakeBody(b, r.opts.MaxBody)
		} else {
			needPost = true // too long for the event; ask for it
		}
	}
	page := r.s.c.currentPage()
	r.with(ev.RequestID, func(x *exchange) {
		if ev.RedirectResponse != nil && len(x.hops) > 0 {
			last := x.hops[len(x.hops)-1]
			last.redirect, last.extra = ev.RedirectResponse, ev.RedirectHasExtraInfo
		}
		x.hops = append(x.hops, h)
		if ev.Type != "" {
			x.rtype = string(ev.Type)
		}
		if len(x.hops) == 1 {
			x.frame, x.page = string(ev.FrameID), page
			x.init = trafficInitiator(ev.Initiator)
		}
		if needPost && r.opts.MaxBody > 0 {
			x.pending++
		}
	})
	if needPost && r.opts.MaxBody > 0 {
		r.readPost(ev.RequestID, h)
	}
	// The response and its end may have been handled first.
	r.maybeFetch(ev.RequestID)
}

// readPost asks for a request body that was too long for the event.
func (r *recorder) readPost(id network.RequestID, h *hop) {
	c := r.s.c
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		var body traffic.Body
		if c.acquire(r.s.ctx) {
			ctx, cancel := context.WithTimeout(r.s.ctx, c.opts.CallTimeout)
			res, err := chromedp.Call(ctx, network.GetRequestPostData, network.GetRequestPostDataParams{RequestID: id})
			cancel()
			c.release()
			if err == nil {
				// cdproto has already decoded base64.
				body = traffic.MakeBody(res.PostData, r.opts.MaxBody)
			} else {
				slog.Debug("record: post data", "url", h.url, "err", err)
			}
		}
		r.with(id, func(x *exchange) {
			h.body = body
			x.pending--
		})
	}()
}

// maybeFetch reads the response body once the response and its end have
// both arrived, if the body is worth keeping.
func (r *recorder) maybeFetch(id network.RequestID) {
	r.mu.Lock()
	x := r.xs[id]
	if x == nil || x.fetching || !x.ended || x.failed != "" || x.final == nil || len(x.hops) == 0 {
		r.mu.Unlock()
		return
	}
	x.fetching = true
	rtype := x.resourceType()
	ok, why := r.opts.Mode.WantsBody(rtype, x.final.MimeType)
	switch {
	case !r.opts.Mode.Wants(rtype):
		ok, why = false, "type"
	case heldBack(x.final) != "":
		ok, why = false, "held_back"
	case r.opts.MaxBody <= 0:
		ok, why = false, "size"
	case ok && x.encoded > 4*float64(r.opts.MaxBody):
		ok, why = false, "size"
	}
	if !ok {
		x.omitted = why
		r.mu.Unlock()
		return
	}
	x.pending++
	r.mu.Unlock()

	c := r.s.c
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		var body *traffic.Body
		omitted := "lost:canceled"
		if c.acquire(r.s.ctx) {
			ctx, cancel := context.WithTimeout(r.s.ctx, c.opts.CallTimeout)
			res, err := chromedp.Call(ctx, network.GetResponseBody, network.GetResponseBodyParams{RequestID: id})
			cancel()
			c.release()
			if err == nil {
				mb := traffic.MakeBody(res.Body, r.opts.MaxBody)
				body, omitted = &mb, ""
			} else {
				omitted = "lost:" + bodyErrReason(err)
			}
		}
		r.with(id, func(x *exchange) {
			x.body, x.omitted = body, omitted
			x.pending--
		})
	}()
}

// heldBack returns the guard's reason when the response is the one the
// guard made up.
func heldBack(resp *network.Response) string {
	if resp == nil {
		return ""
	}
	for k, v := range resp.Headers {
		if strings.EqualFold(k, traffic.GuardHeader) {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
			return "held_back"
		}
	}
	return ""
}

// sweep writes the requests that are complete. With force, it writes
// everything it has, as the capture is stopping.
func (r *recorder) sweep(force bool) {
	now := r.now()
	var out []traffic.Entry
	r.mu.Lock()
	for id, x := range r.xs {
		if len(x.hops) == 0 {
			if force || now.Sub(x.lastEvent) > orphanAfter {
				delete(r.xs, id)
			}
			continue
		}
		if !force && !r.ready(x, now) {
			continue
		}
		delete(r.xs, id)
		out = append(out, r.entries(id, x)...)
	}
	r.mu.Unlock()
	for _, e := range out {
		r.opts.Sink(e)
	}
}

func (r *recorder) ready(x *exchange, now time.Time) bool {
	if !x.ended {
		// Slow, long-polling, or finished by another session (a worker's
		// main script, a cross-site frame's document): it is written when
		// it ends, or as it stands when the capture stops.
		return false
	}
	if x.pending > 0 || now.Sub(x.endedAt) < settle {
		return false
	}
	if now.Sub(x.endedAt) >= extraWait {
		return true
	}
	want := 0
	for _, h := range x.hops[:len(x.hops)-1] {
		if h.extra {
			want++
		}
	}
	if x.finalHasExtra {
		want++
	}
	return len(x.reqExtra) >= want && len(x.respExtra) >= want
}

// entries turns an exchange into one entry per hop.
func (r *recorder) entries(id network.RequestID, x *exchange) []traffic.Entry {
	rtype := x.resourceType()
	if !r.opts.Mode.Wants(rtype) {
		return nil
	}
	tags := []string(nil)
	if x.init != nil && internal(x.init) {
		tags = []string{"jsharvest"}
	}
	if r.challenge(x, rtype) {
		tags = append(tags, detect.TagChallenge)
	}
	var out []traffic.Entry
	ri, si := 0, 0
	for i, h := range x.hops {
		last := i == len(x.hops)-1
		e := traffic.Entry{
			Time: h.wall, Target: r.s.kind, TargetURL: r.s.targetURL, Page: x.page, Frame: x.frame,
			CDPID: string(id), Hop: i, ResourceType: rtype, Method: h.method, URL: h.url,
			Headers: h.headers, Body: h.body, Initiator: x.init, Tags: tags,
		}
		resp, hasExtra := h.redirect, h.extra
		if last {
			resp, hasExtra = x.final, x.finalHasExtra || x.final == nil
		}
		var reqRaw network.Headers
		var respRaw *network.EventResponseReceivedExtraInfo
		switch {
		case hasExtra && !last:
			if ri < len(x.reqExtra) {
				reqRaw = x.reqExtra[ri]
				ri++
			}
			if si < len(x.respExtra) {
				respRaw = x.respExtra[si]
				si++
			}
		case hasExtra:
			// The last pair: an HTTP auth challenge (401, 407) and its retry
			// send two under one hop, and the retry is what was answered.
			if ri < len(x.reqExtra) {
				reqRaw = x.reqExtra[len(x.reqExtra)-1]
			}
			if si < len(x.respExtra) {
				respRaw = x.respExtra[len(x.respExtra)-1]
			}
		}
		if len(reqRaw) > 0 {
			e.Headers = flatHeaders(reqRaw)
		} else if resp != nil && len(resp.RequestHeaders) > 0 {
			e.Headers = flatHeaders(resp.RequestHeaders)
		} else {
			e.HeadersProvisional = true
		}

		switch {
		case !last:
			e.Outcome = "redirect"
			if next := x.hops[i+1]; next.ts > 0 && h.ts > 0 {
				e.DurationMS = ms(next.ts - h.ts)
			}
		case resp != nil && heldBack(resp) != "":
			e.Outcome = "held_back:" + heldBack(resp)
			resp, respRaw = nil, nil
		case x.failed != "":
			e.Outcome = "failed:" + x.failed
		case !x.ended && resp == nil:
			e.Outcome = "incomplete" // no response here: still open, or another target's
		default:
			// A response without an end is a body still streaming, or one the
			// page never read: the request itself got its answer.
			e.Outcome = "ok"
		}
		if last && x.ended && h.ts > 0 && x.endTS >= h.ts {
			e.DurationMS = ms(x.endTS - h.ts)
		}
		if resp != nil || respRaw != nil {
			e.Response = response(resp, respRaw)
			if last && x.memoryCache {
				e.Response.Source = "memory-cache"
			}
			if last && e.Outcome == "ok" {
				if x.body != nil {
					e.Response.Body = *x.body
				}
				e.Response.BodyOmitted = x.omitted
				if !x.ended {
					e.Response.BodyOmitted = "unfinished"
				}
			}
		}
		out = append(out, e)
	}
	return out
}

func response(resp *network.Response, raw *network.EventResponseReceivedExtraInfo) *traffic.Response {
	out := &traffic.Response{Source: "network"}
	if resp != nil {
		out.Status, out.StatusText, out.MIME = resp.Status, resp.StatusText, resp.MimeType
		out.Headers = flatHeaders(resp.Headers)
		out.Protocol, out.RemoteIP = resp.Protocol, resp.RemoteIPAddress
		switch {
		case resp.FromServiceWorker:
			out.Source = "service-worker"
		case resp.FromPrefetchCache:
			out.Source = "prefetch"
		case resp.FromEarlyHints:
			out.Source = "early-hints"
		case resp.FromDiskCache:
			out.Source = "disk-cache"
		}
	}
	if raw != nil {
		// The raw headers have every Set-Cookie, and the status the server
		// really sent (304 where the cache made it a 200).
		if len(raw.Headers) > 0 {
			out.Headers = flatHeaders(raw.Headers)
		}
		if raw.StatusCode != 0 {
			out.Status = raw.StatusCode
		}
	}
	return out
}

// trafficInitiator keeps who made a request, with the stack: the top
// frames and the async chain that led to them, at most maxFrames frames.
func trafficInitiator(in *network.Initiator) *traffic.Initiator {
	if in == nil {
		return nil
	}
	out := &traffic.Initiator{Type: string(in.Type), URL: in.URL, Line: int64(in.LineNumber), Col: int64(in.ColumnNumber)}
	const maxFrames = 16
	async := ""
	const maxChain = 64
	for st := in.Stack; st != nil && len(out.Chain) < maxChain; st = st.Parent {
		if st != in.Stack {
			d := st.Description
			if d == "" {
				d = "async"
			}
			out.Chain = append(out.Chain, d)
		}
	}
	for st := in.Stack; st != nil && len(out.Stack) < maxFrames; st = st.Parent {
		for i, f := range st.CallFrames {
			if len(out.Stack) == maxFrames {
				break
			}
			fr := frame(f)
			if i == 0 {
				fr.Async = async
			}
			out.Stack = append(out.Stack, fr)
		}
		if st.Parent != nil {
			async = st.Parent.Description
			if async == "" {
				async = "async"
			}
		}
	}
	if out.URL == "" && len(out.Stack) > 0 {
		out.URL, out.Line, out.Col = out.Stack[0].URL, out.Stack[0].Line, out.Stack[0].Col
	}
	return out
}

func frame(f *runtime.CallFrame) traffic.Frame {
	return traffic.Frame{Func: f.FunctionName, URL: f.URL, Line: f.LineNumber, Col: f.ColumnNumber}
}

// internal reports whether jsharvest's own code made the request: its
// top frame is jsharvest's (the resolver's fetch). A frame of jsharvest's
// further down is the action tagger's wrapper around a page handler, and
// the request is the page's.
func internal(in *traffic.Initiator) bool {
	if len(in.Stack) > 0 {
		return marker.IsInternal(in.Stack[0].URL)
	}
	return marker.IsInternal(in.URL)
}

func wallTime(t cdp.TimeSinceEpoch) time.Time {
	sec, frac := math.Modf(float64(t))
	return time.Unix(int64(sec), int64(frac*1e9)).UTC()
}

func ms(seconds float64) float64 { return math.Round(seconds*1e6) / 1e3 }

// challenge reports a request a bot challenge made, or that ran on a
// challenge page: it is in the log (it was sent), but it is not one of the
// target's endpoints. The /cdn-cgi/ paths themselves are left to
// detect.InfraPath; this is for what the challenge's code, or a blocked
// page's scripts, asked of the site.
func (r *recorder) challenge(x *exchange, rtype string) bool {
	if in := x.init; in != nil {
		if detect.ChallengeURL(in.URL) {
			return true
		}
		for _, f := range in.Stack {
			if detect.ChallengeURL(f.URL) {
				return true
			}
		}
	}
	if rtype == "Document" || r.s.kind != "page" {
		return false
	}
	c := r.s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.onBlockedPage(x.page)
}
