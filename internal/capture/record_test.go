package capture

import (
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"

	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func testRecorder(mode traffic.Mode, maxBody int) (*recorder, *[]traffic.Entry, *clock) {
	var got []traffic.Entry
	clk := &clock{t: time.Unix(1000, 0)}
	r := newRecorder(&session{c: &Capture{}, kind: "page"}, RecordOptions{Mode: mode, MaxBody: maxBody, Sink: func(e traffic.Entry) { got = append(got, e) }})
	r.now = clk.now
	return r, &got, clk
}

type recEvent struct {
	kind string // events of one kind keep their order, as on one subscription
	f    func(*recorder)
}

// A redirect, then the final response, each hop with raw headers: every
// order that keeps each kind's own order must give the same two entries.
func TestRecorderRedirectAnyOrder(t *testing.T) {
	events := []recEvent{
		{"sent", func(r *recorder) {
			r.onSent(&network.EventRequestWillBeSent{RequestID: "1", Type: "Document", Timestamp: 1,
				Request: &network.Request{Method: "GET", URL: "http://h/old", Headers: network.Headers{"Accept": "x"}}})
		}},
		{"sent", func(r *recorder) {
			r.onSent(&network.EventRequestWillBeSent{RequestID: "1", Type: "Document", Timestamp: 2,
				Request:          &network.Request{Method: "GET", URL: "http://h/new"},
				RedirectResponse: &network.Response{Status: 302, Headers: network.Headers{"Location": "/new"}}, RedirectHasExtraInfo: true})
		}},
		{"sentExtra", func(r *recorder) {
			r.onSentExtra(&network.EventRequestWillBeSentExtraInfo{RequestID: "1", Headers: network.Headers{"Cookie": "a=1", ":path": "/old"}})
		}},
		{"sentExtra", func(r *recorder) {
			r.onSentExtra(&network.EventRequestWillBeSentExtraInfo{RequestID: "1", Headers: network.Headers{"Cookie": "a=2", ":path": "/new"}})
		}},
		{"respExtra", func(r *recorder) {
			r.onResponseExtra(&network.EventResponseReceivedExtraInfo{RequestID: "1", StatusCode: 302, Headers: network.Headers{"Set-Cookie": "a=2", "Location": "/new"}})
		}},
		{"respExtra", func(r *recorder) {
			r.onResponseExtra(&network.EventResponseReceivedExtraInfo{RequestID: "1", StatusCode: 200, Headers: network.Headers{"Content-Type": "text/html"}})
		}},
		{"resp", func(r *recorder) {
			r.onResponse(&network.EventResponseReceived{RequestID: "1", Type: "Document", HasExtraInfo: true,
				Response: &network.Response{URL: "http://h/new", Status: 200, MimeType: "text/html"}})
		}},
		{"fin", func(r *recorder) { r.onFinished(&network.EventLoadingFinished{RequestID: "1", Timestamp: 3}) }},
	}
	runs := 0
	for _, order := range permutations(len(events)) {
		if !keepsKindOrder(events, order) {
			continue
		}
		runs++
		r, got, clk := testRecorder(traffic.API, 0)
		for _, i := range order {
			events[i].f(r)
			// Sweeps between events must not write a half-built request.
			r.sweep(false)
		}
		clk.t = clk.t.Add(settle)
		r.sweep(false)
		if len(*got) != 2 {
			t.Fatalf("order %v: %d entries, want 2", order, len(*got))
		}
		a, b := (*got)[0], (*got)[1]
		if a.Hop == 1 {
			a, b = b, a
		}
		if a.URL != "http://h/old" || a.Outcome != "redirect" || a.Response.Status != 302 || a.Headers["cookie"] != "a=1" ||
			a.Response.Headers["set-cookie"] != "a=2" || a.DurationMS != 1000 {
			t.Errorf("order %v: first hop %+v resp %+v", order, a, a.Response)
		}
		if b.URL != "http://h/new" || b.Outcome != "ok" || b.Response.Status != 200 || b.Headers["cookie"] != "a=2" ||
			b.Response.Headers["content-type"] != "text/html" || b.Response.BodyOmitted != "size" || b.DurationMS != 1000 {
			t.Errorf("order %v: second hop %+v resp %+v", order, b, b.Response)
		}
	}
	if runs != 8*7*6*5*4*3*2/(2*2*2) {
		t.Fatalf("ran %d orders", runs)
	}
}

func keepsKindOrder(events []recEvent, order []int) bool {
	last := map[string]int{}
	for _, i := range order {
		if j, ok := last[events[i].kind]; ok && j > i {
			return false
		}
		last[events[i].kind] = i
	}
	return true
}

func TestRecorderOutcomes(t *testing.T) {
	sent := func(r *recorder, typ network.ResourceType, method string) {
		r.onSent(&network.EventRequestWillBeSent{RequestID: "1", Type: typ, Timestamp: 1,
			Request: &network.Request{Method: method, URL: "http://h/api/x", HasPostData: method == "POST",
				PostDataEntries: []*network.PostDataEntry{{Bytes: []byte(`{"a":1}`)}}}})
	}
	cases := []struct {
		name    string
		mode    traffic.Mode
		events  func(*recorder)
		outcome string // "" for no entry
	}{
		{"held back by the guard", traffic.API, func(r *recorder) {
			sent(r, "Fetch", "POST")
			r.onResponse(&network.EventResponseReceived{RequestID: "1", Type: "Fetch",
				Response: &network.Response{Status: 200, Headers: network.Headers{"X-Jsharvest-Guard": "write"}}})
			r.onFinished(&network.EventLoadingFinished{RequestID: "1", Timestamp: 2})
		}, "held_back:write"},
		{"held back fetch, body never read: no loadingFinished", traffic.API, func(r *recorder) {
			sent(r, "Fetch", "POST")
			r.onResponse(&network.EventResponseReceived{RequestID: "1", Type: "Fetch",
				Response: &network.Response{Status: 200, Headers: network.Headers{"X-Jsharvest-Guard": "write"}}})
		}, "held_back:write"},
		{"answered, body never read", traffic.API, func(r *recorder) {
			sent(r, "Fetch", "GET")
			r.onResponse(&network.EventResponseReceived{RequestID: "1", Type: "Fetch", Response: &network.Response{Status: 200}})
			r.sweep(true)
		}, "ok"},
		{"failed", traffic.API, func(r *recorder) {
			sent(r, "XHR", "GET")
			r.onFailed(&network.EventLoadingFailed{RequestID: "1", Timestamp: 2, ErrorText: "net::ERR_CONNECTION_REFUSED"})
		}, "failed:net::ERR_CONNECTION_REFUSED"},
		{"cors", traffic.API, func(r *recorder) {
			sent(r, "Fetch", "GET")
			r.onFailed(&network.EventLoadingFailed{RequestID: "1", Timestamp: 2, ErrorText: "net::ERR_FAILED",
				CorsErrorStatus: &network.CorsErrorStatus{CorsError: "MissingAllowOriginHeader"}})
		}, "failed:cors:MissingAllowOriginHeader"},
		{"script left out in api mode", traffic.API, func(r *recorder) {
			sent(r, "Script", "GET")
			r.onResponse(&network.EventResponseReceived{RequestID: "1", Type: "Script", Response: &network.Response{Status: 200}})
			r.onFinished(&network.EventLoadingFinished{RequestID: "1", Timestamp: 2})
		}, ""},
		{"script kept in all mode", traffic.All, func(r *recorder) {
			sent(r, "Script", "GET")
			r.onResponse(&network.EventResponseReceived{RequestID: "1", Type: "Script", Response: &network.Response{Status: 200}})
			r.onFinished(&network.EventLoadingFinished{RequestID: "1", Timestamp: 2})
		}, "ok"},
		{"never ends here", traffic.API, func(r *recorder) { sent(r, "Fetch", "GET") }, ""},
	}
	for _, c := range cases {
		r, got, clk := testRecorder(c.mode, 100)
		c.events(r)
		clk.t = clk.t.Add(extraWait)
		r.sweep(false)
		if c.outcome == "" {
			if len(*got) != 0 {
				t.Errorf("%s: wrote %+v", c.name, *got)
			}
			continue
		}
		if len(*got) != 1 {
			t.Errorf("%s: %d entries", c.name, len(*got))
			continue
		}
		e := (*got)[0]
		if e.Outcome != c.outcome {
			t.Errorf("%s: outcome %q, want %q", c.name, e.Outcome, c.outcome)
		}
		if strings.HasPrefix(c.outcome, "held_back") && e.Response != nil {
			t.Errorf("%s: kept the made-up response", c.name)
		}
		if e.Method == "POST" && e.Body.Body != `{"a":1}` {
			t.Errorf("%s: body %q", c.name, e.Body.Body)
		}
	}

	// A request that never ends here is written as incomplete when the
	// capture stops, or when it goes stale.
	r, got, clk := testRecorder(traffic.API, 100)
	sent(r, "EventSource", "GET")
	r.sweep(true)
	if len(*got) != 1 || (*got)[0].Outcome != "incomplete" {
		t.Errorf("forced: %+v", *got)
	}
	// A slow request is kept until it ends, however long that takes.
	r, got, clk = testRecorder(traffic.API, 100)
	sent(r, "Fetch", "GET")
	clk.t = clk.t.Add(orphanAfter + time.Minute)
	r.sweep(false)
	if len(*got) != 0 {
		t.Errorf("slow request written early: %+v", *got)
	}
	r.onResponse(&network.EventResponseReceived{RequestID: "1", Type: "Fetch", Response: &network.Response{Status: 200}})
	r.onFinished(&network.EventLoadingFinished{RequestID: "1", Timestamp: 70})
	clk.t = clk.t.Add(extraWait)
	r.sweep(false)
	if len(*got) != 1 || (*got)[0].Outcome != "ok" || (*got)[0].Response.Status != 200 {
		t.Errorf("slow request: %+v", *got)
	}
	// An HTTP auth retry: two raw pairs under one hop; the answer is the
	// second.
	r, got, clk = testRecorder(traffic.API, 0)
	sent(r, "Fetch", "GET")
	r.onSentExtra(&network.EventRequestWillBeSentExtraInfo{RequestID: "1", Headers: network.Headers{"Accept": "x"}})
	r.onSentExtra(&network.EventRequestWillBeSentExtraInfo{RequestID: "1", Headers: network.Headers{"Authorization": "Basic x"}})
	r.onResponseExtra(&network.EventResponseReceivedExtraInfo{RequestID: "1", StatusCode: 401})
	r.onResponseExtra(&network.EventResponseReceivedExtraInfo{RequestID: "1", StatusCode: 200})
	r.onResponse(&network.EventResponseReceived{RequestID: "1", Type: "Fetch", HasExtraInfo: true, Response: &network.Response{Status: 200}})
	r.onFinished(&network.EventLoadingFinished{RequestID: "1", Timestamp: 2})
	clk.t = clk.t.Add(extraWait)
	r.sweep(false)
	if len(*got) != 1 || (*got)[0].Response.Status != 200 || (*got)[0].Headers["authorization"] != "Basic x" {
		t.Errorf("auth retry: %+v %+v", *got, (*got)[0].Response)
	}
	// Late events for a request already written make no entry.
	r, got, clk = testRecorder(traffic.API, 100)
	r.onSentExtra(&network.EventRequestWillBeSentExtraInfo{RequestID: "9"})
	clk.t = clk.t.Add(orphanAfter + time.Second)
	r.sweep(false)
	r.sweep(true)
	if len(*got) != 0 || len(r.xs) != 0 {
		t.Errorf("orphan: %+v, %d kept", *got, len(r.xs))
	}
}

func TestTrafficInitiator(t *testing.T) {
	in := trafficInitiator(&network.Initiator{Type: "script", Stack: &runtimeStack})
	if len(in.Stack) != 3 || in.Stack[2].Async != "Promise.then" || in.Stack[0].Func != "save" || in.URL != "http://h/app.js" ||
		len(in.Chain) != 1 || in.Chain[0] != "Promise.then" {
		t.Fatalf("%+v", in)
	}
	if !internal(&traffic.Initiator{Stack: []traffic.Frame{{URL: marker.Internal}, {URL: "x"}}}) {
		t.Error("jsharvest's own fetch not seen")
	}
	// The tagger's wrapper sits under every page handler: the request is
	// still the page's.
	if internal(&traffic.Initiator{Stack: []traffic.Frame{{URL: "x"}, {URL: marker.Internal}}}) {
		t.Error("page request taken for jsharvest's")
	}
}

var runtimeStack = runtime.StackTrace{
	CallFrames: []*runtime.CallFrame{
		{FunctionName: "save", URL: "http://h/app.js", LineNumber: 10, ColumnNumber: 4},
		{FunctionName: "submit", URL: "http://h/app.js", LineNumber: 20},
	},
	Parent: &runtime.StackTrace{Description: "Promise.then", CallFrames: []*runtime.CallFrame{
		{FunctionName: "onClick", URL: "http://h/app.js", LineNumber: 30},
	}},
}
