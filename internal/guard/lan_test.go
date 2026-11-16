package guard

import (
	"context"
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/target"
	"regexp"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

func rulesOf(t *testing.T, s string) netsafe.Rules {
	t.Helper()
	r, err := netsafe.ParseHostRules(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBlockPrivate(t *testing.T) {
	rules := rulesOf(t, "MAP lan.jsh.test 127.0.0.1")
	cases := []struct {
		origin, dest string
		rules        netsafe.Rules
		want         bool
	}{
		{"https://app.example.com/", "http://127.0.0.1/", nil, true},
		{"https://app.example.com/", "http://10.0.0.5/", nil, true},
		{"https://app.example.com/", "http://2130706433/", nil, true},
		{"https://app.example.com/", "http://localhost:3000/", nil, true},
		{"https://app.example.com/", "http://a.localhost/", nil, true},
		{"https://app.example.com/", "http://[::1]/", nil, true},
		{"https://app.example.com/", "ws://169.254.169.254/", nil, true},
		{"https://app.example.com/", "https://cdn.example.net/", nil, false},
		{"https://app.example.com/", "data:text/plain,hi", nil, false},
		{"http://127.0.0.1:8770/", "http://127.0.0.1:8771/x", nil, false},
		{"http://localhost:8770/", "http://10.0.0.5/", nil, false},
		{"", "http://127.0.0.1/", nil, true},
		{"about:blank", "http://127.0.0.1/", nil, true},
		{"http://lan.jsh.test/", "http://127.0.0.1/", rules, false},
		{"http://lan.jsh.test/", "http://127.0.0.1/", nil, true}, // no rules: a name is public
		{"https://app.example.com/", "http://lan.jsh.test/", rules, false},
		{"https://app.example.com/", "http://other.jsh.test/", rules, false}, // a name: not a literal, nothing to refuse
	}
	for _, c := range cases {
		if got := blockPrivate(c.dest, c.origin, c.rules); got != c.want {
			t.Errorf("origin %q dest %q: got %v want %v", c.origin, c.dest, got, c.want)
		}
	}
}

func TestReferenceOrigin(t *testing.T) {
	g := &Guard{
		ours:  map[target.ID]bool{"tab": true},
		pages: map[target.ID]target.Info{"tab": {TargetID: "tab"}, "pop": {TargetID: "pop", OpenerID: "tab"}},
	}
	doc := func(frame string) *fetch.EventRequestPaused {
		return &fetch.EventRequestPaused{FrameID: "x", ResourceType: network.ResourceTypeDocument, Request: &network.Request{}}
	}
	ev := func(frame string, rt network.ResourceType) *fetch.EventRequestPaused {
		e := doc(frame)
		e.FrameID, e.ResourceType = cdp.FrameID(frame), rt
		return e
	}
	// The tool's own first navigation: no origin, not judged.
	if o, bare := g.referenceOrigin(ev("tab", network.ResourceTypeDocument), nil, nil); o != "" || !bare {
		t.Errorf("first navigation: %q %v", o, bare)
	}
	// The same frame's subresource with no document known: closed.
	if o, bare := g.referenceOrigin(ev("tab", network.ResourceTypeFetch), nil, nil); o != "" || bare {
		t.Errorf("subresource without origin: %q %v", o, bare)
	}
	g.noteDocument(&fetch.EventRequestPaused{FrameID: "tab", ResourceType: network.ResourceTypeDocument, Request: &network.Request{URL: "https://app.example.com/a"}})
	if o, _ := g.referenceOrigin(ev("tab", network.ResourceTypeFetch), nil, nil); o != "https://app.example.com/a" {
		t.Errorf("main frame: %q", o)
	}
	// A popup takes its opener's.
	if o, bare := g.referenceOrigin(ev("pop", network.ResourceTypeDocument), nil, nil); o != "https://app.example.com/a" || bare {
		t.Errorf("popup: %q %v", o, bare)
	}
	// A subframe: the referer, else the tool's tabs.
	if o, _ := g.referenceOrigin(ev("sub", network.ResourceTypeFetch), map[string]string{"referer": "http://127.0.0.1:1/"}, nil); o != "http://127.0.0.1:1/" {
		t.Errorf("subframe referer: %q", o)
	}
	if o, _ := g.referenceOrigin(ev("sub", network.ResourceTypeFetch), nil, nil); o != "https://app.example.com/a" {
		t.Errorf("subframe fallback: %q", o)
	}
	// A worker with a stage of its own: its URL; without: its headers.
	on, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.stages = []*stage{{on: on, kind: "service_worker", url: "http://127.0.0.1:8770/sw.js"}}
	if o, _ := g.referenceOrigin(ev("", network.ResourceTypeFetch), nil, on); o != "http://127.0.0.1:8770/sw.js" {
		t.Errorf("worker stage: %q", o)
	}
	if o, _ := g.referenceOrigin(ev("", network.ResourceTypeFetch), map[string]string{"origin": "https://p.example"}, nil); o != "https://p.example" {
		t.Errorf("worker header: %q", o)
	}
	// No stage, no header (a worker made during the run, a page with
	// Referrer-Policy: no-referrer): the tool's tabs, as for a subframe.
	if o, _ := g.referenceOrigin(ev("", network.ResourceTypeFetch), nil, nil); o != "https://app.example.com/a" {
		t.Errorf("worker unknown: %q", o)
	}
}

func newTestGuard(rules netsafe.Rules) (*Guard, *[]any) {
	var sent []any
	g := &Guard{
		opts:    Options{HostRules: rules},
		pending: map[fetch.RequestID]*held{}, stats: Stats{ByReason: map[string]int{}},
		ours:  map[target.ID]bool{"tab": true},
		pages: map[target.ID]target.Info{"tab": {TargetID: "tab", URL: "https://app.example.com/"}},
	}
	g.answerFn = func(_ context.Context, p any) error { sent = append(sent, p); return nil }
	return g, &sent
}

func TestHandleFailsPrivate(t *testing.T) {
	g, sent := newTestGuard(nil)
	mk := func(u string) *fetch.EventRequestPaused {
		return &fetch.EventRequestPaused{RequestID: "r1", FrameID: "tab", NetworkID: "n1", ResourceType: network.ResourceTypeFetch,
			Request: &network.Request{URL: u, Method: "GET"}}
	}
	g.handle(mk("http://127.0.0.1:8771/lan/fetch"), nil)
	if len(*sent) != 1 {
		t.Fatalf("answers: %v", *sent)
	}
	f, ok := (*sent)[0].(fetch.FailRequestParams)
	if !ok || f.ErrorReason != network.ErrorReasonBlockedByClient {
		t.Fatalf("not failed as blocked by client: %#v", (*sent)[0])
	}
	recs := g.Take(nil)
	if len(recs) != 1 || recs[0].Reason != ReasonPrivate || recs[0].Action != Fail || recs[0].URL != "http://127.0.0.1:8771/lan/fetch" {
		t.Fatalf("records: %+v", recs)
	}
	if g.Stats().ByReason[ReasonPrivate] != 1 || len(g.pending) != 0 {
		t.Errorf("stats %+v pending %d", g.Stats(), len(g.pending))
	}
	// A request to the page's own origin goes on.
	*sent = nil
	g.handle(mk("https://app.example.com/ok"), nil)
	if _, ok := (*sent)[0].(fetch.ContinueRequestParams); !ok || len(g.Take(nil)) != 0 {
		t.Errorf("ok request: %#v", *sent)
	}
	// -guard-allow does not open the internal network.
	*sent = nil
	g.opts.Rules = Rules{Allow: regexp.MustCompile(`.*`)}
	g.handle(mk("http://10.0.0.5/x"), nil)
	if _, ok := (*sent)[0].(fetch.FailRequestParams); !ok {
		t.Errorf("allow: %#v", *sent)
	}
}

func TestHandlePrivateOriginAndRules(t *testing.T) {
	g, sent := newTestGuard(rulesOf(t, "MAP lan.jsh.test 127.0.0.1"))
	g.pages["tab"] = target.Info{TargetID: "tab", URL: "http://127.0.0.1:8770/"}
	e := &fetch.EventRequestPaused{RequestID: "r", FrameID: "tab", ResourceType: network.ResourceTypeFetch,
		Request: &network.Request{URL: "http://10.0.0.5/", Method: "GET"}}
	g.handle(e, nil)
	if _, ok := (*sent)[0].(fetch.ContinueRequestParams); !ok {
		t.Errorf("private origin: %#v", *sent)
	}
	g.pages["tab"] = target.Info{TargetID: "tab", URL: "https://app.example.com/"}
	*sent = nil
	e.Request = &network.Request{URL: "http://lan.jsh.test:8771/lan/rules", Method: "GET"}
	g.handle(e, nil)
	if _, ok := (*sent)[0].(fetch.ContinueRequestParams); !ok {
		t.Errorf("rules host: %#v", *sent)
	}
}

func TestBlockHost(t *testing.T) {
	g, sent := newTestGuard(rulesOf(t, "MAP lan.jsh.test 127.0.0.1"))
	mk := func(u string) *fetch.EventRequestPaused {
		return &fetch.EventRequestPaused{RequestID: "r", FrameID: "tab", ResourceType: network.ResourceTypeImage,
			Request: &network.Request{URL: u, Method: "GET"}}
	}
	g.handle(mk("https://dev-cdn.example.net/i.png"), nil)
	if _, ok := (*sent)[0].(fetch.ContinueRequestParams); !ok {
		t.Fatalf("before: %#v", *sent)
	}
	g.BlockHost("dev-cdn.example.net")
	g.BlockHost("lan.jsh.test") // the user's host rules: never given up
	*sent = nil
	g.handle(mk("https://Dev-CDN.example.net/other.png"), nil)
	if f, ok := (*sent)[0].(fetch.FailRequestParams); !ok || f.ErrorReason != network.ErrorReasonBlockedByClient {
		t.Fatalf("after: %#v", *sent)
	}
	recs := g.Take(nil)
	if len(recs) != 1 || recs[0].Reason != ReasonPrivateHost || recs[0].Action != Fail {
		t.Errorf("records: %+v", recs)
	}
	*sent = nil
	g.handle(mk("http://lan.jsh.test/i.png"), nil)
	if _, ok := (*sent)[0].(fetch.ContinueRequestParams); !ok {
		t.Errorf("host rules host: %#v", *sent)
	}
}

func TestBlockPrivateUnparsable(t *testing.T) {
	// Go's url.Parse refuses these; Chrome sends them.
	for _, d := range []string{"http://%zz@127.0.0.1:8771/x", "http://127.0.0.1:8771/%zz", "http://[::1]:1/%zz", "http://%zz@localhost/", "http:///x"} {
		if !blockPrivate(d, "https://app.example.com/", nil) {
			t.Errorf("%q passed from a public origin", d)
		}
		if blockPrivate(d, "http://127.0.0.1:8770/", nil) {
			t.Errorf("%q blocked from a private origin", d)
		}
	}
	if blockPrivate("https://cdn.example.net/%zz", "https://app.example.com/", nil) {
		t.Error("a public host with a bad path was blocked")
	}
	if blockPrivate("data:text/plain,%zz", "https://app.example.com/", nil) {
		t.Error("data: is not a network request")
	}
}

func TestBlockedHostUnparsable(t *testing.T) {
	g, sent := newTestGuard(nil)
	g.BlockHost("dev.example.net")
	e := &fetch.EventRequestPaused{RequestID: "r", FrameID: "tab", ResourceType: network.ResourceTypeImage,
		Request: &network.Request{URL: "https://dev.example.net/%zz", Method: "GET"}}
	g.handle(e, nil)
	if _, ok := (*sent)[0].(fetch.FailRequestParams); !ok {
		t.Errorf("a blocked host with an unparsable path passed: %#v", *sent)
	}
}

func TestPopupWithoutOpener(t *testing.T) {
	g, sent := newTestGuard(nil)
	// A page the tool does not own, no opener (target=_blank is noopener by
	// default), at its first navigation: judged, as public.
	g.pages["wild"] = target.Info{TargetID: "wild", URL: "about:blank"}
	e := &fetch.EventRequestPaused{RequestID: "r", FrameID: "wild", ResourceType: network.ResourceTypeDocument,
		Request: &network.Request{URL: "http://127.0.0.1:8771/", Method: "GET"}}
	g.handle(e, nil)
	if _, ok := (*sent)[0].(fetch.FailRequestParams); !ok {
		t.Fatalf("a noopener popup reached the internal network: %#v", *sent)
	}
	// The tool's own tab, first navigation, to the testbed: passes.
	*sent = nil
	g.pages["tab"] = target.Info{TargetID: "tab", URL: "about:blank"}
	e = &fetch.EventRequestPaused{RequestID: "r2", FrameID: "tab", ResourceType: network.ResourceTypeDocument,
		Request: &network.Request{URL: "http://127.0.0.1:8770/", Method: "GET"}}
	g.handle(e, nil)
	if _, ok := (*sent)[0].(fetch.ContinueRequestParams); !ok {
		t.Errorf("the tool's own first navigation: %#v", *sent)
	}
	// A popup of the tool's tab, first navigation, no origin yet: the tool's.
	*sent = nil
	g.pages["pop"] = target.Info{TargetID: "pop", OpenerID: "tab", URL: "about:blank"}
	e = &fetch.EventRequestPaused{RequestID: "r3", FrameID: "pop", ResourceType: network.ResourceTypeDocument,
		Request: &network.Request{URL: "http://127.0.0.1:8770/p", Method: "GET"}}
	g.handle(e, nil)
	if _, ok := (*sent)[0].(fetch.ContinueRequestParams); !ok {
		t.Errorf("a popup of the tool's tab: %#v", *sent)
	}
}

func TestPopupWithoutOpenerOfInternalTarget(t *testing.T) {
	g, sent := newTestGuard(nil)
	g.pages["tab"] = target.Info{TargetID: "tab", URL: "http://127.0.0.1:8770/"}
	g.pages["wild"] = target.Info{TargetID: "wild", URL: "about:blank"}
	e := &fetch.EventRequestPaused{RequestID: "r", FrameID: "wild", ResourceType: network.ResourceTypeDocument,
		Request: &network.Request{URL: "http://127.0.0.1:8770/popup", Method: "GET"}}
	g.handle(e, nil)
	if _, ok := (*sent)[0].(fetch.ContinueRequestParams); !ok {
		t.Errorf("a noopener popup of the testbed was held: %#v", *sent)
	}
}

func TestWorkerOfInternalTargetNoReferrer(t *testing.T) {
	g, sent := newTestGuard(nil)
	g.pages["tab"] = target.Info{TargetID: "tab", URL: "http://127.0.0.1:8770/"}
	e := &fetch.EventRequestPaused{RequestID: "r", FrameID: "", ResourceType: network.ResourceTypeFetch,
		Request: &network.Request{URL: "http://127.0.0.1:8770/api", Method: "GET"}}
	g.handle(e, nil)
	if _, ok := (*sent)[0].(fetch.ContinueRequestParams); !ok {
		t.Errorf("a worker of an internal target was held: %#v", *sent)
	}
}
