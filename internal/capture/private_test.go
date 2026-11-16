package capture

import (
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

func TestClassifyHit(t *testing.T) {
	rules, _ := netsafe.ParseHostRules("MAP lan.jsh.test 127.0.0.1")
	const page = "https://app.example.com/index.html"
	resp := func(u, ip string, h map[string]any) *network.Response {
		return &network.Response{URL: u, RemoteIPAddress: ip, Headers: network.Headers(h)}
	}
	cases := []struct {
		name string
		in   hitInput
		want string // "" none, else penalty
	}{
		{"same origin (rebinding)", hitInput{Resp: resp("https://app.example.com/api", "10.0.0.5", nil), Type: network.ResourceTypeXHR, Kind: "page", Origin: page}, HitCloseTab},
		{"ACAO star", hitInput{Resp: resp("https://dev.example.net/x", "10.0.0.5", map[string]any{"Access-Control-Allow-Origin": "*"}), Type: network.ResourceTypeFetch, Kind: "page", Origin: page}, HitCloseTab},
		{"ACAO matches origin", hitInput{Resp: resp("https://dev.example.net/x", "192.168.1.9", map[string]any{"access-control-allow-origin": "https://app.example.com"}), Type: network.ResourceTypeFetch, Kind: "page", Origin: page}, HitCloseTab},
		{"ACAO of another origin", hitInput{Resp: resp("https://dev.example.net/x", "10.0.0.5", map[string]any{"Access-Control-Allow-Origin": "https://other.example"}), Type: network.ResourceTypeFetch, Kind: "page", Origin: page}, HitBlockHost},
		{"script", hitInput{Resp: resp("https://dev.example.net/a.js", "10.0.0.5", nil), Type: network.ResourceTypeScript, Kind: "page", Origin: page}, HitCloseTab},
		{"worker script", hitInput{Resp: resp("https://dev.example.net/a.js", "10.0.0.5", nil), Type: network.ResourceTypeScript, Kind: "worker", Origin: "https://app.example.com/w.js"}, HitCloseTab},
		{"img of another origin", hitInput{Resp: resp("https://dev-cdn.example.net/i.png", "10.1.2.3", nil), Type: network.ResourceTypeImage, Kind: "page", Origin: page}, HitBlockHost},
		{"font", hitInput{Resp: resp("https://dev-cdn.example.net/f.woff2", "172.16.0.4", nil), Type: network.ResourceTypeFont, Kind: "page", Origin: page}, HitBlockHost},
		{"worker fetch, no CORS", hitInput{Resp: resp("https://dev.example.net/x", "10.0.0.5", nil), Type: network.ResourceTypeFetch, Kind: "service_worker", Origin: "https://app.example.com/sw.js"}, HitBlockHost},
		{"ipv6 loopback in brackets", hitInput{Resp: resp("https://dev.example.net/i.png", "[::1]", nil), Type: network.ResourceTypeImage, Kind: "page", Origin: page}, HitBlockHost},
		{"ipv4-mapped", hitInput{Resp: resp("https://dev.example.net/i.png", "::ffff:10.0.0.1", nil), Type: network.ResourceTypeImage, Kind: "page", Origin: page}, HitBlockHost},
		{"public address", hitInput{Resp: resp("https://app.example.com/api", "93.184.216.34", nil), Type: network.ResourceTypeXHR, Kind: "page", Origin: page}, ""},
		{"empty address", hitInput{Resp: resp("https://app.example.com/api", "", nil), Type: network.ResourceTypeXHR, Kind: "page", Origin: page}, ""},
		{"proxy (Off)", hitInput{Resp: resp("https://app.example.com/api", "127.0.0.1", nil), Type: network.ResourceTypeXHR, Kind: "page", Origin: page, Off: true}, ""},
		{"private origin", hitInput{Resp: resp("http://127.0.0.1:8771/x", "127.0.0.1", nil), Type: network.ResourceTypeXHR, Kind: "page", Origin: "http://127.0.0.1:8770/"}, ""},
		{"host rules host", hitInput{Resp: resp("http://lan.jsh.test:8771/x", "127.0.0.1", nil), Type: network.ResourceTypeXHR, Kind: "page", Origin: page, Rules: rules}, ""},
		{"origin by host rules is internal", hitInput{Resp: resp("http://x.example.net/i.png", "10.0.0.5", nil), Type: network.ResourceTypeImage, Kind: "page", Origin: "http://lan.jsh.test/", Rules: rules}, ""},
	}
	for _, c := range cases {
		h := classifyHit(c.in)
		got := ""
		if h != nil {
			got = h.Penalty
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q (%+v)", c.name, got, c.want, h)
		}
	}
	// The caches are not an answer from the address.
	for _, f := range []func(*network.Response){
		func(r *network.Response) { r.FromDiskCache = true },
		func(r *network.Response) { r.FromPrefetchCache = true },
		func(r *network.Response) { r.FromServiceWorker = true },
	} {
		r := resp("https://app.example.com/api", "10.0.0.5", nil)
		f(r)
		if classifyHit(hitInput{Resp: r, Type: network.ResourceTypeXHR, Kind: "page", Origin: page}) != nil {
			t.Error("a cached or service-worker answer is a hit")
		}
	}
	// What the hit says.
	h := classifyHit(cases[0].in)
	if h.Host != "app.example.com" || h.IP != "10.0.0.5" || !h.SameOrigin || h.Origin != page {
		t.Errorf("hit: %+v", h)
	}
	if h := classifyHit(cases[6].in); h.SameOrigin {
		t.Error("cross-origin said same")
	}
}

func TestNotePrivateHit(t *testing.T) {
	var heard []PrivateHit
	c := &Capture{opts: Options{OnPrivateHit: func(h PrivateHit) { heard = append(heard, h) }}}
	for i := 0; i < 25; i++ {
		c.notePrivateHit(PrivateHit{Host: "h", Penalty: HitBlockHost})
	}
	s := c.Stats()
	if s.PrivateHitCount != 25 || len(s.PrivateAddressHit) != maxPrivateHits || len(heard) != 25 {
		t.Errorf("count %d kept %d heard %d", s.PrivateHitCount, len(s.PrivateAddressHit), len(heard))
	}
}

func TestClassifyHitUnparsableURL(t *testing.T) {
	r := &network.Response{URL: "http://%zz@dev.example.net/x", RemoteIPAddress: "10.0.0.5"}
	h := classifyHit(hitInput{Resp: r, Type: network.ResourceTypeImage, Kind: "page", Origin: "https://app.example.com/"})
	if h == nil || h.Penalty != HitCloseTab {
		t.Fatalf("an unreadable URL from a private address: %+v", h)
	}
	r = &network.Response{URL: "http://%zz@dev.example.net/x", RemoteIPAddress: "93.184.216.34"}
	if classifyHit(hitInput{Resp: r, Type: network.ResourceTypeImage, Kind: "page", Origin: "https://app.example.com/"}) != nil {
		t.Error("a public address is no hit")
	}
	// A bad path: the host is read by hand and kept in the hit; still closed.
	r = &network.Response{URL: "https://dev.example.net/%zz", RemoteIPAddress: "10.0.0.5"}
	if h := classifyHit(hitInput{Resp: r, Type: network.ResourceTypeImage, Kind: "page", Origin: "https://app.example.com/"}); h == nil || h.Penalty != HitCloseTab || h.Host != "dev.example.net" {
		t.Errorf("bad path: %+v", h)
	}
}

func TestPrivateOriginOfSessions(t *testing.T) {
	resp := func(u string) *network.Response { return &network.Response{URL: u, RemoteIPAddress: "10.0.0.5"} }
	run := func(s *session, frame cdp.FrameID, typ network.ResourceType, r *network.Response) *PrivateHit {
		var got *PrivateHit
		s.c.opts.OnPrivateHit = func(h PrivateHit) { got = &h }
		s.checkPrivateResp(frame, typ, r)
		return got
	}
	// A cross-origin iframe session: its own origin, not the tab's. Its
	// script from its own origin is same-origin, hence close-tab; with the
	// tab's origin it would be a cross-origin image (block-host).
	c := &Capture{}
	c.mainDoc.URL = "https://app.example.com/"
	ifr := &session{c: c, kind: "iframe", id: "if1", targetURL: "https://widgets.example.net/f.html"}
	if h := run(ifr, "if1", network.ResourceTypeImage, resp("https://widgets.example.net/i.png")); h == nil || h.Penalty != HitCloseTab || !h.SameOrigin {
		t.Errorf("iframe: %+v", h)
	}
	// The same on a page session is cross-origin.
	pg := &session{c: c, kind: "page", id: "tab"}
	if h := run(pg, "tab", network.ResourceTypeImage, resp("https://widgets.example.net/i.png")); h == nil || h.Penalty != HitBlockHost || h.SameOrigin {
		t.Errorf("page: %+v", h)
	}
	// A same-process subframe whose document was seen: its own origin.
	run(pg, "sub", network.ResourceTypeDocument, &network.Response{URL: "https://widgets.example.net/f.html", RemoteIPAddress: "93.184.216.34"})
	if h := run(pg, "sub", network.ResourceTypeImage, resp("https://widgets.example.net/i.png")); h == nil || !h.SameOrigin {
		t.Errorf("subframe: %+v", h)
	}
}
