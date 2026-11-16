package capture

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

// Penalties of a private-address hit (layer 3).
const (
	// HitCloseTab: JS can read the response: the tab is closed and the
	// host not visited again.
	HitCloseTab = "close-tab"
	// HitBlockHost: the host is failed by the guard for the rest of the
	// run; the crawl goes on.
	HitBlockHost = "block-host"
)

// PrivateHit is a response a page of a public origin got from a private
// address (responseReceived.remoteIPAddress): a fuse behind the guard's
// layer 1 and Chrome's own, not a barrier (a small response may already
// have been read by the page).
type PrivateHit struct {
	Host         string `json:"host"`
	IP           string `json:"ip"`
	URL          string `json:"url"`
	Origin       string `json:"origin"`
	SameOrigin   bool   `json:"same_origin"`
	ResourceType string `json:"resource_type,omitempty"`
	Session      string `json:"session,omitempty"` // target type: page, iframe, worker…
	Penalty      string `json:"penalty"`
}

// hitInput is what the decision needs of one response.
type hitInput struct {
	Resp   *network.Response
	Type   network.ResourceType
	Kind   string // target type of the session that got it
	Origin string // URL of the page or worker that sent the request
	Rules  netsafe.Rules
	// Off: no private address is a hit (the target is internal, or a proxy
	// stands between: remoteIPAddress is then the proxy's, Burp's at 127.0.0.1).
	Off bool
}

func originOf(raw string) (scheme, host, port string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", "", "", false
	}
	port = u.Port()
	if port == "" {
		switch u.Scheme {
		case "http", "ws":
			port = "80"
		case "https", "wss":
			port = "443"
		}
	}
	return u.Scheme, strings.ToLower(u.Hostname()), port, true
}

// classifyHit decides whether a response is a private-address hit and what
// it costs; nil when it is none.
func classifyHit(in hitInput) *PrivateHit {
	r := in.Resp
	if in.Off || r == nil || r.RemoteIPAddress == "" || r.FromDiskCache || r.FromPrefetchCache || r.FromServiceWorker {
		return nil
	}
	ip, err := netip.ParseAddr(strings.Trim(r.RemoteIPAddress, "[]"))
	if err != nil || !netsafe.PrivateAddr(ip) {
		return nil
	}
	if !netsafe.OriginPublic(in.Origin, in.Rules) {
		return nil
	}
	_, host, ok := netsafe.SplitURL(r.URL)
	if !ok || host == "" {
		// A URL Go cannot read that Chrome fetched from a private address:
		// nothing to tell the host by, nothing to exempt. Closed.
		return &PrivateHit{IP: ip.String(), URL: r.URL, Origin: in.Origin, ResourceType: string(in.Type), Session: in.Kind, Penalty: HitCloseTab}
	}
	if in.Rules.Matches(host) {
		return nil // the user's own mapping
	}
	hit := &PrivateHit{Host: host, IP: ip.String(), URL: r.URL, Origin: in.Origin, ResourceType: string(in.Type), Session: in.Kind}
	os, oh, op, ok := originOf(in.Origin)
	ds, dh, dp, _ := originOf(r.URL)
	hit.SameOrigin = ok && os == ds && oh == dh && op == dp
	readable := hit.SameOrigin || in.Type == network.ResourceTypeScript // a script runs in the page or worker, JSONP too
	if !readable {
		acao := ""
		for k, v := range r.Headers {
			if strings.EqualFold(k, "Access-Control-Allow-Origin") {
				acao = strings.TrimSpace(fmt.Sprint(v))
			}
		}
		if acao == "*" || (ok && acao != "" && strings.EqualFold(acao, os+"://"+originHostPort(in.Origin))) {
			readable = true
		}
	}
	hit.Penalty = HitBlockHost
	if _, err := url.Parse(r.URL); err != nil {
		readable = true // what Go cannot read, nothing here can tell is safe: closed
	}
	if readable {
		hit.Penalty = HitCloseTab
	}
	return hit
}

func originHostPort(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// checkPrivate is layer 3 for one response of session s.
func (s *session) checkPrivate(ev *network.EventResponseReceived) {
	s.checkPrivateResp(ev.FrameID, ev.Type, ev.Response)
}

// checkPrivateResp judges a response (or the response of a redirect hop,
// which has no responseReceived of its own) of a frame of session s.
//
// The origin is the document of the frame that sent the request: a
// document's own response is its own origin (what rebinding is made of);
// a frame whose document this session saw has it; else a page session
// takes the tab's main document and an iframe (out-of-process) or worker
// session its own URL. Limit: a same-process subframe whose document the
// session did not see (srcdoc, about:blank, a service worker's) is judged
// by the main document.
func (s *session) checkPrivateResp(frame cdp.FrameID, typ network.ResourceType, resp *network.Response) {
	c := s.c
	if c.opts.NoPrivateCheck || resp == nil {
		return
	}
	c.mu.Lock()
	if typ == network.ResourceTypeDocument && s.kind != "worker" && s.kind != "service_worker" && s.kind != "shared_worker" {
		if s.docs == nil {
			s.docs = map[cdp.FrameID]string{}
		}
		s.docs[frame] = resp.URL
	}
	origin, seen := s.docs[frame]
	if !seen {
		switch s.kind {
		case "page":
			origin = c.mainDoc.URL
		default: // iframe (own process), workers: the target's own URL
			origin = s.targetURL
			if o, ok := s.docs[cdp.FrameID(s.id)]; ok {
				origin = o
			}
		}
	}
	c.mu.Unlock()
	hit := classifyHit(hitInput{Resp: resp, Type: typ, Kind: s.kind, Origin: origin, Rules: c.opts.PrivateRules})
	if hit == nil {
		// A response Go cannot read the URL of, from a private address, is
		// told by the address alone: see classifyHit.
		return
	}
	c.notePrivateHit(*hit)
}

const maxPrivateHits = 20

func (c *Capture) notePrivateHit(h PrivateHit) {
	c.mu.Lock()
	c.stats.PrivateHitCount++
	if len(c.stats.PrivateAddressHit) < maxPrivateHits {
		c.stats.PrivateAddressHit = append(c.stats.PrivateAddressHit, h)
	}
	c.mu.Unlock()
	if c.opts.OnPrivateHit != nil {
		c.opts.OnPrivateHit(h)
	}
}
