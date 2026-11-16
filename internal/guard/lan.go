package guard

import (
	"context"
	"strings"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/target"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

// ReasonPrivate is the reason of a request that a public page sent to a
// private address (layer 1 of the three that keep a public page from
// touching the internal network; the others are netsafe's, at the HTTP
// clients).
const ReasonPrivate = "private-address"

// ReasonPrivateHost is the reason of a request to a host that answered
// from a private address earlier in the run (BlockHost).
const ReasonPrivateHost = "private-address-host"

// Fail answers the request with a network error (BlockedByClient). Only
// layer 1 does: it is not a write that a service worker's background sync
// could send again later, it is a request that must never go.
const Fail Action = "fail"

func internalMapped(host string, rules netsafe.Rules) bool {
	return netsafe.InternalMapped(host, rules)
}

func originPublic(origin string, rules netsafe.Rules) bool {
	return netsafe.OriginPublic(origin, rules)
}

// blockPrivate is the decision of layer 1: a request to a private
// literal, localhost or *.localhost, from an origin that is public. A
// destination the rules map to an internal host is allowed.
func blockPrivate(dest, origin string, rules netsafe.Rules) bool {
	scheme, h, ok := netsafe.SplitURL(dest)
	if !ok {
		return false // no authority: data:, about:, blob:: not a request to a host
	}
	switch scheme {
	case "http", "https", "ws", "wss", "ftp":
	default:
		return false
	}
	if h == "" {
		// An authority with no host that Go cannot read and Chrome might:
		// closed, as a host that cannot be told is.
		return originPublic(origin, rules)
	}
	if internalMapped(h, rules) || netsafe.RefuseHost(h, true) == nil {
		return false
	}
	return originPublic(origin, rules)
}

// pageURL is the document URL of a page target: the last document the
// guard let through for it (a request is paused before its response, so
// before any request of the page it commits), else the URL the browser
// reports for the target. "" when it has none yet. Call with g.mu held.
func (g *Guard) pageURL(id target.ID) string {
	if u := g.tops[string(id)]; u != "" {
		return u
	}
	if info, ok := g.pages[id]; ok && web(info.URL) {
		return info.URL
	}
	return ""
}

// topOrigin is the URL of the top document of the tab a main frame
// belongs to, a popup's through its opener. "" when none is known. Call
// with g.mu held.
func (g *Guard) topOrigin(id target.ID) string {
	for range 16 {
		if u := g.pageURL(id); u != "" {
			return u
		}
		info, ok := g.pages[id]
		if !ok || info.OpenerID == "" {
			return ""
		}
		id = info.OpenerID
	}
	return ""
}

// referenceOrigin finds the origin a paused request is judged from; bare
// is true for the navigation of a main frame that has none (the tool's
// own first navigation, a popup nothing opened it from): it is not a
// page's request and passes unjudged.
//
//   - a main frame: its tab's top document, a popup's its opener's;
//   - a worker's request (no frame): the worker's own URL when the worker
//     has a stage of its own, else its Origin or Referer header;
//   - a frame the guard does not know (a subframe): the Origin or Referer
//     header, else the tool's tabs: public when one of them is, private
//     only when all are.
//
// Nothing known gives "", which is public.
func (g *Guard) referenceOrigin(ev *fetch.EventRequestPaused, headers map[string]string, on context.Context) (origin string, bare bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	frame := string(ev.FrameID)
	if frame == "" {
		if on != nil {
			for _, st := range g.stages {
				if st.on == on && web(st.url) {
					return st.url, false
				}
			}
		}
		// A worker made during the run is paused at browser level and its
		// URL is not at hand (the guard follows page targets only): the
		// headers, else the tool's tabs, as for a subframe. A worker of an
		// internal target with Referrer-Policy: no-referrer is so judged
		// by its tab, private.
		if o := headerOrigin(headers); o != "" {
			return o, false
		}
		return g.oursOrigin(), false
	}
	id := target.ID(frame)
	if _, main := g.pages[id]; main {
		o := g.topOrigin(id)
		// Only the tool's own tab (or a popup of it) with no document yet
		// is the tool navigating; a page nobody of ours opened (a noopener
		// popup) is a page, judged as public.
		if o == "" && !g.owned(id) {
			// Known to be no tab of ours: judged by what the tool's tabs
			// stand for, public unless every one of them is private (a
			// noopener popup of the testbed stays in the testbed).
			return g.oursOrigin(), false
		}
		return o, o == "" && ev.ResourceType == network.ResourceTypeDocument
	}
	if o := headerOrigin(headers); o != "" {
		return o, false
	}
	return g.oursOrigin(), false
}

// owned reports a page of the tool: one of g.ours, or a popup whose
// openers lead to one. Call with g.mu held.
func (g *Guard) owned(id target.ID) bool {
	for range 16 {
		if g.ours[id] {
			return true
		}
		info, ok := g.pages[id]
		if !ok || info.OpenerID == "" {
			return false
		}
		id = info.OpenerID
	}
	return false
}

// oursOrigin is the origin the tool's tabs stand for: a public one when
// any is, else a private one; "" when none has a document. Call with g.mu
// held.
func (g *Guard) oursOrigin() string {
	found := ""
	for tid := range g.ours {
		if o := g.topOrigin(tid); o != "" {
			if originPublic(o, g.opts.HostRules) {
				return o
			}
			found = o
		}
	}
	return found
}

// headerOrigin is what the page cannot forge: the Origin header (not
// "null") or the Referer of the request.
func headerOrigin(headers map[string]string) string {
	if o := headers["origin"]; o != "" && o != "null" && web(o) {
		return o
	}
	if r := headers["referer"]; web(r) {
		return r
	}
	return ""
}

// noteDocument remembers the document a main frame is about to load, for
// the requests it will make. Call it for a document request that passes.
//
// Known limits of layers 1 and 3: the mark is taken as the document is
// requested, before it commits (a navigation that fails or is cancelled
// leaves it); and a WebSocket opened by a worker (or by a page, under
// -guard-allow-websocket) does not go through Fetch, so neither layer sees
// it. Layer 2 (Local Network Access) still applies to it.
func (g *Guard) noteDocument(ev *fetch.EventRequestPaused) {
	if ev.ResourceType != network.ResourceTypeDocument || !web(ev.Request.URL) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, main := g.pages[target.ID(ev.FrameID)]; main {
		if g.tops == nil {
			g.tops = map[string]string{}
		}
		g.tops[string(ev.FrameID)] = ev.Request.URL
	}
}

// BlockHost makes the guard fail every request to host from now on, for
// the rest of the run (layer 3: a host whose answers came from a private
// address). A host the -host-resolver-rules map is never blocked.
func (g *Guard) BlockHost(host string) {
	host = strings.ToLower(strings.Trim(host, "[]."))
	if host == "" || g.opts.HostRules.Matches(host) {
		return
	}
	g.mu.Lock()
	if g.hostBlock == nil {
		g.hostBlock = map[string]bool{}
	}
	g.hostBlock[host] = true
	g.mu.Unlock()
}

// HostBlocked reports a host BlockHost was given.
func (g *Guard) HostBlocked(host string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hostBlock[strings.ToLower(strings.Trim(host, "[]."))]
}

// privateRefused is layers 1 and 3 for one paused request: the reason it
// is failed, "" if it is not.
func (g *Guard) privateRefused(ev *fetch.EventRequestPaused, headers map[string]string, on context.Context) string {
	if _, h, ok := netsafe.SplitURL(ev.Request.URL); ok && h != "" && g.HostBlocked(h) {
		return ReasonPrivateHost
	}
	origin, bare := g.referenceOrigin(ev, headers, on)
	if !bare && blockPrivate(ev.Request.URL, origin, g.opts.HostRules) {
		return ReasonPrivate
	}
	return ""
}
