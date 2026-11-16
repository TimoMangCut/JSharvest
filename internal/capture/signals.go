package capture

import (
	"strings"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// watchSignals reports, for the guard, the responses that carry
// Clear-Site-Data and the WebSockets that open on this session; for the
// session keeper, the redirects requests followed. The raw
// headers are the only place Clear-Site-Data shows: Chrome strips it from
// responseReceived.
func (s *session) watchSignals() {
	o := s.c.opts
	if o.OnClearSiteData != nil {
		go each(chromedp.Events(s.ctx, network.ResponseReceivedExtraInfo), func(ev *network.EventResponseReceivedExtraInfo) {
			for k := range ev.Headers {
				if strings.EqualFold(k, "Clear-Site-Data") {
					o.OnClearSiteData(string(ev.RequestID))
					return
				}
			}
		})
	}
	if o.OnRedirect != nil {
		go each(chromedp.Events(s.ctx, network.RequestWillBeSent), func(ev *network.EventRequestWillBeSent) {
			if ev.RedirectResponse != nil && ev.Request != nil {
				o.OnRedirect(ev.RedirectResponse.URL, ev.Request.URL)
			}
		})
	}
	if o.OnAPIStatus != nil {
		go each(chromedp.Events(s.ctx, network.ResponseReceived), func(ev *network.EventResponseReceived) {
			if u, status, guard, ok := apiStatusOf(ev); ok {
				o.OnAPIStatus(u, status, guard)
			}
		})
	}
	if o.OnWebSocket != nil {
		go each(chromedp.Events(s.ctx, network.WebSocketCreated), func(ev *network.EventWebSocketCreated) {
			o.OnWebSocket(ev.URL)
		})
	}
}

// apiStatusOf reads an XHR/fetch response a server gave: not a document, a
// script or an image, and not one a cache or a service worker answered
// (that status is no word of the server now).
func apiStatusOf(ev *network.EventResponseReceived) (url string, status int, fromGuard, ok bool) {
	if ev == nil || ev.Response == nil || (ev.Type != network.ResourceTypeXHR && ev.Type != network.ResourceTypeFetch) {
		return "", 0, false, false
	}
	r := ev.Response
	if r.FromDiskCache || r.FromPrefetchCache || r.FromServiceWorker {
		return "", 0, false, false
	}
	for k := range r.Headers {
		if strings.EqualFold(k, traffic.GuardHeader) {
			fromGuard = true
			break
		}
	}
	return r.URL, int(r.Status), fromGuard, true
}
