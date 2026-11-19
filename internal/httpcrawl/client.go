package httpcrawl

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/tlsutil"
	"github.com/TimoMangCut/JSharvest/internal/uahints"
)

// DefaultUserAgent is the User-Agent of a stable desktop Chrome: what a
// person's browser sends, not HeadlessChrome. -ua replaces it.
const DefaultUserAgent = marker.FallbackUA

// answer is one response, its body read (and decoded by the transport).
type answer struct {
	URL      string // after redirects
	Status   int
	Header   http.Header
	Body     []byte
	RemoteIP string
	Proto    string
	Took     time.Duration
	Err      error
	// IncompleteChain: the server sent an incomplete certificate chain the
	// AIA completed (tlsutil).
	IncompleteChain bool
}

// client sends the crawl's requests: a browser's headers, a cookie jar of
// its own for the run, a shared rate, and the host map of -host-resolver-rules.
type client struct {
	http      *http.Client
	ua        string
	limit     *limiter
	pageLimit *limiter
	maxBody   int
	jar       http.CookieJar
	aia       *tlsutil.AIA
}

// shouldAbortDocumentBody reports whether a k == document response header
// unambiguously declares a syndication XML stream or binary media file (never
// an HTML page, JSON/YAML API response, or text/plain payload) so the body
// stream can be closed immediately without waiting out hung feed generators.
func shouldAbortDocumentBody(contentType string) bool {
	ct := strings.TrimSpace(strings.ToLower(strings.Split(contentType, ";")[0]))
	if ct == "" {
		return false
	}
	switch ct {
	case "application/rss+xml", "application/atom+xml", "application/rdf+xml",
		"application/pdf", "application/zip", "application/gzip", "application/x-gzip",
		"application/x-tar", "application/x-7z-compressed", "application/x-rar-compressed",
		"application/octet-stream", "application/msword", "application/wasm":
		return true
	}
	for _, pfx := range []string{"image/", "audio/", "video/", "font/", "application/vnd."} {
		if strings.HasPrefix(ct, pfx) {
			return true
		}
	}
	return false
}

// newClient makes the crawl's client. allow decides each URL a redirect
// leads to, as the crawl decides the URLs it asks for.
func newClient(o Options, jar http.CookieJar, allow func(u, first *url.URL, doc bool) bool) (*client, error) {
	rules, err := netsafe.ParseHostRules(o.HostRules)
	if err != nil {
		return nil, err
	}
	dialTimeout := min(o.Timeout, 10*time.Second)
	tlsTimeout := min(o.Timeout, 10*time.Second)
	hdrTimeout := min(o.Timeout, 15*time.Second)
	// The one dialer (internal/netsafe): the name resolved once, every
	// address checked, the address checked dialled. A host the user's
	// -host-resolver-rules map is trusted; an internal target
	// (!TargetPublic) may reach private addresses.
	dialer := &netsafe.Dialer{HostRules: rules, AllowPrivate: o.AllowPrivate, Proxy: o.Proxy, Resolver: o.Resolver, Timeout: dialTimeout}
	dialCtx := dialer.DialContext
	if o.Proxy == nil && o.Resolver == nil {
		dialCtx = newHostPortBreaker(dialCtx)
	}
	tr := &http.Transport{
		Proxy:                 netsafe.ProxyFunc(o.Proxy, rules),
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   16, // up to 4 pages' scripts at once, o.Workers each (HTTP/1.1)
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: hdrTimeout,
		DialContext:           dialCtx,
	}
	if o.Proxy == nil {
		tr.Proxy = nil
	}
	c := &client{ua: o.UserAgent, limit: newLimiter(o.Rate), pageLimit: newLimiter(o.PageRate), maxBody: o.MaxBody, jar: jar}
	switch {
	case o.Insecure:
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case o.Proxy == nil:
		// A server that sends its leaf alone is verified as a browser
		// does: the intermediates its AIA names. Through a proxy
		// the transport's own TLS (Go's verification) is used.
		c.aia = o.AIA
		if c.aia == nil {
			c.aia = tlsutil.New()
		}
		tr.DialTLSContext = c.aia.DialTLS(tr.DialContext, true)
	}
	// Behind a proxy the dialler sees the proxy alone: the host is judged
	// here, on the name the URL carries, before the transport (P2.2).
	guard := netsafe.Guard{Next: tr, AllowPrivate: o.AllowPrivate, Rules: rules}
	c.http = &http.Client{
		Transport: guard,
		Jar:       jar,
		Timeout:   o.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			// A redirect goes where the crawl itself would: in scope, past the
			// policy (no private address of a public target), no credential in
			// the URL, nothing the guard calls destructive.
			if guard.Check(req.URL.Hostname()) != nil {
				return http.ErrUseLastResponse
			}
			var first *url.URL
			if len(via) > 0 {
				first = via[0].URL
			}
			doc := len(via) > 0 && via[0].Header.Get("Sec-Fetch-Dest") == "document"
			if allow != nil && !allow(req.URL, first, doc) {
				return http.ErrUseLastResponse
			}
			if first != nil && !frontier.SameHeaderScope(first.String(), req.URL.String(), nil) {
				// Never forward custom client_headers across origin/RDN boundaries.
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return c, nil
}

// kind of request, for its headers.
type kind int

const (
	document kind = iota
	scriptReq
	dataReq // a manifest, robots.txt, a source map
)

func (c *client) get(ctx context.Context, raw, referer string, k kind) answer {
	return c.getWithHeaders(ctx, raw, referer, k, nil)
}

func (c *client) getWithHeaders(ctx context.Context, raw, referer string, k kind, extra []jsapi.Header) answer {
	if k == document && c.pageLimit != nil {
		if err := c.pageLimit.wait(ctx); err != nil {
			return answer{URL: raw, Err: err}
		}
	}
	if err := c.limit.wait(ctx); err != nil {
		return answer{URL: raw, Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return answer{URL: raw, Err: err}
	}
	h := req.Header
	h.Set("User-Agent", c.ua)
	h.Set("Accept-Language", "en-US,en;q=0.9")
	if req.URL.Scheme == "https" {
		// What a Chrome with this User-Agent sends a secure origin with
		// every request (round 25K): a Chrome UA without them is a
		// browser that is not one.
		for hk, hv := range uahints.Hints(c.ua) {
			h.Set(hk, hv)
		}
	}
	switch k {
	case document:
		h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		h.Set("Upgrade-Insecure-Requests", "1")
		h.Set("Sec-Fetch-Dest", "document")
		h.Set("Sec-Fetch-Mode", "navigate")
		h.Set("Sec-Fetch-User", "?1")
		if referer == "" {
			h.Set("Sec-Fetch-Site", "none")
		} else {
			h.Set("Sec-Fetch-Site", site(raw, referer))
		}
	case scriptReq:
		h.Set("Accept", "*/*")
		h.Set("Sec-Fetch-Dest", "script")
		h.Set("Sec-Fetch-Mode", "no-cors")
		h.Set("Sec-Fetch-Site", site(raw, referer))
	default:
		h.Set("Accept", "*/*")
		h.Set("Sec-Fetch-Dest", "empty")
		h.Set("Sec-Fetch-Mode", "cors")
		h.Set("Sec-Fetch-Site", site(raw, referer))
	}
	if referer != "" {
		h.Set("Referer", referer)
	}
	for _, eh := range extra {
		h.Del(eh.Name)
		h[eh.Name] = []string{eh.Value}
	}
	var remote string
	trace := &remoteTrace{}
	req = req.WithContext(withTrace(req.Context(), trace))
	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return answer{URL: raw, Err: err, Took: time.Since(start)}
	}
	defer resp.Body.Close()
	var body []byte
	if k == document && shouldAbortDocumentBody(resp.Header.Get("Content-Type")) {
		_ = resp.Body.Close()
	} else {
		body, err = io.ReadAll(io.LimitReader(resp.Body, int64(c.maxBody)+1))
	}
	remote = trace.addr()
	a := answer{URL: resp.Request.URL.String(), Status: resp.StatusCode, Header: resp.Header, Body: body,
		RemoteIP: remote, Proto: resp.Proto, Took: time.Since(start)}
	if c.aia != nil && resp.TLS != nil {
		hp := resp.Request.URL.Host
		if resp.Request.URL.Port() == "" {
			hp = net.JoinHostPort(resp.Request.URL.Hostname(), "443")
		}
		a.IncompleteChain = c.aia.Incomplete(hp)
	}
	if err != nil {
		a.Err = err
	} else if len(body) > c.maxBody {
		a.Err = fmt.Errorf("over -max-body (%d bytes)", c.maxBody)
		a.Body = nil
	}
	return a
}

// site is the Sec-Fetch-Site of a request to raw from a page at referer.
func site(raw, referer string) string {
	a, err1 := url.Parse(raw)
	b, err2 := url.Parse(referer)
	switch {
	case err1 != nil || err2 != nil || referer == "":
		return "none"
	case a.Scheme == b.Scheme && a.Host == b.Host:
		return "same-origin"
	case registrable(a.Hostname()) == registrable(b.Hostname()):
		return "same-site"
	}
	return "cross-site"
}

// registrable is the last two labels of a host, near enough for a header.
func registrable(h string) string {
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// --- rate ---

// limiter spaces the run's requests: at most rate a second, all kinds.
type limiter struct {
	mu   sync.Mutex
	gap  time.Duration
	next time.Time
}

func newLimiter(rate float64) *limiter {
	l := &limiter{}
	if rate > 0 {
		l.gap = time.Duration(float64(time.Second) / rate)
	}
	return l
}

func (l *limiter) wait(ctx context.Context) error {
	if l.gap == 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	at := l.next
	if at.Before(now) {
		at = now
	}
	l.next = at.Add(l.gap)
	l.mu.Unlock()
	t := time.NewTimer(time.Until(at))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
