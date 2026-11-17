package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

var (
	// ErrBlocked says an archive refuses our connections: it has blocked
	// this address for a while. The run saves its place and stops.
	ErrBlocked = errors.New("the archive refuses connections: blocked for a while; resume later")
	// ErrExcluded says the archive excludes the domain on its owner's
	// request: nothing to list there, and no retrying.
	ErrExcluded = errors.New("the archive excludes this domain")
	// ErrUnavailable says a source failed this run, after its retries: the
	// other sources go on, and the next run lists it on from where it was.
	ErrUnavailable = errors.New("unavailable for now")
)

// Budget spaces one kind of request: an archive's index, its files.
type Budget struct {
	Gap  time.Duration
	mu   sync.Mutex
	last time.Time
}

func (b *Budget) wait(ctx context.Context) error {
	b.mu.Lock()
	d := time.Until(b.last.Add(b.Gap))
	b.last = time.Now().Add(max(d, 0))
	b.mu.Unlock()
	if d <= 0 {
		return nil
	}
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Client gets from the archives, patiently: it waits when told to slow
// down, and stops when an archive refuses it.
type Client struct {
	HTTP *http.Client
	UA   string
	// Wait is how long a 429 or 503 without Retry-After waits.
	Wait time.Duration
	// Tries per request.
	Tries   int
	mu      sync.Mutex
	refused int
}

// NewClientSafe is the client of the archive services (Wayback, OTX, Common
// Crawl, urlscan). It goes through the run's proxy (netsafe.ProxyFrom: the
// one value every client of the run takes; the environment is never read
// here), except for the hosts the user's host rules map. What it connects
// to is checked as the crawl's client is (netsafe.Dialer, netsafe.Guard):
// a private, loopback or link-local address is refused, and so is a
// redirect to one. The exception is the hosts of services, the URLs the user
// (or a gate's fake archive) declared with JSHARVEST_WAYBACK_URL and the
// like: those are allowed whatever they are. A redirect from one of them to
// another host is checked all the same.
func NewClientSafe(proxy *url.URL, rules netsafe.Rules, services []string) *Client {
	allowed := map[string]bool{}
	for _, raw := range services {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			allowed[netsafe.CanonHostPort(u.Scheme, u.Host)] = true
		}
	}
	// By host and port: a service on 127.0.0.1:8770 does not open the
	// machine's other ports.
	isAllowed := func(hostport string) bool { return allowed[hostport] }
	d := &netsafe.Dialer{HostRules: rules, Proxy: proxy, AllowPrivateAddr: isAllowed, Timeout: 30 * time.Second}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = netsafe.ProxyFunc(proxy, rules)
	tr.DialContext = d.DialContext
	tr.DisableCompression = true
	tr.MaxIdleConns = 64
	tr.MaxIdleConnsPerHost = 32
	tr.IdleConnTimeout = 90 * time.Second
	g := netsafe.Guard{Next: tr, AllowHost: isAllowed, Rules: rules}
	return &Client{HTTP: &http.Client{Transport: g, Timeout: 120 * time.Second}, UA: "jsharvest (archive; +https://github.com/TimoMangCut/JSharvest)",
		Wait: 60 * time.Second, Tries: 4}
}

// Answer is a response read whole.
type Answer struct {
	Status int
	Header http.Header
	Body   []byte
	URL    string // after redirects
}

// Get gets a URL within a budget, reading at most max bytes of the body.
// It sends Accept-Encoding: identity so raw archived payloads match their
// SHA-1 base32 digest.
func (c *Client) Get(ctx context.Context, b *Budget, rawURL string, max int64) (*Answer, error) {
	return c.getWithOpts(ctx, b, rawURL, max, nil, false)
}

// GetWith is Get with headers of the caller's (a Range).
func (c *Client) GetWith(ctx context.Context, b *Budget, rawURL string, max int64, h http.Header) (*Answer, error) {
	return c.getWithOpts(ctx, b, rawURL, max, h, false)
}

// GetIndex gets an archive index/API JSON endpoint with Accept-Encoding: gzip
// and transparently decompresses the body, cutting CDX/index network payloads
// by ~10-15x while keeping raw byte identity for mementos and WARC ranges.
func (c *Client) GetIndex(ctx context.Context, b *Budget, rawURL string, max int64) (*Answer, error) {
	return c.getWithOpts(ctx, b, rawURL, max, nil, true)
}

// GetIndexWith is GetIndex with custom request headers (e.g. URLScan Api-Key).
func (c *Client) GetIndexWith(ctx context.Context, b *Budget, rawURL string, max int64, h http.Header) (*Answer, error) {
	return c.getWithOpts(ctx, b, rawURL, max, h, true)
}

func (c *Client) getWithOpts(ctx context.Context, b *Budget, rawURL string, maxBytes int64, h http.Header, gzipOK bool) (*Answer, error) {
	var last error
	for try := 0; try < c.Tries; try++ {
		if err := b.wait(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
		if err != nil {
			return nil, err
		}
		for k, vs := range h {
			req.Header[k] = vs
		}
		req.Header.Set("User-Agent", c.UA)
		if gzipOK {
			req.Header.Set("Accept-Encoding", "gzip")
		} else {
			req.Header.Set("Accept-Encoding", "identity")
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			last = err
			if errors.Is(err, netsafe.ErrLiteral) || errors.Is(err, netsafe.ErrPrivate) {
				return nil, err // refused by what we are, not a trouble that passes
			}
			if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
				c.mu.Lock()
				c.refused++
				blocked := c.refused >= 5
				c.mu.Unlock()
				if blocked {
					return nil, ErrBlocked
				}
			}
			if err := sleep(ctx, adaptiveBackoff(c.Wait, try)); err != nil {
				return nil, err
			}
			continue
		}
		c.mu.Lock()
		c.refused = 0
		c.mu.Unlock()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if gzipOK && int64(len(body)) <= maxBytes {
			if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
				if dec, derr := decode(ce, body, int(min(maxBytes, 512<<20))); derr == nil {
					body = dec
					resp.Header.Del("Content-Encoding")
				}
			}
		}
		a := &Answer{Status: resp.StatusCode, Header: resp.Header, Body: body, URL: resp.Request.URL.String()}
		switch resp.StatusCode {
		case 429, 502, 503, 504:
			last = fmt.Errorf("%s: %d", rawURL, resp.StatusCode)
			if err := sleep(ctx, retryAfter(resp.Header, adaptiveBackoff(c.Wait, try))); err != nil {
				return nil, err
			}
			continue
		}
		if int64(len(body)) > maxBytes {
			return a, fmt.Errorf("%s: over %d bytes", rawURL, maxBytes)
		}
		return a, nil
	}
	return nil, fmt.Errorf("after %d tries: %w", c.Tries, last)
}

func adaptiveBackoff(base time.Duration, try int) time.Duration {
	if base <= 0 {
		return 0
	}
	var d time.Duration
	switch try {
	case 0:
		d = max(base/12, min(base, 50*time.Millisecond))
	case 1:
		d = max(base/4, min(base, 150*time.Millisecond))
	default:
		d = base
	}
	if d >= 500*time.Millisecond {
		// +/- 15% jitter so concurrent shard workers do not retry in lockstep.
		jitter := float64(d) * (0.85 + 0.30*rand.Float64())
		d = time.Duration(jitter)
	}
	return d
}

// retryAfter reads Retry-After's seconds; def when there are none.
func retryAfter(h http.Header, def time.Duration) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After"))); err == nil && n >= 0 {
		return min(time.Duration(n)*time.Second, 15*time.Minute)
	}
	if t, err := http.ParseTime(h.Get("Retry-After")); err == nil {
		return min(max(time.Until(t), 0), 15*time.Minute)
	}
	return def
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
