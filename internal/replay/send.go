package replay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/tlsutil"
	"github.com/TimoMangCut/JSharvest/internal/uahints"
)

var (
	ErrScope   = errors.New("out of scope: not sent")
	ErrBudget  = errors.New("the request budget (-max) is spent")
	errStopped = errors.New("the run stopped")
	// ErrHostBlocked: the host was given up (a vendor blocks the client
	// there); nothing more is sent to it. It is a kind of errStopped for
	// the callers that skip what was not sent.
	ErrHostBlocked error = hostBlockedErr{}
)

type hostBlockedErr struct{}

func (hostBlockedErr) Error() string        { return "not sent: the host was given up" }
func (hostBlockedErr) Is(target error) bool { return target == errStopped }

// Rate answers: how many times a read is asked again, and the longest
// wait the Sender takes (a longer Retry-After gives the host up).
const (
	rateTries   = 3
	maxRateWait = 60 * time.Second
	// recheckEvery: after a control found the host answering, every
	// this-many blocks in a row ask again.
	recheckEvery = 5
)

// SenderOptions configure what a run may send, and how fast.
type SenderOptions struct {
	// Hosts are the host:port a run may send to; nothing else is sent.
	Hosts map[string]bool
	// Recorded are the addresses the browser reached each host at
	// (response.remote_ip): an address now on the other side of the
	// private/public line is refused (DNS rebinding).
	Recorded map[string]string
	// HostRules are the user's -host-resolver-rules: a host they map is
	// reached where the rule says, trusted.
	HostRules netsafe.Rules
	// AllowPrivate: the target is internal (a private or loopback address,
	// the testbed): its hosts may be reached at private addresses. Unset
	// (the target is public, or not known) no private address is reached,
	// even one the browser reached (plan-28 3.1: the exceptions are the
	// user's host rules and an internal target).
	AllowPrivate bool
	// Resolver looks names up (nil: the system's); tests.
	Resolver netsafe.Resolver
	Rate     time.Duration // between two requests' starts: a ceiling on all of them, whatever the concurrency
	// Concurrency is how many requests may be in flight at once (1: one at
	// a time, the default).
	Concurrency int
	Max         int
	Timeout     time.Duration
	Proxy       *url.URL
	Insecure    bool
	// AIA completes the chains of servers that send their leaf alone (nil:
	// one of the sender's own).
	AIA    *tlsutil.AIA
	Log    string // sent.jsonl
	DryRun bool
	// OnBlock is what a vendor's block does: OnBlockHost (""), OnBlockSkip
	// or OnBlockStop (round 25H).
	OnBlock string
	// ChromePath is the Chrome whose version gives the default UserAgent
	// ("": JSHARVEST_CHROME, else the first Chrome on PATH).
	ChromePath string
	// UserAgent goes with a raw request that has none: the run's browser's
	// (round 25I, N0), never Go's default Go-http-client. Empty:
	// marker.FallbackUA.
	UserAgent string
}

// Sender sends raw requests, one at a time, and logs each.
type Sender struct {
	o       SenderOptions
	client  *http.Client
	mu      sync.Mutex
	n       int
	next    time.Time // the next request's slot: Rate after the one before's
	slots   chan struct{}
	stopped string
	log     *os.File
	enc     *json.Encoder
	ips     map[string]netip.Addr // host: the address its connection went to
	dialer  *netsafe.Dialer
	hosts   map[string]*hostState
	blocked map[string]string         // host: why it was given up
	cdn     map[string]http.CookieJar // role: its CDN cookies (prepare)
}

// hostState is what the Sender knows of one host's blocks.
type hostState struct {
	check      sync.Mutex // one control at a time
	given      string     // why the host was given up, "" while it answers
	checkedAt  time.Time  // when the last control answered
	consec     int        // blocks in a row since an answer that was not one
	good       []byte     // a read the host answered without a block: the control
	goodScheme string
	pauseUntil time.Time // a rate answer's wait
	errs       int       // network errors in a row
}

// Sent is a line of sent.jsonl: what was sent, why, as whom, and the
// answer.
type Sent struct {
	N         int               `json:"n"`
	Time      time.Time         `json:"ts"`
	Purpose   string            `json:"purpose"` // probe, source, control, trial, no-identity, step
	Role      string            `json:"role"`
	Item      string            `json:"item,omitempty"`
	Request   string            `json:"request"`
	Status    int               `json:"status,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	Err       string            `json:"error,omitempty"`
	Refreshed []string          `json:"refreshed,omitempty"`
	Stale     []string          `json:"stale,omitempty"`
	DryRun    bool              `json:"dry_run,omitempty"`
	Block     *Block            `json:"block,omitempty"`
}

func NewSender(o SenderOptions) (*Sender, error) {
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	if o.Concurrency < 1 {
		o.Concurrency = 1
	}
	ob, err := ParseOnBlock(o.OnBlock)
	if err != nil {
		return nil, err
	}
	o.OnBlock = ob
	if o.UserAgent == "" {
		// The Chrome installed's, as the HTTP engine's (round 25K); the
		// constant only when no Chrome answers.
		path := o.ChromePath
		if path == "" {
			path = os.Getenv("JSHARVEST_CHROME")
		}
		o.UserAgent = uahints.LocalChromeUA(path, marker.FallbackUA)
	}
	s := &Sender{o: o, ips: map[string]netip.Addr{}, slots: make(chan struct{}, o.Concurrency), hosts: map[string]*hostState{}, blocked: map[string]string{}}
	s.dialer = &netsafe.Dialer{Resolver: s.resolve, HostRules: o.HostRules, AllowPrivate: o.AllowPrivate, Proxy: o.Proxy,
		Connected: s.pin}
	tr := &http.Transport{
		Proxy:               netsafe.ProxyFunc(o.Proxy, o.HostRules),
		DialContext:         s.dialer.DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: o.Insecure},
		MaxIdleConnsPerHost: max(2, o.Concurrency),
		DisableCompression:  true, // the bodies compared are the server's, as sent
		// HTTP/2 where the server speaks it, as the browser and the HTTP
		// engine do (round 25K): a Chrome User-Agent over HTTP/1.1 alone
		// is a client that is not the browser it says.
		ForceAttemptHTTP2: true,
	}
	if o.Proxy == nil {
		tr.Proxy = nil
		if !o.Insecure {
			if o.AIA == nil {
				o.AIA = tlsutil.New()
			}
			// The pinned dial, then the handshake: the AIA's intermediates
			// when the server sends its leaf alone.
			tr.DialTLSContext = o.AIA.DialTLS(s.dialer.DialContext, true)
		}
	}
	s.client = &http.Client{Transport: netsafe.Guard{Next: tr, AllowPrivate: o.AllowPrivate, Rules: o.HostRules}, Timeout: o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if o.Log != "" {
		if err := os.MkdirAll(filepath.Dir(o.Log), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(o.Log, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, err
		}
		s.log, s.enc = f, json.NewEncoder(f)
	}
	return s, nil
}

// Allow sets the hosts a run may send to, unless the user named them,
// and where the browser reached them.
func (s *Sender) Allow(hosts map[string]bool, recorded map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.o.Hosts == nil {
		s.o.Hosts = hosts
	}
	if s.o.Recorded == nil {
		s.o.Recorded = recorded
	}
}

// DryRun says nothing is sent.
func (s *Sender) DryRun() bool { return s.o.DryRun }

// Options returns a copy of the Sender's configuration.
func (s *Sender) Options() SenderOptions { return s.o }

// Hosts are the hosts the run may send to.
func (s *Sender) Hosts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for h := range s.o.Hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (s *Sender) Close() error {
	if s.log != nil {
		return s.log.Close()
	}
	return nil
}

// Count is how many requests went out (or would have, in a dry run).
func (s *Sender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// Stopped says why the run stopped, "" while it goes on.
func (s *Sender) Stopped() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

func (s *Sender) stop(why string) {
	if s.stopped == "" {
		s.stopped = why
	}
}

// BlockedHosts are the hosts given up, and why (round 25H).
func (s *Sender) BlockedHosts() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.blocked) == 0 {
		return nil
	}
	out := make(map[string]string, len(s.blocked))
	for h, w := range s.blocked {
		out[h] = w
	}
	return out
}

func (s *Sender) hostOf(host string) *hostState {
	s.mu.Lock()
	defer s.mu.Unlock()
	hs := s.hosts[host]
	if hs == nil {
		hs = &hostState{}
		s.hosts[host] = hs
	}
	return hs
}

// giveUpLocked gives a host up; when every host the run may send to is
// given up, the run stops. s.mu is held.
func (s *Sender) giveUpLocked(hs *hostState, host, why string) {
	if hs.given != "" {
		return
	}
	hs.given = why
	s.blocked[host] = why
	for h := range s.o.Hosts {
		if s.blocked[h] == "" {
			return
		}
	}
	s.stop("every host is blocked: " + why)
}

// resolve is the dialer's lookup: the address a host's first connection
// went to stays (the requests that follow do not look it up again), and an
// answer on the other side of the private/public line from the one the
// browser reached is refused (DNS rebinding). Every address still passes
// the dialer's own check.
func (s *Sender) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	s.mu.Lock()
	ip, pinned := s.ips[host]
	s.mu.Unlock()
	if pinned {
		return []netip.Addr{ip}, nil
	}
	look := s.o.Resolver
	if look == nil {
		look = netsafe.SystemResolver
	}
	ips, err := look(ctx, host)
	if err != nil {
		return nil, err
	}
	if rec, err := netip.ParseAddr(s.o.Recorded[host]); err == nil {
		for _, a := range ips {
			if netsafe.PrivateAddr(rec) != netsafe.PrivateAddr(a) {
				return nil, fmt.Errorf("%s now resolves to %s, the browser reached %s: refused (DNS rebinding?)", host, a.Unmap(), rec.Unmap())
			}
		}
	}
	return ips, nil
}

func (s *Sender) pin(host string, ip netip.Addr) {
	s.mu.Lock()
	s.ips[host] = ip
	s.mu.Unlock()
}

// requestURL is where a raw request goes: the scheme asked and the Host
// that was allowed, with the path and query of its request line. The line
// is origin-form ("/…"), "*" for OPTIONS, or absolute-form (http or https,
// no userinfo) naming that same Host; any other form (an opaque one such as
// "a:@127.0.0.1:80/x") is out of scope. The URL is built from parts, not by
// joining strings.
func requestURL(q *http.Request, scheme, host string) (*url.URL, error) {
	ri := q.RequestURI
	bad := func(why string) (*url.URL, error) {
		return nil, fmt.Errorf("%w: the request line %q %s", ErrScope, ri, why)
	}
	switch {
	case ri == "*":
		if q.Method != http.MethodOptions {
			return bad("is * outside OPTIONS")
		}
		return &url.URL{Scheme: scheme, Host: host, Path: "*"}, nil
	case strings.HasPrefix(ri, "/"):
		// Origin-form: "//x/y" is a path here, not an authority.
		path, query, _ := strings.Cut(ri, "?")
		p, err := url.PathUnescape(path)
		if err != nil {
			return bad("does not parse")
		}
		u := &url.URL{Scheme: scheme, Host: host, Path: p, RawQuery: query}
		if p != path {
			u.RawPath = path
		}
		return u, nil
	case len(ri) > 7 && (strings.EqualFold(ri[:7], "http://") || (len(ri) > 8 && strings.EqualFold(ri[:8], "https://"))):
		u, err := url.Parse(ri)
		if err != nil {
			return bad("does not parse")
		}
		if u.User != nil {
			return bad("carries a credential")
		}
		if !strings.EqualFold(u.Host, host) {
			return nil, fmt.Errorf("%w: the request line names %s, its Host %s", ErrScope, u.Host, host)
		}
		out := &url.URL{Scheme: scheme, Host: host, Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
		if out.Path == "" {
			out.Path = "/"
		}
		return out, nil
	}
	return bad("is not origin-form, * or an http(s) URL of the Host")
}

// Send sends a raw request over scheme, for a purpose, as a role. It
// refuses a host out of the run's, a host given up, a request over the
// budget, and any after the run stopped. A vendor's block (Answer.Block)
// is handled by -on-block (round 25H): a rate answer to a read is asked
// again after its wait; another block is checked with a control request
// to the same host, and the host is given up when that is blocked too.
func (s *Sender) Send(ctx context.Context, raw []byte, scheme, purpose, role, item string, note func(*Sent)) (Answer, error) {
	q, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return Answer{}, fmt.Errorf("a raw request that does not read: %w", err)
	}
	host := q.Host
	if !s.o.Hosts[host] {
		return Answer{}, fmt.Errorf("%w: %s", ErrScope, host)
	}
	if _, err := requestURL(q, scheme, host); err != nil {
		return Answer{}, err
	}
	hs := s.hostOf(host)
	began := time.Now()
	var last Answer
	for try := 0; ; try++ {
		s.mu.Lock()
		given := hs.given
		s.mu.Unlock()
		if given != "" {
			if try > 0 {
				return last, nil // the answer this request did get
			}
			return Answer{}, fmt.Errorf("%w: %s: %s", ErrHostBlocked, host, given)
		}
		a, err := s.exchange(ctx, raw, scheme, purpose, role, item, note, hs)
		if err != nil {
			if try > 0 {
				return last, nil
			}
			return a, err
		}
		if a.Err != "" || a.Block == nil {
			if a.Err == "" {
				s.answered(hs, q.Method, raw, scheme, host, q.RequestURI, a)
			}
			return a, nil
		}
		last = a
		if !s.onBlock(ctx, hs, host, scheme, q, a.Block, began, try) {
			return a, nil
		}
	}
}

// answered notes an answer that was the application's: the host's blocks
// in a row end, and a read is kept as its control.
func (s *Sender) answered(hs *hostState, method string, raw []byte, scheme, host, uri string, a Answer) {
	s.mu.Lock()
	keep := hs.good == nil && (method == http.MethodGet || method == http.MethodHead) && a.Status < 500
	hs.consec = 0
	s.mu.Unlock()
	if !keep {
		return
	}
	// The control carries no identity (round 25I review): a cookie, an
	// Authorization, a token in the query are taken out. Sent again later
	// with a role's credential it would go as no role (sent.jsonl says
	// none), and a session that rotates its cookie could be undone by the
	// old one.
	bare := strip(raw, scheme+"://"+host+uri, nil)
	s.mu.Lock()
	if hs.good == nil {
		hs.good, hs.goodScheme = bare, scheme
	}
	s.mu.Unlock()
}

// onBlock handles a vendor's block; true asks the request again (a rate
// answer to a read, after its wait).
func (s *Sender) onBlock(ctx context.Context, hs *hostState, host, scheme string, q *http.Request, b *Block, began time.Time, try int) bool {
	if s.o.OnBlock == OnBlockStop {
		s.mu.Lock()
		s.stop(b.String())
		s.mu.Unlock()
		return false
	}
	if b.Kind == BlockRate {
		idem := q.Method == http.MethodGet || q.Method == http.MethodHead || q.Method == http.MethodOptions
		wait := rateWait(b, try)
		pause := func() {
			s.mu.Lock()
			pauseLocked(hs, wait) // the host's other requests wait too
			s.mu.Unlock()
		}
		switch {
		case idem && try+1 < rateTries && wait <= maxRateWait:
			pause()
			return true
		case !idem && wait <= maxRateWait:
			// A write is not asked again (it may have been done); the
			// host's next requests wait.
			pause()
		case s.o.OnBlock == OnBlockHost:
			why := fmt.Sprintf("%s, asked to wait %s", b, wait.Round(time.Second))
			if wait <= maxRateWait {
				why = fmt.Sprintf("%s, still after %d tries", b, try+1)
			}
			s.mu.Lock()
			s.giveUpLocked(hs, host, why)
			s.mu.Unlock()
		}
		return false
	}
	if s.o.OnBlock == OnBlockHost {
		s.confirm(ctx, hs, host, scheme, q, b, began)
	}
	return false
}

// confirm asks whether a host still answers after a block: its control
// (a read it answered before, else GET /) is sent; blocked too, the host
// is given up. A control is sent at the first block in a row, then every
// recheckEvery blocks, and never twice for blocks that came back together.
func (s *Sender) confirm(ctx context.Context, hs *hostState, host, scheme string, q *http.Request, b *Block, began time.Time) {
	hs.check.Lock()
	defer hs.check.Unlock()
	s.mu.Lock()
	if hs.given != "" || hs.checkedAt.After(began) {
		s.mu.Unlock()
		return
	}
	hs.consec++
	if hs.consec != 1 && hs.consec%recheckEvery != 0 {
		s.mu.Unlock()
		return
	}
	raw, sch := hs.good, hs.goodScheme
	s.mu.Unlock()
	what := "its earlier answered read"
	if raw == nil {
		ua := q.Header.Get("User-Agent")
		if ua == "" {
			ua = s.o.UserAgent
		}
		raw = []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + ua + "\r\nAccept: */*\r\n\r\n")
		sch = scheme
		what = "GET /"
	}
	ca, err := s.exchange(ctx, raw, sch, "block-check", "", host, nil, hs)
	s.mu.Lock()
	defer s.mu.Unlock()
	hs.checkedAt = time.Now()
	switch {
	case err != nil || ca.Err != "":
		// No word either way: the request's own verdict says blocked; the
		// next block asks again.
		hs.consec = 0
	case ca.Block != nil && ca.Block.Kind == BlockRate:
		// Asked to slow down: no word of the block either, and the host
		// waits as for any rate answer (round 25J).
		hs.consec = 0
		pauseLocked(hs, rateWait(ca.Block, 0))
	case ca.Block != nil:
		s.giveUpLocked(hs, host, fmt.Sprintf("%s; the control (%s) was blocked too", b, what))
	default:
		// The host answers: a rule on that request alone. This block is
		// the first of a new run of them: with recheckEvery 5 the next
		// control goes at the fifth block in a row counting this one.
		hs.consec = 1
	}
}

// rateWait is how long a rate answer asks to wait: its Retry-After, else
// 5 s doubled at each try.
func rateWait(b *Block, try int) time.Duration {
	if b.RetryAfter > 0 {
		return b.RetryAfter
	}
	return 5 * time.Second << try
}

// pauseLocked holds a host's next requests back for wait (at most
// maxRateWait). s.mu is held.
func pauseLocked(hs *hostState, wait time.Duration) {
	if until := time.Now().Add(min(wait, maxRateWait)); until.After(hs.pauseUntil) {
		hs.pauseUntil = until
	}
}

// exchange sends one request within the budget, the concurrency, the rate
// and the host's wait, logs it, and reads a block in its answer.
func (s *Sender) exchange(ctx context.Context, raw []byte, scheme, purpose, role, item string, note func(*Sent), hs *hostState) (Answer, error) {
	q, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return Answer{}, fmt.Errorf("a raw request that does not read: %w", err)
	}
	// What goes on the wire, and what the log says went (round 25K).
	raw = s.prepare(raw, scheme, q.Host, q.RequestURI, role)
	if q, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(raw))); err != nil {
		return Answer{}, fmt.Errorf("a raw request that does not read: %w", err)
	}
	body, _ := io.ReadAll(q.Body)
	host := q.Host
	s.mu.Lock()
	if s.stopped != "" {
		s.mu.Unlock()
		return Answer{}, fmt.Errorf("%w: %s", errStopped, s.stopped)
	}
	if s.o.Max > 0 && s.n >= s.o.Max {
		s.mu.Unlock()
		return Answer{}, ErrBudget
	}
	s.n++
	n := s.n
	var pause time.Duration
	if hs != nil {
		pause = time.Until(hs.pauseUntil)
	}
	s.mu.Unlock()
	// A rate answer's wait, for this host only: the others' requests take
	// the slots and turns meanwhile.
	if pause > 0 {
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return Answer{}, ctx.Err()
		}
	}
	// A slot of the in-flight ones, then a turn of the rate's: each request
	// takes the next free turn, so that many at once still keep to it.
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return Answer{}, ctx.Err()
	}
	defer func() { <-s.slots }()
	s.mu.Lock()
	turn := time.Now()
	if s.next.After(turn) {
		turn = s.next
	}
	s.next = turn.Add(s.o.Rate)
	s.mu.Unlock()
	if wait := time.Until(turn); wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return Answer{}, ctx.Err()
		}
	}
	// The run may have stopped while this one waited its turn.
	if why := s.Stopped(); why != "" {
		return Answer{}, fmt.Errorf("%w: %s", errStopped, why)
	}
	line := Sent{N: n, Time: time.Now().UTC(), Purpose: purpose, Role: role, Item: item, Request: string(raw), DryRun: s.o.DryRun}
	defer func() {
		if note != nil {
			note(&line)
		}
		s.write(line)
	}()
	if s.o.DryRun {
		return Answer{Err: "dry run"}, nil
	}
	target, err := requestURL(q, scheme, host)
	if err != nil {
		return Answer{}, err
	}
	req, err := http.NewRequestWithContext(ctx, q.Method, "http://x/", bytes.NewReader(body))
	if err != nil {
		return Answer{}, err
	}
	req.URL = target
	req.Header = q.Header
	req.Host = host
	if len(body) == 0 {
		req.Body, req.ContentLength = http.NoBody, 0
	}
	resp, err := s.client.Do(req)
	if err != nil {
		line.Err = err.Error()
		s.mu.Lock()
		// Five in a row on one host gives that host up (round 25I review:
		// one host down no longer stops the others); the last host given
		// up stops the run.
		if hs != nil {
			if hs.errs++; hs.errs >= 5 {
				s.giveUpLocked(hs, host, "5 errors in a row: "+err.Error())
			}
		}
		s.mu.Unlock()
		return Answer{Err: err.Error()}, nil
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	a := Answer{Status: resp.StatusCode, Header: map[string]string{}, Body: rb}
	for k, vs := range resp.Header {
		a.Header[strings.ToLower(k)] = strings.Join(vs, "\n")
	}
	line.Status, line.Headers = a.Status, a.Header
	s.keepCDN(role, req.URL, a.Header["set-cookie"])
	hb := head(rb, 64<<10)
	line.Body = string(hb)
	a.Block = ClassifyBlock(a.Status, a.Header, hb)
	line.Block = a.Block
	s.mu.Lock()
	if hs != nil {
		hs.errs = 0
	}
	if a.Header["clear-site-data"] != "" {
		s.stop("the target cleared the site's data (Clear-Site-Data): the session may be gone")
	}
	s.mu.Unlock()
	return a, nil
}

func looksHTML(ct string, b []byte) bool {
	if strings.Contains(strings.ToLower(ct), "html") {
		return true
	}
	s := bytes.TrimLeft(b, " \t\r\n")
	return len(s) > 0 && s[0] == '<'
}

func (s *Sender) write(l Sent) {
	if s.enc == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enc.Encode(l)
}
