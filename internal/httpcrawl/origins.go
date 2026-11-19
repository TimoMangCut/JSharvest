package httpcrawl

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// OriginUnreachable is a page the crawl held without sending: its origin,
// or its host:port, stopped answering (round 37.1, A3 and F4).
const OriginUnreachable = "origin-unreachable"

// errOriginDown marks a request held by the origin breaker: nothing was
// sent for it.
var errOriginDown = errors.New("origin unreachable (held, not sent)")

// heldByBreaker says a request never left: the dial breaker or the origin
// breaker held it.
func heldByBreaker(err error) bool {
	return err != nil && (errors.Is(err, errOriginDown) || errors.Is(err, errDialBreaker))
}

// settleKind is what the crawl knows of an origin's shell (round 37.1, A1).
// The dispatch loop holds a second page of an origin that is not settled
// yet; a settled one runs at the crawl's concurrency.
type settleKind uint8

const (
	unsettled settleKind = iota
	// settledNoShell: the origin answered (not with a 2xx HTML page): no
	// app shell to learn from that answer.
	settledNoShell
	// settledShell: the origin served a 2xx HTML page, its print kept.
	settledShell
)

// settle raises an origin's state, never lowers it. Only the crawl's loop
// calls it (like prints).
func (cr *crawler) settle(origin string, k settleKind) {
	if origin == "" {
		return
	}
	if cr.settled[origin] < k {
		cr.settled[origin] = k
	}
}

const (
	originFailThreshold = 3
	originCooldown      = 3 * time.Minute
)

// originHealth is one origin's (scheme://host:port) record of answers. An
// origin never seen to answer lets one request through at a time; three
// transport failures after connecting (a TLS or header timeout, a reset)
// hold the rest for originCooldown, then one request tries again. An
// origin that answered once is never held: a later timeout is that
// request's.
type originHealth struct {
	ok        bool
	fails     int
	downUntil time.Time
	halfOpen  bool
	probing   bool
	probeWait chan struct{}
}

// originTurn is a request's pass through its origin's health.
type originTurn struct {
	origin string
	probe  bool
}

// originEnter waits for the origin's turn: at once for an origin that has
// answered; one at a time for one that has not; errOriginDown while it is
// held.
func (cr *crawler) originEnter(ctx context.Context, raw string) (originTurn, error) {
	origin := originOf(raw)
	if origin == "" {
		return originTurn{}, nil
	}
	for {
		cr.originMu.Lock()
		h := cr.origins[origin]
		if h == nil {
			h = &originHealth{}
			cr.origins[origin] = h
		}
		if h.ok {
			cr.originMu.Unlock()
			return originTurn{origin: origin}, nil
		}
		if !h.downUntil.IsZero() && time.Now().Before(h.downUntil) {
			cr.originMu.Unlock()
			return originTurn{}, errOriginDown
		}
		if h.probing {
			wait := h.probeWait
			cr.originMu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return originTurn{}, ctx.Err()
			}
		}
		if !h.downUntil.IsZero() {
			h.halfOpen = true // the cooldown is over: one request tries again
		}
		h.probing = true
		h.probeWait = make(chan struct{})
		cr.originMu.Unlock()
		return originTurn{origin: origin, probe: true}, nil
	}
}

// originLeave records the answer of a request originEnter let through. It
// must run however the request ended (deferred), or the origin's next
// requests would wait for ever.
func (cr *crawler) originLeave(ctx context.Context, t originTurn, a answer) {
	if t.origin == "" {
		return
	}
	cr.originMu.Lock()
	defer cr.originMu.Unlock()
	h := cr.origins[t.origin]
	if h == nil {
		return
	}
	switch {
	case a.Status > 0:
		h.ok, h.fails, h.downUntil, h.halfOpen = true, 0, time.Time{}, false
	case t.probe && ctx.Err() == nil && afterConnectFailure(a.Err):
		h.fails++
		if h.halfOpen || h.fails >= originFailThreshold {
			h.downUntil = time.Now().Add(originCooldown)
		}
	}
	if t.probe {
		h.probing, h.halfOpen = false, false
		close(h.probeWait)
	}
}

// afterConnectFailure: the connection was made (or the dial is not ours to
// judge) and the origin did not answer: a TLS handshake, response-header
// or body timeout, a reset, an end before the headers. A dial failure is
// the dial breaker's; a refusal by policy or a stop is no failure of the
// origin.
func afterConnectFailure(err error) bool {
	if err == nil || heldByBreaker(err) || errors.Is(err, context.Canceled) {
		return false
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return false
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	var rec tls.RecordHeaderError
	if errors.As(err, &rec) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "TLS handshake timeout") || strings.Contains(msg, "timeout awaiting response headers")
}

// dialHeld says the dial breaker holds raw's host:port open, asked before
// the request takes a -http-rate turn.
func (c *client) dialHeld(raw string) bool {
	if c == nil || c.dials == nil {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return c.dials.isOpen(net.JoinHostPort(host, port))
}
