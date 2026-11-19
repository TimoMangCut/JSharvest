package httpcrawl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

const (
	breakerRefusedThreshold = 2
	breakerTimeoutThreshold = 3
	breakerCooldown         = 3 * time.Minute
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type endpointDialState struct {
	ok          bool
	probing     bool
	probeWait   chan struct{}
	fastStrikes int // ECONNREFUSED or NXDOMAIN (1 strike per dialAll)
	slowStrikes int // dial timeout (1 strike per dialAll)
	openUntil   time.Time
	halfOpen    bool
	lastErr     error
}

type hostPortBreaker struct {
	next     dialFunc
	cooldown time.Duration
	now      func() time.Time

	mu     sync.Mutex
	states map[string]*endpointDialState
}

func newHostPortBreaker(next dialFunc) dialFunc {
	b := &hostPortBreaker{
		next:     next,
		cooldown: breakerCooldown,
		now:      time.Now,
		states:   map[string]*endpointDialState{},
	}
	return b.dialContext
}

func (b *hostPortBreaker) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	key := strings.ToLower(addr)
	for {
		b.mu.Lock()
		st := b.states[key]
		if st == nil {
			st = &endpointDialState{}
			b.states[key] = st
		}
		if st.ok {
			b.mu.Unlock()
			return b.next(ctx, network, addr)
		}
		now := b.now()
		if !st.openUntil.IsZero() {
			if now.Before(st.openUntil) {
				lastErr := st.lastErr
				b.mu.Unlock()
				return nil, fmt.Errorf("dial breaker: %s unreachable (%w)", addr, lastErr)
			}
			// Half-open window expired: allow a single probe through while others wait.
			if st.probing {
				wait := st.probeWait
				b.mu.Unlock()
				select {
				case <-wait:
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			st.probing = true
			st.halfOpen = true
			st.probeWait = make(chan struct{})
			wait := st.probeWait
			b.mu.Unlock()
			return b.runGatedDial(ctx, network, addr, key, wait)
		}
		// First-Dial Gate: while ok == false, serialize initial dial attempts to
		// an unproven host:port so concurrent links to a dead firewall port do not
		// burn N parallel 10s SYN timeouts simultaneously.
		if st.probing {
			wait := st.probeWait
			b.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		st.probing = true
		st.probeWait = make(chan struct{})
		wait := st.probeWait
		b.mu.Unlock()
		return b.runGatedDial(ctx, network, addr, key, wait)
	}
}

func (b *hostPortBreaker) runGatedDial(ctx context.Context, network, addr, key string, wait chan struct{}) (net.Conn, error) {
	conn, err := b.next(ctx, network, addr)
	b.mu.Lock()
	st := b.states[key]
	st.probing = false
	wasHalfOpen := st.halfOpen
	st.halfOpen = false
	if err == nil {
		st.ok = true
		st.fastStrikes = 0
		st.slowStrikes = 0
		st.openUntil = time.Time{}
		st.lastErr = nil
	} else if ctx.Err() == nil && !errors.Is(err, netsafe.ErrPrivate) && !errors.Is(err, netsafe.ErrLiteral) {
		kind := classifyDialFailure(err)
		switch kind {
		case dialFailFast:
			st.fastStrikes++
			st.lastErr = err
			if wasHalfOpen || st.fastStrikes >= breakerRefusedThreshold || st.fastStrikes+st.slowStrikes >= breakerTimeoutThreshold {
				st.openUntil = b.now().Add(b.cooldown)
			}
		case dialFailTimeout:
			st.slowStrikes++
			st.lastErr = err
			if wasHalfOpen || st.slowStrikes >= breakerTimeoutThreshold || st.fastStrikes+st.slowStrikes >= breakerTimeoutThreshold {
				st.openUntil = b.now().Add(b.cooldown)
			}
		}
	}
	close(wait)
	b.mu.Unlock()
	return conn, err
}

type dialFailKind int

const (
	dialFailIgnore dialFailKind = iota
	dialFailFast
	dialFailTimeout
)

func classifyDialFailure(err error) dialFailKind {
	if err == nil {
		return dialFailIgnore
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return dialFailFast
		}
		if dnsErr.IsTimeout {
			return dialFailTimeout
		}
		return dialFailIgnore
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		return dialFailIgnore
	}
	if errors.Is(opErr, syscall.ECONNREFUSED) || errors.Is(opErr, syscall.EHOSTUNREACH) || errors.Is(opErr, syscall.ENETUNREACH) {
		return dialFailFast
	}
	if opErr.Timeout() {
		return dialFailTimeout
	}
	return dialFailIgnore
}
