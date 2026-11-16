package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/scope"
)

// Verdict is what the policy decides about a candidate URL.
type Verdict string

const (
	Allow      Verdict = "allow"
	OutOfScope Verdict = "out_of_scope"
	Private    Verdict = "private_address"
	BadURL     Verdict = "bad_url"
)

// Policy decides which candidates may be fetched. The resolver reads URLs
// out of the target's own code and manifests, which the target controls, so
// nothing is fetched unless it is on an in-scope host; and when the target
// itself is on the public internet, nothing that resolves to a private,
// loopback or link-local address is fetched either. A target that is itself
// internal (an authorized internal test, the local testbed) keeps internal
// hosts in scope.
type Policy struct {
	InScope      scope.Func
	TargetPublic bool
	Lookup       func(ctx context.Context, host string) ([]netip.Addr, error)

	mu    sync.Mutex
	cache map[string]bool // host -> resolves to a non-public address
}

// NewPolicy builds the policy for a target host. With noDNS (the browser
// goes through a proxy or maps hosts itself) the tool does not resolve names
// on its own: its answer could differ from the browser's, and the lookup
// would leave the machine outside the proxy. Then only literal addresses are
// checked; scope still holds every request to the target's domain.
func NewPolicy(target string, inScope scope.Func, noDNS bool) *Policy {
	p := &Policy{InScope: inScope, Lookup: lookup}
	if noDNS {
		p.Lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errNoDNS }
	}
	p.TargetPublic = p.public(target)
	return p
}

func (p *Policy) Check(raw string) Verdict {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return BadURL
	}
	if !p.InScope(u.Hostname()) {
		return OutOfScope
	}
	if p.TargetPublic && !p.public(u.Hostname()) {
		return Private
	}
	return Allow
}

// public reports whether every address a host resolves to is public. A
// host that does not resolve here (a name only the browser can map, say)
// counts as public: scope already keeps it to the target's domain.
func (p *Policy) public(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return isPublic(a)
	}
	p.mu.Lock()
	if p.cache == nil {
		p.cache = map[string]bool{}
	}
	private, ok := p.cache[host]
	p.mu.Unlock()
	if ok {
		return !private
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := p.Lookup(ctx, host)
	private = false
	if err == nil {
		for _, a := range addrs {
			if !isPublic(a) {
				private = true
			}
		}
	}
	p.mu.Lock()
	p.cache[host] = private
	p.mu.Unlock()
	return !private
}

var errNoDNS = errors.New("name resolution left to the browser")

// cgnat is the shared address space of RFC 6598, private in practice.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isPublic(a netip.Addr) bool {
	a = a.Unmap()
	return !(a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() || cgnat.Contains(a))
}

func lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
