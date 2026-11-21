package httpcrawl

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/resolve"
)

func TestRound41PolicyUsesOptionsResolverAndHostRules(t *testing.T) {
	var mu sync.Mutex
	lookups := map[string]int{}
	resFn := func(_ context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		lookups[host]++
		mu.Unlock()
		switch host {
		case "app.example.test":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		case "priv.example.test":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		default:
			return nil, fmt.Errorf("nxdomain: %s", host)
		}
	}

	// 1. Direct NewPolicyWithLookup honors custom lookupFn without touching OS DNS.
	p := resolve.NewPolicyWithLookup("app.example.test", func(h string) bool {
		return strings.HasSuffix(h, ".example.test")
	}, false, resFn)
	if !p.TargetPublic {
		t.Fatal("expected TargetPublic=true for 93.184.216.34")
	}
	if v := p.Check("https://priv.example.test/a.js"); v != resolve.Private {
		t.Fatalf("Check(priv.example.test) = %s, want %s", v, resolve.Private)
	}

	// 2. Crawl wires o.Resolver into both policy and specPolicy (2 policy lookups
	// + 1 internalTarget + 1 dialer = 4 lookups for missing.example.test, 0 OS DNS).
	mu.Lock()
	lookups = map[string]int{}
	mu.Unlock()
	u, _ := url.Parse("http://missing.example.test/")
	_, _ = Crawl(context.Background(), Options{
		Target:      u,
		InScope:     func(string) bool { return true },
		Resolver:    resFn,
		NoSpecProbe: true,
		Timeout:     time.Second,
	})
	mu.Lock()
	gotLookups := lookups["missing.example.test"]
	mu.Unlock()
	if gotLookups < 3 {
		t.Fatalf("Crawl o.Resolver lookups for missing.example.test = %d, want >= 3 (policy + specPolicy + internalTarget/dial)", gotLookups)
	}
}
