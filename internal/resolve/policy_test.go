package resolve

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/scope"
)

func fakeDNS(m map[string]string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := m[host]; ok {
			return []netip.Addr{netip.MustParseAddr(a)}, nil
		}
		return nil, errors.New("no such host")
	}
}

func TestPolicyPublicTarget(t *testing.T) {
	in, _ := scope.New("www.example.com", "rdn")
	p := &Policy{InScope: in, Lookup: fakeDNS(map[string]string{
		"www.example.com":      "93.184.216.34",
		"cdn.example.com":      "93.184.216.35",
		"intranet.example.com": "10.0.0.5",
		"meta.example.com":     "169.254.169.254",
		"cg.example.com":       "100.64.1.1",
	})}
	p.TargetPublic = p.public("www.example.com")
	if !p.TargetPublic {
		t.Fatal("target should be public")
	}
	for raw, want := range map[string]Verdict{
		"https://cdn.example.com/a.js":       Allow,
		"https://other.com/a.js":             OutOfScope,
		"https://intranet.example.com/a.js":  Private,
		"http://meta.example.com/latest":     Private,
		"http://cg.example.com/a.js":         Private,
		"http://127.0.0.1/a.js":              OutOfScope,
		"https://unresolvable.example.com/a": Allow, // scope still holds it to the domain
		"javascript:alert(1)":                BadURL,
		"/relative.js":                       BadURL,
	} {
		if got := p.Check(raw); got != want {
			t.Errorf("Check(%s) = %s, want %s", raw, got, want)
		}
	}
}

func TestPolicyNoDNS(t *testing.T) {
	// Behind a proxy no name is resolved by the tool; literal addresses are
	// still checked.
	in, _ := scope.New("www.example.com", "rdn")
	p := NewPolicy("www.example.com", in, true)
	if !p.TargetPublic {
		t.Fatal("unresolved public target should count as public")
	}
	if got := p.Check("https://intranet.example.com/a.js"); got != Allow {
		t.Errorf("name check = %s, want allow (scope holds it)", got)
	}
}

func TestPolicyInternalTarget(t *testing.T) {
	// An authorized internal target keeps internal hosts in scope.
	in, _ := scope.New("app.corp.internal", "rdn")
	p := &Policy{InScope: in, Lookup: fakeDNS(map[string]string{
		"app.corp.internal": "10.1.2.3",
		"api.corp.internal": "10.1.2.4",
	})}
	p.TargetPublic = p.public("app.corp.internal")
	if p.TargetPublic {
		t.Fatal("internal target taken as public")
	}
	if got := p.Check("http://api.corp.internal/a.js"); got != Allow {
		t.Errorf("internal api = %s, want allow", got)
	}
	// The testbed: an IP target is only itself.
	inIP, _ := scope.New("127.0.0.1", "rdn")
	pIP := NewPolicy("127.0.0.1", inIP, false)
	if got := pIP.Check("http://127.0.0.1:8770/x.js"); got != Allow {
		t.Errorf("testbed = %s, want allow", got)
	}
	if got := pIP.Check("http://localhost:8770/x.js"); got != OutOfScope {
		t.Errorf("localhost from 127.0.0.1 = %s, want out of scope", got)
	}
}

func TestPolicyNetsafeLiteralsAndSpecialRanges(t *testing.T) {
	// Wide scope (as specPolicy uses !IsTrackerHost) under noDNS=true (-proxy):
	// non-standard IPv4 literals and RFC 6761 localhost must be refused, while
	// ordinary public names remain allowed for the proxy/browser to resolve.
	allScope := func(string) bool { return true }
	pNoDNS := NewPolicy("www.example.com", allScope, true)
	if !pNoDNS.TargetPublic {
		t.Fatal("public target with noDNS=true should remain TargetPublic=true")
	}
	for raw, want := range map[string]Verdict{
		"http://localhost/openapi.json":     Private,
		"http://sub.localhost/openapi.json": Private,
		"http://0x7f.1/openapi.json":        Private,
		"http://2130706433/openapi.json":    Private,
		"http://0177.0.0.1/openapi.json":    Private,
		"https://api.example.com/v2/docs":   Allow,
	} {
		if got := pNoDNS.Check(raw); got != want {
			t.Errorf("noDNS Check(%s) = %s, want %s", raw, got, want)
		}
	}

	// DNS responses in netsafe.special ranges (NAT64, 6to4, benchmarking, 240/4, 0/8).
	pDNS := &Policy{InScope: allScope, Lookup: fakeDNS(map[string]string{
		"www.example.com":    "93.184.216.34",
		"nat64.example.com":  "64:ff9b::7f00:1",
		"sixto4.example.com": "2002:7f00:1::1",
		"bench.example.com":  "198.18.0.1",
		"resv.example.com":   "240.0.0.1",
		"zero.example.com":   "0.0.0.1",
	})}
	pDNS.TargetPublic = pDNS.public("www.example.com")
	for _, host := range []string{"nat64.example.com", "sixto4.example.com", "bench.example.com", "resv.example.com", "zero.example.com"} {
		if got := pDNS.Check("https://" + host + "/a.js"); got != Private {
			t.Errorf("Check(%s) = %s, want Private", host, got)
		}
	}

	// localhost as target is recognized as internal even with noDNS=true.
	pLocal := NewPolicy("localhost", allScope, true)
	if pLocal.TargetPublic {
		t.Fatal("localhost target should have TargetPublic=false")
	}
}
