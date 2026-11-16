package netsafe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// rec is a dialer's world: a scripted resolver that counts its calls and a
// dial that records the addresses it was asked to connect to.
type rec struct {
	mu      sync.Mutex
	answers [][]netip.Addr // the nth lookup's answer (the last one repeats)
	err     error
	lookups int
	dials   []string
}

func (r *rec) resolve(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	if r.err != nil {
		return nil, r.err
	}
	if len(r.answers) == 0 {
		return nil, nil
	}
	i := r.lookups - 1
	if i >= len(r.answers) {
		i = len(r.answers) - 1
	}
	return r.answers[i], nil
}

func (r *rec) dial(_ context.Context, _, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.dials = append(r.dials, addr)
	r.mu.Unlock()
	c, _ := net.Pipe()
	return c, nil
}

func ips(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, x := range s {
		out = append(out, netip.MustParseAddr(x))
	}
	return out
}

func newDialer(r *rec) *Dialer { return &Dialer{Resolver: r.resolve, Dial: r.dial} }

func TestRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		ans  []netip.Addr
		err  error
	}{
		{"dns error", nil, errors.New("no such host")},
		{"no address", nil, nil},
		{"one of several private", ips("93.184.216.34", "10.0.0.5"), nil},
		{"cgnat", ips("100.64.1.2"), nil},
		{"cgnat top", ips("100.127.255.254"), nil},
		{"unspecified v4", ips("0.0.0.0"), nil},
		{"unspecified v6", ips("::"), nil},
		{"this network", ips("0.1.2.3"), nil},
		{"metadata", ips("169.254.169.254"), nil},
		{"mapped private", ips("::ffff:10.1.2.3"), nil},
		{"mapped metadata", ips("::ffff:169.254.169.254"), nil},
		{"loopback", ips("127.0.0.1"), nil},
		{"loopback v6", ips("::1"), nil},
		{"ula", ips("fd00::1"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &rec{answers: [][]netip.Addr{tc.ans}, err: tc.err}
			c, err := newDialer(r).DialContext(context.Background(), "tcp", "example.test:443")
			if err == nil {
				c.Close()
				t.Fatalf("dialled %v, want refusal", r.dials)
			}
			if len(r.dials) != 0 {
				t.Fatalf("a connection was tried: %v", r.dials)
			}
		})
	}
}

func TestLiteralPrivateRefused(t *testing.T) {
	r := &rec{}
	for _, a := range []string{"169.254.169.254:80", "127.0.0.1:80", "[::1]:80", "100.64.0.1:80"} {
		if c, err := newDialer(r).DialContext(context.Background(), "tcp", a); err == nil {
			c.Close()
			t.Fatalf("%s dialled", a)
		}
	}
	if r.lookups != 0 || len(r.dials) != 0 {
		t.Fatalf("lookups %d dials %v", r.lookups, r.dials)
	}
}

// Rebinding: the first answer is public, the second private. The dial is by
// the address checked and the name is looked up once.
func TestRebindingNoSecondLookup(t *testing.T) {
	r := &rec{answers: [][]netip.Addr{ips("93.184.216.34"), ips("169.254.169.254")}}
	c, err := newDialer(r).DialContext(context.Background(), "tcp", "rebind.example:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if r.lookups != 1 {
		t.Fatalf("the name was looked up %d times", r.lookups)
	}
	if len(r.dials) != 1 || r.dials[0] != "93.184.216.34:80" {
		t.Fatalf("dials %v, want the checked IP", r.dials)
	}
	for _, a := range r.dials {
		h, _, _ := net.SplitHostPort(a)
		if _, err := netip.ParseAddr(h); err != nil {
			t.Fatalf("dialled by name: %s", a)
		}
	}
}

func TestIPv4First(t *testing.T) {
	r := &rec{answers: [][]netip.Addr{ips("2606:2800:220:1::1", "93.184.216.34")}}
	c, err := newDialer(r).DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(r.dials) != 1 || r.dials[0] != "93.184.216.34:443" {
		t.Fatalf("dials %v", r.dials)
	}
	// A failed address gives way to the next, in that order.
	var order []string
	d := &Dialer{Resolver: r.resolve, Dial: func(_ context.Context, _, a string) (net.Conn, error) {
		order = append(order, a)
		if len(order) == 1 {
			return nil, errors.New("unreachable")
		}
		c, _ := net.Pipe()
		return c, nil
	}}
	c, err = d.DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(order) != 2 || !strings.HasPrefix(order[0], "93.") || !strings.HasPrefix(order[1], "[2606") {
		t.Fatalf("order %v", order)
	}
}

func TestAllowPrivate(t *testing.T) {
	r := &rec{answers: [][]netip.Addr{ips("10.0.0.5")}}
	d := newDialer(r)
	d.AllowPrivate = true
	c, err := d.DialContext(context.Background(), "tcp", "internal.test:8770")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if r.dials[0] != "10.0.0.5:8770" {
		t.Fatalf("dials %v", r.dials)
	}
	// Per host.
	r2 := &rec{answers: [][]netip.Addr{ips("10.0.0.5")}}
	d = newDialer(r2)
	d.AllowPrivateHost = func(h string) bool { return h == "internal.test" }
	if c, err := d.DialContext(context.Background(), "tcp", "internal.test:80"); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}
	if c, err := d.DialContext(context.Background(), "tcp", "other.test:80"); err == nil {
		c.Close()
		t.Fatal("another host reached a private address")
	}
}

func TestHostRulesTrusted(t *testing.T) {
	rules, err := ParseHostRules("MAP *.jsh.test 127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	r := &rec{err: errors.New("no such host")} // the testbed names do not resolve
	d := newDialer(r)
	d.HostRules = rules
	c, err := d.DialContext(context.Background(), "tcp", "app.jsh.test:8770")
	if err != nil {
		t.Fatalf("a host the user mapped to loopback: %v", err)
	}
	c.Close()
	if len(r.dials) != 1 || r.dials[0] != "127.0.0.1:8770" || r.lookups != 0 {
		t.Fatalf("dials %v lookups %d", r.dials, r.lookups)
	}
	// A host the rules do not map is checked, and its DNS failure refuses.
	if c, err := d.DialContext(context.Background(), "tcp", "app.other.test:80"); err == nil {
		c.Close()
		t.Fatal("an unmapped host with a DNS error was dialled")
	}
	// The rule's port wins.
	rules, _ = ParseHostRules("MAP x.jsh.test 127.0.0.1:9")
	d.HostRules = rules
	c, err = d.DialContext(context.Background(), "tcp", "x.jsh.test:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if r.dials[len(r.dials)-1] != "127.0.0.1:9" {
		t.Fatalf("dials %v", r.dials)
	}
}

func TestProxyExempt(t *testing.T) {
	for _, pu := range []string{"http://127.0.0.1:8080", "http://localhost:3128", "https://127.0.0.1:8443", "http://10.1.1.1"} {
		u, _ := url.Parse(pu)
		r := &rec{answers: [][]netip.Addr{ips("127.0.0.1")}}
		d := newDialer(r)
		d.Proxy = u
		port := u.Port()
		if port == "" {
			port = "80"
		}
		c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(u.Hostname(), port))
		if err != nil {
			t.Fatalf("%s: the proxy's own address refused: %v", pu, err)
		}
		c.Close()
		// What is not the proxy is still checked.
		if c, err := d.DialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
			c.Close()
			t.Fatalf("%s: a non-proxy private address dialled", pu)
		}
	}
}

func TestPrivate(t *testing.T) {
	for s, want := range map[string]bool{
		"8.8.8.8": false, "93.184.216.34": false, "2606:2800:220:1::1": false,
		"100.63.255.255": false, "100.128.0.0": false,
		"100.64.0.0": true, "100.127.0.1": true, "10.0.0.1": true, "172.16.0.1": true, "192.168.1.1": true,
		"127.0.0.1": true, "169.254.169.254": true, "0.0.0.0": true, "::": true, "::1": true,
		"::ffff:127.0.0.1": true, "::ffff:8.8.8.8": false, "224.0.0.1": true, "fe80::1": true, "fc00::1": true,
	} {
		if got := Private(net.ParseIP(s)); got != want {
			t.Errorf("Private(%s) = %v", s, got)
		}
	}
	if !Private(nil) {
		t.Error("nil is not an address to dial")
	}
}

func TestInternalTarget(t *testing.T) {
	ctx := context.Background()
	rules, _ := ParseHostRules("MAP *.jsh.test 127.0.0.1")
	fail := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nx") }
	pub := func(context.Context, string) ([]netip.Addr, error) { return ips("93.184.216.34"), nil }
	priv := func(context.Context, string) ([]netip.Addr, error) { return ips("10.0.0.1"), nil }
	mixed := func(context.Context, string) ([]netip.Addr, error) { return ips("10.0.0.1", "93.184.216.34"), nil }
	for _, tc := range []struct {
		name, target string
		rules        Rules
		res          Resolver
		want         bool
	}{
		{"literal loopback", "127.0.0.1:8770", nil, fail, true},
		{"literal public", "93.184.216.34", nil, fail, false},
		{"rule to loopback", "app.jsh.test", rules, fail, true},
		{"dns error is public", "app.jsh.test", nil, fail, false},
		{"public", "example.com", nil, pub, false},
		{"private", "intranet.example", nil, priv, true},
		{"mixed is public", "x.example", nil, mixed, false},
	} {
		if got := InternalTargetVia(ctx, tc.target, tc.rules, tc.res, false); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

func TestConnectedAndRules(t *testing.T) {
	var gotHost string
	var gotIP netip.Addr
	r := &rec{answers: [][]netip.Addr{ips("93.184.216.34")}}
	d := newDialer(r)
	d.Connected = func(h string, ip netip.Addr) { gotHost, gotIP = h, ip }
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if gotHost != "example.com" || gotIP.String() != "93.184.216.34" {
		t.Fatalf("%s %s", gotHost, gotIP)
	}
	if _, err := ParseHostRules("EXCLUDE x"); err == nil {
		t.Fatal("EXCLUDE understood")
	}
}
