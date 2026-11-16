package netsafe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestProxyFromErrorsNoCredential(t *testing.T) {
	for _, in := range []string{"user:s3cret@127.0.0.1:badport", "http://user:p@ssword@127.0.0.1:badport", "http://u:s3cret@:80x"} {
		_, _, err := ProxyFrom(in, nil)
		if err == nil {
			t.Errorf("%q accepted", in)
			continue
		}
		for _, leak := range []string{"s3cret", "ssword", "user:", "u:"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%q: the error leaks %q: %v", in, leak, err)
			}
		}
	}
	for in, want := range map[string]string{
		"http://user:p@ssword@h:1": "http://h:1", "user:s3cret@h:1": "h:1", "http://a:b@h:1": "http://h:1", "http://h:1": "http://h:1",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRefuseHostZoneAndDoubleDot(t *testing.T) {
	for _, h := range []string{"2606:2800:220:1:248:1893:25c8:1946%lo", "[2606:2800:220:1:248:1893:25c8:1946%25lo]", "fe80::1%eth0", "127.0.0.1..", "127.0.0.1...", "0x7f.1.."} {
		if err := RefuseHost(h, true); !errors.Is(err, ErrLiteral) {
			t.Errorf("%q: %v", h, err)
		}
	}
	// A zone is refused for any target: it names an interface of this machine.
	if err := RefuseHost("fe80::1%eth0", false); !errors.Is(err, ErrLiteral) {
		t.Errorf("zone, internal target: %v", err)
	}
	if _, lit, err := LiteralHost("fe80::1%eth0"); !lit || err == nil {
		t.Errorf("LiteralHost with a zone: %v %v", lit, err)
	}
}

func TestGuardZoneAndIPv6Rules(t *testing.T) {
	for _, g := range []Guard{{}, {AllowPrivate: true}} {
		if err := g.Check("2606:2800:220:1:248:1893:25c8:1946%lo"); err == nil {
			t.Errorf("%+v: a zone passed", g)
		}
	}
	rules, _ := ParseHostRules("MAP fd00::5 127.0.0.1")
	if err := (Guard{Rules: rules}).Check("fd00::5"); err != nil {
		t.Errorf("a mapped IPv6 host: %v", err)
	}
	if err := (Guard{Rules: rules}).Check("fd00::6"); err == nil {
		t.Error("an unmapped private IPv6 host passed")
	}
}

func TestDialerRefusesZone(t *testing.T) {
	for _, allow := range []bool{false, true} {
		r := &rec{answers: [][]netip.Addr{ips("2606:2800:220:1::1")}}
		d := newDialer(r)
		d.AllowPrivate = allow
		if c, err := d.DialContext(context.Background(), "tcp", "[2606:2800:220:1::1%lo]:80"); err == nil {
			c.Close()
			t.Fatalf("allow=%v: dialled %v with a zone", allow, r.dials)
		}
		// A resolver that answers with a zone is refused too.
		z, _ := netip.ParseAddr("fe80::1%lo")
		r2 := &rec{answers: [][]netip.Addr{{z}}}
		d = newDialer(r2)
		d.AllowPrivate = allow
		if c, err := d.DialContext(context.Background(), "tcp", "z.example:80"); err == nil {
			c.Close()
			t.Fatalf("allow=%v: dialled %v for an answer with a zone", allow, r2.dials)
		}
	}
}

func TestPrivateRanges(t *testing.T) {
	for s, want := range map[string]bool{
		"64:ff9b::7f00:1": true, "64:ff9b::a00:1": true, "64:ff9b::808:808": true, "64:ff9b:1::1": true,
		"2002:7f00:1::": true, "2002:808:808::1": true, // 6to4: the whole range is refused
		"::7f00:1": true, "::808:808": true, "::ffff:0:7f00:1": true, "::ffff:0:808:808": true,
		"2001::1": true, "2001:0:4136:e378:8000:63bf:3fff:fdd2": true,
		"255.255.255.255": true, "240.0.0.1": true, "250.1.2.3": true, "198.18.0.1": true, "198.19.255.255": true, "192.0.0.1": true, "192.0.0.255": true,
		// TEST-NET stays public (the lan gate's origin is 198.51.100.10).
		"192.0.2.1": false, "198.51.100.10": false, "203.0.113.5": false,
		"198.17.255.255": false, "198.20.0.1": false, "192.0.1.1": false, "2001:db8::1": false, "2001:1::1": false, "2606:4700::1": false,
		"8.8.8.8": false, "93.184.216.34": false, "64:ff9a::1": false,
	} {
		if got := PrivateAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("PrivateAddr(%s) = %v, want %v", s, got, want)
		}
		if got := Private(net.ParseIP(s)); got != want {
			t.Errorf("Private(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestIsProxyUnicodeVsPunycode(t *testing.T) {
	u, _ := url.Parse("http://bücher.example:3128")
	r := &rec{answers: [][]netip.Addr{ips("10.0.0.9")}}
	d := newDialer(r)
	d.Proxy = u
	c, err := d.DialContext(context.Background(), "tcp", "xn--bcher-kva.example:3128")
	if err != nil {
		t.Fatalf("the proxy's own (punycode) address was refused: %v", err)
	}
	c.Close()
	u2, _ := url.Parse("http://xn--bcher-kva.example:3128")
	d.Proxy = u2
	c, err = d.DialContext(context.Background(), "tcp", "BÜCHER.example:3128")
	if err != nil {
		t.Fatalf("the proxy's own (unicode) address was refused: %v", err)
	}
	c.Close()
	// Another host on the same port is not the proxy.
	if c, err := d.DialContext(context.Background(), "tcp", "other.example:3128"); err == nil {
		c.Close()
		t.Fatal("another host passed as the proxy")
	}
}

var _ = http.StatusOK

func TestPunycodeLabel(t *testing.T) {
	for in, want := range map[string]string{"bücher": "xn--bcher-kva", "münchen": "xn--mnchen-3ya", "ü": "xn--tda", "例え": "xn--r8jz45g"} {
		if got, ok := punycodeLabel(in); !ok || got != want {
			t.Errorf("%s -> %s %v, want %s", in, got, ok, want)
		}
	}
	if _, ok := punycodeLabel("plain"); ok {
		t.Error("an ASCII label encoded")
	}
}

func TestInternalTargetViaProxyDoesNoDNS(t *testing.T) {
	calls := 0
	res := func(context.Context, string) ([]netip.Addr, error) { calls++; return ips("10.0.0.1"), nil }
	rules, _ := ParseHostRules("MAP *.jsh.test 127.0.0.1")
	if InternalTargetVia(context.Background(), "intranet.example", nil, res, true) || calls != 0 {
		t.Fatalf("a name behind a proxy: calls %d", calls)
	}
	if !InternalTargetVia(context.Background(), "intranet.example", nil, res, false) || calls != 1 {
		t.Fatalf("a name with no proxy: calls %d", calls)
	}
	// Literals and host rules still decide.
	for _, tc := range []struct {
		target string
		rules  Rules
		want   bool
	}{{"127.0.0.1:8770", nil, true}, {"[::1]:80", nil, true}, {"8.8.8.8", nil, false}, {"app.jsh.test", rules, true}} {
		if got := InternalTargetVia(context.Background(), tc.target, tc.rules, res, true); got != tc.want {
			t.Errorf("%s: %v", tc.target, got)
		}
	}
	if calls != 1 {
		t.Fatalf("the resolver was called %d times", calls)
	}
	// A target that resolves to a public and a private address is public.
	mixed := func(context.Context, string) ([]netip.Addr, error) { return ips("93.184.216.34", "::1"), nil }
	if InternalTargetVia(context.Background(), "mixed.example", nil, mixed, false) {
		t.Fatal("a mixed answer made the target internal")
	}
}
