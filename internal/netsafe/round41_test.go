package netsafe

import (
	"context"
	"net/netip"
	"testing"
)

func TestRound41IPv6SiteLocalRefused(t *testing.T) {
	for _, raw := range []string{
		"fec0::1",
		"fed0:1234::abcd",
		"feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	} {
		a := netip.MustParseAddr(raw)
		if !PrivateAddr(a) {
			t.Fatalf("PrivateAddr(%s) = false, want true (RFC 3879 site-local)", raw)
		}
		r := &rec{answers: [][]netip.Addr{{a}}}
		if c, err := newDialer(r).DialContext(context.Background(), "tcp", "example.test:443"); err == nil {
			c.Close()
			t.Fatalf("dialled site-local %s", raw)
		}
	}
	if PrivateAddr(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("public IPv6 address wrongly marked PrivateAddr")
	}
}
