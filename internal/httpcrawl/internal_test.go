package httpcrawl

import (
	"context"
	"net/netip"
	"net/url"
	"testing"
)

func TestInternalTargetNotFromPolicy(t *testing.T) {
	calls := 0
	ans := func(a ...string) func(context.Context, string) ([]netip.Addr, error) {
		return func(context.Context, string) ([]netip.Addr, error) {
			calls++
			var out []netip.Addr
			for _, s := range a {
				out = append(out, netip.MustParseAddr(s))
			}
			return out, nil
		}
	}
	u := func(s string) *url.URL { x, _ := url.Parse(s); return x }
	px, _ := url.Parse("http://127.0.0.1:8899")
	for _, tc := range []struct {
		name string
		o    Options
		want bool
	}{
		{"public and ::1", Options{Target: u("http://mixed.example/"), Resolver: ans("93.184.216.34", "::1")}, false},
		{"public and rebinding private", Options{Target: u("http://mixed.example/"), Resolver: ans("93.184.216.34", "169.254.169.254")}, false},
		{"all private", Options{Target: u("http://intranet.example/"), Resolver: ans("10.0.0.1", "10.0.0.2")}, true},
		{"private literal", Options{Target: u("http://127.0.0.1:8770/")}, true},
		{"host rule to loopback", Options{Target: u("http://app.jsh.test/"), HostRules: "MAP *.jsh.test 127.0.0.1"}, true},
		{"proxy: no lookup", Options{Target: u("http://intranet.example/"), Resolver: ans("10.0.0.1"), Proxy: px}, false},
		{"proxy: literal", Options{Target: u("http://10.1.2.3/"), Proxy: px}, true},
		{"proxy: localhost", Options{Target: u("http://localhost:3000/"), Proxy: px}, true},
	} {
		before := calls
		if got := internalTarget(context.Background(), tc.o); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
		if tc.o.Proxy != nil && calls != before {
			t.Errorf("%s: the resolver was called behind a proxy", tc.name)
		}
	}
}
