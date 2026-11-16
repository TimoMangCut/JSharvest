package netsafe

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefuseHost(t *testing.T) {
	refuse := []string{
		"127.0.0.1", "2130706433", "0x7f.1", "0177.0.0.1", "127.1", "0x7f000001", "10.1",
		"[::ffff:127.0.0.1]", "::ffff:127.0.0.1", "[::ffff:7f00:1]", "[::]", "[::1]", "0.0.0.0", "0", "0x",
		"169.254.169.254", "2852039166", "100.64.0.1", "192.168.1.1", "[fd00::1]",
		"localhost", "LOCALHOST.", "Localhost", "a.b.localhost", "a.localhost.",
		"256.0.0.1", "1.2.3.4.5", "09.1", "127.0.0.256", "4294967296", "1.16777216", "127.0.0.1.",
	}
	for _, h := range refuse {
		err := RefuseHost(h, true)
		if err == nil {
			t.Errorf("%q passed", h)
		} else if !errors.Is(err, ErrLiteral) {
			t.Errorf("%q: %v", h, err)
		}
		if RefuseHost(h, false) != nil {
			t.Errorf("%q refused for an internal target", h)
		}
	}
	for _, h := range []string{"example.com", "8.8.8.8", "93.184.216.34", "localhostx.com", "1.2.3.a", "notlocalhost.example", "[2606:2800:220:1::1]", "app.localhost.example.com", "1.2.3.4a"} {
		if err := RefuseHost(h, true); err != nil {
			t.Errorf("%q refused: %v", h, err)
		}
	}
}

func TestLiteralHostValues(t *testing.T) {
	for h, want := range map[string]string{
		"2130706433": "127.0.0.1", "0x7f.1": "127.0.0.1", "0177.0.0.1": "127.0.0.1", "127.1": "127.0.0.1",
		"0x7f000001": "127.0.0.1", "10.1": "10.0.0.1", "8.8.8.8": "8.8.8.8", "[::ffff:7f00:1]": "127.0.0.1",
	} {
		a, lit, err := LiteralHost(h)
		if err != nil || !lit || a.Unmap().String() != want {
			t.Errorf("%s: %v %v %v, want %s", h, a, lit, err, want)
		}
	}
	if _, lit, err := LiteralHost("example.com"); lit || err != nil {
		t.Error("a name read as a literal")
	}
	if _, lit, _ := LiteralHost("1.2.3.a"); lit {
		t.Error("1.2.3.a is a name")
	}
}

func TestGuardRoundTripper(t *testing.T) {
	hit := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++ }))
	defer srv.Close()
	rules, _ := ParseHostRules("MAP *.jsh.test 127.0.0.1")
	do := func(g Guard, u string) error {
		g.Next = http.DefaultTransport
		req, _ := http.NewRequest("GET", u, nil)
		resp, err := g.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
		return err
	}
	if err := do(Guard{}, "http://0x7f.1/"); !errors.Is(err, ErrLiteral) {
		t.Fatalf("%v", err)
	}
	if hit != 0 {
		t.Fatal("reached the server")
	}
	if err := do(Guard{AllowPrivate: true}, srv.URL); err != nil || hit != 1 {
		t.Fatalf("internal target: %v %d", err, hit)
	}
	// A mapped host is trusted (and is not a literal anyway); a literal the
	// rules do not map is refused.
	g := Guard{Rules: rules}
	if g.Check("app.jsh.test") != nil || g.Check("127.0.0.1") == nil {
		t.Fatal("rules")
	}
}
