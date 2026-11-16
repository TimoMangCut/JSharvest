package replay

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

// P2.2: behind a proxy the dialer sees the proxy only, so a public target's
// run refuses a private host by its name, in any number form, before the
// request reaches the transport (the proxy gets no connection).
func TestSenderProxyRefusesPrivateHosts(t *testing.T) {
	var conns int32
	px := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("proxied")) }))
	px.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&conns, 1)
		}
	}
	px.Start()
	defer px.Close()
	pu, _ := url.Parse(px.URL)
	for _, host := range []string{"2130706433", "localhost", "LOCALHOST.", "0x7f.1", "0177.0.0.1", "127.1", "[::ffff:7f00:1]", "169.254.169.254", "256.0.0.1", "a.b.localhost"} {
		s, err := NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 4, Proxy: pu})
		if err != nil {
			t.Fatal(err)
		}
		a, err := s.Send(context.Background(), rawGet(host), "http", "probe", "user", "x", nil)
		if err != nil || a.Status != 0 || !strings.Contains(a.Err, netsafe.ErrLiteral.Error()) {
			t.Errorf("%s: %+v %v", host, a, err)
		}
	}
	if n := atomic.LoadInt32(&conns); n != 0 {
		t.Fatalf("the proxy got %d connections", n)
	}
	// A public name goes through the proxy; an internal target's private host too.
	s, _ := NewSender(SenderOptions{Hosts: map[string]bool{"example.com": true}, Max: 4, Proxy: pu})
	if a, err := s.Send(context.Background(), rawGet("example.com"), "http", "probe", "user", "x", nil); err != nil || a.Status != 200 {
		t.Fatalf("public name: %+v %v", a, err)
	}
	s, _ = NewSender(SenderOptions{Hosts: map[string]bool{"10.0.0.5": true}, Max: 4, Proxy: pu, AllowPrivate: true})
	if a, err := s.Send(context.Background(), rawGet("10.0.0.5"), "http", "probe", "user", "x", nil); err != nil || a.Status != 200 {
		t.Fatalf("internal target: %+v %v", a, err)
	}
}
