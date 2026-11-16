package replay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

// refused: the Send ended in the dialer's refusal (the transport's error is
// the Answer's Err).
func refused(a Answer, err error) bool {
	return err == nil && a.Status == 0 && (strings.Contains(a.Err, netsafe.ErrPrivate.Error()) || strings.Contains(a.Err, netsafe.ErrLiteral.Error()))
}

func rawGet(host string) []byte {
	return []byte("GET /latest/meta-data/ HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
}

// P2.1: a host the browser never reached (no Recorded) that resolves to the
// metadata address is refused, not dialled.
func TestSenderUnrecordedMetadataRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := "169.254.169.254:80"
	s, err := NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 2, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Send(ctx, rawGet(host), "http", "probe", "user", "x", nil)
	if !refused(a, err) {
		t.Fatalf("answer %+v err %v, want a private-address refusal", a, err)
	}
}

func TestSenderNamedHostToMetadataRefused(t *testing.T) {
	ctx := context.Background()
	host := "only-in-code.example:80"
	var looked int32
	s, err := NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 2, Timeout: 2 * time.Second,
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			atomic.AddInt32(&looked, 1)
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if a, err := s.Send(ctx, rawGet(host), "http", "probe", "user", "x", nil); !refused(a, err) {
		t.Fatalf("answer %+v err %v", a, err)
	}
	if looked != 1 {
		t.Fatalf("looked up %d times", looked)
	}
	// CGNAT too (the old private() missed it).
	s.o.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("100.64.0.9")}, nil
	}
	s, _ = NewSender(s.o)
	if a, err := s.Send(ctx, rawGet(host), "http", "probe", "user", "x", nil); !refused(a, err) {
		t.Fatalf("cgnat: answer %+v err %v", a, err)
	}
}

// A recorded private IP is the browser's evidence the host is internal; a
// recorded public one does not let a private answer through (rebinding),
// and a recorded public one still passes the shared check.
func TestSenderRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	host := srv.Listener.Addr().String()
	h, _, _ := net.SplitHostPort(host)
	ctx := context.Background()

	// Recorded at a private address, the target public: still closed.
	s, _ := NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 4, Recorded: map[string]string{h: h}})
	if a, err := s.Send(ctx, rawGet(host), "http", "probe", "user", "x", nil); !refused(a, err) {
		t.Fatalf("recorded loopback host, public target: %+v %v", a, err)
	}
	// No record, no AllowPrivate: closed.
	s, _ = NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 4})
	if a, err := s.Send(ctx, rawGet(host), "http", "probe", "user", "x", nil); !refused(a, err) {
		t.Fatalf("unrecorded loopback: %+v %v", a, err)
	}
	// An internal target.
	s, _ = NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 4, AllowPrivate: true})
	if a, err := s.Send(ctx, rawGet(host), "http", "probe", "user", "x", nil); err != nil || a.Status != 200 {
		t.Fatalf("AllowPrivate: %v %v", a.Status, err)
	}
	// Recorded public, answers private now: rebinding.
	s, _ = NewSender(SenderOptions{Hosts: map[string]bool{"x.example:80": true}, Max: 4, Recorded: map[string]string{"x.example": "93.184.216.34"},
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
		}})
	a, err := s.Send(ctx, rawGet("x.example:80"), "http", "probe", "user", "x", nil)
	if err != nil || a.Status != 0 || !strings.Contains(a.Err, "DNS rebinding") {
		t.Fatalf("rebinding: %+v %v", a, err)
	}
}

// -host-resolver-rules: a host the user maps is reached there.
func TestSenderHostRules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	rules, _ := netsafe.ParseHostRules("MAP *.jsh.test 127.0.0.1")
	host := "app.jsh.test:" + port
	s, _ := NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 4, HostRules: rules,
		Resolver: func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nx") }})
	if a, err := s.Send(context.Background(), rawGet(host), "http", "probe", "user", "x", nil); err != nil || a.Status != 200 {
		t.Fatalf("%v %v", a.Status, err)
	}
}
