package replay

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The request line cannot name another place than the Host the run was
// allowed: an opaque request-URI (a:@127.0.0.1:port/…) once made the URL
// http://allowed.examplea:@127.0.0.1:port/….
func TestSenderRequestURIForms(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(r.Method + " " + r.URL.RequestURI()))
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	mk := func() *Sender {
		s, err := NewSender(SenderOptions{Hosts: map[string]bool{"allowed.example": true}, Max: 20, AllowPrivate: true})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ctx := context.Background()
	for _, line := range []string{
		"GET a:@" + addr + "/secret HTTP/1.1",
		"GET x:" + addr + "/secret HTTP/1.1",
		"GET http://" + addr + "/secret HTTP/1.1",
		"GET http://u:p@allowed.example/secret HTTP/1.1",
		"GET ftp://allowed.example/secret HTTP/1.1",
		"GET * HTTP/1.1", // * is for OPTIONS only
	} {
		before := atomic.LoadInt32(&hits)
		_, err := mk().Send(ctx, []byte(line+"\r\nHost: allowed.example\r\n\r\n"), "http", "probe", "user", "x", nil)
		if !errors.Is(err, ErrScope) {
			t.Errorf("%q: err = %v, want ErrScope", line, err)
		}
		if atomic.LoadInt32(&hits) != before {
			t.Errorf("%q reached the server", line)
		}
	}
}

func TestRequestURLStar(t *testing.T) {
	q, _ := http.ReadRequest(bufioReader("OPTIONS * HTTP/1.1\r\nHost: h.example\r\n\r\n"))
	u, err := requestURL(q, "https", "h.example")
	if err != nil || u.RequestURI() != "*" || u.Host != "h.example" {
		t.Fatalf("%v %v", u, err)
	}
	q, _ = http.ReadRequest(bufioReader("GET * HTTP/1.1\r\nHost: h.example\r\n\r\n"))
	if _, err := requestURL(q, "https", "h.example"); !errors.Is(err, ErrScope) {
		t.Fatalf("GET *: %v", err)
	}
}

func bufioReader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

func TestSenderRequestURIAccepted(t *testing.T) {
	var got []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.RequestURI+" "+r.Host)
		w.Write([]byte("ok"))
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	addr := ln.Addr().String()
	s, _ := NewSender(SenderOptions{Hosts: map[string]bool{addr: true}, Max: 20, AllowPrivate: true})
	for _, tc := range []struct{ line, want string }{
		{"GET /a/b?x=1&y=%20z HTTP/1.1", "GET /a/b?x=1&y=%20z " + addr},
		{"GET //x/y HTTP/1.1", "GET //x/y " + addr},
		{"GET http://" + addr + "/abs?q=1 HTTP/1.1", "GET /abs?q=1 " + addr},
	} {
		got = nil
		a, err := s.Send(context.Background(), []byte(tc.line+"\r\nHost: "+addr+"\r\n\r\n"), "http", "probe", "user", "x", nil)
		if err != nil || a.Status != 200 || len(got) != 1 || !strings.EqualFold(got[0], tc.want) {
			t.Errorf("%q: %+v %v server saw %q, want %q", tc.line, a, err, got, tc.want)
		}
	}
}
