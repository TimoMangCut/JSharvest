package archive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// An archive service's redirect to a local or metadata address is not
// followed: the client of the services is no door to the machine's own
// services.
func TestClientRefusesRedirectToLoopback(t *testing.T) {
	var secret int32
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secret, 1)
		w.Write([]byte("secret"))
	}))
	defer inner.Close()
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL+"/secret", http.StatusFound)
	}))
	defer outer.Close()
	c := newClientWith(nil, nil)
	c.Tries = 1
	c.Get(context.Background(), &Budget{}, outer.URL+"/x", 1<<10)
	if n := atomic.LoadInt32(&secret); n != 0 {
		t.Fatalf("the redirect to %s was followed (%d hits)", inner.URL, n)
	}
}

func TestClientSafeServiceHostAllowed(t *testing.T) {
	var secret, svc int32
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secret, 1)
	}))
	defer inner.Close()
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, inner.URL+"/secret", http.StatusFound)
			return
		}
		atomic.AddInt32(&svc, 1)
		w.Write([]byte("service"))
	}))
	defer outer.Close()
	// The service the user declared is on loopback: allowed. Its redirect to
	// another loopback host is not.
	c := NewClientSafe(nil, nil, []string{outer.URL})
	c.Tries = 1
	if a, err := c.Get(context.Background(), &Budget{}, outer.URL+"/x", 1<<10); err != nil || string(a.Body) != "service" {
		t.Fatalf("the declared service: %v %v", a, err)
	}
	c.Get(context.Background(), &Budget{}, outer.URL+"/redir", 1<<10)
	if atomic.LoadInt32(&secret) != 0 {
		t.Fatal("a redirect from a service to another loopback host was followed")
	}
	// Nothing declared: the same server is refused.
	c = NewClientSafe(nil, nil, nil)
	c.Tries = 1
	before := atomic.LoadInt32(&svc)
	if _, err := c.Get(context.Background(), &Budget{}, outer.URL+"/x", 1<<10); err == nil || atomic.LoadInt32(&svc) != before {
		t.Fatalf("an undeclared loopback service was reached: %v", err)
	}
	// 169.254.169.254 is refused with or without a redirect.
	if _, err := c.Get(context.Background(), &Budget{}, "http://169.254.169.254/latest/meta-data/", 1<<10); err == nil {
		t.Fatal("the metadata address was asked")
	}
}
