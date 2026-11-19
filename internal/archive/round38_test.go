package archive

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/scope"
)

// A (round 38): Stage 1 streams 3 subdomains via ExtraHostCh into independent
// OTX and URLScan queues; URLScan fails on the first extra host without
// stalling OTX, and Stage 2 ModeResume with 4 ExtraHosts queries OTX only once
// for the 4th delta host.
func TestRound38ExtraHostsStreamingFanoutAndResumeDelta(t *testing.T) {
	var otxMu sync.Mutex
	otxCounts := map[string]int{}

	otxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		host := ""
		if len(parts) >= 5 {
			host, _ = url.PathUnescape(parts[4])
		}
		otxMu.Lock()
		otxCounts[host]++
		otxMu.Unlock()
		resp := fmt.Sprintf(`{"url_list":[{"url":"https://%s/app.js","date":"2024-05-01T00:00:00"}],"has_next":false}`, host)
		_, _ = w.Write([]byte(resp))
	}))
	defer otxSrv.Close()

	usSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/search") {
			q := r.URL.Query().Get("q")
			if q == "domain:example.com" {
				_, _ = w.Write([]byte(`{"results":[],"has_more":false}`))
				return
			}
			// Fail slowly on extra subdomains so we prove URLScan errors/latency
			// never block OTX's independent queue.
			time.Sleep(40 * time.Millisecond)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"warning":"not logged in"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer usSrv.Close()

	services := []string{otxSrv.URL, usSrv.URL}
	mkOTX := func() *OTX {
		cl := NewClientSafe(nil, nil, services)
		cl.Tries, cl.Wait = 1, time.Millisecond
		return &OTX{Base: otxSrv.URL, Client: cl, Budget: &Budget{Gap: time.Millisecond}}
	}
	mkUS := func() *URLScan {
		cl := NewClientSafe(nil, nil, services)
		cl.Tries, cl.Wait = 1, time.Millisecond
		return &URLScan{Base: usSrv.URL, Client: cl, Budget: &Budget{Gap: time.Millisecond}, Pages: 2, Results: 2}
	}

	inScope, err := scope.New("example.com", "rdn")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	archDir := filepath.Join(root, "example.com", "archive")

	streamCh := make(chan string, 8)
	go func() {
		for _, h := range []string{"sub1.example.com", "sub2.example.com", "SUB1.example.com", "sub3.example.com"} {
			streamCh <- h
			time.Sleep(5 * time.Millisecond)
		}
		close(streamCh)
	}()

	_, err = Run(context.Background(), Options{
		Dir:         archDir,
		Root:        root,
		Host:        "example.com",
		InScope:     inScope,
		Sources:     []string{"otx", "urlscan"},
		ExtraHostCh: streamCh,
		Mode:        ModeListOnly,
		OTX:         mkOTX(),
		URLScan:     mkUS(),
	})
	if err != nil {
		t.Fatalf("Stage 1 ModeListOnly failed: %v", err)
	}

	otxMu.Lock()
	for _, want := range []string{"example.com", "sub1.example.com", "sub2.example.com", "sub3.example.com"} {
		if otxCounts[want] != 1 {
			t.Fatalf("Stage 1 OTX count for %s = %d, want 1 (all=%v)", want, otxCounts[want], otxCounts)
		}
	}
	otxMu.Unlock()

	// Stage 2 ModeResume with 4 ExtraHosts: only sub4.example.com is new for OTX.
	_, err = Run(context.Background(), Options{
		Dir:        archDir,
		Root:       root,
		Host:       "example.com",
		InScope:    inScope,
		Sources:    []string{"otx", "urlscan"},
		ExtraHosts: []string{"sub1.example.com", "sub2.example.com", "sub3.example.com", "sub4.example.com"},
		Live:       false,
		Mode:       ModeResume,
		OTX:        mkOTX(),
		URLScan:    mkUS(),
	})
	if err != nil {
		t.Fatalf("Stage 2 ModeResume failed: %v", err)
	}

	otxMu.Lock()
	defer otxMu.Unlock()
	for _, h := range []string{"example.com", "sub1.example.com", "sub2.example.com", "sub3.example.com", "sub4.example.com"} {
		if otxCounts[h] != 1 {
			t.Fatalf("after Stage 2 OTX count for %s = %d, want exactly 1 (all=%v)", h, otxCounts[h], otxCounts)
		}
	}
	var keys []string
	for k := range otxCounts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if len(keys) != 5 {
		t.Fatalf("unexpected OTX queried hosts: %v", keys)
	}
}

// A (round 38): when OTX hits ErrBlocked on the first streamed extra host while
// the producer keeps pushing 50 more hosts onto an unbuffered ExtraHostCh,
// Stage 1 returns ErrBlocked cleanly without deadlocking or blocking the producer.
func TestRound38ExtraHostsStreamingOTXBlockedMidStream(t *testing.T) {
	var otxCl *Client
	var otxSrv *httptest.Server
	var rootOnce, closeOnce sync.Once
	rootServed := make(chan struct{})
	otxSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/example.com/") {
			_, _ = w.Write([]byte(`{"url_list":[],"has_next":false}`))
			rootOnce.Do(func() { close(rootServed) })
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer otxSrv.Close()

	otxCl = NewClientSafe(nil, nil, []string{otxSrv.URL})
	otxCl.Tries, otxCl.Wait = 2, time.Millisecond

	inScope, err := scope.New("example.com", "rdn")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	archDir := filepath.Join(root, "example.com", "archive")

	// Unbuffered channel proves the router drains all 50 subsequent hosts
	// without blocking the producer even after OTX aborts on host 1.
	streamCh := make(chan string)
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		<-rootServed
		closeOnce.Do(func() {
			otxCl.suspect()
			otxSrv.Close()
		})
		for i := 1; i <= 50; i++ {
			streamCh <- fmt.Sprintf("sub%d.example.com", i)
		}
		close(streamCh)
	}()

	_, err = Run(context.Background(), Options{
		Dir:         archDir,
		Root:        root,
		Host:        "example.com",
		InScope:     inScope,
		Sources:     []string{"otx"},
		ExtraHostCh: streamCh,
		Mode:        ModeListOnly,
		Workers:     2,
		OTX:         &OTX{Base: otxSrv.URL, Client: otxCl, Budget: &Budget{Gap: time.Millisecond}},
	})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked from OTX mid-stream, got %v", err)
	}
	select {
	case <-producerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("producer blocked pushing hosts after OTX hit ErrBlocked")
	}
}
