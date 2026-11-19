package archive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Reviewer round 17 (MAX-01): Common Crawl, a collection at a time; page 0
// alone when it is not full; a capture's bytes from its WARC file.
func TestCommonCrawlCollections(t *testing.T) {
	var numPages, busy atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/collinfo.json":
			io.WriteString(w, `[{"id":"C3"},{"id":"C2"},{"id":"C1"}]`)
		case r.URL.Query().Get("showNumPages") == "true":
			numPages.Add(1)
			io.WriteString(w, `{"pages":1}`)
		case strings.HasPrefix(r.URL.Path, "/C3-"):
			busy.Add(1)
			w.WriteHeader(504) // the newest, the busiest: always
		case strings.HasPrefix(r.URL.Path, "/C2-"):
			fmt.Fprintln(w, `{"url":"https://a.test/x.js","timestamp":"20260101000000","status":"200","mime":"application/javascript","digest":"D","filename":"crawl-data/f.warc.gz","offset":"10","length":"20"}`)
		default:
			w.WriteHeader(404) // nothing in C1
			io.WriteString(w, "No Captures found")
		}
	}))
	defer srv.Close()
	c := newClient()
	c.Wait, c.Tries = time.Millisecond, 3
	r := testRunner(t, Options{Host: "a.test", Sources: []string{"commoncrawl"},
		CC: &CommonCrawl{Index: srv.URL, Client: c, Budget: &Budget{}, Collections: 3}})
	if err := r.list(context.Background()); err != nil {
		t.Fatal(err)
	}
	cc := r.st.CC
	if r.st.Summary.Listed["commoncrawl"] != 1 || !cc.Listed["C2"] || !cc.Listed["C1"] || cc.Listed["C3"] || cc.Done || !r.partial {
		t.Fatalf("listed %v, state %+v, partial %v", r.st.Summary.Listed, cc, r.partial)
	}
	if busy.Load() != 3 || numPages.Load() != 0 {
		t.Fatalf("C3 asked %d times (want 3 tries), showNumPages %d times (page 0 was not full)", busy.Load(), numPages.Load())
	}
	// The capture keeps its WARC range.
	r.js.Sync()
	gs, _ := r.groups()
	if len(gs) != 1 || gs[0].warc.WARC == nil || gs[0].warc.WARC.Offset != 10 || gs[0].warc.WARC.Length != 20 {
		t.Fatalf("%+v", gs)
	}
}

func TestCommonCrawlFetch(t *testing.T) {
	rec := warcRecord(t, "response", "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 15\r\n\r\nfetch('/api/w')")
	file := append(append(bytes.Repeat([]byte("x"), 100), rec...), bytes.Repeat([]byte("y"), 50)...)
	var rng string
	var rngMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rngMu.Lock()
		rng = r.Header.Get("Range")
		rngMu.Unlock()
		http.ServeContent(w, r, "f.warc.gz", time.Time{}, bytes.NewReader(file))
	}))
	defer srv.Close()
	cc := &CommonCrawl{Data: srv.URL, Client: newClient(), Files: &Budget{}}
	got, err := cc.Fetch(context.Background(), &WARCRef{File: "crawl-data/f.warc.gz", Offset: 100, Length: int64(len(rec))}, 1<<20)
	if err != nil || got.Status != 200 || string(got.Body) != "fetch('/api/w')" || rng != fmt.Sprintf("bytes=100-%d", 100+len(rec)-1) {
		t.Fatalf("%+v %v %q", got, err, rng)
	}
	if _, err := cc.Fetch(context.Background(), &WARCRef{File: "../etc/passwd", Offset: 0, Length: 1}, 1<<20); err == nil {
		t.Fatal("a path out of the data set")
	}
}

// MAX-05: urlscan's public scans: the pages they visited, and the scripts
// the target's own pages loaded. Listed beside the other sources, at once.
func TestURLScan(t *testing.T) {
	var results atomic.Int32
	var key string
	var keyMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyMu.Lock()
		key = r.Header.Get("Api-Key")
		keyMu.Unlock()
		switch {
		case r.URL.Path == "/api/v1/search/" && r.URL.Query().Get("q") == "domain:a.test":
			io.WriteString(w, `{"results":[
{"_id":"s1","task":{"url":"https://a.test/","time":"2025-03-01T10:00:00.000Z"},"page":{"url":"https://a.test/login","mimeType":"text/html","status":"200"},"sort":[1,"s1"]},
{"_id":"s2","task":{"url":"https://other.test/","time":"2025-02-01T10:00:00.000Z"},"page":{"url":"https://other.test/","mimeType":"text/html","status":200},"sort":[2,"s2"]}],
"has_more":false}`)
		case r.URL.Path == "/api/v1/result/s1/":
			results.Add(1)
			io.WriteString(w, `{"lists":{"urls":["https://a.test/login","https://a.test/js/app.4f2a.js","https://cdn.other.test/lib.js"]}}`)
		default:
			t.Errorf("asked %s", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	us := &URLScan{Base: srv.URL, Key: "k", Client: newClient(), Budget: &Budget{}, Pages: 2, Results: 5}
	r := testRunner(t, Options{Host: "a.test", Sources: []string{"urlscan"}, URLScan: us,
		InScope: func(h string) bool { return h == "a.test" }})
	if err := r.list(context.Background()); err != nil {
		t.Fatal(err)
	}
	if results.Load() != 1 || key != "k" || r.st.URLScan.Read != 1 || !r.st.URLScan.Searched {
		t.Fatalf("results read %d, key %q, state %+v", results.Load(), key, r.st.URLScan)
	}
	r.js.Sync()
	gs, _ := r.groups()
	if len(gs) != 1 || gs[0].latest.URL != "https://a.test/js/app.4f2a.js" || gs[0].latest.Source != "urlscan" {
		t.Fatalf("%+v", gs)
	}
	if r.st.Summary.Skipped["out of scope"] != 3 { // other.test twice, the CDN's script
		t.Fatalf("skipped %v", r.st.Summary.Skipped)
	}
}
