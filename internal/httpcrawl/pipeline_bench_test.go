package httpcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// JSH_PIPE_BENCH=1 go test -run TestPipelineBench -v ./internal/httpcrawl
// measures a crawl against its -http-rate floor on a site with latency and
// one slow script a page (round 25L, step 2.3: measure before changing).
func TestPipelineBench(t *testing.T) {
	if os.Getenv("JSH_PIPE_BENCH") == "" {
		t.Skip("JSH_PIPE_BENCH not set")
	}
	const pages, scripts, rtt, slow = 20, 10, 120 * time.Millisecond, 1500 * time.Millisecond
	var n atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		time.Sleep(rtt)
		p := strings.TrimPrefix(r.URL.Path, "/")
		switch {
		case p == "":
			w.Header().Set("Content-Type", "text/html")
			var b strings.Builder
			b.WriteString("<!doctype html><title>home</title>")
			for i := 1; i < pages; i++ {
				fmt.Fprintf(&b, `<a href="/p%d">p%d</a>`, i, i)
			}
			for k := range scripts {
				fmt.Fprintf(&b, `<script src="/s/home-%d.js"></script>`, k)
			}
			w.Write([]byte(b.String()))
		case strings.HasPrefix(p, "p"):
			w.Header().Set("Content-Type", "text/html")
			var b strings.Builder
			fmt.Fprintf(&b, "<!doctype html><title>%s</title><h1>%s</h1>", p, p)
			for k := range scripts {
				fmt.Fprintf(&b, `<script src="/s/%s-%d.js"></script>`, p, k)
			}
			w.Write([]byte(b.String()))
		case strings.HasPrefix(p, "s/"):
			if strings.HasSuffix(p, "-0.js") {
				time.Sleep(slow)
			}
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, "console.log(%q)", p)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	began := time.Now()
	if _, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 1, Rate: benchRate(), MaxPages: 100,
		Script: func(Script) {}, Page: func(Page) {}, Log: func(string, ...any) {}}); err != nil {
		t.Fatal(err)
	}
	took := time.Since(began)
	floor := time.Duration(float64(n.Load()) / benchRate() * float64(time.Second))
	t.Logf("requests %d, took %s, -http-rate floor %s, %.0f%% of the ceiling", n.Load(), took.Round(time.Millisecond), floor.Round(time.Millisecond), 100*floor.Seconds()/took.Seconds())
}

func benchRate() float64 {
	var r float64 = 5
	fmt.Sscan(os.Getenv("JSH_PIPE_RATE"), &r)
	return r
}
