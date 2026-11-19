package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// D: six hosts serve the same bundle and map. The map is fetched once; the
// source it carries is stored once and names all six scripts as its pages,
// with no sighting lost even when the hosts are crawled concurrently.
func TestRound371ReusedMapSourcesNameEveryHost(t *testing.T) {
	const bundle = "fetch('/api/app');\n//# sourceMappingURL=app.js.map\n"
	const mapJSON = `{"version":3,"file":"app.js","sources":["src/main.js"],"sourcesContent":["export const load = () => fetch('/api/orders/list');"],"mappings":"AAAA"}`
	var mapHits atomic.Int64
	var hosts []*httptest.Server
	for range 6 {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/app.js":
				w.Header().Set("Content-Type", "application/javascript")
				fmt.Fprint(w, bundle)
			case "/app.js.map":
				mapHits.Add(1)
				time.Sleep(50 * time.Millisecond)
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, mapJSON)
			default:
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<!doctype html><title>portal</title><script src="/app.js"></script>`)
			}
		}))
		defer srv.Close()
		hosts = append(hosts, srv)
	}
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<!doctype html><title>seed</title>")
		for _, h := range hosts {
			fmt.Fprintf(&b, `<a href="%s/">x</a>`, h.URL)
		}
		w.Write([]byte(b.String()))
	}))
	defer seed.Close()
	target, _ := url.Parse(seed.URL + "/")
	out := t.TempDir()
	if _, err := RunHTTP(context.Background(), Config{Target: target, OutRoot: out, Role: "anon", ScopeMode: "fqdn", Depth: 1, NavTimeout: 5 * time.Second},
		HTTPOptions{Rate: 500, PageWorkers: 4, NoSpecProbe: true, SourceMaps: true}); err != nil {
		t.Fatal(err)
	}
	if hits := mapHits.Load(); hits != 1 {
		t.Errorf("the map was fetched %d times, want once", hits)
	}
	idx, err := filepath.Glob(filepath.Join(out, "*", "anon", "index.jsonl"))
	if err != nil || len(idx) != 1 {
		t.Fatalf("index.jsonl: %v %v", idx, err)
	}
	f, err := os.Open(idx[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	found := false
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 16<<20)
	for sc.Scan() {
		var e struct {
			Tags  []string `json:"tags"`
			Pages []string `json:"pages"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil || !strings.Contains(strings.Join(e.Tags, ","), "source:src/main.js") {
			continue
		}
		found = true
		for _, h := range hosts {
			want := h.URL + "/app.js"
			ok := false
			for _, p := range e.Pages {
				if p == want {
					ok = true
				}
			}
			if !ok {
				t.Errorf("source src/main.js does not name %s among its pages: %v", want, e.Pages)
			}
		}
	}
	if !found {
		t.Fatal("source src/main.js not in index.jsonl")
	}
}
