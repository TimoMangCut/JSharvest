package archive

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// newClient makes an archive client open to loopback test servers.
func newClient() *Client {
	c := newClientWith(nil, nil)
	c.HTTP.Transport = c.HTTP.Transport.(netsafe.Guard).Next
	tr := c.HTTP.Transport.(*http.Transport)
	tr.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	return c
}

func newClientWith(proxy *url.URL, rules netsafe.Rules) *Client {
	return NewClientSafe(proxy, rules, nil)
}

func warcRecord(t *testing.T, typ, httpPart string) []byte {
	t.Helper()
	rec := fmt.Sprintf("WARC/1.0\r\nWARC-Type: %s\r\nWARC-Target-URI: https://app.test/a.js\r\nWARC-Payload-Digest: sha1:ABC\r\nContent-Length: %d\r\n\r\n%s\r\n\r\n",
		typ, len(httpPart), httpPart)
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(rec))
	zw.Close()
	return b.Bytes()
}

func TestReadRecord(t *testing.T) {
	plain := "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 12\r\n\r\nconsole.log1"
	r, err := ReadRecord(warcRecord(t, "response", plain), 1<<20)
	if err != nil || r.Status != 200 || string(r.Body) != "console.log1" || r.TargetURI != "https://app.test/a.js" || r.PayloadDigest != "sha1:ABC" {
		t.Fatalf("%+v %v", r, err)
	}
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	if r, err := ReadRecord(warcRecord(t, "response", chunked), 1<<20); err != nil || string(r.Body) != "hello world" {
		t.Fatalf("chunked: %+v %v", r, err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("var x = 1;"))
	zw.Close()
	coded := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", gz.Len(), gz.String())
	if r, err := ReadRecord(warcRecord(t, "response", coded), 1<<20); err != nil || string(r.Body) != "var x = 1;" {
		t.Fatalf("gzip: %+v %v", r, err)
	}
	if _, err := ReadRecord(warcRecord(t, "revisit", plain), 1<<20); err != ErrNotResponse {
		t.Fatalf("revisit: %v", err)
	}
	if _, err := ReadRecord(warcRecord(t, "response", plain), 4); err == nil {
		t.Fatal("over the size limit")
	}
}

func historical(archived []endpoints.Endpoint, current [][]endpoints.Endpoint) []endpoints.Endpoint {
	var out []endpoints.Endpoint
	for _, a := range archived {
		if !a.ThirdParty && !generic(a) && !matches(a, current) {
			out = append(out, a)
		}
	}
	return out
}

func TestHistorical(t *testing.T) {
	ep := func(m, p string, bases ...string) endpoints.Endpoint {
		return endpoints.Endpoint{Method: m, Path: p, Bases: bases}
	}
	current := [][]endpoints.Endpoint{{
		ep("GET", "/api/v2/items/{id}"),
		ep("POST", "/api/v2/orders"),
		{Method: "GET", Path: "/users/{}", Base: "/api/v2"},
		ep("", "/api/v2/reports/{}/export"),
	}}
	archived := []endpoints.Endpoint{
		ep("GET", "/api/v2/items/{}"),      // the same, another placeholder
		ep("GET", "/api/v1/legacy-export"), // gone: historical
		ep("POST", "/api/v2/orders"),       // the same
		ep("DELETE", "/api/v2/orders"),     // another method: historical
		ep("GET", "/api/v2/users/{id}"),    // the current one has a base
		ep("GET", "{}/reports/{}/export"),  // an unknown base, the same end
		ep("GET", "/api/{}"),               // too generic to tell
		{Method: "GET", Path: "/x/y", ThirdParty: true},
	}
	var got []string
	for _, e := range historical(archived, current) {
		got = append(got, e.Method+" "+e.Path)
	}
	if want := []string{"GET /api/v1/legacy-export", "DELETE /api/v2/orders"}; !slices.Equal(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
}

func TestParseCDX(t *testing.T) {
	// A real answer of the CDX server (testdata/cdx-example.json).
	b, err := os.ReadFile("testdata/cdx-example.json")
	if err != nil {
		t.Fatal(err)
	}
	caps, resume, err := parseCDX(b)
	if err != nil || len(caps) != 3 || resume != "eJxLzs_VSa1IzC3ISdXUVzAyMDAyMDUyMTAxNDOyAAB_YgeU" {
		t.Fatalf("%v %q %v", caps, resume, err)
	}
	c := caps[0]
	if c.URL != "http://example.com/" || c.Timestamp != "20020120142510" || c.Digest != "HT2DYGA5UKZCPBSFVCV3JOBXGW2G5UUA" || c.Status != "200" ||
		c.MIME != "text/html" || c.Time.Year() != 2002 || caps[1].URL != "http://www.example.com/" {
		t.Fatalf("%+v %+v", c, caps[1])
	}
	// The last page: no resume key; an empty answer: nothing archived.
	if _, resume, err := parseCDX([]byte(`[["timestamp","original"],["2020","https://a.test/x.js"]]`)); err != nil || resume != "" {
		t.Fatal(resume, err)
	}
	if caps, _, err := parseCDX(nil); err != nil || caps != nil {
		t.Fatal(caps, err)
	}
	if got := Normalize("HTTPS://App.Test:443/a.js?v=1"); got != "https://app.test/a.js?v=1" {
		t.Fatal(got)
	}
	w := &Wayback{Base: "https://web.archive.org"}
	if got := w.Memento(Capture{URL: "https://a.test/x.js", Timestamp: "20200101000000"}); got != "https://web.archive.org/web/20200101000000id_/https://a.test/x.js" {
		t.Fatal(got)
	}
}

func TestClient(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("Accept-Encoding %q", r.Header.Get("Accept-Encoding"))
		}
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
		case 2:
			w.WriteHeader(503)
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()
	c := newClient()
	c.Wait = time.Millisecond
	a, err := c.Get(context.Background(), &Budget{}, srv.URL, 100)
	if err != nil || string(a.Body) != "ok" || n.Load() != 3 {
		t.Fatalf("%v %v %d", a, err, n.Load())
	}
	// Refused, again and again: blocked.
	dead := httptest.NewServer(http.NotFoundHandler())
	addr := dead.URL
	dead.Close()
	c = newClient()
	c.Wait, c.Tries = time.Millisecond, 10
	if _, err := c.Get(context.Background(), &Budget{}, addr, 100); !errors.Is(err, ErrBlocked) {
		t.Fatalf("refused: %v", err)
	}
	// An excluded domain.
	ex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `{"error":"org.archive.wayback.exception.AdministrativeAccessControlException: Blocked Site Error"}`)
	}))
	defer ex.Close()
	w := &Wayback{Base: ex.URL, Client: newClient(), Index: &Budget{}, PageSize: 10}
	if _, _, err := w.Page(context.Background(), "a.test", ""); !errors.Is(err, ErrExcluded) {
		t.Fatalf("excluded: %v", err)
	}
}

func TestClassify(t *testing.T) {
	cur := &current{catalogs: [][]endpoints.Endpoint{{
		{Method: "GET", Path: "/api/v2/orders"},
		{Path: "/api/v2{}"}, // a wrapper's: matches nothing
	}}}
	archived := []endpoints.Endpoint{
		{Method: "GET", Path: "/api/v1/orders"},
		{Method: "GET", Path: "/api/v2/export-all"},
		{Method: "GET", Path: "/internal/debug-panel", Kind: "string"},
		{Method: "GET", Path: "/api/{}"},
	}
	lines, inCode := classify(archived, cur, func(string) (store.Entry, bool) { return store.Entry{}, false })
	var got []string
	for _, l := range lines {
		got = append(got, l.Class+" "+l.Path)
	}
	want := []string{"version_changed /api/v1/orders", "historical /api/v2/export-all", "low /internal/debug-panel", "low /api/{}"}
	if !slices.Equal(got, want) || inCode != 0 {
		t.Fatalf("%v %d", got, inCode)
	}
}

func TestInScripts(t *testing.T) {
	files := [][]byte{[]byte(`const x = "/api/v1/users"; label("orders"); // GET /api/v2/hidden-report
fetch("/api/v3/teams/" + id + "/members"); fetch(` + "`/api/v3/projects/${p}/export`" + `)`)}
	for p, want := range map[string]bool{
		"/api/v2/hidden-report":      true,  // written out, in a comment
		"/api/v1/{}/orders":          false, // its pieces are, not its path
		"/api/v1/legacy-export":      false,
		"/api/v3/projects/{}/export": true,  // a template literal
		"/api/v3/teams/{}/members":   false, // built by concatenation: not written out
		"/a/{}":                      false, // too little to tell
	} {
		if got := inScripts(endpoints.Endpoint{Path: p}, files); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}
