package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCanonicalKey(t *testing.T) {
	cases := []struct{ in, want string }{
		// Real names from the testbed builds.
		{"http://h/static/js/main.7b54536e.js", "h/static/js/main.[h].js"},
		{"http://h/static/js/16.a8b9b39f.chunk.js", "h/static/js/16.[h].chunk.js"},
		{"http://h/assets/index-tkF5t2Ua.js", "h/assets/index-[h].js"},
		{"http://h/assets/calc.worker-wfrOGA0t.js", "h/assets/calc.worker-[h].js"},
		{"http://h/chunk-LADWWXNY.js", "h/chunk-[h].js"},
		{"http://h/polyfills-B6TNHZQ6.js", "h/polyfills-[h].js"},
		{"http://h/workbox-2fbc6a65.js", "h/workbox-[h].js"},
		{"http://h/_next/static/chunks/pages/index-4f351d505ee1cb62.js", "h/_next/static/chunks/pages/index-[h].js"},
		{"http://h/_next/static/chunks/pages/items/[id]-148c5e1c4d48bae8.js", "h/_next/static/chunks/pages/items/[id]-[h].js"},
		{"http://h/_next/static/chunks/472.fc7b8c7ef44800b8.js", "h/_next/static/chunks/472.[h].js"},
		// A Rollup hash may contain "-" or "_".
		{"http://h/assets/index-D-eBaYxL.js", "h/assets/index-[h].js"},
		// The Next.js build id directory.
		{"http://h/_next/static/Xb3kQ9pLm2Rt7vW1yZ0aC/_buildManifest.js", "h/_next/static/[h]/_buildManifest.js"},
		// Query and fragment are dropped, the host is lowercased.
		{"https://CDN.Example.com/app.js?v=3#x", "cdn.example.com/app.js"},
		// Words and versions must survive.
		{"http://h/js/settings.js", "h/js/settings.js"},
		{"http://h/js/app-settings.js", "h/js/app-settings.js"},
		{"http://h/js/vendor-react.js", "h/js/vendor-react.js"},
		{"http://h/js/foo.decade.js", "h/js/foo.decade.js"},
		{"http://h/js/jquery-3.7.1.min.js", "h/js/jquery-3.7.1.min.js"},
		{"http://h/js/20240101.bundle.js", "h/js/20240101.bundle.js"},
		// CamelCase component names are words, not hashes; .cjs is JS too.
		{"http://h/js/app-HomePage.js", "h/js/app-HomePage.js"},
		{"http://h/js/ui-CheckBox.js", "h/js/ui-CheckBox.js"},
		{"http://h/js/x-Settings.js", "h/js/x-Settings.js"},
		{"http://h/assets/index-Bo3xJF6r.js", "h/assets/index-[h].js"},
		{"http://h/assets/home-QmTKpwZr.js", "h/assets/home-[h].js"},
		{"http://h/lib/util-a1B2c3D4.cjs", "h/lib/util-[h].cjs"},
		// CMS & bundler cache-busted families (Round 34).
		{"https://h/sites/default/files/js/js_-or32LOFfuoCLfXnNJEfHuUaXbuH5QX.js", "h/sites/default/files/js/js_[h].js"},
		{"https://h/wp-content/cache/autoptimize/js/autoptimize_090440247985fc1b6a15d99098ac5d8c.js", "h/wp-content/cache/autoptimize/js/autoptimize_[h].js"},
		{"https://h/wp-content/litespeed/js/132/063b9d1f55b0dc299afeaabde2930a00.js", "h/wp-content/litespeed/js/132/[h].js"},
		{"https://h/wp-content/uploads/essential-addons-elementor/eael-94821.min.js", "h/wp-content/uploads/essential-addons-elementor/eael-[h].min.js"},
		{"https://h/assets/app-4f351d505ee1cb62.min.js", "h/assets/app-[h].min.js"},
		// Semantic underscore names stay intact.
		{"https://h/modules/quicklink/js/quicklink_init.js?v=1", "h/modules/quicklink/js/quicklink_init.js"},
		{"https://h/js/eu_cookie_compliance.min.js", "h/js/eu_cookie_compliance.min.js"},
		// Not an absolute URL: no key.
		{"", ""},
		{"/relative.js", ""},
	}
	for _, c := range cases {
		if got := CanonicalKey(c.in); got != c.want {
			t.Errorf("CanonicalKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSHA1B32(t *testing.T) {
	// Python: base64.b32encode(hashlib.sha1(b"abc").digest())
	if got, want := SHA1B32([]byte("abc")), "VGMT4NSHA2AWVOR6EVYXQUGCNSONBWE5"; got != want {
		t.Fatalf("SHA1B32(abc) = %s, want %s", got, want)
	}
}

func TestLoadV1Index(t *testing.T) {
	dir := copyDir(t, "testdata/v1")
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, e := range readIndex(t, dir) {
		if len(e.Kinds) != 1 || e.Kinds[0] != "file" {
			t.Errorf("%s: kinds = %v, want [file]", e.SHA256[:8], e.Kinds)
		}
		if len(e.Via) != 1 || e.Via[0] != "network" {
			t.Errorf("%s: via = %v, want [network]", e.SHA256[:8], e.Via)
		}
		if len(e.SHA1B32) != 32 {
			t.Errorf("%s: sha1_b32 = %q", e.SHA256[:8], e.SHA1B32)
		}
		if len(e.CanonicalKeys) == 0 || len(e.URLs) == 0 {
			t.Errorf("%s: urls %v canonical %v", e.SHA256[:8], e.URLs, e.CanonicalKeys)
		}
	}
}

func TestMerge(t *testing.T) {
	s, err := Open(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("console.log(1)")
	isNew, err := s.Add(Record{Body: body, URL: "http://h/a.js?v=1", Kind: "file", Via: "network", Target: "page",
		Page: "http://h/", Headers: map[string]string{"ETag": `"x"`, "Set-Cookie": "secret"}, Source: "live"})
	if err != nil || !isNew {
		t.Fatalf("first Add = %v, %v", isNew, err)
	}
	isNew, err = s.Add(Record{Body: body, Kind: "inline", Via: "debugger", Target: "worker", Page: "http://h/p",
		Initiator: &Initiator{Type: "script", URL: "http://h/main.js", Line: 3}, Source: "wayback"})
	if err != nil || isNew {
		t.Fatalf("second Add = %v, %v", isNew, err)
	}
	e := s.entries[mustOnlyKey(t, s)]
	check := func(name string, got, want any) {
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	check("kinds", e.Kinds, []string{"file", "inline"})
	check("via", e.Via, []string{"network", "debugger"})
	check("targets", e.Targets, []string{"page", "worker"})
	check("urls", e.URLs, []string{"http://h/a.js?v=1"})
	check("canonical", e.CanonicalKeys, []string{"h/a.js", "h/p#inline"})
	check("pages", e.Pages, []string{"http://h/", "http://h/p"})
	check("headers", e.Headers, map[string]string{"etag": `"x"`})
	check("initiators", len(e.Initiators), 1)
	check("source", e.Source, "both")
}

func TestSighting(t *testing.T) {
	s, err := Open(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.Add(Record{Body: []byte("x()"), URL: "http://h/a.js", Kind: "file", Target: "page"})
	key := mustOnlyKey(t, s)
	if isNew, err := s.Add(Record{SHA256: key, Kind: "file", Target: "worker", Page: "http://h/w"}); isNew || err != nil {
		t.Fatalf("sighting Add = %v, %v", isNew, err)
	}
	// A sighting of unknown content is ignored.
	s.Add(Record{SHA256: strings.Repeat("0", 64), Target: "iframe"})
	e := s.entries[key]
	if fmt.Sprint(e.Targets) != "[page worker]" || fmt.Sprint(e.Pages) != "[http://h/w]" || s.Len() != 1 {
		t.Errorf("targets %v pages %v len %d", e.Targets, e.Pages, s.Len())
	}
}

func TestMergesAreFlushed(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.Add(Record{Body: []byte("x"), URL: "http://h/a.js", Kind: "file"})
	s.Flush()
	// A merge into a known script, and a body-less sighting, are changes the
	// background flush must write.
	s.Add(Record{Body: []byte("x"), URL: "http://h/b.js", Kind: "file"})
	s.Add(Record{SHA256: mustOnlyKey(t, s), Target: "worker"})
	if s.unflushed != 2 {
		t.Fatalf("unflushed = %d after a merge and a sighting, want 2", s.unflushed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go s.AutoFlush(ctx, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	cancel()
	e := readIndex(t, dir)[0]
	if fmt.Sprint(e.URLs) != "[http://h/a.js http://h/b.js]" || fmt.Sprint(e.Targets) != "[worker]" {
		t.Errorf("index on disk: urls %v targets %v", e.URLs, e.Targets)
	}
}

func TestInlineCanonicalKeyUsesDocument(t *testing.T) {
	s, _ := Open(t.TempDir(), Options{})
	s.Add(Record{Body: []byte("x()"), URL: "http://h/frame.html", Kind: "inline", Page: "http://h/"})
	s.Add(Record{Body: []byte("y()"), Kind: "inline", Page: "http://h/p"})
	var keys []string
	for _, k := range s.order {
		keys = append(keys, s.entries[k].CanonicalKeys...)
	}
	if fmt.Sprint(keys) != "[h/frame.html#inline h/p#inline]" {
		t.Errorf("inline keys = %v", keys)
	}
}

func TestLimits(t *testing.T) {
	s, err := Open(t.TempDir(), Options{MaxBody: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(Record{Body: []byte("01234567890"), Kind: "file"}); err != ErrTooLarge {
		t.Errorf("over-size Add err = %v, want ErrTooLarge", err)
	}
	if isNew, err := s.Add(Record{Kind: "file"}); isNew || err != nil {
		t.Errorf("empty Add = %v, %v", isNew, err)
	}
	for i := range 300 {
		s.Add(Record{Body: []byte("x"), URL: fmt.Sprintf("http://h/%d.js", i), Kind: "file"})
	}
	if n := len(s.entries[mustOnlyKey(t, s)].URLs); n != maxURLs {
		t.Errorf("urls = %d, want cap %d", n, maxURLs)
	}
}

func TestConcurrentAdd(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := range 100 {
		wg.Go(func() {
			for i := range 20 {
				// 40 distinct bodies, each added by several goroutines.
				body := fmt.Appendf(nil, "b%d", (g+i)%40)
				if _, err := s.Add(Record{Body: body, URL: fmt.Sprintf("http://h/%d.js", g), Kind: "file", Via: "network"}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := len(readIndex(t, dir)); got != 40 {
		t.Errorf("index lines = %d, want 40", got)
	}
}

func TestRecoverOrphans(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.Add(Record{Body: []byte("indexed"), URL: "http://h/a.js", Kind: "file"})
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	// A run killed after writing a body but before flushing the index.
	orphan := []byte("orphan")
	s2, _ := Open(t.TempDir(), Options{})
	s2.Add(Record{Body: orphan, Kind: "file"})
	key := mustOnlyKey(t, s2)
	if err := os.WriteFile(filepath.Join(dir, "js", key+".js"), orphan, 0o644); err != nil {
		t.Fatal(err)
	}

	s3, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := s3.Recovered(); rec != 1 || s3.Len() != 2 {
		t.Fatalf("recovered %d, len %d; want 1, 2", rec, s3.Len())
	}
	if k := s3.entries[key].Kinds; len(k) != 1 || k[0] != "unknown" {
		t.Errorf("orphan kinds = %v", k)
	}
}

func TestDiscardDamaged(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	// A truncated write under a final name, and a leftover temp file.
	bad := filepath.Join(dir, "js", strings.Repeat("ab", 32)+".js")
	if err := os.WriteFile(bad, []byte("truncated"), 0o644); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "js", ".tmp-123")
	if err := os.WriteFile(tmp, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rec, disc := s.Recovered(); rec != 0 || disc != 1 || s.Len() != 0 {
		t.Fatalf("recovered %d, discarded %d, len %d; want 0, 1, 0", rec, disc, s.Len())
	}
	for _, p := range []string{bad, tmp} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists", filepath.Base(p))
		}
	}
}

func mustOnlyKey(t *testing.T, s *Store) string {
	t.Helper()
	if len(s.order) != 1 {
		t.Fatalf("store has %d entries, want 1", len(s.order))
	}
	return s.order[0]
}

func readIndex(t *testing.T, dir string) []Entry {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestArchiveSources(t *testing.T) {
	s, err := Open(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	body := []byte("var old = 1;")
	s.Add(Record{Body: body, URL: "https://app.test/old.js", Kind: "file", Source: "wayback", Alive: &yes,
		Archive: &ArchiveSeen{First: time.Unix(100, 0), Last: time.Unix(200, 0), Captures: 3}})
	s.Add(Record{Body: body, URL: "https://app.test/old.js", Kind: "file", Source: "commoncrawl",
		Archive: &ArchiveSeen{First: time.Unix(50, 0), Last: time.Unix(150, 0), Captures: 1}})
	e := s.entries[mustOnlyKey(t, s)]
	if e.Source != "wayback" || len(e.Sources) != 2 || e.Alive == nil || !*e.Alive || e.Archive.First != time.Unix(50, 0) || e.Archive.Last != time.Unix(200, 0) || e.Archive.Captures != 3 {
		t.Fatalf("two archives: %+v %+v", e, e.Archive)
	}
	s.Add(Record{Body: body, URL: "https://app.test/old.js", Kind: "file", Source: "live"})
	if e.Source != "both" {
		t.Fatalf("live and an archive: %s", e.Source)
	}
	if s.BySHA1(SHA1B32(body)) != e.SHA256 || s.BySHA1("NOPE") != "" {
		t.Fatal("BySHA1")
	}
}
