package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRound41StoreFlushAmortized(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	const total = 2000
	for i := range total {
		body := []byte(fmt.Sprintf("export const endpoint_%d = '/api/v1/r/%d';\n", i, i))
		if _, err := st.Add(Record{
			Body:   body,
			URL:    fmt.Sprintf("https://app.example/js/c_%d.js", i),
			Kind:   "file",
			Via:    "http",
			Source: "live",
		}); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	// Under fixed flushEveryNew=50, 2,000 unique files triggered 40 full index
	// rewrites; geometric max(50, len(order)/10) keeps it <= 25.
	if st.flushes > 25 {
		t.Fatalf("expected geometric flush count <= 25 for %d files, got %d", total, st.flushes)
	}
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Len(); got != total {
		t.Fatalf("reloaded store Len() = %d, want %d", got, total)
	}

	// SaveMap writes atomically with 0600 permissions and leaves no temp files.
	mapBody := []byte(`{"version":3,"sources":["a.js"],"sourcesContent":["1"]}`)
	if err := st.SaveMap(mapBody); err != nil {
		t.Fatalf("SaveMap: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "maps"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("maps dir entries = %v, err = %v", entries, err)
	}
	if strings.HasPrefix(entries[0].Name(), ".tmp-") {
		t.Fatalf("leftover temp file in maps dir: %s", entries[0].Name())
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("map file permissions = %04o, want 0600", perm)
	}
}

func TestRound41StoreBudgetCountsJSAndMaps(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, Options{MaxRunBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}

	js1 := bytes.Repeat([]byte("a"), 600)
	sha1, isNew, err := st.Put(Record{Body: js1, URL: "https://app.example/a.js", Kind: "file", Source: "live"})
	if err != nil || !isNew || st.BytesWritten() != 600 {
		t.Fatalf("first Put: isNew=%v err=%v bytes=%d", isNew, err, st.BytesWritten())
	}

	// Duplicate content and SHA-only sightings must NOT consume or fail MaxRunBytes.
	if _, isNew, err := st.Put(Record{Body: js1, URL: "https://app.example/a-copy.js", Kind: "file", Source: "live"}); err != nil || isNew {
		t.Fatalf("duplicate Put failed: isNew=%v err=%v", isNew, err)
	}
	if gotSHA, _, err := st.Put(Record{SHA256: sha1, URL: "https://other.example/a.js", Kind: "file", Source: "live"}); err != nil || gotSHA != sha1 {
		t.Fatalf("sighting Put failed: gotSHA=%q err=%v", gotSHA, err)
	}
	if st.BytesWritten() != 600 {
		t.Fatalf("dedupe/sighting changed BytesWritten: got %d, want 600", st.BytesWritten())
	}

	// SaveMap counts toward the same run budget; re-saving existing map is free.
	map1 := bytes.Repeat([]byte("m"), 350)
	if err := st.SaveMap(map1); err != nil {
		t.Fatalf("first SaveMap: %v", err)
	}
	if st.BytesWritten() != 950 {
		t.Fatalf("after SaveMap BytesWritten = %d, want 950", st.BytesWritten())
	}
	if err := st.SaveMap(map1); err != nil || st.BytesWritten() != 950 {
		t.Fatalf("idempotent SaveMap: err=%v bytes=%d", err, st.BytesWritten())
	}

	// Exceeding remaining 50 bytes via either SaveMap or Put returns ErrStoreBudget.
	map2 := bytes.Repeat([]byte("n"), 100)
	if err := st.SaveMap(map2); !errors.Is(err, ErrStoreBudget) {
		t.Fatalf("oversize SaveMap err = %v, want ErrStoreBudget", err)
	}
	js2 := bytes.Repeat([]byte("b"), 100)
	if _, _, err := st.Put(Record{Body: js2, URL: "https://app.example/b.js", Kind: "file", Source: "live"}); !errors.Is(err, ErrStoreBudget) {
		t.Fatalf("oversize Put err = %v, want ErrStoreBudget", err)
	}
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}

	// Next run opening the same directory starts with a fresh per-run byte counter.
	st2, err := Open(dir, Options{MaxRunBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if _, isNew, err := st2.Put(Record{Body: js2, URL: "https://app.example/b.js", Kind: "file", Source: "live"}); err != nil || !isNew {
		t.Fatalf("new run Put failed: isNew=%v err=%v", isNew, err)
	}
}
