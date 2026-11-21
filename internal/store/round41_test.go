package store

import (
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
