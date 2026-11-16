package endpoints

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/store"
)

func TestExtractCachedWarmsAnalyzeWithoutReparse(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	src := []byte(`export function loadOrders(id: string) { return fetch("/api/v2/orders/" + id); }`)
	hint := "https://app.example.com/src/orders.ts"
	sha, _, err := st.Put(store.Record{
		Body:   src,
		URL:    hint,
		Kind:   "source",
		Via:    "sourcemap",
		Target: "http",
		Tags:   []string{"sourcemap"},
		Source: "live",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}

	r1 := ExtractCached(dir, src, hint)
	if len(r1.Endpoints) != 1 || r1.Endpoints[0].URL != "/api/v2/orders/{}" {
		t.Fatalf("ExtractCached endpoints = %+v, want /api/v2/orders/{}", r1.Endpoints)
	}

	cachePath := filepath.Join(dir, CacheDir, sha+".json")
	fi, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("missing static cache file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("cache file mode = %04o, want 0600", perm)
	}

	// Remove js/<sha>.js to prove Analyze hits the warm static/<sha>.json cache
	// directly without reading or re-parsing js/<sha>.js a second time.
	if err := os.Remove(filepath.Join(dir, "js", sha+".js")); err != nil {
		t.Fatal(err)
	}
	scripts, err := Analyze(dir, 1)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if len(scripts) != 1 || len(scripts[0].Endpoints) != 1 || scripts[0].Endpoints[0].URL != "/api/v2/orders/{}" {
		t.Fatalf("Analyze did not reuse warm cache: %+v", scripts)
	}
}
